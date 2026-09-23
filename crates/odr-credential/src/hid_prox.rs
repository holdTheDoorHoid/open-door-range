//! HID Prox H10301 — the 26-bit format, over the air.
//!
//! This module exists to make one point, and Module 0.3 is built on it: **the bits a
//! prox card broadcasts are the bits the reader puts on the wire.** There is no
//! translation step where something could be checked, no key that could be verified,
//! no nonce that could make a replay stale. The facility code and card number you pull
//! off the RF layer in Module 0 are the same facility code and card number you will
//! sniff off D0/D1 in Module 1, bit for bit.
//!
//! # H10301, the 26-bit Wiegand payload
//!
//! ```text
//! bit  0      leading parity, EVEN over bits 1..12   (facility code + top 4 of card)
//! bits 1..8   facility code, 8 bits, MSB first
//! bits 9..24  card number, 16 bits, MSB first
//! bit  25     trailing parity, ODD over bits 13..24  (bottom 12 of card)
//! ```
//!
//! Two parity bits over 24 bits of payload. They catch a single bit error on the wire.
//! They are computed by anyone, from the payload, with no secret — so they stop noise
//! and stop nothing else. Module 1.2 flips a card-number bit, recomputes both parity
//! bits, and the panel opens a different door.
//!
//! # The 44-bit block on the card
//!
//! An HID prox card does not store the 26 Wiegand bits on their own. It stores a
//! 44-bit block:
//!
//! ```text
//! bits 43..38   zero
//! bit  37       1 — marks a short (under 37-bit) format
//! bits 36..27   zero
//! bit  26       1 — the length sentinel: the highest set bit below the marker says
//!                   how many format bits follow, here 26
//! bits 25..0    the Wiegand payload
//! ```
//!
//! The sentinel is how a reader that was never told the format still knows the length:
//! it finds the top set bit and counts down. That is also why a 26-bit and a 35-bit
//! credential can sit on the same reader — and why "the reader supports our format" is
//! not a security property.
//!
//! For facility code 123, card number 4567 the block is `0x2006F623AE`, which is the
//! vector this module is tested against.
//!
//! # On the air
//!
//! FSK, 125 kHz carrier, nominally RF/50: a data bit is six cycles of fc/8 or five
//! cycles of fc/10. A 96-bit block goes out as an 8-bit raw preamble `00011101`
//! followed by the 44 data bits Manchester coded into 88 more.

use crate::credential::{Credential, CredentialFormat};
use crate::error::{CredentialError, Result};
use crate::modulation::{
    fsk_demodulate, fsk_event_stream, manchester_decode, manchester_encode, CarrierConfig,
    EventStream, FskParams,
};

/// The 8-bit raw preamble at the head of every HID block.
///
/// Not Manchester coded — that is the point of it. Manchester data can never contain
/// three identical bits in a row, so `000` is a sync pattern that cannot be forged by
/// the payload.
pub const PREAMBLE: [bool; 8] = [false, false, false, true, true, true, false, true];

/// Data bits in an HID short-format block.
pub const BLOCK_BITS: usize = 44;

/// Total bits on the air per block: 8 preamble + 88 Manchester half-bits.
pub const AIR_BITS: usize = 96;

/// Bit index of the short-format marker inside the 44-bit block.
pub const SHORT_FORMAT_MARKER_BIT: u32 = 37;

/// Bits in the H10301 Wiegand payload.
pub const WIEGAND_BITS: usize = 26;

/// A 26-bit HID H10301 credential: a facility code and a card number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct H10301 {
    /// Facility code, 8 bits. Sites are issued one; it is not a secret and is often
    /// printed on the card.
    pub facility_code: u8,
    /// Card number, 16 bits.
    pub card_number: u16,
}

impl H10301 {
    /// A credential with the given facility code and card number.
    pub const fn new(facility_code: u8, card_number: u16) -> Self {
        Self {
            facility_code,
            card_number,
        }
    }

    /// The 24 payload bits, MSB first: facility code then card number.
    pub const fn payload24(&self) -> u32 {
        ((self.facility_code as u32) << 16) | self.card_number as u32
    }

    /// The leading parity bit: **even** over the top 12 payload bits.
    pub const fn leading_parity(&self) -> bool {
        (self.payload24() >> 12).count_ones() % 2 == 1
    }

    /// The trailing parity bit: **odd** over the bottom 12 payload bits.
    pub const fn trailing_parity(&self) -> bool {
        (self.payload24() & 0xFFF).count_ones().is_multiple_of(2)
    }

    /// The exact 26 bits the reader will clock out on D0/D1, first bit first.
    ///
    /// This is the function drill 0.3 is built on: the learner reads the facility code
    /// and card number off the RF layer, calls this, and predicts the wire before the
    /// wire has carried anything. `odr-wiegand` will produce the same 26 bits from its
    /// own independent encoder; if the two ever disagree, one of them is wrong and the
    /// drill fails rather than lying.
    pub fn wiegand_bits(&self) -> [bool; WIEGAND_BITS] {
        let mut out = [false; WIEGAND_BITS];
        out[0] = self.leading_parity();
        let payload = self.payload24();
        for i in 0..24 {
            out[1 + i] = (payload >> (23 - i)) & 1 == 1;
        }
        out[25] = self.trailing_parity();
        out
    }

    /// The same 26 bits as a right-aligned integer.
    pub fn wiegand_u32(&self) -> u32 {
        let mut v = 0u32;
        for b in self.wiegand_bits() {
            v = (v << 1) | u32::from(b);
        }
        v
    }

    /// The 44-bit block as stored on the card.
    pub fn raw44(&self) -> u64 {
        (1u64 << SHORT_FORMAT_MARKER_BIT) | (1u64 << WIEGAND_BITS) | u64::from(self.wiegand_u32())
    }

    /// Recover a credential from a 44-bit block.
    ///
    /// Checks the short-format marker and the 26-bit length sentinel, and verifies
    /// both Wiegand parity bits. A block whose parity does not hold comes back as
    /// [`CredentialError::ParityFailed`] — unlike EM4100 there is no partial read to
    /// report, because a prox reader that does not like the parity simply says nothing.
    pub fn from_raw44(raw: u64) -> Result<Self> {
        if raw >> 44 != 0 {
            return Err(CredentialError::ValueTooWide {
                field: "hid block",
                bits: 44,
            });
        }
        if (raw >> SHORT_FORMAT_MARKER_BIT) & 1 != 1 {
            return Err(CredentialError::PreambleNotFound {
                decoder: "hid_prox short-format marker",
            });
        }
        // The sentinel is the highest set bit strictly below the marker.
        let below_marker = raw & ((1u64 << SHORT_FORMAT_MARKER_BIT) - 1);
        let sentinel = 63 - below_marker.leading_zeros();
        if below_marker == 0 || sentinel as usize != WIEGAND_BITS {
            return Err(CredentialError::PreambleNotFound {
                decoder: "hid_prox 26-bit length sentinel",
            });
        }

        let wiegand = (raw & 0x03FF_FFFF) as u32;
        let candidate = Self {
            facility_code: ((wiegand >> 17) & 0xFF) as u8,
            card_number: ((wiegand >> 1) & 0xFFFF) as u16,
        };
        let leading = (wiegand >> 25) & 1 == 1;
        let trailing = wiegand & 1 == 1;
        if leading != candidate.leading_parity() || trailing != candidate.trailing_parity() {
            return Err(CredentialError::ParityFailed {
                decoder: "hid_prox",
            });
        }
        Ok(candidate)
    }

    /// Recover a credential from 26 Wiegand bits, first bit first.
    pub fn from_wiegand_bits(bits: &[bool]) -> Result<Self> {
        if bits.len() != WIEGAND_BITS {
            return Err(CredentialError::StreamTooShort {
                needed: WIEGAND_BITS,
                got: bits.len(),
            });
        }
        let mut v = 0u64;
        for &b in bits {
            v = (v << 1) | u64::from(b);
        }
        Self::from_raw44((1u64 << SHORT_FORMAT_MARKER_BIT) | (1u64 << WIEGAND_BITS) | v)
    }

    /// As a [`Credential`]: 26 bits, format [`CredentialFormat::Wiegand26H10301`].
    pub fn to_credential(&self) -> Credential {
        Credential::from_u64(
            CredentialFormat::Wiegand26H10301,
            WIEGAND_BITS as u16,
            u64::from(self.wiegand_u32()),
        )
        .expect("26 bits always fits")
    }

    /// The 96 bits that go out over the air, first bit first.
    pub fn air_bits(&self) -> Vec<bool> {
        air_bits_for_block(self.raw44())
    }

    /// The modulation the reader sees, `repeats` blocks back to back.
    pub fn event_stream(&self, repeats: usize, cfg: &CarrierConfig) -> EventStream {
        block_event_stream(self.raw44(), repeats, cfg)
    }
}

/// Wrap an arbitrary 44-bit block in its preamble and Manchester coding.
pub fn air_bits_for_block(raw44: u64) -> Vec<bool> {
    let mut data = Vec::with_capacity(BLOCK_BITS);
    for i in 0..BLOCK_BITS {
        data.push((raw44 >> (BLOCK_BITS - 1 - i)) & 1 == 1);
    }
    let mut out = Vec::with_capacity(AIR_BITS);
    out.extend_from_slice(&PREAMBLE);
    out.extend(manchester_encode(&data));
    out
}

/// FSK modulation for `repeats` copies of a 44-bit block.
pub fn block_event_stream(raw44: u64, repeats: usize, cfg: &CarrierConfig) -> EventStream {
    let one = air_bits_for_block(raw44);
    let mut all = Vec::with_capacity(one.len() * repeats.max(1));
    for _ in 0..repeats.max(1) {
        all.extend_from_slice(&one);
    }
    fsk_event_stream(&all, &FskParams::HID_PROX, cfg)
}

/// Recover the 44-bit block from the modulation.
///
/// FSK-demodulate, find the raw preamble, Manchester-decode the 88 bits after it.
/// Parity is left to [`H10301::from_raw44`], so a block with broken parity is still
/// recovered and still inspectable.
pub fn demodulate_block(stream: &EventStream) -> Result<u64> {
    let bits = fsk_demodulate(stream, &FskParams::HID_PROX)?;
    if bits.len() < AIR_BITS {
        return Err(CredentialError::StreamTooShort {
            needed: AIR_BITS,
            got: bits.len(),
        });
    }
    for start in 0..=bits.len() - AIR_BITS {
        if bits[start..start + PREAMBLE.len()] != PREAMBLE {
            continue;
        }
        let body = &bits[start + PREAMBLE.len()..start + AIR_BITS];
        let Ok(data) = manchester_decode(body) else {
            continue;
        };
        let mut raw = 0u64;
        for b in data {
            raw = (raw << 1) | u64::from(b);
        }
        return Ok(raw);
    }
    Err(CredentialError::PreambleNotFound {
        decoder: "hid_prox",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-verified vector. Facility code 123, card number 4567:
    ///
    /// * payload   `01111011 0001000111010111`
    /// * leading   even parity over `011110110001` (seven ones) -> 1
    /// * trailing  odd parity over `000111010111` (seven ones)  -> 0
    /// * Wiegand   `1 01111011 0001000111010111 0` = `0x02F623AE`
    /// * block     marker bit 37 | sentinel bit 26 | Wiegand   = `0x2006F623AE`
    const FC: u8 = 123;
    const CN: u16 = 4567;
    const WIEGAND: u32 = 0x02F6_23AE;
    const BLOCK: u64 = 0x20_06F6_23AE;

    #[test]
    fn hand_verified_wiegand_pattern() {
        let c = H10301::new(FC, CN);
        assert!(c.leading_parity(), "even parity over seven ones is 1");
        assert!(!c.trailing_parity(), "odd parity over seven ones is 0");
        assert_eq!(c.wiegand_u32(), WIEGAND);
        assert_eq!(
            c.to_credential().to_bit_string(),
            "10111101100010001110101110"
        );
    }

    #[test]
    fn hand_verified_block() {
        assert_eq!(H10301::new(FC, CN).raw44(), BLOCK);
        assert_eq!(H10301::from_raw44(BLOCK).unwrap(), H10301::new(FC, CN));
    }

    #[test]
    fn wiegand_bit_positions_are_where_the_spec_says() {
        let c = H10301::new(FC, CN);
        let bits = c.wiegand_bits();
        assert_eq!(bits.len(), 26);
        // facility code occupies bits 1..=8, MSB first
        let fc: u32 = bits[1..9].iter().fold(0, |a, &b| (a << 1) | u32::from(b));
        assert_eq!(fc, u32::from(FC));
        // card number occupies bits 9..=24
        let cn: u32 = bits[9..25].iter().fold(0, |a, &b| (a << 1) | u32::from(b));
        assert_eq!(cn, u32::from(CN));
    }

    #[test]
    fn parity_catches_a_single_flipped_card_number_bit() {
        let good = H10301::new(FC, CN).raw44();
        // Flip one card-number bit without touching the parity bits.
        let bad = good ^ (1 << 5);
        assert!(matches!(
            H10301::from_raw44(bad),
            Err(CredentialError::ParityFailed { .. })
        ));
    }

    #[test]
    fn parity_does_not_catch_a_recomputed_forgery() {
        // Module 1.2 in miniature: change the card number, recompute both parity
        // bits, and the result is a perfectly valid credential for a different badge.
        let forged = H10301::new(FC, CN.wrapping_add(1));
        let parsed = H10301::from_raw44(forged.raw44()).unwrap();
        assert_eq!(parsed.card_number, CN + 1);
        assert_eq!(parsed.facility_code, FC);
    }

    #[test]
    fn rejects_blocks_without_the_short_format_marker() {
        assert!(H10301::from_raw44(u64::from(WIEGAND) | (1 << 26)).is_err());
    }

    #[test]
    fn rejects_blocks_with_a_wrong_length_sentinel() {
        let raw = (1u64 << SHORT_FORMAT_MARKER_BIT) | (1 << 30) | u64::from(WIEGAND);
        assert!(H10301::from_raw44(raw).is_err());
    }

    #[test]
    fn rejects_oversized_blocks() {
        assert!(H10301::from_raw44(1u64 << 44).is_err());
    }

    #[test]
    fn air_frame_is_ninety_six_bits() {
        let bits = H10301::new(FC, CN).air_bits();
        assert_eq!(bits.len(), AIR_BITS);
        assert_eq!(bits[..8], PREAMBLE);
    }

    #[test]
    fn modulation_round_trip() {
        let cfg = CarrierConfig::default();
        let card = H10301::new(FC, CN);
        let stream = card.event_stream(2, &cfg);
        assert_eq!(demodulate_block(&stream).unwrap(), BLOCK);
        assert_eq!(
            H10301::from_raw44(demodulate_block(&stream).unwrap()).unwrap(),
            card
        );
    }

    #[test]
    fn modulation_round_trip_over_many_credentials() {
        let cfg = CarrierConfig::default();
        let mut rng = crate::Rng::new(0x0001_0301);
        for _ in 0..64 {
            let card = H10301::new(rng.next_u32() as u8, rng.next_u32() as u16);
            let stream = card.event_stream(1, &cfg);
            let raw = demodulate_block(&stream).unwrap();
            assert_eq!(H10301::from_raw44(raw).unwrap(), card);
        }
    }

    #[test]
    fn a_block_takes_about_four_and_a_half_milliseconds() {
        let cfg = CarrierConfig::default();
        let stream = H10301::new(FC, CN).event_stream(1, &cfg);
        // 96 bits at 48 or 50 carrier cycles each, 8 us per cycle.
        assert!(stream.end_us > 36_000 && stream.end_us < 39_000);
    }

    #[test]
    fn from_wiegand_bits_round_trips() {
        let card = H10301::new(FC, CN);
        let bits = card.wiegand_bits();
        assert_eq!(H10301::from_wiegand_bits(&bits).unwrap(), card);
        assert!(H10301::from_wiegand_bits(&bits[..25]).is_err());
    }
}
