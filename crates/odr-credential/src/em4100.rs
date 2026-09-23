//! EM4100 / EM4102 — the 125 kHz tag that has no secrets to keep.
//!
//! An EM4100 is a coil, a capacitor, a small state machine and 64 bits of laser-fused
//! ROM. It cannot receive a command, cannot be challenged, cannot be switched off and
//! cannot tell one reader from another. Put it in a field and it shouts its number,
//! over and over, to anything listening, forever.
//!
//! There is nothing to attack here in the cryptographic sense, and that is the lesson
//! of Module 0.1: the credential most buildings still run on is a number broadcast in
//! the clear. Everything in this module is framing and error detection, not security.
//!
//! # The 64-bit frame
//!
//! Transmitted first bit first:
//!
//! ```text
//! bit  0 ..  8   nine 1 bits — the header. Nothing else in a valid frame can
//!                produce a run of nine ones, so this is the frame sync.
//! bit  9 .. 58   ten rows of (4 data bits + 1 even row-parity bit)
//!                row 0 = high nibble of the version/customer byte
//!                row 1 = low nibble of that byte
//!                rows 2..9 = the 32-bit ID, most significant nibble first
//! bit 59 .. 62   four column-parity bits, even, one per data-bit column
//! bit 63         stop bit, always 0
//! ```
//!
//! So the payload is 40 bits — an 8-bit version/customer code and a 32-bit ID — and
//! the other 24 bits are sync and parity. The row and column parity together form a
//! rectangular code: it will catch any single bit error and tell you exactly where it
//! was. It will not catch a deliberate edit, because there is no key involved in
//! computing it. Parity is not integrity; Module 1.2 makes the same point on the
//! Wiegand wire.
//!
//! # On the air
//!
//! Manchester coded, ASK/OOK, usually one bit per 64 carrier cycles (RF/64), so a
//! 64-bit frame takes 32.768 ms at 125 kHz. The tag repeats the frame back to back
//! with no gap; the reader finds the header and syncs.

use crate::credential::{Credential, CredentialFormat};
use crate::error::{CredentialError, Result};
use crate::modulation::{
    ask_demodulate, ask_event_stream, manchester_decode, manchester_encode, CarrierConfig,
    EventStream, RF_64,
};

/// Bits in one EM4100 frame.
pub const FRAME_BITS: usize = 64;

/// Length of the all-ones header.
pub const HEADER_BITS: usize = 9;

/// Number of 4-bit data rows.
pub const DATA_ROWS: usize = 10;

/// A tag's permanent identity: an 8-bit version/customer code and a 32-bit ID.
///
/// Together these are the 40 bits people mean when they read "the number off a tag".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Em4100Tag {
    /// Version / customer code. Conventionally identifies who ordered the batch.
    pub version: u8,
    /// The 32-bit identity.
    pub id: u32,
}

impl Em4100Tag {
    /// A tag with the given version code and ID.
    pub const fn new(version: u8, id: u32) -> Self {
        Self { version, id }
    }

    /// Build from the 40-bit number printed on the tag or shown by a cloner.
    ///
    /// Fails if the value does not fit in 40 bits.
    pub fn from_id40(value: u64) -> Result<Self> {
        if value >= 1 << 40 {
            return Err(CredentialError::ValueTooWide {
                field: "em4100 id",
                bits: 40,
            });
        }
        Ok(Self {
            version: (value >> 32) as u8,
            id: value as u32,
        })
    }

    /// The 40-bit number: version code in the top 8 bits, ID in the low 32.
    pub const fn id40(&self) -> u64 {
        ((self.version as u64) << 32) | self.id as u64
    }

    /// The ten 4-bit rows, in transmission order.
    pub const fn nibbles(&self) -> [u8; DATA_ROWS] {
        let v = self.id40();
        let mut out = [0u8; DATA_ROWS];
        let mut i = 0;
        while i < DATA_ROWS {
            out[i] = ((v >> (36 - 4 * i)) & 0xF) as u8;
            i += 1;
        }
        out
    }

    /// Encode to the 64-bit on-air frame, computing all parity.
    pub fn encode(&self) -> Em4100Frame {
        let nibbles = self.nibbles();
        let mut bits = [false; FRAME_BITS];

        for b in bits.iter_mut().take(HEADER_BITS) {
            *b = true;
        }

        let mut columns = [false; 4];
        for (row, &nibble) in nibbles.iter().enumerate() {
            let mut row_parity = false;
            for col in 0..4 {
                let bit = (nibble >> (3 - col)) & 1 == 1;
                bits[HEADER_BITS + row * 5 + col] = bit;
                row_parity ^= bit;
                columns[col] ^= bit;
            }
            bits[HEADER_BITS + row * 5 + 4] = row_parity;
        }

        for (col, &parity) in columns.iter().enumerate() {
            bits[HEADER_BITS + DATA_ROWS * 5 + col] = parity;
        }
        // bits[63] is the stop bit and stays false.

        Em4100Frame::from_bits(&bits)
    }

    /// As a [`Credential`]: 40 bits, format [`CredentialFormat::Em4100`].
    pub fn to_credential(&self) -> Credential {
        Credential::from_u64(CredentialFormat::Em4100, 40, self.id40())
            .expect("40 bits always fits a 40-bit credential")
    }
}

/// The 64 bits as they go out over the air, first-transmitted bit in bit 63.
///
/// Stored as a `u64` because it is exactly 64 bits and because that makes
/// "corrupt one bit and watch the read fail" a one-line experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Em4100Frame(pub u64);

impl Em4100Frame {
    /// Build from a bit array in transmission order.
    pub fn from_bits(bits: &[bool; FRAME_BITS]) -> Self {
        let mut v = 0u64;
        for &b in bits.iter() {
            v = (v << 1) | u64::from(b);
        }
        Self(v)
    }

    /// The bits in transmission order.
    pub fn bits(&self) -> [bool; FRAME_BITS] {
        let mut out = [false; FRAME_BITS];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = (self.0 >> (63 - i)) & 1 == 1;
        }
        out
    }

    /// Bit `index` in transmission order.
    pub const fn bit(&self, index: usize) -> bool {
        if index >= FRAME_BITS {
            return false;
        }
        (self.0 >> (63 - index)) & 1 == 1
    }

    /// Flip one bit. The tool for "now break the parity and watch what happens".
    pub const fn with_bit_flipped(&self, index: usize) -> Self {
        if index >= FRAME_BITS {
            return Self(self.0);
        }
        Self(self.0 ^ (1u64 << (63 - index)))
    }

    /// Decode the frame.
    ///
    /// Always returns the payload it read, *and* a separate parity report. A reader
    /// that throws away a failed read and a reader that reports "I read this, but the
    /// parity is wrong on row 4" are different tools, and the second one is the one
    /// you want when you are learning what a marginal read looks like.
    pub fn decode(&self) -> Em4100Read {
        let bits = self.bits();

        let header_ok = bits.iter().take(HEADER_BITS).all(|&b| b);

        let mut value = 0u64;
        let mut rows = [false; DATA_ROWS];
        let mut computed_columns = [false; 4];
        for (row, row_ok) in rows.iter_mut().enumerate() {
            let mut nibble = 0u64;
            let mut parity = false;
            for col in 0..4 {
                let bit = bits[HEADER_BITS + row * 5 + col];
                nibble = (nibble << 1) | u64::from(bit);
                parity ^= bit;
                computed_columns[col] ^= bit;
            }
            value = (value << 4) | nibble;
            *row_ok = parity == bits[HEADER_BITS + row * 5 + 4];
        }

        let mut columns = [false; 4];
        for (col, ok) in columns.iter_mut().enumerate() {
            *ok = computed_columns[col] == bits[HEADER_BITS + DATA_ROWS * 5 + col];
        }

        let stop_ok = !bits[63];

        Em4100Read {
            tag: Em4100Tag {
                version: (value >> 32) as u8,
                id: value as u32,
            },
            parity: Em4100Parity {
                header_ok,
                rows,
                columns,
                stop_ok,
            },
        }
    }

    /// Manchester half-bits for `repeats` back-to-back copies of the frame.
    ///
    /// A real tag never stops; `repeats` is how long you left it in the field.
    pub fn half_bits(&self, repeats: usize) -> Vec<bool> {
        let bits = self.bits();
        let mut all = Vec::with_capacity(FRAME_BITS * repeats);
        for _ in 0..repeats.max(1) {
            all.extend_from_slice(&bits);
        }
        manchester_encode(&all)
    }

    /// The modulation the reader actually sees.
    ///
    /// `rf_divisor` is carrier cycles per data bit — [`RF_64`]
    /// for the common part.
    pub fn event_stream(
        &self,
        repeats: usize,
        rf_divisor: u32,
        cfg: &CarrierConfig,
    ) -> EventStream {
        ask_event_stream(&self.half_bits(repeats), rf_divisor.max(2) / 2, cfg)
    }
}

/// The result of reading a frame: payload plus a separate verdict on the parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Em4100Read {
    /// What the data bits said, whether or not the parity agrees.
    pub tag: Em4100Tag,
    /// Whether each part of the error-detecting code held.
    pub parity: Em4100Parity,
}

/// Which parts of an EM4100 frame's error-detecting code held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Em4100Parity {
    /// All nine header bits were 1.
    pub header_ok: bool,
    /// Per-row even parity, rows 0..9 in transmission order.
    pub rows: [bool; DATA_ROWS],
    /// Per-column even parity, columns 0..3.
    pub columns: [bool; 4],
    /// The stop bit was 0.
    pub stop_ok: bool,
}

impl Em4100Parity {
    /// Whether the whole frame checks out.
    pub fn is_valid(&self) -> bool {
        self.header_ok
            && self.stop_ok
            && self.rows.iter().all(|&b| b)
            && self.columns.iter().all(|&b| b)
    }

    /// The single bit position the rectangular code points at, if exactly one row and
    /// one column failed.
    ///
    /// This is the payoff of a two-dimensional parity: one bad bit is not merely
    /// detected, it is located. Returned as `(row, column)` into the data grid.
    pub fn single_error_location(&self) -> Option<(usize, usize)> {
        let bad_rows: Vec<usize> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, &ok)| !ok)
            .map(|(i, _)| i)
            .collect();
        let bad_cols: Vec<usize> = self
            .columns
            .iter()
            .enumerate()
            .filter(|(_, &ok)| !ok)
            .map(|(i, _)| i)
            .collect();
        match (bad_rows.as_slice(), bad_cols.as_slice()) {
            ([r], [c]) => Some((*r, *c)),
            _ => None,
        }
    }
}

/// Recover a frame from the modulation.
///
/// Does what a reader does: sample the half-bits, try both Manchester phase
/// alignments, hunt for the nine-bit header, take the 64 bits that follow. Parity is
/// *not* checked here — the frame comes back and [`Em4100Frame::decode`] says whether
/// it holds, so a bad read is reportable as a bad read.
pub fn demodulate(stream: &EventStream, rf_divisor: u32) -> Result<Em4100Frame> {
    let cfg = CarrierConfig::new(stream.carrier_hz);
    let half_cycles = rf_divisor.max(2) / 2;
    let half_us = cfg.cycles_to_us(u64::from(half_cycles)).max(1);
    let total_halves = (stream.end_us / half_us) as usize;
    if total_halves < FRAME_BITS * 2 {
        return Err(CredentialError::StreamTooShort {
            needed: FRAME_BITS * 2,
            got: total_halves,
        });
    }
    let halves = ask_demodulate(stream, half_cycles, total_halves);

    for phase in [0usize, 1] {
        let usable = &halves[phase..];
        let trimmed = &usable[..usable.len() - usable.len() % 2];
        let Ok(bits) = manchester_decode(trimmed) else {
            continue;
        };
        if let Some(frame) = find_framed(&bits) {
            return Ok(frame);
        }
    }
    Err(CredentialError::PreambleNotFound { decoder: "em4100" })
}

/// Find the nine-ones header in a decoded bit sequence and take the frame after it.
fn find_framed(bits: &[bool]) -> Option<Em4100Frame> {
    if bits.len() < FRAME_BITS {
        return None;
    }
    for start in 0..=bits.len() - FRAME_BITS {
        if bits[start..start + HEADER_BITS].iter().all(|&b| b) {
            // A header must be preceded by the stop bit of the previous frame, or be
            // the very first thing seen. Without this a run of ones inside the data
            // could be mistaken for sync on a mid-frame entry.
            if start > 0 && bits[start - 1] {
                continue;
            }
            let mut arr = [false; FRAME_BITS];
            arr.copy_from_slice(&bits[start..start + FRAME_BITS]);
            return Some(Em4100Frame::from_bits(&arr));
        }
    }
    None
}

/// The usual RF divisor, re-exported so callers do not have to reach into
/// [`crate::modulation`] for the common case.
pub const DEFAULT_RF_DIVISOR: u32 = RF_64;

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from the Priority 1 Design EM4100 protocol note:
    /// version `$06`, data `$001259E3`.
    const EXAMPLE: Em4100Tag = Em4100Tag::new(0x06, 0x0012_59E3);

    #[test]
    fn nibbles_are_transmission_order() {
        assert_eq!(EXAMPLE.nibbles(), [0, 6, 0, 0, 1, 2, 5, 9, 0xE, 3]);
    }

    #[test]
    fn frame_has_the_documented_shape() {
        let frame = EXAMPLE.encode();
        let bits = frame.bits();
        assert!(bits[..HEADER_BITS].iter().all(|&b| b), "nine header ones");
        assert!(!bits[63], "stop bit is zero");
        assert_eq!(bits.len(), 64);
    }

    #[test]
    fn encode_decode_round_trip_with_valid_parity() {
        let frame = EXAMPLE.encode();
        let read = frame.decode();
        assert_eq!(read.tag, EXAMPLE);
        assert!(read.parity.is_valid());
        assert!(read.parity.header_ok);
        assert!(read.parity.stop_ok);
        assert!(read.parity.rows.iter().all(|&b| b));
        assert!(read.parity.columns.iter().all(|&b| b));
    }

    #[test]
    fn round_trip_over_many_ids() {
        let mut rng = crate::Rng::new(0x4100);
        for _ in 0..500 {
            let tag = Em4100Tag::from_id40(rng.next_u64() & 0xFF_FFFF_FFFF).unwrap();
            let read = tag.encode().decode();
            assert_eq!(read.tag, tag);
            assert!(read.parity.is_valid());
        }
    }

    #[test]
    fn a_flipped_data_bit_breaks_one_row_and_one_column() {
        let frame = EXAMPLE.encode();
        // Flip data bit (row 4, column 2): id nibble index 4 is 0x1.
        let index = HEADER_BITS + 4 * 5 + 2;
        let corrupted = frame.with_bit_flipped(index);
        let read = corrupted.decode();

        assert!(!read.parity.is_valid(), "corruption must be reportable");
        assert!(!read.parity.rows[4]);
        assert!(!read.parity.columns[2]);
        assert_eq!(read.parity.single_error_location(), Some((4, 2)));
        // The payload still comes back — a bad read is readable, just untrusted.
        assert_ne!(read.tag, EXAMPLE);
    }

    #[test]
    fn a_flipped_parity_bit_breaks_only_its_row() {
        let frame = EXAMPLE.encode();
        let corrupted = frame.with_bit_flipped(HEADER_BITS + 7 * 5 + 4);
        let read = corrupted.decode();
        assert!(!read.parity.is_valid());
        assert!(!read.parity.rows[7]);
        assert!(read.parity.columns.iter().all(|&b| b));
        // Payload is untouched: only the check bit moved.
        assert_eq!(read.tag, EXAMPLE);
    }

    #[test]
    fn a_broken_header_is_reported() {
        let frame = EXAMPLE.encode().with_bit_flipped(3);
        let read = frame.decode();
        assert!(!read.parity.header_ok);
        assert!(!read.parity.is_valid());
    }

    #[test]
    fn a_set_stop_bit_is_reported() {
        let frame = EXAMPLE.encode().with_bit_flipped(63);
        let read = frame.decode();
        assert!(!read.parity.stop_ok);
        assert!(!read.parity.is_valid());
    }

    #[test]
    fn modulation_round_trip() {
        let cfg = CarrierConfig::default();
        let frame = EXAMPLE.encode();
        let stream = frame.event_stream(3, RF_64, &cfg);
        let recovered = demodulate(&stream, RF_64).unwrap();
        assert_eq!(recovered, frame);
        assert_eq!(recovered.decode().tag, EXAMPLE);
    }

    #[test]
    fn modulation_round_trip_at_rf_32() {
        let cfg = CarrierConfig::default();
        let frame = EXAMPLE.encode();
        let stream = frame.event_stream(3, crate::modulation::RF_32, &cfg);
        let recovered = demodulate(&stream, crate::modulation::RF_32).unwrap();
        assert_eq!(recovered, frame);
    }

    #[test]
    fn one_frame_of_field_time_is_thirty_three_milliseconds() {
        let cfg = CarrierConfig::default();
        let stream = EXAMPLE.encode().event_stream(1, RF_64, &cfg);
        // 64 bits x 64 carrier cycles x 8 us
        assert_eq!(stream.end_us, 32_768);
    }

    #[test]
    fn a_truncated_stream_is_an_error_not_a_panic() {
        let cfg = CarrierConfig::default();
        let mut stream = EXAMPLE.encode().event_stream(1, RF_64, &cfg);
        stream.end_us = 1_000;
        assert!(demodulate(&stream, RF_64).is_err());
    }

    #[test]
    fn id40_round_trip() {
        assert_eq!(Em4100Tag::from_id40(0x06_0012_59E3).unwrap(), EXAMPLE);
        assert_eq!(EXAMPLE.id40(), 0x06_0012_59E3);
        assert!(Em4100Tag::from_id40(1 << 40).is_err());
    }

    #[test]
    fn credential_is_forty_bits() {
        let c = EXAMPLE.to_credential();
        assert_eq!(c.bit_len, 40);
        assert_eq!(c.as_u64(), 0x06_0012_59E3);
        assert_eq!(c.format, CredentialFormat::Em4100);
    }
}
