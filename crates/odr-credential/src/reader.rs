//! The reader: energise a field, run a protocol, emit a credential.
//!
//! A reader is the least interesting device in an access-control system and the one
//! most often blamed. It holds no access list, makes no decision, and in the legacy
//! case does not even parse what it read — it clocks bits at a panel and the panel
//! decides. Modelling it properly matters because the whole of Module 1 depends on
//! seeing that the reader is a pipe.
//!
//! # What it does
//!
//! * **125 kHz** — energise, watch the field, demodulate. The reader is handed a
//!   [`EventStream`](crate::modulation::EventStream) and works from that alone. It
//!   cannot tell an issued tag from a clone because there is nothing in the signal
//!   that differs.
//! * **13.56 MHz** — run the card's authentication with whatever keys it was
//!   configured with, then read the block or file the credential lives in. A reader
//!   with the wrong key gets nothing, which is the entire difference between the two
//!   halves of Module 0.
//!
//! Either way the output is a [`Credential`]: format, bit count, bits. `odr-bus` turns
//! that into a Wiegand pulse train or an OSDP payload; this crate does not know which
//! and must not.

use crate::card::{Card, Technology};
use crate::credential::{Credential, CredentialFormat};
use crate::desfire::{DesfireReader, BLOCK as AES_BLOCK};
use crate::error::{CredentialError, Result};
use crate::hid_prox::{self, H10301};
use crate::mifare::{KeyType, MifareReader};
use crate::modulation::CarrierConfig;
use crate::writable::{sniff, LfCapture};

/// Which radios a reader has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderKind {
    /// 125 kHz only — the prox reader on most doors.
    Lf125kHz,
    /// 13.56 MHz only.
    Hf13_56MHz,
    /// Both, which is what most multi-technology readers are: two radios in one
    /// housing, and a credential accepted by either.
    Dual,
}

impl ReaderKind {
    /// Whether this reader can talk to a card on the given radio.
    pub const fn covers(self, technology: Technology) -> bool {
        matches!(
            (self, technology),
            (Self::Dual, _)
                | (Self::Lf125kHz, Technology::Lf125kHz)
                | (Self::Hf13_56MHz, Technology::Hf13_56MHz)
        )
    }
}

/// How a reader is configured for 13.56 MHz cards.
///
/// A reader is given keys at commissioning. It is worth noticing that these keys sit
/// in a device screwed to the *unsecured* side of the door, which is a recurring theme
/// from here to the end of Module 3.
#[derive(Debug, Clone)]
pub struct HfConfig {
    /// MIFARE Classic key and key type for the block the credential lives in.
    pub mifare_key: Option<(KeyType, u64)>,
    /// The block a MIFARE credential is read from.
    pub mifare_block: u8,
    /// DESFire application key.
    pub desfire_key: Option<[u8; AES_BLOCK]>,
    /// DESFire key number.
    pub desfire_key_no: u8,
    /// DESFire file number the credential is read from.
    pub desfire_file: u8,
}

impl Default for HfConfig {
    fn default() -> Self {
        Self {
            mifare_key: Some((KeyType::A, crate::mifare::DEFAULT_KEY)),
            mifare_block: 4,
            desfire_key: None,
            desfire_key_no: 0,
            desfire_file: 1,
        }
    }
}

/// A reader.
#[derive(Debug, Clone)]
pub struct Reader {
    /// Which radios it has.
    pub kind: ReaderKind,
    /// Carrier parameters for the 125 kHz side.
    pub carrier: CarrierConfig,
    /// How many frame repetitions to collect before decoding. A real reader watches
    /// for a few frames and takes a consistent one; more repeats means a better
    /// chance of syncing on a tag that entered the field mid-frame.
    pub field_repeats: usize,
    /// Keys for the 13.56 MHz side.
    pub hf: HfConfig,
    /// Seed for the reader's own nonces. Determinism again: the same reader with the
    /// same seed produces the same `nR`, so a captured trace replays identically.
    pub seed: u64,
}

impl Reader {
    /// A 125 kHz prox reader.
    pub fn lf_125khz() -> Self {
        Self {
            kind: ReaderKind::Lf125kHz,
            carrier: CarrierConfig::default(),
            field_repeats: 3,
            hf: HfConfig::default(),
            seed: 0,
        }
    }

    /// A 13.56 MHz reader.
    pub fn hf_13_56mhz() -> Self {
        Self {
            kind: ReaderKind::Hf13_56MHz,
            ..Self::lf_125khz()
        }
    }

    /// A multi-technology reader, which is what is usually on the wall.
    pub fn dual() -> Self {
        Self {
            kind: ReaderKind::Dual,
            ..Self::lf_125khz()
        }
    }

    /// Present a card and read it.
    ///
    /// For a 125 kHz card this demodulates the field response and decodes it. For a
    /// 13.56 MHz card it runs the authentication with the configured keys. Either
    /// way, failure is a structured error — a reader that cannot read a card is an
    /// ordinary event at a door, not a bug.
    pub fn present(&mut self, card: &mut Card) -> Result<Credential> {
        if !self.kind.covers(card.technology()) {
            return Err(CredentialError::WrongTechnology {
                reader: match self.kind {
                    ReaderKind::Lf125kHz => Technology::Lf125kHz.name(),
                    ReaderKind::Hf13_56MHz => Technology::Hf13_56MHz.name(),
                    ReaderKind::Dual => "125 kHz + 13.56 MHz",
                },
                card: card.technology().name(),
            });
        }

        match card.technology() {
            Technology::Lf125kHz => {
                let stream = card.field_response(self.field_repeats, &self.carrier)?;
                self.decode_lf(&stream)
            }
            Technology::Hf13_56MHz => self.read_hf(card),
        }
    }

    /// Demodulate and decode a 125 kHz field response.
    ///
    /// Exposed separately because it is the whole of the "sniff and clone" workflow: a
    /// capture from anywhere — a tag in the field, a recorded stream, later a real
    /// capture imported through `odr-cli` — goes in here.
    pub fn decode_lf(&self, stream: &crate::modulation::EventStream) -> Result<Credential> {
        match sniff(stream)? {
            LfCapture::Em4100 { frame, .. } => {
                let read = frame.decode();
                if !read.parity.is_valid() {
                    return Err(CredentialError::ParityFailed { decoder: "em4100" });
                }
                Ok(read.tag.to_credential())
            }
            LfCapture::HidProx { raw44 } => Ok(H10301::from_raw44(raw44)?.to_credential()),
        }
    }

    fn read_hf(&mut self, card: &mut Card) -> Result<Credential> {
        if let Some(mifare) = card.as_mifare_mut() {
            let (key_type, key) = self.hf.mifare_key.ok_or(CredentialError::AccessDenied {
                operation: "MIFARE read without a configured key",
            })?;
            let mut reader = MifareReader::new(self.seed);
            let block = self.hf.mifare_block;
            let (mut session, _) = reader.authenticate(mifare, block, key_type, key, None)?;
            return session.read_credential(mifare, block);
        }
        if let Some(desfire) = card.as_desfire_mut() {
            let key = self.hf.desfire_key.ok_or(CredentialError::AccessDenied {
                operation: "DESFire read without a configured key",
            })?;
            let mut reader = DesfireReader::new(self.seed, key);
            let (mut session, _) = reader.authenticate(desfire, self.hf.desfire_key_no)?;
            return reader.read_credential(desfire, &mut session, self.hf.desfire_file);
        }
        Err(CredentialError::WrongTechnology {
            reader: "13.56 MHz",
            card: card.technology().name(),
        })
    }
}

impl Default for Reader {
    fn default() -> Self {
        Self::dual()
    }
}

/// The exact Wiegand bit pattern a reader will emit for an H10301 credential.
///
/// Drill 0.3's predicate lives here: the learner reads a facility code and a card
/// number off the RF layer, calls this, and has the 26 bits the wire will carry before
/// the wire has carried anything. `odr-wiegand` builds the same 26 bits from its own
/// encoder; if the two ever disagree, the drill fails rather than teaching a lie.
pub fn h10301_wiegand_bits(card: &H10301) -> [bool; hid_prox::WIEGAND_BITS] {
    card.wiegand_bits()
}

/// Decode a 125 kHz capture without a reader.
///
/// What the attacker's own tool does. Returns the credential *and* the technology, so
/// a drill can say "you captured an EM4100" rather than just handing over 40 bits.
pub fn decode_capture(
    stream: &crate::modulation::EventStream,
) -> Result<(CredentialFormat, Credential)> {
    match sniff(stream)? {
        LfCapture::Em4100 { frame, .. } => {
            let read = frame.decode();
            Ok((CredentialFormat::Em4100, read.tag.to_credential()))
        }
        LfCapture::HidProx { raw44 } => {
            let card = H10301::from_raw44(raw44)?;
            Ok((CredentialFormat::Wiegand26H10301, card.to_credential()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desfire::DesfireEv2;
    use crate::em4100::Em4100Tag;
    use crate::mifare::{AccessBits, MifareClassic1k, DEFAULT_KEY};
    use crate::writable::WritableTag;

    #[test]
    fn reads_an_em4100() {
        let mut card = Card::em4100(Em4100Tag::new(0x06, 0x0012_59E3));
        let mut reader = Reader::lf_125khz();
        let credential = reader.present(&mut card).unwrap();
        assert_eq!(credential.format, CredentialFormat::Em4100);
        assert_eq!(credential.as_u64(), 0x06_0012_59E3);
    }

    #[test]
    fn reads_an_hid_prox_and_emits_the_wiegand_pattern() {
        let mut card = Card::hid_prox(H10301::new(123, 4567));
        let mut reader = Reader::lf_125khz();
        let credential = reader.present(&mut card).unwrap();
        assert_eq!(credential.format, CredentialFormat::Wiegand26H10301);
        assert_eq!(credential.bit_len, 26);
        assert_eq!(credential.as_u64(), 0x02F6_23AE);
        assert_eq!(
            credential.bits(),
            h10301_wiegand_bits(&H10301::new(123, 4567)).to_vec()
        );
    }

    /// Drill 0.2's flag, in one test: a clone the reader accepts, where the original
    /// was never presented.
    #[test]
    fn a_clone_reads_identically_to_the_original() {
        let mut reader = Reader::lf_125khz();
        let original = Em4100Tag::new(0x2A, 0x0BAD_C0DE);

        // The attacker sniffs the victim's tag once.
        let stream = Card::em4100(original)
            .field_response(4, &reader.carrier)
            .unwrap();
        let capture = sniff(&stream).unwrap();

        let mut blank = WritableTag::blank();
        blank.clone_from_capture(&capture).unwrap();
        let mut clone = Card::writable(blank);

        let from_clone = reader.present(&mut clone).unwrap();
        let mut genuine = Card::em4100(original);
        let from_original = reader.present(&mut genuine).unwrap();
        assert_eq!(from_clone, from_original);
    }

    #[test]
    fn an_lf_reader_refuses_an_hf_card() {
        let mut card = Card::mifare(MifareClassic1k::new(1, 1));
        let mut reader = Reader::lf_125khz();
        assert!(matches!(
            reader.present(&mut card),
            Err(CredentialError::WrongTechnology { .. })
        ));
    }

    #[test]
    fn reads_a_mifare_classic_block() {
        let mut inner = MifareClassic1k::new(0x1122_3344, 7);
        inner.force_sector_keys(1, 0xA0A1_A2A3_A4A5, DEFAULT_KEY, AccessBits::transport());
        inner.force_block(4, [0x5A; 16]);
        let mut card = Card::mifare(inner);

        let mut reader = Reader::hf_13_56mhz();
        reader.hf.mifare_key = Some((KeyType::A, 0xA0A1_A2A3_A4A5));
        let credential = reader.present(&mut card).unwrap();
        assert_eq!(credential.format, CredentialFormat::MifareClassicBlock);
        assert_eq!(credential.data, vec![0x5A; 16]);
    }

    #[test]
    fn a_mifare_reader_with_the_wrong_key_gets_nothing() {
        let mut inner = MifareClassic1k::new(0x1122_3344, 7);
        inner.force_sector_keys(1, 0xA0A1_A2A3_A4A5, DEFAULT_KEY, AccessBits::transport());
        let mut card = Card::mifare(inner);
        let mut reader = Reader::hf_13_56mhz();
        reader.hf.mifare_key = Some((KeyType::A, 0x0000_0000_0001));
        assert!(reader.present(&mut card).is_err());
    }

    #[test]
    fn reads_a_desfire_file() {
        let key = [0x42u8; AES_BLOCK];
        let mut inner = DesfireEv2::new(99, 0, key);
        inner.set_file(1, b"desfire-badge".to_vec());
        let mut card = Card::desfire(inner);

        let mut reader = Reader::hf_13_56mhz();
        reader.hf.desfire_key = Some(key);
        let credential = reader.present(&mut card).unwrap();
        assert_eq!(credential.format, CredentialFormat::DesfireFile);
        assert_eq!(&credential.data[..13], b"desfire-badge");
    }

    #[test]
    fn a_desfire_reader_without_a_key_refuses_rather_than_panicking() {
        let mut card = Card::desfire(DesfireEv2::new(1, 0, [0u8; AES_BLOCK]));
        let mut reader = Reader::hf_13_56mhz();
        reader.hf.desfire_key = None;
        assert!(matches!(
            reader.present(&mut card),
            Err(CredentialError::AccessDenied { .. })
        ));
    }

    #[test]
    fn a_dual_reader_takes_either() {
        let mut reader = Reader::dual();
        assert!(reader
            .present(&mut Card::em4100(Em4100Tag::new(1, 2)))
            .is_ok());
        let mut inner = MifareClassic1k::new(5, 5);
        inner.force_block(4, [1; 16]);
        assert!(reader.present(&mut Card::mifare(inner)).is_ok());
    }

    #[test]
    fn a_bad_read_is_reported_not_silently_accepted() {
        // Corrupt the tag's frame so its parity fails, then present it.
        let broken = Em4100Tag::new(0x06, 0x0012_59E3)
            .encode()
            .with_bit_flipped(30);
        let mut tag = WritableTag::blank();
        tag.write_em4100_frame(broken, crate::modulation::RF_64);
        let mut card = Card::writable(tag);

        let mut reader = Reader::lf_125khz();
        assert!(matches!(
            reader.present(&mut card),
            Err(CredentialError::ParityFailed { .. })
        ));
    }
}
