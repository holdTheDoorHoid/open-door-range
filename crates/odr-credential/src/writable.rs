//! The writable tag — a T5577-class blank, and why cloning 125 kHz is not an attack.
//!
//! A T5577 is a 125 kHz tag with RAM instead of fused ROM and a small configuration
//! block that tells it which modulation to speak. Programme the configuration for
//! ASK/Manchester at RF/64 and write the right 64 bits and it *is* an EM4100 — not an
//! emulation of one, not a device pretending to be one. It energises in the same
//! field, answers with the same edges at the same microseconds, and the reader has no
//! channel through which it could learn otherwise.
//!
//! That is drill 0.2, and it is deliberately anticlimactic. There is nothing to
//! defeat. There is no authentication step that was bypassed, no check that was
//! fooled. The format simply has no concept of a card being the one it was issued as.
//!
//! # No detection hook
//!
//! This module exposes no `is_clone()`, no provenance flag, no "cloned" bit that a
//! [`Reader`](crate::Reader) could consult. Real hardware does not have one, and an
//! engine that quietly kept one would teach a lie: a learner would come away thinking
//! the problem is detectable at the reader, and it is not. The clone's
//! [`EventStream`] is equal, event for event, to the original's — there is a test in
//! this module that asserts exactly that, and if it ever fails, the *simulation* is
//! wrong.
//!
//! (Physical-layer fingerprinting of tag analogue characteristics is a real research
//! area. It is not something a deployed access-control reader does, and it is not
//! modelled here.)

use crate::em4100::{Em4100Frame, Em4100Tag};
use crate::error::{CredentialError, Result};
use crate::hid_prox::{self, H10301};
use crate::modulation::{CarrierConfig, EventStream, RF_64};

/// What a writable tag has been programmed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagProgram {
    /// ASK/Manchester, an EM4100 frame at the given RF divisor.
    Em4100 {
        /// The 64-bit frame, parity and all, exactly as it will be emitted.
        frame: Em4100Frame,
        /// Carrier cycles per bit. Must match what the original tag used or the
        /// reader's bit clock will not line up.
        rf_divisor: u32,
    },
    /// FSK, an HID 44-bit block.
    HidProx {
        /// The 44-bit block, emitted verbatim.
        raw44: u64,
    },
}

/// A blank, writable 125 kHz tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WritableTag {
    program: Option<TagProgram>,
}

impl WritableTag {
    /// A tag straight out of the bag: configured for nothing, answering nothing.
    pub const fn blank() -> Self {
        Self { program: None }
    }

    /// Whether anything has been written to it.
    pub const fn is_blank(&self) -> bool {
        self.program.is_none()
    }

    /// What it is currently programmed as.
    pub const fn program(&self) -> Option<TagProgram> {
        self.program
    }

    /// Write an EM4100 identity, re-deriving the frame (and its parity) from the ID.
    pub fn write_em4100(&mut self, tag: Em4100Tag) {
        self.write_em4100_frame(tag.encode(), RF_64);
    }

    /// Write a raw EM4100 frame, bit for bit.
    ///
    /// Takes the frame rather than the ID on purpose: a cloner copies the *bits*, so
    /// a tag whose parity was wrong at the factory clones with its parity still wrong.
    pub fn write_em4100_frame(&mut self, frame: Em4100Frame, rf_divisor: u32) {
        self.program = Some(TagProgram::Em4100 { frame, rf_divisor });
    }

    /// Write an HID H10301 credential.
    pub fn write_hid_prox(&mut self, card: H10301) {
        self.write_hid_block(card.raw44());
    }

    /// Write a raw 44-bit HID block, bit for bit.
    pub fn write_hid_block(&mut self, raw44: u64) {
        self.program = Some(TagProgram::HidProx { raw44 });
    }

    /// Wipe it.
    pub fn erase(&mut self) {
        self.program = None;
    }

    /// Programme this tag from something sniffed off the air.
    ///
    /// This is the whole of the 125 kHz cloning attack: demodulate whatever the
    /// victim's tag was shouting, write the same bits here. No key is needed because
    /// there is no key; no interaction with the victim is needed beyond being within
    /// a few centimetres of it once.
    pub fn clone_from_capture(&mut self, capture: &LfCapture) -> Result<()> {
        match *capture {
            LfCapture::Em4100 { frame, rf_divisor } => {
                self.write_em4100_frame(frame, rf_divisor);
            }
            LfCapture::HidProx { raw44 } => self.write_hid_block(raw44),
        }
        Ok(())
    }

    /// What the tag emits in a reader's field.
    ///
    /// A blank tag is [`CredentialError::BlankTag`] rather than an empty stream,
    /// because "nothing happened" and "a tag with nothing on it" are different
    /// diagnoses when you are standing at a door wondering why it will not open.
    pub fn event_stream(&self, repeats: usize, cfg: &CarrierConfig) -> Result<EventStream> {
        match self.program {
            None => Err(CredentialError::BlankTag),
            Some(TagProgram::Em4100 { frame, rf_divisor }) => {
                Ok(frame.event_stream(repeats, rf_divisor, cfg))
            }
            Some(TagProgram::HidProx { raw44 }) => {
                Ok(hid_prox::block_event_stream(raw44, repeats, cfg))
            }
        }
    }
}

/// What a sniffer pulled off the air.
///
/// The attacker's entire input for drill 0.2: a few tens of milliseconds of one tag
/// in one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfCapture {
    /// An ASK/Manchester frame and the bit rate it was sent at.
    Em4100 {
        /// The 64 bits, as received — parity not judged.
        frame: Em4100Frame,
        /// Carrier cycles per bit, recovered from the edge spacing.
        rf_divisor: u32,
    },
    /// An FSK HID block.
    HidProx {
        /// The 44 bits, as received.
        raw44: u64,
    },
}

/// Identify and capture whatever technology is speaking in a stream.
///
/// Tries ASK/Manchester at each of the three common EM4100 bit rates, then FSK. A
/// real cloner does the same sweep and prints "Chipset detected: EM4100"; there is no
/// negotiation and nothing is asked of the tag, because the tag cannot be asked
/// anything.
pub fn sniff(stream: &EventStream) -> Result<LfCapture> {
    for divisor in [RF_64, crate::modulation::RF_32, crate::modulation::RF_16] {
        if let Ok(frame) = crate::em4100::demodulate(stream, divisor) {
            return Ok(LfCapture::Em4100 {
                frame,
                rf_divisor: divisor,
            });
        }
    }
    if let Ok(raw44) = hid_prox::demodulate_block(stream) {
        return Ok(LfCapture::HidProx { raw44 });
    }
    Err(CredentialError::PreambleNotFound {
        decoder: "lf sniffer",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_tag_says_nothing() {
        let tag = WritableTag::blank();
        assert!(tag.is_blank());
        assert!(matches!(
            tag.event_stream(1, &CarrierConfig::default()),
            Err(CredentialError::BlankTag)
        ));
    }

    #[test]
    fn em4100_clone_is_indistinguishable_on_the_air() {
        let cfg = CarrierConfig::default();
        let original = Em4100Tag::new(0x06, 0x0012_59E3);
        let genuine = original.encode().event_stream(4, RF_64, &cfg);

        // The attacker sees only the stream.
        let capture = sniff(&genuine).unwrap();
        let mut blank = WritableTag::blank();
        blank.clone_from_capture(&capture).unwrap();

        let cloned = blank.event_stream(4, &cfg).unwrap();
        assert_eq!(
            cloned, genuine,
            "a clone must be equal event for event; there is nothing to detect"
        );
    }

    #[test]
    fn hid_clone_is_indistinguishable_on_the_air() {
        let cfg = CarrierConfig::default();
        let original = H10301::new(123, 4567);
        let genuine = original.event_stream(3, &cfg);

        let capture = sniff(&genuine).unwrap();
        assert_eq!(
            capture,
            LfCapture::HidProx {
                raw44: original.raw44()
            }
        );

        let mut blank = WritableTag::blank();
        blank.clone_from_capture(&capture).unwrap();
        assert_eq!(blank.event_stream(3, &cfg).unwrap(), genuine);
    }

    #[test]
    fn a_clone_copies_bits_not_meaning() {
        // Programme a frame whose parity is deliberately wrong, clone it, and watch
        // the badness survive the copy intact. A cloner does not understand formats.
        let cfg = CarrierConfig::default();
        let broken = Em4100Tag::new(0x11, 0xDEAD_BEEF)
            .encode()
            .with_bit_flipped(20);
        let genuine = broken.event_stream(4, RF_64, &cfg);

        let capture = sniff(&genuine).unwrap();
        let mut blank = WritableTag::blank();
        blank.clone_from_capture(&capture).unwrap();

        match blank.program().unwrap() {
            TagProgram::Em4100 { frame, .. } => {
                assert_eq!(frame, broken);
                assert!(!frame.decode().parity.is_valid());
            }
            other => panic!("expected an EM4100 program, got {other:?}"),
        }
    }

    #[test]
    fn erase_makes_it_blank_again() {
        let mut tag = WritableTag::blank();
        tag.write_em4100(Em4100Tag::new(1, 2));
        assert!(!tag.is_blank());
        tag.erase();
        assert!(tag.is_blank());
    }

    #[test]
    fn sniffing_noise_is_an_error() {
        let cfg = CarrierConfig::default();
        let stream = EventStream::empty(&cfg);
        assert!(sniff(&stream).is_err());
    }
}
