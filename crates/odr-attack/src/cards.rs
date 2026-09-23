//! **Module 0 — the attacker before the wire.**
//!
//! Two actors, both thin wrappers around attacks `odr-credential` already
//! implements. They exist so that Module 0's drills run through the same
//! actor-and-knowledge API as everything else: a learner who has watched a
//! [`crate::Sniffer`] accumulate credentials should meet a [`TagCloner`] that
//! accumulates them the same way, and a flag predicate should be the same shape
//! whether the attack was against a card or against a bus.
//!
//! The card-layer machinery is not reimplemented here and must not be. If an
//! attack in this module ever disagrees with `odr-credential`, the drill is
//! wrong rather than the card.

use alloc::string::String;
use alloc::vec::Vec;

use odr_bus::{Micros, Presentation, SourceId, TapId, TapKind};
use odr_credential::mifare::{KeyType, MifareClassic1k, MifareReader};
use odr_credential::modulation::{CarrierConfig, EventStream};
use odr_credential::nested::{NestedAttack, NestedCapture, NonceDistance};
use odr_credential::writable::{sniff, LfCapture, WritableTag};
use odr_credential::{Card, Reader};
use odr_wiegand::BitVec;

use crate::error::{AttackError, Result};
use crate::knowledge::{
    format_id_for, CaptureMedium, CapturedCredential, KnowledgeCell, Known, Provenance,
    RecoveredKey, TagCapture,
};
use crate::Attacker;

// ---------------------------------------------------------------------------
// TagCloner
// ---------------------------------------------------------------------------

/// **Curriculum 0.2: copy a 125 kHz tag onto a blank.**
///
/// There is nothing to defeat. An EM4100 or HID Prox tag has no processor, no
/// key and no challenge; it shouts its number at anything that energises it,
/// forever, to anyone. The whole attack is: stand near the victim's pocket once
/// with a coil, demodulate what comes back, write the same bits to a T5577.
///
/// The clone is **indistinguishable at the reader**, and that is not a
/// modelling convenience: `odr-credential` asserts that the clone's event
/// stream equals the original's, event for event. There is no provenance flag
/// on a writable tag and no "is this genuine" field on a card, because real
/// readers have neither.
///
/// What the range *can* distinguish is the physical token, through
/// [`odr_bus::SourceId`], which is what makes drill 0.2's flag — "a cloned tag
/// presents and the controller grants, where the original tag was never
/// presented" — a question the engine can answer.
pub struct TagCloner {
    name: String,
    knowledge: KnowledgeCell,
    tag: WritableTag,
    capture: Option<LfCapture>,
    reader: Reader,
}

impl core::fmt::Debug for TagCloner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TagCloner")
            .field("name", &self.name)
            .field("captured", &self.capture.is_some())
            .field("blank", &self.tag.is_blank())
            .finish()
    }
}

impl TagCloner {
    /// A cloner holding one blank tag.
    pub fn new(name: impl Into<String>) -> TagCloner {
        TagCloner::sharing(name, KnowledgeCell::new())
    }

    /// A cloner pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> TagCloner {
        TagCloner {
            name: name.into(),
            knowledge,
            tag: WritableTag::blank(),
            capture: None,
            reader: Reader::lf_125khz(),
        }
    }

    /// Sniff whatever is talking in a field.
    ///
    /// The only input is the modulation the tag produced. Nothing is asked of
    /// the tag, because a tag cannot be asked anything.
    pub fn sniff_field(&mut self, stream: &EventStream, t_us: Micros) -> Result<LfCapture> {
        let capture = sniff(stream)?;
        self.capture = Some(capture);
        self.knowledge.update(|k| {
            k.tag_captures
                .push(Known::observed(TagCapture { capture, t_us }, t_us, None))
        });
        Ok(capture)
    }

    /// Brush past a card in somebody's pocket.
    ///
    /// A convenience over [`TagCloner::sniff_field`] for a drill that wants to
    /// say "one brush past the victim" rather than assemble an event stream.
    pub fn brush_past(&mut self, card: &Card, t_us: Micros) -> Result<LfCapture> {
        let stream = card.field_response(4, &CarrierConfig::default())?;
        self.sniff_field(&stream, t_us)
    }

    /// Write what was sniffed onto the blank.
    pub fn write_blank(&mut self) -> Result<()> {
        let capture = self.capture.ok_or_else(|| AttackError::Unearned {
            wanted: "something to clone",
            detail: alloc::string::ToString::to_string("nothing has been sniffed yet"),
        })?;
        self.tag.clone_from_capture(&capture)?;
        Ok(())
    }

    /// The cloned tag, as a card that can be held up to a reader.
    pub fn clone_card(&self) -> Card {
        Card::writable(self.tag.clone())
    }

    /// What the cloned tag produces when it is read.
    pub fn read_clone(&mut self) -> Result<odr_credential::Credential> {
        let mut card = self.clone_card();
        Ok(self.reader.present(&mut card)?)
    }

    /// The clone as something to hold up to an `odr-bus` reader.
    ///
    /// `source` is the **attacker's own token**, distinct from the victim's, so
    /// the world's event log can say the original was never presented.
    pub fn presentation(&mut self, source: SourceId) -> Result<Presentation> {
        let credential = self.read_clone()?;
        let bits = BitVec::from_bools(&credential.bits());
        let capture = CapturedCredential {
            bits: bits.clone(),
            t_us: 0,
            link: None,
            segment: 0,
            medium: CaptureMedium::Air,
            address: None,
        };
        self.knowledge.update(|k| {
            k.credentials.push(Known::derived(
                capture,
                "a 125 kHz tag sniffed out of the air and written to a blank",
            ))
        });
        Ok(
            Presentation::new(source, format_id_for(credential.format), bits)
                .labelled("cloned tag"),
        )
    }

    /// True if the blank has been written.
    pub fn is_armed(&self) -> bool {
        !self.tag.is_blank()
    }

    /// What was sniffed, if anything.
    pub fn capture(&self) -> Option<LfCapture> {
        self.capture
    }
}

impl Attacker for TagCloner {
    fn name(&self) -> &str {
        &self.name
    }
    fn position(&self) -> TapKind {
        // There is no tap. A 125 kHz cloner is a coil and a pocket, and the
        // closest honest description of what it does to the system is nothing.
        TapKind::Passive
    }
    fn knowledge(&self) -> &KnowledgeCell {
        &self.knowledge
    }
    fn tap(&self) -> Option<TapId> {
        None
    }
}

// ---------------------------------------------------------------------------
// NestedAttacker
// ---------------------------------------------------------------------------

/// **Curriculum 0.4: recover every sector key of a MIFARE Classic card.**
///
/// Crypto1 was broken in public in 2008 and is still on badges today. The
/// nested attack needs one sector key the attacker already has — in practice a
/// factory default nobody changed, which is published and therefore free — and
/// recovers the rest from the card's own nonce generator.
///
/// The honest part, and the reason this wrapper is thin: **the recovery step
/// cannot see the card.** [`NestedAttacker::recover`] takes a capture and a
/// calibrated distance and nothing else, so there is no path by which it could
/// read a key out of the card model. The one key it is given is used only by
/// [`NestedAttacker::calibrate`], which measures the *reader's* timing, and the
/// probes it takes are abandoned before pass three — an eavesdropper without
/// the target key cannot produce a valid `{aR}` and does not pretend to.
pub struct NestedAttacker {
    name: String,
    knowledge: KnowledgeCell,
    attack: NestedAttack,
    distance: Option<NonceDistance>,
}

impl core::fmt::Debug for NestedAttacker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NestedAttacker")
            .field("name", &self.name)
            .field("distance", &self.distance)
            .finish()
    }
}

impl NestedAttacker {
    /// An attacker who knows one sector key.
    ///
    /// `known_key` is filed as [`Provenance::Published`], because the case this
    /// models is a sector still on its factory default. An attacker who somehow
    /// has a *site* key for one sector has a different starting position and a
    /// drill should say so.
    pub fn new(
        name: impl Into<String>,
        known_block: u8,
        known_key_type: KeyType,
        known_key: u64,
    ) -> NestedAttacker {
        NestedAttacker::sharing(
            name,
            KnowledgeCell::new(),
            known_block,
            known_key_type,
            known_key,
        )
    }

    /// An attacker pooling what it learns with other actors.
    pub fn sharing(
        name: impl Into<String>,
        knowledge: KnowledgeCell,
        known_block: u8,
        known_key_type: KeyType,
        known_key: u64,
    ) -> NestedAttacker {
        knowledge.update(|k| {
            k.keys.push(Known::new(
                RecoveredKey::mifare_sector(known_key),
                Provenance::Published {
                    source: "a MIFARE Classic sector still on a factory default key",
                },
            ))
        });
        NestedAttacker {
            name: name.into(),
            knowledge,
            attack: NestedAttack::new(known_block, known_key_type, known_key),
            distance: None,
        }
    }

    /// How many probes each recovery takes. Two pins the key; more buys
    /// certainty at two authentications each.
    pub fn with_samples(mut self, samples: usize) -> NestedAttacker {
        self.attack.samples = samples.max(2);
        self
    }

    /// How far either side of the predicted nonce to search. Zero would do
    /// against a perfectly regular reader; a real capture has jitter.
    pub fn with_window(mut self, window: u32) -> NestedAttacker {
        self.attack.window = window;
        self
    }

    /// **Step 1: measure the reader's timing.**
    ///
    /// The only use of the known key in the whole attack, and it measures
    /// something about the *reader* rather than about the target sector — which
    /// is why one calibration serves the whole card. This is exactly the kind of
    /// calibration the governing rule permits: an attacker with a reader and a
    /// card it can authenticate to really can perform it.
    pub fn calibrate(
        &mut self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
    ) -> Result<NonceDistance> {
        let d = self.attack.calibrate(card, reader)?;
        self.distance = Some(d);
        self.knowledge.update(|k| {
            k.notes.push(alloc::format!(
                "calibrated the nonce distance at {} generator steps",
                d.0
            ))
        });
        Ok(d)
    }

    /// **Step 2: take probes against a target sector.**
    ///
    /// Each probe is one authentication to the known sector followed by a
    /// nested authentication to the target that is abandoned before pass three.
    /// The target key is neither needed nor touched.
    pub fn capture(
        &self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
        target_block: u8,
        target_key_type: KeyType,
    ) -> Result<NestedCapture> {
        Ok(self
            .attack
            .capture(card, reader, target_block, target_key_type)?)
    }

    /// **Step 3: turn a capture into a key.**
    ///
    /// Takes the capture and the calibrated distance, and nothing else. It
    /// cannot see the card, so it cannot cheat.
    pub fn recover(&mut self, capture: &NestedCapture) -> Result<u64> {
        let distance = self.distance.ok_or_else(|| AttackError::Unearned {
            wanted: "the nonce distance",
            detail: alloc::string::ToString::to_string("calibrate() has not been run"),
        })?;
        let (key, stats) = self.attack.recover(capture, distance)?;
        self.knowledge.update(|k| {
            k.keys.push(Known::new(
                RecoveredKey::mifare_sector(key),
                Provenance::BruteForced {
                    candidates: stats.keys_tested as u128,
                },
            ));
            k.notes.push(alloc::format!(
                "recovered a sector key from {} cipher states",
                stats.states_examined
            ));
        });
        Ok(key)
    }

    /// Probe and recover one sector in one call.
    pub fn recover_sector(
        &mut self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
        target_block: u8,
        target_key_type: KeyType,
    ) -> Result<u64> {
        if self.distance.is_none() {
            self.calibrate(card, reader)?;
        }
        let capture = self.capture(card, reader, target_block, target_key_type)?;
        self.recover(&capture)
    }

    /// **Prove a recovered key by using it**: authenticate, then read the
    /// block.
    ///
    /// Drill 0.4's flag is exactly this returning `Ok`. There is no answer
    /// string to compare against; either the card opens up to the recovered key
    /// or it does not.
    pub fn read_block(
        &mut self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
        block: u8,
        key_type: KeyType,
        key: u64,
    ) -> Result<odr_credential::Credential> {
        let credential = odr_credential::nested::prove(card, reader, block, key_type, key)?;
        let bits = BitVec::from_bools(&credential.bits());
        self.knowledge.update(|k| {
            k.credentials.push(Known::derived(
                CapturedCredential {
                    bits,
                    t_us: 0,
                    link: None,
                    segment: 0,
                    medium: CaptureMedium::Air,
                    address: None,
                },
                "a MIFARE Classic block read under a recovered sector key",
            ))
        });
        Ok(credential)
    }

    /// Every sector key the attacker holds, as 48-bit values.
    pub fn sector_keys(&self) -> Vec<u64> {
        self.knowledge
            .read(|k| {
                k.keys
                    .iter()
                    .filter(|x| x.value.kind == crate::knowledge::KeyKind::MifareSector)
                    .map(|x| x.value.as_mifare_key())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The calibrated distance, once it has been measured.
    pub fn distance(&self) -> Option<NonceDistance> {
        self.distance
    }
}

impl Attacker for NestedAttacker {
    fn name(&self) -> &str {
        &self.name
    }
    fn position(&self) -> TapKind {
        TapKind::Passive
    }
    fn knowledge(&self) -> &KnowledgeCell {
        &self.knowledge
    }
    fn tap(&self) -> Option<TapId> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odr_bus::FormatId;
    use odr_credential::em4100::Em4100Tag;
    use odr_credential::hid_prox::H10301;
    use odr_credential::CredentialFormat;

    #[test]
    fn a_cloner_starts_with_a_blank_and_nothing_sniffed() {
        let cloner = TagCloner::new("coil");
        assert!(!cloner.is_armed());
        assert_eq!(cloner.capture(), None);
        assert!(cloner.tap().is_none());
        assert!(cloner.knowledge().snapshot().is_honest());
    }

    #[test]
    fn an_em4100_clone_carries_the_victims_number() {
        let victim = Em4100Tag::new(0x2A, 0x0BAD_C0DE);
        let mut cloner = TagCloner::new("coil");
        cloner.brush_past(&Card::em4100(victim), 1_000).unwrap();
        cloner.write_blank().unwrap();
        let read = cloner.read_clone().unwrap();
        assert_eq!(read.format, CredentialFormat::Em4100);
        assert_eq!(read.as_u64(), victim.id40());
    }

    #[test]
    fn card_layer_formats_get_their_own_tags_on_the_wire() {
        assert_eq!(
            format_id_for(CredentialFormat::Wiegand26H10301),
            FormatId::H10301
        );
        assert!(format_id_for(CredentialFormat::Em4100).is_external());
        assert!(format_id_for(CredentialFormat::MifareClassicBlock).is_external());
        assert_ne!(
            format_id_for(CredentialFormat::Em4100),
            format_id_for(CredentialFormat::MifareClassicBlock)
        );
    }

    #[test]
    fn a_presentation_from_a_clone_is_the_attackers_own_token() {
        let mut cloner = TagCloner::new("coil");
        cloner
            .brush_past(&Card::hid_prox(H10301::new(7, 9)), 0)
            .unwrap();
        cloner.write_blank().unwrap();
        let p = cloner.presentation(SourceId(42)).unwrap();
        assert_eq!(p.source, SourceId(42));
        assert_eq!(p.bit_len(), 26);
        assert_eq!(p.format, FormatId::H10301);
        assert_eq!(p.label.as_deref(), Some("cloned tag"));
    }

    #[test]
    fn a_nested_attacker_will_not_recover_before_it_has_calibrated() {
        let mut attacker = NestedAttacker::new("proxmark", 0, KeyType::A, 0xFFFF_FFFF_FFFF);
        assert_eq!(attacker.distance(), None);
        let capture = NestedCapture {
            uid: 1,
            block: 4,
            key_type: KeyType::A,
            samples: Vec::new(),
        };
        assert!(matches!(
            attacker.recover(&capture),
            Err(AttackError::Unearned { .. })
        ));
        // The one key it starts with is published, not handed over.
        let k = attacker.knowledge().snapshot();
        assert_eq!(k.keys.len(), 1);
        assert!(matches!(k.keys[0].provenance, Provenance::Published { .. }));
        assert!(k.is_honest());
    }
}
