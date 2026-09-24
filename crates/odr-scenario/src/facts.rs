//! **Engine-derived truth**: the values a predicate compares against, and
//! where each of them came from.
//!
//! A flag predicate reads three things: the [`World`](odr_bus::World) and its
//! event log, the attacker's [`Knowledge`](odr_attack::Knowledge), and this.
//! Everything in here was produced by running the engine — a frame off the bus,
//! a card the seed generated, a cost the wire timing implies — and nothing in
//! here is a constant written by hand. That is the property that makes a
//! learner's claim checkable without the drill degenerating into a lookup.
//!
//! The rule for adding a field: if a learner could get the value by reading
//! this source file, it does not belong here.

use alloc::string::String;
use alloc::vec::Vec;

use odr_attack::SweepReport;
use odr_bus::Micros;
use odr_credential::desfire::AttackFailure;
use odr_osdp::Frame;

use crate::submission::{FieldSpan, FrameField};
use crate::tasks::Tasks;

/// A credential exactly as the engine put it on a wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransmittedCredential {
    /// When the first edge went out.
    pub t_us: Micros,
    /// Facility code, as the format decodes it.
    pub facility_code: Option<u64>,
    /// Card number.
    pub card_number: Option<u64>,
    /// The bits, in transmission order.
    pub bits: Vec<bool>,
    /// Whether the parity rules the format defines all passed.
    pub parity_valid: bool,
}

/// **The layout of a frame the engine generated**, field by field.
///
/// Drill 2.1's flag is "learner correctly labels the byte offsets of a frame
/// the engine generated", so this is derived from the frame that actually
/// crossed the bus rather than from a diagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameLayout {
    /// When it crossed.
    pub t_us: Micros,
    /// The octets, mark byte included.
    pub bytes: Vec<u8>,
    /// Every field, in wire order.
    pub spans: Vec<FieldSpan>,
    /// The sequence number, which lives in the control byte's bottom two bits
    /// rather than at a byte offset of its own.
    pub sequence: u8,
    /// The command or reply code byte.
    pub code: u8,
    /// A name for that code, when it is one the standard defines.
    pub code_name: String,
}

impl FrameLayout {
    /// Work out where every field of a frame sits.
    ///
    /// The arithmetic mirrors `odr_osdp::Frame::encode` exactly, because a
    /// layout that disagreed with the encoder would mark a correct answer
    /// wrong.
    pub fn of(frame: &Frame, t_us: Micros) -> FrameLayout {
        let mut spans = Vec::new();
        let mut at = 0usize;
        if frame.mark {
            spans.push(FieldSpan::new(FrameField::Mark, at, 1));
            at += 1;
        }
        spans.push(FieldSpan::new(FrameField::Som, at, 1));
        at += 1;
        spans.push(FieldSpan::new(FrameField::Address, at, 1));
        at += 1;
        spans.push(FieldSpan::new(FrameField::Length, at, 2));
        at += 2;
        spans.push(FieldSpan::new(FrameField::Control, at, 1));
        at += 1;
        if let Some(sb) = &frame.security {
            let n = sb.encoded_len();
            spans.push(FieldSpan::new(FrameField::SecurityBlock, at, n));
            at += n;
        }
        spans.push(FieldSpan::new(FrameField::Id, at, 1));
        at += 1;
        if !frame.payload.is_empty() {
            spans.push(FieldSpan::new(FrameField::Payload, at, frame.payload.len()));
            at += frame.payload.len();
        }
        if frame
            .security
            .as_ref()
            .and_then(|s| s.scs_type)
            .is_some_and(|s| s.has_mac())
        {
            spans.push(FieldSpan::new(FrameField::Mac, at, 4));
            at += 4;
        }
        spans.push(FieldSpan::new(FrameField::Crc, at, frame.trailer_len()));

        let code_name = match (frame.is_reply, frame.command_code(), frame.reply_code()) {
            (false, Some(c), _) => alloc::format!("{c:?}"),
            (true, _, Some(r)) => alloc::format!("{r:?}"),
            _ => alloc::format!("{:#04x}", frame.id),
        };

        FrameLayout {
            t_us,
            bytes: frame.encode(),
            spans,
            sequence: frame.sequence,
            code: frame.id,
            code_name,
        }
    }

    /// The span for one field, if the frame has it.
    pub fn span(&self, field: FrameField) -> Option<FieldSpan> {
        self.spans.iter().copied().find(|s| s.field == field)
    }

    /// The fields a learner has to label to earn drill 2.1.
    ///
    /// Everything the frame actually contains except the mark byte, which is a
    /// line-idle artefact rather than a field and is absent on this bench.
    pub fn required(&self) -> Vec<FieldSpan> {
        self.spans
            .iter()
            .copied()
            .filter(|s| s.field != FrameField::Mark)
            .collect()
    }
}

/// What a nested attack recovered from a MIFARE Classic card, beside what the
/// card was actually provisioned with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MifareOutcome {
    /// `(sector, key A)` as the card was provisioned. Ground truth.
    pub configured: Vec<(u8, u64)>,
    /// `(sector, key A)` as the attacker recovered them.
    pub recovered: Vec<(u8, u64)>,
    /// Which block holds the credential.
    pub credential_block: u8,
    /// What is in it, as the card was provisioned.
    pub credential: Vec<u8>,
    /// What the attacker read out of it, once it held the key.
    pub read_back: Option<Vec<u8>>,
}

/// What happened to a deliberately desynchronised link. Drill 2.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesyncTrace {
    /// When the controller's sequence numbering was pushed out of step.
    pub forced_at_us: Micros,
    /// When the peripheral first objected.
    pub noticed_at_us: Option<Micros>,
    /// When traffic resumed normally.
    pub recovered_at_us: Option<Micros>,
    /// How many times the simulation was started. More than one means the
    /// learner restarted it, which is what the drill forbids.
    pub starts: usize,
}

/// What the MAC forgery did, and what the genuine one would cost. Drill 4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeryOutcome {
    /// Whether the PD accepted a frame the attacker built.
    pub accepted: bool,
    /// How many candidates it took.
    pub attempts: u64,
    /// How many MAC bytes carry anything on this bus, **measured** from
    /// genuine frames rather than read out of the configuration.
    pub effective_mac_bytes: u8,
    /// Whether the engine's own cause chain attributes the acceptance to the
    /// attacker's frame.
    pub attributable: bool,
    /// The genuine 32-bit search space.
    pub genuine_space: u128,
    /// What the genuine search would cost, in the engine's own words.
    pub genuine_projected: String,
}

/// What the IV-reuse attack found. Drill 4.3.
///
/// The `decryptor_refused` field is the one that makes the flag mean anything:
/// the frame whose plaintext was recovered is a frame the attacker's own
/// chained decryptor could not open, so the recovery really did come from the
/// codebook rather than from decrypting it the ordinary way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvReuseOutcome {
    /// How many groups of identical ciphertext were found.
    pub collisions: usize,
    /// How many replies the implant swallowed to freeze the chain.
    pub suppressed: usize,
    /// When the frame whose plaintext was recovered crossed.
    pub recovered_at_us: Micros,
    /// Its command or reply code byte.
    pub recovered_id: u8,
    /// The plaintext.
    pub plaintext: Vec<u8>,
    /// Whether a shadow decryptor built from the recovered key refused that
    /// same frame.
    pub decryptor_refused: bool,
}

/// **Everything a predicate needs that is neither in the world's log nor in
/// the attacker's knowledge base.**
///
/// Assembled by [`crate::run`] as it drives a drill. A field left `None` means
/// this drill does not use it, not that something failed.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// Drill 0.1: the tag id the engine generated from the seed.
    pub tag_id40: Option<u64>,
    /// Drills 0.3 and 1.1: what the reader actually put on the wire.
    pub transmitted: Option<TransmittedCredential>,
    /// Drill 0.3: the bits predicted from the RF layer, before the wire saw
    /// anything.
    pub predicted_bits: Option<Vec<bool>>,
    /// Drill 0.4.
    pub mifare: Option<MifareOutcome>,
    /// Drill 0.5: why each attack stopped.
    pub diagnoses: Vec<AttackFailure>,
    /// Drill 0.5: whether every attack really did stop.
    pub all_attacks_failed: bool,
    /// Drill 1.5: the number the drill ends on.
    pub sweep: Option<SweepReport>,
    /// Drill 2.1.
    pub frame_layout: Option<FrameLayout>,
    /// Drill 2.4.
    pub desync: Option<DesyncTrace>,
    /// Drill 3.1: the cryptogram the PD transmitted, taken off the wire.
    pub client_cryptogram: Option<[u8; 16]>,
    /// Credentials the attacker recovered, whatever route it took to them:
    /// read in the clear, decrypted under a cracked key, or lifted out of a
    /// commissioning session.
    ///
    /// Separate from the attacker's knowledge base because some actors hand
    /// their recovered reads back as return values rather than filing them, and
    /// a predicate should not have to know which.
    pub recovered_credentials: Vec<odr_attack::CapturedCredential>,
    /// Drill 4.1: when the engine's own log says people badged in.
    pub badge_times: Vec<Micros>,
    /// Drill 4.1: when the attacker's traffic analysis says they did.
    pub inferred_badge_times: Vec<Micros>,
    /// Drill 4.2.
    pub forgery: Option<ForgeryOutcome>,
    /// Drill 4.3.
    pub iv_reuse: Option<IvReuseOutcome>,
    /// Drills 5.1 to 5.3.
    pub detection: Option<crate::module5::DetectionOutcome>,
    /// The key the endpoints were commissioned with, when the scenario set
    /// one. Ground truth, compared against what an attacker recovered.
    pub site_key: Option<[u8; 16]>,
    /// Long-running attacks this drill started.
    pub tasks: Tasks,
    /// Whether an attacker actor was clipped on and driven at all.
    ///
    /// Used only to word the `outstanding` list helpfully — no predicate
    /// depends on it, because "did the attack happen" is a question for the
    /// world's event log rather than for a flag we set ourselves.
    pub attack_performed: bool,
}
