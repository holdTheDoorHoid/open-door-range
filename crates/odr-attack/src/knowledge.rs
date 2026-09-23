//! **What the attacker knows, and how it came to know it.**
//!
//! This module is the reason the crate is shaped the way it is. An attacker
//! actor is not a function that opens a door; it is a thing that sits at a tap
//! position, watches, acts, and *accumulates state*. The drill flags in
//! `docs/CURRICULUM.md` are checked against that accumulated state — "attacker
//! holds the SCBK", "the attacker has extracted a card number", "attacker
//! recovers a plaintext payload" — so it is modelled explicitly here rather
//! than left as a side effect of running an attack.
//!
//! # The governing rule
//!
//! **An attacker may only use what an attacker could actually have.** Every
//! fact in a [`Knowledge`] base is wrapped in [`Known`], which carries a
//! [`Provenance`] saying where it came from: read off a wire, derived from
//! something already known, measured from the tap position, brute-forced,
//! published, or physically held.
//!
//! There is a seventh variant, [`Provenance::Unearned`], which nothing in this
//! crate ever produces. It exists so that a violation of the rule is *nameable
//! and testable* rather than invisible: [`Knowledge::unearned`] returns the
//! facts an actor was handed rather than obtained, and every attack in this
//! crate has a test asserting that list is empty. A future actor that reaches
//! into a node it has not compromised has to either lie in its provenance or
//! fail that test.
//!
//! # Sharing
//!
//! [`KnowledgeCell`] is a cheap clonable handle onto one knowledge base, so
//! several actors can pool what they know — which is what a real operator does,
//! and what curriculum 3.5 needs (a keyset capturer hands the site key to a
//! decryptor). It never panics: a re-entrant borrow returns `None` or `false`
//! rather than aborting the page.

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use odr_bus::{BusDir, FormatId, LinkId, Micros, TapId};
use odr_credential::writable::LfCapture;
use odr_osdp::security::{KeyType, ScsType};
use odr_osdp::weak_keys::WeakKeyPattern;
use odr_osdp::Frame;
use odr_wiegand::{BitVec, Credential, Decoded, FormatCandidate, SweepCost};

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Where a fact in a [`Knowledge`] base came from.
///
/// Read the variants as an exhaustive list of the ways an attacker is allowed
/// to come by something. Anything outside this list is cheating, and
/// [`Provenance::Unearned`] is what cheating would have to be labelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// Read directly off a link the actor was sitting on.
    Observed {
        /// When, in virtual microseconds.
        t_us: Micros,
        /// Which probe saw it, when the actor had one.
        tap: Option<TapId>,
    },
    /// Computed from things already in this knowledge base.
    Derived {
        /// What it was computed from.
        from: &'static str,
    },
    /// Found by trying candidates until one fitted.
    BruteForced {
        /// How many candidates were tried.
        candidates: u128,
    },
    /// Public information — SCBK-D, the published weak-key family, a factory
    /// default nobody changed. Knowing it requires no access at all.
    Published {
        /// Where it is published.
        source: &'static str,
    },
    /// Measured by the actor from its own tap position: a timing distance, the
    /// width of a MAC, the cadence of a poll loop.
    Calibrated {
        /// What was measured.
        what: &'static str,
    },
    /// Something the attacker physically has: a blank tag, a card of its own, a
    /// laptop with an RS-485 dongle.
    Held {
        /// What it is.
        what: &'static str,
    },
    /// **A value the actor was handed rather than obtained.**
    ///
    /// Nothing in this crate ever constructs one. It exists so that a violation
    /// of the governing rule is a value a test can find
    /// ([`Knowledge::unearned`]) rather than something that quietly works.
    Unearned {
        /// What was handed over, and by whom.
        what: &'static str,
    },
}

impl Provenance {
    /// True if this fact was read straight off a link.
    pub fn is_observation(&self) -> bool {
        matches!(self, Provenance::Observed { .. })
    }

    /// True if this fact was handed to the actor rather than obtained by it.
    pub fn is_unearned(&self) -> bool {
        matches!(self, Provenance::Unearned { .. })
    }

    /// When the fact was learned, for the facts that have a time.
    pub fn t_us(&self) -> Option<Micros> {
        match self {
            Provenance::Observed { t_us, .. } => Some(*t_us),
            _ => None,
        }
    }

    /// A one-line description, in the register the UI uses.
    pub fn describe(&self) -> String {
        match self {
            Provenance::Observed { t_us, tap } => match tap {
                Some(t) => alloc::format!("observed on {t} at t={t_us}us"),
                None => alloc::format!("observed at t={t_us}us"),
            },
            Provenance::Derived { from } => alloc::format!("derived from {from}"),
            Provenance::BruteForced { candidates } => {
                alloc::format!("brute-forced in {candidates} candidates")
            }
            Provenance::Published { source } => alloc::format!("published: {source}"),
            Provenance::Calibrated { what } => alloc::format!("measured from the tap: {what}"),
            Provenance::Held { what } => alloc::format!("the attacker's own {what}"),
            Provenance::Unearned { what } => alloc::format!("HANDED OVER, not obtained: {what}"),
        }
    }
}

/// A fact, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known<T> {
    /// The fact.
    pub value: T,
    /// How the attacker came by it.
    pub provenance: Provenance,
}

impl<T> Known<T> {
    /// Wrap a value with its provenance.
    pub fn new(value: T, provenance: Provenance) -> Known<T> {
        Known { value, provenance }
    }

    /// Wrap a value read off a link.
    pub fn observed(value: T, t_us: Micros, tap: Option<TapId>) -> Known<T> {
        Known::new(value, Provenance::Observed { t_us, tap })
    }

    /// Wrap a value computed from other facts.
    pub fn derived(value: T, from: &'static str) -> Known<T> {
        Known::new(value, Provenance::Derived { from })
    }
}

// ---------------------------------------------------------------------------
// The facts themselves
// ---------------------------------------------------------------------------

/// Which medium a credential was lifted off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaptureMedium {
    /// A D0/D1 pair.
    Wiegand,
    /// A CLOCK/DATA pair.
    ClockData,
    /// The payload of an OSDP `REPLY_RAW`.
    OsdpRaw,
    /// The 125 kHz or 13.56 MHz air interface, before any wire.
    Air,
}

impl CaptureMedium {
    /// A short name for the UI.
    pub fn name(self) -> &'static str {
        match self {
            CaptureMedium::Wiegand => "wiegand",
            CaptureMedium::ClockData => "clock-and-data",
            CaptureMedium::OsdpRaw => "osdp REPLY_RAW",
            CaptureMedium::Air => "the air interface",
        }
    }
}

/// A credential the attacker lifted off something.
///
/// Note what it is **not**: a decoded facility code and card number. It is the
/// bits, exactly as they crossed, because that is all a tap gets and because a
/// replay does not need to understand them. [`CapturedCredential::interpret`]
/// is available when a drill wants the numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedCredential {
    /// The bits, in transmission order.
    pub bits: BitVec,
    /// When the frame started.
    pub t_us: Micros,
    /// Which link it crossed, when it crossed one.
    pub link: Option<LinkId>,
    /// Which segment of that link.
    pub segment: u16,
    /// What it was lifted off.
    pub medium: CaptureMedium,
    /// The OSDP address it was reported at, for a bus capture.
    pub address: Option<u8>,
}

impl CapturedCredential {
    /// Best-effort reading of the bits.
    ///
    /// Nothing on a wire says which format a frame is; the panel is simply
    /// configured to believe one. This returns the most plausible reading, and
    /// [`CapturedCredential::candidates`] returns all of them.
    pub fn interpret(&self) -> Decoded {
        odr_wiegand::infer_formats(&self.bits)
            .into_iter()
            .next()
            .map_or_else(|| odr_wiegand::decode_raw(&self.bits), |c| c.decoded)
    }

    /// Every card format that fits these bits, parity-valid first.
    pub fn candidates(&self) -> Vec<FormatCandidate> {
        odr_wiegand::infer_formats(&self.bits)
    }

    /// The facility code under the most plausible reading.
    pub fn facility_code(&self) -> Option<u64> {
        self.interpret().facility_code
    }

    /// The card number under the most plausible reading.
    pub fn card_number(&self) -> Option<u64> {
        self.interpret().card_number
    }

    /// How many bits were captured.
    pub fn bit_len(&self) -> usize {
        self.bits.len()
    }
}

/// What kind of key was recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyKind {
    /// A Secure Channel Base Key.
    Scbk,
    /// A MIFARE Classic sector key.
    MifareSector,
}

/// A key the attacker holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredKey {
    /// The key bytes. A MIFARE sector key occupies the first six.
    pub key: [u8; 16],
    /// What it is.
    pub kind: KeyKind,
    /// The PD address it belongs to, for an SCBK.
    pub address: Option<u8>,
    /// Which sample-code pattern it matched, if it is a weak key.
    pub pattern: Option<WeakKeyPattern>,
    /// Whether the key's owner announced it as the published default.
    pub key_type: Option<KeyType>,
}

impl RecoveredKey {
    /// An SCBK.
    pub fn scbk(key: [u8; 16], address: Option<u8>) -> RecoveredKey {
        RecoveredKey {
            key,
            kind: KeyKind::Scbk,
            address,
            pattern: odr_osdp::weak_keys::classify(&key),
            key_type: None,
        }
    }

    /// A MIFARE Classic sector key, from its 48-bit value.
    pub fn mifare_sector(key48: u64) -> RecoveredKey {
        let mut key = [0u8; 16];
        key[..6].copy_from_slice(&key48.to_be_bytes()[2..]);
        RecoveredKey {
            key,
            kind: KeyKind::MifareSector,
            address: None,
            pattern: None,
            key_type: None,
        }
    }

    /// The 48-bit value of a MIFARE sector key.
    pub fn as_mifare_key(&self) -> u64 {
        let mut v = 0u64;
        for b in &self.key[..6] {
            v = (v << 8) | u64::from(*b);
        }
        v
    }
}

/// A Secure Channel handshake, exactly as it appeared on the bus.
///
/// Every field here travels in the clear, before any key material exists. That
/// is the whole of the weak-key attack: these four values plus an offline sweep
/// of the published sample keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedHandshake {
    /// The PD address.
    pub address: u8,
    /// The ACU's nonce, from `CMD_CHLNG`.
    pub rnd_a: [u8; 8],
    /// The PD's nonce, from `REPLY_CCRYPT`.
    pub rnd_b: [u8; 8],
    /// The PD's identifier, from `REPLY_CCRYPT`.
    pub cuid: [u8; 8],
    /// The client cryptogram, from `REPLY_CCRYPT`.
    pub client_cryptogram: [u8; 16],
    /// Which key the security block claimed — default or site.
    pub key_type: KeyType,
    /// The sequence number `CMD_CHLNG` carried.
    pub chlng_sequence: u8,
    /// When the challenge crossed.
    pub t_us: Micros,
}

/// One OSDP frame as an attacker saw it.
///
/// The payload is kept **as it was on the wire**, which under SCS_17/SCS_18 is
/// ciphertext. An attacker holds frames it cannot read; that is the normal
/// case, and it is what makes drill 4.1 interesting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFrame {
    /// When it crossed.
    pub t_us: Micros,
    /// Which way.
    pub dir: BusDir,
    /// The frame.
    pub frame: Frame,
}

/// **The only thing a traffic analyst is allowed to look at.**
///
/// The command or reply code byte sits *before* the encrypted region of an OSDP
/// frame, so it is readable at every security level the protocol offers. So are
/// the address, the direction, the security block type and the length. The
/// payload is not, and this type does not carry it — which is how
/// [`crate::TrafficAnalyst`] is kept honest structurally rather than by
/// promising.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextHeader {
    /// When it crossed.
    pub t_us: Micros,
    /// Which way.
    pub dir: BusDir,
    /// The PD address.
    pub address: u8,
    /// The command or reply code byte, in the clear.
    pub id: u8,
    /// True for a reply.
    pub is_reply: bool,
    /// The security block type, when there was one.
    pub scs: Option<ScsType>,
    /// How many payload bytes there were. A length, never a byte of content —
    /// and it is on the wire in the length field anyway.
    pub payload_len: usize,
}

impl PlaintextHeader {
    /// Read a header off a frame **without touching its payload**.
    pub fn from_frame(t_us: Micros, dir: BusDir, frame: &Frame) -> PlaintextHeader {
        PlaintextHeader {
            t_us,
            dir,
            address: frame.address,
            id: frame.id,
            is_reply: frame.is_reply,
            scs: frame.scs_type(),
            payload_len: frame.payload.len(),
        }
    }

    /// True if this is a reply carrying a card read.
    pub fn is_card_read(&self) -> bool {
        self.is_reply && self.id == odr_osdp::Reply::Raw.to_u8()
    }

    /// True if this is the controller driving an output — the door, in nearly
    /// every deployment.
    pub fn is_output_command(&self) -> bool {
        !self.is_reply && self.id == odr_osdp::Command::Out.to_u8()
    }
}

/// Somebody went through a door, inferred without any key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadgeEvent {
    /// When the card read crossed the bus.
    pub t_us: Micros,
    /// Which reader.
    pub address: u8,
    /// Whether the controller went on to drive an output, which on a normal
    /// installation means the door opened. `None` when the analyst saw no
    /// output command either way.
    pub granted: Option<bool>,
}

/// A payload the attacker read despite it being meant to be protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredPlaintext {
    /// When the frame crossed.
    pub t_us: Micros,
    /// The PD address.
    pub address: u8,
    /// The command or reply code.
    pub id: u8,
    /// The plaintext.
    pub bytes: Vec<u8>,
    /// How it was recovered, in a phrase the UI can print.
    pub method: &'static str,
}

/// What a brute-force sweep cost, and whether it found anything.
#[derive(Debug, Clone, PartialEq)]
pub struct SweepReport {
    /// How many credentials were actually put on the wire.
    pub attempted: u128,
    /// How many the configured sweep covers in total.
    pub sweep_space: u128,
    /// What the configured sweep would cost end to end.
    pub sweep_cost: SweepCost,
    /// What the format's **whole** credential space would cost. This is the
    /// number curriculum drill 1.5 ends on.
    pub format_space_cost: SweepCost,
    /// How much virtual time the attempts actually took.
    pub elapsed_us: Micros,
    /// The credential that opened the door, if one did.
    pub hit: Option<Credential>,
}

/// What the attacker measured about the MACs on this bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacFacts {
    /// How many MAC bytes carry anything, measured from genuine frames.
    ///
    /// On a real bus this is 4. A drill that has shortened the MAC so curriculum
    /// 4.2 completes in front of a learner leaves the remaining bytes zero, and
    /// an attacker sitting on the line can see that — which is why this is a
    /// measurement rather than a parameter.
    pub effective_bytes: u8,
    /// How many genuine MACs the measurement is based on.
    pub samples: usize,
}

impl MacFacts {
    /// The size of the forgery space, in bits.
    pub fn bits(&self) -> u32 {
        u32::from(self.effective_bytes) * 8
    }

    /// How many candidates a blind forgery has to sweep to be certain.
    pub fn search_space(&self) -> u128 {
        1u128 << self.bits().min(126)
    }
}

/// A 125 kHz tag the attacker pulled out of the air.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagCapture {
    /// What the sniffer demodulated.
    pub capture: LfCapture,
    /// When, in virtual microseconds.
    pub t_us: Micros,
}

// ---------------------------------------------------------------------------
// Knowledge
// ---------------------------------------------------------------------------

/// **Everything one attacker, or one pooled group of attackers, knows.**
///
/// Flag predicates are queries against this. The fields are public because a
/// drill, a detector or the site's inspector should be able to display any of
/// it without this crate guessing what they want.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Knowledge {
    /// Credentials lifted off a wire, a bus or the air.
    pub credentials: Vec<Known<CapturedCredential>>,
    /// Keys the attacker holds.
    pub keys: Vec<Known<RecoveredKey>>,
    /// Secure Channel handshakes seen in the clear.
    pub handshakes: Vec<Known<ObservedHandshake>>,
    /// OSDP frames, payloads and all, exactly as they crossed.
    pub frames: Vec<Known<ObservedFrame>>,
    /// Plaintext headers only — what a traffic analyst is allowed to hold.
    pub headers: Vec<Known<PlaintextHeader>>,
    /// PD addresses seen answering.
    pub addresses: Vec<Known<u8>>,
    /// Badge-ins inferred from traffic.
    pub badge_events: Vec<Known<BadgeEvent>>,
    /// Payloads recovered despite protection.
    pub plaintexts: Vec<Known<RecoveredPlaintext>>,
    /// Brute-force sweeps and what they cost.
    pub sweeps: Vec<Known<SweepReport>>,
    /// What was measured about the MACs on this bus.
    pub mac_facts: Vec<Known<MacFacts>>,
    /// 125 kHz tags sniffed out of the air.
    pub tag_captures: Vec<Known<TagCapture>>,
    /// Free-text narration for the UI. Never a fact.
    pub notes: Vec<String>,
}

impl Knowledge {
    /// An attacker that knows nothing.
    pub fn new() -> Knowledge {
        Knowledge::default()
    }

    /// **The provenance audit.**
    ///
    /// Every fact an actor was handed rather than obtained. Nothing in this
    /// crate produces one, so this is empty for every attack here — and a test
    /// that asserts it is empty is a real assertion rather than a tautology,
    /// because the variant exists and could be produced.
    pub fn unearned(&self) -> Vec<&Provenance> {
        let mut out: Vec<&Provenance> = Vec::new();
        macro_rules! sweep {
            ($($field:ident),* $(,)?) => {
                $(
                    for k in &self.$field {
                        if k.provenance.is_unearned() {
                            out.push(&k.provenance);
                        }
                    }
                )*
            };
        }
        sweep!(
            credentials,
            keys,
            handshakes,
            frames,
            headers,
            addresses,
            badge_events,
            plaintexts,
            sweeps,
            mac_facts,
            tag_captures,
        );
        out
    }

    /// True if nothing in here was handed over.
    pub fn is_honest(&self) -> bool {
        self.unearned().is_empty()
    }

    /// Every SCBK the attacker holds.
    pub fn scbks(&self) -> Vec<[u8; 16]> {
        self.keys
            .iter()
            .filter(|k| k.value.kind == KeyKind::Scbk)
            .map(|k| k.value.key)
            .collect()
    }

    /// True if the attacker holds this SCBK.
    pub fn holds_scbk(&self, key: &[u8; 16]) -> bool {
        self.keys
            .iter()
            .any(|k| k.value.kind == KeyKind::Scbk && &k.value.key == key)
    }

    /// The SCBK for an address, preferring one recorded against it.
    pub fn scbk_for(&self, address: u8) -> Option<[u8; 16]> {
        self.keys
            .iter()
            .find(|k| k.value.kind == KeyKind::Scbk && k.value.address == Some(address))
            .or_else(|| self.keys.iter().find(|k| k.value.kind == KeyKind::Scbk))
            .map(|k| k.value.key)
    }

    /// Every set of credential bits the attacker captured.
    pub fn credential_bits(&self) -> Vec<BitVec> {
        self.credentials
            .iter()
            .map(|c| c.value.bits.clone())
            .collect()
    }

    /// True if the attacker captured exactly these bits.
    pub fn holds_credential(&self, bits: &BitVec) -> bool {
        self.credentials.iter().any(|c| &c.value.bits == bits)
    }

    /// Card numbers under the most plausible reading of each capture.
    pub fn card_numbers(&self) -> Vec<u64> {
        self.credentials
            .iter()
            .filter_map(|c| c.value.card_number())
            .collect()
    }

    /// The handshake recorded for an address, most recent last.
    pub fn handshake_for(&self, address: u8) -> Option<&ObservedHandshake> {
        self.handshakes
            .iter()
            .rev()
            .map(|k| &k.value)
            .find(|h| h.address == address)
    }

    /// Frames in the order they crossed.
    pub fn observed_frames(&self) -> Vec<ObservedFrame> {
        self.frames.iter().map(|f| f.value.clone()).collect()
    }

    /// Record a fact, keeping insertion order. A convenience so an actor does
    /// not spell out `Known::new` at every call site.
    pub fn record<T>(list: &mut Vec<Known<T>>, value: T, provenance: Provenance) {
        list.push(Known::new(value, provenance));
    }

    /// Merge another knowledge base into this one, keeping both provenances.
    ///
    /// This is two operators comparing notes, which is exactly what curriculum
    /// 3.5 is: one actor captures the key, another decrypts with it.
    pub fn absorb(&mut self, other: &Knowledge) {
        self.credentials.extend(other.credentials.iter().cloned());
        self.keys.extend(other.keys.iter().cloned());
        self.handshakes.extend(other.handshakes.iter().cloned());
        self.frames.extend(other.frames.iter().cloned());
        self.headers.extend(other.headers.iter().cloned());
        self.addresses.extend(other.addresses.iter().cloned());
        self.badge_events.extend(other.badge_events.iter().cloned());
        self.plaintexts.extend(other.plaintexts.iter().cloned());
        self.sweeps.extend(other.sweeps.iter().cloned());
        self.mac_facts.extend(other.mac_facts.iter().cloned());
        self.tag_captures.extend(other.tag_captures.iter().cloned());
        self.notes.extend(other.notes.iter().cloned());
    }

    /// A short summary for the UI's "what the attacker has" panel.
    pub fn summary(&self) -> String {
        alloc::format!(
            "{} credential(s), {} key(s), {} handshake(s), {} frame(s), {} badge event(s), {} recovered payload(s)",
            self.credentials.len(),
            self.keys.len(),
            self.handshakes.len(),
            self.frames.len(),
            self.badge_events.len(),
            self.plaintexts.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// The shared handle
// ---------------------------------------------------------------------------

/// A cheap clonable handle onto one [`Knowledge`] base.
///
/// Clone it into a tap's closure and the tap writes into the same knowledge the
/// actor reads. Clone it into a second actor and the two pool what they know.
///
/// **It never panics.** A re-entrant borrow — which should not happen, since
/// the engine runs one tap at a time — returns `None` or `false` instead of
/// aborting, because this code runs in a browser tab.
#[derive(Debug, Clone, Default)]
pub struct KnowledgeCell(Rc<RefCell<Knowledge>>);

impl KnowledgeCell {
    /// A new, empty knowledge base.
    pub fn new() -> KnowledgeCell {
        KnowledgeCell::default()
    }

    /// Read something out of it. `None` if it was already borrowed.
    pub fn read<R>(&self, f: impl FnOnce(&Knowledge) -> R) -> Option<R> {
        self.0.try_borrow().ok().map(|k| f(&k))
    }

    /// Change it. `false` if it was already borrowed, in which case nothing
    /// happened.
    pub fn update(&self, f: impl FnOnce(&mut Knowledge)) -> bool {
        match self.0.try_borrow_mut() {
            Ok(mut k) => {
                f(&mut k);
                true
            }
            Err(_) => false,
        }
    }

    /// A copy of everything known right now.
    pub fn snapshot(&self) -> Knowledge {
        self.read(|k| k.clone()).unwrap_or_default()
    }

    /// True if the two handles point at the same knowledge base.
    pub fn is_same(&self, other: &KnowledgeCell) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

/// The format tag `odr-credential` cards are reported under on a wire.
///
/// [`FormatId`] reserves everything at or above `EXTERNAL_BASE` for the card
/// layer, so a cloned EM4100 presented to a reader is distinguishable in the
/// log from a 26-bit Wiegand frame that happens to be the same width.
pub fn format_id_for(format: odr_credential::CredentialFormat) -> FormatId {
    use odr_credential::CredentialFormat as C;
    match format {
        C::Wiegand26H10301 => FormatId::H10301,
        C::Em4100 => FormatId(FormatId::EXTERNAL_BASE),
        C::MifareClassicBlock => FormatId(FormatId::EXTERNAL_BASE + 1),
        C::DesfireFile => FormatId(FormatId::EXTERNAL_BASE + 2),
        _ => FormatId::UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_this_crate_records_is_unearned_by_construction() {
        let mut k = Knowledge::new();
        k.addresses.push(Known::observed(0x01, 10, None));
        k.keys.push(Known::derived(
            RecoveredKey::scbk(odr_osdp::SCBK_D, Some(1)),
            "a captured handshake",
        ));
        assert!(k.is_honest());

        // And the audit really does find a violation when one is planted.
        k.addresses.push(Known::new(
            0x02,
            Provenance::Unearned {
                what: "read out of the controller's configuration",
            },
        ));
        assert_eq!(k.unearned().len(), 1);
        assert!(!k.is_honest());
    }

    #[test]
    fn a_recovered_scbk_classifies_itself() {
        let k = RecoveredKey::scbk(odr_osdp::SCBK_D, None);
        assert_eq!(
            k.pattern,
            Some(WeakKeyPattern::Ascending { start: 0x30 }),
            "SCBK-D is a member of the published weak family"
        );
    }

    #[test]
    fn a_mifare_key_round_trips_through_its_sixteen_byte_slot() {
        let key = 0xA0A1_A2A3_A4A5u64;
        assert_eq!(RecoveredKey::mifare_sector(key).as_mifare_key(), key);
    }

    #[test]
    fn a_shared_cell_is_seen_by_both_holders() {
        let a = KnowledgeCell::new();
        let b = a.clone();
        assert!(a.is_same(&b));
        a.update(|k| k.notes.push("one".into()));
        assert_eq!(b.snapshot().notes.len(), 1);
    }

    #[test]
    fn a_reentrant_borrow_is_refused_rather_than_a_panic() {
        let cell = KnowledgeCell::new();
        let ok = cell.read(|_| cell.update(|k| k.notes.push("nested".into())));
        assert_eq!(ok, Some(false), "the inner write was refused, not a panic");
    }
}
