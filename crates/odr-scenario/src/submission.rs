//! **What a learner hands in — and why it is not an answer string.**
//!
//! `DESIGN.md` §3 is categorical: drills do not describe attacks, they run
//! them, and a flag is earned when the engine's own state satisfies a
//! predicate. Most drills here need nothing from the learner at all, because
//! the thing being checked is that a door opened or that an attacker holds a
//! key.
//!
//! Four drills legitimately need the learner to say something, and it is worth
//! being precise about why they are not an exception to the rule:
//!
//! | Drill | What is submitted | What it is checked against |
//! |---|---|---|
//! | 0.1 | a 40-bit tag id | the id the engine generated from the session seed |
//! | 0.3 | facility code, card number, and the 26 bits | the bits the reader then put on the wire |
//! | 0.5 | a diagnosis per attack | the failure each attack actually hit |
//! | 1.1 | facility code and card number | what the engine transmitted |
//! | 2.1 | byte offsets | the layout of a frame the engine generated |
//! | 3.1 | a 16-byte cryptogram | the one the PD then transmitted |
//! | 4.1 | a list of times | the engine's own presentation log |
//! | 5.x | a detection report | an answer key the rule set never saw |
//!
//! In every row the right-hand column is a value the engine produced from a
//! seed. There is no constant in this crate that a learner could read instead
//! of doing the work, and a different seed gives a different correct answer.
//! That is what separates a *claim checked against engine-derived truth* from
//! an answer string, and it is the whole of the distinction.

use alloc::string::String;
use alloc::vec::Vec;

use odr_bus::Micros;
use odr_credential::desfire::AttackFailure;
use odr_detect::Report;

/// **One field of an OSDP frame, as a thing a learner points at.**
///
/// Drill 2.1's flag is "learner correctly labels the byte offsets of a frame
/// the engine generated", so the vocabulary has to be closed: a scorer cannot
/// compare free text, and "the length bit" and "length field" would have to be
/// the same answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum FrameField {
    /// The optional `0xFF` mark byte before SOM.
    Mark,
    /// Start of message, `0x53`.
    Som,
    /// The address byte. Bit 7 set means the frame is a reply.
    Address,
    /// The two-byte length field, LSB first.
    Length,
    /// The control byte: sequence in bits 0-1, CRC flag in bit 2, security
    /// block flag in bit 3.
    Control,
    /// The security block, when control bit 3 is set.
    SecurityBlock,
    /// The command or reply code. **Plaintext in every OSDP security mode**,
    /// which is what makes drill 4.1 work.
    Id,
    /// The payload, encrypted or not.
    Payload,
    /// The four-byte truncated MAC, under SCS_15 to SCS_18.
    Mac,
    /// The trailer: CRC-16/AUG-CCITT, or a one-byte checksum.
    Crc,
}

impl FrameField {
    /// A short label for the UI.
    pub fn name(self) -> &'static str {
        match self {
            FrameField::Mark => "mark",
            FrameField::Som => "som",
            FrameField::Address => "address",
            FrameField::Length => "length",
            FrameField::Control => "control",
            FrameField::SecurityBlock => "security-block",
            FrameField::Id => "id",
            FrameField::Payload => "payload",
            FrameField::Mac => "mac",
            FrameField::Crc => "crc",
        }
    }
}

/// Where one field sits in a frame's octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpan {
    /// Which field.
    pub field: FrameField,
    /// Byte offset from the start of the frame, mark byte included when there
    /// is one.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
}

impl FieldSpan {
    /// Build a span.
    pub const fn new(field: FrameField, offset: usize, length: usize) -> FieldSpan {
        FieldSpan {
            field,
            offset,
            length,
        }
    }
}

/// A time a learner claims a badge-in happened at. Drill 4.1.
pub type ClaimedTime = Micros;

/// **A learner's claim, typed.**
///
/// Compared against a value the engine derived from its seed — never against a
/// constant. See the module docs for the full table.
///
/// Additive: new variants may appear, so match with a `_` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Submission {
    /// Drill 0.1: the tag id read off the modulated carrier.
    TagId(u64),
    /// Drills 0.3 and 1.1: a credential read off the air or off the wire, and
    /// — for 0.3 — the bit pattern predicted from it.
    Credential {
        /// Facility code.
        facility_code: u64,
        /// Card number.
        card_number: u64,
        /// The exact bits the reader is predicted to emit. Empty when the
        /// drill does not ask for them.
        bits: Vec<bool>,
    },
    /// Drill 0.5: why each Module 0 attack stopped against a DESFire card.
    Diagnoses(Vec<AttackFailure>),
    /// Drill 2.1: the byte offsets of the fields of a frame.
    FrameLayout(Vec<FieldSpan>),
    /// Drill 3.1: the client cryptogram, predicted before the PD sends it.
    Cryptogram([u8; 16]),
    /// Drill 4.1: the times of every badge-in over the simulated day.
    BadgeTimes(Vec<ClaimedTime>),
    /// Drills 5.1 to 5.3: what the learner's rule set found.
    ///
    /// The rule set itself is not carried here — it is run by the caller, since
    /// a `RuleSet` is a list of trait objects and cannot be a plain value. What
    /// is submitted is its output, which is what gets scored against a key the
    /// rule set never saw.
    Detection(Report),
    /// Drill 0.6: the reference section was read.
    ///
    /// Not a claim about anything. It exists so that a section which completes
    /// by being read has a way to say it has been, without the API pretending
    /// a flag was earned.
    Acknowledged,
    /// Free text, for a drill that wants a diagnosis in the learner's own
    /// words. Never scored — the engine still decides.
    Note(String),
}

impl Submission {
    /// A short name for the shape of this submission, used in error messages.
    pub fn shape(&self) -> &'static str {
        match self {
            Submission::TagId(_) => "a tag id",
            Submission::Credential { .. } => "a facility code and card number",
            Submission::Diagnoses(_) => "a diagnosis per attack",
            Submission::FrameLayout(_) => "byte offsets",
            Submission::Cryptogram(_) => "a client cryptogram",
            Submission::BadgeTimes(_) => "a list of times",
            Submission::Detection(_) => "a detection report",
            Submission::Acknowledged => "an acknowledgement",
            Submission::Note(_) => "a note",
        }
    }
}
