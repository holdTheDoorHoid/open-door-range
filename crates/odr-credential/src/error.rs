//! One error type for the whole crate.
//!
//! Nothing in `odr-credential` panics on malformed input. A card that answers with
//! garbage, a bitstream with a broken preamble, a key that does not fit in 48 bits —
//! all of it comes back as a [`CredentialError`], because in a teaching simulation the
//! failure *is* the lesson and a panic would throw it away.

use core::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, CredentialError>;

/// Everything that can go wrong in the card layer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialError {
    /// A value was handed in that does not fit the field it was destined for.
    ///
    /// `field` names the field, `bits` is how wide it actually is.
    ValueTooWide {
        /// Name of the field the value was destined for, e.g. `"facility_code"`.
        field: &'static str,
        /// Width of that field in bits.
        bits: u32,
    },

    /// A modulated bitstream did not begin with the expected preamble or header.
    PreambleNotFound {
        /// Which decoder was looking, e.g. `"em4100"` or `"hid_prox"`.
        decoder: &'static str,
    },

    /// A Manchester half-bit pair was `00` or `11`, which encodes nothing.
    ///
    /// On real hardware this is what a half-read looks like: the tag left the field
    /// part-way through a bit cell.
    ManchesterViolation {
        /// Index of the offending half-bit pair, counted from the start of the stream.
        pair_index: usize,
    },

    /// The stream was shorter than the frame the decoder needed.
    StreamTooShort {
        /// Bits the decoder needed.
        needed: usize,
        /// Bits it actually got.
        got: usize,
    },

    /// A frame decoded structurally but its parity or checksum does not hold.
    ///
    /// The payload is still available from the decoder — a bad read is reportable
    /// *as a bad read*, which is the point.
    ParityFailed {
        /// Which decoder, e.g. `"em4100"`.
        decoder: &'static str,
    },

    /// A block, sector or key index that does not exist on this card.
    OutOfRange {
        /// What was indexed, e.g. `"block"`.
        what: &'static str,
        /// The index asked for.
        index: u32,
        /// One past the largest valid index.
        limit: u32,
    },

    /// The card's access conditions forbid this operation with this key.
    AccessDenied {
        /// Human-readable description of the operation that was refused.
        operation: &'static str,
    },

    /// An operation needed an authenticated session and there was not one.
    NotAuthenticated,

    /// The protocol exchange arrived in the wrong order.
    ProtocolViolation {
        /// What the model expected next.
        expected: &'static str,
    },

    /// A cryptographic response did not verify.
    ///
    /// For MIFARE Classic this is a bad `ar`/`at`; for DESFire it is a bad `RndA'`.
    /// It is the ordinary outcome of presenting the wrong key, and of every replay
    /// attempt against a card that challenges freshly.
    AuthenticationFailed {
        /// Which side rejected: `"card"` or `"reader"`.
        rejected_by: &'static str,
    },

    /// A block was read as a value block but is not in value-block format.
    NotAValueBlock {
        /// The block number.
        block: u8,
    },

    /// The card in the field does not speak the protocol the reader is running.
    WrongTechnology {
        /// What the reader was running, e.g. `"125 kHz ASK"`.
        reader: &'static str,
        /// What the card speaks.
        card: &'static str,
    },

    /// A writable (clone) tag was presented with nothing programmed into it.
    BlankTag,

    /// An attack ran to completion and recovered nothing.
    ///
    /// Distinct from a bug: the attack was well-formed, the observation was simply
    /// not sufficient.
    AttackExhausted {
        /// Which attack, e.g. `"nested"`.
        attack: &'static str,
        /// Why it ran out.
        detail: &'static str,
    },
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooWide { field, bits } => {
                write!(f, "value does not fit {field} ({bits} bits)")
            }
            Self::PreambleNotFound { decoder } => {
                write!(f, "{decoder}: preamble not found in stream")
            }
            Self::ManchesterViolation { pair_index } => {
                write!(f, "manchester violation at half-bit pair {pair_index}")
            }
            Self::StreamTooShort { needed, got } => {
                write!(f, "stream too short: needed {needed} bits, got {got}")
            }
            Self::ParityFailed { decoder } => write!(f, "{decoder}: parity check failed"),
            Self::OutOfRange { what, index, limit } => {
                write!(f, "{what} {index} out of range (limit {limit})")
            }
            Self::AccessDenied { operation } => write!(f, "access denied: {operation}"),
            Self::NotAuthenticated => f.write_str("no authenticated session"),
            Self::ProtocolViolation { expected } => {
                write!(f, "protocol violation: expected {expected}")
            }
            Self::AuthenticationFailed { rejected_by } => {
                write!(f, "authentication failed (rejected by {rejected_by})")
            }
            Self::NotAValueBlock { block } => {
                write!(f, "block {block} is not in value-block format")
            }
            Self::WrongTechnology { reader, card } => {
                write!(f, "reader speaks {reader}, card speaks {card}")
            }
            Self::BlankTag => f.write_str("writable tag has nothing programmed"),
            Self::AttackExhausted { attack, detail } => {
                write!(f, "{attack} attack exhausted: {detail}")
            }
        }
    }
}

impl std::error::Error for CredentialError {}
