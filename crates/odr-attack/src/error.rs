//! The crate's error type.
//!
//! Nothing in `odr-attack` panics. An attack that cannot proceed says why, in a
//! structured value, because the engine also runs inside a browser where a
//! panic is an unrecoverable abort of the whole page — and because "the attack
//! did not work" is a result a drill has to be able to display rather than a
//! bug.

use alloc::string::String;
use core::fmt;

use odr_bus::BusError;
use odr_credential::CredentialError;
use odr_osdp::channel::ChannelError;
use odr_osdp::payload::PayloadError;
use odr_wiegand::{BitError, FormatError};

/// Everything that can stop an attacker actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackError {
    /// The actor has not been clipped onto a link yet, so it has neither seen
    /// anything nor anywhere to transmit.
    NotAttached {
        /// The actor's name.
        actor: String,
    },
    /// The actor is attached to a link of the wrong kind — a Wiegand sniffer on
    /// an RS-485 bus, say.
    WrongMedium {
        /// What the actor needs.
        wanted: &'static str,
        /// What it found.
        found: &'static str,
    },
    /// **The governing rule, enforced.**
    ///
    /// The actor was asked to use a value it has not observed, derived,
    /// measured, brute-forced or brought with it. An attacker may only use what
    /// an attacker could actually have, and this is what that looks like when
    /// somebody asks for more.
    Unearned {
        /// What was asked for.
        wanted: &'static str,
        /// Why the actor does not have it.
        detail: String,
    },
    /// The attack ran out of material or out of candidates.
    Exhausted {
        /// Which attack.
        attack: &'static str,
        /// What ran out.
        detail: String,
    },
    /// A capture was expected to contain a complete Secure Channel handshake
    /// and did not.
    IncompleteHandshake {
        /// The PD address, if one was identified.
        address: Option<u8>,
        /// Which frame was missing.
        missing: &'static str,
    },
    /// A candidate key did not reproduce the captured handshake, so it is the
    /// wrong key.
    KeyRejected,
    /// The world model refused an operation.
    Bus(BusError),
    /// A secure-channel operation failed.
    Channel(ChannelError),
    /// An OSDP payload could not be decoded.
    Payload(PayloadError),
    /// A Wiegand card format rejected the data offered to it.
    Format(FormatError),
    /// A bit-buffer operation was out of range.
    Bits(BitError),
    /// A card-layer operation failed.
    Credential(CredentialError),
}

impl fmt::Display for AttackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackError::NotAttached { actor } => {
                write!(f, "{actor} is not clipped onto a link")
            }
            AttackError::WrongMedium { wanted, found } => {
                write!(f, "this actor needs {wanted}, but it is on {found}")
            }
            AttackError::Unearned { wanted, detail } => write!(
                f,
                "an attacker may only use what it could actually have: {wanted} ({detail})"
            ),
            AttackError::Exhausted { attack, detail } => {
                write!(f, "{attack} ran out: {detail}")
            }
            AttackError::IncompleteHandshake { address, missing } => match address {
                Some(a) => write!(f, "no {missing} for address {a:#04x} in the capture"),
                None => write!(f, "no {missing} in the capture"),
            },
            AttackError::KeyRejected => {
                write!(f, "the candidate key does not reproduce the handshake")
            }
            AttackError::Bus(e) => write!(f, "world model: {e}"),
            AttackError::Channel(e) => write!(f, "secure channel: {e}"),
            AttackError::Payload(e) => write!(f, "payload: {e}"),
            AttackError::Format(e) => write!(f, "card format: {e:?}"),
            AttackError::Bits(e) => write!(f, "bits: {e}"),
            AttackError::Credential(e) => write!(f, "credential: {e:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AttackError {}

impl From<BusError> for AttackError {
    fn from(e: BusError) -> Self {
        AttackError::Bus(e)
    }
}

impl From<ChannelError> for AttackError {
    fn from(e: ChannelError) -> Self {
        AttackError::Channel(e)
    }
}

impl From<PayloadError> for AttackError {
    fn from(e: PayloadError) -> Self {
        AttackError::Payload(e)
    }
}

impl From<FormatError> for AttackError {
    fn from(e: FormatError) -> Self {
        AttackError::Format(e)
    }
}

impl From<BitError> for AttackError {
    fn from(e: BitError) -> Self {
        AttackError::Bits(e)
    }
}

impl From<CredentialError> for AttackError {
    fn from(e: CredentialError) -> Self {
        AttackError::Credential(e)
    }
}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, AttackError>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn the_governing_rule_has_a_readable_message() {
        let e = AttackError::Unearned {
            wanted: "an SCBK",
            detail: "nothing has been recovered for this address".to_string(),
        };
        let text = alloc::format!("{e}");
        assert!(text.contains("an attacker may only use what it could actually have"));
        assert!(text.contains("an SCBK"));
    }

    #[test]
    fn every_variant_prints_something_useful() {
        let cases = alloc::vec![
            AttackError::NotAttached {
                actor: "sniffer".to_string(),
            },
            AttackError::WrongMedium {
                wanted: "a two-wire link",
                found: "rs485",
            },
            AttackError::Exhausted {
                attack: "weak key sweep",
                detail: "no handshake".to_string(),
            },
            AttackError::IncompleteHandshake {
                address: Some(1),
                missing: "CMD_CHLNG",
            },
            AttackError::IncompleteHandshake {
                address: None,
                missing: "REPLY_CCRYPT",
            },
            AttackError::KeyRejected,
        ];
        for e in cases {
            assert!(!alloc::format!("{e}").is_empty());
        }
    }
}
