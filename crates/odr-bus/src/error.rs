//! The crate's error type.
//!
//! Nothing in `odr-bus` panics. Every fallible operation returns
//! [`BusError`], including the ones a caller is unlikely to get wrong, because
//! the engine also runs inside a browser where a panic is an unrecoverable
//! abort of the whole page.

use alloc::string::String;
use core::fmt;

use odr_osdp::channel::ChannelError;
use odr_osdp::frame::ParseError;
use odr_osdp::payload::PayloadError;
use odr_wiegand::{BitError, FormatError};

use crate::ids::{ControllerId, DoorId, LinkId, ReaderId, TapId};

/// Everything that can go wrong in the world model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusError {
    /// A reader handle does not name a reader in this world.
    UnknownReader(ReaderId),
    /// A controller handle does not name a controller in this world.
    UnknownController(ControllerId),
    /// A door handle does not name a door in this world.
    UnknownDoor(DoorId),
    /// A link handle does not name a link in this world.
    UnknownLink(LinkId),
    /// A tap handle does not name a tap in this world.
    UnknownTap(TapId),
    /// A component was borrowed re-entrantly. This is an engine bug rather
    /// than a caller error; it is an error instead of a panic so a browser
    /// session survives it.
    Reentered {
        /// What was being reached for.
        what: &'static str,
    },
    /// The link is not of the kind the operation needs — injecting OSDP bytes
    /// onto a Wiegand pair, say.
    WrongLinkKind {
        /// The link in question.
        link: LinkId,
        /// What the caller wanted.
        wanted: &'static str,
        /// What the link actually is.
        found: &'static str,
    },
    /// A node was attached to a link that does not connect to it.
    NotOnLink {
        /// The link.
        link: LinkId,
        /// A description of what was not attached.
        what: String,
    },
    /// A segment index is past the end of the link.
    NoSuchSegment {
        /// The link.
        link: LinkId,
        /// The index asked for.
        segment: u16,
    },
    /// The world was built with something missing or contradictory.
    Config(String),
    /// An OSDP secure-channel operation failed.
    Channel(ChannelError),
    /// An OSDP frame could not be parsed.
    Frame(ParseError),
    /// An OSDP payload could not be decoded.
    Payload(PayloadError),
    /// A Wiegand card format rejected the data offered to it.
    Format(FormatError),
    /// A bit-buffer operation was out of range.
    Bits(BitError),
    /// A capture file could not be read.
    Capture(crate::capture::CaptureError),
}

impl fmt::Display for BusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusError::UnknownReader(id) => write!(f, "no such reader: {id}"),
            BusError::UnknownController(id) => write!(f, "no such controller: {id}"),
            BusError::UnknownDoor(id) => write!(f, "no such door: {id}"),
            BusError::UnknownLink(id) => write!(f, "no such link: {id}"),
            BusError::UnknownTap(id) => write!(f, "no such tap: {id}"),
            BusError::Reentered { what } => write!(f, "{what} was already borrowed"),
            BusError::WrongLinkKind {
                link,
                wanted,
                found,
            } => write!(f, "{link} is a {found} link, not {wanted}"),
            BusError::NotOnLink { link, what } => write!(f, "{what} is not attached to {link}"),
            BusError::NoSuchSegment { link, segment } => {
                write!(f, "{link} has no segment {segment}")
            }
            BusError::Config(m) => write!(f, "scenario configuration: {m}"),
            BusError::Channel(e) => write!(f, "secure channel: {e:?}"),
            BusError::Frame(e) => write!(f, "frame: {e:?}"),
            BusError::Payload(e) => write!(f, "payload: {e:?}"),
            BusError::Format(e) => write!(f, "card format: {e:?}"),
            BusError::Bits(e) => write!(f, "bits: {e:?}"),
            BusError::Capture(e) => write!(f, "capture: {e}"),
        }
    }
}

impl From<ChannelError> for BusError {
    fn from(e: ChannelError) -> Self {
        BusError::Channel(e)
    }
}

impl From<ParseError> for BusError {
    fn from(e: ParseError) -> Self {
        BusError::Frame(e)
    }
}

impl From<PayloadError> for BusError {
    fn from(e: PayloadError) -> Self {
        BusError::Payload(e)
    }
}

impl From<FormatError> for BusError {
    fn from(e: FormatError) -> Self {
        BusError::Format(e)
    }
}

impl From<BitError> for BusError {
    fn from(e: BitError) -> Self {
        BusError::Bits(e)
    }
}

impl From<crate::capture::CaptureError> for BusError {
    fn from(e: crate::capture::CaptureError) -> Self {
        BusError::Capture(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BusError {}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, BusError>;
