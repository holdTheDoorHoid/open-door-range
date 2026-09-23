//! The crate's error type.
//!
//! Nothing in `odr-detect` panics. A detector is handed bytes that came off a
//! wire — which is to say bytes chosen by whoever was on that wire — and it
//! also runs inside a browser, where a panic is an unrecoverable abort of the
//! whole page.
//!
//! Note what is *not* here: running a detector cannot fail. A detector that
//! cannot reach a conclusion says so in a [`Finding`](crate::Finding)'s
//! confidence, or says nothing at all. "I could not analyse this traffic" is
//! not an error condition on a bus, it is the normal state of affairs.

use alloc::string::String;
use core::fmt;

use odr_bus::{BusError, CaptureError};

/// Everything that can go wrong in the defensive half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectError {
    /// A capture file could not be read.
    Capture(CaptureError),
    /// Generating a scored day needed the world model, and the world model
    /// said no.
    Bus(BusError),
    /// A generated day was asked for something contradictory — no episodes, or
    /// a gap so large the timestamps would overflow.
    Scenario(String),
}

impl fmt::Display for DetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectError::Capture(e) => write!(f, "capture: {e}"),
            DetectError::Bus(e) => write!(f, "world model: {e}"),
            DetectError::Scenario(s) => write!(f, "scenario: {s}"),
        }
    }
}

impl From<CaptureError> for DetectError {
    fn from(e: CaptureError) -> DetectError {
        DetectError::Capture(e)
    }
}

impl From<BusError> for DetectError {
    fn from(e: BusError) -> DetectError {
        DetectError::Bus(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DetectError {}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, DetectError>;
