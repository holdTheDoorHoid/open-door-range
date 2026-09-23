//! **The detectors themselves.**
//!
//! Eight rules, one module each. Every one of them answers the same two
//! questions, and the second one is the hard one:
//!
//! 1. Can this be seen from the wire at all?
//! 2. Can it be seen **without firing on benign traffic**?
//!
//! `docs/CURRICULUM.md` drill 5.2 is that second question made explicit: catch
//! the downgrade, and do not fire on a genuinely legacy reader being added to
//! the bus. Each detector here names the benign case it was most likely to trip
//! on, in its [`rationale`](crate::Detector::rationale) and in its rustdoc, and
//! the test suite runs each one against exactly that case and asserts silence.
//!
//! | Module | Detector | Signals |
//! |---|---|---|
//! | [`posture`] | [`PostureDetector`] | [`CleartextBus`](crate::Signal::CleartextBus), [`SensitiveCommandInClear`](crate::Signal::SensitiveCommandInClear) |
//! | [`keys`] | [`KeyDetector`] | [`DefaultKeyInUse`](crate::Signal::DefaultKeyInUse), [`NullCipher`](crate::Signal::NullCipher) |
//! | [`keyset`] | [`KeysetDetector`] | [`KeysetObserved`](crate::Signal::KeysetObserved) |
//! | [`downgrade`] | [`DowngradeDetector`] | [`CapabilityDowngrade`](crate::Signal::CapabilityDowngrade), [`SecureChannelLost`](crate::Signal::SecureChannelLost), [`DeviceIdentityChanged`](crate::Signal::DeviceIdentityChanged) |
//! | [`injection`] | [`InjectionDetector`] | [`SequenceAnomaly`](crate::Signal::SequenceAnomaly), [`CadenceViolation`](crate::Signal::CadenceViolation), [`UnsolicitedReply`](crate::Signal::UnsolicitedReply), [`DuplicateAddress`](crate::Signal::DuplicateAddress) |
//! | [`replay`] | [`ReplayDetector`] | [`ReplayedFrame`](crate::Signal::ReplayedFrame), [`ReplayedCredential`](crate::Signal::ReplayedCredential) |
//! | [`wire`] | [`WireDetector`] | [`UnauthenticatedWire`](crate::Signal::UnauthenticatedWire), [`MalformedCredential`](crate::Signal::MalformedCredential) |
//! | [`traffic`] | [`TrafficDetector`] | [`TrafficPatternExposed`](crate::Signal::TrafficPatternExposed) |
//!
//! # The gap rule, and what survives a gap
//!
//! Several detectors track continuity — sequence numbers, the command/reply
//! cadence — and continuity cannot be asserted across a silence. A monitor that
//! was unplugged for a minute, or a link that genuinely went quiet, has no
//! standing to say the next frame's sequence number is wrong. So every
//! continuity rule **resets after `gap_us` of silence** (30 seconds by
//! default).
//!
//! What does *not* reset is knowledge about a device. "Address 1 claimed
//! AES-128" is a fact about a reader, not about a stretch of wire, and a
//! monitor is entitled to remember it across an outage. That asymmetry is
//! deliberate and it is what makes [`DowngradeDetector`] work at all.

pub mod downgrade;
pub mod injection;
pub mod keys;
pub mod keyset;
pub mod posture;
pub mod replay;
pub mod traffic;
pub mod wire;

pub use downgrade::DowngradeDetector;
pub use injection::InjectionDetector;
pub use keys::KeyDetector;
pub use keyset::KeysetDetector;
pub use posture::PostureDetector;
pub use replay::{credential_events, unsolicited_replies, CredentialEvent, ReplayDetector};
pub use traffic::{badge_events, BadgeEvent, TrafficDetector};
pub use wire::WireDetector;

use odr_bus::Micros;

/// How long a silence has to be before a continuity rule forgets what it knew.
///
/// Thirty seconds is far longer than any OSDP poll interval and far shorter
/// than a coffee break. It is a parameter on every detector that uses it,
/// because the right value depends on the site's polling cadence and a
/// defender should be able to say so.
pub const DEFAULT_GAP_US: Micros = 30_000_000;
