//! What can go wrong while assembling or driving a drill.
//!
//! A panic in a browser is a dead tab (`DESIGN.md` §3), so nothing here
//! unwraps and nothing here aborts. Every failure is a value, including the
//! interesting ones — "that drill does not exist", "that submission is the
//! wrong shape for this drill" — because a learner has to be shown them.

use alloc::string::String;

use crate::ids::DrillId;

/// The result type used throughout this crate.
pub type Result<T> = core::result::Result<T, ScenarioError>;

/// Something went wrong building or running a drill.
///
/// Additive: new variants may appear, so match with a `_` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScenarioError {
    /// No drill in the catalogue has that id.
    UnknownDrill {
        /// What was asked for.
        id: String,
    },
    /// No scenario in the catalogue has that id.
    UnknownScenario {
        /// What was asked for.
        id: String,
    },
    /// The drill is reference prose and has no bench to build.
    ///
    /// Drill 0.6 (`docs/BYPASS.md`). Asking for its world is a caller bug
    /// rather than a runtime failure, so it says so rather than returning an
    /// empty world that would quietly look like a bench.
    NotSimulated {
        /// Which drill.
        drill: DrillId,
    },
    /// A learner submission of the wrong shape arrived — a list of times for a
    /// drill that wants a facility code, say.
    WrongSubmission {
        /// Which drill.
        drill: DrillId,
        /// What that drill wants.
        expected: &'static str,
    },
    /// The world refused an operation.
    Bus(odr_bus::BusError),
    /// An attacker actor refused, or its attack did not work.
    Attack(odr_attack::AttackError),
    /// The defensive half refused — usually a capture that would not parse.
    Detect(odr_detect::DetectError),
    /// A credential would not encode, or a card layer operation failed.
    Credential(String),
    /// The drill ran but did not reach the state it needed to reach, so there
    /// is nothing to evaluate.
    ///
    /// This is a bug in the scenario or in an engine beneath it, never a
    /// learner error: a learner who has not earned a flag gets an unearned
    /// [`Flag`](crate::Flag) with an `outstanding` list, not this.
    DidNotRun {
        /// Which drill.
        drill: DrillId,
        /// What was missing.
        detail: String,
    },
}

impl core::fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ScenarioError::UnknownDrill { id } => write!(f, "no such drill: {id}"),
            ScenarioError::UnknownScenario { id } => write!(f, "no such scenario: {id}"),
            ScenarioError::NotSimulated { drill } => {
                write!(f, "drill {drill} is reference prose and has no bench")
            }
            ScenarioError::WrongSubmission { drill, expected } => {
                write!(f, "drill {drill} expects {expected}")
            }
            ScenarioError::Bus(e) => write!(f, "world: {e}"),
            ScenarioError::Attack(e) => write!(f, "attacker: {e}"),
            ScenarioError::Detect(e) => write!(f, "monitor: {e}"),
            ScenarioError::Credential(d) => write!(f, "card layer: {d}"),
            ScenarioError::DidNotRun { drill, detail } => {
                write!(
                    f,
                    "drill {drill} did not reach its starting state: {detail}"
                )
            }
        }
    }
}

impl From<odr_bus::BusError> for ScenarioError {
    fn from(e: odr_bus::BusError) -> ScenarioError {
        ScenarioError::Bus(e)
    }
}

impl From<odr_attack::AttackError> for ScenarioError {
    fn from(e: odr_attack::AttackError) -> ScenarioError {
        ScenarioError::Attack(e)
    }
}

impl From<odr_detect::DetectError> for ScenarioError {
    fn from(e: odr_detect::DetectError) -> ScenarioError {
        ScenarioError::Detect(e)
    }
}

impl From<odr_wiegand::FormatError> for ScenarioError {
    fn from(e: odr_wiegand::FormatError) -> ScenarioError {
        ScenarioError::Credential(alloc::format!("{e}"))
    }
}

impl From<odr_credential::CredentialError> for ScenarioError {
    fn from(e: odr_credential::CredentialError) -> ScenarioError {
        ScenarioError::Credential(alloc::format!("{e:?}"))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ScenarioError {}
