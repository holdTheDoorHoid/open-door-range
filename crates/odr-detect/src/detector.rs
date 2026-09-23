//! **The detector framework: one rule, and a set of them.**
//!
//! A [`Detector`] is a pure function from a [`Monitor`] to a list of
//! [`Finding`]s. It is deliberately not a state machine fed one frame at a
//! time: several of the conclusions in `docs/CURRICULUM.md` Module 5 are only
//! reachable by looking backwards — "this address *used to* claim AES-128" —
//! and a detector that has to be handed history separately is a detector that
//! can be handed the wrong history.
//!
//! # Running a detector cannot fail
//!
//! There is no `Result` here. A detector that cannot reach a conclusion emits
//! nothing, or emits a finding with a low [`Confidence`](crate::Confidence).
//! "I could not tell" is the normal state of a bus, not an error.
//!
//! # A rule set is a learner's answer
//!
//! Module 5's flag is "the learner's rule set is run against a generated day of
//! traffic containing both attacks and benign events, and is scored on true
//! positives and false positives". [`RuleSet`] is that answer:
//! [`RuleSet::standard`] is the worked one, and a learner builds their own with
//! [`RuleSet::with`].
//!
//! ```
//! use odr_detect::{Monitor, RuleSet};
//!
//! let line = r#"{"t_us":0,"line":"rs485","dir":"acu_to_pd","bytes":"530108000460ba00"}"#;
//! let monitor = Monitor::from_capture(line).unwrap();
//! let report = RuleSet::standard().run(&monitor);
//! assert!(report.evidence_checks(&monitor));
//! ```

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::finding::{Finding, Report, Signal};
use crate::observe::Monitor;
use crate::rules;

/// One rule.
///
/// Implement this to add a rule of your own. The contract is the governing rule
/// of the crate: **everything you are allowed to know is in the `monitor`.** If
/// your detector needs a fact that is not in there, either infer it from the
/// traffic or accept that a defender could not have known it either.
pub trait Detector {
    /// A stable name, used in the UI and in a rule set's roster.
    fn name(&self) -> &str;

    /// The signals this detector can emit.
    ///
    /// Used to report coverage: a rule set that emits no
    /// [`Signal::CapabilityDowngrade`] cannot possibly catch curriculum 3.6,
    /// and [`RuleSet::covers`] says so before the capture is even generated.
    fn signals(&self) -> &'static [Signal];

    /// One sentence on what the rule looks for, and what it deliberately does
    /// not fire on.
    fn rationale(&self) -> &'static str;

    /// Examine a capture and report.
    fn run(&self, monitor: &Monitor) -> Vec<Finding>;
}

/// **A collection of detectors, run together.**
///
/// The order detectors are added in does not affect the result: [`Report::new`]
/// sorts findings into a canonical order, so the same capture and the same set
/// of rules always give the same report.
pub struct RuleSet {
    name: String,
    detectors: Vec<Box<dyn Detector>>,
}

impl core::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RuleSet")
            .field("name", &self.name)
            .field("detectors", &self.detectors.len())
            .finish()
    }
}

impl RuleSet {
    /// An empty rule set. A learner starts here.
    pub fn empty(name: impl Into<String>) -> RuleSet {
        RuleSet {
            name: name.into(),
            detectors: Vec::new(),
        }
    }

    /// **Every detector this crate ships**, which is the worked answer to
    /// curriculum 5.1–5.3.
    ///
    /// Each is default-configured. The ones with a false-positive trade-off —
    /// [`DowngradeDetector`](crate::rules::DowngradeDetector) and
    /// [`ReplayDetector`](crate::rules::ReplayDetector) in particular — are
    /// configured conservatively, which is the choice `README.md` argues for
    /// and the tests pin down.
    pub fn standard() -> RuleSet {
        RuleSet::empty("standard")
            .with(Box::new(rules::PostureDetector::default()))
            .with(Box::new(rules::KeyDetector::default()))
            .with(Box::new(rules::KeysetDetector::default()))
            .with(Box::new(rules::DowngradeDetector::default()))
            .with(Box::new(rules::InjectionDetector::default()))
            .with(Box::new(rules::ReplayDetector::default()))
            .with(Box::new(rules::WireDetector::default()))
            .with(Box::new(rules::TrafficDetector::default()))
    }

    /// Add a detector.
    pub fn with(mut self, detector: Box<dyn Detector>) -> RuleSet {
        self.detectors.push(detector);
        self
    }

    /// Add a detector in place.
    pub fn push(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// The rule set's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How many detectors are in it.
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// True if there are no detectors.
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// The detectors, for a roster in the UI.
    pub fn detectors(&self) -> impl Iterator<Item = &dyn Detector> {
        self.detectors.iter().map(|d| d.as_ref())
    }

    /// Every signal any detector in the set can emit, in [`Signal::ALL`] order.
    pub fn signals(&self) -> Vec<Signal> {
        Signal::ALL
            .iter()
            .copied()
            .filter(|s| self.covers(*s))
            .collect()
    }

    /// True if some detector in the set can emit this signal.
    ///
    /// Coverage is not correctness — a detector that emits the right signal for
    /// the wrong reason still scores badly — but the absence of coverage is a
    /// guaranteed false negative, and it is worth telling a learner before they
    /// run the day.
    pub fn covers(&self, signal: Signal) -> bool {
        self.detectors.iter().any(|d| d.signals().contains(&signal))
    }

    /// Run every detector and collect the findings.
    pub fn run(&self, monitor: &Monitor) -> Report {
        let mut out = Vec::new();
        for d in &self.detectors {
            out.extend(d.run(monitor));
        }
        Report::new(out)
    }

    /// The roster, one detector per line with its rationale.
    pub fn explain(&self) -> String {
        let mut s = alloc::format!("rule set \"{}\" — {} detectors\n", self.name, self.len());
        for d in &self.detectors {
            s.push_str(&alloc::format!("  {}: {}\n", d.name(), d.rationale()));
        }
        s
    }
}

impl Default for RuleSet {
    fn default() -> RuleSet {
        RuleSet::standard()
    }
}
