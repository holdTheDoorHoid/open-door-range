//! **Scoring a rule set — curriculum drills 5.1 to 5.3.**
//!
//! > *Flags:* the learner's rule set is run against a generated day of traffic
//! > containing both attacks and benign events, and is scored on true positives
//! > and false positives.
//!
//! The answer key is generated alongside the capture and kept **separate from
//! it**. The detector is handed the capture; the scorer is handed the key. That
//! separation is the whole architecture: a rule set that could see the key
//! would score perfectly and mean nothing.
//!
//! # Three verdicts, not two
//!
//! A scorer with only "attack" and "not attack" cannot represent the honest
//! answer to drill 5.3, which is that a `CMD_KEYSET` is a real event with an
//! undecidable cause. So [`Verdict`] has a third value, [`Verdict::Ambiguous`],
//! and a finding that matches one is counted on its own and excluded from both
//! precision and recall. A learner is neither rewarded for reporting a
//! commissioning nor punished for it — which is exactly the position a
//! defender is in.
//!
//! # Benign events are first-class
//!
//! [`AnswerKey::benign`] lists the things in the day that look like attacks and
//! are not: a legacy reader added, a person badging twice, a reader
//! power-cycling, an installer commissioning a door. They carry no expectation,
//! so a finding that lands on one is a plain false positive. **A scorer with no
//! benign traffic teaches a learner to alert on everything**, and this one
//! would rather cost a learner precision than let them get away with that.

use alloc::string::String;
use alloc::vec::Vec;

use odr_bus::Micros;

use crate::finding::{Finding, Report, Signal};
use crate::observe::fmt_us;

/// What kind of thing an expectation describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// Something was done to this link. Finding it is a true positive; missing
    /// it is a false negative.
    Attack,
    /// A real weakness in how the link is configured, rather than an event —
    /// a cleartext bus, the default key, a null cipher, an exposed schedule.
    /// Scored the same way as an attack, and separated from one because the
    /// remediation is completely different.
    Weakness,
    /// The observable is real and its cause cannot be determined from traffic.
    /// A finding here is counted separately and excluded from precision and
    /// recall; not finding it costs nothing either.
    Ambiguous,
}

impl Verdict {
    /// A short name for the UI.
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Attack => "attack",
            Verdict::Weakness => "weakness",
            Verdict::Ambiguous => "ambiguous",
        }
    }

    /// True if this verdict is scored for precision and recall.
    pub fn is_scored(self) -> bool {
        !matches!(self, Verdict::Ambiguous)
    }
}

/// One thing the key says is in the capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// Which signal should report it.
    pub signal: Signal,
    /// The earliest moment a detector could honestly have said it.
    pub t_us: Micros,
    /// How long after `t_us` a finding still counts as catching this.
    pub window_us: Micros,
    /// How it scores.
    pub verdict: Verdict,
    /// What it is, in a learner's words.
    pub label: String,
}

impl Expected {
    /// Build an expectation.
    pub fn new(
        signal: Signal,
        t_us: Micros,
        window_us: Micros,
        verdict: Verdict,
        label: impl Into<String>,
    ) -> Expected {
        Expected {
            signal,
            t_us,
            window_us,
            verdict,
            label: label.into(),
        }
    }

    /// True if a finding is close enough in time and carries the right signal.
    pub fn matches(&self, finding: &Finding) -> bool {
        finding.what == self.signal
            && finding.t_us >= self.t_us
            && finding.t_us <= self.t_us.saturating_add(self.window_us)
    }
}

/// Something in the capture that looks like an attack and is not.
///
/// Carried in the key so that a learner reading their own false positives can
/// see *what they fired on*, rather than only that they fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenignEvent {
    /// When it happened.
    pub t_us: Micros,
    /// How long it lasted.
    pub duration_us: Micros,
    /// What it was.
    pub label: String,
    /// The signal a naive rule would have raised on it.
    pub looks_like: Option<Signal>,
}

impl BenignEvent {
    /// Build one.
    pub fn new(
        t_us: Micros,
        duration_us: Micros,
        label: impl Into<String>,
        looks_like: Option<Signal>,
    ) -> BenignEvent {
        BenignEvent {
            t_us,
            duration_us,
            label: label.into(),
            looks_like,
        }
    }

    /// True if a finding landed inside this event.
    pub fn covers(&self, finding: &Finding) -> bool {
        finding.t_us >= self.t_us && finding.t_us <= self.t_us.saturating_add(self.duration_us)
    }
}

/// **The ground truth, kept away from the capture.**
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnswerKey {
    expected: Vec<Expected>,
    benign: Vec<BenignEvent>,
}

impl AnswerKey {
    /// An empty key.
    pub fn new() -> AnswerKey {
        AnswerKey::default()
    }

    /// Add an expectation.
    pub fn expect(&mut self, e: Expected) {
        self.expected.push(e);
    }

    /// Add a benign event.
    pub fn note_benign(&mut self, b: BenignEvent) {
        self.benign.push(b);
    }

    /// Everything the key expects, in time order.
    pub fn expected(&self) -> &[Expected] {
        &self.expected
    }

    /// The benign events in the capture.
    pub fn benign(&self) -> &[BenignEvent] {
        &self.benign
    }

    /// How many expectations are scored, excluding ambiguous ones.
    pub fn scored_len(&self) -> usize {
        self.expected
            .iter()
            .filter(|e| e.verdict.is_scored())
            .count()
    }

    /// Sort into time order. Called by the generator once the whole day is
    /// assembled, so scoring is deterministic.
    pub(crate) fn sort(&mut self) {
        self.expected
            .sort_by(|a, b| a.t_us.cmp(&b.t_us).then(a.signal.cmp(&b.signal)));
        self.benign.sort_by_key(|b| b.t_us);
    }

    /// Score a report against this key.
    pub fn score(&self, report: &Report) -> Score {
        let findings = report.findings();
        let mut used = alloc::vec![false; findings.len()];
        let mut hits = Vec::new();
        let mut ambiguous = Vec::new();
        let mut missed = Vec::new();

        for expected in &self.expected {
            let found = findings
                .iter()
                .enumerate()
                .find(|(i, f)| !used[*i] && expected.matches(f));
            match found {
                Some((i, f)) => {
                    used[i] = true;
                    let hit = Hit {
                        expected: expected.clone(),
                        finding: f.clone(),
                        latency_us: f.t_us.saturating_sub(expected.t_us),
                    };
                    if expected.verdict.is_scored() {
                        hits.push(hit);
                    } else {
                        ambiguous.push(hit);
                    }
                }
                None => {
                    if expected.verdict.is_scored() {
                        missed.push(expected.clone());
                    }
                }
            }
        }

        let false_positives: Vec<FalsePositive> = findings
            .iter()
            .enumerate()
            .filter(|(i, _)| !used[*i])
            .map(|(_, f)| FalsePositive {
                finding: f.clone(),
                benign: self
                    .benign
                    .iter()
                    .find(|b| b.covers(f))
                    .map(|b| b.label.clone()),
            })
            .collect();

        Score {
            hits,
            ambiguous,
            missed,
            false_positives,
            findings: findings.len(),
        }
    }
}

/// An expectation and the finding that caught it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// What the key said was there.
    pub expected: Expected,
    /// The finding that caught it.
    pub finding: Finding,
    /// How long after the earliest honest moment the detector said it.
    pub latency_us: Micros,
}

/// A finding that matched nothing in the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalsePositive {
    /// The finding.
    pub finding: Finding,
    /// The benign event it landed on, when it landed on one. `None` means it
    /// fired on nothing in particular, which is usually a tuning problem rather
    /// than a logic one.
    pub benign: Option<String>,
}

/// **How a rule set did.**
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Score {
    hits: Vec<Hit>,
    ambiguous: Vec<Hit>,
    missed: Vec<Expected>,
    false_positives: Vec<FalsePositive>,
    findings: usize,
}

impl Score {
    /// Expectations that were caught.
    pub fn true_positives(&self) -> &[Hit] {
        &self.hits
    }

    /// Findings that matched nothing the key expected.
    pub fn false_positives(&self) -> &[FalsePositive] {
        &self.false_positives
    }

    /// Expectations that were missed.
    pub fn false_negatives(&self) -> &[Expected] {
        &self.missed
    }

    /// Findings that matched an [`Verdict::Ambiguous`] expectation: correct
    /// observations of things whose cause the wire does not carry.
    pub fn ambiguous(&self) -> &[Hit] {
        &self.ambiguous
    }

    /// How many findings the rule set produced in total.
    pub fn findings(&self) -> usize {
        self.findings
    }

    /// True positives as a percentage of all scored findings, rounded down.
    ///
    /// Integer arithmetic on purpose: `DESIGN.md` §3 wants a score that is
    /// identical on every machine, and a rounded float is a bad way to get
    /// there.
    pub fn precision_pct(&self) -> u32 {
        let scored = self.hits.len() + self.false_positives.len();
        if scored == 0 {
            return 100;
        }
        (self.hits.len() as u64 * 100 / scored as u64) as u32
    }

    /// Expectations caught as a percentage of scored expectations.
    pub fn recall_pct(&self) -> u32 {
        let total = self.hits.len() + self.missed.len();
        if total == 0 {
            return 100;
        }
        (self.hits.len() as u64 * 100 / total as u64) as u32
    }

    /// The longest gap between an expectation's earliest honest moment and the
    /// finding that caught it.
    ///
    /// This is the number a defender actually cares about. A rule that catches
    /// everything six hours late has caught nothing.
    pub fn worst_time_to_detect_us(&self) -> Micros {
        self.hits.iter().map(|h| h.latency_us).max().unwrap_or(0)
    }

    /// The mean detection latency over the caught expectations.
    pub fn mean_time_to_detect_us(&self) -> Micros {
        if self.hits.is_empty() {
            return 0;
        }
        let total: u64 = self.hits.iter().map(|h| h.latency_us).sum();
        total / self.hits.len() as u64
    }

    /// The detection latency for one expectation, if it was caught.
    pub fn time_to_detect_us(&self, signal: Signal, at_us: Micros) -> Option<Micros> {
        self.hits
            .iter()
            .find(|h| h.expected.signal == signal && h.expected.t_us == at_us)
            .map(|h| h.latency_us)
    }

    /// True if nothing fired on benign traffic.
    ///
    /// The single most useful assertion in the suite: a rule set that catches
    /// less and never cries wolf is a better rule set than one that catches
    /// more and does.
    pub fn is_quiet_on_benign(&self) -> bool {
        self.false_positives.iter().all(|f| f.benign.is_none())
    }

    /// A scoreboard a learner can read.
    pub fn explain(&self) -> String {
        let mut s = alloc::format!(
            "{} findings — {} true positives, {} false positives, {} missed, {} ambiguous\n\
             precision {}%, recall {}%, worst time to detect {}\n",
            self.findings,
            self.hits.len(),
            self.false_positives.len(),
            self.missed.len(),
            self.ambiguous.len(),
            self.precision_pct(),
            self.recall_pct(),
            fmt_us(self.worst_time_to_detect_us())
        );
        for h in &self.hits {
            s.push_str(&alloc::format!(
                "  caught  [{}] {} — {} (after {})\n",
                h.expected.verdict.name(),
                h.expected.signal.name(),
                h.expected.label,
                fmt_us(h.latency_us)
            ));
        }
        for h in &self.ambiguous {
            s.push_str(&alloc::format!(
                "  noted   [ambiguous] {} — {} (neither right nor wrong)\n",
                h.expected.signal.name(),
                h.expected.label
            ));
        }
        for e in &self.missed {
            s.push_str(&alloc::format!(
                "  MISSED  [{}] {} — {} at {}\n",
                e.verdict.name(),
                e.signal.name(),
                e.label,
                fmt_us(e.t_us)
            ));
        }
        for f in &self.false_positives {
            match &f.benign {
                Some(b) => s.push_str(&alloc::format!(
                    "  FALSE   {} at {} — fired on: {}\n",
                    f.finding.what.name(),
                    fmt_us(f.finding.t_us),
                    b
                )),
                None => s.push_str(&alloc::format!(
                    "  FALSE   {} at {}\n",
                    f.finding.what.name(),
                    fmt_us(f.finding.t_us)
                )),
            }
        }
        s
    }
}
