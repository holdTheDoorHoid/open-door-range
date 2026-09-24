//! **Module 5 — the other chair.**
//!
//! Every earlier module replayed from a monitoring position, with the question
//! changed from *can I do this* to *could anybody have noticed*. This module
//! wires `odr-detect`'s day generator and scorer into three drills.
//!
//! # What the learner actually submits
//!
//! **A rule set they composed.** `docs/CURRICULUM.md` drill 5.2 says *build* a
//! detection rule, and [`RuleSetSpec`] is the buildable shape: a selection of
//! `odr-detect`'s rules with their parameters set, which
//! [`run_composed`] builds and runs against the same generated day. A learner
//! starting from `RuleSetSpec::standard()` and turning one toggle off is doing
//! exactly what the drill asks, and is scored on what that costs.
//!
//! `odr-detect`'s [`RuleSet`] itself is a list of trait objects, so it cannot
//! be a plain value inside [`Submission`](crate::Submission) — a caller that
//! ran a rule set elsewhere hands over its [`Report`] instead. That is not a
//! weakening: a report cites the frames that justify every finding and
//! [`Report::evidence_checks`](odr_detect::Report::evidence_checks) re-reads
//! them against the capture, so a report full of invented findings fails the
//! citation check before it ever reaches the scorer.
//!
//! # The answer key the rule set never sees
//!
//! [`odr_detect::generate_day`] returns two things that are deliberately kept
//! apart: a capture, which is newline-delimited JSON and is the only thing a
//! detector is given, and an answer key built from the *scenario script* —
//! what each episode was constructed to do. Scoring compares one against the
//! other.
//!
//! # Three verdicts, not two
//!
//! [`Verdict::Ambiguous`](odr_detect::Verdict) is why drill 5.3 can be honest.
//! A `CMD_KEYSET` on the bus is both the worst thing that can happen there and
//! completely undecidable: a commissioning and an attacker in install mode
//! produce identical traffic, and the only thing separating them is whether an
//! installer was booked, which is a change record rather than a capture. A
//! learner is neither rewarded for reporting it nor punished for it, which is
//! exactly the position a defender is in.

use alloc::string::String;
use alloc::vec::Vec;

use odr_detect::{
    generate_day, BenignEvent, Confidence, Day, DayOptions, Episode, Monitor, Report, RuleSet,
    RuleSetSpec, Score, Signal,
};

use crate::error::Result;

/// A day of traffic, a learner's findings, and how they scored.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionOutcome {
    /// The generated day: the capture, and the key that is kept away from it.
    pub day: Day,
    /// What the rule set reported.
    pub report: Report,
    /// How it did against the key.
    pub score: Score,
    /// Whether every citation in the report still names the bytes it claims to.
    pub evidence_checks: bool,
}

impl DetectionOutcome {
    /// When an episode starts and ends in the day's timeline.
    pub fn span(&self, episode: Episode) -> Option<(u64, u64)> {
        self.day
            .timeline()
            .iter()
            .find(|s| s.episode == episode)
            .map(|s| (s.start_us, s.start_us + s.duration_us))
    }

    /// Whether the report fired `signal` inside `episode`'s stretch of the day.
    ///
    /// The episodes are separate worlds concatenated with a minute of silence
    /// between them, so "inside this episode" is a real question with a real
    /// answer rather than a fudge.
    pub fn fired_during(&self, signal: Signal, episode: Episode) -> bool {
        match self.span(episode) {
            None => false,
            Some((from, to)) => self
                .report
                .of(signal)
                .any(|f| f.t_us >= from && f.t_us <= to),
        }
    }

    /// Whether any finding at all landed inside `episode`.
    pub fn any_finding_during(&self, episode: Episode) -> bool {
        match self.span(episode) {
            None => false,
            Some((from, to)) => self
                .report
                .findings()
                .iter()
                .any(|f| f.t_us >= from && f.t_us <= to),
        }
    }

    /// Whether the report's finding for `signal` admits it cannot be sure.
    pub fn is_ambiguous(&self, signal: Signal) -> bool {
        self.report
            .of(signal)
            .any(|f| f.confidence == Confidence::Ambiguous)
    }

    /// Which episode of the day a moment falls in, if it falls in one.
    ///
    /// What it is for is naming a false positive. "A downgrade was reported at
    /// t=349 s" tells a learner nothing; "a downgrade was reported during the
    /// reader-replacement episode" tells them which benign event their rule
    /// fired on and therefore which knob to turn. The episodes are separate
    /// worlds concatenated with a minute of silence between them, so a moment
    /// belongs to at most one of them.
    pub fn episode_at(&self, t_us: u64) -> Option<Episode> {
        self.day
            .timeline()
            .iter()
            .find(|s| t_us >= s.start_us && t_us <= s.start_us + s.duration_us)
            .map(|s| s.episode)
    }

    /// The benign events scattered through the day.
    ///
    /// Carried out to a caller so a rule editor can show a learner what is in
    /// the traffic that is *supposed* to look like an attack — before they run,
    /// not only after they have fired on one.
    pub fn benign(&self) -> &[BenignEvent] {
        self.day.key().benign()
    }

    /// A one-line summary for the flag's evidence list.
    pub fn summary(&self) -> String {
        alloc::format!(
            "{} findings; {} true positive(s), {} false positive(s), {} missed, {} ambiguous; \
             precision {}%, recall {}%",
            self.report.len(),
            self.score.true_positives().len(),
            self.score.false_positives().len(),
            self.score.false_negatives().len(),
            self.score.ambiguous().len(),
            self.score.precision_pct(),
            self.score.recall_pct(),
        )
    }
}

/// Generate the day drills 5.1 to 5.3 are scored against.
pub fn day(seed: u64) -> Result<Day> {
    Ok(generate_day(seed, &DayOptions::default())?)
}

/// Run a learner's rule set against a day and score it.
pub fn run_ruleset(day: &Day, rules: &RuleSet) -> Result<DetectionOutcome> {
    let monitor: Monitor = day.monitor()?;
    let report = rules.run(&monitor);
    Ok(score_report(day, &monitor, report))
}

/// **Run a rule set the learner composed**, against the same day and the same
/// answer key as any preset.
///
/// This is drill 5.2's actual exercise. There is no second scoring path and no
/// allowance for a composed set: it is built into an ordinary
/// [`RuleSet`] and handed the same capture, so a set that
/// alerts on everything scores exactly as badly as a hand-written one that
/// does — which `odr-detect`'s
/// `a_composed_set_tuned_to_alert_on_everything_scores_badly` pins down.
pub fn run_composed(day: &Day, spec: &RuleSetSpec) -> Result<DetectionOutcome> {
    run_ruleset(day, &spec.build())
}

/// Score findings that were produced elsewhere.
///
/// Used when the learner's rule set has already been run — the site holds the
/// rule set, this crate holds the key.
pub fn score_report(day: &Day, monitor: &Monitor, report: Report) -> DetectionOutcome {
    let evidence_checks = report.evidence_checks(monitor);
    let score = day.key().score(&report);
    DetectionOutcome {
        day: day.clone(),
        report,
        score,
        evidence_checks,
    }
}

/// **The signals a Module 3 attack is visible as, if it is visible at all.**
///
/// Drill 5.1 asks which of Module 3's attacks a passive monitor can see. This
/// list is the answer, and the interesting half is what is *missing* from it:
///
/// * **3.2, the default key** — [`Signal::DefaultKeyInUse`]. Visible with
///   certainty, because the key type is announced in the clear in the
///   handshake's key-type byte.
/// * **3.4, install mode** and **3.5, keyset capture** —
///   [`Signal::KeysetObserved`], and only ever ambiguously. The frame is
///   unmistakable and its authorisation is not in any frame.
/// * **3.6, the downgrade** — [`Signal::CapabilityDowngrade`], and only
///   probably: a monitor cannot prove the *earlier* capability claim was the
///   true one.
/// * **3.3, weak keys** — nothing. An attacker who captures a handshake and
///   sweeps 768 candidates on a laptop in the car park transmits nothing and
///   changes nothing. There is no signal for it because there is no observable,
///   and a rule set that claims to detect it is claiming something a defender
///   cannot have.
pub const MODULE_3_VISIBLE: &[Signal] = &[
    Signal::DefaultKeyInUse,
    Signal::KeysetObserved,
    Signal::CapabilityDowngrade,
];

/// The benign episodes drill 5.2's rule must stay quiet on.
///
/// A rule that alerts on any peripheral not claiming AES-128 catches the
/// downgrade and fires on every legacy reader ever installed. These two are the
/// traffic that separates a rule from a renaming of the problem.
pub const DOWNGRADE_FALSE_POSITIVE_CASES: &[Episode] =
    &[Episode::LegacyReaderAdded, Episode::ReaderReplaced];

/// **A rule set that catches more and cries wolf**, for drill 5.2's negative
/// half.
///
/// The difference from the standard set is that the downgrade rule stops
/// checking device identity across a capability change. That catches the
/// identity-spoofing variant of the attack — an implant that rewrites
/// `REPLY_PDID` as well as `REPLY_PDCAP`, which costs the attacker nothing —
/// and alerts on every reader swap in the building. Both halves of that trade
/// are real, and a learner should see the price rather than be told about it.
///
/// It is `odr-detect`'s [`RuleSet::strict`] preset, which is also reachable as
/// the composition `RuleSetSpec::preset("strict")` — the same four rules,
/// selectable one at a time in the rule editor.
pub fn strict_ruleset() -> RuleSet {
    RuleSet::strict()
}

/// The episodes carrying the Module 3 attacks, for drill 5.1's evidence list.
pub fn attack_episodes() -> Vec<Episode> {
    alloc::vec![
        Episode::DefaultKey,
        Episode::Commissioning,
        Episode::Downgrade,
    ]
}
