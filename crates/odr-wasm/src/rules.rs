//! **The rule catalogue and the detection report, as JSON the site renders.**
//!
//! `site/ENGINE-API.md` §13. Module 5's drills ask a learner to *build* a
//! detection rule set, so the bridge has to carry two things it did not carry
//! before: the parts a rule set is built from, and enough of the score to show
//! a learner **why** their set fired where it should not have.
//!
//! Both are the engine's own data. [`catalog`] is a straight rendering of
//! `odr_detect::catalog::RULES` — every label, every sentence and every legal
//! range comes from the table the detectors themselves are configured from, so
//! the site cannot hold a stale copy of a bound. [`detection`] is a rendering
//! of `odr_detect::Score`, with the [`Finding`]s' own evidence attached: the
//! frames that justify each conclusion, their timestamps and their octets.
//!
//! # Why the evidence crosses the boundary at all
//!
//! A score without its reasoning teaches a learner to chase a number. The
//! entire argument of `odr-detect`'s README — and of curriculum Module 5 — is
//! that a finding is checkable: it cites frames, and
//! `Evidence::check` re-reads them. The site shows those citations beside the
//! finding so the learner can see the benign legacy reader their rule fired on
//! rather than being told they lost a point.
//!
//! # The caps, and why they are stated rather than silent
//!
//! A rule set tuned to alert on everything produces a couple of thousand
//! findings, and `docs/UI.md`'s rule is collapse, never remove. So the lists
//! here are capped and every list carries its **full** count beside the capped
//! one: the interface can say "13 of 2,169 shown" rather than quietly drawing
//! thirteen and letting the learner believe that is all there was.

use alloc::string::String;
use alloc::vec::Vec;

use odr_detect::catalog::{ParamKind, RuleSetSpec, PRESETS, RULES};
use odr_detect::{Episode, Expected, FalsePositive, Finding, Hit, Signal};
use odr_scenario::DetectionOutcome;

use crate::json::{b, nu, nz, s, Json};

/// How many findings of each kind cross the boundary.
///
/// Enough that a learner reading a bad score can see the shape of what went
/// wrong, and few enough that a 2,000-finding rule set does not send several
/// megabytes into a render path. The counts beside them are not capped.
const LIST_CAP: usize = 60;

/// How many cited frames per finding.
///
/// The detectors already truncate their own evidence — a four-hour cleartext
/// run cites six frames, first and last included — so this only bites on a
/// finding that cited more than a screenful anyway.
const FRAME_CAP: usize = 8;

// ---------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------

/// **Every selectable rule, its parameters and their legal ranges**, plus the
/// presets and what the learner currently has selected.
pub fn catalog(spec: &RuleSetSpec) -> Json {
    let mut o = Json::obj();
    o.set(
        "rules",
        Json::Arr(RULES.iter().map(|r| rule_json(r, spec)).collect()),
    )
    .set(
        "presets",
        Json::Arr(
            PRESETS
                .iter()
                .map(|(id, label, help)| {
                    let mut p = Json::obj();
                    p.set("id", s(*id))
                        .set("label", s(*label))
                        .set("help", s(*help))
                        .set(
                            "text",
                            s(RuleSetSpec::preset(id)
                                .map(|p| p.encode())
                                .unwrap_or_default()),
                        );
                    p
                })
                .collect(),
        ),
    )
    .set("selection", selection(spec));
    o
}

/// What the learner has selected right now, as one object.
pub fn selection(spec: &RuleSetSpec) -> Json {
    let mut o = Json::obj();
    o.set("text", s(spec.encode()))
        .set("name", s(spec.name()))
        .set(
            "preset",
            match spec.matching_preset() {
                Some(p) => s(p),
                None => Json::Null,
            },
        )
        .set("ruleCount", nz(spec.len()))
        .set(
            "signals",
            Json::Arr(spec.signals().iter().map(|x| signal_json(*x)).collect()),
        );
    o
}

fn rule_json(r: &odr_detect::RuleSpec, spec: &RuleSetSpec) -> Json {
    let chosen = spec.get(r.id);
    let mut o = Json::obj();
    o.set("id", s(r.id))
        .set("label", s(r.label))
        .set("catches", s(r.catches))
        .set("falsePositives", s(r.false_positives))
        .set("inStandard", b(r.in_standard))
        .set("selected", b(chosen.is_some()))
        .set(
            "signals",
            Json::Arr(r.signals.iter().map(|x| signal_json(*x)).collect()),
        )
        .set(
            "params",
            Json::Arr(
                r.params
                    .iter()
                    .map(|p| {
                        let (min, max) = p.kind.bounds();
                        let value = chosen.and_then(|c| c.value(p.id)).unwrap_or(p.default);
                        let mut pj = Json::obj();
                        pj.set("id", s(p.id))
                            .set("label", s(p.label))
                            .set("help", s(p.help))
                            .set("type", s(p.kind.name()))
                            .set("min", nu(min))
                            .set("max", nu(max))
                            .set("default", nu(p.default))
                            .set("value", nu(value))
                            .set("changed", b(value != p.default));
                        if matches!(p.kind, ParamKind::Duration { .. }) {
                            pj.set("unit", s("us"));
                        }
                        pj
                    })
                    .collect(),
            ),
        );
    o
}

fn signal_json(x: Signal) -> Json {
    let mut o = Json::obj();
    o.set("id", s(x.name())).set("describes", s(x.describe()));
    o
}

// ---------------------------------------------------------------------------
// The score, with its reasoning
// ---------------------------------------------------------------------------

/// **The detection outcome**: the day, the score, and every finding tied to the
/// frames that justify it.
pub fn detection(d: &DetectionOutcome, spec: &RuleSetSpec, ran: bool) -> Json {
    let score = &d.score;
    let mut totals = Json::obj();
    totals
        .set("findings", nz(score.findings()))
        .set("truePositives", nz(score.true_positives().len()))
        .set("falsePositives", nz(score.false_positives().len()))
        .set("falseNegatives", nz(score.false_negatives().len()))
        .set("ambiguous", nz(score.ambiguous().len()))
        .set("precisionPct", nu(u64::from(score.precision_pct())))
        .set("recallPct", nu(u64::from(score.recall_pct())))
        .set("quietOnBenign", b(score.is_quiet_on_benign()))
        .set("worstTimeToDetectUs", nu(score.worst_time_to_detect_us()))
        .set("meanTimeToDetectUs", nu(score.mean_time_to_detect_us()));

    let mut o = Json::obj();
    o.set("ran", b(ran))
        .set("ruleSet", selection(spec))
        .set("evidenceChecks", b(d.evidence_checks))
        .set("score", totals)
        .set(
            "caught",
            Json::Arr(capped(score.true_positives(), |h| hit_json(h, d))),
        )
        .set(
            "ambiguousHits",
            Json::Arr(capped(score.ambiguous(), |h| hit_json(h, d))),
        )
        .set(
            "missed",
            Json::Arr(capped(score.false_negatives(), |e| missed_json(e, d))),
        )
        .set(
            "falsePositives",
            Json::Arr(capped(score.false_positives(), |f| {
                false_positive_json(f, d)
            })),
        )
        .set(
            "benign",
            Json::Arr(
                d.benign()
                    .iter()
                    .map(|x| {
                        let mut bj = Json::obj();
                        bj.set("tUs", nu(x.t_us))
                            .set("durationUs", nu(x.duration_us))
                            .set("label", s(x.label.clone()))
                            .set(
                                "looksLike",
                                match x.looks_like {
                                    Some(sig) => s(sig.name()),
                                    None => Json::Null,
                                },
                            )
                            .set(
                                "episode",
                                match d.episode_at(x.t_us) {
                                    Some(e) => episode_json(e),
                                    None => Json::Null,
                                },
                            );
                        bj
                    })
                    .collect(),
            ),
        )
        .set(
            "episodes",
            Json::Arr(
                d.day
                    .timeline()
                    .iter()
                    .map(|span| {
                        let mut ej = Json::obj();
                        ej.set("id", s(span.episode.name()))
                            .set("describes", s(span.episode.describe()))
                            .set("startUs", nu(span.start_us))
                            .set("endUs", nu(span.start_us + span.duration_us));
                        ej
                    })
                    .collect(),
            ),
        )
        .set("listCap", nz(LIST_CAP))
        .set("summary", s(d.summary()));
    o
}

/// The first [`LIST_CAP`] of a slice, mapped. The full length is always
/// reported separately, so nothing is silently dropped.
fn capped<T, F: Fn(&T) -> Json>(items: &[T], f: F) -> Vec<Json> {
    items.iter().take(LIST_CAP).map(f).collect()
}

fn hit_json(h: &Hit, d: &DetectionOutcome) -> Json {
    let mut o = finding_json(&h.finding, d);
    o.set("label", s(h.expected.label.clone()))
        .set("verdict", s(h.expected.verdict.name()))
        .set("expectedUs", nu(h.expected.t_us))
        .set("latencyUs", nu(h.latency_us));
    o
}

fn missed_json(e: &Expected, d: &DetectionOutcome) -> Json {
    let mut o = Json::obj();
    o.set("signal", s(e.signal.name()))
        .set("describes", s(e.signal.describe()))
        .set("label", s(e.label.clone()))
        .set("verdict", s(e.verdict.name()))
        .set("tUs", nu(e.t_us))
        .set(
            "episode",
            match d.episode_at(e.t_us) {
                Some(ep) => episode_json(ep),
                None => Json::Null,
            },
        );
    o
}

fn false_positive_json(f: &FalsePositive, d: &DetectionOutcome) -> Json {
    let mut o = finding_json(&f.finding, d);
    o.set(
        "benign",
        match &f.benign {
            Some(label) => s(label.clone()),
            None => Json::Null,
        },
    );
    o
}

/// One finding, with the frames that justify it.
fn finding_json(f: &Finding, d: &DetectionOutcome) -> Json {
    let mut o = Json::obj();
    o.set("signal", s(f.what.name()))
        .set("describes", s(f.what.describe()))
        .set("tUs", nu(f.t_us))
        .set("severity", s(f.severity.name()))
        .set("confidence", s(f.confidence.name()))
        .set("note", s(f.evidence.note.clone()))
        .set("frameCount", nz(f.evidence.refs.len()))
        .set(
            "episode",
            match d.episode_at(f.t_us) {
                Some(e) => episode_json(e),
                None => Json::Null,
            },
        )
        .set(
            "frames",
            Json::Arr(
                f.evidence
                    .refs
                    .iter()
                    .take(FRAME_CAP)
                    .map(|r| {
                        let mut fj = Json::obj();
                        fj.set("index", nz(r.index))
                            .set("tUs", nu(r.t_us))
                            .set("summary", s(r.summary.clone()))
                            .set("hex", s(hex(&r.bytes)))
                            .set(
                                "bytes",
                                Json::Arr(
                                    r.bytes
                                        .iter()
                                        .map(|x| crate::json::n(f64::from(*x)))
                                        .collect(),
                                ),
                            );
                        fj
                    })
                    .collect(),
            ),
        );
    o
}

fn episode_json(e: Episode) -> Json {
    let mut o = Json::obj();
    o.set("id", s(e.name())).set("describes", s(e.describe()));
    o
}

/// Uppercase hex, space separated — the register the inspector already uses.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        for shift in [4, 0] {
            let nibble = (byte >> shift) & 0xF;
            out.push(
                char::from_digit(u32::from(nibble), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}
