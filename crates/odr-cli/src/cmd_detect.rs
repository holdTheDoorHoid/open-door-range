//! **`odr detect` — what a passive monitor on this link could conclude.**
//!
//! A thin front end on `odr-detect`, and thin on purpose. Every rule, every
//! severity and every confidence value here comes from that crate; this module
//! contributes formatting and an exit code and nothing else. If a finding looks
//! wrong, the argument is with `odr-detect`, which is where the benign-case
//! tests live.
//!
//! # Read the confidence, not just the signal
//!
//! `odr-detect`'s `Confidence` is a statement about *the link*, not about the
//! code. `ambiguous` means the observable is real and its cause cannot be
//! determined from traffic by anyone, ever — a `CMD_KEYSET` is both the worst
//! thing on the bus and undecidable. This command prints the confidence beside
//! every finding for that reason, and prints the evidence note, which carries
//! the benign explanation the rule considered.
//!
//! # Exit code
//!
//! 1 when any printed finding is `high` or `critical`. `--min-severity` moves
//! both the printing threshold and, with it, the exit code, so
//! `odr detect --min-severity critical` is a usable gate in a script.

use odr_detect::{Confidence, Finding, Monitor, Report, RuleSet, Severity};

use crate::args::{Flags, UsageError};
use crate::json::Json;
use crate::out::{fmt_us, heading, hex, pad_right};
use crate::{Run, EXIT_FINDINGS, EXIT_OK};

/// Flags on this command that take a value.
pub const VALUE_FLAGS: &[&str] = &["min-severity"];

/// Run `odr detect`.
pub fn run(mut flags: Flags) -> Run {
    let json = match flags.has("json") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let quiet = match flags.has("quiet") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let min = match flags.value("min-severity") {
        Ok(Some(v)) => match parse_severity(&v) {
            Some(s) => s,
            None => {
                return Run::usage(UsageError::BadValue {
                    flag: "min-severity".to_string(),
                    value: v,
                    expected: "one of info, low, medium, high, critical".to_string(),
                })
            }
        },
        Ok(None) => Severity::Info,
        Err(e) => return Run::usage(e),
    };
    let path = match flags.one_positional("capture") {
        Ok(p) => p,
        Err(e) => return Run::usage(e),
    };
    if let Err(e) = flags.finish() {
        return Run::usage(e);
    }

    // Loaded through this crate's own reader first, so that a malformed capture
    // is reported the same way by every command rather than through whichever
    // error type happens to be underneath.
    let capture = match crate::capture::Capture::load(&path) {
        Ok(c) => c,
        Err(e) => return Run::failure(e),
    };
    let text = to_capture_text(&capture);
    let monitor = match Monitor::from_capture(&text) {
        Ok(m) => m,
        Err(e) => return Run::failure(format!("{}: {e}", capture.label)),
    };

    let report = RuleSet::standard().run(&monitor);
    let shown: Vec<&Finding> = report
        .findings()
        .iter()
        .filter(|f| f.severity >= min)
        .collect();
    let alarming = shown.iter().any(|f| f.severity >= Severity::High);
    let evidence_holds = report.evidence_checks(&monitor);

    let out = if json {
        render_json(&capture.label, &monitor, &report, &shown, evidence_holds)
    } else {
        render_text(
            &capture.label,
            &monitor,
            &report,
            &shown,
            evidence_holds,
            quiet,
        )
    };

    Run {
        out,
        err: String::new(),
        code: if alarming { EXIT_FINDINGS } else { EXIT_OK },
    }
}

fn parse_severity(text: &str) -> Option<Severity> {
    Some(match text.trim().to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => return None,
    })
}

/// Re-serialise the loaded capture in the interchange format.
///
/// A round trip rather than handing the file straight over, so that a detector
/// sees exactly the events this tool's other commands report on — including the
/// sort by time — and never anything else in the file.
fn to_capture_text(capture: &crate::capture::Capture) -> String {
    let events: Vec<odr_bus::CaptureEvent> = capture
        .events
        .iter()
        .map(|e| odr_bus::CaptureEvent {
            t_us: e.t_us,
            line: e.line.clone(),
            dir: e.dir.clone(),
            bytes: e.bytes.clone(),
        })
        .collect();
    odr_bus::capture::write_ndjson(&events)
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

fn render_text(
    label: &str,
    monitor: &Monitor,
    report: &Report,
    shown: &[&Finding],
    evidence_holds: bool,
    quiet: bool,
) -> String {
    let mut s = String::new();
    s.push_str(&format!("odr detect — {label}\n"));
    s.push_str(&format!(
        "{} observations over {}, rule set \"standard\" (8 detectors)\n",
        monitor.len(),
        crate::out::fmt_dur(monitor.span_us())
    ));
    s.push_str(&format!(
        "{} findings, {} shown\n",
        report.len(),
        shown.len()
    ));

    if shown.is_empty() {
        s.push_str("\nno findings at or above the severity threshold.\n");
        s.push_str(
            "That is not the same as \"nothing happened\". odr-detect's README lists ten \
             things\na passive monitor cannot see at all — a well-formed injected frame on \
             an unsecured\nbus is first on it.\n",
        );
        return s;
    }

    heading(&mut s, "findings");
    for f in shown {
        s.push_str(&format!(
            "{}  {}  {}  {}\n",
            fmt_us(f.t_us),
            pad_right(
                &format!("[{}/{}]", f.severity.name(), f.confidence.name()),
                22
            ),
            pad_right(f.what.name(), 28),
            f.what.describe(),
        ));
        if quiet {
            continue;
        }
        if !f.evidence.note.is_empty() {
            s.push_str(&format!("    why    {}\n", f.evidence.note));
        }
        for r in &f.evidence.refs {
            s.push_str(&format!("    cited  {}\n", r.summary));
        }
        s.push('\n');
    }

    heading(&mut s, "reading this");
    s.push_str(
        "confidence is a statement about the link, not about the rule:\n\
         \x20 certain    the bytes say so, and nothing benign produces those bytes\n\
         \x20 probable   a benign explanation exists; this pattern fits the finding far better\n\
         \x20 possible   a benign explanation is plausible and was not excluded\n\
         \x20 ambiguous  the observable is real and its cause is not on the wire, for anyone\n",
    );
    s.push_str(&format!(
        "\nevidence citations {}.\n",
        if evidence_holds {
            "all re-checked against the capture and hold"
        } else {
            "DO NOT all hold — this is a bug in odr-detect, please report it"
        }
    ));
    s
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn render_json(
    label: &str,
    monitor: &Monitor,
    report: &Report,
    shown: &[&Finding],
    evidence_holds: bool,
) -> String {
    Json::obj()
        .with("command", Json::str("detect"))
        .with("capture", Json::str(label))
        .with("rule_set", Json::str("standard"))
        .with("observations", Json::Num(monitor.len() as u64))
        .with("span_us", Json::Num(monitor.span_us()))
        .with("findings_total", Json::Num(report.len() as u64))
        .with("evidence_checks", Json::Bool(evidence_holds))
        .with("findings", Json::arr(shown.iter().map(|f| finding_json(f))))
        .render()
}

fn finding_json(f: &Finding) -> Json {
    Json::obj()
        .with("t_us", Json::Num(f.t_us))
        .with("signal", Json::str(f.what.name()))
        .with("describes", Json::str(f.what.describe()))
        .with("severity", Json::str(f.severity.name()))
        .with("confidence", Json::str(f.confidence.name()))
        .with(
            "confidence_means",
            Json::str(confidence_means(f.confidence)),
        )
        .with("note", Json::str(&f.evidence.note))
        .with(
            "evidence",
            Json::arr(f.evidence.refs.iter().map(|r| {
                Json::obj()
                    .with("index", Json::Num(r.index as u64))
                    .with("t_us", Json::Num(r.t_us))
                    .with("bytes", Json::str(hex(&r.bytes)))
                    .with("summary", Json::str(&r.summary))
            })),
        )
}

fn confidence_means(c: Confidence) -> &'static str {
    match c {
        Confidence::Certain => "the bytes say so, and nothing benign produces those bytes",
        Confidence::Probable => {
            "a benign explanation exists, and this pattern fits the finding far better"
        }
        Confidence::Possible => "a benign explanation is plausible and was not excluded",
        Confidence::Ambiguous => {
            "the observable is real and its cause cannot be determined from traffic, by anyone"
        }
    }
}
