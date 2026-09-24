//! **What a learner hands in, and the form the site draws to take it.**
//!
//! Seven drills plus the reference section ask the learner for something, and
//! `odr-scenario`'s [`Submission`] is a typed claim rather than an answer
//! string: a facility code, a set of byte offsets, sixteen bytes of cryptogram,
//! a list of times. Those are compared against values the engine generated from
//! its seed, so a different seed gives a different correct answer.
//!
//! The mock had no way to take a typed claim, so it approximated those
//! predicates by watching which field the learner opened in the decode tree.
//! That is exactly the shortcut this crate is not allowed to take, so the
//! contract grew a form: [`spec`] describes what this drill wants, in the
//! engine's own terms, and the site renders it. **The engine composes the
//! form** — drill 2.1's field list comes from the layout of the frame that
//! actually crossed the bus, so the site never has to know what an OSDP frame
//! contains.
//!
//! Module 5 is the exception, and for the reason `odr-scenario`'s `module5`
//! module gives: its input is a rule set, which is a list of trait objects
//! rather than a value. The form there chooses between rule sets the engine
//! then *runs*.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use odr_credential::desfire::AttackFailure;
use odr_scenario::submission::{FieldSpan, FrameField};
use odr_scenario::{Drill, Facts, Submission};

use crate::json::{self, Json};

/// Which rule set Module 5 runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleChoice {
    /// Nothing at all: the honest floor.
    #[default]
    Empty,
    /// `odr-detect`'s standard set.
    Standard,
    /// The strict downgrade rule, which catches more and cries wolf.
    Strict,
}

impl RuleChoice {
    /// Parse the value the form carries.
    pub fn parse(v: &str) -> RuleChoice {
        match v {
            "standard" => RuleChoice::Standard,
            "strict" => RuleChoice::Strict,
            _ => RuleChoice::Empty,
        }
    }

    /// The value the form carries.
    pub fn name(self) -> &'static str {
        match self {
            RuleChoice::Empty => "empty",
            RuleChoice::Standard => "standard",
            RuleChoice::Strict => "strict",
        }
    }
}

/// The three failures drill 0.5 asks a learner to recognise.
const FAILURES: [AttackFailure; 3] = [
    AttackFailure::NoStaticSecretToCopy,
    AttackFailure::ChallengeIsFreshEachExchange,
    AttackFailure::KeyNeverTransmitted,
];

/// A form field.
struct Sf {
    id: String,
    label: String,
    kind: &'static str,
    help: String,
    options: Vec<(String, String)>,
}

fn sf(
    id: impl Into<String>,
    label: impl Into<String>,
    kind: &'static str,
    help: impl Into<String>,
) -> Sf {
    Sf {
        id: id.into(),
        label: label.into(),
        kind,
        help: help.into(),
        options: Vec::new(),
    }
}

/// **The form this drill wants**, or `null` when it wants nothing.
///
/// `facts` is the run's own measurements, which is where drill 2.1's field list
/// comes from.
pub fn spec(drill: &Drill, facts: &Facts, values: &BTreeMap<String, String>) -> Json {
    let Some(prompt) = drill.submission else {
        if drill.id.module == 5 {
            return module5_spec(values);
        }
        return Json::Null;
    };
    let fields: Vec<Sf> = match (drill.id.module, drill.id.index) {
        (0, 1) => alloc::vec![sf(
            "tag_id",
            "Tag ID (40 bits)",
            "text",
            "Decimal, or hex with a leading 0x. Read it off the Tag ID field in the decode tree — \
             ten data nibbles, row parity stripped.",
        )],
        (0, 3) => alloc::vec![
            sf("facility_code", "Facility code", "number", "Eight bits, from the RF payload."),
            sf("card_number", "Card number", "number", "Sixteen bits."),
            sf(
                "bits",
                "The 26 bits the reader will emit",
                "text",
                "Twenty-six characters of 0 and 1, in transmission order, parity included. Predict \
                 them from the RF layer before you look at the wire.",
            ),
        ],
        (0, 5) => FAILURES
            .iter()
            .map(|fail| {
                sf(
                    format!("diag_{}", fail_key(*fail)),
                    fail.name(),
                    "boolean",
                    fail.explanation().chars().take(160).collect::<String>() + "…",
                )
            })
            .collect(),
        (0, 6) => alloc::vec![sf(
            "read",
            "I have read docs/BYPASS.md",
            "boolean",
            "This section simulates nothing and completes by being read. That is why it is marked \
             REFERENCE rather than filed under Bronze.",
        )],
        (1, 1) => alloc::vec![
            sf(
                "facility_code",
                "Facility code",
                "number",
                "Bits 1-8 of the D0/D1 frame."
            ),
            sf("card_number", "Card number", "number", "Bits 9-24."),
        ],
        (2, 1) => return layout_spec(prompt, facts, values),
        (3, 1) => alloc::vec![sf(
            "cryptogram",
            "Client cryptogram (16 bytes)",
            "text",
            "Thirty-two hex digits. Spaces are ignored. AES-ECB(S-ENC, RND.A ‖ RND.B).",
        )],
        (4, 1) => alloc::vec![sf(
            "times",
            "Badge-in times, in seconds",
            "text",
            "Comma-separated, one per badge-in, correct to a second. Read them off the reply codes \
             — you never need a key.",
        )],
        _ => Vec::new(),
    };
    if fields.is_empty() {
        return Json::Null;
    }
    form(prompt, fields, values)
}

fn fail_key(f: AttackFailure) -> &'static str {
    match f {
        AttackFailure::NoStaticSecretToCopy => "static",
        AttackFailure::ChallengeIsFreshEachExchange => "fresh",
        AttackFailure::KeyNeverTransmitted => "key",
    }
}

fn layout_spec(prompt: &str, facts: &Facts, values: &BTreeMap<String, String>) -> Json {
    let Some(layout) = &facts.frame_layout else {
        return form(
            "no card read has crossed the bus yet — run the bench and find REPLY_RAW",
            Vec::new(),
            values,
        );
    };
    let mut fields = Vec::new();
    for span in layout.required() {
        let name = span.field.name();
        fields.push(sf(
            format!("off_{name}"),
            format!("{name} — byte offset"),
            "number",
            "Counting from the first byte of the frame as it is shown in the inspector.",
        ));
        fields.push(sf(
            format!("len_{name}"),
            format!("{name} — length"),
            "number",
            "In bytes.",
        ));
    }
    form(prompt, fields, values)
}

fn module5_spec(values: &BTreeMap<String, String>) -> Json {
    let mut choice = sf(
        "ruleset",
        "Rule set to run against the day",
        "select",
        "A Module 5 drill submits a rule set, not a value: the engine runs it against a generated \
         day and scores the report against an answer key the rules never see. The empty set is the \
         honest floor — it catches nothing and cries wolf about nothing.",
    );
    choice.options = alloc::vec![
        (
            String::from("empty"),
            String::from("nothing at all (the floor)")
        ),
        (
            String::from("standard"),
            String::from("odr-detect's standard set")
        ),
        (
            String::from("strict"),
            String::from("strict downgrade rule — catches more, cries wolf")
        ),
    ];
    form(
        "a detection rule set, which the engine runs rather than compares",
        alloc::vec![choice],
        values,
    )
}

fn form(prompt: &str, fields: Vec<Sf>, values: &BTreeMap<String, String>) -> Json {
    let mut o = Json::obj();
    o.set("prompt", json::s(prompt)).set(
        "fields",
        Json::Arr(
            fields
                .into_iter()
                .map(|f| {
                    let mut jf = Json::obj();
                    jf.set("id", json::s(f.id.clone()))
                        .set("label", json::s(f.label))
                        .set("type", json::s(f.kind))
                        .set("help", json::s(f.help))
                        .set(
                            "value",
                            json::s(values.get(&f.id).cloned().unwrap_or_default()),
                        );
                    if !f.options.is_empty() {
                        jf.set(
                            "options",
                            Json::Arr(
                                f.options
                                    .into_iter()
                                    .map(|(v, l)| Json::Arr(alloc::vec![json::s(v), json::s(l)]))
                                    .collect(),
                            ),
                        );
                    }
                    jf
                })
                .collect(),
        ),
    );
    o
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Build the typed claim from what the learner typed.
///
/// `None` when the form is not filled in far enough to make a claim — which the
/// predicate then reports as outstanding, in its own words, rather than this
/// function guessing.
pub fn parse(
    drill: &Drill,
    facts: &Facts,
    values: &BTreeMap<String, String>,
) -> Option<Submission> {
    match (drill.id.module, drill.id.index) {
        (0, 1) => num(values.get("tag_id")?).map(Submission::TagId),
        (0, 3) => Some(Submission::Credential {
            facility_code: num(values.get("facility_code")?)?,
            card_number: num(values.get("card_number")?)?,
            bits: bits(values.get("bits")?)?,
        }),
        (0, 5) => {
            let picked: Vec<AttackFailure> = FAILURES
                .iter()
                .copied()
                .filter(|f| {
                    values
                        .get(&format!("diag_{}", fail_key(*f)))
                        .is_some_and(|v| v == "true")
                })
                .collect();
            if picked.is_empty() {
                None
            } else {
                Some(Submission::Diagnoses(picked))
            }
        }
        (0, 6) => values
            .get("read")
            .filter(|v| *v == "true")
            .map(|_| Submission::Acknowledged),
        (1, 1) => Some(Submission::Credential {
            facility_code: num(values.get("facility_code")?)?,
            card_number: num(values.get("card_number")?)?,
            bits: Vec::new(),
        }),
        (2, 1) => {
            let layout = facts.frame_layout.as_ref()?;
            let mut spans = Vec::new();
            for want in layout.required() {
                let name = want.field.name();
                let off = num(values.get(&format!("off_{name}"))?)? as usize;
                let len = num(values.get(&format!("len_{name}"))?)? as usize;
                spans.push(FieldSpan::new(field_by_name(name)?, off, len));
            }
            Some(Submission::FrameLayout(spans))
        }
        (3, 1) => {
            let raw = hex16(values.get("cryptogram")?)?;
            Some(Submission::Cryptogram(raw))
        }
        (4, 1) => {
            let text = values.get("times")?;
            let mut out = Vec::new();
            for part in text.split([',', ' ', '\n']) {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                out.push(seconds_to_us(part)?);
            }
            if out.is_empty() {
                None
            } else {
                Some(Submission::BadgeTimes(out))
            }
        }
        _ => None,
    }
}

fn field_by_name(name: &str) -> Option<FrameField> {
    Some(match name {
        "mark" => FrameField::Mark,
        "som" => FrameField::Som,
        "address" => FrameField::Address,
        "length" => FrameField::Length,
        "control" => FrameField::Control,
        "security-block" => FrameField::SecurityBlock,
        "id" => FrameField::Id,
        "payload" => FrameField::Payload,
        "mac" => FrameField::Mac,
        "crc" => FrameField::Crc,
        _ => return None,
    })
}

/// Decimal, or hex with a `0x` prefix.
fn num(v: &str) -> Option<u64> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    if let Some(rest) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).ok();
    }
    v.parse().ok()
}

/// A string of `0` and `1`, with anything else rejected.
fn bits(v: &str) -> Option<Vec<bool>> {
    let mut out = Vec::new();
    for c in v.chars() {
        match c {
            '0' => out.push(false),
            '1' => out.push(true),
            c if c.is_ascii_whitespace() || c == '_' => {}
            _ => return None,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Thirty-two hex digits.
fn hex16(v: &str) -> Option<[u8; 16]> {
    let digits: Vec<u8> = v
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .map(|c| c.to_digit(16).map(|d| d as u8))
        .collect::<Option<Vec<u8>>>()?;
    if digits.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in digits.chunks(2).enumerate() {
        out[i] = (pair[0] << 4) | pair[1];
    }
    Some(out)
}

/// `"13.7"` seconds to microseconds, without a float parse that could be
/// locale-sensitive.
fn seconds_to_us(v: &str) -> Option<u64> {
    let (whole, frac) = match v.split_once('.') {
        Some((w, f)) => (w, f),
        None => (v, ""),
    };
    let secs: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut micros = 0u64;
    let mut scale = 100_000u64;
    for c in frac.chars().take(6) {
        micros += u64::from(c.to_digit(10)?) * scale;
        scale /= 10;
    }
    Some(secs * 1_000_000 + micros)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_take_decimal_and_hex() {
        assert_eq!(num("42"), Some(42));
        assert_eq!(num("0x2A"), Some(42));
        assert_eq!(num(" "), None);
        assert_eq!(num("nope"), None);
    }

    #[test]
    fn seconds_become_microseconds() {
        assert_eq!(seconds_to_us("13.7"), Some(13_700_000));
        assert_eq!(seconds_to_us("0.05"), Some(50_000));
        assert_eq!(seconds_to_us("4"), Some(4_000_000));
    }

    #[test]
    fn a_cryptogram_is_thirty_two_hex_digits() {
        assert!(hex16("00112233445566778899AABBCCDDEEFF").is_some());
        assert!(hex16("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF").is_some());
        assert!(hex16("0011").is_none());
    }
}
