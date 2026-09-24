//! **The bench, as the collapsible groups `docs/UI.md` asks for.**
//!
//! The rule is *collapse, never remove*: every group states the thing that
//! matters on one summary line, and that line is also mirrored into the
//! always-visible bench strip. A learner wondering why their replay failed can
//! see that Secure Channel is on without opening anything.
//!
//! # These groups set as well as report
//!
//! Version 2 of the contract said they only reported, and said why: a bench
//! came from a [`ScenarioId`] and a seed, and
//! inventing a seam here would have meant this crate assembling worlds of its
//! own — a second, divergent definition of every bench above the crate whose
//! job is to define them.
//!
//! The seam now exists in the right place. `odr_scenario::options` owns it:
//! which options a bench accepts, what their legal values are, what each one
//! does, and what a value costs the drill that is loaded. **This module renders
//! that list and carries none of its own**, which is the same rule as before —
//! the bridge transports what the engine below decides.
//!
//! So a field is one of two things:
//!
//! * **settable** — it came from `odr_scenario::options::describe`, and
//!   `setConfig` rebuilds the bench through `scenario::build_with`;
//! * **fixed** — a value derived from the built world that is not a setting at
//!   all (the PD address, what the attacker ended up holding), or a setting
//!   this bench genuinely cannot express, which still has to be *visible*.
//!   `fixedReason` is `odr-scenario`'s own sentence about why.
//!
//! # What is deliberately not shown
//!
//! The card's facility code and number. `CardSetup` holds them, and drill 1.1's
//! flag is "submit the facility code and card number the engine transmitted".
//! Printing them in a panel would turn the drill into a lookup, so the card
//! group states the *technology*, which is what the group is for.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_bus::{ScRequirement, World};
use odr_scenario::ids::DrillId;
use odr_scenario::options::{self, BenchOptions, OptionKind, OptionSpec, OptionValue};
use odr_scenario::{Bench, CardSetup, ScenarioId};

use crate::bench::{Run, Tap};
use crate::json::{self, Json};

/// One field of a configuration group.
struct FieldSpec {
    id: String,
    label: String,
    kind: &'static str,
    value: Json,
    help: String,
    critical: bool,
    /// `None` when the field is settable.
    fixed_reason: Option<String>,
    /// `select` only.
    choices: Option<Vec<(String, String)>>,
    /// `number` only.
    range: Option<(i64, i64, &'static str)>,
    /// What this value costs the loaded drill. The control stays live.
    warning: Option<String>,
    /// The learner moved this away from the bench's own setting.
    changed: bool,
}

/// A read-only field: a value the built world reports that is not a setting.
fn derived(id: &str, label: &str, kind: &'static str, value: Json, help: &str) -> FieldSpec {
    FieldSpec {
        id: id.to_string(),
        label: label.to_string(),
        kind,
        value,
        help: help.to_string(),
        critical: false,
        fixed_reason: Some(String::from(
            "Read off the bench that was built. This is what the simulation did, not a control.",
        )),
        choices: None,
        range: None,
        warning: None,
        changed: false,
    }
}

/// A field this bench cannot express, shown anyway because "collapse, never
/// remove" means nothing that affects behaviour is invisible.
fn unsupported(
    scenario: ScenarioId,
    option_id: &'static str,
    label: &str,
    kind: &'static str,
    value: Json,
    help: &str,
) -> FieldSpec {
    FieldSpec {
        id: option_id.to_string(),
        label: label.to_string(),
        kind,
        value,
        help: help.to_string(),
        critical: false,
        fixed_reason: Some(
            options::unsupported_reason(scenario, option_id)
                .unwrap_or_else(|| String::from("This bench does not have one.")),
        ),
        choices: None,
        range: None,
        warning: None,
        changed: false,
    }
}

/// A settable field, straight from `odr-scenario`'s option list.
fn from_option(spec: &OptionSpec) -> FieldSpec {
    let (kind, value, choices, range) = match (&spec.kind, &spec.value) {
        (OptionKind::Boolean, OptionValue::Bool(v)) => ("boolean", json::b(*v), None, None),
        (OptionKind::Choice(cs), v) => (
            "select",
            json::s(v.as_string()),
            Some(
                cs.iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
            ),
            None,
        ),
        (OptionKind::Number { min, max, unit }, OptionValue::Number(n)) => (
            "number",
            json::n(*n as f64),
            None,
            Some((*min, *max, *unit)),
        ),
        // The two halves of an option always agree; this arm exists so the
        // match is total rather than because it can happen.
        (_, v) => ("select", json::s(v.as_string()), None, None),
    };
    FieldSpec {
        id: spec.id.to_string(),
        label: spec.label.to_string(),
        kind,
        value,
        help: spec.help.to_string(),
        critical: spec.critical,
        fixed_reason: None,
        choices,
        range,
        warning: spec.warning.clone(),
        changed: spec.changed,
    }
}

/// The groups, in the order the bench strip shows them.
pub fn groups(
    run: &Run,
    taps: &[Tap],
    scenario: ScenarioId,
    drill: Option<DrillId>,
    opts: &BenchOptions,
) -> Json {
    let bench = run.outcome.bench.as_ref();
    let specs = options::describe(scenario, drill, opts);
    Json::Arr(alloc::vec![
        card_group(bench, scenario, &specs),
        reader_group(bench, scenario, &specs),
        link_group(bench, scenario, &specs),
        security_group(bench, scenario, &specs),
        controller_group(bench, &specs),
        attacker_group(run, taps),
    ])
}

/// The settable fields belonging to one group, in the engine's own order.
fn for_group<'a>(specs: &'a [OptionSpec], group: &str) -> impl Iterator<Item = &'a OptionSpec> {
    let group = group.to_string();
    specs.iter().filter(move |s| s.group == group)
}

/// Which group, and what its summary line says. Separate from the fields so
/// the one assembler below takes a value rather than eight positional
/// arguments.
struct GroupHeader {
    id: &'static str,
    title: &'static str,
    node: &'static str,
    critical: bool,
    summary: String,
    alert: bool,
}

fn group(head: GroupHeader, mut fields: Vec<FieldSpec>, specs: &[OptionSpec]) -> Json {
    fields.extend(for_group(specs, head.id).map(from_option));
    let mut o = Json::obj();
    o.set("id", json::s(head.id))
        .set("title", json::s(head.title))
        .set("node", json::s(head.node))
        .set("critical", json::b(head.critical))
        .set("summary", json::s(head.summary))
        .set("alert", json::b(head.alert))
        .set(
            "fields",
            Json::Arr(fields.into_iter().map(render_field).collect()),
        );
    o
}

fn render_field(fs: FieldSpec) -> Json {
    let mut jf = Json::obj();
    jf.set("id", json::s(fs.id))
        .set("label", json::s(fs.label))
        .set("type", json::s(fs.kind))
        .set("value", fs.value)
        .set("help", json::s(fs.help))
        .set("critical", json::b(fs.critical))
        .set("changed", json::b(fs.changed));
    if let Some(choices) = fs.choices {
        jf.set(
            "options",
            Json::Arr(
                choices
                    .into_iter()
                    .map(|(v, label)| Json::Arr(alloc::vec![json::s(v), json::s(label)]))
                    .collect(),
            ),
        );
    }
    if let Some((min, max, unit)) = fs.range {
        jf.set("min", json::n(min as f64))
            .set("max", json::n(max as f64))
            .set("unit", json::s(unit));
    }
    match fs.fixed_reason {
        Some(reason) => {
            jf.set("fixed", json::b(true))
                .set("fixedReason", json::s(reason));
        }
        None => {
            jf.set("fixed", json::b(false));
        }
    }
    if let Some(w) = fs.warning {
        jf.set("warning", json::s(w));
    }
    jf
}

fn card_group(bench: Option<&Bench>, scenario: ScenarioId, specs: &[OptionSpec]) -> Json {
    // A Wiegand bench has no card *layer* — Module 0 is where the credential
    // itself is the subject — but it still has a token in its script, and what
    // technology that token is remains the thing this group is for.
    let from_script = bench
        .and_then(|bx| bx.primary_credential())
        .map(|c| c.format);
    let (name, note) = match bench.map(|b| &b.cards) {
        Some(CardSetup::Em4100 { .. }) => (
            "EM4100, 125 kHz",
            "No processor, no key, no challenge. It answers with the same bits every time.",
        ),
        Some(CardSetup::HidProx { .. }) => (
            "HID Prox H10301, 125 kHz",
            "Twenty-six bits of facility code and card number, over the air and then over the wire.",
        ),
        Some(CardSetup::MifareClassic { .. }) => (
            "MIFARE Classic 1k, 13.56 MHz",
            "Crypto1, broken in 2008, still on badges. Sector keys are recoverable from traffic.",
        ),
        Some(CardSetup::Desfire { .. }) => (
            "DESFire EV2, 13.56 MHz",
            "Real mutual authentication with real keys. The working contrast.",
        ),
        _ => match from_script {
            Some(fmt) => (
                fmt.name(),
                "The token the script presents. Module 0 is where the credential itself is the \
                 subject; here it is the thing the wire carries.",
            ),
            None => (
                "no card layer",
                "This bench starts at the wire. The credential is Module 0's subject.",
            ),
        },
    };
    let mut fields = alloc::vec![
        derived("type", "Type", "select", json::s(name), note),
        derived(
            "values",
            "Facility code / card number",
            "select",
            json::s("generated from the session seed"),
            "Deliberately not printed here. Drill 1.1's flag is to submit what the engine \
             transmitted, and a panel that showed it would make that a lookup.",
        ),
    ];
    if options::unsupported_reason(scenario, options::FORMAT).is_some() {
        if let Some(fmt) = from_script {
            fields.push(unsupported(
                scenario,
                options::FORMAT,
                "Credential format",
                "select",
                json::s(fmt.name()),
                "Which bit layout the reader emits and the panel is configured to believe.",
            ));
        }
    }
    group(
        GroupHeader {
            id: "card",
            title: "Credential",
            node: "card",
            critical: false,
            summary: format!("{name} — provisioned from the session seed"),
            alert: false,
        },
        fields,
        specs,
    )
}

fn reader_group(bench: Option<&Bench>, scenario: ScenarioId, specs: &[OptionSpec]) -> Json {
    let pd = bench.and_then(|b| {
        b.reader
            .and_then(|r| b.world.reader(r).ok())
            .and_then(|r| r.protocol.pd_config().cloned())
    });
    match pd {
        Some(pd) => {
            let aes = pd.capabilities.claims_aes128();
            group(
                GroupHeader {
                    id: "reader",
                    title: "Reader (PD)",
                    node: "reader",
                    critical: false,
                    summary: format!(
                        "PD {}, AES-128 {}",
                        pd.address,
                        if aes { "supported" } else { "NOT supported" }
                    ),
                    alert: !aes,
                },
                alloc::vec![derived(
                    "address",
                    "PD address",
                    "number",
                    json::n(f64::from(pd.address)),
                    "Bit 7 of the address byte carries direction, so an address is seven bits.",
                )],
                specs,
            )
        }
        None => group(
            GroupHeader {
                id: "reader",
                title: "Reader (PD)",
                node: "reader",
                critical: false,
                summary: String::from("legacy reader — one-way, nothing to talk back with"),
                alert: false,
            },
            alloc::vec![
                derived(
                    "protocol",
                    "Protocol",
                    "select",
                    json::s("Wiegand or clock-and-data"),
                    "A legacy reader drives a pair of wires and has no way of hearing a reply.",
                ),
                unsupported(
                    scenario,
                    options::PD_INSTALL,
                    "Reader install mode",
                    "boolean",
                    json::b(false),
                    "An uncommissioned reader takes a key from anything that asks.",
                ),
            ],
            specs,
        ),
    }
}

fn link_group(bench: Option<&Bench>, scenario: ScenarioId, specs: &[OptionSpec]) -> Json {
    let Some(bench) = bench else {
        return group(
            GroupHeader {
                id: "link",
                title: "Link",
                node: "link",
                critical: false,
                summary: String::from("no link — this section simulates nothing"),
                alert: false,
            },
            Vec::new(),
            specs,
        );
    };
    let (protocol, baud) = match bench.world.link(bench.link) {
        Ok(odr_bus::Link::Rs485(bus)) => ("OSDP over RS-485", Some(bus.timing.baud)),
        Ok(odr_bus::Link::ClockData(_)) => ("Clock-and-data (ABA track 2)", None),
        _ => ("Wiegand D0/D1", None),
    };
    let poll = bench
        .world
        .controllers()
        .filter_map(|c| c.mode.acu_config())
        .map(|c| 1_000_000.0 / c.poll_interval_us.max(1) as f64)
        .next();
    let mut summary = String::from(protocol);
    if let Some(b) = baud {
        summary.push_str(&format!(", {b} baud"));
    }
    if let Some(p) = poll {
        summary.push_str(&format!(", {p:.0} polls/s"));
    }
    let mut fields = Vec::new();
    if options::unsupported_reason(scenario, options::LINK).is_some() {
        fields.push(unsupported(
            scenario,
            options::LINK,
            "Wire protocol",
            "select",
            json::s(protocol),
            "Which physical layer sits between reader and panel.",
        ));
    }
    if options::unsupported_reason(scenario, options::BAUD).is_some() {
        fields.push(unsupported(
            scenario,
            options::BAUD,
            "Line rate",
            "select",
            json::s("n/a"),
            "The line rate of a bus. There is no bus here.",
        ));
    }
    if let Some(p) = poll {
        fields.push(derived(
            "pollRate",
            "Poll rate",
            "number",
            json::n(p),
            "What the poll interval works out to. Real installations poll hard, and the timeline \
             shows it honestly.",
        ));
    }
    group(
        GroupHeader {
            id: "link",
            title: "Link",
            node: "link",
            critical: false,
            summary,
            alert: false,
        },
        fields,
        specs,
    )
}

fn security_group(bench: Option<&Bench>, scenario: ScenarioId, specs: &[OptionSpec]) -> Json {
    let acu = bench.and_then(|b| {
        b.world
            .controllers()
            .filter_map(|c| c.mode.acu_config())
            .next()
            .cloned()
    });
    let Some(acu) = acu else {
        return group(
            GroupHeader {
                id: "security",
                title: "Secure Channel",
                node: "controller",
                critical: true,
                summary: String::from("OFF — there is no secure channel on a Wiegand pair, ever"),
                alert: true,
            },
            alloc::vec![unsupported(
                scenario,
                options::SECURE_CHANNEL,
                "Secure Channel",
                "boolean",
                json::b(false),
                "Whether the link runs an authenticated, encrypted channel.",
            )],
            specs,
        );
    };
    let on = acu.sc.wants_secure_channel();
    let key = match acu.key_type {
        odr_osdp::KeyType::Default => "SCBK-D (the published default)",
        _ if odr_osdp::weak_keys::is_weak(&acu.scbk) => "a key from the published sample family",
        _ => "site key",
    };
    let mode = if acu.encrypt_payloads {
        "SCS_17/18"
    } else {
        "SCS_15/16 (null cipher — MAC only)"
    };
    let mac_bits = u32::from(acu.mac_len) * 8;
    let summary = if on {
        format!("on, {key}, {mode}, {mac_bits}-bit MAC")
    } else {
        String::from("OFF — everything on this bus is in the clear")
    };
    group(
        GroupHeader {
            id: "security",
            title: "Secure Channel",
            node: "controller",
            critical: true,
            summary,
            alert: !on,
        },
        Vec::new(),
        specs,
    )
}

fn controller_group(bench: Option<&Bench>, specs: &[OptionSpec]) -> Json {
    let Some(bench) = bench else {
        return group(
            GroupHeader {
                id: "controller",
                title: "Controller (ACU)",
                node: "controller",
                critical: false,
                summary: String::from("no controller — this section simulates nothing"),
                alert: false,
            },
            Vec::new(),
            specs,
        );
    };
    let acu = bench
        .world
        .controllers()
        .filter_map(|c| c.mode.acu_config())
        .next()
        .cloned();
    let strike_ms = bench
        .world
        .door(bench.door)
        .map(|d| d.strike_time_us / 1000)
        .unwrap_or(0);
    let install = acu.as_ref().is_some_and(|a| a.install_mode);
    let requires = acu
        .as_ref()
        .is_some_and(|a| matches!(a.sc, ScRequirement::Required));
    let summary = format!(
        "{}{} · strike {:.1} s",
        if requires {
            "requires Secure Channel"
        } else if acu.as_ref().is_some_and(|a| a.sc.wants_secure_channel()) {
            "Secure Channel if available"
        } else {
            "accepts cleartext"
        },
        if install { " · INSTALL MODE ON" } else { "" },
        strike_ms as f64 / 1000.0
    );
    group(
        GroupHeader {
            id: "controller",
            title: "Controller (ACU)",
            node: "controller",
            critical: false,
            summary,
            alert: install,
        },
        Vec::new(),
        specs,
    )
}

fn attacker_group(run: &Run, taps: &[Tap]) -> Json {
    let knowledge = run.outcome.knowledge.as_ref();
    let keys = knowledge.map_or(0, |k| k.keys.len());
    let creds = knowledge.map_or(0, |k| k.credentials.len());
    let frames = knowledge.map_or(0, |k| k.frames.len());
    let summary = if taps.is_empty() {
        String::from("nothing clipped on — the bench runs untouched")
    } else {
        format!(
            "{} tap(s), running {} · {keys} key(s), {creds} credential(s), {frames} frame(s) held",
            taps.len(),
            run.runner.name()
        )
    };
    group(
        GroupHeader {
            id: "attacker",
            title: "Attacker position",
            node: "tap",
            critical: false,
            summary,
            alert: false,
        },
        alloc::vec![
            derived(
                "runner",
                "What the bench ran",
                "select",
                json::s(run.runner.name()),
                "The taps decide this. With the attack's tap fitted the drill's attack is \
                 performed; with a probe and nothing else it listens; with nothing clipped on the \
                 bench simply runs.",
            ),
            derived(
                "keys",
                "Keys recovered",
                "number",
                json::n(keys as f64),
                "Every one carries a provenance saying how it was obtained. Nothing here was \
                 handed to the attacker.",
            ),
            derived(
                "captured",
                "Frames held",
                "number",
                json::n(frames as f64),
                "Frames the attacker kept, payloads and all — readable or not.",
            ),
        ],
        &[],
    )
}

/// Whether the bench claims to be secured at all, before anything runs.
pub fn initial_posture(world: &World) -> bool {
    world
        .controllers()
        .filter_map(|c| c.mode.acu_config())
        .any(|c| c.sc.wants_secure_channel())
}
