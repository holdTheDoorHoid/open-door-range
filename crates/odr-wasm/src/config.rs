//! **The bench, as the collapsible groups `docs/UI.md` asks for.**
//!
//! The rule is *collapse, never remove*: every group states the thing that
//! matters on one summary line, and that line is also mirrored into the
//! always-visible bench strip. A learner wondering why their replay failed can
//! see that Secure Channel is on without opening anything.
//!
//! # These groups report; they do not set
//!
//! The mock's controls changed a summary line and nothing else. The real engine
//! cannot do better, and it is worth saying exactly why rather than pretending:
//! a bench is assembled by [`odr_scenario::scenario::build`], which takes a
//! [`ScenarioId`](odr_scenario::ScenarioId) and a seed and nothing else. There
//! is no seam for "the same scenario with Secure Channel switched on", and
//! inventing one here would mean this crate assembling worlds of its own — a
//! second, divergent definition of every bench, sitting above the crate whose
//! whole job is to define them.
//!
//! So each field carries `fixed: true` and a sentence saying which drill to
//! open for the other setting. That keeps the rule `docs/UI.md` actually
//! states — nothing that changes the simulation is invisible — while refusing
//! to offer a control that would lie about what it does.
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
use odr_scenario::{Bench, CardSetup};

use crate::bench::{Run, Tap};
use crate::json::{self, Json};

/// One field of a configuration group.
struct FieldSpec {
    id: &'static str,
    label: &'static str,
    kind: &'static str,
    value: Json,
    help: &'static str,
    critical: bool,
}

fn f(
    id: &'static str,
    label: &'static str,
    kind: &'static str,
    value: Json,
    help: &'static str,
) -> FieldSpec {
    FieldSpec {
        id,
        label,
        kind,
        value,
        help,
        critical: false,
    }
}

/// Why every field is read-only. Shown under the control.
const FIXED: &str =
    "Fixed by this drill's bench. odr-scenario assembles a bench from a scenario and a seed, so \
     the way to see the other setting is to open the drill that uses it.";

/// The groups, in the order the bench strip shows them.
pub fn groups(run: &Run, taps: &[Tap]) -> Json {
    let bench = run.outcome.bench.as_ref();
    Json::Arr(alloc::vec![
        card_group(bench),
        reader_group(bench),
        link_group(bench),
        security_group(bench),
        controller_group(bench),
        attacker_group(run, taps),
    ])
}

fn group(
    id: &'static str,
    title: &'static str,
    node: &'static str,
    critical: bool,
    summary: String,
    alert: bool,
    fields: Vec<FieldSpec>,
) -> Json {
    let mut o = Json::obj();
    o.set("id", json::s(id))
        .set("title", json::s(title))
        .set("node", json::s(node))
        .set("critical", json::b(critical))
        .set("summary", json::s(summary))
        .set("alert", json::b(alert))
        .set(
            "fields",
            Json::Arr(
                fields
                    .into_iter()
                    .map(|fs| {
                        let mut jf = Json::obj();
                        jf.set("id", json::s(fs.id))
                            .set("label", json::s(fs.label))
                            .set("type", json::s(fs.kind))
                            .set("value", fs.value)
                            .set("help", json::s(fs.help))
                            .set("critical", json::b(fs.critical))
                            .set("fixed", json::b(true))
                            .set("fixedReason", json::s(FIXED));
                        jf
                    })
                    .collect(),
            ),
        );
    o
}

fn card_group(bench: Option<&Bench>) -> Json {
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
    group(
        "card",
        "Credential",
        "card",
        false,
        format!("{name} — provisioned from the session seed"),
        false,
        alloc::vec![
            f("type", "Type", "select", json::s(name), note),
            f(
                "values",
                "Facility code / card number",
                "select",
                json::s("generated from the session seed"),
                "Deliberately not printed here. Drill 1.1's flag is to submit what the engine \
                 transmitted, and a panel that showed it would make that a lookup.",
            ),
        ],
    )
}

fn reader_group(bench: Option<&Bench>) -> Json {
    let pd = bench.and_then(|b| {
        b.reader
            .and_then(|r| b.world.reader(r).ok())
            .and_then(|r| r.protocol.pd_config().cloned())
    });
    match pd {
        Some(pd) => {
            let aes = pd.capabilities.claims_aes128();
            group(
                "reader",
                "Reader (PD)",
                "reader",
                false,
                format!(
                    "PD {}, AES-128 {}",
                    pd.address,
                    if aes { "supported" } else { "NOT supported" }
                ),
                !aes,
                alloc::vec![
                    f(
                        "address",
                        "PD address",
                        "number",
                        json::n(f64::from(pd.address)),
                        "Bit 7 of the address byte carries direction, so an address is seven bits.",
                    ),
                    f(
                        "supportsCrypto",
                        "Supports AES-128",
                        "boolean",
                        json::b(aes),
                        "Reported in the PDCAP reply, function code 0x09. This is the entry the \
                         downgrade attack deletes.",
                    ),
                    f(
                        "installMode",
                        "PD in install mode",
                        "boolean",
                        json::b(pd.install_mode),
                        "An uncommissioned PD takes a key from anything that turns up claiming the \
                         default.",
                    ),
                ],
            )
        }
        None => group(
            "reader",
            "Reader (PD)",
            "reader",
            false,
            String::from("legacy reader — one-way, nothing to talk back with"),
            false,
            alloc::vec![f(
                "protocol",
                "Protocol",
                "select",
                json::s("Wiegand or clock-and-data"),
                "A legacy reader drives a pair of wires and has no way of hearing a reply.",
            )],
        ),
    }
}

fn link_group(bench: Option<&Bench>) -> Json {
    let Some(bench) = bench else {
        return group(
            "link",
            "Link",
            "link",
            false,
            String::from("no link — this section simulates nothing"),
            false,
            Vec::new(),
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
    group(
        "link",
        "Link",
        "link",
        false,
        summary,
        false,
        alloc::vec![
            f(
                "protocol",
                "Protocol",
                "select",
                json::s(protocol),
                "Which physical layer sits between reader and panel.",
            ),
            f(
                "baud",
                "Baud",
                "select",
                baud.map_or(json::s("n/a"), |b| json::s(b.to_string())),
                "The line rate. It is what makes an online MAC forgery cost what drill 4.2 says it \
                 costs.",
            ),
            f(
                "pollRate",
                "Poll rate",
                "select",
                poll.map_or(json::s("n/a"), |p| json::s(format!("{p:.0} / s"))),
                "Real installations poll hard. The timeline shows it honestly.",
            ),
        ],
    )
}

fn security_group(bench: Option<&Bench>) -> Json {
    let acu = bench.and_then(|b| {
        b.world
            .controllers()
            .filter_map(|c| c.mode.acu_config())
            .next()
            .cloned()
    });
    let Some(acu) = acu else {
        return group(
            "security",
            "Secure Channel",
            "controller",
            true,
            String::from("OFF — there is no secure channel on a Wiegand pair, ever"),
            true,
            alloc::vec![f(
                "enabled",
                "Secure Channel",
                "boolean",
                json::b(false),
                "Wiegand has no cryptography in its specification. There is nothing here to turn \
                 on.",
            )],
        );
    };
    let on = acu.sc.wants_secure_channel();
    let key = match acu.key_type {
        odr_osdp::KeyType::Default => "SCBK-D (the published default)",
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
        "security",
        "Secure Channel",
        "controller",
        true,
        summary,
        !on,
        alloc::vec![
            f(
                "enabled",
                "Secure Channel",
                "boolean",
                json::b(on),
                "OSDP ships with this off. Most deployments leave it off.",
            ),
            f(
                "key",
                "Base key",
                "select",
                json::s(key),
                "SCBK-D is printed in the specification. Everybody has it.",
            ),
            f(
                "mode",
                "Cipher mode",
                "select",
                json::s(mode),
                "SCS_15/16 are null ciphers. They authenticate and do not conceal.",
            ),
            FieldSpec {
                critical: mac_bits < 32,
                ..f(
                    "macBits",
                    "MAC length",
                    "select",
                    json::s(format!("{mac_bits} bits")),
                    "OSDP truncates to four bytes. Drill 4.2 rigs this bench shorter so a forgery \
                     completes while you watch, and says so.",
                )
            },
        ],
    )
}

fn controller_group(bench: Option<&Bench>) -> Json {
    let Some(bench) = bench else {
        return group(
            "controller",
            "Controller (ACU)",
            "controller",
            false,
            String::from("no controller — this section simulates nothing"),
            false,
            Vec::new(),
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
    let trusts = acu.as_ref().is_some_and(|a| a.trust_pdcap);
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
        "controller",
        "Controller (ACU)",
        "controller",
        false,
        summary,
        install,
        alloc::vec![
            f(
                "requireSecure",
                "Require Secure Channel",
                "boolean",
                json::b(requires),
                "If set, the controller refuses to run a PD that reports no crypto support — \
                 unless something rewrites that report.",
            ),
            FieldSpec {
                critical: install,
                ..f(
                    "installMode",
                    "Install mode",
                    "boolean",
                    json::b(install),
                    "A controller in install mode hands out the SCBK on request. Installers leave \
                     it on.",
                )
            },
            f(
                "trustPdcap",
                "Trust the PDCAP reply",
                "boolean",
                json::b(trusts),
                "Nothing authenticates a capability report, so this is the downgrade attack's \
                 target.",
            ),
            f(
                "strikeMs",
                "Strike time",
                "number",
                json::n(strike_ms as f64),
                "How long the door stays unlocked after a grant.",
            ),
        ],
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
        "attacker",
        "Attacker position",
        "tap",
        false,
        summary,
        false,
        alloc::vec![
            f(
                "runner",
                "What the bench ran",
                "select",
                json::s(run.runner.name()),
                "The taps decide this. With the attack's tap fitted the drill's attack is \
                 performed; with a probe and nothing else it listens; with nothing clipped on the \
                 bench simply runs.",
            ),
            f(
                "keys",
                "Keys recovered",
                "number",
                json::n(keys as f64),
                "Every one carries a provenance saying how it was obtained. Nothing here was \
                 handed to the attacker.",
            ),
            f(
                "captured",
                "Frames held",
                "number",
                json::n(frames as f64),
                "Frames the attacker kept, payloads and all — readable or not.",
            ),
        ],
    )
}

/// Whether the bench claims to be secured at all, before anything runs.
pub fn initial_posture(world: &World) -> bool {
    world
        .controllers()
        .filter_map(|c| c.mode.acu_config())
        .any(|c| c.sc.wants_secure_channel())
}
