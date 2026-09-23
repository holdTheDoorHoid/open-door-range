//! **`odr export` — a reference capture to compare hardware against.**
//!
//! Somebody with a bench needs something to hold their capture up to. These
//! scenarios are that: this is what the range believes a clean badge-in, a
//! cleartext OSDP bus, or a secure channel under the published default key
//! looks like, byte for byte. Run the same traffic on real equipment, capture
//! it, and point `odr verify` at both.
//!
//! # Built with `odr-bus`, deliberately
//!
//! `odr-scenario` owns drill definitions and flag predicates; this command does
//! not use it and does not want to. A reference capture should be the smallest
//! thing that produces the traffic in question, assembled from
//! [`WorldBuilder`](odr_bus::WorldBuilder) and the ready-made benches, so that
//! reading the scenario list tells you what is on the bus without opening a
//! drill definition.
//!
//! # The capture is taken from a probe, not from the world
//!
//! Every scenario clips a [`odr_bus::PassiveTap`] on and exports
//! from that, because that is what a real capture is: one probe point's view of
//! one segment. `World::export_capture` would mix every link in the world,
//! which no piece of test equipment can do.
//!
//! # And it carries `bits`
//!
//! `DESIGN.md` §3's second amendment makes `bits` optional and authoritative
//! when present. A scenario knows exactly how many bits went onto a two-wire
//! pair, so it says so — otherwise the reference capture would be ambiguous in
//! precisely the way the amendment exists to fix.

use odr_bus::capture::{export_from_tap, CaptureOptions};
use odr_bus::{
    clock_data_bench, osdp_bench, wiegand_bench, AccessList, AcuConfig, BusDir, InjectingTap,
    Injection, OsdpBenchSpec, PassiveTap, PdConfig, Presentation, Rs485Timing, ScRequirement,
    SourceId, Tap,
};
use odr_osdp::{Frame, Reply};
use odr_wiegand::{CardFormat, ClockDataTiming, Credential};

use crate::args::{parse_u64, Flags, UsageError};
use crate::json::Json;
use crate::out::pad_right;
use crate::Run;

/// Flags on this command that take a value.
pub const VALUE_FLAGS: &[&str] = &["scenario", "seed", "out"];

/// One thing this command can build.
struct Scenario {
    /// The name given to `--scenario`.
    name: &'static str,
    /// What is on the wire, in one line.
    summary: &'static str,
    /// What a contributor should compare against, in one or two sentences.
    detail: &'static str,
}

/// The scenarios, deliberately few.
///
/// Five, one per shape of traffic somebody with a bench can actually reproduce.
/// Anything more belongs in `odr-scenario` as a drill.
const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "wiegand-badge-in",
        summary: "one 26-bit H10301 card read on a D0/D1 pair, granted",
        detail: "Compare the bit pattern and the parity. This is the whole of the legacy \
                 interface: no authentication, no reply channel, one frame.",
    },
    Scenario {
        name: "clock-data-badge-in",
        summary: "the same card on an ABA track-2 clock-and-data pair",
        detail: "Exported with line \"clock_data\", which DESIGN.md section 3's first \
                 amendment added so a capture can say which of the two legacy protocols \
                 it recorded.",
    },
    Scenario {
        name: "osdp-clear",
        summary: "an OSDP bus with no secure channel: ID, CAP, POLL, and a card read",
        detail: "The commonest deployment there is. Compare the polling cadence, the \
                 sequence numbering, and REPLY_RAW's format byte and bit count.",
    },
    Scenario {
        name: "osdp-secure",
        summary: "the same bus running Secure Channel under SCBK-D",
        detail: "The four-frame handshake, then SCS_15/16 for empty payloads and \
                 SCS_17/18 for the card read. The interesting comparisons are the \
                 handshake payload lengths and which security block an empty payload \
                 gets — see odr-osdp's uncertainty ledger, entries 3 to 6.",
    },
    Scenario {
        name: "osdp-replay",
        summary: "a cleartext bus with a captured REPLY_RAW put back on it",
        detail: "For checking a defensive rule set: odr-detect should report the \
                 duplicated reply, and should say honestly that a well-formed injected \
                 command would not have been visible at all.",
    },
];

/// Run `odr export`.
pub fn run(mut flags: Flags) -> Run {
    let json = match flags.has("json") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let list = match flags.has("list") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let scenario = match flags.value("scenario") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let seed = match flags.value("seed") {
        Ok(Some(v)) => match parse_u64("seed", &v) {
            Ok(n) => n,
            Err(e) => return Run::usage(e),
        },
        Ok(None) => 1,
        Err(e) => return Run::usage(e),
    };
    let out_path = match flags.value("out") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    if let Err(e) = flags.finish() {
        return Run::usage(e);
    }

    if list || scenario.is_none() {
        return Run::ok(if json { list_json() } else { list_text() });
    }

    let name = scenario.unwrap_or_default();
    let known = match SCENARIOS.iter().find(|s| s.name == name) {
        Some(s) => s,
        None => {
            return Run::usage(UsageError::BadValue {
                flag: "scenario".to_string(),
                value: name,
                expected: format!(
                    "one of {}",
                    SCENARIOS
                        .iter()
                        .map(|s| s.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
        }
    };

    let capture = match build(&name, seed) {
        Ok(c) => c,
        Err(e) => return Run::failure(format!("scenario \"{name}\": {e}")),
    };

    let lines = capture.lines().filter(|l| !l.trim().is_empty()).count();

    if let Some(path) = out_path {
        if let Err(e) = std::fs::write(&path, &capture) {
            return Run::failure(format!("{path}: {e}"));
        }
        return Run::ok(if json {
            Json::obj()
                .with("command", Json::str("export"))
                .with("scenario", Json::str(known.name))
                .with("seed", Json::Num(seed))
                .with("events", Json::Num(lines as u64))
                .with("written_to", Json::str(&path))
                .render()
        } else {
            format!("wrote {lines} events to {path} (scenario {name}, seed {seed})\n")
        });
    }

    if json {
        return Run::ok(
            Json::obj()
                .with("command", Json::str("export"))
                .with("scenario", Json::str(known.name))
                .with("summary", Json::str(known.summary))
                .with("seed", Json::Num(seed))
                .with("events", Json::Num(lines as u64))
                .with("capture", Json::str(&capture))
                .render(),
        );
    }
    Run::ok(capture)
}

fn list_text() -> String {
    let mut s = String::from("odr export — reference captures\n\n");
    for sc in SCENARIOS {
        s.push_str(&format!("  {}  {}\n", pad_right(sc.name, 21), sc.summary));
        s.push_str(&format!("  {}  {}\n\n", pad_right("", 21), sc.detail));
    }
    s.push_str("Write one with:\n  odr export --scenario osdp-secure -o reference.ndjson\n");
    s
}

fn list_json() -> String {
    Json::obj()
        .with("command", Json::str("export"))
        .with(
            "scenarios",
            Json::arr(SCENARIOS.iter().map(|s| {
                Json::obj()
                    .with("name", Json::str(s.name))
                    .with("summary", Json::str(s.summary))
                    .with("detail", Json::str(s.detail))
            })),
        )
        .render()
}

// ---------------------------------------------------------------------------
// The scenarios themselves
// ---------------------------------------------------------------------------

/// A card everybody can recognise in a hex dump, and nobody's real badge.
fn demo_card() -> Credential {
    Credential::new(CardFormat::H10301, 42, 1337)
}

/// Build one scenario's capture.
fn build(name: &str, seed: u64) -> Result<String, odr_bus::BusError> {
    match name {
        "wiegand-badge-in" => wiegand_badge_in(seed),
        "clock-data-badge-in" => clock_data_badge_in(seed),
        "osdp-clear" => osdp(seed, false, false),
        "osdp-secure" => osdp(seed, true, false),
        "osdp-replay" => osdp(seed, false, true),
        _ => Ok(String::new()),
    }
}

fn wiegand_badge_in(seed: u64) -> Result<String, odr_bus::BusError> {
    let card = demo_card();
    let access = AccessList::new()
        .with_credential(&card)?
        .assuming(CardFormat::H10301);
    let mut bench = wiegand_bench(seed, access)?;
    let probe = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("probe")))?;
    let presented = Presentation::from_credential(SourceId(0), &card)?;
    bench.world.present(bench.reader, 1_000_000, presented)?;
    bench.world.run_until(3_000_000)?;
    let tap = bench.world.tap(probe)?;
    Ok(annotate_bits(
        &export_from_tap(tap, &CaptureOptions::default()),
        tap,
    ))
}

fn clock_data_badge_in(seed: u64) -> Result<String, odr_bus::BusError> {
    let card = demo_card();
    let access = AccessList::allow_all();
    let mut bench = clock_data_bench(seed, access, Default::default())?;
    let probe = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("probe")))?;
    let presented = Presentation::from_credential(SourceId(0), &card)?;
    bench.world.present(bench.reader, 1_000_000, presented)?;
    // A track-2 frame is long: one bit period per bit, and the default period
    // is a millisecond.
    let _ = ClockDataTiming::default();
    bench.world.run_until(5_000_000)?;
    let tap = bench.world.tap(probe)?;
    Ok(annotate_bits(
        &export_from_tap(
            tap,
            &CaptureOptions {
                distinguish_clock_data: true,
            },
        ),
        tap,
    ))
}

/// The three OSDP scenarios, which differ only in two booleans.
fn osdp(seed: u64, secure: bool, replay: bool) -> Result<String, odr_bus::BusError> {
    let card = demo_card();
    let access = AccessList::new()
        .with_credential(&card)?
        .assuming(CardFormat::H10301);

    let (acu, pd) = if secure {
        (
            AcuConfig::polling([0x01]).with_default_key(ScRequirement::IfAvailable),
            PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable),
        )
    } else {
        (AcuConfig::polling([0x01]), PdConfig::at(0x01))
    };

    let mut bench = osdp_bench(
        seed,
        OsdpBenchSpec {
            acu,
            pds: vec![pd],
            timing: Rs485Timing::at_baud(9600),
            access,
            start_polling_at_us: 0,
        },
    )?;
    let probe = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("probe")))?;
    let attacker = if replay {
        Some(
            bench
                .world
                .add_tap(bench.link, Box::new(InjectingTap::new("attacker")))?,
        )
    } else {
        None
    };

    let pd_id = bench.pd();
    bench.world.run_until(1_000_000)?;
    let presented = Presentation::from_credential(SourceId(0), &card)?;
    bench.world.present(pd_id, 1_000_000, presented)?;
    bench.world.run_until(3_000_000)?;

    if let Some(attacker) = attacker {
        // Put the reader's own card-read reply back on the bus, unchanged. On a
        // cleartext bus this is the whole attack; odr-detect's ReplayDetector
        // is what should notice it.
        //
        // The timing is not decoration. `odr-bus` has no carrier sense: a
        // transmission scheduled for a moment that turns out to be busy
        // collides, and a collision delivers nothing and leaves no trace in a
        // capture at all (odr-bus's ledger #4, odr-detect's "not detectable"
        // #9). So the injection aims at the middle of the gap after the last
        // frame the probe saw, which is what an attacker with a scope does.
        let (last_seen, captured) = {
            let tap = bench.world.tap(probe)?;
            (
                tap.seen().last().map(|s| s.t_us).unwrap_or(3_000_000),
                tap.seen()
                    .iter()
                    .filter_map(|s| s.frame())
                    .find(|f| f.reply_code() == Some(Reply::Raw)),
            )
        };
        if let Some(frame) = captured {
            bench.world.inject(
                attacker,
                Injection::bus_frame(last_seen + 60_000, BusDir::PdToAcu, clone_frame(&frame)),
            )?;
        }
        bench.world.run_until(5_000_000)?;
    }

    let tap = bench.world.tap(probe)?;
    Ok(export_from_tap(tap, &CaptureOptions::default()))
}

/// A frame is `Clone`; this exists only to name why one is being copied.
fn clone_frame(frame: &Frame) -> Frame {
    frame.clone()
}

/// Add the `bits` field to the two-wire lines of an exported capture.
///
/// `export_from_tap` emits one line per entry of the tap's buffer, in order, so
/// the true bit count of each two-wire event is right there beside it. See the
/// module docs for why this crate adds a field the exporter does not.
fn annotate_bits(ndjson: &str, tap: &dyn Tap) -> String {
    let seen = tap.seen();
    let mut out = String::with_capacity(ndjson.len() + seen.len() * 12);
    for (i, line) in ndjson.lines().enumerate() {
        let bits = seen.get(i).and_then(|s| s.bits.as_ref()).map(|b| b.len());
        match (bits, line.strip_suffix('}')) {
            (Some(n), Some(body)) => {
                out.push_str(body);
                out.push_str(&format!(",\"bits\":{n}}}"));
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    out
}
