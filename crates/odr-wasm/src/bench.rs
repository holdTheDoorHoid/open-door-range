//! **One run of a bench, projected into what the site draws.**
//!
//! The engine below `odr-wasm` is not incremental: `odr-scenario` builds a
//! bench, clips an attack onto it, runs the whole script and hands back an
//! [`Outcome`]. Everything the site asks for afterwards — the traffic list, the
//! timeline, the state at a cursor position, the flag — is a *projection of
//! that one run*, computed once here and then read.
//!
//! That is why `site/ENGINE-API.md` can promise synchronous accessors: the work
//! happens in `loadDrill` and in the tap controls, and every call on a render
//! path is a slice of a `Vec`.
//!
//! # Taps gate the simulation
//!
//! `site/ENGINE-API.md` §4 is categorical: if no tap can write to the link, the
//! engine must not produce injected frames, substituted credentials or the
//! door-open events that follow from them. The mock filtered canned rows. Here
//! the tap decides **which runner the drill is driven with**:
//!
//! | Learner's taps | Runner | What happens |
//! |---|---|---|
//! | satisfy the drill's [`TapPlan`](odr_scenario::TapPlan) list | [`run::solve`] | the attack is clipped on and performed |
//! | present, but not the ones the attack needs | [`run::observe_only`] | a passive probe, the script, no analysis |
//! | none | [`run::baseline`] | the bench with nothing clipped to it |
//!
//! Each plan consumes a **distinct** learner tap, so drill 4.3 — which needs an
//! inline implant *and* a separate passive analyser on the same pair — is not
//! satisfied by one inline tap doing both jobs.
//!
//! The bridge never decides a flag. It decides which of `odr-scenario`'s own
//! entry points to call, and `odr-scenario` decides the flag from the world
//! that came out.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_attack::knowledge::{KeyKind, ObservedFrame};
use odr_attack::shadow::ShadowSession;
use odr_bus::{
    BusDir, DecisionReason, Micros, Origin, RecordKind, ScDecline, ScEvent, SourceId, TapAction,
    World,
};
use odr_osdp::security::KeyType;
use odr_osdp::Frame;
use odr_scenario::ids::TapMode;
use odr_scenario::{run, Drill, Outcome};
use odr_wiegand::BitVec;

use crate::decode::{self, Field};

/// The attacker's own blank, as `odr-scenario`'s runner numbers tokens.
const ATTACKER_TOKEN: SourceId = SourceId(7);

/// Which of `odr-scenario`'s entry points a bench was driven with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runner {
    /// Nothing clipped on.
    Baseline,
    /// A passive probe clipped on and no analysis performed.
    ObserveOnly,
    /// The attack clipped on and performed.
    Solve,
}

impl Runner {
    /// The name the site shows.
    pub fn name(self) -> &'static str {
        match self {
            Runner::Baseline => "baseline",
            Runner::ObserveOnly => "observe-only",
            Runner::Solve => "solve",
        }
    }
}

/// A tap the learner has placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tap {
    /// Opaque id.
    pub id: String,
    /// `"card-reader"` or `"reader-controller"`.
    pub link_id: String,
    /// The mode.
    pub mode: TapMode,
    /// Whether Bronze placed it rather than the learner.
    pub pre_placed: bool,
}

/// Whether the taps on the bench satisfy the drill's plan, matching each plan
/// to a **distinct** tap.
pub fn plan_satisfied(drill: &Drill, taps: &[Tap]) -> bool {
    let mut used = alloc::vec![false; taps.len()];
    for plan in drill.taps {
        let want_link = plan.link.name();
        let hit = taps
            .iter()
            .enumerate()
            .position(|(i, t)| !used[i] && t.link_id == want_link && capable(t.mode, plan.mode));
        match hit {
            Some(i) => used[i] = true,
            None => return false,
        }
    }
    true
}

/// Can a tap in `have` mode do what a plan asking for `want` needs?
///
/// Everything can listen. Writing needs an injecting or inline tap. Cutting the
/// link needs an inline one and nothing else will do — which is the whole of
/// drill 1.4's hint.
fn capable(have: TapMode, want: TapMode) -> bool {
    match want {
        TapMode::Sniff => true,
        TapMode::Inject => matches!(have, TapMode::Inject | TapMode::Inline),
        TapMode::Inline => matches!(have, TapMode::Inline),
    }
}

/// Which runner this set of taps earns.
pub fn choose_runner(drill: &Drill, taps: &[Tap]) -> Runner {
    if plan_satisfied(drill, taps) {
        Runner::Solve
    } else if taps.is_empty() {
        Runner::Baseline
    } else {
        Runner::ObserveOnly
    }
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// What a frame row was built from, kept so the decode tree can be built on
/// demand rather than for all several thousand of them at once.
#[derive(Debug, Clone)]
pub enum Source {
    /// An OSDP frame off the bus.
    Osdp(Frame),
    /// A bit stream off a two-wire line or out of the air.
    Bits(BitVec),
}

/// The security facts about a frame, as `site/ENGINE-API.md` §6 shapes them.
#[derive(Debug, Clone, Default)]
pub struct Secure {
    /// Whether a security block is present.
    pub active: bool,
    /// `"SCS_17"`, or `None`.
    pub scs: Option<String>,
    /// The raw type byte.
    pub scs_byte: Option<u8>,
    /// Whether the payload is encrypted.
    pub encrypted: bool,
    /// MAC width in bits, as it goes on the wire.
    pub mac_bits: u32,
}

/// One row of the traffic list, and the material its detail is built from.
#[derive(Debug, Clone)]
pub struct FrameView {
    /// Opaque id, `"f12"`.
    pub id: String,
    /// Virtual microseconds.
    pub t_us: Micros,
    /// `"rf" | "wiegand" | "clockdata" | "rs485"`.
    pub line: &'static str,
    /// `"rf" | "wire" | "bus"`.
    pub lane: &'static str,
    /// `"acu_to_pd" | "pd_to_acu" | "card_to_reader" | "wire"`.
    pub dir: &'static str,
    /// `"POLL"`, `"RAW"`, `"D0/D1"`.
    pub label: String,
    /// The stable machine name drill filters key off.
    pub kind: String,
    /// One line of prose.
    pub summary: String,
    /// The teaching note, or empty.
    pub note: String,
    /// `"bus" | "card" | "reader" | "attacker"`.
    pub origin: &'static str,
    /// Whether a tap produced it.
    pub tapped: bool,
    /// `"hex"` or `"bits"`.
    pub view: &'static str,
    /// The octets on the wire.
    pub bytes: Vec<u8>,
    /// The security facts.
    pub secure: Secure,
    /// What to decode.
    pub source: Source,
    /// The recovered plaintext, when the attacker's key opened it.
    pub plaintext: Option<Vec<u8>>,
}

impl FrameView {
    /// The decode tree, built on demand.
    pub fn fields(&self) -> Vec<Field> {
        match &self.source {
            Source::Osdp(frame) => decode::osdp_fields(frame, self.plaintext.as_deref()),
            Source::Bits(bits) => {
                if self.lane == "rf" {
                    decode::rf_fields(bits, &self.summary)
                } else {
                    decode::wiegand_fields(bits, self.kind.ends_with("_substituted"))
                }
            }
        }
    }

    /// The bits, for a frame whose view is `"bits"`.
    pub fn bits(&self) -> Option<&BitVec> {
        match &self.source {
            Source::Bits(b) => Some(b),
            Source::Osdp(_) => None,
        }
    }

    /// Whether the bench can read this frame's payload.
    ///
    /// True on anything that was never encrypted, and true on an encrypted
    /// frame only when a key the attacker actually holds opened it.
    pub fn key_held(&self) -> bool {
        !self.secure.encrypted || self.plaintext.is_some()
    }
}

/// A timeline marker.
#[derive(Debug, Clone)]
pub struct Marker {
    /// When.
    pub t_us: Micros,
    /// What to print.
    pub label: String,
    /// `"card" | "grant" | "deny" | "attack" | "handshake"`.
    pub kind: &'static str,
}

/// A state change the cursor folds over.
#[derive(Debug, Clone)]
pub struct StateEvent {
    /// When.
    pub t_us: Micros,
    /// What changed.
    pub patch: Patch,
}

/// One field of the bench state.
#[derive(Debug, Clone)]
pub enum Patch {
    /// The door lock changed.
    Door(bool),
    /// The controller decided.
    Decision {
        /// Whether it granted.
        granted: bool,
        /// The credential it decided on, as prose.
        credential: Option<String>,
    },
    /// The secure channel moved.
    Sc {
        /// `"off" | "configured" | "established" | "downgraded"`.
        state: &'static str,
        /// `"SCS_17/18"` or `"SCS_15/16"`.
        scs: Option<String>,
        /// `"SCBK-D"` or `"SCBK"`.
        key: Option<String>,
    },
}

/// **One complete run, projected.**
#[derive(Debug)]
pub struct Run {
    /// Which runner produced it.
    pub runner: Runner,
    /// The outcome the predicate is evaluated against.
    pub outcome: Outcome,
    /// How long the bench runs for.
    pub duration_us: Micros,
    /// Every frame, in time order.
    pub frames: Vec<FrameView>,
    /// Frame id to index.
    pub index: BTreeMap<String, usize>,
    /// Timeline markers.
    pub markers: Vec<Marker>,
    /// State changes.
    pub events: Vec<StateEvent>,
    /// The secure-channel posture before anything happened.
    pub sc_initial: &'static str,
}

/// Drive one drill at the position the learner has put the bench in.
pub fn drive(drill: &Drill, seed: u64, taps: &[Tap]) -> Result<Run, String> {
    drive_with(drill, seed, taps, &odr_scenario::BenchOptions::default())
}

/// Drive one drill on a bench the learner has reconfigured.
///
/// [`BenchOptions::default()`](odr_scenario::BenchOptions) is [`drive`]
/// exactly — the scenario as its own definition has it.
pub fn drive_with(
    drill: &Drill,
    seed: u64,
    taps: &[Tap],
    opts: &odr_scenario::BenchOptions,
) -> Result<Run, String> {
    let runner = choose_runner(drill, taps);
    let outcome = match runner {
        Runner::Solve => run::solve_with(drill.id, seed, opts),
        Runner::ObserveOnly => match run::observe_only_with(drill.id, seed, opts) {
            // A scenario with no bench has nothing to clip a probe onto, so
            // the honest fallback is the baseline rather than an error page.
            Err(_) => run::baseline_with(drill.id, seed, opts),
            ok => ok,
        },
        Runner::Baseline => run::baseline_with(drill.id, seed, opts),
    }
    .map_err(|e| format!("{e}"))?;
    Ok(project_outcome(runner, outcome))
}

/// Turn an outcome into everything the site reads.
pub fn project_outcome(runner: Runner, outcome: Outcome) -> Run {
    let mut frames = Vec::new();
    let mut markers = Vec::new();
    let mut events = Vec::new();
    let mut duration_us = 0;
    let mut sc_initial = "off";

    if let Some(bench) = &outcome.bench {
        duration_us = bench.script.duration_us.max(bench.world.now());
        sc_initial = initial_sc(&bench.world);
        collect(&bench.world, &mut frames, &mut markers, &mut events);
        decrypt_what_the_attacker_can(&mut frames, &outcome, &bench.world);
    } else if let Some(det) = &outcome.facts.detection {
        // Module 5 has no bench: it scores a generated day seen from a
        // monitoring position, and the traffic list shows that capture.
        if let Ok(monitor) = det.day.monitor() {
            duration_us = monitor.end_us();
            collect_monitor(&monitor, &mut frames);
        }
        markers.extend(day_markers(&det.day));
        markers.extend(finding_markers(det));
    }

    if duration_us == 0 {
        // Drill 0.6 simulates nothing. A one-second axis keeps the transport
        // controls from dividing by zero.
        duration_us = 1_000_000;
    }

    frames.sort_by_key(|f| f.t_us);
    for (i, f) in frames.iter_mut().enumerate() {
        f.id = format!("f{}", i + 1);
    }
    let index = frames
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id.clone(), i))
        .collect();
    markers.sort_by_key(|m| m.t_us);
    events.sort_by_key(|e| e.t_us);

    Run {
        runner,
        outcome,
        duration_us,
        frames,
        index,
        markers,
        events,
        sc_initial,
    }
}

/// The posture the bench was commissioned with, before any handshake.
fn initial_sc(world: &World) -> &'static str {
    let wants = world
        .controllers()
        .filter_map(|c| c.mode.acu_config())
        .any(|c| c.sc.wants_secure_channel());
    if wants {
        "configured"
    } else {
        "off"
    }
}

/// Walk the event log once, building frames, markers and state changes.
fn collect(
    world: &World,
    frames: &mut Vec<FrameView>,
    markers: &mut Vec<Marker>,
    events: &mut Vec<StateEvent>,
) {
    let link_is_cut = world
        .log()
        .records()
        .iter()
        .any(|r| matches!(&r.kind, RecordKind::TapAction { action, .. } if matches!(action, TapAction::Replaced { .. } | TapAction::ReplacedBits { .. } | TapAction::Dropped { .. })));

    // The reader's most recent wire output, so an inline tap's downstream frame
    // can be labelled by whether it actually *changed* the bits, not merely by
    // being inline. A transparent implant that passes a frame through unaltered
    // is not a substitution, and calling it one contradicts the drill.
    let mut last_reader_wire_bits: Option<BitVec> = None;

    for record in world.log().records() {
        match &record.kind {
            RecordKind::CredentialPresented {
                source,
                bits,
                label,
                ..
            } => {
                let cloned = *source == ATTACKER_TOKEN;
                let describe = describe_bits(bits);
                frames.push(FrameView {
                    id: String::new(),
                    t_us: record.t_us,
                    line: "rf",
                    lane: "rf",
                    dir: "card_to_reader",
                    label: String::from("RF"),
                    kind: String::from("rf_present"),
                    summary: format!(
                        "card presented — {describe}{}",
                        label.as_ref().map_or(String::new(), |l| format!(" ({l})"))
                    ),
                    note: if cloned {
                        String::from(
                            "A writable tag carrying a number copied from somebody else's badge. \
                             The reader cannot tell.",
                        )
                    } else {
                        String::from(
                            "A tag with no processor, no key and no challenge. It shouts its \
                             number at anything that energises it.",
                        )
                    },
                    origin: if cloned { "attacker" } else { "card" },
                    tapped: false,
                    view: "bits",
                    bytes: odr_bus::capture::pack_bits(bits),
                    secure: Secure::default(),
                    source: Source::Bits(bits.clone()),
                    plaintext: None,
                });
                markers.push(Marker {
                    t_us: record.t_us,
                    label: String::from(if cloned {
                        "cloned tag presented"
                    } else {
                        "card presented"
                    }),
                    kind: "card",
                });
            }
            RecordKind::WireTx {
                origin, kind, bits, ..
            } => {
                let from_tap = matches!(origin, Origin::Tap(_));
                let line = match kind {
                    odr_bus::log::WireKind::Wiegand => "wiegand",
                    odr_bus::log::WireKind::ClockData => "clockdata",
                };
                let base = line;
                // An inline tap that emits the same bits it received has swapped
                // nothing; only a genuine change is a substitution.
                let changed =
                    from_tap && link_is_cut && last_reader_wire_bits.as_ref() != Some(bits);
                let relayed = from_tap && link_is_cut && !changed;
                if !from_tap {
                    last_reader_wire_bits = Some(bits.clone());
                }
                let k = if changed {
                    format!("{base}_substituted")
                } else if relayed {
                    format!("{base}_relayed")
                } else if from_tap {
                    format!("{base}_injected")
                } else {
                    String::from(base)
                };
                frames.push(FrameView {
                    id: String::new(),
                    t_us: record.t_us,
                    line,
                    lane: "wire",
                    dir: "wire",
                    label: String::from(if line == "wiegand" {
                        "D0/D1"
                    } else {
                        "CLK/DATA"
                    }),
                    summary: format!(
                        "{}-bit pulse train — {}{}",
                        bits.len(),
                        describe_bits(bits),
                        if changed {
                            " (substituted)"
                        } else if relayed {
                            " (passed through)"
                        } else if from_tap {
                            " (injected)"
                        } else {
                            ""
                        }
                    ),
                    note: if from_tap {
                        String::from(
                            "Driven onto the wire by the tap. The panel has no way to tell this \
                             from the reader's own output, because nothing on this link is signed.",
                        )
                    } else {
                        String::from(
                            "Idle high, one pulse per bit. There is no cryptography in this \
                             encoding to attack.",
                        )
                    },
                    kind: k,
                    origin: if from_tap { "attacker" } else { "reader" },
                    tapped: from_tap,
                    view: "bits",
                    bytes: odr_bus::capture::pack_bits(bits),
                    secure: Secure::default(),
                    source: Source::Bits(bits.clone()),
                    plaintext: None,
                });
            }
            RecordKind::BusTx {
                origin,
                dir,
                bytes,
                frame,
                ..
            } => {
                let Some(frame) = frame else { continue };
                frames.push(bus_frame(record.t_us, *origin, *dir, bytes, frame));
            }
            RecordKind::TapAction { action, .. } => {
                if let Some(label) = tap_action_label(action) {
                    markers.push(Marker {
                        t_us: record.t_us,
                        label,
                        kind: "attack",
                    });
                }
            }
            RecordKind::AccessDecision {
                granted,
                bits,
                reason,
                ..
            } => {
                events.push(StateEvent {
                    t_us: record.t_us,
                    patch: Patch::Decision {
                        granted: *granted,
                        credential: credential_label(bits, reason),
                    },
                });
                if !*granted {
                    markers.push(Marker {
                        t_us: record.t_us,
                        label: String::from("access denied"),
                        kind: "deny",
                    });
                }
            }
            RecordKind::StrikeFired { .. } => {
                markers.push(Marker {
                    t_us: record.t_us,
                    label: String::from("STRIKE FIRES — door opens"),
                    kind: "grant",
                });
            }
            RecordKind::DoorLock { locked, .. } => {
                events.push(StateEvent {
                    t_us: record.t_us,
                    patch: Patch::Door(!*locked),
                });
            }
            RecordKind::SecureChannel { event, .. } => {
                sc_event(record.t_us, event, markers, events);
            }
            _ => {}
        }
    }
}

fn sc_event(
    t_us: Micros,
    event: &ScEvent,
    markers: &mut Vec<Marker>,
    events: &mut Vec<StateEvent>,
) {
    match event {
        ScEvent::Requested { .. } => markers.push(Marker {
            t_us,
            label: String::from("secure channel handshake"),
            kind: "handshake",
        }),
        ScEvent::Established {
            key_type,
            encrypted,
            ..
        } => {
            markers.push(Marker {
                t_us,
                label: String::from("secure channel up"),
                kind: "handshake",
            });
            events.push(StateEvent {
                t_us,
                patch: Patch::Sc {
                    state: "established",
                    scs: Some(String::from(if *encrypted {
                        "SCS_17/18"
                    } else {
                        "SCS_15/16 (null cipher)"
                    })),
                    key: Some(String::from(match key_type {
                        KeyType::Default => "SCBK-D",
                        _ => "SCBK",
                    })),
                },
            });
        }
        ScEvent::Declined { reason, .. } => {
            if *reason == ScDecline::PdDoesNotClaimAes128 {
                markers.push(Marker {
                    t_us,
                    label: String::from("downgrade accepted — link runs in the clear"),
                    kind: "attack",
                });
                events.push(StateEvent {
                    t_us,
                    patch: Patch::Sc {
                        state: "downgraded",
                        scs: None,
                        key: None,
                    },
                });
            }
        }
        ScEvent::KeysetSent { secured, .. } => markers.push(Marker {
            t_us,
            label: String::from(if *secured {
                "CMD_KEYSET — site key pushed inside a channel"
            } else {
                "CMD_KEYSET — site key pushed in the clear"
            }),
            kind: "attack",
        }),
        ScEvent::Dropped { .. } => events.push(StateEvent {
            t_us,
            patch: Patch::Sc {
                state: "configured",
                scs: None,
                key: None,
            },
        }),
        ScEvent::Failed { .. } | ScEvent::KeysetAccepted { .. } => {}
    }
}

fn tap_action_label(action: &TapAction) -> Option<String> {
    match action {
        TapAction::Dropped { what } => Some(format!("tap swallowed {what}")),
        TapAction::Replaced { .. } => Some(String::from("tap rewrote a frame in flight")),
        TapAction::ReplacedBits { .. } => Some(String::from("credential substituted")),
        TapAction::Injected { len } => Some(format!("attacker injected {len} bytes")),
        TapAction::VerdictIgnored { reason } => {
            Some(format!("tap could not alter the wire: {reason}"))
        }
        TapAction::Note(_) => None,
    }
}

fn credential_label(bits: &BitVec, reason: &DecisionReason) -> Option<String> {
    if let DecisionReason::Unreadable { .. } = reason {
        return Some(String::from("unreadable"));
    }
    odr_wiegand::decode(odr_wiegand::CardFormat::H10301, bits)
        .ok()
        .and_then(|d| match (d.facility_code, d.card_number) {
            (Some(f), Some(c)) => Some(format!("{f}/{c}")),
            _ => None,
        })
}

fn describe_bits(bits: &BitVec) -> String {
    odr_wiegand::decode(odr_wiegand::CardFormat::H10301, bits)
        .ok()
        .and_then(|d| match (d.facility_code, d.card_number) {
            (Some(f), Some(c)) => Some(format!("FC {f} / {c}")),
            _ => None,
        })
        .unwrap_or_else(|| format!("{} bits, {}", bits.len(), bits.to_hex_string()))
}

/// One OSDP frame on the bus.
fn bus_frame(t_us: Micros, origin: Origin, dir: BusDir, bytes: &[u8], frame: &Frame) -> FrameView {
    let from_tap = matches!(origin, Origin::Tap(_));
    let name = decode::code_name(frame);
    let mut kind = name.to_lowercase();
    if kind == "rmac_i" {
        kind = String::from("rmac_i");
    }
    let downgraded = frame.reply_code() == Some(odr_osdp::Reply::PdCap)
        && from_tap
        && odr_osdp::payload::PdCapabilities::decode(&frame.payload)
            .map(|c| !c.entries.iter().any(|e| e.function_code == 0x09))
            .unwrap_or(false);
    if downgraded {
        kind = String::from("pdcap_downgraded");
    } else if from_tap {
        kind = format!("{kind}_injected");
    }

    let scs = frame.scs_type();
    let secure = Secure {
        active: frame.security.is_some(),
        scs: scs.map(decode::scs_name),
        scs_byte: frame.security.as_ref().map(|s| s.raw_type),
        encrypted: frame.is_encrypted(),
        mac_bits: if frame.mac.is_some() { 32 } else { 0 },
    };

    let summary = bus_summary(frame, &name, from_tap, downgraded);
    let note = bus_note(frame, from_tap, downgraded);

    FrameView {
        id: String::new(),
        t_us,
        line: "rs485",
        lane: "bus",
        dir: match dir {
            BusDir::AcuToPd => "acu_to_pd",
            BusDir::PdToAcu => "pd_to_acu",
        },
        label: name,
        kind,
        summary,
        note,
        origin: if from_tap {
            "attacker"
        } else if matches!(origin, Origin::Reader(_)) {
            "reader"
        } else {
            "bus"
        },
        tapped: from_tap,
        view: "hex",
        bytes: bytes.to_vec(),
        secure,
        source: Source::Osdp(frame.clone()),
        plaintext: None,
    }
}

fn bus_summary(frame: &Frame, name: &str, from_tap: bool, downgraded: bool) -> String {
    use odr_osdp::codes::Reply;
    if downgraded {
        return String::from("PDCAP — as the controller received it, security entry deleted");
    }
    let tail = if from_tap { " (attacker)" } else { "" };
    match frame.reply_code() {
        Some(Reply::Raw) if !frame.is_encrypted() => {
            match odr_osdp::payload::RawCardRead::decode(&frame.payload) {
                Ok(read) => {
                    let bits = decode::unpack_bits(&read.data, usize::from(read.bit_count));
                    format!("RAW — card read, {}{tail}", describe_bits(&bits))
                }
                Err(_) => format!("RAW — card read{tail}"),
            }
        }
        Some(Reply::Raw) => String::from("RAW — card read (sealed)"),
        Some(Reply::Ccrypt) => String::from("CCRYPT — cUID, RND.B, client cryptogram"),
        Some(Reply::RmacI) => String::from("RMAC_I — MAC chain seeded"),
        Some(Reply::PdCap) => String::from("PDCAP — as the reader sent it"),
        Some(Reply::Nak) => format!("NAK — {}", frame.payload.first().copied().unwrap_or(0)),
        _ => match frame.command_code() {
            Some(odr_osdp::Command::Chlng) => String::from("CHLNG — RND.A"),
            Some(odr_osdp::Command::Scrypt) => String::from("SCRYPT — server cryptogram"),
            Some(odr_osdp::Command::Keyset) => {
                String::from("KEYSET — the site key, on the link it protects")
            }
            Some(odr_osdp::Command::Out) => format!("OUT — energise strike{tail}"),
            _ => format!("{name}{tail}"),
        },
    }
}

fn bus_note(frame: &Frame, from_tap: bool, downgraded: bool) -> String {
    use odr_osdp::codes::{Command, Reply};
    if downgraded {
        return String::from(
            "The 0x09 communication-security entry is gone. The controller now believes it is \
             talking to a reader that cannot do AES, and will talk to it in the clear.",
        );
    }
    if from_tap {
        return String::from(
            "Put on the bus by the attacker, not by the controller. Nothing in an OSDP frame says \
             who wrote it.",
        );
    }
    match (frame.command_code(), frame.reply_code()) {
        (Some(Command::Poll), _) => String::from(
            "The heartbeat. Tens of these a second, forever, whether or not anything is \
             happening. That density is the whole of drill 4.1.",
        ),
        (_, Some(Reply::Raw)) if frame.is_encrypted() => String::from(
            "You can see that a card was read. You cannot see whose. The reply code told you the \
             first half for free.",
        ),
        (_, Some(Reply::Raw)) => String::from(
            "The credential, in the clear, on a bus sold as the secure replacement for Wiegand. No \
             key was needed to read this.",
        ),
        (Some(Command::Keyset), _) => String::from(
            "The site key crossing the link it exists to protect. There is no key exchange in \
             OSDP, so commissioning simply sends it.",
        ),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Decryption, when the attacker holds a key
// ---------------------------------------------------------------------------

/// Open what the attacker's own recovered key opens, and nothing else.
///
/// `sealed` in `site/ENGINE-API.md` §6 is how "we hold the key" is expressed,
/// and this is the only thing that fills it in. The key comes from the
/// attacker's [`Knowledge`](odr_attack::Knowledge) — so on drill 4.1, whose
/// predicate insists the attacker held no key at any point, every encrypted
/// payload stays sealed and the lesson survives.
fn decrypt_what_the_attacker_can(frames: &mut [FrameView], outcome: &Outcome, world: &World) {
    let Some(knowledge) = outcome.knowledge.as_ref() else {
        return;
    };
    let keys: Vec<_> = knowledge
        .keys
        .iter()
        .filter(|k| k.value.kind == KeyKind::Scbk)
        .map(|k| k.value.clone())
        .collect();
    if keys.is_empty() {
        return;
    }
    let mac_len = world
        .controllers()
        .filter_map(|c| c.mode.acu_config())
        .map(|c| c.mac_len)
        .next()
        .unwrap_or(4);

    let observed: Vec<ObservedFrame> = frames
        .iter()
        .filter_map(|f| match &f.source {
            Source::Osdp(frame) => Some(ObservedFrame {
                t_us: f.t_us,
                dir: if f.dir == "pd_to_acu" {
                    BusDir::PdToAcu
                } else {
                    BusDir::AcuToPd
                },
                frame: frame.clone(),
            }),
            Source::Bits(_) => None,
        })
        .collect();

    for key in keys {
        let address = key
            .address
            .or_else(|| observed.first().map(|f| f.frame.address & 0x7F));
        let Some(address) = address else { continue };
        let Ok(mut session) =
            ShadowSession::reconstruct(key.key, KeyType::SiteKey, mac_len, address, &observed)
        else {
            continue;
        };
        let opened = session.replay(&observed);
        let by_time: BTreeMap<(Micros, u8), Vec<u8>> = opened
            .into_iter()
            .map(|d| ((d.t_us, d.id), d.plaintext))
            .collect();
        for f in frames.iter_mut() {
            if !f.secure.encrypted || f.plaintext.is_some() {
                continue;
            }
            if let Source::Osdp(frame) = &f.source {
                if let Some(pt) = by_time.get(&(f.t_us, frame.id)) {
                    f.plaintext = Some(pt.clone());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Module 5: a capture rather than a bench
// ---------------------------------------------------------------------------

fn collect_monitor(monitor: &odr_detect::Monitor, frames: &mut Vec<FrameView>) {
    for obs in monitor.observations() {
        let Some(frame) = &obs.frame else { continue };
        let dir = match obs.bus_dir() {
            Some(BusDir::PdToAcu) => BusDir::PdToAcu,
            _ => BusDir::AcuToPd,
        };
        frames.push(bus_frame(
            obs.t_us,
            Origin::Controller(odr_bus::ControllerId(0)),
            dir,
            &obs.bytes,
            frame,
        ));
    }
}

/// Every finding the rule set reported, on the timeline where it fired.
fn finding_markers(det: &odr_scenario::DetectionOutcome) -> Vec<Marker> {
    det.report
        .findings()
        .iter()
        .map(|f| Marker {
            t_us: f.t_us,
            label: format!("{} — {}", f.what.name(), f.confidence.name()),
            kind: "attack",
        })
        .collect()
}

/// Episode boundaries as markers, for the Module 5 timeline.
pub fn day_markers(day: &odr_detect::Day) -> Vec<Marker> {
    day.timeline()
        .iter()
        .map(|span| Marker {
            t_us: span.start_us,
            label: span.episode.name().to_string(),
            kind: "handshake",
        })
        .collect()
}
