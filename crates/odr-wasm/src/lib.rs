//! **The wasm-bindgen surface the site talks to.**
//!
//! Item 7 in the Open Door Range build order (`DESIGN.md` §6). Below it sit the
//! engines; above it sits `site/`, which knows nothing about any of them. The
//! contract between the two is `site/ENGINE-API.md`, and this crate exists to
//! satisfy it — `site/js/engine-mock.js` implements the same contract in
//! JavaScript and is kept as the reference implementation.
//!
//! ```text
//!   odr-scenario ──Outcome──▶ odr-wasm ──JSON──▶ site/js/engine-wasm.js
//! ```
//!
//! # Three rules this crate keeps
//!
//! **It never decides a flag.** `odr-scenario` owns every predicate. This crate
//! chooses which of its entry points to call — and that choice is made by the
//! taps the learner placed, which is `site/ENGINE-API.md` §4's requirement that
//! taps gate the simulation. The verdict, the evidence and the `outstanding`
//! list all come back from `odr-scenario` untouched.
//!
//! **It never decides the readable/sealed split either.** [`decode`] marks a
//! field opaque when the frame's own security block says its payload is
//! encrypted, and never otherwise. The command byte is plaintext in every OSDP
//! security mode and is always in the readable group.
//!
//! **Determinism survives the boundary.** The session seed is derived from the
//! drill id alone, so the same drill produces the same bytes, the same flag and
//! the same evidence on every machine and in every browser.
//!
//! # Everything is synchronous after boot
//!
//! `site/ENGINE-API.md` promises it, and the shape of `odr-scenario` makes it
//! easy: one run produces one [`bench::Run`], and every accessor afterwards is a
//! slice of a `Vec`. The work happens in `loadDrill` and when a tap changes.
//!
//! # Module map
//!
//! | Module | What lives there |
//! |---|---|
//! | [`json`] | the hand-rolled JSON writer |
//! | [`decode`] | the decode tree and the readable/sealed split |
//! | [`mod@bench`] | one run, projected into frames, markers and state |
//! | [`config`] | the collapsible groups, derived from the bench |
//! | [`submit`] | the typed claims seven drills take |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

pub mod bench;
pub mod config;
pub mod decode;
pub mod json;
pub mod submit;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_bus::Micros;
use odr_scenario::ids::{Band, DrillId, LinkRole, TapMode};
use odr_scenario::options::{self as bench_options, BenchOptions};
use odr_scenario::{catalog, module5, Drill, Facts, Outcome, ScenarioId};
use wasm_bindgen::prelude::*;

use bench::{Marker, Patch, Run, Runner, Tap};
use json::{b, n, nu, nz, s, strs, Json};

/// The API version `site/ENGINE-API.md` §0 names. Bump on a breaking change.
pub const ENGINE_API_VERSION: u32 = 3;

/// The session seed, derived from the drill so a reload gives the same bench.
///
/// `DESIGN.md` §3: the same scenario always produces the same bytes, so flags
/// are stable and a bug is reproducible from a seed. Nothing here reads a
/// clock.
fn seed_for(drill: DrillId) -> u64 {
    // Kept below 2^53 so it survives the JSON boundary exactly: the site prints
    // it, and a seed that came back rounded would be a seed nobody could
    // reproduce a bug from.
    0x0D_C0FF_EE00 ^ ((drill.module as u64) << 16) ^ ((drill.index as u64) << 8)
}

/// The scenario free play runs on when the caller names none.
const DEFAULT_SANDBOX: ScenarioId = ScenarioId::OsdpClear;

/// **The engine.**
///
/// One of these exists per page. Everything `site/ENGINE-API.md` describes is a
/// method on it, and every method returns a JSON string the JavaScript wrapper
/// parses.
#[wasm_bindgen]
pub struct Engine {
    version: u32,
    band: Band,
    drill: Option<&'static Drill>,
    sandbox: bool,
    scenario: ScenarioId,
    seed: u64,
    taps: Vec<Tap>,
    tap_seq: u32,
    options: BenchOptions,
    values: BTreeMap<String, String>,
    rules: submit::RuleChoice,
    short_done: BTreeMap<String, bool>,
    run: Run,
    error: Option<String>,
}

#[wasm_bindgen]
impl Engine {
    /// Boot with drill 1.1 loaded, as `site/ENGINE-API.md` §0 requires.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Engine {
        let drill = catalog::drill_by_name("1.1").or_else(|| catalog::DRILLS.first());
        let d = drill.expect("the catalogue is a static table and is never empty");
        let seed = seed_for(d.id);
        let taps = pre_placed(d, Band::Bronze, 0);
        let opts = BenchOptions::default();
        let run = bench::drive_with(d, seed, &taps, &opts).unwrap_or_else(|_| empty_run());
        Engine {
            version: 1,
            band: Band::Bronze,
            drill: Some(d),
            sandbox: false,
            scenario: d.scenario,
            seed,
            tap_seq: taps.len() as u32,
            taps,
            options: BenchOptions::default(),
            values: BTreeMap::new(),
            rules: submit::RuleChoice::default(),
            short_done: BTreeMap::new(),
            run,
            error: None,
        }
    }

    /// `engine.version` — increases on every state mutation.
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The last error a rebuild produced, or an empty string.
    #[wasm_bindgen(js_name = lastError)]
    pub fn last_error(&self) -> String {
        self.error.clone().unwrap_or_default()
    }

    // -----------------------------------------------------------------
    // §1 Catalogue
    // -----------------------------------------------------------------

    /// `engine.catalog()`.
    pub fn catalog(&self) -> String {
        let modules: Vec<Json> = catalog::MODULES
            .iter()
            .map(|m| {
                let mut o = Json::obj();
                o.set("id", s(m.id.as_string()))
                    .set("number", n(f64::from(m.number)))
                    .set("title", s(m.title))
                    .set("blurb", s(m.blurb))
                    .set(
                        "drills",
                        Json::Arr(
                            catalog::drills_in(m.id)
                                .into_iter()
                                .map(|d| {
                                    let mut dj = Json::obj();
                                    dj.set("id", s(d.id.as_string()))
                                        .set("title", s(d.title))
                                        .set("band", s(d.band.name()))
                                        .set("simulated", b(d.is_simulated()))
                                        .set("summary", s(d.summary))
                                        .set("moduleId", s(m.id.as_string()));
                                    dj
                                })
                                .collect(),
                        ),
                    );
                o
            })
            .collect();
        let mut out = Json::obj();
        out.set("modules", Json::Arr(modules))
            .set("drillCount", nz(catalog::drill_count()));
        out.render()
    }

    /// `engine.getDrill(id)`.
    #[wasm_bindgen(js_name = getDrill)]
    pub fn get_drill(&self, id: &str) -> String {
        let Some(d) = catalog::drill_by_name(id) else {
            return String::from("null");
        };
        let module = catalog::MODULES.iter().find(|m| m.id == d.module);
        let mut g = Json::obj();
        g.set("bronze", strs(d.guidance.bronze.iter().copied()))
            .set("silver", strs(d.guidance.silver.iter().copied()))
            .set("gold", strs(d.guidance.gold.iter().copied()));
        let mut o = Json::obj();
        o.set("id", s(d.id.as_string()))
            .set("title", s(d.title))
            .set("band", s(d.band.name()))
            .set("simulated", b(d.is_simulated()))
            .set("moduleId", s(d.module.as_string()))
            .set("moduleTitle", s(module.map_or("", |m| m.title)))
            .set("moduleNumber", n(f64::from(module.map_or(0, |m| m.number))))
            .set("summary", s(d.summary))
            .set("objective", s(d.objective))
            .set("flagText", s(d.flag_text))
            .set("note", s(d.note))
            .set("scenario", s(d.scenario.name()))
            .set("completion", s(d.completion.name()))
            .set("guidance", g)
            .set("hints", strs(d.hints.iter().copied()))
            .set(
                "taps",
                Json::Arr(
                    d.taps
                        .iter()
                        .map(|t| {
                            let mut tj = Json::obj();
                            tj.set("linkId", s(t.link.name()))
                                .set("mode", s(t.mode.name()))
                                .set("label", s(t.label));
                            tj
                        })
                        .collect(),
                ),
            );
        o.render()
    }

    // -----------------------------------------------------------------
    // §2 Session
    // -----------------------------------------------------------------

    /// `engine.loadDrill(drillId, band)`.
    #[wasm_bindgen(js_name = loadDrill)]
    pub fn load_drill(&mut self, drill_id: &str, band: &str) -> String {
        let Some(d) = catalog::drill_by_name(drill_id) else {
            self.error = Some(format!("unknown drill {drill_id}"));
            return self.session();
        };
        self.band = Band::parse(band).unwrap_or(Band::Bronze);
        self.drill = Some(d);
        self.sandbox = false;
        self.scenario = d.scenario;
        self.seed = seed_for(d.id);
        self.options = BenchOptions::default();
        self.values.clear();
        self.rules = submit::RuleChoice::default();
        self.short_done.clear();
        self.tap_seq = 0;
        self.taps = pre_placed(d, self.band, 0);
        self.tap_seq = self.taps.len() as u32;
        self.rebuild();
        self.session()
    }

    /// `engine.loadSandbox(scenarioId?)`.
    #[wasm_bindgen(js_name = loadSandbox)]
    pub fn load_sandbox(&mut self, scenario_id: Option<String>) -> String {
        self.scenario = scenario_id
            .as_deref()
            .and_then(ScenarioId::parse)
            .unwrap_or(DEFAULT_SANDBOX);
        self.drill = None;
        self.sandbox = true;
        self.seed = 0x0D_C0FF_EE00;
        self.taps.clear();
        self.options = BenchOptions::default();
        self.values.clear();
        self.short_done.clear();
        self.rebuild();
        self.session()
    }

    /// `engine.session`.
    #[wasm_bindgen(getter)]
    pub fn session(&self) -> String {
        let mut o = Json::obj();
        o.set(
            "drillId",
            self.drill.map_or(Json::Null, |d| s(d.id.as_string())),
        )
        .set("band", s(self.band.name()))
        .set("scenarioId", s(self.scenario.name()))
        .set("sandbox", b(self.sandbox))
        .set(
            "title",
            s(self
                .drill
                .map_or_else(|| String::from("Free play"), |d| d.display_title())),
        )
        .set("durationUs", nu(self.run.duration_us))
        .set("seed", nu(self.seed))
        .set("runner", s(self.run.runner.name()));
        o.render()
    }

    /// `engine.setBand(band)`.
    #[wasm_bindgen(js_name = setBand)]
    pub fn set_band(&mut self, band: &str) -> String {
        self.band = Band::parse(band).unwrap_or(self.band);
        self.bump();
        self.session()
    }

    // -----------------------------------------------------------------
    // §3 Configuration
    // -----------------------------------------------------------------

    /// `engine.configGroups()`.
    #[wasm_bindgen(js_name = configGroups)]
    pub fn config_groups(&self) -> String {
        self.groups_json().render()
    }

    /// `engine.setConfig(groupId, fieldId, value)`.
    ///
    /// Applies the option through `odr_scenario::options`, rebuilds the bench
    /// deterministically and bumps the version so the site re-renders. The
    /// group id is not used to find the field — `odr-scenario` owns the option
    /// list and each option knows its own group — but a field claimed to be in
    /// the wrong group is refused, because a site that has drifted from the
    /// contract should hear about it rather than silently set something else.
    #[wasm_bindgen(js_name = setConfig)]
    pub fn set_config(&mut self, group_id: &str, field_id: &str, value: &str) -> String {
        let specs = bench_options::describe(self.scenario, self.drill_id(), &self.options);
        if let Some(spec) = specs.iter().find(|s| s.id == field_id) {
            if !group_id.is_empty() && spec.group != group_id {
                return self.refused(
                    field_id,
                    format!(
                        "{field_id} belongs to the {} group, not {group_id}",
                        spec.group
                    ),
                );
            }
        }
        let mut next = self.options.clone();
        match bench_options::apply(self.scenario, &mut next, field_id, value) {
            Ok(applied) => {
                self.options = applied;
                self.rebuild();
                let mut o = Json::obj();
                o.set("ok", b(true)).set("groups", self.groups_json());
                o.render()
            }
            Err(e) => self.refused(field_id, format!("{e}")),
        }
    }

    /// `engine.resetConfig()` — put every option back to the bench's own
    /// setting.
    ///
    /// The bench a scenario defines is the thing a drill's guidance was written
    /// against, so there has to be one move back to it that is not "remember
    /// what four things you changed".
    #[wasm_bindgen(js_name = resetConfig)]
    pub fn reset_config(&mut self) -> String {
        self.options = BenchOptions::default();
        self.rebuild();
        let mut o = Json::obj();
        o.set("ok", b(true)).set("groups", self.groups_json());
        o.render()
    }

    // -----------------------------------------------------------------
    // §4 Topology and taps
    // -----------------------------------------------------------------

    /// `engine.topology()`.
    pub fn topology(&self) -> String {
        let door_open = self.state_struct(self.run.duration_us).0;
        let protocol = match self
            .run
            .outcome
            .bench
            .as_ref()
            .and_then(|bx| bx.world.link(bx.link).ok())
        {
            Some(odr_bus::Link::Rs485(_)) => "osdp",
            Some(odr_bus::Link::ClockData(_)) => "clockdata",
            Some(odr_bus::Link::Wiegand(_)) => "wiegand",
            None => "wiegand",
        };
        let node = |id: &str, label: &str, sub: &str, cg: &str, state: &str| {
            let mut o = Json::obj();
            o.set("id", s(id))
                .set("label", s(label))
                .set("sub", s(sub))
                .set("configGroup", s(cg))
                .set("state", s(state));
            o
        };
        let link = |id: &str,
                    from: &str,
                    to: &str,
                    label: &str,
                    proto: &str,
                    tappable: bool,
                    cg: &str,
                    cut: bool| {
            let mut o = Json::obj();
            o.set("id", s(id))
                .set("from", s(from))
                .set("to", s(to))
                .set("label", s(label))
                .set("protocol", s(proto))
                .set("tappable", b(tappable))
                .set("cut", b(cut))
                .set("configGroup", s(cg));
            o
        };
        let cut = |link_id: &str| {
            self.taps
                .iter()
                .any(|t| t.link_id == link_id && t.mode == TapMode::Inline)
        };
        let mut o = Json::obj();
        o.set(
            "nodes",
            Json::Arr(alloc::vec![
                node("card", "Card", "credential", "card", "idle"),
                node("reader", "Reader", "PD", "reader", "idle"),
                node("controller", "Controller", "ACU", "controller", "idle"),
                node(
                    "door",
                    "Door",
                    "strike",
                    "controller",
                    if door_open { "open" } else { "closed" }
                ),
            ]),
        )
        .set(
            "links",
            Json::Arr(alloc::vec![
                link(
                    "card-reader",
                    "card",
                    "reader",
                    "rf",
                    "rf",
                    true,
                    "card",
                    cut("card-reader")
                ),
                link(
                    "reader-controller",
                    "reader",
                    "controller",
                    "wire",
                    protocol,
                    true,
                    "link",
                    cut("reader-controller")
                ),
                link(
                    "controller-door",
                    "controller",
                    "door",
                    "strike",
                    "relay",
                    false,
                    "controller",
                    false
                ),
            ]),
        )
        .set("taps", Json::Arr(self.taps.iter().map(tap_json).collect()));
        o.render()
    }

    /// `engine.addTap({ linkId, mode })`.
    ///
    /// **More than one tap may sit on a link.** `site/ENGINE-API.md` §4 used to
    /// say at most one; drill 4.3 needs an inline implant and a passive analyser
    /// on the same pair, which is what a real operator has and what `odr-bus`
    /// allows, so the contract was widened rather than the drill narrowed.
    /// A second tap in the *same* mode on the same link is refused, because two
    /// identical probes are not a second capability.
    #[wasm_bindgen(js_name = addTap)]
    pub fn add_tap(&mut self, link_id: &str, mode: &str) -> String {
        let Some(mode) = parse_mode(mode) else {
            return refusal("that is not a tap mode");
        };
        if link_id != "card-reader" && link_id != "reader-controller" {
            return refusal("that link cannot be tapped");
        }
        if self
            .taps
            .iter()
            .any(|t| t.link_id == link_id && t.mode == mode)
        {
            return refusal("there is already a tap in that mode on this link");
        }
        self.tap_seq += 1;
        let tap = Tap {
            id: format!("tap{}", self.tap_seq),
            link_id: link_id.to_string(),
            mode,
            pre_placed: false,
        };
        self.taps.push(tap.clone());
        self.rebuild();
        let mut o = Json::obj();
        o.set("ok", b(true)).set("tap", tap_json(&tap));
        o.render()
    }

    /// `engine.setTapMode(tapId, mode)`.
    #[wasm_bindgen(js_name = setTapMode)]
    pub fn set_tap_mode(&mut self, tap_id: &str, mode: &str) -> String {
        let Some(mode) = parse_mode(mode) else {
            return refusal("that is not a tap mode");
        };
        let Some(i) = self.taps.iter().position(|t| t.id == tap_id) else {
            return refusal("no such tap");
        };
        self.taps[i].mode = mode;
        let tap = self.taps[i].clone();
        self.rebuild();
        let mut o = Json::obj();
        o.set("ok", b(true)).set("tap", tap_json(&tap));
        o.render()
    }

    /// `engine.removeTap(tapId)`.
    #[wasm_bindgen(js_name = removeTap)]
    pub fn remove_tap(&mut self, tap_id: &str) -> String {
        self.taps.retain(|t| t.id != tap_id);
        self.rebuild();
        let mut o = Json::obj();
        o.set("ok", b(true));
        o.render()
    }

    // -----------------------------------------------------------------
    // §5 Time
    // -----------------------------------------------------------------

    /// `engine.duration()`.
    pub fn duration(&self) -> f64 {
        self.run.duration_us as f64
    }

    /// `engine.nextEventUs(tUs)`.
    #[wasm_bindgen(js_name = nextEventUs)]
    pub fn next_event_us(&self, t_us: f64) -> f64 {
        let t = clamp_us(t_us);
        self.run
            .frames
            .iter()
            .map(|f| f.t_us)
            .find(|&ft| ft > t)
            .unwrap_or(self.run.duration_us) as f64
    }

    /// `engine.prevEventUs(tUs)`.
    #[wasm_bindgen(js_name = prevEventUs)]
    pub fn prev_event_us(&self, t_us: f64) -> f64 {
        let t = clamp_us(t_us);
        self.run
            .frames
            .iter()
            .map(|f| f.t_us)
            .rev()
            .find(|&ft| ft < t)
            .unwrap_or(0) as f64
    }

    /// `engine.stateAt(tUs)`.
    #[wasm_bindgen(js_name = stateAt)]
    pub fn state_at(&self, t_us: f64) -> String {
        let t = clamp_us(t_us);
        let (door, decision, credential, sc, scs, key) = self.state_struct(t);
        let captured = if self.taps.is_empty() {
            0
        } else {
            self.run.frames.iter().filter(|f| f.t_us <= t).count()
        };
        let mut a = Json::obj();
        a.set("taps", nz(self.taps.len()))
            .set(
                "inline",
                b(self.taps.iter().any(|x| x.mode == TapMode::Inline)),
            )
            .set(
                "holdsKeys",
                b(self
                    .run
                    .outcome
                    .knowledge
                    .as_ref()
                    .is_some_and(|k| !k.keys.is_empty())),
            )
            .set("captured", nz(captured));
        let mut o = Json::obj();
        o.set("tUs", nu(t))
            .set("door", s(if door { "open" } else { "closed" }))
            .set("strike", s(if door { "energised" } else { "idle" }))
            .set("decision", s(decision))
            .set("lastCredential", credential.map_or(Json::Null, s))
            .set("secureChannel", s(sc))
            .set("scs", scs.map_or(Json::Null, s))
            .set("key", key.map_or(Json::Null, s))
            .set("attacker", a);
        o.render()
    }

    /// `engine.markers()`.
    pub fn markers(&self) -> String {
        Json::Arr(self.run.markers.iter().map(marker_json).collect()).render()
    }

    // -----------------------------------------------------------------
    // §6 Traffic
    // -----------------------------------------------------------------

    /// `engine.frames(opts)`.
    pub fn frames(
        &self,
        from_us: f64,
        to_us: f64,
        collapse_idle: bool,
        filter: Option<String>,
        limit: f64,
    ) -> String {
        let (rows, total, collapsed) = self.frame_rows(from_us, to_us, collapse_idle, &filter);
        let limit = if limit <= 0.0 { 4000 } else { limit as usize };
        let truncated = rows.len() > limit;
        let shown: Vec<Json> = rows
            .iter()
            .skip(rows.len().saturating_sub(limit))
            .map(|r| r.json.clone())
            .collect();
        let mut o = Json::obj();
        o.set("total", nz(total))
            .set("truncated", b(truncated))
            .set("collapsed", collapsed)
            .set("rows", Json::Arr(shown));
        o.render()
    }

    /// `engine.frame(id)`.
    pub fn frame(&self, id: &str) -> String {
        let Some(&i) = self.run.index.get(id) else {
            return String::from("null");
        };
        let f = &self.run.frames[i];
        let fields = f.fields();
        let mut sec = Json::obj();
        sec.set("active", b(f.secure.active))
            .set("scs", f.secure.scs.clone().map_or(Json::Null, s))
            .set(
                "scsByte",
                f.secure.scs_byte.map_or(Json::Null, |v| n(f64::from(v))),
            )
            .set("encrypted", b(f.secure.encrypted))
            .set("macBits", n(f64::from(f.secure.mac_bits)))
            .set("keyHeld", b(f.key_held()));
        let mut o = Json::obj();
        o.set("id", s(f.id.clone()))
            .set("tUs", nu(f.t_us))
            .set("line", s(f.line))
            .set("lane", s(f.lane))
            .set("dir", s(f.dir))
            .set("label", s(f.label.clone()))
            .set("kind", s(f.kind.clone()))
            .set("summary", s(f.summary.clone()))
            .set("view", s(f.view))
            .set("note", s(f.note.clone()))
            .set("origin", s(f.origin))
            .set("tapped", b(f.tapped))
            .set("secure", sec)
            .set(
                "bytes",
                Json::Arr(f.bytes.iter().map(|x| n(f64::from(*x))).collect()),
            )
            .set(
                "bits",
                match f.bits() {
                    Some(bits) => Json::Arr(
                        bits.iter()
                            .map(|x| n(if x { 1.0f64 } else { 0.0f64 }))
                            .collect(),
                    ),
                    None => Json::Null,
                },
            )
            .set(
                "fields",
                Json::Arr(fields.iter().map(decode::Field::to_json).collect()),
            );
        o.render()
    }

    // -----------------------------------------------------------------
    // §7 Timeline
    // -----------------------------------------------------------------

    /// `engine.timeline({ fromUs, toUs, bins, collapseIdle })`.
    pub fn timeline(&self, from_us: f64, to_us: f64, bins: f64, collapse_idle: bool) -> String {
        let from = clamp_us(from_us);
        let to = if to_us.is_finite() && to_us > 0.0 {
            clamp_us(to_us)
        } else {
            self.run.duration_us
        };
        let bins = (bins as usize).clamp(1, 4000);
        let span = to.saturating_sub(from).max(1);
        let (rows, _total, collapsed) =
            self.frame_rows(from as f64, to as f64, collapse_idle, &None);

        let mut rf = alloc::vec![0.0f64; bins];
        let mut wire = alloc::vec![0.0f64; bins];
        let mut bus = alloc::vec![0.0f64; bins];
        for row in &rows {
            let i = (((row.t_us.saturating_sub(from)) as f64 / span as f64) * bins as f64) as usize;
            let i = i.min(bins - 1);
            match row.lane {
                "rf" => rf[i] += 1.0,
                "wire" => wire[i] += 1.0,
                _ => bus[i] += 1.0,
            }
        }

        let density = |id: &str, label: &str, counts: &[f64]| {
            let mut o = Json::obj();
            o.set("id", s(id))
                .set("label", s(label))
                .set("type", s("density"))
                .set("bins", Json::Arr(counts.iter().map(|c| n(*c)).collect()));
            o
        };

        // The door lane is a state track, not a density: it says what the door
        // was doing, which is the authoritative record of a successful attack.
        let mut segments = Vec::new();
        let mut cur_from = from;
        let mut cur_open = false;
        for e in &self.run.events {
            if let Patch::Door(open) = e.patch {
                if e.t_us < from || e.t_us > to {
                    if e.t_us < from {
                        cur_open = open;
                    }
                    continue;
                }
                let mut seg = Json::obj();
                seg.set("fromUs", nu(cur_from))
                    .set("toUs", nu(e.t_us))
                    .set("state", s(if cur_open { "open" } else { "closed" }));
                segments.push(seg);
                cur_from = e.t_us;
                cur_open = open;
            }
        }
        let mut seg = Json::obj();
        seg.set("fromUs", nu(cur_from))
            .set("toUs", nu(to))
            .set("state", s(if cur_open { "open" } else { "closed" }));
        segments.push(seg);
        let mut door = Json::obj();
        door.set("id", s("door"))
            .set("label", s("Door"))
            .set("type", s("state"))
            .set("segments", Json::Arr(segments));

        let mut o = Json::obj();
        o.set("fromUs", nu(from))
            .set("toUs", nu(to))
            .set("bins", nz(bins))
            .set("honest", b(!collapse_idle))
            .set("collapsed", collapsed)
            .set(
                "markers",
                Json::Arr(
                    self.run
                        .markers
                        .iter()
                        .filter(|m| m.t_us >= from && m.t_us <= to)
                        .map(marker_json)
                        .collect(),
                ),
            )
            .set(
                "lanes",
                Json::Arr(alloc::vec![
                    density("rf", "RF", &rf),
                    density("wire", "Wire", &wire),
                    density("bus", "Bus", &bus),
                    door,
                ]),
            );
        o.render()
    }

    // -----------------------------------------------------------------
    // §9 Flags
    // -----------------------------------------------------------------

    /// `engine.flag()`.
    ///
    /// The verdict comes from `odr-scenario`. Nothing here decides it.
    pub fn flag(&self) -> String {
        let Some(drill) = self.drill else {
            let mut o = Json::obj();
            o.set("drillId", Json::Null)
                .set("predicate", s(""))
                .set("earned", b(false))
                .set("evidence", Json::Arr(Vec::new()))
                .set("outstanding", Json::Arr(Vec::new()));
            return o.render();
        };
        let submission = submit::parse(drill, &self.run.outcome.facts, &self.values);
        let flag = match self.run.outcome.flag(submission.as_ref()) {
            Ok(f) => f,
            Err(e) => {
                let mut o = Json::obj();
                o.set("drillId", s(drill.id.as_string()))
                    .set("predicate", s(drill.flag_text))
                    .set("earned", b(false))
                    .set("simulated", b(drill.is_simulated()))
                    .set("evidence", Json::Arr(Vec::new()))
                    .set("outstanding", strs([format!("{e}")]));
                return o.render();
            }
        };
        let mut o = Json::obj();
        o.set("drillId", s(drill.id.as_string()))
            .set("predicate", s(flag.predicate))
            .set("earned", b(flag.earned))
            .set("simulated", b(flag.is_simulated()))
            .set("completion", s(flag.completion.name()))
            .set("evidence", strs(flag.evidence.iter().cloned()))
            .set("outstanding", strs(flag.outstanding.iter().cloned()))
            .set(
                "measurement",
                match &flag.measurement {
                    None => Json::Null,
                    Some(m) => {
                        let mut mj = Json::obj();
                        mj.set("label", s(m.label.clone()))
                            .set("value", s(m.value.clone()))
                            .set("compareWith", s(m.compare_with.clone()));
                        mj
                    }
                },
            );
        o.render()
    }

    /// `engine.observe(action)`.
    ///
    /// The real predicates read the world, the attacker's knowledge base and
    /// the run's measurements, so none of them needs to be told that a learner
    /// clicked something. It is kept because `site/ENGINE-API.md` §9 describes
    /// it and a future predicate might want it.
    ///
    /// It deliberately does **not** bump the version: an observation changes no
    /// engine state, and a version bump would invalidate the wrapper's caches
    /// on every cursor move.
    pub fn observe(&self, _kind: &str, _a: &str, _b: f64) {}

    /// `engine.submission()` — the form this drill wants, or `null`.
    pub fn submission(&self) -> String {
        let Some(drill) = self.drill else {
            return String::from("null");
        };
        submit::spec(drill, &self.run.outcome.facts, &self.values).render()
    }

    /// `engine.submitField(id, value)` — record one field of the form.
    ///
    /// Returns the flag, re-evaluated. Module 5's rule-set choice re-runs the
    /// day, because there the submission *is* the thing that gets run.
    #[wasm_bindgen(js_name = submitField)]
    pub fn submit_field(&mut self, id: &str, value: &str) -> String {
        self.values.insert(id.to_string(), value.to_string());
        if id == "ruleset" {
            self.rules = submit::RuleChoice::parse(value);
            self.rebuild();
        } else {
            self.bump();
        }
        self.flag()
    }

    /// `engine.clearSubmission()`.
    #[wasm_bindgen(js_name = clearSubmission)]
    pub fn clear_submission(&mut self) -> String {
        self.values.clear();
        self.rules = submit::RuleChoice::default();
        self.rebuild();
        self.flag()
    }

    // -----------------------------------------------------------------
    // §10 Long-running attacks
    // -----------------------------------------------------------------

    /// How many long-running tasks this drill started.
    #[wasm_bindgen(js_name = taskCount)]
    pub fn task_count(&self) -> usize {
        self.run.outcome.facts.tasks.len()
    }

    /// `engine.taskStates(elapsedMs)`.
    ///
    /// The **one** place wall-clock time enters the engine, passed in by the
    /// site. Nothing a flag depends on reads it.
    #[wasm_bindgen(js_name = taskStates)]
    pub fn task_states(&self, elapsed_ms: f64) -> String {
        let ms = if elapsed_ms.is_finite() && elapsed_ms > 0.0 {
            elapsed_ms as u64
        } else {
            0
        };
        let states = self.run.outcome.task_states(ms);
        Json::Arr(
            states
                .iter()
                .map(|t| {
                    let mut o = Json::obj();
                    o.set("id", s(t.id))
                        .set("label", s(t.label.clone()))
                        .set("shortLabel", s(t.short_label.clone()))
                        .set(
                            "shortDone",
                            b(t.short_done || self.short_done.get(t.id).copied().unwrap_or(false)),
                        )
                        .set("note", s(t.note.clone()))
                        .set("done", n(t.done as f64))
                        .set("total", n(t.total as f64))
                        .set("fraction", n(t.fraction))
                        .set("remainingSeconds", n(t.remaining_seconds))
                        .set("projected", s(t.projected.clone()));
                    o
                })
                .collect(),
        )
        .render()
    }

    /// `engine.startTask(id)` — mark the shortened run complete.
    ///
    /// The genuine bar is never marked complete, which is the whole of the
    /// decision in `docs/UI.md`.
    #[wasm_bindgen(js_name = startTask)]
    pub fn start_task(&mut self, id: &str) -> String {
        let known = self.run.outcome.facts.tasks.iter().any(|t| t.id == id);
        if known {
            self.short_done.insert(id.to_string(), true);
            self.bump();
        }
        let mut o = Json::obj();
        o.set("ok", b(known));
        o.render()
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    fn bump(&mut self) {
        self.version = self.version.saturating_add(1);
    }

    fn drill_id(&self) -> Option<DrillId> {
        self.drill.map(|d| d.id)
    }

    fn groups_json(&self) -> Json {
        config::groups(
            &self.run,
            &self.taps,
            self.scenario,
            self.drill_id(),
            &self.options,
        )
    }

    /// A refusal, with the engine's own sentence and the unchanged groups.
    fn refused(&self, field_id: &str, error: String) -> String {
        let _ = field_id;
        let mut o = Json::obj();
        o.set("ok", b(false))
            .set("error", s(error))
            .set("groups", self.groups_json());
        o.render()
    }
}

impl Default for Engine {
    fn default() -> Engine {
        Engine::new()
    }
}

/// A row of the traffic list, kept with the fields the collapser needs.
struct Row {
    t_us: Micros,
    lane: &'static str,
    json: Json,
}

impl Engine {
    /// Re-run the bench. Called whenever something that changes it changes.
    fn rebuild(&mut self) {
        self.error = None;
        let run = match self.drill {
            Some(d) if d.id.module == 5 => self.drive_module5(d),
            Some(d) => bench::drive_with(d, self.seed, &self.taps, &self.options),
            None => drive_sandbox(self.scenario, self.seed, &self.options),
        };
        match run {
            Ok(r) => self.run = r,
            Err(e) => {
                self.error = Some(e);
            }
        }
        self.bump();
    }

    /// Module 5 submits a rule set, which is run rather than compared.
    fn drive_module5(&self, drill: &'static Drill) -> Result<Run, String> {
        let satisfied = bench::plan_satisfied(drill, &self.taps);
        let day = module5::day(self.seed).map_err(|e| format!("{e}"))?;
        let rules = match (satisfied, self.rules) {
            (true, submit::RuleChoice::Standard) => odr_detect::RuleSet::standard(),
            (true, submit::RuleChoice::Strict) => module5::strict_ruleset(),
            _ => odr_detect::RuleSet::empty("nothing at all"),
        };
        let detection = module5::run_ruleset(&day, &rules).map_err(|e| format!("{e}"))?;
        let outcome = Outcome {
            drill: drill.id,
            seed: self.seed,
            bench: None,
            knowledge: None,
            facts: Facts {
                detection: Some(detection),
                attack_performed: satisfied,
                ..Facts::default()
            },
        };
        Ok(bench::project_outcome(
            if satisfied && self.rules != submit::RuleChoice::Empty {
                Runner::Solve
            } else {
                Runner::Baseline
            },
            outcome,
        ))
    }

    /// The door, decision, credential and secure-channel posture at `t`.
    fn state_struct(
        &self,
        t: Micros,
    ) -> (
        bool,
        &'static str,
        Option<String>,
        &'static str,
        Option<String>,
        Option<String>,
    ) {
        let mut door = false;
        let mut decision = "none";
        let mut credential = None;
        let mut sc = self.run.sc_initial;
        let mut scs = None;
        let mut key = None;
        for e in &self.run.events {
            if e.t_us > t {
                break;
            }
            match &e.patch {
                Patch::Door(open) => door = *open,
                Patch::Decision {
                    granted,
                    credential: c,
                } => {
                    decision = if *granted { "granted" } else { "denied" };
                    credential = c.clone();
                }
                Patch::Sc {
                    state,
                    scs: sv,
                    key: kv,
                } => {
                    sc = state;
                    scs = sv.clone();
                    key = kv.clone();
                }
            }
        }
        (door, decision, credential, sc, scs, key)
    }

    /// The rows of the traffic list, with idle polling collapsed on request.
    fn frame_rows(
        &self,
        from_us: f64,
        to_us: f64,
        collapse_idle: bool,
        filter: &Option<String>,
    ) -> (Vec<Row>, usize, Json) {
        let from = clamp_us(from_us);
        let to = if to_us.is_finite() && to_us > 0.0 {
            clamp_us(to_us)
        } else {
            u64::MAX
        };
        let needle = filter
            .as_ref()
            .map(|f| f.to_lowercase())
            .filter(|f| !f.is_empty());

        let mut matched: Vec<&bench::FrameView> = Vec::new();
        for f in &self.run.frames {
            if f.t_us < from || f.t_us > to {
                continue;
            }
            if let Some(q) = &needle {
                if !f.label.to_lowercase().contains(q)
                    && !f.summary.to_lowercase().contains(q)
                    && !f.kind.contains(q)
                {
                    continue;
                }
            }
            matched.push(f);
        }
        let total = matched.len();

        if !collapse_idle {
            let rows = matched
                .into_iter()
                .map(|f| Row {
                    t_us: f.t_us,
                    lane: f.lane,
                    json: row_json(f),
                })
                .collect();
            return (rows, total, Json::Null);
        }

        // Runs of four or more consecutive POLL/ACK frames, with nothing else
        // between them, become one collapsed span. The site keeps showing the
        // count, because compression must always be a thing a learner can see
        // they chose.
        let mut rows: Vec<Row> = Vec::new();
        let mut spans: Vec<Json> = Vec::new();
        let mut hidden = 0usize;
        let mut runlen: Vec<&bench::FrameView> = Vec::new();
        let flush = |run: &mut Vec<&bench::FrameView>,
                     rows: &mut Vec<Row>,
                     spans: &mut Vec<Json>,
                     hidden: &mut usize| {
            if run.len() >= 4 {
                let first = run[0];
                let last = run[run.len() - 1];
                let mut sp = Json::obj();
                sp.set("fromUs", nu(first.t_us))
                    .set("toUs", nu(last.t_us))
                    .set("count", nz(run.len()));
                spans.push(sp);
                *hidden += run.len();
                let mut o = Json::obj();
                o.set("id", s(format!("collapse-{}", first.id)))
                    .set("collapsed", b(true))
                    .set("tUs", nu(first.t_us))
                    .set("toUs", nu(last.t_us))
                    .set("count", nz(run.len()))
                    .set("lane", s("bus"))
                    .set("line", s("rs485"))
                    .set("dir", s("acu_to_pd"))
                    .set("label", s("⋯"))
                    .set(
                        "summary",
                        s(format!("{} idle POLL/ACK frames hidden", run.len())),
                    )
                    .set("kind", s("collapsed"));
                rows.push(Row {
                    t_us: first.t_us,
                    lane: "bus",
                    json: o,
                });
            } else {
                for f in run.iter() {
                    rows.push(Row {
                        t_us: f.t_us,
                        lane: f.lane,
                        json: row_json(f),
                    });
                }
            }
            run.clear();
        };
        for f in matched {
            if f.kind == "poll" || f.kind == "ack" {
                runlen.push(f);
            } else {
                flush(&mut runlen, &mut rows, &mut spans, &mut hidden);
                rows.push(Row {
                    t_us: f.t_us,
                    lane: f.lane,
                    json: row_json(f),
                });
            }
        }
        flush(&mut runlen, &mut rows, &mut spans, &mut hidden);

        let mut c = Json::obj();
        c.set("hiddenFrames", nz(hidden))
            .set("spans", Json::Arr(spans));
        (rows, total, c)
    }
}

fn row_json(f: &bench::FrameView) -> Json {
    let mut sec = Json::obj();
    sec.set("active", b(f.secure.active))
        .set("scs", f.secure.scs.clone().map_or(Json::Null, s))
        .set("encrypted", b(f.secure.encrypted))
        .set("macBits", n(f64::from(f.secure.mac_bits)));
    let mut o = Json::obj();
    o.set("id", s(f.id.clone()))
        .set("tUs", nu(f.t_us))
        .set("line", s(f.line))
        .set("lane", s(f.lane))
        .set("dir", s(f.dir))
        .set("label", s(f.label.clone()))
        .set("kind", s(f.kind.clone()))
        .set("summary", s(f.summary.clone()))
        .set("secure", sec)
        .set("origin", s(f.origin))
        .set("tapped", b(f.tapped))
        .set("length", nz(f.bytes.len()));
    o
}

fn marker_json(m: &Marker) -> Json {
    let mut o = Json::obj();
    o.set("tUs", nu(m.t_us))
        .set("label", s(m.label.clone()))
        .set("kind", s(m.kind));
    o
}

fn tap_json(t: &Tap) -> Json {
    let mut o = Json::obj();
    o.set("id", s(t.id.clone()))
        .set("linkId", s(t.link_id.clone()))
        .set("mode", s(t.mode.name()))
        .set("prePlaced", b(t.pre_placed));
    o
}

fn refusal(why: &str) -> String {
    let mut o = Json::obj();
    o.set("ok", b(false)).set("error", s(why));
    o.render()
}

fn parse_mode(v: &str) -> Option<TapMode> {
    Some(match v {
        "sniff" => TapMode::Sniff,
        "inject" => TapMode::Inject,
        "inline" => TapMode::Inline,
        _ => return None,
    })
}

fn clamp_us(v: f64) -> Micros {
    if !v.is_finite() || v <= 0.0 {
        0
    } else {
        v as Micros
    }
}

/// Bronze pre-places exactly the drill's taps. Silver and Gold place none.
fn pre_placed(drill: &Drill, band: Band, from: u32) -> Vec<Tap> {
    drill
        .taps_for(band)
        .iter()
        .enumerate()
        .map(|(i, plan)| Tap {
            id: format!("tap{}", from as usize + i + 1),
            link_id: String::from(match plan.link {
                LinkRole::CardToReader => "card-reader",
                LinkRole::ReaderToController => "reader-controller",
            }),
            mode: plan.mode,
            pre_placed: true,
        })
        .collect()
}

/// Free play: the bench, run, with nothing performed on it.
fn drive_sandbox(scenario: ScenarioId, seed: u64, opts: &BenchOptions) -> Result<Run, String> {
    let mut b =
        odr_scenario::scenario::build_with(scenario, seed, opts).map_err(|e| format!("{e}"))?;
    b.run_script().map_err(|e| format!("{e}"))?;
    let outcome = Outcome {
        drill: DrillId::new(0, 0),
        seed,
        bench: Some(b),
        knowledge: None,
        facts: Facts::default(),
    };
    Ok(bench::project_outcome(Runner::Baseline, outcome))
}

/// A run with nothing in it, for the boot path that cannot fail in practice.
fn empty_run() -> Run {
    let outcome = Outcome {
        drill: DrillId::new(0, 6),
        seed: 0,
        bench: None,
        knowledge: None,
        facts: Facts::default(),
    };
    bench::project_outcome(Runner::Baseline, outcome)
}

/// `createEngine()`'s Rust half.
#[wasm_bindgen(js_name = createEngine)]
pub fn create_engine() -> Engine {
    Engine::new()
}

/// The contract version this build satisfies.
#[wasm_bindgen(js_name = engineApiVersion)]
pub fn engine_api_version() -> u32 {
    ENGINE_API_VERSION
}

#[cfg(test)]
mod tests;
