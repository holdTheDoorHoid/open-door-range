# `odr-wasm`

The boundary. Item 7 in the Open Door Range build order (`DESIGN.md` §6).

Below it sit the engines — `odr-scenario` and, under that, `odr-bus`,
`odr-attack`, `odr-detect`, `odr-osdp`, `odr-wiegand`, `odr-credential`. Above
it sits `site/`, which knows nothing about any of them. The contract between the
two is `site/ENGINE-API.md`, and this crate exists to satisfy it.

```
odr-scenario ──Outcome──▶ odr-wasm ──JSON string──▶ site/js/engine-wasm.js ──▶ site/js/app.js
```

```
wasm-pack build crates/odr-wasm --target web --out-dir ../../site/pkg
cargo test -p odr-wasm
cargo clippy -p odr-wasm --all-targets -- -D warnings
```

`site/pkg` is generated and git-ignored. CI builds it before deploying Pages.

## Constraints it keeps

- **`#![forbid(unsafe_code)]`.** wasm-bindgen 0.2.128 permits it on both the
  native and the `wasm32-unknown-unknown` targets; there is nothing to
  apologise for here.
- **`#![warn(missing_docs)]`**, `cargo fmt` clean, clippy clean at `-D warnings`.
- **`wasm-bindgen` is the only new dependency**, plus the workspace's own
  crates. No `serde`, no `serde-wasm-bindgen`: the JSON shapes in the contract
  are objects, arrays, strings and numbers, so the writer in [`json`] is about
  a hundred lines and costs less than either.
- **This crate is excluded from the `no_std` discipline** — it is the boundary,
  and `wasm-bindgen` is a `std` crate. Everything below it is still `no_std` +
  `alloc` and still builds for `wasm32-unknown-unknown` on its own.

## Three rules

**It never decides a flag.** `odr-scenario` owns every predicate. This crate
chooses *which of `odr-scenario`'s entry points to call*, and that choice is
made by the taps the learner placed — which is `site/ENGINE-API.md` §4's
requirement that taps gate the simulation. The verdict, the `evidence` list and
the `outstanding` list come back untouched.

**It never decides the readable/sealed split either.** `decode.rs` marks a field
`opaque` when, and only when, it is the payload of a frame whose own security
block says it is encrypted. The command or reply byte is plaintext in every OSDP
security mode and is always in the readable group; there is a test
(`the_command_byte_is_readable_on_an_encrypted_frame`) that says so, and another
(`a_cleartext_frame_seals_nothing`) for the other half.

**It never decides what a bench can be, either.** `setConfig` hands the option
straight to `odr_scenario::options::apply` and rebuilds through
`scenario::build_with`. Which options a bench accepts, their legal values, the
sentence refusing an impossible one and the sentence warning about a costly one
all come from `odr-scenario`. This crate groups them into the six panels the
site draws and adds the values the built world reports — the PD address, the
poll rate, what the attacker ended up holding — which are marked `fixed`
because they are not settings.

**Determinism survives the boundary.** The session seed is derived from the
drill id and nothing else, so the same drill gives the same bytes, the same flag
and the same evidence on every machine and in every browser
(`the_same_drill_gives_the_same_bytes_twice`). Options do not weaken that: the
same options and the same seed give the same bytes whatever order they were set
in (`the_same_options_give_the_same_bytes_across_a_rebuild`). The seed is kept below 2^53 so it
survives JSON exactly: a seed that came back rounded would be a seed nobody
could reproduce a bug from.

## Module map

| Module | What lives there |
|---|---|
| `json` | the hand-rolled JSON writer |
| `decode` | the decode tree, the offsets, and the readable/sealed split |
| `bench` | one run of a bench, projected into frames, markers and state |
| `config` | the collapsible groups: `odr-scenario`'s option list, plus the values the built bench reports |
| `submit` | the typed claims seven drills take, and the form for them |
| `rules` | Module 5's rule catalogue and its scored report, as JSON the site renders |
| `lib` | the `#[wasm_bindgen]` surface itself |

## How the contract maps

| `site/ENGINE-API.md` | Here | Source |
|---|---|---|
| §1 `catalog`, `getDrill` | `Engine::catalog`, `Engine::get_drill` | `odr_scenario::catalog` |
| §2 `loadDrill`, `session` | `Engine::load_drill` | `run::solve` / `observe_only` / `baseline` |
| §3 `configGroups`, `setConfig`, `resetConfig` | `config::groups`, `Engine::set_config` | `odr_scenario::options` + the built `Bench`, read back |
| §4 `topology`, taps | `Engine::topology`, `add_tap` … | learner state + `Drill::taps_for` |
| §5 `stateAt`, `markers` | `bench::Run::events`, `::markers` | `odr_bus::EventLog` |
| §6 `frames`, `frame` | `bench::FrameView`, `decode::osdp_fields` | `RecordKind::BusTx` / `WireTx` / `CredentialPresented` |
| §7 `timeline` | `Engine::timeline` | the same frames, binned |
| §9 `flag` | `Engine::flag` | `Outcome::flag` — untouched |
| §9 submissions | `submit::spec`, `submit::parse` | `odr_scenario::Submission` |
| §10 tasks | `Engine::task_states` | `Outcome::task_states` |
| §13 `ruleCatalog`, `setRules`, `detection` | `rules::catalog`, `Engine::set_rules`, `Engine::detection` | `odr_detect::catalog::RULES` + `module5::run_composed` |

### Everything is synchronous after boot

`odr-scenario` is not incremental: it builds a bench, clips an attack on, runs
the whole script and returns one `Outcome`. Everything the site asks for
afterwards is a projection of that one run, computed once in `bench::project_outcome`
and then read. So the work happens in `loadDrill` and when a tap changes, and
every accessor the site calls inside a render path or a `requestAnimationFrame`
is a slice of a `Vec`.

### Taps choose the runner

| Learner's taps | Runner | What happens |
|---|---|---|
| satisfy the drill's `TapPlan` list | `run::solve` | the attack is clipped on and performed |
| present, but not what the attack needs | `run::observe_only` | a passive probe, the script, no analysis |
| none | `run::baseline` | the bench with nothing clipped to it |

Each plan consumes a **distinct** tap, so drill 4.3 — an inline implant *and* a
passive analyser on the same pair — is not satisfied by one inline tap doing
both jobs. Capability is ordered the way the hardware is: anything can listen,
writing needs an injecting or inline tap, cutting the link needs an inline one.

`run::baseline` and `run::observe_only` are `odr-scenario`'s own negative
controls, and its test suite already asserts that no flag is earned by either.
That is what makes this mapping safe: the bridge is choosing between three
things the crate below already guarantees the properties of.

### `sealed` is real decryption

`site/ENGINE-API.md` §6's `sealed` block is filled in only when the attacker's
own `Knowledge` holds an SCBK for that address — recovered by the drill's attack,
with a `Provenance` saying how — and an `odr_attack::ShadowSession`
reconstructed from the captured handshake actually decrypts the frame. On drill
3.2 the card read opens down to a decoded facility code and card number. On
drill 4.1, whose predicate insists the attacker held no key at any point, every
payload stays sealed and the traffic-analysis lesson survives
(`a_recovered_key_opens_the_payload_and_nothing_else_does`).

### The rule editor publishes parts, not a menu

`site/ENGINE-API.md` §13. `docs/CURRICULUM.md` drill 5.2 asks a learner to
**build** a detection rule, so `Engine::rule_catalog` hands the site
`odr_detect::catalog::RULES` — every selectable rule with its label, the line
saying what it catches, the line saying what it will false-positive on, and
every parameter with the bounds the detector itself enforces. **The site
hardcodes no rule, no default and no bound**, which is the same discipline §3's
option list already keeps: a bound the site invented would be a second opinion
about what the engine accepts.

`Engine::set_rules` parses a composition, refuses one that names an unknown rule
or an out-of-range value *in the engine's own words*, and re-runs the day.
`Engine::detection` renders `odr_detect::Score` with each finding's evidence
attached: the frames that justify it, their timestamps and their octets, plus
the benign event any false positive landed on. A score without its reasoning
teaches a learner to chase a number, and the whole argument of `odr-detect`'s
README is that a finding is checkable.

Two caps, both stated in the JSON rather than applied silently: at most 60
findings per list and 8 cited frames per finding, with the **full** counts
carried in `score`. A rule set dragged to its loudest legal tuning produces
several hundred findings on the default day, and `docs/UI.md`'s rule is
collapse, never remove — so the interface can say "60 of 716 shown".

## Measured

Chromium, release build, on the machine this was written on.

| Drill | Frames | `loadDrill` | `frames()` | `timeline(600)` | Full site render |
|---|---|---|---|---|---|
| 1.1 | 2 | 0.3 ms | 0.1 ms | 0.3 ms | — |
| 2.2 | 69 | 2.5 ms | 0.8 ms | 0.7 ms | — |
| 3.2 | 91 | 7.9 ms | 1.3 ms | 0.6 ms | — |
| 4.1 | 552 | 5.7 ms | 5.5 ms | 1.3 ms | 39 ms |
| 5.1 | 3,552 | 38.7 ms | 27.8 ms | 5.4 ms | 166 ms |

`frames()` is the engine serialising plus the browser parsing. `stateAt`, which
the site calls on every animation frame, is 0.02 ms.

Playback at 20× holds 60 fps everywhere except drill 5.1 — a fifteen-minute
generated day, 3,552 rows — where it settles at about 30. The remaining cost
there is the browser laying out a very long table, not the engine: every
JavaScript step in the animation frame measures under a millisecond. Two things
were done about it rather than shortening the list, which `docs/UI.md` forbids:
the cursor's "this frame has not happened yet" dimming now touches only the rows
the cursor crossed instead of all of them, and the rows carry
`content-visibility: auto` so the browser skips layout for the ones off screen
(p95 frame time 67 ms → 43 ms). Nobody plays a fifteen-minute day at 1×; they
scrub it, which is instant.

The wasm binary is 963 KB, fetched once from the page's own origin. It is the
only request the page makes beyond its own static files.

## Things I am not certain about

Roughly in order of how much they would matter if they turned out wrong.

1. **The option list is `odr-scenario`'s; the *grouping* is this crate's.**
   Version 2 of the contract said configuration was read-only and gave the
   honest reason. That is now fixed where it belonged: `BenchOptions` threaded
   into `scenario::build_with` and the three runners, so `setConfig` rebuilds a
   real bench rather than this crate assembling worlds of its own. What is still
   this crate's invention is which of the six `ConfigGroup`s an option lands in
   — `odr-scenario` names a group on each `OptionSpec`, but those group names
   were chosen to match the panels the site already had, so the coupling runs
   the wrong way by one step. A scenario that wanted a seventh panel would have
   to say so here as well.

2. **A drill whose attack cannot run on a reconfigured bench falls back to the
   baseline.** `run::solve_with` does that, and only when the options are
   non-default — an actor giving up on a stock bench is still an error. The
   learner sees an unearned flag with its `outstanding` list, which is right,
   but the *reason the attack could not start* is not carried anywhere: it is
   inferable from the warning beside the control that caused it, and nothing
   more. If it needs to be explicit, `Facts` would need a field for it.

3. **The runner choice is the bridge's, not the engine's.** Nothing in
   `odr-scenario` says "these taps mean run `solve`". The mapping is defensible
   (it is exactly §4's tap gate, and the three runners are the crate's own
   entry points with its own negative-control tests behind them) but it is a
   policy this crate invented, and a reader looking for it in the curriculum
   will not find it.

4. **The shortened run in drill 4.2 has already completed by the time the bar
   appears.** Clipping the tap on is what runs it, so the learner does not press
   a button and watch "MAC forged" arrive. `docs/UI.md`'s decision survives —
   the genuine bar crawls with a date on it, which is the half that teaches —
   but the theatre of the fast one completing is gone.

5. **Module 5's rule set is composed now, and the three presets are still
   there.** This entry used to read "a choice of three, not a rule set the
   learner wrote", and that was the biggest gap between the written curriculum
   and what existed: drill 5.2 says *build* a rule. `odr-detect` grew a
   catalogue — the rules as data, with their parameters and bounds — so a form
   can produce one after all, and §13 carries it. The presets survive as
   starting points, which is what "start from standard and change one thing"
   needs. What I am **not** certain of is the granularity: the catalogue
   exposes the parameters the detector structs already had, and those were
   chosen as tuning knobs rather than as teaching material. `require_same_identity`
   is exactly drill 5.2's lesson; `max_evidence` is housekeeping a learner has
   no reason to touch, and it is offered beside it with equal weight.

6. **The submission forms are my reading of what each predicate wants.**
   `odr-scenario` names the shape in prose (`Drill::submission`) and the typed
   variant in `Submission`; the mapping from form fields to variant is here. If
   a drill's prompt and its predicate ever disagree, this file is where the
   disagreement would hide.

7. **`observe()` is a no-op.** No predicate reads it. Keeping the call and
   implementing nothing is the honest option — the alternative was the mock's,
   which was to let "you opened this field" stand in for "you submitted the
   right value".

8. **Free play performs no attack.** A tap in free play is drawn and listens.
   Making it do more would mean this crate choosing an attack for a bench with
   no drill to say which attack the bench is for. Free play *is* where the
   widest set of bench options is settable with nothing warning about them, so
   it is now a place a practitioner can build a bus and read it rather than only
   a place to watch one.

9. **The bit-level decode assumes H10301 for anything 26 bits wide.** Nothing on
   a wire says which format a frame is — the panel is simply configured to
   believe one — so the inspector shows the most plausible reading and a frame
   of another width falls back to a raw bit stream. `odr_wiegand::infer_formats`
   could offer the alternatives; the interface has nowhere to put them yet.

10. **Module 5's traffic list is the generated day's capture, replayed through
    the same frame renderer.** Its rows carry a synthetic origin (there is no
    world behind them, only a capture), so `origin` is always `bus` there and
    `tapped` is always false. A finding's marker is on the timeline, which is
    what the drill is about, but a learner who expects the attacker-origin
    highlighting they saw in Module 2 will not get it.

11. **The frame ids are positional** (`f1`, `f2`, …), assigned after sorting.
    They are stable for a given drill and seed, which is all `site/ENGINE-API.md`
    asks of an opaque string, but they are not stable across a tap change — and
    the site does re-select by id after one. In practice the selection is
    cleared on a bench change, so this has not bitten; it would if a future
    version tried to keep it.


12. **The rule editor is drawn by a file this crate does not own.**
    `site/js/ui/ruleeditor.js` renders the catalogue, and
    `site/js/engine-wasm.js` — the thin JS wrapper — does not yet forward
    `ruleCatalog`, `setRules` and `detection`, and still exports
    `ENGINE_API_VERSION = 3` while this crate exports 4. The editor falls
    through to the wasm object the wrapper holds until three forwarding methods
    are added there. Nothing is broken by it and it is the first thing to tidy.

13. **The detail caps are a guess.** 60 findings per list and 8 cited frames per
    finding were chosen so a pathologically loud rule set stays well under a
    megabyte of JSON. The number that actually matters is how much a learner
    needs to see to understand *why* their set fired, and I do not know what
    that number is — 60 is comfortably more than any sensible rule set produces
    on the default day and comfortably less than the 716 false positives a
    deliberately bad one does.

## Ethics

Nothing new here. This crate transports what the engines below produce, and they
are simulated protocol machinery with no vendor-specific exploit code and no
real credential data (`DESIGN.md` §5). The one thing it adds is the promise on
the tin: **it touches no network**. There is no `fetch`, no `XMLHttpRequest` and
no host binding for either; the page's only request is the static fetch of its
own `.wasm`.
