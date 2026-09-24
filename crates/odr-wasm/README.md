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

**Determinism survives the boundary.** The session seed is derived from the
drill id and nothing else, so the same drill gives the same bytes, the same flag
and the same evidence on every machine and in every browser
(`the_same_drill_gives_the_same_bytes_twice`). The seed is kept below 2^53 so it
survives JSON exactly: a seed that came back rounded would be a seed nobody
could reproduce a bug from.

## Module map

| Module | What lives there |
|---|---|
| `json` | the hand-rolled JSON writer |
| `decode` | the decode tree, the offsets, and the readable/sealed split |
| `bench` | one run of a bench, projected into frames, markers and state |
| `config` | the collapsible groups, derived from the bench that was built |
| `submit` | the typed claims seven drills take, and the form for them |
| `lib` | the `#[wasm_bindgen]` surface itself |

## How the contract maps

| `site/ENGINE-API.md` | Here | Source |
|---|---|---|
| §1 `catalog`, `getDrill` | `Engine::catalog`, `Engine::get_drill` | `odr_scenario::catalog` |
| §2 `loadDrill`, `session` | `Engine::load_drill` | `run::solve` / `observe_only` / `baseline` |
| §3 `configGroups` | `config::groups` | the built `Bench`, read back |
| §4 `topology`, taps | `Engine::topology`, `add_tap` … | learner state + `Drill::taps_for` |
| §5 `stateAt`, `markers` | `bench::Run::events`, `::markers` | `odr_bus::EventLog` |
| §6 `frames`, `frame` | `bench::FrameView`, `decode::osdp_fields` | `RecordKind::BusTx` / `WireTx` / `CredentialPresented` |
| §7 `timeline` | `Engine::timeline` | the same frames, binned |
| §9 `flag` | `Engine::flag` | `Outcome::flag` — untouched |
| §9 submissions | `submit::spec`, `submit::parse` | `odr_scenario::Submission` |
| §10 tasks | `Engine::task_states` | `Outcome::task_states` |

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

The wasm binary is 935 KB, fetched once from the page's own origin. It is the
only request the page makes beyond its own static files.

## Things I am not certain about

Roughly in order of how much they would matter if they turned out wrong.

1. **Configuration is read-only, and that is a real loss.** `site/ENGINE-API.md`
   §3 now says so, and `config.rs` explains why: a bench comes from a
   `ScenarioId` and a seed, and building one here would put a second, divergent
   definition of every bench above the crate that defines them. But the mock let
   a learner flip Secure Channel and watch the bench strip change, and that was
   a good thing to be able to do. If it should come back, the fix is in
   `odr-scenario` — a `BenchOptions` parameter to `scenario::build`, threaded
   into the runners — not here.

2. **The runner choice is the bridge's, not the engine's.** Nothing in
   `odr-scenario` says "these taps mean run `solve`". The mapping is defensible
   (it is exactly §4's tap gate, and the three runners are the crate's own
   entry points with its own negative-control tests behind them) but it is a
   policy this crate invented, and a reader looking for it in the curriculum
   will not find it.

3. **The shortened run in drill 4.2 has already completed by the time the bar
   appears.** Clipping the tap on is what runs it, so the learner does not press
   a button and watch "MAC forged" arrive. `docs/UI.md`'s decision survives —
   the genuine bar crawls with a date on it, which is the half that teaches —
   but the theatre of the fast one completing is gone.

4. **Module 5's rule set is a choice of three, not a rule set the learner
   wrote.** `odr-detect`'s `RuleSet` is a list of trait objects; there is no
   value a form can produce. The three are "nothing at all", the standard set,
   and the strict downgrade rule, and choosing between them is a real question
   with a real answer — 5.2 is precisely about the strict one's false
   positives. It is still a menu rather than a rule editor.

5. **The submission forms are my reading of what each predicate wants.**
   `odr-scenario` names the shape in prose (`Drill::submission`) and the typed
   variant in `Submission`; the mapping from form fields to variant is here. If
   a drill's prompt and its predicate ever disagree, this file is where the
   disagreement would hide.

6. **`observe()` is a no-op.** No predicate reads it. Keeping the call and
   implementing nothing is the honest option — the alternative was the mock's,
   which was to let "you opened this field" stand in for "you submitted the
   right value".

7. **Free play performs no attack.** A tap in free play is drawn and listens.
   Making it do more would mean this crate choosing an attack for a bench with
   no drill to say which attack the bench is for.

8. **The bit-level decode assumes H10301 for anything 26 bits wide.** Nothing on
   a wire says which format a frame is — the panel is simply configured to
   believe one — so the inspector shows the most plausible reading and a frame
   of another width falls back to a raw bit stream. `odr_wiegand::infer_formats`
   could offer the alternatives; the interface has nowhere to put them yet.

9. **Module 5's traffic list is the generated day's capture, replayed through
   the same frame renderer.** Its rows carry a synthetic origin (there is no
   world behind them, only a capture), so `origin` is always `bus` there and
   `tapped` is always false. A finding's marker is on the timeline, which is
   what the drill is about, but a learner who expects the attacker-origin
   highlighting they saw in Module 2 will not get it.

10. **The frame ids are positional** (`f1`, `f2`, …), assigned after sorting.
    They are stable for a given drill and seed, which is all `site/ENGINE-API.md`
    asks of an opaque string, but they are not stable across a tap change — and
    the site does re-select by id after one. In practice the selection is
    cleared on a bench change, so this has not bitten; it would if a future
    version tried to keep it.

## Ethics

Nothing new here. This crate transports what the engines below produce, and they
are simulated protocol machinery with no vendor-specific exploit code and no
real credential data (`DESIGN.md` §5). The one thing it adds is the promise on
the tin: **it touches no network**. There is no `fetch`, no `XMLHttpRequest` and
no host binding for either; the page's only request is the static fetch of its
own `.wasm`.
