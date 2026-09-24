# `odr-scenario`

The drills. Item 6 in the Open Door Range build order (`DESIGN.md` §3 and §6).

Below this crate sit a working door system (`odr-bus`), a set of attacker actors
(`odr-attack`) and a defender's monitor (`odr-detect`). Above it sit `odr-wasm`
and the site. This crate is the course: **29 drills**, the benches they run on,
the guidance a learner reads at each band, and the predicate that decides
whether each flag is earned.

```
ScenarioId ──build──▶ Bench ──solve──▶ Outcome ──evaluate──▶ Flag
                                │                    ▲
                                ├── Knowledge ───────┤
                                ├── Facts ───────────┤
                                    Submission ──────┘
```

```
cargo test -p odr-scenario
cargo build --target wasm32-unknown-unknown -p odr-scenario
cargo clippy -p odr-scenario --all-targets -- -D warnings
```

## Constraints it keeps

- **`no_std` + `alloc`.** Dependencies are `odr-attack`, `odr-bus`,
  `odr-credential`, `odr-detect`, `odr-osdp` and `odr-wiegand`.
- **`#![forbid(unsafe_code)]`**, `#![warn(missing_docs)]`.
- **Builds for `wasm32-unknown-unknown`.**
- **Deterministic.** Seeded randomness only. The one wall clock in the whole
  workspace is `Task::state(elapsed_ms)`, which drives drill 4.2's crawling
  progress bar and touches nothing a flag depends on.
- **No panics.** Everything fallible returns `ScenarioError`.

## The drill model

A **scenario** is a starting position: a door system assembled with `odr-bus`'s
builder, its two endpoints configured the way the lesson requires, plus a
*script* — the badge-ins that door sees when you press Run. A scenario contains
no attack. Pressing Run on an untouched bench produces an ordinary day at an
ordinary door.

A **drill** wraps one scenario with:

| Field | What it is |
|---|---|
| `id`, `title`, `module` | the curriculum number, verbatim from `docs/CURRICULUM.md` |
| `band` | the band it was *written for*; shown as "designed for silver" |
| `completion` | `Flag`, `Measurement` or `Reference` — see below |
| `summary`, `objective`, `flag_text`, `note` | the prose a learner reads |
| `guidance` | Bronze steps, a Silver standing line, and an empty Gold list |
| `hints` | in order, on request, never at Gold |
| `taps` | where the attack has to sit. **Bronze pre-places exactly this list; Silver and Gold place none** |
| `submission` | what typed claim the drill takes, or `None` |

Bands change the guidance, never the bench (`docs/UI.md`). There are tests for
each half of that: `gold_gets_the_objective_and_nothing_else` and
`bronze_pre_places_the_taps_and_nothing_else_does`.

### Two drills are not flag-shaped

Forcing them into that mould would be the one dishonest thing in the course, so
`Completion` has three variants:

- **1.5** ends on a **number** — the wall-clock cost of sweeping the whole
  credential space at the wire timing the learner chose. `Completion::Measurement`,
  and the `Flag` carries a `Measurement` rather than pretending something was
  achieved.
- **0.6** ends by **being read**. It simulates nothing, `docs/BYPASS.md` says so
  in its first line, and `Completion::Reference` is how the API says it without
  filing the section under Bronze and hoping nobody notices. `is_simulated()`
  returns `false`, which `site/ENGINE-API.md` renders as "REFERENCE — no flag".

`only_two_drills_are_not_flag_shaped` pins the list at exactly those two.

## How predicates are expressed

**A flag predicate is a query against engine state. There are no answer
strings.** A different seed gives a different correct answer, and there is a
test (`a_different_seed_gives_a_different_answer_to_submit`) asserting that one
session's answer does not open another's drill.

The only fixed key material anywhere in this crate is *published*: SCBK-D and
the MIFARE transport key, both of which appear in predicates because "this link
is on the key from the manual" is the lesson of drills 3.2 and 0.4 rather than a
secret a learner could look up. Every site key, card number, facility code, tag
id and nonce comes from the session seed.

Every predicate in `flag.rs` reads some combination of three things:

1. **The `World` and its `EventLog`.** The log's `cause` field makes it a graph,
   so "the PD ACKed a command originated by the attacker" is
   `log.originator(seq)` naming a tap, and "the controller granted with no
   credential behind it" is a query over `presentations()` and `grants()`.
2. **The attacker's `Knowledge`.** Every fact carries a `Provenance`, so a
   predicate can insist a key was *brute-forced* rather than held, and
   `Knowledge::unearned()` is checked where the attack's honesty is the lesson.
3. **`Facts`** — what the run measured: a frame's layout, a card's provisioned
   keys, the cost of a sweep, the width of a MAC as measured off the wire.

A `Flag` comes back with `earned`, an `evidence` list of what the engine
observed (with times and ids), and an `outstanding` list of what it is still
waiting for. The second list is not decoration: "not yet" is not feedback, and a
learner who has not earned a flag has to be told what is missing in engine
terms.

### The seven drills that take a learner submission

These are **claims checked against values the engine generated from its seed**,
never answer strings:

| Drill | Submitted | Checked against |
|---|---|---|
| 0.1 | a 40-bit tag id | the id read off the modulated carrier this session's seed produced |
| 0.3 | facility code, card number, 26 bits | the bits the reader then put on the wire |
| 0.5 | a diagnosis per attack | the failure each attack actually hit, as a closed enum |
| 1.1 | facility code and card number | what the engine transmitted |
| 2.1 | byte offsets per field | the layout of a frame the engine generated, computed to mirror the encoder |
| 3.1 | a 16-byte cryptogram | the one the peripheral then transmitted |
| 4.1 | a list of times | the engine's own presentation log, ±1 s |

Drill 0.6 also carries a `submission`, and it is the one that is not a claim
about anything: `Submission::Acknowledged` is how a section that completes by
being read says it has been, without the API pretending a flag was earned.

Module 5's input is a detection **rule set**, which is a list of trait objects
rather than a value. It is handed to `run::score_module_5` and *run*, not
compared — so those three drills have `submission: None` and a
`Submission::Detection` variant exists only for a caller that scored a report
elsewhere.

## Running a drill

```rust
use odr_scenario::{run, DrillId};

// Drive drill 1.3 to completion.
let solved = run::solve(DrillId::new(1, 3), 0xC0FFEE).unwrap();
assert!(solved.flag(None).unwrap().earned);

// The same bench with nothing clipped to it earns nothing.
let plain = run::baseline(DrillId::new(1, 3), 0xC0FFEE).unwrap();
assert!(!plain.flag(None).unwrap().earned);
```

`solve` is *one* route to a flag, written to be the shortest honest one. A
learner at the bench takes their own, and the predicate cannot tell the
difference: it reads the world, the knowledge base and the measurements.

There are three negative controls, in increasing strength:

- `baseline` — the bench with nothing clipped on.
- `observe_only` — a passive probe clipped on, the script run, and no analysis
  performed. Used for 3.2, 3.3, 3.5 and 4.4, where the *analysis* is the attack
  and a flag earnable by listening alone would make the rest decoration.
- a deliberately wrong submission, for each of the seven submission drills.

## Drill 4.2's two tracks

`docs/UI.md` decided this and the crate implements it literally. The bench sets
`mac_len = 1`, so the forgery finishes while a learner watches; four MAC bytes
still go on the wire and only the first carries anything, which is why
`MacForger::calibrate` can *measure* the rigging from genuine frames instead of
being told about it. `ForgeryOutcome::effective_mac_bytes` is that measurement,
and the drill's `note` says out loud that a real bus returns 4.

Alongside it, `Facts::tasks` carries the genuine 32-bit search as a `Task`:
a candidate count, a rate measured from the bus (`MacForger::us_per_attempt` —
one round trip at this link's baud rate), and a projected duration.
`Outcome::task_states(elapsed_ms)` advances it. There is a test asserting that a
week of wall clock moves it less than 1%.

Drill 1.5 uses the same machinery for the Wiegand sweep, with the rate taken
from `BruteForcer::us_per_credential`.

## Test coverage

`cargo test -p odr-scenario` → **13 unit tests + 49 integration tests + 1
doctest**, all passing. `cargo test --workspace` is green.
`cargo clippy -p odr-scenario --all-targets -- -D warnings` is clean, as are
`cargo fmt` and `RUSTDOCFLAGS="-D warnings" cargo doc -p odr-scenario --no-deps`.

Per drill: earned when driven to completion, and not earned otherwise.

| Drill | Earned | Not earned without the attack | Wrong submission refused |
|---|---|---|---|
| 0.1 | ✓ | ✓ (tag never energised) | ✓ |
| 0.2 | ✓ | ✓ (no grant, no strike) | — |
| 0.3 | ✓ | ✓ (no submission) | ✓ |
| 0.4 | ✓ | ✓ (no keys recovered) | — |
| 0.5 | ✓ | ✓ (attacks not run) | ✓ |
| 0.6 | ✓ (on acknowledgement) | ✓ (unread) | — |
| 1.1 | ✓ | ✓ (no submission) | ✓ |
| 1.2 | ✓ | ✓ (no forged frame arrives) | — |
| 1.3 | ✓ | ✓ (**every grant has a card behind it**) | — |
| 1.4 | ✓ | ✓ (no substitution recorded) | — |
| 1.5 | ✓ (measurement) | ✓ (no sweep run) | — |
| 1.6 | ✓ | ✓ (no replay) | — |
| 2.1 | ✓ | ✓ (no submission) | ✓ (one field moved by a byte) |
| 2.2 | ✓ | ✓ (no capture) | — |
| 2.3 | ✓ | ✓ (nothing injected, no ACK) | — |
| 2.4 | ✓ | ✓ (no desync forced) | — |
| 3.1 | ✓ | ✓ (no submission) | ✓ |
| 3.2 | ✓ | ✓ + `observe_only` | — |
| 3.3 | ✓ | ✓ + `observe_only` | — |
| 3.4 | ✓ | ✓ (no key harvested) | — |
| 3.5 | ✓ | ✓ + `observe_only` | — |
| 3.6 | ✓ | ✓ (link stays secured) | — |
| 4.1 | ✓ | ✓ (no submission) | ✓ |
| 4.2 | ✓ | ✓ (no forgery run) | — |
| 4.3 | ✓ | ✓ (no IV collisions) | — |
| 4.4 | ✓ | ✓ + `observe_only` | — |
| 5.1 | ✓ | ✓ (empty rule set) | — |
| 5.2 | ✓ | ✓ (empty rule set) **and a strict rule set that fires on a reader swap** | — |
| 5.3 | ✓ | ✓ (empty rule set) | — |

Plus catalogue structure (29 drills, 6+6+4+6+4+3, curriculum order, every
scenario reachable, every scenario buildable), determinism (same seed → same
capture, same flag, same evidence), and the two band invariants.

## The one thing in the curriculum that could not be implemented faithfully

**Drill 4.4's flag says "attacker reads a card number from a
MACed-but-unencrypted link", and this bench cannot produce that frame.**

`odr-bus`'s peripheral always asks for encryption on `REPLY_RAW`
(`crates/odr-bus/src/reader.rs`, the `Command::Poll` arm passes
`encrypt: true` unconditionally). `AcuConfig::encrypt_payloads` controls the
*controller's* commands only, so a bus can run a null cipher in one direction
and not the other. `odr-attack`'s own README flags this as its first
uncertainty and names the fix: **one field, `PdConfig::encrypt_payloads`,
defaulting to `true`, threaded into that one call** — the exact twin of the
`mac_len` change that made drill 4.2 runnable.

That is a change to another crate, so it is reported here rather than worked
around. What this drill does instead is the command direction: the door-open
`CMD_OUT`, in the clear, inside an established Secure Channel session. The
predicate asks for "a payload recovered from a link whose frames carried a MAC
and no encryption", the guidance says plainly which half of the link the bench
can show and why, and `NullCipherReader::card_reads` is already wired in so the
reply-direction half starts working the moment that field exists.

## Things I was not certain about

Roughly in order of how much they would matter if they turned out wrong.

1. **Drill 2.4's flag says "the learner recovers a desynchronised link".** In
   this engine the *controller* recovers it: it restarts from sequence zero
   when the peripheral NAKs, with no learner action. The predicate therefore
   checks the checkable thing — a sequence fault really happened, the same
   running world went on to carry normal traffic, and the simulation was
   started exactly once — and the guidance is written as "watch what recovers
   it and find that in the log" rather than pretending the learner did it. If
   the drill is meant to require an action, `odr-bus` would need a controller
   that does *not* self-resynchronise, and that is a change to another crate.

2. **"Predict it before the engine sends it" is not enforced by the engine.**
   Drills 0.3 and 3.1 both say "before", and a `Submission` carries no
   timestamp — nothing here can tell a prediction from a transcription. The
   ordering is the interface's to enforce (take the submission, *then* run),
   and `solve` is written in that order so the reference route is honest. If
   this matters more than it looks, the fix is a submission that carries the
   world's `now()` at the moment it was taken.

3. **Module 5's bands are my judgement, not the curriculum's.**
   `docs/CURRICULUM.md` gives 5.1–5.3 no band; I made all three Silver, which
   matches their shape (an objective plus a sandbox). Their titles are also
   mine — the curriculum states them as questions rather than naming them.

4. **Drill 5.1's predicate is "everything in the answer key, nothing
   invented"**, not a typed list of which Module 3 attacks are visible. The
   curriculum asks "which of the four attacks in module 3 are visible to a
   passive monitor at all?" and the flag line for the module is about scoring a
   rule set, so the predicate follows the flag line. The *answer* to the
   question is carried as `module5::MODULE_3_VISIBLE` and stated in the flag's
   evidence, including the interesting half: the weak-key crack of drill 3.3 is
   absent because it produces no observable at all. A future revision might want
   a typed "visible / not visible" submission instead.

5. **The 100% precision and recall in drill 5.1's evidence inherits
   `odr-detect`'s own caveat.** That crate's README says to read the number with
   suspicion: the answer key and the standard detectors were written by the same
   hand. The parts of Module 5 that are independent evidence are the
   false-positive cases — and drill 5.2's negative test, which runs the strict
   downgrade rule and asserts it fires on a benign reader swap, is one of them.

6. **Drill 1.5's bench enrols a low card number on purpose.** A sweep that
   starts at zero has to reach the enrolled credential inside a browser tab, so
   `WiegandSweep` draws a card number in 0..=63. Low card numbers are real —
   sites number from 1 — but the reason *this* bench has one is the tab. The
   figure the drill ends on is computed for the whole 16,777,216-credential
   space at the bench's own timing, so the number is not affected; only the
   demonstration is.

7. **Drill 4.1's "simulated day" is 36 seconds of bus carrying seven
   badge-ins.** The limit is the screen, not the engine: a real day at 9600 baud
   is a few hundred thousand frames and the honest-by-default timeline would
   have to render all of them. Nothing in the predicate changes if the day gets
   longer.

8. **Drill 2.1 asks for byte offsets, and the sequence number has none.** The
   curriculum lists "sequence number" beside SOM, address, length and CRC, but
   it lives in the bottom two bits of the control byte. It is carried as a
   derived value on `FrameLayout` and named in the guidance rather than being a
   submittable span. The submitted set is every field the frame actually has,
   mark byte excepted.

9. **Drill 0.2's flag depends on a `SourceId` convention.** The victim's token
   is `SourceId(0)` and the attacker's blank is `SourceId(7)`, and the predicate
   asserts that nothing presented at the reader was `SourceId(0)`. `SourceId` is
   load-bearing by design in `odr-bus`, but the specific numbering is this
   crate's, and a scenario that presented a third token would need the predicate
   widened.

10. **`site/ENGINE-API.md` §4 says at most one tap per link; drill 4.3 needs
    two.** The IV-reuse attack is an inline implant *and* a passive analyser on
    the same pair, which is what a real operator has and what `odr-bus` allows.
    The drill's `taps` list both. Either the site's constraint needs loosening
    for that drill or the UI needs a way to show two boxes on one cable.

11. **Drill 1.2 has its own bench rather than sharing 1.1's.** The curriculum
    says "watch the panel accept a different badge", and the flag as written
    only requires a parity-valid frame carrying an unpresented number — which
    would be satisfied without any grant. `WiegandParityFlip` enrols the card
    number one bit away from the one presented, so both the prose and the flag
    hold. That is an interpretation, and it is the generous one.

12. **Drill 0.4 recovers three sectors, not sixteen.** Enough to show it is not
    a fluke, at about the same cost per sector. The full sixteen is the same
    loop and roughly five times the run time.

13. **Drill 3.5 inherits `KeysetCapturer`'s assumption** that the last handshake
    for an address is the site-key one. `odr-attack`'s README flags it, and
    `odr-bus`'s flags the commissioning ordering as unverified against real
    hardware. If a real controller waits for the next reset rather than
    re-handshaking, the capture has to be split differently and this drill's
    second half moves.

14. **`Task::projected` is a duration, not a date.** `site/ENGINE-API.md` shows
    "8.5 years — 27 March 2035". This engine has no wall clock and no epoch, so
    it produces the duration and the date is the site's to render. Inventing an
    epoch here to print a date would be the engine claiming to know something it
    does not.

15. **`Outcome::engine_answer` is a spoiler by construction.** It exists because
    the test suite has to submit a correct answer without writing one down, and
    it is derived from the run rather than stored — but it is still the answer,
    and a front end should not put it behind a button labelled "hint".

16. **The `Facts` struct is wide.** Fourteen optional fields, most of them used
    by one drill. The alternative was a trait object per drill, which would have
    moved the predicates out of one readable file and into twenty-nine small
    ones. If a third of the curriculum changes shape this is the thing to
    revisit.

## Ethics

Simulated protocol machinery (`DESIGN.md` §5). No vendor-specific exploit code,
no real credential data, no product named. The weak-key material is the already
published Mellon family (Petro & Vargas, Bishop Fox, 2023). Drill 0.6 exists
because a course that teaches only the electronic attacks leaves a learner with
a badly calibrated sense of where the risk is, and Module 5 exists because a
building owner should be able to run the same range and learn what their own bus
would look like under each attack.
