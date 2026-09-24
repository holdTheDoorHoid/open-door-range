# `odr-detect`

The defender's half. Given only what a passive monitor on the link can see —
bytes and timing — what can be concluded, and when?

This is item 5 in the Open Door Range build order alongside `odr-attack`
(`DESIGN.md` §3 and §6), and the crate `DESIGN.md` §5 calls a first-class part
of the project rather than an afterthought. The whole of Module 5 of
`docs/CURRICULUM.md` lives here: every earlier module replayed from a monitoring
position, with the question changed from *can I do this* to *could anybody have
noticed*.

```
credential ──▶ READER ──wire or bus──▶ CONTROLLER ──▶ DOOR
                        ▲
                     monitor ──▶ Monitor ──▶ RuleSet ──▶ Report ──▶ Score
```

## The governing rule

**A detector may only see what a passive monitor on the link sees.** It gets
octets off the wire and it gets timing. It does **not** get the engine's ground
truth — not node configuration, not keys, not the access list, and not the
`cause` field that makes `odr-bus`'s own event log a graph. If a detector needs
to know something, it infers it from traffic or it accepts that a defender could
not have known it either.

That rule is the mirror of the one governing `odr-attack`, and it is what makes
Module 5 honest. A detector that quietly read world state would score perfectly
against every drill and teach nothing, because a defender standing in a riser
with an RS-485 dongle does not have world state.

The rule is enforced structurally rather than by discipline. `Monitor` is built
from a capture file, and a file of timestamps and hex has nowhere to hide an
opinion. `Monitor::from_tap` exists for convenience and **discards
`odr_bus::Origin`** on the way in — the world knows an injecting tap drove a
frame, and a probe clipped to the pair does not. There is a test asserting that
`Monitor::from_tap` and `Monitor::from_capture` produce identical results, which
is the structural proof that the convenience is not a back door.

## Constraints it keeps

- **`no_std` + `alloc`.** Dependencies are `odr-bus`, `odr-osdp` and
  `odr-wiegand` and nothing else, because nothing else is on the wire.
- **`#![forbid(unsafe_code)]`**, `#![warn(missing_docs)]`.
- **Builds for `wasm32-unknown-unknown`.**
- **Deterministic.** Seeded randomness only, integer arithmetic throughout, no
  map iteration, findings sorted into a canonical order. The same seed gives the
  same capture, the same report and the same score on every machine.
- **No panics.** Everything fallible returns `DetectError`. A panic in a browser
  is a dead tab.

```
cargo test -p odr-detect
cargo build --target wasm32-unknown-unknown -p odr-detect
cargo clippy -p odr-detect --all-targets -- -D warnings
```

## Module layout

| Module | Contents |
|---|---|
| `observe` | `Monitor`, `Observation` — the governing rule, as a type |
| `finding` | `Finding`, `Signal`, `Severity`, `Confidence`, `Evidence`, `FrameRef`, `Report` |
| `detector` | the `Detector` trait and `RuleSet` — one rule, and a learner's answer |
| `catalog` | `RuleSpec`, `RuleParam`, `RuleSetSpec` — the selectable rules and their parameters, as data an interface can draw |
| `rules` | the eight detectors, one module each |
| `scenario` | `generate_day` — a day of mixed traffic and its answer key, kept apart |
| `score` | `AnswerKey`, `Expected`, `Verdict`, `Score` — true and false positives, time to detection |
| `error` | `DetectError` |

The commonly used items are re-exported at the crate root.

## The evidence model

```rust
pub struct Finding {
    pub t_us:       Micros,      // the earliest moment this could honestly be said
    pub severity:   Severity,    // how much it matters, if true
    pub what:       Signal,      // a closed vocabulary, not a string
    pub evidence:   Evidence,    // which frames say so, and the reasoning
    pub confidence: Confidence,  // how sure the wire allows a detector to be
}
```

Three things about this shape are load-bearing.

**Evidence cites frames, and the citations are checkable.** `Evidence` carries
`FrameRef`s — the index into the monitor's stream, the timestamp, and the octets
themselves — plus a `note` giving the reasoning in a sentence or two, including
the benign explanation that was considered and why it was or was not excluded.
`Evidence::check(&monitor)` re-reads every citation and confirms it still names
the same bytes. Module 5's whole point is that a learner can check the
reasoning, which is impossible if a rule can say "suspicious" and stop. There is
a test asserting that every finding of every detector over a whole generated day
checks out.

**`Signal` is an enum, not free text.** A scorer cannot compare sentences.
Everything variable — which address, which key, how many frames — lives in the
note.

**Severity and confidence are separate axes.** Severity is about impact;
confidence is about what the link permits. A `Critical` finding with
`Confidence::Ambiguous` is not a contradiction — it is the exact shape of drill
5.3, where a `CMD_KEYSET` is both the worst thing on the bus and undecidable.

`Confidence` has four values, and they are statements about *the link* rather
than about the code:

| Value | Meaning |
|---|---|
| `Certain` | the bytes say so, and nothing benign produces those bytes |
| `Probable` | a benign explanation exists, and the specific pattern seen is much more consistent with the finding |
| `Possible` | a benign explanation is plausible and was not excluded |
| `Ambiguous` | the observable is real and its cause cannot be determined from traffic, by anyone, ever |

## The detectors

Eight rules. Each names the benign traffic it was most likely to fire on, and the
suite runs each one against exactly that traffic and asserts silence.

| Detector | Signals | Best confidence | The benign case it must not fire on |
|---|---|---|---|
| `PostureDetector` | `CleartextBus`, `SensitiveCommandInClear` | Certain | a secured bus with one legacy peripheral — reported per address, not per link |
| `KeyDetector` | `DefaultKeyInUse`, `NullCipher` | Certain | **every properly encrypted bus**, because an empty payload legitimately uses SCS_15 |
| `KeysetDetector` | `KeysetObserved` | Ambiguous | nothing; it fires on commissionings on purpose and says it cannot tell |
| `DowngradeDetector` | `CapabilityDowngrade`, `SecureChannelLost`, `DeviceIdentityChanged` | Probable | a legacy reader added; a reader replaced; a reader power-cycling |
| `InjectionDetector` | `SequenceAnomaly`, `CadenceViolation`, `UnsolicitedReply`, `DuplicateAddress` | Probable | a retransmission; a sequence reset; a peripheral that has gone offline |
| `ReplayDetector` | `ReplayedFrame`, `ReplayedCredential` | Probable | **a person badging twice** |
| `WireDetector` | `UnauthenticatedWire`, `MalformedCredential` | Certain | (no false-positive case; there is almost nothing to say) |
| `TrafficDetector` | `TrafficPatternExposed` | Certain | it fires on healthy buses on purpose — that is the finding |

### Two rules worth reading the source for

**The downgrade (drill 5.2).** The naive rule — alert on any peripheral that does
not claim AES-128 — catches the downgrade and fires on every legacy reader ever
installed. Three things make the difference: a downgrade is a *change* and needs
a prior claim from the same address; device memory outlives link continuity, so a
monitor may remember "address 1 claimed AES-128" across a silence even though it
may not remember a sequence number across one; and `REPLY_PDID` separates a
capability drop from a reader replacement. That last one buys **quiet, not
security** — `REPLY_PDID` is exactly as unauthenticated as `REPLY_PDCAP`, and an
attacker already rewriting one can rewrite the other for free.
`DowngradeDetector::strict()` turns the identity check off, catches the
identity-spoofing variant, and alerts on every reader swap; both halves of that
trade are asserted in the suite so a learner sees the price rather than being
told about it.

**Replay, and a rule that turned out to be wrong.** This module started with:
*a byte-identical OSDP frame is a replay, because two genuine reads produce
different frames — the sequence number advances.* Running it against a generated
day showed it is wrong. **The sequence number is two bits.** It cycles 1, 2, 3,
so one repeat in three collides, and two genuine reads of the same card four
seconds apart come out byte-for-byte identical, CRC included. The rule fired on
people badging twice and on readers re-issuing `REPLY_PDID` after a reboot. What
replaced it is about the conversation rather than the bytes: a reply that is
byte-identical to an earlier one **and that nothing asked for** — the command it
should be answering had already been answered. Two bits of sequence was never an
anti-replay measure, and `two_bits_of_sequence_make_byte_identical_frames_worthless_on_their_own`
is the test that pins what that costs a defender.

## Composing a rule set — what drill 5.2 actually asks for

`docs/CURRICULUM.md` drill 5.2 says **build** a detection rule, not pick one:

> Build a detection rule that catches the downgrade and does not fire on a
> genuine legacy reader being added to the bus.

`RuleSet` is a list of trait objects, which is the right shape for running
detectors and the wrong shape for a learner to hold: it cannot be named,
serialised, compared to a preset, or drawn as a form. `catalog` is the shape
that can.

```rust
use odr_detect::catalog::RuleSetSpec;

let mut mine = RuleSetSpec::standard();      // start from the worked answer
mine.set_param("downgrade", "require_same_identity", 0)?;   // change one thing
let report = mine.build().run(&monitor);     // and run it
```

A `RuleSpec` carries a stable id, a label, **one line on what the rule catches
and one line on what it will false-positive on**, the signals it can emit, and
its tunable parameters with their legal ranges. That second line is not a
footnote: the second question every detector in this crate answers is *can it be
seen without firing on benign traffic*, and a learner choosing rules needs that
answer before they choose rather than after they score.

Three properties the suite pins down:

- **The catalogue describes the detectors that exist.** Every entry builds a
  detector whose own `name()` and `signals()` match the spec, so a control drawn
  from this table cannot be a control that changes nothing.
- **The presets are built from the same parts.** `RuleSetSpec::standard()`
  produces exactly the detectors `RuleSet::standard()` does, asserted by running
  both over a whole generated day and comparing the reports. That is what makes
  "start from standard and change one thing" a real workflow rather than a
  second code path.
- **Each rule changes the score in the way it claims.** Removing any one rule
  from the standard set loses findings, and every finding lost carries one of
  that rule's own signals.

A composition round-trips through one line of text —
`posture;downgrade:require_same_identity=0` — with defaults omitted, so a set
that changed one thing reads as one thing changed. Rules are held in catalogue
order however they were selected, so two learners who chose the same rules in
different orders hold equal compositions. An unknown rule, an unknown parameter
or a value outside the declared range is a `DetectError::Rule` naming the rule,
the parameter and the legal range — never something quietly dropped, because a
learner whose rule was silently discarded would be scored on a set they did not
build.

**Composing buys control, not indulgence.** There is no second scoring path: a
composed set is built into an ordinary `RuleSet` and handed the same capture and
the same key, so
`a_composed_set_tuned_to_alert_on_everything_scores_badly` — every threshold
dragged to its loudest legal value — still lands under 20% precision, fires on
the named benign events repeatedly, and is asserted to do so.

## What is **not** detectable, and why

This list is teaching material. A learner who finishes Module 5 believing a
monitor catches everything has learned the wrong thing; the useful conclusion is
which attacks monitoring answers and which ones only configuration answers.

**1. A well-formed injected frame on an unsecured bus.** Not hard to spot —
*indistinguishable*. An attacker who waits for the gap between polls, uses the
sequence number the conversation expects, and addresses the right peripheral
emits the same bytes a legitimate controller would have emitted. There is no
origin field, no signature, and no per-device secret outside Secure Channel. The
crate emits nothing, and
`a_well_formed_frame_in_the_gap_is_not_detectable_and_the_suite_says_so` asserts
the silence so that a later "improvement" which starts firing has to argue with a
test. The defensive answer is not a better rule; it is that injection on an
unsecured bus is a configuration problem.

**2. A replayed command.** A `CMD_OUT` put back on an unsecured bus is byte-for-
byte what the controller itself sends to open the door, arrives where the
controller's own command would arrive, and is answered the same way.
`ReplayDetector` deliberately covers replies only.

**3. Whether a `CMD_KEYSET` was authorised.** The event is unmistakable and the
authorisation is not in any frame. OSDP has no notion of who a controller is.
A commissioning and an attacker in install mode produce identical traffic, and
the only thing that separates them is whether an installer was booked — which is
a change record, not a capture. This is drill 5.3's answer, and the finding
carries `Confidence::Ambiguous` however loud its severity.

**4. A patient Wiegand replay.** On a D0/D1 pair there is no sequence number, no
CRC and no conversation: a replayed badge and a re-badged badge are the same
bits. All that separates them is the interval, and an attacker who waits a second
is simply not detectable. `ReplayDetector::human_min_us` is a claim about hands,
not about protocols, and the wire-side finding is only `Possible` for that
reason.

**5. Anything at all about an inline Wiegand implant.** The implant sits upstream
of the probe, so what the probe records is what the implant chose to send. A
monitor on the panel side of an implant cannot tell the reader, the implant and
an injector apart — all three produce pulses. Curriculum drill 1.4's substituted
credential is invisible from here by construction.

**6. Which card format a Wiegand frame is.** The wire does not say; the panel is
simply configured to believe one. The capture format carries no bit count
either, so a 26-bit read and a 32-bit read can be the same four bytes. A monitor
guesses from parity, and parity is ambiguous by construction — a 37-bit frame is
genuinely both an H10304 and an H10302.

**7. The credential inside a properly encrypted frame.** Obviously. Worth stating
because the *schedule* is not protected — see `TrafficDetector`.

**8. Whether the earlier capability reply was the forged one.** The downgrade
detector concludes "this address stopped claiming AES-128". It cannot prove the
earlier claim was the true one rather than an implant that has just been removed.
Hence `Probable`, never `Certain`.

**9. A collision.** `odr-bus` models a collision as nothing being delivered, so a
tap's buffer — and therefore a capture — contains no trace of it. A real probe
would record framing errors and garbage. If a drill ever needs "the attacker
tried and missed the gap" to be visible, the capture format needs an event for
it; see *Things I was not certain about* below.

**10. Anything on a link the probe is not clipped to.** One monitor is one probe
point. A world with two links, or one link cut by an inline implant, needs two
monitors, and a detector that reasoned across both would be concluding things a
defender could not have.

## Scoring — drills 5.1 to 5.3

`generate_day(seed, &DayOptions::default())` builds a day by **running the
engine**: twelve episodes, each its own `odr-bus` world, captured from one
passive probe and concatenated with a minute of silence between them. Every frame
in the capture came from real reader and controller state machines rather than
from a fixture writing plausible-looking bytes.

The two outputs are deliberately separate. `Day::capture()` is the
newline-delimited JSON of `DESIGN.md` §3 and is the only thing a detector ever
sees. `Day::key()` is the ground truth, built from the **scenario script** —
what each episode was constructed to do — rather than from the engine's event
log or from what the detectors happened to find.

Six benign events are scattered through the day, five of them in episodes that exist
mainly to carry one:

| Episode | Why it is there |
|---|---|
| `LegacyReaderAdded` | drill 5.2's named false positive: a reader that has never claimed AES-128 has not been downgraded |
| `ReaderReplaced` | the hard one: a capability drop at the same address, with nobody attacking anything |
| `ReaderPowerCycle` | a sequence reset and a rebuilt secure channel, which is what a naive rule calls an attack |
| `Commissioning` | byte-for-byte what an attacker in install mode produces |
| `CleartextBus` | contains a person badging twice, four seconds apart |

`Score` reports true positives, false positives, false negatives and detection
latency, with `is_quiet_on_benign()` as the single most useful assertion in the
suite. A rule set that catches less and never cries wolf is a better rule set
than one that catches more and does.

**There are three verdicts, not two.** `Verdict::Ambiguous` exists because a
scorer with only "attack" and "not attack" cannot represent drill 5.3's answer. A
finding matching an ambiguous expectation is counted separately and excluded from
both precision and recall: a learner is neither rewarded for reporting a
commissioning nor punished for it, which is exactly the position a defender is
in.

The standard rule set scores 100% precision and 100% recall against the default
day, with two ambiguous observations and no false positives. **Read that number
with suspicion**: the answer key and the detectors were written by the same hand,
and two key entries were added after the fact once the generator turned out to
produce observables the first draft had not anticipated (the door command the
forged reply provokes, and the duplicate answer the bus replay creates). Both are
genuine observables that an ideal detector should report, but the number is not
independent evidence. The tests that *are* independent evidence are the
false-positive ones, where a detector is run against traffic built specifically to
break it, and `a_rule_set_that_alerts_on_everything_scores_badly`, which checks
that the scorer can tell a good rule set from a loud one.

The rule editor changes who runs that second kind of test. A learner who starts
from `standard`, turns the downgrade rule's identity check off and runs it does
not read "100% is suspicious" in a README — they watch precision fall to 91%
and read the false positive back as *a reader was replaced with a legacy model
at the same address*. The number that teaches something is the one the learner
broke.

## Tests

`cargo test -p odr-detect` → **67 unit tests + 5 doctests**, all passing.
`cargo clippy -p odr-detect --all-targets -- -D warnings` is clean, as are
`cargo fmt` and `RUSTDOCFLAGS="-D warnings" cargo doc -p odr-detect --no-deps`.

The suite is organised around one question per test, and the questions come in
pairs: *does this rule catch the attack* and *does this rule stay quiet on the
benign traffic that looks like it*. Three classes carry more weight than the
rest:

- **Provenance.** A scenario is run, its capture is exported, the world is
  dropped, and the detectors run against the re-imported file. If a detector
  could only work with the world alive, these fail. One of them re-exports the
  monitor and asserts the second pass produces an identical report.
- **False positives.** Each detector against the benign case named in its own
  rustdoc, asserting silence — including the one that would have made
  `NullCipher` useless, where an ordinary encrypted bus is full of SCS_15 frames
  because an empty payload has nothing to encrypt.
- **Admissions of blindness.** Where an attack is genuinely invisible, a test
  asserts the silence.
- **The catalogue against the detectors.** Every selectable rule builds a
  detector whose own name and signals match the spec; the composed `standard`
  set produces a report identical to the hand-written preset's; removing any one
  rule loses findings carrying only that rule's signals; and a composition
  round-trips through its encoding. These are what stop the rule editor
  offering a control that changes nothing, or a bound the detector does not
  actually enforce.

## Things I was not certain about

1. **`ReplayDetector::human_min_us` defaults to 800 ms**, and it is a guess about
   how fast a person can present a badge twice rather than anything measured. A
   turnstile, a mantrap and a loading dock all behave differently. It is a field
   for that reason, and the finding it produces on a two-wire link is only
   `Possible`. If anyone has real badge-in interval data, this is the number to
   replace first.
2. **`InjectionDetector::min_command_gap_us` defaults to 20 ms**, chosen as an
   order of magnitude below `AcuConfig::reply_timeout_us`'s default of 200 ms so
   a lost reply does not look like an injection. Both numbers are `odr-bus`
   defaults that its own README flags as plausible rather than sourced, so this
   one inherits that uncertainty.
3. **`DEFAULT_GAP_US` is 30 seconds**, the silence after which a continuity rule
   forgets what it knew. The asymmetry it enforces — timing state resets across a
   gap, device knowledge does not — is a judgement I am confident in; the
   specific number is not. A site polling every two seconds wants a smaller one.
4. **The day is a sequence of episodes, not one continuous world.** A `World` is
   assembled up front, so it cannot gain a peripheral at lunchtime or enter
   install mode at four. Concatenating episode captures with a gap is honest
   about a link going quiet while somebody works on it, and it is *not* the same
   as a single unbroken day. A detector that depended on continuity across the
   whole capture would behave differently against real hardware.
5. **`Signal::CleartextBus` is reported per address, not per link.** That is
   right for drill 5.2 and it means a bus where every peripheral is unsecured
   produces one finding per peripheral rather than one for the bus. Whether a
   defender's console wants those coalesced is a UI question this crate does not
   answer.
6. **Collisions are invisible in a capture.** See point 9 of the undetectable
   list. This is a property of `odr-bus`'s model rather than of this crate, and
   it means "the attacker missed the gap" is currently a thing the range can do
   and cannot show. Fixing it would need a capture-format event for line noise,
   and `DESIGN.md` §3 marks the format **DECIDED**, so it is not this crate's
   call.
7. **The severity ladder is a product judgement.** `Critical` for exposed key
   material and door control, `High` for a posture that makes an attack free.
   Nothing in the crate branches on it; it is there for a console to sort by, and
   a site with a different risk model should feel free to disagree.
8. **`KeyDetector` will not report the default key on a bus that runs no Secure
   Channel at all**, even when a capability reply admits to it, because a key
   nothing is using is not a key in use and `CleartextBus` already says something
   more useful. That is a deliberate suppression and it is the kind of thing that
   is obviously right until somebody wants an inventory of which readers are
   still on SCBK-D. `trust_capability_claim` does not currently express that
   distinction.

9. **The parameter ranges in `catalog` are judgement, not measurement.** They are
   wide enough to let a learner be obviously wrong on purpose — `min_frames` of
   1, a 600-second replay window — because watching a badly tuned rule score
   badly is the lesson, and narrow enough to keep a browser tab responsive. A
   different bench might want tighter ones. What they are *not* is a claim about
   what a real deployment should be set to.

10. **Every parameter is one `u64`.** Flags are 0 and 1, counts are counts,
    durations are microseconds. That keeps a composition exactly reproducible
    across the wasm boundary — `DESIGN.md` §3 — at the cost of a parameter that
    genuinely wanted a fraction or an enum having nowhere to go. Nothing in the
    eight detectors wants one today. The first rule that does will need the
    catalogue to grow a kind rather than the existing kinds to be bent.

11. **A composed set is named, and the name is not part of it.** Two
    compositions that run the same detectors with the same tuning compare equal
    whatever they are called, and the encoding does not carry the name. That is
    what makes "you are running the standard set" a checkable statement rather
    than a label somebody typed — but it does mean a learner cannot save two
    differently-named copies of the same set and have them stay distinct.
