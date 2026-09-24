# The engine contract

What `site/` needs from `crates/odr-wasm`.

The front end talks to exactly one object. Two implementations of this contract ship:

- **`site/js/engine-wasm.js`** — the real engine, `crates/odr-wasm` compiled to
  WebAssembly. This is what `site/js/app.js` imports.
- **`site/js/engine-mock.js`** — the reference implementation, in JavaScript, with
  canned-but-honest data. Kept deliberately: it is the readable statement of what this
  document means, and it lets the site be worked on without a Rust toolchain or a
  `site/pkg` build.

Switching between them is one line in `site/js/app.js`:

```js
import { createEngine } from './engine-wasm.js';   // ← the real engine
import { createEngine } from './engine-mock.js';   // ← the reference, no build needed
```

Nothing else in the site imports the engine. If you find yourself needing to change a
second file, the contract below is wrong and should be fixed here first.

Build the real one with:

```
wasm-pack build crates/odr-wasm --target web --out-dir ../../site/pkg
```

`site/pkg` is generated and git-ignored; CI builds it before deploying.

---

## What changed in version 4

**A rule editor for Module 5** (§13). `docs/CURRICULUM.md` drill 5.2 says *build* a
detection rule that catches the downgrade and does not fire on a genuine legacy reader —
and v3 offered a menu of three pre-made rule sets, which made the most interesting
exercise in the defender's module multiple-choice. Three calls fix that:

1. **`engine.ruleCatalog()`** publishes the parts a rule set is built from: every
   selectable rule with a stable id, a label, one line on what it catches, one line on
   **what it will false-positive on**, and its tunable parameters with their legal ranges.
   It is a rendering of `odr_detect::catalog::RULES`, which is the same table the
   detectors are configured from. **The site hardcodes no rule, no default and no bound.**
2. **`engine.setRules(text)`** takes a composition — a preset name, or
   `posture;downgrade:require_same_identity=0` — builds it and runs it against the
   generated day. A refusal names the rule, the parameter and the legal range, and
   changes nothing: a learner whose rule was silently dropped would be scored on a set
   they did not build.
3. **`engine.detection()`** returns the score **with its reasoning** — the day's
   episodes, the benign events planted in it, every true positive with its detection
   latency and the frames that justify it, every attack missed, and every false positive
   named with the benign event it landed on.

`engine.submitField('ruleset', …)` still exists and now takes a composition as well as a
preset name; §9's Module 5 form is the "start from" control beside the builder.
`engine-mock.js` implements v4, including the rule editor: a reference implementation
that could only offer a menu would be describing a different contract.

**Not yet forwarded by `engine-wasm.js`.** The wrapper in `site/js/engine-wasm.js` does
not yet carry `ruleCatalog`, `setRules` and `detection`, and still exports
`ENGINE_API_VERSION = 3`. `site/js/ui/ruleeditor.js` falls through to the wasm object the
wrapper holds until three forwarding methods are added there. That is a two-minute
change and is listed here so it is not forgotten.

## What changed in version 3

**Configuration sets as well as reports** (§3). Version 2 said the wasm engine refused
every `setConfig`, and gave an honest reason: a bench came from a `ScenarioId` and a seed,
and there was no seam for "the same bench with Secure Channel on". The seam now exists in
the right place — `odr_scenario::options::BenchOptions`, threaded into
`scenario::build_with` and the three runners — so the controls are live again without the
bridge inventing a second definition of any bench. Four consequences for this document:

1. **`setConfig` applies, rebuilds and bumps the version.** It refuses only when the
   bench cannot be built that way, and says which of the three reasons it is.
2. **Fields carry `warning` and `changed`.** A setting that would make the loaded drill
   unwinnable is applied and warned about rather than blocked — docs/UI.md's recorded
   feedback is prefer warning over blocking, and a drill that refused its own defence
   setting would forbid the "run the attack, then run the fix" exercise the engine was
   built for. `fixed` survives for the genuinely impossible and for values read off the
   run.
3. **`engine.resetConfig()` is new.** One move back to the bench the scenario defines.
4. **The option ids and their legal values come from the engine.** The table in §3 is
   documentation, not a contract the site may hardcode.

`engine-mock.js` implements v3 and is still the readable statement of what this means.

## What changed in version 2

Version 1 was written against the mock. The real engine needed five changes, each of
which is the engine's behaviour winning over the document's guess. They are listed
together here so a reader of version 1 can find them; each is also written into its own
section below.

1. **More than one tap may sit on a link** (§4). Version 1 said at most one and made
   `addTap` change the mode of an existing tap. Drill 4.3 is an inline implant *and* a
   passive analyser on the same pair — what a real operator carries, and what `odr-bus`
   allows. `addTap` now adds; a second tap in the *same* mode on the same link is
   refused, because two identical probes are not a second capability.
2. **Configuration reports; it does not set** (§3). Every field grew `fixed` and
   `fixedReason`, and the wasm engine refused every `setConfig`. **Superseded by v3**,
   which put the seam into `odr-scenario` where it belonged; `fixed` and `fixedReason`
   survive for the fields that genuinely are not controls.
3. **Drills that take a typed claim now have somewhere to type it** (§9). Seven drills
   plus the reference section submit a claim that `odr-scenario` checks against a value
   the engine generated from its seed. The mock approximated those predicates by watching
   which field you opened in the decode tree; the real engine cannot, so the contract
   grew `engine.submission()`, `engine.submitField()` and `engine.clearSubmission()`.
   **The engine composes the form** — drill 2.1's field list comes from the layout of the
   frame that actually crossed the bus.
4. **`engine.observe()` is advisory** (§9). No real predicate reads it. It is kept
   because a future one might, and it deliberately does not bump `engine.version`.
5. **`TaskState.projected` is a duration; the site adds the date** (§10). The engine has
   no wall clock and no epoch, and inventing one to print a calendar date would be the
   engine claiming to know something it does not. `remainingSeconds` is there and
   `site/js/ui/drill.js` renders the date from it — the only wall-clock arithmetic on the
   site's side, and nothing a flag depends on reads it.

**Nothing in this API may touch the network.** The site's privacy promise is literal: no
backend, no telemetry, no fetch of any kind at runtime. The wasm binary is loaded as a
static asset from the same origin and that is the only request the page ever makes.

---

## 0. Module surface

```js
export const ENGINE_KIND;          // 'mock' | 'wasm'
export const ENGINE_API_VERSION;   // integer; bump on a breaking change. Currently 4.
export async function createEngine(options?): Promise<Engine>;
```

`createEngine` is async so the wasm build can `await init()` inside it. `options` is
reserved; the site passes nothing today. The returned object must be usable immediately
— it boots with a drill already loaded (both engines load `1.1`; the site then calls
`loadDrill` with whatever `localStorage` remembered).

The wasm engine's methods return JSON **strings** across the boundary and
`engine-wasm.js` parses them, so everything below still arrives as plain JavaScript
values. That is a performance decision rather than a contract one: a string crosses once
as a length-prefixed copy and the browser's own parser builds the graph in native code,
where handing back a live object means one crossing per property. A drill-4.1 traffic
list — 552 frames — costs about 5 ms that way.

### Types used throughout

- **`tUs`** — virtual microseconds since the start of the scenario, integer. Every time
  in this API is `tUs`. There is no wall-clock time anywhere in the engine except the one
  place `taskStates` says otherwise.
- **`bytes`** — `number[]`, one element per octet, `0..255`. Not a `Uint8Array`: the site
  slices, maps and joins these, and a plain array crosses the wasm boundary predictably.
  If you return a typed array, the site's `.slice()`/`.map()` calls still work, but say
  so here.
- **`FrameId`, `TapId`, `DrillId`** — opaque strings. `DrillId` is the curriculum number
  as a string: `"1.3"`, `"4.2"`.
- All returned objects are plain JSON-able values. No getters, no proxies, no functions.

### Mutation and versioning

`engine.version` is an integer that increases on every state mutation. The site does not
currently poll it, but it must exist so a future incremental renderer can.

Everything is synchronous after `createEngine` resolves. The site calls these functions
inside render paths and during `requestAnimationFrame`; if the real engine needs to do
work that takes more than a millisecond or two, do it in `loadDrill`, not in the
accessors.

---

## 1. Catalogue

### `engine.catalog() → Catalog`

```ts
type Catalog = {
  modules: Array<{
    id: string;            // 'm0' … 'm5'
    number: number;        // 0 … 5
    title: string;         // 'The credential'
    blurb: string;         // one or two sentences, module-level
    drills: Array<{
      id: DrillId;         // '0.1'
      title: string;
      band: 'bronze' | 'silver' | 'gold' | 'reference';
      simulated: boolean;  // false for 0.6 — the reference section
      summary: string;
      moduleId: string;
    }>;
  }>;
  drillCount: number;      // total across all modules
};
```

The site renders the course navigation straight from this and never hardcodes a drill
list. `docs/CURRICULUM.md` currently defines **29** drills (6 + 6 + 4 + 6 + 4 + 3), not
31; the interface displays whatever `drillCount` says, so if drills are added the site
needs no change.

`band` here is the band the drill was *written for*. It is shown as "designed for
silver". It is independent of the band the learner has selected.

### `engine.getDrill(id) → Drill | null`

```ts
type Drill = {
  id: DrillId;
  title: string;
  band: 'bronze' | 'silver' | 'gold' | 'reference';
  simulated: boolean;
  moduleId: string; moduleTitle: string; moduleNumber: number;
  summary: string;      // what the drill is about, 1–3 sentences
  objective: string;    // what the learner must make happen. One sentence.
  flagText: string;     // the flag predicate in prose, shown verbatim in the flag card
  note: string;         // optional extra paragraph; '' if none
  scenario: string;     // scenario id, informational
  guidance: {
    bronze: string[];   // ordered steps. Bronze only. May be empty.
    silver: string[];   // reserved; the site renders a standing line instead
    gold: string[];     // must be empty — Gold gets the objective and nothing else
  };
  hints: string[];      // revealed one at a time, on request, never at Gold
};
```

---

## 2. Session

### `engine.loadDrill(drillId, band) → Session`

Resets the bench to this drill's starting position and returns the session. `band` is
`'bronze' | 'silver' | 'gold'`.

**Bronze pre-places the taps** (docs/UI.md). Silver and Gold must place none — the site
relies on this, and a Silver bench that quietly arrives with an inline tap already fitted
makes drill 1.4 meaningless.

Changing band reloads the drill. Difficulty changes the guidance, never the bench, so a
reload is the honest way to get back to a consistent starting position.

### `engine.loadSandbox(scenarioId?) → Session`

Free play. Same bench, no drill, no flag.

In the wasm engine free play runs the bench's own script with **nothing performed on
it**: the attacks belong to drills, because a drill is what says which attack this bench
is for. A tap placed in free play is drawn and listens; it does not run an attack. The
bench strip says which runner is in force, so this is visible rather than inferred.

### `engine.session` (property) → `Session`

```ts
type Session = {
  drillId: DrillId | null;   // null in free play
  band: 'bronze' | 'silver' | 'gold';
  scenarioId: string;
  sandbox: boolean;
  title: string;             // '1.3 Replay' or 'Free play'
  durationUs: number;
  seed: number;              // integer, always below 2^53 so it survives JSON exactly
  runner: 'baseline' | 'observe-only' | 'solve';   // v2 — see §4
};
```

### `engine.setBand(band) → Session`

Records the band without reloading. The site calls `loadDrill` instead; keep this for
free play.

---

## 3. Configuration

The rule from docs/UI.md is **collapse, never remove**. Every group must produce a
summary line that states the thing that matters even when the group is folded, because
that line is also rendered in the always-visible bench strip at the top of the page.

**The engine owns the option list.** Which options a bench accepts, what their legal
values are, what each one does and what a value costs the drill that is loaded all come
from `odr_scenario::options`. The site renders that list and carries none of its own — a
control the site invented would be a second, divergent statement of what a bench is,
which is the thing §3 has always existed to prevent. The lists genuinely differ per
bench: Secure Channel is meaningless on a Wiegand pair, and a card-layer bench has no
bus.

### `engine.configGroups() → ConfigGroup[]`

```ts
type ConfigGroup = {
  id: string;              // 'card' | 'reader' | 'link' | 'security' | 'controller' | 'attacker'
  title: string;           // 'Secure Channel'
  node: string;            // which topology node opens this group
  critical: boolean;
  summary: string;         // 'on, SCBK-D, SCS_17/18, 32-bit MAC'  ← required, never empty
  alert: boolean;          // true when this setting is the likely cause of a surprise
                           // (Secure Channel off, install mode on). Drawn with ▲ and a
                           // border — never colour alone.
  fields: Array<{
    id: string;            // the option id: 'secureChannel', 'macBytes', 'trustPdcap'
    label: string;
    type: 'boolean' | 'number' | 'select';
    value: boolean | number | string;
    options?: Array<[value: string, label: string]>;  // select only
    min?: number; max?: number; unit?: string;        // number only; unit is 'ms', 'bytes'
    help: string;          // one sentence, shown under the control
    critical?: boolean;    // this value is worth drawing attention to
    changed?: boolean;     // v3 — the learner moved it off the bench's own setting
    fixed?: boolean;       // the engine reports this and will not set it
    fixedReason?: string;  // why, in the engine's own words
    warning?: string;      // v3 — what this value costs the drill that is loaded.
                           // THE CONTROL STAYS LIVE. See below.
  }>;
};
```

**Two kinds of "no", and they must look different.**

**`fixed` fields are rendered as text, not as a dead control**, with `fixedReason`
printed under them. A field is fixed for one of two reasons: it is a value read off the
run rather than a setting (the PD address, the frames the attacker held), or it is a
setting this bench genuinely cannot express — and it is still *shown*, because "collapse,
never remove" means nothing that affects behaviour is invisible. A Wiegand bench states
that Secure Channel is off and says why it cannot be turned on.

**`warning` fields are rendered as live controls with the sentence beside them.** The
setting is real, the bench will build, and the drill's flag will stop being earnable.
docs/UI.md records the owner's feedback as *prefer warning over blocking*: watching a
drill stop working when you turn its defence on is the exercise, not an accident — drill
3.6 is the downgrade and drill 5.2 is detecting it, and `odr-bus` models both settings of
`trust_pdcap` precisely so a learner can run the attack and then run the fix. A control
that refused would forbid that.

`summary` is a **correctness requirement**, not decoration. A learner who cannot see that
Secure Channel is on while wondering why their replay failed has been misled by the
interface. The summary is computed from the bench that was *built*, so it moves when an
option moves without the site doing anything.

### `engine.setConfig(groupId, fieldId, value) → { ok, groups?, error? }`

Applies immediately, **rebuilds the bench**, bumps `engine.version`, and affects
everything the engine subsequently reports — traffic, timeline, topology, flag. `value`
crosses as a string for `select` and `number` fields and as a boolean or `"true"`/
`"false"` for `boolean` ones.

On `ok: false`, `error` is a human-readable sentence and the site surfaces it in the
notice bar rather than silently discarding the input. The engine refuses in exactly three
cases, all of them "this bench cannot be built that way":

1. the option is not one this scenario accepts — *"There is no Secure Channel on a
   Wiegand or clock-and-data pair…"*;
2. the value is not one of the option's declared legal values, and the error lists them;
3. there is no such option at all.

It does **not** refuse because a drill is loaded. That case is the `warning` field above.

**Determinism survives an option change.** The same options plus the same seed always
produce the same bytes, in any order they were set in, on any machine
(`the_same_options_give_the_same_bytes_across_a_rebuild`).

### `engine.resetConfig() → { ok, groups? }`

Puts every option back to the bench's own setting. New in v3, and it exists because the
bench a scenario defines is the one a drill's guidance was written against, so there has
to be one move back to it that is not "remember which four things you changed".
`loadDrill` and `loadSandbox` also clear the options — changing band or drill is a return
to a known starting position.

### What the options are

Not a fixed list — ask the engine. As of v3 a full OSDP bench offers:

| id | type | what it does |
|---|---|---|
| `secureChannel` | select `off` / `if-available` / `required` | how hard both endpoints insist |
| `key` | select `scbk-d` / `weak` / `site` | the published default, the sample-code family, or neither |
| `nullCipher` | boolean | SCS_15/16 — authenticate without encrypting |
| `macBytes` | number 1–4 | four is the only honest width; shorter is drill 4.2's rig |
| `trustPdcap` | boolean | believe the unauthenticated capability reply. Drill 3.6's target, and its defence |
| `acuInstallMode` | boolean | the controller hands out the site key on request |
| `pdInstallMode` | boolean | the reader will take a key from anyone |
| `pdClaimsAes` | boolean | what the PDCAP reply says. The entry the downgrade deletes |
| `baud` | select | the line rate |
| `pollMs` | number 10–2000 | how much idle traffic there is |
| `format` | select | the credential format on the wire |
| `strikeMs` | number | how long the door stays unlocked |

A legacy bench offers `linkType` (`wiegand` / `clockdata`), `format` and `strikeMs`, and
reports the rest as fixed. A card-layer bench offers `strikeMs`. Drill 0.6 and Module 5
offer nothing and say why.

---

## 4. Topology and taps

### `engine.topology() → Topology`

```ts
type Topology = {
  nodes: Array<{
    id: 'card' | 'reader' | 'controller' | 'door';
    label: string;          // 'Reader'
    sub: string;            // 'PD'
    configGroup: string;    // which ConfigGroup opens when the node is activated
    state: string;          // 'open' | 'closed' for the door; 'idle' otherwise
  }>;
  links: Array<{
    id: 'card-reader' | 'reader-controller' | 'controller-door';
    from: string; to: string;
    label: string;
    protocol: 'rf' | 'wiegand' | 'clockdata' | 'osdp' | 'relay';
    tappable: boolean;
    cut: boolean;           // true when an inline tap has severed this link
    configGroup: string;
  }>;
  taps: Array<{
    id: TapId;
    linkId: string;
    mode: 'sniff' | 'inject' | 'inline';
    prePlaced: boolean;     // true when Bronze placed it rather than the learner
  }>;
};
```

`cut` drives the drawing directly: the link is rendered as two severed stubs with the
implant sitting in the gap between them. That picture is the point of the topology strip,
so `cut` must be true for `inline` and false for everything else.

**More than one tap may sit on a link.** Version 1 of this document said at most one, and
that was wrong: drill 4.3's IV-reuse attack is an inline implant *and* a passive analyser
on the same pair, which is what a real operator carries and what `odr-bus` allows. The
drill's own `taps` list names both. `addTap` therefore **adds**; it does not change an
existing tap's mode. A second tap in the *same* mode on the same link is refused, with a
reason: two identical probes are not a second capability.

The tap panel draws the taps on a link as a list you add to and remove from, and the
topology strip draws an inline tap in the path with the link severed either side of it,
and any other tap hanging off the link on a lead. With two fitted you see both.

### `engine.addTap({ linkId, mode }) → { ok, tap?, error? }`
### `engine.setTapMode(tapId, mode) → { ok, tap? }`
### `engine.removeTap(tapId) → { ok }`

**Taps must actually gate the simulation.** If no tap can write to the link, the engine
must not produce injected frames, substituted credentials or downgraded PDCAP replies,
and must not produce the door-open events that follow from them. The mock does this by
tagging each attacker-produced frame and event with the capability it needs
(`'any' | 'write' | 'inline'`) and filtering on the current taps. The site depends on the
behaviour either way: drill 1.3's flag is "the controller granted when no credential was
presented", and it must not be earnable by pressing Run with no tap fitted.

**How the wasm engine does it.** `odr-scenario` is not incremental — it builds a bench,
clips an attack on, runs the whole script and hands back one outcome — so the taps decide
*which of its entry points the drill is driven with*, and `Session.runner` reports which:

| Learner's taps | `runner` | What happens |
|---|---|---|
| satisfy the drill's `taps` list | `solve` | the attack is clipped on and performed |
| present, but not the ones the attack needs | `observe-only` | a passive probe, the script run, no analysis |
| none | `baseline` | the bench with nothing clipped to it |

Each entry in the drill's list consumes a **distinct** tap, so drill 4.3 is not satisfied
by one inline tap doing both jobs. Capability is ordered the way the hardware is: anything
can listen, writing needs an injecting or inline tap, and cutting the link needs an inline
one and nothing else will do.

The bridge never decides a flag. It decides which run to perform; `odr-scenario` reads
the world that came out and decides the flag.

---

## 5. Time

### `engine.duration() → tUs`
### `engine.nextEventUs(tUs) → tUs` / `engine.prevEventUs(tUs) → tUs`

The next/previous frame boundary. These drive the Step controls, so "step" means "to the
next thing that happened", not a fixed time increment.

### `engine.stateAt(tUs) → State`

```ts
type State = {
  tUs: number;
  door: 'open' | 'closed';
  strike: 'idle' | 'energised';
  decision: 'none' | 'granted' | 'denied';
  lastCredential: string | null;      // '42/24601'
  secureChannel: 'off' | 'configured' | 'established' | 'downgraded';
  scs: string | null;                 // 'SCS_17/18'
  key: string | null;                 // 'SCBK-D'
  attacker: {
    taps: number;
    inline: boolean;
    holdsKeys: boolean;
    captured: number;                 // frames in the attacker's buffer
  };
};
```

Called on every animation frame during playback. Keep it cheap, or memoise.

`door` drives the animation. The strike-fire event on the timeline is the authoritative
record; the swinging door is the reward (docs/UI.md).

### `engine.markers() → Marker[]`

```ts
type Marker = { tUs: number; label: string; kind: 'card' | 'grant' | 'deny' | 'attack' | 'handshake' };
```

Each `kind` gets a glyph as well as a colour. Colour never carries meaning alone.

---

## 6. Traffic

### `engine.frames(opts) → FramePage`

```ts
opts = {
  fromUs?: number;        // default 0
  toUs?: number;          // default Infinity
  collapseIdle?: boolean; // default false — see §8
  filter?: string | null; // case-insensitive substring over label, summary, kind
  limit?: number;         // default 4000; the newest `limit` rows are returned
}

type FramePage = {
  total: number;          // matching frames before the limit
  truncated: boolean;
  collapsed: null | { hiddenFrames: number; spans: Array<{ fromUs, toUs, count }> };
  rows: Array<FrameRow | CollapsedRow>;
};

type FrameRow = {
  id: FrameId;
  tUs: number;
  line: 'rf' | 'wiegand' | 'rs485';
  lane: 'rf' | 'wire' | 'bus';
  dir: 'acu_to_pd' | 'pd_to_acu' | 'card_to_reader' | 'wire';
  label: string;          // 'POLL', 'RAW', 'D0/D1'
  kind: string;           // stable machine name: 'poll', 'raw', 'pdcap_downgraded'
  summary: string;        // one line of prose
  secure: { active, scs, encrypted, macBits };
  origin: 'bus' | 'card' | 'reader' | 'attacker';
  tapped: boolean;
  length: number;         // bytes
};

type CollapsedRow = {
  id: string; collapsed: true;
  tUs: number; toUs: number; count: number;
  lane: 'bus'; line: 'rs485'; dir: string; label: '⋯';
  summary: string; kind: 'collapsed';
};
```

`kind` is what drill predicates and the site's filters key off. Keep the names stable.
For a bus frame it is the lower-cased command or reply name, so the full set is the OSDP
code set: `poll`, `ack`, `nak`, `busy`, `cap`, `pdcap`, `id`, `pdid`, `raw`, `out`,
`led`, `buz`, `chlng`, `ccrypt`, `scrypt`, `rmac_i`, `keyset`, `lstat`, `lstatr` and so
on. For a wire or RF frame it is `rf_present`, `wiegand` or `clockdata`.

Two suffixes and one replacement carry the attacker's hand:

- **`_injected`** — the frame came from a tap rather than from the endpoint whose address
  it carries: `out_injected`, `wiegand_injected`.
- **`_substituted`** — an inline tap consumed the real frame and emitted its own:
  `wiegand_substituted`.
- **`pdcap_downgraded`** — a `PDCAP` reply from a tap with the 0x09 communication-security
  entry deleted. Named rather than suffixed because it is the downgrade attack and drill
  5.2 is about recognising exactly this.

Plus `collapsed`, for the rows §8 produces.

### `engine.frame(id) → FrameDetail | null`

This is the one the interface is built around. Get it right.

```ts
type FrameDetail = {
  id: FrameId; tUs: number;
  line, lane, dir, label, kind, summary: as above;
  view: 'hex' | 'bits';       // 'bits' for RF and Wiegand, where bytes are a lie
  note: string;               // teaching note about this frame. May be ''.
  origin: string; tapped: boolean;
  secure: { active: boolean; scs: string | null; scsByte?: number;
            encrypted: boolean; macBits: number; keyHeld: boolean };
  bytes: number[];            // every octet on the wire, mark byte included
  bits: number[] | null;      // 0/1 per bit, for view: 'bits'
  fields: Field[];            // the decode tree, in wire order
};

type Field = {
  id: string;                 // stable; drill predicates name these
  name: string;               // 'Security block'
  value: string;              // '02 18' — displayed verbatim, selectable text
  meaning: string;            // 'SCS_18'
  note: string;               // the teaching sentence. May be ''.
  visibility: 'clear' | 'opaque';

  // Position — exactly one of these addressing modes per field:
  offset?: number;            // absolute byte offset into `bytes`
  length?: number;            // in bytes
  offsetInPayload?: number;   // byte offset relative to the PARENT field (-1 = not present on the wire)
  bitOffset?: number;         // bit offset into `bits`, for view: 'bits'
  bitLength?: number;

  children?: Field[];         // nested decode, e.g. the control byte's three flags
  sealed?: {                  // present only on an encrypted payload the bench can decrypt
    length: number;
    bytes: string;            // 'DC 4E CE …' — the recovered PLAINTEXT, space-separated hex
    fields: Field[];          // its decode tree, offsets relative to the plaintext
  };
};
```

**The split is structural.** The inspector always draws two labelled groups:

- *Readable without a key* — every field with `visibility: 'clear'`.
- *Requires the session key* — every field with `visibility: 'opaque'`.

Both groups are drawn on every frame, in every security mode. On a cleartext frame the
second is drawn empty and says so, which is the Module 2 lesson. On an SCS_17/18 frame
the **command or reply code must appear in the readable group** — it is plaintext in every
OSDP security mode, and a learner meets that fact by looking at it three modules before
drill 4.1 makes it matter. This is not a toggle and not a tooltip. If the engine ever
marks the command byte `opaque`, the interface is lying.

`sealed` is how "we hold the key" is expressed. The plaintext is rendered *beneath* the
ciphertext with a KEY HELD marker on every row, so it can never be mistaken for something
an observer had.

**In the wasm engine `sealed` is real AES.** It is filled in only when the attacker's own
knowledge base holds an SCBK for that address — recovered from the capture by the drill's
attack, with a provenance saying how — and a shadow session reconstructed from the
handshake actually decrypts the frame. `secure.keyHeld` says whether that happened.
Drill 4.1's predicate insists the attacker held no key at any point, so on that bench
every payload stays sealed and the traffic-analysis lesson survives intact; drill 3.2's
attack recovers SCBK-D from the handshake and the card read opens, down to a decoded
facility code and card number.

Mark a field `offsetInPayload: -1` to show something that is conspicuously **absent** —
the site renders it with `value: 'absent'`. That is how the downgraded PDCAP reply shows
the missing 0x09 communication-security entry.

`engine.frame()` also records that the learner looked at this frame; see §9.

---

## 7. Timeline

### `engine.timeline({ fromUs, toUs, bins, collapseIdle }) → Timeline`

```ts
type Timeline = {
  fromUs: number; toUs: number; bins: number;
  honest: boolean;                 // false once collapseIdle is on
  collapsed: null | { hiddenFrames: number; spans: [...] };
  markers: Marker[];
  lanes: Array<
    | { id: 'rf' | 'wire' | 'bus'; label: string; type: 'density'; bins: number[] }
    | { id: 'door'; label: string; type: 'state';
        segments: Array<{ fromUs: number; toUs: number; state: 'open' | 'closed' }> }
  >;
};
```

`bins` is the requested bucket count; the site asks for about 600 and scales the bars
against the lane maximum. A density lane returns a count per bucket, not a normalised
value — the site needs the counts to tell 20 polls/s from 50.

---

## 8. Honest density

**DECIDED (docs/UI.md): honest by default, collapse on request.**

- The bus lane and the traffic list show *every* frame by default. A real OSDP link polls
  tens of times a second and the timeline should look like it.
- `collapseIdle: true` groups runs of four or more consecutive POLL/ACK pairs, with no
  other traffic between them, into one collapsed span.
- The engine reports what was hidden (`collapsed.hiddenFrames`, `collapsed.spans`). The
  site displays that count permanently while collapse is on, because compression must
  always be a thing the learner can see they chose.
- **Non-sticky.** The site resets `collapseIdle` to false on every `loadDrill`. The
  engine must not persist it.

---

## 9. Flags

Drills do not check typed answers. A flag is earned when the engine's own state satisfies
the predicate (DESIGN.md §3).

### `engine.flag() → Flag`

```ts
type Flag = {
  drillId: DrillId | null;
  predicate: string;        // prose, shown verbatim
  earned: boolean;
  simulated?: boolean;      // false for reference sections — renders as 'REFERENCE — no flag'
  evidence: string[];       // what the engine observed, in its own words, with times
  outstanding: string[];    // what is still missing. Shown only while unearned.
  completion?: 'flag' | 'measurement' | 'reference';   // v2
  measurement?: null | { label: string; value: string; compareWith: string };  // v2
};
```

`evidence` is what makes the flag trustworthy: "Controller granted at t=13.700 s on
credential 42/24601" is a claim about engine state. Write these in engine terms, with
times and ids, not as congratulation.

The site calls `flag()` after every learner action and writes completion to
`localStorage` the first time `earned` goes true. Completion is per drill, not per band.

### `engine.observe(action) → void`

```ts
{ type: 'frame_selected', frameId, frameKind }
{ type: 'field_opened',   fieldId }
{ type: 'cursor',         tUs }
{ type: 'diagnosis',      text? }
```

**Advisory as of v2.** The mock used these to approximate the predicates that take a
typed claim: it watched which field you opened in the decode tree and called that the
answer. The real predicates read the world, the attacker's knowledge base and the run's
measurements, and none of them reads an observation. The call is kept because a future
predicate might want it, and because removing it would be a breaking change for no gain.

The wasm engine's `observe` deliberately does **not** bump `engine.version`: an
observation changes no engine state, and a bump would drop the wrapper's caches on every
cursor move.

### `engine.submission() → SubmissionForm | null`   *(v2)*

The seven drills that take a typed claim, plus the reference section, say what they want
here. `null` when the drill wants nothing.

```ts
type SubmissionForm = {
  prompt: string;            // what the drill asks for, in the engine's own words
  fields: Array<{
    id: string;
    label: string;
    type: 'text' | 'number' | 'boolean' | 'select';
    help: string;
    value: string;           // what the learner has entered so far, '' if nothing
    options?: Array<[value: string, label: string]>;   // select only
  }>;
};
```

**The engine composes the form.** Drill 2.1's field list is one offset-and-length pair per
field of the frame that actually crossed the bus, derived from the layout the engine
generated; the site never has to know what an OSDP frame contains. Module 5's form is a
choice of *rule set*, because a Module 5 drill submits a list of detectors rather than a
value and the engine runs it rather than comparing it.

Module 5's `ruleset` field is the **"start from"** control (v4): its options are the
presets `ruleCatalog()` lists, plus — when the learner has composed something that is not
a preset — one more option carrying their own composition, so the selector never reports
a preset while the engine is running something else. The field's value is a composition
string, and `submitField('ruleset', text)` accepts either form.

### `engine.submitField(id, value) → Flag`   *(v2)*
### `engine.clearSubmission() → Flag`   *(v2)*

One field at a time, as a string; the engine parses. Both return the re-evaluated flag.
A submission that changes what the engine *runs* — Module 5's rule set — re-runs the
bench, so the site re-reads everything after a submission rather than only the flag card.

These are claims, not answer strings: each is compared against a value this session's
seed produced. A different seed gives a different correct answer and there is nothing in
the repository to look up. That is why the bench's card panel does not print the facility
code and card number: it would turn drill 1.1 into a lookup.

---

## 10. Long-running attacks

**DECIDED (docs/UI.md): run the real one on a bar that never finishes.** Drill 4.2's
shortened MAC completes in seconds and the drill proceeds. Alongside it, the genuine
computation starts and keeps running, with a crawling progress bar and a projected
completion date rendered in full.

### `engine.tasks` (property) → array; `engine.startTask(id) → { ok }`
### `engine.taskStates(elapsedMs) → TaskState[]`

```ts
type TaskState = {
  id: string;               // 'mac-forge', 'wiegand-sweep'
  label: string;            // '32-bit MAC forgery — the real one'
  shortLabel: string;       // 'shortened MAC (12 bits) — for the drill'
  shortDone: boolean;       // the shortened run has completed
  note: string;             // why the number is what it is
  done: number; total: number; fraction: number;
  remainingSeconds: number;
  projected: string;        // '8.5 years — 27 March 2035'
};
```

`elapsedMs` is wall-clock milliseconds since the drill was loaded, passed in by the site.
This is the **only** place wall-clock time enters the engine, and it is deliberately not
part of the simulation: it exists so the bar crawls at a rate the learner can feel.

The rates must be defensible arithmetic, not drama. The wasm engine measures them off the
bench rather than choosing them: `MacForger::us_per_attempt` is one round trip at this
link's actual baud rate, and `BruteForcer::us_per_credential` is one Wiegand frame plus
the settle time at this bench's actual wire timing. Turn the baud rate up and both numbers
move. The reasoning is in `note`, in the engine's own words.

**`projected` is a duration, not a date** (v2). The engine has no wall clock and no epoch;
inventing one to print "27 March 2035" would be the engine claiming to know something it
does not. `docs/UI.md` decided the date is rendered in full, so `site/js/ui/drill.js`
computes it from `remainingSeconds` and appends it. That is the only wall-clock arithmetic
on the site's side and nothing a flag depends on reads it.

`startTask` marks the shortened run complete. The real bar is never marked complete.
Note that in the wasm engine the shortened run has usually **already** completed by the
time the bar appears: clipping the drill's tap on is what runs it, so the button is
normally the "✔ the shortened run finished" state from the outset. The half that matters
— a bar still crawling, with a date on it — is unaffected.

---

## 11. What the site does NOT need

So you do not build it:

- No serialisation, save or export. Progress is drill completion in `localStorage`, and
  the site owns that.
- No pause/resume of engine time. The site owns the playback cursor and calls `stateAt`.
- No streaming or events. Pull-based accessors, all synchronous.
- No frame composer yet. When it lands it wants `engine.composeFrame(spec) → FrameDetail`
  plus `engine.injectFrame(tapId, bytes)`; nothing in the current interface calls either.
- No capture import yet. `odr-cli` owns the NDJSON seam (DESIGN.md §3). When the site
  grows an import, it wants `engine.loadCapture(ndjsonText) → Session`.

---

## 12. Where the two engines differ

`site/js/engine-mock.js` is the reference implementation and is kept. These are the places
the two engines are not the same thing, so a reader of either knows what they are looking
at.

### What the real engine does properly

0. **Module 5's day is real traffic** (§13). The mock's day, its answer key and the
   findings each rule produces on it are hand-written and say so. The real engine
   generates twelve episodes by running `odr-bus`, exports one passive probe's capture,
   and runs the detectors against the re-imported file — so the frames a finding cites are
   frames a bus produced. What the mock does implement honestly is the *mechanism*: a
   composition selects rules, rules produce findings, findings are scored against a key
   containing benign events, and a set that alerts on everything scores badly in both.
1. **The bytes are real.** Cryptograms, ciphertext and MACs are AES, computed by
   `odr-osdp`, not seeded filler. So are the CRCs, control bytes, security-block layout,
   lengths and Wiegand parity, which the mock also got right.
2. **`sealed` is real decryption** (§6). The mock printed a canned plaintext; the real
   engine reconstructs the session from the handshake under a key the attacker's own
   attack recovered, and refuses when it has no key.
3. **The flags are the curriculum's predicates.** Every verdict, every line of `evidence`
   and every line of `outstanding` comes from `odr-scenario`'s `flag.rs`, reading the
   world's event log, the attacker's knowledge base and the run's measurements. The mock
   approximated several of them; `attacker.holdsKeys`, in particular, was inferred from
   the configured key plus the presence of a tap, and is now the attacker actually holding
   one, with a provenance.
4. **Taps gate by running a different attack, not by filtering rows** (§4).
5. **Drill 4.1's day is the engine's day** — 36 seconds of bus carrying seven badge-ins,
   generated by running the bus rather than written out. `odr-scenario`'s README explains
   why it is 36 seconds and not 24 hours: the limit is the screen, not the engine.

### What the real engine cannot do that the mock appeared to

1. **Configuration is read-only** (§3). The mock's controls changed a summary line; the
   real engine has no seam to change a bench after it is built, and says so rather than
   offering a control that does nothing.
2. **Free play performs no attack** (§2). A tap in free play listens.
3. **Drill 1.6's clock-and-data is a separate bench**, which `odr-scenario` builds; the
   mock reused the Wiegand scenario. This one is a straight improvement, listed here only
   because version 1 named it as a shortcut.

### What neither engine does

**Drill 4.4 cannot show a null cipher in the reply direction.** `odr-bus`'s peripheral
asks for encryption on `REPLY_RAW` unconditionally, so the bench runs a null cipher on the
command half of the link and not the reply half. `odr-scenario`'s README names the
one-field fix in `odr-bus` and the drill's guidance says plainly which half it can show.
That is a change to another crate and is reported rather than worked around.

---

## 13. The rule editor (Module 5)   *(v4)*

`docs/CURRICULUM.md` Module 5 replays every earlier module from a monitoring position,
and its flag line is:

> the learner's rule set is run against a generated day of traffic containing both
> attacks and benign events, and is scored on true positives and false positives.

Drill 5.2 is sharper than that: *build* a detection rule that catches the downgrade and
does not fire on a genuine legacy reader being added to the bus. So the engine publishes
the parts, takes a composition, and hands back a score that shows its reasoning.

### `engine.ruleCatalog() → RuleCatalog`

```ts
type RuleCatalog = {
  rules: Array<{
    id: string;                 // 'downgrade' — the same string the detector answers to
    label: string;
    catches: string;            // one line: what it finds
    falsePositives: string;     // one line: what it will fire on that is not an attack
    inStandard: boolean;        // whether the 'standard' preset includes it
    selected: boolean;          // whether it is in the set the engine currently holds
    signals: Array<{ id: string; describes: string }>;
    params: Array<{
      id: string;               // matches the field name on the detector struct
      label: string;
      help: string;             // what moving it buys, and what it costs
      type: 'toggle' | 'count' | 'duration';
      unit?: 'us';              // duration only
      min: number; max: number; // the engine's bounds, inclusive
      default: number;          // the detector's own default; a toggle is 0 or 1
      value: number;            // what is set now, or the default when unselected
      changed: boolean;
    }>;
  }>;
  presets: Array<{ id: string; label: string; help: string; text: string }>;
  selection: Selection;
};

type Selection = {
  text: string;                 // the composition, round-trips through setRules
  name: string;
  preset: string | null;        // the preset this is identical to, if any
  ruleCount: number;
  signals: Array<{ id: string; describes: string }>;
};
```

**Everything the interface draws is in here.** A bound changed in `odr-detect` cannot go
stale in the site, because there is no copy of it in the site to go stale. A rule added to
the catalogue appears in the editor without the editor being touched.

### `engine.setRules(text) → { ok, error, selection }`

`text` is a preset id (`'standard'`) or a composition:

```
posture;downgrade:require_same_identity=0;traffic:min_events=1
```

Rule ids separated by `;`, each optionally followed by `:` and comma-separated
`name=value` pairs. Values are whole numbers — a toggle is `0` or `1`, a duration is
microseconds. **Only parameters that differ from the detector's default are written**, so
a set that changed one thing reads as one thing changed, and the ordering is the
catalogue's, so two learners who selected the same rules in different orders produce the
same string.

A refusal (`ok: false`) names the rule, the parameter and the legal range, and leaves the
engine holding what it held. `setRules` runs the set and re-evaluates the flag, so the
site re-reads everything afterwards rather than only the flag card.

### `engine.detection() → Detection | null`

`null` outside Module 5.

```ts
type Detection = {
  ran: boolean;                 // a non-empty set was run against a real capture
  probeOnLink: boolean;         // a monitor that is not clipped on sees nothing
  error: string | null;         // the last refusal, if any
  ruleSet: Selection;
  evidenceChecks: boolean;      // every citation still names the bytes it claims to
  score: {
    findings, truePositives, falsePositives, falseNegatives, ambiguous: number;
    precisionPct, recallPct: number;       // integers; see below
    quietOnBenign: boolean;
    worstTimeToDetectUs, meanTimeToDetectUs: tUs;
  };
  caught:         Finding[];    // + label, verdict, expectedUs, latencyUs
  ambiguousHits:  Finding[];    // matched an ambiguous expectation
  missed:         Array<{ signal, describes, label, verdict, tUs, episode }>;
  falsePositives: Finding[];    // + benign: string | null
  benign:   Array<{ tUs, durationUs, label, looksLike, episode }>;
  episodes: Array<{ id, describes, startUs, endUs }>;
  listCap: number;              // how many of each list are drawn; see below
  summary: string;
};

type Finding = {
  signal: string; describes: string;
  tUs: tUs; severity: string; confidence: string;
  note: string;                 // the reasoning, including the benign explanation
  episode: { id, describes } | null;
  frameCount: number;
  frames: Array<{ index: number; tUs: tUs; summary: string; hex: string; bytes: bytes }>;
};
```

Four things about this shape are load-bearing.

**Every finding carries the frames that justify it.** `odr-detect`'s rule is that a
finding with no evidence is an opinion; `Evidence::check` re-reads every citation against
the capture and `evidenceChecks` reports the result. A score without its reasoning teaches
a learner to chase a number.

**Every false positive is named.** `benign` is the label of the benign event the finding
landed on, and `episode` says which stretch of the day that was. "A downgrade was reported
at t=349 s" tells a learner nothing; "a downgrade was reported during the
reader-replacement episode" tells them which knob to turn. That is the whole of drill 5.2.

**There are three verdicts, not two.** `ambiguous` counts findings that matched an
expectation whose cause the wire does not carry — a `CMD_KEYSET` is both the worst thing
on a bus and undecidable. They are excluded from precision and recall: a learner is
neither rewarded for reporting a commissioning nor punished for it, which is exactly the
position a defender is in. That is drill 5.3's answer.

**`benign` is available before the learner runs anything.** The traffic that is supposed
to look like an attack is part of the exercise, not a punishment revealed afterwards.

`precisionPct` and `recallPct` are integers, floored. `DESIGN.md` §3 wants a score that is
identical on every machine, and a rounded float is a bad way to get there.

**The lists are capped, and say so.** A rule set tuned to alert on everything produces
hundreds of findings. `caught`, `missed`, `falsePositives` and `ambiguousHits` carry at
most `listCap` entries each while `score` carries the full counts, so the interface can
say "60 of 716 shown" rather than quietly drawing sixty. `docs/UI.md`: collapse, never
remove.

### What the editor must not do

**It must not score anything.** `odr-scenario` owns the answer key and the scorer, and the
key is built from the scenario script rather than from what any detector found. A site
that computed a number would be a second opinion about what a good rule set is.

**It must not block a bad rule set.** `docs/UI.md`'s recorded feedback is prefer warning
over blocking. A set that will obviously score badly is run anyway: watching it score
badly is the lesson, and an editor that refused to run it would be teaching by assertion.
