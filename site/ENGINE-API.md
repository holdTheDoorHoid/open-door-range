# The engine contract

What `site/` needs from `crates/odr-wasm`.

The front end talks to exactly one object. `site/js/engine-mock.js` implements this
contract today with canned-but-honest data; when the WebAssembly build is ready, ship
`site/js/engine-wasm.js` exporting the same names and change one line in
`site/js/app.js`:

```js
import { createEngine } from './engine-mock.js';   // → './engine-wasm.js'
```

Nothing else in the site imports the engine. If you find yourself needing to change a
second file, the contract below is wrong and should be fixed here first.

**Nothing in this API may touch the network.** The site's privacy promise is literal: no
backend, no telemetry, no fetch of any kind at runtime. The wasm binary is loaded as a
static asset from the same origin and that is the only request the page ever makes.

---

## 0. Module surface

```js
export const ENGINE_KIND;          // 'mock' | 'wasm'
export const ENGINE_API_VERSION;   // integer; bump on a breaking change. Currently 1.
export async function createEngine(options?): Promise<Engine>;
```

`createEngine` is async so the wasm build can `await init()` inside it. `options` is
reserved; the site passes nothing today. The returned object must be usable immediately
— it boots with a drill already loaded (the mock loads `1.1`; the site then calls
`loadDrill` with whatever `localStorage` remembered).

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

### `engine.session` (property) → `Session`

```ts
type Session = {
  drillId: DrillId | null;   // null in free play
  band: 'bronze' | 'silver' | 'gold';
  scenarioId: string;
  sandbox: boolean;
  title: string;             // '1.3 Replay' or 'Free play'
  durationUs: number;
  seed: number;
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
    id: string;
    label: string;
    type: 'boolean' | 'number' | 'select';
    value: boolean | number | string;
    options?: Array<[value: string, label: string]>;  // select only
    min?: number; max?: number;                       // number only
    help: string;          // one sentence, shown under the control
    critical?: boolean;
  }>;
};
```

`summary` is a **correctness requirement**, not decoration. A learner who cannot see that
Secure Channel is on while wondering why their replay failed has been misled by the
interface.

### `engine.setConfig(groupId, fieldId, value) → { ok, groups?, error? }`

Applies immediately and affects everything the engine subsequently reports. On `ok:
false`, return a human-readable `error`; the site will surface it rather than silently
discarding the input.

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

At most one tap per link. `addTap` on a link that already has one changes its mode.

### `engine.addTap({ linkId, mode }) → { ok, tap?, error? }`
### `engine.setTapMode(tapId, mode) → { ok, tap? }`
### `engine.removeTap(tapId) → { ok }`

**Taps must actually gate the simulation.** If no tap can write to the link, the engine
must not produce injected frames, substituted credentials or downgraded PDCAP replies,
and must not produce the door-open events that follow from them. The mock does this by
tagging each attacker-produced frame and event with the capability it needs
(`'any' | 'write' | 'inline'`) and filtering on the current taps. The real engine gets
this for free by running the actual bus. The site depends on the behaviour either way:
drill 1.3's flag is "the controller granted when no credential was presented", and it
must not be earnable by pressing Run with no tap fitted.

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
The ones currently in use: `rf_present`, `wiegand`, `wiegand_substituted`, `poll`, `ack`,
`raw`, `out`, `out_injected`, `cap`, `pdcap`, `pdcap_downgraded`, `chlng`, `ccrypt`,
`scrypt`, `rmac_i`, `collapsed`.

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
};
```

`evidence` is what makes the flag trustworthy: "Controller granted at t=13.700 s on
credential 42/24601" is a claim about engine state. Write these in engine terms, with
times and ids, not as congratulation.

The site calls `flag()` after every learner action and writes completion to
`localStorage` the first time `earned` goes true. Completion is per drill, not per band.

### `engine.observe(action) → void`

Some flags depend on the learner *reading* something the engine generated — drill 1.1
("submit the facility code and card number the engine transmitted"), 2.1 ("label the byte
offsets"). The site reports those actions so the engine can hold them as session state:

```ts
{ type: 'frame_selected', frameId, frameKind }
{ type: 'field_opened',   fieldId }
{ type: 'cursor',         tUs }
{ type: 'diagnosis',      text? }        // for the diagnose-style drills, 0.5 / 5.1 / 5.3
```

These are observations, not answers. The engine still decides whether the predicate holds.
`engine.frame(id)` implies a `frame_selected` observation; the site does not send a
duplicate.

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

The rates must be defensible arithmetic, not drama. The mock uses 16 candidate frames per
second for a 32-bit MAC forgery (an online attack, one round trip per attempt at 9600
baud → ~8.5 years) and 18.5 credentials per second for a 26-bit Wiegand sweep at real
wire timing (→ ~42 days). Keep whatever the engine can defend; put the reasoning in
`note`.

`startTask` marks the shortened run complete. The real bar is never marked complete.

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

## 12. Known mock shortcuts

Things the mock fakes that the real engine should do properly. None of them change the
shape of the API.

1. **Cryptograms, ciphertext and MACs are seeded pseudo-random filler.** Correct lengths,
   correct positions, not the output of AES. The CRCs, control bytes, security-block
   layout, lengths and Wiegand parity *are* real and computed.
2. **Drill 4.1's "day" is 40 seconds of bus** carrying seven badge-ins. The real engine
   should generate a full day; nothing in the interface changes when it does.
3. **Several predicates are approximated.** `attacker.holdsKeys` is inferred from the
   configured key plus the presence of a tap, rather than from an attacker actor that
   actually derived them. Drills 3.3, 3.4, 3.5, 4.3 and the Module 5 detection scoring are
   stubs against the real `odr-attack` and `odr-detect` behaviour.
4. **Configuration changes do not re-run the scenario.** Setting Secure Channel on in the
   mock changes the summary lines and the bench strip, but the canned traffic does not
   regenerate. The real engine re-runs, and the site will pick that up with no change: it
   re-reads `frames()`, `timeline()` and `stateAt()` after every `setConfig`.
5. **Clock-and-data (drill 1.6) reuses the Wiegand scenario.** The link panel offers the
   encoding; the mock does not produce a different bit stream for it.
