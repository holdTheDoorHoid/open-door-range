# `odr-bus`

The world model. A card, a reader, a wire or a bus, a controller and a door,
assembled into a running system that can be observed and interfered with.

This is item 4 in the Open Door Range build order (`DESIGN.md` §3 and §6).
`odr-attack`, `odr-detect`, `odr-scenario`, `odr-wasm` and the site are all
built on the API here, so the shape of this crate matters more than any single
feature in it.

```
credential ──▶ READER ──wire or bus──▶ CONTROLLER ──▶ DOOR
                         ▲
                        tap
```

## Constraints it keeps

- **`no_std` + `alloc`.** No `std::time`, no threads, no OS randomness, no
  `getrandom`. Dependencies are `odr-osdp` and `odr-wiegand` and nothing else.
- **`#![forbid(unsafe_code)]`**, `#![warn(missing_docs)]`.
- **Builds for `wasm32-unknown-unknown`.**
- **Deterministic.** A virtual microsecond clock the caller drives; one seeded
  SplitMix64 (`odr_osdp::rng::SeededRng`) behind every nonce; an event queue
  that breaks ties by insertion order; no map iteration anywhere; integer
  arithmetic throughout. Same seed, same inputs, byte-identical event log.
- **No panics.** Every fallible operation returns `BusError`. A panic in a
  browser is a dead tab.

```
cargo test -p odr-bus
cargo build --target wasm32-unknown-unknown -p odr-bus
cargo clippy -p odr-bus --all-targets -- -D warnings
```

## Module layout

| Module | Contents |
|---|---|
| `world` | `World` — the clock, the event queue, the dispatch loop, and every accessor a flag predicate needs |
| `log` | `EventLog`, `LogRecord`, `RecordKind` — the primary output, not debug logging |
| `sched` | the priority queue, the internal event type, `Injection`/`InjectionPayload` |
| `credential` | `Presentation`, `FormatId`, `CredentialSource` — the seam `odr-credential` plugs into |
| `reader` | `Reader`: Wiegand, clock-and-data, and a full OSDP PD (`PdConfig`, `PdRuntime`) |
| `controller` | `Controller`: a legacy panel, and a full OSDP ACU (`AcuConfig`, `PdSession`, polling, Secure Channel) |
| `door` | `Door`: strike, lock state, position switch, request-to-exit |
| `link` | `WiegandLink`, `ClockDataLink`, `Rs485Bus`, and `Chain` — the segment model taps depend on |
| `tap` | `PassiveTap`, `InjectingTap`, `InlineTap`, and the `Tap` / `TapPolicy` traits |
| `access` | `AccessList`, `AccessEntry`, `AccessPolicy` |
| `capture` | the newline-delimited JSON format of `DESIGN.md` §3, export **and** import |
| `builder` | `WorldBuilder`, plus `wiegand_bench` / `clock_data_bench` / `osdp_bench` |
| `error` | `BusError` |
| `ids` | `ReaderId`, `ControllerId`, `DoorId`, `LinkId`, `TapId`, `SourceId`, `Origin`, `Endpoint` |

The commonly used items are re-exported at the crate root.

## The event log schema

Every state change emits one record. The site's timeline and traffic list render
straight from this; `odr-detect` reasons over it; `odr-scenario` evaluates flag
predicates against it.

```rust
pub struct LogRecord {
    pub seq:   u64,          // position in the log, assigned in order
    pub t_us:  u64,          // virtual microseconds
    pub cause: Option<u64>,  // the seq of the record that caused this one
    pub kind:  RecordKind,
}
```

`seq` is the tie-break when two records share a timestamp, and it is stable
across runs of the same seeded scenario — which is what makes the determinism
test meaningful.

`cause` is what turns the log from a list into a graph. `EventLog::originator`
walks it: "the PD ACKed a command originated by the attacker" (curriculum 2.3)
is `log.originator(ack.seq) == Some(Origin::Tap(t))`.

### Record kinds

| Kind | Emitted when |
|---|---|
| `Started { seed }` | always first; a log identifies the run that produced it |
| `CredentialPresented { reader, source, format, bits, label }` | a token was held up to a reader |
| `CredentialRejected { reader, source, reason }` | it produced nothing usable |
| `WireTx { link, segment, origin, kind, bits }` | bits were driven onto a two-wire segment |
| `WireRx { link, segment, receiver, kind, bits, start_us, end_us }` | a frame was recovered at the far end |
| `WireAnomaly { link, segment, anomaly }` | something was wrong electrically |
| `BusTx { link, segment, origin, dir, bytes, frame }` | octets were driven onto a bus segment |
| `BusRx { link, segment, receiver, dir, bytes, frame }` | they were delivered to a listener |
| `BusCollision { link, segment, origins }` | two transmitters overlapped |
| `TapAction { tap, link, action }` | a tap dropped, replaced, injected, or was overruled |
| `SecureChannel { endpoint, event }` | requested / established / failed / declined / keyset |
| `Protocol { endpoint, event }` | command, reply, timeout, BUSY, NAK, sequence, offline/online |
| `AccessDecision { controller, granted, bits, format, reason }` | a controller decided |
| `StrikeFired { door, controller, duration_us }` | **the authoritative record of a door opening** |
| `DoorLock` / `DoorPosition` / `RequestToExit` | door state |
| `Note { text }` | a drill's narrative; never affects behaviour |

`RecordKind` is `#[non_exhaustive]`: match with a `_` arm.

`WireTx`/`WireRx` and `BusTx`/`BusRx` are deliberately separate. What a reader
emitted and what the panel received are different facts, and the difference is
the entire subject of curriculum drills 1.2 and 1.4.

### Query helpers

`presentations()`, `decisions()`, `grants()`, `strikes()`, `transmissions()`,
`bus_frames()`, `injected_by(tap)`, `injection_count(tap)`, `actions_by(tap)`,
`between(a, b)`, `find(pred)`, `cause_chain(seq)`, `originator(seq)`,
`root_origin(seq)`. `records()` is public, so anything not covered is an
iterator chain away.

## The credential seam

`odr-bus` does **not** depend on `odr-credential`, by design. A reader here does
not know what a MIFARE sector is. All it knows is:

```rust
pub struct Presentation {
    pub source: SourceId,        // which physical token — a clone is not its original
    pub format: FormatId,        // an opaque tag; the engine never branches on it
    pub bits:   BitVec,          // what the token produced
    pub label:  Option<String>,  // for the log and the UI only
}
```

Two ways in, both stable:

1. **Push** — `World::present(reader, at_us, presentation)`. Explicit, and what
   every test and most drills use.
2. **Pull** — implement `CredentialSource` on a card type and
   `World::attach_source(reader, token)`. The reader asks the token for bits
   when it is presented, which is the right shape for a card that answers
   differently each time. `StaticToken` and `ScriptedToken` are worked examples.

`FormatId` is an opaque `u32` with well-known constants for the formats
`odr-wiegand` models; everything at or above `FormatId::EXTERNAL_BASE`
(`0x8000_0000`) is reserved for `odr-credential` to allocate as it likes.

**`SourceId` is load-bearing.** Curriculum drill 0.2 — "a cloned tag presents
and the controller grants, where the original tag was never presented" — is only
answerable because two tokens carrying identical bits have different ids.

## The link model: one chain, N segments

Every link is a chain of things hanging off it, ordered outward from the
controller, in the order they were attached:

```
ACU ──┬────────┬──────────┬────── PD at 0x02
      │        │          │
   tap A    tap B   PD at 0x01
```

An **inline tap cuts the chain**, so a link is divided into *segments*: segment
0 is the controller's, and each inline tap adds one more. Everything about taps
follows from that:

- a passive or injecting tap sees exactly the traffic on its own segment;
- an inline tap receives on one segment and decides what reaches the other, with
  independent transmit and receive on each side;
- a PD attached beyond an inline tap is invisible to the controller unless the
  tap relays for it.

`World::tap_placements(link)` reports this for the UI's topology strip.

Wiegand and clock-and-data links are **unidirectional**, reader to controller,
because the real interface is: there is no channel from panel to reader on a
D0/D1 pair. The RS-485 bus is half duplex and multidrop, with a real turnaround
delay, and two transmitters that overlap destroy each other — there is a test.

## Taps

| Kind | Sees | Can transmit | Can alter |
|---|---|---|---|
| `PassiveTap` | its segment | no | no |
| `InjectingTap` | its segment | yes, and can collide | no |
| `InlineTap` | everything crossing it | yes, both sides independently | yes |

Every tap is handed an `Observation` carrying **both** the raw octets and the
decoded `Frame` when one decodes, because some drills work at byte level and
some at protocol level.

A passive or injecting tap that returns a modifying verdict gets a
`TapAction::VerdictIgnored` record rather than a silent no-op — "a tap that does
not cut the wire cannot change what crosses it" is a thing the range should
teach, not hide.

The whole of the downgrade attack:

```rust
let implant = InlineTap::rewrite_frames("downgrade", |frame| {
    if frame.reply_code() != Some(Reply::PdCap) { return false; }
    match PdCapabilities::decode(&frame.payload) {
        Ok(mut caps) => {
            let changed = caps.strip_security_capability();
            frame.payload = caps.encode();
            changed
        }
        Err(_) => false,
    }
});
world.add_tap(link, Box::new(implant))?;
```

`rewrite_frames` returns `false` to pass the original bytes through untouched,
including their original CRC, so a tap that cares about one reply type does not
disturb the rest of the bus. Replacing a frame that carried a MAC does *not*
recompute the MAC — the tap has no session key — which is why the downgrade has
to happen before the handshake.

## Two modelling decisions that carry the curriculum

These are the two settings that decide whether the Mellon downgrade works, and
both are modelled rather than assumed:

**`AcuConfig::trust_pdcap`** (default `true`). The controller decides whether to
run a Secure Channel handshake **from the PD's capability reply** — an
unauthenticated frame sent before any key material exists. With it `true`, a
reader that claims it cannot do AES-128 is talked to in the clear *even when
`AcuConfig::sc` is `ScRequirement::Required`*, because "required" in this class
of product means "required of readers that support it". That sentence is the
vulnerability, and it is what makes curriculum 3.6's flag — "both endpoints were
configured to require Secure Channel" — reachable. Set it `false` and the
handshake runs regardless; the attack becomes a no-op and a genuinely legacy
reader is `Refused` instead. Both paths have tests.

**`PdConfig::answer_clear_when_required`** (default `true`). A PD cannot
*initiate* a secure channel — OSDP has one master and it is the controller — so
a reader set to "use Secure Channel" can only refuse clear-text commands, and a
reader that refuses everything is a reader that does not work. Vendors ship the
permissive behaviour. Set it `false` and the downgrade turns into a denial of
service instead of a bypass, which is the interesting half of curriculum 5.2.
There is a test for that too.

## The capture seam

`DESIGN.md` §3 fixes the format; `capture` implements both halves.

```
{"t_us":12345,"line":"rs485","dir":"acu_to_pd","bytes":"53000e00..."}
```

Export is a projection of the event log: `World::export_capture()` for
everything driven onto every medium, or `export_from_tap(tap, opts)` for one
probe point's view, which is what a real capture is. Import is
`CaptureReplay::parse(text)`, which gives `osdp_frames()`, `card_reads()` and
`injections(shift_us, target)` — a list of transmissions ready to hand to an
injecting tap. `odr-cli` needs the reader; writing it now is how the three gaps
below were found.

### What the format does not carry

1. **Bit counts on a Wiegand line.** `bytes` is a byte string, so a 26-bit card
   read exports as four bytes with six bits of padding and the importer cannot
   tell 26 from 27 or 32. `CaptureEvent::wiegand_candidates()` returns every
   reading that fits a known card format, parity-valid first — the same answer
   `odr_wiegand::infer_formats` gives, for the same reason. `ReplayTarget::
   WireExact(format)` skips the guessing when the scenario knows the format.
2. **Which link and which segment.** One reader and one bus, it does not matter.
   Two links, or one link cut by an inline tap into two electrically separate
   halves, and a whole-world export mixes them. Use `export_from_tap`.
3. **Clock-and-data.** The `line` field has two values and neither is
   clock-and-data. A clock-and-data link therefore exports as `"wiegand"` by
   default, which is lossy. `CaptureOptions::distinguish_clock_data` emits
   `"clock_data"` instead for our own tooling; the importer accepts either. This
   is flagged rather than fixed because the format is marked **DECIDED** and
   extending it is not this crate's call.

## Things I was not certain about

1. **`trust_pdcap` is a name I invented.** Real products spell this setting
   several ways ("Secure Channel: required / if supported / off", "install
   mode", "allow clear text") and the mapping from any given vendor's checkbox
   to this boolean is a guess. The *behaviour* — a controller that decides from
   an unauthenticated PDCAP and then carries on in the clear — is what the
   Mellon paper describes, and that is what is modelled. If someone has a real
   panel's configuration screen, the naming and the defaults are worth a second
   look.
2. **`answer_clear_when_required` defaults to permissive** on the reasoning
   above. I have not verified that against a real reader. If real readers NAK
   clear-text commands once Secure Channel is enabled, the default should flip
   and curriculum 3.6 needs reworking — the downgrade would be a denial of
   service, not a bypass, and that is a materially different lesson.
3. **RS-485 is modelled per transmission, not per byte.** A transmission
   occupies its segment for `bytes × 10 bits ÷ baud` plus propagation; two
   overlapping transmissions mark each other collided and deliver nothing.
   That is honest about *whether* a collision happened and about the size of the
   gap an injector has to hit, but it does not model partial frames, framing
   errors, or a receiver resynchronising mid-collision. A drill about recovering
   a partially corrupted frame would need a finer model.
4. **The bus has no carrier sense.** A transmission's start time is computed
   from the segment's idle time when it is *scheduled*, not when it fires, so a
   transmitter that was told to speak at a moment that later became busy
   collides instead of waiting. That is what an unsophisticated injector does
   and it makes collisions reachable, but a real OSDP device would usually back
   off.
5. **Clock-and-data framing uses a flush timer**, because `odr-wiegand` exposes
   a whole-capture decoder for CLOCK/DATA rather than a streaming one. Wiegand
   uses the streaming `WireDecoder` plus an engine-scheduled flush, since that
   decoder only notices a frame boundary when the *next* edge arrives. Both are
   driven by `interframe_gap_us`; neither models a panel's own input filter.
6. **Legacy panels match the access list on the bits they received**, not on a
   decoded facility code and card number. That is what a panel actually has, and
   it keeps drill 1.2 a statement about data. It does mean a clock-and-data
   access list is a track-2 bit pattern rather than a card number, which reads
   oddly until you remember the panel is configured for one format and believes
   it. `AccessList::assumed_format` and `require_valid_parity` control the rest.
7. **Wiegand listeners see the decoded frame, not the raw edges.** A passive tap
   on a two-wire segment is notified when that segment's decoder produces a
   frame, so it sees what a receiver on that segment would have decoded —
   including the glitches. A learner wanting the edge stream itself would need a
   new observation kind; nothing in the curriculum asks for one yet.
8. **`Origin` on a wire observation is "who last drove this segment".** Under a
   collision that names the most recent transmitter. A receiver could not do
   better, but it is an approximation rather than a fact.
9. **The install-mode flow** — meet an uncommissioned PD on SCBK-D, push the site
   key with `CMD_KEYSET`, then re-handshake under the new key — follows the
   Mellon description rather than a captured commissioning session. The order of
   operations, and whether real controllers re-handshake immediately or wait for
   the next reset, is worth checking against hardware.
10. **`Rs485Timing::turnaround_us` defaults to 1 ms** and
    `PdConfig::reply_delay_us` to 2 ms. Both are plausible rather than sourced.
    They are fields for that reason, and no test depends on the exact numbers.
11. **`World::step_budget`** (default 5,000,000) exists so a scenario that
    schedules events at the same instant for ever returns an error instead of
    hanging a browser tab. It is a safety net, not a spec.

## Tests

`cargo test -p odr-bus` → **60 unit tests + 4 doctests**, all passing.
`cargo clippy -p odr-bus --all-targets -- -D warnings` is clean, as is
`cargo fmt` and `RUSTDOCFLAGS="-D warnings" cargo doc -p odr-bus --no-deps`.

The suite is organised by curriculum module and each test is named for the claim
it makes. The ones that matter most:

- a clean Wiegand badge-in end to end, credential → reader → wire → panel →
  strike, and the door relocking on its own;
- an OSDP polling loop reaching steady state (`ID`, `CAP`, then `POLL` for ever)
  with sequence numbers, and a second address that never answers going
  `Offline` without disturbing the first;
- Secure Channel established under SCBK-D with a card read delivered encrypted,
  and the command byte still readable in the clear alongside it;
- a passive tap that observes everything and changes nothing — asserted by
  exporting the capture with and without it and comparing byte for byte;
- **an inline tap performing a PDCAP downgrade that the controller actually
  accepts**, with both endpoints configured to require Secure Channel, plus the
  two negative controls: a controller that does not trust PDCAP, and a genuinely
  legacy reader that is refused rather than downgraded;
- a replay via an injecting tap on a Wiegand link granting access with no card
  present, and the same thing on clock-and-data;
- an inline implant substituting one credential for another with the reader's
  own output unchanged;
- a multidrop bus with two PDs at two addresses, and a separate test that two
  transmitters at once destroy each other;
- install mode handing the site key to the bus, observed by a tap that injected
  nothing;
- a determinism test running the same seeded scenario twice and asserting
  byte-identical event logs, plus one asserting that a different seed changes
  the nonces and nothing structural, plus one asserting that stepping one event
  at a time gives the same log as running to a deadline;
- capture export → import → replay round trip, on both line types.

## The one curriculum predicate this crate cannot express

**Drill 4.2, truncated MACs.** The flag is "the learner produces a frame the PD
accepts whose MAC was not derived from the session key", with the engine running
a shortened MAC so it completes in seconds. The *acceptance* half is expressible
— the PD rejects a bad MAC with a NAK and does not advance its chain, so an
attacker can hammer it, and `EventLog::originator` proves who sent the frame
that was accepted. The *shortened MAC* half is not: `odr-osdp` truncates to a
fixed four bytes (`crypto::truncate_mac`) and there is no knob to make it
shorter. Making the drill runnable needs a configurable truncation length in
`odr-osdp`, plumbed through `PdConfig`/`AcuConfig` here. Everything else in
`docs/CURRICULUM.md` is a query against types in this crate.
