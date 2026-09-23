# `odr-attack`

The attacker actors of [Open Door Range](../../DESIGN.md). Item 5 in the build
order (`DESIGN.md` §3 and §6), and the offensive half of it.

`odr-bus` models a door system honestly enough that the attacks in
`docs/CURRICULUM.md` fall out of *using* it. This crate is the things that do
the using.

```
cargo test -p odr-attack
cargo build --target wasm32-unknown-unknown -p odr-attack
cargo clippy -p odr-attack --all-targets -- -D warnings
```

## What an actor is

Not a function that opens a door. A device that sits at a tap position,
observes, acts, and **accumulates attacker state** — recovered keys, captured
credentials, inferred schedules. That accumulated state is what the drill flags
are checked against, so it is modelled explicitly as a [`Knowledge`] base rather
than left as a side effect of running an attack.

Every actor is built, clipped onto a link, driven, and then read:

```rust
let mut sniffer = Sniffer::new("ceiling void");
sniffer.attach(&mut world, link)?;
world.run_until(2_000_000)?;
sniffer.harvest(&world)?;

let known = sniffer.knowledge().snapshot();
assert_eq!(known.credentials[0].value.card_number(), Some(1337));
assert!(known.credentials[0].provenance.is_observation());
assert!(known.is_honest());
```

## The governing rule

**An attacker may only use what an attacker could actually have.**

No actor here reads a key, a credential or a configuration value out of a node
it has not compromised. If an attack needs a value, it observed it, derived it,
measured it from its own tap position, brute-forced it, or brought it with it.

That is enforced three ways, in increasing order of how much they are worth:

1. **By the engine.** An actor declares a `TapKind`, and `odr-bus` enforces it:
   a tap that reports `Passive` cannot transmit or alter traffic whatever its
   code asks for. "Zero frames injected" is the world's own statement
   (`EventLog::injection_count`), not the actor's.
2. **By the API.** `Replayer::replay` refuses bits that are not in its capture
   buffer. `Injector::forge` refuses an address it has not heard answering.
   `NestedAttacker::recover` takes a capture and a measured distance and has no
   path to the card at all. Each returns `AttackError::Unearned`, and each has a
   test.
3. **By provenance.** Every fact in a `Knowledge` base is a `Known<T>` carrying
   a `Provenance`:

   | Variant | Means |
   |---|---|
   | `Observed { t_us, tap }` | read straight off a link |
   | `Derived { from }` | computed from other facts already held |
   | `BruteForced { candidates }` | found by trying candidates until one fitted |
   | `Published { source }` | SCBK-D, the weak-key family, a factory default |
   | `Calibrated { what }` | measured from the tap: a timing distance, a MAC width |
   | `Held { what }` | the attacker's own blank tag, its own card |
   | `Unearned { what }` | **handed over rather than obtained** |

   Nothing in this crate ever constructs `Unearned`. It exists so a violation is
   *nameable and testable* rather than invisible: `Knowledge::unearned()` returns
   the facts an actor was handed, and every attack has a test asserting that
   list is empty. Because the variant exists and could be produced, that test is
   a real assertion rather than a tautology.

This matters more than it sounds. A range whose attacks quietly cheat teaches
that the attacks are easier than they are, and a learner who then meets the real
thing concludes the subject is fake. It is also what makes `odr-detect`'s side
of the exercise meaningful: a defender can only be asked "what could you have
concluded?" if the attacker was genuinely restricted to what crossed the wire.

## Module layout

| Module | Contents |
|---|---|
| `knowledge` | `Knowledge`, `Known<T>`, `Provenance`, `KnowledgeCell`, and the fact types |
| `wiegand` | `Sniffer`, `Replayer`, `Implant`, `BruteForcer` |
| `cards` | `TagCloner`, `NestedAttacker` — Module 0 through the same API |
| `osdp_passive` | `PassiveEavesdropper`, `WeakKeyCracker`, `KeysetCapturer`, `TrafficAnalyst`, `NullCipherReader` |
| `osdp_active` | `Injector`, `Downgrader`, `InstallModeHarvester` |
| `osdp_crypto` | `IvReuseExploiter`, `MacForger`, `MacSearch` |
| `shadow` | `ShadowSession` — somebody else's Secure Channel session, reconstructed |
| `error` | `AttackError` |

The commonly used items are re-exported at the crate root. `Attacker` is the one
trait they all implement: a name, a position, a knowledge base, and a tap
handle.

## The actors

| Actor | Position | Curriculum | What it needs |
|---|---|---|---|
| `TagCloner` | the air | 0.2 | one brush past a pocket |
| `NestedAttacker` | a reader in a bag | 0.4 | one sector still on a factory key |
| `Sniffer` | passive, two-wire | 1.1, 1.3, 1.6 | two clips |
| `Replayer` | injecting, two-wire | 1.3, 1.6 | two clips and a transmitter |
| `Implant` | inline, two-wire | 1.2, 1.4 | to cut the cable |
| `BruteForcer` | injecting, two-wire | 1.5 | time |
| `PassiveEavesdropper` | passive, RS-485 | 2.2 | an unsecured bus |
| `Injector` | injecting, RS-485 | 2.3 | a gap in the polling |
| `WeakKeyCracker` | passive, RS-485 | 3.2, 3.3 | one handshake, and a sample-code key |
| `InstallModeHarvester` | injecting, RS-485 | 3.4 | an unused address, and install mode left on |
| `KeysetCapturer` | passive, RS-485 | 3.5 | to be there during commissioning |
| `Downgrader` | inline, RS-485 | 3.6 | to be inline before the handshake |
| `TrafficAnalyst` | passive, RS-485 | 4.1 | **nothing. No key, ever** |
| `MacForger` | inline, RS-485 | 4.2 | time, and no attempt limiter |
| `IvReuseExploiter` | inline, RS-485 | 4.3 | to suppress replies, and one anchor plaintext |
| `NullCipherReader` | passive, RS-485 | 4.4 | a link using SCS_15/SCS_16 |

### Sharing what they know

`KnowledgeCell` is a cheap clonable handle onto one knowledge base, so several
actors can pool what they hold — which is what a real operator does, and what
curriculum 3.5 and 4.3 need (one actor captures a key, another decrypts with
it). `Actor::sharing(name, cell)` is the constructor for that. The cell never
panics: a re-entrant borrow returns `None`/`false` rather than aborting the page.

## The one change made outside this crate

Drill 4.2 was not runnable: `odr_osdp::crypto::truncate_mac` truncates to a
fixed four bytes with no knob, so the shortened variant the drill needs could
not be configured. The change is minimal and additive:

* `odr_osdp::crypto::truncate_mac_to(mac, len)` keeps the first `len` bytes and
  **zeroes the rest**. At `len = 4` it is `truncate_mac` byte for byte.
* `SecureChannel::set_mac_len` / `with_mac_len` / `mac_len`, defaulting to 4.
* `odr_bus::PdConfig::mac_len` and `AcuConfig::mac_len`, both defaulting to 4,
  applied where the two channels are constructed.

**Four MAC bytes still go on the wire either way.** Only the first `len` of them
carry strength; the rest are zero. That keeps the frame layout, every parser and
every capture unchanged — and it makes the rigging visible on the bus, which is
the point: `MacForger::calibrate` *measures* the width it is up against by
counting significant bytes in genuine MACs, rather than being told. On a real
bus that measurement returns 4 and the attack does not finish.

It is documented in both crates as a teaching device and not a protocol option,
because OSDP has no such option. Every pre-existing test in `odr-osdp` and
`odr-bus` passes unchanged.

## Two things worth reading the code for

**`TrafficAnalyst` is kept honest structurally.** It never stores a frame. It
stores a `PlaintextHeader`, which has no payload field at all — only the time,
direction, address, id byte, security block type and length, every one of which
is outside the encrypted region. There is therefore no payload byte in the
analyst's possession for it to accidentally use, and
`drill_4_1_the_analyst_never_touches_a_payload` proves it by replacing every
payload byte in a capture with `0xA5` and asserting the timeline is identical.

**`ShadowSession` is not a `SecureChannel`.** An eavesdropper is neither
endpoint, and a single `SecureChannel` only advances the half of the MAC chain
it is responsible for — an ACU's C-MAC moves when it *seals* a command, and an
observer seals nothing. So the shadow keeps one C-MAC/R-MAC pair and verifies
and decrypts against `odr-osdp`'s own primitives, computing byte for byte what
the two endpoints jointly compute. A wrong key is rejected in four AES
operations, which is what the weak-key sweep's inner loop is.

## Tests

`cargo test -p odr-attack` → **47 unit + 31 integration + 1 doc test**.

`tests/curriculum.rs` walks `docs/CURRICULUM.md` drill by drill, with each test
written as that drill's flag predicate against engine state. Nothing compares a
typed answer and nothing asserts an actor's claim about itself: every assertion
is the world's event log, a component the world holds, or a knowledge base
together with the provenance of every fact in it.

The ones worth knowing about:

* a clone opening a door where the original token never touched the reader, and
  a nested attack whose recovery step is structurally unable to see the card;
* an implant proved transparent *first*, then armed, with the reader's own
  output unchanged and the panel's input substituted — four separate assertions
  from four separate log records;
* a brute forcer that finds an enrolled card and then reports the honest
  sixteen-million-credential figure for the whole space;
* a weak-key crack from one handshake going on to decrypt a card read that was
  genuinely encrypted on the wire, and the negative control where a real key
  survives all 768 candidates;
* an install-mode harvester that ends up holding the site key the real reader
  was commissioned with, having sent nothing but valid PD replies and caused no
  collisions — plus the control where install mode is off and it gets nothing;
* a traffic analyst reconstructing five badge-ins on a fully encrypted bus,
  compared against the engine's own presentation log, holding no key and no
  payload byte;
* a MAC forgery the PD accepts, attributed to the attacker by the engine's cause
  chain, with the genuine 32-bit search alongside it as a counter and a rate;
* IV reuse reading the plaintext of frames the attacker's own decryptor cannot;
* determinism: the same seed gives the same attack and the same capture, and a
  different seed changes the nonces without changing whether the attack works.

## Things I was not certain about

Listed in rough order of how much they would matter if they turned out wrong.

1. **Drill 4.4's card-number half is not reachable from a scenario.** The flag is
   "attacker reads a card number from a MACed-but-unencrypted link", and
   `odr-bus`'s PD always asks for encryption on `REPLY_RAW`
   (`reader.rs`, the `Command::Poll` arm passes `encrypt: true` unconditionally).
   `AcuConfig::encrypt_payloads` controls the *controller's* commands only, so a
   bus can be configured with a null cipher in one direction and not the other.
   `NullCipherReader` handles both and is tested both ways — against a live bus
   for the command direction (it reads the door-open `CMD_OUT` in the clear
   inside a Secure Channel session) and against an `odr-osdp`-built SCS_16
   `REPLY_RAW` for the card-number direction. Making the drill's literal flag
   reachable needs one field, `PdConfig::encrypt_payloads`, defaulting to `true`,
   threaded into that one call — the exact twin of the `mac_len` change above. I
   did not add it because the brief authorised one change outside this crate and
   that was the MAC length.

2. **What IV reuse actually buys, in drill 4.3.** Being precise about this
   matters, because the imprecise version teaches something false. CBC with a
   reused IV does not yield plaintext from nothing; there is no arithmetic that
   turns a repeated ciphertext into its plaintext without an anchor. What it
   yields is **equality** — two frames carry the same plaintext — which becomes
   plaintext recovery once one member of the group is known. So
   `IvReuseExploiter` keeps a codebook and extends known plaintexts across an
   epoch, and the end-to-end test anchors the codebook from a weak-key crack.
   The reason that is not circular is the attack's own doing: an implant that
   suppresses replies sees frames the controller never received, and processing
   them moves its decryptor's chain out of step, so the retransmissions are out
   of the decryptor's reach and IV reuse reads them anyway. That is a real
   failure mode of a real decryptor, and the test asserts both halves. But it is
   a narrower claim than "IV reuse recovers plaintext", and a reviewer should
   decide whether the drill should say so more loudly than the actor's rustdoc
   does.

3. **The only IV-reuse window this engine has is the command direction.** A
   PD's reply IV is its C-MAC, which advances on every command it opens, and a
   PD only speaks when polled — so two replies never share an IV. Commands do,
   because their IV is the R-MAC and the ACU's R-MAC only moves when it opens a
   reply. The exploiter therefore freezes the chain by dropping replies and
   collects the controller's retransmissions. If a real controller behaves
   differently on timeout — resending a *different* command, or resetting the
   session rather than retrying — the window closes and the drill needs
   rebuilding. Worth checking against hardware; it is the same "first thing to
   check" the `odr-osdp` README flags.

4. **"Legitimate protocol requests" in drill 3.4.** The flag says the attacker's
   only frames were legitimate protocol requests. `InstallModeHarvester` sends
   *replies*, not requests — it impersonates a peripheral and the controller
   volunteers the key, which is what "ask it for the key, it tells you" means in
   the Mellon description. The test asserts the stronger, checkable thing: every
   frame it sent was a well-formed OSDP reply, addressed to the address it
   claimed, with a reply code in the standard, and it never collided with
   anybody. If the drill means something narrower by "requests", the wording
   should move rather than the code.

5. **`MacForger` isolates the PD by dropping the controller's commands.** That is
   realistic for an inline implant and it is what keeps the PD's session alive
   and its sequence numbering attributable to the attacker. It is also loud: the
   controller times out, retries, and eventually marks the address offline, which
   a monitor would see. A quieter forger would have to interleave with the
   polling and live with the controller advancing the sequence underneath it,
   which is a harder attack and a better Module 5 exercise. The current one is
   the blunt version and the rustdoc says so.

6. **The forger sweeps rather than guesses.** The target MAC is fixed for a given
   sequence number while the chain is frozen (a rejected frame advances neither
   the C-MAC nor the R-MAC), so a counter covers the space in at most `2^(8·n)`
   tries per sequence class instead of expecting to. That is correct here and is
   what a real attacker would do, but it depends on the PD not re-keying, not
   rate-limiting and not logging — all three of which are true of OSDP and none
   of which is true of a well-built product in another domain.

7. **`TrafficAnalyst`'s tolerance is a parameter, not a derivation.** The gap
   between a card being presented and the `REPLY_RAW` crossing the bus is the
   reader's read time plus up to one polling interval. The polling interval is
   the single most visible thing on an OSDP link, so an attacker really can
   measure it — but `TrafficTimeline::compare` takes the tolerance from the
   caller rather than inferring it from the capture. A sharper version would
   measure the poll cadence and derive the window, and would then be able to say
   how confident it is. Drill 4.1 does not need that yet.

8. **`TagCloner` reports `TapKind::Passive`.** A 125 kHz cloner is a coil and a
   pocket; it has no tap and does nothing to the system it is attacking. Passive
   is the closest honest description, but the `Attacker` trait's `position` is
   really "where on a link does this sit", and a card-layer actor does not sit on
   a link at all. If Module 0 grows more actors this may want its own variant.

9. **`KeysetCapturer::decrypt_after_commissioning` assumes the last handshake for
   an address is the site-key one.** That is true of the commissioning flow
   `odr-bus` models (establish under SCBK-D, push the key, re-handshake), and it
   is what the Mellon description says. A controller that waits for the next
   reset rather than re-handshaking immediately would need the capture split
   differently, and the `odr-bus` README already flags that ordering as
   unverified against hardware.

10. **The knowledge base keeps whole frames.** `Knowledge::frames` holds every
    observed frame, payload included, which is what a real capture is and what
    the weak-key and keyset attacks need. It also means a long run's knowledge
    base is proportional to the traffic. A browser running a simulated day at
    9600 baud is fine; a capture import of a real week would want a windowed
    store. `TrafficAnalyst` deliberately does not use it, for the reason above.

11. **`pooled()` de-duplicates by handle identity, not by fact.** Two actors
    sharing one `KnowledgeCell` are counted once; two actors that independently
    observed the same frame are counted twice. That is the right answer for
    provenance — two observations of one event really are two pieces of
    evidence — but a UI summing "what the attacker knows" should de-duplicate
    for display.

## Ethics

Simulated protocol machinery. No vendor-specific exploit code, no real
credential data, no product named. The weak-key material is the already
published Mellon family (Petro & Vargas, Bishop Fox, 2023). Every attack here is
visible in the same `EventLog` a defender would be reading, which is what Module
5 of the curriculum is for.
