# Open Door Range — design

**Authoritative spec.** Read this before touching code. Decisions marked **DECIDED** came
from the owner and must not be changed without asking.

## 1. What this is

A browser-based virtual range for physical access control. You get a simulated door
system — credential → reader → wire/bus → controller → door strike — that you can wire
up, run, tap, and attack, plus guided drills that drive that same simulation.

It exists because learning reader-to-panel attacks currently requires buying a reader, a
panel, RS-485 transceivers, and a bench. That gate keeps the subject in the hands of
people who already have a lab. The range removes the gate.

**DECIDED — audience is both, in layers.** A beginner follows a guided course and is
never lost. A practitioner ignores the course, opens the sandbox, and has a real tool:
byte-level frame inspection, a frame composer, key management, bus timing.

## 2. Scope

**DECIDED — the whole reader-to-panel stack**, not OSDP alone. The arc matters: legacy
protocols are broken by design, OSDP is sold as the fix, and OSDP's own failures are
what most of this teaches.

### Track 0 — the credential
- 125 kHz: EM4100 and HID Prox (H10301 over the air), modulation, cloning
- 13.56 MHz: MIFARE Classic and Crypto1, contrasted with DESFire EV2 and Seos, which hold
- Non-simulated reference section on mechanical and sensor bypass, included deliberately
  so the course does not leave a learner with a miscalibrated sense of where risk lives

### Track 1 — legacy wire protocols
- Wiegand 26 / 34 / 37-bit and H10301-family formats: facility code, card number, parity
- D0/D1 pulse train, timing, idle-high signalling
- Clock-and-data (ABA track-2 magstripe emulation)
- Attacks: passive sniffing, replay, inline implant (Tick/ESPKey class), facility-code
  and card-number brute force, and the fact that there is no crypto to attack

### Track 2 — OSDP
- Frame structure: mark, SOM 0x53, address (bit 7 = reply), length LSB/MSB, control byte
  (seq bits 0-1, CRC bit 2, SCB bit 3), optional security block, command/reply id,
  payload, CRC-16/AUG-CCITT (poly 0x1021, init 0x1D0F, check 0xE5CC) or checksum
- Full v2.2.2 command and reply code set
- Secure Channel: SCBK and SCBK-D, the CHLNG/CCRYPT/SCRYPT/RMAC_I handshake,
  AES-128 CBC-MAC, packet encryption, SCS_11–SCS_18 security block types
- Multidrop addressing, polling cadence, sequence numbers, BUSY/NAK handling

### Track 3 — the five Mellon attacks (Bishop Fox, Petro & Vargas, 2023)
1. Passive eavesdropping — encryption is optional and frequently off
2. Downgrade — rewrite the PDCAP reply so the reader claims no crypto support
3. Install mode — controllers left in install mode hand out the SCBK on request
4. Weak keys — the ~768 sample-code patterns (repeated byte, ascending, descending runs)
5. Keyset capture — no secure key exchange; sniff CMD_KEYSET during commissioning

Plus the medium/low weaknesses, which are the more interesting teaching material:
32-bit truncated MACs; IVs derived from MACs, so IV reuse; 48 bits of CP nonce entropy
in the session key; 2-bit sequence numbers; CBC rather than GCM; SCS_15/16 are null
ciphers; **the command byte is plaintext even inside a secure channel**, so traffic
analysis — seeing when a person badges in — works on an encrypted bus.

## 3. Architecture

**DECIDED — one Rust engine, compiled to WebAssembly for the site.** The reason is not
language preference: it means the teaching simulation and the real-capture analyser are
literally the same code, so a drill can never teach something the analyser disagrees
with. The same crates build a command-line tool.

```
open-door-range/
  crates/
    odr-credential/ the card layer: 125 kHz EM4100 and HID Prox, 13.56 MHz MIFARE
                    Classic and Crypto1, DESFire/Seos as the working contrast
    odr-wiegand/    Wiegand + clock-and-data: formats, parity, bit streams, pulse timing
    odr-osdp/       frames, command/reply set, CRC + checksum, secure channel, AES-128
    odr-bus/        virtual RS-485 multidrop and virtual Wiegand wire; ACU and PD state
                    machines; taps for sniff / inject / inline MITM
    odr-attack/     attacker actors: sniff, replay, downgrade, install-mode, weak-key,
                    keyset capture, traffic analysis
    odr-detect/     the defensive half — what a passive monitor can conclude
    odr-scenario/   drill definitions and flag predicates, data-driven
    odr-wasm/       wasm-bindgen surface consumed by the site
    odr-cli/        phase-two seam: load a capture, replay it through the same engines
  site/             static HTML/CSS/JS, no framework, no build step of its own
  docs/             protocol reference and the ethics note
```

### The rule that makes drills trustworthy

**Drills do not describe attacks. They run them.** A drill step is a scenario executed by
the engine, and a flag is earned when the engine's own state satisfies a predicate — the
attacker actually holds the SCBK, the controller actually ACKed a frame the attacker
forged. There are no hardcoded answer strings to check against. If the engine is wrong,
the drill fails rather than lying.

### Determinism

A virtual microsecond clock drives everything. No wall-clock time, no randomness without
a seed. The same scenario always produces the same bytes, so flags are stable, bugs are
reproducible, and a capture can be replayed identically on any machine.

### Capture format (the phase-two seam)

**DECIDED — hardware capture import is phase two, but the seam is designed now.**
Newline-delimited JSON, one line per observed event:

```
{"t_us": 12345, "line": "rs485" | "wiegand" | "clock_data",
 "dir": "acu_to_pd" | "pd_to_acu" | "wire",
 "bytes": "53000e00...", "bits": 26}
```

`odr-cli` reads it today. Importers for TheTick's capture output, logic-analyser CSV, and
pcap come later without touching the engines.

Two amendments, made 2026-09-23 once `odr-bus` had built against the original:

- **`clock_data` is a third line type.** Folding it into `wiegand` would have meant the
  format could not say which of two protocols it had recorded, which is exactly the
  question an importer needs answered.
- **`bits` is optional and authoritative when present.** A 26-bit Wiegand frame occupies
  four bytes, and without a bit count an importer cannot tell 26 from 32 — it has to guess
  from parity, which is ambiguous by construction. Writers that know the true length say
  so; readers that see no `bits` field fall back to enumerating the parity-valid readings.

## 4. Product decisions

- **DECIDED — sandbox with drills layered on top.** One live bench, always pokeable; the
  course drives that same bench rather than a separate scripted mock.
- **DECIDED — CTF flags, local only.** Progress lives in the browser. No backend, no
  accounts, no data collected about anyone who uses it. A village can run it competitively
  by having people show their screen.
- **DECIDED — online is fine, and offline is now supported too.** The site is plain GitHub
  Pages. v1 shipped online-only; offline was added afterwards at the maintainer's request,
  because a workshop runs in a room on one access point. A service worker caches the app
  shell and the wasm on first load, and `tools/make-offline-bundle.sh` produces a
  self-contained folder to hand out on a USB stick. Both cache only same-origin assets, so
  the request-free privacy property is preserved. See `docs/WORKSHOP.md`.
- **DECIDED — GPLv3.** The OSDP dissector and Mellon detectors this shares lineage with
  were written inside a GPLv3 codebase, and copyleft keeps this from being absorbed into a
  closed vendor training product.
- **DECIDED — the name is Open Door Range.**

## 5. Ethics posture

Everything here is simulated. No real credentials, no vendor-specific exploit code, no
targeting of a named product. The weak-key material is the already-published Mellon
family. The defensive half (`odr-detect`) is a first-class part of the project, not an
afterthought — the point is that a defender can run the same range and learn what their
own bus would look like under each attack.

## 6. Build order

1. Workspace, licence, CI, Pages skeleton
2. `odr-osdp` — frames and secure channel, unit-tested against known vectors
3. `odr-wiegand` — formats and timing
3b. `odr-credential` — the card layer
4. `odr-bus` — ACU/PD state machines and taps
5. `odr-attack` and `odr-detect`
6. `odr-scenario` and the drill content
7. `odr-wasm` and the site
8. Pages deploy
