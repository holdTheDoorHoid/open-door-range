# `odr-cli`

The command line. Point the range's own engine at a real capture and find out
where the two disagree.

This is item 8's other half in the Open Door Range build order (`DESIGN.md` §3
and §6). `odr-wasm` and the site are one consumer of the engine; this is the
other, and there is nothing between them. The same `odr-osdp` parses the frames,
the same `odr-wiegand` reads the card, the same `odr-bus` reads the capture
format, and the same `odr-detect` rules produce the findings. That is the whole
point of §3: a drill cannot teach something the analyser disagrees with, because
they are the same code.

```
capture.ndjson ──▶ odr-bus::capture ──▶ odr-osdp / odr-wiegand ──▶ output
                                    └──▶ odr-detect::Monitor ────┘
```

## Why it exists

`CONTRIBUTING.md` says the most valuable contribution this project can receive
is a correction from real hardware, and every protocol crate ships a ledger of
what it was unsure about because the OSDP specification is paywalled and the open
implementations disagree with each other. **`odr verify` turns those ledger
entries into checks**, runs them against real bytes, and ends with a block that
goes straight into `.github/ISSUE_TEMPLATE/hardware-correction.yml`.

If you have a bench, this is the tool that turns two minutes of capture into
something this project can act on.

## Constraints it keeps

- **The one crate here that may use `std`**, and the only one the workspace's
  wasm build excludes. Everything it analyses with is still `no_std` + `alloc`.
- **`#![forbid(unsafe_code)]`**, `#![warn(missing_docs)]`.
- **No argument-parsing dependency.** Hand-rolled in `args`. The workspace has
  kept to `aes` alone, and six subcommands with a dozen long flags between them
  do not justify breaking that. The test suite's JSON validator is hand-rolled
  for the same reason.
- **No panics on input.** A malformed capture is a diagnostic and an exit code.
  There is a test that feeds every command rubbish and asserts a message.
- **No colour.** Not "off by default" — none, so there is no terminal detection
  to get wrong and nothing to strip when output is pasted into an issue. Machine
  consumers use `--json`, which every command supports.

```
cargo test -p odr-cli
cargo clippy -p odr-cli --all-targets -- -D warnings
cargo build --workspace --target wasm32-unknown-unknown --exclude odr-cli
```

## Module layout

| Module | Contents |
|---|---|
| `args` | `Flags`, `UsageError`, and the value parsers — the hand-rolled command line |
| `capture` | `Capture`, `Event`, `Item` — loading, plus the `bits` field and what did *not* decode |
| `out` | plain-text formatting: timestamps, hex, percentiles, wrapping |
| `json` | a small value tree, so `--json` is valid by construction |
| `cmd_decode` | `odr decode` |
| `cmd_detect` | `odr detect` |
| `cmd_stats` | `odr stats` |
| `cmd_verify` | `odr verify` — `Check`, `Verdict`, and the thirteen checks |
| `cmd_replay` | `odr replay` |
| `cmd_export` | `odr export` and the five scenarios |
| `help` | help text, in one place |

`run(&args) -> Run` is the whole public surface: it takes an argument list and
hands back what would have been printed and the exit code, which is how the
suite exercises every command without a subprocess. `main.rs` does nothing else.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | it ran and found nothing wrong |
| 1 | it ran and the analysis found something |
| 2 | the command line, or the file, could not be read |

`odr verify && deploy` is a reasonable thing to write, so the codes are part of
the interface and there is an integration test that runs the real binary and
asserts them.

---

## `odr export`

Start here. A reference capture, so that somebody with a bench has something to
hold their own capture up to. Five scenarios, deliberately few — anything richer
is a drill and belongs in `odr-scenario`.

```
$ odr export --list
odr export — reference captures

  wiegand-badge-in       one 26-bit H10301 card read on a D0/D1 pair, granted
  clock-data-badge-in    the same card on an ABA track-2 clock-and-data pair
  osdp-clear             an OSDP bus with no secure channel: ID, CAP, POLL, and a card read
  osdp-secure            the same bus running Secure Channel under SCBK-D
  osdp-replay            a cleartext bus with a captured REPLY_RAW put back on it
  (each name is followed by a paragraph saying what to compare; trimmed here)

$ odr export --scenario osdp-secure -o reference.ndjson
wrote 44 events to reference.ndjson (scenario osdp-secure, seed 1)
```

Each scenario is built from `odr-bus`'s benches and captured through a
`PassiveTap`, because that is what a real capture is: one probe point's view of
one segment. Deterministic — the same seed gives byte-identical output on every
machine, and `--seed` changes the nonces and nothing structural.

Two-wire scenarios emit the optional `bits` field, which `DESIGN.md` §3's second
amendment makes authoritative when present:

```
{"t_us":1120052,"line":"wiegand","dir":"wire","bytes":"95029cc0","bits":26}
```

## `odr decode`

The site's frame inspector in text. Two things it exists to get right.

**An encrypted frame gets an honest split.** It is not opaque: the address, the
sequence number, the security block, the MAC and *the command byte itself* are
in the clear, and that last one is why traffic analysis works on an encrypted
bus.

```
$ odr decode --from 0.29s --to 0.65s reference.ndjson
odr decode — reference.ndjson
6 events shown of 44, 44 frames, 0 undecodable, 0.008343s to 2.897551s

#4    0.297798s  rs485    ACU->PD  addr 0x01  seq 2  CHLNG             8 payload bytes  [SCS_11]
       purpose  handshake: the controller's challenge, RND.A
       clear    everything: a handshake frame carries no session ciphertext (8 bytes)
#5    0.344599s  rs485    PD->ACU  addr 0x01  seq 2  CCRYPT            32 payload bytes  [SCS_12]
       purpose  handshake: the peripheral's cryptogram, cUID and RND.B
       clear    everything: a handshake frame carries no session ciphertext (32 bytes)
#8    0.617462s  rs485    ACU->PD  addr 0x01  seq 1  POLL              0 payload bytes  [SCS_15]
       purpose  in session, authenticated, payload NOT encrypted
       clear    everything, including the 0 payload bytes — this block authenticates
                but does not encrypt (MAC a87c48da)
```

and for a frame that is genuinely encrypted:

```
$ odr decode --code RAW --code OUT reference.ndjson
#17   1.175466s  rs485    PD->ACU  addr 0x01  seq 2  RAW               16 payload bytes  [SCS_18]
       purpose  in session, authenticated and encrypted
       clear    RAW (0x50), address 0x01, sequence 2, MAC f00a1624
       opaque   the 16 payload bytes, AES-128-CBC under S-ENC
       note     the command byte above is NOT encrypted, which is what makes
                traffic analysis work on an encrypted bus
#18   1.306726s  rs485    ACU->PD  addr 0x01  seq 3  OUT               16 payload bytes  [SCS_17]
       purpose  in session, authenticated and encrypted
       clear    OUT (0x68), address 0x01, sequence 3, MAC b987fd7d
       opaque   the 16 payload bytes, AES-128-CBC under S-ENC
       note     the command byte above is NOT encrypted, which is what makes
                traffic analysis work on an encrypted bus
```

Those two lines are the whole of Mellon's traffic-analysis point in one screen:
somebody with no key at all can see that a card was read at 1.175466s and that
the door was driven 131 ms later.

**A frame that did not decode gets a reason**, with an offset, on a line marked
`!`:

```
! #2    0.139529s  rs485  not a frame at offset 0: CRC mismatch: expected 0x13c9, found 0xecc9
```

A two-wire event is read with its declared bit count when the capture has one,
and with every parity-valid candidate when it does not. Clock-and-data goes
through the ABA track-2 decoder rather than the card-format one:

```
$ odr decode badge.ndjson
#0    1.120052s  wiegand     wire  4 bytes, 26 bits declared
       26 bits  H10301    FC 42 CN 1337  parity ok

$ odr decode clock-data.ndjson
#0    1.149401s  clock_data  wire  10 bytes, 80 bits declared
       80 bits  ABA track 2  "000421337"  LRC ok  parity ok
```

Filters: `--line`, `--address`, `--from`, `--to`, `--code` (repeatable, and
`POLL`, `CMD_POLL` and `0x60` all work), `--limit`, `--bytes`. Times take a
suffix: `1500000`, `1.5s`, `250ms`, `900us`. Exits 1 if any frame in the capture
failed to decode.

## `odr detect`

`odr-detect`'s standard rule set — eight detectors — with the evidence each
finding cites and the confidence the wire permits.

```
$ odr detect replay.ndjson
odr detect — replay.ndjson
117 observations over 4.933s, rule set "standard" (8 detectors)
5 findings, 5 shown

findings
--------
0.415369s  [high/certain]          cleartext_bus                 this address is being talked to with no encryption and no authentication
    why    address 0x01: 117 consecutive frames over 4.933761s carried no security block, so
           nothing on this link is encrypted or authenticated. 2 of them report a credential,
           in the clear. Nothing here is an attack; this is what the link is configured to be.
    cited  #0 t=0.008343s ACU->PD addr 0x01 seq 0 ID
    ...

3.016676s  [high/probable]         replayed_frame                a byte-identical frame carrying a payload was sent twice
    why    these two replies are byte-identical, 1.880858s apart, and nothing asked for the
           second one — the command it should be answering had already been answered. [...]
           Byte-identical on its own would prove nothing: the sequence number is two bits, so
           one genuine repeat in three is identical too.
    cited  #19 t=1.135818s PD->ACU addr 0x01 seq 3 RAW
    cited  #50 t=3.016676s PD->ACU addr 0x01 seq 3 RAW

reading this
------------
confidence is a statement about the link, not about the rule:
  certain    the bytes say so, and nothing benign produces those bytes
  probable   a benign explanation exists; this pattern fits the finding far better
  possible   a benign explanation is plausible and was not excluded
  ambiguous  the observable is real and its cause is not on the wire, for anyone

evidence citations all re-checked against the capture and hold.
```

Every rule and every severity comes from `odr-detect`; this command contributes
formatting and an exit code. If a finding looks wrong the argument is with that
crate, which is where the benign-case tests live — and its README carries the
list of ten things a passive monitor cannot see at all, which is teaching
material rather than an apology.

`--min-severity` moves the printing threshold and the exit code with it.
`--quiet` drops the evidence. Exits 1 when any printed finding is high or
critical.

## `odr stats`

No judgements. The shape of the traffic, so that two people looking at two
different buses can tell whether they are looking at the same thing.

```
$ odr stats clear.ndjson
odr stats — clear.ndjson
50 events, 0.008343s to 2.920275s (2.911s)
  rs485        50
50 OSDP frames, 0 undecodable

codes
-----
     22  0x60  POLL
      1  0x61  ID
      1  0x62  CAP
      1  0x68  OUT

     22  0x40  ACK
      1  0x45  PDID
      1  0x46  PDCAP
      1  0x50  RAW

per address
-----------
  0x01  25 commands, 25 replies
        posture   cleartext: nothing encrypted, nothing authenticated
        blocks    50 cleartext, 0 handshake, 0 MAC-only, 0 encrypted
        sequence  0:2 1:16 2:16 3:16
        poll gap  n=21  min 118.686ms  median 118.686ms  p90 118.686ms  max 249.872ms
        reply in  n=25  min 10.343ms  median 10.343ms  p90 18.676ms  max 38.468ms

bus timing
----------
  frame to frame  n=49  min 10.343ms  median 38.468ms  p90 108.343ms  max 112.510ms
  (start to start. A capture records when a transmission began, not how long it
   occupied the line, so this is an upper bound on the idle gap an injector
   would have to hit.)
```

On a bus running Secure Channel the per-address block reads
`posture   secure channel, payloads encrypted` and adds
`key       SCBK-D, the published default — announced in the clear`.

Timing is a five-number summary rather than a mean, because a bus is not
normally distributed: one retry after a timeout moves a mean and does not move a
median, and it is exactly the event somebody wants to see in the maximum.
Percentiles are nearest-rank over integers, so every number printed is a
measurement that actually occurred.

## `odr verify`

**The command this crate exists for.** Thirteen checks, each naming the
uncertainty ledger entry it relates to.

| Check | What it tests | Ledger |
|---|---|---|
| `frame-trailers` | CRC-16/AUG-CCITT and checksum validity | `odr-osdp` preamble |
| `command-codes` | every command id is in the claimed v2.2.2 set | `odr-osdp` preamble |
| `reply-codes` | every reply id is in the claimed set | `odr-osdp` preamble |
| `abort-code` | `CMD_ABORT` is `0xA2`, not `0x7A` | `odr-osdp` #1 |
| `single-source-codes` | `CMD_DIAG`, `CMD_RMODE`, `CMD_TDSET` exist at all | `odr-osdp` #2 |
| `handshake-payload-lengths` | CHLNG 8, CCRYPT 32, SCRYPT 16, RMAC_I 16 | `odr-osdp` #3, #4 |
| `security-block-lengths` | SCS_11–14 are 3 bytes, SCS_15–18 are 2 | `odr-osdp` #5 |
| `mac-and-padding` | a 4-byte wire MAC, block-aligned ciphertext | `odr-osdp` #11 |
| `null-cipher-selection` | an empty payload uses the MAC-only block | `odr-osdp` #6 |
| `mac-chain-iv` | the chain only advances when the other direction speaks | `odr-osdp` "one finding worth a second opinion" |
| `sequence-cycle` | commands cycle 1, 2, 3, 1 and use 0 only after a reset | `odr-bus` ACU/PD, `odr-detect` replay rule |
| `timing-model` | the model's fixed overhead is plausible for this line | `odr-bus` #3, #10; `odr-detect` #2 |
| `wiegand-bit-counts` | two-wire events carry an authoritative bit count | `DESIGN.md` §3 amendment 2, `odr-bus` capture #1 |

Four verdicts, and the useful one is not `pass`:

| Verdict | Meaning |
|---|---|
| `pass` | the capture agrees with what the engine assumes |
| `differs` | the capture disagrees. **This is the finding. File it.** |
| `inconclusive` | the capture does not contain the traffic this check needs |
| `n/a` | the check does not apply to this kind of capture |

`inconclusive` is loud rather than hidden, and says what would settle it —
because "your capture does not answer this, and here is the traffic that would"
is a useful thing to tell somebody with the hardware in front of them and five
minutes left.

Against a capture the engine made, everything the capture exercises passes:

```
$ odr verify reference.ndjson
pass           handshake-payload-lengths
               4 handshake frames, every payload the expected length
               · CMD_CHLNG 8 bytes (RND.A) — as expected
               · REPLY_CCRYPT 32 bytes (cUID(8) RND.B(8) cryptogram(16)) — as expected
               · CMD_SCRYPT 16 bytes (the server cryptogram) — as expected
               · REPLY_RMAC_I 16 bytes (the initial R-MAC) — as expected

pass           mac-and-padding
               36 in-session frames, every one with a 4-byte MAC and block-aligned ciphertext
               · This is stronger than it looks: a wire MAC of any length other
                 than four would have left the ciphertext ragged.

inconclusive   mac-chain-iv
               no two secured commands to one address with no reply between them
               · The strict poll/response cadence hides this weakness, so a
                 healthy capture will not settle it.
               · To settle it: suppress or delay one reply — pull the reader's
                 TX pair for a moment — so the controller sends two commands in
                 a row, and compare the two ciphertexts.
```

Against a capture carrying a contested command byte with a valid trailer:

```
differs        abort-code
               1 command(s) used 0x7A, which odr-osdp does not assign to any command
               · first at 0.286340s, address 0x01, 0 payload bytes
               · If this equipment means CMD_ABORT by 0x7A, go-osdp is right
                 and this project is wrong. That is exactly the correction
                 ledger entry #1 asks for.
               ledger: odr-osdp "Things I was not certain about" #1 — genuinely
                 contested. libosdp and jeff say 0xA2; go-osdp says 0x7A, which
                 is REPLY_FTSTAT in the other direction. odr-osdp uses 0xA2 on
                 two sources to one.
```

and the run ends with the block that is the point of the whole command:

```
----------------------------------------------------------------------------
copy from here into .github/ISSUE_TEMPLATE/hardware-correction.yml
----------------------------------------------------------------------------

odr verify 0.1.0 — capture corrupt.ndjson
50 events, 49 frames, 0.008343s to 2.920275s

  differs        frame-trailers              1/50 frames failed their trailer check
  differs        command-codes               2 command code(s) not in odr-osdp's set, over 2 frames
  pass           reply-codes                 25 replies, all 4 known
  differs        abort-code                  1 command(s) used 0x7A, which odr-osdp does not assign to any command
  inconclusive   handshake-payload-lengths   no secure channel handshake in this capture
  ...

Which uncertainty ledger entry this resolves:
  [abort-code] odr-osdp "Things I was not certain about" #1 — genuinely contested.
      libosdp and jeff say 0xA2; go-osdp says 0x7A, which is REPLY_FTSTAT in
      the other direction. odr-osdp uses 0xA2 on two sources to one.

----------------------------------------------------------------------------
```

`odr verify --list` prints the checks and their ledger entries with no capture at
all. Exits 1 if any check differs.

## `odr replay`

Where `verify` checks documented assumptions, this drives the engine's own code
over the recorded bytes.

- **Re-encoding.** Every frame is parsed and encoded again, and compared byte for
  byte with the wire. This is the sharpest test in the tool: it exercises the
  header, the security block, the MAC placement and the trailer at once.
- **The conversation.** A reply nobody asked for, a command sent before the
  previous was answered, a reply whose sequence does not match its command — the
  engine's state machines produce none of those.
- **The handshake.** Where the capture has `CMD_CHLNG` and `REPLY_CCRYPT`, the
  client cryptogram is recomputed under SCBK-D and then, failing that, the whole
  published Mellon weak-key family.

```
$ odr replay reference.ndjson
odr replay — reference.ndjson
44 frames replayed through the engine, 0 divergence(s)

The engine reproduced every frame in this capture, and the conversation followed
the shape its state machines produce. That is a real result: it means a drill
built on these bytes teaches the same thing the bus does.

notes
-----
0.344599s  address 0x01: the client cryptogram verifies under SCBK-D,
             the published default key. Two things follow — this bus is
             keyed with a key anyone can look up, and odr-osdp's
             session-key derivation agrees with this equipment (ledger
             entry #3 and #4).
```

That note is the strongest single result this tool produces against real
hardware. `odr-osdp`'s ledger entry #4 — the initial R-MAC construction — is
single-source, from libosdp alone. A cryptogram that verifies is independent
evidence that the derivation is right.

```
$ odr replay replay.ndjson
117 frames replayed through the engine, 1 divergence(s)

divergences
-----------
3.016676s  #50  unsolicited-reply
    engine expected  a command to address 0x01 first
    capture had      RAW with nothing outstanding
    reading          OSDP has one master; a peripheral speaks only when polled
```

A divergence on a capture from real equipment is more likely an assumption in
this engine than a fault in the hardware, and the output says so. Exits 1 if
anything diverged.

## Things I was not certain about

1. **`odr-bus`'s capture exporter does not emit `bits`.** `DESIGN.md` §3's
   second amendment makes the field optional and authoritative when present, and
   `write_ndjson` has no way to carry it; `parse_ndjson` ignores it as an unknown
   field. So `odr export` appends it for two-wire events (it knows the true bit
   count, from the tap's own `BitVec`) and `crate::capture` reads it back off the
   line by hand. That is two small pieces of format handling living here rather
   than in the crate that owns the format. **The right fix is a `bits: Option<usize>`
   on `CaptureEvent`**, which is `odr-bus`'s call and not this crate's.
2. **`timing-model`'s fixed overhead is 3 ms**, being `odr-bus`'s default
   `turnaround_us` of 1 ms plus `PdConfig::reply_delay_us` of 2 ms, and the check
   solves for the implied line rate from there. `odr-bus`'s own ledger #10 says
   both numbers are plausible rather than sourced, so this check inherits that
   and can only really say "the model is self-consistent with a standard baud
   rate". A capture annotated with the *configured* baud rate would let it say
   something much stronger; the capture format has nowhere to put one.
3. **The 15% tolerance on the implied baud rate** is a judgement, picked so that
   9600 and 19200 cannot be confused. Nothing measured it.
4. **`mac-chain-iv` needs traffic a healthy bus does not produce.** Two secured
   commands to one address with no reply between them only happens when a reply
   is lost or suppressed, so on an ordinary capture the check is inconclusive by
   construction and says so. That is honest, and it also means the ledger entry
   `odr-osdp` most wants checked is the one hardest to check by accident.
5. **`sequence-cycle` calls a gap a break.** A frame the probe missed and a
   peripheral that numbers differently look identical from a capture, and the
   check says so in its note rather than trying to tell them apart. On the
   deliberately corrupted capture in the suite it fires for exactly that reason:
   one frame was made undecodable, so the next sequence number does not follow.
6. **`replay` checks the conversation per address, not per link.** A multidrop
   bus where the controller interleaves addresses is handled correctly, but a
   capture that mixes two electrically separate segments — which `odr-bus`'s
   capture README warns a whole-world export can do — would produce divergences
   that are artefacts of the export rather than facts about the bus. Use
   `export_from_tap`, which is what `odr export` does.
7. **`decode`'s `--code` filter matches the id byte**, so `--code 0x76` selects
   both `CMD_CHLNG` and `REPLY_CCRYPT`, which share that value in opposite
   directions. Combine it with `--line` and read the direction column. Splitting
   the flag into `--command` and `--reply` felt like more surface than the
   ambiguity costs.
8. **`stats`'s reply latency pairs a reply with the most recent command to that
   address**, which is what an ACU does. On a bus with a lost reply and a retry,
   the retry's latency is measured from the retry, so a timeout does not appear
   in this number at all. The `frame to frame` spread is where a stall shows up.
9. **Exit code 1 from `detect` fires on high or critical.** That means a
   perfectly ordinary cleartext OSDP bus exits 1, which is correct — a cleartext
   bus *is* the finding — but it will surprise somebody using it as a smoke test.
   `--min-severity critical` is the narrower gate.
10. **`verify` prints the capture path into the copy block**, which on a shared
    machine is a path somebody may not want in a public issue. Nothing else in
    the block identifies the machine, and redacting it would mean the person
    pasting it loses track of which capture it was.

## Tests

`cargo test -p odr-cli` → **57 unit tests, 5 integration tests and 1 doctest**,
all passing. `cargo clippy -p odr-cli --all-targets -- -D warnings` is clean, as
are `cargo fmt` and `RUSTDOCFLAGS="-D warnings" cargo doc -p odr-cli --no-deps`.

The captures in the suite are not fixtures. Every one is produced by
`odr export`, which runs the engine, so a change in `odr-bus` that alters what
goes on the wire shows up here rather than being papered over by a hand-written
byte string that nothing keeps honest.

Four classes carry the weight:

- **Every command against a real capture**, asserting the thing that command
  exists to say — that `decode` splits an encrypted frame honestly, that
  `replay` verifies the cryptogram under SCBK-D, that `verify`'s copy block
  lists every check.
- **A deliberately corrupted capture**, built by parsing a real frame, changing
  its command byte to the contested `0x7A` and **recomputing its CRC through the
  engine**, so it survives the frame parser and reaches the code checks instead
  of being thrown out as corruption. The test asserts that `verify` exits 1 and
  names ledger entry #1.
- **Malformed and missing input** on every command: a file that is not there, a
  line missing `t_us`, a `bytes` field that is not hex, a timestamp that says
  `"soon"`, raw control bytes, and an empty file. Each asserts a diagnostic and
  the right exit code rather than a panic.
- **`--json` on every command**, checked with a JSON parser written in the test
  module, so that "it is valid JSON" is an assertion rather than a hope — and
  that parser has its own test proving it rejects a trailing comma, an
  unterminated array and a raw newline inside a string.

The integration suite runs the real binary as a process, because exit codes are
the interface a script sees and a library test cannot check them.
