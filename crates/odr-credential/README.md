# odr-credential

The card layer of [Open Door Range](../../DESIGN.md): what happens *before* the wire.

Everything downstream of this crate — Wiegand pulse trains, OSDP frames, controllers,
door strikes — is about moving a number from a reader to a panel. This crate is about
where that number comes from, and how little most credentials do to protect it.

| Frequency | What | What it defends against |
|---|---|---|
| 125 kHz | EM4100 / EM4102 | nothing at all |
| 125 kHz | HID Prox H10301 | nothing at all |
| 125 kHz | T5577-class writable tag | it *is* the attack |
| 13.56 MHz | MIFARE Classic 1K + Crypto1 | a cipher broken in public in 2008 |
| 13.56 MHz | DESFire EV2 (AES mutual auth) | this one holds |

Builds for `wasm32-unknown-unknown` and native. No `std::time`, no threads, no OS
randomness, `#![forbid(unsafe_code)]`. Every random value comes from a caller-supplied
seed, so the same scenario produces the same bytes on any machine.

```
cargo test -p odr-credential
cargo build --target wasm32-unknown-unknown -p odr-credential
cargo clippy -p odr-credential --all-targets -- -D warnings
```

141 tests (123 unit + 16 integration + 2 doc), about 20 seconds in a debug build. The
slow ones are the real Crypto1 key recoveries.

---

## Module layout

| Module | What is in it |
|---|---|
| `modulation` | `(t_us, state)` event streams, Manchester coding, ASK and FSK modulation and demodulation. The same shape `odr-wiegand` uses for D0/D1. |
| `em4100` | The 64-bit frame: 9-bit header, ten 4-bit rows with row parity, four column-parity bits, stop bit. Encode, decode, and a **separate** parity report so a bad read is reportable as one. |
| `hid_prox` | H10301: the 26-bit Wiegand payload, the 44-bit on-card block, FSK on the air, and `wiegand_bits()` — the exact pattern drill 0.3 asks a learner to predict. |
| `writable` | A T5577-class blank, `sniff()`, and cloning. No detection hook, deliberately. |
| `crypto1` | The cipher: 48-bit LFSR, the filter function, key load, rollback, the 16-bit nonce generator. |
| `crypto1::recovery` | State recovery from 32 keystream bits — the engine under every practical MIFARE attack. |
| `mifare` | MIFARE Classic 1K: sectors, blocks, key A/B, access bits, value blocks, the manufacturer block, CRC_A, and the three-pass authentication with encrypted parity. |
| `nested` | The nested attack. Calibrate, probe, predict the nonce, recover the state, roll back to the key, prove it by authenticating. |
| `desfire` | AES mutual authentication, session key derivation, and the Module 0.5 machinery: three earlier attacks actually run against it, three structured diagnoses out. |
| `card` / `reader` | One enum over every credential, and a reader that energises a field, runs a protocol and emits a `Credential` (format id, bit count, bits). |

`Credential` deliberately carries no facility-code field. Readers forward bits they do
not parse; that is how readers work, and it is why Module 1's re-encoding attacks are
possible at all.

`tests/module_0.rs` walks the curriculum drill by drill, with each test written as the
flag predicate from `docs/CURRICULUM.md`.

---

## Where each bit layout came from

Everything below was checked against a source rather than recalled. Where a source was
ambiguous it is flagged in "Simplifications and things I was unsure about".

### EM4100 — 64-bit frame

Nine header ones, ten rows of four data bits plus an even row-parity bit, four even
column-parity bits, a zero stop bit. The 40-bit payload is an 8-bit version/customer
code and a 32-bit ID.

Source: the Priority 1 Design EM4100 protocol note
(<https://www.priority1design.com.au/em4100_protocol.html>), including its worked
example — version `$06`, data `$001259E3`, transmitted as nibbles
`0 0 1 2 5 9 E 3` — which is the vector `em4100.rs` is tested against.

Bit rates RF/64, RF/32 and RF/16 are all supported; RF/64 is the default, giving
1953.125 bit/s and a 32.768 ms frame at 125 kHz.

The nine-ones header is a valid frame sync because no valid frame body can produce a
run of nine ones: a row of four ones forces its parity bit to zero, so the longest
achievable run is eight.

### HID Prox H10301 — 26-bit Wiegand payload

```
bit  0      leading parity, EVEN over bits 1..12   (facility code + top 4 of card)
bits 1..8   facility code, 8 bits, MSB first
bits 9..24  card number, 16 bits, MSB first
bit  25     trailing parity, ODD over bits 13..24  (bottom 12 of card)
```

Sources: HID's own "Understanding Card Data Formats"
(<https://www.idesco.com/files/articles/HID%20-%20Understanding%20card%20formats.pdf>)
and the field layouts published by card vendors. The parity *direction* (leading even,
trailing odd) was verified arithmetically against a real Proxmark3 decode, below.

### HID Prox — the 44-bit on-card block

```
bits 43..38   zero
bit  37       1 — short-format (under 37-bit) marker
bits 36..27   zero
bit  26       1 — length sentinel: the highest set bit below the marker gives the
                  format length, here 26
bits 25..0    the Wiegand payload
```

Source: the Proxmark3 client's HID handling — `client/src/cmdlfhid.c` and
`get_length_from_header()` in the Wiegand format code, which determines format length
by finding the top set bit, and whose comment marks bit index 37 as the short-format
discriminator.

Cross-checked arithmetically against a Proxmark3 decode line of the form

```
HID Prox TAG ID: 2006f623ae (11d7) - Format Len: 26 bit - FC: 123 - Card: 4567
```

Taking `0x2006F623AE`: bit 37 set, bit 26 set, low 26 bits `0x02F623AE`; `(v >> 17) &
0xFF = 123`, `(v >> 1) & 0xFFFF = 4567`, leading parity bit 1 over seven ones (even
parity, correct) and trailing parity bit 0 over seven ones (odd parity, correct).
Facility code, card number and *both* parity bits fall out of the same 40-bit value
consistently, which is a strong check that the layout is right. `0x2006F623AE` is the
vector `hid_prox.rs` is tested against.

### HID Prox — modulation

FSK on a 125 kHz carrier, nominally RF/50: a `1` is six sub-carrier cycles of fc/8 (48
carrier cycles) and a `0` is five cycles of fc/10 (50). On the air a block is 96 bits:
an 8-bit **raw** preamble `00011101` followed by the 44 data bits Manchester coded into
88 more.

Source: the Proxmark3 FSK demodulator's own description — "HID Prox demod — FSK RF/50
with preamble of 00011101 (then manchester encoded)" — and the pairing of `8 + 2*44 =
96`. The raw preamble works as sync precisely because Manchester data can never contain
three identical bits in a row, so `000` cannot be forged by the payload.

### Crypto1 — cipher

48-bit LFSR held as two 24-bit halves, with the non-linear filter reading twenty
odd-indexed bits.

Sources: the `crapto1` reference implementation (Nohl, Plötz, Bettendorf; GPL) as
carried in `RfidResearchGroup/proxmark3` at `common/crapto1/crapto1.h`, for
`LF_POLY_ODD = 0x29CE5C`, `LF_POLY_EVEN = 0x870804`, the filter's packed truth tables
and the MIFARE bit/byte order; and Garcia et al., *Dismantling MIFARE Classic*
(ESORICS 2008) for the published feedback polynomial and filter structure.

The two were cross-checked against each other rather than trusted, and the checks are
tests in `crypto1/mod.rs`:

* `feedback_taps_match_the_published_polynomial` derives the tap positions back out of
  the two 24-bit masks and asserts they equal the paper's
  `x0 + x5 + x9 + x10 + x12 + x14 + x15 + x17 + x19 + x24 + x25 + x27 + x29 + x35 +
  x39 + x41 + x42 + x43`, equivalently `x^48 + x^43 + x^39 + x^38 + x^36 + x^34 + x^33
  + x^31 + x^29 + x^24 + x^23 + x^21 + x^19 + x^13 + x^9 + x^7 + x^6 + x^5 + 1`.
* `filter_constants_are_two_tables_not_five` asserts that the five packed constants are
  two distinct 4-bit truth tables (`0xD938` at nibbles 1 and 4, `0xF22C` at nibbles 0,
  2 and 3) shifted into place, which is what the "six instantiations of three
  functions" description requires. A mistyped constant fails this rather than producing
  a plausible-looking wrong cipher.
* `the_filter_reads_only_odd_indexed_state_bits` checks the filter's inputs are paper
  indices `x9, x11, ... x47`, and that bits 20..23 of the half-register cannot reach it
  at all.

**The strongest check is against real hardware.** `matches_a_real_captured_authentication`
replays a published `mfkey32v2` test vector — a genuine MIFARE Classic authentication
with key `A0A1A2A3A4A5`, `uid 12345678`, `nt 1AD8DF2B`, `{nr} 1D316024`, `{ar}
620EF048`, plus a second `(nt, nr, ar)` triple from the same card — and requires this
implementation to reproduce `{aR}` bit for bit. That exercises key loading, byte and
bit order, the `is_encrypted` feedback rule and `prng_successor` simultaneously.
Vector from the `mfkey32v2` documentation
(<https://github.com/equipter/mfkey32v2>).

The nonce generator is the 16-bit LFSR `x^16 + x^14 + x^13 + x^11 + 1`, implemented as
`prng_successor` exactly as `crapto1` does it (byte-swapped shift with taps at 16, 18,
19, 21). `there_are_only_sixty_five_thousand_nonces` walks the whole cycle and asserts
the period is 65535.

### Crypto1 — state recovery

`crypto1::recovery::recover_states` finds every cipher state consistent with 32
keystream bits and the 32 input bits shifted in alongside them — about 2^16 of them, as
the arithmetic demands (48 unknowns, 32 constraints).

The algorithm was **derived from the cipher's structure rather than transcribed** from
`crapto1`, and then checked against the cipher empirically. The derivation, in full, is
in the module docs; the shape is:

1. The filter reads only odd-indexed register bits, so the register splits into two
   halves that take turns being filtered and alternate keystream bits constrain
   alternate halves.
2. A single keystream bit sees only 20 of a half-register's 24 bits, so each half
   starts from 2^20 seeds, halved immediately by its first keystream bit.
3. Four extensions later each half-register is fully determined, and each further
   extension needs exactly **one bit** from the opposite half: the parity of that half
   under the odd tap mask. Guess it, record the guess, and record what this half
   produces in return.
4. Two candidates from opposite halves are compatible only when each one's guesses
   match the other's productions. Eleven extensions accrue 22 bits of matching key;
   sort both lists and merge.

`recovers_the_state_it_was_never_given` asserts the true state is in the output and
that the population is between 2^14 and 2^18; `every_recovered_state_really_produces_
the_keystream` runs 500 candidates back through the cipher.

### The nested attack

Standard: calibrate the nonce distance with the known key, take two nested nonce probes
on the target, predict the plaintext nonce from the reference nonce and the distance,
confirm with three encrypted parity bits, XOR out 32 keystream bits, recover states,
roll back 32 steps, and pick the key that also explains the second probe.

Two things were done deliberately to keep the attack honest:

* **It never reads a key out of the card model.** The one key it is given — the
  attacker's known sector — is used only by `calibrate`, which measures the *reader's*
  timing. Nothing in `recover()` can see the card at all; it takes a capture and a
  distance.
* **The probes are abandoned at pass three.** An attacker without the target key cannot
  produce a valid `{aR}`, so `probe_nested_nonce` runs the first two passes and walks
  away. `drill_0_4_the_attack_never_completes_an_authentication_it_could_not_afford`
  asserts the card has no session afterwards. Disambiguation between the ~2^16
  candidate keys therefore comes from a *second probe*, not from an `{aR}` an
  eavesdropper would only have if a legitimate reader had been present.

The encrypted-parity check comes from the ISO 14443-A rule that byte *n*'s odd parity
bit is masked with the keystream bit that also encrypts bit 0 of byte *n+1*. Three of
the four nonce parity bits fall inside the same 32-bit keystream word and are checkable
for free.

### MIFARE Classic 1K — memory and access bits

64 blocks of 16 bytes, 16 sectors of 4. Block 0 is the manufacturer block (UID, BCC,
SAK `0x08`, ATQA `04 00`). Each sector trailer is `key A (6) | access bits (3) | GPB
(1) | key B (6)`.

Access bits are stored twice, straight and inverted:

```
byte 6 = !C2 (4 bits) | !C1 (4 bits)
byte 7 =  C1 (4 bits) | !C3 (4 bits)
byte 8 =  C3 (4 bits) |  C2 (4 bits)
byte 9 = general-purpose byte
```

with bit *n* of each nibble belonging to block group *n*. The transport configuration
`FF 07 80 69` decodes under this layout to `C1C2C3 = 000` for the three data groups and
`001` for the trailer, which is the documented transport state and is asserted as a
test.

Value blocks: `value | !value | value | addr | !addr | addr | !addr`, value stored
little-endian.

CRC_A is ISO 14443-A: polynomial `x^16 + x^12 + x^5 + 1` reflected to `0x8408`, initial
value `0x6363`, checked against `CRC_A(00 00) = 0x1EA0`.

### DESFire — AES authentication

EV1-style `AuthenticateAES` (`0xAA`), three passes, AES-128 CBC with the IV chaining
forward across them:

```
reader -> card   AUTH_AES(key number)
card   -> reader E(K, RndB)                     status 0xAF
reader -> card   E(K, RndA || RndB<<<8)         status 0xAF
card   -> reader E(K, RndA<<<8)                 status 0x00
```

Session key `SK = RndA[0..4] || RndB[0..4] || RndA[12..16] || RndB[12..16]`.

Source: the Proxmark3 *unofficial DESFire bible*
(<https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/unofficial_desfire_bible.md>),
which gives both the message flow with its status bytes and that exact session-key
formula, corroborated by TI's application note *MIFARE DESFire EV1 AES Authentication
with TRF7970A* (SLOA213).

The AES primitive itself is pinned by the FIPS-197 AES-128 single-block vector
(key `000102...0f`, plaintext `00112233...ff`, ciphertext `69c4e0d86a7b0430d8cdb78070b4c55a`).

---

## Simplifications, and things I was unsure about

Listed in rough order of how much they would matter if they turned out wrong.

1. **HID FSK polarity.** That HID uses fc/8 and fc/10 at a nominal RF/50 bit rate is
   solid. *Which* of the two frequencies carries a `1` is a convention — HID is usually
   described as FSK2a, i.e. inverted, and I could not confirm the polarity from a
   primary source in the time available. This crate fixes `1 = fc/8 x 6` and
   `0 = fc/10 x 5` and demodulates with the same convention, so round trips are exact
   and nothing in the curriculum depends on it. If a real capture is ever imported and
   comes out inverted, flip `FskParams::HID_PROX`.

2. **The HID short-format marker at bit 37.** The 26-bit length sentinel at bit 26 is
   well supported — it falls out of the Proxmark3 "find the top set bit" length logic
   and it decodes real captures correctly. The *constant* bit at index 37 is inferred
   from Proxmark3 output values (`0x20...` prefix on short-format blocks) plus the
   comment in the length-detection code, not from a specification. If it is actually
   part of a longer fixed preamble, only `H10301::raw44`/`from_raw44` would change; the
   26 Wiegand bits, which are what drill 0.3 is about, are unaffected.

3. **MIFARE sector-trailer access-condition table.** The data-block table (read / write
   / increment / decrement per `C1C2C3`) is the standard one and I am confident in it.
   The trailer table — who may write key A, read or write the access bits, read or
   write key B — is transcribed from the standard table and was *not* verified against
   a real card in this work. The invariant that matters, that key A is never readable
   in any configuration, is enforced structurally and tested across all eight codes.

4. **Nonce generator tick rate.** Real MIFARE Classic cards clock the nonce LFSR
   continuously; the figure usually quoted is one step per 9.44 µs. `NONCE_TICK_US` is
   10, so the virtual clock stays in whole microseconds. What the nested attack needs is
   not the number but its *stability* — that the same elapsed time always advances the
   generator by the same amount — and that holds here as it does on the real card.
   Because the simulated reader's timing is perfectly regular, the calibrated distance
   is exact and the `window` sweep never has to work. The sweep and the parity filter
   are implemented anyway, because a real capture has jitter and an attack that only
   works on a jitter-free card would be teaching the wrong thing.

5. **The nested AUTH command is modelled as four bytes of keystream**, not as a full
   encrypted command frame with its CRC. Both ends consume the same amount, so they stay
   in step and the attack is unaffected, but the exact byte count a real card consumes
   here was not verified.

6. **Data-transfer parity bits are not modelled.** Encrypted parity is implemented
   where it matters — the nonce, where the attacks live. Read and write payloads are
   enciphered byte-wise without their per-byte parity bits. A future darkside
   implementation would need them.

7. **No anticollision, no ATQA/SAK exchange, no HALT/WUPA.** The UID is simply known,
   as it is in practice: it goes out in the clear before anything else. `reset_field()`
   stands in for dropping the card out of the field.

8. **MIFARE value-block *commands* are not implemented** — `increment`, `decrement`,
   `restore`, `transfer`. The value-block *format* and the access bits that govern
   those operations are, because they are part of understanding what the card is for.

9. **DESFire is EV1-style AES authentication only.** `AuthenticateEV2First` (`0x71`),
   its CMAC-based SV1/SV2 session-key derivation, transaction MAC counters, AES-CMAC
   secure messaging and proximity checking are **not implemented**. None of them change
   the answer to drill 0.5. Secure messaging after authentication is modelled as plain
   CBC over the file data with a running IV, which is not real EV1 secure messaging
   (no CRC, no padding scheme). **Seos is not implemented at all** — it is a different
   stack (SIO objects over ISO 7816) that reaches the same conclusion by the same
   route, and the module says so rather than faking it.

10. **The darkside attack is not implemented.** Recovering a first key with no known key
    at all, from the parity leak in a card's rejection of a malformed authentication,
    needs a card model that answers a failed authentication with an encrypted NACK and a
    different search. Drill 0.4 is built on the nested attack; darkside would be an
    extension. `nested.rs` states this in its module docs.

11. **Manchester polarity.** `1 = (high, low)`, matching the Proxmark3 demodulator. The
    opposite convention exists (G.E. Thomas vs IEEE 802.3) and real decoders try both.
    Trying both is a demodulator concern, not a format concern, so it is not modelled:
    feed `manchester_decode` an inverted stream and you get inverted bits, exactly as a
    misconfigured reader would.

12. **The demodulators are idealised.** No noise, no drift, no partial reads except the
    ones you construct deliberately. The EM4100 demodulator tries both Manchester phases
    and the three common RF divisors; it does not try biphase or PSK, which EM4100 parts
    also support. There is no analogue model and there is not meant to be — but it does
    mean "the read failed" in this crate always has a structural cause.

13. **`sniff()` tries EM4100 before HID Prox.** A false EM4100 match on an FSK stream
    would require every Manchester pair across the whole capture to be valid, which is
    vanishingly unlikely, but the ordering is an assumption rather than a proof.

14. **`Credential::bit_len` is a `u16`** and `as_u64()` truncates past 64 bits. Fine for
    every format modelled; a MIFARE block wants `data` instead, and the docs say so.

---

## Things this crate deliberately does not have

* **No clone-detection hook.** `WritableTag` exposes no provenance flag and `Card` has
  no "is this genuine" field, because real readers have neither. An engine that quietly
  kept one would teach that the problem is detectable at the reader. It is not. The
  test `em4100_clone_is_indistinguishable_on_the_air` asserts the clone's event stream
  equals the original's; if that ever fails, the *simulation* is wrong.

* **No dependency on `odr-wiegand` or `odr-osdp`.** `Credential` is a format
  identifier, a bit count and bits. Wiring happens in `odr-bus`. `h10301_wiegand_bits`
  and `odr-wiegand`'s own encoder are independent implementations of the same 26 bits
  on purpose: if they ever disagree, a drill fails rather than teaching a lie.

* **Nothing for drill 0.6.** Mechanical and sensor bypass is reference prose in `docs/`.
  It simulates nothing and says so. There is a deliberately empty test in
  `tests/module_0.rs` so the absence is visible rather than an oversight.
