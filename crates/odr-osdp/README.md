# `odr-osdp`

OSDP v2.2.2 — frames, the full command and reply set, and Secure Channel.

This is item 2 in the Open Door Range build order (see `DESIGN.md` §3 and §6).
Everything else in the workspace sits on top of it: `odr-bus` drives ACU and PD
state machines with it, `odr-attack` rewrites frames it produced, `odr-detect`
draws conclusions from frames it parsed, and `odr-cli` replays real captures
through the same code the browser runs.

It doubles as documentation. The rustdoc is written for someone learning OSDP,
not just someone calling the API — `cargo doc -p odr-osdp --open` is a
reasonable way to read the protocol.

## Constraints it keeps

- **`no_std` + `alloc`.** No `std::time`, no threads, no OS randomness, no
  `getrandom`. The only dependency is `aes` for the AES-128 block function; CRC
  and every OSDP construction are implemented here.
- **Deterministic.** Every nonce is a parameter. `rng::SeededRng` (SplitMix64)
  exists for callers that want repeatable pseudo-random values; it is explicitly
  *not* a key generator. The same scenario produces the same bytes on every
  machine, which is what makes CTF flags stable (`DESIGN.md` §3).
- **`#![forbid(unsafe_code)]`**, `#![warn(missing_docs)]`.
- **Builds for `wasm32-unknown-unknown`** with and without default features.
- **No panics on parsed data.** Every decoder is bounds-checked and returns a
  structured error. There is no `unwrap` on anything that came off a wire.

The `std` feature (on by default) does nothing but add `std::error::Error`
impls to the three error types.

## Module layout

| Module | Contents |
|---|---|
| `crc` | CRC-16/AUG-CCITT (poly `0x1021`, init `0x1D0F`) and the two's-complement one-byte checksum |
| `codes` | `Command` and `Reply` — the full v2.2.2 code set as exhaustive enums, with `name()` and classifiers |
| `security` | `ScsType` (SCS_11–SCS_18), `KeyType`, `SecurityBlock` |
| `frame` | `Frame` encode/parse, `ParseError`, and `Scanner` — a tolerant, resynchronising stream scanner |
| `payload` | Typed encode/decode for the payloads that carry meaning |
| `crypto` | AES-128 ECB/CBC, session-key derivation, cryptograms, two-key CBC-MAC, `0x80 00 …` padding |
| `channel` | `SecureChannel` — the four-frame handshake from either side, then `seal`/`open`; plus `recover_weak_scbk` |
| `weak_keys` | The published Mellon weak-key family as a generator, and `classify` / `is_weak` |
| `rng` | `SeededRng`, a deterministic non-cryptographic PRNG |

`Scanner` has two modes. `Scanner::new` is for a live stream: it stops at the
first truncation and `remaining()` hands back the partial tail. `Scanner::offline`
is for a complete capture: it reports a truncation and then resynchronises past
it, so one `0x53` inside a payload followed by large-looking length bytes cannot
swallow the rest of the file.

## Typed payloads

Modelled: `PDID`, `PDCAP` (including `claims_aes128`, `uses_default_key` and
`strip_security_capability`), `RAW`, `KEYPAD`, `LSTATR`, `ISTATR`/`OSTATR`/`RSTATR`
(one `StatusList` type — they share a shape), `OUT`, `LED`, `BUZ`, `TEXT`,
`COMSET`/`COM`, `KEYSET`, `NAK` with the full error-code set, and `CCRYPT`.

Deliberately left as opaque bytes, with no decoder: the biometric family
(`BIOREAD`, `BIOMATCH`, `BIOREADR`, `BIOMATCHR`), file transfer
(`FILETRANSFER`, `FTSTAT`), the manufacturer-specific family (`MFG`, `MFGREP`,
`MFGSTATR`, `MFGERRR`), smart-card/transparent mode (`XWR`, `XRD`, `PIVDATA`,
`PIVDATAR`, `GENAUTH`, `GENAUTHR`, `CRAUTH`, `CRAUTHR`, `KEEPACTIVE`),
`ACURXSIZE`, `ABORT`, `FMT`, and the trivial single-byte request payloads of
`ID`/`CAP`/`LSTAT`/`ISTAT`/`OSTAT`/`RSTAT`. None of these carries a Track-3
attack; add them when a drill needs one.

## Tests

`cargo test -p odr-osdp` → **141 unit tests + 10 doctests**, all passing.
`cargo clippy -p odr-osdp --all-targets -- -D warnings` is clean.

Coverage worth knowing about:

- The CRC catalogue check value: `crc16(b"123456789") == 0xE5CC`, plus a
  FIPS-197 known-answer test for AES-128.
- Every command code and every reply code round-tripped through the wire in
  eight variants each (mark/no mark, CRC/checksum, security block or not,
  payload lengths) — 432 encode/parse cycles.
- All eight security block types round-tripped.
- Malformed input: bad CRC, bad checksum, every possible truncation point,
  implausible length fields, a security block that overruns the frame, a frame
  with no room for its MAC, garbage before SOM, a stream that starts mid-frame,
  resync after a corrupt frame, and ~6500 pseudo-random buffers biased to look
  like frames — asserting only that nothing panics.
- A complete four-frame handshake under SCBK-D between two instances, every
  frame passing through `encode`/`parse` in between, ending in a bidirectional
  encrypted exchange and a 40-round chained session.
- MAC truncation: the wire MAC is the first 4 bytes of the 16-byte value, and
  the other 12 are non-zero.
- Weak-key detection and enumeration (768 distinct keys), and
  `recover_weak_scbk` cracking a captured handshake.
- The five Mellon attacks where they belong to this layer: downgrade (rewrite a
  real `PDCAP` frame), keyset capture (recover a site key from wire bytes),
  weak keys (crack a handshake, then decrypt traffic the attacker never took
  part in), and traffic analysis (name every frame of a fully encrypted session
  with no key at all).

## Things I was not certain about

Please verify these against real captures, or against the normative text if
anyone has access to it.

**The big one.** None of this was checked against IEC 60839-11-5 / SIA OSDP
v2.2.2 itself — that document is paywalled. Everything below was verified by
cross-referencing three independent implementations: `goToMain/libosdp` (C),
`smartrent/jeff` (Elixir) and `verkada/go-osdp` (Go). Two- and three-way
agreement is strong evidence, but it is not authority, and all three could
inherit the same misreading.

1. **`CMD_ABORT = 0xA2` — genuinely contested.** libosdp and jeff say `0xA2`;
   go-osdp says `0x7A`. I used `0xA2` (two sources to one, and go-osdp lacks the
   whole `0xA1..0xA7` extended block, suggesting it predates it). Note `0x7A` is
   `REPLY_FTSTAT` in the other direction, so a withdrawn `0x7A` assignment for
   ABORT is plausible. **Check this against a capture from real v2.2 gear.**
2. **`CMD_DIAG = 0x63`, `CMD_RMODE = 0x6C`, `CMD_TDSET = 0x6D` — single-source.**
   `DIAG` appears only in go-osdp; `RMODE` and `TDSET` only in libosdp, which
   marks both deprecated/obsolete. All three are included so a legacy capture
   decodes, and all three are flagged low-confidence in their doc comments. They
   may not exist in v2.2.2 at all.
3. **S-MAC1 / S-MAC2 derivation constants (`01 01` and `01 02`).** Verified in
   libosdp's `osdp_sc.c` and independently in jeff's `secure_channel.ex`, and
   they follow the same pattern as the `01 82` used for S-ENC. High confidence,
   but not from the standard. The six-bytes-of-RND.A-plus-eight-zero-bytes
   layout is confirmed in both.
4. **The initial R-MAC construction** — `AES-ECB(S-MAC2, AES-ECB(S-MAC1,
   server_cryptogram))`. libosdp is the only cross-referenced implementation
   with a PD side, so this is single-source. It is the natural two-key CBC-MAC
   of one block with a zero IV, which is reassuring, but it is one source.
5. **SCS_13 and SCS_14 are 3 bytes, not 2.** libosdp sends the key-type byte on
   SCS_13 as well as SCS_11/SCS_12, and sends `0x01` ("ACU authenticated") on
   SCS_14. I implemented that. The parser accepts any `scb_len ≥ 2`, so a peer
   that sends 2-byte SCS_13/SCS_14 blocks will still be read correctly.
6. **SCS_15 vs SCS_17 selection.** I follow libosdp: an empty payload uses the
   MAC-only block even when encryption was requested, because there is nothing
   to encrypt. This is observable on the wire (every `POLL`/`ACK` is visibly the
   cheap shape) and I would like to confirm real equipment does the same.
7. **`PDID` byte order.** libosdp writes vendor code and serial number
   little-endian. Vendor codes are conventionally *printed* as big-endian OUIs,
   so `vendor_code_u32()` may want reversing for display. The raw `[u8; 3]` and
   `[u8; 4]` fields are always available and are the safe thing to use.
8. **Control-code semantics**, as opposed to field layout: `OUT` control codes
   above `0x01`, `TEXT` control codes, `BUZ` tone codes, and `LED` temporary/
   permanent control codes. The byte positions are solid; the meanings of the
   individual values are from implementations and are marked medium confidence
   in the doc comments. Nothing in the crate depends on them.
9. **`LedColor` values `0x04`–`0x07`** (blue, magenta, cyan, white). `0x00`–`0x03`
   are original OSDP and certain. The later four are consistent across sources
   but unverified.
10. **`MAX_FRAME_LEN = 1600` is our own choice**, not a spec value. It exists so
    a corrupted length field cannot make a parser buffer 64 KiB. OSDP's real
    maximum is negotiated with `CMD_ACURXSIZE`; 1440 is the figure usually
    quoted. If a capture contains a legitimately larger frame this cap will
    reject it.
11. **The block-aligned MAC padding edge case.** When the MAC input is already a
    multiple of 16, no `0x80` padding is appended — libosdp only. Same for
    `pad_for_encryption`. This makes the padding non-removable in the general
    case, which `strip_padding` documents and works around.
12. **`KEYSET` key types other than `0x01`.** Only SCBK is modelled. If a vendor
    uses another value the payload still decodes; only the interpretation is
    missing.
13. **`RAW` format-code semantics.** The field is preserved and the bit count is
    honoured, but what a non-zero format code *means* is not modelled.

### One finding worth a second opinion

The MAC chain in each direction only advances when the *other* direction speaks:
the IV for a command MAC is the R-MAC, which changes only when a reply is
processed. Two commands sent back to back therefore MAC from the same IV *and
encrypt under the same CBC IV*, so identical plaintext yields identical
ciphertext, and a command replayed before the PD has answered still verifies.
This follows libosdp exactly and is implemented faithfully rather than repaired
— it is the sharpest form of the "IVs derived from MACs" weakness. See the tests
`two_consecutive_commands_reuse_the_same_cbc_iv` and
`a_replayed_command_is_only_stopped_once_a_reply_has_advanced_the_chain` in
`channel.rs`. In normal operation the strict poll/response cadence hides it; an
attacker who can suppress or delay a reply does not have to live with that.

If a real capture shows the chain advancing differently, that changes the
weakness and several drills, so it is the first thing to check against hardware.
