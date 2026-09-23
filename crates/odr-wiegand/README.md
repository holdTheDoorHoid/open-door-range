# odr-wiegand

Track 1 of the Open Door Range: the legacy reader-to-panel wire protocols that
OSDP was meant to replace. Card formats and parity, the D0/D1 pulse train and
its timing, ABA track-2 clock-and-data, and the attack primitives that fall out
of all three for free.

Zero dependencies. `#![forbid(unsafe_code)]`. `no_std` + `alloc`, so it builds
for `wasm32-unknown-unknown` unchanged — the browser range and the command-line
analyser run the same bytes, which is the point of `DESIGN.md` §3.

All time is a `u64` of **virtual microseconds supplied by the caller**. Nothing
here reads a clock, spawns a thread, or asks the OS for randomness.

```
cargo test -p odr-wiegand
cargo build --target wasm32-unknown-unknown -p odr-wiegand
cargo clippy -p odr-wiegand --all-targets -- -D warnings
```

## Module layout

| Module | Contents |
|---|---|
| `bits` | `BitVec` — a transmission-order bit buffer. Index 0 is the first bit on the wire; integers are read and written MSB-first; hex is left-padded. Every accessor returns `Option`/`Result` rather than panicking. |
| `parity` | `Parity`, `Coverage`, `ParityRule`, `ParityCheck`, `ParityReport`. Parity is declarative: a format is a list of rules, encoding applies them, decoding checks each one and reports it separately. |
| `format` | `CardFormat` (H10301, H10306, Corporate 1000, H10304, H10302, `Raw`), `Credential`, `encode`, `decode`, `decode_raw`, `infer_formats`. Decoding succeeds on bad parity and reports it; that is a deliberate API decision, see below. |
| `wire` | `Line`, `Level`, `Transition`, `WiegandTiming`, `encode_transitions`, `WireDecoder` (streaming) and `decode_transitions` (whole capture), `TimingAnomaly`. |
| `clock_data` | ABA track 2: `AbaTrack2`, `encode_char`, `lrc_nibble`, `decode_aba`; and the physical layer: `CdLine`, `CdTransition`, `ClockDataTiming`, `encode_clock_data`, `decode_clock_data`, `ClockDataAnomaly`. |
| `attack` | `Capture` (sniff + replay), `CredentialSweep` + `SweepCost` (brute force and what it costs in wall-clock time), `inline_tamper` / `substitute_fields` (the implant-in-the-housing case). |

The commonly used items are re-exported at the crate root.

## Two API decisions worth knowing about

**Bad parity is a result, not an error.** `decode` returns `Ok` whenever the
frame is the right width, with a per-rule `ParityReport` alongside the fields.
On a live wire a parity failure is a diagnostic signal — a marginal cable run, a
reader with a failing driver, a clumsy implant — and a decoder that throws the
frame away destroys exactly the evidence the range exists to show. Errors are
reserved for mismatches between a format and the data offered to it (wrong
width, oversized field, facility code where the format has none).

**Format inference returns a list.** Nothing on a Wiegand wire says which format
a frame is; the panel is simply configured to believe one. `infer_formats`
returns every reading that fits, parity-valid first, with the raw passthrough
always last. A 37-bit frame is genuinely both an H10304 and an H10302.

## Where each format's layout came from

Bit layouts and parity coverage were taken from
[`client/src/wiegand_formats.c`](https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/wiegand_formats.c)
in the RfidResearchGroup Proxmark3 client (`Pack_H10301`, `Pack_H10306`,
`Pack_C1k35s`, `Pack_H10304`, `Pack_H10302`), cross-checked against the
commonly published field descriptions for each format. That file is the most
reviewed open implementation of these layouts; vendor documentation for the
proprietary ones is not public.

`tests/vectors.rs` contains a second implementation of H10301, H10306,
Corporate 1000 and H10304, transcribed from those functions in their original
mask-and-shift style, and compares it against this crate's declarative rules
over the whole 8-bit facility-code space for H10301 and a spread of edge values
for the others. Two implementations that disagree about nothing is the real
evidence here; the Corporate 1000 parity combs in particular are the sort of
thing that is plausible and wrong.

Summarising what that settled:

* **H10301 (26)** — bit 0 even over bits 1–12, FC bits 1–8, CN bits 9–24,
  bit 25 odd over bits 13–24.
* **H10306 (34)** — bit 0 even over 1–16, FC 1–16, CN 17–32, bit 33 odd over
  17–32.
* **Corporate 1000 (35)** — company code bits 2–13, card number bits 14–33;
  bit 1 even over bits 2–33 skipping every position `p` where `p % 3 == 1`,
  bit 34 odd over bits 1–32 skipping every `p` where `p % 3 == 0`, and bit 0 odd
  over *all* of bits 1–34 including the other two parity bits. The rules
  therefore have to be applied in that order, which is why
  `CardFormat::parity_rules()` documents itself as being in application order.
* **H10304 (37)** — FC 1–16, CN 17–35; bit 0 even over 1–18 and bit 36 odd over
  18–35. The two 18-bit windows genuinely overlap at bit 18.
* **H10302 (37)** — same two parity rules, 35-bit card number at bits 1–35, no
  facility code.

Wiegand pulse timing (20–100 µs pulse, typically 50 µs; 200 µs – 20 ms period,
typically 1–2 ms) is the de-facto figure quoted across reader datasheets rather
than anything normative — there is no published standard for the D0/D1
interface. Every figure is a field on `WiegandTiming` for that reason.

ABA track 2 follows ISO/IEC 7811: five bits per character, four data bits sent
LSB-first plus an odd parity bit, values 0x0–0xF mapping to ASCII `'0'`–`'?'`,
start sentinel `;` (0x0B), field separator `=` (0x0D), end sentinel `?` (0x0F),
LRC last.

## Things I was unsure about

1. **The LRC's own parity bit.** The LRC's four data bits are unambiguous — the
   XOR of every character from the start sentinel through the end sentinel, so
   each bit column over that run comes out even. Its *fifth* bit is described
   inconsistently in secondary sources: some say odd parity over its own four
   bits like any other character, some say even parity over the parity column.
   This crate implements the first (odd parity over its own nibble), which is
   what the clearer sources state and what stripe-writing tools do. If a real
   capture ever disagrees, `AbaDecoded` exposes the LRC character's own
   `parity_ok` separately from `lrc_valid`, so the two can be told apart without
   an API change.

2. **Clock-and-data DATA polarity.** Sources describe DATA high as a one bit,
   but both lines are also described as open-collector idle-high, which makes an
   idle line read as a continuous one. Real readers differ. I modelled DATA as a
   level line with `ClockDataTiming::data_active_low` (default `false`, high
   means one) and made the idle level the level that means zero. Sampling is on
   the CLOCK falling edge, which the sources agree on.

3. **Clock-and-data timing figures.** I could not find a quotable normative
   spec for bit period, clock pulse width or setup time on the access-control
   clock-and-data interface. The defaults (1 ms bit period, 200 µs clock pulse,
   200 µs setup) are plausible rather than sourced. They are parameters, and the
   tolerance checks are proportional (half to twice nominal) rather than
   absolute, so nothing depends on the exact numbers being right.

4. **What a decoder should do with an out-of-spec pulse.** A pulse shorter than
   `min_pulse_us` or longer than `max_pulse_us` is reported as a
   `TimingAnomaly` *and still decoded into a bit*, on the grounds that a panel
   with a faster input filter would have taken it and hiding it would hide the
   interesting case. A simultaneous pulse on both lines is the one case where
   the bit is dropped, because no conforming transmitter produces it and there
   is no defensible value to decode. Both choices are documented on the relevant
   items; if `odr-bus` wants different behaviour it should be a parameter rather
   than a silent change here.

5. **Whether `Raw` should carry a bit count.** `CardFormat::Raw { bit_len }`
   does, so that `encode` has a width to target. Frames wider than 64 bits
   decode fine — `Decoded::bits` always holds them — but report
   `card_number: None`, since no integer can hold the value. Arbitrary-width
   streams are meant to stay as `BitVec` and go straight to the wire or to
   replay, neither of which needs a format at all.

6. **Frame boundary detection.** A gap larger than
   `WiegandTiming::interframe_gap_us` between two pulse *starts* ends the frame.
   Real panels use a timeout after the last pulse instead. The two are
   equivalent for well-formed traffic and differ only for a trailing partial
   pulse; `WireDecoder::flush()` covers the end-of-capture case explicitly.

## Test coverage

90 tests: 53 unit, 26 integration (`tests/vectors.rs`), 11 doc tests.

Covering: hand-computed known-good 26-bit vectors including the exact bit
pattern and hex; cross-implementation agreement over the whole H10301 facility
code space and a spread of Corporate 1000, H10306 and H10304 values; bit-level
round trips for every format; parity-failure detection, including that every
single-bit flip in a 26-bit frame is caught and that a two-bit flip inside one
window is not; D0/D1 encode → transition stream → decode round trips for every
format; simultaneous-pulse glitches, short/long pulses, too-close pulses, stray
and out-of-order edges, mid-frame resynchronisation, and a glitch burst followed
by a clean frame; ABA encode/decode with a hand-computed bit pattern and LRC,
plus LRC column parity, parity failures, and every missing-sentinel error path;
clock-and-data wire round trips in both polarities with setup and width
violations; format inference returning multiple candidates for an ambiguous
37-bit frame; replay, credential sweeps driven end-to-end onto the wire, sweep
cost, and inline tamper; and determinism of the whole pipeline.
