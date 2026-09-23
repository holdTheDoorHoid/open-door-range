//! Clock-and-data: ABA track-2 magstripe emulation over two wires.
//!
//! The other legacy reader output. Where Wiegand uses two data lines and no
//! clock, clock-and-data uses one **DATA** line that simply holds the current
//! bit's level and one **CLOCK** line that pulses once per bit; the panel
//! samples DATA on the falling edge of CLOCK. Readers that output this are
//! emulating a swipe of a magnetic stripe, so the bits are not a Wiegand card
//! format at all — they are ISO/IEC 7811 *track 2* exactly as it would come off
//! the head of a stripe reader.
//!
//! # Track 2 encoding
//!
//! Track 2 is a 5-bit alphabet: four data bits sent **least significant bit
//! first**, then one parity bit chosen so each character has an **odd** number
//! of ones. The sixteen four-bit values map to ASCII `'0'` (0x30) through
//! `'?'` (0x3F), so:
//!
//! | value | char | meaning |
//! |---|---|---|
//! | 0x0–0x9 | `0`–`9` | digits |
//! | 0x0B | `;` | start sentinel |
//! | 0x0D | `=` | field separator |
//! | 0x0F | `?` | end sentinel |
//!
//! A track reads: any number of leading zero bits (clocking-in bits), the start
//! sentinel, the data characters, the end sentinel, an **LRC** character, then
//! trailing zeros.
//!
//! The LRC is a longitudinal parity: its four data bits are the XOR of the four
//! data bits of every character from the start sentinel through the end
//! sentinel inclusive, so each bit *column* over that range ends up even. Its
//! own fifth bit is odd parity over its own four bits, exactly like every other
//! character. (Source note: this two-part rule is the one thing here that is
//! commonly stated wrongly; see the crate README.)
//!
//! # What this buys an attacker
//!
//! Nothing is different from Wiegand. The parity and the LRC are integrity
//! checks against a dirty read head, not against a person with a logic
//! analyser, and there is no key anywhere in the scheme. The value of modelling
//! it is that a lot of installed door hardware speaks this rather than Wiegand,
//! and people are surprised that "it's a magstripe protocol" is all there is
//! to it.

use crate::bits::BitVec;
use crate::wire::Level;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};

/// Start sentinel, `;`.
pub const START_SENTINEL: u8 = 0x0B;
/// Field separator, `=`.
pub const FIELD_SEPARATOR: u8 = 0x0D;
/// End sentinel, `?`.
pub const END_SENTINEL: u8 = 0x0F;

/// Bits per track-2 character: four data plus one parity.
pub const BITS_PER_CHAR: usize = 5;

/// Map a four-bit value to its track-2 ASCII character.
///
/// Returns `None` for values above 0x0F.
pub fn nibble_to_char(nibble: u8) -> Option<char> {
    if nibble > 0x0F {
        return None;
    }
    Some((0x30 + nibble) as char)
}

/// Map a track-2 ASCII character back to its four-bit value.
///
/// Accepts `'0'`–`'?'` (0x30–0x3F). Returns `None` for anything else.
pub fn char_to_nibble(c: char) -> Option<u8> {
    let v = c as u32;
    if (0x30..=0x3F).contains(&v) {
        Some((v - 0x30) as u8)
    } else {
        None
    }
}

/// Encode one character as its five wire bits: data LSB-first, then odd parity.
pub fn encode_char(nibble: u8) -> [bool; 5] {
    let n = nibble & 0x0F;
    let d = [
        n & 1 == 1,
        (n >> 1) & 1 == 1,
        (n >> 2) & 1 == 1,
        (n >> 3) & 1 == 1,
    ];
    let ones = d.iter().filter(|b| **b).count();
    [d[0], d[1], d[2], d[3], ones % 2 == 0]
}

/// The LRC nibble for a run of characters: the XOR of them all.
///
/// The run must be the start sentinel, the data, and the end sentinel — the
/// sentinels are included.
pub fn lrc_nibble(chars_including_sentinels: &[u8]) -> u8 {
    chars_including_sentinels
        .iter()
        .fold(0u8, |acc, c| acc ^ (c & 0x0F))
}

/// One character as it was found on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbaCharacter {
    /// Bit offset of the character's first bit within the stream.
    pub bit_offset: usize,
    /// The four data bits, as a value.
    pub nibble: u8,
    /// The fifth bit as transmitted.
    pub parity_bit: bool,
    /// Whether that fifth bit was the correct odd parity.
    pub parity_ok: bool,
}

impl AbaCharacter {
    /// The ASCII character this represents.
    pub fn as_char(self) -> char {
        nibble_to_char(self.nibble).unwrap_or('?')
    }
}

/// Encoding options for a track.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbaEncoding {
    /// Zero bits emitted before the start sentinel. Real readers send a run of
    /// these to let the panel's clock recovery settle; 10–20 is typical.
    pub leading_zeros: usize,
    /// Zero bits emitted after the LRC.
    pub trailing_zeros: usize,
}

impl Default for AbaEncoding {
    fn default() -> Self {
        AbaEncoding {
            leading_zeros: 10,
            trailing_zeros: 10,
        }
    }
}

impl AbaEncoding {
    /// No padding at all — just sentinels, data and LRC. Handy in tests.
    pub fn bare() -> Self {
        AbaEncoding {
            leading_zeros: 0,
            trailing_zeros: 0,
        }
    }
}

/// A track-2 message: the characters between the sentinels.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AbaTrack2 {
    /// Four-bit values, *excluding* the start sentinel, end sentinel and LRC.
    /// May contain [`FIELD_SEPARATOR`].
    pub data: Vec<u8>,
}

/// Why a track could not be built or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbaError {
    /// A character outside the track-2 alphabet appeared in a string.
    BadCharacter {
        /// The character.
        ch: char,
        /// Its position in the input string.
        at: usize,
    },
    /// A sentinel appeared inside the data, where it would confuse a decoder.
    SentinelInData {
        /// The offending value.
        nibble: u8,
        /// Its index in the data.
        at: usize,
    },
    /// No start sentinel was found anywhere in the bit stream.
    NoStartSentinel,
    /// A start sentinel was found but the stream ended before an end sentinel.
    NoEndSentinel {
        /// Bit offset where the start sentinel was found.
        start_bit: usize,
    },
    /// The end sentinel was found but there were fewer than five bits left for
    /// the LRC.
    TruncatedLrc {
        /// Bit offset where the LRC should have begun.
        at_bit: usize,
    },
}

impl fmt::Display for AbaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbaError::BadCharacter { ch, at } => {
                write!(f, "{ch:?} at offset {at} is not a track-2 character")
            }
            AbaError::SentinelInData { nibble, at } => {
                write!(f, "sentinel value {nibble:#x} at data index {at}")
            }
            AbaError::NoStartSentinel => f.write_str("no start sentinel in the stream"),
            AbaError::NoEndSentinel { start_bit } => {
                write!(
                    f,
                    "start sentinel at bit {start_bit} but no end sentinel followed"
                )
            }
            AbaError::TruncatedLrc { at_bit } => {
                write!(f, "stream ended at bit {at_bit}, before the LRC")
            }
        }
    }
}

impl AbaTrack2 {
    /// Build from four-bit values.
    ///
    /// # Errors
    /// [`AbaError::SentinelInData`] if a start or end sentinel appears in the
    /// data, which would make the track ambiguous. A field separator is fine.
    pub fn new(data: Vec<u8>) -> Result<Self, AbaError> {
        for (at, n) in data.iter().enumerate() {
            let n = n & 0x0F;
            if n == START_SENTINEL || n == END_SENTINEL {
                return Err(AbaError::SentinelInData { nibble: n, at });
            }
        }
        Ok(AbaTrack2 {
            data: data.into_iter().map(|n| n & 0x0F).collect(),
        })
    }

    /// Build from a string of track-2 characters, e.g. `"1234567=890"`.
    ///
    /// The sentinels are supplied by the encoder, so do not include them.
    ///
    /// # Errors
    /// [`AbaError::BadCharacter`] for anything outside `'0'`–`'?'`,
    /// [`AbaError::SentinelInData`] for `;` or `?`.
    pub fn from_ascii(s: &str) -> Result<Self, AbaError> {
        let mut data = Vec::with_capacity(s.len());
        for (at, ch) in s.char_indices() {
            match char_to_nibble(ch) {
                Some(n) => data.push(n),
                None => return Err(AbaError::BadCharacter { ch, at }),
            }
        }
        AbaTrack2::new(data)
    }

    /// The full character run including both sentinels, as it goes on the wire
    /// before the LRC.
    pub fn framed(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.data.len() + 2);
        v.push(START_SENTINEL);
        v.extend_from_slice(&self.data);
        v.push(END_SENTINEL);
        v
    }

    /// The LRC character for this track.
    pub fn lrc(&self) -> u8 {
        lrc_nibble(&self.framed())
    }

    /// Encode to bits: padding, sentinels, data, LRC, padding.
    ///
    /// ```
    /// use odr_wiegand::clock_data::{AbaEncoding, AbaTrack2, decode_aba};
    ///
    /// let track = AbaTrack2::from_ascii("12345=678").unwrap();
    /// let bits = track.encode(&AbaEncoding::default());
    /// let decoded = decode_aba(&bits).unwrap();
    /// assert_eq!(decoded.track.to_string(), "12345=678");
    /// assert!(decoded.lrc_valid);
    /// assert!(decoded.parity_valid());
    /// ```
    pub fn encode(&self, opts: &AbaEncoding) -> BitVec {
        let framed = self.framed();
        let lrc = lrc_nibble(&framed);
        let mut bits = BitVec::with_capacity(
            opts.leading_zeros + (framed.len() + 1) * BITS_PER_CHAR + opts.trailing_zeros,
        );
        bits.extend_zeros(opts.leading_zeros);
        for n in &framed {
            for b in encode_char(*n) {
                bits.push(b);
            }
        }
        for b in encode_char(lrc) {
            bits.push(b);
        }
        bits.extend_zeros(opts.trailing_zeros);
        bits
    }
}

impl fmt::Display for AbaTrack2 {
    /// The data as track-2 characters, without sentinels or LRC.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for n in &self.data {
            // Every nibble is masked to 0x0F on construction, so this never
            // falls back.
            f.write_char(nibble_to_char(*n).unwrap_or('?'))?;
        }
        Ok(())
    }
}

impl core::str::FromStr for AbaTrack2 {
    type Err = AbaError;

    fn from_str(s: &str) -> Result<Self, AbaError> {
        AbaTrack2::from_ascii(s)
    }
}

/// The sixteen track-2 characters, indexed by nibble value.
pub const TRACK2_ALPHABET: &str = "0123456789:;<=>?";

/// What a decoder recovered from a track-2 bit stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbaDecoded {
    /// The data between the sentinels.
    pub track: AbaTrack2,
    /// Every character read, sentinels and LRC included, with its parity
    /// result. Index 0 is the start sentinel; the last entry is the LRC.
    pub characters: Vec<AbaCharacter>,
    /// Bit offset at which the start sentinel was found. Anything before it was
    /// leading zeros or noise.
    pub start_bit: usize,
    /// The LRC that was transmitted.
    pub lrc_observed: u8,
    /// The LRC the data implies.
    pub lrc_expected: u8,
    /// Whether they match.
    pub lrc_valid: bool,
}

impl AbaDecoded {
    /// True when every character's odd-parity bit was correct.
    pub fn parity_valid(&self) -> bool {
        self.characters.iter().all(|c| c.parity_ok)
    }

    /// Indices into [`AbaDecoded::characters`] whose parity was wrong.
    pub fn parity_failures(&self) -> Vec<usize> {
        self.characters
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.parity_ok)
            .map(|(i, _)| i)
            .collect()
    }

    /// True when both parity and the LRC check out.
    pub fn is_clean(&self) -> bool {
        self.lrc_valid && self.parity_valid()
    }
}

fn read_char(bits: &BitVec, at: usize) -> Option<AbaCharacter> {
    let mut nibble = 0u8;
    for i in 0..4 {
        if bits.get(at + i)? {
            nibble |= 1 << i;
        }
    }
    let parity_bit = bits.get(at + 4)?;
    let expected = encode_char(nibble)[4];
    Some(AbaCharacter {
        bit_offset: at,
        nibble,
        parity_bit,
        parity_ok: parity_bit == expected,
    })
}

/// Find the start sentinel and decode a track-2 stream.
///
/// The search slides one bit at a time, so a capture that began mid-stream, or
/// that is preceded by an arbitrary number of clocking-in zeros, still decodes.
/// Parity and LRC failures are **reported, not raised** — a stripe read with one
/// bad character is still evidence about what was swiped.
///
/// # Errors
/// [`AbaError::NoStartSentinel`], [`AbaError::NoEndSentinel`] or
/// [`AbaError::TruncatedLrc`] when the stream does not contain a whole message.
pub fn decode_aba(bits: &BitVec) -> Result<AbaDecoded, AbaError> {
    let ss = encode_char(START_SENTINEL);
    let mut start_bit = None;
    if bits.len() >= BITS_PER_CHAR {
        for offset in 0..=bits.len() - BITS_PER_CHAR {
            if (0..BITS_PER_CHAR).all(|i| bits.get(offset + i) == Some(ss[i])) {
                start_bit = Some(offset);
                break;
            }
        }
    }
    let start_bit = start_bit.ok_or(AbaError::NoStartSentinel)?;

    let mut characters = Vec::new();
    let mut data = Vec::new();
    let mut at = start_bit;
    let mut saw_end = false;

    while let Some(ch) = read_char(bits, at) {
        characters.push(ch);
        at += BITS_PER_CHAR;
        if ch.nibble == END_SENTINEL && characters.len() > 1 {
            saw_end = true;
            break;
        }
        if characters.len() > 1 {
            data.push(ch.nibble);
        }
    }
    if !saw_end {
        return Err(AbaError::NoEndSentinel { start_bit });
    }

    let lrc_char = read_char(bits, at).ok_or(AbaError::TruncatedLrc { at_bit: at })?;
    characters.push(lrc_char);

    let framed: Vec<u8> = characters[..characters.len() - 1]
        .iter()
        .map(|c| c.nibble)
        .collect();
    let lrc_expected = lrc_nibble(&framed);

    Ok(AbaDecoded {
        track: AbaTrack2 { data },
        characters,
        start_bit,
        lrc_observed: lrc_char.nibble,
        lrc_expected,
        lrc_valid: lrc_char.nibble == lrc_expected,
    })
}

// ---------------------------------------------------------------------------
// Physical layer
// ---------------------------------------------------------------------------

/// Which of the two clock-and-data lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CdLine {
    /// Strobe. Pulses once per bit; the panel samples on the falling edge.
    Clock,
    /// Level line. Holds the current bit for the whole bit period.
    Data,
}

impl CdLine {
    /// `"CLOCK"` or `"DATA"`.
    pub fn name(self) -> &'static str {
        match self {
            CdLine::Clock => "CLOCK",
            CdLine::Data => "DATA",
        }
    }
}

impl fmt::Display for CdLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One edge on one clock-and-data line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CdTransition {
    /// Virtual microseconds.
    pub t_us: u64,
    /// Which line moved.
    pub line: CdLine,
    /// The level it moved to.
    pub level: Level,
}

impl fmt::Display for CdTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:>10} us  {} -> {}", self.t_us, self.line, self.level)
    }
}

/// Timing for the clock-and-data wire, in virtual microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockDataTiming {
    /// One bit's worth of time, start to start.
    pub bit_period_us: u64,
    /// How long CLOCK is held low each bit.
    pub clock_low_us: u64,
    /// How early DATA is settled before CLOCK falls. A panel that samples on
    /// the falling edge needs this to be non-zero.
    pub data_setup_us: u64,
    /// `true` if a low DATA line means a one bit. Readers differ; the common
    /// convention (and the default here) is that high means one.
    pub data_active_low: bool,
    /// Silence longer than this ends the message.
    pub interframe_gap_us: u64,
}

impl Default for ClockDataTiming {
    /// A nominal reader: 1 ms per bit, a 200 µs clock pulse, DATA settled
    /// 200 µs before the strobe falls.
    fn default() -> Self {
        ClockDataTiming {
            bit_period_us: 1_000,
            clock_low_us: 200,
            data_setup_us: 200,
            data_active_low: false,
            interframe_gap_us: 20_000,
        }
    }
}

impl ClockDataTiming {
    /// The DATA level that represents `bit`.
    pub fn level_for(&self, bit: bool) -> Level {
        match (bit, self.data_active_low) {
            (true, false) | (false, true) => Level::High,
            _ => Level::Low,
        }
    }

    /// The bit a DATA level represents.
    pub fn bit_for(&self, level: Level) -> bool {
        matches!(level, Level::High) != self.data_active_low
    }
}

/// Encode a bit stream onto the CLOCK and DATA lines.
///
/// For each bit: DATA is driven to the bit's level at the start of the bit
/// period, then CLOCK falls `data_setup_us` later and rises `clock_low_us`
/// after that. DATA edges are only emitted when the level actually changes,
/// which is what a real line looks like.
pub fn encode_clock_data(
    bits: &BitVec,
    timing: &ClockDataTiming,
    start_us: u64,
) -> Vec<CdTransition> {
    let mut out = Vec::with_capacity(bits.len() * 3);
    // Idle DATA sits at the level meaning zero, so a leading zero produces no
    // DATA edge — exactly as on a real wire.
    let mut current = timing.level_for(false);
    for (i, bit) in bits.iter().enumerate() {
        let t = start_us + i as u64 * timing.bit_period_us;
        let want = timing.level_for(bit);
        if want != current {
            out.push(CdTransition {
                t_us: t,
                line: CdLine::Data,
                level: want,
            });
            current = want;
        }
        out.push(CdTransition {
            t_us: t + timing.data_setup_us,
            line: CdLine::Clock,
            level: Level::Low,
        });
        out.push(CdTransition {
            t_us: t + timing.data_setup_us + timing.clock_low_us,
            line: CdLine::Clock,
            level: Level::High,
        });
    }
    out
}

/// Something wrong on the clock-and-data wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockDataAnomaly {
    /// DATA moved less than `data_setup_us` before the sampling edge, so the
    /// bit the panel latched is whatever won the race.
    SetupViolation {
        /// When the clock fell.
        t_us: u64,
        /// How long before that DATA last moved.
        setup_us: u64,
    },
    /// The CLOCK pulse was outside half to twice its nominal width.
    ClockWidthOutOfSpec {
        /// When the pulse started.
        t_us: u64,
        /// Measured width.
        width_us: u64,
    },
    /// Two sampling edges closer than half the nominal bit period.
    PeriodOutOfSpec {
        /// When the second edge fell.
        t_us: u64,
        /// Measured gap.
        period_us: u64,
    },
    /// A transition arrived out of time order.
    OutOfOrder {
        /// The offending timestamp.
        t_us: u64,
        /// The timestamp already seen.
        previous_us: u64,
    },
}

impl fmt::Display for ClockDataAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClockDataAnomaly::SetupViolation { t_us, setup_us } => {
                write!(
                    f,
                    "{t_us} us: DATA settled only {setup_us} us before the strobe"
                )
            }
            ClockDataAnomaly::ClockWidthOutOfSpec { t_us, width_us } => {
                write!(f, "{t_us} us: CLOCK pulse {width_us} us")
            }
            ClockDataAnomaly::PeriodOutOfSpec { t_us, period_us } => {
                write!(f, "{t_us} us: strobes {period_us} us apart")
            }
            ClockDataAnomaly::OutOfOrder { t_us, previous_us } => {
                write!(f, "{t_us} us: arrived after {previous_us} us")
            }
        }
    }
}

/// A message recovered from the clock-and-data wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CdFrame {
    /// When the first bit was sampled.
    pub start_us: u64,
    /// When the last bit was sampled.
    pub end_us: u64,
    /// The bits.
    pub bits: BitVec,
}

/// Everything recovered from a clock-and-data capture.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CdCapture {
    /// Messages, split on the inter-frame gap.
    pub frames: Vec<CdFrame>,
    /// Anomalies in order.
    pub anomalies: Vec<ClockDataAnomaly>,
}

impl CdCapture {
    /// True when nothing electrically odd happened.
    pub fn is_clean(&self) -> bool {
        self.anomalies.is_empty()
    }
}

/// Recover bits by sampling DATA on every falling edge of CLOCK.
///
/// ```
/// use odr_wiegand::clock_data::{
///     AbaEncoding, AbaTrack2, ClockDataTiming, decode_aba, decode_clock_data,
///     encode_clock_data,
/// };
///
/// let timing = ClockDataTiming::default();
/// let bits = AbaTrack2::from_ascii("4815162342").unwrap().encode(&AbaEncoding::default());
/// let edges = encode_clock_data(&bits, &timing, 0);
/// let capture = decode_clock_data(&edges, &timing);
/// assert_eq!(capture.frames[0].bits, bits);
/// assert_eq!(decode_aba(&capture.frames[0].bits).unwrap().track.to_string(), "4815162342");
/// ```
pub fn decode_clock_data(transitions: &[CdTransition], timing: &ClockDataTiming) -> CdCapture {
    let mut cap = CdCapture::default();
    let mut data_level = timing.level_for(false);
    let mut data_changed_at: Option<u64> = None;
    let mut clock_level = Level::High;
    let mut clock_fell_at: Option<u64> = None;
    let mut last_sample: Option<u64> = None;
    let mut last_seen: Option<u64> = None;

    let mut frame_bits = BitVec::new();
    let mut frame_start = 0u64;
    let mut frame_end = 0u64;

    for tr in transitions {
        if let Some(prev) = last_seen {
            if tr.t_us < prev {
                cap.anomalies.push(ClockDataAnomaly::OutOfOrder {
                    t_us: tr.t_us,
                    previous_us: prev,
                });
            }
        }
        last_seen = Some(last_seen.map_or(tr.t_us, |p| p.max(tr.t_us)));

        match tr.line {
            CdLine::Data => {
                if tr.level != data_level {
                    data_level = tr.level;
                    data_changed_at = Some(tr.t_us);
                }
            }
            CdLine::Clock => {
                match tr.level {
                    Level::Low => {
                        if clock_level == Level::Low {
                            continue; // already low; nothing to sample twice
                        }
                        clock_level = Level::Low;
                        clock_fell_at = Some(tr.t_us);

                        if let Some(changed) = data_changed_at {
                            let setup = tr.t_us.saturating_sub(changed);
                            if setup < timing.data_setup_us {
                                cap.anomalies.push(ClockDataAnomaly::SetupViolation {
                                    t_us: tr.t_us,
                                    setup_us: setup,
                                });
                            }
                        }

                        if let Some(prev) = last_sample {
                            let period = tr.t_us.saturating_sub(prev);
                            if period > timing.interframe_gap_us {
                                if !frame_bits.is_empty() {
                                    cap.frames.push(CdFrame {
                                        start_us: frame_start,
                                        end_us: frame_end,
                                        bits: core::mem::take(&mut frame_bits),
                                    });
                                }
                            } else if period * 2 < timing.bit_period_us {
                                cap.anomalies.push(ClockDataAnomaly::PeriodOutOfSpec {
                                    t_us: tr.t_us,
                                    period_us: period,
                                });
                            }
                        }

                        if frame_bits.is_empty() {
                            frame_start = tr.t_us;
                        }
                        frame_bits.push(timing.bit_for(data_level));
                        frame_end = tr.t_us;
                        last_sample = Some(tr.t_us);
                    }
                    Level::High => {
                        if clock_level == Level::High {
                            continue;
                        }
                        clock_level = Level::High;
                        if let Some(fell) = clock_fell_at.take() {
                            let width = tr.t_us.saturating_sub(fell);
                            if width * 2 < timing.clock_low_us || width > timing.clock_low_us * 2 {
                                cap.anomalies.push(ClockDataAnomaly::ClockWidthOutOfSpec {
                                    t_us: fell,
                                    width_us: width,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    if !frame_bits.is_empty() {
        cap.frames.push(CdFrame {
            start_us: frame_start,
            end_us: frame_end,
            bits: frame_bits,
        });
    }
    cap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn character_alphabet() {
        assert_eq!(nibble_to_char(0x0B), Some(';'));
        assert_eq!(nibble_to_char(0x0D), Some('='));
        assert_eq!(nibble_to_char(0x0F), Some('?'));
        assert_eq!(char_to_nibble('0'), Some(0));
        assert_eq!(char_to_nibble('9'), Some(9));
        assert_eq!(char_to_nibble('A'), None);
    }

    #[test]
    fn start_sentinel_bit_pattern() {
        // 0x0B = 1011; LSB first is 1,1,0,1; three ones, so odd parity adds 0.
        assert_eq!(
            encode_char(START_SENTINEL),
            [true, true, false, true, false]
        );
        // 0x0F = 1111; four ones, so odd parity adds 1.
        assert_eq!(encode_char(END_SENTINEL), [true, true, true, true, true]);
        // 0x0D = 1101; LSB first is 1,0,1,1; three ones -> 0.
        assert_eq!(
            encode_char(FIELD_SEPARATOR),
            [true, false, true, true, false]
        );
        // 0x00: no ones, so odd parity adds 1.
        assert_eq!(encode_char(0), [false, false, false, false, true]);
    }

    #[test]
    fn every_character_has_odd_parity() {
        for n in 0u8..16 {
            let c = encode_char(n);
            assert_eq!(c.iter().filter(|b| **b).count() % 2, 1, "nibble {n:#x}");
        }
    }

    #[test]
    fn lrc_makes_every_column_even() {
        let track = AbaTrack2::from_ascii("12345=678").unwrap();
        let framed = track.framed();
        let lrc = track.lrc();
        let mut all = framed.clone();
        all.push(lrc);
        for column in 0..4 {
            let ones = all.iter().filter(|n| (*n >> column) & 1 == 1).count();
            assert_eq!(ones % 2, 0, "column {column} is not even");
        }
    }

    #[test]
    fn encode_decode_round_trip_with_lrc() {
        let track = AbaTrack2::from_ascii("6011000990139424=25121011").unwrap();
        let bits = track.encode(&AbaEncoding::default());
        let d = decode_aba(&bits).unwrap();
        assert_eq!(d.track, track);
        assert!(d.lrc_valid);
        assert!(d.parity_valid());
        assert!(d.is_clean());
        assert_eq!(d.start_bit, 10);
        // start sentinel + data + end sentinel + LRC
        assert_eq!(d.characters.len(), track.data.len() + 3);
    }

    #[test]
    fn bare_encoding_has_expected_length() {
        let track = AbaTrack2::from_ascii("123").unwrap();
        let bits = track.encode(&AbaEncoding::bare());
        // SS + 3 data + ES + LRC = 6 characters.
        assert_eq!(bits.len(), 6 * BITS_PER_CHAR);
        assert_eq!(decode_aba(&bits).unwrap().start_bit, 0);
    }

    #[test]
    fn a_flipped_bit_shows_up_as_parity_and_lrc_failure() {
        let track = AbaTrack2::from_ascii("1234").unwrap();
        let mut bits = track.encode(&AbaEncoding::bare());
        bits.set(5, !bits.get(5).unwrap()).unwrap(); // first data character
        let d = decode_aba(&bits).unwrap();
        assert!(!d.parity_valid());
        assert_eq!(d.parity_failures(), alloc::vec![1]);
        assert!(!d.lrc_valid);
    }

    #[test]
    fn sentinels_are_rejected_in_data() {
        assert!(matches!(
            AbaTrack2::from_ascii("12;34"),
            Err(AbaError::SentinelInData {
                nibble: 0x0B,
                at: 2
            })
        ));
        assert!(matches!(
            AbaTrack2::from_ascii("12x"),
            Err(AbaError::BadCharacter { ch: 'x', .. })
        ));
    }

    #[test]
    fn missing_sentinels_are_errors_not_panics() {
        assert_eq!(
            decode_aba(&BitVec::zeros(50)).unwrap_err(),
            AbaError::NoStartSentinel
        );
        assert_eq!(
            decode_aba(&BitVec::new()).unwrap_err(),
            AbaError::NoStartSentinel
        );
        let mut bits = BitVec::new();
        for b in encode_char(START_SENTINEL) {
            bits.push(b);
        }
        for b in encode_char(1) {
            bits.push(b);
        }
        assert_eq!(
            decode_aba(&bits).unwrap_err(),
            AbaError::NoEndSentinel { start_bit: 0 }
        );
    }

    #[test]
    fn truncated_lrc_is_reported() {
        let track = AbaTrack2::from_ascii("12").unwrap();
        let bits = track.encode(&AbaEncoding::bare());
        let short = bits.slice(0, bits.len() - 3).unwrap();
        assert!(matches!(
            decode_aba(&short),
            Err(AbaError::TruncatedLrc { .. })
        ));
    }

    #[test]
    fn clock_and_data_wire_round_trip() {
        let timing = ClockDataTiming::default();
        let track = AbaTrack2::from_ascii("987654321=0").unwrap();
        let bits = track.encode(&AbaEncoding::default());
        let edges = encode_clock_data(&bits, &timing, 1_234);
        let cap = decode_clock_data(&edges, &timing);
        assert!(cap.is_clean(), "{:?}", cap.anomalies);
        assert_eq!(cap.frames.len(), 1);
        assert_eq!(cap.frames[0].bits, bits);
        assert_eq!(decode_aba(&cap.frames[0].bits).unwrap().track, track);
    }

    #[test]
    fn inverted_data_polarity_round_trips() {
        let timing = ClockDataTiming {
            data_active_low: true,
            ..ClockDataTiming::default()
        };
        let bits = BitVec::from_bin_str("1100101").unwrap();
        let edges = encode_clock_data(&bits, &timing, 0);
        let cap = decode_clock_data(&edges, &timing);
        assert_eq!(cap.frames[0].bits, bits);
    }

    #[test]
    fn setup_violation_is_flagged() {
        let timing = ClockDataTiming::default();
        let edges = [
            // DATA moves only 10 us before the strobe falls.
            CdTransition {
                t_us: 990,
                line: CdLine::Data,
                level: Level::High,
            },
            CdTransition {
                t_us: 1_000,
                line: CdLine::Clock,
                level: Level::Low,
            },
            CdTransition {
                t_us: 1_200,
                line: CdLine::Clock,
                level: Level::High,
            },
        ];
        let cap = decode_clock_data(&edges, &timing);
        assert!(cap
            .anomalies
            .iter()
            .any(|a| matches!(a, ClockDataAnomaly::SetupViolation { setup_us: 10, .. })));
        assert_eq!(cap.frames[0].bits.to_bin_string(), "1");
    }

    #[test]
    fn clock_width_out_of_spec_is_flagged() {
        let timing = ClockDataTiming::default();
        let edges = [
            CdTransition {
                t_us: 0,
                line: CdLine::Clock,
                level: Level::Low,
            },
            CdTransition {
                t_us: 10,
                line: CdLine::Clock,
                level: Level::High,
            },
        ];
        let cap = decode_clock_data(&edges, &timing);
        assert!(cap.anomalies.iter().any(|a| matches!(
            a,
            ClockDataAnomaly::ClockWidthOutOfSpec { width_us: 10, .. }
        )));
    }
}
