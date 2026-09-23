//! **The capture seam.**
//!
//! `DESIGN.md` §3 fixes the interchange format exactly, and this module is
//! both halves of it: export from a live event log, and import back into
//! something replayable.
//!
//! ```text
//! {"t_us": 12345, "line": "rs485" | "wiegand",
//!  "dir": "acu_to_pd" | "pd_to_acu" | "wire", "bytes": "53000e00..."}
//! ```
//!
//! Newline-delimited, one line per observed event, in time order. Both halves
//! exist now, before any hardware importer does, because writing the reader
//! is the only way to find out whether the format actually carries what a
//! replay needs. It mostly does; see "What the format does not carry" below.
//!
//! # What gets exported
//!
//! Transmissions — what was *driven onto a medium* — not receptions. A capture
//! is what a probe saw, and a probe sees the line, not a receiver's opinion of
//! it. Use [`export_from_tap`] to get one probe point's view instead of every
//! segment of every link at once, which is what [`export_ndjson`] gives.
//!
//! # What the format does not carry
//!
//! Three things, all of them worth knowing before trusting a round trip:
//!
//! 1. **Bit counts on a Wiegand line.** `bytes` is a byte string, so a 26-bit
//!    card read exports as four bytes with six bits of padding, and the import
//!    side cannot tell 26 from 27 or 32. [`CaptureEvent::wiegand_candidates`]
//!    hands back every reading that fits a known card format, parity-valid
//!    first, which is the same thing `odr_wiegand::infer_formats` does for the
//!    same reason: nothing on the wire says which format it was.
//! 2. **Which link and which segment.** With one reader and one bus this does
//!    not matter. With two links, or with an inline tap cutting one link into
//!    two electrically separate halves, an exported capture mixes them. Export
//!    per-probe with [`export_from_tap`] when that matters.
//! 3. **Clock-and-data.** The `line` field has two values and neither is
//!    clock-and-data. By default a clock-and-data link exports as `"wiegand"`,
//!    which is lossy; set [`CaptureOptions::distinguish_clock_data`] to emit
//!    `"clock_data"` instead when both ends of the pipe are ours. The importer
//!    accepts either.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use odr_osdp::frame::{ScanEvent, Scanner};
use odr_osdp::Frame;
use odr_wiegand::{BitVec, CardFormat, KNOWN_FORMATS};

use crate::ids::{BusDir, Micros};
use crate::log::{EventLog, LogRecord, RecordKind, WireKind};
use crate::sched::Injection;

/// Which physical line an event was on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureLine {
    /// An RS-485 bus.
    Rs485,
    /// A Wiegand D0/D1 pair.
    Wiegand,
    /// A clock-and-data pair. Not one of the two values `DESIGN.md` §3 names;
    /// produced only when [`CaptureOptions::distinguish_clock_data`] is set,
    /// and always accepted on import.
    ClockData,
    /// Something a future importer produced that this crate does not know.
    /// Preserved rather than rejected, so a capture from other tooling still
    /// round-trips.
    Other(String),
}

impl CaptureLine {
    /// The spelling used in the file.
    pub fn as_str(&self) -> &str {
        match self {
            CaptureLine::Rs485 => "rs485",
            CaptureLine::Wiegand => "wiegand",
            CaptureLine::ClockData => "clock_data",
            CaptureLine::Other(s) => s,
        }
    }

    /// Parse the spelling used in the file.
    pub fn parse(s: &str) -> CaptureLine {
        match s {
            "rs485" => CaptureLine::Rs485,
            "wiegand" => CaptureLine::Wiegand,
            "clock_data" | "clock-and-data" => CaptureLine::ClockData,
            other => CaptureLine::Other(other.to_string()),
        }
    }

    /// True if this line carries OSDP frames.
    pub fn is_bus(&self) -> bool {
        matches!(self, CaptureLine::Rs485)
    }
}

impl fmt::Display for CaptureLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which way an event was travelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureDir {
    /// Controller to peripheral.
    AcuToPd,
    /// Peripheral to controller.
    PdToAcu,
    /// A one-way line, where there is only one direction to be going in.
    Wire,
    /// Something a future importer produced that this crate does not know.
    Other(String),
}

impl CaptureDir {
    /// The spelling used in the file.
    pub fn as_str(&self) -> &str {
        match self {
            CaptureDir::AcuToPd => "acu_to_pd",
            CaptureDir::PdToAcu => "pd_to_acu",
            CaptureDir::Wire => "wire",
            CaptureDir::Other(s) => s,
        }
    }

    /// Parse the spelling used in the file.
    pub fn parse(s: &str) -> CaptureDir {
        match s {
            "acu_to_pd" => CaptureDir::AcuToPd,
            "pd_to_acu" => CaptureDir::PdToAcu,
            "wire" => CaptureDir::Wire,
            other => CaptureDir::Other(other.to_string()),
        }
    }

    /// The bus direction, if this is one.
    pub fn bus_dir(&self) -> Option<BusDir> {
        match self {
            CaptureDir::AcuToPd => Some(BusDir::AcuToPd),
            CaptureDir::PdToAcu => Some(BusDir::PdToAcu),
            _ => None,
        }
    }
}

impl fmt::Display for CaptureDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One line of a capture file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureEvent {
    /// Virtual microseconds.
    pub t_us: Micros,
    /// Which line.
    pub line: CaptureLine,
    /// Which direction.
    pub dir: CaptureDir,
    /// The octets.
    pub bytes: Vec<u8>,
}

impl CaptureEvent {
    /// The OSDP frame these bytes decode to, if they decode.
    pub fn frame(&self) -> Option<Frame> {
        Frame::parse(&self.bytes).ok().map(|(f, _)| f)
    }

    /// Every OSDP frame in these bytes, for a capture line that packed more
    /// than one.
    pub fn frames(&self) -> Vec<Frame> {
        Scanner::offline(&self.bytes)
            .filter_map(|e| match e {
                ScanEvent::Frame { frame, .. } => Some(*frame),
                _ => None,
            })
            .collect()
    }

    /// The bits, on the assumption that every bit of every byte is data.
    ///
    /// Right for a byte-aligned stream and wrong for a 26-bit card read; see
    /// [`CaptureEvent::wiegand_candidates`].
    pub fn all_bits(&self) -> BitVec {
        let mut out = BitVec::with_capacity(self.bytes.len() * 8);
        for b in &self.bytes {
            for i in 0..8 {
                out.push(b & (0x80 >> i) != 0);
            }
        }
        out
    }

    /// Plausible readings of a Wiegand line's bytes, parity-valid first.
    ///
    /// The exported byte string is the bit stream left-aligned and padded, so
    /// the original bit count is gone. This tries every known card format
    /// whose width would have produced this many bytes and returns the ones
    /// that fit, best first. An empty result means the bytes are not a card
    /// read in any format this crate knows — which is itself useful.
    pub fn wiegand_candidates(&self) -> Vec<BitVec> {
        let all = self.all_bits();
        let byte_len = self.bytes.len();
        let mut out = Vec::new();
        let mut fallback = Vec::new();
        for format in KNOWN_FORMATS {
            let len = format.bit_len();
            if len == 0 || len.div_ceil(8) != byte_len {
                continue;
            }
            let candidate = match all.slice(0, len) {
                Some(b) => b,
                None => continue,
            };
            match odr_wiegand::decode(*format, &candidate) {
                Ok(d) if d.parity_valid() => out.push(candidate),
                _ => fallback.push(candidate),
            }
        }
        out.extend(fallback);
        if out.is_empty() {
            out.push(all);
        }
        out
    }
}

/// How to write a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureOptions {
    /// Emit `"clock_data"` for clock-and-data links instead of folding them
    /// into `"wiegand"`. Off by default, because `DESIGN.md` §3 names exactly
    /// two line values and this crate does not get to add a third to the
    /// interchange format on its own authority.
    pub distinguish_clock_data: bool,
}

/// What went wrong reading a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureError {
    /// Which line of the file, counting from 1.
    pub line: usize,
    /// What was wrong.
    pub kind: CaptureErrorKind,
}

/// The kinds of malformed capture line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureErrorKind {
    /// The line is not a JSON object.
    NotAnObject,
    /// A required field is missing.
    MissingField(&'static str),
    /// A field has the wrong shape.
    BadField {
        /// Which field.
        field: &'static str,
        /// What was wrong with it.
        detail: String,
    },
    /// The hex string is not hex, or has an odd length.
    BadHex {
        /// The offending text, truncated.
        text: String,
    },
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: ", self.line)?;
        match &self.kind {
            CaptureErrorKind::NotAnObject => f.write_str("not a JSON object"),
            CaptureErrorKind::MissingField(n) => write!(f, "missing field \"{n}\""),
            CaptureErrorKind::BadField { field, detail } => {
                write!(f, "field \"{field}\": {detail}")
            }
            CaptureErrorKind::BadHex { text } => write!(f, "not a hex string: \"{text}\""),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CaptureError {}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// Lowercase hex, no separators.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    out
}

/// Parse lowercase or uppercase hex with no separators.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Pack bits MSB-first, left-aligned, padding the last byte with zeros.
///
/// The same packing `REPLY_RAW` uses, so a Wiegand line and an OSDP card read
/// of the same credential export as the same byte string.
pub fn pack_bits(bits: &BitVec) -> Vec<u8> {
    let mut out = alloc::vec![0u8; bits.len().div_ceil(8)];
    for (i, bit) in bits.iter().enumerate() {
        if bit {
            if let Some(b) = out.get_mut(i / 8) {
                *b |= 0x80 >> (i % 8);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Turn one log record into a capture event, if it is one.
pub fn record_to_event(record: &LogRecord, opts: &CaptureOptions) -> Option<CaptureEvent> {
    match &record.kind {
        RecordKind::BusTx { dir, bytes, .. } => Some(CaptureEvent {
            t_us: record.t_us,
            line: CaptureLine::Rs485,
            dir: match dir {
                BusDir::AcuToPd => CaptureDir::AcuToPd,
                BusDir::PdToAcu => CaptureDir::PdToAcu,
            },
            bytes: bytes.clone(),
        }),
        RecordKind::WireTx { kind, bits, .. } => Some(CaptureEvent {
            t_us: record.t_us,
            line: match kind {
                WireKind::Wiegand => CaptureLine::Wiegand,
                WireKind::ClockData if opts.distinguish_clock_data => CaptureLine::ClockData,
                WireKind::ClockData => CaptureLine::Wiegand,
            },
            dir: CaptureDir::Wire,
            bytes: pack_bits(bits),
        }),
        _ => None,
    }
}

/// Serialise capture events as newline-delimited JSON.
///
/// One object per line, keys in the order `DESIGN.md` §3 writes them, and a
/// trailing newline. The output is byte-identical for identical input, which
/// is what lets a determinism test compare two runs by comparing two strings.
pub fn write_ndjson(events: &[CaptureEvent]) -> String {
    let mut out = String::new();
    for e in events {
        out.push_str("{\"t_us\":");
        push_u64(&mut out, e.t_us);
        out.push_str(",\"line\":\"");
        out.push_str(e.line.as_str());
        out.push_str("\",\"dir\":\"");
        out.push_str(e.dir.as_str());
        out.push_str("\",\"bytes\":\"");
        out.push_str(&to_hex(&e.bytes));
        out.push_str("\"}\n");
    }
    out
}

fn push_u64(out: &mut String, mut v: u64) {
    if v == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    for b in &buf[i..] {
        out.push(*b as char);
    }
}

/// Every transmission in a log, as capture events.
pub fn events_from_log(log: &EventLog, opts: &CaptureOptions) -> Vec<CaptureEvent> {
    log.records()
        .iter()
        .filter_map(|r| record_to_event(r, opts))
        .collect()
}

/// Export a whole event log in the format `DESIGN.md` §3 fixes.
pub fn export_ndjson(log: &EventLog) -> String {
    write_ndjson(&events_from_log(log, &CaptureOptions::default()))
}

/// Export a whole event log with non-default options.
pub fn export_ndjson_with(log: &EventLog, opts: &CaptureOptions) -> String {
    write_ndjson(&events_from_log(log, opts))
}

/// Export only what one tap could see — the honest "this is what my probe
/// recorded".
///
/// A tap sees its own segment, so this is the export to use whenever a link
/// has an inline tap on it, or whenever a world has more than one link.
pub fn export_from_tap(tap: &dyn crate::tap::Tap, opts: &CaptureOptions) -> String {
    let events: Vec<CaptureEvent> = tap
        .seen()
        .iter()
        .map(|s| CaptureEvent {
            t_us: s.t_us,
            line: match (s.bits.is_some(), s.wire_kind) {
                (false, _) => CaptureLine::Rs485,
                (true, Some(WireKind::ClockData)) if opts.distinguish_clock_data => {
                    CaptureLine::ClockData
                }
                (true, _) => CaptureLine::Wiegand,
            },
            dir: match s.dir {
                Some(BusDir::AcuToPd) => CaptureDir::AcuToPd,
                Some(BusDir::PdToAcu) => CaptureDir::PdToAcu,
                None => CaptureDir::Wire,
            },
            bytes: match &s.bits {
                Some(b) => pack_bits(b),
                None => s.bytes.clone(),
            },
        })
        .collect();
    write_ndjson(&events)
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Parse newline-delimited JSON back into capture events.
///
/// Blank lines are skipped. Unknown fields are ignored, so a richer capture
/// from a future importer still reads. Unknown `line` and `dir` values are
/// preserved rather than rejected.
pub fn parse_ndjson(text: &str) -> Result<Vec<CaptureEvent>, CaptureError> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(parse_line(trimmed, line_no)?);
    }
    Ok(out)
}

fn parse_line(text: &str, line_no: usize) -> Result<CaptureEvent, CaptureError> {
    let body = text
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or(CaptureError {
            line: line_no,
            kind: CaptureErrorKind::NotAnObject,
        })?;

    let mut t_us: Option<u64> = None;
    let mut line: Option<CaptureLine> = None;
    let mut dir: Option<CaptureDir> = None;
    let mut bytes: Option<Vec<u8>> = None;

    for field in split_fields(body) {
        let (key, value) = match field.split_once(':') {
            Some(p) => p,
            None => continue,
        };
        let key = key.trim().trim_matches('"');
        let value = value.trim();
        match key {
            "t_us" => {
                let digits = value.trim_matches('"');
                t_us = Some(digits.parse::<u64>().map_err(|_| CaptureError {
                    line: line_no,
                    kind: CaptureErrorKind::BadField {
                        field: "t_us",
                        detail: alloc::format!("\"{digits}\" is not a non-negative integer"),
                    },
                })?);
            }
            "line" => line = Some(CaptureLine::parse(value.trim_matches('"'))),
            "dir" => dir = Some(CaptureDir::parse(value.trim_matches('"'))),
            "bytes" => {
                let hex = value.trim_matches('"');
                bytes = Some(from_hex(hex).ok_or_else(|| CaptureError {
                    line: line_no,
                    kind: CaptureErrorKind::BadHex {
                        text: hex.chars().take(32).collect(),
                    },
                })?);
            }
            _ => {}
        }
    }

    Ok(CaptureEvent {
        t_us: t_us.ok_or(CaptureError {
            line: line_no,
            kind: CaptureErrorKind::MissingField("t_us"),
        })?,
        line: line.ok_or(CaptureError {
            line: line_no,
            kind: CaptureErrorKind::MissingField("line"),
        })?,
        dir: dir.ok_or(CaptureError {
            line: line_no,
            kind: CaptureErrorKind::MissingField("dir"),
        })?,
        bytes: bytes.ok_or(CaptureError {
            line: line_no,
            kind: CaptureErrorKind::MissingField("bytes"),
        })?,
    })
}

/// Split an object body on commas that are not inside a string.
fn split_fields(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            ',' if !in_string => {
                out.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start <= body.len() {
        out.push(&body[start..]);
    }
    out
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// A parsed capture, ready to be put back on a link.
///
/// This is the other half of the seam: `odr-cli` loads a file, builds one of
/// these, and drives the same engines the browser runs. Today it replays a
/// capture this crate produced; tomorrow it replays one from a logic analyser,
/// with no change to anything below it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureReplay {
    events: Vec<CaptureEvent>,
}

impl CaptureReplay {
    /// Wrap a list of events, sorted by time.
    ///
    /// The sort is stable, so events sharing a timestamp keep their file
    /// order — which matters, because that order is how a capture records
    /// which of two simultaneous things happened first.
    pub fn new(mut events: Vec<CaptureEvent>) -> CaptureReplay {
        events.sort_by_key(|e| e.t_us);
        CaptureReplay { events }
    }

    /// Parse a capture file.
    pub fn parse(text: &str) -> Result<CaptureReplay, CaptureError> {
        Ok(CaptureReplay::new(parse_ndjson(text)?))
    }

    /// The events, in time order.
    pub fn events(&self) -> &[CaptureEvent] {
        &self.events
    }

    /// How many events there are.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True if the capture is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// When the first event happened.
    pub fn start_us(&self) -> Micros {
        self.events.first().map(|e| e.t_us).unwrap_or(0)
    }

    /// When the last event happened.
    pub fn end_us(&self) -> Micros {
        self.events.last().map(|e| e.t_us).unwrap_or(0)
    }

    /// Every OSDP frame in the capture, with its timestamp and direction.
    pub fn osdp_frames(&self) -> Vec<(Micros, BusDir, Frame)> {
        let mut out = Vec::new();
        for e in &self.events {
            if !e.line.is_bus() {
                continue;
            }
            let dir = match e.dir.bus_dir() {
                Some(d) => d,
                None => continue,
            };
            for f in e.frames() {
                out.push((e.t_us, dir, f));
            }
        }
        out
    }

    /// Every card read in the capture, as the most plausible bit pattern.
    ///
    /// Covers both lines: a Wiegand event's bytes are unpacked back into bits,
    /// and an OSDP `REPLY_RAW` payload gives its bit count exactly.
    pub fn card_reads(&self) -> Vec<(Micros, BitVec)> {
        let mut out = Vec::new();
        for e in &self.events {
            match &e.line {
                CaptureLine::Rs485 => {
                    for f in e.frames() {
                        if f.reply_code() == Some(odr_osdp::Reply::Raw) {
                            if let Ok(raw) = odr_osdp::RawCardRead::decode(&f.payload) {
                                out.push((e.t_us, BitVec::from_bools(&raw.bits())));
                            }
                        }
                    }
                }
                _ => {
                    if let Some(bits) = e.wiegand_candidates().into_iter().next() {
                        out.push((e.t_us, bits));
                    }
                }
            }
        }
        out
    }

    /// Turn the capture into transmissions for an injecting or inline tap.
    ///
    /// `shift_us` is added to every timestamp, so a capture taken at
    /// `t = 1.2 s` can be replayed at `t = 30 s` in a fresh world. Events on a
    /// line the target link does not speak are skipped rather than mangled.
    pub fn injections(&self, shift_us: Micros, onto: ReplayTarget) -> Vec<Injection> {
        let mut out = Vec::new();
        for e in &self.events {
            let at = e.t_us.saturating_add(shift_us);
            match (onto, &e.line) {
                (ReplayTarget::Rs485, CaptureLine::Rs485) => {
                    let dir = e.dir.bus_dir().unwrap_or(BusDir::AcuToPd);
                    out.push(Injection::bus_bytes(at, dir, e.bytes.clone()));
                }
                (ReplayTarget::Wire, CaptureLine::Wiegand)
                | (ReplayTarget::Wire, CaptureLine::ClockData) => {
                    if let Some(bits) = e.wiegand_candidates().into_iter().next() {
                        out.push(Injection::wire_bits(at, bits));
                    }
                }
                (ReplayTarget::WireExact(format), CaptureLine::Wiegand)
                | (ReplayTarget::WireExact(format), CaptureLine::ClockData) => {
                    if let Some(bits) = e.all_bits().slice(0, format.bit_len()) {
                        out.push(Injection::wire_bits(at, bits));
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// Which kind of link a capture is being replayed onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayTarget {
    /// An RS-485 bus: the bytes go back verbatim.
    Rs485,
    /// A two-wire link, taking the most plausible bit count for each event.
    Wire,
    /// A two-wire link, taking exactly this format's bit count and ignoring
    /// what the parity says. Use it when the capture is known to be one
    /// format, which is the case whenever the scenario built it.
    WireExact(CardFormat),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = alloc::vec![0x53, 0x00, 0x0E, 0xFF];
        assert_eq!(to_hex(&bytes), "53000eff");
        assert_eq!(from_hex("53000eff"), Some(bytes.clone()));
        assert_eq!(from_hex("53000EFF"), Some(bytes));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }

    #[test]
    fn one_line_is_the_format_design_specifies() {
        let ev = CaptureEvent {
            t_us: 12345,
            line: CaptureLine::Rs485,
            dir: CaptureDir::AcuToPd,
            bytes: alloc::vec![0x53, 0x00, 0x0E, 0x00],
        };
        assert_eq!(
            write_ndjson(&[ev]),
            "{\"t_us\":12345,\"line\":\"rs485\",\"dir\":\"acu_to_pd\",\"bytes\":\"53000e00\"}\n"
        );
    }

    #[test]
    fn writing_then_reading_gives_back_the_same_events() {
        let events = alloc::vec![
            CaptureEvent {
                t_us: 0,
                line: CaptureLine::Rs485,
                dir: CaptureDir::AcuToPd,
                bytes: alloc::vec![1, 2, 3],
            },
            CaptureEvent {
                t_us: 9_999_999_999,
                line: CaptureLine::Wiegand,
                dir: CaptureDir::Wire,
                bytes: alloc::vec![0xFF],
            },
        ];
        let text = write_ndjson(&events);
        assert_eq!(parse_ndjson(&text).unwrap(), events);
    }

    #[test]
    fn unknown_fields_and_spacing_are_tolerated() {
        let text = "{ \"t_us\": 7 , \"line\": \"rs485\", \"dir\": \"pd_to_acu\", \
                    \"bytes\": \"40\", \"probe\": \"tap#1\" }\n\n";
        let events = parse_ndjson(text).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].t_us, 7);
        assert_eq!(events[0].bytes, alloc::vec![0x40]);
    }

    #[test]
    fn a_broken_line_names_itself() {
        let text = "{\"t_us\":1,\"line\":\"rs485\",\"dir\":\"wire\",\"bytes\":\"53\"}\n\
                    {\"line\":\"rs485\",\"dir\":\"wire\",\"bytes\":\"53\"}\n";
        let err = parse_ndjson(text).unwrap_err();
        assert_eq!(err.line, 2);
        assert_eq!(err.kind, CaptureErrorKind::MissingField("t_us"));
    }

    #[test]
    fn a_twenty_six_bit_read_survives_the_byte_padding() {
        let cred = odr_wiegand::Credential::new(CardFormat::H10301, 42, 1337);
        let bits = cred.encode().unwrap();
        let ev = CaptureEvent {
            t_us: 1,
            line: CaptureLine::Wiegand,
            dir: CaptureDir::Wire,
            bytes: pack_bits(&bits),
        };
        assert_eq!(ev.bytes.len(), 4);
        let candidates = ev.wiegand_candidates();
        assert_eq!(candidates[0], bits);
    }
}
