//! **Loading a capture, and everything the engine says about it.**
//!
//! The parsing is `odr-bus`'s — [`parse_ndjson`] reads the format `DESIGN.md`
//! §3 fixes — and the frame decoding is `odr-osdp`'s [`Scanner`] in its offline
//! mode. This module adds exactly two things on top, both of which a
//! file-oriented tool needs and a browser does not:
//!
//! 1. **The `bits` field.** `DESIGN.md` §3's second amendment makes `bits`
//!    optional and authoritative when present, because a 26-bit Wiegand frame
//!    and a 32-bit one are the same four bytes. `odr-bus`'s importer ignores
//!    unknown fields, which is correct and tolerant but drops `bits` on the
//!    floor, so this module reads it back off the line itself. A capture that
//!    carries it stops being ambiguous; one that does not falls back to
//!    enumerating the parity-valid readings, exactly as the amendment says.
//! 2. **What did *not* decode.** [`Monitor`](odr_detect::Monitor) keeps an
//!    undecodable event whole, which is the right thing for a detector. An
//!    analyser has to be able to say *why* — a CRC mismatch, a truncated tail,
//!    bytes before the first SOM — so every [`ScanEvent`] is kept, not just the
//!    frames.
//!
//! Nothing here re-implements a protocol. If this module disagrees with the
//! engine about what a byte means, this module is wrong.

use std::fmt;
use std::path::Path;

use odr_bus::capture::{parse_ndjson, CaptureDir, CaptureError, CaptureEvent, CaptureLine};
use odr_osdp::frame::{ScanEvent, Scanner};
use odr_osdp::{Frame, ParseError};
use odr_wiegand::BitVec;

/// Why a capture could not be loaded at all.
///
/// Distinct from "the capture loaded and contains broken frames", which is an
/// analysis result rather than an input error, and which every command reports
/// instead of refusing to run.
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Io {
        /// What was asked for.
        path: String,
        /// What the operating system said.
        error: std::io::Error,
    },
    /// A line of the file is not a capture event.
    Malformed {
        /// What was asked for.
        path: String,
        /// Which line, and what was wrong with it.
        error: CaptureError,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io { path, error } => write!(f, "{path}: {error}"),
            LoadError::Malformed { path, error } => write!(f, "{path}: {error}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// One thing the capture scanner found inside one capture event's bytes.
///
/// A bus line usually holds exactly one frame. It can hold several, and on real
/// hardware it can hold a frame plus the tail of a previous one, so all four
/// [`ScanEvent`] outcomes are kept.
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    /// A frame that parsed and whose trailer checked out.
    Frame {
        /// Offset within the event's bytes.
        offset: usize,
        /// Length in bytes.
        len: usize,
        /// The decoded frame.
        frame: Box<Frame>,
    },
    /// Bytes before the next plausible start of frame.
    Garbage {
        /// Offset within the event's bytes.
        offset: usize,
        /// How many bytes.
        len: usize,
    },
    /// Something that began with SOM and is not a frame.
    Malformed {
        /// Offset of the SOM that failed.
        offset: usize,
        /// Why it failed.
        error: ParseError,
    },
    /// The event's bytes ran out mid-frame.
    Incomplete {
        /// Offset of the partial frame.
        offset: usize,
        /// Always a [`ParseError::Truncated`].
        error: ParseError,
    },
}

impl Item {
    /// The frame, if this is one.
    pub fn frame(&self) -> Option<&Frame> {
        match self {
            Item::Frame { frame, .. } => Some(frame),
            _ => None,
        }
    }

    /// True if this item is a decoding failure rather than a frame or padding.
    pub fn is_problem(&self) -> bool {
        matches!(self, Item::Malformed { .. } | Item::Incomplete { .. })
    }
}

/// One line of a capture file, with everything the engine could say about it.
#[derive(Debug, Clone)]
pub struct Event {
    /// Which line of the file it came from, counting from 1.
    pub source_line: usize,
    /// Position in the capture after sorting by time, counting from 0.
    pub index: usize,
    /// Virtual microseconds.
    pub t_us: u64,
    /// Which physical line.
    pub line: CaptureLine,
    /// Which direction the file claims.
    pub dir: CaptureDir,
    /// The octets.
    pub bytes: Vec<u8>,
    /// The authoritative bit count, when the writer knew it and said so.
    ///
    /// `DESIGN.md` §3, second amendment. `None` means the reader has to guess,
    /// and [`Event::wiegand_readings`] then returns every parity-valid guess
    /// rather than pretending to one answer.
    pub declared_bits: Option<usize>,
    /// What the frame scanner found, for a bus line. Empty for a two-wire line.
    pub items: Vec<Item>,
}

impl Event {
    /// True if this was on an RS-485 bus.
    pub fn is_bus(&self) -> bool {
        self.line.is_bus()
    }

    /// True if this was on a Wiegand or clock-and-data pair.
    pub fn is_wire(&self) -> bool {
        matches!(self.line, CaptureLine::Wiegand | CaptureLine::ClockData)
    }

    /// The frames in this event, in offset order.
    pub fn frames(&self) -> impl Iterator<Item = &Frame> {
        self.items.iter().filter_map(|i| i.frame())
    }

    /// The bit readings of a two-wire event, best first.
    ///
    /// One reading, exactly, when the capture declared `bits`. Otherwise every
    /// reading that fits a known card format, parity-valid first — the answer
    /// `odr_wiegand::infer_formats` gives, for the reason its README gives:
    /// nothing on a D0/D1 pair says which format a frame is.
    pub fn wiegand_readings(&self) -> Vec<BitVec> {
        let event = CaptureEvent {
            t_us: self.t_us,
            line: self.line.clone(),
            dir: self.dir.clone(),
            bytes: self.bytes.clone(),
        };
        match self.declared_bits {
            Some(n) => match event.all_bits().slice(0, n) {
                Some(bits) => vec![bits],
                None => event.wiegand_candidates(),
            },
            None => event.wiegand_candidates(),
        }
    }
}

/// A whole capture file, loaded.
#[derive(Debug, Clone)]
pub struct Capture {
    /// How to name this capture in output — the path, or `-` for standard
    /// input.
    pub label: String,
    /// The events, sorted by time with a stable sort so that two events sharing
    /// a timestamp keep their file order.
    pub events: Vec<Event>,
}

impl Capture {
    /// Read a capture from a file, or from standard input when `path` is `-`.
    pub fn load(path: &str) -> Result<Capture, LoadError> {
        let text = if path == "-" {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).map_err(|error| {
                LoadError::Io {
                    path: "<stdin>".to_string(),
                    error,
                }
            })?;
            buf
        } else {
            std::fs::read_to_string(Path::new(path)).map_err(|error| LoadError::Io {
                path: path.to_string(),
                error,
            })?
        };
        let label = if path == "-" { "<stdin>" } else { path };
        Capture::parse(&text, label)
    }

    /// Parse capture text that is already in memory.
    pub fn parse(text: &str, label: &str) -> Result<Capture, LoadError> {
        let events = parse_ndjson(text).map_err(|error| LoadError::Malformed {
            path: label.to_string(),
            error,
        })?;

        // `parse_ndjson` yields one event per non-blank line, in file order, so
        // walking the same lines recovers both the file line number and the
        // `bits` field it does not model.
        let extras: Vec<(usize, Option<usize>)> = text
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, l)| (i + 1, declared_bits(l)))
            .collect();

        let mut out = Vec::with_capacity(events.len());
        for (i, e) in events.into_iter().enumerate() {
            let (source_line, declared_bits) = extras.get(i).copied().unwrap_or((i + 1, None));
            let items = if e.line.is_bus() {
                scan(&e.bytes)
            } else {
                Vec::new()
            };
            out.push(Event {
                source_line,
                index: 0,
                t_us: e.t_us,
                line: e.line,
                dir: e.dir,
                bytes: e.bytes,
                declared_bits,
                items,
            });
        }
        out.sort_by_key(|e| e.t_us);
        for (i, e) in out.iter_mut().enumerate() {
            e.index = i;
        }
        Ok(Capture {
            label: label.to_string(),
            events: out,
        })
    }

    /// True if the capture has no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// When the first event happened.
    pub fn start_us(&self) -> u64 {
        self.events.first().map(|e| e.t_us).unwrap_or(0)
    }

    /// When the last event happened.
    pub fn end_us(&self) -> u64 {
        self.events.last().map(|e| e.t_us).unwrap_or(0)
    }

    /// Every OSDP frame in the capture, with the event it came from.
    pub fn frames(&self) -> impl Iterator<Item = (&Event, &Frame)> {
        self.events
            .iter()
            .flat_map(|e| e.frames().map(move |f| (e, f)))
    }

    /// How many frames failed to decode.
    pub fn problem_count(&self) -> usize {
        self.events
            .iter()
            .flat_map(|e| e.items.iter())
            .filter(|i| i.is_problem())
            .count()
    }
}

/// Run the offline scanner over one event's bytes.
///
/// Offline and not streaming: a capture is a complete file, and one `0x53`
/// inside a payload followed by large-looking length bytes must not swallow the
/// rest of it. See `odr-osdp`'s `Scanner` docs.
fn scan(bytes: &[u8]) -> Vec<Item> {
    Scanner::offline(bytes)
        .map(|e| match e {
            ScanEvent::Frame { offset, len, frame } => Item::Frame { offset, len, frame },
            ScanEvent::Garbage { offset, len } => Item::Garbage { offset, len },
            ScanEvent::Malformed { offset, error } => Item::Malformed { offset, error },
            ScanEvent::Incomplete { offset, error } => Item::Incomplete { offset, error },
        })
        .collect()
}

/// Pull the optional `bits` field off a raw capture line.
///
/// Deliberately narrow: it looks for the key and reads the digits after it,
/// rather than parsing JSON a second time. A `bits` that is not a plain
/// non-negative integer is treated as absent, because the amendment says the
/// field is authoritative *when present*, and a field that does not parse is
/// not present in any useful sense.
fn declared_bits(line: &str) -> Option<usize> {
    let at = line.find("\"bits\"")?;
    let rest = line.get(at + "\"bits\"".len()..)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let digits: String = rest
        .trim_start_matches('"')
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BADGE: &str =
        r#"{"t_us":1000000,"line":"wiegand","dir":"wire","bytes":"0a15390e","bits":26}"#;

    #[test]
    fn a_declared_bit_count_is_believed_over_the_parity_guess() {
        let capture = Capture::parse(BADGE, "test").unwrap();
        let event = &capture.events[0];
        assert_eq!(event.declared_bits, Some(26));
        let readings = event.wiegand_readings();
        assert_eq!(readings.len(), 1, "a declared count is not a guess");
        assert_eq!(readings[0].len(), 26);
    }

    #[test]
    fn without_a_declared_bit_count_every_parity_valid_reading_is_offered() {
        let line = r#"{"t_us":1000000,"line":"wiegand","dir":"wire","bytes":"0a15390e"}"#;
        let capture = Capture::parse(line, "test").unwrap();
        assert_eq!(capture.events[0].declared_bits, None);
        assert!(!capture.events[0].wiegand_readings().is_empty());
    }

    #[test]
    fn a_bad_crc_is_kept_as_a_problem_rather_than_dropped() {
        // A POLL with its last CRC byte flipped.
        let line = r#"{"t_us":5,"line":"rs485","dir":"acu_to_pd","bytes":"530108000460ba01"}"#;
        let capture = Capture::parse(line, "test").unwrap();
        assert_eq!(capture.problem_count(), 1);
        assert!(capture.frames().next().is_none());
    }

    #[test]
    fn events_are_sorted_by_time_and_indexed_but_remember_their_file_line() {
        let text = format!(
            "{}\n{}\n",
            r#"{"t_us":2000000,"line":"wiegand","dir":"wire","bytes":"0a15390e"}"#, BADGE
        );
        let capture = Capture::parse(&text, "test").unwrap();
        assert_eq!(capture.events[0].t_us, 1_000_000);
        assert_eq!(capture.events[0].source_line, 2);
        assert_eq!(capture.events[0].index, 0);
        assert_eq!(capture.events[1].index, 1);
    }

    #[test]
    fn a_broken_line_is_a_load_error_that_names_the_line() {
        let text = "{\"line\":\"rs485\",\"dir\":\"wire\",\"bytes\":\"53\"}\n";
        let err = Capture::parse(text, "test").unwrap_err();
        assert!(err.to_string().contains("line 1"));
        assert!(err.to_string().contains("t_us"));
    }
}
