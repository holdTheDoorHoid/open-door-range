//! The D0/D1 physical layer.
//!
//! Wiegand's wire protocol is about as simple as a digital protocol gets, and
//! its simplicity is exactly why it is indefensible.
//!
//! Two signal lines run from the reader to the panel: **D0** and **D1**. Both
//! are open-collector outputs pulled high by the panel, so both sit at logic
//! high when nothing is happening. To send a zero bit the reader pulls D0 low
//! for a short pulse and lets it go; to send a one bit it pulses D1 instead.
//! The panel counts pulses. When the pulses stop for long enough, the frame is
//! over and its length tells the panel which format to apply.
//!
//! That is the whole protocol. There is no clock, no framing, no addressing, no
//! error correction beyond the card format's own parity, no acknowledgement,
//! and above all **no authentication of the reader**. Anything that can pull
//! two wires low can present any credential. That is the point Track 1 of the
//! range exists to make, and this module is the machinery that makes it
//! observable rather than merely asserted.
//!
//! # Timing
//!
//! There is no single normative standard; the de-facto figures come from HID's
//! and Sensor Engineering's reader specifications and are widely quoted as:
//!
//! * pulse width 20–100 µs, typically **50 µs**
//! * pulse period (start of one pulse to the start of the next) 200 µs – 20 ms,
//!   typically **1–2 ms**
//!
//! Real readers vary within and sometimes outside that envelope, so every
//! figure in [`WiegandTiming`] is a parameter. Seeing what a panel does when a
//! reader — or an implant — drives the line out of spec is a legitimate thing
//! to want to try.
//!
//! # Determinism
//!
//! Time is a `u64` of virtual microseconds supplied by the caller. Nothing here
//! reads a clock. The same bits and the same timing always produce byte-for-byte
//! the same transition list, on any machine.

use crate::bits::BitVec;
use alloc::vec::Vec;
use core::fmt;

/// Which of the two data lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Line {
    /// Pulsed to send a zero bit.
    D0,
    /// Pulsed to send a one bit.
    D1,
}

impl Line {
    /// The line that carries `bit`.
    pub fn for_bit(bit: bool) -> Line {
        if bit {
            Line::D1
        } else {
            Line::D0
        }
    }

    /// The bit value a pulse on this line means.
    pub fn bit_value(self) -> bool {
        matches!(self, Line::D1)
    }

    /// The other line.
    pub fn other(self) -> Line {
        match self {
            Line::D0 => Line::D1,
            Line::D1 => Line::D0,
        }
    }

    /// `"D0"` or `"D1"`.
    pub fn name(self) -> &'static str {
        match self {
            Line::D0 => "D0",
            Line::D1 => "D1",
        }
    }
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Logic level on a line. Idle is [`Level::High`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Level {
    /// Line released; the panel's pull-up wins. This is idle.
    High,
    /// Line pulled down by the reader. This is a pulse.
    Low,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Level::High => "high",
            Level::Low => "low",
        })
    }
}

/// One edge on one line at one virtual microsecond.
///
/// This is the unit of the capture format described in `DESIGN.md` §3 and the
/// unit an implant or a logic analyser actually sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Transition {
    /// Virtual microseconds since the start of the simulation.
    pub t_us: u64,
    /// Which line moved.
    pub line: Line,
    /// The level it moved *to*.
    pub level: Level,
}

impl fmt::Display for Transition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:>10} us  {} -> {}", self.t_us, self.line, self.level)
    }
}

/// Timing parameters for one reader, in virtual microseconds.
///
/// The `pulse_width_us` / `pulse_period_us` pair drives the *encoder*; the
/// `min_`/`max_` pair and `interframe_gap_us` drive the *decoder*'s tolerance.
/// Keeping them in one struct means a scenario can deliberately give a reader
/// and a panel different opinions about what is acceptable, which is how real
/// interoperability failures happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WiegandTiming {
    /// How long a pulse is held low when transmitting. Typical 50 µs.
    pub pulse_width_us: u64,
    /// Start of one pulse to the start of the next. Typical 1–2 ms.
    pub pulse_period_us: u64,
    /// Shortest pulse a decoder will accept without complaining. Typical 20 µs.
    pub min_pulse_us: u64,
    /// Longest pulse a decoder will accept without complaining. Typical 100 µs.
    pub max_pulse_us: u64,
    /// Shortest gap between consecutive pulse starts a decoder accepts.
    /// Typical 200 µs.
    pub min_period_us: u64,
    /// Longest gap between consecutive pulse starts that still counts as being
    /// inside the same frame. A larger gap ends the frame. Typical 20 ms.
    pub interframe_gap_us: u64,
}

impl Default for WiegandTiming {
    /// The commonly quoted nominal reader: 50 µs pulses, 2 ms apart, frames
    /// separated by more than 20 ms.
    fn default() -> Self {
        WiegandTiming {
            pulse_width_us: 50,
            pulse_period_us: 2_000,
            min_pulse_us: 20,
            max_pulse_us: 100,
            min_period_us: 200,
            interframe_gap_us: 20_000,
        }
    }
}

impl WiegandTiming {
    /// A fast reader: 40 µs pulses 1 ms apart. Halves the time a brute-force
    /// sweep takes, which is worth being able to demonstrate.
    pub fn fast() -> Self {
        WiegandTiming {
            pulse_width_us: 40,
            pulse_period_us: 1_000,
            ..Self::default()
        }
    }

    /// How long a frame of `bits` bits occupies on the wire, from the start of
    /// the first pulse to the end of the last.
    pub fn frame_duration_us(&self, bits: usize) -> u64 {
        if bits == 0 {
            return 0;
        }
        (bits as u64 - 1) * self.pulse_period_us + self.pulse_width_us
    }
}

/// Encode a frame as a list of edges.
///
/// Bit *i* is a pulse starting at `start_us + i * pulse_period_us` on D0 (zero)
/// or D1 (one), released `pulse_width_us` later. The returned list is sorted by
/// time and contains exactly `2 * bits.len()` entries.
///
/// ```
/// use odr_wiegand::{BitVec, WiegandTiming, encode_transitions, Level, Line};
///
/// let bits = BitVec::from_bin_str("101").unwrap();
/// let edges = encode_transitions(&bits, &WiegandTiming::default(), 0);
/// assert_eq!(edges.len(), 6);
/// assert_eq!(edges[0].line, Line::D1);
/// assert_eq!(edges[0].level, Level::Low);
/// assert_eq!(edges[1].t_us, 50);          // released after the pulse width
/// assert_eq!(edges[2].line, Line::D0);    // the zero bit
/// assert_eq!(edges[2].t_us, 2_000);       // one period later
/// ```
pub fn encode_transitions(bits: &BitVec, timing: &WiegandTiming, start_us: u64) -> Vec<Transition> {
    let mut out = Vec::with_capacity(bits.len() * 2);
    for (i, bit) in bits.iter().enumerate() {
        let line = Line::for_bit(bit);
        let t = start_us + i as u64 * timing.pulse_period_us;
        out.push(Transition {
            t_us: t,
            line,
            level: Level::Low,
        });
        out.push(Transition {
            t_us: t + timing.pulse_width_us,
            line,
            level: Level::High,
        });
    }
    out
}

/// Something wrong with the electrical picture.
///
/// These are the things a panel's firmware silently swallows and a person
/// staring at a door that will not open never gets told about. Surfacing them
/// is half the value of a simulated wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingAnomaly {
    /// A pulse shorter than `min_pulse_us`. The bit is still decoded — a real
    /// panel with a faster input filter would have taken it too — but it is
    /// flagged.
    PulseTooShort {
        /// When the pulse started.
        t_us: u64,
        /// Which line.
        line: Line,
        /// Measured width.
        width_us: u64,
    },
    /// A pulse longer than `max_pulse_us`.
    PulseTooLong {
        /// When the pulse started.
        t_us: u64,
        /// Which line.
        line: Line,
        /// Measured width.
        width_us: u64,
    },
    /// Both D0 and D1 were low at the same moment.
    ///
    /// No conforming reader does this. It means a collision between two
    /// transmitters — the reader and something else on the same pair, which is
    /// precisely what a badly timed inline implant looks like — or a shorted
    /// cable. Neither pulse produces a bit.
    SimultaneousPulse {
        /// When the overlap began.
        t_us: u64,
    },
    /// Two pulses closer together than `min_period_us`.
    PeriodTooShort {
        /// Start of the second pulse.
        t_us: u64,
        /// Measured start-to-start gap.
        period_us: u64,
    },
    /// A line went high when it was already high.
    UnexpectedRelease {
        /// When.
        t_us: u64,
        /// Which line.
        line: Line,
    },
    /// A line was pulled low when it was already low.
    DuplicateAssert {
        /// When.
        t_us: u64,
        /// Which line.
        line: Line,
    },
    /// A transition arrived with a timestamp earlier than the previous one.
    ///
    /// The decoder processes it anyway, using the earlier timestamp, so a
    /// mis-sorted capture degrades rather than exploding.
    OutOfOrder {
        /// The offending timestamp.
        t_us: u64,
        /// The timestamp already seen.
        previous_us: u64,
    },
}

impl fmt::Display for TimingAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimingAnomaly::PulseTooShort {
                t_us,
                line,
                width_us,
            } => {
                write!(f, "{t_us} us: {line} pulse only {width_us} us")
            }
            TimingAnomaly::PulseTooLong {
                t_us,
                line,
                width_us,
            } => {
                write!(f, "{t_us} us: {line} pulse held {width_us} us")
            }
            TimingAnomaly::SimultaneousPulse { t_us } => {
                write!(f, "{t_us} us: D0 and D1 low together")
            }
            TimingAnomaly::PeriodTooShort { t_us, period_us } => {
                write!(f, "{t_us} us: pulses only {period_us} us apart")
            }
            TimingAnomaly::UnexpectedRelease { t_us, line } => {
                write!(f, "{t_us} us: {line} released but was not asserted")
            }
            TimingAnomaly::DuplicateAssert { t_us, line } => {
                write!(f, "{t_us} us: {line} asserted but was already low")
            }
            TimingAnomaly::OutOfOrder { t_us, previous_us } => {
                write!(f, "{t_us} us: arrived after {previous_us} us")
            }
        }
    }
}

/// A complete frame lifted off the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireFrame {
    /// Start of the first pulse.
    pub start_us: u64,
    /// End of the last pulse.
    pub end_us: u64,
    /// The bits, in transmission order.
    pub bits: BitVec,
}

/// What the decoder emits as it consumes edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireEvent {
    /// A bit was recovered. Emitted when the pulse is *released*, because that
    /// is the moment its width is known.
    Bit {
        /// Start of the pulse that carried it.
        t_us: u64,
        /// The bit value.
        value: bool,
    },
    /// The inter-frame gap elapsed (or [`WireDecoder::flush`] was called) and a
    /// frame is complete.
    Frame(WireFrame),
    /// Something was wrong electrically.
    Anomaly(TimingAnomaly),
}

/// A streaming D0/D1 decoder.
///
/// Feed it [`Transition`]s in time order; it returns the events each one
/// produced. It never panics and never gives up: after a glitch it keeps
/// counting pulses, so a capture that starts mid-frame or contains a burst of
/// noise still yields every frame after the damage. That resynchronisation
/// behaviour is what a real panel does too, and it is why injecting a frame
/// into a live wire works so well.
///
/// ```
/// use odr_wiegand::{BitVec, WiegandTiming, WireDecoder, encode_transitions};
///
/// let timing = WiegandTiming::default();
/// let bits = BitVec::from_bin_str("10110001").unwrap();
/// let mut dec = WireDecoder::new(timing);
/// for t in encode_transitions(&bits, &timing, 1_000) {
///     dec.push(t);
/// }
/// let frames = dec.flush();
/// assert_eq!(frames.len(), 1);
/// assert_eq!(frames[0].bits, bits);
/// ```
#[derive(Clone, Debug)]
pub struct WireDecoder {
    timing: WiegandTiming,
    /// `Some(start_us)` while the line is held low.
    d0_low_since: Option<u64>,
    d1_low_since: Option<u64>,
    /// Set when a pulse overlapped the other line, so its bit is discarded.
    d0_glitched: bool,
    d1_glitched: bool,
    last_seen_us: Option<u64>,
    last_pulse_start_us: Option<u64>,
    frame_start_us: Option<u64>,
    frame_end_us: u64,
    frame: BitVec,
}

impl WireDecoder {
    /// A decoder with the given tolerances.
    pub fn new(timing: WiegandTiming) -> Self {
        WireDecoder {
            timing,
            d0_low_since: None,
            d1_low_since: None,
            d0_glitched: false,
            d1_glitched: false,
            last_seen_us: None,
            last_pulse_start_us: None,
            frame_start_us: None,
            frame_end_us: 0,
            frame: BitVec::new(),
        }
    }

    /// The timing tolerances in force.
    pub fn timing(&self) -> &WiegandTiming {
        &self.timing
    }

    /// Bits accumulated in the frame currently being received.
    pub fn pending_bits(&self) -> &BitVec {
        &self.frame
    }

    fn low_since(&self, line: Line) -> Option<u64> {
        match line {
            Line::D0 => self.d0_low_since,
            Line::D1 => self.d1_low_since,
        }
    }

    fn set_low_since(&mut self, line: Line, v: Option<u64>) {
        match line {
            Line::D0 => self.d0_low_since = v,
            Line::D1 => self.d1_low_since = v,
        }
    }

    fn glitched(&self, line: Line) -> bool {
        match line {
            Line::D0 => self.d0_glitched,
            Line::D1 => self.d1_glitched,
        }
    }

    fn set_glitched(&mut self, line: Line, v: bool) {
        match line {
            Line::D0 => self.d0_glitched = v,
            Line::D1 => self.d1_glitched = v,
        }
    }

    fn take_frame(&mut self) -> Option<WireFrame> {
        if self.frame.is_empty() {
            self.frame_start_us = None;
            return None;
        }
        let frame = WireFrame {
            start_us: self.frame_start_us.unwrap_or(0),
            end_us: self.frame_end_us,
            bits: core::mem::take(&mut self.frame),
        };
        self.frame_start_us = None;
        Some(frame)
    }

    /// Consume one edge and return everything it caused.
    ///
    /// The returned vector is usually empty or one element; it can hold two
    /// (a frame boundary followed by the first bit of the next frame) or more
    /// when anomalies pile up.
    pub fn push(&mut self, tr: Transition) -> Vec<WireEvent> {
        let mut out = Vec::new();

        let t = match self.last_seen_us {
            Some(prev) if tr.t_us < prev => {
                out.push(WireEvent::Anomaly(TimingAnomaly::OutOfOrder {
                    t_us: tr.t_us,
                    previous_us: prev,
                }));
                tr.t_us
            }
            _ => tr.t_us,
        };
        self.last_seen_us = Some(self.last_seen_us.map_or(t, |p| p.max(t)));

        match tr.level {
            Level::Low => self.assert_line(t, tr.line, &mut out),
            Level::High => self.release_line(t, tr.line, &mut out),
        }
        out
    }

    fn assert_line(&mut self, t: u64, line: Line, out: &mut Vec<WireEvent>) {
        if self.low_since(line).is_some() {
            out.push(WireEvent::Anomaly(TimingAnomaly::DuplicateAssert {
                t_us: t,
                line,
            }));
            return;
        }

        // A long enough silence since the previous pulse ends the frame before
        // this one begins.
        if let Some(prev) = self.last_pulse_start_us {
            let gap = t.saturating_sub(prev);
            if gap > self.timing.interframe_gap_us {
                if let Some(frame) = self.take_frame() {
                    out.push(WireEvent::Frame(frame));
                }
                self.last_pulse_start_us = None;
            } else if gap < self.timing.min_period_us {
                out.push(WireEvent::Anomaly(TimingAnomaly::PeriodTooShort {
                    t_us: t,
                    period_us: gap,
                }));
            }
        }

        self.set_low_since(line, Some(t));
        self.set_glitched(line, false);

        if self.low_since(line.other()).is_some() {
            // Both lines low: a collision. Neither pulse yields a bit.
            out.push(WireEvent::Anomaly(TimingAnomaly::SimultaneousPulse {
                t_us: t,
            }));
            self.set_glitched(line, true);
            self.set_glitched(line.other(), true);
        }
    }

    fn release_line(&mut self, t: u64, line: Line, out: &mut Vec<WireEvent>) {
        let Some(since) = self.low_since(line) else {
            out.push(WireEvent::Anomaly(TimingAnomaly::UnexpectedRelease {
                t_us: t,
                line,
            }));
            return;
        };
        self.set_low_since(line, None);

        let width = t.saturating_sub(since);
        if width < self.timing.min_pulse_us {
            out.push(WireEvent::Anomaly(TimingAnomaly::PulseTooShort {
                t_us: since,
                line,
                width_us: width,
            }));
        } else if width > self.timing.max_pulse_us {
            out.push(WireEvent::Anomaly(TimingAnomaly::PulseTooLong {
                t_us: since,
                line,
                width_us: width,
            }));
        }

        if self.glitched(line) {
            self.set_glitched(line, false);
            return;
        }

        if self.frame.is_empty() {
            self.frame_start_us = Some(since);
        }
        self.frame.push(line.bit_value());
        self.frame_end_us = t;
        self.last_pulse_start_us = Some(since);
        out.push(WireEvent::Bit {
            t_us: since,
            value: line.bit_value(),
        });
    }

    /// End any frame in progress and return it.
    ///
    /// Call this after the last transition of a capture, or when virtual time
    /// has advanced past the inter-frame gap with no further edges.
    pub fn flush(&mut self) -> Vec<WireFrame> {
        self.take_frame().into_iter().collect()
    }
}

/// Everything recovered from a list of edges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireCapture {
    /// Complete frames, in order.
    pub frames: Vec<WireFrame>,
    /// Every anomaly seen, in order.
    pub anomalies: Vec<TimingAnomaly>,
}

impl WireCapture {
    /// True when nothing electrically odd happened.
    pub fn is_clean(&self) -> bool {
        self.anomalies.is_empty()
    }
}

/// Decode a whole list of edges in one go.
///
/// Convenience over [`WireDecoder`] for the common case of a finished capture.
/// Transitions are expected in time order; out-of-order ones are reported as
/// [`TimingAnomaly::OutOfOrder`] rather than rejected.
pub fn decode_transitions(transitions: &[Transition], timing: &WiegandTiming) -> WireCapture {
    let mut dec = WireDecoder::new(*timing);
    let mut cap = WireCapture::default();
    for tr in transitions {
        for ev in dec.push(*tr) {
            match ev {
                WireEvent::Frame(f) => cap.frames.push(f),
                WireEvent::Anomaly(a) => cap.anomalies.push(a),
                WireEvent::Bit { .. } => {}
            }
        }
    }
    cap.frames.extend(dec.flush());
    cap
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(s: &str) -> BitVec {
        BitVec::from_bin_str(s).unwrap()
    }

    #[test]
    fn round_trip_recovers_the_exact_bits() {
        let timing = WiegandTiming::default();
        let original = bits("10111101100010001110101110");
        let edges = encode_transitions(&original, &timing, 5_000);
        let cap = decode_transitions(&edges, &timing);
        assert!(cap.is_clean(), "{:?}", cap.anomalies);
        assert_eq!(cap.frames.len(), 1);
        assert_eq!(cap.frames[0].bits, original);
        assert_eq!(cap.frames[0].start_us, 5_000);
    }

    #[test]
    fn two_frames_separated_by_a_gap() {
        let timing = WiegandTiming::default();
        let a = bits("1010");
        let b = bits("0011");
        let mut edges = encode_transitions(&a, &timing, 0);
        let second_start = timing.frame_duration_us(a.len()) + timing.interframe_gap_us + 1_000;
        edges.extend(encode_transitions(&b, &timing, second_start));
        let cap = decode_transitions(&edges, &timing);
        assert!(cap.is_clean(), "{:?}", cap.anomalies);
        assert_eq!(cap.frames.len(), 2);
        assert_eq!(cap.frames[0].bits, a);
        assert_eq!(cap.frames[1].bits, b);
    }

    #[test]
    fn simultaneous_pulse_is_flagged_and_drops_both_bits() {
        let timing = WiegandTiming::default();
        let edges = [
            Transition {
                t_us: 0,
                line: Line::D0,
                level: Level::Low,
            },
            Transition {
                t_us: 10,
                line: Line::D1,
                level: Level::Low,
            },
            Transition {
                t_us: 50,
                line: Line::D0,
                level: Level::High,
            },
            Transition {
                t_us: 60,
                line: Line::D1,
                level: Level::High,
            },
            // A clean bit afterwards: the decoder must have resynchronised.
            Transition {
                t_us: 2_000,
                line: Line::D1,
                level: Level::Low,
            },
            Transition {
                t_us: 2_050,
                line: Line::D1,
                level: Level::High,
            },
        ];
        let cap = decode_transitions(&edges, &timing);
        assert!(cap
            .anomalies
            .iter()
            .any(|a| matches!(a, TimingAnomaly::SimultaneousPulse { .. })));
        assert_eq!(cap.frames.len(), 1);
        assert_eq!(
            cap.frames[0].bits,
            bits("1"),
            "only the clean pulse became a bit"
        );
    }

    #[test]
    fn short_and_long_pulses_are_flagged_but_still_decoded() {
        let timing = WiegandTiming::default();
        let edges = [
            Transition {
                t_us: 0,
                line: Line::D1,
                level: Level::Low,
            },
            Transition {
                t_us: 5,
                line: Line::D1,
                level: Level::High,
            }, // 5 us: too short
            Transition {
                t_us: 2_000,
                line: Line::D0,
                level: Level::Low,
            },
            Transition {
                t_us: 2_500,
                line: Line::D0,
                level: Level::High,
            }, // 500 us: too long
        ];
        let cap = decode_transitions(&edges, &timing);
        assert_eq!(cap.frames.len(), 1);
        assert_eq!(cap.frames[0].bits, bits("10"));
        assert!(cap
            .anomalies
            .iter()
            .any(|a| matches!(a, TimingAnomaly::PulseTooShort { width_us: 5, .. })));
        assert!(cap
            .anomalies
            .iter()
            .any(|a| matches!(a, TimingAnomaly::PulseTooLong { width_us: 500, .. })));
    }

    #[test]
    fn pulses_too_close_together_are_flagged() {
        let timing = WiegandTiming::default();
        let edges = [
            Transition {
                t_us: 0,
                line: Line::D1,
                level: Level::Low,
            },
            Transition {
                t_us: 50,
                line: Line::D1,
                level: Level::High,
            },
            Transition {
                t_us: 100,
                line: Line::D0,
                level: Level::Low,
            },
            Transition {
                t_us: 150,
                line: Line::D0,
                level: Level::High,
            },
        ];
        let cap = decode_transitions(&edges, &timing);
        assert!(cap
            .anomalies
            .iter()
            .any(|a| matches!(a, TimingAnomaly::PeriodTooShort { period_us: 100, .. })));
        assert_eq!(cap.frames[0].bits, bits("10"));
    }

    #[test]
    fn stray_edges_do_not_panic() {
        let timing = WiegandTiming::default();
        let edges = [
            Transition {
                t_us: 0,
                line: Line::D0,
                level: Level::High,
            }, // release, never asserted
            Transition {
                t_us: 10,
                line: Line::D1,
                level: Level::Low,
            },
            Transition {
                t_us: 20,
                line: Line::D1,
                level: Level::Low,
            }, // duplicate assert
            Transition {
                t_us: 60,
                line: Line::D1,
                level: Level::High,
            },
            Transition {
                t_us: 30,
                line: Line::D0,
                level: Level::Low,
            }, // out of order
            Transition {
                t_us: 80,
                line: Line::D0,
                level: Level::High,
            },
        ];
        let cap = decode_transitions(&edges, &timing);
        assert!(cap
            .anomalies
            .iter()
            .any(|a| matches!(a, TimingAnomaly::UnexpectedRelease { .. })));
        assert!(cap
            .anomalies
            .iter()
            .any(|a| matches!(a, TimingAnomaly::DuplicateAssert { .. })));
        assert!(cap
            .anomalies
            .iter()
            .any(|a| matches!(a, TimingAnomaly::OutOfOrder { .. })));
        assert_eq!(cap.frames.len(), 1);
    }

    #[test]
    fn frame_duration_matches_the_edges() {
        let timing = WiegandTiming::default();
        let b = bits("10101010101010101010101010");
        let edges = encode_transitions(&b, &timing, 0);
        let last = edges.last().unwrap();
        assert_eq!(last.t_us, timing.frame_duration_us(b.len()));
    }
}
