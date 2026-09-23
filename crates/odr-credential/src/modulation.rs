//! The RF layer: bits into a timed event stream, and back.
//!
//! A 125 kHz card has no processor and no transmitter. It steals power from the
//! reader's field and answers by *changing how much of that field it absorbs* — the
//! reader watches its own carrier amplitude wobble. So the honest representation of a
//! card's answer is not "a byte array", it is a sequence of instants at which the
//! load changed state.
//!
//! That is exactly the shape `odr-wiegand` uses for D0/D1: a stream of
//! `(t_us, state)` pairs. Same idea, six orders of magnitude apart in voltage.
//!
//! # Why this matters for the course
//!
//! Module 0.2 asks a learner to clone a tag and have the reader accept it. If the
//! reader were handed a decoded tag ID by some back channel, "indistinguishable"
//! would be an assertion the engine makes about itself. Here the reader is handed an
//! [`EventStream`] and nothing else, so indistinguishability is structural: the
//! clone's stream is equal, event for event, to the original's. There is no detection
//! hook because real hardware does not have one.
//!
//! # The two modulations modelled
//!
//! * **ASK / OOK with Manchester coding** — EM4100 and friends. The tag shorts its
//!   coil for half a bit cell. See [`manchester_encode`] and [`ask_event_stream`].
//! * **FSK** — HID Prox. The tag divides the carrier by 8 or by 10 and the *sub-carrier
//!   frequency* carries the data. See [`fsk_event_stream`].
//!
//! Everything is in integer microseconds off an integer carrier-cycle counter, so
//! there is no accumulated floating-point drift and two runs are bit-identical.

use crate::error::{CredentialError, Result};

/// The standard low-frequency carrier: 125 kHz. One cycle is exactly 8 µs.
pub const CARRIER_125_KHZ: u32 = 125_000;

/// The usual EM4100 data rate: one bit per 64 carrier cycles (RF/64), so 32 cycles
/// per Manchester half-bit and 1953.125 bit/s at 125 kHz.
pub const RF_64: u32 = 64;

/// EM4100 tags are also made at RF/32 and RF/16. The bit layout does not change.
pub const RF_32: u32 = 32;

/// See [`RF_32`].
pub const RF_16: u32 = 16;

/// Carrier parameters for a 125 kHz link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierConfig {
    /// Carrier frequency in Hz. 125 kHz unless you are deliberately detuning.
    pub carrier_hz: u32,
}

impl CarrierConfig {
    /// A carrier at an arbitrary frequency.
    pub const fn new(carrier_hz: u32) -> Self {
        Self { carrier_hz }
    }

    /// Convert a carrier-cycle count to microseconds.
    ///
    /// Integer arithmetic against the cycle counter, never an accumulated delta, so
    /// timestamps do not drift over a 96-bit frame.
    pub const fn cycles_to_us(&self, cycles: u64) -> u64 {
        if self.carrier_hz == 0 {
            return 0;
        }
        cycles * 1_000_000 / self.carrier_hz as u64
    }
}

impl Default for CarrierConfig {
    fn default() -> Self {
        Self::new(CARRIER_125_KHZ)
    }
}

/// One instant at which the modulation state changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModulationEvent {
    /// Microseconds since the card entered the field.
    pub t_us: u64,
    /// The state the link took at `t_us`.
    ///
    /// For ASK this is "tag load applied"; for FSK it is the sub-carrier's high half.
    /// The polarity is a convention, and a convention is all a reader has — which is
    /// why a reader cannot tell a clone from an original.
    pub state: bool,
}

/// A card's answer, as the reader actually sees it.
///
/// Events are transitions only: the first event carries the initial state at `t_us`
/// 0, and there is one further event per change. A stream with two events describes a
/// card that answered with a single level change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStream {
    /// The carrier this was generated against.
    pub carrier_hz: u32,
    /// Transitions, strictly increasing in `t_us`.
    pub events: Vec<ModulationEvent>,
    /// When the stream ends. The last event's state holds until here.
    pub end_us: u64,
}

impl EventStream {
    /// An empty stream — a card that is not in the field.
    pub fn empty(cfg: &CarrierConfig) -> Self {
        Self {
            carrier_hz: cfg.carrier_hz,
            events: Vec::new(),
            end_us: 0,
        }
    }

    /// The modulation state at `t_us`, `false` before the first event.
    pub fn level_at(&self, t_us: u64) -> bool {
        match self.events.partition_point(|e| e.t_us <= t_us) {
            0 => false,
            i => self.events[i - 1].state,
        }
    }

    /// How many transitions the stream contains.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the card said nothing at all.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Sample the stream at the centre of `count` slots of `slot_us` each.
    ///
    /// This is what an ASK receiver does: it knows the bit rate, so it looks once per
    /// half-bit and does not care about edge placement.
    pub fn sample_slots(&self, slot_us: u64, count: usize) -> Vec<bool> {
        (0..count)
            .map(|i| self.level_at(i as u64 * slot_us + slot_us / 2))
            .collect()
    }

    /// Append a transition, coalescing a repeat of the current state.
    ///
    /// The very first event is always recorded, even when it is a "low", so the
    /// stream states its initial level rather than leaving a reader to assume one.
    fn push(&mut self, t_us: u64, state: bool) {
        if self.events.last().map(|e| e.state) == Some(state) {
            return;
        }
        self.events.push(ModulationEvent { t_us, state });
    }
}

// ---------------------------------------------------------------------------
// Manchester
// ---------------------------------------------------------------------------

/// Manchester-encode a bit sequence into half-bits.
///
/// Convention here, matching the Proxmark3 demodulator: a data **1** is the half-bit
/// pair `(high, low)`, a data **0** is `(low, high)`. Every bit cell therefore
/// contains exactly one mid-cell transition, which is the whole point — the reader
/// recovers the clock from the data and does not need the tag to hold a frequency.
///
/// The inverse convention (G.E. Thomas vs IEEE 802.3) exists and real decoders try
/// both. Doing so is a demodulator concern, not a format concern, so it is not
/// modelled: if you feed [`manchester_decode`] an inverted stream you get inverted
/// bits, exactly as a misconfigured reader would.
pub fn manchester_encode(bits: &[bool]) -> Vec<bool> {
    let mut out = Vec::with_capacity(bits.len() * 2);
    for &b in bits {
        out.push(b);
        out.push(!b);
    }
    out
}

/// Decode Manchester half-bits back to data bits.
///
/// Fails with [`CredentialError::ManchesterViolation`] on a `00` or `11` pair, which
/// is what a half-read looks like — the tag left the field mid-cell. That is a
/// reportable bad read, not a panic.
pub fn manchester_decode(half_bits: &[bool]) -> Result<Vec<bool>> {
    if !half_bits.len().is_multiple_of(2) {
        return Err(CredentialError::StreamTooShort {
            needed: half_bits.len() + 1,
            got: half_bits.len(),
        });
    }
    let mut out = Vec::with_capacity(half_bits.len() / 2);
    for (i, pair) in half_bits.as_chunks::<2>().0.iter().enumerate() {
        match (pair[0], pair[1]) {
            (true, false) => out.push(true),
            (false, true) => out.push(false),
            _ => return Err(CredentialError::ManchesterViolation { pair_index: i }),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ASK / OOK
// ---------------------------------------------------------------------------

/// Turn a half-bit sequence into a timed ASK event stream.
///
/// `cycles_per_half_bit` is half the RF divisor: 32 for the usual RF/64.
pub fn ask_event_stream(
    half_bits: &[bool],
    cycles_per_half_bit: u32,
    cfg: &CarrierConfig,
) -> EventStream {
    let mut stream = EventStream::empty(cfg);
    for (i, &level) in half_bits.iter().enumerate() {
        let cycles = i as u64 * u64::from(cycles_per_half_bit);
        stream.push(cfg.cycles_to_us(cycles), level);
    }
    stream.end_us = cfg.cycles_to_us(half_bits.len() as u64 * u64::from(cycles_per_half_bit));
    stream
}

/// Recover half-bits from an ASK event stream by sampling mid-slot.
///
/// `count` is how many half-bits to recover; the caller knows the frame length
/// because the format does.
pub fn ask_demodulate(stream: &EventStream, cycles_per_half_bit: u32, count: usize) -> Vec<bool> {
    let cfg = CarrierConfig::new(stream.carrier_hz);
    let slot_us = cfg.cycles_to_us(u64::from(cycles_per_half_bit));
    stream.sample_slots(slot_us.max(1), count)
}

// ---------------------------------------------------------------------------
// FSK
// ---------------------------------------------------------------------------

/// How a bit is painted onto the carrier in an FSK link.
///
/// HID Prox at 125 kHz uses two sub-carriers a long way apart — the carrier divided
/// by 8 and by 10 — and sends a whole number of sub-carrier cycles per bit. That is
/// why the two bit cells are not quite the same length: six cycles of fc/8 is 48
/// carrier cycles, five cycles of fc/10 is 50. Nominally it is "RF/50"; in truth it
/// is 48 or 50 and the demodulator counts cycles rather than trusting a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FskParams {
    /// Carrier divisor used for a data `1`.
    pub divisor_one: u32,
    /// Sub-carrier cycles sent per data `1`.
    pub cycles_one: u32,
    /// Carrier divisor used for a data `0`.
    pub divisor_zero: u32,
    /// Sub-carrier cycles sent per data `0`.
    pub cycles_zero: u32,
}

impl FskParams {
    /// HID Prox: a `1` is six cycles of fc/8, a `0` is five cycles of fc/10.
    ///
    /// The *frequencies* fc/8 and fc/10 and the nominal RF/50 bit rate are
    /// well-established. Which of the two frequencies carries a `1` is a polarity
    /// convention (HID is usually described as FSK2a, i.e. inverted); this crate
    /// fixes one and demodulates with the same one, so a round trip is exact. See
    /// the README for the caveat.
    pub const HID_PROX: Self = Self {
        divisor_one: 8,
        cycles_one: 6,
        divisor_zero: 10,
        cycles_zero: 5,
    };

    /// Carrier cycles occupied by one data bit of the given value.
    pub const fn bit_cycles(&self, bit: bool) -> u32 {
        if bit {
            self.divisor_one * self.cycles_one
        } else {
            self.divisor_zero * self.cycles_zero
        }
    }
}

/// Paint a bit sequence onto the carrier as FSK.
///
/// Each sub-carrier cycle becomes two events — high for the first half of the period,
/// low for the second. A 96-bit HID frame therefore produces a little under 1100
/// events, which is the honest count: the reader really is watching that many edges.
pub fn fsk_event_stream(bits: &[bool], params: &FskParams, cfg: &CarrierConfig) -> EventStream {
    let mut stream = EventStream::empty(cfg);
    let mut cycle = 0u64;
    for &bit in bits {
        let (divisor, count) = if bit {
            (params.divisor_one, params.cycles_one)
        } else {
            (params.divisor_zero, params.cycles_zero)
        };
        for _ in 0..count {
            let half = u64::from(divisor) / 2;
            stream.events.push(ModulationEvent {
                t_us: cfg.cycles_to_us(cycle),
                state: true,
            });
            stream.events.push(ModulationEvent {
                t_us: cfg.cycles_to_us(cycle + half),
                state: false,
            });
            cycle += u64::from(divisor);
        }
    }
    stream.end_us = cfg.cycles_to_us(cycle);
    stream
}

/// Recover bits from an FSK event stream by measuring sub-carrier periods.
///
/// Walks rising edge to rising edge, classifies each period as `divisor_one` or
/// `divisor_zero` carrier cycles, then groups runs into bits. A real demodulator
/// tolerates jitter and hunts for the bit boundary; this one does not need to,
/// because the stream it is given was generated against the same clock. What it does
/// share with the real thing is that it derives the bit rate *from the signal* rather
/// than being told.
pub fn fsk_demodulate(stream: &EventStream, params: &FskParams) -> Result<Vec<bool>> {
    let cfg = CarrierConfig::new(stream.carrier_hz);
    let one_us = cfg.cycles_to_us(u64::from(params.divisor_one));
    let zero_us = cfg.cycles_to_us(u64::from(params.divisor_zero));

    // Rising edges only: one per sub-carrier period.
    let rises: Vec<u64> = stream
        .events
        .iter()
        .filter(|e| e.state)
        .map(|e| e.t_us)
        .collect();
    if rises.len() < 2 {
        return Err(CredentialError::StreamTooShort {
            needed: 2,
            got: rises.len(),
        });
    }

    // Period after each rising edge; the final period runs to end_us.
    let mut periods = Vec::with_capacity(rises.len());
    for i in 0..rises.len() {
        let end = rises.get(i + 1).copied().unwrap_or(stream.end_us);
        periods.push(end.saturating_sub(rises[i]));
    }

    let mut bits = Vec::new();
    let mut i = 0usize;
    while i < periods.len() {
        let p = periods[i];
        let (bit, run) = if p == one_us {
            (true, params.cycles_one as usize)
        } else if p == zero_us {
            (false, params.cycles_zero as usize)
        } else {
            // An unrecognised period: the stream is not this FSK flavour.
            return Err(CredentialError::PreambleNotFound { decoder: "fsk" });
        };
        if i + run > periods.len() {
            break; // a truncated final bit; stop cleanly rather than guess
        }
        let expected = if bit { one_us } else { zero_us };
        if periods[i..i + run].iter().any(|&q| q != expected) {
            return Err(CredentialError::PreambleNotFound { decoder: "fsk" });
        }
        bits.push(bit);
        i += run;
    }
    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_cycle_is_eight_microseconds() {
        let cfg = CarrierConfig::default();
        assert_eq!(cfg.cycles_to_us(1), 8);
        assert_eq!(cfg.cycles_to_us(64), 512); // one RF/64 bit cell
    }

    #[test]
    fn manchester_round_trip() {
        let bits = vec![true, false, false, true, true, true, false];
        let halves = manchester_encode(&bits);
        assert_eq!(halves.len(), bits.len() * 2);
        assert_eq!(manchester_decode(&halves).unwrap(), bits);
    }

    #[test]
    fn manchester_rejects_a_flat_cell() {
        let mut halves = manchester_encode(&[true, false, true]);
        halves[2] = halves[3]; // flatten the middle cell
        match manchester_decode(&halves) {
            Err(CredentialError::ManchesterViolation { pair_index }) => {
                assert_eq!(pair_index, 1);
            }
            other => panic!("expected a manchester violation, got {other:?}"),
        }
    }

    #[test]
    fn ask_event_stream_round_trips() {
        let bits = vec![true, false, true, true, false, false, true, false];
        let halves = manchester_encode(&bits);
        let cfg = CarrierConfig::default();
        let stream = ask_event_stream(&halves, RF_64 / 2, &cfg);
        let recovered = ask_demodulate(&stream, RF_64 / 2, halves.len());
        assert_eq!(recovered, halves);
        assert_eq!(manchester_decode(&recovered).unwrap(), bits);
    }

    #[test]
    fn ask_stream_records_only_transitions() {
        // Two identical adjacent half-bits produce one event, not two.
        let cfg = CarrierConfig::default();
        let stream = ask_event_stream(&[true, true, false, false], 32, &cfg);
        assert_eq!(stream.len(), 2);
        assert_eq!(stream.events[0].t_us, 0);
        assert_eq!(stream.events[1].t_us, 64 * 8);
    }

    #[test]
    fn level_at_holds_between_events() {
        let cfg = CarrierConfig::default();
        let stream = ask_event_stream(&[true, false], 32, &cfg);
        assert!(stream.level_at(0));
        assert!(stream.level_at(100));
        assert!(!stream.level_at(300));
    }

    #[test]
    fn fsk_round_trips() {
        let bits = vec![false, false, false, true, true, true, false, true];
        let cfg = CarrierConfig::default();
        let stream = fsk_event_stream(&bits, &FskParams::HID_PROX, &cfg);
        assert_eq!(fsk_demodulate(&stream, &FskParams::HID_PROX).unwrap(), bits);
    }

    #[test]
    fn fsk_bit_cells_are_nearly_but_not_exactly_equal() {
        let p = FskParams::HID_PROX;
        assert_eq!(p.bit_cycles(true), 48);
        assert_eq!(p.bit_cycles(false), 50);
    }

    #[test]
    fn fsk_rejects_an_alien_stream() {
        let cfg = CarrierConfig::default();
        let stream = ask_event_stream(&manchester_encode(&[true, false]), 32, &cfg);
        assert!(fsk_demodulate(&stream, &FskParams::HID_PROX).is_err());
    }
}
