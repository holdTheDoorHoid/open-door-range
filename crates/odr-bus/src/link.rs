//! The links: a Wiegand pair, a clock-and-data pair, and an RS-485 multidrop
//! bus.
//!
//! # One model for all three: the chain
//!
//! Every link is a **chain of things hanging off it, ordered outward from the
//! controller**:
//!
//! ```text
//!   ACU ──┬──────┬──────────┬────── PD
//!         │      │          │
//!      tap A  tap B      PD at 0x02
//! ```
//!
//! Items go into the chain in the order they are attached, and each new item
//! is further from the controller than the last. An **inline tap cuts the
//! chain**, so a link is divided into *segments*: segment 0 is the controller's
//! own segment, and each inline tap adds one more. Everything about taps
//! follows from that one rule:
//!
//! * a passive or injecting tap sees exactly the traffic on its own segment;
//! * an inline tap receives on one segment and decides what reaches the other;
//! * a PD attached beyond an inline tap is invisible to the controller unless
//!   the tap relays for it.
//!
//! # What each link models
//!
//! | Link | Direction | Sharing | Collisions |
//! |---|---|---|---|
//! | [`WiegandLink`] | reader → controller only | none; D0/D1 are driven by whoever pulls them | overlapping pulses are glitches, reported by `odr-wiegand` |
//! | [`ClockDataLink`] | reader → controller only | as above | as above |
//! | [`Rs485Bus`] | both, half duplex | multidrop, many PDs on one pair | two transmitters overlapping destroys both |
//!
//! The two legacy links are unidirectional because the real interface is:
//! there is no channel from panel to reader on a D0/D1 pair. That is why an
//! LED on a Wiegand reader needs its own wire, and it is half of why OSDP
//! exists.

use alloc::string::String;
use alloc::vec::Vec;

use odr_wiegand::{CdTransition, ClockDataTiming, WiegandTiming, WireDecoder};

use crate::ids::{BusDir, ControllerId, LinkId, Micros, Origin, ReaderId, TapId};
use crate::tap::TapKind;

/// Something hanging off a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainItem {
    /// A tap.
    Tap(TapId, TapKind),
    /// A peripheral device.
    Pd(ReaderId),
}

impl ChainItem {
    /// True if this item cuts the link.
    pub fn is_inline(self) -> bool {
        matches!(self, ChainItem::Tap(_, TapKind::Inline))
    }

    /// The tap, if this is one.
    pub fn tap(self) -> Option<TapId> {
        match self {
            ChainItem::Tap(t, _) => Some(t),
            ChainItem::Pd(_) => None,
        }
    }

    /// The reader, if this is one.
    pub fn reader(self) -> Option<ReaderId> {
        match self {
            ChainItem::Pd(r) => Some(r),
            ChainItem::Tap(..) => None,
        }
    }
}

/// The chain of items on a link, and the segment arithmetic that follows from
/// it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chain {
    items: Vec<ChainItem>,
}

impl Chain {
    /// An empty chain.
    pub fn new() -> Chain {
        Chain { items: Vec::new() }
    }

    /// Every item, ordered outward from the controller.
    pub fn items(&self) -> &[ChainItem] {
        &self.items
    }

    /// Append an item at the far end.
    pub fn push(&mut self, item: ChainItem) {
        self.items.push(item);
    }

    /// Insert an item at a position, clamped to the end.
    pub fn insert(&mut self, position: usize, item: ChainItem) {
        let p = position.min(self.items.len());
        self.items.insert(p, item);
    }

    /// Insert a tap just before the trailing peripheral, which is what "put a
    /// tap on this reader's cable" means on a point-to-point link.
    pub fn insert_before_trailing_pd(&mut self, item: ChainItem) {
        match self.items.iter().rposition(|i| i.reader().is_some()) {
            Some(p) => self.items.insert(p, item),
            None => self.items.push(item),
        }
    }

    /// How many segments this chain divides the link into. Always at least 1.
    pub fn segment_count(&self) -> u16 {
        let inline = self.items.iter().filter(|i| i.is_inline()).count();
        inline.saturating_add(1).min(u16::MAX as usize) as u16
    }

    /// The segment an item sits on: the number of inline taps between it and
    /// the controller.
    ///
    /// For an inline tap this is its **controller-side** segment; its
    /// peripheral side is one higher.
    pub fn segment_of(&self, index: usize) -> u16 {
        self.items
            .iter()
            .take(index)
            .filter(|i| i.is_inline())
            .count()
            .min(u16::MAX as usize) as u16
    }

    /// Where a tap sits, or `None` if it is not on this link.
    pub fn position_of_tap(&self, tap: TapId) -> Option<usize> {
        self.items.iter().position(|i| i.tap() == Some(tap))
    }

    /// The segment a reader is attached to.
    pub fn segment_of_reader(&self, reader: ReaderId) -> Option<u16> {
        let idx = self.items.iter().position(|i| i.reader() == Some(reader))?;
        Some(self.segment_of(idx))
    }

    /// The segment a non-inline tap listens on, or for an inline tap, its
    /// controller-side segment.
    pub fn segment_of_tap(&self, tap: TapId) -> Option<u16> {
        let idx = self.position_of_tap(tap)?;
        Some(self.segment_of(idx))
    }

    /// Every reader on a given segment.
    pub fn readers_on(&self, segment: u16) -> Vec<ReaderId> {
        self.items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| item.reader().filter(|_| self.segment_of(i) == segment))
            .collect()
    }

    /// Every non-inline tap listening on a given segment.
    pub fn listeners_on(&self, segment: u16) -> Vec<TapId> {
        self.items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| match item {
                ChainItem::Tap(t, k) if !k.can_alter() && self.segment_of(i) == segment => Some(*t),
                _ => None,
            })
            .collect()
    }

    /// The inline tap whose controller-side segment is `segment`, if any.
    ///
    /// Traffic travelling away from the controller on `segment` reaches this
    /// tap, which decides whether it continues onto `segment + 1`.
    pub fn inline_outbound_from(&self, segment: u16) -> Option<TapId> {
        self.items
            .iter()
            .enumerate()
            .find_map(|(i, item)| match item {
                ChainItem::Tap(t, TapKind::Inline) if self.segment_of(i) == segment => Some(*t),
                _ => None,
            })
    }

    /// The inline tap whose peripheral-side segment is `segment`, if any.
    ///
    /// Traffic travelling towards the controller on `segment` reaches this
    /// tap, which decides whether it continues onto `segment - 1`.
    pub fn inline_inbound_from(&self, segment: u16) -> Option<TapId> {
        if segment == 0 {
            return None;
        }
        self.inline_outbound_from(segment - 1)
    }

    /// Every tap on this link, in order.
    pub fn taps(&self) -> Vec<TapId> {
        self.items.iter().filter_map(|i| i.tap()).collect()
    }

    /// Every reader on this link, in order.
    pub fn readers(&self) -> Vec<ReaderId> {
        self.items.iter().filter_map(|i| i.reader()).collect()
    }
}

// ---------------------------------------------------------------------------
// Two-wire links
// ---------------------------------------------------------------------------

/// The signal state of one segment of a Wiegand pair.
#[derive(Debug, Clone)]
pub(crate) struct WireSegState {
    pub(crate) decoder: WireDecoder,
    /// Who most recently drove this segment. Used to attribute a decoded
    /// frame; under a collision it names the most recent transmitter, which is
    /// the best a receiver could do too.
    pub(crate) last_origin: Option<Origin>,
    /// Bumped on every edge, so a stale flush event can be ignored.
    pub(crate) generation: u64,
}

/// The signal state of one segment of a clock-and-data pair.
#[derive(Debug, Clone, Default)]
pub(crate) struct CdSegState {
    pub(crate) pending: Vec<CdTransition>,
    pub(crate) generation: u64,
    /// Who most recently drove this segment.
    pub(crate) last_origin: Option<Origin>,
}

/// A Wiegand D0/D1 pair between a reader and a controller.
///
/// Unidirectional: a reader talks, a panel listens, and nothing in the
/// protocol lets the panel answer. Bits become edges through
/// `odr_wiegand::encode_transitions` and edges become bits again through
/// `odr_wiegand::WireDecoder`, so every timing anomaly that crate models — a
/// short pulse, a pulse on both lines at once, an out-of-order edge — happens
/// here for real rather than being asserted.
#[derive(Debug, Clone)]
pub struct WiegandLink {
    /// Handle.
    pub id: LinkId,
    /// A name for the UI.
    pub name: String,
    /// The controller at the near end.
    pub controller: ControllerId,
    /// The reader at the far end.
    pub reader: ReaderId,
    /// Pulse timing.
    pub timing: WiegandTiming,
    /// How long an edge takes to cross one segment. Small, but not zero, and
    /// it is what makes an inline tap's relay observable on the timeline.
    pub propagation_us: Micros,
    /// How long an inline tap takes to decide and start re-emitting.
    pub relay_delay_us: Micros,
    pub(crate) chain: Chain,
    pub(crate) segments: Vec<WireSegState>,
}

/// A clock-and-data pair between a reader and a controller.
///
/// The same shape as [`WiegandLink`] with ABA track-2 encoding on top, which
/// is curriculum drill 1.6's point: a different physical layer, an identical
/// outcome.
#[derive(Debug, Clone)]
pub struct ClockDataLink {
    /// Handle.
    pub id: LinkId,
    /// A name for the UI.
    pub name: String,
    /// The controller at the near end.
    pub controller: ControllerId,
    /// The reader at the far end.
    pub reader: ReaderId,
    /// Clock and data timing.
    pub timing: ClockDataTiming,
    /// Propagation delay for one segment.
    pub propagation_us: Micros,
    /// How long an inline tap takes to decide and start re-emitting.
    pub relay_delay_us: Micros,
    pub(crate) chain: Chain,
    pub(crate) segments: Vec<CdSegState>,
}

// ---------------------------------------------------------------------------
// RS-485
// ---------------------------------------------------------------------------

/// A transmission currently occupying a bus segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingTx {
    pub(crate) txid: u64,
    pub(crate) origin: Origin,
    pub(crate) dir: BusDir,
    pub(crate) bytes: Vec<u8>,
    pub(crate) end_us: Micros,
    pub(crate) collided: bool,
}

/// The state of one segment of an RS-485 bus.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BusSegState {
    pub(crate) active: Vec<PendingTx>,
    /// The earliest time a well-behaved transmitter may start, accounting for
    /// the bus turnaround after the last transmission finished.
    pub(crate) free_at_us: Micros,
    pub(crate) next_txid: u64,
}

/// RS-485 line parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rs485Timing {
    /// Line rate. OSDP's usual values are 9600, 19200, 38400, 57600, 115200
    /// and 230400.
    pub baud: u32,
    /// Bits on the wire per byte, including start and stop. 8N1 is 10.
    pub bits_per_byte: u32,
    /// How long a device waits after the line goes idle before driving it.
    ///
    /// This is the half-duplex turnaround, and it is real: it is why an OSDP
    /// bus at 9600 baud cannot poll as fast as the frame length alone
    /// suggests, and it is the gap an injecting attacker has to hit.
    pub turnaround_us: Micros,
    /// Propagation delay across one segment.
    pub propagation_us: Micros,
}

impl Default for Rs485Timing {
    fn default() -> Rs485Timing {
        Rs485Timing {
            baud: 9600,
            bits_per_byte: 10,
            turnaround_us: 1_000,
            propagation_us: 10,
        }
    }
}

impl Rs485Timing {
    /// Line parameters at a given baud rate, otherwise default.
    pub fn at_baud(baud: u32) -> Rs485Timing {
        Rs485Timing {
            baud: baud.max(1),
            ..Rs485Timing::default()
        }
    }

    /// How long `len` bytes take to clock out.
    ///
    /// Saturating and integer-only, so it is identical on every machine.
    pub fn bytes_duration_us(&self, len: usize) -> Micros {
        let baud = self.baud.max(1) as u64;
        let bits = (len as u64).saturating_mul(self.bits_per_byte.max(1) as u64);
        bits.saturating_mul(1_000_000) / baud
    }
}

/// An RS-485 multidrop bus: one controller, several peripherals, one pair,
/// half duplex.
///
/// Addressing is by the OSDP address byte, not by position, so two PDs on one
/// pair are distinguished only by a number they were configured with — and
/// `CMD_COMSET` changes that number, unauthenticated, over the same bus.
#[derive(Debug, Clone)]
pub struct Rs485Bus {
    /// Handle.
    pub id: LinkId,
    /// A name for the UI.
    pub name: String,
    /// The controller.
    pub controller: ControllerId,
    /// Line parameters.
    pub timing: Rs485Timing,
    pub(crate) chain: Chain,
    pub(crate) segments: Vec<BusSegState>,
}

// ---------------------------------------------------------------------------
// The link enum
// ---------------------------------------------------------------------------

/// A link between a controller and one or more readers.
#[derive(Debug, Clone)]
pub enum Link {
    /// A Wiegand D0/D1 pair.
    Wiegand(WiegandLink),
    /// A clock-and-data pair.
    ClockData(ClockDataLink),
    /// An RS-485 multidrop bus.
    Rs485(Rs485Bus),
}

impl Link {
    /// Handle.
    pub fn id(&self) -> LinkId {
        match self {
            Link::Wiegand(l) => l.id,
            Link::ClockData(l) => l.id,
            Link::Rs485(l) => l.id,
        }
    }

    /// Name.
    pub fn name(&self) -> &str {
        match self {
            Link::Wiegand(l) => &l.name,
            Link::ClockData(l) => &l.name,
            Link::Rs485(l) => &l.name,
        }
    }

    /// A short kind name, as used in the capture format's `line` field for the
    /// two that appear there.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Link::Wiegand(_) => "wiegand",
            Link::ClockData(_) => "clock_data",
            Link::Rs485(_) => "rs485",
        }
    }

    /// The controller at the near end.
    pub fn controller(&self) -> ControllerId {
        match self {
            Link::Wiegand(l) => l.controller,
            Link::ClockData(l) => l.controller,
            Link::Rs485(l) => l.controller,
        }
    }

    /// The chain of taps and peripherals.
    pub fn chain(&self) -> &Chain {
        match self {
            Link::Wiegand(l) => &l.chain,
            Link::ClockData(l) => &l.chain,
            Link::Rs485(l) => &l.chain,
        }
    }

    /// How many segments the link is divided into.
    pub fn segment_count(&self) -> u16 {
        self.chain().segment_count()
    }

    pub(crate) fn chain_mut(&mut self) -> &mut Chain {
        match self {
            Link::Wiegand(l) => &mut l.chain,
            Link::ClockData(l) => &mut l.chain,
            Link::Rs485(l) => &mut l.chain,
        }
    }

    /// Rebuild per-segment state after the chain changed.
    ///
    /// Cutting a live link resets the electrical state of the segments either
    /// side, which is honest: clipping an implant into a running cable really
    /// does disturb it.
    pub(crate) fn resync_segments(&mut self) {
        let want = self.segment_count() as usize;
        match self {
            Link::Wiegand(l) => {
                let timing = l.timing;
                l.segments = (0..want)
                    .map(|_| WireSegState {
                        decoder: WireDecoder::new(timing),
                        last_origin: None,
                        generation: 0,
                    })
                    .collect();
            }
            Link::ClockData(l) => {
                l.segments = (0..want).map(|_| CdSegState::default()).collect();
            }
            Link::Rs485(l) => {
                l.segments.resize_with(want, BusSegState::default);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tap(n: u32, k: TapKind) -> ChainItem {
        ChainItem::Tap(TapId(n), k)
    }

    #[test]
    fn a_chain_with_no_inline_taps_is_one_segment() {
        let mut c = Chain::new();
        c.push(tap(0, TapKind::Passive));
        c.push(tap(1, TapKind::Injecting));
        c.push(ChainItem::Pd(ReaderId(0)));
        assert_eq!(c.segment_count(), 1);
        assert_eq!(c.segment_of_reader(ReaderId(0)), Some(0));
        assert_eq!(c.listeners_on(0), alloc::vec![TapId(0), TapId(1)]);
    }

    #[test]
    fn an_inline_tap_cuts_the_chain_in_two() {
        let mut c = Chain::new();
        c.push(tap(0, TapKind::Inline));
        c.push(ChainItem::Pd(ReaderId(0)));
        assert_eq!(c.segment_count(), 2);
        assert_eq!(c.segment_of_reader(ReaderId(0)), Some(1));
        assert_eq!(c.inline_outbound_from(0), Some(TapId(0)));
        assert_eq!(c.inline_inbound_from(1), Some(TapId(0)));
        assert_eq!(c.inline_inbound_from(0), None);
    }

    #[test]
    fn a_pd_in_front_of_the_cut_stays_with_the_controller() {
        let mut c = Chain::new();
        c.push(ChainItem::Pd(ReaderId(9)));
        c.push(tap(0, TapKind::Inline));
        c.push(ChainItem::Pd(ReaderId(0)));
        assert_eq!(c.segment_of_reader(ReaderId(9)), Some(0));
        assert_eq!(c.segment_of_reader(ReaderId(0)), Some(1));
        assert_eq!(c.readers_on(0), alloc::vec![ReaderId(9)]);
        assert_eq!(c.readers_on(1), alloc::vec![ReaderId(0)]);
    }

    #[test]
    fn two_inline_taps_make_three_segments() {
        let mut c = Chain::new();
        c.push(tap(0, TapKind::Inline));
        c.push(tap(1, TapKind::Passive));
        c.push(tap(2, TapKind::Inline));
        c.push(ChainItem::Pd(ReaderId(0)));
        assert_eq!(c.segment_count(), 3);
        assert_eq!(c.segment_of_tap(TapId(1)), Some(1));
        assert_eq!(c.segment_of_reader(ReaderId(0)), Some(2));
        assert_eq!(c.inline_outbound_from(1), Some(TapId(2)));
    }

    #[test]
    fn a_tap_lands_in_front_of_the_trailing_peripheral() {
        let mut c = Chain::new();
        c.push(ChainItem::Pd(ReaderId(0)));
        c.insert_before_trailing_pd(tap(0, TapKind::Inline));
        assert_eq!(c.items()[0], tap(0, TapKind::Inline));
        assert_eq!(c.items()[1], ChainItem::Pd(ReaderId(0)));
    }

    #[test]
    fn byte_timing_is_integer_and_stable() {
        let t = Rs485Timing::at_baud(9600);
        assert_eq!(t.bytes_duration_us(1), 1041);
        assert_eq!(t.bytes_duration_us(8), 8333);
        assert_eq!(Rs485Timing::at_baud(115_200).bytes_duration_us(8), 694);
    }
}
