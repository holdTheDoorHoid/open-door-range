//! The event queue and the internal event type.
//!
//! The engine is a plain discrete-event simulator: a priority queue of
//! `(t_us, seq)` and a loop that pops the earliest. Nothing sleeps, nothing
//! polls a clock, and the caller decides how far time advances.
//!
//! **Ties are broken by insertion order, never by anything else.** Two events
//! scheduled for the same microsecond run in the order they were scheduled.
//! That, plus a seeded PRNG for every nonce, is what makes a scenario produce
//! byte-identical output on every machine (`DESIGN.md` §3). There is no map
//! iteration anywhere in the engine for the same reason.

use alloc::boxed::Box;
use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::{Ordering, Reverse};

use odr_osdp::Frame;
use odr_wiegand::{BitVec, CdTransition, Transition};

use crate::credential::Presentation;
use crate::ids::{BusDir, ControllerId, DoorId, LinkId, Micros, Origin, ReaderId, TapId};

/// Something the engine has to do at a particular virtual microsecond.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SimEvent {
    /// A token is held up to a reader.
    Present {
        reader: ReaderId,
        presentation: Box<Presentation>,
    },
    /// A token attached to a reader as a [`crate::CredentialSource`] is held
    /// up to it; the reader asks the token for bits when this fires.
    PresentAttached { reader: ReaderId },
    /// A reader has finished reading and now drives the wire or queues a
    /// `REPLY_RAW`.
    ReaderEmit { reader: ReaderId, token: u64 },
    /// One D0/D1 edge arrives at the receiving end of a wire segment.
    WiegandEdge {
        link: LinkId,
        segment: u16,
        tr: Transition,
    },
    /// One CLOCK/DATA edge arrives at the receiving end of a wire segment.
    CdEdge {
        link: LinkId,
        segment: u16,
        tr: CdTransition,
    },
    /// The inter-frame gap on a Wiegand segment has elapsed, so the pulses
    /// buffered in its decoder are a complete frame. `generation` makes the
    /// event cancellable: a later edge bumps the segment's generation and this
    /// firing is then ignored.
    WireFlush {
        link: LinkId,
        segment: u16,
        generation: u64,
    },
    /// The inter-frame gap on a clock-and-data segment has elapsed, so
    /// whatever is buffered is a complete frame. `generation` makes the event
    /// cancellable: a later edge bumps the segment's generation and this
    /// firing is then ignored.
    CdFlush {
        link: LinkId,
        segment: u16,
        generation: u64,
    },
    /// A transmitter begins driving a bus segment.
    BusTxStart {
        link: LinkId,
        segment: u16,
        origin: Origin,
        dir: BusDir,
        bytes: Vec<u8>,
    },
    /// A transmission finishes. If nothing collided with it, this is where it
    /// is delivered.
    BusTxEnd {
        link: LinkId,
        segment: u16,
        txid: u64,
    },
    /// A controller does its next scheduled thing — usually poll the next
    /// address.
    AcuTick { controller: ControllerId },
    /// A controller's reply timer expires.
    AcuTimeout {
        controller: ControllerId,
        token: u64,
    },
    /// A door strike times out and the door relocks.
    DoorRelock { door: DoorId, token: u64 },
    /// A door's position switch changes.
    DoorPosition { door: DoorId, open: bool },
    /// A door's request-to-exit input changes.
    DoorRex { door: DoorId, asserted: bool },
    /// A tap transmits something it was told to transmit in advance.
    TapInject {
        tap: TapId,
        payload: Box<InjectionPayload>,
    },
}

/// What a tap puts on a link.
///
/// The segment is implied by the tap's position and the direction of travel:
/// an inline tap transmitting [`BusDir::AcuToPd`] drives its PD-side segment,
/// and one transmitting [`BusDir::PdToAcu`] drives its ACU-side segment, which
/// is exactly what a two-port implant does. A passive or injecting tap has
/// only one segment and drives that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionPayload {
    /// Raw octets onto an RS-485 bus.
    BusBytes {
        /// Which way they travel.
        dir: BusDir,
        /// The octets.
        bytes: Vec<u8>,
    },
    /// An OSDP frame onto an RS-485 bus. Encoded at transmission time, so the
    /// CRC is always right; build the bytes by hand if a bad CRC is the point.
    BusFrame {
        /// Which way it travels.
        dir: BusDir,
        /// The frame.
        frame: Box<Frame>,
    },
    /// A run of bits onto a Wiegand or clock-and-data pair, travelling towards
    /// the controller — the only direction those links have.
    WireBits {
        /// The bits, in transmission order.
        bits: BitVec,
    },
}

impl InjectionPayload {
    /// How many bytes or bits this carries, for the log summary.
    pub fn len(&self) -> usize {
        match self {
            InjectionPayload::BusBytes { bytes, .. } => bytes.len(),
            InjectionPayload::BusFrame { frame, .. } => frame.wire_len(),
            InjectionPayload::WireBits { bits } => bits.len(),
        }
    }

    /// True if there is nothing to transmit.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A transmission a tap has been told to make at a particular time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Injection {
    /// When to transmit.
    pub at_us: Micros,
    /// What to transmit.
    pub payload: InjectionPayload,
}

impl Injection {
    /// Raw octets onto a bus.
    pub fn bus_bytes(at_us: Micros, dir: BusDir, bytes: Vec<u8>) -> Injection {
        Injection {
            at_us,
            payload: InjectionPayload::BusBytes { dir, bytes },
        }
    }

    /// An OSDP frame onto a bus.
    pub fn bus_frame(at_us: Micros, dir: BusDir, frame: Frame) -> Injection {
        Injection {
            at_us,
            payload: InjectionPayload::BusFrame {
                dir,
                frame: Box::new(frame),
            },
        }
    }

    /// Bits onto a Wiegand or clock-and-data pair.
    pub fn wire_bits(at_us: Micros, bits: BitVec) -> Injection {
        Injection {
            at_us,
            payload: InjectionPayload::WireBits { bits },
        }
    }
}

struct Entry {
    t_us: Micros,
    seq: u64,
    cause: Option<u64>,
    ev: SimEvent,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.t_us == other.t_us && self.seq == other.seq
    }
}
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.t_us
            .cmp(&other.t_us)
            .then_with(|| self.seq.cmp(&other.seq))
    }
}

/// The event queue.
#[derive(Default)]
pub(crate) struct Scheduler {
    heap: BinaryHeap<Reverse<Entry>>,
    next_seq: u64,
}

impl Scheduler {
    pub(crate) fn new() -> Scheduler {
        Scheduler {
            heap: BinaryHeap::new(),
            next_seq: 0,
        }
    }

    /// Queue an event. Ties at the same `t_us` fire in insertion order.
    pub(crate) fn push(&mut self, t_us: Micros, cause: Option<u64>, ev: SimEvent) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.heap.push(Reverse(Entry {
            t_us,
            seq,
            cause,
            ev,
        }));
    }

    /// When the next event is due.
    pub(crate) fn peek_time(&self) -> Option<Micros> {
        self.heap.peek().map(|Reverse(e)| e.t_us)
    }

    /// Take the earliest event.
    pub(crate) fn pop(&mut self) -> Option<(Micros, Option<u64>, SimEvent)> {
        self.heap.pop().map(|Reverse(e)| (e.t_us, e.cause, e.ev))
    }

    /// How many events are queued.
    pub(crate) fn len(&self) -> usize {
        self.heap.len()
    }
}
