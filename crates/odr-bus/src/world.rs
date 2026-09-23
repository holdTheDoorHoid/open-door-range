//! The world: everything that exists, and the loop that makes time pass.
//!
//! # How time works
//!
//! The caller drives it. [`World::step`] processes exactly one queued event;
//! [`World::run_until`] processes every event due at or before a deadline and
//! then parks the clock there. Nothing sleeps, nothing reads a wall clock, and
//! the engine never advances time on its own — which is what lets the site
//! offer "step through the handshake" and "run a simulated day" as the same
//! control (`docs/UI.md`).
//!
//! # How determinism works
//!
//! One seeded PRNG, shared by everything that needs a nonce; a queue that
//! breaks ties by insertion order; no map iteration; integer arithmetic
//! throughout. Two runs of the same scenario with the same seed produce
//! byte-identical event logs, and there is a test that asserts exactly that.
//!
//! # Reading the world
//!
//! Everything a drill's flag predicate needs is either on the
//! [`EventLog`] or on a component reachable from here:
//! [`World::reader`] for a PD's configured SCBK, [`World::controller`] for a
//! session's security state, [`World::door`] for the strike count,
//! [`World::tap`] for what one probe saw.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_osdp::frame::{ScanEvent, Scanner};
use odr_osdp::rng::SeededRng;
use odr_osdp::Frame;
use odr_wiegand::{
    decode_clock_data, encode_clock_data, encode_transitions, BitVec, ClockDataTiming,
    WiegandTiming, WireEvent,
};

use crate::access::AccessList;
use crate::capture::{export_ndjson, CaptureOptions};
use crate::controller::{AcuConfig, CardDecision, Controller, ControllerMode, SessionStage};
use crate::credential::{CredentialSource, Presentation};
use crate::door::{Door, DoorPosition, LockState};
use crate::error::{BusError, Result};
use crate::ids::{BusDir, ControllerId, DoorId, Endpoint, LinkId, Micros, Origin, ReaderId, TapId};
use crate::link::{ChainItem, ClockDataLink, Link, PendingTx, Rs485Bus, Rs485Timing, WiegandLink};
use crate::log::{EventLog, LineAnomaly, RecordKind, TapAction, WireKind};
use crate::reader::{clock_data_bits, Reader, ReaderProtocol};
use crate::sched::{Injection, InjectionPayload, Scheduler, SimEvent};
use crate::tap::{Observation, ObservedTraffic, Tap, TapCtx, TapKind, TapPlacement, TapVerdict};

/// Where on a link a tap is clipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TapPosition {
    /// At the controller end, in front of everything else. An inline tap here
    /// is between the panel and every peripheral, which is the classic
    /// man-in-the-middle position and the default.
    #[default]
    AtController,
    /// Beyond everything attached so far.
    AtFarEnd,
    /// Immediately in front of one reader — the implant in the housing.
    BeforeReader(ReaderId),
    /// An explicit index in the chain, counting outward from the controller.
    Index(u16),
}

/// A tap and where it sits.
struct TapEntry {
    link: LinkId,
    kind: TapKind,
    tap: Option<Box<dyn Tap>>,
}

/// Everything that exists, plus the clock.
pub struct World {
    now: Micros,
    seed: u64,
    rng: SeededRng,
    sched: Scheduler,
    log: EventLog,
    readers: Vec<Option<Reader>>,
    controllers: Vec<Option<Controller>>,
    doors: Vec<Option<Door>>,
    links: Vec<Option<Link>>,
    taps: Vec<TapEntry>,
    cause: Option<u64>,
    steps: u64,
    /// Guard against a scenario that schedules events at the same instant for
    /// ever. Hit in a browser it would be a hung tab, so it is an error.
    pub step_budget: u64,
}

impl core::fmt::Debug for World {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("World")
            .field("now_us", &self.now)
            .field("seed", &self.seed)
            .field("records", &self.log.len())
            .field("queued", &self.sched.len())
            .field("readers", &self.readers.len())
            .field("controllers", &self.controllers.len())
            .field("links", &self.links.len())
            .field("taps", &self.taps.len())
            .finish()
    }
}

impl World {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// An empty world with a given seed.
    ///
    /// The seed is the only source of variation in the whole engine. Two
    /// worlds built with the same seed and driven the same way produce
    /// identical logs.
    pub fn new(seed: u64) -> World {
        let mut w = World {
            now: 0,
            seed,
            rng: SeededRng::new(seed),
            sched: Scheduler::new(),
            log: EventLog::new(),
            readers: Vec::new(),
            controllers: Vec::new(),
            doors: Vec::new(),
            links: Vec::new(),
            taps: Vec::new(),
            cause: None,
            steps: 0,
            step_budget: 5_000_000,
        };
        w.log.push(0, None, RecordKind::Started { seed });
        w
    }

    /// Add a reader.
    pub fn add_reader(&mut self, reader: Reader) -> ReaderId {
        let id = ReaderId(self.readers.len() as u32);
        let mut r = reader;
        r.id = id;
        if let Some(crate::reader::BusyPolicy::Next(n)) = r.pd_config().map(|c| c.busy_policy) {
            r.osdp.busy_left = n;
        }
        self.readers.push(Some(r));
        id
    }

    /// Add a controller.
    pub fn add_controller(&mut self, controller: Controller) -> ControllerId {
        let id = ControllerId(self.controllers.len() as u32);
        let mut c = controller;
        c.id = id;
        self.controllers.push(Some(c));
        id
    }

    /// Add a door.
    pub fn add_door(&mut self, door: Door) -> DoorId {
        let id = DoorId(self.doors.len() as u32);
        let mut d = door;
        d.id = id;
        self.doors.push(Some(d));
        id
    }

    /// Wire a controller to the door it drives.
    pub fn attach_door(&mut self, controller: ControllerId, door: DoorId) -> Result<()> {
        if self
            .doors
            .get(door.index())
            .and_then(|d| d.as_ref())
            .is_none()
        {
            return Err(BusError::UnknownDoor(door));
        }
        let c = self.controller_mut(controller)?;
        c.door = Some(door);
        Ok(())
    }

    /// Add a Wiegand D0/D1 link between a controller and a reader.
    pub fn add_wiegand_link(
        &mut self,
        name: impl Into<String>,
        controller: ControllerId,
        reader: ReaderId,
        timing: WiegandTiming,
    ) -> Result<LinkId> {
        let id = LinkId(self.links.len() as u32);
        let mut chain = crate::link::Chain::new();
        chain.push(ChainItem::Pd(reader));
        let mut link = Link::Wiegand(WiegandLink {
            id,
            name: name.into(),
            controller,
            reader,
            timing,
            propagation_us: 1,
            relay_delay_us: 200,
            chain,
            segments: Vec::new(),
        });
        link.resync_segments();
        self.links.push(Some(link));
        self.reader_mut(reader)?.link = Some(id);
        self.controller_mut(controller)?.links.push(id);
        Ok(id)
    }

    /// Add a clock-and-data link between a controller and a reader.
    pub fn add_clock_data_link(
        &mut self,
        name: impl Into<String>,
        controller: ControllerId,
        reader: ReaderId,
        timing: ClockDataTiming,
    ) -> Result<LinkId> {
        let id = LinkId(self.links.len() as u32);
        let mut chain = crate::link::Chain::new();
        chain.push(ChainItem::Pd(reader));
        let mut link = Link::ClockData(ClockDataLink {
            id,
            name: name.into(),
            controller,
            reader,
            timing,
            propagation_us: 1,
            relay_delay_us: 200,
            chain,
            segments: Vec::new(),
        });
        link.resync_segments();
        self.links.push(Some(link));
        self.reader_mut(reader)?.link = Some(id);
        self.controller_mut(controller)?.links.push(id);
        Ok(id)
    }

    /// Add an RS-485 multidrop bus.
    ///
    /// Peripherals are attached afterwards with [`World::attach_pd`], and the
    /// order matters: each is further from the controller than the last, so an
    /// inline tap added between two of them cuts only the far one off.
    pub fn add_rs485_bus(
        &mut self,
        name: impl Into<String>,
        controller: ControllerId,
        timing: Rs485Timing,
    ) -> Result<LinkId> {
        let id = LinkId(self.links.len() as u32);
        let mut link = Link::Rs485(Rs485Bus {
            id,
            name: name.into(),
            controller,
            timing,
            chain: crate::link::Chain::new(),
            segments: Vec::new(),
        });
        link.resync_segments();
        self.links.push(Some(link));
        self.controller_mut(controller)?.links.push(id);
        Ok(id)
    }

    /// Attach a peripheral to an RS-485 bus, beyond everything already on it.
    pub fn attach_pd(&mut self, link: LinkId, reader: ReaderId) -> Result<()> {
        if self
            .readers
            .get(reader.index())
            .and_then(|r| r.as_ref())
            .is_none()
        {
            return Err(BusError::UnknownReader(reader));
        }
        {
            let l = self.link_mut(link)?;
            if !matches!(l, Link::Rs485(_)) {
                return Err(BusError::WrongLinkKind {
                    link,
                    wanted: "an RS-485 bus",
                    found: l.kind_name(),
                });
            }
            l.chain_mut().push(ChainItem::Pd(reader));
            l.resync_segments();
        }
        self.reader_mut(reader)?.link = Some(link);
        Ok(())
    }

    /// Clip a tap onto a link at the controller end.
    pub fn add_tap(&mut self, link: LinkId, tap: Box<dyn Tap>) -> Result<TapId> {
        self.add_tap_at(link, tap, TapPosition::default())
    }

    /// Clip a tap onto a link at a chosen position.
    ///
    /// Adding an **inline** tap cuts the link, so the electrical state of the
    /// segments either side is reset. That is honest: clipping an implant into
    /// a live cable really does disturb it.
    pub fn add_tap_at(
        &mut self,
        link: LinkId,
        tap: Box<dyn Tap>,
        position: TapPosition,
    ) -> Result<TapId> {
        let id = TapId(self.taps.len() as u32);
        let kind = tap.kind();
        {
            let l = self.link_mut(link)?;
            let item = ChainItem::Tap(id, kind);
            match position {
                TapPosition::AtController => l.chain_mut().insert(0, item),
                TapPosition::AtFarEnd => l.chain_mut().push(item),
                TapPosition::BeforeReader(r) => {
                    let idx = l
                        .chain()
                        .items()
                        .iter()
                        .position(|i| i.reader() == Some(r))
                        .unwrap_or(l.chain().items().len());
                    l.chain_mut().insert(idx, item);
                }
                TapPosition::Index(i) => l.chain_mut().insert(i as usize, item),
            }
            l.resync_segments();
        }
        self.taps.push(TapEntry {
            link,
            kind,
            tap: Some(tap),
        });
        let pending = match self.taps.get_mut(id.index()).and_then(|e| e.tap.as_mut()) {
            Some(t) => t.take_pending(),
            None => Vec::new(),
        };
        for inj in pending {
            self.queue_injection(id, inj);
        }
        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// The current virtual time.
    pub fn now(&self) -> Micros {
        self.now
    }

    /// The seed this world was built with.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The world's seeded PRNG.
    ///
    /// Use it when a scenario needs a reproducible value of its own — the
    /// randomised credential curriculum drill 1.1 asks the learner to decode,
    /// for instance. Drawing from it shifts every nonce the engine produces
    /// afterwards, which is still perfectly deterministic but means the same
    /// seed with and without the draw are different runs. Draw everything up
    /// front, before the first [`World::step`], and that never bites.
    pub fn rng(&mut self) -> &mut SeededRng {
        &mut self.rng
    }

    /// The event log.
    pub fn log(&self) -> &EventLog {
        &self.log
    }

    /// How many events are still queued.
    pub fn queued(&self) -> usize {
        self.sched.len()
    }

    /// How many events have been processed.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// A reader.
    pub fn reader(&self, id: ReaderId) -> Result<&Reader> {
        self.readers
            .get(id.index())
            .and_then(|r| r.as_ref())
            .ok_or(BusError::UnknownReader(id))
    }

    /// A reader, mutably.
    pub fn reader_mut(&mut self, id: ReaderId) -> Result<&mut Reader> {
        self.readers
            .get_mut(id.index())
            .and_then(|r| r.as_mut())
            .ok_or(BusError::UnknownReader(id))
    }

    /// A controller.
    pub fn controller(&self, id: ControllerId) -> Result<&Controller> {
        self.controllers
            .get(id.index())
            .and_then(|c| c.as_ref())
            .ok_or(BusError::UnknownController(id))
    }

    /// A controller, mutably.
    pub fn controller_mut(&mut self, id: ControllerId) -> Result<&mut Controller> {
        self.controllers
            .get_mut(id.index())
            .and_then(|c| c.as_mut())
            .ok_or(BusError::UnknownController(id))
    }

    /// A door.
    pub fn door(&self, id: DoorId) -> Result<&Door> {
        self.doors
            .get(id.index())
            .and_then(|d| d.as_ref())
            .ok_or(BusError::UnknownDoor(id))
    }

    /// A door, mutably.
    pub fn door_mut(&mut self, id: DoorId) -> Result<&mut Door> {
        self.doors
            .get_mut(id.index())
            .and_then(|d| d.as_mut())
            .ok_or(BusError::UnknownDoor(id))
    }

    /// A link.
    pub fn link(&self, id: LinkId) -> Result<&Link> {
        self.links
            .get(id.index())
            .and_then(|l| l.as_ref())
            .ok_or(BusError::UnknownLink(id))
    }

    /// A link, mutably.
    pub fn link_mut(&mut self, id: LinkId) -> Result<&mut Link> {
        self.links
            .get_mut(id.index())
            .and_then(|l| l.as_mut())
            .ok_or(BusError::UnknownLink(id))
    }

    /// A tap, for reading what it saw.
    pub fn tap(&self, id: TapId) -> Result<&dyn Tap> {
        self.taps
            .get(id.index())
            .and_then(|e| e.tap.as_deref())
            .ok_or(BusError::UnknownTap(id))
    }

    /// Which kind a tap is.
    ///
    /// Curriculum drill 1.4's flag begins "the tap is inline", so this is a
    /// question the engine has to be able to answer.
    pub fn tap_kind(&self, id: TapId) -> Result<TapKind> {
        self.taps
            .get(id.index())
            .map(|e| e.kind)
            .ok_or(BusError::UnknownTap(id))
    }

    /// Every reader in the world.
    pub fn readers(&self) -> impl Iterator<Item = &Reader> {
        self.readers.iter().filter_map(|r| r.as_ref())
    }

    /// Every controller in the world.
    pub fn controllers(&self) -> impl Iterator<Item = &Controller> {
        self.controllers.iter().filter_map(|c| c.as_ref())
    }

    /// Every door in the world.
    pub fn doors(&self) -> impl Iterator<Item = &Door> {
        self.doors.iter().filter_map(|d| d.as_ref())
    }

    /// Every link in the world.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.links.iter().filter_map(|l| l.as_ref())
    }

    /// Where every tap on a link sits, for the UI's topology strip.
    pub fn tap_placements(&self, link: LinkId) -> Result<Vec<TapPlacement>> {
        let l = self.link(link)?;
        let chain = l.chain();
        let mut out = Vec::new();
        for (pos, item) in chain.items().iter().enumerate() {
            if let ChainItem::Tap(id, kind) = item {
                let controller_side = chain.segment_of(pos);
                let reader_side = if kind.can_alter() {
                    controller_side.saturating_add(1)
                } else {
                    controller_side
                };
                out.push(TapPlacement {
                    link,
                    kind: *kind,
                    name: self
                        .tap(*id)
                        .map(|t| t.name().to_string())
                        .unwrap_or_default(),
                    segment_controller_side: controller_side,
                    segment_reader_side: reader_side,
                    position: pos as u16,
                });
            }
        }
        Ok(out)
    }

    /// Export the whole world's traffic in the capture format.
    pub fn export_capture(&self) -> String {
        export_ndjson(&self.log)
    }

    /// Export the whole world's traffic with non-default options.
    pub fn export_capture_with(&self, opts: &CaptureOptions) -> String {
        crate::capture::export_ndjson_with(&self.log, opts)
    }

    // -----------------------------------------------------------------------
    // Driving the world
    // -----------------------------------------------------------------------

    /// Present a credential to a reader at a chosen time.
    pub fn present(
        &mut self,
        reader: ReaderId,
        at_us: Micros,
        presentation: Presentation,
    ) -> Result<()> {
        self.reader(reader)?;
        self.sched.push(
            at_us.max(self.now),
            None,
            SimEvent::Present {
                reader,
                presentation: Box::new(presentation),
            },
        );
        Ok(())
    }

    /// Present whatever token is attached to a reader.
    pub fn present_attached(&mut self, reader: ReaderId, at_us: Micros) -> Result<()> {
        self.reader(reader)?;
        self.sched.push(
            at_us.max(self.now),
            None,
            SimEvent::PresentAttached { reader },
        );
        Ok(())
    }

    /// Attach a token to a reader, for the pull half of the credential seam.
    pub fn attach_source(
        &mut self,
        reader: ReaderId,
        source: Box<dyn CredentialSource>,
    ) -> Result<()> {
        self.reader_mut(reader)?.set_source(source);
        Ok(())
    }

    /// Tell a tap to transmit something at a chosen time.
    pub fn inject(&mut self, tap: TapId, injection: Injection) -> Result<()> {
        let kind = self.tap_kind(tap)?;
        if !kind.can_transmit() {
            let link = self.taps[tap.index()].link;
            self.log.push(
                self.now,
                None,
                RecordKind::TapAction {
                    tap,
                    link,
                    action: TapAction::VerdictIgnored {
                        reason: "a passive tap cannot transmit",
                    },
                },
            );
            return Ok(());
        }
        self.queue_injection(tap, injection);
        Ok(())
    }

    fn queue_injection(&mut self, tap: TapId, injection: Injection) {
        self.sched.push(
            injection.at_us.max(self.now),
            self.cause,
            SimEvent::TapInject {
                tap,
                payload: Box::new(injection.payload),
            },
        );
    }

    /// Assert or release a door's request-to-exit input.
    pub fn set_rex(&mut self, door: DoorId, at_us: Micros, asserted: bool) -> Result<()> {
        self.door(door)?;
        self.sched.push(
            at_us.max(self.now),
            None,
            SimEvent::DoorRex { door, asserted },
        );
        Ok(())
    }

    /// Open or close a door's leaf.
    pub fn set_door_position(&mut self, door: DoorId, at_us: Micros, open: bool) -> Result<()> {
        self.door(door)?;
        self.sched.push(
            at_us.max(self.now),
            None,
            SimEvent::DoorPosition { door, open },
        );
        Ok(())
    }

    /// Make a PD answer `REPLY_BUSY` to its next `n` commands.
    pub fn make_busy(&mut self, reader: ReaderId, n: u8) -> Result<()> {
        self.reader_mut(reader)?.osdp.busy_left = n;
        Ok(())
    }

    /// Push a controller's sequence numbering out of step with a PD, without
    /// resetting anything else.
    ///
    /// Curriculum drill 2.4 asks a learner to recover a desynchronised link
    /// *without* restarting the simulation; this is how a drill creates the
    /// fault in the first place.
    pub fn desynchronise(&mut self, controller: ControllerId, address: u8) -> Result<()> {
        let c = self.controller_mut(controller)?;
        match c.session_mut(address) {
            Some(s) => {
                // Skip exactly one value of the 1,2,3 cycle. That is the
                // smallest change the PD cannot mistake for a retransmission,
                // so it NAKs rather than repeating its last answer.
                s.sequence = match s.sequence & 0x03 {
                    3 => 1,
                    other => other + 1,
                };
                Ok(())
            }
            None => Err(BusError::Config(alloc::format!(
                "controller has no session for address {address:#04x}"
            ))),
        }
    }

    /// Start a controller polling. Called by the builder; safe to call again.
    pub fn start_polling(&mut self, controller: ControllerId, at_us: Micros) -> Result<()> {
        let c = self.controller(controller)?;
        if c.acu_config().is_none() {
            return Err(BusError::Config(
                "start_polling on a controller that is not an OSDP ACU".to_string(),
            ));
        }
        self.sched
            .push(at_us.max(self.now), None, SimEvent::AcuTick { controller });
        Ok(())
    }

    /// Leave a note in the event log.
    pub fn note(&mut self, text: impl Into<String>) {
        let t = self.now;
        self.log
            .push(t, None, RecordKind::Note { text: text.into() });
    }

    /// Process exactly one queued event.
    ///
    /// Returns `false` when the queue is empty. The clock jumps to the event's
    /// time; it never moves on its own.
    pub fn step(&mut self) -> Result<bool> {
        let (t, cause, ev) = match self.sched.pop() {
            Some(x) => x,
            None => return Ok(false),
        };
        self.now = self.now.max(t);
        self.cause = cause;
        self.steps = self.steps.saturating_add(1);
        self.dispatch(ev)?;
        self.cause = None;
        Ok(true)
    }

    /// Process every event due at or before `deadline_us`, then park the clock
    /// at the deadline.
    ///
    /// Returns how many events ran.
    pub fn run_until(&mut self, deadline_us: Micros) -> Result<u64> {
        let mut ran = 0u64;
        loop {
            match self.sched.peek_time() {
                Some(t) if t <= deadline_us => {}
                _ => break,
            }
            if !self.step()? {
                break;
            }
            ran = ran.saturating_add(1);
            if ran > self.step_budget {
                return Err(BusError::Config(alloc::format!(
                    "step budget of {} exhausted before reaching t={}us",
                    self.step_budget,
                    deadline_us
                )));
            }
        }
        self.now = self.now.max(deadline_us);
        Ok(ran)
    }

    /// Run for a further span of virtual time.
    pub fn run_for(&mut self, duration_us: Micros) -> Result<u64> {
        let deadline = self.now.saturating_add(duration_us);
        self.run_until(deadline)
    }

    /// Process up to `n` events, stopping early if the queue empties.
    pub fn run_steps(&mut self, n: u64) -> Result<u64> {
        let mut ran = 0;
        while ran < n {
            if !self.step()? {
                break;
            }
            ran += 1;
        }
        Ok(ran)
    }

    // -----------------------------------------------------------------------
    // Logging helpers
    // -----------------------------------------------------------------------

    fn emit(&mut self, kind: RecordKind) -> u64 {
        let t = self.now;
        let cause = self.cause;
        self.log.push(t, cause, kind)
    }

    fn schedule(&mut self, at_us: Micros, ev: SimEvent) {
        let at = at_us.max(self.now);
        let cause = self.cause;
        self.sched.push(at, cause, ev);
    }

    fn schedule_caused_by(&mut self, at_us: Micros, cause: Option<u64>, ev: SimEvent) {
        let at = at_us.max(self.now);
        self.sched.push(at, cause, ev);
    }

    // -----------------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------------

    fn dispatch(&mut self, ev: SimEvent) -> Result<()> {
        match ev {
            SimEvent::Present {
                reader,
                presentation,
            } => self.on_present(reader, *presentation),
            SimEvent::PresentAttached { reader } => {
                let at = self.now;
                let pulled = self.reader_mut(reader)?.pull_source(at);
                match pulled {
                    Some(p) => self.on_present(reader, p),
                    None => {
                        self.emit(RecordKind::CredentialRejected {
                            reader,
                            source: crate::ids::SourceId(u32::MAX),
                            reason: "the attached token did not answer".to_string(),
                        });
                        Ok(())
                    }
                }
            }
            SimEvent::ReaderEmit { reader, token } => self.on_reader_emit(reader, token),
            SimEvent::WiegandEdge { link, segment, tr } => self.on_wiegand_edge(link, segment, tr),
            SimEvent::WireFlush {
                link,
                segment,
                generation,
            } => self.on_wire_flush(link, segment, generation),
            SimEvent::CdEdge { link, segment, tr } => {
                let l = self.link_mut(link)?;
                if let Link::ClockData(cd) = l {
                    if let Some(seg) = cd.segments.get_mut(segment as usize) {
                        seg.pending.push(tr);
                        seg.generation = seg.generation.saturating_add(1);
                        let generation = seg.generation;
                        let gap = cd.timing.interframe_gap_us;
                        self.schedule(
                            tr.t_us.saturating_add(gap),
                            SimEvent::CdFlush {
                                link,
                                segment,
                                generation,
                            },
                        );
                    }
                }
                Ok(())
            }
            SimEvent::CdFlush {
                link,
                segment,
                generation,
            } => self.on_cd_flush(link, segment, generation),
            SimEvent::BusTxStart {
                link,
                segment,
                origin,
                dir,
                bytes,
            } => self.on_bus_tx_start(link, segment, origin, dir, bytes),
            SimEvent::BusTxEnd {
                link,
                segment,
                txid,
            } => self.on_bus_tx_end(link, segment, txid),
            SimEvent::AcuTick { controller } => self.on_acu_tick(controller),
            SimEvent::AcuTimeout { controller, token } => self.on_acu_timeout(controller, token),
            SimEvent::DoorRelock { door, token } => {
                let d = self.door_mut(door)?;
                if d.relock_token != token {
                    return Ok(());
                }
                d.lock = LockState::Locked;
                self.emit(RecordKind::DoorLock { door, locked: true });
                Ok(())
            }
            SimEvent::DoorPosition { door, open } => {
                let d = self.door_mut(door)?;
                d.position = if open {
                    DoorPosition::Open
                } else {
                    DoorPosition::Closed
                };
                self.emit(RecordKind::DoorPosition { door, open });
                Ok(())
            }
            SimEvent::DoorRex { door, asserted } => {
                let unlocks = {
                    let d = self.door_mut(door)?;
                    d.rex = asserted;
                    d.rex_unlocks
                };
                self.emit(RecordKind::RequestToExit { door, asserted });
                if asserted && unlocks {
                    self.fire_strike(door, None)?;
                }
                Ok(())
            }
            SimEvent::TapInject { tap, payload } => self.on_tap_inject(tap, *payload),
        }
    }

    // -----------------------------------------------------------------------
    // Credentials
    // -----------------------------------------------------------------------

    fn on_present(&mut self, reader: ReaderId, presentation: Presentation) -> Result<()> {
        let seq = self.emit(RecordKind::CredentialPresented {
            reader,
            source: presentation.source,
            format: presentation.format,
            bits: presentation.bits.clone(),
            label: presentation.label.clone(),
        });
        let (read_time, token) = {
            let r = self.reader_mut(reader)?;
            r.pending = Some(presentation);
            r.emit_token = r.emit_token.saturating_add(1);
            (r.read_time_us, r.emit_token)
        };
        self.schedule_caused_by(
            self.now.saturating_add(read_time),
            Some(seq),
            SimEvent::ReaderEmit { reader, token },
        );
        Ok(())
    }

    fn on_reader_emit(&mut self, reader: ReaderId, token: u64) -> Result<()> {
        let (presentation, protocol, link) = {
            let r = self.reader_mut(reader)?;
            if r.emit_token != token {
                return Ok(());
            }
            (r.pending.take(), r.protocol.clone(), r.link)
        };
        let presentation = match presentation {
            Some(p) => p,
            None => return Ok(()),
        };
        let link = match link {
            Some(l) => l,
            None => {
                self.emit(RecordKind::CredentialRejected {
                    reader,
                    source: presentation.source,
                    reason: "the reader is not connected to anything".to_string(),
                });
                return Ok(());
            }
        };
        let segment = self
            .link(link)?
            .chain()
            .segment_of_reader(reader)
            .unwrap_or(0);

        match protocol {
            ReaderProtocol::Wiegand => {
                let now = self.now;
                self.wire_emit(
                    link,
                    segment,
                    Origin::Reader(reader),
                    presentation.bits,
                    now,
                )
            }
            ReaderProtocol::ClockData(cfg) => match clock_data_bits(&cfg, &presentation) {
                Some(bits) => {
                    let now = self.now;
                    self.wire_emit(link, segment, Origin::Reader(reader), bits, now)
                }
                None => {
                    self.emit(RecordKind::CredentialRejected {
                        reader,
                        source: presentation.source,
                        reason: "the reader could not turn these bits into track-2 data"
                            .to_string(),
                    });
                    Ok(())
                }
            },
            ReaderProtocol::Osdp(_) => {
                let at = self.now;
                let r = self.reader_mut(reader)?;
                r.osdp.held_read = Some(crate::reader::HeldRead {
                    source: presentation.source,
                    format: presentation.format,
                    bits: presentation.bits,
                    at_us: at,
                });
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------------
    // Two-wire links
    // -----------------------------------------------------------------------

    /// Drive a run of bits onto one segment of a two-wire link.
    fn wire_emit(
        &mut self,
        link: LinkId,
        segment: u16,
        origin: Origin,
        bits: BitVec,
        at_us: Micros,
    ) -> Result<()> {
        enum Edges {
            Wiegand(Vec<odr_wiegand::Transition>),
            Cd(Vec<odr_wiegand::CdTransition>),
        }
        let (kind, edges, propagation) = {
            let l = self.link(link)?;
            match l {
                Link::Wiegand(w) => (
                    WireKind::Wiegand,
                    Edges::Wiegand(encode_transitions(&bits, &w.timing, at_us)),
                    w.propagation_us,
                ),
                Link::ClockData(c) => (
                    WireKind::ClockData,
                    Edges::Cd(encode_clock_data(&bits, &c.timing, at_us)),
                    c.propagation_us,
                ),
                Link::Rs485(_) => {
                    return Err(BusError::WrongLinkKind {
                        link,
                        wanted: "a two-wire link",
                        found: "rs485",
                    })
                }
            }
        };
        if segment >= self.link(link)?.segment_count() {
            return Err(BusError::NoSuchSegment { link, segment });
        }
        match self.link_mut(link)? {
            Link::Wiegand(w) => {
                if let Some(seg) = w.segments.get_mut(segment as usize) {
                    seg.last_origin = Some(origin);
                }
            }
            Link::ClockData(c) => {
                if let Some(seg) = c.segments.get_mut(segment as usize) {
                    seg.last_origin = Some(origin);
                }
            }
            Link::Rs485(_) => {}
        }
        let cause = Some(self.emit(RecordKind::WireTx {
            link,
            segment,
            origin,
            kind,
            bits,
        }));
        match edges {
            Edges::Wiegand(list) => {
                for tr in list {
                    let mut moved = tr;
                    moved.t_us = moved.t_us.saturating_add(propagation);
                    self.schedule_caused_by(
                        moved.t_us,
                        cause,
                        SimEvent::WiegandEdge {
                            link,
                            segment,
                            tr: moved,
                        },
                    );
                }
            }
            Edges::Cd(list) => {
                for tr in list {
                    let mut moved = tr;
                    moved.t_us = moved.t_us.saturating_add(propagation);
                    self.schedule_caused_by(
                        moved.t_us,
                        cause,
                        SimEvent::CdEdge {
                            link,
                            segment,
                            tr: moved,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn on_wiegand_edge(
        &mut self,
        link: LinkId,
        segment: u16,
        tr: odr_wiegand::Transition,
    ) -> Result<()> {
        let (events, generation, gap) = {
            let l = self.link_mut(link)?;
            match l {
                Link::Wiegand(w) => {
                    let gap = w.timing.interframe_gap_us;
                    match w.segments.get_mut(segment as usize) {
                        Some(seg) => {
                            seg.generation = seg.generation.saturating_add(1);
                            (seg.decoder.push(tr), seg.generation, gap)
                        }
                        None => return Err(BusError::NoSuchSegment { link, segment }),
                    }
                }
                _ => {
                    return Err(BusError::WrongLinkKind {
                        link,
                        wanted: "a wiegand link",
                        found: self.link(link)?.kind_name(),
                    })
                }
            }
        };
        // A frame ends when the line has been quiet for longer than the
        // inter-frame gap. `odr-wiegand`'s decoder only notices that when the
        // next edge arrives, so the engine has to ask it.
        self.schedule(
            tr.t_us.saturating_add(gap).saturating_add(1),
            SimEvent::WireFlush {
                link,
                segment,
                generation,
            },
        );
        for ev in events {
            match ev {
                WireEvent::Frame(frame) => {
                    self.deliver_wire_frame(
                        link,
                        segment,
                        WireKind::Wiegand,
                        frame.bits,
                        frame.start_us,
                        frame.end_us,
                    )?;
                }
                WireEvent::Anomaly(a) => {
                    self.emit(RecordKind::WireAnomaly {
                        link,
                        segment,
                        anomaly: LineAnomaly::Wiegand(a),
                    });
                }
                WireEvent::Bit { .. } => {}
            }
        }
        Ok(())
    }

    fn on_wire_flush(&mut self, link: LinkId, segment: u16, generation: u64) -> Result<()> {
        let frames = {
            let l = self.link_mut(link)?;
            match l {
                Link::Wiegand(w) => match w.segments.get_mut(segment as usize) {
                    Some(seg) if seg.generation == generation => seg.decoder.flush(),
                    _ => return Ok(()),
                },
                _ => return Ok(()),
            }
        };
        for f in frames {
            self.deliver_wire_frame(
                link,
                segment,
                WireKind::Wiegand,
                f.bits,
                f.start_us,
                f.end_us,
            )?;
        }
        Ok(())
    }

    fn on_cd_flush(&mut self, link: LinkId, segment: u16, generation: u64) -> Result<()> {
        let (capture, timing) = {
            let l = self.link_mut(link)?;
            match l {
                Link::ClockData(c) => {
                    let timing = c.timing;
                    match c.segments.get_mut(segment as usize) {
                        Some(seg) if seg.generation == generation => {
                            let pending = core::mem::take(&mut seg.pending);
                            (decode_clock_data(&pending, &timing), timing)
                        }
                        _ => return Ok(()),
                    }
                }
                _ => return Ok(()),
            }
        };
        let _ = timing;
        for a in capture.anomalies {
            self.emit(RecordKind::WireAnomaly {
                link,
                segment,
                anomaly: LineAnomaly::ClockData(a),
            });
        }
        for f in capture.frames {
            self.deliver_wire_frame(
                link,
                segment,
                WireKind::ClockData,
                f.bits,
                f.start_us,
                f.end_us,
            )?;
        }
        Ok(())
    }

    /// A complete frame arrived at the receiving end of a wire segment.
    fn deliver_wire_frame(
        &mut self,
        link: LinkId,
        segment: u16,
        kind: WireKind,
        bits: BitVec,
        start_us: Micros,
        end_us: Micros,
    ) -> Result<()> {
        let (listeners, inline, controller, relay_delay, origin) = {
            let l = self.link(link)?;
            let chain = l.chain();
            let (relay, origin) = match l {
                Link::Wiegand(w) => (
                    w.relay_delay_us,
                    w.segments.get(segment as usize).and_then(|s| s.last_origin),
                ),
                Link::ClockData(c) => (
                    c.relay_delay_us,
                    c.segments.get(segment as usize).and_then(|s| s.last_origin),
                ),
                Link::Rs485(_) => (0, None),
            };
            (
                chain.listeners_on(segment),
                chain.inline_inbound_from(segment),
                l.controller(),
                relay,
                origin.unwrap_or(Origin::Controller(l.controller())),
            )
        };

        let receiver = match inline {
            Some(t) => Endpoint::Tap(t),
            None => Endpoint::Controller(controller),
        };
        self.emit(RecordKind::WireRx {
            link,
            segment,
            receiver,
            kind,
            bits: bits.clone(),
            start_us,
            end_us,
        });

        for t in listeners {
            let verdict = self.run_tap_wire(t, link, segment, origin, kind, &bits)?;
            self.reject_verdict_if_not_inline(t, link, verdict);
        }

        match inline {
            Some(t) => {
                let verdict = self.run_tap_wire(t, link, segment, origin, kind, &bits)?;
                let forward = match verdict {
                    TapVerdict::Pass => Some(bits),
                    TapVerdict::Drop => {
                        self.emit(RecordKind::TapAction {
                            tap: t,
                            link,
                            action: TapAction::Dropped {
                                what: alloc::format!("{}-bit frame", bits.len()),
                            },
                        });
                        None
                    }
                    TapVerdict::ReplaceBits(new) => {
                        self.emit(RecordKind::TapAction {
                            tap: t,
                            link,
                            action: TapAction::ReplacedBits {
                                before: bits,
                                after: new.clone(),
                            },
                        });
                        Some(new)
                    }
                    TapVerdict::ReplaceBytes(_) | TapVerdict::ReplaceFrame(_) => {
                        self.emit(RecordKind::TapAction {
                            tap: t,
                            link,
                            action: TapAction::VerdictIgnored {
                                reason: "a two-wire link carries bits, not bytes or frames",
                            },
                        });
                        Some(bits)
                    }
                };
                if let Some(out_bits) = forward {
                    let at = self.now.saturating_add(relay_delay);
                    self.wire_emit(
                        link,
                        segment.saturating_sub(1),
                        Origin::Tap(t),
                        out_bits,
                        at,
                    )?;
                }
                Ok(())
            }
            None => {
                let decision = self.controller(controller)?.decide(&bits);
                self.apply_decision(controller, decision)
            }
        }
    }

    // -----------------------------------------------------------------------
    // RS-485
    // -----------------------------------------------------------------------

    /// Put octets on a bus segment, respecting the turnaround.
    fn bus_emit(
        &mut self,
        link: LinkId,
        segment: u16,
        origin: Origin,
        dir: BusDir,
        bytes: Vec<u8>,
        at_us: Micros,
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let start = {
            let l = self.link(link)?;
            match l {
                Link::Rs485(b) => match b.segments.get(segment as usize) {
                    Some(seg) => at_us.max(seg.free_at_us),
                    None => return Err(BusError::NoSuchSegment { link, segment }),
                },
                _ => {
                    return Err(BusError::WrongLinkKind {
                        link,
                        wanted: "an RS-485 bus",
                        found: l.kind_name(),
                    })
                }
            }
        };
        self.schedule(
            start,
            SimEvent::BusTxStart {
                link,
                segment,
                origin,
                dir,
                bytes,
            },
        );
        Ok(())
    }

    fn on_bus_tx_start(
        &mut self,
        link: LinkId,
        segment: u16,
        origin: Origin,
        dir: BusDir,
        bytes: Vec<u8>,
    ) -> Result<()> {
        let frame = Frame::parse(&bytes).ok().map(|(f, _)| Box::new(f));
        let tx_seq = self.emit(RecordKind::BusTx {
            link,
            segment,
            origin,
            dir,
            bytes: bytes.clone(),
            frame,
        });
        // Everything this transmission goes on to cause hangs off it, which is
        // what makes "the PD ACKed a frame the attacker forged" answerable.
        self.cause = Some(tx_seq);

        let (txid, end, collided_with) = {
            let timing = match self.link(link)? {
                Link::Rs485(b) => b.timing,
                l => {
                    return Err(BusError::WrongLinkKind {
                        link,
                        wanted: "an RS-485 bus",
                        found: l.kind_name(),
                    })
                }
            };
            let now = self.now;
            let duration = timing
                .bytes_duration_us(bytes.len())
                .saturating_add(timing.propagation_us);
            let l = self.link_mut(link)?;
            let seg = match l {
                Link::Rs485(b) => match b.segments.get_mut(segment as usize) {
                    Some(s) => s,
                    None => return Err(BusError::NoSuchSegment { link, segment }),
                },
                _ => return Ok(()),
            };
            let txid = seg.next_txid;
            seg.next_txid = seg.next_txid.saturating_add(1);
            let end = now.saturating_add(duration);
            let mut collided_with = Vec::new();
            if !seg.active.is_empty() {
                collided_with = seg.active.iter().map(|t| t.origin).collect();
                for t in seg.active.iter_mut() {
                    t.collided = true;
                }
            }
            let collided = !collided_with.is_empty();
            seg.active.push(PendingTx {
                txid,
                origin,
                dir,
                bytes,
                end_us: end,
                collided,
            });
            (txid, end, collided_with)
        };

        if !collided_with.is_empty() {
            let mut origins = collided_with;
            origins.push(origin);
            self.emit(RecordKind::BusCollision {
                link,
                segment,
                origins,
            });
        }
        self.schedule(
            end,
            SimEvent::BusTxEnd {
                link,
                segment,
                txid,
            },
        );
        Ok(())
    }

    fn on_bus_tx_end(&mut self, link: LinkId, segment: u16, txid: u64) -> Result<()> {
        let tx = {
            let turnaround = match self.link(link)? {
                Link::Rs485(b) => b.timing.turnaround_us,
                _ => 0,
            };
            let now = self.now;
            let l = self.link_mut(link)?;
            let seg = match l {
                Link::Rs485(b) => match b.segments.get_mut(segment as usize) {
                    Some(s) => s,
                    None => return Ok(()),
                },
                _ => return Ok(()),
            };
            let idx = seg.active.iter().position(|t| t.txid == txid);
            let tx = idx.map(|i| seg.active.remove(i));
            if seg.active.is_empty() {
                seg.free_at_us = now.saturating_add(turnaround);
            }
            tx
        };
        let tx = match tx {
            Some(t) if !t.collided => t,
            _ => return Ok(()),
        };
        self.bus_deliver(link, segment, tx)
    }

    fn bus_deliver(&mut self, link: LinkId, segment: u16, tx: PendingTx) -> Result<()> {
        let (listeners, inline, readers, controller) = {
            let l = self.link(link)?;
            let chain = l.chain();
            let inline = match tx.dir {
                BusDir::AcuToPd => chain.inline_outbound_from(segment),
                BusDir::PdToAcu => chain.inline_inbound_from(segment),
            };
            (
                chain.listeners_on(segment),
                inline,
                chain.readers_on(segment),
                l.controller(),
            )
        };

        let frame = Frame::parse(&tx.bytes).ok().map(|(f, _)| f);

        // Bystanders see the line whatever it carries.
        for t in listeners {
            let verdict = self.run_tap_bus(
                t,
                (link, segment),
                tx.origin,
                tx.dir,
                &tx.bytes,
                frame.as_ref(),
            )?;
            self.reject_verdict_if_not_inline(t, link, verdict);
        }

        // Terminating devices.
        match tx.dir {
            BusDir::AcuToPd => {
                for r in readers {
                    if tx.origin == Origin::Reader(r) {
                        continue;
                    }
                    self.emit(RecordKind::BusRx {
                        link,
                        segment,
                        receiver: Endpoint::Reader(r),
                        dir: tx.dir,
                        bytes: tx.bytes.clone(),
                        frame: frame.clone().map(Box::new),
                    });
                    self.reader_receive(r, link, segment, &tx.bytes)?;
                }
            }
            BusDir::PdToAcu => {
                if segment == 0 {
                    self.emit(RecordKind::BusRx {
                        link,
                        segment,
                        receiver: Endpoint::Controller(controller),
                        dir: tx.dir,
                        bytes: tx.bytes.clone(),
                        frame: frame.clone().map(Box::new),
                    });
                    self.controller_receive(controller, &tx.bytes)?;
                }
            }
        }

        // The implant decides whether any of it crosses the cut.
        if let Some(t) = inline {
            let verdict = self.run_tap_bus(
                t,
                (link, segment),
                tx.origin,
                tx.dir,
                &tx.bytes,
                frame.as_ref(),
            )?;
            let next = match tx.dir {
                BusDir::AcuToPd => segment.saturating_add(1),
                BusDir::PdToAcu => segment.saturating_sub(1),
            };
            let forward = match verdict {
                TapVerdict::Pass => Some(tx.bytes.clone()),
                TapVerdict::Drop => {
                    self.emit(RecordKind::TapAction {
                        tap: t,
                        link,
                        action: TapAction::Dropped {
                            what: alloc::format!("{} bytes", tx.bytes.len()),
                        },
                    });
                    None
                }
                TapVerdict::ReplaceBytes(new) => {
                    self.emit(RecordKind::TapAction {
                        tap: t,
                        link,
                        action: TapAction::Replaced {
                            before: tx.bytes.clone(),
                            after: new.clone(),
                        },
                    });
                    Some(new)
                }
                TapVerdict::ReplaceFrame(f) => {
                    let new = f.encode();
                    self.emit(RecordKind::TapAction {
                        tap: t,
                        link,
                        action: TapAction::Replaced {
                            before: tx.bytes.clone(),
                            after: new.clone(),
                        },
                    });
                    Some(new)
                }
                TapVerdict::ReplaceBits(_) => {
                    self.emit(RecordKind::TapAction {
                        tap: t,
                        link,
                        action: TapAction::VerdictIgnored {
                            reason: "an RS-485 bus carries bytes, not bare bits",
                        },
                    });
                    Some(tx.bytes.clone())
                }
            };
            if let Some(bytes) = forward {
                let at = self.now;
                self.bus_emit(link, next, Origin::Tap(t), tx.dir, bytes, at)?;
            }
        }
        Ok(())
    }

    fn reader_receive(
        &mut self,
        reader: ReaderId,
        link: LinkId,
        segment: u16,
        bytes: &[u8],
    ) -> Result<()> {
        let frames: Vec<Frame> = Scanner::offline(bytes)
            .filter_map(|e| match e {
                ScanEvent::Frame { frame, .. } => Some(*frame),
                _ => None,
            })
            .collect();
        for frame in frames {
            let (outcome, reply_delay) = {
                let mut r = match self.readers.get_mut(reader.index()).and_then(|r| r.take()) {
                    Some(r) => r,
                    None => return Err(BusError::Reentered { what: "a reader" }),
                };
                let delay = r.pd_config().map(|c| c.reply_delay_us).unwrap_or(0);
                let outcome = r.handle_command(&frame, &mut self.rng);
                if let Some(slot) = self.readers.get_mut(reader.index()) {
                    *slot = Some(r);
                }
                (outcome, delay)
            };
            for ev in outcome.protocol {
                self.emit(RecordKind::Protocol {
                    endpoint: Endpoint::Reader(reader),
                    event: ev,
                });
            }
            for ev in outcome.secure_channel {
                self.emit(RecordKind::SecureChannel {
                    endpoint: Endpoint::Reader(reader),
                    event: ev,
                });
            }
            if let Some(reply) = outcome.reply {
                let at = self.now.saturating_add(reply_delay);
                self.bus_emit(
                    link,
                    segment,
                    Origin::Reader(reader),
                    BusDir::PdToAcu,
                    reply.encode(),
                    at,
                )?;
            }
        }
        Ok(())
    }

    fn controller_receive(&mut self, controller: ControllerId, bytes: &[u8]) -> Result<()> {
        let frames: Vec<Frame> = Scanner::offline(bytes)
            .filter_map(|e| match e {
                ScanEvent::Frame { frame, .. } => Some(*frame),
                _ => None,
            })
            .collect();
        for frame in frames {
            let (outcome, poll_interval) = {
                let mut c = match self
                    .controllers
                    .get_mut(controller.index())
                    .and_then(|c| c.take())
                {
                    Some(c) => c,
                    None => {
                        return Err(BusError::Reentered {
                            what: "a controller",
                        })
                    }
                };
                let interval = c
                    .acu_config()
                    .map(|a| a.poll_interval_us)
                    .unwrap_or(100_000);
                let outcome = c.handle_reply(&frame);
                // The reply landed, so any pending timeout is stale.
                c.osdp.timeout_token = c.osdp.timeout_token.saturating_add(1);
                c.osdp.awaiting = None;
                if let Some(slot) = self.controllers.get_mut(controller.index()) {
                    *slot = Some(c);
                }
                (outcome, interval)
            };
            for ev in outcome.protocol {
                self.emit(RecordKind::Protocol {
                    endpoint: Endpoint::Controller(controller),
                    event: ev,
                });
            }
            for ev in outcome.secure_channel {
                self.emit(RecordKind::SecureChannel {
                    endpoint: Endpoint::Controller(controller),
                    event: ev,
                });
            }
            if let Some(decision) = outcome.decision {
                self.apply_decision(controller, decision)?;
            }
            let delay = outcome.retry_after_us.unwrap_or(poll_interval);
            let at = self.now.saturating_add(delay);
            self.schedule(at, SimEvent::AcuTick { controller });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Controller polling
    // -----------------------------------------------------------------------

    fn on_acu_tick(&mut self, controller: ControllerId) -> Result<()> {
        let (action, timeout, link) = {
            let mut c = match self
                .controllers
                .get_mut(controller.index())
                .and_then(|c| c.take())
            {
                Some(c) => c,
                None => {
                    return Err(BusError::Reentered {
                        what: "a controller",
                    })
                }
            };
            if c.osdp.awaiting.is_some() {
                if let Some(slot) = self.controllers.get_mut(controller.index()) {
                    *slot = Some(c);
                }
                return Ok(());
            }
            let cfg_timeout = c
                .acu_config()
                .map(|a| a.reply_timeout_us)
                .unwrap_or(200_000);
            let bus = c.links.iter().copied().find(|l| {
                matches!(
                    self.links.get(l.index()).and_then(|x| x.as_ref()),
                    Some(Link::Rs485(_))
                )
            });
            let action = c.next_command(&mut self.rng);
            if let Some(idx) = action.session {
                if action.command.is_some() {
                    c.osdp.awaiting = Some(idx);
                    c.osdp.timeout_token = c.osdp.timeout_token.saturating_add(1);
                }
            }
            let token = c.osdp.timeout_token;
            if let Some(slot) = self.controllers.get_mut(controller.index()) {
                *slot = Some(c);
            }
            (action, (cfg_timeout, token), bus)
        };

        for ev in action.protocol {
            self.emit(RecordKind::Protocol {
                endpoint: Endpoint::Controller(controller),
                event: ev,
            });
        }
        for ev in action.secure_channel {
            self.emit(RecordKind::SecureChannel {
                endpoint: Endpoint::Controller(controller),
                event: ev,
            });
        }

        let link = match link {
            Some(l) => l,
            None => return Ok(()),
        };
        match action.command {
            Some(frame) => {
                let at = self.now;
                self.bus_emit(
                    link,
                    0,
                    Origin::Controller(controller),
                    BusDir::AcuToPd,
                    frame.encode(),
                    at,
                )?;
                let (cfg_timeout, token) = timeout;
                self.schedule(
                    self.now.saturating_add(cfg_timeout),
                    SimEvent::AcuTimeout { controller, token },
                );
            }
            None => {
                // Nothing to say to this address; come back on the next slot.
                let interval = self
                    .controller(controller)?
                    .acu_config()
                    .map(|a| a.poll_interval_us)
                    .unwrap_or(100_000);
                self.schedule(
                    self.now.saturating_add(interval),
                    SimEvent::AcuTick { controller },
                );
            }
        }
        Ok(())
    }

    fn on_acu_timeout(&mut self, controller: ControllerId, token: u64) -> Result<()> {
        let (outcome, interval) = {
            let mut c = match self
                .controllers
                .get_mut(controller.index())
                .and_then(|c| c.take())
            {
                Some(c) => c,
                None => {
                    return Err(BusError::Reentered {
                        what: "a controller",
                    })
                }
            };
            if c.osdp.timeout_token != token {
                if let Some(slot) = self.controllers.get_mut(controller.index()) {
                    *slot = Some(c);
                }
                return Ok(());
            }
            let idx = c.osdp.awaiting.take();
            let interval = c
                .acu_config()
                .map(|a| a.poll_interval_us)
                .unwrap_or(100_000);
            let mut outcome = crate::controller::AcuReplyOutcome::default();
            if let Some(i) = idx {
                c.handle_timeout(i, &mut outcome);
            }
            if let Some(slot) = self.controllers.get_mut(controller.index()) {
                *slot = Some(c);
            }
            (outcome, interval)
        };
        for ev in outcome.protocol {
            self.emit(RecordKind::Protocol {
                endpoint: Endpoint::Controller(controller),
                event: ev,
            });
        }
        let at = self.now.saturating_add(interval);
        self.schedule(at, SimEvent::AcuTick { controller });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Decisions and doors
    // -----------------------------------------------------------------------

    fn apply_decision(&mut self, controller: ControllerId, decision: CardDecision) -> Result<()> {
        let seq = self.emit(RecordKind::AccessDecision {
            controller,
            granted: decision.granted,
            bits: decision.bits,
            format: decision.format,
            reason: decision.reason,
        });
        if !decision.granted {
            return Ok(());
        }
        let door = self.controller(controller)?.door;
        if let Some(d) = door {
            let saved = self.cause;
            self.cause = Some(seq);
            let r = self.fire_strike(d, Some(controller));
            self.cause = saved;
            r?;
        }
        Ok(())
    }

    /// Release the strike.
    ///
    /// The one record the site treats as authoritative proof that a door
    /// opened, and therefore that an attack worked.
    pub fn fire_strike(&mut self, door: DoorId, controller: Option<ControllerId>) -> Result<()> {
        let (duration, token) = {
            let d = self.door_mut(door)?;
            d.lock = LockState::Unlocked;
            d.strike_count = d.strike_count.saturating_add(1);
            d.relock_token = d.relock_token.saturating_add(1);
            (d.strike_time_us, d.relock_token)
        };
        self.emit(RecordKind::StrikeFired {
            door,
            controller,
            duration_us: duration,
        });
        self.emit(RecordKind::DoorLock {
            door,
            locked: false,
        });
        self.schedule(
            self.now.saturating_add(duration),
            SimEvent::DoorRelock { door, token },
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Taps
    // -----------------------------------------------------------------------

    fn run_tap_bus(
        &mut self,
        tap: TapId,
        where_: (LinkId, u16),
        origin: Origin,
        dir: BusDir,
        bytes: &[u8],
        frame: Option<&Frame>,
    ) -> Result<TapVerdict> {
        let (link, segment) = where_;
        let obs = Observation {
            t_us: self.now,
            link,
            segment,
            origin,
            traffic: ObservedTraffic::Bus { dir, bytes, frame },
        };
        self.run_tap(tap, link, &obs)
    }

    fn run_tap_wire(
        &mut self,
        tap: TapId,
        link: LinkId,
        segment: u16,
        origin: Origin,
        kind: WireKind,
        bits: &BitVec,
    ) -> Result<TapVerdict> {
        let obs = Observation {
            t_us: self.now,
            link,
            segment,
            origin,
            traffic: ObservedTraffic::Wire { kind, bits },
        };
        self.run_tap(tap, link, &obs)
    }

    fn run_tap(&mut self, tap: TapId, link: LinkId, obs: &Observation<'_>) -> Result<TapVerdict> {
        let mut boxed = match self.taps.get_mut(tap.index()).and_then(|e| e.tap.take()) {
            Some(t) => t,
            None => return Err(BusError::UnknownTap(tap)),
        };
        let mut injections = Vec::new();
        let mut notes = Vec::new();
        let verdict = {
            let mut ctx = TapCtx {
                now: self.now,
                rng: &mut self.rng,
                injections: &mut injections,
                notes: &mut notes,
            };
            boxed.observe(&mut ctx, obs)
        };
        injections.extend(boxed.take_pending());
        if let Some(slot) = self.taps.get_mut(tap.index()) {
            slot.tap = Some(boxed);
        }
        for n in notes {
            self.emit(RecordKind::TapAction {
                tap,
                link,
                action: TapAction::Note(n),
            });
        }
        for inj in injections {
            self.queue_injection(tap, inj);
        }
        Ok(verdict)
    }

    fn reject_verdict_if_not_inline(&mut self, tap: TapId, link: LinkId, verdict: TapVerdict) {
        if verdict != TapVerdict::Pass {
            self.emit(RecordKind::TapAction {
                tap,
                link,
                action: TapAction::VerdictIgnored {
                    reason: "this tap does not cut the link, so it cannot change what crosses it",
                },
            });
        }
    }

    fn on_tap_inject(&mut self, tap: TapId, payload: InjectionPayload) -> Result<()> {
        let entry = match self.taps.get(tap.index()) {
            Some(e) => e,
            None => return Err(BusError::UnknownTap(tap)),
        };
        let link = entry.link;
        let kind = entry.kind;
        if !kind.can_transmit() {
            self.emit(RecordKind::TapAction {
                tap,
                link,
                action: TapAction::VerdictIgnored {
                    reason: "a passive tap cannot transmit",
                },
            });
            return Ok(());
        }
        let len = payload.len();
        let base = self.link(link)?.chain().segment_of_tap(tap).unwrap_or(0);
        self.emit(RecordKind::TapAction {
            tap,
            link,
            action: TapAction::Injected { len },
        });
        let now = self.now;
        match payload {
            InjectionPayload::BusBytes { dir, bytes } => {
                let segment = self.injection_segment(kind, base, Some(dir));
                self.bus_emit(link, segment, Origin::Tap(tap), dir, bytes, now)
            }
            InjectionPayload::BusFrame { dir, frame } => {
                let segment = self.injection_segment(kind, base, Some(dir));
                self.bus_emit(link, segment, Origin::Tap(tap), dir, frame.encode(), now)
            }
            InjectionPayload::WireBits { bits } => {
                let segment = self.injection_segment(kind, base, None);
                self.wire_emit(link, segment, Origin::Tap(tap), bits, now)
            }
        }
    }

    /// Which segment a tap's own transmission goes onto.
    ///
    /// A passive or injecting tap has exactly one, so it is that one. An
    /// inline tap has two — one on each side of the cut — and which one it
    /// drives follows from the direction it is sending: towards the
    /// peripherals means the far side, towards the controller means the near
    /// side. Bits on a two-wire link always travel towards the controller.
    fn injection_segment(&self, kind: TapKind, base: u16, dir: Option<BusDir>) -> u16 {
        if !kind.can_alter() {
            return base;
        }
        match dir {
            Some(BusDir::AcuToPd) => base.saturating_add(1),
            Some(BusDir::PdToAcu) | None => base,
        }
    }
}

/// Convenience: a controller's session stage for an address, for a drill
/// predicate that wants to say "the link reached steady state".
pub fn session_stage(world: &World, controller: ControllerId, address: u8) -> Option<SessionStage> {
    world
        .controller(controller)
        .ok()?
        .session(address)
        .map(|s| s.stage)
}

/// Convenience: build an OSDP controller with an access list in one call.
pub fn osdp_controller(
    id: ControllerId,
    name: &str,
    config: AcuConfig,
    access: AccessList,
) -> Controller {
    let mut c = Controller::osdp(id, name, config);
    c.access = access;
    c
}

/// Convenience: the mode of a controller, for a UI that wants to label it.
pub fn controller_mode_name(mode: &ControllerMode) -> &'static str {
    match mode {
        ControllerMode::Legacy => "legacy panel",
        ControllerMode::Osdp(_) => "osdp controller",
    }
}
