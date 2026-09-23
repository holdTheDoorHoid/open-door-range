//! **Taps — the reason this crate exists.**
//!
//! A tap is a device clipped onto a *link*, and where it sits is the whole
//! point. The topology strip in the UI draws it there because a learner who
//! has seen a box appear between the reader and the panel understands why an
//! inline implant works without being told (`docs/UI.md`).
//!
//! Three kinds, in increasing order of what they can do:
//!
//! | Kind | Sees | Can transmit | Can alter traffic |
//! |---|---|---|---|
//! | [`PassiveTap`] | everything on its segment | no | no |
//! | [`InjectingTap`] | everything on its segment | yes, and can collide | no |
//! | [`InlineTap`] | everything crossing it | yes, on both sides independently | yes |
//!
//! An [`InlineTap`] **cuts the link**. The two halves become separate
//! segments with separate electrical state, which is why the reader can keep
//! emitting a credential the controller never sees, and why a passive
//! bystander on the reader side observes something different from one on the
//! panel side. That is not a modelling convenience — it is the difference
//! between an implant and a sniffer.
//!
//! # Bytes and frames, both
//!
//! Every tap sees an [`Observation`] carrying **both** the raw octets and the
//! decoded frame when one decodes. Some drills work at byte level (curriculum
//! 2.1, labelling offsets) and some at protocol level (3.6, rewriting a
//! capability reply), and a tap should not have to choose.
//!
//! # The one-liner the downgrade attack needs
//!
//! ```
//! use odr_bus::{InlineTap, TapVerdict};
//! use odr_osdp::{Reply, PdCapabilities};
//!
//! // Rewrite one field of one reply type; pass everything else through.
//! let implant = InlineTap::rewrite_frames("downgrade", |frame| {
//!     if frame.reply_code() != Some(Reply::PdCap) {
//!         return false;
//!     }
//!     match PdCapabilities::decode(&frame.payload) {
//!         Ok(mut caps) => {
//!             let changed = caps.strip_security_capability();
//!             frame.payload = caps.encode();
//!             changed
//!         }
//!         Err(_) => false,
//!     }
//! });
//! assert_eq!(implant.name(), "downgrade");
//! # let _: TapVerdict = TapVerdict::Pass;
//! ```

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_osdp::rng::SeededRng;
use odr_osdp::Frame;
use odr_wiegand::BitVec;

use crate::ids::{BusDir, LinkId, Micros, Origin};
use crate::log::WireKind;
use crate::sched::{Injection, InjectionPayload};

/// Which of the three kinds a tap is.
///
/// Queryable on a live world through
/// [`World::tap_kind`](crate::World::tap_kind), because curriculum drill 1.4's
/// flag begins "the tap is inline".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TapKind {
    /// Observes and nothing else.
    Passive,
    /// Observes and can transmit onto the same segment, colliding with
    /// whatever else is talking.
    Injecting,
    /// Cuts the link and relays between the two halves, altering as it likes.
    Inline,
}

impl TapKind {
    /// True if this kind can transmit.
    pub fn can_transmit(self) -> bool {
        !matches!(self, TapKind::Passive)
    }

    /// True if this kind can alter traffic in flight.
    pub fn can_alter(self) -> bool {
        matches!(self, TapKind::Inline)
    }

    /// A short name for the UI.
    pub fn name(self) -> &'static str {
        match self {
            TapKind::Passive => "passive",
            TapKind::Injecting => "injecting",
            TapKind::Inline => "inline",
        }
    }
}

/// What a tap is looking at.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ObservedTraffic<'a> {
    /// Octets on an RS-485 bus.
    Bus {
        /// Which way they are travelling.
        dir: BusDir,
        /// The octets.
        bytes: &'a [u8],
        /// The OSDP frame they decode to, if they decode. `None` is itself
        /// information: a collision fragment, another protocol, or a frame
        /// with a broken CRC.
        frame: Option<&'a Frame>,
    },
    /// Bits on a Wiegand or clock-and-data pair, always travelling towards the
    /// controller.
    Wire {
        /// Which physical layer.
        kind: WireKind,
        /// The bits, in transmission order.
        bits: &'a BitVec,
    },
}

/// One piece of traffic, presented to a tap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Observation<'a> {
    /// When.
    pub t_us: Micros,
    /// Which link.
    pub link: LinkId,
    /// Which segment of that link. An inline tap sees traffic arriving on one
    /// side and decides whether it reaches the other.
    pub segment: u16,
    /// Who transmitted it. [`Origin::Tap`] means another tap did, which is how
    /// two implants on one link see each other.
    pub origin: Origin,
    /// What it is.
    pub traffic: ObservedTraffic<'a>,
}

impl<'a> Observation<'a> {
    /// The raw octets, for bus traffic.
    pub fn bytes(&self) -> Option<&'a [u8]> {
        match self.traffic {
            ObservedTraffic::Bus { bytes, .. } => Some(bytes),
            ObservedTraffic::Wire { .. } => None,
        }
    }

    /// The decoded OSDP frame, if there is one.
    pub fn frame(&self) -> Option<&'a Frame> {
        match self.traffic {
            ObservedTraffic::Bus { frame, .. } => frame,
            ObservedTraffic::Wire { .. } => None,
        }
    }

    /// The bits, for wire traffic.
    pub fn bits(&self) -> Option<&'a BitVec> {
        match self.traffic {
            ObservedTraffic::Wire { bits, .. } => Some(bits),
            ObservedTraffic::Bus { .. } => None,
        }
    }

    /// The direction, for bus traffic.
    pub fn dir(&self) -> Option<BusDir> {
        match self.traffic {
            ObservedTraffic::Bus { dir, .. } => Some(dir),
            ObservedTraffic::Wire { .. } => None,
        }
    }
}

/// What a tap decides should happen to the traffic it was shown.
///
/// Only an [`InlineTap`] can return anything other than [`TapVerdict::Pass`]
/// and have it mean something. A passive or injecting tap that tries gets a
/// [`TapAction::VerdictIgnored`](crate::TapAction::VerdictIgnored) record
/// instead of a silent no-op, because "a tap that does not cut the wire cannot
/// change what crosses it" is a thing the range should teach rather than hide.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TapVerdict {
    /// Forward unchanged.
    #[default]
    Pass,
    /// Swallow it. The far side never sees it.
    Drop,
    /// Forward these octets instead. Bus links only.
    ReplaceBytes(Vec<u8>),
    /// Forward this frame instead; it is encoded at forwarding time, so its
    /// CRC is recomputed. Bus links only.
    ///
    /// Replacing a frame that carried a MAC does **not** recompute the MAC —
    /// the tap has no session key. That is the correct behaviour and the
    /// reason the downgrade attack has to happen before the handshake.
    ReplaceFrame(Box<Frame>),
    /// Forward these bits instead. Wiegand and clock-and-data links only.
    ReplaceBits(BitVec),
}

/// What a tap keeps for itself: its own view of the wire.
///
/// `odr-attack` reads this rather than the world's event log when a drill's
/// flag depends on what an attacker could see from one probe point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenTraffic {
    /// When.
    pub t_us: Micros,
    /// Which link.
    pub link: LinkId,
    /// Which segment.
    pub segment: u16,
    /// Who transmitted it.
    pub origin: Origin,
    /// Direction, for bus traffic.
    pub dir: Option<BusDir>,
    /// Octets, for bus traffic.
    pub bytes: Vec<u8>,
    /// Bits, for wire traffic.
    pub bits: Option<BitVec>,
    /// Which physical layer, for wire traffic.
    pub wire_kind: Option<WireKind>,
}

impl SeenTraffic {
    /// Re-parse the octets as an OSDP frame.
    ///
    /// Parsed on demand rather than stored, so a sniffer's buffer stays the
    /// size of the wire traffic it saw.
    pub fn frame(&self) -> Option<Frame> {
        Frame::parse(&self.bytes).ok().map(|(f, _)| f)
    }

    fn from_observation(obs: &Observation<'_>) -> SeenTraffic {
        let (dir, bytes, bits, wire_kind) = match obs.traffic {
            ObservedTraffic::Bus { dir, bytes, .. } => (Some(dir), bytes.to_vec(), None, None),
            ObservedTraffic::Wire { bits, kind } => {
                (None, Vec::new(), Some(bits.clone()), Some(kind))
            }
        };
        SeenTraffic {
            t_us: obs.t_us,
            link: obs.link,
            segment: obs.segment,
            origin: obs.origin,
            dir,
            bytes,
            bits,
            wire_kind,
        }
    }
}

/// What a tap is handed while it decides.
///
/// It can look at the clock, draw reproducible pseudo-random values, schedule
/// transmissions of its own, and leave a note in the event log. It cannot
/// reach into the world, which is deliberate: a tap is a box on a wire, not an
/// oracle.
pub struct TapCtx<'a> {
    pub(crate) now: Micros,
    pub(crate) rng: &'a mut SeededRng,
    pub(crate) injections: &'a mut Vec<Injection>,
    pub(crate) notes: &'a mut Vec<String>,
}

impl TapCtx<'_> {
    /// The current virtual time.
    pub fn now(&self) -> Micros {
        self.now
    }

    /// The world's seeded PRNG. Using anything else breaks determinism.
    pub fn rng(&mut self) -> &mut SeededRng {
        self.rng
    }

    /// Transmit as soon as the medium allows.
    pub fn inject(&mut self, payload: InjectionPayload) {
        self.injections.push(Injection {
            at_us: self.now,
            payload,
        });
    }

    /// Transmit at a chosen time. A time in the past is treated as "now".
    pub fn inject_at(&mut self, at_us: Micros, payload: InjectionPayload) {
        self.injections.push(Injection {
            at_us: at_us.max(self.now),
            payload,
        });
    }

    /// Put octets on a bus.
    pub fn inject_bus(&mut self, dir: BusDir, bytes: Vec<u8>) {
        self.inject(InjectionPayload::BusBytes { dir, bytes });
    }

    /// Put an OSDP frame on a bus.
    pub fn inject_frame(&mut self, dir: BusDir, frame: Frame) {
        self.inject(InjectionPayload::BusFrame {
            dir,
            frame: Box::new(frame),
        });
    }

    /// Put bits on a Wiegand or clock-and-data pair.
    pub fn inject_bits(&mut self, bits: BitVec) {
        self.inject(InjectionPayload::WireBits { bits });
    }

    /// Leave a note in the event log, attributed to this tap.
    pub fn note(&mut self, text: impl Into<String>) {
        self.notes.push(text.into());
    }
}

/// A device on a link.
///
/// Implement this for a custom attacker or monitor. The three provided types
/// cover every drill in `docs/CURRICULUM.md`; this trait is here so
/// `odr-attack` and `odr-detect` can build their own without this crate
/// knowing about them.
pub trait Tap {
    /// A name for the UI and the log.
    fn name(&self) -> &str;

    /// Which of the three kinds this is. The engine enforces it: a tap that
    /// reports [`TapKind::Passive`] cannot transmit or alter traffic no matter
    /// what its `observe` returns.
    fn kind(&self) -> TapKind;

    /// Look at one piece of traffic and decide what happens to it.
    fn observe(&mut self, ctx: &mut TapCtx<'_>, obs: &Observation<'_>) -> TapVerdict;

    /// Hand over transmissions queued before the tap saw any traffic.
    ///
    /// Drained when the tap is added to a world and after every `observe`
    /// call, so a scripted replay can be loaded up front.
    fn take_pending(&mut self) -> Vec<Injection> {
        Vec::new()
    }

    /// Everything this tap has seen, if it keeps a record.
    fn seen(&self) -> &[SeenTraffic] {
        &[]
    }
}

// ---------------------------------------------------------------------------
// Passive
// ---------------------------------------------------------------------------

/// A tap that observes and changes nothing.
///
/// The Mellon "passive eavesdropping" attack is this type plus a reader of its
/// [`seen`](Tap::seen) buffer, and that is the finding: on an unsecured bus,
/// no interference is required.
#[derive(Debug, Clone, Default)]
pub struct PassiveTap {
    name: String,
    seen: Vec<SeenTraffic>,
    recording: bool,
}

impl PassiveTap {
    /// A recording passive tap.
    pub fn new(name: impl Into<String>) -> PassiveTap {
        PassiveTap {
            name: name.into(),
            seen: Vec::new(),
            recording: true,
        }
    }

    /// A passive tap that does not keep a buffer, for long runs where only the
    /// world's event log matters.
    pub fn silent(name: impl Into<String>) -> PassiveTap {
        PassiveTap {
            name: name.into(),
            seen: Vec::new(),
            recording: false,
        }
    }

    /// Everything observed so far.
    pub fn buffer(&self) -> &[SeenTraffic] {
        &self.seen
    }

    /// Forget everything observed so far.
    pub fn clear(&mut self) {
        self.seen.clear();
    }
}

impl Tap for PassiveTap {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> TapKind {
        TapKind::Passive
    }

    fn observe(&mut self, _ctx: &mut TapCtx<'_>, obs: &Observation<'_>) -> TapVerdict {
        if self.recording {
            self.seen.push(SeenTraffic::from_observation(obs));
        }
        TapVerdict::Pass
    }

    fn seen(&self) -> &[SeenTraffic] {
        &self.seen
    }
}

// ---------------------------------------------------------------------------
// Injecting
// ---------------------------------------------------------------------------

type Reaction = Box<dyn FnMut(&mut TapCtx<'_>, &Observation<'_>)>;

/// A tap that observes and can also transmit onto the same segment.
///
/// It shares the medium with everyone else, so on RS-485 it **can collide**,
/// and the engine models that honestly: two transmitters overlapping produce a
/// [`BusCollision`](crate::RecordKind::BusCollision) record and nothing usable
/// reaches anybody. An attacker who wants their frame to land has to find the
/// gap, which is exactly the constraint real bus injection works under.
///
/// On a Wiegand pair there is no arbitration at all: overlapping pulses are
/// glitches, and `odr-wiegand`'s decoder reports them.
pub struct InjectingTap {
    name: String,
    seen: Vec<SeenTraffic>,
    queue: Vec<Injection>,
    reaction: Option<Reaction>,
}

impl core::fmt::Debug for InjectingTap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InjectingTap")
            .field("name", &self.name)
            .field("seen", &self.seen.len())
            .field("queued", &self.queue.len())
            .field("reactive", &self.reaction.is_some())
            .finish()
    }
}

impl InjectingTap {
    /// An injecting tap with nothing queued.
    pub fn new(name: impl Into<String>) -> InjectingTap {
        InjectingTap {
            name: name.into(),
            seen: Vec::new(),
            queue: Vec::new(),
            reaction: None,
        }
    }

    /// An injecting tap that decides what to transmit from what it sees.
    ///
    /// The closure cannot alter traffic — only an [`InlineTap`] can — but it
    /// can transmit through [`TapCtx`], which is how a replay triggered by
    /// observing a real badge-in is written.
    pub fn reacting<F>(name: impl Into<String>, f: F) -> InjectingTap
    where
        F: FnMut(&mut TapCtx<'_>, &Observation<'_>) + 'static,
    {
        InjectingTap {
            name: name.into(),
            seen: Vec::new(),
            queue: Vec::new(),
            reaction: Some(Box::new(f)),
        }
    }

    /// Queue a transmission for a fixed time.
    pub fn with_injection(mut self, injection: Injection) -> InjectingTap {
        self.queue.push(injection);
        self
    }

    /// Queue several.
    pub fn with_injections(
        mut self,
        injections: impl IntoIterator<Item = Injection>,
    ) -> InjectingTap {
        self.queue.extend(injections);
        self
    }

    /// Everything observed so far.
    pub fn buffer(&self) -> &[SeenTraffic] {
        &self.seen
    }
}

impl Tap for InjectingTap {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> TapKind {
        TapKind::Injecting
    }

    fn observe(&mut self, ctx: &mut TapCtx<'_>, obs: &Observation<'_>) -> TapVerdict {
        self.seen.push(SeenTraffic::from_observation(obs));
        if let Some(f) = self.reaction.as_mut() {
            f(ctx, obs);
        }
        TapVerdict::Pass
    }

    fn take_pending(&mut self) -> Vec<Injection> {
        core::mem::take(&mut self.queue)
    }

    fn seen(&self) -> &[SeenTraffic] {
        &self.seen
    }
}

// ---------------------------------------------------------------------------
// Inline
// ---------------------------------------------------------------------------

/// The decision procedure inside an [`InlineTap`].
///
/// Implemented for every `FnMut(&mut TapCtx, &Observation) -> TapVerdict`, so
/// a closure is a policy.
pub trait TapPolicy {
    /// Decide what happens to one piece of traffic.
    fn decide(&mut self, ctx: &mut TapCtx<'_>, obs: &Observation<'_>) -> TapVerdict;
}

impl<F> TapPolicy for F
where
    F: FnMut(&mut TapCtx<'_>, &Observation<'_>) -> TapVerdict,
{
    fn decide(&mut self, ctx: &mut TapCtx<'_>, obs: &Observation<'_>) -> TapVerdict {
        self(ctx, obs)
    }
}

/// A tap that **cuts the link** and relays between the two halves.
///
/// This is the man-in-the-middle: independent transmit and receive on each
/// side, and a decision for every frame — pass, drop, modify, or substitute.
/// The Wiegand implant (curriculum 1.4) and the OSDP downgrade (3.6) are both
/// this type with a four-line policy.
pub struct InlineTap {
    name: String,
    seen: Vec<SeenTraffic>,
    policy: Box<dyn TapPolicy>,
}

impl core::fmt::Debug for InlineTap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InlineTap")
            .field("name", &self.name)
            .field("seen", &self.seen.len())
            .finish()
    }
}

impl InlineTap {
    /// An inline tap with an arbitrary policy.
    pub fn new<P: TapPolicy + 'static>(name: impl Into<String>, policy: P) -> InlineTap {
        InlineTap {
            name: name.into(),
            seen: Vec::new(),
            policy: Box::new(policy),
        }
    }

    /// An inline tap that changes nothing.
    ///
    /// Not useless: it proves the implant is transparent before it is armed,
    /// which is the first half of curriculum drill 1.4, and it still cuts the
    /// link, so the segments either side are electrically separate.
    pub fn pass_through(name: impl Into<String>) -> InlineTap {
        InlineTap::new(name, |_: &mut TapCtx<'_>, _: &Observation<'_>| {
            TapVerdict::Pass
        })
    }

    /// An inline tap that rewrites OSDP frames.
    ///
    /// The closure is handed a mutable copy of each frame that decodes and
    /// returns whether it changed anything. `false` passes the original bytes
    /// through untouched — including their original CRC — so a tap that only
    /// cares about one reply type does not disturb the rest of the bus.
    ///
    /// This is the shape the downgrade attack needs, and it is the reason
    /// [`TapVerdict::ReplaceFrame`] exists separately from
    /// [`TapVerdict::ReplaceBytes`].
    pub fn rewrite_frames<F>(name: impl Into<String>, mut f: F) -> InlineTap
    where
        F: FnMut(&mut Frame) -> bool + 'static,
    {
        InlineTap::new(
            name,
            move |_ctx: &mut TapCtx<'_>, obs: &Observation<'_>| match obs.frame() {
                Some(original) => {
                    let mut edited = original.clone();
                    if f(&mut edited) {
                        TapVerdict::ReplaceFrame(Box::new(edited))
                    } else {
                        TapVerdict::Pass
                    }
                }
                None => TapVerdict::Pass,
            },
        )
    }

    /// An inline tap that substitutes bit patterns on a Wiegand or
    /// clock-and-data pair.
    ///
    /// The closure returns `Some(replacement)` to swap a credential and `None`
    /// to let it through. This is the implant in the reader housing.
    pub fn substitute_bits<F>(name: impl Into<String>, mut f: F) -> InlineTap
    where
        F: FnMut(&BitVec) -> Option<BitVec> + 'static,
    {
        InlineTap::new(
            name,
            move |_ctx: &mut TapCtx<'_>, obs: &Observation<'_>| match obs.bits() {
                Some(bits) => match f(bits) {
                    Some(replacement) => TapVerdict::ReplaceBits(replacement),
                    None => TapVerdict::Pass,
                },
                None => TapVerdict::Pass,
            },
        )
    }

    /// An inline tap that drops whatever the predicate selects and passes the
    /// rest.
    pub fn dropping<F>(name: impl Into<String>, mut f: F) -> InlineTap
    where
        F: FnMut(&Observation<'_>) -> bool + 'static,
    {
        InlineTap::new(name, move |_ctx: &mut TapCtx<'_>, obs: &Observation<'_>| {
            if f(obs) {
                TapVerdict::Drop
            } else {
                TapVerdict::Pass
            }
        })
    }

    /// A name for the UI.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Everything observed so far.
    pub fn buffer(&self) -> &[SeenTraffic] {
        &self.seen
    }
}

impl Tap for InlineTap {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> TapKind {
        TapKind::Inline
    }

    fn observe(&mut self, ctx: &mut TapCtx<'_>, obs: &Observation<'_>) -> TapVerdict {
        self.seen.push(SeenTraffic::from_observation(obs));
        self.policy.decide(ctx, obs)
    }

    fn seen(&self) -> &[SeenTraffic] {
        &self.seen
    }
}

/// A tap built from a closure, of whichever kind you say it is.
///
/// The escape hatch for a one-off. Prefer the three named types: they say what
/// they are, and the UI draws them differently.
pub struct FnTap {
    name: String,
    kind: TapKind,
    f: Box<dyn TapPolicy>,
}

impl core::fmt::Debug for FnTap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FnTap")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish()
    }
}

impl FnTap {
    /// Build one.
    pub fn new<P: TapPolicy + 'static>(name: impl Into<String>, kind: TapKind, policy: P) -> FnTap {
        FnTap {
            name: name.into(),
            kind,
            f: Box::new(policy),
        }
    }
}

impl Tap for FnTap {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> TapKind {
        self.kind
    }

    fn observe(&mut self, ctx: &mut TapCtx<'_>, obs: &Observation<'_>) -> TapVerdict {
        self.f.decide(ctx, obs)
    }
}

/// A short description of a tap for the UI's topology strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapPlacement {
    /// Which link it is clipped to.
    pub link: LinkId,
    /// Which kind it is.
    pub kind: TapKind,
    /// Its name.
    pub name: String,
    /// The segment on the controller side of it. For a passive or injecting
    /// tap this equals [`segment_reader_side`](TapPlacement::segment_reader_side):
    /// it does not cut anything.
    pub segment_controller_side: u16,
    /// The segment on the reader side of it.
    pub segment_reader_side: u16,
    /// Position among the taps on this link, counting from the reader end.
    pub position: u16,
}

impl TapPlacement {
    /// True if this tap splits the link.
    pub fn cuts_link(&self) -> bool {
        self.kind.can_alter()
    }

    /// A one-line description, in the register the topology strip uses.
    pub fn describe(&self) -> String {
        let mut s = String::new();
        s.push_str(self.kind.name());
        s.push_str(" tap \"");
        s.push_str(&self.name);
        s.push('"');
        if self.cuts_link() {
            s.push_str(" (cuts the link)");
        }
        s.push_str(" on ");
        s.push_str(&self.link.to_string());
        s
    }
}
