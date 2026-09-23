//! **The event log — the primary output of this crate.**
//!
//! Every state change in the world lands here as a timestamped
//! [`LogRecord`]. The site's timeline and traffic list are rendered straight
//! from it; `odr-detect` draws its conclusions from it; `odr-scenario`
//! evaluates flag predicates against it. It is not debug output, and nothing in
//! the engine changes state without recording why.
//!
//! # Shape
//!
//! ```text
//! LogRecord { seq, t_us, cause, kind }
//!               │     │     │      └── what happened
//!               │     │     └───────── the seq of the record that caused this one
//!               │     └─────────────── virtual microseconds
//!               └───────────────────── strictly increasing, assigned in order
//! ```
//!
//! `seq` is the tie-break: two records can share a `t_us` (a frame is
//! transmitted and a tap notes it in the same microsecond) and `seq` says which
//! the engine did first. It is also stable across runs of the same seeded
//! scenario, which is what makes a determinism test meaningful.
//!
//! `cause` is what turns the log into a graph rather than a list. "The PD ACKed
//! a command originated by the attacker" (curriculum drill 2.3) is
//! [`EventLog::originator`] on the ACK's `seq` coming back
//! [`Origin::Tap`].
//!
//! # Queries
//!
//! [`EventLog`] carries the query helpers the curriculum's flag predicates
//! need. They are deliberately small and composable: `records()` is public, and
//! anything not covered here is an iterator chain away.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use odr_osdp::{Frame, KeyType};
use odr_wiegand::clock_data::ClockDataAnomaly;
use odr_wiegand::{BitVec, TimingAnomaly};

use crate::credential::FormatId;
use crate::ids::{
    BusDir, ControllerId, DoorId, Endpoint, LinkId, Micros, Origin, ReaderId, SourceId, TapId,
};

/// Which physical layer a wire record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WireKind {
    /// Wiegand D0/D1.
    Wiegand,
    /// Clock-and-data (ABA track 2).
    ClockData,
}

impl WireKind {
    /// A short name for the UI.
    pub fn name(self) -> &'static str {
        match self {
            WireKind::Wiegand => "wiegand",
            WireKind::ClockData => "clock-and-data",
        }
    }
}

/// Something that went wrong electrically on a two-wire link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineAnomaly {
    /// A D0/D1 timing problem.
    Wiegand(TimingAnomaly),
    /// A clock-and-data timing problem.
    ClockData(ClockDataAnomaly),
}

/// What a tap did to traffic passing it.
///
/// Observation is not recorded here — a tap on a segment observes everything on
/// that segment by definition, and the `BusTx`/`WireTx` records already say
/// what there was to see. Only *interference* is an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapAction {
    /// The tap swallowed traffic that would otherwise have been forwarded.
    Dropped {
        /// A description of what was dropped, for the UI.
        what: String,
    },
    /// The tap forwarded different bytes than it received.
    Replaced {
        /// What arrived.
        before: Vec<u8>,
        /// What left.
        after: Vec<u8>,
    },
    /// The tap forwarded a different bit pattern than it received, on a
    /// Wiegand or clock-and-data link.
    ReplacedBits {
        /// What arrived.
        before: BitVec,
        /// What left.
        after: BitVec,
    },
    /// The tap transmitted traffic of its own.
    Injected {
        /// How many bytes or bits, for the UI summary.
        len: usize,
    },
    /// The tap asked to change traffic but is not inline, so the request had
    /// no effect.
    ///
    /// This is recorded rather than silently ignored because "a passive tap
    /// cannot alter the wire" is a thing the range is supposed to teach, and a
    /// learner who wrote a modifying passive tap should see why nothing
    /// happened.
    VerdictIgnored {
        /// Why it was ignored.
        reason: &'static str,
    },
    /// A free-text note from the tap.
    Note(String),
}

/// Why a secure channel was not attempted or did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScDecline {
    /// The controller's policy is "never".
    PolicyDisabled,
    /// The PD's capability reply did not claim AES-128 support.
    ///
    /// **This is the downgrade attack's footprint.** A controller configured to
    /// require Secure Channel records this and then carries on in the clear,
    /// because it believed an unauthenticated `PDCAP` reply. A passive monitor
    /// that sees a PD go from claiming AES-128 to not claiming it has seen the
    /// attack (curriculum 5.2).
    PdDoesNotClaimAes128,
    /// The controller has not yet asked for capabilities.
    CapabilitiesUnknown,
    /// The handshake was attempted and the PD failed it.
    HandshakeFailed,
}

/// A secure-channel lifecycle event at one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScEvent {
    /// The controller began a handshake with this address.
    Requested {
        /// PD address.
        address: u8,
        /// Which key the handshake claims to use.
        key_type: KeyType,
    },
    /// The handshake completed and traffic from here on is secured.
    Established {
        /// PD address.
        address: u8,
        /// Which key was used.
        key_type: KeyType,
        /// Whether payloads will actually be encrypted (SCS_17/18) as opposed
        /// to merely MACed (SCS_15/16, the null ciphers).
        encrypted: bool,
    },
    /// The handshake failed.
    Failed {
        /// PD address.
        address: u8,
        /// A description of the failure.
        reason: String,
    },
    /// No handshake was attempted.
    Declined {
        /// PD address.
        address: u8,
        /// Why.
        reason: ScDecline,
    },
    /// The session was torn down, usually by a timeout or a sequence reset.
    Dropped {
        /// PD address.
        address: u8,
    },
    /// A `CMD_KEYSET` was sent, pushing a new SCBK to the PD.
    KeysetSent {
        /// PD address.
        address: u8,
        /// Whether it went out inside an established secure channel. `false`
        /// is the keyset-capture weakness (curriculum 3.5): the site key
        /// crossed the bus in the clear.
        secured: bool,
    },
    /// The PD accepted a new SCBK.
    KeysetAccepted {
        /// PD address.
        address: u8,
    },
}

/// A protocol-level event on an OSDP link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolEvent {
    /// A command went out to an address.
    CommandSent {
        /// PD address.
        address: u8,
        /// The command id byte.
        command: u8,
        /// The sequence number used.
        sequence: u8,
        /// Whether it was secured.
        secured: bool,
    },
    /// A reply came back.
    ReplyReceived {
        /// PD address.
        address: u8,
        /// The reply id byte.
        reply: u8,
        /// The sequence number carried.
        sequence: u8,
        /// Whether it was secured.
        secured: bool,
    },
    /// No reply arrived inside the timeout.
    ReplyTimeout {
        /// PD address.
        address: u8,
        /// Which attempt this was, counting from 1.
        attempt: u8,
    },
    /// The controller gave up on an address.
    PdOffline {
        /// PD address.
        address: u8,
    },
    /// The controller heard from an address it had given up on.
    PdOnline {
        /// PD address.
        address: u8,
    },
    /// The PD said `REPLY_BUSY`.
    Busy {
        /// PD address.
        address: u8,
    },
    /// The PD said `REPLY_NAK`.
    Nak {
        /// PD address.
        address: u8,
        /// The NAK error code.
        error: u8,
    },
    /// A frame arrived with a sequence number the receiver did not expect.
    SequenceMismatch {
        /// PD address.
        address: u8,
        /// What the receiver wanted.
        expected: u8,
        /// What arrived.
        got: u8,
    },
    /// Both ends agreed to restart from sequence zero.
    SequenceReset {
        /// PD address.
        address: u8,
    },
    /// The PD reported its capabilities.
    CapabilitiesReported {
        /// PD address.
        address: u8,
        /// Whether the report claims AES-128.
        claims_aes128: bool,
        /// Whether the report admits to the default key.
        uses_default_key: bool,
    },
    /// The PD reported a card read.
    CardReadReported {
        /// PD address.
        address: u8,
        /// The format code byte from `REPLY_RAW`.
        format_code: u8,
        /// How many bits.
        bit_count: u16,
    },
    /// A frame was received that the receiver could not use.
    FrameRejected {
        /// PD address, if known.
        address: u8,
        /// Why.
        reason: String,
    },
}

/// Why a controller granted or denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    /// The bits matched an access-list entry.
    Matched {
        /// The entry's label, if it had one.
        label: Option<String>,
    },
    /// The bits did not match any entry.
    NoMatch,
    /// The policy grants everything. Useful for drills about the wire rather
    /// than about authorisation.
    AllowAll,
    /// The policy denies everything.
    DenyAll,
    /// The frame arrived but could not be read as a credential at all.
    Unreadable {
        /// A description of the problem.
        detail: String,
    },
    /// Parity failed and the controller is configured to reject on parity.
    ParityRejected,
}

/// What happened.
///
/// Records are additive: a new variant may appear in a later version, so match
/// with a `_` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordKind {
    /// The simulation began. Always the first record, and it carries the seed,
    /// so a log identifies the run that produced it.
    Started {
        /// The seed the world was built with.
        seed: u64,
    },
    /// A token was presented to a reader.
    CredentialPresented {
        /// Which reader.
        reader: ReaderId,
        /// Which physical token.
        source: SourceId,
        /// What the bits claim to be.
        format: FormatId,
        /// The bits the token produced.
        bits: BitVec,
        /// A human label, if the scenario gave one.
        label: Option<String>,
    },
    /// A token was presented and the reader did not produce anything — out of
    /// range, wrong technology, or a card that refused.
    CredentialRejected {
        /// Which reader.
        reader: ReaderId,
        /// Which physical token.
        source: SourceId,
        /// Why.
        reason: String,
    },
    /// Bits were driven onto one segment of a two-wire link.
    WireTx {
        /// Which link.
        link: LinkId,
        /// Which segment, counting from the reader end. Segments exist because
        /// an inline tap cuts the link in two.
        segment: u16,
        /// Who drove them.
        origin: Origin,
        /// Wiegand or clock-and-data.
        kind: WireKind,
        /// The bits, in transmission order.
        bits: BitVec,
    },
    /// A frame was recovered at the receiving end of a wire segment.
    WireRx {
        /// Which link.
        link: LinkId,
        /// Which segment.
        segment: u16,
        /// Who received it.
        receiver: Endpoint,
        /// Wiegand or clock-and-data.
        kind: WireKind,
        /// The bits as recovered, which need not equal what was transmitted.
        bits: BitVec,
        /// When the first edge arrived.
        start_us: Micros,
        /// When the last edge arrived.
        end_us: Micros,
    },
    /// Something was wrong electrically.
    WireAnomaly {
        /// Which link.
        link: LinkId,
        /// Which segment.
        segment: u16,
        /// What was wrong.
        anomaly: LineAnomaly,
    },
    /// Bytes were driven onto one segment of an RS-485 bus.
    BusTx {
        /// Which link.
        link: LinkId,
        /// Which segment, counting from the controller end.
        segment: u16,
        /// Who drove them.
        origin: Origin,
        /// Which way they were travelling.
        dir: BusDir,
        /// The octets, exactly as they went out.
        bytes: Vec<u8>,
        /// The frame those octets decode to, if they decode.
        frame: Option<Box<Frame>>,
    },
    /// Bytes were delivered to a listener on a bus segment.
    BusRx {
        /// Which link.
        link: LinkId,
        /// Which segment.
        segment: u16,
        /// Who received them.
        receiver: Endpoint,
        /// Which way they were travelling.
        dir: BusDir,
        /// The octets as received.
        bytes: Vec<u8>,
        /// The frame those octets decode to, if they decode.
        frame: Option<Box<Frame>>,
    },
    /// Two transmitters were driving the same segment at the same time, so
    /// nothing usable reached anybody.
    BusCollision {
        /// Which link.
        link: LinkId,
        /// Which segment.
        segment: u16,
        /// Everyone who was transmitting.
        origins: Vec<Origin>,
    },
    /// A tap interfered with traffic.
    TapAction {
        /// Which tap.
        tap: TapId,
        /// Which link it sits on.
        link: LinkId,
        /// What it did.
        action: TapAction,
    },
    /// A secure-channel lifecycle event.
    SecureChannel {
        /// Where it happened.
        endpoint: Endpoint,
        /// What happened.
        event: ScEvent,
    },
    /// A protocol-level event on an OSDP link.
    Protocol {
        /// Where it happened.
        endpoint: Endpoint,
        /// What happened.
        event: ProtocolEvent,
    },
    /// A controller decided whether to open a door.
    AccessDecision {
        /// Which controller.
        controller: ControllerId,
        /// The verdict.
        granted: bool,
        /// The bits it decided on, as it received them.
        bits: BitVec,
        /// What it believed the format was.
        format: FormatId,
        /// Why.
        reason: DecisionReason,
    },
    /// **The strike fired.** The authoritative record of a door being opened,
    /// and therefore of a successful attack.
    StrikeFired {
        /// Which door.
        door: DoorId,
        /// Which controller drove it, if any. `None` means something else did
        /// — a request-to-exit, or a manual override.
        controller: Option<ControllerId>,
        /// How long the strike will be held.
        duration_us: Micros,
    },
    /// The door's lock state changed.
    DoorLock {
        /// Which door.
        door: DoorId,
        /// True if it is now locked.
        locked: bool,
    },
    /// The door's position switch changed.
    DoorPosition {
        /// Which door.
        door: DoorId,
        /// True if the door leaf is now open.
        open: bool,
    },
    /// The request-to-exit input changed.
    RequestToExit {
        /// Which door.
        door: DoorId,
        /// True if REX is now asserted.
        asserted: bool,
    },
    /// A note from the scenario or a drill. Never affects behaviour.
    Note {
        /// The text.
        text: String,
    },
}

/// One entry in the event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// Position in the log, assigned in order and starting at zero.
    pub seq: u64,
    /// Virtual microseconds.
    pub t_us: Micros,
    /// The record that caused this one, if the engine knew.
    pub cause: Option<u64>,
    /// What happened.
    pub kind: RecordKind,
}

impl LogRecord {
    /// The link this record concerns, if it concerns one.
    pub fn link(&self) -> Option<LinkId> {
        match &self.kind {
            RecordKind::WireTx { link, .. }
            | RecordKind::WireRx { link, .. }
            | RecordKind::WireAnomaly { link, .. }
            | RecordKind::BusTx { link, .. }
            | RecordKind::BusRx { link, .. }
            | RecordKind::BusCollision { link, .. }
            | RecordKind::TapAction { link, .. } => Some(*link),
            _ => None,
        }
    }

    /// Who drove this onto a medium, if anybody.
    pub fn origin(&self) -> Option<Origin> {
        match &self.kind {
            RecordKind::WireTx { origin, .. } | RecordKind::BusTx { origin, .. } => Some(*origin),
            _ => None,
        }
    }

    /// The OSDP frame this record carries, if it carries one.
    pub fn frame(&self) -> Option<&Frame> {
        match &self.kind {
            RecordKind::BusTx { frame, .. } | RecordKind::BusRx { frame, .. } => frame.as_deref(),
            _ => None,
        }
    }

    /// True if this record is traffic driven onto a medium, as opposed to
    /// traffic received or an internal state change.
    ///
    /// This is the set the capture format exports; see
    /// [`crate::capture::export_ndjson`].
    pub fn is_transmission(&self) -> bool {
        matches!(
            self.kind,
            RecordKind::WireTx { .. } | RecordKind::BusTx { .. }
        )
    }
}

/// The world's observable output.
///
/// Records are append-only and never reordered. Cloning a log is cheap enough
/// for a determinism test to hold two of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventLog {
    records: Vec<LogRecord>,
}

impl EventLog {
    /// An empty log.
    pub fn new() -> EventLog {
        EventLog {
            records: Vec::new(),
        }
    }

    /// Append a record and return its `seq`.
    pub(crate) fn push(&mut self, t_us: Micros, cause: Option<u64>, kind: RecordKind) -> u64 {
        let seq = self.records.len() as u64;
        self.records.push(LogRecord {
            seq,
            t_us,
            cause,
            kind,
        });
        seq
    }

    /// Every record, in order.
    pub fn records(&self) -> &[LogRecord] {
        &self.records
    }

    /// How many records there are.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True if nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// One record by `seq`.
    pub fn get(&self, seq: u64) -> Option<&LogRecord> {
        self.records.get(seq as usize)
    }

    /// Records whose timestamp falls in `[from, to)`.
    pub fn between(&self, from: Micros, to: Micros) -> impl Iterator<Item = &LogRecord> {
        self.records
            .iter()
            .filter(move |r| r.t_us >= from && r.t_us < to)
    }

    /// Records matching a predicate.
    pub fn find<'a, F>(&'a self, pred: F) -> impl Iterator<Item = &'a LogRecord>
    where
        F: Fn(&LogRecord) -> bool + 'a,
    {
        self.records.iter().filter(move |r| pred(r))
    }

    /// Every credential presentation.
    ///
    /// The denominator for "the controller granted when no credential was
    /// presented" (curriculum 1.3) and for "the original was never presented"
    /// (0.2).
    pub fn presentations(&self) -> impl Iterator<Item = &LogRecord> {
        self.find(|r| matches!(r.kind, RecordKind::CredentialPresented { .. }))
    }

    /// Every access decision.
    pub fn decisions(&self) -> impl Iterator<Item = &LogRecord> {
        self.find(|r| matches!(r.kind, RecordKind::AccessDecision { .. }))
    }

    /// Every grant.
    pub fn grants(&self) -> impl Iterator<Item = &LogRecord> {
        self.find(|r| matches!(r.kind, RecordKind::AccessDecision { granted: true, .. }))
    }

    /// Every strike fire — the authoritative record of a door opening.
    pub fn strikes(&self) -> impl Iterator<Item = &LogRecord> {
        self.find(|r| matches!(r.kind, RecordKind::StrikeFired { .. }))
    }

    /// Every transmission onto a medium, which is what a capture contains.
    pub fn transmissions(&self) -> impl Iterator<Item = &LogRecord> {
        self.find(|r| r.is_transmission())
    }

    /// Every OSDP frame that went onto a bus, with the direction it travelled.
    pub fn bus_frames(&self) -> impl Iterator<Item = (&LogRecord, BusDir, &Frame)> {
        self.records.iter().filter_map(|r| match &r.kind {
            RecordKind::BusTx {
                dir,
                frame: Some(f),
                ..
            } => Some((r, *dir, f.as_ref())),
            _ => None,
        })
    }

    /// Everything a given tap transmitted.
    ///
    /// "Zero frames injected" (curriculum 2.2) is this iterator being empty.
    pub fn injected_by(&self, tap: TapId) -> impl Iterator<Item = &LogRecord> {
        self.find(move |r| r.origin() == Some(Origin::Tap(tap)))
    }

    /// How many transmissions a tap made.
    pub fn injection_count(&self, tap: TapId) -> usize {
        self.injected_by(tap).count()
    }

    /// Everything a given tap did to traffic that was not its own.
    pub fn actions_by(&self, tap: TapId) -> impl Iterator<Item = &LogRecord> {
        self.find(move |r| matches!(&r.kind, RecordKind::TapAction { tap: t, .. } if *t == tap))
    }

    /// Walk `cause` back from a record to the root that started the chain.
    ///
    /// The returned vector starts with the record itself and ends with the
    /// root. A cycle (which should be impossible, since `cause` always points
    /// at an earlier `seq`) terminates the walk rather than hanging.
    pub fn cause_chain(&self, seq: u64) -> Vec<&LogRecord> {
        let mut out = Vec::new();
        let mut cursor = Some(seq);
        while let Some(s) = cursor {
            let rec = match self.get(s) {
                Some(r) => r,
                None => break,
            };
            out.push(rec);
            cursor = match rec.cause {
                Some(c) if c < s => Some(c),
                _ => None,
            };
        }
        out
    }

    /// Who provoked a record: the [`Origin`] of the nearest transmission in
    /// its cause chain, **not counting the record itself**.
    ///
    /// This is how "the PD ACKed a command originated by the attacker actor"
    /// (curriculum 2.3) is answered: take the ACK's `seq`, ask who provoked
    /// it, and check for [`Origin::Tap`]. Skipping the
    /// record itself is the whole point — an ACK's own origin is the PD, and
    /// the interesting question is what made it speak.
    ///
    /// Use [`EventLog::root_origin`] for the far end of the chain instead.
    pub fn originator(&self, seq: u64) -> Option<Origin> {
        self.cause_chain(seq)
            .into_iter()
            .skip(1)
            .find_map(|r| r.origin())
    }

    /// The [`Origin`] at the far end of a record's cause chain.
    ///
    /// On a live bus this is usually the transmission that started the whole
    /// conversation, so it is a blunter instrument than
    /// [`EventLog::originator`]; it is here for tracing a chain to its root in
    /// the UI.
    pub fn root_origin(&self, seq: u64) -> Option<Origin> {
        self.cause_chain(seq)
            .into_iter()
            .filter_map(|r| r.origin())
            .next_back()
    }

    /// The timestamp of the last record, or zero for an empty log.
    pub fn last_t_us(&self) -> Micros {
        self.records.last().map(|r| r.t_us).unwrap_or(0)
    }
}
