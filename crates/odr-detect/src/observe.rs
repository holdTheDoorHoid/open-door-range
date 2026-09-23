//! **What a passive monitor on the link actually has.**
//!
//! This module is the governing rule of the crate, expressed as a type. A
//! [`Monitor`] is a list of [`Observation`]s: a timestamp, which line, which
//! direction, and the octets or bits. Nothing else. There is no node
//! configuration in here, no key, no access list, no `cause` field, and no way
//! to ask the engine what really happened.
//!
//! That restriction is the whole point of curriculum Module 5. A detector that
//! quietly read the world's own state would score perfectly against every drill
//! and teach nothing, because a defender standing in a riser with an RS-485
//! dongle does not have the world's own state. They have this.
//!
//! # Two ways in, and what each one drops
//!
//! * [`Monitor::from_capture`] parses the newline-delimited JSON of
//!   `DESIGN.md` §3. This is the honest route and the one the provenance tests
//!   use: a capture is a file, and a file cannot smuggle ground truth.
//! * [`Monitor::from_tap`] reads a live [`PassiveTap`](odr_bus::PassiveTap)'s
//!   buffer. It is the same information, and it **deliberately discards
//!   [`Origin`](odr_bus::Origin)** — the world knows a frame came from a tap
//!   rather than from the controller, and a monitor clipped to the pair does
//!   not. Keeping that field would make every injection detector trivially
//!   correct and completely useless.
//!
//! # Direction is not cheating
//!
//! RS-485 is one differential pair and a probe on it cannot tell which
//! transceiver drove the line. The capture format carries a `dir` field
//! anyway, and that is fine, because bit 7 of the OSDP address byte says
//! whether a frame is a reply — so direction is recoverable from the bytes
//! themselves. [`Observation::direction`] prefers the frame's own reply bit and
//! falls back to the file's claim, which means a detector's conclusions do not
//! depend on a field a real probe would have had to infer.
//!
//! # What the format costs us
//!
//! A Wiegand capture is byte-padded, so the original bit count is gone (see
//! `odr-bus`'s `capture` module). [`Observation::bits`] holds the most
//! plausible reading — parity-valid in a known card format, best first — and
//! [`Observation::wiegand_candidates`] hands back all of them. A detector that
//! cares about the difference must say so in its confidence.

use alloc::string::String;
use alloc::vec::Vec;

use odr_bus::capture::{pack_bits, parse_ndjson, to_hex};
use odr_bus::log::WireKind;
use odr_bus::{BusDir, CaptureDir, CaptureEvent, CaptureLine, Micros, Tap};
use odr_osdp::frame::{ScanEvent, Scanner};
use odr_osdp::{Command, Frame, Reply, ScsType};
use odr_wiegand::BitVec;

use crate::error::Result;

/// One thing a monitor saw on the link.
///
/// Constructed only by a [`Monitor`], so the `index` is always a valid handle
/// back into the stream that produced it. That is what makes
/// [`Evidence`](crate::Evidence) checkable.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    /// Position in the monitor's stream, counting from zero.
    ///
    /// This is the evidence handle. A finding cites indices, and
    /// [`Evidence::check`](crate::Evidence::check) re-reads them.
    pub index: usize,
    /// Virtual microseconds, as the capture recorded them.
    pub t_us: Micros,
    /// Which physical line.
    pub line: CaptureLine,
    /// Which direction the capture claims. Prefer [`Observation::direction`].
    pub dir: CaptureDir,
    /// The octets, exactly as they were on the line.
    pub bytes: Vec<u8>,
    /// The OSDP frame these octets decode to, if they decode.
    ///
    /// `None` on a bus is itself information: a collision fragment, another
    /// protocol, or a frame with a broken CRC.
    pub frame: Option<Frame>,
    /// The most plausible bit reading, for a two-wire line.
    ///
    /// See the module docs: the capture format does not carry a bit count, so
    /// this is an inference and not a fact.
    pub bits: Option<BitVec>,
}

impl Observation {
    /// True if this was on an RS-485 bus.
    pub fn is_bus(&self) -> bool {
        self.line.is_bus()
    }

    /// True if this was on a Wiegand or clock-and-data pair.
    pub fn is_wire(&self) -> bool {
        matches!(self.line, CaptureLine::Wiegand | CaptureLine::ClockData)
    }

    /// Which way it was travelling, preferring the frame's own reply bit over
    /// the capture file's claim.
    pub fn direction(&self) -> CaptureDir {
        match &self.frame {
            Some(f) if self.is_bus() => {
                if f.is_reply {
                    CaptureDir::PdToAcu
                } else {
                    CaptureDir::AcuToPd
                }
            }
            _ => self.dir.clone(),
        }
    }

    /// The bus direction, for bus traffic.
    pub fn bus_dir(&self) -> Option<BusDir> {
        self.direction().bus_dir()
    }

    /// True if this is a command travelling from the controller.
    pub fn is_command(&self) -> bool {
        self.bus_dir() == Some(BusDir::AcuToPd)
    }

    /// True if this is a reply travelling towards the controller.
    pub fn is_reply(&self) -> bool {
        self.bus_dir() == Some(BusDir::PdToAcu)
    }

    /// The peripheral address this frame concerns, with the reply bit masked
    /// off.
    pub fn address(&self) -> Option<u8> {
        self.frame.as_ref().map(|f| f.address & 0x7F)
    }

    /// The two-bit sequence number, if this is a frame.
    pub fn sequence(&self) -> Option<u8> {
        self.frame.as_ref().map(|f| f.sequence & 0x03)
    }

    /// The command code, if this is a command that carries a known one.
    pub fn command(&self) -> Option<Command> {
        self.frame.as_ref().and_then(|f| f.command_code())
    }

    /// The reply code, if this is a reply that carries a known one.
    pub fn reply(&self) -> Option<Reply> {
        self.frame.as_ref().and_then(|f| f.reply_code())
    }

    /// The security block type, if the frame carried a security block with a
    /// type byte this crate knows.
    pub fn scs(&self) -> Option<ScsType> {
        self.frame.as_ref().and_then(|f| f.scs_type())
    }

    /// True if the frame carried a security block at all.
    ///
    /// The difference between this and [`Observation::scs`] matters: a block
    /// with an unrecognised type byte still means "this link is doing
    /// something secure-channel shaped".
    pub fn has_security_block(&self) -> bool {
        self.frame.as_ref().is_some_and(|f| f.security.is_some())
    }

    /// True if the frame's payload was encrypted — SCS_17 or SCS_18, and not
    /// the null ciphers.
    pub fn is_encrypted(&self) -> bool {
        self.frame.as_ref().is_some_and(|f| f.is_encrypted())
    }

    /// True if this frame is one of the four secure-channel handshake types.
    pub fn is_handshake(&self) -> bool {
        self.scs().is_some_and(|s| s.is_handshake())
    }

    /// True if this frame is an in-session secured frame — SCS_15 through
    /// SCS_18, the four types that only exist once a handshake has completed.
    pub fn is_in_session(&self) -> bool {
        self.scs().is_some_and(|s| !s.is_handshake())
    }

    /// Every plausible bit reading of a two-wire event, parity-valid first.
    ///
    /// Empty for bus traffic.
    pub fn wiegand_candidates(&self) -> Vec<BitVec> {
        if !self.is_wire() {
            return Vec::new();
        }
        CaptureEvent {
            t_us: self.t_us,
            line: self.line.clone(),
            dir: self.dir.clone(),
            bytes: self.bytes.clone(),
        }
        .wiegand_candidates()
    }

    /// The octets as lowercase hex, for an evidence note.
    pub fn hex(&self) -> String {
        to_hex(&self.bytes)
    }

    /// A one-line description, in the register the traffic list uses.
    ///
    /// ```
    /// use odr_detect::Monitor;
    ///
    /// let line = r#"{"t_us":1000,"line":"rs485","dir":"acu_to_pd","bytes":"530108000460ba00"}"#;
    /// let monitor = Monitor::from_capture(line).unwrap();
    /// let poll = &monitor.observations()[0];
    /// assert!(poll.summary().contains("POLL"));
    /// assert!(poll.summary().contains("ACU->PD"));
    /// ```
    pub fn summary(&self) -> String {
        let mut s = alloc::format!("#{} t={}", self.index, fmt_us(self.t_us));
        match (&self.line, &self.frame) {
            (CaptureLine::Rs485, Some(f)) => {
                s.push_str(if f.is_reply { " PD->ACU" } else { " ACU->PD" });
                s.push_str(&alloc::format!(
                    " addr {:#04x} seq {} {}",
                    f.address & 0x7F,
                    f.sequence & 0x03,
                    frame_name(f)
                ));
                if let Some(scs) = f.scs_type() {
                    s.push_str(&alloc::format!(" [SCS_{:02X}]", scs.to_u8()));
                } else if f.security.is_some() {
                    s.push_str(" [unknown security block]");
                }
            }
            (CaptureLine::Rs485, None) => {
                s.push_str(&alloc::format!(
                    " rs485 {} undecodable bytes",
                    self.bytes.len()
                ));
            }
            (line, _) => {
                s.push_str(&alloc::format!(" {line} "));
                match &self.bits {
                    Some(b) => {
                        s.push_str(&alloc::format!("{} bits {}", b.len(), b.to_hex_string()))
                    }
                    None => s.push_str(&self.hex()),
                }
            }
        }
        s
    }
}

/// The name of whatever a frame carries, for a summary line.
fn frame_name(f: &Frame) -> String {
    if f.is_reply {
        match f.reply_code() {
            Some(r) => String::from(r.name()),
            None => alloc::format!("reply {:#04x}", f.id),
        }
    } else {
        match f.command_code() {
            Some(c) => String::from(c.name()),
            None => alloc::format!("command {:#04x}", f.id),
        }
    }
}

/// Virtual microseconds as seconds with six decimal places.
///
/// Written out by hand because `core::fmt` has no fixed-point formatter and
/// this crate has no business pulling in a float one.
pub fn fmt_us(t_us: Micros) -> String {
    alloc::format!("{}.{:06}s", t_us / 1_000_000, t_us % 1_000_000)
}

/// **Everything a passive monitor on one link recorded.**
///
/// One monitor is one probe point. A world with two links, or one link cut by
/// an inline implant, needs two monitors, because a probe clipped to one pair
/// cannot hear the other — and pretending otherwise is how a detector ends up
/// concluding things a defender could not have.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Monitor {
    observations: Vec<Observation>,
}

impl Monitor {
    /// An empty monitor.
    pub fn new() -> Monitor {
        Monitor {
            observations: Vec::new(),
        }
    }

    /// Parse a capture file in the format `DESIGN.md` §3 fixes.
    ///
    /// **This is the honest constructor.** A capture is a file of timestamps
    /// and hex; there is nowhere in it to hide the engine's opinion of what
    /// happened. Every detector in this crate has a test that runs it against
    /// a re-imported capture and nothing else.
    pub fn from_capture(text: &str) -> Result<Monitor> {
        Ok(Monitor::from_events(parse_ndjson(text)?))
    }

    /// Build from already-parsed capture events.
    ///
    /// Events are sorted by time with a stable sort, so two events sharing a
    /// timestamp keep their file order — which is how a capture records which
    /// of two simultaneous things happened first.
    pub fn from_events(mut events: Vec<CaptureEvent>) -> Monitor {
        events.sort_by_key(|e| e.t_us);
        let mut observations = Vec::with_capacity(events.len());
        for e in events {
            push_event(&mut observations, e);
        }
        Monitor { observations }
    }

    /// Build from a live passive tap's buffer.
    ///
    /// The tap's [`Origin`](odr_bus::Origin) is discarded on the way in. See
    /// the module docs: a probe on a pair cannot tell which transceiver drove
    /// the line, and a detector that could would be measuring the simulator
    /// rather than the traffic.
    ///
    /// The tap may be of any kind — an inline implant's own view is a
    /// legitimate probe point — but a defender's monitor is a
    /// [`PassiveTap`](odr_bus::PassiveTap).
    pub fn from_tap(tap: &dyn Tap) -> Monitor {
        let events = tap
            .seen()
            .iter()
            .map(|s| CaptureEvent {
                t_us: s.t_us,
                line: match (s.bits.is_some(), s.wire_kind) {
                    (false, _) => CaptureLine::Rs485,
                    (true, Some(WireKind::ClockData)) => CaptureLine::ClockData,
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
        Monitor::from_events(events)
    }

    /// Everything observed, in time order.
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// One observation by index.
    pub fn get(&self, index: usize) -> Option<&Observation> {
        self.observations.get(index)
    }

    /// How many observations there are.
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// True if the monitor saw nothing at all.
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// When the first observation happened.
    pub fn start_us(&self) -> Micros {
        self.observations.first().map(|o| o.t_us).unwrap_or(0)
    }

    /// When the last observation happened.
    pub fn end_us(&self) -> Micros {
        self.observations.last().map(|o| o.t_us).unwrap_or(0)
    }

    /// How long the capture covers.
    pub fn span_us(&self) -> Micros {
        self.end_us().saturating_sub(self.start_us())
    }

    /// Every observation on an RS-485 bus.
    pub fn bus(&self) -> impl Iterator<Item = &Observation> {
        self.observations.iter().filter(|o| o.is_bus())
    }

    /// Every observation on a two-wire link.
    pub fn wire(&self) -> impl Iterator<Item = &Observation> {
        self.observations.iter().filter(|o| o.is_wire())
    }

    /// Every observation that decoded into an OSDP frame.
    pub fn frames(&self) -> impl Iterator<Item = &Observation> {
        self.observations.iter().filter(|o| o.frame.is_some())
    }

    /// Every frame concerning one peripheral address.
    pub fn for_address(&self, address: u8) -> impl Iterator<Item = &Observation> + '_ {
        let want = address & 0x7F;
        self.observations
            .iter()
            .filter(move |o| o.address() == Some(want))
    }

    /// Every peripheral address that appeared on the bus, in ascending order.
    ///
    /// Note that this is *addresses seen answering or being addressed*, not a
    /// device inventory. Two readers swapped at one address are one entry here,
    /// which is precisely the ambiguity curriculum 5.2 is about.
    pub fn addresses(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for o in self.frames() {
            if let Some(a) = o.address() {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// Observations whose timestamp falls in `[from, to)`.
    pub fn between(&self, from: Micros, to: Micros) -> impl Iterator<Item = &Observation> {
        self.observations
            .iter()
            .filter(move |o| o.t_us >= from && o.t_us < to)
    }

    /// The whole capture, re-serialised in the interchange format.
    ///
    /// Round-tripping through this is how the provenance tests prove a detector
    /// used nothing but the file.
    pub fn to_capture(&self) -> String {
        let events: Vec<CaptureEvent> = self
            .observations
            .iter()
            .map(|o| CaptureEvent {
                t_us: o.t_us,
                line: o.line.clone(),
                dir: o.dir.clone(),
                bytes: o.bytes.clone(),
            })
            .collect();
        odr_bus::capture::write_ndjson(&events)
    }
}

/// Turn one capture line into one or more observations.
///
/// A bus line that packs several frames becomes one observation per frame, so
/// an evidence citation names a frame rather than a buffer. Anything that does
/// not decode is kept whole, because "these bytes were on the wire and were not
/// a frame" is a fact a detector may want.
fn push_event(out: &mut Vec<Observation>, e: CaptureEvent) {
    if !e.line.is_bus() {
        let bits = e.wiegand_candidates().into_iter().next();
        out.push(Observation {
            index: out.len(),
            t_us: e.t_us,
            line: e.line,
            dir: e.dir,
            bytes: e.bytes,
            frame: None,
            bits,
        });
        return;
    }

    let mut any = false;
    for event in Scanner::offline(&e.bytes) {
        if let ScanEvent::Frame { offset, len, frame } = event {
            let bytes = e
                .bytes
                .get(offset..offset.saturating_add(len))
                .unwrap_or(&[])
                .to_vec();
            out.push(Observation {
                index: out.len(),
                t_us: e.t_us,
                line: e.line.clone(),
                dir: e.dir.clone(),
                bytes,
                frame: Some(*frame),
                bits: None,
            });
            any = true;
        }
    }
    if !any {
        out.push(Observation {
            index: out.len(),
            t_us: e.t_us,
            line: e.line,
            dir: e.dir,
            bytes: e.bytes,
            frame: None,
            bits: None,
        });
    }
}
