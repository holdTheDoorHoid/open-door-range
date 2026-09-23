//! **Module 1 — the attacker on a D0/D1 or CLOCK/DATA pair.**
//!
//! Four actors, and between them the whole of curriculum Module 1:
//!
//! | Actor | Position | Drill |
//! |---|---|---|
//! | [`Sniffer`] | passive | 1.1, 1.3, 1.6 |
//! | [`Replayer`] | injecting | 1.3, 1.6 |
//! | [`Implant`] | inline | 1.2, 1.4 |
//! | [`BruteForcer`] | injecting | 1.5 |
//!
//! There is no cryptography in this module because there is none on the wire.
//! Every one of these is the protocol's ordinary operation performed by
//! somebody other than the reader, which is the finding, and the code is
//! correspondingly short.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_bus::{
    InjectingTap, Injection, InlineTap, LinkId, Micros, Observation, ObservedTraffic, PassiveTap,
    TapCtx, TapId, TapKind, TapPosition, TapVerdict, World,
};
use odr_bus::{ReaderId, WireKind};
use odr_wiegand::{BitVec, CardFormat, Credential, CredentialSweep, SweepCost, WiegandTiming};

use crate::error::{AttackError, Result};
use crate::knowledge::{
    CaptureMedium, CapturedCredential, Knowledge, KnowledgeCell, Known, Provenance, SweepReport,
};
use crate::Attacker;

use alloc::rc::Rc;
use core::cell::RefCell;

/// Turn one thing a tap saw on a two-wire link into a capture.
fn wire_capture(seen: &odr_bus::SeenTraffic) -> Option<CapturedCredential> {
    let bits = seen.bits.clone()?;
    let medium = match seen.wire_kind {
        Some(WireKind::Wiegand) => CaptureMedium::Wiegand,
        Some(WireKind::ClockData) => CaptureMedium::ClockData,
        None => return None,
    };
    Some(CapturedCredential {
        bits,
        t_us: seen.t_us,
        link: Some(seen.link),
        segment: seen.segment,
        medium,
        address: None,
    })
}

// ---------------------------------------------------------------------------
// Sniffer
// ---------------------------------------------------------------------------

/// **Passive capture off a D0/D1 or CLOCK/DATA link.**
///
/// A pair of clips on a cable inside a ceiling void. It transmits nothing, so
/// there is nothing for the panel to notice, and the credential it lifts stays
/// valid for as long as the card stays enrolled — there is no counter, no
/// timestamp and no nonce anywhere in the protocol to expire it.
///
/// Curriculum 1.1 asks a learner to decode what this captured by hand; 1.3 and
/// 1.6 hand it to a [`Replayer`].
pub struct Sniffer {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    consumed: usize,
}

impl core::fmt::Debug for Sniffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sniffer")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .finish()
    }
}

impl Sniffer {
    /// A sniffer with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> Sniffer {
        Sniffer::sharing(name, KnowledgeCell::new())
    }

    /// A sniffer pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> Sniffer {
        Sniffer {
            name: name.into(),
            knowledge,
            tap: None,
            consumed: 0,
        }
    }

    /// Clip it onto a link at the controller end.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.attach_at(world, link, TapPosition::default())
    }

    /// Clip it onto a link at a chosen position.
    pub fn attach_at(
        &mut self,
        world: &mut World,
        link: LinkId,
        position: TapPosition,
    ) -> Result<TapId> {
        let id = world.add_tap_at(link, Box::new(PassiveTap::new(self.name.clone())), position)?;
        self.tap = Some(id);
        Ok(id)
    }

    /// Take everything the probe has recorded since the last call into the
    /// knowledge base. Returns how many new credentials were learned.
    pub fn harvest(&mut self, world: &World) -> Result<usize> {
        let tap = self.tap.ok_or_else(|| AttackError::NotAttached {
            actor: self.name.clone(),
        })?;
        let seen = world.tap(tap)?.seen();
        let mut learned = 0;
        let mut new: Vec<Known<CapturedCredential>> = Vec::new();
        for s in seen.iter().skip(self.consumed) {
            if let Some(c) = wire_capture(s) {
                let t = c.t_us;
                new.push(Known::observed(c, t, Some(tap)));
                learned += 1;
            }
        }
        self.consumed = seen.len();
        self.knowledge.update(|k| k.credentials.extend(new));
        Ok(learned)
    }

    /// Everything captured so far.
    pub fn captures(&self) -> Vec<CapturedCredential> {
        self.knowledge
            .read(|k| k.credentials.iter().map(|c| c.value.clone()).collect())
            .unwrap_or_default()
    }

    /// The most recent capture.
    pub fn latest(&self) -> Option<CapturedCredential> {
        self.knowledge
            .read(|k| k.credentials.last().map(|c| c.value.clone()))
            .flatten()
    }
}

impl Attacker for Sniffer {
    fn name(&self) -> &str {
        &self.name
    }
    fn position(&self) -> TapKind {
        TapKind::Passive
    }
    fn knowledge(&self) -> &KnowledgeCell {
        &self.knowledge
    }
    fn tap(&self) -> Option<TapId> {
        self.tap
    }
}

// ---------------------------------------------------------------------------
// Replayer
// ---------------------------------------------------------------------------

/// **Re-emit a captured bit pattern.**
///
/// The replay box: the same clips as a [`Sniffer`], plus a transmitter. It
/// records what crosses the wire and can put any of it back, at whatever timing
/// it likes, whenever it likes — nothing downstream can tell, because there is
/// nothing in a Wiegand frame that says when it was produced or by what.
///
/// It refuses to replay bits it has not captured. That is not politeness: it is
/// [the governing rule](crate::knowledge) enforced, so a drill cannot
/// accidentally teach that an attacker can send a credential it never saw.
pub struct Replayer {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    consumed: usize,
    replays: usize,
}

impl core::fmt::Debug for Replayer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Replayer")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .field("replays", &self.replays)
            .finish()
    }
}

impl Replayer {
    /// A replay box with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> Replayer {
        Replayer::sharing(name, KnowledgeCell::new())
    }

    /// A replay box pooling what it knows with other actors — a [`Sniffer`]
    /// somewhere else on the cable, for instance.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> Replayer {
        Replayer {
            name: name.into(),
            knowledge,
            tap: None,
            consumed: 0,
            replays: 0,
        }
    }

    /// Clip it onto a link.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.attach_at(world, link, TapPosition::default())
    }

    /// Clip it onto a link at a chosen position.
    pub fn attach_at(
        &mut self,
        world: &mut World,
        link: LinkId,
        position: TapPosition,
    ) -> Result<TapId> {
        let id = world.add_tap_at(
            link,
            Box::new(InjectingTap::new(self.name.clone())),
            position,
        )?;
        self.tap = Some(id);
        Ok(id)
    }

    /// Take what the box has heard into the knowledge base.
    pub fn harvest(&mut self, world: &World) -> Result<usize> {
        let tap = self.tap.ok_or_else(|| AttackError::NotAttached {
            actor: self.name.clone(),
        })?;
        let seen = world.tap(tap)?.seen();
        let mut learned = 0;
        let mut new: Vec<Known<CapturedCredential>> = Vec::new();
        for s in seen.iter().skip(self.consumed) {
            // Skip the box's own transmissions: replaying a replay teaches
            // nothing and would let the knowledge base grow without bound.
            if s.origin == odr_bus::Origin::Tap(tap) {
                continue;
            }
            if let Some(c) = wire_capture(s) {
                let t = c.t_us;
                new.push(Known::observed(c, t, Some(tap)));
                learned += 1;
            }
        }
        self.consumed = seen.len();
        self.knowledge.update(|k| k.credentials.extend(new));
        Ok(learned)
    }

    /// Put a capture back on the wire at `at_us`.
    ///
    /// # Errors
    /// [`AttackError::Unearned`] if these bits are not in the knowledge base —
    /// an attacker cannot transmit a credential it never saw.
    pub fn replay(
        &mut self,
        world: &mut World,
        at_us: Micros,
        capture: &CapturedCredential,
    ) -> Result<()> {
        let tap = self.tap.ok_or_else(|| AttackError::NotAttached {
            actor: self.name.clone(),
        })?;
        let held = self
            .knowledge
            .read(|k| k.holds_credential(&capture.bits))
            .unwrap_or(false);
        if !held {
            return Err(AttackError::Unearned {
                wanted: "a credential to replay",
                detail: "these bits are not in the attacker's capture buffer".to_string(),
            });
        }
        world.inject(tap, Injection::wire_bits(at_us, capture.bits.clone()))?;
        self.replays += 1;
        Ok(())
    }

    /// Put the most recent capture back on the wire.
    pub fn replay_latest(&mut self, world: &mut World, at_us: Micros) -> Result<()> {
        let latest = self
            .knowledge
            .read(|k| k.credentials.last().map(|c| c.value.clone()))
            .flatten()
            .ok_or_else(|| AttackError::Exhausted {
                attack: "wiegand replay",
                detail: "nothing has been captured yet".to_string(),
            })?;
        self.replay(world, at_us, &latest)
    }

    /// How many frames this box has put back on the wire.
    pub fn replays(&self) -> usize {
        self.replays
    }
}

impl Attacker for Replayer {
    fn name(&self) -> &str {
        &self.name
    }
    fn position(&self) -> TapKind {
        TapKind::Injecting
    }
    fn knowledge(&self) -> &KnowledgeCell {
        &self.knowledge
    }
    fn tap(&self) -> Option<TapId> {
        self.tap
    }
}

// ---------------------------------------------------------------------------
// Implant
// ---------------------------------------------------------------------------

/// What an [`Implant`] does to the next credential that crosses it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ImplantMode {
    /// Forward everything untouched. The implant is still cutting the cable,
    /// and it is still recording — it is just not lying yet.
    #[default]
    PassThrough,
    /// Forward this exact bit pattern instead, whatever arrives.
    Substitute(BitVec),
    /// Forward this credential instead, re-encoded with correct parity for its
    /// format.
    Impersonate(Credential),
    /// Swallow the credential. The panel sees nothing at all.
    Swallow,
}

#[derive(Debug, Default)]
struct ImplantState {
    mode: ImplantMode,
    swaps: usize,
    swallowed: usize,
    consumed: Vec<BitVec>,
}

/// **The inline implant — the Tick / ESPKey class of device.**
///
/// A small board cut into the reader's own D0/D1 pair, usually inside the
/// housing where the cable is reachable without leaving the secure side of the
/// door. It passes everything through while it is being installed, records
/// every badge that goes past, and then substitutes a credential of its own
/// with correct parity.
///
/// The panel cannot notice, and that is not a modelling shortcut: the only
/// integrity check on a Wiegand frame is a parity bit, and the implant computes
/// it. Curriculum drill 1.4's flag has four parts — the tap is inline, the
/// reader's original credential was consumed, the controller granted on a
/// substitute, and the reader's own output was unchanged — and all four are
/// visible in the world's event log because the implant really does cut the
/// link into two electrically separate segments.
pub struct Implant {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    state: Rc<RefCell<ImplantState>>,
}

impl core::fmt::Debug for Implant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Implant")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .field("swaps", &self.swaps())
            .finish()
    }
}

impl Implant {
    /// An implant with a knowledge base of its own, passing everything through.
    pub fn new(name: impl Into<String>) -> Implant {
        Implant::sharing(name, KnowledgeCell::new())
    }

    /// An implant pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> Implant {
        Implant {
            name: name.into(),
            knowledge,
            tap: None,
            state: Rc::new(RefCell::new(ImplantState::default())),
        }
    }

    /// Cut the cable immediately in front of a reader — inside the housing.
    pub fn attach_before(
        &mut self,
        world: &mut World,
        link: LinkId,
        reader: ReaderId,
    ) -> Result<TapId> {
        self.attach_at(world, link, TapPosition::BeforeReader(reader))
    }

    /// Cut the cable at the controller end.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.attach_at(world, link, TapPosition::default())
    }

    /// Cut the cable at a chosen position.
    pub fn attach_at(
        &mut self,
        world: &mut World,
        link: LinkId,
        position: TapPosition,
    ) -> Result<TapId> {
        let state = self.state.clone();
        let knowledge = self.knowledge.clone();
        let tap = InlineTap::new(
            self.name.clone(),
            move |ctx: &mut TapCtx<'_>, obs: &Observation<'_>| {
                let bits = match obs.traffic {
                    ObservedTraffic::Wire { bits, kind } => (bits, kind),
                    ObservedTraffic::Bus { .. } => return TapVerdict::Pass,
                };
                let (bits, kind) = bits;
                let capture = CapturedCredential {
                    bits: bits.clone(),
                    t_us: ctx.now(),
                    link: Some(obs.link),
                    segment: obs.segment,
                    medium: match kind {
                        WireKind::Wiegand => CaptureMedium::Wiegand,
                        WireKind::ClockData => CaptureMedium::ClockData,
                    },
                    address: None,
                };
                let t = capture.t_us;
                knowledge.update(|k| k.credentials.push(Known::observed(capture, t, None)));

                let mut st = match state.try_borrow_mut() {
                    Ok(s) => s,
                    Err(_) => return TapVerdict::Pass,
                };
                st.consumed.push(bits.clone());
                match st.mode.clone() {
                    ImplantMode::PassThrough => TapVerdict::Pass,
                    ImplantMode::Swallow => {
                        st.swallowed += 1;
                        TapVerdict::Drop
                    }
                    ImplantMode::Substitute(replacement) => {
                        st.swaps += 1;
                        TapVerdict::ReplaceBits(replacement)
                    }
                    ImplantMode::Impersonate(cred) => {
                        // `inline_tamper` re-encodes the replacement through
                        // the format's own parity rules, so what leaves the
                        // implant is a frame a panel has no grounds to doubt.
                        match odr_wiegand::inline_tamper(bits, &cred) {
                            Ok(result) => {
                                st.swaps += 1;
                                TapVerdict::ReplaceBits(result.emitted)
                            }
                            Err(_) => TapVerdict::Pass,
                        }
                    }
                }
            },
        );
        let id = world.add_tap_at(link, Box::new(tap), position)?;
        self.tap = Some(id);
        Ok(id)
    }

    /// Stop lying. Still inline, still recording.
    pub fn pass_through(&self) {
        self.set_mode(ImplantMode::PassThrough);
    }

    /// Emit these exact bits in place of whatever arrives.
    pub fn substitute_bits(&self, bits: BitVec) {
        self.set_mode(ImplantMode::Substitute(bits));
    }

    /// Emit this credential in place of whatever arrives, with valid parity.
    pub fn impersonate(&self, credential: Credential) {
        self.set_mode(ImplantMode::Impersonate(credential));
    }

    /// Emit this facility code and card number in place of whatever arrives.
    pub fn impersonate_card(&self, format: CardFormat, facility_code: u64, card_number: u64) {
        self.impersonate(Credential::new(format, facility_code, card_number));
    }

    /// Swallow credentials. The panel sees nothing — a denial of service that
    /// costs one wire cut.
    pub fn swallow(&self) {
        self.set_mode(ImplantMode::Swallow);
    }

    fn set_mode(&self, mode: ImplantMode) {
        let _ = self.state.try_borrow_mut().map(|mut s| s.mode = mode);
    }

    /// What the implant will do to the next credential.
    pub fn mode(&self) -> ImplantMode {
        self.state
            .try_borrow()
            .map(|s| s.mode.clone())
            .unwrap_or_default()
    }

    /// How many credentials it has substituted.
    pub fn swaps(&self) -> usize {
        self.state.try_borrow().map(|s| s.swaps).unwrap_or(0)
    }

    /// How many it has swallowed.
    pub fn swallowed(&self) -> usize {
        self.state.try_borrow().map(|s| s.swallowed).unwrap_or(0)
    }

    /// Every credential that reached the implant — including the ones it
    /// replaced, which the panel never saw.
    pub fn consumed(&self) -> Vec<BitVec> {
        self.state
            .try_borrow()
            .map(|s| s.consumed.clone())
            .unwrap_or_default()
    }
}

impl Attacker for Implant {
    fn name(&self) -> &str {
        &self.name
    }
    fn position(&self) -> TapKind {
        TapKind::Inline
    }
    fn knowledge(&self) -> &KnowledgeCell {
        &self.knowledge
    }
    fn tap(&self) -> Option<TapId> {
        self.tap
    }
}

// ---------------------------------------------------------------------------
// BruteForcer
// ---------------------------------------------------------------------------

/// What one slice of a sweep did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepStep {
    /// How many credentials this slice put on the wire.
    pub attempted: usize,
    /// How many have been attempted in total.
    pub total_attempted: u128,
    /// Virtual microseconds now.
    pub now_us: Micros,
    /// True if the controller granted during this slice.
    pub granted: bool,
    /// The credential that did it.
    pub hit: Option<Credential>,
    /// True if the sweep has no candidates left.
    pub finished: bool,
}

/// **Sweeping the credential space at real wire timing.**
///
/// Curriculum drill 1.5 does not end on a flag. It ends on a *number*: what the
/// full space actually costs at the timing the learner chose. This actor exists
/// to produce that number honestly, and to let a learner watch a few thousand
/// of the sixteen million go past first so the number means something.
///
/// The honest figures come from [`odr_wiegand::SweepCost`], which is the same
/// arithmetic the analyser uses, and they are reported whether or not the sweep
/// found anything. A 26-bit format is 16,777,216 credentials; at nominal reader
/// timing with a settle gap that is over a week of continuous transmission —
/// which is why real attackers sweep one facility code rather than the space,
/// and why drill 1.5 asks the learner to compare the figure with 1.3's replay.
pub struct BruteForcer {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    format: CardFormat,
    sweep: CredentialSweep,
    timing: WiegandTiming,
    settle_us: Micros,
    attempted: u128,
    started_us: Option<Micros>,
    grants_at_start: usize,
    hit: Option<Credential>,
}

impl core::fmt::Debug for BruteForcer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BruteForcer")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .field("attempted", &self.attempted)
            .field("hit", &self.hit)
            .finish()
    }
}

impl BruteForcer {
    /// A brute forcer over a given sweep.
    pub fn new(name: impl Into<String>, sweep: CredentialSweep) -> BruteForcer {
        BruteForcer::sharing(name, KnowledgeCell::new(), sweep)
    }

    /// A brute forcer pooling what it learns with other actors.
    pub fn sharing(
        name: impl Into<String>,
        knowledge: KnowledgeCell,
        sweep: CredentialSweep,
    ) -> BruteForcer {
        let timing = WiegandTiming::default();
        BruteForcer {
            name: name.into(),
            knowledge,
            tap: None,
            format: sweep.format(),
            sweep,
            settle_us: timing.interframe_gap_us,
            timing,
            attempted: 0,
            started_us: None,
            grants_at_start: 0,
            hit: None,
        }
    }

    /// Transmit at a different rate. This is the knob curriculum 1.5 asks the
    /// learner to turn: the answer changes by an order of magnitude and the
    /// conclusion does not.
    pub fn with_timing(mut self, timing: WiegandTiming, settle_us: Micros) -> BruteForcer {
        self.timing = timing;
        self.settle_us = settle_us;
        self
    }

    /// Clip it onto a link.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        let id = world.add_tap(link, Box::new(InjectingTap::new(self.name.clone())))?;
        self.tap = Some(id);
        self.grants_at_start = world.log().grants().count();
        self.started_us = Some(world.now());
        Ok(id)
    }

    /// How long one credential takes on this wire at this timing.
    pub fn us_per_credential(&self) -> Micros {
        self.timing
            .frame_duration_us(self.format.bit_len())
            .saturating_add(self.settle_us)
    }

    /// What the configured sweep costs, end to end.
    pub fn cost(&self) -> SweepCost {
        self.sweep.cost(&self.timing, self.settle_us)
    }

    /// **What the format's whole credential space costs.** The number drill 1.5
    /// ends on.
    pub fn format_space_cost(&self) -> Result<SweepCost> {
        let full = CredentialSweep::exhaustive(self.format)?;
        Ok(full.cost(&self.timing, self.settle_us))
    }

    /// Put the next `n` candidates on the wire and let the world run through
    /// them.
    ///
    /// Sweeping is driven a slice at a time rather than in one blocking loop
    /// because the full space is sixteen million frames and a browser has to
    /// stay answering. The site renders the projected finish from
    /// [`BruteForcer::cost`] while this crawls.
    pub fn step(&mut self, world: &mut World, n: usize) -> Result<SweepStep> {
        let tap = self.tap.ok_or_else(|| AttackError::NotAttached {
            actor: self.name.clone(),
        })?;
        let per = self.us_per_credential();
        let mut at = world.now().saturating_add(per);
        let mut attempted = 0usize;
        let mut queued: Vec<Credential> = Vec::new();
        for _ in 0..n {
            let cred = match self.sweep.next() {
                Some(c) => c,
                None => break,
            };
            let bits = cred.encode()?;
            world.inject(tap, Injection::wire_bits(at, bits))?;
            queued.push(cred);
            at = at.saturating_add(per);
            attempted += 1;
        }
        let grants_before = world.log().grants().count();
        world.run_until(at.saturating_add(per))?;
        let granted = world.log().grants().count() > grants_before;
        self.attempted = self.attempted.saturating_add(attempted as u128);

        if granted && self.hit.is_none() {
            // Which candidate did it? The grant record carries the bits the
            // panel decided on, so match them against what was queued.
            let bits = world
                .log()
                .grants()
                .last()
                .and_then(|r| match &r.kind {
                    odr_bus::RecordKind::AccessDecision { bits, .. } => Some(bits.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            self.hit = queued
                .into_iter()
                .find(|c| c.encode().map(|b| b == bits).unwrap_or(false));
        }

        Ok(SweepStep {
            attempted,
            total_attempted: self.attempted,
            now_us: world.now(),
            granted,
            hit: self.hit,
            finished: attempted < n,
        })
    }

    /// Sweep until the controller grants or `max_attempts` have gone past.
    ///
    /// `max_attempts` is not a nicety. The full 26-bit space is sixteen million
    /// frames and the engine has a step budget; a drill that wants the honest
    /// cost should read [`BruteForcer::format_space_cost`] rather than wait.
    pub fn run_until_granted(
        &mut self,
        world: &mut World,
        max_attempts: usize,
        slice: usize,
    ) -> Result<SweepReport> {
        let slice = slice.max(1);
        let mut done = 0usize;
        while done < max_attempts {
            let take = slice.min(max_attempts - done);
            let step = self.step(world, take)?;
            done += step.attempted;
            if step.granted || step.finished {
                break;
            }
        }
        let report = self.report(world)?;
        let r = report.clone();
        self.knowledge.update(|k| {
            k.sweeps.push(Known::new(
                r,
                Provenance::Calibrated {
                    what: "the wall-clock cost of a sweep at this wire timing",
                },
            ))
        });
        Ok(report)
    }

    /// The honest arithmetic, whether or not anything was found.
    pub fn report(&self, world: &World) -> Result<SweepReport> {
        Ok(SweepReport {
            attempted: self.attempted,
            sweep_space: self.sweep.credential_count(),
            sweep_cost: self.cost(),
            format_space_cost: self.format_space_cost()?,
            elapsed_us: world.now().saturating_sub(self.started_us.unwrap_or(0)),
            hit: self.hit,
        })
    }

    /// How many credentials have gone onto the wire.
    pub fn attempted(&self) -> u128 {
        self.attempted
    }

    /// The credential that opened the door, if one did.
    pub fn hit(&self) -> Option<&Credential> {
        self.hit.as_ref()
    }
}

impl Attacker for BruteForcer {
    fn name(&self) -> &str {
        &self.name
    }
    fn position(&self) -> TapKind {
        TapKind::Injecting
    }
    fn knowledge(&self) -> &KnowledgeCell {
        &self.knowledge
    }
    fn tap(&self) -> Option<TapId> {
        self.tap
    }
}

/// Knowledge-base access shared by the four actors above, for a caller that
/// holds several of them and wants one view.
pub fn pooled(actors: &[&dyn Attacker]) -> Knowledge {
    let mut out = Knowledge::new();
    let mut seen: Vec<&KnowledgeCell> = Vec::new();
    for a in actors {
        let cell = a.knowledge();
        if seen.iter().any(|c| c.is_same(cell)) {
            continue;
        }
        seen.push(cell);
        out.absorb(&cell.snapshot());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use odr_bus::{wiegand_bench, AccessList, Presentation, SourceId};

    fn cred(fc: u64, cn: u64) -> Credential {
        Credential::new(CardFormat::H10301, fc, cn)
    }

    #[test]
    fn a_wire_capture_interprets_itself_and_keeps_the_raw_bits() {
        let c = cred(42, 1337);
        let bits = c.encode().unwrap();
        let capture = CapturedCredential {
            bits: bits.clone(),
            t_us: 5,
            link: None,
            segment: 0,
            medium: CaptureMedium::Wiegand,
            address: None,
        };
        assert_eq!(capture.bits, bits, "the bits are kept exactly as observed");
        assert_eq!(capture.facility_code(), Some(42));
        assert_eq!(capture.card_number(), Some(1337));
        assert!(!capture.candidates().is_empty());
    }

    #[test]
    fn an_implant_starts_transparent() {
        let implant = Implant::new("fresh");
        assert_eq!(implant.mode(), ImplantMode::PassThrough);
        assert_eq!(implant.swaps(), 0);
        assert_eq!(implant.swallowed(), 0);
        assert!(implant.consumed().is_empty());
    }

    #[test]
    fn an_implant_that_swallows_leaves_the_panel_with_nothing() {
        let c = cred(42, 1337);
        let access = AccessList::allow_all();
        let mut bench = wiegand_bench(0xBEEF, access).unwrap();
        let mut implant = Implant::new("cut");
        implant
            .attach_before(&mut bench.world, bench.link, bench.reader)
            .unwrap();
        implant.swallow();
        bench
            .world
            .present(
                bench.reader,
                0,
                Presentation::from_credential(SourceId(0), &c).unwrap(),
            )
            .unwrap();
        bench.world.run_until(2_000_000).unwrap();
        assert_eq!(implant.swallowed(), 1);
        assert_eq!(bench.world.log().decisions().count(), 0);
        assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 0);
    }

    #[test]
    fn a_sweep_costs_what_the_arithmetic_says_it_costs() {
        let sweep = CredentialSweep::exhaustive(CardFormat::H10301).unwrap();
        let forcer = BruteForcer::new("sweeper", sweep);
        let cost = forcer.cost();
        assert_eq!(cost.credentials, 16_777_216);
        assert_eq!(
            cost.total_us,
            cost.credentials * u128::from(cost.us_per_credential)
        );
        assert_eq!(forcer.us_per_credential(), cost.us_per_credential);
        assert_eq!(forcer.attempted(), 0);
        assert!(forcer.hit().is_none());
    }

    #[test]
    fn an_unattached_wiegand_actor_is_an_error_rather_than_a_panic() {
        let bench = wiegand_bench(1, AccessList::new()).unwrap();
        let mut sniffer = Sniffer::new("unclipped");
        assert!(matches!(
            sniffer.harvest(&bench.world),
            Err(AttackError::NotAttached { .. })
        ));
        assert!(sniffer.transmitted_nothing(&bench.world));
    }

    #[test]
    fn pooling_two_actors_that_share_a_cell_does_not_double_count() {
        let cell = KnowledgeCell::new();
        let sniffer = Sniffer::sharing("a", cell.clone());
        let replayer = Replayer::sharing("b", cell.clone());
        cell.update(|k| k.notes.push("one".into()));
        let pooled = pooled(&[&sniffer as &dyn Attacker, &replayer as &dyn Attacker]);
        assert_eq!(pooled.notes.len(), 1, "one shared base, counted once");

        let lone = Sniffer::new("c");
        lone.knowledge().update(|k| k.notes.push("two".into()));
        let pooled = pooled_of(&[&sniffer, &lone]);
        assert_eq!(pooled.notes.len(), 2);
    }

    fn pooled_of(actors: &[&dyn Attacker]) -> Knowledge {
        pooled(actors)
    }
}
