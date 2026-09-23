//! The controller: a legacy panel, or a full OSDP access control unit.
//!
//! # The flag that the downgrade attack actually targets
//!
//! [`AcuConfig::trust_pdcap`] is the whole of curriculum drill 3.6. It is
//! `true` by default, and that default is the deployed reality:
//!
//! * With `trust_pdcap: true`, the controller decides whether to run a Secure
//!   Channel handshake **from the PD's capability reply** — an unauthenticated
//!   frame sent before any key material is in play. A reader that says it
//!   cannot do AES-128 gets talked to in the clear, and this is true even when
//!   [`AcuConfig::sc`] is [`ScRequirement::Required`], because "required"
//!   in this class of product means "required of readers that support it".
//!   That sentence is the vulnerability.
//! * With `trust_pdcap: false`, the controller attempts the handshake
//!   regardless of what the capability reply claimed. A genuinely legacy
//!   reader then NAKs and, under [`ScRequirement::Required`], is refused
//!   rather than downgraded. This is the defence, and it is also why the
//!   detection rule in curriculum 5.2 is hard: a refused legacy reader and a
//!   downgraded modern one look similar in a log until you notice that one of
//!   them used to claim AES-128.
//!
//! Both settings are modelled so a drill can run the attack and then run the
//! fix and see it hold.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_osdp::codes::{Command, Reply};
use odr_osdp::payload::{KeysetCommand, Nak, NakError, OutputCommand, PdCapabilities, PdId};
use odr_osdp::rng::SeededRng;
use odr_osdp::{Frame, KeyType, RawCardRead, SecureChannel, SCBK_D};
use odr_wiegand::{BitVec, CardFormat};

use crate::access::{AccessList, AccessPolicy};
use crate::credential::FormatId;
use crate::ids::{ControllerId, DoorId, LinkId, Micros};
use crate::log::{DecisionReason, ProtocolEvent, ScDecline, ScEvent};
use crate::reader::ScRequirement;

/// An OSDP controller's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcuConfig {
    /// The addresses this controller polls, in order.
    pub addresses: Vec<u8>,
    /// How long between one poll finishing and the next starting.
    pub poll_interval_us: Micros,
    /// How long to wait for a reply before counting a timeout.
    pub reply_timeout_us: Micros,
    /// How many times to repeat a command before giving up on an address.
    pub max_retries: u8,
    /// How long to wait after `REPLY_BUSY` before trying again.
    pub busy_retry_us: Micros,
    /// How much this controller insists on Secure Channel.
    pub sc: ScRequirement,
    /// Decide whether to run a handshake from the PD's own capability reply.
    /// See the module docs; this is the downgrade attack's target.
    pub trust_pdcap: bool,
    /// Encrypt payloads (SCS_17/18) rather than only authenticating them
    /// (SCS_15/16, the null ciphers of curriculum drill 4.4).
    pub encrypt_payloads: bool,
    /// The site key this controller holds.
    pub scbk: [u8; 16],
    /// Whether that key is the published default.
    pub key_type: KeyType,
    /// Install mode: commission an uncommissioned PD by establishing a channel
    /// under SCBK-D and then pushing [`AcuConfig::scbk`] with `CMD_KEYSET`.
    ///
    /// This is the third Mellon attack in one boolean. A controller left in
    /// install mode hands the site key to anything that turns up claiming the
    /// default key — including an attacker's laptop.
    pub install_mode: bool,
    /// Send `CMD_OUT` to the PD when access is granted, as well as driving the
    /// controller's own strike relay. Harmless, and it is what makes the
    /// `POLL, ACK, RAW, ACK, OUT` signature of curriculum drill 4.1 visible.
    pub drive_pd_output: bool,
    /// Which output number `CMD_OUT` addresses.
    pub output_number: u8,
    /// **How many MAC bytes carry strength. Four, unless a drill rigs it.**
    ///
    /// The controller-side twin of [`PdConfig::mac_len`](crate::PdConfig::mac_len);
    /// see that field. Four is the only value OSDP has, and it is the default.
    /// Both ends must agree, or every session frame fails its MAC check.
    pub mac_len: u8,
}

impl Default for AcuConfig {
    fn default() -> AcuConfig {
        AcuConfig {
            addresses: alloc::vec![0x01],
            poll_interval_us: 100_000,
            reply_timeout_us: 200_000,
            max_retries: 2,
            busy_retry_us: 50_000,
            sc: ScRequirement::Disabled,
            trust_pdcap: true,
            encrypt_payloads: true,
            scbk: SCBK_D,
            key_type: KeyType::Default,
            install_mode: false,
            drive_pd_output: true,
            output_number: 0,
            mac_len: 4,
        }
    }
}

impl AcuConfig {
    /// A controller polling one address, with no Secure Channel.
    pub fn polling(addresses: impl IntoIterator<Item = u8>) -> AcuConfig {
        AcuConfig {
            addresses: addresses.into_iter().map(|a| a & 0x7F).collect(),
            ..AcuConfig::default()
        }
    }

    /// Use Secure Channel with the published default key.
    pub fn with_default_key(mut self, requirement: ScRequirement) -> AcuConfig {
        self.scbk = SCBK_D;
        self.key_type = KeyType::Default;
        self.sc = requirement;
        self
    }

    /// Use Secure Channel with a site key.
    pub fn with_site_key(mut self, scbk: [u8; 16], requirement: ScRequirement) -> AcuConfig {
        self.scbk = scbk;
        self.key_type = KeyType::SiteKey;
        self.sc = requirement;
        self
    }

    /// Set whether the controller believes an unauthenticated capability
    /// reply. See the module docs.
    pub fn trusting_pdcap(mut self, trust: bool) -> AcuConfig {
        self.trust_pdcap = trust;
        self
    }

    /// Turn install mode on or off.
    pub fn in_install_mode(mut self, yes: bool) -> AcuConfig {
        self.install_mode = yes;
        self
    }

    /// Rig the MAC width for curriculum drill 4.2. See [`AcuConfig::mac_len`].
    pub fn with_mac_len(mut self, len: u8) -> AcuConfig {
        self.mac_len = len.clamp(1, 4);
        self
    }
}

/// How far a controller has got with one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStage {
    /// Nothing known. The next command goes out on sequence 0, which is the
    /// protocol's "I have just started" marker.
    NeedsReset,
    /// Identity known; ask for capabilities.
    NeedsCapabilities,
    /// Capabilities known; begin a Secure Channel handshake.
    NeedsSecureChannel,
    /// `REPLY_CCRYPT` received; send `CMD_SCRYPT`.
    NeedsScrypt,
    /// Session established under the default key and this controller is in
    /// install mode; push the site key.
    NeedsKeyset,
    /// Steady state: polling.
    Online,
    /// Gave up after too many timeouts.
    Offline,
    /// Policy refused to talk to this PD at all.
    Refused,
}

impl SessionStage {
    /// True if this is a working link.
    pub fn is_online(self) -> bool {
        matches!(self, SessionStage::Online)
    }
}

/// The controller's state for one PD address.
#[derive(Debug)]
pub struct PdSession {
    /// The address.
    pub address: u8,
    /// How far the controller has got.
    pub stage: SessionStage,
    /// The sequence number most recently used.
    pub sequence: u8,
    /// How many times the current command has been sent.
    pub attempts: u8,
    /// Whether the next transmission repeats the current sequence number
    /// rather than advancing it.
    pub retrying: bool,
    /// The identity the PD reported.
    pub pd_id: Option<PdId>,
    /// The capability report the PD sent — **as received**, which under a
    /// downgrade attack is not what the PD sent.
    pub capabilities: Option<PdCapabilities>,
    /// The secure channel, once started.
    pub channel: Option<SecureChannel>,
    /// True once the channel is usable.
    pub secure: bool,
    /// The key this session is using.
    pub scbk: [u8; 16],
    /// Whether that key is the published default.
    pub key_type: KeyType,
    /// The last `REPLY_CCRYPT`, waiting to be turned into `CMD_SCRYPT`.
    pub(crate) ccrypt: Option<Box<Frame>>,
    /// A command queued out of band — the `CMD_OUT` after a grant.
    pub(crate) queued: Option<Box<Frame>>,
    /// The command currently outstanding.
    pub(crate) outstanding: Option<u8>,
    /// True once this controller has pushed a key to this PD.
    pub keyset_sent: bool,
}

impl PdSession {
    fn new(address: u8, scbk: [u8; 16], key_type: KeyType) -> PdSession {
        PdSession {
            address,
            stage: SessionStage::NeedsReset,
            sequence: 0,
            attempts: 0,
            retrying: false,
            pd_id: None,
            capabilities: None,
            channel: None,
            secure: false,
            scbk,
            key_type,
            ccrypt: None,
            queued: None,
            outstanding: None,
            keyset_sent: false,
        }
    }

    fn advance_sequence(&mut self) -> u8 {
        if self.retrying {
            self.retrying = false;
            return self.sequence;
        }
        self.sequence = match self.sequence & 0x03 {
            3 => 1,
            other => other + 1,
        };
        self.sequence
    }
}

/// The controller's live OSDP state.
#[derive(Debug, Default)]
pub struct AcuRuntime {
    /// One session per configured address.
    pub sessions: Vec<PdSession>,
    /// Which session the next poll goes to.
    pub cursor: usize,
    /// Cancels a stale reply timer.
    pub(crate) timeout_token: u64,
    /// Which session is waiting for a reply.
    pub(crate) awaiting: Option<usize>,
}

/// What kind of panel this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerMode {
    /// A legacy panel: it listens to a Wiegand or clock-and-data pair and has
    /// no way of talking back.
    Legacy,
    /// An OSDP access control unit.
    Osdp(Box<AcuConfig>),
}

impl ControllerMode {
    /// The OSDP configuration, if this is an OSDP controller.
    pub fn acu_config(&self) -> Option<&AcuConfig> {
        match self {
            ControllerMode::Osdp(c) => Some(c),
            ControllerMode::Legacy => None,
        }
    }
}

/// A controller.
#[derive(Debug)]
pub struct Controller {
    /// Handle.
    pub id: ControllerId,
    /// A name for the UI.
    pub name: String,
    /// Which links it is attached to.
    pub links: Vec<LinkId>,
    /// The door it drives.
    pub door: Option<DoorId>,
    /// What it will open the door for.
    pub access: AccessList,
    /// Legacy panel or OSDP controller.
    pub mode: ControllerMode,
    /// The live OSDP state.
    pub osdp: AcuRuntime,
}

/// What a controller decided about a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardDecision {
    /// The bits it decided on, as received.
    pub bits: BitVec,
    /// What it believed the format was.
    pub format: FormatId,
    /// The verdict.
    pub granted: bool,
    /// Why.
    pub reason: DecisionReason,
}

/// What a controller wants to transmit next.
#[derive(Debug, Default)]
pub(crate) struct AcuAction {
    pub(crate) command: Option<Frame>,
    pub(crate) session: Option<usize>,
    pub(crate) protocol: Vec<ProtocolEvent>,
    pub(crate) secure_channel: Vec<ScEvent>,
}

/// What a controller made of a reply.
#[derive(Debug, Default)]
pub(crate) struct AcuReplyOutcome {
    pub(crate) protocol: Vec<ProtocolEvent>,
    pub(crate) secure_channel: Vec<ScEvent>,
    pub(crate) decision: Option<CardDecision>,
    /// Ask the world to retry sooner than the poll interval, e.g. after BUSY.
    pub(crate) retry_after_us: Option<Micros>,
}

impl Controller {
    /// A legacy panel.
    pub fn legacy(id: ControllerId, name: impl Into<String>) -> Controller {
        Controller {
            id,
            name: name.into(),
            links: Vec::new(),
            door: None,
            access: AccessList::new(),
            mode: ControllerMode::Legacy,
            osdp: AcuRuntime::default(),
        }
    }

    /// An OSDP controller.
    pub fn osdp(id: ControllerId, name: impl Into<String>, config: AcuConfig) -> Controller {
        let sessions = config
            .addresses
            .iter()
            .map(|a| PdSession::new(*a, config.scbk, config.key_type))
            .collect();
        Controller {
            id,
            name: name.into(),
            links: Vec::new(),
            door: None,
            access: AccessList::new(),
            mode: ControllerMode::Osdp(Box::new(config)),
            osdp: AcuRuntime {
                sessions,
                ..AcuRuntime::default()
            },
        }
    }

    /// Set the access list.
    pub fn with_access(mut self, access: AccessList) -> Controller {
        self.access = access;
        self
    }

    /// The OSDP configuration, if there is one.
    pub fn acu_config(&self) -> Option<&AcuConfig> {
        self.mode.acu_config()
    }

    /// The session for an address.
    pub fn session(&self, address: u8) -> Option<&PdSession> {
        self.osdp.sessions.iter().find(|s| s.address == address)
    }

    /// The session for an address, mutably.
    pub fn session_mut(&mut self, address: u8) -> Option<&mut PdSession> {
        self.osdp.sessions.iter_mut().find(|s| s.address == address)
    }

    /// True if the link to an address is currently secured.
    pub fn is_secure(&self, address: u8) -> bool {
        self.session(address).is_some_and(|s| s.secure)
    }

    // -- access decision -----------------------------------------------------

    /// Decide whether to open the door for a bit pattern.
    ///
    /// The bits are what arrived, not what any reader intended to send. That
    /// distinction is the whole of curriculum drills 1.2 and 1.4.
    pub fn decide(&self, bits: &BitVec) -> CardDecision {
        let decoded = match self.access.assumed_format {
            Some(f) => odr_wiegand::decode(f, bits).ok(),
            None => odr_wiegand::infer_formats(bits)
                .into_iter()
                .next()
                .map(|c| c.decoded),
        };
        let format = decoded
            .as_ref()
            .map(|d| FormatId::for_card_format(d.format))
            .unwrap_or(FormatId::UNKNOWN);

        if let Some(d) = &decoded {
            if self.access.require_valid_parity && !d.parity_valid() {
                return CardDecision {
                    bits: bits.clone(),
                    format,
                    granted: false,
                    reason: DecisionReason::ParityRejected,
                };
            }
        } else if self.access.assumed_format.is_some() {
            return CardDecision {
                bits: bits.clone(),
                format,
                granted: false,
                reason: DecisionReason::Unreadable {
                    detail: "bits do not fit the configured card format".to_string(),
                },
            };
        }

        match self.access.policy {
            AccessPolicy::AllowAll => CardDecision {
                bits: bits.clone(),
                format,
                granted: true,
                reason: DecisionReason::AllowAll,
            },
            AccessPolicy::DenyAll => CardDecision {
                bits: bits.clone(),
                format,
                granted: false,
                reason: DecisionReason::DenyAll,
            },
            AccessPolicy::List => match self.access.lookup(bits) {
                Some(entry) => CardDecision {
                    bits: bits.clone(),
                    format,
                    granted: true,
                    reason: DecisionReason::Matched {
                        label: entry.label.clone(),
                    },
                },
                None => CardDecision {
                    bits: bits.clone(),
                    format,
                    granted: false,
                    reason: DecisionReason::NoMatch,
                },
            },
        }
    }

    // -- OSDP polling --------------------------------------------------------

    /// Build the next command to put on the bus.
    pub(crate) fn next_command(&mut self, rng: &mut SeededRng) -> AcuAction {
        let mut action = AcuAction::default();
        let cfg = match self.mode.acu_config() {
            Some(c) => c.clone(),
            None => return action,
        };
        if self.osdp.sessions.is_empty() {
            return action;
        }
        // Round-robin, skipping addresses policy has refused outright.
        let n = self.osdp.sessions.len();
        let mut chosen = None;
        for step in 0..n {
            let idx = (self.osdp.cursor + step) % n;
            if self.osdp.sessions[idx].stage != SessionStage::Refused {
                chosen = Some(idx);
                break;
            }
        }
        let idx = match chosen {
            Some(i) => i,
            None => return action,
        };
        self.osdp.cursor = (idx + 1) % n;

        let (frame, protocol, sc) = self.build_command(idx, &cfg, rng);
        action.protocol = protocol;
        action.secure_channel = sc;
        if frame.is_some() {
            action.session = Some(idx);
        }
        action.command = frame;
        action
    }

    fn build_command(
        &mut self,
        idx: usize,
        cfg: &AcuConfig,
        rng: &mut SeededRng,
    ) -> (Option<Frame>, Vec<ProtocolEvent>, Vec<ScEvent>) {
        let mut protocol = Vec::new();
        let mut sc = Vec::new();
        let session = match self.osdp.sessions.get_mut(idx) {
            Some(s) => s,
            None => return (None, protocol, sc),
        };
        let address = session.address;

        // A queued out-of-band command jumps the queue.
        if let Some(q) = session.queued.take() {
            let seq = session.advance_sequence();
            let frame = reseal(session, cfg, *q, seq);
            protocol.push(ProtocolEvent::CommandSent {
                address,
                command: frame.id,
                sequence: frame.sequence,
                secured: frame.security.is_some(),
            });
            session.outstanding = Some(frame.id);
            return (Some(frame), protocol, sc);
        }

        let frame = match session.stage {
            SessionStage::NeedsReset => {
                session.sequence = 0;
                session.retrying = true; // advance_sequence must not move off 0
                session.channel = None;
                session.secure = false;
                let seq = session.advance_sequence();
                Some(Frame::command(address, seq, Command::Id, Vec::new()))
            }
            SessionStage::NeedsCapabilities => {
                let seq = session.advance_sequence();
                Some(Frame::command(address, seq, Command::Cap, Vec::new()))
            }
            SessionStage::NeedsSecureChannel => {
                let seq = session.advance_sequence();
                let mut ch =
                    SecureChannel::acu(session.scbk, session.key_type).with_mac_len(cfg.mac_len);
                let rnd_a = rng.nonce8();
                match ch.challenge(address, seq, rnd_a) {
                    Ok(f) => {
                        sc.push(ScEvent::Requested {
                            address,
                            key_type: session.key_type,
                        });
                        session.channel = Some(ch);
                        Some(f)
                    }
                    Err(e) => {
                        sc.push(ScEvent::Failed {
                            address,
                            reason: alloc::format!("{e:?}"),
                        });
                        session.stage = SessionStage::Online;
                        None
                    }
                }
            }
            SessionStage::NeedsScrypt => {
                let seq = session.advance_sequence();
                let ccrypt = session.ccrypt.take();
                match (session.channel.as_mut(), ccrypt) {
                    (Some(ch), Some(cc)) => match ch.handle_ccrypt(&cc, seq) {
                        Ok(f) => Some(f),
                        Err(e) => {
                            sc.push(ScEvent::Failed {
                                address,
                                reason: alloc::format!("{e:?}"),
                            });
                            session.stage = if cfg.sc.requires() {
                                SessionStage::Refused
                            } else {
                                SessionStage::Online
                            };
                            None
                        }
                    },
                    _ => {
                        session.stage = SessionStage::NeedsSecureChannel;
                        None
                    }
                }
            }
            SessionStage::NeedsKeyset => {
                let seq = session.advance_sequence();
                let payload = KeysetCommand::scbk(cfg.scbk).encode();
                let secured = session.secure;
                let f = match (session.secure, session.channel.as_mut()) {
                    (true, Some(ch)) => ch
                        .seal(address, seq, Command::Keyset.to_u8(), &payload, true)
                        .ok(),
                    _ => Some(Frame::command(address, seq, Command::Keyset, payload)),
                };
                if f.is_some() {
                    session.keyset_sent = true;
                    sc.push(ScEvent::KeysetSent { address, secured });
                }
                f
            }
            SessionStage::Online => {
                let seq = session.advance_sequence();
                let f = match (session.secure, session.channel.as_mut()) {
                    (true, Some(ch)) => ch
                        .seal(
                            address,
                            seq,
                            Command::Poll.to_u8(),
                            &[],
                            cfg.encrypt_payloads,
                        )
                        .ok(),
                    _ => Some(Frame::command(address, seq, Command::Poll, Vec::new())),
                };
                f
            }
            SessionStage::Offline => {
                // Keep knocking. An address that comes back answers a reset.
                session.sequence = 0;
                session.retrying = true;
                let seq = session.advance_sequence();
                Some(Frame::command(address, seq, Command::Id, Vec::new()))
            }
            SessionStage::Refused => None,
        };

        if let Some(f) = &frame {
            protocol.push(ProtocolEvent::CommandSent {
                address,
                command: f.id,
                sequence: f.sequence,
                secured: f.security.is_some(),
            });
            session.outstanding = Some(f.id);
        }
        (frame, protocol, sc)
    }

    /// Handle a reply from a PD.
    pub(crate) fn handle_reply(&mut self, frame: &Frame) -> AcuReplyOutcome {
        let mut out = AcuReplyOutcome::default();
        let cfg = match self.mode.acu_config() {
            Some(c) => c.clone(),
            None => return out,
        };
        if !frame.is_reply {
            return out;
        }
        let idx = match self
            .osdp
            .sessions
            .iter()
            .position(|s| s.address == frame.address)
        {
            Some(i) => i,
            None => return out,
        };

        // Open a secured reply before looking at it.
        let mut plaintext = frame.payload.clone();
        let mut secured = false;
        if frame.scs_type().is_some_and(|s| s.has_mac()) {
            secured = true;
            let session = match self.osdp.sessions.get_mut(idx) {
                Some(s) => s,
                None => return out,
            };
            match session.channel.as_mut().map(|ch| ch.open(frame)) {
                Some(Ok(p)) => plaintext = p,
                Some(Err(e)) => {
                    out.protocol.push(ProtocolEvent::FrameRejected {
                        address: frame.address,
                        reason: alloc::format!("secure channel rejected the reply: {e:?}"),
                    });
                    return out;
                }
                None => {
                    out.protocol.push(ProtocolEvent::FrameRejected {
                        address: frame.address,
                        reason: "secured reply with no session".to_string(),
                    });
                    return out;
                }
            }
        }

        let reply = frame.reply_code();
        {
            let session = match self.osdp.sessions.get_mut(idx) {
                Some(s) => s,
                None => return out,
            };
            session.attempts = 0;
            session.outstanding = None;
            if session.stage == SessionStage::Offline {
                out.protocol.push(ProtocolEvent::PdOnline {
                    address: frame.address,
                });
            }
            out.protocol.push(ProtocolEvent::ReplyReceived {
                address: frame.address,
                reply: frame.id,
                sequence: frame.sequence,
                secured,
            });
        }

        match reply {
            Some(Reply::Busy) => {
                out.protocol.push(ProtocolEvent::Busy {
                    address: frame.address,
                });
                out.retry_after_us = Some(cfg.busy_retry_us);
            }
            Some(Reply::Nak) => {
                let code = Nak::decode(&plaintext).map(|n| n.error_code).unwrap_or(0);
                out.protocol.push(ProtocolEvent::Nak {
                    address: frame.address,
                    error: code,
                });
                self.handle_nak(idx, &cfg, code, &mut out);
            }
            Some(Reply::PdId) => {
                if let Some(s) = self.osdp.sessions.get_mut(idx) {
                    s.pd_id = PdId::decode(&plaintext).ok();
                    s.stage = SessionStage::NeedsCapabilities;
                }
            }
            Some(Reply::PdCap) => {
                let caps = PdCapabilities::decode(&plaintext).ok();
                let claims = caps.as_ref().is_some_and(|c| c.claims_aes128());
                let default_key = caps.as_ref().is_some_and(|c| c.uses_default_key());
                out.protocol.push(ProtocolEvent::CapabilitiesReported {
                    address: frame.address,
                    claims_aes128: claims,
                    uses_default_key: default_key,
                });
                if let Some(s) = self.osdp.sessions.get_mut(idx) {
                    s.capabilities = caps;
                }
                self.decide_secure_channel(idx, &cfg, claims, default_key, &mut out);
            }
            Some(Reply::Ccrypt) => {
                if let Some(s) = self.osdp.sessions.get_mut(idx) {
                    s.ccrypt = Some(Box::new(frame.clone()));
                    s.stage = SessionStage::NeedsScrypt;
                }
            }
            Some(Reply::RmacI) => {
                let address = frame.address;
                let mut established = false;
                let mut key_type = KeyType::Default;
                if let Some(s) = self.osdp.sessions.get_mut(idx) {
                    match s.channel.as_mut().map(|ch| ch.handle_rmac_i(frame)) {
                        Some(Ok(())) => {
                            s.secure = true;
                            established = true;
                            key_type = s.key_type;
                        }
                        Some(Err(e)) => {
                            out.secure_channel.push(ScEvent::Failed {
                                address,
                                reason: alloc::format!("{e:?}"),
                            });
                            s.secure = false;
                            s.stage = if cfg.sc.requires() {
                                SessionStage::Refused
                            } else {
                                SessionStage::Online
                            };
                        }
                        None => {
                            s.stage = SessionStage::Online;
                        }
                    }
                }
                if established {
                    out.secure_channel.push(ScEvent::Established {
                        address,
                        key_type,
                        encrypted: cfg.encrypt_payloads,
                    });
                    let wants_keyset = cfg.install_mode
                        && key_type == KeyType::Default
                        && cfg.key_type == KeyType::SiteKey;
                    if let Some(s) = self.osdp.sessions.get_mut(idx) {
                        s.stage = if wants_keyset && !s.keyset_sent {
                            SessionStage::NeedsKeyset
                        } else {
                            SessionStage::Online
                        };
                    }
                }
            }
            Some(Reply::Ack) => {
                if let Some(s) = self.osdp.sessions.get_mut(idx) {
                    if s.stage == SessionStage::NeedsKeyset {
                        // The PD took the site key; re-handshake under it.
                        s.scbk = cfg.scbk;
                        s.key_type = cfg.key_type;
                        s.channel = None;
                        s.secure = false;
                        s.stage = SessionStage::NeedsSecureChannel;
                    } else if !s.stage.is_online() && s.stage != SessionStage::Refused {
                        s.stage = SessionStage::Online;
                    }
                }
            }
            Some(Reply::Raw) => {
                if let Ok(raw) = RawCardRead::decode(&plaintext) {
                    let bits = BitVec::from_bools(&raw.bits());
                    out.protocol.push(ProtocolEvent::CardReadReported {
                        address: frame.address,
                        format_code: raw.format_code,
                        bit_count: raw.bit_count,
                    });
                    let decision = self.decide(&bits);
                    if decision.granted && cfg.drive_pd_output {
                        let payload = OutputCommand {
                            output: cfg.output_number,
                            control_code: 0x01,
                            timer_100ms: 30,
                        }
                        .encode();
                        if let Some(s) = self.osdp.sessions.get_mut(idx) {
                            s.queued = Some(Box::new(Frame::command(
                                s.address,
                                s.sequence,
                                Command::Out,
                                payload,
                            )));
                        }
                    }
                    out.decision = Some(decision);
                } else {
                    out.protocol.push(ProtocolEvent::FrameRejected {
                        address: frame.address,
                        reason: "REPLY_RAW payload did not decode".to_string(),
                    });
                }
            }
            _ => {}
        }
        out
    }

    fn handle_nak(&mut self, idx: usize, cfg: &AcuConfig, code: u8, out: &mut AcuReplyOutcome) {
        let address = self.osdp.sessions.get(idx).map(|s| s.address).unwrap_or(0);
        match NakError::from_u8(code) {
            Some(NakError::SequenceNumber) => {
                if let Some(s) = self.osdp.sessions.get_mut(idx) {
                    s.stage = SessionStage::NeedsReset;
                    s.sequence = 0;
                    s.retrying = false;
                }
                out.protocol.push(ProtocolEvent::SequenceReset { address });
            }
            Some(NakError::SecureChannelUnsupported) | Some(NakError::SecurityConditionsNotMet) => {
                out.secure_channel.push(ScEvent::Declined {
                    address,
                    reason: ScDecline::HandshakeFailed,
                });
                if let Some(s) = self.osdp.sessions.get_mut(idx) {
                    s.secure = false;
                    s.channel = None;
                    s.stage = if cfg.sc.requires() {
                        SessionStage::Refused
                    } else {
                        SessionStage::Online
                    };
                }
            }
            _ => {
                if let Some(s) = self.osdp.sessions.get_mut(idx) {
                    if !s.stage.is_online() && s.stage != SessionStage::Refused {
                        s.stage = SessionStage::Online;
                    }
                }
            }
        }
    }

    /// The decision that the downgrade attack exists to influence.
    fn decide_secure_channel(
        &mut self,
        idx: usize,
        cfg: &AcuConfig,
        claims_aes128: bool,
        pd_uses_default_key: bool,
        out: &mut AcuReplyOutcome,
    ) {
        let address = self.osdp.sessions.get(idx).map(|s| s.address).unwrap_or(0);
        let attempt = match cfg.sc {
            ScRequirement::Disabled => false,
            ScRequirement::IfAvailable | ScRequirement::Required => {
                if cfg.trust_pdcap {
                    claims_aes128
                } else {
                    true
                }
            }
        };
        if attempt {
            if let Some(s) = self.osdp.sessions.get_mut(idx) {
                // Commissioning: a PD that admits to the default key has to be
                // met on the default key, because that is the only key it has.
                // The site key is pushed afterwards, with `CMD_KEYSET`, over a
                // channel anybody can read. That is the whole of the
                // keyset-capture weakness and it is not a bug in this code.
                if cfg.install_mode && pd_uses_default_key && !s.keyset_sent {
                    s.scbk = SCBK_D;
                    s.key_type = KeyType::Default;
                }
                s.stage = SessionStage::NeedsSecureChannel;
            }
            return;
        }
        let reason = if cfg.sc == ScRequirement::Disabled {
            ScDecline::PolicyDisabled
        } else {
            ScDecline::PdDoesNotClaimAes128
        };
        out.secure_channel
            .push(ScEvent::Declined { address, reason });
        if let Some(s) = self.osdp.sessions.get_mut(idx) {
            // Note what does *not* happen here: a controller set to "require"
            // still goes online in the clear, because it trusted an
            // unauthenticated capability reply. Turn off `trust_pdcap` to get
            // the behaviour the setting's name implies.
            s.stage = if cfg.sc.requires() && !cfg.trust_pdcap {
                SessionStage::Refused
            } else {
                SessionStage::Online
            };
        }
    }

    /// A reply did not arrive. Returns true if the address has just gone
    /// offline.
    pub(crate) fn handle_timeout(&mut self, idx: usize, out: &mut AcuReplyOutcome) -> bool {
        let max = self.mode.acu_config().map(|c| c.max_retries).unwrap_or(0);
        let session = match self.osdp.sessions.get_mut(idx) {
            Some(s) => s,
            None => return false,
        };
        session.attempts = session.attempts.saturating_add(1);
        session.outstanding = None;
        let address = session.address;
        out.protocol.push(ProtocolEvent::ReplyTimeout {
            address,
            attempt: session.attempts,
        });
        if session.attempts > max {
            let already = session.stage == SessionStage::Offline;
            session.stage = SessionStage::Offline;
            session.attempts = 0;
            session.retrying = false;
            session.secure = false;
            session.channel = None;
            if !already {
                out.protocol.push(ProtocolEvent::PdOffline { address });
                return true;
            }
            return false;
        }
        session.retrying = true;
        false
    }
}

/// Re-seal a queued command under the session's current channel.
fn reseal(session: &mut PdSession, cfg: &AcuConfig, frame: Frame, seq: u8) -> Frame {
    if session.secure {
        if let Some(ch) = session.channel.as_mut() {
            if let Ok(f) = ch.seal(
                frame.address,
                seq,
                frame.id,
                &frame.payload,
                cfg.encrypt_payloads,
            ) {
                return f;
            }
        }
    }
    let mut f = frame;
    f.sequence = seq & 0x03;
    f
}

/// The card format a legacy panel is usually configured for.
pub const DEFAULT_PANEL_FORMAT: CardFormat = CardFormat::H10301;
