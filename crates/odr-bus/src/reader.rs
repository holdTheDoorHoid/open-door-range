//! The reader: a legacy Wiegand or clock-and-data transmitter, or a full OSDP
//! peripheral device.
//!
//! # The OSDP PD is a real peripheral, not a stub
//!
//! It has an address, a **configurable** capability report, two-bit sequence
//! handling with retransmission, `REPLY_BUSY`, `REPLY_NAK`, and an optional
//! Secure Channel with a configurable SCBK, an SCBK-D mode and an install-mode
//! flag. The capability report in particular is a real
//! [`PdCapabilities`] value rather than a constant, because curriculum drill
//! 3.6 rewrites it in flight and the controller has to be able to believe the
//! rewrite.
//!
//! # The setting the downgrade attack needs
//!
//! [`PdConfig::answer_clear_when_required`] defaults to `true`, and that
//! default is the deployed reality rather than a convenience. A PD cannot
//! *initiate* a secure channel — OSDP has exactly one master and it is the
//! controller — so a reader configured to "use Secure Channel" can only refuse
//! clear-text commands, and a reader that refuses everything is a reader that
//! does not work. Vendors ship the permissive behaviour. Set the flag to
//! `false` to get the strict reader, and watch the downgrade attack turn into
//! a denial of service instead of a bypass, which is the interesting half of
//! curriculum 5.2.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_osdp::codes::{Command, Reply};
use odr_osdp::payload::{
    Capability, CapabilityFunction, ComsetCommand, KeysetCommand, Nak, NakError, PdId,
};
use odr_osdp::rng::SeededRng;
use odr_osdp::{Frame, KeyType, PdCapabilities, RawCardRead, SecureChannel, SCBK_D};
use odr_wiegand::{AbaEncoding, AbaTrack2, BitVec, CardFormat};

use crate::credential::{CredentialSource, FormatId, Presentation};
use crate::ids::{LinkId, Micros, ReaderId, SourceId};
use crate::log::{ProtocolEvent, ScEvent};

/// How much an endpoint insists on Secure Channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScRequirement {
    /// Never attempt it. This is what most deployed OSDP is.
    #[default]
    Disabled,
    /// Use it if the other end says it can. **This is the setting the Mellon
    /// downgrade attack targets**, and it is the factory default on a great
    /// deal of equipment.
    IfAvailable,
    /// Require it.
    Required,
}

impl ScRequirement {
    /// True if a handshake should be attempted at all.
    pub fn wants_secure_channel(self) -> bool {
        !matches!(self, ScRequirement::Disabled)
    }

    /// True if traffic in the clear is a policy violation.
    pub fn requires(self) -> bool {
        matches!(self, ScRequirement::Required)
    }
}

/// When a PD answers `REPLY_BUSY` instead of doing what it was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BusyPolicy {
    /// Never busy.
    #[default]
    Never,
    /// Answer `BUSY` to the next `n` commands, then behave normally. Set at
    /// build time, or at any point with
    /// [`World::make_busy`](crate::World::make_busy).
    Next(u8),
}

/// What a clock-and-data reader puts on the wire when it is shown a card.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClockDataConfig {
    /// Leading and trailing zeros around the character stream.
    pub encoding: AbaEncoding,
    /// The card format the reader assumes when it has to turn Wiegand-shaped
    /// bits into track-2 digits. `None` means "infer", which is what the
    /// auto-detecting readers do.
    pub assumed_format: Option<CardFormat>,
}

/// An OSDP peripheral device's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdConfig {
    /// Bus address, 0..=0x7E. `0x7F` is the configuration address.
    pub address: u8,
    /// What `REPLY_PDID` reports.
    pub pd_id: PdId,
    /// What `REPLY_PDCAP` reports. A real, mutable value: the downgrade attack
    /// rewrites it in flight and a commissioning tool would rewrite it here.
    pub capabilities: PdCapabilities,
    /// The Secure Channel Base Key this PD holds.
    pub scbk: [u8; 16],
    /// Whether that key is the published default (SCBK-D) or a site key.
    pub key_type: KeyType,
    /// How much this PD insists on Secure Channel.
    pub sc: ScRequirement,
    /// Answer clear-text commands even when [`PdConfig::sc`] is
    /// [`ScRequirement::Required`]. Defaults to `true`; see the module docs
    /// for why that is the honest default.
    pub answer_clear_when_required: bool,
    /// Accept `CMD_KEYSET` with no secure channel at all.
    ///
    /// Real PDs normally refuse, which is why the keyset-capture attack
    /// targets commissioning *inside an SCBK-D channel* — secured, and
    /// readable by anyone who has read the published default key. Set this to
    /// `true` for the blunter version.
    pub accept_keyset_unsecured: bool,
    /// The PD is uncommissioned and will take a key from anyone who asks
    /// nicely over an SCBK-D channel.
    pub install_mode: bool,
    /// The chip identifier reported in `REPLY_CCRYPT`.
    pub cuid: [u8; 8],
    /// How long after receiving a command the reply starts.
    pub reply_delay_us: Micros,
    /// When to answer `REPLY_BUSY`.
    pub busy_policy: BusyPolicy,
    /// Which reader number card reads are reported against.
    pub reader_number: u8,
    /// **How many MAC bytes carry strength. Four, unless a drill rigs it.**
    ///
    /// OSDP sends four and offers no way to change that, so `4` is the only
    /// honest value and it is the default. Curriculum drill 4.2 sets it to 1 or
    /// 2 so a forgery completes while a learner is watching; see
    /// [`odr_osdp::SecureChannel::set_mac_len`] for what that does and does not
    /// claim. Four bytes still go on the wire either way — the ones beyond this
    /// count are zero, which is deliberately visible to anyone reading the bus.
    ///
    /// The [`AcuConfig`](crate::AcuConfig) at the other end must be set to
    /// match, or the handshake completes and every session frame then fails its
    /// MAC check.
    pub mac_len: u8,

    /// Whether this PD encrypts the payloads it seals, as opposed to merely
    /// authenticating them.
    ///
    /// `true` is normal: a sealed reply uses SCS_18, ciphertext and all. Setting
    /// it to `false` drops the PD to SCS_16 — a security block that carries a MAC
    /// and leaves the payload in the clear. That is a real, specified mode, and
    /// some deployments run it believing "secure channel is on" means the card
    /// number is hidden. It is not. This is what curriculum drill 4.4 is about,
    /// and why the null cipher needs to be reachable from a scenario rather than
    /// only constructible by hand.
    pub encrypt_payloads: bool,
}

impl Default for PdConfig {
    fn default() -> PdConfig {
        PdConfig {
            address: 0x01,
            pd_id: PdId {
                vendor_code: [0x00, 0x4F, 0x44],
                model: 1,
                version: 1,
                serial_number: [0x00, 0x00, 0x00, 0x01],
                firmware_major: 1,
                firmware_minor: 0,
                firmware_build: 0,
            },
            capabilities: default_capabilities(true, true),
            scbk: SCBK_D,
            key_type: KeyType::Default,
            sc: ScRequirement::Disabled,
            answer_clear_when_required: true,
            accept_keyset_unsecured: false,
            install_mode: false,
            cuid: [0xAA; 8],
            reply_delay_us: 2_000,
            busy_policy: BusyPolicy::Never,
            reader_number: 0,
            mac_len: 4,
            encrypt_payloads: true,
        }
    }
}

impl PdConfig {
    /// A PD at a given address with no Secure Channel — the overwhelmingly
    /// common deployment, and the starting point for Module 2.
    pub fn at(address: u8) -> PdConfig {
        PdConfig {
            address: address & 0x7F,
            ..PdConfig::default()
        }
    }

    /// Turn on Secure Channel with the published default key.
    pub fn with_default_key(mut self, requirement: ScRequirement) -> PdConfig {
        self.scbk = SCBK_D;
        self.key_type = KeyType::Default;
        self.sc = requirement;
        self.capabilities = default_capabilities(true, true);
        self
    }

    /// Turn on Secure Channel with a site key.
    pub fn with_site_key(mut self, scbk: [u8; 16], requirement: ScRequirement) -> PdConfig {
        self.scbk = scbk;
        self.key_type = KeyType::SiteKey;
        self.sc = requirement;
        self.capabilities = default_capabilities(true, false);
        self
    }

    /// Replace the capability report wholesale.
    pub fn with_capabilities(mut self, caps: PdCapabilities) -> PdConfig {
        self.capabilities = caps;
        self
    }

    /// Set the busy policy.
    pub fn with_busy(mut self, policy: BusyPolicy) -> PdConfig {
        self.busy_policy = policy;
        self
    }

    /// Run the secure channel as a null cipher — MAC only, payload in the clear —
    /// for curriculum drill 4.4. See [`PdConfig::encrypt_payloads`].
    pub fn with_null_cipher(mut self) -> PdConfig {
        self.encrypt_payloads = false;
        self
    }

    /// Rig the MAC width for curriculum drill 4.2. See [`PdConfig::mac_len`].
    pub fn with_mac_len(mut self, len: u8) -> PdConfig {
        self.mac_len = len.clamp(1, 4);
        self
    }

    /// True if this PD's key is the published default.
    pub fn uses_default_key(&self) -> bool {
        self.key_type == KeyType::Default
    }
}

/// A capability report for a reader that does or does not do crypto.
///
/// The entry the downgrade attack removes is
/// [`CapabilityFunction::CommunicationSecurity`]; everything else here is
/// ordinary furniture so that a capability reply looks like one.
pub fn default_capabilities(aes128: bool, default_key: bool) -> PdCapabilities {
    let mut entries = alloc::vec![
        Capability::new(CapabilityFunction::ContactStatusMonitoring, 1, 2),
        Capability::new(CapabilityFunction::OutputControl, 1, 1),
        Capability::new(CapabilityFunction::CardDataFormat, 1, 0),
        Capability::new(CapabilityFunction::ReaderLedControl, 1, 1),
        Capability::new(CapabilityFunction::ReaderAudibleOutput, 1, 1),
        Capability::new(CapabilityFunction::CheckCharacterSupport, 1, 0),
    ];
    if aes128 {
        entries.push(Capability::new(
            CapabilityFunction::CommunicationSecurity,
            0x01,
            if default_key { 0x01 } else { 0x00 },
        ));
    }
    entries.push(Capability::new(CapabilityFunction::Readers, 1, 1));
    entries.push(Capability::new(CapabilityFunction::OsdpVersion, 2, 2));
    PdCapabilities { entries }
}

/// Which protocol a reader speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderProtocol {
    /// Wiegand D0/D1.
    Wiegand,
    /// Clock-and-data (ABA track 2).
    ClockData(ClockDataConfig),
    /// OSDP over RS-485.
    Osdp(Box<PdConfig>),
}

impl ReaderProtocol {
    /// A short name for the UI.
    pub fn name(&self) -> &'static str {
        match self {
            ReaderProtocol::Wiegand => "wiegand",
            ReaderProtocol::ClockData(_) => "clock-and-data",
            ReaderProtocol::Osdp(_) => "osdp",
        }
    }

    /// The OSDP configuration, if this is an OSDP reader.
    pub fn pd_config(&self) -> Option<&PdConfig> {
        match self {
            ReaderProtocol::Osdp(c) => Some(c),
            _ => None,
        }
    }
}

/// A card read the PD is holding until the controller next polls it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldRead {
    /// Which token produced it.
    pub source: SourceId,
    /// What the bits claim to be.
    pub format: FormatId,
    /// The bits.
    pub bits: BitVec,
    /// When the reader finished reading it.
    pub at_us: Micros,
}

/// The OSDP PD's live protocol state.
#[derive(Debug, Clone, Default)]
pub struct PdRuntime {
    /// The sequence number the PD expects on the next command.
    pub expected_sequence: u8,
    /// The reply sent last, retransmitted if the ACU repeats a sequence
    /// number. Two bits of sequence and an unauthenticated retransmit is the
    /// whole of OSDP's replay defence.
    pub last_reply: Option<Box<Frame>>,
    /// The sequence number the last reply answered.
    pub last_sequence: Option<u8>,
    /// The secure channel, once a handshake has started.
    pub channel: Option<SecureChannel>,
    /// True once the session is usable.
    pub secure: bool,
    /// How many more commands get `REPLY_BUSY`.
    pub busy_left: u8,
    /// A card read waiting for the next poll.
    pub held_read: Option<HeldRead>,
    /// Whether a `CMD_KEYSET` has been accepted in this run.
    pub keyset_accepted: bool,
}

/// A reader.
pub struct Reader {
    /// Handle.
    pub id: ReaderId,
    /// A name for the UI.
    pub name: String,
    /// Which protocol it speaks.
    pub protocol: ReaderProtocol,
    /// Which link it is attached to.
    pub link: Option<LinkId>,
    /// How long it takes from a card being presented to bits leaving.
    pub read_time_us: Micros,
    /// The OSDP protocol state, present only for OSDP readers.
    pub osdp: PdRuntime,
    pub(crate) source: Option<Box<dyn CredentialSource>>,
    pub(crate) emit_token: u64,
    pub(crate) pending: Option<Presentation>,
}

impl core::fmt::Debug for Reader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reader")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("link", &self.link)
            .field("osdp", &self.osdp)
            .field("has_source", &self.source.is_some())
            .finish()
    }
}

/// What a PD decided to do about one command.
#[derive(Debug, Default)]
pub(crate) struct PdOutcome {
    pub(crate) reply: Option<Frame>,
    pub(crate) protocol: Vec<ProtocolEvent>,
    pub(crate) secure_channel: Vec<ScEvent>,
    /// The card read this reply carried, so the world can record that the PD
    /// has handed it over.
    pub(crate) delivered_read: Option<HeldRead>,
}

impl Reader {
    /// A reader speaking a given protocol.
    pub fn new(id: ReaderId, name: impl Into<String>, protocol: ReaderProtocol) -> Reader {
        Reader {
            id,
            name: name.into(),
            protocol,
            link: None,
            read_time_us: 50_000,
            osdp: PdRuntime::default(),
            source: None,
            emit_token: 0,
            pending: None,
        }
    }

    /// Set how long a read takes.
    pub fn with_read_time(mut self, us: Micros) -> Reader {
        self.read_time_us = us;
        self
    }

    /// The OSDP configuration, if this is an OSDP reader.
    pub fn pd_config(&self) -> Option<&PdConfig> {
        self.protocol.pd_config()
    }

    /// The OSDP configuration for mutation, if this is an OSDP reader.
    pub fn pd_config_mut(&mut self) -> Option<&mut PdConfig> {
        match &mut self.protocol {
            ReaderProtocol::Osdp(c) => Some(c),
            _ => None,
        }
    }

    /// The bus address, if this is an OSDP reader.
    pub fn address(&self) -> Option<u8> {
        self.pd_config().map(|c| c.address)
    }

    /// The SCBK this PD is configured with.
    ///
    /// Exposed because curriculum drill 3.3's flag is "attacker-recovered SCBK
    /// equals the PD's configured SCBK", which is not a question that can be
    /// asked without it. This is a simulator; the key is a scenario parameter,
    /// not a secret.
    pub fn scbk(&self) -> Option<[u8; 16]> {
        self.pd_config().map(|c| c.scbk)
    }

    /// True if this PD currently has an established secure channel.
    pub fn secure_channel_established(&self) -> bool {
        self.osdp.secure
    }

    // -- credential ----------------------------------------------------------

    /// Attach a token that will be asked for bits when it is presented.
    pub fn set_source(&mut self, source: Box<dyn CredentialSource>) {
        self.source = Some(source);
    }

    /// Whether a token is attached.
    pub fn has_source(&self) -> bool {
        self.source.is_some()
    }

    pub(crate) fn pull_source(&mut self, at_us: Micros) -> Option<Presentation> {
        self.source.as_mut()?.present(at_us)
    }

    // -- OSDP ----------------------------------------------------------------

    /// Reset the PD's protocol state, as a power cycle would.
    pub fn reset_protocol(&mut self) {
        self.osdp.expected_sequence = 0;
        self.osdp.last_reply = None;
        self.osdp.last_sequence = None;
        self.osdp.channel = None;
        self.osdp.secure = false;
    }

    fn next_sequence(current: u8) -> u8 {
        match current & 0x03 {
            3 => 1,
            other => other + 1,
        }
    }

    /// Handle one command frame and produce the reply.
    ///
    /// Never panics and never returns an error: a PD that cannot make sense of
    /// a frame answers `NAK` or says nothing at all, which is what real
    /// hardware does and what an attacker probing the bus needs to see.
    pub(crate) fn handle_command(&mut self, frame: &Frame, rng: &mut SeededRng) -> PdOutcome {
        let mut out = PdOutcome::default();
        let cfg = match self.protocol.pd_config() {
            Some(c) => c.clone(),
            None => return out,
        };
        if frame.is_reply {
            return out;
        }
        let addressed = frame.address == cfg.address || frame.is_broadcast();
        if !addressed {
            return out;
        }

        // -- sequence handling -------------------------------------------
        let seq = frame.sequence & 0x03;
        if seq == 0 {
            // "I have just started." Everything resets, including any secure
            // session, because the ACU cannot have kept one.
            self.osdp.expected_sequence = 0;
            self.osdp.channel = None;
            self.osdp.secure = false;
            out.protocol.push(ProtocolEvent::SequenceReset {
                address: cfg.address,
            });
        } else if seq != self.osdp.expected_sequence {
            if Some(seq) == self.osdp.last_sequence {
                // A retry. Repeat the previous answer verbatim; do not
                // re-execute the command. Two bits of sequence number and an
                // unauthenticated retransmit is all of OSDP's replay defence.
                out.reply = self.osdp.last_reply.as_deref().cloned();
                return out;
            }
            out.protocol.push(ProtocolEvent::SequenceMismatch {
                address: cfg.address,
                expected: self.osdp.expected_sequence,
                got: seq,
            });
            let nak = Frame::reply(
                cfg.address,
                seq,
                Reply::Nak,
                Nak::new(NakError::SequenceNumber).encode(),
            );
            self.remember(&nak, seq);
            out.reply = Some(nak);
            return out;
        }

        // -- busy --------------------------------------------------------
        if self.osdp.busy_left > 0 {
            self.osdp.busy_left = self.osdp.busy_left.saturating_sub(1);
            let busy = Frame::reply(cfg.address, seq, Reply::Busy, Vec::new());
            self.remember(&busy, seq);
            self.osdp.expected_sequence = Self::next_sequence(seq);
            out.protocol.push(ProtocolEvent::Busy {
                address: cfg.address,
            });
            out.reply = Some(busy);
            return out;
        }

        // -- secured frames ----------------------------------------------
        let secured_in = frame.scs_type().is_some_and(|s| s.has_mac());
        let mut plaintext = frame.payload.clone();
        if secured_in {
            match self.osdp.channel.as_mut() {
                Some(ch) => match ch.open(frame) {
                    Ok(p) => plaintext = p,
                    Err(e) => {
                        out.protocol.push(ProtocolEvent::FrameRejected {
                            address: cfg.address,
                            reason: alloc::format!("secure channel rejected the frame: {e:?}"),
                        });
                        let nak = Frame::reply(
                            cfg.address,
                            seq,
                            Reply::Nak,
                            Nak::new(NakError::SecurityConditionsNotMet).encode(),
                        );
                        self.remember(&nak, seq);
                        self.osdp.expected_sequence = Self::next_sequence(seq);
                        out.reply = Some(nak);
                        return out;
                    }
                },
                None => {
                    out.protocol.push(ProtocolEvent::FrameRejected {
                        address: cfg.address,
                        reason: "secured frame with no session".to_string(),
                    });
                    let nak = Frame::reply(
                        cfg.address,
                        seq,
                        Reply::Nak,
                        Nak::new(NakError::SecurityConditionsNotMet).encode(),
                    );
                    self.remember(&nak, seq);
                    self.osdp.expected_sequence = Self::next_sequence(seq);
                    out.reply = Some(nak);
                    return out;
                }
            }
        } else if cfg.sc.requires() && !cfg.answer_clear_when_required && !self.is_handshake(frame)
        {
            out.protocol.push(ProtocolEvent::FrameRejected {
                address: cfg.address,
                reason: "policy requires secure channel and this frame was in the clear"
                    .to_string(),
            });
            let nak = Frame::reply(
                cfg.address,
                seq,
                Reply::Nak,
                Nak::new(NakError::SecurityConditionsNotMet).encode(),
            );
            self.remember(&nak, seq);
            self.osdp.expected_sequence = Self::next_sequence(seq);
            out.reply = Some(nak);
            return out;
        }

        // -- the command itself ------------------------------------------
        let reply = self.execute(&cfg, frame, seq, &plaintext, rng, &mut out);
        if let Some(r) = &reply {
            self.remember(r, seq);
            self.osdp.expected_sequence = Self::next_sequence(seq);
        }
        out.reply = reply;
        out
    }

    fn is_handshake(&self, frame: &Frame) -> bool {
        matches!(
            frame.command_code(),
            Some(Command::Chlng) | Some(Command::Scrypt)
        )
    }

    fn remember(&mut self, frame: &Frame, seq: u8) {
        self.osdp.last_reply = Some(Box::new(frame.clone()));
        self.osdp.last_sequence = Some(seq);
    }

    fn seal_or_plain(
        &mut self,
        cfg: &PdConfig,
        seq: u8,
        reply: Reply,
        payload: Vec<u8>,
        encrypt: bool,
    ) -> Frame {
        if self.osdp.secure {
            if let Some(ch) = self.osdp.channel.as_mut() {
                if let Ok(f) = ch.seal(cfg.address, seq, reply.to_u8(), &payload, encrypt) {
                    return f;
                }
            }
        }
        Frame::reply(cfg.address, seq, reply, payload)
    }

    fn execute(
        &mut self,
        cfg: &PdConfig,
        frame: &Frame,
        seq: u8,
        plaintext: &[u8],
        rng: &mut SeededRng,
        out: &mut PdOutcome,
    ) -> Option<Frame> {
        let cmd = frame.command_code();
        match cmd {
            Some(Command::Poll) => {
                if let Some(read) = self.osdp.held_read.take() {
                    let raw = RawCardRead::from_bits(cfg.reader_number, 0, read.bits.as_slice());
                    out.protocol.push(ProtocolEvent::CardReadReported {
                        address: cfg.address,
                        format_code: raw.format_code,
                        bit_count: raw.bit_count,
                    });
                    let frame = self.seal_or_plain(
                        cfg,
                        seq,
                        Reply::Raw,
                        raw.encode(),
                        cfg.encrypt_payloads,
                    );
                    out.delivered_read = Some(read);
                    Some(frame)
                } else {
                    Some(self.seal_or_plain(cfg, seq, Reply::Ack, Vec::new(), false))
                }
            }
            Some(Command::Id) => {
                Some(self.seal_or_plain(cfg, seq, Reply::PdId, cfg.pd_id.encode(), false))
            }
            Some(Command::Cap) => {
                let payload = cfg.capabilities.encode();
                Some(self.seal_or_plain(cfg, seq, Reply::PdCap, payload, false))
            }
            Some(Command::Chlng) => {
                if !cfg.sc.wants_secure_channel() {
                    out.secure_channel.push(ScEvent::Failed {
                        address: cfg.address,
                        reason: "secure channel disabled on this PD".to_string(),
                    });
                    return Some(Frame::reply(
                        cfg.address,
                        seq,
                        Reply::Nak,
                        Nak::new(NakError::SecureChannelUnsupported).encode(),
                    ));
                }
                let mut ch =
                    SecureChannel::pd(cfg.scbk, cfg.key_type, cfg.cuid).with_mac_len(cfg.mac_len);
                let rnd_b = rng.nonce8();
                match ch.handle_challenge(frame, rnd_b) {
                    Ok(reply) => {
                        self.osdp.channel = Some(ch);
                        self.osdp.secure = false;
                        Some(reply)
                    }
                    Err(e) => {
                        out.secure_channel.push(ScEvent::Failed {
                            address: cfg.address,
                            reason: alloc::format!("{e:?}"),
                        });
                        Some(Frame::reply(
                            cfg.address,
                            seq,
                            Reply::Nak,
                            Nak::new(NakError::SecurityConditionsNotMet).encode(),
                        ))
                    }
                }
            }
            Some(Command::Scrypt) => match self.osdp.channel.as_mut() {
                Some(ch) => match ch.handle_scrypt(frame) {
                    Ok(reply) => {
                        self.osdp.secure = true;
                        out.secure_channel.push(ScEvent::Established {
                            address: cfg.address,
                            key_type: cfg.key_type,
                            encrypted: true,
                        });
                        Some(reply)
                    }
                    Err(e) => {
                        self.osdp.secure = false;
                        out.secure_channel.push(ScEvent::Failed {
                            address: cfg.address,
                            reason: alloc::format!("{e:?}"),
                        });
                        Some(Frame::reply(
                            cfg.address,
                            seq,
                            Reply::Nak,
                            Nak::new(NakError::SecurityConditionsNotMet).encode(),
                        ))
                    }
                },
                None => Some(Frame::reply(
                    cfg.address,
                    seq,
                    Reply::Nak,
                    Nak::new(NakError::SecurityConditionsNotMet).encode(),
                )),
            },
            Some(Command::Keyset) => {
                let allowed = self.osdp.secure || cfg.accept_keyset_unsecured;
                if !allowed {
                    return Some(Frame::reply(
                        cfg.address,
                        seq,
                        Reply::Nak,
                        Nak::new(NakError::SecurityConditionsNotMet).encode(),
                    ));
                }
                match KeysetCommand::decode(plaintext)
                    .ok()
                    .and_then(|k| k.as_aes128())
                {
                    Some(key) => {
                        if let Some(c) = self.pd_config_mut() {
                            c.scbk = key;
                            c.key_type = KeyType::SiteKey;
                            c.install_mode = false;
                        }
                        self.osdp.keyset_accepted = true;
                        out.secure_channel.push(ScEvent::KeysetAccepted {
                            address: cfg.address,
                        });
                        let mut cfg2 = cfg.clone();
                        cfg2.key_type = KeyType::SiteKey;
                        Some(self.seal_or_plain(&cfg2, seq, Reply::Ack, Vec::new(), false))
                    }
                    None => Some(Frame::reply(
                        cfg.address,
                        seq,
                        Reply::Nak,
                        Nak::new(NakError::CommandLength).encode(),
                    )),
                }
            }
            Some(Command::Comset) => match ComsetCommand::decode(plaintext) {
                Ok(c) => {
                    if let Some(k) = self.pd_config_mut() {
                        k.address = c.address & 0x7F;
                    }
                    let mut cfg2 = cfg.clone();
                    cfg2.address = c.address & 0x7F;
                    Some(self.seal_or_plain(&cfg2, seq, Reply::Com, c.encode(), false))
                }
                Err(_) => Some(Frame::reply(
                    cfg.address,
                    seq,
                    Reply::Nak,
                    Nak::new(NakError::CommandLength).encode(),
                )),
            },
            Some(Command::Out)
            | Some(Command::Led)
            | Some(Command::Buz)
            | Some(Command::Text)
            | Some(Command::AcuRxSize) => {
                Some(self.seal_or_plain(cfg, seq, Reply::Ack, Vec::new(), false))
            }
            Some(Command::Lstat) | Some(Command::Istat) | Some(Command::Ostat)
            | Some(Command::Rstat) => {
                Some(self.seal_or_plain(cfg, seq, Reply::Ack, Vec::new(), false))
            }
            _ => Some(Frame::reply(
                cfg.address,
                seq,
                Reply::Nak,
                Nak::new(NakError::UnknownCommand).encode(),
            )),
        }
    }
}

/// Turn a presentation into the bits a clock-and-data reader puts on the wire.
///
/// If the presentation is already ABA track 2, it goes out as it is. Otherwise
/// the reader decodes it as a card, builds the decimal digits a magstripe
/// reader would emit, and encodes those as track 2. Returns `None` when the
/// bits cannot be read as either.
pub(crate) fn clock_data_bits(
    cfg: &ClockDataConfig,
    presentation: &Presentation,
) -> Option<BitVec> {
    if presentation.format == FormatId::ABA_TRACK2 {
        return Some(presentation.bits.clone());
    }
    let decoded = match cfg.assumed_format {
        Some(f) => odr_wiegand::decode(f, &presentation.bits).ok()?,
        None => {
            odr_wiegand::infer_formats(&presentation.bits)
                .into_iter()
                .next()?
                .decoded
        }
    };
    let card = decoded.card_number?;
    let mut digits = String::new();
    if let Some(fc) = decoded.facility_code {
        digits.push_str(&alloc::format!("{fc:05}"));
    }
    digits.push_str(&alloc::format!("{card}"));
    let track = AbaTrack2::from_ascii(&digits).ok()?;
    Some(track.encode(&cfg.encoding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_wraps_one_two_three() {
        assert_eq!(Reader::next_sequence(0), 1);
        assert_eq!(Reader::next_sequence(1), 2);
        assert_eq!(Reader::next_sequence(2), 3);
        assert_eq!(Reader::next_sequence(3), 1);
    }

    #[test]
    fn stripping_the_security_capability_is_visible_on_the_report() {
        let mut caps = default_capabilities(true, true);
        assert!(caps.claims_aes128());
        assert!(caps.uses_default_key());
        assert!(caps.strip_security_capability());
        assert!(!caps.claims_aes128());
    }
}
