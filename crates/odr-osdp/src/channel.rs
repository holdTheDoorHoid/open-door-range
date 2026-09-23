//! OSDP Secure Channel: the handshake, and sealing/opening frames afterwards.
//!
//! One [`SecureChannel`] represents one end of one session. Drive two of them
//! against each other and you have a working bus; drive one against a capture
//! and you have an analyser.
//!
//! # The handshake, in four frames
//!
//! ```text
//! ACU                                                       PD
//!  |-- CMD_CHLNG      SCS_11  RND.A (8) ------------------->|
//!  |                                                        |  derive S-ENC,
//!  |                                                        |  S-MAC1, S-MAC2
//!  |<- REPLY_CCRYPT   SCS_12  cUID(8) RND.B(8) CCRYPT(16) --|
//!  |  verify client cryptogram                              |
//!  |-- CMD_SCRYPT     SCS_13  server cryptogram (16) ------>|
//!  |                                      verify it, derive |
//!  |                                      the initial R-MAC |
//!  |<- REPLY_RMAC_I   SCS_14  R-MAC_0 (16) -----------------|
//!  |                                                        |
//!  |========== session established, SCS_15..18 =============|
//! ```
//!
//! Both sides prove they hold the SCBK, and both end up with the same three
//! session keys and the same MAC chain state. Nothing else about the session is
//! negotiated — no cipher suite, no version, no key length. AES-128, CBC,
//! CBC-MAC, take it or leave it.
//!
//! # What this session does not give you
//!
//! Faithfully implemented, and deliberately not repaired:
//!
//! * **The MAC is truncated to 32 bits.** See [`crate::crypto::truncate_mac`].
//! * **IVs come from MACs.** Encryption IVs are the ones' complement of the
//!   previous MAC in the opposite direction, so they are fully predictable from
//!   traffic already seen. Worse, the chain in one direction only advances when
//!   the *other* direction speaks: two commands sent back to back, with no
//!   reply between them, encrypt under the identical IV and MAC from the
//!   identical IV. See the tests
//!   `two_consecutive_commands_reuse_the_same_cbc_iv` and
//!   `a_replayed_command_is_only_stopped_once_a_reply_has_advanced_the_chain`.
//! * **Only 48 bits of RND.A reach the key derivation**, and RND.B reaches none
//!   of it — the PD contributes zero entropy to the session keys.
//! * **The command/reply id is never encrypted**, so traffic analysis works.
//! * **The handshake is not bound to the capability exchange** that preceded
//!   it, which is what lets a downgrade happen before this code ever runs.
//! * **SCS_15/SCS_16 are a supported mode** in which nothing is encrypted at
//!   all.
//!
//! # Determinism
//!
//! Every nonce is a parameter. [`SecureChannel::challenge`] takes RND.A;
//! [`SecureChannel::handle_challenge`] takes RND.B. Nothing in this module
//! reads a clock or an entropy source. Use [`crate::rng::SeededRng`] if you
//! want reproducible pseudo-random nonces.

use crate::codes::{Command, Reply};
use crate::crypto::{
    cbc_decrypt, cbc_encrypt, cbc_mac, client_cryptogram, derive_session_keys, ecb_encrypt_block,
    iv_from_mac, pad_for_encryption, server_cryptogram, strip_padding, truncate_mac, SessionKeys,
    BLOCK,
};
use crate::frame::Frame;
use crate::payload::{Ccrypt, PayloadError};
use crate::security::{KeyType, ScsType, SecurityBlock};
use crate::weak_keys::{self, WeakKeyPattern};
use alloc::vec::Vec;
use core::fmt;

/// Which end of the bus this channel is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Access Control Unit: the controller, the panel. Sends commands.
    Acu,
    /// Peripheral Device: the reader. Sends replies, and only when polled.
    Pd,
}

impl Role {
    /// The other end.
    pub fn peer(self) -> Role {
        match self {
            Role::Acu => Role::Pd,
            Role::Pd => Role::Acu,
        }
    }
}

/// Where a channel is in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelState {
    /// Nothing has happened yet.
    Idle,
    /// ACU: `CMD_CHLNG` sent, waiting for `REPLY_CCRYPT`.
    /// PD: `CMD_CHLNG` received and answered, waiting for `CMD_SCRYPT`.
    Challenged,
    /// ACU: `CMD_SCRYPT` sent, waiting for `REPLY_RMAC_I`.
    Cryptogram,
    /// Both sides authenticated; SCS_15..SCS_18 traffic may flow.
    Established,
    /// The handshake failed. A channel in this state will not seal or open
    /// anything; build a new one.
    Failed,
}

impl ChannelState {
    /// Can this channel seal and open session frames?
    pub fn is_established(self) -> bool {
        matches!(self, ChannelState::Established)
    }
}

/// Everything that can go wrong driving a secure channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// The operation is not legal from the channel's current state.
    WrongState {
        /// Where the channel actually is.
        state: ChannelState,
    },
    /// This operation belongs to the other role.
    WrongRole {
        /// The role this channel actually has.
        role: Role,
    },
    /// The frame's command or reply code is not the one expected here.
    UnexpectedCode {
        /// The raw id byte that arrived.
        got: u8,
    },
    /// The frame has no security block, or the wrong kind for this step.
    UnexpectedSecurityBlock {
        /// The security block type that arrived, if it was recognised.
        got: Option<ScsType>,
    },
    /// A payload could not be decoded.
    Payload(PayloadError),
    /// The peer's cryptogram did not verify.
    ///
    /// This means the two ends do not hold the same SCBK — or that someone in
    /// the middle is not who they claim to be. It is the one moment in OSDP
    /// where authentication actually bites.
    CryptogramMismatch,
    /// A session frame arrived with no MAC field.
    MissingMac,
    /// The 32-bit MAC did not match.
    ///
    /// Thirty-two bits, so a blind forgery succeeds about one time in four
    /// billion. There is no attempt limiter anywhere in the protocol.
    MacMismatch {
        /// The MAC the frame carried.
        got: [u8; 4],
        /// The MAC this end computed.
        expected: [u8; 4],
    },
    /// An encrypted payload was not a whole number of AES blocks.
    NotBlockAligned {
        /// The payload length that arrived.
        len: usize,
    },
    /// A frame arrived from the wrong direction for this channel's role — a PD
    /// receiving a reply, say.
    WrongDirection,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelError::WrongState { state } => {
                write!(f, "operation not valid in state {state:?}")
            }
            ChannelError::WrongRole { role } => write!(f, "operation not valid for role {role:?}"),
            ChannelError::UnexpectedCode { got } => {
                write!(f, "unexpected command/reply code 0x{got:02x}")
            }
            ChannelError::UnexpectedSecurityBlock { got } => {
                write!(f, "unexpected security block {got:?}")
            }
            ChannelError::Payload(e) => write!(f, "payload: {e}"),
            ChannelError::CryptogramMismatch => {
                write!(
                    f,
                    "cryptogram did not verify: the peer holds a different SCBK"
                )
            }
            ChannelError::MissingMac => write!(f, "session frame carried no MAC"),
            ChannelError::MacMismatch { got, expected } => write!(
                f,
                "MAC mismatch: frame carried {got:02x?}, computed {expected:02x?}"
            ),
            ChannelError::NotBlockAligned { len } => {
                write!(
                    f,
                    "encrypted payload of {len} bytes is not a multiple of 16"
                )
            }
            ChannelError::WrongDirection => write!(f, "frame travelling the wrong way"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChannelError {}

impl From<PayloadError> for ChannelError {
    fn from(e: PayloadError) -> Self {
        ChannelError::Payload(e)
    }
}

/// One end of one OSDP Secure Channel session.
///
/// Construct with [`SecureChannel::acu`] or [`SecureChannel::pd`], run the
/// handshake, then use [`SecureChannel::seal`] and [`SecureChannel::open`].
///
/// # Example: a complete session between two instances
///
/// ```
/// use odr_osdp::channel::{SecureChannel, Role};
/// use odr_osdp::codes::{Command, Reply};
/// use odr_osdp::security::KeyType;
/// use odr_osdp::weak_keys::SCBK_D;
///
/// let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
/// let mut pd  = SecureChannel::pd(SCBK_D, KeyType::Default, [0xAA; 8]);
///
/// let chlng  = acu.challenge(1, 0, [0x01; 8]).unwrap();
/// let ccrypt = pd.handle_challenge(&chlng, [0x02; 8]).unwrap();
/// let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
/// let rmac   = pd.handle_scrypt(&scrypt).unwrap();
/// acu.handle_rmac_i(&rmac).unwrap();
/// assert!(acu.state().is_established() && pd.state().is_established());
///
/// // An encrypted command, and the PD reading it.
/// let cmd = acu.seal(1, 2, Command::Out.to_u8(), &[0, 1, 50, 0], true).unwrap();
/// assert_eq!(pd.open(&cmd).unwrap(), vec![0, 1, 50, 0]);
/// ```
#[derive(Debug, Clone)]
pub struct SecureChannel {
    role: Role,
    state: ChannelState,
    scbk: [u8; BLOCK],
    key_type: KeyType,
    cuid: [u8; 8],
    rnd_a: [u8; 8],
    rnd_b: [u8; 8],
    keys: Option<SessionKeys>,
    client_cryptogram: [u8; BLOCK],
    server_cryptogram: [u8; BLOCK],
    c_mac: [u8; BLOCK],
    r_mac: [u8; BLOCK],
}

impl SecureChannel {
    fn new(role: Role, scbk: [u8; BLOCK], key_type: KeyType, cuid: [u8; 8]) -> Self {
        Self {
            role,
            state: ChannelState::Idle,
            scbk,
            key_type,
            cuid,
            rnd_a: [0; 8],
            rnd_b: [0; 8],
            keys: None,
            client_cryptogram: [0; BLOCK],
            server_cryptogram: [0; BLOCK],
            c_mac: [0; BLOCK],
            r_mac: [0; BLOCK],
        }
    }

    /// Create the controller side.
    ///
    /// `key_type` is what the ACU announces in the handshake security block;
    /// it should match what `scbk` actually is, and a mismatch is exactly the
    /// kind of thing a drill might want to stage.
    pub fn acu(scbk: [u8; BLOCK], key_type: KeyType) -> Self {
        Self::new(Role::Acu, scbk, key_type, [0; 8])
    }

    /// Create the reader side. `cuid` is the PD's unique identifier, sent in
    /// the clear in `REPLY_CCRYPT`.
    pub fn pd(scbk: [u8; BLOCK], key_type: KeyType, cuid: [u8; 8]) -> Self {
        Self::new(Role::Pd, scbk, key_type, cuid)
    }

    /// Which end this is.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Where the handshake has got to.
    pub fn state(&self) -> ChannelState {
        self.state
    }

    /// The derived session keys, once the challenge has been processed.
    ///
    /// Exposed so an attack actor can demonstrate that recovering the SCBK
    /// really does yield the session keys, and so a detector can show a
    /// learner what the derivation produced.
    pub fn session_keys(&self) -> Option<&SessionKeys> {
        self.keys.as_ref()
    }

    /// The current C-MAC — the last MAC computed in the ACU-to-PD direction.
    ///
    /// Public because the next reply's encryption IV is its ones' complement,
    /// and showing that to a learner is the point of the exercise.
    pub fn c_mac(&self) -> [u8; BLOCK] {
        self.c_mac
    }

    /// The current R-MAC — the last MAC computed in the PD-to-ACU direction,
    /// seeded by `REPLY_RMAC_I`.
    pub fn r_mac(&self) -> [u8; BLOCK] {
        self.r_mac
    }

    /// The nonces exchanged, once known: `(RND.A, RND.B)`.
    pub fn nonces(&self) -> ([u8; 8], [u8; 8]) {
        (self.rnd_a, self.rnd_b)
    }

    // -- handshake, ACU side -------------------------------------------------

    /// **ACU.** Build `CMD_CHLNG` carrying `rnd_a`.
    ///
    /// The nonce is supplied by the caller so the exchange is reproducible.
    pub fn challenge(
        &mut self,
        address: u8,
        sequence: u8,
        rnd_a: [u8; 8],
    ) -> Result<Frame, ChannelError> {
        if self.role != Role::Acu {
            return Err(ChannelError::WrongRole { role: self.role });
        }
        self.rnd_a = rnd_a;
        self.keys = Some(derive_session_keys(&self.scbk, &rnd_a));
        self.state = ChannelState::Challenged;

        let mut frame = Frame::command(address, sequence, Command::Chlng, rnd_a.to_vec());
        frame.security = Some(SecurityBlock::handshake(ScsType::Chlng, self.key_type));
        Ok(frame)
    }

    /// **ACU.** Verify `REPLY_CCRYPT` and build `CMD_SCRYPT`.
    ///
    /// This is where the PD is actually authenticated: if
    /// [`ChannelError::CryptogramMismatch`] comes back, the reader does not
    /// hold the key the controller thinks it does.
    pub fn handle_ccrypt(&mut self, frame: &Frame, sequence: u8) -> Result<Frame, ChannelError> {
        if self.role != Role::Acu {
            return Err(ChannelError::WrongRole { role: self.role });
        }
        if self.state != ChannelState::Challenged {
            return Err(ChannelError::WrongState { state: self.state });
        }
        if !frame.is_reply {
            return Err(ChannelError::WrongDirection);
        }
        if frame.reply_code() != Some(Reply::Ccrypt) {
            return Err(ChannelError::UnexpectedCode { got: frame.id });
        }
        if frame.scs_type() != Some(ScsType::Ccrypt) {
            return Err(ChannelError::UnexpectedSecurityBlock {
                got: frame.scs_type(),
            });
        }

        let body = Ccrypt::decode(&frame.payload)?;
        let keys = match self.keys {
            Some(k) => k,
            None => return Err(ChannelError::WrongState { state: self.state }),
        };
        let expected = client_cryptogram(&keys.s_enc, &self.rnd_a, &body.rnd_b);
        if expected != body.client_cryptogram {
            self.state = ChannelState::Failed;
            return Err(ChannelError::CryptogramMismatch);
        }

        self.cuid = body.cuid;
        self.rnd_b = body.rnd_b;
        self.client_cryptogram = body.client_cryptogram;
        self.server_cryptogram = server_cryptogram(&keys.s_enc, &self.rnd_a, &self.rnd_b);
        self.state = ChannelState::Cryptogram;

        let mut out = Frame::command(
            frame.address,
            sequence,
            Command::Scrypt,
            self.server_cryptogram.to_vec(),
        );
        out.security = Some(SecurityBlock::handshake(ScsType::Scrypt, self.key_type));
        Ok(out)
    }

    /// **ACU.** Accept `REPLY_RMAC_I` and open the session.
    ///
    /// The payload seeds the MAC chain. Note the ACU does not have to trust it
    /// blindly: it can compute the same value itself, and this method checks
    /// that it matches.
    pub fn handle_rmac_i(&mut self, frame: &Frame) -> Result<(), ChannelError> {
        if self.role != Role::Acu {
            return Err(ChannelError::WrongRole { role: self.role });
        }
        if self.state != ChannelState::Cryptogram {
            return Err(ChannelError::WrongState { state: self.state });
        }
        if !frame.is_reply {
            return Err(ChannelError::WrongDirection);
        }
        if frame.reply_code() != Some(Reply::RmacI) {
            return Err(ChannelError::UnexpectedCode { got: frame.id });
        }
        if frame.scs_type() != Some(ScsType::RmacI) {
            return Err(ChannelError::UnexpectedSecurityBlock {
                got: frame.scs_type(),
            });
        }
        if frame.payload.len() < BLOCK {
            self.state = ChannelState::Failed;
            return Err(ChannelError::Payload(PayloadError::TooShort {
                expected: BLOCK,
                actual: frame.payload.len(),
            }));
        }
        let keys = match self.keys {
            Some(k) => k,
            None => return Err(ChannelError::WrongState { state: self.state }),
        };
        let expected = initial_rmac(&keys, &self.server_cryptogram);
        if frame.payload[..BLOCK] != expected {
            self.state = ChannelState::Failed;
            return Err(ChannelError::CryptogramMismatch);
        }
        self.r_mac = expected;
        self.c_mac = [0; BLOCK];
        self.state = ChannelState::Established;
        Ok(())
    }

    // -- handshake, PD side --------------------------------------------------

    /// **PD.** Answer `CMD_CHLNG` with `REPLY_CCRYPT`, using `rnd_b` as this
    /// end's nonce.
    ///
    /// Everything this reply contains — the PD's identifier, the nonce, and the
    /// cryptogram — goes out unprotected, because there is no session yet.
    pub fn handle_challenge(
        &mut self,
        frame: &Frame,
        rnd_b: [u8; 8],
    ) -> Result<Frame, ChannelError> {
        if self.role != Role::Pd {
            return Err(ChannelError::WrongRole { role: self.role });
        }
        if frame.is_reply {
            return Err(ChannelError::WrongDirection);
        }
        if frame.command_code() != Some(Command::Chlng) {
            return Err(ChannelError::UnexpectedCode { got: frame.id });
        }
        if frame.scs_type() != Some(ScsType::Chlng) {
            return Err(ChannelError::UnexpectedSecurityBlock {
                got: frame.scs_type(),
            });
        }
        if frame.payload.len() < 8 {
            return Err(ChannelError::Payload(PayloadError::TooShort {
                expected: 8,
                actual: frame.payload.len(),
            }));
        }

        let mut rnd_a = [0u8; 8];
        rnd_a.copy_from_slice(&frame.payload[..8]);
        self.rnd_a = rnd_a;
        self.rnd_b = rnd_b;
        let keys = derive_session_keys(&self.scbk, &rnd_a);
        self.client_cryptogram = client_cryptogram(&keys.s_enc, &rnd_a, &rnd_b);
        self.server_cryptogram = server_cryptogram(&keys.s_enc, &rnd_a, &rnd_b);
        self.keys = Some(keys);
        self.state = ChannelState::Challenged;

        let body = Ccrypt {
            cuid: self.cuid,
            rnd_b,
            client_cryptogram: self.client_cryptogram,
        };
        let mut out = Frame::reply(frame.address, frame.sequence, Reply::Ccrypt, body.encode());
        out.security = Some(SecurityBlock::handshake(ScsType::Ccrypt, self.key_type));
        Ok(out)
    }

    /// **PD.** Verify `CMD_SCRYPT` and answer with `REPLY_RMAC_I`, opening the
    /// session.
    pub fn handle_scrypt(&mut self, frame: &Frame) -> Result<Frame, ChannelError> {
        if self.role != Role::Pd {
            return Err(ChannelError::WrongRole { role: self.role });
        }
        if self.state != ChannelState::Challenged {
            return Err(ChannelError::WrongState { state: self.state });
        }
        if frame.is_reply {
            return Err(ChannelError::WrongDirection);
        }
        if frame.command_code() != Some(Command::Scrypt) {
            return Err(ChannelError::UnexpectedCode { got: frame.id });
        }
        if frame.scs_type() != Some(ScsType::Scrypt) {
            return Err(ChannelError::UnexpectedSecurityBlock {
                got: frame.scs_type(),
            });
        }
        if frame.payload.len() < BLOCK {
            return Err(ChannelError::Payload(PayloadError::TooShort {
                expected: BLOCK,
                actual: frame.payload.len(),
            }));
        }
        if frame.payload[..BLOCK] != self.server_cryptogram {
            self.state = ChannelState::Failed;
            return Err(ChannelError::CryptogramMismatch);
        }

        let keys = match self.keys {
            Some(k) => k,
            None => return Err(ChannelError::WrongState { state: self.state }),
        };
        let rmac = initial_rmac(&keys, &self.server_cryptogram);
        self.r_mac = rmac;
        self.c_mac = [0; BLOCK];
        self.state = ChannelState::Established;

        let mut out = Frame::reply(frame.address, frame.sequence, Reply::RmacI, rmac.to_vec());
        out.security = Some(SecurityBlock::rmac_i(true));
        Ok(out)
    }

    // -- session traffic -----------------------------------------------------

    /// Build a secured frame carrying `id` and `plaintext`.
    ///
    /// The frame is a command if this channel is the ACU and a reply if it is
    /// the PD. `encrypt` selects between the MAC-only null cipher
    /// (SCS_15/SCS_16) and MAC-plus-encryption (SCS_17/SCS_18).
    ///
    /// An empty payload always uses SCS_15/SCS_16 even when `encrypt` is true:
    /// there is nothing to encrypt, so the standard does not ask for it. That
    /// is a small but real information leak — `POLL` and `ACK` are always
    /// visibly the cheap null-cipher shape.
    ///
    /// Sealing advances the MAC chain, so calling it twice for the same logical
    /// frame produces two different MACs and desynchronises the session.
    pub fn seal(
        &mut self,
        address: u8,
        sequence: u8,
        id: u8,
        plaintext: &[u8],
        encrypt: bool,
    ) -> Result<Frame, ChannelError> {
        if !self.state.is_established() {
            return Err(ChannelError::WrongState { state: self.state });
        }
        let keys = match self.keys {
            Some(k) => k,
            None => return Err(ChannelError::WrongState { state: self.state }),
        };
        let is_cmd = self.role == Role::Acu;

        // The IV for both encryption and the MAC comes from the MAC most
        // recently computed in the OPPOSITE direction.
        let chain_iv = if is_cmd { self.r_mac } else { self.c_mac };

        let (scs, payload) = if encrypt && !plaintext.is_empty() {
            let mut buf = pad_for_encryption(plaintext);
            cbc_encrypt(&keys.s_enc, &iv_from_mac(&chain_iv), &mut buf);
            (
                if is_cmd {
                    ScsType::CmdEncrypted
                } else {
                    ScsType::ReplyEncrypted
                },
                buf,
            )
        } else {
            (
                if is_cmd {
                    ScsType::CmdMacOnly
                } else {
                    ScsType::ReplyMacOnly
                },
                plaintext.to_vec(),
            )
        };

        let mut frame = Frame {
            mark: false,
            address: address & 0x7F,
            is_reply: !is_cmd,
            sequence: sequence & 0x03,
            use_crc: true,
            security: Some(SecurityBlock::new(scs)),
            id,
            payload,
            mac: None,
        };

        // Encrypt-then-MAC, over SOM..end-of-ciphertext with the length field
        // already final.
        let full = match cbc_mac(&keys, &chain_iv, &frame.bytes_for_mac()) {
            Some(m) => m,
            None => return Err(ChannelError::WrongState { state: self.state }),
        };
        frame.mac = Some(truncate_mac(&full));
        if is_cmd {
            self.c_mac = full;
        } else {
            self.r_mac = full;
        }
        Ok(frame)
    }

    /// Verify and decrypt a secured frame from the peer, returning the
    /// plaintext payload.
    ///
    /// Rejects a frame travelling the wrong way, a frame with no MAC, a frame
    /// whose MAC does not match, and an encrypted payload that is not
    /// block-aligned. A rejected frame does **not** advance the MAC chain, so
    /// a failed forgery does not desynchronise a healthy session.
    pub fn open(&mut self, frame: &Frame) -> Result<Vec<u8>, ChannelError> {
        if !self.state.is_established() {
            return Err(ChannelError::WrongState { state: self.state });
        }
        let keys = match self.keys {
            Some(k) => k,
            None => return Err(ChannelError::WrongState { state: self.state }),
        };
        // A PD opens commands; an ACU opens replies.
        let expect_reply = self.role == Role::Acu;
        if frame.is_reply != expect_reply {
            return Err(ChannelError::WrongDirection);
        }
        let scs = match frame.scs_type() {
            Some(s) if s.has_mac() && s.is_command_side() != expect_reply => s,
            got => return Err(ChannelError::UnexpectedSecurityBlock { got }),
        };
        let carried = frame.mac.ok_or(ChannelError::MissingMac)?;

        let is_cmd = !expect_reply;
        let chain_iv = if is_cmd { self.r_mac } else { self.c_mac };

        let full = match cbc_mac(&keys, &chain_iv, &frame.bytes_for_mac()) {
            Some(m) => m,
            None => return Err(ChannelError::WrongState { state: self.state }),
        };
        let expected = truncate_mac(&full);
        if expected != carried {
            return Err(ChannelError::MacMismatch {
                got: carried,
                expected,
            });
        }

        let plaintext = if scs.is_encrypted() {
            if frame.payload.is_empty() || !frame.payload.len().is_multiple_of(BLOCK) {
                return Err(ChannelError::NotBlockAligned {
                    len: frame.payload.len(),
                });
            }
            let mut buf = frame.payload.clone();
            cbc_decrypt(&keys.s_enc, &iv_from_mac(&chain_iv), &mut buf);
            strip_padding(&buf).to_vec()
        } else {
            frame.payload.clone()
        };

        // Only advance the chain once the frame has been accepted.
        if is_cmd {
            self.c_mac = full;
        } else {
            self.r_mac = full;
        }
        Ok(plaintext)
    }
}

/// Compute the initial R-MAC that seeds the MAC chain.
///
/// `R-MAC₀ = AES-ECB(S-MAC2, AES-ECB(S-MAC1, server_cryptogram))`.
///
/// This is the two-key CBC-MAC construction over exactly one block with a zero
/// IV, which is why it can be written as two plain ECB encryptions. Both ends
/// can compute it, so `REPLY_RMAC_I` is really a confirmation rather than a
/// transfer.
///
/// **Confidence: medium-high.** Verified against `libosdp`'s `osdp_sc.c`, which
/// is the only one of the three cross-referenced implementations that has a PD
/// side. It matches the spec's construction as described in secondary sources
/// but was not read from the normative text.
pub fn initial_rmac(keys: &SessionKeys, server_cryptogram: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = *server_cryptogram;
    ecb_encrypt_block(&keys.s_mac1, &mut out);
    ecb_encrypt_block(&keys.s_mac2, &mut out);
    out
}

/// Test one candidate SCBK against a captured handshake.
///
/// Given the two nonces and the client cryptogram — all three of which travel
/// in the clear — recompute the cryptogram under `candidate` and see whether it
/// matches. No interaction with the bus is needed: this is a pure offline
/// check, costing four AES operations.
pub fn scbk_matches_handshake(
    candidate: &[u8; BLOCK],
    rnd_a: &[u8; 8],
    rnd_b: &[u8; 8],
    observed_client_cryptogram: &[u8; BLOCK],
) -> bool {
    let keys = derive_session_keys(candidate, rnd_a);
    client_cryptogram(&keys.s_enc, rnd_a, rnd_b) == *observed_client_cryptogram
}

/// Mellon attack 4, end to end: try the whole published weak-key family against
/// a captured handshake.
///
/// Returns the key and the pattern it came from, or `None` if the installation
/// is using something outside the sample-code family.
///
/// Note what this needs: one `CMD_CHLNG` and one `REPLY_CCRYPT`, both of which
/// are sent before any encryption exists. There is no need to be present when a
/// card is read, no need to transmit anything, and no way for the bus to notice.
///
/// ```
/// use odr_osdp::channel::{SecureChannel, recover_weak_scbk};
/// use odr_osdp::security::KeyType;
/// use odr_osdp::weak_keys::SCBK_D;
/// use odr_osdp::payload::Ccrypt;
///
/// let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
/// let mut pd  = SecureChannel::pd(SCBK_D, KeyType::Default, [7; 8]);
/// let chlng = acu.challenge(1, 0, [0x5A; 8]).unwrap();
/// let ccrypt = pd.handle_challenge(&chlng, [0xC3; 8]).unwrap();
///
/// // Everything below comes from two sniffed frames.
/// let mut rnd_a = [0u8; 8];
/// rnd_a.copy_from_slice(&chlng.payload[..8]);
/// let body = Ccrypt::decode(&ccrypt.payload).unwrap();
/// let (key, _pattern) =
///     recover_weak_scbk(&rnd_a, &body.rnd_b, &body.client_cryptogram).unwrap();
/// assert_eq!(key, SCBK_D);
/// ```
pub fn recover_weak_scbk(
    rnd_a: &[u8; 8],
    rnd_b: &[u8; 8],
    observed_client_cryptogram: &[u8; BLOCK],
) -> Option<([u8; BLOCK], WeakKeyPattern)> {
    weak_keys::enumerate().find_map(|pattern| {
        let key = pattern.key();
        if scbk_matches_handshake(&key, rnd_a, rnd_b, observed_client_cryptogram) {
            Some((key, pattern))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes::{Command, Reply};
    use crate::frame::Frame;
    use crate::weak_keys::SCBK_D;
    use alloc::vec;

    /// Run the full four-frame handshake and return both ends.
    fn handshake(scbk: [u8; 16]) -> (SecureChannel, SecureChannel) {
        let mut acu = SecureChannel::acu(scbk, KeyType::Default);
        let mut pd = SecureChannel::pd(scbk, KeyType::Default, [0xC0; 8]);

        let chlng = acu.challenge(0x01, 0, [0x11; 8]).unwrap();
        // Everything must survive a trip through the wire format, not just
        // through memory.
        let (chlng, _) = Frame::parse(&chlng.encode()).unwrap();

        let ccrypt = pd.handle_challenge(&chlng, [0x22; 8]).unwrap();
        let (ccrypt, _) = Frame::parse(&ccrypt.encode()).unwrap();

        let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
        let (scrypt, _) = Frame::parse(&scrypt.encode()).unwrap();

        let rmac = pd.handle_scrypt(&scrypt).unwrap();
        let (rmac, _) = Frame::parse(&rmac.encode()).unwrap();

        acu.handle_rmac_i(&rmac).unwrap();
        (acu, pd)
    }

    #[test]
    fn full_handshake_with_scbk_d_establishes_both_ends() {
        let (acu, pd) = handshake(SCBK_D);
        assert_eq!(acu.state(), ChannelState::Established);
        assert_eq!(pd.state(), ChannelState::Established);
        assert_eq!(acu.session_keys(), pd.session_keys());
        assert_eq!(acu.r_mac(), pd.r_mac());
        assert_eq!(acu.c_mac(), pd.c_mac());
        assert_eq!(acu.nonces(), pd.nonces());
        assert_eq!(acu.cuid, [0xC0; 8], "the ACU learned the PD's identifier");
    }

    #[test]
    fn handshake_frames_have_the_right_codes_and_blocks() {
        let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
        let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [1; 8]);

        let chlng = acu.challenge(1, 0, [0xAB; 8]).unwrap();
        assert_eq!(chlng.command_code(), Some(Command::Chlng));
        assert_eq!(chlng.scs_type(), Some(ScsType::Chlng));
        assert_eq!(chlng.payload.len(), 8);
        assert_eq!(chlng.mac, None);
        assert_eq!(
            chlng.security.as_ref().unwrap().key_type(),
            Some(KeyType::Default),
            "the key type is announced in the clear"
        );

        let ccrypt = pd.handle_challenge(&chlng, [0xCD; 8]).unwrap();
        assert_eq!(ccrypt.reply_code(), Some(Reply::Ccrypt));
        assert_eq!(ccrypt.scs_type(), Some(ScsType::Ccrypt));
        assert_eq!(ccrypt.payload.len(), 32);

        let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
        assert_eq!(scrypt.command_code(), Some(Command::Scrypt));
        assert_eq!(scrypt.scs_type(), Some(ScsType::Scrypt));
        assert_eq!(scrypt.payload.len(), 16);

        let rmac = pd.handle_scrypt(&scrypt).unwrap();
        assert_eq!(rmac.reply_code(), Some(Reply::RmacI));
        assert_eq!(rmac.scs_type(), Some(ScsType::RmacI));
        assert_eq!(rmac.payload.len(), 16);
        assert_eq!(rmac.security.as_ref().unwrap().data, vec![0x01]);
    }

    #[test]
    fn handshake_works_with_a_site_key_too() {
        let mut rng = crate::rng::SeededRng::new(99);
        let site_key = rng.key16();
        assert!(!crate::weak_keys::is_weak(&site_key));
        let (acu, pd) = handshake(site_key);
        assert!(acu.state().is_established());
        assert!(pd.state().is_established());
    }

    #[test]
    fn a_pd_with_the_wrong_key_fails_authentication() {
        let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
        let mut pd = SecureChannel::pd([0xFF; 16], KeyType::SiteKey, [1; 8]);
        let chlng = acu.challenge(1, 0, [0x11; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [0x22; 8]).unwrap();
        assert_eq!(
            acu.handle_ccrypt(&ccrypt, 1),
            Err(ChannelError::CryptogramMismatch)
        );
        assert_eq!(acu.state(), ChannelState::Failed);
    }

    #[test]
    fn an_acu_with_the_wrong_key_fails_authentication() {
        // The PD answers the challenge fine (it cannot tell yet), but the
        // server cryptogram it receives will not match.
        let mut acu = SecureChannel::acu([0x01; 16], KeyType::SiteKey);
        let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [1; 8]);
        let chlng = acu.challenge(1, 0, [0x11; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [0x22; 8]).unwrap();
        // The ACU's own check fails first, so forge a SCRYPT to reach the PD.
        assert!(acu.handle_ccrypt(&ccrypt, 1).is_err());
        let mut forged = Frame::command(1, 1, Command::Scrypt, vec![0x00; 16]);
        forged.security = Some(SecurityBlock::handshake(ScsType::Scrypt, KeyType::Default));
        assert_eq!(
            pd.handle_scrypt(&forged),
            Err(ChannelError::CryptogramMismatch)
        );
        assert_eq!(pd.state(), ChannelState::Failed);
    }

    #[test]
    fn encrypted_exchange_round_trips_both_ways() {
        let (mut acu, mut pd) = handshake(SCBK_D);

        // ACU commands the door open.
        let cmd = acu
            .seal(1, 1, Command::Out.to_u8(), &[0x00, 0x01, 0x32, 0x00], true)
            .unwrap();
        assert_eq!(cmd.scs_type(), Some(ScsType::CmdEncrypted));
        assert_ne!(
            cmd.payload,
            vec![0x00, 0x01, 0x32, 0x00],
            "it is ciphertext"
        );
        assert_eq!(cmd.payload.len() % 16, 0);
        let (cmd, _) = Frame::parse(&cmd.encode()).unwrap();
        assert_eq!(pd.open(&cmd).unwrap(), vec![0x00, 0x01, 0x32, 0x00]);

        // PD replies with a card read.
        let card = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34];
        let rep = pd.seal(1, 1, Reply::Raw.to_u8(), &card, true).unwrap();
        assert_eq!(rep.scs_type(), Some(ScsType::ReplyEncrypted));
        let (rep, _) = Frame::parse(&rep.encode()).unwrap();
        assert_eq!(acu.open(&rep).unwrap(), card);

        // And the chains stayed in step.
        assert_eq!(acu.c_mac(), pd.c_mac());
        assert_eq!(acu.r_mac(), pd.r_mac());
    }

    #[test]
    fn a_long_encrypted_exchange_stays_in_step() {
        let (mut acu, mut pd) = handshake(SCBK_D);
        for i in 0..40u8 {
            let seq = (i % 3) + 1;
            let payload = alloc::vec![i; (i as usize % 37) + 1];
            let cmd = acu
                .seal(1, seq, Command::Mfg.to_u8(), &payload, true)
                .unwrap();
            let (cmd, _) = Frame::parse(&cmd.encode()).unwrap();
            assert_eq!(pd.open(&cmd).unwrap(), payload, "command {i}");

            let rep_payload = alloc::vec![i ^ 0xFF; (i as usize % 19) + 1];
            let rep = pd
                .seal(1, seq, Reply::MfgRep.to_u8(), &rep_payload, true)
                .unwrap();
            let (rep, _) = Frame::parse(&rep.encode()).unwrap();
            assert_eq!(acu.open(&rep).unwrap(), rep_payload, "reply {i}");
        }
    }

    #[test]
    fn null_cipher_mode_leaves_the_payload_readable() {
        let (mut acu, mut pd) = handshake(SCBK_D);
        let card = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cmd = acu.seal(1, 1, Command::Text.to_u8(), &card, false).unwrap();
        assert_eq!(cmd.scs_type(), Some(ScsType::CmdMacOnly));
        assert_eq!(
            cmd.payload, card,
            "SCS_15 is a null cipher: the bytes are right there"
        );
        assert!(cmd.mac.is_some(), "but it is still authenticated");
        assert_eq!(pd.open(&cmd).unwrap(), card);
    }

    #[test]
    fn an_empty_payload_uses_the_mac_only_block_even_when_encryption_is_asked_for() {
        let (mut acu, mut pd) = handshake(SCBK_D);
        let poll = acu.seal(1, 1, Command::Poll.to_u8(), &[], true).unwrap();
        assert_eq!(poll.scs_type(), Some(ScsType::CmdMacOnly));
        assert!(poll.payload.is_empty());
        assert_eq!(pd.open(&poll).unwrap(), Vec::<u8>::new());
    }

    /// The MAC on the wire is four bytes of a sixteen-byte value.
    #[test]
    fn the_wire_mac_is_truncated_to_32_bits() {
        let (mut acu, _pd) = handshake(SCBK_D);
        let f = acu.seal(1, 1, Command::Poll.to_u8(), &[], false).unwrap();
        let mac = f.mac.expect("session frames carry a MAC");
        assert_eq!(mac.len(), 4);
        // The full value is retained internally and the wire value is its
        // prefix — twelve bytes of strength discarded.
        let full = acu.c_mac();
        assert_eq!(mac, [full[0], full[1], full[2], full[3]]);
        assert_ne!(&full[4..], &[0u8; 12], "the discarded bytes were not zero");

        // And the frame really is only 4 bytes longer than the unsecured shape
        // plus its 2-byte security block.
        let bare = Frame::command(1, 1, Command::Poll, vec![]);
        assert_eq!(f.declared_len(), bare.declared_len() + 2 + 4);
    }

    #[test]
    fn a_tampered_payload_fails_the_mac_check() {
        let (mut acu, mut pd) = handshake(SCBK_D);
        let mut cmd = acu
            .seal(1, 1, Command::Out.to_u8(), &[0, 1, 50, 0], true)
            .unwrap();
        cmd.payload[0] ^= 0x01;
        assert!(matches!(
            pd.open(&cmd),
            Err(ChannelError::MacMismatch { .. })
        ));
    }

    #[test]
    fn a_tampered_id_byte_fails_the_mac_check() {
        // Traffic analysis reads the id without a key, but it cannot be
        // *rewritten* without one: the MAC covers it.
        let (mut acu, mut pd) = handshake(SCBK_D);
        let mut cmd = acu.seal(1, 1, Command::Poll.to_u8(), &[], false).unwrap();
        cmd.id = Command::Out.to_u8();
        assert!(matches!(
            pd.open(&cmd),
            Err(ChannelError::MacMismatch { .. })
        ));
    }

    #[test]
    fn a_rejected_frame_does_not_desynchronise_the_session() {
        let (mut acu, mut pd) = handshake(SCBK_D);
        let good = acu.seal(1, 1, Command::Poll.to_u8(), &[], false).unwrap();

        let mut forged = good.clone();
        forged.mac = Some([0, 0, 0, 0]);
        assert!(pd.open(&forged).is_err());

        // The genuine frame still opens afterwards.
        assert_eq!(pd.open(&good).unwrap(), Vec::<u8>::new());
    }

    /// **A real weakness, not a bug in this code.**
    ///
    /// The MAC IV for a command is the R-MAC, and the R-MAC only advances when
    /// a *reply* is processed. So a command replayed before the PD has answered
    /// chains from exactly the same IV and its MAC still verifies. Only the
    /// two-bit sequence number stands between that and a working replay.
    #[test]
    fn a_replayed_command_is_only_stopped_once_a_reply_has_advanced_the_chain() {
        let (mut acu, mut pd) = handshake(SCBK_D);
        let first = acu.seal(1, 1, Command::Poll.to_u8(), &[], false).unwrap();
        assert_eq!(pd.open(&first).unwrap(), Vec::<u8>::new());

        // Replayed immediately: the MAC still verifies.
        assert_eq!(
            pd.open(&first).unwrap(),
            Vec::<u8>::new(),
            "the MAC chain has not moved, so the replay is cryptographically valid"
        );

        // Once the PD answers, the R-MAC advances and the replay dies.
        let _ = pd.seal(1, 1, Reply::Ack.to_u8(), &[], false).unwrap();
        assert!(matches!(
            pd.open(&first),
            Err(ChannelError::MacMismatch { .. })
        ));
    }

    /// The IV-reuse weakness, at its sharpest: two consecutive commands with no
    /// reply between them encrypt under the *same* CBC IV, because the IV is
    /// the complement of an R-MAC that has not moved. Identical plaintext
    /// therefore produces byte-identical ciphertext on the wire.
    #[test]
    fn two_consecutive_commands_reuse_the_same_cbc_iv() {
        let (mut acu, _pd) = handshake(SCBK_D);
        let plaintext = b"badge 0001 door3";
        let a = acu
            .seal(1, 1, Command::Mfg.to_u8(), plaintext, true)
            .unwrap();
        let b = acu
            .seal(1, 2, Command::Mfg.to_u8(), plaintext, true)
            .unwrap();
        assert_eq!(
            a.payload, b.payload,
            "same key, same IV, same plaintext, same ciphertext"
        );
        assert_ne!(a.mac, b.mac, "the MACs do differ: the C-MAC chain advanced");
    }

    #[test]
    fn frames_from_the_wrong_direction_are_refused() {
        let (mut acu, mut pd) = handshake(SCBK_D);
        let cmd = acu.seal(1, 1, Command::Poll.to_u8(), &[], false).unwrap();
        assert_eq!(acu.open(&cmd), Err(ChannelError::WrongDirection));
        let rep = pd.seal(1, 1, Reply::Ack.to_u8(), &[], false).unwrap();
        assert_eq!(pd.open(&rep), Err(ChannelError::WrongDirection));
    }

    #[test]
    fn unsecured_frames_are_refused_by_an_established_channel() {
        let (_acu, mut pd) = handshake(SCBK_D);
        let bare = Frame::command(1, 1, Command::Poll, vec![]);
        assert!(matches!(
            pd.open(&bare),
            Err(ChannelError::UnexpectedSecurityBlock { got: None })
        ));
    }

    #[test]
    fn a_misaligned_ciphertext_is_refused() {
        let (mut acu, mut pd) = handshake(SCBK_D);
        let mut cmd = acu
            .seal(1, 1, Command::Mfg.to_u8(), &[1, 2, 3], true)
            .unwrap();
        cmd.payload.truncate(15);
        // The MAC check is computed over the truncated frame, so it fails
        // first; force the MAC to match to reach the alignment check.
        let keys = *acu.session_keys().unwrap();
        let iv = pd.r_mac();
        let full = cbc_mac(&keys, &iv, &cmd.bytes_for_mac()).unwrap();
        cmd.mac = Some(truncate_mac(&full));
        assert!(matches!(
            pd.open(&cmd),
            Err(ChannelError::NotBlockAligned { len: 15 })
        ));
    }

    #[test]
    fn operations_are_refused_in_the_wrong_state() {
        let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
        assert!(matches!(
            acu.seal(1, 0, Command::Poll.to_u8(), &[], false),
            Err(ChannelError::WrongState {
                state: ChannelState::Idle
            })
        ));
        let bare = Frame::reply(1, 0, Reply::Ack, vec![]);
        assert!(matches!(
            acu.open(&bare),
            Err(ChannelError::WrongState { .. })
        ));
    }

    #[test]
    fn operations_are_refused_for_the_wrong_role() {
        let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [0; 8]);
        assert_eq!(
            pd.challenge(1, 0, [0; 8]),
            Err(ChannelError::WrongRole { role: Role::Pd })
        );
        let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
        let chlng = acu.challenge(1, 0, [0; 8]).unwrap();
        let mut acu2 = SecureChannel::acu(SCBK_D, KeyType::Default);
        assert_eq!(
            acu2.handle_challenge(&chlng, [0; 8]),
            Err(ChannelError::WrongRole { role: Role::Acu })
        );
    }

    #[test]
    fn handshake_steps_reject_the_wrong_frame() {
        let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [0; 8]);
        let poll = Frame::command(1, 0, Command::Poll, vec![]);
        assert!(matches!(
            pd.handle_challenge(&poll, [0; 8]),
            Err(ChannelError::UnexpectedCode { .. })
        ));

        // Right code, no security block.
        let chlng_no_sb = Frame::command(1, 0, Command::Chlng, vec![0; 8]);
        assert!(matches!(
            pd.handle_challenge(&chlng_no_sb, [0; 8]),
            Err(ChannelError::UnexpectedSecurityBlock { got: None })
        ));

        // Right code and block, payload too short for RND.A.
        let mut short = Frame::command(1, 0, Command::Chlng, vec![0; 3]);
        short.security = Some(SecurityBlock::handshake(ScsType::Chlng, KeyType::Default));
        assert!(matches!(
            pd.handle_challenge(&short, [0; 8]),
            Err(ChannelError::Payload(PayloadError::TooShort { .. }))
        ));
    }

    #[test]
    fn a_forged_rmac_i_is_rejected() {
        let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
        let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [1; 8]);
        let chlng = acu.challenge(1, 0, [0x11; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [0x22; 8]).unwrap();
        let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
        let _ = pd.handle_scrypt(&scrypt).unwrap();

        let mut forged = Frame::reply(1, 1, Reply::RmacI, vec![0x00; 16]);
        forged.security = Some(SecurityBlock::rmac_i(true));
        assert_eq!(
            acu.handle_rmac_i(&forged),
            Err(ChannelError::CryptogramMismatch)
        );
        assert_eq!(acu.state(), ChannelState::Failed);
    }

    /// The IV-derivation weakness, demonstrated: identical plaintext sealed at
    /// the same chain position produces identical ciphertext.
    #[test]
    fn identical_chain_state_produces_identical_ciphertext() {
        let (mut a1, _) = handshake(SCBK_D);
        let (mut a2, _) = handshake(SCBK_D);
        let p = b"badge 1234";
        let f1 = a1.seal(1, 1, Command::Mfg.to_u8(), p, true).unwrap();
        let f2 = a2.seal(1, 1, Command::Mfg.to_u8(), p, true).unwrap();
        assert_eq!(
            f1.payload, f2.payload,
            "no random IV: same key, same chain state, same ciphertext"
        );
    }

    /// The IV is not secret — it is the complement of a MAC that was on the
    /// wire four bytes at a time, and the full value is derivable by anyone
    /// with the key. This test shows an observer with the session keys can
    /// decrypt without any channel object at all.
    #[test]
    fn a_passive_observer_with_the_keys_can_decrypt() {
        let (mut acu, pd) = handshake(SCBK_D);
        let keys = *acu.session_keys().unwrap();
        let chain_iv = pd.r_mac();
        let plaintext = b"open sesame";
        let cmd = acu
            .seal(1, 1, Command::Mfg.to_u8(), plaintext, true)
            .unwrap();

        let mut buf = cmd.payload.clone();
        cbc_decrypt(&keys.s_enc, &iv_from_mac(&chain_iv), &mut buf);
        assert_eq!(strip_padding(&buf), plaintext);
    }

    /// Mellon attack 4, executed against a handshake this crate produced.
    #[test]
    fn a_default_key_handshake_is_cracked_from_two_sniffed_frames() {
        let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
        let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [0x99; 8]);
        let chlng = acu.challenge(3, 0, [0x37; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [0x73; 8]).unwrap();

        // The attacker has only wire bytes.
        let wire_chlng = chlng.encode();
        let wire_ccrypt = ccrypt.encode();
        let (chlng, _) = Frame::parse(&wire_chlng).unwrap();
        let (ccrypt, _) = Frame::parse(&wire_ccrypt).unwrap();
        let mut rnd_a = [0u8; 8];
        rnd_a.copy_from_slice(&chlng.payload[..8]);
        let body = Ccrypt::decode(&ccrypt.payload).unwrap();

        let (key, pattern) =
            recover_weak_scbk(&rnd_a, &body.rnd_b, &body.client_cryptogram).expect("cracked");
        assert_eq!(key, SCBK_D);
        assert_eq!(pattern, WeakKeyPattern::Ascending { start: 0x30 });

        // And the recovered key really does reproduce the session keys.
        assert_eq!(
            &derive_session_keys(&key, &rnd_a),
            acu.session_keys().unwrap()
        );
    }

    #[test]
    fn a_weak_repeated_byte_key_is_also_cracked() {
        let key = [0x5A; 16];
        assert!(crate::weak_keys::is_weak(&key));
        let mut acu = SecureChannel::acu(key, KeyType::SiteKey);
        let mut pd = SecureChannel::pd(key, KeyType::SiteKey, [1; 8]);
        let chlng = acu.challenge(1, 0, [0xF0; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [0x0F; 8]).unwrap();
        let body = Ccrypt::decode(&ccrypt.payload).unwrap();
        let (found, pattern) =
            recover_weak_scbk(&[0xF0; 8], &body.rnd_b, &body.client_cryptogram).unwrap();
        assert_eq!(found, key);
        assert_eq!(pattern, WeakKeyPattern::Repeated { byte: 0x5A });
    }

    #[test]
    fn a_strong_key_survives_the_weak_key_sweep() {
        let mut rng = crate::rng::SeededRng::new(0x5EED);
        let key = rng.key16();
        assert!(!crate::weak_keys::is_weak(&key));
        let mut acu = SecureChannel::acu(key, KeyType::SiteKey);
        let mut pd = SecureChannel::pd(key, KeyType::SiteKey, [1; 8]);
        let chlng = acu.challenge(1, 0, [0x42; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [0x24; 8]).unwrap();
        let body = Ccrypt::decode(&ccrypt.payload).unwrap();
        assert_eq!(
            recover_weak_scbk(&[0x42; 8], &body.rnd_b, &body.client_cryptogram),
            None
        );
    }

    #[test]
    fn scbk_candidate_check_is_exact() {
        let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
        let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [1; 8]);
        let chlng = acu.challenge(1, 0, [1; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [2; 8]).unwrap();
        let body = Ccrypt::decode(&ccrypt.payload).unwrap();
        assert!(scbk_matches_handshake(
            &SCBK_D,
            &[1; 8],
            &body.rnd_b,
            &body.client_cryptogram
        ));
        assert!(!scbk_matches_handshake(
            &[0; 16],
            &[1; 8],
            &body.rnd_b,
            &body.client_cryptogram
        ));
    }

    #[test]
    fn initial_rmac_is_two_ecb_passes() {
        let keys = derive_session_keys(&SCBK_D, &[3; 8]);
        let cryptogram = [0x11u8; 16];
        let mut manual = cryptogram;
        ecb_encrypt_block(&keys.s_mac1, &mut manual);
        ecb_encrypt_block(&keys.s_mac2, &mut manual);
        assert_eq!(initial_rmac(&keys, &cryptogram), manual);
    }

    #[test]
    fn role_peer_flips() {
        assert_eq!(Role::Acu.peer(), Role::Pd);
        assert_eq!(Role::Pd.peer(), Role::Acu);
    }

    /// The whole session must be reproducible byte for byte, because drills
    /// depend on it (DESIGN.md section 3).
    #[test]
    fn a_session_is_byte_for_byte_deterministic() {
        fn run() -> Vec<u8> {
            let (mut acu, mut pd) = handshake(SCBK_D);
            let mut out = Vec::new();
            for i in 0..8u8 {
                let c = acu
                    .seal(1, i % 4, Command::Mfg.to_u8(), &[i; 5], true)
                    .unwrap();
                out.extend(c.encode());
                pd.open(&c).unwrap();
                let r = pd
                    .seal(1, i % 4, Reply::MfgRep.to_u8(), &[i; 3], true)
                    .unwrap();
                out.extend(r.encode());
                acu.open(&r).unwrap();
            }
            out
        }
        assert_eq!(run(), run());
    }
}
