//! DESFire EV2 — the designed contrast, and why the Module 0 attacks stop here.
//!
//! Module 0.5 is deliberately the one drill where nothing works. The learner runs the
//! 125 kHz cloning attack and the Crypto1 nested attack against a DESFire card,
//! watches both fail, and has to say *why*. The point is not that DESFire is
//! unbreakable — it is that the three things the earlier attacks depended on are all
//! absent, and being able to name which one is missing is the transferable skill.
//!
//! # What this module implements
//!
//! Enough of DESFire's AES mutual authentication that the attacks genuinely fail
//! against real cryptography rather than against a `return Err`. Specifically the
//! EV1-style `AuthenticateAES` (`0xAA`) three-pass exchange:
//!
//! ```text
//! reader -> card   AUTH_AES(key number)
//! card   -> reader E(K, RndB)                     status 0xAF, more to come
//! reader -> card   E(K, RndA || RndB<<<8)         status 0xAF
//! card   -> reader E(K, RndA<<<8)                 status 0x00, done
//! ```
//!
//! AES-128 in CBC, IV chaining forward across the passes. Both sides draw a fresh
//! 16-byte random number; each proves it decrypted the other's by returning it rotated
//! one byte left — a rotation, so a replayed ciphertext does not survive. The session
//! key is assembled from halves of both randoms:
//!
//! ```text
//! SK = RndA[0..4] || RndB[0..4] || RndA[12..16] || RndB[12..16]
//! ```
//!
//! # What this module does not implement
//!
//! EV2's `AuthenticateEV2First` (`0x71`), which derives session keys through a
//! CMAC-based KDF over SV1/SV2 and adds transaction MAC counters, secure messaging in
//! the AES-CMAC mode, and proximity checking. None of that changes the answer to drill
//! 0.5, and all of it would be a large amount of code that nothing in Module 0
//! exercises. Seos is not implemented at all: it is a different stack (SIO objects
//! over ISO 7816 / SE OS) that reaches the same conclusion by the same route.
//!
//! This is stated plainly rather than quietly: if a later module needs real EV2
//! secure messaging, it is not here yet.

use crate::credential::{Credential, CredentialFormat};
use crate::error::{CredentialError, Result};
use crate::rng::Rng;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use std::collections::BTreeMap;

/// AES block size, and the length of both random challenges.
pub const BLOCK: usize = 16;

/// Status byte meaning "additional frame expected".
pub const STATUS_ADDITIONAL_FRAME: u8 = 0xAF;

/// Status byte meaning "operation OK".
pub const STATUS_OK: u8 = 0x00;

/// Encrypt a buffer with AES-128 in CBC mode, returning the final IV.
///
/// Written out rather than pulled from a CBC crate because seeing the chaining is
/// part of the lesson: it is the same construction OSDP Secure Channel uses in
/// Module 3, and the same one whose IV derivation Module 4.3 attacks.
pub fn cbc_encrypt(key: &[u8; BLOCK], iv: &[u8; BLOCK], data: &mut [u8]) -> [u8; BLOCK] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut chain = *iv;
    for block in data.chunks_mut(BLOCK) {
        if block.len() != BLOCK {
            break;
        }
        for (b, c) in block.iter_mut().zip(chain.iter()) {
            *b ^= c;
        }
        let mut ga = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut ga);
        block.copy_from_slice(&ga);
        chain.copy_from_slice(block);
    }
    chain
}

/// Decrypt a buffer with AES-128 in CBC mode, returning the final IV.
pub fn cbc_decrypt(key: &[u8; BLOCK], iv: &[u8; BLOCK], data: &mut [u8]) -> [u8; BLOCK] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut chain = *iv;
    for block in data.chunks_mut(BLOCK) {
        if block.len() != BLOCK {
            break;
        }
        let mut next = [0u8; BLOCK];
        next.copy_from_slice(block);
        let mut ga = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut ga);
        block.copy_from_slice(&ga);
        for (b, c) in block.iter_mut().zip(chain.iter()) {
            *b ^= c;
        }
        chain = next;
    }
    chain
}

/// Rotate a 16-byte block one byte to the left.
///
/// The step that makes a captured response useless: the card does not return the
/// number it was sent, it returns a transformation of it, so a recording cannot stand
/// in for knowledge of the key.
pub fn rotate_left_one(block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    out[..BLOCK - 1].copy_from_slice(&block[1..]);
    out[BLOCK - 1] = block[0];
    out
}

/// The key derived from one successful authentication.
///
/// It lasts for the session and nothing else. There is no long-term key on the air at
/// any point, which is the third of the three reasons the Module 0 attacks fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    /// The AES-128 session key.
    pub key: [u8; BLOCK],
    /// Running CBC IV for secure messaging after authentication.
    pub iv: [u8; BLOCK],
}

impl SessionKeys {
    /// Derive from the two random challenges.
    ///
    /// `SK = RndA[0..4] || RndB[0..4] || RndA[12..16] || RndB[12..16]`. Both sides can
    /// compute it and neither transmitted it.
    pub fn derive(rnd_a: &[u8; BLOCK], rnd_b: &[u8; BLOCK]) -> Self {
        let mut key = [0u8; BLOCK];
        key[0..4].copy_from_slice(&rnd_a[0..4]);
        key[4..8].copy_from_slice(&rnd_b[0..4]);
        key[8..12].copy_from_slice(&rnd_a[12..16]);
        key[12..16].copy_from_slice(&rnd_b[12..16]);
        Self {
            key,
            iv: [0u8; BLOCK],
        }
    }
}

/// Everything an eavesdropper sees of one DESFire authentication.
///
/// Compare with [`crate::mifare::AuthTrace`]: same idea, and the difference is
/// entirely in what the fields are worth. Every value here is an AES ciphertext under
/// a key that never appears, over plaintext that is fresh random data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesfireTranscript {
    /// Key number the authentication named.
    pub key_no: u8,
    /// `E(K, RndB)` — pass one.
    pub enc_rnd_b: [u8; BLOCK],
    /// `E(K, RndA || RndB<<<8)` — pass two.
    pub enc_challenge: [u8; BLOCK * 2],
    /// `E(K, RndA<<<8)` — pass three.
    pub enc_rnd_a_rot: [u8; BLOCK],
}

/// What the card is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardState {
    Idle,
    Challenged {
        key_no: u8,
        rnd_b: [u8; BLOCK],
        enc_rnd_b: [u8; BLOCK],
    },
    Authenticated {
        key_no: u8,
        session: SessionKeys,
    },
}

/// A DESFire EV2 card, as far as Module 0 needs one.
#[derive(Debug, Clone)]
pub struct DesfireEv2 {
    keys: BTreeMap<u8, [u8; BLOCK]>,
    files: BTreeMap<u8, Vec<u8>>,
    rng: Rng,
    state: CardState,
}

impl DesfireEv2 {
    /// A card with one application key and one file.
    ///
    /// `seed` drives the card's challenge generator. Deterministic, like everything
    /// else in the range — note that the *attacks* still fail, which is the honest
    /// outcome: they fail because of the protocol, not because of entropy the
    /// simulation happens to have.
    pub fn new(seed: u64, key_no: u8, key: [u8; BLOCK]) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(key_no, key);
        Self {
            keys,
            files: BTreeMap::new(),
            rng: Rng::new(seed),
            state: CardState::Idle,
        }
    }

    /// Install another application key.
    pub fn set_key(&mut self, key_no: u8, key: [u8; BLOCK]) {
        self.keys.insert(key_no, key);
    }

    /// Write a file's contents. Personalisation, not reachable over the air.
    pub fn set_file(&mut self, file_no: u8, data: Vec<u8>) {
        self.files.insert(file_no, data);
    }

    /// Whether a session is currently open.
    pub const fn is_authenticated(&self) -> bool {
        matches!(self.state, CardState::Authenticated { .. })
    }

    /// Drop the card out of the field. Session and challenge both go.
    pub fn reset_field(&mut self) {
        self.state = CardState::Idle;
    }

    /// Pass one: the card answers with `E(K, RndB)`.
    ///
    /// A fresh `RndB` every single time. That one sentence is most of drill 0.5.
    pub fn authenticate_aes_start(&mut self, key_no: u8) -> Result<[u8; BLOCK]> {
        let key = *self.keys.get(&key_no).ok_or(CredentialError::OutOfRange {
            what: "key number",
            index: u32::from(key_no),
            limit: 16,
        })?;
        let rnd_b = self.rng.next_block16();
        let mut buf = rnd_b;
        cbc_encrypt(&key, &[0u8; BLOCK], &mut buf);
        self.state = CardState::Challenged {
            key_no,
            rnd_b,
            enc_rnd_b: buf,
        };
        Ok(buf)
    }

    /// Pass three: check the reader's answer and prove knowledge in return.
    ///
    /// The card verifies that the reader returned `RndB` rotated — which requires
    /// having decrypted it, which requires the key — and answers with `RndA` rotated,
    /// which proves the same thing in the other direction without either side ever
    /// sending the key or anything derived from it alone.
    pub fn authenticate_aes_finish(
        &mut self,
        enc_challenge: &[u8; BLOCK * 2],
    ) -> Result<[u8; BLOCK]> {
        let CardState::Challenged {
            key_no,
            rnd_b,
            enc_rnd_b,
        } = self.state
        else {
            return Err(CredentialError::ProtocolViolation {
                expected: "an AuthenticateAES request",
            });
        };
        let key = *self.keys.get(&key_no).ok_or(CredentialError::OutOfRange {
            what: "key number",
            index: u32::from(key_no),
            limit: 16,
        })?;

        let mut plain = *enc_challenge;
        cbc_decrypt(&key, &enc_rnd_b, &mut plain);

        let mut rnd_a = [0u8; BLOCK];
        rnd_a.copy_from_slice(&plain[..BLOCK]);
        let mut returned = [0u8; BLOCK];
        returned.copy_from_slice(&plain[BLOCK..]);

        if returned != rotate_left_one(&rnd_b) {
            self.state = CardState::Idle;
            return Err(CredentialError::AuthenticationFailed {
                rejected_by: "card",
            });
        }

        let mut answer = rotate_left_one(&rnd_a);
        let mut last_ct = [0u8; BLOCK];
        last_ct.copy_from_slice(&enc_challenge[BLOCK..]);
        cbc_encrypt(&key, &last_ct, &mut answer);

        self.state = CardState::Authenticated {
            key_no,
            session: SessionKeys::derive(&rnd_a, &rnd_b),
        };
        Ok(answer)
    }

    /// Read a file through an authenticated session.
    pub fn read_file(&mut self, file_no: u8) -> Result<Vec<u8>> {
        let CardState::Authenticated {
            key_no,
            mut session,
        } = self.state
        else {
            return Err(CredentialError::NotAuthenticated);
        };
        let mut padded = self
            .files
            .get(&file_no)
            .ok_or(CredentialError::OutOfRange {
                what: "file number",
                index: u32::from(file_no),
                limit: 32,
            })?
            .clone();
        while padded.len() % BLOCK != 0 {
            padded.push(0);
        }
        session.iv = cbc_encrypt(&session.key, &session.iv, &mut padded);
        self.state = CardState::Authenticated { key_no, session };
        Ok(padded)
    }

    /// The session key the card holds, for scenario assertions only.
    ///
    /// Never reachable over the air; used by drills to check that both ends derived
    /// the same key.
    pub fn session_keys(&self) -> Option<SessionKeys> {
        match self.state {
            CardState::Authenticated { session, .. } => Some(session),
            _ => None,
        }
    }

    /// The key number a session authenticated with.
    pub fn authenticated_key_no(&self) -> Option<u8> {
        match self.state {
            CardState::Authenticated { key_no, .. } => Some(key_no),
            _ => None,
        }
    }
}

/// A DESFire reader: one key, and a seeded source for its own challenge.
#[derive(Debug, Clone)]
pub struct DesfireReader {
    key: [u8; BLOCK],
    rng: Rng,
}

impl DesfireReader {
    /// A reader holding one application key.
    pub fn new(seed: u64, key: [u8; BLOCK]) -> Self {
        Self {
            key,
            rng: Rng::new(seed),
        }
    }

    /// Run all three passes against a card.
    ///
    /// Returns the session keys and the transcript an eavesdropper would have. Both
    /// sides end up with the same session key and neither sent it.
    pub fn authenticate(
        &mut self,
        card: &mut DesfireEv2,
        key_no: u8,
    ) -> Result<(SessionKeys, DesfireTranscript)> {
        card.reset_field();
        let enc_rnd_b = card.authenticate_aes_start(key_no)?;

        let mut rnd_b = enc_rnd_b;
        cbc_decrypt(&self.key, &[0u8; BLOCK], &mut rnd_b);

        let rnd_a = self.rng.next_block16();
        let mut challenge = [0u8; BLOCK * 2];
        challenge[..BLOCK].copy_from_slice(&rnd_a);
        challenge[BLOCK..].copy_from_slice(&rotate_left_one(&rnd_b));
        cbc_encrypt(&self.key, &enc_rnd_b, &mut challenge);

        let enc_rnd_a_rot = card.authenticate_aes_finish(&challenge)?;

        let mut last_ct = [0u8; BLOCK];
        last_ct.copy_from_slice(&challenge[BLOCK..]);
        let mut answer = enc_rnd_a_rot;
        cbc_decrypt(&self.key, &last_ct, &mut answer);
        if answer != rotate_left_one(&rnd_a) {
            return Err(CredentialError::AuthenticationFailed {
                rejected_by: "reader",
            });
        }

        Ok((
            SessionKeys::derive(&rnd_a, &rnd_b),
            DesfireTranscript {
                key_no,
                enc_rnd_b,
                enc_challenge: challenge,
                enc_rnd_a_rot,
            },
        ))
    }

    /// Read a file and hand it on as a [`Credential`].
    pub fn read_credential(
        &mut self,
        card: &mut DesfireEv2,
        session: &mut SessionKeys,
        file_no: u8,
    ) -> Result<Credential> {
        let mut data = card.read_file(file_no)?;
        session.iv = cbc_decrypt(&session.key, &session.iv, &mut data);
        Credential::from_bytes(CredentialFormat::DesfireFile, &data)
    }
}

// ---------------------------------------------------------------------------
// Module 0.5 — running the earlier attacks and diagnosing the failures
// ---------------------------------------------------------------------------

/// Why an attack that works on an earlier credential stops here.
///
/// Drill 0.5 passes on correct diagnosis, so these are the answers, and each one is
/// produced by an attack that was actually run rather than by a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackFailure {
    /// The 125 kHz cloning attack.
    NoStaticSecretToCopy,
    /// Replaying a captured exchange.
    ChallengeIsFreshEachExchange,
    /// The Crypto1 nested attack.
    KeyNeverTransmitted,
}

impl AttackFailure {
    /// A short name, for a drill's answer field.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoStaticSecretToCopy => "no static secret to copy",
            Self::ChallengeIsFreshEachExchange => "challenge is fresh each exchange",
            Self::KeyNeverTransmitted => "key never transmitted",
        }
    }

    /// The explanation the drill marks against.
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::NoStaticSecretToCopy => {
                "An EM4100 or a prox card answers with the same bits every time, so the \
                 bits are the credential and copying them copies the card. A DESFire \
                 answers with a freshly encrypted random challenge, so there is no fixed \
                 bitstring to write onto a blank. What a cloner captures is a recording of \
                 one conversation, and a recording cannot hold a conversation."
            }
            Self::ChallengeIsFreshEachExchange => {
                "Every response is bound to the challenge it answered. The card draws a new \
                 RndB and the reader a new RndA for each exchange, and each side proves \
                 itself by returning the other's random number transformed. A captured \
                 answer is an answer to a question nobody is asking any more."
            }
            Self::KeyNeverTransmitted => {
                "The nested attack needs the card to hand over keystream: an encrypted value \
                 whose plaintext the attacker can predict. MIFARE Classic does that, because \
                 its nonce comes from a 16-bit LFSR. DESFire's challenges are full-entropy \
                 and AES-encrypted, so an observed ciphertext reveals no keystream, and the \
                 key itself never appears on the air in any form — the card proves it knows \
                 the key without transmitting anything derived from the key alone."
            }
        }
    }
}

/// The result of pointing an earlier attack at a DESFire card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackOutcome {
    /// It worked. Not expected in this module.
    Succeeded,
    /// It ran, and stopped here, for this reason.
    Failed(AttackFailure),
}

impl AttackOutcome {
    /// Whether the attack failed, and if so why.
    pub const fn failure(self) -> Option<AttackFailure> {
        match self {
            Self::Succeeded => None,
            Self::Failed(reason) => Some(reason),
        }
    }
}

/// What a nonce-predictability probe concluded.
///
/// This is a real computation, not a label: it tests whether a series of observed
/// challenges lie on the orbit of MIFARE Classic's 16-bit nonce LFSR. That test
/// passes for MIFARE and fails for DESFire, and the difference is the whole reason
/// one is attackable from a capture and the other is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoncePredictability {
    /// Consecutive pairs tested.
    pub pairs_tested: usize,
    /// Pairs where the second value is a generator successor of the first.
    pub pairs_on_orbit: usize,
}

impl NoncePredictability {
    /// Whether every pair was predictable from its predecessor.
    pub const fn is_predictable(&self) -> bool {
        self.pairs_tested > 0 && self.pairs_on_orbit == self.pairs_tested
    }
}

/// Test whether a series of observed challenges behave like MIFARE tag nonces.
pub fn probe_nonce_predictability(observed: &[u32]) -> NoncePredictability {
    let mut pairs_tested = 0;
    let mut pairs_on_orbit = 0;
    for pair in observed.windows(2) {
        pairs_tested += 1;
        if crate::nested::distance_between(pair[0], pair[1]).is_some() {
            pairs_on_orbit += 1;
        }
    }
    NoncePredictability {
        pairs_tested,
        pairs_on_orbit,
    }
}

/// Run the 125 kHz cloning attack against a DESFire card.
///
/// Really runs it: capture one full authentication, build a device that re-emits
/// exactly what the card emitted, and present it to a reader. The reader draws a new
/// `RndA`, the recording answers for the old one, and the reader rejects it. Nothing
/// here is hard-coded — remove the freshness from the protocol and this function would
/// return [`AttackOutcome::Succeeded`].
pub fn attempt_clone(card: &mut DesfireEv2, key: [u8; BLOCK], seed: u64) -> AttackOutcome {
    let mut reader = DesfireReader::new(seed, key);
    let Ok((_, transcript)) = reader.authenticate(card, 0) else {
        return AttackOutcome::Failed(AttackFailure::NoStaticSecretToCopy);
    };

    // The clone: everything the attacker saw the card say, and nothing else. It is
    // then presented to the same reader, later — which is what a cloner does.
    let mut clone = ReplayTag::from_transcript(&transcript);
    match reader.authenticate_replay(&mut clone) {
        Ok(()) => AttackOutcome::Succeeded,
        Err(_) => AttackOutcome::Failed(AttackFailure::NoStaticSecretToCopy),
    }
}

/// Replay a captured reader-side message at a live card.
///
/// Really runs it: take the exact `E(K, RndA || RndB<<<8)` from a captured exchange
/// and send it into a fresh authentication. The card has drawn a new `RndB`, so the
/// rotated value it is offered belongs to a conversation that is over, and it refuses.
pub fn attempt_replay(card: &mut DesfireEv2, key: [u8; BLOCK], seed: u64) -> AttackOutcome {
    let mut reader = DesfireReader::new(seed, key);
    let Ok((_, transcript)) = reader.authenticate(card, 0) else {
        return AttackOutcome::Failed(AttackFailure::ChallengeIsFreshEachExchange);
    };

    card.reset_field();
    if card.authenticate_aes_start(transcript.key_no).is_err() {
        return AttackOutcome::Failed(AttackFailure::ChallengeIsFreshEachExchange);
    }
    match card.authenticate_aes_finish(&transcript.enc_challenge) {
        Ok(_) => AttackOutcome::Succeeded,
        Err(_) => AttackOutcome::Failed(AttackFailure::ChallengeIsFreshEachExchange),
    }
}

/// Point the Crypto1 nested attack's machinery at a DESFire card.
///
/// The nested attack has one precondition: an encrypted value whose plaintext the
/// attacker can predict, so that XOR gives keystream. This runs the test for that
/// precondition — [`probe_nonce_predictability`] — against challenges harvested from
/// the card, and the test genuinely fails, because AES ciphertext of full-entropy
/// randoms does not lie on a 16-bit LFSR orbit.
///
/// `rounds` is how many challenges to harvest.
pub fn attempt_crypto1_recovery(
    card: &mut DesfireEv2,
    key_no: u8,
    rounds: usize,
) -> (AttackOutcome, NoncePredictability) {
    let mut observed = Vec::with_capacity(rounds);
    for _ in 0..rounds.max(2) {
        card.reset_field();
        match card.authenticate_aes_start(key_no) {
            Ok(enc) => observed.push(u32::from_be_bytes([enc[0], enc[1], enc[2], enc[3]])),
            Err(_) => break,
        }
    }
    card.reset_field();

    let probe = probe_nonce_predictability(&observed);
    let outcome = if probe.is_predictable() {
        AttackOutcome::Succeeded
    } else {
        AttackOutcome::Failed(AttackFailure::KeyNeverTransmitted)
    };
    (outcome, probe)
}

/// All three of drill 0.5's diagnoses, from three attacks that were actually run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContrastReport {
    /// Outcome of the 125 kHz cloning attack.
    pub cloning: AttackOutcome,
    /// Outcome of replaying a captured exchange.
    pub replay: AttackOutcome,
    /// Outcome of the Crypto1 nested attack's precondition.
    pub crypto1_nested: AttackOutcome,
    /// What the nonce-predictability probe measured.
    pub nonce_probe: NoncePredictability,
}

impl ContrastReport {
    /// Whether every attack failed, which is the expected outcome.
    pub fn all_failed(&self) -> bool {
        self.cloning.failure().is_some()
            && self.replay.failure().is_some()
            && self.crypto1_nested.failure().is_some()
    }

    /// The three diagnoses, in drill order.
    pub fn diagnoses(&self) -> Vec<AttackFailure> {
        [self.cloning, self.replay, self.crypto1_nested]
            .into_iter()
            .filter_map(AttackOutcome::failure)
            .collect()
    }
}

/// Run drill 0.5: present the Module 0 attacks to a DESFire card and report.
pub fn run_contrast(card: &mut DesfireEv2, key: [u8; BLOCK], seed: u64) -> ContrastReport {
    let cloning = attempt_clone(card, key, seed);
    let replay = attempt_replay(card, key, seed ^ 0x1111);
    let (crypto1_nested, nonce_probe) = attempt_crypto1_recovery(card, 0, 8);
    card.reset_field();
    ContrastReport {
        cloning,
        replay,
        crypto1_nested,
        nonce_probe,
    }
}

/// A device that re-emits a captured card side and nothing else.
///
/// This is what a 125 kHz cloner *is*, generalised: a recording with a radio. Against
/// EM4100 it is indistinguishable from the original. Against DESFire it gets one pass
/// in before the conversation moves on without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayTag {
    /// The `E(K, RndB)` it heard once.
    pub enc_rnd_b: [u8; BLOCK],
    /// The `E(K, RndA<<<8)` it heard once.
    pub enc_rnd_a_rot: [u8; BLOCK],
}

impl ReplayTag {
    /// Build one from a captured transcript.
    pub fn from_transcript(transcript: &DesfireTranscript) -> Self {
        Self {
            enc_rnd_b: transcript.enc_rnd_b,
            enc_rnd_a_rot: transcript.enc_rnd_a_rot,
        }
    }
}

impl DesfireReader {
    /// Run the three passes against a replay device.
    ///
    /// Deliberately a separate entry point: it makes visible that the reader does
    /// exactly what it always does, and that the difference is entirely on the card
    /// side. Nothing about the reader detects a clone; the protocol simply does not
    /// complete.
    pub fn authenticate_replay(&mut self, tag: &mut ReplayTag) -> Result<()> {
        let mut rnd_b = tag.enc_rnd_b;
        cbc_decrypt(&self.key, &[0u8; BLOCK], &mut rnd_b);

        let rnd_a = self.rng.next_block16();
        let mut challenge = [0u8; BLOCK * 2];
        challenge[..BLOCK].copy_from_slice(&rnd_a);
        challenge[BLOCK..].copy_from_slice(&rotate_left_one(&rnd_b));
        cbc_encrypt(&self.key, &tag.enc_rnd_b, &mut challenge);

        let mut last_ct = [0u8; BLOCK];
        last_ct.copy_from_slice(&challenge[BLOCK..]);
        let mut answer = tag.enc_rnd_a_rot;
        cbc_decrypt(&self.key, &last_ct, &mut answer);
        if answer != rotate_left_one(&rnd_a) {
            return Err(CredentialError::AuthenticationFailed {
                rejected_by: "reader",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto1::NonceLfsr;

    const KEY: [u8; BLOCK] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];

    fn card() -> DesfireEv2 {
        let mut c = DesfireEv2::new(0xD35F_1234, 0, KEY);
        c.set_file(1, b"badge-0451".to_vec());
        c
    }

    #[test]
    fn aes_cbc_round_trips() {
        let mut data = *b"sixteen byte blk sixteen byte blk";
        let iv = [7u8; BLOCK];
        let original = data;
        cbc_encrypt(&KEY, &iv, &mut data);
        assert_ne!(data, original);
        cbc_decrypt(&KEY, &iv, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn cbc_matches_the_fips_197_single_block_vector() {
        // FIPS-197 AES-128 example: key 000102..0f, plaintext 00112233..ff,
        // ciphertext 69c4e0d86a7b0430d8cdb78070b4c55a. With a zero IV, CBC of one
        // block is ECB of one block, so this pins the primitive itself.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut data = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        cbc_encrypt(&key, &[0u8; BLOCK], &mut data);
        assert_eq!(
            data,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
    }

    #[test]
    fn rotation_is_one_byte_left() {
        let mut block = [0u8; BLOCK];
        for (i, b) in block.iter_mut().enumerate() {
            *b = i as u8;
        }
        let rotated = rotate_left_one(&block);
        assert_eq!(rotated[0], 1);
        assert_eq!(rotated[BLOCK - 1], 0);
    }

    #[test]
    fn mutual_authentication_succeeds_and_both_sides_agree() {
        let mut card = card();
        let mut reader = DesfireReader::new(0xBEEF, KEY);
        let (session, transcript) = reader.authenticate(&mut card, 0).unwrap();
        assert!(card.is_authenticated());
        assert_eq!(card.authenticated_key_no(), Some(0));
        assert_eq!(card.session_keys().unwrap().key, session.key);
        // The session key is not in the transcript in any form.
        assert!(!transcript
            .enc_challenge
            .windows(BLOCK)
            .any(|w| w == &session.key[..]));
        assert!(transcript.enc_rnd_b != session.key);
    }

    #[test]
    fn the_session_key_differs_every_time() {
        let mut card = card();
        let mut reader = DesfireReader::new(0xBEEF, KEY);
        let (first, t1) = reader.authenticate(&mut card, 0).unwrap();
        let (second, t2) = reader.authenticate(&mut card, 0).unwrap();
        assert_ne!(first.key, second.key);
        assert_ne!(t1.enc_rnd_b, t2.enc_rnd_b);
    }

    #[test]
    fn a_wrong_key_is_rejected_by_the_card() {
        let mut card = card();
        let mut wrong = KEY;
        wrong[0] ^= 1;
        let mut reader = DesfireReader::new(1, wrong);
        assert!(reader.authenticate(&mut card, 0).is_err());
        assert!(!card.is_authenticated());
    }

    #[test]
    fn reading_a_file_needs_a_session() {
        let mut card = card();
        assert!(matches!(
            card.read_file(1),
            Err(CredentialError::NotAuthenticated)
        ));

        let mut reader = DesfireReader::new(2, KEY);
        let (mut session, _) = reader.authenticate(&mut card, 0).unwrap();
        let credential = reader.read_credential(&mut card, &mut session, 1).unwrap();
        assert_eq!(&credential.data[..10], b"badge-0451");
        assert_eq!(credential.format, CredentialFormat::DesfireFile);
    }

    #[test]
    fn unknown_key_and_file_numbers_are_errors_not_panics() {
        let mut card = card();
        assert!(card.authenticate_aes_start(9).is_err());
        let mut reader = DesfireReader::new(3, KEY);
        let (mut session, _) = reader.authenticate(&mut card, 0).unwrap();
        assert!(reader.read_credential(&mut card, &mut session, 7).is_err());
    }

    #[test]
    fn finishing_without_starting_is_a_protocol_violation() {
        let mut card = card();
        assert!(matches!(
            card.authenticate_aes_finish(&[0u8; BLOCK * 2]),
            Err(CredentialError::ProtocolViolation { .. })
        ));
    }

    // --- Module 0.5 -------------------------------------------------------

    #[test]
    fn cloning_fails_because_there_is_no_static_secret() {
        let mut card = card();
        let outcome = attempt_clone(&mut card, KEY, 0x0402);
        assert_eq!(
            outcome,
            AttackOutcome::Failed(AttackFailure::NoStaticSecretToCopy)
        );
    }

    #[test]
    fn replay_fails_because_the_challenge_is_fresh() {
        let mut card = card();
        let outcome = attempt_replay(&mut card, KEY, 0x0403);
        assert_eq!(
            outcome,
            AttackOutcome::Failed(AttackFailure::ChallengeIsFreshEachExchange)
        );
    }

    #[test]
    fn the_nested_attack_has_no_predictable_nonce_to_work_with() {
        let mut card = card();
        let (outcome, probe) = attempt_crypto1_recovery(&mut card, 0, 8);
        assert_eq!(
            outcome,
            AttackOutcome::Failed(AttackFailure::KeyNeverTransmitted)
        );
        assert_eq!(probe.pairs_tested, 7);
        assert_eq!(probe.pairs_on_orbit, 0);
    }

    #[test]
    fn the_same_probe_says_yes_to_mifare_nonces() {
        // The diagnosis is a computation, not a label: run it on values from the
        // MIFARE nonce generator and it reports "predictable".
        let mut generator = NonceLfsr::seeded(0x1357_9BDF);
        let nonces: Vec<u32> = (0..8)
            .map(|_| {
                let n = generator.nonce();
                generator.advance(137);
                n
            })
            .collect();
        let probe = probe_nonce_predictability(&nonces);
        assert!(probe.is_predictable());
        assert_eq!(probe.pairs_on_orbit, 7);
    }

    #[test]
    fn drill_0_5_produces_three_diagnoses() {
        let mut card = card();
        let report = run_contrast(&mut card, KEY, 0x0405);
        assert!(report.all_failed());
        assert_eq!(
            report.diagnoses(),
            vec![
                AttackFailure::NoStaticSecretToCopy,
                AttackFailure::ChallengeIsFreshEachExchange,
                AttackFailure::KeyNeverTransmitted,
            ]
        );
        for reason in report.diagnoses() {
            assert!(!reason.explanation().is_empty());
            assert!(!reason.name().is_empty());
        }
    }
}
