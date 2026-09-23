//! The nested attack: one known sector key becomes all of them.
//!
//! This is drill 0.4, and it is not a demonstration. Everything here runs against the
//! [`crate::crypto1`] implementation the card itself uses, from values visible on the
//! air, and finishes holding a key it was never told. Nothing in this module reads a
//! key out of the card model. The one key it is *given* — the sector the attacker
//! already knows — is used for a single purpose, measuring a timing distance, and
//! never touches the recovery of any other key.
//!
//! # The flaw it exploits
//!
//! A first authentication sends the tag nonce `nT` in the clear. A *nested* one — an
//! authentication made while a session is already open — sends it encrypted, masked
//! with the first 32 keystream bits of the cipher keyed with the **new** sector's key.
//!
//! That would be fine if `nT` were unpredictable. It is not. The tag nonce comes from
//! a free-running 16-bit LFSR, so there are only 65535 of them and, more usefully,
//! one nonce determines every later one. An attacker who sees a nonce in the clear and
//! controls the timing knows what the next one will be. Knowing `nT` while seeing
//! `{nT}` gives 32 bits of keystream from a key nobody has handed over — which is
//! exactly what [`crate::crypto1::recover_states`] eats.
//!
//! And the card gives up that nonce **before anyone has proved anything**. The
//! attacker never completes the exchange, never gets access, and does not need to.
//!
//! # The run
//!
//! 1. **Calibrate.** Authenticate to the known sector in the clear, then nested to the
//!    *same* sector. The known key decrypts the second nonce, so the attacker can
//!    measure how many generator steps the reader's protocol timing costs. That
//!    distance is the only thing the known key is used for.
//! 2. **Probe, twice.** Authenticate in the clear to the known sector — nonce visible
//!    — then send a nested authentication to the target and abandon it at pass three.
//!    Repeat. Two encrypted nonces from the same unknown key.
//! 3. **Confirm the prediction.** Each nonce byte carries a parity bit encrypted with
//!    the keystream bit that also encrypts the next byte's first bit. Three of those
//!    are checkable against any candidate nonce, for free, before any search runs.
//! 4. **Recover.** `ks1 = {nT} xor nT` from the first probe feeds the state recovery:
//!    about 2^16 candidate cipher states.
//! 5. **Roll back and sift.** Undo the 32 nonce steps to read a key out of each
//!    candidate register, and keep the one that also explains the second probe. Two
//!    probes, 32 bits of agreement, one key.
//! 6. **Prove it.** Authenticate to the target sector with the recovered key and read
//!    the block. The drill's flag is that this succeeds, not that a string matched.
//!
//! # What is not here
//!
//! The **darkside attack** — recovering a first key from a card with no known key at
//! all, by exploiting the parity bits a card leaks when it rejects a malformed
//! authentication — is **not implemented**. It needs a card model that answers a
//! failed authentication with an encrypted NACK, and a different search. Drill 0.4 is
//! built on the nested attack; darkside would be an extension, and this module says so
//! rather than pretending.

use crate::credential::Credential;
use crate::crypto1::{bebit, odd_parity8, prng_successor, recover_states, Crypto1};
use crate::error::{CredentialError, Result};
use crate::mifare::{
    KeyType, MifareClassic1k, MifareReader, NonceProbe, BLOCKS_PER_SECTOR, SECTOR_COUNT,
};

/// How many generator steps the reader's protocol timing costs between a reference
/// nonce seen in the clear and the nested nonce that follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceDistance(pub u32);

/// One probe and the plaintext nonce that predicts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NestedSample {
    /// The tag nonce seen in the clear on the preceding authentication.
    pub reference_nt: u32,
    /// The abandoned nested authentication.
    pub probe: NonceProbe,
}

/// Everything the attacker collected. Every field was visible on the air.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedCapture {
    /// Card UID, from anticollision.
    pub uid: u32,
    /// Block the probes targeted.
    pub block: u8,
    /// Key type the probes asked for.
    pub key_type: KeyType,
    /// Two or more samples. The first drives the state recovery; the rest sift it.
    pub samples: Vec<NestedSample>,
}

/// A recovered sector key and what it cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovered {
    /// A block in the sector the key belongs to.
    pub block: u8,
    /// Which key.
    pub key_type: KeyType,
    /// The key itself, derived from observation alone.
    pub key: u64,
    /// Search statistics.
    pub stats: NestedStats,
}

/// What a nested recovery cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NestedStats {
    /// Candidate nonces the prediction window offered for the first sample.
    pub nonce_candidates: usize,
    /// Candidates that survived the encrypted-parity check.
    pub nonces_after_parity: usize,
    /// Full state recoveries run.
    pub recoveries: usize,
    /// Cipher states examined across all recoveries.
    pub states_examined: usize,
    /// Candidate keys that survived the first sample and were tested against the rest.
    pub keys_tested: usize,
}

/// The attacker.
#[derive(Debug, Clone, Copy)]
pub struct NestedAttack {
    /// A block in the sector whose key is already known.
    pub known_block: u8,
    /// Which key of that sector is known.
    pub known_key_type: KeyType,
    /// The known key. Used **only** to calibrate the nonce distance.
    pub known_key: u64,
    /// How far either side of the predicted nonce to search. Zero would do against a
    /// perfectly regular reader; a real capture has jitter, so the attack sweeps.
    pub window: u32,
    /// How many probes to take. Two is enough to pin the key; more costs two
    /// authentications each and buys certainty.
    pub samples: usize,
}

impl NestedAttack {
    /// An attacker who knows one sector key.
    pub const fn new(known_block: u8, known_key_type: KeyType, known_key: u64) -> Self {
        Self {
            known_block,
            known_key_type,
            known_key,
            window: 4,
            samples: 2,
        }
    }

    /// Step 1: measure how far the tag's nonce generator runs between a reference
    /// nonce and the nested nonce that follows it.
    ///
    /// The only use of the known key in the whole attack. Note that it measures the
    /// *reader's* timing, not anything about the target sector, which is why one
    /// calibration serves the whole card.
    pub fn calibrate(
        &self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
    ) -> Result<NonceDistance> {
        let (mut session, reference) = reader.authenticate(
            card,
            self.known_block,
            self.known_key_type,
            self.known_key,
            None,
        )?;
        let probe =
            reader.probe_nested_nonce(card, self.known_block, self.known_key_type, &mut session)?;

        // The known key decrypts this one nonce — causally, because the keystream bit
        // that reveals nonce bit i is produced before bit i is fed in.
        let mut cipher = Crypto1::from_key(self.known_key);
        let nt = crate::mifare::feed_nonce_encrypted(&mut cipher, probe.uid, probe.nt_enc);

        distance_between(reference.nt_enc, nt)
            .map(NonceDistance)
            .ok_or(CredentialError::AttackExhausted {
                attack: "nested",
                detail: "the two nonces are not on the same generator orbit",
            })
    }

    /// Step 2: collect probes against a target block.
    ///
    /// Each sample costs one authentication to the known sector — which the attacker
    /// can do, it has the key — followed by a nested authentication to the target
    /// that is abandoned before pass three. The target key is neither needed nor
    /// touched.
    pub fn capture(
        &self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
        target_block: u8,
        target_key_type: KeyType,
    ) -> Result<NestedCapture> {
        let mut samples = Vec::with_capacity(self.samples.max(2));
        for _ in 0..self.samples.max(2) {
            let (mut session, reference) = reader.authenticate(
                card,
                self.known_block,
                self.known_key_type,
                self.known_key,
                None,
            )?;
            let probe =
                reader.probe_nested_nonce(card, target_block, target_key_type, &mut session)?;
            samples.push(NestedSample {
                reference_nt: reference.nt_enc,
                probe,
            });
        }
        Ok(NestedCapture {
            uid: card.uid(),
            block: target_block,
            key_type: target_key_type,
            samples,
        })
    }

    /// Steps 3 to 5: turn a capture into a key.
    ///
    /// Takes nothing but the capture and the calibrated distance. It cannot see the
    /// card, so it cannot cheat.
    pub fn recover(
        &self,
        capture: &NestedCapture,
        distance: NonceDistance,
    ) -> Result<(u64, NestedStats)> {
        let mut stats = NestedStats::default();
        let first = capture
            .samples
            .first()
            .ok_or(CredentialError::AttackExhausted {
                attack: "nested",
                detail: "no samples captured",
            })?;
        if capture.samples.len() < 2 {
            return Err(CredentialError::AttackExhausted {
                attack: "nested",
                detail: "a second probe is needed to pin one key out of the candidates",
            });
        }

        // Candidate plaintext nonces for every sample, nearest prediction first.
        let confirmations: Vec<Vec<u32>> = capture.samples[1..]
            .iter()
            .map(|s| self.candidate_nonces(s, distance))
            .collect();

        for candidate_nt in self.candidate_nonces(first, distance) {
            stats.nonce_candidates += 1;
            stats.nonces_after_parity += 1;
            stats.recoveries += 1;

            let keystream = first.probe.nt_enc ^ candidate_nt;
            let states = recover_states(keystream, capture.uid ^ candidate_nt);
            stats.states_examined += states.len();

            for state in &states {
                let mut back = *state;
                back.rollback_word(capture.uid ^ candidate_nt, false);
                let key = back.key();
                stats.keys_tested += 1;

                // A candidate key must also explain every other probe. Each one is
                // 32 bits of agreement, so one extra probe is decisive.
                let consistent =
                    capture.samples[1..]
                        .iter()
                        .zip(&confirmations)
                        .all(|(sample, candidates)| {
                            candidates
                                .iter()
                                .any(|&nt| key_explains(key, capture.uid, nt, sample.probe.nt_enc))
                        });
                if consistent {
                    return Ok((key, stats));
                }
            }
        }

        Err(CredentialError::AttackExhausted {
            attack: "nested",
            detail: "no candidate nonce in the window produced a key consistent with every probe",
        })
    }

    /// Plaintext nonce candidates for one sample, filtered by the encrypted parity
    /// bits and ordered nearest-prediction-first.
    fn candidate_nonces(&self, sample: &NestedSample, distance: NonceDistance) -> Vec<u32> {
        let mut deltas: Vec<i64> = (-(self.window as i64)..=(self.window as i64)).collect();
        deltas.sort_by_key(|d| (d.abs(), *d));
        deltas
            .into_iter()
            .map(|delta| {
                let steps = (i64::from(distance.0) + delta).rem_euclid(65_535) as u32;
                prng_successor(sample.reference_nt, steps)
            })
            .filter(|&nt| parity_agrees(nt, sample.probe.nt_enc ^ nt, &sample.probe.nt_parity))
            .collect()
    }

    /// Calibrate, capture and recover one key, end to end.
    pub fn run(
        &self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
        target_block: u8,
        target_key_type: KeyType,
    ) -> Result<Recovered> {
        let distance = self.calibrate(card, reader)?;
        self.run_with_distance(card, reader, target_block, target_key_type, distance)
    }

    /// As [`NestedAttack::run`], reusing a distance already measured.
    ///
    /// Calibration costs two authentications and is good for the whole card, so an
    /// attacker sweeping sixteen sectors does it once.
    pub fn run_with_distance(
        &self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
        target_block: u8,
        target_key_type: KeyType,
        distance: NonceDistance,
    ) -> Result<Recovered> {
        let capture = self.capture(card, reader, target_block, target_key_type)?;
        let (key, stats) = self.recover(&capture, distance)?;
        Ok(Recovered {
            block: target_block,
            key_type: target_key_type,
            key,
            stats,
        })
    }

    /// Sweep every sector of the card for the given key type.
    ///
    /// The sector the attacker already knows is skipped. Sectors that fail are
    /// reported rather than silently dropped, so a partial sweep is distinguishable
    /// from a complete one.
    ///
    /// Each sector costs one full state recovery. That is seconds, not hours — which
    /// is the number drill 0.4 wants a learner to sit with.
    #[allow(clippy::type_complexity)]
    pub fn recover_all(
        &self,
        card: &mut MifareClassic1k,
        reader: &mut MifareReader,
        key_type: KeyType,
    ) -> Result<Vec<core::result::Result<Recovered, (u8, CredentialError)>>> {
        let distance = self.calibrate(card, reader)?;
        let known_sector = MifareClassic1k::sector_of(self.known_block);
        let mut out = Vec::new();
        for sector in 0..SECTOR_COUNT as u8 {
            if sector == known_sector && key_type == self.known_key_type {
                continue;
            }
            let block = sector * BLOCKS_PER_SECTOR as u8;
            match self.run_with_distance(card, reader, block, key_type, distance) {
                Ok(found) => out.push(Ok(found)),
                Err(e) => out.push(Err((sector, e))),
            }
        }
        Ok(out)
    }
}

/// Does this key, with this nonce, produce the encrypted nonce that was observed?
///
/// Thirty-two bits of agreement. A wrong key passes with probability 2^-32, so one
/// extra probe is enough to reduce 2^16 candidates to one.
fn key_explains(key: u64, uid: u32, nt: u32, observed_nt_enc: u32) -> bool {
    let mut cipher = Crypto1::from_key(key);
    let ks1 = cipher.word(uid ^ nt, false);
    ks1 ^ nt == observed_nt_enc
}

/// Check a candidate nonce against the three usable encrypted parity bits.
///
/// Byte *n*'s parity is masked with the keystream bit that also encrypts bit 0 of
/// byte *n+1*, so for the first three bytes that bit is inside the same 32-bit
/// keystream word and the check is free. The fourth byte's masking bit belongs to the
/// next word and is not available here.
///
/// Three bits throws away seven candidate nonces in eight before any search runs.
pub fn parity_agrees(candidate_nt: u32, keystream: u32, observed: &[bool; 4]) -> bool {
    (0..3).all(|i| {
        let byte = (candidate_nt >> (24 - 8 * i)) as u8;
        observed[i] == odd_parity8(byte) ^ bebit(keystream, 8 * (i + 1))
    })
}

/// How many generator steps separate two tag nonces, if they are on the same orbit.
///
/// Brute force over the generator's whole 65535-step cycle, which takes a handful of
/// milliseconds. There are only 65535 nonces; that is the point.
pub fn distance_between(from: u32, to: u32) -> Option<u32> {
    let mut current = from;
    for step in 0..65_535u32 {
        if current == to {
            return Some(step);
        }
        current = prng_successor(current, 1);
    }
    None
}

/// Prove a recovered key by using it: authenticate, then read the block.
///
/// Drill 0.4's flag predicate is exactly this call returning `Ok`. There is no answer
/// string to compare against; either the card opens up to the recovered key or it
/// does not.
pub fn prove(
    card: &mut MifareClassic1k,
    reader: &mut MifareReader,
    block: u8,
    key_type: KeyType,
    key: u64,
) -> Result<Credential> {
    let (mut session, _) = reader.authenticate(card, block, key_type, key, None)?;
    session.read_credential(card, block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mifare::{AccessBits, DEFAULT_KEY};
    use crate::Rng;

    const UID: u32 = 0x2A23_4F80;
    const KNOWN_KEY: u64 = 0xFFFF_FFFF_FFFF;
    const TARGET_KEY: u64 = 0x1A98_2C7E_459A;
    const CREDENTIAL: [u8; 16] = [
        0x04, 0x5A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6, 0xD7,
        0xE8,
    ];

    fn card_with_one_known_sector() -> MifareClassic1k {
        let mut card = MifareClassic1k::new(UID, 0xBADC_0FFE);
        card.force_sector_keys(0, KNOWN_KEY, DEFAULT_KEY, AccessBits::transport());
        card.force_sector_keys(1, TARGET_KEY, 0x0102_0304_0506, AccessBits::transport());
        card.force_sector_keys(2, 0xDEAD_BEEF_CAFE, DEFAULT_KEY, AccessBits::transport());
        card.force_block(4, CREDENTIAL);
        card
    }

    #[test]
    fn calibration_finds_a_stable_distance() {
        let mut card = card_with_one_known_sector();
        let mut reader = MifareReader::new(1);
        let attack = NestedAttack::new(0, KeyType::A, KNOWN_KEY);

        let first = attack.calibrate(&mut card, &mut reader).unwrap();
        let second = attack.calibrate(&mut card, &mut reader).unwrap();
        assert_eq!(
            first, second,
            "the reader's timing is regular, so the distance must be"
        );
        assert!(first.0 > 0);
    }

    #[test]
    fn a_probe_needs_no_key_and_grants_no_access() {
        let mut card = card_with_one_known_sector();
        let mut reader = MifareReader::new(2);
        let (mut session, _) = reader
            .authenticate(&mut card, 0, KeyType::A, KNOWN_KEY, None)
            .unwrap();

        let probe = reader
            .probe_nested_nonce(&mut card, 4, KeyType::A, &mut session)
            .unwrap();
        assert_eq!(probe.block, 4);
        // Pass three never happened, so the card has no session and nothing opened.
        assert!(!card.has_session());
    }

    #[test]
    fn parity_check_rejects_wrong_nonces() {
        let mut card = card_with_one_known_sector();
        let mut reader = MifareReader::new(2);
        let attack = NestedAttack::new(0, KeyType::A, KNOWN_KEY);
        let distance = attack.calibrate(&mut card, &mut reader).unwrap();
        let capture = attack
            .capture(&mut card, &mut reader, 4, KeyType::A)
            .unwrap();
        let sample = capture.samples[0];

        let truth = prng_successor(sample.reference_nt, distance.0);
        assert!(parity_agrees(
            truth,
            sample.probe.nt_enc ^ truth,
            &sample.probe.nt_parity
        ));

        let mut rejected = 0;
        for delta in 1..=16u32 {
            let wrong = prng_successor(sample.reference_nt, distance.0 + delta);
            if !parity_agrees(wrong, sample.probe.nt_enc ^ wrong, &sample.probe.nt_parity) {
                rejected += 1;
            }
        }
        assert!(rejected >= 10, "three parity bits should kill most of them");
    }

    /// The drill 0.4 flag predicate, run for real.
    #[test]
    fn nested_attack_recovers_a_key_it_was_never_given() {
        let mut card = card_with_one_known_sector();
        let mut reader = MifareReader::new(0x5EED);
        let attack = NestedAttack::new(0, KeyType::A, KNOWN_KEY);

        let recovered = attack.run(&mut card, &mut reader, 4, KeyType::A).unwrap();

        // The flag: the attacker's key equals the card's configured key, and the
        // attacker never read that field, never held the key, and never completed an
        // authentication to that sector.
        assert_eq!(recovered.key, TARGET_KEY);
        assert_eq!(recovered.key, card.sector_key(1, KeyType::A).unwrap());
        assert_eq!(recovered.stats.recoveries, 1);
        assert!(recovered.stats.states_examined > 1 << 14);

        // And prove it the way the drill does: use the key.
        let credential = prove(&mut card, &mut reader, 4, KeyType::A, recovered.key).unwrap();
        assert_eq!(credential.data, CREDENTIAL);
    }

    #[test]
    fn nested_attack_recovers_key_b_as_well() {
        let mut card = card_with_one_known_sector();
        let mut reader = MifareReader::new(0xF00D);
        let attack = NestedAttack::new(0, KeyType::A, KNOWN_KEY);

        let recovered = attack.run(&mut card, &mut reader, 4, KeyType::B).unwrap();
        assert_eq!(recovered.key, 0x0102_0304_0506);
    }

    #[test]
    fn recovery_works_on_the_capture_alone() {
        // The recovery half of the attack never sees the card. Feed it only what an
        // eavesdropper wrote down and it still produces the key.
        let mut card = card_with_one_known_sector();
        let mut reader = MifareReader::new(11);
        let attack = NestedAttack::new(0, KeyType::A, KNOWN_KEY);
        let distance = attack.calibrate(&mut card, &mut reader).unwrap();
        let capture = attack
            .capture(&mut card, &mut reader, 8, KeyType::A)
            .unwrap();

        let (key, _) = attack.recover(&capture, distance).unwrap();
        assert_eq!(key, 0xDEAD_BEEF_CAFE);
    }

    #[test]
    fn recovery_fails_cleanly_on_a_hopeless_capture() {
        let mut card = card_with_one_known_sector();
        let mut reader = MifareReader::new(13);
        let attack = NestedAttack::new(0, KeyType::A, KNOWN_KEY);
        let distance = attack.calibrate(&mut card, &mut reader).unwrap();
        let mut capture = attack
            .capture(&mut card, &mut reader, 4, KeyType::A)
            .unwrap();

        // Corrupt the observation beyond repair.
        for sample in &mut capture.samples {
            sample.probe.nt_enc ^= 0xFFFF_FFFF;
            sample.probe.nt_parity = [false; 4];
        }

        match attack.recover(&capture, distance) {
            Err(CredentialError::AttackExhausted { attack, .. }) => assert_eq!(attack, "nested"),
            other => panic!("expected a clean exhaustion, got {other:?}"),
        }
    }

    #[test]
    fn a_single_probe_is_not_enough() {
        let mut card = card_with_one_known_sector();
        let mut reader = MifareReader::new(17);
        let mut attack = NestedAttack::new(0, KeyType::A, KNOWN_KEY);
        attack.samples = 2;
        let distance = attack.calibrate(&mut card, &mut reader).unwrap();
        let mut capture = attack
            .capture(&mut card, &mut reader, 4, KeyType::A)
            .unwrap();
        capture.samples.truncate(1);
        assert!(attack.recover(&capture, distance).is_err());
    }

    #[test]
    fn distance_between_is_the_inverse_of_prng_successor() {
        let mut rng = Rng::new(3);
        for _ in 0..20 {
            let base = prng_successor(rng.next_u32(), 32);
            let steps = (rng.next_u32() % 1000) + 1;
            let later = prng_successor(base, steps);
            assert_eq!(distance_between(base, later), Some(steps));
        }
    }
}
