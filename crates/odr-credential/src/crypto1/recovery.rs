//! Recovering a Crypto1 state from 32 bits of keystream.
//!
//! This is the engine underneath every practical MIFARE Classic attack. Give it
//! thirty-two keystream bits and the thirty-two input bits that were shifted in
//! alongside them, and it returns every 48-bit cipher state consistent with both —
//! about 2^16 of them, from which one more observation picks the right one. Roll that
//! state backwards through the nonce and you have the sector key.
//!
//! # Why 2^48 does not cost 2^48
//!
//! Two structural facts about Crypto1, and nothing else:
//!
//! 1. **The filter reads only odd-indexed register bits.** So the register splits into
//!    two 24-bit halves that take turns being filtered, and consecutive keystream bits
//!    constrain *alternate* halves. Each half can be searched on its own.
//! 2. **A single keystream bit sees only twenty bits.** The other four bits of the
//!    half-register it reads are invisible, so the search starts from 2^20 candidates,
//!    not 2^24, and half of those are killed by the very first keystream bit.
//!
//! What stops the two halves from being searched entirely independently is the
//! feedback, which mixes both. The trick — and it is the whole algorithm — is that
//! each half needs exactly **one bit** from the other per step: the parity of the
//! other half under the odd tap mask. So each half is extended by *guessing* that one
//! bit, and the guess is recorded. Two candidates from opposite halves are compatible
//! only when each one's guesses match what the other actually produces. That turns an
//! impossible 2^19 x 2^19 cross product into a sort-and-merge on a 22-bit key.
//!
//! # Shape of the run
//!
//! ```text
//! 2^20 seeds per half, halved by the first keystream bit        ~2^19 each
//! four free extensions: the half-register becomes fully known    ~2^19 each
//! eleven guessed extensions: 22 bits of matching key accrue      ~2^19 each
//! sort both halves, merge on the key                             ~2^16 states
//! ```
//!
//! Thirty-two constraints on forty-eight unknowns leaves sixteen bits of freedom, and
//! 2^16 is exactly what comes out — which is a useful sanity check on the whole
//! construction, and one of the tests below asserts it.
//!
//! # Credit
//!
//! The observation that the odd/even split makes Crypto1 searchable is Nohl and
//! Plötz's, developed by Garcia et al. and implemented in `crapto1`. The algorithm
//! here was derived from those structural facts rather than transcribed, and is
//! checked against the cipher itself by [`recover_states`]'s round-trip tests.

use super::{bebit, filter, parity32, Crypto1, HALF_MASK, LF_POLY_EVEN, LF_POLY_ODD};

/// Free extensions before a half-register is fully determined.
const FREE_EXTENSIONS: usize = 4;

/// Extensions that must guess one bit from the opposite half.
const GUESSED_EXTENSIONS: usize = 11;

/// A precomputed truth table for [`filter`] over its twenty significant bits.
///
/// 2^20 bits — 128 KiB — and it turns the filter from five shifts into one load.
/// Built once per recovery, which is free next to the 30-odd million lookups that
/// follow.
struct FilterTable {
    words: Vec<u64>,
}

impl FilterTable {
    fn new() -> Self {
        let mut words = vec![0u64; 1 << 14];
        for v in 0..(1u32 << 20) {
            if filter(v) {
                words[(v >> 6) as usize] |= 1u64 << (v & 63);
            }
        }
        Self { words }
    }

    #[inline]
    fn get(&self, v: u32) -> bool {
        let v = v & 0x000F_FFFF;
        (self.words[(v >> 6) as usize] >> (v & 63)) & 1 == 1
    }
}

/// What a recovery run cost and produced.
///
/// Exposed so a drill can show the learner the actual numbers rather than asserting
/// that the attack is cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryStats {
    /// Surviving candidates for the half-register filtered by even-indexed keystream.
    pub even_step_candidates: usize,
    /// Surviving candidates for the half filtered by odd-indexed keystream.
    pub odd_step_candidates: usize,
    /// Complete cipher states the merge produced.
    pub states: usize,
}

/// Every cipher state consistent with 32 bits of keystream.
///
/// `keystream` is the 32 keystream bits in MIFARE transmission order; `input` is the
/// 32 bits that were shifted into the feedback over the same period, unencrypted (for
/// the nonce exchange that is `uid xor nT`).
///
/// The returned states are the cipher **after** those 32 steps — roll back through
/// the same input with [`Crypto1::rollback_word`] to reach the key.
pub fn recover_states(keystream: u32, input: u32) -> Vec<Crypto1> {
    recover_states_with_stats(keystream, input).0
}

/// [`recover_states`], and the numbers behind it.
pub fn recover_states_with_stats(keystream: u32, input: u32) -> (Vec<Crypto1>, RecoveryStats) {
    let table = FilterTable::new();

    // Chain A holds the half-register filtered at even step numbers, chain B the one
    // filtered at odd step numbers.
    let mut a = seed_chain(&table, keystream, 0);
    let mut b = seed_chain(&table, keystream, 1);

    // Phase two: extend both, guessing the one bit each needs from the other and
    // recording, for every candidate, both what it guessed and what it produced.
    //
    // Entries are packed as (match_key << 32) | register. A's key is
    // (produced << 11) | guessed; B's is (guessed << 11) | produced, so two
    // compatible candidates have equal keys.
    let mut a: Vec<u64> = a.drain(..).map(u64::from).collect();
    let mut b: Vec<u64> = b.drain(..).map(u64::from).collect();
    let mut scratch: Vec<u64> = Vec::with_capacity(a.len());

    for j in 0..GUESSED_EXTENSIONS {
        let m = FREE_EXTENSIONS + j;

        // A_{m+1} = A_m<<1 | b, with b = parity(ODD & B_m) ^ parity(EVEN & A_m) ^ in.
        let want = bebit(keystream, 2 * m + 2);
        let in_bit = bebit(input, 2 * m + 1);
        scratch.clear();
        for &entry in &a {
            let reg = entry as u32;
            let key = (entry >> 32) as u32;
            let own = parity32(LF_POLY_EVEN & reg) ^ in_bit;
            for guess in [false, true] {
                let next = ((reg << 1) | u32::from(guess ^ own)) & HALF_MASK;
                if table.get(next) == want {
                    let produced = parity32(LF_POLY_ODD & next);
                    let key = key
                        | (u32::from(guess) << j)
                        | (u32::from(produced) << (GUESSED_EXTENSIONS + j));
                    scratch.push((u64::from(key) << 32) | u64::from(next));
                }
            }
        }
        core::mem::swap(&mut a, &mut scratch);

        // B_{m+1} = B_m<<1 | b, with b = parity(ODD & A_{m+1}) ^ parity(EVEN & B_m) ^ in.
        // B publishes parity(ODD & B_m) — the bit A just guessed at this index.
        let want = bebit(keystream, 2 * m + 3);
        let in_bit = bebit(input, 2 * m + 2);
        scratch.clear();
        for &entry in &b {
            let reg = entry as u32;
            let key = (entry >> 32) as u32;
            let produced = parity32(LF_POLY_ODD & reg);
            let own = parity32(LF_POLY_EVEN & reg) ^ in_bit;
            for guess in [false, true] {
                let next = ((reg << 1) | u32::from(guess ^ own)) & HALF_MASK;
                if table.get(next) == want {
                    let key = key
                        | (u32::from(produced) << j)
                        | (u32::from(guess) << (GUESSED_EXTENSIONS + j));
                    scratch.push((u64::from(key) << 32) | u64::from(next));
                }
            }
        }
        core::mem::swap(&mut b, &mut scratch);

        if a.is_empty() || b.is_empty() {
            break;
        }
    }

    let stats_a = a.len();
    let stats_b = b.len();

    // Merge on the match key.
    a.sort_unstable();
    b.sort_unstable();

    let last_in = bebit(input, 31);
    let mut states = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        let ka = a[i] >> 32;
        let kb = b[j] >> 32;
        match ka.cmp(&kb) {
            core::cmp::Ordering::Less => i += 1,
            core::cmp::Ordering::Greater => j += 1,
            core::cmp::Ordering::Equal => {
                let i_end = a[i..].partition_point(|&e| e >> 32 == ka) + i;
                let j_end = b[j..].partition_point(|&e| e >> 32 == kb) + j;
                for &ea in &a[i..i_end] {
                    let reg_a = ea as u32;
                    for &eb in &b[j..j_end] {
                        let reg_b = eb as u32;
                        // O_32 = O_30<<1 | b_31
                        let feedback = parity32(LF_POLY_ODD & reg_b)
                            ^ parity32(LF_POLY_EVEN & reg_a)
                            ^ last_in;
                        states.push(Crypto1 {
                            odd: ((reg_a << 1) | u32::from(feedback)) & HALF_MASK,
                            even: reg_b,
                        });
                    }
                }
                i = i_end;
                j = j_end;
            }
        }
    }

    let stats = RecoveryStats {
        even_step_candidates: stats_a,
        odd_step_candidates: stats_b,
        states: states.len(),
    };
    (states, stats)
}

/// Seed one half-register and extend it until it is fully determined.
///
/// `first_step` is 0 for the half filtered at even step numbers, 1 for the other.
/// The first keystream bit halves 2^20 seeds; each of the four extensions doubles the
/// list and the next keystream bit halves it again, so the population stays near 2^19
/// while the registers grow from 20 known bits to all 24.
fn seed_chain(table: &FilterTable, keystream: u32, first_step: usize) -> Vec<u32> {
    let want = bebit(keystream, first_step);
    let mut current: Vec<u32> = Vec::with_capacity(1 << 19);
    for v in 0..(1u32 << 20) {
        if table.get(v) == want {
            current.push(v);
        }
    }

    let mut next: Vec<u32> = Vec::with_capacity(1 << 19);
    for m in 1..=FREE_EXTENSIONS {
        let want = bebit(keystream, first_step + 2 * m);
        next.clear();
        for &v in &current {
            let base = v << 1;
            if table.get(base) == want {
                next.push(base);
            }
            if table.get(base | 1) == want {
                next.push(base | 1);
            }
        }
        core::mem::swap(&mut current, &mut next);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rng;

    /// Run a state forward 32 steps and collect the keystream, the way a card does
    /// while it shifts in `uid xor nT`.
    fn keystream_of(state: Crypto1, input: u32) -> (u32, Crypto1) {
        let mut s = state;
        let ks = s.word(input, false);
        (ks, s)
    }

    #[test]
    fn filter_table_agrees_with_the_filter() {
        let table = FilterTable::new();
        let mut rng = Rng::new(5);
        for _ in 0..10_000 {
            let v = rng.next_u32() & 0x000F_FFFF;
            assert_eq!(table.get(v), filter(v));
        }
    }

    #[test]
    fn recovers_the_state_it_was_never_given() {
        let start = Crypto1::from_key(0xA0A1_A2A3_A4A5);
        let input = 0x1234_5678u32;
        let (ks, after) = keystream_of(start, input);

        let (states, stats) = recover_states_with_stats(ks, input);
        assert!(
            states.contains(&after),
            "the true state must be among {} candidates",
            stats.states
        );

        // Thirty-two constraints on forty-eight unknowns: about 2^16 survivors.
        assert!(
            stats.states > 1 << 14 && stats.states < 1 << 18,
            "expected roughly 2^16 states, got {}",
            stats.states
        );
    }

    #[test]
    fn every_recovered_state_really_produces_the_keystream() {
        let start = Crypto1::from_key(0x0123_4567_89AB);
        let input = 0xDEAD_BEEFu32;
        let (ks, _) = keystream_of(start, input);

        let states = recover_states(ks, input);
        assert!(!states.is_empty());
        // Roll each candidate back through the input and run it forward again.
        for state in states.iter().take(500) {
            let mut rolled = *state;
            rolled.rollback_word(input, false);
            let (candidate_ks, candidate_end) = keystream_of(rolled, input);
            assert_eq!(candidate_ks, ks);
            assert_eq!(candidate_end, *state);
        }
    }

    #[test]
    fn rolling_a_recovered_state_back_yields_the_key() {
        let key = 0xFFFF_FFFF_FFFFu64;
        let input = 0xCAFE_F00Du32;
        let (ks, after) = keystream_of(Crypto1::from_key(key), input);

        let states = recover_states(ks, input);
        let mut found = false;
        for state in &states {
            let mut rolled = *state;
            rolled.rollback_word(input, false);
            if rolled.key() == key {
                found = true;
                assert_eq!(*state, after);
                break;
            }
        }
        assert!(found, "the real key must be among the recovered candidates");
    }

    #[test]
    fn works_for_seeded_random_keys() {
        let mut rng = Rng::new(0x5EED);
        for _ in 0..2 {
            let key = rng.next_crypto1_key();
            let input = rng.next_u32();
            let (ks, after) = keystream_of(Crypto1::from_key(key), input);
            assert!(recover_states(ks, input).contains(&after));
        }
    }
}
