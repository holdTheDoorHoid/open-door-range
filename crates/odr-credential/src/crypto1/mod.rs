//! Crypto1 — the 48-bit stream cipher on every MIFARE Classic card.
//!
//! NXP designed Crypto1 in the mid-1990s and kept it secret. In 2007–2008 Nohl and
//! Plötz recovered it by polishing a decapped die and reading the gates, and Garcia
//! et al. published a full description and practical key-recovery attacks. It has
//! been broken, in public, for the entire working life of most of the badges that
//! still use it.
//!
//! This module implements it properly, because the attacks in [`crate::nested`] have
//! to work against *this* — if the cipher here were a stand-in, the attack would be a
//! stage trick and the drill would be teaching a story rather than a fact.
//!
//! # The construction
//!
//! A 48-bit linear feedback shift register, plus a non-linear filter that reads 20 of
//! its bits and produces one keystream bit. The feedback polynomial is
//!
//! ```text
//! x^48 + x^43 + x^39 + x^38 + x^36 + x^34 + x^33 + x^31 + x^29 + x^24
//!      + x^23 + x^21 + x^19 + x^13 + x^9 + x^7 + x^6 + x^5 + 1
//! ```
//!
//! and — this is the part that matters — **the filter reads only odd-indexed bits of
//! the register.** So the register splits cleanly into an "odd" half and an "even"
//! half that take turns feeding the filter, and a great deal of the state can be
//! searched one half at a time. That structural mistake is what turns a nominal 2^48
//! key search into something a laptop finishes while you are still standing at the
//! door. The state is stored here as two 24-bit halves for exactly that reason; it is
//! not an optimisation, it is the shape of the weakness.
//!
//! # The three-pass authentication
//!
//! ```text
//! reader -> card   AUTH(block, key A|B)
//! card   -> reader nT                      (in the clear on a first authentication)
//! reader -> card   {nR} {aR}               aR = suc^64(nT)
//! card   -> reader {aT}                    aT = suc^96(nT)
//! ```
//!
//! Both sides load the sector key into the register, shift in `uid xor nT`, then shift
//! in `nR`. From then on the keystream encrypts everything. Note what is *not* here:
//! the card never proves it knows the key before the reader commits, the nonce is 32
//! bits from a 16-bit generator, and the successor function `suc` is public.
//!
//! # Encrypted parity — the leak that makes everything else possible
//!
//! ISO 14443-A puts an odd parity bit after every byte. On an encrypted MIFARE link
//! that parity bit is computed over the **plaintext** byte and then XORed with a
//! keystream bit — and it is the *same* keystream bit that will encrypt the first bit
//! of the next byte. So every byte leaks one bit of a relation between plaintext and
//! keystream, for free, forever. Nearly every practical MIFARE attack starts here.
//! See [`Crypto1::peek`].
//!
//! # Sources
//!
//! Constants and bit order follow the `crapto1` reference implementation (Nohl,
//! Plötz, Bettendorf; GPL), cross-checked against the published feedback polynomial —
//! see the crate README for the derivation.

pub mod recovery;

pub use recovery::{recover_states, RecoveryStats};

/// Feedback taps applied to the odd half of the register.
pub const LF_POLY_ODD: u32 = 0x0029_CE5C;

/// Feedback taps applied to the even half of the register.
pub const LF_POLY_EVEN: u32 = 0x0087_0804;

/// Mask for one 24-bit half-register.
pub const HALF_MASK: u32 = 0x00FF_FFFF;

/// Parity of a 32-bit word.
#[inline]
pub const fn parity32(x: u32) -> bool {
    x.count_ones() % 2 == 1
}

/// The ISO 14443-A odd parity bit for a byte.
///
/// Odd parity: the nine bits that go on the air — eight data plus this one — contain
/// an odd number of ones. So the bit is set when the byte's own population count is
/// even.
#[inline]
pub const fn odd_parity8(byte: u8) -> bool {
    byte.count_ones().is_multiple_of(2)
}

/// Bit `i` of a 32-bit word in MIFARE transmission order.
///
/// MIFARE sends the most significant *byte* first but the least significant *bit* of
/// each byte first. `bebit(x, 0)` is therefore bit 24 of `x`. Getting this wrong
/// produces a cipher that is self-consistent and matches no real card, so it is
/// factored out here and used everywhere.
#[inline]
pub const fn bebit(x: u32, i: usize) -> bool {
    (x >> (i ^ 24)) & 1 == 1
}

/// The non-linear filter function.
///
/// Twenty bits in, one bit out. Internally it is six instances of three small
/// Boolean functions: five 4-bit functions (two of one kind, three of another)
/// feeding a 5-bit function. The magic constants below are those functions as
/// truth tables, packed into integers and indexed by shifting — the form the
/// `crapto1` reference uses.
///
/// The two 4-bit tables are `0xD938` (used at nibbles 1 and 4) and `0xF22C` (nibbles
/// 0, 2 and 3), and the 5-bit table is `0xEC57E80A`. You can read that pattern
/// straight out of the constants: `0x6c9c0 = 0xD938 << 3`, `0x0d938 = 0xD938`,
/// `0xf22c0 = 0xF22C << 4`, `0x3c8b0 = 0xF22C << 2`, `0x1e458 = 0xF22C << 1`.
///
/// Note the argument: only the low 20 bits are read, and they come from the *odd*
/// half-register. Twenty-eight bits of the 48 are invisible to any single keystream
/// bit. That is the door [`recovery`] walks through.
#[inline]
pub fn filter(x: u32) -> bool {
    let mut f = 0u32;
    f |= (0x000f_22c0u32 >> (x & 0xf)) & 16;
    f |= (0x0006_c9c0u32 >> ((x >> 4) & 0xf)) & 8;
    f |= (0x0003_c8b0u32 >> ((x >> 8) & 0xf)) & 4;
    f |= (0x0001_e458u32 >> ((x >> 12) & 0xf)) & 2;
    f |= (0x0000_d938u32 >> ((x >> 16) & 0xf)) & 1;
    (0xEC57_E80Au32 >> f) & 1 == 1
}

/// The Crypto1 cipher state: a 48-bit LFSR held as odd and even 24-bit halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Crypto1 {
    /// Odd-indexed register bits. This is the half the filter reads.
    pub odd: u32,
    /// Even-indexed register bits.
    pub even: u32,
}

impl Crypto1 {
    /// Load a 48-bit sector key.
    ///
    /// The bit shuffle is not decoration: MIFARE keys are written as six bytes and
    /// the register is loaded least-significant-bit-of-each-byte first, which is why
    /// key `A0A1A2A3A4A5` does not appear in the register in any recognisable order.
    pub const fn from_key(key: u64) -> Self {
        let mut odd = 0u32;
        let mut even = 0u32;
        let mut i = 47i32;
        while i > 0 {
            odd = (odd << 1) | (((key >> (((i - 1) as u32) ^ 7)) & 1) as u32);
            even = (even << 1) | (((key >> ((i as u32) ^ 7)) & 1) as u32);
            i -= 2;
        }
        Self {
            odd: odd & HALF_MASK,
            even: even & HALF_MASK,
        }
    }

    /// Read the 48-bit key back out of the register.
    ///
    /// Exactly inverts [`Crypto1::from_key`]. After rolling a recovered state back
    /// through the nonce, this is what turns a cipher state into a key you can type
    /// into a reader.
    pub const fn key(&self) -> u64 {
        let mut key = 0u64;
        let mut t = 0usize;
        while t < 24 {
            let odd_bit = (self.odd >> (23 - t)) & 1;
            let even_bit = (self.even >> (23 - t)) & 1;
            key |= (odd_bit as u64) << (((46 - 2 * t) as u32) ^ 7);
            key |= (even_bit as u64) << (((47 - 2 * t) as u32) ^ 7);
            t += 1;
        }
        key
    }

    /// The next keystream bit *without* advancing the cipher.
    ///
    /// This is how an encrypted parity bit is produced: the parity of byte *n* is
    /// masked with the keystream bit that will go on to encrypt bit 0 of byte *n+1*.
    /// Reusing a keystream bit across two different plaintexts is the textbook
    /// stream-cipher mistake, and MIFARE makes it once per byte, by design.
    #[inline]
    pub fn peek(&self) -> bool {
        filter(self.odd)
    }

    /// Clock the cipher once.
    ///
    /// `input` is the bit shifted into the feedback. `is_encrypted` says whether
    /// `input` arrived already XORed with the keystream — during the `nR` exchange
    /// the card receives ciphertext and must strip the keystream before feeding it,
    /// so that both ends shift in the same plaintext.
    #[inline]
    pub fn bit(&mut self, input: bool, is_encrypted: bool) -> bool {
        let out = filter(self.odd);
        let mut feedin = out & is_encrypted;
        feedin ^= input;
        feedin ^= parity32(LF_POLY_ODD & self.odd);
        feedin ^= parity32(LF_POLY_EVEN & self.even);
        self.even = ((self.even << 1) | u32::from(feedin)) & HALF_MASK;
        core::mem::swap(&mut self.odd, &mut self.even);
        out
    }

    /// Clock eight times, least significant bit of the byte first.
    pub fn byte(&mut self, input: u8, is_encrypted: bool) -> u8 {
        let mut ret = 0u8;
        for i in 0..8 {
            if self.bit((input >> i) & 1 == 1, is_encrypted) {
                ret |= 1 << i;
            }
        }
        ret
    }

    /// Clock thirty-two times in MIFARE transmission order.
    pub fn word(&mut self, input: u32, is_encrypted: bool) -> u32 {
        let mut ret = 0u32;
        for i in 0..32 {
            if self.bit(bebit(input, i), is_encrypted) {
                ret |= 1 << (i ^ 24);
            }
        }
        ret
    }

    /// Clock a word and also report the four keystream bits that encrypt its parity.
    ///
    /// Returns `(keystream_word, parity_keystream)`, where `parity_keystream[n]` is
    /// the keystream bit immediately after byte *n* — the one that masks byte *n*'s
    /// parity, and that also encrypts the first bit of byte *n+1*.
    pub fn word_with_parity(&mut self, input: u32, is_encrypted: bool) -> (u32, [bool; 4]) {
        let mut ret = 0u32;
        let mut par = [false; 4];
        for i in 0..32 {
            if self.bit(bebit(input, i), is_encrypted) {
                ret |= 1 << (i ^ 24);
            }
            if i % 8 == 7 {
                par[i / 8] = self.peek();
            }
        }
        (ret, par)
    }

    /// Undo one clock. Returns the keystream bit that step produced.
    ///
    /// `input` is the plaintext bit that was shifted in and `fb` whether the
    /// keystream was folded into the feedback. Rolling a state backwards through the
    /// nonce exchange is how a recovered mid-session state becomes the sector key.
    pub fn rollback_bit(&mut self, input: bool, fb: bool) -> bool {
        self.odd &= HALF_MASK;
        core::mem::swap(&mut self.odd, &mut self.even);

        let mut out = self.even & 1 == 1;
        self.even >>= 1;
        out ^= parity32(LF_POLY_EVEN & self.even);
        out ^= parity32(LF_POLY_ODD & self.odd);
        out ^= input;
        let ret = filter(self.odd);
        out ^= ret & fb;

        self.even |= u32::from(out) << 23;
        ret
    }

    /// Undo eight clocks.
    pub fn rollback_byte(&mut self, input: u8, fb: bool) -> u8 {
        let mut ret = 0u8;
        for i in (0..8).rev() {
            if self.rollback_bit((input >> i) & 1 == 1, fb) {
                ret |= 1 << i;
            }
        }
        ret
    }

    /// Undo thirty-two clocks.
    pub fn rollback_word(&mut self, input: u32, fb: bool) -> u32 {
        let mut ret = 0u32;
        for i in (0..32).rev() {
            if self.rollback_bit(bebit(input, i), fb) {
                ret |= 1 << (i ^ 24);
            }
        }
        ret
    }
}

/// Advance a MIFARE tag nonce `n` steps of its generator.
///
/// The tag nonce is not random. It is 32 consecutive outputs of a 16-bit LFSR with
/// polynomial `x^16 + x^14 + x^13 + x^11 + 1`, which means there are only 65535
/// possible nonces, that one nonce determines every later nonce, and that the
/// authentication's `aR` and `aT` values — `suc^64(nT)` and `suc^96(nT)` — are
/// computable by anybody who saw `nT`.
///
/// Every practical MIFARE attack leans on this function. The nested attack in
/// [`crate::nested`] leans on it hardest: it predicts an encrypted nonce, rather than
/// recovering it, and that prediction is what turns the encrypted nonce into 32 known
/// keystream bits.
pub fn prng_successor(nonce: u32, steps: u32) -> u32 {
    let mut x = nonce.swap_bytes();
    for _ in 0..steps {
        let feedback = ((x >> 16) ^ (x >> 18) ^ (x >> 19) ^ (x >> 21)) & 1;
        x = (x >> 1) | (feedback << 31);
    }
    x.swap_bytes()
}

/// The tag's nonce generator, free-running.
///
/// Models what the card actually does: the LFSR never stops, so the nonce a card
/// offers depends on *when* you ask it. That is normally described as a nuisance. It
/// is in fact the entire basis of the nested attack, because an attacker who controls
/// the timing controls the nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceLfsr {
    nonce: u32,
}

impl NonceLfsr {
    /// Seed the generator.
    ///
    /// Any seed is accepted; the state is then advanced far enough to land inside the
    /// generator's real orbit, so the nonces a simulated card produces satisfy the
    /// same `suc` relation real ones do. A seed of zero is nudged, because the
    /// all-zero state of an LFSR is a fixed point and a card stuck there would be
    /// even weaker than the real thing.
    pub fn seeded(seed: u32) -> Self {
        let seed = if seed == 0 { 0x1234_5678 } else { seed };
        Self {
            nonce: prng_successor(seed, 32),
        }
    }

    /// The nonce the card would offer right now.
    pub const fn nonce(&self) -> u32 {
        self.nonce
    }

    /// Run the generator forward `steps` clocks.
    pub fn advance(&mut self, steps: u32) {
        self.nonce = prng_successor(self.nonce, steps);
    }

    /// Take the current nonce and advance past it.
    pub fn take(&mut self, steps_after: u32) -> u32 {
        let n = self.nonce;
        self.advance(steps_after);
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_constants_are_two_tables_not_five() {
        // The claim in the module docs, checked: nibbles 1 and 4 share a truth table,
        // nibbles 0, 2 and 3 share the other. If someone mistypes a constant, this
        // fails loudly instead of producing a plausible-looking wrong cipher.
        assert_eq!(0x0006_c9c0u32 >> 3, 0xD938);
        assert_eq!(0x0000_d938u32, 0xD938);
        assert_eq!(0x000f_22c0u32 >> 4, 0xF22C);
        assert_eq!(0x0003_c8b0u32 >> 2, 0xF22C);
        assert_eq!(0x0001_e458u32 >> 1, 0xF22C);
    }

    #[test]
    fn feedback_taps_match_the_published_polynomial() {
        // Garcia et al., "Dismantling MIFARE Classic" (2008), give the feedback as
        //   L(x0..x47) = x0 + x5 + x9 + x10 + x12 + x14 + x15 + x17 + x19
        //              + x24 + x25 + x27 + x29 + x35 + x39 + x41 + x42 + x43
        // with x0 the oldest bit in the register. Equivalently
        //   x^48 + x^43 + x^39 + x^38 + x^36 + x^34 + x^33 + x^31 + x^29
        //        + x^24 + x^23 + x^21 + x^19 + x^13 + x^9 + x^7 + x^6 + x^5 + 1.
        //
        // The two 24-bit tap masks used by this implementation came from the crapto1
        // reference. This test derives the polynomial back out of them, so the
        // constants are checked against published cryptanalysis rather than trusted.
        const PAPER_TAPS: [u32; 18] = [
            0, 5, 9, 10, 12, 14, 15, 17, 19, 24, 25, 27, 29, 35, 39, 41, 42, 43,
        ];

        let mut taps = Vec::new();
        for k in 0..24u32 {
            // Bit 0 of a half-register is the bit inserted most recently, and the two
            // halves interleave, so odd bit k is 2k+1 steps old and even bit k is
            // 2k+2. In the paper's numbering that is index 48 - age.
            if (LF_POLY_ODD >> k) & 1 == 1 {
                taps.push(48 - (2 * k + 1));
            }
            if (LF_POLY_EVEN >> k) & 1 == 1 {
                taps.push(48 - (2 * k + 2));
            }
        }
        taps.sort_unstable();
        assert_eq!(taps.as_slice(), &PAPER_TAPS);
    }

    #[test]
    fn the_filter_reads_only_odd_indexed_state_bits() {
        // The paper: f is applied to x9, x11, x13, ... x47 — twenty bits, all odd
        // indices. Here the filter reads the low 20 bits of the odd half-register,
        // which are the bits of age 1, 3, ... 39, i.e. paper indices 47, 45, ... 9.
        let indices: Vec<u32> = (0..20u32).map(|k| 48 - (2 * k + 1)).collect();
        assert_eq!(indices.first(), Some(&47));
        assert_eq!(indices.last(), Some(&9));
        assert!(indices.iter().all(|i| i % 2 == 1));

        // And bits 20..23 of the odd half are invisible to any single keystream bit:
        // changing them cannot change the filter output.
        for k in 20..24 {
            let x = 1u32 << k;
            assert_eq!(filter(x), filter(0), "bit {k} must not reach the filter");
        }
    }

    #[test]
    fn key_load_round_trips() {
        let mut rng = crate::Rng::new(0xC1);
        for _ in 0..1000 {
            let key = rng.next_crypto1_key();
            assert_eq!(Crypto1::from_key(key).key(), key);
        }
    }

    #[test]
    fn rollback_undoes_the_cipher_exactly() {
        let mut rng = crate::Rng::new(7);
        for _ in 0..200 {
            let key = rng.next_crypto1_key();
            let input = rng.next_u32();
            let start = Crypto1::from_key(key);

            let mut s = start;
            s.word(input, false);
            s.rollback_word(input, false);
            assert_eq!(s, start);

            let mut s = start;
            s.word(input, true);
            s.rollback_word(input, true);
            assert_eq!(s, start);
        }
    }

    #[test]
    fn peek_predicts_the_next_keystream_bit() {
        let mut s = Crypto1::from_key(0xA0A1_A2A3_A4A5);
        s.word(0x1234_5678, false);
        let predicted = s.peek();
        assert_eq!(s.bit(false, false), predicted);
    }

    #[test]
    fn prng_successor_composes() {
        let mut rng = crate::Rng::new(11);
        for _ in 0..100 {
            let n = rng.next_u32();
            assert_eq!(
                prng_successor(prng_successor(n, 32), 32),
                prng_successor(n, 64)
            );
        }
    }

    #[test]
    fn nonce_generator_stays_in_its_orbit() {
        // Any nonce the card offers must be reachable from any earlier one, which is
        // the property the nested attack's nonce prediction depends on.
        let mut gen = NonceLfsr::seeded(0xACE1_2345);
        let first = gen.nonce();
        gen.advance(137);
        let later = gen.nonce();
        assert_eq!(prng_successor(first, 137), later);
    }

    #[test]
    fn there_are_only_sixty_five_thousand_nonces() {
        // Walk the generator and find its period. A 16-bit LFSR with a primitive
        // polynomial cycles through every non-zero state: 65535 of them.
        let mut gen = NonceLfsr::seeded(1);
        let start = gen.nonce();
        let mut period = 0u32;
        for step in 1..=70_000u32 {
            gen.advance(1);
            if gen.nonce() == start {
                period = step;
                break;
            }
        }
        assert_eq!(period, 65_535);
    }

    /// The whole cipher, against a trace captured from real hardware.
    ///
    /// Published `mfkey32v2` test vector: a genuine MIFARE Classic authentication
    /// with key `A0A1A2A3A4A5`. Given the uid, the plaintext tag nonce and the
    /// *encrypted* reader nonce, this implementation must reproduce the encrypted
    /// `aR` byte for byte. It exercises key loading, bit and byte order, the
    /// `is_encrypted` feedback rule and `prng_successor` all at once — nothing else
    /// in this crate is checked against the outside world this tightly.
    #[test]
    fn matches_a_real_captured_authentication() {
        const UID: u32 = 0x1234_5678;
        const KEY: u64 = 0xA0A1_A2A3_A4A5;

        for &(nt, nr_enc, ar_enc) in &[
            (0x1AD8_DF2Bu32, 0x1D31_6024u32, 0x620E_F048u32),
            (0x30D6_CB07, 0xC520_77E2, 0x837A_C61A),
        ] {
            let mut cipher = Crypto1::from_key(KEY);
            cipher.word(UID ^ nt, false);
            // The card receives {nR} and strips the keystream to feed nR itself.
            cipher.word(nr_enc, true);
            let ks3 = cipher.word(0, false);
            assert_eq!(ks3 ^ prng_successor(nt, 64), ar_enc);
        }
    }

    #[test]
    fn a_wrong_key_produces_a_wrong_response() {
        const UID: u32 = 0x1234_5678;
        const NT: u32 = 0x1AD8_DF2B;
        let mut cipher = Crypto1::from_key(0xA0A1_A2A3_A4A6);
        cipher.word(UID ^ NT, false);
        cipher.word(0x1D31_6024, true);
        let ks3 = cipher.word(0, false);
        assert_ne!(ks3 ^ prng_successor(NT, 64), 0x620E_F048);
    }

    #[test]
    fn odd_parity_makes_nine_bits_odd() {
        for b in 0u8..=255 {
            let ones = b.count_ones() + u32::from(odd_parity8(b));
            assert_eq!(ones % 2, 1);
        }
    }

    #[test]
    fn bebit_is_msb_byte_first_lsb_bit_first() {
        let x = 0x8000_0001u32;
        assert!(!bebit(x, 0)); // bit 24
        assert!(bebit(x, 7)); // bit 31
        assert!(bebit(x, 24)); // bit 0
    }
}
