//! A deterministic, seeded random number generator.
//!
//! There is no `getrandom` here and no `std::time`. Every random value in the
//! simulation — a card's challenge, a reader's nonce, a randomised credential in a
//! drill — is drawn from an [`Rng`] the caller seeded. Two consequences:
//!
//! * the same scenario produces the same bytes on any machine, in a browser or on a
//!   command line, so a drill flag is stable and a bug is reproducible;
//! * the crate builds for `wasm32-unknown-unknown` without a JavaScript shim.
//!
//! The generator is SplitMix64 (Steele, Lea & Flood, 2014) — one multiply-xorshift
//! round per output word. It is not cryptographically strong and does not need to be:
//! it stands in for a card's hardware RNG in a simulation whose whole point is that
//! you can rerun it.
//!
//! Note the deliberate exception: the MIFARE Classic card does **not** draw its tag
//! nonce from here. It draws it from [`crate::crypto1::NonceLfsr`], a faithful model
//! of the 16-bit LFSR NXP actually shipped — because the weakness of that generator
//! is the entire basis of the nested attack.

/// A seeded, deterministic pseudo-random number generator (SplitMix64).
///
/// ```
/// use odr_credential::Rng;
///
/// let mut a = Rng::new(0xDEAD_BEEF);
/// let mut b = Rng::new(0xDEAD_BEEF);
/// assert_eq!(a.next_u64(), b.next_u64());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Create a generator from a seed. Any seed is valid, including zero.
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The generator's current internal state.
    ///
    /// Useful for snapshotting a scenario mid-run and resuming it identically.
    pub const fn state(&self) -> u64 {
        self.state
    }

    /// Draw the next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Draw the next 32 bits.
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Draw a value in `0..n`. Returns 0 when `n` is 0.
    ///
    /// Uses the multiply-shift reduction, which is very slightly biased for `n` that
    /// do not divide 2^64. The bias is irrelevant at simulation scale and the method
    /// is branch-free, so a drill never stalls.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        ((self.next_u64() as u128 * n as u128) >> 64) as u64
    }

    /// Fill a byte buffer.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    /// Draw a 16-byte block, the shape DESFire wants for `RndA` and `RndB`.
    pub fn next_block16(&mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        self.fill_bytes(&mut out);
        out
    }

    /// Draw a 48-bit MIFARE Classic key.
    pub fn next_crypto1_key(&mut self) -> u64 {
        self.next_u64() & 0xFFFF_FFFF_FFFF
    }
}

impl Default for Rng {
    /// Seed 0. Deliberate: a default-constructed range is still reproducible.
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn below_respects_bound() {
        let mut r = Rng::new(7);
        for _ in 0..1000 {
            assert!(r.below(10) < 10);
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn fill_bytes_handles_ragged_tail() {
        let mut r = Rng::new(9);
        let mut buf = [0u8; 13];
        r.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn crypto1_key_fits_48_bits() {
        let mut r = Rng::new(3);
        for _ in 0..100 {
            assert!(r.next_crypto1_key() < 1 << 48);
        }
    }
}
