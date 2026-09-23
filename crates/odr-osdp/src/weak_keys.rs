//! The published "Mellon" weak-key family.
//!
//! Attack 4 of the five Bishop Fox / Mellon findings (Petro & Vargas, 2023) is
//! that a large fraction of deployed OSDP installations use a Secure Channel
//! Base Key taken verbatim from vendor sample code or documentation. Those
//! sample keys are not random: they are a handful of obvious byte patterns,
//! roughly 768 keys in total, and an attacker who captures one secure-channel
//! handshake can try every one of them offline in microseconds.
//!
//! We generate the family rather than shipping a table, because the *shape* of
//! the family is the teaching point: these are the keys a human types when they
//! need "some bytes" and do not think of the key as a secret.
//!
//! # The three patterns
//!
//! | Pattern    | Description                                   | Count |
//! |------------|-----------------------------------------------|-------|
//! | Repeated   | one byte repeated 16 times                    | 256   |
//! | Ascending  | 16 bytes counting up from a start byte (wraps) | 256   |
//! | Descending | 16 bytes counting down from a start byte (wraps) | 256 |
//!
//! 768 keys total, with a small overlap that [`enumerate`] does not
//! de-duplicate (see [`WeakKeyPattern`]).
//!
//! # Why SCBK-D is in here
//!
//! The OSDP default key [`SCBK_D`] is
//! `30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F` — the ASCII digits `0`
//! through `9` followed by the four bytes after them. That is exactly the
//! ascending run starting at `0x30`, so the standard's own "install mode"
//! default key is a member of the weak family. That is not a coincidence or a
//! bug; SCBK-D is *designed* to be public. The problem is installations that
//! never move off it.

/// The OSDP default Secure Channel Base Key, "SCBK-D".
///
/// Published in the specification and therefore known to everyone. A PD that is
/// still using it advertises the fact in the CHLNG/CCRYPT security block (the
/// key-type byte is `0` for SCBK-D, `1` for a real site key), so an eavesdropper
/// does not even have to guess — see [`crate::security::SecurityBlock`].
pub const SCBK_D: [u8; 16] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

/// Which of the three sample-code patterns a weak key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeakKeyPattern {
    /// A single byte repeated sixteen times, e.g. `AA AA AA ... AA`.
    Repeated {
        /// The repeated byte.
        byte: u8,
    },
    /// Sixteen bytes counting upward from `start`, wrapping at `0xFF`.
    ///
    /// [`SCBK_D`] is `Ascending { start: 0x30 }`.
    Ascending {
        /// First byte of the run.
        start: u8,
    },
    /// Sixteen bytes counting downward from `start`, wrapping at `0x00`.
    Descending {
        /// First byte of the run.
        start: u8,
    },
}

impl WeakKeyPattern {
    /// Materialise the 16-byte key this pattern describes.
    pub fn key(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        match self {
            WeakKeyPattern::Repeated { byte } => out = [byte; 16],
            WeakKeyPattern::Ascending { start } => {
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = start.wrapping_add(i as u8);
                }
            }
            WeakKeyPattern::Descending { start } => {
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = start.wrapping_sub(i as u8);
                }
            }
        }
        out
    }
}

/// Total number of keys [`enumerate`] yields: 256 of each of the three
/// patterns.
///
/// Note this counts *pattern instances*, not distinct keys. `Ascending`,
/// `Descending` and `Repeated` all collapse to the same key when the step would
/// be zero — there is no such case here, since ascending and descending both
/// have a real step — but a `Repeated` key is never equal to an ascending or
/// descending one, so in practice all 768 are distinct. The published figure
/// people quote is "about 768".
pub const WEAK_KEY_COUNT: usize = 768;

/// Enumerate the whole weak-key family, in a stable order:
/// all 256 repeated-byte keys, then all 256 ascending runs, then all 256
/// descending runs.
///
/// The iterator is lazy and allocates nothing, so an attacker actor can run it
/// inside a WASM worker without building a 12 KiB table first.
///
/// ```
/// use odr_osdp::weak_keys::{enumerate, SCBK_D};
/// assert!(enumerate().any(|p| p.key() == SCBK_D));
/// ```
pub fn enumerate() -> impl Iterator<Item = WeakKeyPattern> {
    let repeated = (0u16..=255).map(|b| WeakKeyPattern::Repeated { byte: b as u8 });
    let ascending = (0u16..=255).map(|b| WeakKeyPattern::Ascending { start: b as u8 });
    let descending = (0u16..=255).map(|b| WeakKeyPattern::Descending { start: b as u8 });
    repeated.chain(ascending).chain(descending)
}

/// Test a candidate key against the family.
///
/// Returns the pattern it matches, or `None` if the key is not one of the
/// published samples. This does not mean the key is *good* — it only means it
/// is not in this particular published list.
///
/// ```
/// use odr_osdp::weak_keys::{classify, WeakKeyPattern, SCBK_D};
/// assert_eq!(classify(&SCBK_D), Some(WeakKeyPattern::Ascending { start: 0x30 }));
/// assert_eq!(classify(&[0xAB; 16]), Some(WeakKeyPattern::Repeated { byte: 0xAB }));
/// ```
pub fn classify(key: &[u8; 16]) -> Option<WeakKeyPattern> {
    let first = key[0];

    if key.iter().all(|&b| b == first) {
        return Some(WeakKeyPattern::Repeated { byte: first });
    }
    let ascending = WeakKeyPattern::Ascending { start: first };
    if ascending.key() == *key {
        return Some(ascending);
    }
    let descending = WeakKeyPattern::Descending { start: first };
    if descending.key() == *key {
        return Some(descending);
    }
    None
}

/// Convenience predicate: is this key a member of the published weak family?
pub fn is_weak(key: &[u8; 16]) -> bool {
    classify(key).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;

    #[test]
    fn scbk_d_is_the_ascending_run_from_0x30() {
        assert_eq!(WeakKeyPattern::Ascending { start: 0x30 }.key(), SCBK_D);
        assert!(is_weak(&SCBK_D));
        assert_eq!(
            classify(&SCBK_D),
            Some(WeakKeyPattern::Ascending { start: 0x30 })
        );
    }

    #[test]
    fn enumerate_yields_768_patterns() {
        assert_eq!(enumerate().count(), WEAK_KEY_COUNT);
    }

    #[test]
    fn every_enumerated_pattern_classifies_back_to_itself() {
        for pattern in enumerate() {
            let key = pattern.key();
            assert_eq!(classify(&key), Some(pattern), "round trip for {pattern:?}");
        }
    }

    #[test]
    fn all_768_keys_are_distinct() {
        let set: BTreeSet<Vec<u8>> = enumerate().map(|p| p.key().to_vec()).collect();
        assert_eq!(set.len(), WEAK_KEY_COUNT);
    }

    #[test]
    fn runs_wrap_around() {
        let k = WeakKeyPattern::Ascending { start: 0xF8 }.key();
        assert_eq!(
            &k[..10],
            &[0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01]
        );
        let k = WeakKeyPattern::Descending { start: 0x03 }.key();
        assert_eq!(&k[..6], &[0x03, 0x02, 0x01, 0x00, 0xFF, 0xFE]);
    }

    #[test]
    fn a_real_random_looking_key_is_not_weak() {
        let key = [
            0x8f, 0x2b, 0x00, 0xd1, 0x47, 0x9c, 0x63, 0xaa, 0x11, 0xfe, 0x5d, 0x30, 0x77, 0xc4,
            0x19, 0xe2,
        ];
        assert!(!is_weak(&key));
        assert_eq!(classify(&key), None);
    }
}
