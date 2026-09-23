//! Parity: the only integrity check legacy Wiegand has.
//!
//! There is no MAC, no signature, no nonce. A Wiegand frame carries one or
//! three parity bits and that is the entire defence. Parity catches a single
//! flipped bit on a long cable run; it catches nothing at all that an attacker
//! does on purpose, because an attacker recomputes it. That gap is the lesson
//! of Track 1 in the range, so parity gets its own module and its own vocabulary
//! rather than being buried inside the format code.
//!
//! Parity is modelled *declaratively*: a format is a list of [`ParityRule`]s,
//! each saying "bit N is even/odd parity over this set of bit positions".
//! Encoding applies the rules; decoding checks them and reports each one
//! separately. That separation is deliberate — a decoder must be able to say
//! "this parses as H10301 with facility code 42, **but the trailing parity bit
//! is wrong**", because on a live wire a parity failure is a diagnostic signal
//! (a marginal cable, a reader with a dying LED driver, a clumsy implant), not
//! a reason to throw the frame away.

use crate::bits::BitVec;
use alloc::vec::Vec;
use core::fmt;

/// Which way a parity bit leans.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Parity {
    /// The parity bit is chosen so the total number of one bits — the covered
    /// bits *plus the parity bit itself* — is even.
    Even,
    /// The parity bit is chosen so that total is odd.
    Odd,
}

impl Parity {
    /// The parity bit value given how many of the covered bits are ones.
    pub fn bit_for(self, ones: usize) -> bool {
        match self {
            Parity::Even => ones % 2 == 1,
            Parity::Odd => ones % 2 == 0,
        }
    }

    /// Short human name, for UI and log lines.
    pub fn name(self) -> &'static str {
        match self {
            Parity::Even => "even",
            Parity::Odd => "odd",
        }
    }
}

/// Which bit positions a parity bit covers.
///
/// Most formats cover a contiguous run. HID Corporate 1000 does not — its two
/// inner parity bits cover interleaved combs of positions — so an explicit
/// index list is also supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// `len` bits starting at `start`, inclusive of `start`.
    Range {
        /// First covered index.
        start: usize,
        /// Number of covered indices.
        len: usize,
    },
    /// An explicit, arbitrary set of indices.
    Indices(Vec<usize>),
}

impl Coverage {
    /// Expand to the list of covered indices.
    pub fn indices(&self) -> Vec<usize> {
        match self {
            Coverage::Range { start, len } => (*start..start + len).collect(),
            Coverage::Indices(v) => v.clone(),
        }
    }

    /// How many bits are covered.
    pub fn count(&self) -> usize {
        match self {
            Coverage::Range { len, .. } => *len,
            Coverage::Indices(v) => v.len(),
        }
    }

    /// Every index in `start..=end` whose value modulo `modulus` is not
    /// `skip_residue`.
    ///
    /// This exists for Corporate 1000, whose inner parity bits cover "two out
    /// of every three" positions. Spelling that out as a literal list of
    /// twenty-two numbers twice would be unreadable and easy to mistype.
    pub fn comb(start: usize, end_inclusive: usize, modulus: usize, skip_residue: usize) -> Coverage {
        let idx = (start..=end_inclusive).filter(|p| p % modulus != skip_residue).collect();
        Coverage::Indices(idx)
    }
}

/// One parity bit: where it lives, which way it leans, and what it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityRule {
    /// Index of the parity bit itself.
    pub bit: usize,
    /// Even or odd.
    pub parity: Parity,
    /// The bits it is computed over. Must not include `bit`.
    pub coverage: Coverage,
    /// Human label, e.g. `"leading even parity"`.
    pub label: &'static str,
}

impl ParityRule {
    /// Compute what the parity bit *should* be for these bits.
    ///
    /// Returns `None` if any covered index is past the end of `bits`, which is
    /// how a short or truncated frame is reported rather than panicked on.
    pub fn compute(&self, bits: &BitVec) -> Option<bool> {
        let mut ones = 0usize;
        for i in self.coverage.indices() {
            if bits.get(i)? {
                ones += 1;
            }
        }
        Some(self.parity.bit_for(ones))
    }

    /// Write the correct parity bit into `bits`.
    ///
    /// Returns `false` if the frame is too short for the rule; the caller
    /// decides whether that is an error.
    pub fn apply(&self, bits: &mut BitVec) -> bool {
        match self.compute(bits) {
            Some(v) => bits.set(self.bit, v).is_ok(),
            None => false,
        }
    }

    /// Compare the parity bit present in `bits` against the computed value.
    pub fn check(&self, bits: &BitVec) -> ParityCheck {
        let expected = self.compute(bits);
        let observed = bits.get(self.bit);
        ParityCheck {
            bit: self.bit,
            parity: self.parity,
            label: self.label,
            covered: self.coverage.count(),
            expected,
            observed,
        }
    }
}

/// The result of checking one [`ParityRule`] against a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParityCheck {
    /// Index of the parity bit.
    pub bit: usize,
    /// Even or odd.
    pub parity: Parity,
    /// Human label copied from the rule.
    pub label: &'static str,
    /// How many bits the rule covers.
    pub covered: usize,
    /// What the bit should have been; `None` if the frame was too short.
    pub expected: Option<bool>,
    /// What the bit actually was; `None` if the frame was too short.
    pub observed: Option<bool>,
}

impl ParityCheck {
    /// True only when both values are present and equal.
    ///
    /// A truncated frame is *not* valid parity — it is unknown parity — and
    /// this returns `false` for it. Use [`ParityCheck::is_indeterminate`] to
    /// tell the two apart.
    pub fn is_ok(&self) -> bool {
        matches!((self.expected, self.observed), (Some(a), Some(b)) if a == b)
    }

    /// True when the frame was too short to evaluate the rule.
    pub fn is_indeterminate(&self) -> bool {
        self.expected.is_none() || self.observed.is_none()
    }
}

impl fmt::Display for ParityCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = if self.is_indeterminate() {
            "indeterminate"
        } else if self.is_ok() {
            "ok"
        } else {
            "FAILED"
        };
        write!(
            f,
            "bit {} ({} {}, over {} bits): {}",
            self.bit,
            self.parity.name(),
            self.label,
            self.covered,
            state
        )
    }
}

/// Every parity check for one frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParityReport {
    /// One entry per rule, in the order the format declares them.
    pub checks: Vec<ParityCheck>,
}

impl ParityReport {
    /// Build a report by running every rule against `bits`.
    pub fn evaluate(rules: &[ParityRule], bits: &BitVec) -> ParityReport {
        ParityReport { checks: rules.iter().map(|r| r.check(bits)).collect() }
    }

    /// True when every rule passed.
    ///
    /// A format with no parity rules at all (the raw passthrough) reports
    /// `true` — vacuously, and that is the honest answer: nothing was claimed,
    /// so nothing failed.
    pub fn is_valid(&self) -> bool {
        self.checks.iter().all(ParityCheck::is_ok)
    }

    /// True when at least one rule could not be evaluated.
    pub fn is_indeterminate(&self) -> bool {
        self.checks.iter().any(ParityCheck::is_indeterminate)
    }

    /// The rules that failed.
    pub fn failures(&self) -> impl Iterator<Item = &ParityCheck> {
        self.checks.iter().filter(|c| !c.is_ok())
    }

    /// Number of rules checked.
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// True when the format declares no parity at all.
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }
}

/// Even parity over an arbitrary byte-sized value, for convenience.
///
/// Returns the bit that would make the total number of ones even.
pub fn even_parity_bit(value: u64) -> bool {
    value.count_ones() % 2 == 1
}

/// Odd parity over an arbitrary value.
pub fn odd_parity_bit(value: u64) -> bool {
    value.count_ones() % 2 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_direction() {
        // Two ones covered: even parity adds 0, odd parity adds 1.
        assert!(!Parity::Even.bit_for(2));
        assert!(Parity::Odd.bit_for(2));
        assert!(Parity::Even.bit_for(3));
        assert!(!Parity::Odd.bit_for(3));
    }

    #[test]
    fn rule_apply_then_check() {
        let rule = ParityRule {
            bit: 0,
            parity: Parity::Even,
            coverage: Coverage::Range { start: 1, len: 4 },
            label: "test",
        };
        let mut bits = BitVec::from_bin_str("01110").unwrap();
        assert!(rule.apply(&mut bits));
        // Three ones covered -> even parity bit is 1.
        assert_eq!(bits.to_bin_string(), "11110");
        assert!(rule.check(&bits).is_ok());

        bits.set(0, false).unwrap();
        assert!(!rule.check(&bits).is_ok());
    }

    #[test]
    fn short_frame_is_indeterminate_not_a_panic() {
        let rule = ParityRule {
            bit: 0,
            parity: Parity::Odd,
            coverage: Coverage::Range { start: 1, len: 40 },
            label: "test",
        };
        let bits = BitVec::zeros(5);
        let check = rule.check(&bits);
        assert!(check.is_indeterminate());
        assert!(!check.is_ok());
    }

    #[test]
    fn comb_coverage() {
        // Corporate 1000's even rule: 2..=33 skipping p % 3 == 1.
        let c = Coverage::comb(2, 33, 3, 1);
        let idx = c.indices();
        assert_eq!(&idx[..6], &[2, 3, 5, 6, 8, 9]);
        assert_eq!(idx.len(), 22);
        assert!(!idx.contains(&4));
    }
}
