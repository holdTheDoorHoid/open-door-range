//! Bit vectors, in transmission order.
//!
//! Everything in this crate agrees on one convention, and it is worth stating
//! plainly because half the confusion around Wiegand comes from people using
//! two conventions at once:
//!
//! > **Bit index 0 is the first bit that appears on the wire.**
//!
//! A 26-bit H10301 credential is 26 bits long; index 0 is the leading parity
//! bit, index 25 is the trailing parity bit. When such a frame is written as a
//! number (the usual "hex dump" of a card), index 0 is the *most significant*
//! bit of that number. So [`BitVec::extract_u64`] reads a field MSB-first, and
//! [`BitVec::to_hex_string`] pads on the **left**.
//!
//! [`BitVec`] stores one `bool` per bit. That is wasteful and entirely
//! deliberate: this crate is read by people learning the protocol, and a
//! `Vec<bool>` you can index is easier to reason about than a packed word pair.
//! Credentials are tens of bits long, so the cost is nothing.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Things that can go wrong building or reading a [`BitVec`].
///
/// None of these ever come from data observed on a wire — a wire only ever
/// produces bits. They come from *programmer* input: a bad literal, a field
/// wider than 64 bits, an index past the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitError {
    /// A character other than `0`, `1`, `_` or whitespace appeared in a binary
    /// literal.
    BadBinaryChar {
        /// The offending character.
        ch: char,
        /// Its byte offset in the input string.
        at: usize,
    },
    /// Asked for more than 64 bits as an integer.
    TooWide {
        /// The requested width.
        len: usize,
    },
    /// A value does not fit in the requested number of bits.
    ValueTooLarge {
        /// The value that did not fit.
        value: u64,
        /// The field width it was asked to fit in.
        len: usize,
    },
    /// An index (or a `start + len` window) ran past the end of the vector.
    OutOfRange {
        /// First bit index requested.
        start: usize,
        /// Number of bits requested.
        len: usize,
        /// Length of the vector that was indexed.
        have: usize,
    },
}

impl fmt::Display for BitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitError::BadBinaryChar { ch, at } => {
                write!(
                    f,
                    "unexpected character {ch:?} at offset {at} in binary literal"
                )
            }
            BitError::TooWide { len } => write!(f, "{len} bits will not fit in a u64"),
            BitError::ValueTooLarge { value, len } => {
                write!(f, "value {value} does not fit in {len} bits")
            }
            BitError::OutOfRange { start, len, have } => {
                write!(
                    f,
                    "bits {start}..{} requested but only {have} present",
                    start + len
                )
            }
        }
    }
}

/// A sequence of bits in transmission order.
///
/// See the [module docs](self) for the indexing convention.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct BitVec {
    bits: Vec<bool>,
}

impl BitVec {
    /// An empty bit vector.
    pub fn new() -> Self {
        BitVec { bits: Vec::new() }
    }

    /// An empty bit vector with room for `n` bits.
    pub fn with_capacity(n: usize) -> Self {
        BitVec {
            bits: Vec::with_capacity(n),
        }
    }

    /// `n` zero bits. Useful as a canvas before fields and parity are written.
    pub fn zeros(n: usize) -> Self {
        BitVec {
            bits: alloc::vec![false; n],
        }
    }

    /// Build from a slice of booleans, first element transmitted first.
    pub fn from_bools(bits: &[bool]) -> Self {
        BitVec {
            bits: bits.to_vec(),
        }
    }

    /// Parse a binary literal such as `"1000_0110_0011"`.
    ///
    /// `_` and ASCII whitespace are ignored so that layouts can be written out
    /// with the field boundaries visible.
    ///
    /// # Errors
    /// [`BitError::BadBinaryChar`] if any other character appears.
    pub fn from_bin_str(s: &str) -> Result<Self, BitError> {
        let mut bits = Vec::with_capacity(s.len());
        for (at, ch) in s.char_indices() {
            match ch {
                '0' => bits.push(false),
                '1' => bits.push(true),
                '_' => {}
                c if c.is_ascii_whitespace() => {}
                other => return Err(BitError::BadBinaryChar { ch: other, at }),
            }
        }
        Ok(BitVec { bits })
    }

    /// Render `value` as `len` bits, most significant bit first.
    ///
    /// # Errors
    /// [`BitError::TooWide`] if `len > 64`, [`BitError::ValueTooLarge`] if the
    /// value needs more than `len` bits.
    pub fn from_u64_msb(value: u64, len: usize) -> Result<Self, BitError> {
        if len > 64 {
            return Err(BitError::TooWide { len });
        }
        if len < 64 && value >= (1u64 << len) {
            return Err(BitError::ValueTooLarge { value, len });
        }
        let mut bits = Vec::with_capacity(len);
        for i in (0..len).rev() {
            bits.push((value >> i) & 1 == 1);
        }
        Ok(BitVec { bits })
    }

    /// Number of bits held.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// True when there are no bits.
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Bit at `index`, or `None` past the end. Never panics.
    pub fn get(&self, index: usize) -> Option<bool> {
        self.bits.get(index).copied()
    }

    /// Overwrite the bit at `index`.
    ///
    /// # Errors
    /// [`BitError::OutOfRange`] if `index` is past the end.
    pub fn set(&mut self, index: usize, value: bool) -> Result<(), BitError> {
        match self.bits.get_mut(index) {
            Some(slot) => {
                *slot = value;
                Ok(())
            }
            None => Err(BitError::OutOfRange {
                start: index,
                len: 1,
                have: self.bits.len(),
            }),
        }
    }

    /// Append one bit.
    pub fn push(&mut self, value: bool) {
        self.bits.push(value);
    }

    /// Append all of `other`.
    pub fn extend(&mut self, other: &BitVec) {
        self.bits.extend_from_slice(&other.bits);
    }

    /// Append `n` zero bits (leading clock bits, idle padding, and so on).
    pub fn extend_zeros(&mut self, n: usize) {
        self.bits.resize(self.bits.len() + n, false);
    }

    /// Iterate bits in transmission order.
    pub fn iter(&self) -> impl Iterator<Item = bool> + '_ {
        self.bits.iter().copied()
    }

    /// Borrow the backing slice.
    pub fn as_slice(&self) -> &[bool] {
        &self.bits
    }

    /// Read `len` bits starting at `start` as an integer, MSB first.
    ///
    /// Returns `None` rather than panicking if the window runs off the end or
    /// is wider than 64 bits — decoders run on data they did not create.
    pub fn extract_u64(&self, start: usize, len: usize) -> Option<u64> {
        if len > 64 || start.checked_add(len)? > self.bits.len() {
            return None;
        }
        let mut value = 0u64;
        for i in 0..len {
            value = (value << 1) | u64::from(self.bits[start + i]);
        }
        Some(value)
    }

    /// Copy `len` bits starting at `start` into a new [`BitVec`].
    ///
    /// Returns `None` if the window runs off the end.
    pub fn slice(&self, start: usize, len: usize) -> Option<BitVec> {
        let end = start.checked_add(len)?;
        if end > self.bits.len() {
            return None;
        }
        Some(BitVec {
            bits: self.bits[start..end].to_vec(),
        })
    }

    /// Write `value` into `len` bits starting at `start`, MSB first.
    ///
    /// # Errors
    /// [`BitError::OutOfRange`] if the window runs off the end,
    /// [`BitError::TooWide`] / [`BitError::ValueTooLarge`] as for
    /// [`BitVec::from_u64_msb`].
    pub fn set_field(&mut self, start: usize, len: usize, value: u64) -> Result<(), BitError> {
        if len > 64 {
            return Err(BitError::TooWide { len });
        }
        if start + len > self.bits.len() {
            return Err(BitError::OutOfRange {
                start,
                len,
                have: self.bits.len(),
            });
        }
        if len < 64 && value >= (1u64 << len) {
            return Err(BitError::ValueTooLarge { value, len });
        }
        for i in 0..len {
            self.bits[start + i] = (value >> (len - 1 - i)) & 1 == 1;
        }
        Ok(())
    }

    /// How many bits are set.
    pub fn count_ones(&self) -> usize {
        self.bits.iter().filter(|b| **b).count()
    }

    /// Render as `0`/`1` characters, first transmitted bit leftmost.
    pub fn to_bin_string(&self) -> String {
        self.bits
            .iter()
            .map(|b| if *b { '1' } else { '0' })
            .collect()
    }

    /// Render as uppercase hex, left-padded to a whole number of nibbles.
    ///
    /// A 26-bit frame therefore becomes 7 hex digits with the top two bits of
    /// the leading digit always zero. This is the same convention card tools
    /// print, so a value here can be pasted into one of them.
    pub fn to_hex_string(&self) -> String {
        let pad = (4 - self.bits.len() % 4) % 4;
        let total = self.bits.len() + pad;
        let mut out = String::with_capacity(total / 4);
        let mut nibble = 0u8;
        for i in 0..total {
            let bit = if i < pad { false } else { self.bits[i - pad] };
            nibble = (nibble << 1) | u8::from(bit);
            if i % 4 == 3 {
                out.push(
                    char::from_digit(u32::from(nibble), 16)
                        .unwrap_or('?')
                        .to_ascii_uppercase(),
                );
                nibble = 0;
            }
        }
        out
    }

    /// The same bits in reverse order.
    ///
    /// Occasionally useful when a reader has been wired backwards, which does
    /// happen and which the range should be able to show.
    pub fn reversed(&self) -> BitVec {
        let mut bits = self.bits.clone();
        bits.reverse();
        BitVec { bits }
    }
}

impl fmt::Debug for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitVec[{}]({})", self.bits.len(), self.to_bin_string())
    }
}

impl fmt::Display for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_bin_string())
    }
}

impl FromIterator<bool> for BitVec {
    fn from_iter<T: IntoIterator<Item = bool>>(iter: T) -> Self {
        BitVec {
            bits: iter.into_iter().collect(),
        }
    }
}

impl From<Vec<bool>> for BitVec {
    fn from(bits: Vec<bool>) -> Self {
        BitVec { bits }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_literal_round_trip() {
        let b = BitVec::from_bin_str("1000_0110 0011").unwrap();
        assert_eq!(b.len(), 12);
        assert_eq!(b.to_bin_string(), "100001100011");
    }

    #[test]
    fn bad_binary_char_is_reported_not_panicked() {
        let e = BitVec::from_bin_str("10102").unwrap_err();
        assert_eq!(e, BitError::BadBinaryChar { ch: '2', at: 4 });
    }

    #[test]
    fn msb_first_integer_conversion() {
        let b = BitVec::from_u64_msb(0b1011, 4).unwrap();
        assert_eq!(b.to_bin_string(), "1011");
        assert_eq!(b.extract_u64(0, 4), Some(0b1011));
        assert_eq!(b.extract_u64(1, 2), Some(0b01));
    }

    #[test]
    fn extract_past_the_end_returns_none() {
        let b = BitVec::zeros(8);
        assert_eq!(b.extract_u64(4, 8), None);
        assert_eq!(b.extract_u64(0, 65), None);
        assert_eq!(b.get(99), None);
    }

    #[test]
    fn value_too_large_is_rejected() {
        assert_eq!(
            BitVec::from_u64_msb(256, 8).unwrap_err(),
            BitError::ValueTooLarge { value: 256, len: 8 }
        );
    }

    #[test]
    fn hex_is_left_padded() {
        // 26 bits -> 7 nibbles.
        let b = BitVec::zeros(26);
        assert_eq!(b.to_hex_string(), "0000000");
        let mut b = BitVec::zeros(26);
        b.set(25, true).unwrap();
        assert_eq!(b.to_hex_string(), "0000001");
    }

    #[test]
    fn set_field_writes_msb_first() {
        let mut b = BitVec::zeros(10);
        b.set_field(2, 4, 0b1010).unwrap();
        assert_eq!(b.to_bin_string(), "0010100000");
    }
}
