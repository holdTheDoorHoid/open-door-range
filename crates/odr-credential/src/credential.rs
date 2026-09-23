//! What a reader emits after a successful read.
//!
//! Deliberately dumb: a format identifier, a bit count, and the bits. `odr-bus` will
//! hand this to either a Wiegand wire or an OSDP `osdp_RAW` payload, and this crate
//! must not know or care which. There is no facility-code field here — that belongs
//! to the *format*, and a reader that does not understand the format still forwards
//! the bits perfectly well. That is not a simplification; it is how readers work, and
//! it is why re-encoding attacks on the wire are possible at all.

use crate::error::{CredentialError, Result};

/// Which bit layout the accompanying bits are in.
///
/// This is an identifier, not a parser. The bits travel regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CredentialFormat {
    /// 26-bit HID H10301: leading even parity, 8-bit facility code, 16-bit card
    /// number, trailing odd parity. See [`crate::hid_prox`].
    Wiegand26H10301,
    /// A 40-bit EM4100 tag identity: 8-bit version/customer code then a 32-bit ID.
    /// See [`crate::em4100`].
    Em4100,
    /// 128 bits read out of one MIFARE Classic block. See [`crate::mifare`].
    MifareClassicBlock,
    /// Bytes read out of a DESFire file after mutual authentication.
    /// See [`crate::desfire`].
    DesfireFile,
    /// Bits of no declared format — what an implant or a frame composer produces.
    Raw,
}

impl CredentialFormat {
    /// A short stable name, for logs and for the site's UI.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wiegand26H10301 => "wiegand26-h10301",
            Self::Em4100 => "em4100",
            Self::MifareClassicBlock => "mifare-classic-block",
            Self::DesfireFile => "desfire-file",
            Self::Raw => "raw",
        }
    }
}

/// A credential as it leaves the reader.
///
/// Bits are stored **most-significant-first**: bit index 0 is the first bit the
/// reader will clock onto the wire. `data[0] & 0x80` is that bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Which layout the bits are in.
    pub format: CredentialFormat,
    /// How many bits are meaningful. The tail of the last byte is padding.
    pub bit_len: u16,
    /// The bits, MSB-first, `ceil(bit_len / 8)` bytes long.
    pub data: Vec<u8>,
}

impl Credential {
    /// Build a credential from a right-aligned integer.
    ///
    /// `bit_len` must be 64 or fewer and `value` must fit in it.
    pub fn from_u64(format: CredentialFormat, bit_len: u16, value: u64) -> Result<Self> {
        if bit_len > 64 {
            return Err(CredentialError::ValueTooWide {
                field: "credential",
                bits: 64,
            });
        }
        if bit_len < 64 && value >= (1u64 << bit_len) {
            return Err(CredentialError::ValueTooWide {
                field: "credential",
                bits: u32::from(bit_len),
            });
        }
        let bytes = usize::from(bit_len).div_ceil(8);
        let mut data = vec![0u8; bytes];
        for i in 0..usize::from(bit_len) {
            // bit i (MSB-first) is bit (bit_len - 1 - i) of the integer
            let shift = usize::from(bit_len) - 1 - i;
            if (value >> shift) & 1 == 1 {
                data[i / 8] |= 0x80 >> (i % 8);
            }
        }
        Ok(Self {
            format,
            bit_len,
            data,
        })
    }

    /// Build a credential from a bit slice, first-transmitted bit first.
    pub fn from_bits(format: CredentialFormat, bits: &[bool]) -> Result<Self> {
        let bit_len = u16::try_from(bits.len()).map_err(|_| CredentialError::ValueTooWide {
            field: "credential",
            bits: u32::from(u16::MAX),
        })?;
        let mut data = vec![0u8; bits.len().div_ceil(8)];
        for (i, &b) in bits.iter().enumerate() {
            if b {
                data[i / 8] |= 0x80 >> (i % 8);
            }
        }
        Ok(Self {
            format,
            bit_len,
            data,
        })
    }

    /// Build a credential from whole bytes.
    pub fn from_bytes(format: CredentialFormat, bytes: &[u8]) -> Result<Self> {
        let bit_len =
            u16::try_from(bytes.len() * 8).map_err(|_| CredentialError::ValueTooWide {
                field: "credential",
                bits: u32::from(u16::MAX),
            })?;
        Ok(Self {
            format,
            bit_len,
            data: bytes.to_vec(),
        })
    }

    /// Bit `index`, counted from the first bit transmitted. `None` past the end.
    pub fn bit(&self, index: usize) -> Option<bool> {
        if index >= usize::from(self.bit_len) {
            return None;
        }
        self.data
            .get(index / 8)
            .map(|byte| (byte >> (7 - index % 8)) & 1 == 1)
    }

    /// All the bits, first-transmitted first.
    pub fn bits(&self) -> Vec<bool> {
        (0..usize::from(self.bit_len))
            .map(|i| self.bit(i).unwrap_or(false))
            .collect()
    }

    /// The bits as a right-aligned integer. Saturates at the low 64 bits.
    ///
    /// For every format in Module 0 and Module 1 this is lossless; for a MIFARE block
    /// it is not, and you want [`Credential::data`] instead.
    pub fn as_u64(&self) -> u64 {
        let mut v = 0u64;
        for i in 0..usize::from(self.bit_len).min(64) {
            v = (v << 1) | u64::from(self.bit(i).unwrap_or(false));
        }
        v
    }

    /// Render as a bit string, e.g. `"00111011..."`. For drill UI and for logs.
    pub fn to_bit_string(&self) -> String {
        self.bits()
            .into_iter()
            .map(|b| if b { '1' } else { '0' })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_u64() {
        let c = Credential::from_u64(CredentialFormat::Wiegand26H10301, 26, 0x02F6_23AE).unwrap();
        assert_eq!(c.as_u64(), 0x02F6_23AE);
        assert_eq!(c.bit_len, 26);
        assert_eq!(c.data.len(), 4);
    }

    #[test]
    fn bit_zero_is_first_transmitted() {
        // 26-bit H10301 for FC 123 / card 4567 starts with a set leading parity bit.
        let c = Credential::from_u64(CredentialFormat::Wiegand26H10301, 26, 0x02F6_23AE).unwrap();
        assert_eq!(c.bit(0), Some(true));
        assert_eq!(c.bit(25), Some(false));
        assert_eq!(c.bit(26), None);
    }

    #[test]
    fn rejects_values_that_do_not_fit() {
        assert!(Credential::from_u64(CredentialFormat::Raw, 8, 256).is_err());
        assert!(Credential::from_u64(CredentialFormat::Raw, 8, 255).is_ok());
        assert!(Credential::from_u64(CredentialFormat::Raw, 65, 0).is_err());
    }

    #[test]
    fn bits_round_trip() {
        let bits = vec![true, false, true, true, false, false, false, true, true];
        let c = Credential::from_bits(CredentialFormat::Raw, &bits).unwrap();
        assert_eq!(c.bits(), bits);
        assert_eq!(c.to_bit_string(), "101100011");
    }
}
