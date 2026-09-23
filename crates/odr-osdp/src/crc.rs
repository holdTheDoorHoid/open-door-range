//! Frame integrity: CRC-16/AUG-CCITT and the one-byte checksum.
//!
//! An OSDP frame ends in a *trailer* that protects everything before it. Which
//! trailer is used is announced by bit 2 of the control byte:
//!
//! * bit 2 set  → a two-byte CRC-16, little-endian (this is what every modern
//!   deployment uses, and what OSDP v2 requires for secure channel)
//! * bit 2 clear → a single-byte checksum, kept for compatibility with very old
//!   equipment
//!
//! Neither is a security control. Both are error-detection codes with no key,
//! so anyone on the bus can recompute them after tampering with a frame. That
//! is precisely why the Mellon "downgrade" and "inline implant" attacks work on
//! an unencrypted bus: rewriting a reply and fixing up the CRC is trivial.

/// Generator polynomial for OSDP's CRC-16, in normal (non-reflected) form.
///
/// This is the classic CCITT polynomial `x^16 + x^12 + x^5 + 1`.
pub const CRC_POLY: u16 = 0x1021;

/// Initial CRC register value.
///
/// `0x1D0F` is what distinguishes *AUG-CCITT* from the many other CRC-16
/// variants that share the `0x1021` polynomial. Getting this wrong is the most
/// common reason a hand-rolled OSDP parser rejects valid traffic.
pub const CRC_INIT: u16 = 0x1D0F;

/// The published check value of CRC-16/AUG-CCITT over the ASCII bytes
/// `"123456789"`.
///
/// Every CRC catalogue entry carries one of these. If [`crc16`] does not
/// produce this, the implementation is wrong — see the unit test in this
/// module.
pub const CRC_CHECK_VALUE: u16 = 0xE5CC;

/// Compute CRC-16/AUG-CCITT over `data`.
///
/// Parameters: poly `0x1021`, init `0x1D0F`, input **not** reflected, output
/// **not** reflected, final XOR `0x0000`.
///
/// ```
/// use odr_osdp::crc::crc16;
/// assert_eq!(crc16(b"123456789"), 0xE5CC);
/// ```
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = CRC_INIT;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ CRC_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Compute the one-byte OSDP checksum over `data`.
///
/// This is the two's-complement 8-bit checksum: the returned byte is whatever
/// value makes the sum of `data` plus that byte come out to zero modulo 256.
/// So verification is simply "add up every byte including the trailer and
/// check you got 0".
///
/// ```
/// use odr_osdp::crc::{checksum, checksum_is_valid};
/// let body = [0x53u8, 0x00, 0x08, 0x00, 0x00, 0x60];
/// let c = checksum(&body);
/// assert!(checksum_is_valid(&body, c));
/// ```
pub fn checksum(data: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for &byte in data {
        sum = sum.wrapping_add(byte);
    }
    // Two's complement: negate, i.e. (!sum + 1).
    (!sum).wrapping_add(1)
}

/// Verify a one-byte checksum trailer against the frame body that precedes it.
pub fn checksum_is_valid(body: &[u8], trailer: u8) -> bool {
    checksum(body) == trailer
}

/// Verify a CRC-16 trailer against the frame body that precedes it.
pub fn crc16_is_valid(body: &[u8], trailer: u16) -> bool {
    crc16(body) == trailer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalogue check value. If this test fails, nothing downstream of it
    /// can be trusted.
    #[test]
    fn crc_check_value_is_e5cc() {
        assert_eq!(crc16(b"123456789"), 0xE5CC);
        assert_eq!(crc16(b"123456789"), CRC_CHECK_VALUE);
    }

    #[test]
    fn crc_of_empty_input_is_the_init_value() {
        assert_eq!(crc16(&[]), CRC_INIT);
    }

    #[test]
    fn crc_is_order_sensitive() {
        assert_ne!(crc16(b"ab"), crc16(b"ba"));
    }

    #[test]
    fn checksum_sums_to_zero() {
        let body = [0x53u8, 0x00, 0x08, 0x00, 0x00, 0x60];
        let c = checksum(&body);
        let total = body
            .iter()
            .fold(0u8, |a, &b| a.wrapping_add(b))
            .wrapping_add(c);
        assert_eq!(total, 0);
        assert!(checksum_is_valid(&body, c));
    }

    #[test]
    fn checksum_of_zero_sum_is_zero() {
        assert_eq!(checksum(&[0x00, 0x00]), 0x00);
        assert_eq!(checksum(&[0x01, 0xFF]), 0x00);
    }
}
