//! Security blocks: the optional header that says what, if anything, secure
//! channel is doing to this frame.
//!
//! When bit 3 of the control byte is set, a *security block* sits between the
//! control byte and the command/reply id:
//!
//! ```text
//! scb_len   total length of the security block INCLUDING these two bytes
//! scb_type  one of SCS_11 .. SCS_18
//! ...       scb_len - 2 further bytes of type-specific data
//! ```
//!
//! The eight types come in four pairs, ACU-to-PD then PD-to-ACU:
//!
//! | Pair            | ACU → PD | PD → ACU | Meaning                                   |
//! |-----------------|----------|----------|-------------------------------------------|
//! | Challenge       | SCS_11   | SCS_12   | `CMD_CHLNG` / `REPLY_CCRYPT`               |
//! | Cryptogram      | SCS_13   | SCS_14   | `CMD_SCRYPT` / `REPLY_RMAC_I`              |
//! | MAC only        | SCS_15   | SCS_16   | authenticated, **payload in the clear**    |
//! | MAC + encrypted | SCS_17   | SCS_18   | authenticated and encrypted                |
//!
//! # SCS_15 and SCS_16 are a null cipher
//!
//! A bus running SCS_15/16 has "secure channel established" in every status
//! display and every audit log, and every byte of every card read is legible to
//! anyone with a $10 RS-485 dongle. The frames are authenticated, not
//! confidential. This is a supported, spec-compliant mode, and it is a common
//! default. It is also the reason "is secure channel on?" is the wrong question
//! to ask an installer.

/// The eight OSDP secure channel block types.
///
/// Numeric values `0x11` through `0x18`, which is where the names come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScsType {
    /// ACU → PD. Carries `CMD_CHLNG` and RND.A. Security block data: one byte,
    /// the key type (see [`KeyType`]).
    Chlng = 0x11,
    /// PD → ACU. Carries `REPLY_CCRYPT`. Security block data: one byte, the key
    /// type.
    Ccrypt = 0x12,
    /// ACU → PD. Carries `CMD_SCRYPT` and the server cryptogram. No extra data.
    Scrypt = 0x13,
    /// PD → ACU. Carries `REPLY_RMAC_I` and the initial R-MAC. No extra data.
    RmacI = 0x14,
    /// ACU → PD. MAC present, payload **not** encrypted.
    CmdMacOnly = 0x15,
    /// PD → ACU. MAC present, payload **not** encrypted.
    ReplyMacOnly = 0x16,
    /// ACU → PD. MAC present, payload encrypted under S-ENC.
    CmdEncrypted = 0x17,
    /// PD → ACU. MAC present, payload encrypted under S-ENC.
    ReplyEncrypted = 0x18,
}

impl ScsType {
    /// Parse a raw security block type byte.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x11 => ScsType::Chlng,
            0x12 => ScsType::Ccrypt,
            0x13 => ScsType::Scrypt,
            0x14 => ScsType::RmacI,
            0x15 => ScsType::CmdMacOnly,
            0x16 => ScsType::ReplyMacOnly,
            0x17 => ScsType::CmdEncrypted,
            0x18 => ScsType::ReplyEncrypted,
            _ => return None,
        })
    }

    /// The raw byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Does a frame with this block carry a four-byte truncated MAC just before
    /// the trailer?
    ///
    /// Only the four "in session" types do. The handshake types (SCS_11–SCS_14)
    /// do not, because no MAC chain exists yet.
    pub fn has_mac(self) -> bool {
        matches!(
            self,
            ScsType::CmdMacOnly
                | ScsType::ReplyMacOnly
                | ScsType::CmdEncrypted
                | ScsType::ReplyEncrypted
        )
    }

    /// Is the payload of a frame with this block encrypted?
    ///
    /// `false` for SCS_15/SCS_16 — the null-cipher modes.
    pub fn is_encrypted(self) -> bool {
        matches!(self, ScsType::CmdEncrypted | ScsType::ReplyEncrypted)
    }

    /// Is this a handshake block rather than an in-session one?
    pub fn is_handshake(self) -> bool {
        matches!(
            self,
            ScsType::Chlng | ScsType::Ccrypt | ScsType::Scrypt | ScsType::RmacI
        )
    }

    /// Is this block type only ever sent by the ACU (the controller)?
    pub fn is_command_side(self) -> bool {
        matches!(
            self,
            ScsType::Chlng | ScsType::Scrypt | ScsType::CmdMacOnly | ScsType::CmdEncrypted
        )
    }

    /// The standard total length of this security block, counting the `scb_len`
    /// and `scb_type` bytes themselves.
    ///
    /// `3` for SCS_11 and SCS_12 (they carry the key-type byte), `2` for every
    /// other type. A parser should accept other lengths and let the caller
    /// decide; this is what an encoder emits.
    pub fn standard_len(self) -> u8 {
        match self {
            ScsType::Chlng | ScsType::Ccrypt => 3,
            _ => 2,
        }
    }
}

/// Which base key the handshake is using, as announced in the SCS_11 / SCS_12
/// security block.
///
/// This byte is sent **in the clear, before any encryption exists**, which
/// means a passive listener learns whether the installation ever moved off the
/// default key just by watching one handshake. That is the reconnaissance step
/// of the weak-key attack, and it costs the attacker nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyType {
    /// `0x00` — SCBK-D, the published default key. See
    /// [`crate::weak_keys::SCBK_D`].
    Default = 0x00,
    /// `0x01` — a site-specific SCBK was installed with `CMD_KEYSET`.
    SiteKey = 0x01,
}

impl KeyType {
    /// Parse the key-type byte. Anything other than `0` or `1` is unknown.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(KeyType::Default),
            0x01 => Some(KeyType::SiteKey),
            _ => None,
        }
    }

    /// The raw byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A parsed security block.
///
/// `data` holds the `scb_len - 2` bytes after the type byte. For SCS_11 and
/// SCS_12 that is a single key-type byte; for the others it is normally empty.
/// Unknown trailing bytes are preserved rather than rejected, so an analyser
/// can show a capture from equipment that does something non-standard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityBlock {
    /// The block type, or `None` if the byte was not one of `0x11..=0x18`.
    ///
    /// Kept as an `Option` so that a malformed or future block does not stop a
    /// capture from being displayed.
    pub scs_type: Option<ScsType>,
    /// The raw type byte, always preserved even when `scs_type` is `None`.
    pub raw_type: u8,
    /// Everything after the type byte. Bounded by `scb_len`.
    pub data: alloc::vec::Vec<u8>,
}

impl SecurityBlock {
    /// Build a security block of a known type with no extra data.
    pub fn new(scs_type: ScsType) -> Self {
        Self {
            scs_type: Some(scs_type),
            raw_type: scs_type.to_u8(),
            data: alloc::vec::Vec::new(),
        }
    }

    /// Build an SCS_11 or SCS_12 handshake block announcing which base key is
    /// in use.
    pub fn handshake(scs_type: ScsType, key_type: KeyType) -> Self {
        Self {
            scs_type: Some(scs_type),
            raw_type: scs_type.to_u8(),
            data: alloc::vec![key_type.to_u8()],
        }
    }

    /// Total encoded length of this block, including the two header bytes.
    pub fn encoded_len(&self) -> usize {
        2 + self.data.len()
    }

    /// The key type announced in an SCS_11/SCS_12 block, if this is one and the
    /// byte is present and recognised.
    pub fn key_type(&self) -> Option<KeyType> {
        match self.scs_type {
            Some(ScsType::Chlng) | Some(ScsType::Ccrypt) => {
                self.data.first().copied().and_then(KeyType::from_u8)
            }
            _ => None,
        }
    }

    /// Convenience: does the frame carrying this block have a MAC field?
    pub fn has_mac(&self) -> bool {
        self.scs_type.is_some_and(ScsType::has_mac)
    }

    /// Convenience: is the payload of the frame carrying this block encrypted?
    pub fn is_encrypted(&self) -> bool {
        self.scs_type.is_some_and(ScsType::is_encrypted)
    }

    /// Serialise the block, `scb_len` first.
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(self.encoded_len());
        out.push(self.encoded_len() as u8);
        out.push(self.raw_type);
        out.extend_from_slice(&self.data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eight_types_round_trip() {
        for raw in 0x11u8..=0x18 {
            let t = ScsType::from_u8(raw).expect("known type");
            assert_eq!(t.to_u8(), raw);
        }
        assert_eq!(ScsType::from_u8(0x10), None);
        assert_eq!(ScsType::from_u8(0x19), None);
        assert_eq!(ScsType::from_u8(0x00), None);
    }

    #[test]
    fn scs_15_and_16_are_a_null_cipher() {
        assert!(ScsType::CmdMacOnly.has_mac());
        assert!(!ScsType::CmdMacOnly.is_encrypted());
        assert!(ScsType::ReplyMacOnly.has_mac());
        assert!(!ScsType::ReplyMacOnly.is_encrypted());
    }

    #[test]
    fn handshake_blocks_have_no_mac() {
        for t in [
            ScsType::Chlng,
            ScsType::Ccrypt,
            ScsType::Scrypt,
            ScsType::RmacI,
        ] {
            assert!(t.is_handshake());
            assert!(!t.has_mac());
            assert!(!t.is_encrypted());
        }
    }

    #[test]
    fn direction_split_is_odd_even() {
        assert!(ScsType::Chlng.is_command_side());
        assert!(!ScsType::Ccrypt.is_command_side());
        assert!(ScsType::CmdEncrypted.is_command_side());
        assert!(!ScsType::ReplyEncrypted.is_command_side());
    }

    #[test]
    fn handshake_block_encodes_key_type() {
        let b = SecurityBlock::handshake(ScsType::Chlng, KeyType::Default);
        assert_eq!(b.encode(), alloc::vec![0x03, 0x11, 0x00]);
        assert_eq!(b.key_type(), Some(KeyType::Default));

        let b = SecurityBlock::handshake(ScsType::Ccrypt, KeyType::SiteKey);
        assert_eq!(b.encode(), alloc::vec![0x03, 0x12, 0x01]);
        assert_eq!(b.key_type(), Some(KeyType::SiteKey));
    }

    #[test]
    fn plain_block_is_two_bytes() {
        let b = SecurityBlock::new(ScsType::CmdEncrypted);
        assert_eq!(b.encode(), alloc::vec![0x02, 0x17]);
        assert_eq!(b.encoded_len(), 2);
        assert_eq!(b.key_type(), None);
    }

    #[test]
    fn standard_lengths() {
        assert_eq!(ScsType::Chlng.standard_len(), 3);
        assert_eq!(ScsType::Ccrypt.standard_len(), 3);
        for t in [
            ScsType::Scrypt,
            ScsType::RmacI,
            ScsType::CmdMacOnly,
            ScsType::ReplyMacOnly,
            ScsType::CmdEncrypted,
            ScsType::ReplyEncrypted,
        ] {
            assert_eq!(t.standard_len(), 2);
        }
    }
}
