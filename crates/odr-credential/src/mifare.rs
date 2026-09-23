//! MIFARE Classic 1K — the upgrade that mostly was not.
//!
//! Moving from 125 kHz to 13.56 MHz bought a processor, memory, sector keys and a
//! mutual authentication. On paper that is a different class of credential. In
//! practice the cipher protecting all of it is [Crypto1](crate::crypto1), broken in
//! public in 2008, and the card is still on lanyards today.
//!
//! This module is the card: its memory, its keys, its access conditions, and the
//! three-pass authentication exactly as [`crate::nested`] needs to attack it.
//!
//! # Memory
//!
//! 1 KiB in 64 blocks of 16 bytes, grouped into 16 sectors of 4 blocks.
//!
//! ```text
//! block 0         manufacturer block: UID, BCC, SAK, ATQA, vendor bytes. Read-only.
//! blocks 1, 2     data
//! block 3         sector trailer: key A (6) | access bits (3) | GPB (1) | key B (6)
//! ... x16 sectors
//! ```
//!
//! **Key A is never readable.** Every access configuration returns zeros in its place.
//! That is the one hard guarantee in the layout, and it is worth noticing that it is
//! also the only one Crypto1 does not undermine — the key does not leak because it is
//! read, it leaks because the cipher protecting it is weak.
//!
//! # Access bits
//!
//! Three bits per block group — C1, C2, C3 — stored twice in bytes 6..8 of the
//! trailer, once straight and once inverted, so a corrupted trailer bricks the sector
//! rather than silently opening it. The transport configuration is `FF 07 80 69`:
//! every data block readable and writable with either key, and key B readable, which
//! is why so many cards in the field have key B set to a default nobody changed.
//!
//! # Value blocks
//!
//! A block in value format holds a signed 32-bit value three times (twice straight,
//! once inverted) and a one-byte address four times. That redundancy, plus the
//! `increment`/`decrement`/`transfer` command set, is what makes MIFARE Classic a
//! stored-value card — and it is why a broken cipher here is not only a door problem.

use crate::credential::{Credential, CredentialFormat};
use crate::crypto1::{odd_parity8, prng_successor, Crypto1, NonceLfsr};
use crate::error::{CredentialError, Result};
use crate::rng::Rng;

/// Bytes per block.
pub const BLOCK_SIZE: usize = 16;
/// Blocks on a 1K card.
pub const BLOCK_COUNT: usize = 64;
/// Sectors on a 1K card.
pub const SECTOR_COUNT: usize = 16;
/// Blocks per sector.
pub const BLOCKS_PER_SECTOR: usize = 4;

/// The default key half the world's MIFARE Classic cards still ship with.
pub const DEFAULT_KEY: u64 = 0xFFFF_FFFF_FFFF;

/// Transport-configuration access bytes 6..9 of a sector trailer.
pub const TRANSPORT_ACCESS: [u8; 4] = [0xFF, 0x07, 0x80, 0x69];

/// Microseconds of card time per step of the tag's nonce generator.
///
/// Real cards clock the nonce LFSR continuously off the 13.56 MHz field; the figure
/// usually quoted for MIFARE Classic is one step per 9.44 µs. Rounded to 10 here so
/// the virtual clock stays in whole microseconds. What the nested attack actually
/// needs is not this number but its *stability*: that the same elapsed time always
/// advances the generator by the same amount. That is true of the real card and true
/// here, and it is the property being exploited.
pub const NONCE_TICK_US: u64 = 10;

/// Which of a sector's two keys is in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyType {
    /// Key A. Never readable, in any access configuration.
    A,
    /// Key B. Readable in some configurations — which is how it leaks.
    B,
}

impl KeyType {
    /// The ISO 14443-A command byte: `0x60` for key A, `0x61` for key B.
    pub const fn command_byte(self) -> u8 {
        match self {
            Self::A => 0x60,
            Self::B => 0x61,
        }
    }

    /// Short name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }
}

/// Which key, if any, permits an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRequirement {
    /// Not permitted with either key.
    Never,
    /// Key A only.
    KeyA,
    /// Key B only.
    KeyB,
    /// Either key.
    Either,
}

impl KeyRequirement {
    /// Whether authenticating with `key` satisfies this requirement.
    pub const fn permits(self, key: KeyType) -> bool {
        matches!(
            (self, key),
            (Self::Either, _) | (Self::KeyA, KeyType::A) | (Self::KeyB, KeyType::B)
        )
    }
}

/// What a data block's access bits allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataBlockAccess {
    /// Read the 16 bytes.
    pub read: KeyRequirement,
    /// Overwrite the 16 bytes.
    pub write: KeyRequirement,
    /// Value-block increment.
    pub increment: KeyRequirement,
    /// Value-block decrement, transfer and restore.
    pub decrement: KeyRequirement,
}

/// What a sector trailer's access bits allow.
///
/// There is no `key_a_read`: it does not exist. Key A is never readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrailerAccess {
    /// Overwrite key A.
    pub key_a_write: KeyRequirement,
    /// Read the access bits themselves.
    pub access_read: KeyRequirement,
    /// Rewrite the access bits.
    pub access_write: KeyRequirement,
    /// Read key B out of the trailer.
    pub key_b_read: KeyRequirement,
    /// Overwrite key B.
    pub key_b_write: KeyRequirement,
}

/// A sector's twelve access bits, as C1/C2/C3 per block group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessBits {
    /// `[group][0..3]` = C1, C2, C3. Groups 0..2 are data blocks, group 3 the trailer.
    pub c: [[bool; 3]; 4],
    /// The general-purpose byte, byte 9 of the trailer. Not an access bit; the card
    /// does not interpret it, which makes it a nice place to hide things.
    pub gpb: u8,
}

impl AccessBits {
    /// The transport configuration a card ships with: `FF 07 80 69`.
    pub fn transport() -> Self {
        Self::from_bytes(&TRANSPORT_ACCESS).expect("transport bytes are self-consistent")
    }

    /// Parse bytes 6..9 of a sector trailer.
    ///
    /// The straight and inverted copies must agree. They are stored as
    ///
    /// ```text
    /// byte 6 = !C2 (4 bits) | !C1 (4 bits)
    /// byte 7 =  C1 (4 bits) | !C3 (4 bits)
    /// byte 8 =  C3 (4 bits) |  C2 (4 bits)
    /// byte 9 = general-purpose byte
    /// ```
    ///
    /// with bit *n* of each nibble belonging to block group *n*.
    pub fn from_bytes(bytes: &[u8; 4]) -> Result<Self> {
        let inv_c2 = bytes[0] >> 4;
        let inv_c1 = bytes[0] & 0xF;
        let c1 = bytes[1] >> 4;
        let inv_c3 = bytes[1] & 0xF;
        let c3 = bytes[2] >> 4;
        let c2 = bytes[2] & 0xF;

        if c1 != (!inv_c1 & 0xF) || c2 != (!inv_c2 & 0xF) || c3 != (!inv_c3 & 0xF) {
            return Err(CredentialError::ParityFailed {
                decoder: "mifare access bits",
            });
        }

        let mut c = [[false; 3]; 4];
        for (group, slot) in c.iter_mut().enumerate() {
            slot[0] = (c1 >> group) & 1 == 1;
            slot[1] = (c2 >> group) & 1 == 1;
            slot[2] = (c3 >> group) & 1 == 1;
        }
        Ok(Self { c, gpb: bytes[3] })
    }

    /// Render back to bytes 6..9 of a trailer.
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut c1 = 0u8;
        let mut c2 = 0u8;
        let mut c3 = 0u8;
        for (group, slot) in self.c.iter().enumerate() {
            c1 |= u8::from(slot[0]) << group;
            c2 |= u8::from(slot[1]) << group;
            c3 |= u8::from(slot[2]) << group;
        }
        [
            ((!c2 & 0xF) << 4) | (!c1 & 0xF),
            (c1 << 4) | (!c3 & 0xF),
            (c3 << 4) | c2,
            self.gpb,
        ]
    }

    /// The three-bit condition code for a block group, as `C1 C2 C3`.
    pub fn code(&self, group: usize) -> u8 {
        let g = self.c.get(group).copied().unwrap_or([false; 3]);
        (u8::from(g[0]) << 2) | (u8::from(g[1]) << 1) | u8::from(g[2])
    }

    /// What a data block group permits.
    pub fn data_access(&self, group: usize) -> DataBlockAccess {
        use KeyRequirement::*;
        let (read, write, increment, decrement) = match self.code(group) {
            0b000 => (Either, Either, Either, Either),
            0b001 => (Either, Never, Never, Either),
            0b010 => (Either, Never, Never, Never),
            0b011 => (KeyB, KeyB, Never, Never),
            0b100 => (Either, KeyB, Never, Never),
            0b101 => (KeyB, Never, Never, Never),
            0b110 => (Either, KeyB, KeyB, Either),
            _ => (Never, Never, Never, Never),
        };
        DataBlockAccess {
            read,
            write,
            increment,
            decrement,
        }
    }

    /// What the sector trailer permits.
    pub fn trailer_access(&self) -> TrailerAccess {
        use KeyRequirement::*;
        let (key_a_write, access_read, access_write, key_b_read, key_b_write) = match self.code(3) {
            0b000 => (KeyA, KeyA, Never, KeyA, KeyA),
            0b001 => (KeyA, KeyA, KeyA, KeyA, KeyA),
            0b010 => (Never, KeyA, Never, KeyA, Never),
            0b011 => (KeyB, Either, KeyB, Never, KeyB),
            0b100 => (KeyB, Either, Never, Never, KeyB),
            0b101 => (Never, Either, KeyB, Never, Never),
            _ => (Never, Either, Never, Never, Never),
        };
        TrailerAccess {
            key_a_write,
            access_read,
            access_write,
            key_b_read,
            key_b_write,
        }
    }
}

/// A block in MIFARE value format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueBlock {
    /// The signed value, stored little-endian.
    pub value: i32,
    /// The one-byte address, stored four times. Conventionally the block's own number,
    /// used by `restore`/`transfer` to check the value came from where it claims.
    pub address: u8,
}

impl ValueBlock {
    /// Render to the 16-byte on-card layout.
    ///
    /// `value | !value | value | addr | !addr | addr | !addr`
    pub fn encode(&self) -> [u8; BLOCK_SIZE] {
        let v = self.value.to_le_bytes();
        let n = (!self.value).to_le_bytes();
        let a = self.address;
        [
            v[0], v[1], v[2], v[3], n[0], n[1], n[2], n[3], v[0], v[1], v[2], v[3], a, !a, a, !a,
        ]
    }

    /// Parse, checking every redundant copy.
    pub fn decode(block: &[u8; BLOCK_SIZE], number: u8) -> Result<Self> {
        let value = i32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let inverted = i32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let repeat = i32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let a = block[12];
        if value != !inverted
            || value != repeat
            || block[13] != !a
            || block[14] != a
            || block[15] != !a
        {
            return Err(CredentialError::NotAValueBlock { block: number });
        }
        Ok(Self { value, address: a })
    }
}

/// ISO 14443-A CRC_A over a byte string.
///
/// Polynomial `x^16 + x^12 + x^5 + 1` reflected to `0x8408`, initial value `0x6363`.
/// It is a transmission check and nothing more: it is unkeyed, so on an encrypted
/// link it protects against noise and on any link it protects against nothing else.
pub fn crc_a(data: &[u8]) -> u16 {
    let mut crc = 0x6363u16;
    for &byte in data {
        let mut b = byte ^ (crc as u8);
        b ^= b << 4;
        let b = u16::from(b);
        crc = (crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4);
    }
    crc
}

/// The challenge a card answers an authentication request with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthChallenge {
    /// The nonce as it appears on the air. Equal to the plaintext nonce on a first
    /// authentication, and `nT xor ks1` on a nested one.
    pub nt_enc: u32,
    /// The four parity bits as they appear on the air, one per byte of the nonce.
    ///
    /// On a nested authentication each is the plaintext byte's odd parity XORed with
    /// a keystream bit — and the *same* keystream bit encrypts the first bit of the
    /// following byte. Three bits of free verification for anyone guessing the nonce.
    pub nt_parity: [bool; 4],
    /// Whether this challenge went out encrypted.
    pub encrypted: bool,
}

/// Everything an eavesdropper sees of one authentication.
///
/// This is the attacker's *entire* input in drill 0.4. Note what is not in it: the
/// plaintext nonce of a nested authentication, the session key, and the sector key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthTrace {
    /// Card UID, sent in the clear during anticollision before any of this.
    pub uid: u32,
    /// Block the authentication named.
    pub block: u8,
    /// Which key was requested.
    pub key_type: KeyType,
    /// Whether the exchange happened inside an existing session.
    pub nested: bool,
    /// The nonce as observed. Plaintext when `!nested`.
    pub nt_enc: u32,
    /// Parity bits of the nonce as observed.
    pub nt_parity: [bool; 4],
    /// `{nR}` as observed.
    pub nr_enc: u32,
    /// `{aR}` as observed.
    pub ar_enc: u32,
    /// `{aT}` as observed.
    pub at_enc: u32,
    /// Virtual time at which the card generated its nonce.
    ///
    /// An attacker with a logic analyser has this; it is what makes the tag nonce
    /// predictable.
    pub t_us: u64,
}

/// The first two passes of a nested authentication, observed and then abandoned.
///
/// Everything here is visible on the air. Nothing here required knowing the key of
/// the sector being probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceProbe {
    /// Card UID, from anticollision.
    pub uid: u32,
    /// Block the probe named.
    pub block: u8,
    /// Key type the probe asked for.
    pub key_type: KeyType,
    /// The encrypted nonce, `nT xor ks1`.
    pub nt_enc: u32,
    /// The four encrypted parity bits.
    pub nt_parity: [bool; 4],
    /// Virtual time at which the card generated the nonce.
    pub t_us: u64,
}

/// An authenticated session: the shared cipher state, plus what it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The reader's copy of the cipher. The card holds an identical one.
    pub cipher: Crypto1,
    /// Sector the session authenticated to.
    pub sector: u8,
    /// Key type the session authenticated with.
    pub key_type: KeyType,
}

/// Work in progress on the card between the challenge and the response.
#[derive(Debug, Clone, Copy)]
struct PendingAuth {
    cipher: Crypto1,
    nt: u32,
    sector: u8,
    key_type: KeyType,
}

/// A MIFARE Classic 1K card.
#[derive(Debug, Clone)]
pub struct MifareClassic1k {
    blocks: [[u8; BLOCK_SIZE]; BLOCK_COUNT],
    uid: u32,
    nonces: NonceLfsr,
    clock_us: u64,
    session: Option<(Crypto1, u8, KeyType)>,
    pending: Option<PendingAuth>,
}

impl MifareClassic1k {
    /// A blank card: every sector at the default key and transport access bits.
    ///
    /// `seed` initialises the tag's nonce generator. Two cards with the same seed
    /// answer identically, which is what makes a drill reproducible.
    pub fn new(uid: u32, seed: u64) -> Self {
        let mut card = Self {
            blocks: [[0u8; BLOCK_SIZE]; BLOCK_COUNT],
            uid,
            nonces: NonceLfsr::seeded((seed ^ (seed >> 32)) as u32),
            clock_us: 0,
            session: None,
            pending: None,
        };
        card.write_manufacturer_block();
        for sector in 0..SECTOR_COUNT as u8 {
            card.force_sector_keys(sector, DEFAULT_KEY, DEFAULT_KEY, AccessBits::transport());
        }
        card
    }

    /// A card with per-sector random keys drawn from `rng`, and a credential in
    /// block 4 — the shape drill 0.4 runs against.
    pub fn provisioned(uid: u32, rng: &mut Rng, credential: &[u8; BLOCK_SIZE]) -> Self {
        let seed = rng.next_u64();
        let mut card = Self::new(uid, seed);
        for sector in 0..SECTOR_COUNT as u8 {
            let key_a = rng.next_crypto1_key();
            let key_b = rng.next_crypto1_key();
            card.force_sector_keys(sector, key_a, key_b, AccessBits::transport());
        }
        card.force_block(4, *credential);
        card
    }

    /// The UID, which is broadcast in the clear before any authentication.
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Virtual time on the card's clock.
    pub const fn clock_us(&self) -> u64 {
        self.clock_us
    }

    /// The sector a block belongs to.
    pub const fn sector_of(block: u8) -> u8 {
        block / BLOCKS_PER_SECTOR as u8
    }

    /// Whether a block is its sector's trailer.
    pub const fn is_trailer(block: u8) -> bool {
        block % BLOCKS_PER_SECTOR as u8 == BLOCKS_PER_SECTOR as u8 - 1
    }

    /// The trailer block number for a sector.
    pub const fn trailer_of(sector: u8) -> u8 {
        sector * BLOCKS_PER_SECTOR as u8 + BLOCKS_PER_SECTOR as u8 - 1
    }

    fn check_block(block: u8) -> Result<usize> {
        if usize::from(block) >= BLOCK_COUNT {
            return Err(CredentialError::OutOfRange {
                what: "block",
                index: u32::from(block),
                limit: BLOCK_COUNT as u32,
            });
        }
        Ok(usize::from(block))
    }

    fn write_manufacturer_block(&mut self) {
        let uid = self.uid.to_be_bytes();
        let bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
        // UID | BCC | SAK (0x08 = MIFARE Classic 1K) | ATQA (0x04 0x00) | vendor bytes
        self.blocks[0] = [
            uid[0], uid[1], uid[2], uid[3], bcc, 0x08, 0x04, 0x00, 0x62, 0x63, 0x64, 0x65, 0x66,
            0x67, 0x68, 0x69,
        ];
    }

    /// Set a sector's keys and access bits directly, bypassing the card's own access
    /// control.
    ///
    /// This is personalisation, not an attack surface: it is what the issuer's
    /// encoder does before the card ever reaches a door. Nothing reachable over the
    /// air can do it.
    pub fn force_sector_keys(&mut self, sector: u8, key_a: u64, key_b: u64, access: AccessBits) {
        let trailer = usize::from(Self::trailer_of(sector));
        if trailer >= BLOCK_COUNT {
            return;
        }
        let a = key_a.to_be_bytes();
        let b = key_b.to_be_bytes();
        let access_bytes = access.to_bytes();
        let mut block = [0u8; BLOCK_SIZE];
        block[0..6].copy_from_slice(&a[2..8]);
        block[6..10].copy_from_slice(&access_bytes);
        block[10..16].copy_from_slice(&b[2..8]);
        self.blocks[trailer] = block;
    }

    /// Write a block directly, bypassing access control. Personalisation only.
    pub fn force_block(&mut self, block: u8, data: [u8; BLOCK_SIZE]) {
        if let Ok(index) = Self::check_block(block) {
            self.blocks[index] = data;
        }
    }

    /// Read a block directly, bypassing access control.
    ///
    /// For scenario setup and for checking a drill's outcome — never reachable from
    /// the attacker side, which must go through [`Session::read_block`].
    pub fn peek_block(&self, block: u8) -> Result<[u8; BLOCK_SIZE]> {
        Self::check_block(block).map(|i| self.blocks[i])
    }

    /// The configured key for a sector.
    ///
    /// Scenario and flag-predicate use: drill 0.4's flag is "the attacker's recovered
    /// key equals this", which the engine can only check if it can ask.
    pub fn sector_key(&self, sector: u8, key_type: KeyType) -> Result<u64> {
        let trailer = Self::check_block(Self::trailer_of(sector))?;
        let block = &self.blocks[trailer];
        let range = match key_type {
            KeyType::A => 0..6,
            KeyType::B => 10..16,
        };
        let mut key = 0u64;
        for &byte in &block[range] {
            key = (key << 8) | u64::from(byte);
        }
        Ok(key)
    }

    /// A sector's access bits.
    pub fn access_bits(&self, sector: u8) -> Result<AccessBits> {
        let trailer = Self::check_block(Self::trailer_of(sector))?;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.blocks[trailer][6..10]);
        AccessBits::from_bytes(&bytes)
    }

    /// Take the card out of the field.
    ///
    /// Everything volatile goes: the session cipher and any half-finished
    /// authentication. There is no persistent state to attack, which is the one thing
    /// MIFARE Classic gets structurally right — and it is why an attacker must work
    /// from observation rather than from anything left behind.
    pub fn reset_field(&mut self) {
        self.session = None;
        self.pending = None;
    }

    /// Whether a session is currently open.
    pub const fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Step the card's clock forward, advancing the tag nonce generator with it.
    pub fn advance_to(&mut self, now_us: u64) {
        let elapsed = now_us.saturating_sub(self.clock_us);
        self.clock_us = self.clock_us.max(now_us);
        let steps = elapsed / NONCE_TICK_US;
        self.nonces.advance((steps % 65_535) as u32);
    }

    /// Pass one: the card answers an authentication request with a nonce.
    ///
    /// If a session is already open this is a *nested* authentication: four bytes of
    /// the old session's keystream are consumed by the encrypted command, the old
    /// session is dropped, and the nonce goes out encrypted under the **new** key.
    /// That last detail is the whole of drill 0.4: the card hands an attacker 32 bits
    /// of keystream from a key nobody has, masked only by a nonce the attacker can
    /// predict.
    pub fn auth_request(
        &mut self,
        block: u8,
        key_type: KeyType,
        now_us: u64,
    ) -> Result<AuthChallenge> {
        Self::check_block(block)?;
        self.advance_to(now_us);

        let sector = Self::sector_of(block);
        let key = self.sector_key(sector, key_type)?;
        let nt = self.nonces.take(1);

        let encrypted = self.session.is_some();
        if let Some((old, _, _)) = self.session.as_mut() {
            // The AUTH command itself went out encrypted: four bytes of keystream.
            old.word(0, false);
        }
        self.session = None;

        let mut cipher = Crypto1::from_key(key);
        let (ks1, parity_ks) = cipher.word_with_parity(self.uid ^ nt, false);

        let (nt_enc, nt_parity) = if encrypted {
            let mut parity = [false; 4];
            for (i, slot) in parity.iter_mut().enumerate() {
                let byte = (nt >> (24 - 8 * i)) as u8;
                *slot = odd_parity8(byte) ^ parity_ks[i];
            }
            (ks1 ^ nt, parity)
        } else {
            let mut parity = [false; 4];
            for (i, slot) in parity.iter_mut().enumerate() {
                *slot = odd_parity8((nt >> (24 - 8 * i)) as u8);
            }
            (nt, parity)
        };

        self.pending = Some(PendingAuth {
            cipher,
            nt,
            sector,
            key_type,
        });

        Ok(AuthChallenge {
            nt_enc,
            nt_parity,
            encrypted,
        })
    }

    /// Pass three: the card checks `{aR}` and answers with `{aT}`.
    ///
    /// Note the asymmetry. The reader proves knowledge of the key first. A card will
    /// happily run the first two passes with anyone — which is why an attacker can
    /// harvest nonces all day without ever knowing a key.
    pub fn auth_response(&mut self, nr_enc: u32, ar_enc: u32) -> Result<u32> {
        let mut pending = self
            .pending
            .take()
            .ok_or(CredentialError::ProtocolViolation {
                expected: "an authentication request",
            })?;

        pending.cipher.word(nr_enc, true);
        let ks3 = pending.cipher.word(0, false);
        if ks3 ^ ar_enc != prng_successor(pending.nt, 64) {
            return Err(CredentialError::AuthenticationFailed {
                rejected_by: "card",
            });
        }

        let ks4 = pending.cipher.word(0, false);
        let at_enc = ks4 ^ prng_successor(pending.nt, 96);
        self.session = Some((pending.cipher, pending.sector, pending.key_type));
        Ok(at_enc)
    }

    /// Card side of an encrypted read.
    fn handle_read(&mut self, block: u8) -> Result<[u8; BLOCK_SIZE]> {
        let index = Self::check_block(block)?;
        let (_, sector, key_type) = self.session.ok_or(CredentialError::NotAuthenticated)?;
        if Self::sector_of(block) != sector {
            return Err(CredentialError::AccessDenied {
                operation: "read outside the authenticated sector",
            });
        }
        let access = self.access_bits(sector)?;
        let mut data = self.blocks[index];

        if Self::is_trailer(block) {
            let t = access.trailer_access();
            if !t.access_read.permits(key_type) {
                return Err(CredentialError::AccessDenied {
                    operation: "read sector trailer",
                });
            }
            // Key A is never readable. Key B only when the access bits say so.
            data[0..6].fill(0);
            if !t.key_b_read.permits(key_type) {
                data[10..16].fill(0);
            }
        } else {
            let group = usize::from(block % BLOCKS_PER_SECTOR as u8);
            if !access.data_access(group).read.permits(key_type) {
                return Err(CredentialError::AccessDenied {
                    operation: "read data block",
                });
            }
        }
        Ok(data)
    }

    /// Card side of an encrypted write.
    fn handle_write(&mut self, block: u8, data: [u8; BLOCK_SIZE]) -> Result<()> {
        let index = Self::check_block(block)?;
        let (_, sector, key_type) = self.session.ok_or(CredentialError::NotAuthenticated)?;
        if Self::sector_of(block) != sector || block == 0 {
            return Err(CredentialError::AccessDenied {
                operation: "write outside the authenticated sector",
            });
        }
        let access = self.access_bits(sector)?;
        if Self::is_trailer(block) {
            let t = access.trailer_access();
            if !t.access_write.permits(key_type) {
                return Err(CredentialError::AccessDenied {
                    operation: "write sector trailer",
                });
            }
        } else {
            let group = usize::from(block % BLOCKS_PER_SECTOR as u8);
            if !access.data_access(group).write.permits(key_type) {
                return Err(CredentialError::AccessDenied {
                    operation: "write data block",
                });
            }
        }
        self.blocks[index] = data;
        Ok(())
    }
}

/// XOR a byte string with keystream, advancing the cipher.
///
/// Encryption and decryption are the same operation, which is what makes a stream
/// cipher convenient and what makes keystream reuse fatal.
pub fn crypt_bytes(cipher: &mut Crypto1, data: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| cipher.byte(0, false) ^ b).collect()
}

impl Session {
    /// Read a block through the session.
    ///
    /// Command and response are both enciphered with the shared keystream. The CRC is
    /// checked after decryption — it is unkeyed and detects noise, not tampering.
    pub fn read_block(
        &mut self,
        card: &mut MifareClassic1k,
        block: u8,
    ) -> Result<[u8; BLOCK_SIZE]> {
        let mut command = [0x30u8, block, 0, 0];
        let crc = crc_a(&command[..2]).to_le_bytes();
        command[2] = crc[0];
        command[3] = crc[1];
        // Both sides consume the same keystream for the command.
        let _ = crypt_bytes(&mut self.cipher, &command);
        let mut card_cipher = card.session.ok_or(CredentialError::NotAuthenticated)?.0;
        let _ = crypt_bytes(&mut card_cipher, &command);

        let data = card.handle_read(block)?;
        let mut response = Vec::with_capacity(BLOCK_SIZE + 2);
        response.extend_from_slice(&data);
        response.extend_from_slice(&crc_a(&data).to_le_bytes());

        let on_air = crypt_bytes(&mut card_cipher, &response);
        if let Some(entry) = card.session.as_mut() {
            entry.0 = card_cipher;
        }
        let plain = crypt_bytes(&mut self.cipher, &on_air);

        if plain.len() != BLOCK_SIZE + 2 {
            return Err(CredentialError::StreamTooShort {
                needed: BLOCK_SIZE + 2,
                got: plain.len(),
            });
        }
        let mut out = [0u8; BLOCK_SIZE];
        out.copy_from_slice(&plain[..BLOCK_SIZE]);
        if crc_a(&out).to_le_bytes() != plain[BLOCK_SIZE..] {
            return Err(CredentialError::ParityFailed { decoder: "crc_a" });
        }
        Ok(out)
    }

    /// Write a block through the session.
    pub fn write_block(
        &mut self,
        card: &mut MifareClassic1k,
        block: u8,
        data: [u8; BLOCK_SIZE],
    ) -> Result<()> {
        let mut command = [0xA0u8, block, 0, 0];
        let crc = crc_a(&command[..2]).to_le_bytes();
        command[2] = crc[0];
        command[3] = crc[1];
        let _ = crypt_bytes(&mut self.cipher, &command);
        let mut card_cipher = card.session.ok_or(CredentialError::NotAuthenticated)?.0;
        let _ = crypt_bytes(&mut card_cipher, &command);
        let _ = crypt_bytes(&mut self.cipher, &data);
        let _ = crypt_bytes(&mut card_cipher, &data);
        if let Some(entry) = card.session.as_mut() {
            entry.0 = card_cipher;
        }
        card.handle_write(block, data)
    }

    /// Read a block and hand it on as a [`Credential`].
    pub fn read_credential(&mut self, card: &mut MifareClassic1k, block: u8) -> Result<Credential> {
        let data = self.read_block(card, block)?;
        Credential::from_bytes(CredentialFormat::MifareClassicBlock, &data)
    }
}

/// A reader that knows some keys and holds a virtual clock.
///
/// The clock matters. Everything in [`crate::nested`] turns on the fact that the
/// reader's protocol timing is repeatable, so the tag's free-running nonce generator
/// lands in a predictable place.
#[derive(Debug, Clone)]
pub struct MifareReader {
    /// Virtual time, in microseconds.
    pub now_us: u64,
    /// Time one authentication exchange occupies.
    pub auth_duration_us: u64,
    /// Time one read or write occupies.
    pub command_duration_us: u64,
    rng: Rng,
}

impl MifareReader {
    /// A reader with a seeded nonce source.
    pub fn new(seed: u64) -> Self {
        Self {
            now_us: 0,
            auth_duration_us: 2_600,
            command_duration_us: 1_400,
            rng: Rng::new(seed),
        }
    }

    /// Run a full three-pass authentication and return the session and the trace an
    /// eavesdropper would have captured.
    ///
    /// `nested` uses the reader's existing session to carry the encrypted AUTH
    /// command; pass the previous [`Session`] in.
    pub fn authenticate(
        &mut self,
        card: &mut MifareClassic1k,
        block: u8,
        key_type: KeyType,
        key: u64,
        previous: Option<&mut Session>,
    ) -> Result<(Session, AuthTrace)> {
        let t_us = self.now_us;
        let nested = previous.is_some();
        match previous {
            // The encrypted AUTH command: four bytes of the old keystream.
            Some(session) => {
                session.cipher.word(0, false);
            }
            // No session to nest inside, so the reader drops the field first. Both
            // ends start clean and the nonce goes out in the open.
            None => card.reset_field(),
        }

        let challenge = card.auth_request(block, key_type, t_us)?;

        let mut cipher = Crypto1::from_key(key);
        let nt = if challenge.encrypted {
            feed_nonce_encrypted(&mut cipher, card.uid, challenge.nt_enc)
        } else {
            cipher.word(card.uid ^ challenge.nt_enc, false);
            challenge.nt_enc
        };

        let nr = self.rng.next_u32();
        let ks2 = cipher.word(nr, false);
        let nr_enc = ks2 ^ nr;
        let ks3 = cipher.word(0, false);
        let ar_enc = ks3 ^ prng_successor(nt, 64);

        let at_enc = card.auth_response(nr_enc, ar_enc)?;

        let ks4 = cipher.word(0, false);
        if ks4 ^ at_enc != prng_successor(nt, 96) {
            return Err(CredentialError::AuthenticationFailed {
                rejected_by: "reader",
            });
        }

        self.now_us += self.auth_duration_us;

        let trace = AuthTrace {
            uid: card.uid,
            block,
            key_type,
            nested,
            nt_enc: challenge.nt_enc,
            nt_parity: challenge.nt_parity,
            nr_enc,
            ar_enc,
            at_enc,
            t_us,
        };
        Ok((
            Session {
                cipher,
                sector: MifareClassic1k::sector_of(block),
                key_type,
            },
            trace,
        ))
    }

    /// Run only the first two passes of a nested authentication and walk away.
    ///
    /// This is what an attacker who does **not** hold the target key can do, and it
    /// is the asymmetry at the heart of drill 0.4: the card offers its nonce before
    /// anybody has proved anything. The exchange is abandoned at pass three — the
    /// card never grants anything — but the encrypted nonce and its parity bits have
    /// already gone out.
    ///
    /// Timing matches [`MifareReader::authenticate`] exactly, so a distance measured
    /// with full authentications applies to probes.
    pub fn probe_nested_nonce(
        &mut self,
        card: &mut MifareClassic1k,
        block: u8,
        key_type: KeyType,
        session: &mut Session,
    ) -> Result<NonceProbe> {
        let t_us = self.now_us;
        // The encrypted AUTH command: four bytes of the old session's keystream.
        session.cipher.word(0, false);
        let challenge = card.auth_request(block, key_type, t_us)?;
        self.now_us += self.auth_duration_us;
        if !challenge.encrypted {
            return Err(CredentialError::ProtocolViolation {
                expected: "an encrypted nonce from a nested authentication",
            });
        }
        Ok(NonceProbe {
            uid: card.uid,
            block,
            key_type,
            nt_enc: challenge.nt_enc,
            nt_parity: challenge.nt_parity,
            t_us,
        })
    }

    /// Read a block through a session, charging the clock for it.
    pub fn read_block(
        &mut self,
        card: &mut MifareClassic1k,
        session: &mut Session,
        block: u8,
    ) -> Result<[u8; BLOCK_SIZE]> {
        let out = session.read_block(card, block)?;
        self.now_us += self.command_duration_us;
        Ok(out)
    }
}

/// Shift `uid xor nT` into a cipher when `nT` arrived encrypted.
///
/// The keystream bit that decrypts nonce bit *i* is produced from a state that has
/// only absorbed bits 0..i-1, so the operation is causal even though the keystream
/// depends on the very value it is decrypting. Returns the recovered plaintext nonce.
pub fn feed_nonce_encrypted(cipher: &mut Crypto1, uid: u32, nt_enc: u32) -> u32 {
    let mut nt = 0u32;
    for i in 0..32 {
        let ks = cipher.peek();
        let bit = crate::crypto1::bebit(nt_enc, i) ^ ks;
        if bit {
            nt |= 1 << (i ^ 24);
        }
        cipher.bit(bit ^ crate::crypto1::bebit(uid, i), false);
    }
    nt
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: u32 = 0xDEAD_BEEF;

    #[test]
    fn transport_access_bytes_round_trip() {
        let access = AccessBits::from_bytes(&TRANSPORT_ACCESS).unwrap();
        assert_eq!(access.to_bytes(), TRANSPORT_ACCESS);
        assert_eq!(access.gpb, 0x69);
        // data groups are 000, the trailer group is 001
        assert_eq!(access.code(0), 0b000);
        assert_eq!(access.code(1), 0b000);
        assert_eq!(access.code(2), 0b000);
        assert_eq!(access.code(3), 0b001);
    }

    #[test]
    fn corrupted_access_bits_are_rejected() {
        let mut bytes = TRANSPORT_ACCESS;
        bytes[1] ^= 0x10;
        assert!(AccessBits::from_bytes(&bytes).is_err());
    }

    #[test]
    fn transport_permissions_are_wide_open() {
        let access = AccessBits::transport();
        let data = access.data_access(0);
        assert_eq!(data.read, KeyRequirement::Either);
        assert_eq!(data.write, KeyRequirement::Either);
        let trailer = access.trailer_access();
        assert_eq!(trailer.key_b_read, KeyRequirement::KeyA);
        assert_eq!(trailer.key_a_write, KeyRequirement::KeyA);
    }

    #[test]
    fn every_access_code_round_trips_through_bytes() {
        for code in 0..8u8 {
            let mut bits = AccessBits::transport();
            for group in 0..4 {
                bits.c[group] = [(code >> 2) & 1 == 1, (code >> 1) & 1 == 1, code & 1 == 1];
            }
            let bytes = bits.to_bytes();
            assert_eq!(AccessBits::from_bytes(&bytes).unwrap(), bits);
        }
    }

    #[test]
    fn key_a_is_never_readable_in_any_configuration() {
        for code in 0..8u8 {
            let mut bits = AccessBits::transport();
            bits.c[3] = [(code >> 2) & 1 == 1, (code >> 1) & 1 == 1, code & 1 == 1];
            let mut card = MifareClassic1k::new(UID, 1);
            card.force_sector_keys(1, 0xA0A1_A2A3_A4A5, 0xB0B1_B2B3_B4B5, bits);

            let mut reader = MifareReader::new(9);
            let auth = reader.authenticate(&mut card, 7, KeyType::A, 0xA0A1_A2A3_A4A5, None);
            let Ok((mut session, _)) = auth else { continue };
            if let Ok(trailer) = session.read_block(&mut card, 7) {
                assert_eq!(&trailer[0..6], &[0u8; 6], "key A leaked with code {code:b}");
            }
        }
    }

    #[test]
    fn manufacturer_block_has_a_valid_bcc() {
        let card = MifareClassic1k::new(UID, 0);
        let block = card.peek_block(0).unwrap();
        assert_eq!(block[0..4], UID.to_be_bytes());
        assert_eq!(block[4], block[0] ^ block[1] ^ block[2] ^ block[3]);
        assert_eq!(block[5], 0x08, "SAK for a 1K card");
        assert_eq!(&block[6..8], &[0x04, 0x00], "ATQA");
    }

    #[test]
    fn sector_and_trailer_arithmetic() {
        assert_eq!(MifareClassic1k::sector_of(0), 0);
        assert_eq!(MifareClassic1k::sector_of(7), 1);
        assert_eq!(MifareClassic1k::trailer_of(0), 3);
        assert_eq!(MifareClassic1k::trailer_of(15), 63);
        assert!(MifareClassic1k::is_trailer(3));
        assert!(!MifareClassic1k::is_trailer(4));
    }

    #[test]
    fn value_block_round_trips() {
        let v = ValueBlock {
            value: -1_234_567,
            address: 5,
        };
        let encoded = v.encode();
        assert_eq!(ValueBlock::decode(&encoded, 5).unwrap(), v);
    }

    #[test]
    fn a_corrupted_value_block_is_rejected() {
        let v = ValueBlock {
            value: 42,
            address: 5,
        };
        let mut encoded = v.encode();
        encoded[4] ^= 0xFF;
        assert!(matches!(
            ValueBlock::decode(&encoded, 5),
            Err(CredentialError::NotAValueBlock { .. })
        ));
    }

    #[test]
    fn crc_a_of_a_known_string() {
        // ISO 14443-A worked example: CRC_A over 00 00 is 0x1EA0.
        assert_eq!(crc_a(&[0x00, 0x00]), 0x1EA0);
    }

    #[test]
    fn full_authentication_succeeds_and_reads_a_block() {
        let mut card = MifareClassic1k::new(UID, 0x1234);
        card.force_sector_keys(1, 0xA0A1_A2A3_A4A5, DEFAULT_KEY, AccessBits::transport());
        card.force_block(4, [0xAA; BLOCK_SIZE]);

        let mut reader = MifareReader::new(77);
        let (mut session, trace) = reader
            .authenticate(&mut card, 4, KeyType::A, 0xA0A1_A2A3_A4A5, None)
            .unwrap();
        assert!(!trace.nested);
        assert_eq!(trace.uid, UID);

        let data = reader.read_block(&mut card, &mut session, 4).unwrap();
        assert_eq!(data, [0xAA; BLOCK_SIZE]);
    }

    #[test]
    fn a_wrong_key_is_rejected_by_the_card() {
        let mut card = MifareClassic1k::new(UID, 0x1234);
        card.force_sector_keys(1, 0xA0A1_A2A3_A4A5, DEFAULT_KEY, AccessBits::transport());
        let mut reader = MifareReader::new(5);
        let err = reader
            .authenticate(&mut card, 4, KeyType::A, 0x0000_0000_0001, None)
            .unwrap_err();
        assert_eq!(
            err,
            CredentialError::AuthenticationFailed {
                rejected_by: "card"
            }
        );
    }

    #[test]
    fn a_nested_authentication_hides_its_nonce() {
        let mut card = MifareClassic1k::new(UID, 0x99);
        card.force_sector_keys(0, DEFAULT_KEY, DEFAULT_KEY, AccessBits::transport());
        card.force_sector_keys(1, 0xA0A1_A2A3_A4A5, DEFAULT_KEY, AccessBits::transport());

        let mut reader = MifareReader::new(3);
        let (mut first, t1) = reader
            .authenticate(&mut card, 0, KeyType::A, DEFAULT_KEY, None)
            .unwrap();
        assert!(!t1.nested);

        let (_, t2) = reader
            .authenticate(&mut card, 4, KeyType::A, 0xA0A1_A2A3_A4A5, Some(&mut first))
            .unwrap();
        assert!(t2.nested);
        // The observed value is not a valid nonce of the tag's generator, because it
        // has been masked with keystream.
        assert_ne!(t2.nt_enc, prng_successor(t1.nt_enc, 0));
    }

    #[test]
    fn reading_outside_the_authenticated_sector_is_refused() {
        let mut card = MifareClassic1k::new(UID, 1);
        let mut reader = MifareReader::new(1);
        let (mut session, _) = reader
            .authenticate(&mut card, 4, KeyType::A, DEFAULT_KEY, None)
            .unwrap();
        assert!(matches!(
            session.read_block(&mut card, 8),
            Err(CredentialError::AccessDenied { .. })
        ));
    }

    #[test]
    fn reading_without_authenticating_is_refused() {
        let mut card = MifareClassic1k::new(UID, 1);
        let mut session = Session {
            cipher: Crypto1::from_key(DEFAULT_KEY),
            sector: 1,
            key_type: KeyType::A,
        };
        assert!(matches!(
            session.read_block(&mut card, 4),
            Err(CredentialError::NotAuthenticated)
        ));
    }

    #[test]
    fn out_of_range_blocks_are_errors_not_panics() {
        let card = MifareClassic1k::new(UID, 1);
        assert!(card.peek_block(64).is_err());
        assert!(card.sector_key(16, KeyType::A).is_err());
    }

    #[test]
    fn the_nonce_generator_advances_with_the_clock() {
        let mut card = MifareClassic1k::new(UID, 0x2468);
        let mut reader = MifareReader::new(1);
        let (_, first) = reader
            .authenticate(&mut card, 0, KeyType::A, DEFAULT_KEY, None)
            .unwrap();
        let (_, second) = reader
            .authenticate(&mut card, 0, KeyType::A, DEFAULT_KEY, None)
            .unwrap();
        assert_ne!(first.nt_enc, second.nt_enc);
        // Both are plaintext nonces from the same LFSR, so one follows the other.
        let distance = (0..65_535u32)
            .find(|&d| prng_successor(first.nt_enc, d) == second.nt_enc)
            .expect("the second nonce must be a successor of the first");
        assert!(distance > 0);
    }

    #[test]
    fn provisioned_cards_have_distinct_sector_keys() {
        let mut rng = Rng::new(0xC0FFEE);
        let card = MifareClassic1k::provisioned(UID, &mut rng, &[0x11; BLOCK_SIZE]);
        let a0 = card.sector_key(0, KeyType::A).unwrap();
        let a1 = card.sector_key(1, KeyType::A).unwrap();
        assert_ne!(a0, a1);
        assert_ne!(a0, DEFAULT_KEY);
        assert_eq!(card.peek_block(4).unwrap(), [0x11; BLOCK_SIZE]);
    }
}
