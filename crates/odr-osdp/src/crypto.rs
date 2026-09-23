//! AES-128 primitives and the OSDP key-derivation / MAC constructions.
//!
//! OSDP Secure Channel is built entirely out of AES-128. There is no hash, no
//! HMAC, no AEAD. Everything below is assembled from raw ECB and CBC block
//! operations, which is where several of the weaknesses come from.
//!
//! # What lives here
//!
//! * [`ecb_encrypt_block`] / [`ecb_decrypt_block`] — single-block AES-128
//! * [`cbc_encrypt`] / [`cbc_decrypt`] — CBC over whole blocks
//! * [`derive_session_keys`] — S-ENC, S-MAC1, S-MAC2 from the SCBK and RND.A
//! * [`client_cryptogram`] / [`server_cryptogram`] — the mutual-auth proofs
//! * [`cbc_mac`] — the two-key CBC-MAC OSDP uses, and [`truncate_mac`]
//! * [`pad_for_encryption`] / [`strip_padding`] — the `0x80 00 …` padding
//!
//! # No randomness in this module
//!
//! Nothing here generates a nonce. `RND.A` and `RND.B` are always passed in by
//! the caller, because DESIGN.md section 3 requires that the same scenario
//! produce the same bytes on every machine. If you want repeatable "random"
//! nonces, use [`crate::rng::SeededRng`].

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec::Vec;

/// AES block size, in bytes. OSDP never uses anything else.
pub const BLOCK: usize = 16;

/// Encrypt one 16-byte block in place with AES-128 in ECB mode.
///
/// ECB on a single block is just "the AES permutation", which is how OSDP uses
/// it: for key derivation and for the cryptograms, where the input is exactly
/// one block. Multi-block ECB would be a real flaw; OSDP does not do that.
pub fn ecb_encrypt_block(key: &[u8; BLOCK], block: &mut [u8; BLOCK]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut ga = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut ga);
    block.copy_from_slice(ga.as_slice());
}

/// Decrypt one 16-byte block in place with AES-128 in ECB mode.
pub fn ecb_decrypt_block(key: &[u8; BLOCK], block: &mut [u8; BLOCK]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut ga = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut ga);
    block.copy_from_slice(ga.as_slice());
}

/// Encrypt `data` in place with AES-128-CBC. `data.len()` must be a non-zero
/// multiple of 16; anything else is a no-op on the trailing bytes and is
/// reported by the return value.
///
/// Returns `false` if the length was not a whole number of blocks, in which
/// case nothing is modified.
pub fn cbc_encrypt(key: &[u8; BLOCK], iv: &[u8; BLOCK], data: &mut [u8]) -> bool {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK) {
        return false;
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut chain = *iv;
    for chunk in data.chunks_mut(BLOCK) {
        for (c, p) in chunk.iter_mut().zip(chain.iter()) {
            *c ^= *p;
        }
        let mut ga = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut ga);
        chunk.copy_from_slice(ga.as_slice());
        chain.copy_from_slice(chunk);
    }
    true
}

/// Decrypt `data` in place with AES-128-CBC. Same length rule as
/// [`cbc_encrypt`].
pub fn cbc_decrypt(key: &[u8; BLOCK], iv: &[u8; BLOCK], data: &mut [u8]) -> bool {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK) {
        return false;
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut chain = *iv;
    for chunk in data.chunks_mut(BLOCK) {
        let ciphertext: [u8; BLOCK] = {
            let mut t = [0u8; BLOCK];
            t.copy_from_slice(chunk);
            t
        };
        let mut ga = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut ga);
        chunk.copy_from_slice(ga.as_slice());
        for (p, c) in chunk.iter_mut().zip(chain.iter()) {
            *p ^= *c;
        }
        chain = ciphertext;
    }
    true
}

/// The three per-session keys derived from the SCBK at the start of a secure
/// channel handshake.
///
/// All three are AES keys in their own right; none of them is ever transmitted.
/// An eavesdropper who learns the SCBK can recompute all three from RND.A,
/// which is sent in the clear in `CMD_CHLNG` — that is the whole of the
/// weak-key attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    /// Encrypts and decrypts frame payloads (SCS_17 / SCS_18).
    pub s_enc: [u8; BLOCK],
    /// Keys every CBC-MAC block *except* the last one.
    pub s_mac1: [u8; BLOCK],
    /// Keys the final CBC-MAC block.
    pub s_mac2: [u8; BLOCK],
}

/// Derivation constants, documented here because they are the single most
/// error-prone part of an OSDP implementation.
///
/// Each session key is one AES-ECB encryption under the SCBK of a 16-byte
/// block laid out as:
///
/// ```text
/// byte  0: 0x01                 (fixed)
/// byte  1: purpose constant     (0x82 S-ENC, 0x01 S-MAC1, 0x02 S-MAC2)
/// bytes 2..8: RND.A[0..6]       (the first SIX bytes of the ACU nonce)
/// bytes 8..16: 0x00             (zero padding)
/// ```
///
/// **Two things worth staring at.** First, only six of RND.A's eight bytes
/// reach the derivation, so the session keys carry at most 48 bits of ACU
/// entropy no matter how good the ACU's random number generator is — one of
/// the medium-severity Mellon findings. Second, RND.B never appears in key
/// derivation at all; it only proves liveness in the cryptograms. The PD
/// therefore contributes nothing to the session keys.
///
/// **Confidence.** The `0x01, 0x82` pair for S-ENC is stated directly in the
/// task spec and matches every implementation I cross-checked. The `0x01,0x01`
/// and `0x01,0x02` pairs for S-MAC1 and S-MAC2 follow the same pattern and
/// match `libosdp`'s `osdp_sc.c`. See the README's "uncertain" section.
pub mod derivation {
    /// First byte of every derivation block.
    pub const PREFIX: u8 = 0x01;
    /// Purpose byte for S-ENC.
    pub const S_ENC: u8 = 0x82;
    /// Purpose byte for S-MAC1.
    pub const S_MAC1: u8 = 0x01;
    /// Purpose byte for S-MAC2.
    pub const S_MAC2: u8 = 0x02;
    /// How many bytes of RND.A take part. Yes, six, not eight.
    pub const RND_A_BYTES: usize = 6;
}

/// Build one derivation block: `01 <purpose> RND.A[0..6] 00 00 00 00 00 00 00 00`.
fn derivation_block(purpose: u8, rnd_a: &[u8; 8]) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    block[0] = derivation::PREFIX;
    block[1] = purpose;
    block[2..2 + derivation::RND_A_BYTES].copy_from_slice(&rnd_a[..derivation::RND_A_BYTES]);
    block
}

/// Derive S-ENC, S-MAC1 and S-MAC2 from the base key and the ACU nonce.
///
/// `scbk` is the site key, or [`crate::weak_keys::SCBK_D`] if the PD has never
/// been commissioned. `rnd_a` is the eight-byte nonce the ACU sent in
/// `CMD_CHLNG`.
pub fn derive_session_keys(scbk: &[u8; BLOCK], rnd_a: &[u8; 8]) -> SessionKeys {
    let mut s_enc = derivation_block(derivation::S_ENC, rnd_a);
    let mut s_mac1 = derivation_block(derivation::S_MAC1, rnd_a);
    let mut s_mac2 = derivation_block(derivation::S_MAC2, rnd_a);
    ecb_encrypt_block(scbk, &mut s_enc);
    ecb_encrypt_block(scbk, &mut s_mac1);
    ecb_encrypt_block(scbk, &mut s_mac2);
    SessionKeys {
        s_enc,
        s_mac1,
        s_mac2,
    }
}

/// The PD's proof that it holds the SCBK: `AES-ECB(S-ENC, RND.A || RND.B)`.
///
/// `RND.A || RND.B` is 8 + 8 = exactly one AES block, so a single ECB
/// encryption is all this is. Sent to the ACU in `REPLY_CCRYPT`.
pub fn client_cryptogram(
    s_enc: &[u8; BLOCK],
    rnd_a: &[u8; 8],
    rnd_b: &[u8; 8],
) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    block[..8].copy_from_slice(rnd_a);
    block[8..].copy_from_slice(rnd_b);
    ecb_encrypt_block(s_enc, &mut block);
    block
}

/// The ACU's proof that it holds the SCBK: `AES-ECB(S-ENC, RND.B || RND.A)`.
///
/// Same construction as [`client_cryptogram`] with the two nonces swapped, so
/// the two sides cannot replay each other's value. Sent in `CMD_SCRYPT`.
pub fn server_cryptogram(
    s_enc: &[u8; BLOCK],
    rnd_a: &[u8; 8],
    rnd_b: &[u8; 8],
) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    block[..8].copy_from_slice(rnd_b);
    block[8..].copy_from_slice(rnd_a);
    ecb_encrypt_block(s_enc, &mut block);
    block
}

/// Pad a payload for encryption the OSDP way and return the padded copy.
///
/// The rule is ISO/IEC 9797-1 padding method 2: append a single `0x80` byte,
/// then as many `0x00` bytes as it takes to reach a block boundary. **If the
/// payload is already a whole number of blocks, no padding is added at all** —
/// which means the padding is not unambiguously removable, and
/// [`strip_padding`] has to guess. OSDP lives with that because the frame
/// length field bounds the plaintext anyway.
///
/// An empty payload returns empty; callers should send SCS_15/SCS_16 (MAC only,
/// no encryption) rather than encrypt nothing.
pub fn pad_for_encryption(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(data);
    if out.is_empty() || out.len() % BLOCK != 0 {
        out.push(0x80);
        while out.len() % BLOCK != 0 {
            out.push(0x00);
        }
    }
    out
}

/// Remove OSDP encryption padding, best-effort.
///
/// Scans back over trailing `0x00` bytes; if the first non-zero byte found is
/// `0x80`, that byte and everything after it is dropped. If it is not, the
/// buffer is returned untouched on the assumption the plaintext filled the
/// final block exactly.
///
/// This is genuinely ambiguous — a plaintext legitimately ending in
/// `80 00 00` is indistinguishable from a padded one. Real OSDP deployments
/// avoid the problem because the meaningful payload length is implied by the
/// command, not by the padding.
pub fn strip_padding(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0x00 {
        end -= 1;
    }
    if end > 0 && data[end - 1] == 0x80 {
        &data[..end - 1]
    } else {
        data
    }
}

/// Compute OSDP's two-key CBC-MAC over `data` and return the full 16-byte
/// result.
///
/// The construction, which is CBC-MAC with a different key on the final block
/// (a "two-key" or retail MAC):
///
/// 1. Pad `data` to a block boundary with `0x80 00 …`, *unless* it is already a
///    whole number of blocks, in which case it is used as-is.
/// 2. CBC-encrypt every block but the last under **S-MAC1**, starting from
///    `iv`.
/// 3. CBC-encrypt the final block under **S-MAC2**, chained from the previous
///    ciphertext block.
/// 4. The MAC is that final ciphertext block.
///
/// The IV is *not* random and *not* secret: it is the previous MAC in the
/// opposite direction (see [`crate::channel::SecureChannel`]). That reuse is
/// the "IVs derived from MACs" weakness the range teaches, and it is
/// implemented here faithfully rather than fixed.
///
/// Returns `None` only if `data` is empty, which never happens for a real frame
/// (the header alone is five bytes).
pub fn cbc_mac(keys: &SessionKeys, iv: &[u8; BLOCK], data: &[u8]) -> Option<[u8; BLOCK]> {
    if data.is_empty() {
        return None;
    }
    let mut buf = Vec::from(data);
    if buf.len() % BLOCK != 0 {
        buf.push(0x80);
        while buf.len() % BLOCK != 0 {
            buf.push(0x00);
        }
    }

    let padded_len = buf.len();
    let mut chain = *iv;
    if padded_len > BLOCK {
        let head = &mut buf[..padded_len - BLOCK];
        cbc_encrypt(&keys.s_mac1, &chain, head);
        chain.copy_from_slice(&head[head.len() - BLOCK..]);
    }
    let tail = &mut buf[padded_len - BLOCK..];
    cbc_encrypt(&keys.s_mac2, &chain, tail);

    let mut mac = [0u8; BLOCK];
    mac.copy_from_slice(tail);
    Some(mac)
}

/// Take the first four bytes of a 16-byte MAC — what actually goes on the wire.
///
/// OSDP transmits **32 bits** of a 128-bit MAC. That is twelve bytes of
/// authentication strength thrown away to save four bytes per frame on a bus
/// that is usually running at 9600 baud with nothing else to say. A forger
/// gets a 1-in-4-billion chance per attempt, and the protocol has no attempt
/// limiter, so on a bus polled 20 times a second an online forgery attack is
/// merely slow rather than impossible. This is one of the medium-severity
/// Mellon findings.
pub fn truncate_mac(mac: &[u8; BLOCK]) -> [u8; 4] {
    [mac[0], mac[1], mac[2], mac[3]]
}

/// Derive the payload-encryption IV from a MAC, by bitwise complement.
///
/// OSDP does not carry an IV in the frame. Instead, the IV for encrypting a
/// command payload is `NOT(R-MAC)` — the ones' complement of the last MAC seen
/// in the *reply* direction — and for a reply payload it is `NOT(C-MAC)`.
///
/// This means the IV is fully determined by traffic an eavesdropper has already
/// seen. CBC with a predictable IV leaks equality of plaintext prefixes, and
/// because the MAC chain only advances when a secure frame is exchanged, an
/// attacker who can stall the bus can induce outright IV reuse. Faithfully
/// implemented; deliberately not fixed.
pub fn iv_from_mac(mac: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut iv = [0u8; BLOCK];
    for (dst, src) in iv.iter_mut().zip(mac.iter()) {
        *dst = !*src;
    }
    iv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::weak_keys::SCBK_D;

    /// FIPS-197 appendix C.1 known-answer test for AES-128. If this fails the
    /// `aes` crate is not doing what we think it is.
    #[test]
    fn aes128_known_answer() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        ecb_encrypt_block(&key, &mut block);
        assert_eq!(
            block,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
        ecb_decrypt_block(&key, &mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }

    #[test]
    fn cbc_round_trips() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let plain = *b"sixteen bytes!!!thirty two byte!";
        let mut buf = plain;
        assert!(cbc_encrypt(&key, &iv, &mut buf));
        assert_ne!(buf, plain);
        assert!(cbc_decrypt(&key, &iv, &mut buf));
        assert_eq!(buf, plain);
    }

    #[test]
    fn cbc_rejects_partial_blocks() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut buf = [0u8; 17];
        assert!(!cbc_encrypt(&key, &iv, &mut buf));
        assert!(!cbc_decrypt(&key, &iv, &mut buf));
        let mut empty: [u8; 0] = [];
        assert!(!cbc_encrypt(&key, &iv, &mut empty));
    }

    #[test]
    fn derivation_block_layout() {
        let rnd_a = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
        let b = derivation_block(derivation::S_ENC, &rnd_a);
        assert_eq!(
            b,
            [0x01, 0x82, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        // The last two bytes of RND.A never make it in: 48 bits of entropy.
        let mut rnd_a2 = rnd_a;
        rnd_a2[6] = 0xFF;
        rnd_a2[7] = 0xFF;
        assert_eq!(derivation_block(derivation::S_ENC, &rnd_a2), b);
    }

    #[test]
    fn only_48_bits_of_rnd_a_reach_the_session_keys() {
        let rnd_a = [1, 2, 3, 4, 5, 6, 7, 8];
        let rnd_a_alt = [1, 2, 3, 4, 5, 6, 0xDE, 0xAD];
        assert_eq!(
            derive_session_keys(&SCBK_D, &rnd_a),
            derive_session_keys(&SCBK_D, &rnd_a_alt),
            "changing RND.A[6..8] must not change the session keys — this is the weakness"
        );
    }

    #[test]
    fn session_keys_are_three_distinct_values() {
        let k = derive_session_keys(&SCBK_D, &[9; 8]);
        assert_ne!(k.s_enc, k.s_mac1);
        assert_ne!(k.s_enc, k.s_mac2);
        assert_ne!(k.s_mac1, k.s_mac2);
    }

    #[test]
    fn cryptograms_differ_by_nonce_order() {
        let k = derive_session_keys(&SCBK_D, &[1; 8]);
        let a = [1u8; 8];
        let b = [2u8; 8];
        assert_ne!(client_cryptogram(&k.s_enc, &a, &b), server_cryptogram(&k.s_enc, &a, &b));
    }

    #[test]
    fn padding_round_trip() {
        assert_eq!(pad_for_encryption(b"abc").len(), 16);
        assert_eq!(pad_for_encryption(b"abc")[3], 0x80);
        assert_eq!(strip_padding(&pad_for_encryption(b"abc")), b"abc");

        let exact = [0x41u8; 16];
        assert_eq!(pad_for_encryption(&exact).len(), 16, "full blocks are not padded");
        assert_eq!(strip_padding(&exact), &exact);
    }

    #[test]
    fn mac_truncates_to_four_bytes() {
        let mac = [
            0xde, 0xad, 0xbe, 0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ];
        assert_eq!(truncate_mac(&mac), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn cbc_mac_is_deterministic_and_length_sensitive() {
        let keys = derive_session_keys(&SCBK_D, &[7; 8]);
        let iv = [0u8; 16];
        let m1 = cbc_mac(&keys, &iv, b"hello").unwrap();
        let m2 = cbc_mac(&keys, &iv, b"hello").unwrap();
        assert_eq!(m1, m2);
        let m3 = cbc_mac(&keys, &iv, b"hellp").unwrap();
        assert_ne!(m1, m3);
        assert!(cbc_mac(&keys, &iv, b"").is_none());
    }

    #[test]
    fn cbc_mac_spans_multiple_blocks() {
        let keys = derive_session_keys(&SCBK_D, &[7; 8]);
        let iv = [1u8; 16];
        let long = [0x5Au8; 40];
        let m = cbc_mac(&keys, &iv, &long).unwrap();
        let mut tweaked = long;
        tweaked[0] ^= 0x01; // a change in the FIRST block must reach the MAC
        assert_ne!(m, cbc_mac(&keys, &iv, &tweaked).unwrap());
    }

    #[test]
    fn cbc_mac_depends_on_the_iv() {
        let keys = derive_session_keys(&SCBK_D, &[7; 8]);
        let d = b"the quick brown fox";
        assert_ne!(
            cbc_mac(&keys, &[0u8; 16], d).unwrap(),
            cbc_mac(&keys, &[1u8; 16], d).unwrap()
        );
    }

    #[test]
    fn iv_is_the_complement_of_the_mac() {
        let mac = [0x00u8; 16];
        assert_eq!(iv_from_mac(&mac), [0xFFu8; 16]);
        let mac = [0xA5u8; 16];
        assert_eq!(iv_from_mac(&mac), [0x5Au8; 16]);
    }
}
