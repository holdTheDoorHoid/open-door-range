//! **OSDP v2.2.2 — frames, command set and secure channel.**
//!
//! This is the protocol foundation of the [Open Door Range](https://github.com/holdTheDoorHoid/open-door-range),
//! a browser-based virtual range for physical access control. It is used three
//! ways, and that shapes every decision in it:
//!
//! 1. **A simulator** builds frames and drives a secure channel from either
//!    end, so a drill can run an attack rather than describe one.
//! 2. **An attacker** rewrites frames, cracks weak keys and reads traffic it
//!    has no key for.
//! 3. **An offline analyser** parses a capture that may start mid-frame, may
//!    contain corruption, and may never reveal a key at all.
//!
//! # Rules this crate keeps
//!
//! * **No clocks, no threads, no OS randomness.** The crate is `no_std` +
//!   `alloc` and every nonce is a parameter. DESIGN.md section 3 makes
//!   determinism a requirement: the same scenario must produce the same bytes
//!   on every machine, so CTF flags are stable and bugs are reproducible from a
//!   seed. [`rng::SeededRng`] exists for callers who want repeatable
//!   pseudo-random values; it is not a key generator.
//! * **No panics on parsed data.** Every decoder is bounds-checked and returns
//!   a structured error. There is no `unwrap` on anything that came off a wire.
//! * **`forbid(unsafe_code)`.**
//! * **Builds for `wasm32-unknown-unknown`** as well as native.
//!
//! # Module map
//!
//! | Module | What it holds |
//! |--------|---------------|
//! | [`crc`] | CRC-16/AUG-CCITT and the one-byte checksum |
//! | [`codes`] | the [`Command`] and [`Reply`] code sets |
//! | [`security`] | security block types SCS_11..SCS_18 and the key-type byte |
//! | [`frame`] | [`Frame`] encode/parse, and [`Scanner`] for byte streams |
//! | [`payload`] | typed encode/decode for the payloads that carry meaning |
//! | [`crypto`] | AES-128 primitives, key derivation, CBC-MAC, padding |
//! | [`channel`] | [`SecureChannel`]: the handshake and session traffic |
//! | [`weak_keys`] | the published Mellon weak-key family, as a generator |
//! | [`rng`] | a seeded, non-cryptographic PRNG for reproducible nonces |
//!
//! # A first tour
//!
//! Build a poll, put it on the wire, read it back:
//!
//! ```
//! use odr_osdp::{Frame, Command};
//!
//! let poll = Frame::command(0x01, 0, Command::Poll, vec![]);
//! let wire = poll.encode();
//! //  SOM   addr  len_lsb len_msb ctrl  POLL  crc_lo crc_hi
//! assert_eq!(wire, [0x53, 0x01, 0x08,   0x00,   0x04, 0x60, 0xBA,  0x00]);
//!
//! let (parsed, consumed) = Frame::parse(&wire).unwrap();
//! assert_eq!(consumed, wire.len());
//! assert_eq!(parsed.command_code(), Some(Command::Poll));
//! ```
//!
//! Run a complete secure channel between two ends using the default key:
//!
//! ```
//! use odr_osdp::{SecureChannel, KeyType, Command, SCBK_D};
//!
//! let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
//! let mut pd  = SecureChannel::pd(SCBK_D, KeyType::Default, [0xAA; 8]);
//!
//! let chlng  = acu.challenge(1, 0, [0x01; 8]).unwrap();
//! let ccrypt = pd.handle_challenge(&chlng, [0x02; 8]).unwrap();
//! let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
//! let rmac   = pd.handle_scrypt(&scrypt).unwrap();
//! acu.handle_rmac_i(&rmac).unwrap();
//!
//! let cmd = acu.seal(1, 2, Command::Out.to_u8(), &[0, 1, 50, 0], true).unwrap();
//! assert_eq!(pd.open(&cmd).unwrap(), vec![0, 1, 50, 0]);
//! ```
//!
//! # What it teaches, by being accurate
//!
//! The crate implements OSDP's weaknesses rather than fixing them, because the
//! weaknesses are the curriculum. In particular:
//!
//! * The command and reply `id` byte is **plaintext even inside a secure
//!   channel**, so a listener with no key still sees when a card was read and a
//!   door opened. [`frame`] documents this; there is a test named
//!   `command_id_is_plaintext_inside_a_secure_channel`.
//! * The MAC is **truncated to 32 bits** — see [`crypto::truncate_mac`].
//! * **IVs are derived from MACs**, so they are predictable from observed
//!   traffic — see [`crypto::iv_from_mac`].
//! * Only **48 bits of the ACU nonce** reach the session keys, and the PD's
//!   nonce contributes none — see [`crypto::derivation`].
//! * **SCS_15 and SCS_16 are a supported null cipher**: authenticated,
//!   unencrypted — see [`security::ScsType`].
//! * The **capability exchange is unauthenticated**, so it can be rewritten
//!   before the handshake ever runs — see
//!   [`payload::PdCapabilities::strip_security_capability`].
//! * The **SCBK is pushed in the clear** during commissioning — see
//!   [`payload::KeysetCommand`].
//! * The published **weak-key family** is a generator, and
//!   [`channel::recover_weak_scbk`] cracks a captured handshake with it.
//!
//! # Ethics
//!
//! Everything here is simulated protocol machinery. There is no
//! vendor-specific exploit code and no real credential data. The weak-key
//! material is the already-published Mellon family (Petro & Vargas, Bishop Fox,
//! 2023). The defensive use — showing a building owner what their own bus would
//! look like under each attack — is a first-class purpose, not a fig leaf.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod channel;
pub mod codes;
pub mod crc;
pub mod crypto;
pub mod frame;
pub mod payload;
pub mod rng;
pub mod security;
pub mod weak_keys;

pub use channel::{ChannelError, ChannelState, Role, SecureChannel};
pub use codes::{Command, Reply};
pub use crc::{checksum, crc16};
pub use crypto::SessionKeys;
pub use frame::{Direction, Frame, ParseError, ScanEvent, Scanner};
pub use payload::{NakError, PayloadError, PdCapabilities, RawCardRead};
pub use rng::SeededRng;
pub use security::{KeyType, ScsType, SecurityBlock};
pub use weak_keys::SCBK_D;

#[cfg(test)]
mod integration_tests;
