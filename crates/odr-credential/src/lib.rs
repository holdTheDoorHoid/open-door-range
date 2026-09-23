//! The card layer of [Open Door Range]: what happens *before* the wire.
//!
//! Everything downstream of this crate — Wiegand pulse trains, OSDP frames, the
//! controller, the door strike — is about moving a number from a reader to a panel.
//! This crate is about where that number comes from, and how little most credentials
//! do to protect it.
//!
//! # What is modelled
//!
//! | Frequency | Technology | What it defends against |
//! |---|---|---|
//! | 125 kHz | [`em4100`] | nothing at all |
//! | 125 kHz | [`hid_prox`] (H10301) | nothing at all |
//! | 125 kHz | [`writable`] (T5577-class clone) | it *is* the attack |
//! | 13.56 MHz | [`mifare`] + [`crypto1`] | a cipher broken in 2008 |
//! | 13.56 MHz | [`desfire`] | AES mutual authentication — this one holds |
//!
//! # The shape of the thing
//!
//! A [`Card`] sits in a reader's field. A [`Reader`] energises the field, runs
//! whichever protocol the card speaks, and — if the exchange succeeds — emits a
//! [`Credential`]: a format identifier, a bit count, and the bits. That output is
//! deliberately dumb, because downstream it becomes either a Wiegand pulse train or an
//! OSDP `osdp_RAW` payload, and this crate must not care which.
//!
//! For the 125 kHz cards the reader does not take a shortcut: the card produces a
//! modulation [`EventStream`](modulation::EventStream) — `(t_us, state)` pairs, the
//! same shape `odr-wiegand` uses for D0/D1 — and the reader demodulates it. That is
//! what makes cloning honest here. A cloned tag is not *declared* indistinguishable;
//! it emits the same events, so the reader has nothing to distinguish it by.
//!
//! # Determinism
//!
//! No wall clock, no OS randomness, no threads. Every random value comes from a
//! caller-supplied seed via [`Rng`]. The same seed always produces the same bytes, so
//! a drill flag is stable and a bug is reproducible. The crate compiles for
//! `wasm32-unknown-unknown` unchanged.
//!
//! # Example: the whole of Module 0.3 in eight lines
//!
//! ```
//! use odr_credential::{Card, Reader, hid_prox::H10301};
//!
//! let mut card = Card::hid_prox(H10301::new(123, 4567));
//! let mut reader = Reader::lf_125khz();
//! let credential = reader.present(&mut card).expect("a good read");
//!
//! // The exact 26 bits the reader will clock out on D0/D1, predicted before the
//! // wire has seen anything.
//! assert_eq!(credential.bit_len, 26);
//! assert_eq!(credential.as_u64(), 0x02F6_23AE);
//! ```
//!
//! [Open Door Range]: https://github.com/holdTheDoorHoid/open-door-range

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto1;
pub mod desfire;
pub mod em4100;
pub mod hid_prox;
pub mod mifare;
pub mod modulation;
pub mod nested;
pub mod rng;
pub mod writable;

mod card;
mod credential;
mod error;
mod reader;

pub use card::{Card, Technology};
pub use credential::{Credential, CredentialFormat};
pub use error::{CredentialError, Result};
pub use reader::{decode_capture, h10301_wiegand_bits, HfConfig, Reader, ReaderKind};
pub use rng::Rng;
