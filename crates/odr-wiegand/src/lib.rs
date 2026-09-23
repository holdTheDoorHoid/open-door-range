//! Legacy reader-to-panel wire protocols: Wiegand and clock-and-data.
//!
//! This is Track 1 of the Open Door Range (see `DESIGN.md` §2). It models the
//! protocols that OSDP was invented to replace — the ones that still run most
//! of the doors in the world — at three levels:
//!
//! 1. **Card data formats** ([`format`]) — how a facility code and a card
//!    number become a run of bits, and how parity is computed over them.
//! 2. **The physical layer** ([`wire`], [`clock_data`]) — how those bits become
//!    edges on a pair of wires, with timing, and how edges become bits again,
//!    including everything that can go wrong electrically.
//! 3. **Attack primitives** ([`attack`]) — replay, brute force, and inline
//!    substitution. They are three lines of code each, and that is the finding.
//!
//! # The shape of the problem
//!
//! A Wiegand reader is a transmitter with no identity. It pulls two wires low
//! in a pattern; the panel counts the pulses and looks up whatever number comes
//! out. Nothing authenticates the reader, nothing authenticates the panel,
//! nothing is encrypted, nothing is nonced, and the only integrity check is a
//! parity bit that an attacker recomputes for free. Every attack in
//! [`attack`] is really just "use the protocol correctly, from the wrong end of
//! the cable".
//!
//! # Determinism
//!
//! Every time in this crate is a `u64` of **virtual microseconds supplied by
//! the caller**. Nothing reads a clock, nothing spawns a thread, nothing asks
//! the OS for randomness. The crate is `no_std` (it uses `alloc`) and builds
//! for `wasm32-unknown-unknown` unchanged, so the browser range and the
//! command-line analyser run byte-for-byte identical code — which is the whole
//! reason `DESIGN.md` §3 insists on one engine.
//!
//! # A tour
//!
//! ```
//! use odr_wiegand::{
//!     decode, decode_transitions, encode, encode_transitions, infer_formats,
//!     inline_tamper, CardFormat, Capture, Credential, WiegandTiming,
//! };
//!
//! // 1. A credential becomes bits, with parity.
//! let cred = Credential::new(CardFormat::H10301, 42, 1337);
//! let bits = encode(&cred).unwrap();
//! assert_eq!(bits.len(), 26);
//!
//! // 2. Bits become edges on D0/D1, and edges become bits again.
//! let timing = WiegandTiming::default();
//! let edges = encode_transitions(&bits, &timing, 0);
//! let capture = decode_transitions(&edges, &timing);
//! assert_eq!(capture.frames[0].bits, bits);
//!
//! // 3. Nothing on the wire says which format it was, so ask for candidates.
//! let candidates = infer_formats(&capture.frames[0].bits);
//! assert_eq!(candidates[0].decoded.format, CardFormat::H10301);
//! assert_eq!(candidates[0].decoded.facility_code, Some(42));
//!
//! // 4. And a sniffed frame can simply be sent again, or replaced.
//! let sniffed = Capture::from_frame(&capture.frames[0]);
//! let _replay = sniffed.replay(5_000_000, &timing);
//! let forged = inline_tamper(&sniffed.bits, &Credential::new(CardFormat::H10301, 1, 1))
//!     .unwrap();
//! assert!(decode(CardFormat::H10301, &forged.emitted).unwrap().parity_valid());
//! ```
//!
//! # Module map
//!
//! | Module | What lives there |
//! |---|---|
//! | [`bits`] | [`BitVec`], the transmission-order bit buffer everything speaks |
//! | [`parity`] | declarative parity rules and per-rule check reports |
//! | [`format`] | H10301, H10306, Corporate 1000, H10304, H10302, raw; inference |
//! | [`wire`] | D0/D1 edges, timing, the streaming decoder, timing anomalies |
//! | [`clock_data`] | ABA track 2, LRC, and the CLOCK/DATA physical layer |
//! | [`attack`] | replay, credential sweeps and their wall-clock cost, inline tamper |
//!
//! The commonly used items are re-exported at the crate root; the rest stay in
//! their modules.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

pub mod attack;
pub mod bits;
pub mod clock_data;
pub mod format;
pub mod parity;
pub mod wire;

pub use attack::{
    inline_tamper, substitute_fields, Capture, CredentialSweep, SweepCost, TamperResult,
};
pub use bits::{BitError, BitVec};
pub use clock_data::{
    decode_aba, decode_clock_data, encode_clock_data, AbaDecoded, AbaEncoding, AbaError, AbaTrack2,
    CdLine, CdTransition, ClockDataTiming,
};
pub use format::{
    decode, decode_raw, encode, infer_formats, CardFormat, Credential, Decoded, FormatCandidate,
    FormatError, KNOWN_FORMATS,
};
pub use parity::{Coverage, Parity, ParityCheck, ParityReport, ParityRule};
pub use wire::{
    decode_transitions, encode_transitions, Level, Line, TimingAnomaly, Transition, WiegandTiming,
    WireCapture, WireDecoder, WireEvent, WireFrame,
};
