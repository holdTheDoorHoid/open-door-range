//! **The world model: wires, buses, readers, controllers, doors and taps.**
//!
//! This is item 4 in the Open Door Range build order (`DESIGN.md` §6). It is
//! where a card, a reader, a wire, a controller and a door stop being separate
//! libraries and become a running system that can be watched and interfered
//! with. `odr-attack`, `odr-detect`, `odr-scenario` and the site are all built
//! on the types here.
//!
//! ```text
//!   credential ──▶ READER ──wire or bus──▶ CONTROLLER ──▶ DOOR
//!                            ▲
//!                           tap
//! ```
//!
//! # The four things that shape every decision in this crate
//!
//! **A virtual microsecond clock, driven by the caller.** [`World::step`] runs
//! one queued event; [`World::run_until`] runs to a deadline. Nothing sleeps,
//! nothing reads wall time, nothing runs on a thread. The engine is `no_std` +
//! `alloc` and builds for `wasm32-unknown-unknown`.
//!
//! **Determinism.** One seeded PRNG ([`odr_osdp::rng::SeededRng`]) supplies
//! every nonce; the event queue breaks ties by insertion order; there is no
//! map iteration anywhere. The same seed and the same inputs produce a
//! byte-identical [`EventLog`], which is what makes a CTF flag stable and a bug
//! reproducible (`DESIGN.md` §3).
//!
//! **The event log is the product, not a side effect.** Every state change
//! emits a [`LogRecord`]. The site's timeline and traffic list render straight
//! from it, `odr-detect` reasons over it, and the capture format in
//! [`capture`] is a projection of it.
//!
//! **No panics.** Everything fallible returns [`BusError`]. A panic in a
//! browser is a dead tab.
//!
//! # A tour
//!
//! A badge-in, end to end:
//!
//! ```
//! use odr_bus::{wiegand_bench, AccessList, Presentation, SourceId};
//! use odr_wiegand::{CardFormat, Credential};
//!
//! let card = Credential::new(CardFormat::H10301, 42, 1337);
//! let access = AccessList::new().with_credential(&card).unwrap();
//! let mut bench = wiegand_bench(0xC0FFEE, access).unwrap();
//!
//! let presented = Presentation::from_credential(SourceId(0), &card).unwrap();
//! bench.world.present(bench.reader, 1_000_000, presented).unwrap();
//! bench.world.run_until(2_000_000).unwrap();
//!
//! assert_eq!(bench.world.log().grants().count(), 1);
//! assert_eq!(bench.world.log().strikes().count(), 1);
//! assert!(bench.world.door(bench.door).unwrap().strike_count == 1);
//! ```
//!
//! # Module map
//!
//! | Module | What lives there |
//! |---|---|
//! | [`world`] | [`World`]: the clock, the queue, and the dispatch loop |
//! | [`log`] | [`EventLog`], [`LogRecord`], [`RecordKind`] — the observable output |
//! | [`credential`] | the seam `odr-credential` plugs into, and nothing more |
//! | [`reader`] | Wiegand, clock-and-data and OSDP peripheral state machines |
//! | [`controller`] | legacy panel and OSDP controller, polling, Secure Channel |
//! | [`door`] | strike, lock state, position switch, request-to-exit |
//! | [`link`] | the Wiegand pair, the clock-and-data pair, the RS-485 bus, segments |
//! | [`tap`] | passive, injecting and inline (MITM) taps |
//! | [`access`] | the access list a controller decides against |
//! | [`capture`] | the newline-delimited JSON format `DESIGN.md` §3 fixes, both ways |
//! | [`builder`] | fluent assembly, and two ready-made benches |
//!
//! # Where the attacks live
//!
//! Nowhere in this crate — and that is the point. `odr-bus` provides the
//! mechanisms honestly enough that the attacks in `docs/CURRICULUM.md` fall
//! out of using them:
//!
//! * **Replay** is an [`InjectingTap`] with a queued [`Injection`].
//! * **The implant** is an [`InlineTap`] built with
//!   [`InlineTap::substitute_bits`].
//! * **The downgrade** is an [`InlineTap`] built with
//!   [`InlineTap::rewrite_frames`], against a controller whose
//!   [`AcuConfig::trust_pdcap`] is `true`.
//! * **Install mode** is [`AcuConfig::install_mode`].
//! * **Passive eavesdropping** is a [`PassiveTap`] and a read of its buffer.
//!
//! # Ethics
//!
//! Simulated protocol machinery, no vendor-specific exploit code, no real
//! credential data. The defensive half is first class: every attack above is
//! visible in the same [`EventLog`] a defender would be reading, which is what
//! Module 5 of the curriculum is for.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod access;
pub mod builder;
pub mod capture;
pub mod controller;
pub mod credential;
pub mod door;
pub mod error;
pub mod ids;
pub mod link;
pub mod log;
pub mod reader;
pub mod sched;
pub mod tap;
pub mod world;

pub use access::{AccessEntry, AccessList, AccessPolicy};
pub use builder::{
    clock_data_bench, osdp_bench, wiegand_bench, ClockDataBench, OsdpBench, OsdpBenchSpec,
    WiegandBench, WorldBuilder,
};
pub use capture::{
    export_from_tap, export_ndjson, export_ndjson_with, parse_ndjson, CaptureDir, CaptureError,
    CaptureErrorKind, CaptureEvent, CaptureLine, CaptureOptions, CaptureReplay, ReplayTarget,
};
pub use controller::{
    AcuConfig, CardDecision, Controller, ControllerMode, PdSession, SessionStage,
};
pub use credential::{CredentialSource, FormatId, Presentation, ScriptedToken, StaticToken};
pub use door::{Door, DoorPosition, LockState};
pub use error::{BusError, Result};
pub use ids::{
    BusDir, ControllerId, DoorId, Endpoint, LinkId, Micros, Origin, ReaderId, SourceId, TapId,
};
pub use link::{Chain, ChainItem, ClockDataLink, Link, Rs485Bus, Rs485Timing, WiegandLink};
pub use log::{
    DecisionReason, EventLog, LineAnomaly, LogRecord, ProtocolEvent, RecordKind, ScDecline,
    ScEvent, TapAction, WireKind,
};
pub use reader::{
    default_capabilities, BusyPolicy, ClockDataConfig, HeldRead, PdConfig, PdRuntime, Reader,
    ReaderProtocol, ScRequirement,
};
pub use sched::{Injection, InjectionPayload};
pub use tap::{
    FnTap, InjectingTap, InlineTap, Observation, ObservedTraffic, PassiveTap, SeenTraffic, Tap,
    TapCtx, TapKind, TapPlacement, TapPolicy, TapVerdict,
};
pub use world::{TapPosition, World};

#[cfg(test)]
mod tests;
