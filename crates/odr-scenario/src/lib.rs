//! **The drills.**
//!
//! Item 6 in the Open Door Range build order (`DESIGN.md` §3 and §6). Below it
//! sit a working door system (`odr-bus`), a set of attacker actors
//! (`odr-attack`) and a defender's monitor (`odr-detect`). Above it sits
//! `odr-wasm` and the site. This crate is the course: twenty-nine drills, the
//! benches they run on, the guidance a learner reads at each band, and the
//! predicate that decides whether each flag is earned.
//!
//! ```text
//!   ScenarioId ──build──▶ Bench ──solve──▶ Outcome ──evaluate──▶ Flag
//!                                  │                    ▲
//!                                  └── Knowledge ───────┤
//!                                  └── Facts ───────────┤
//!                                      Submission ──────┘
//! ```
//!
//! # The rule that governs everything here
//!
//! **A flag predicate is a query against engine state. There are no answer
//! strings.**
//!
//! Every flag in `docs/CURRICULUM.md` is a statement about what the simulation
//! must have done — "the controller granted access at a time when no credential
//! was presented to the reader", "attacker-recovered SCBK equals the PD's
//! configured SCBK, recovered from capture alone". Each is implemented in
//! [`flag`] as a predicate over the [`World`](odr_bus::World), its event log,
//! and the attacker's [`Knowledge`](odr_attack::Knowledge). `odr-bus`'s log
//! carries a `cause` field that makes it a graph; `odr-attack`'s knowledge
//! carries provenance. Between them every predicate in the curriculum is
//! expressible, and grep will find no string constant in this crate that a
//! learner could type to pass a drill.
//!
//! Seven drills legitimately take learner input — a facility code, a set of
//! byte offsets, a predicted cryptogram, a list of times. Those are **claims
//! checked against values the engine generated from its seed**, not answer
//! strings, and [`submission`] explains the difference at length because the
//! difference is the whole design.
//!
//! # Two drills are not flag-shaped
//!
//! Forcing them into that mould would be the one dishonest thing in the course,
//! so [`Completion`] has three variants rather than one:
//!
//! * **1.5** ends on a *number* — the wall-clock cost of sweeping the whole
//!   credential space at the timing the learner chose. [`Completion::Measurement`].
//! * **0.6** ends by *being read*. It simulates nothing and `docs/BYPASS.md`
//!   says so in its first line. [`Completion::Reference`].
//!
//! # A tour
//!
//! ```
//! use odr_scenario::{catalog, run, DrillId};
//!
//! // Drive drill 1.3 — replay on a Wiegand door — to completion.
//! let solved = run::solve(DrillId::new(1, 3), 0xC0FFEE).unwrap();
//! let flag = solved.flag(None).unwrap();
//! assert!(flag.earned, "{:?}", flag.outstanding);
//!
//! // The same bench with nothing clipped to it earns nothing.
//! let plain = run::baseline(DrillId::new(1, 3), 0xC0FFEE).unwrap();
//! assert!(!plain.flag(None).unwrap().earned);
//!
//! // And the catalogue is data.
//! let drill = catalog::drill_by_name("1.3").unwrap();
//! assert_eq!(drill.title, "Replay");
//! assert_eq!(catalog::drill_count(), 29);
//! ```
//!
//! # Module map
//!
//! | Module | What lives there |
//! |---|---|
//! | [`ids`] | [`DrillId`], [`ModuleId`], [`Band`], [`Completion`], [`TapPlan`] |
//! | [`scenario`] | [`ScenarioId`] and [`Bench`] — one per distinct configuration the curriculum needs |
//! | [`drill`] | [`Drill`], [`Guidance`], [`Module`] — the shape of a drill |
//! | [`catalog`] | all twenty-nine, in curriculum order, with the guidance text |
//! | [`submission`] | [`Submission`] — a learner's typed claim, and why it is not an answer |
//! | [`facts`] | [`Facts`] — the engine-derived truth a predicate compares against |
//! | [`flag`] | [`Flag`], [`FlagContext`], [`evaluate`] — the predicates |
//! | [`run`] | [`Outcome`], [`solve`], [`baseline`] — driving a drill, and the negative control |
//! | [`tasks`] | [`Task`], [`TaskState`] — drill 4.2's bar that never finishes |
//! | [`module5`] | the defensive half wired into drills 5.1 to 5.3 |
//! | [`error`] | [`ScenarioError`] |
//!
//! # Constraints it keeps
//!
//! `no_std` + `alloc`, `#![forbid(unsafe_code)]`, builds for
//! `wasm32-unknown-unknown`. Deterministic: seeded randomness only, no wall
//! clock anywhere except [`Task::state`], which is explicitly outside the
//! simulation and touches nothing a flag depends on. No panics — everything
//! fallible returns [`ScenarioError`], because a panic in a browser is a dead
//! tab.
//!
//! # Ethics
//!
//! Everything here is simulated (`DESIGN.md` §5). No vendor-specific exploit
//! code, no real credential data, no product named. The weak-key material is
//! the already-published Mellon family (Petro & Vargas, Bishop Fox, 2023). Two
//! drills teach something the range cannot fully show — the real cost of a
//! 32-bit MAC, and a null cipher in the reply direction this engine cannot
//! produce — and in both cases the guidance says so rather than papering over
//! it.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod catalog;
pub mod drill;
pub mod error;
pub mod facts;
pub mod flag;
pub mod ids;
pub mod module5;
pub mod run;
pub mod scenario;
pub mod submission;
pub mod tasks;

pub use catalog::{drill_by_name, drill_count, drills_in, drills_using, DRILLS, MODULES};
pub use drill::{Drill, Guidance, Module};
pub use error::{Result, ScenarioError};
pub use facts::{
    DesyncTrace, Facts, ForgeryOutcome, FrameLayout, IvReuseOutcome, MifareOutcome,
    TransmittedCredential,
};
pub use flag::{evaluate, Flag, FlagContext, Measurement};
pub use ids::{Band, Completion, DrillId, LinkRole, ModuleId, TapMode, TapPlan};
pub use module5::DetectionOutcome;
pub use run::{baseline, solve, Outcome};
pub use scenario::{Bench, CardSetup, ScenarioId, Script, ScriptedBadge};
pub use submission::{FieldSpan, FrameField, Submission};
pub use tasks::{Task, TaskState};

#[cfg(test)]
mod tests;
