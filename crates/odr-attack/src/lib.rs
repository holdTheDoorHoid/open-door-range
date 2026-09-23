//! **The attacker actors of the Open Door Range.**
//!
//! This is item 5 in the build order (`DESIGN.md` §3 and §6), and the offensive
//! half of it. `odr-bus` models a door system honestly enough that the attacks
//! fall out of using it; this crate is the things that do the using.
//!
//! An actor here is **not** a function that opens a door. It is a device that
//! sits at a tap position, observes, acts, and accumulates *attacker state* —
//! recovered keys, captured credentials, inferred schedules. That accumulated
//! state is what the flag predicates in `docs/CURRICULUM.md` are checked
//! against ("attacker holds the SCBK", "the attacker has extracted a card
//! number", "attacker recovers a plaintext payload"), so it is modelled
//! explicitly as [`Knowledge`] rather than left as a side effect.
//!
//! # The governing rule
//!
//! **An attacker may only use what an attacker could actually have.**
//!
//! No actor in this crate reads a key, a credential or a configuration value
//! out of a node it has not compromised. If an attack needs a value, it
//! observed it, derived it, measured it from its own tap position, brute-forced
//! it, or brought it with it — and [`Provenance`] records which. There is a
//! [`Provenance::Unearned`] variant that nothing here ever constructs, so that
//! a violation is a value a test can find rather than something that quietly
//! works: every attack below has a test asserting
//! [`Knowledge::unearned`] is empty.
//!
//! This matters more than it sounds. A range whose attacks quietly cheat
//! teaches that the attacks are easier than they are, and a learner who then
//! meets the real thing concludes the subject is fake. It is also the property
//! that makes `odr-detect`'s side of the exercise meaningful: a defender can
//! only be asked "what could you have concluded?" if the attacker was genuinely
//! restricted to what crossed the wire.
//!
//! # The actors
//!
//! | Actor | Position | Curriculum |
//! |---|---|---|
//! | [`TagCloner`] | the air interface | 0.2 |
//! | [`NestedAttacker`] | a reader in a pocket | 0.4 |
//! | [`Sniffer`] | passive, two-wire | 1.1, 1.3, 1.6 |
//! | [`Replayer`] | injecting, two-wire | 1.3, 1.6 |
//! | [`Implant`] | inline, two-wire | 1.2, 1.4 |
//! | [`BruteForcer`] | injecting, two-wire | 1.5 |
//! | [`PassiveEavesdropper`] | passive, RS-485 | 2.2 |
//! | [`Injector`] | injecting, RS-485 | 2.3 |
//! | [`WeakKeyCracker`] | passive, RS-485 | 3.2, 3.3 |
//! | [`InstallModeHarvester`] | injecting, RS-485 | 3.4 |
//! | [`KeysetCapturer`] | passive, RS-485 | 3.5 |
//! | [`Downgrader`] | inline, RS-485 | 3.6 |
//! | [`TrafficAnalyst`] | passive, RS-485 | 4.1 |
//! | [`MacForger`] | inline, RS-485 | 4.2 |
//! | [`IvReuseExploiter`] | inline, RS-485 | 4.3 |
//! | [`NullCipherReader`] | passive, RS-485 | 4.4 |
//!
//! # The shape of an actor
//!
//! Every one of them is built, clipped onto a link, driven, and then read:
//!
//! ```
//! use odr_attack::{Attacker, Sniffer};
//! use odr_bus::{wiegand_bench, AccessList, Presentation, SourceId};
//! use odr_wiegand::{CardFormat, Credential};
//!
//! let card = Credential::new(CardFormat::H10301, 42, 1337);
//! let access = AccessList::new().with_credential(&card).unwrap();
//! let mut bench = wiegand_bench(0xC0FFEE, access).unwrap();
//!
//! // Clips on the cable. It transmits nothing.
//! let mut sniffer = Sniffer::new("ceiling void");
//! sniffer.attach(&mut bench.world, bench.link).unwrap();
//!
//! let p = Presentation::from_credential(SourceId(0), &card).unwrap();
//! bench.world.present(bench.reader, 1_000_000, p).unwrap();
//! bench.world.run_until(2_000_000).unwrap();
//!
//! // What the attacker now knows, and where it got it.
//! sniffer.harvest(&bench.world).unwrap();
//! let known = sniffer.knowledge().snapshot();
//! assert_eq!(known.credentials.len(), 1);
//! assert_eq!(known.credentials[0].value.card_number(), Some(1337));
//! assert!(known.credentials[0].provenance.is_observation());
//! assert!(known.is_honest(), "nothing here was handed over");
//! assert_eq!(bench.world.log().injection_count(sniffer.tap().unwrap()), 0);
//! ```
//!
//! # Constraints it keeps
//!
//! * **`no_std` + `alloc`**, `#![forbid(unsafe_code)]`, builds for
//!   `wasm32-unknown-unknown`.
//! * **Deterministic.** A virtual microsecond clock driven by the caller, and
//!   [`odr_osdp::rng::SeededRng`] behind every guess an attacker makes. The
//!   same seed gives the same attack, byte for byte, which is what makes a CTF
//!   flag stable.
//! * **No panics.** Every failure is an [`AttackError`], including "the attack
//!   did not work", which a drill has to be able to display.
//!
//! # Ethics
//!
//! Simulated protocol machinery. No vendor-specific exploit code, no real
//! credential data, no product named. The weak-key material is the already
//! published Mellon family (Petro & Vargas, Bishop Fox, 2023). Every attack
//! here is visible in the same [`odr_bus::EventLog`] a defender would be
//! reading, which is what Module 5 of the curriculum is for.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod cards;
pub mod error;
pub mod knowledge;
pub mod osdp_active;
pub mod osdp_crypto;
pub mod osdp_passive;
pub mod shadow;
pub mod wiegand;

pub use cards::{NestedAttacker, TagCloner};
pub use error::{AttackError, Result};
pub use knowledge::{
    format_id_for, BadgeEvent, CaptureMedium, CapturedCredential, KeyKind, Knowledge,
    KnowledgeCell, Known, MacFacts, ObservedFrame, ObservedHandshake, PlaintextHeader, Provenance,
    RecoveredKey, RecoveredPlaintext, SweepReport, TagCapture,
};
pub use osdp_active::{Downgrader, HarvestOutcome, Injector, InstallModeHarvester};
pub use osdp_crypto::{
    ForgeProgress, IvCollision, IvEpoch, IvReuseExploiter, MacForger, MacSearch,
};
pub use osdp_passive::{
    KeysetCapturer, NullCipherReader, PassiveEavesdropper, TimelineComparison, TrafficAnalyst,
    TrafficTimeline, WeakKeyCracker,
};
pub use shadow::{DecryptedFrame, ShadowSession};
pub use wiegand::{BruteForcer, Implant, ImplantMode, Replayer, Sniffer, SweepStep};

use odr_bus::{TapId, TapKind};

/// **What every actor in this crate has in common.**
///
/// A name, a position on the link, a knowledge base, and — once it has been
/// clipped on — the handle of its tap, which is what a flag predicate needs in
/// order to ask the engine "how many frames did this thing transmit?"
///
/// The trait is deliberately thin. Actors differ enormously in what they *do*;
/// what they share is being a box on a wire that knows things.
pub trait Attacker {
    /// A name for the log and the UI.
    fn name(&self) -> &str;

    /// Where this actor has to sit for its attack to work.
    ///
    /// The engine enforces it: an actor that reports [`TapKind::Passive`]
    /// cannot transmit or alter traffic whatever its code tries.
    fn position(&self) -> TapKind;

    /// What it knows, and where each piece came from.
    fn knowledge(&self) -> &KnowledgeCell;

    /// The tap it is clipped to, once it has been attached.
    fn tap(&self) -> Option<TapId>;

    /// True if this actor has never transmitted anything, according to the
    /// world's own event log.
    ///
    /// Curriculum drills 2.2 and 3.4 both turn on this: "from passive
    /// observation only — zero frames injected".
    fn transmitted_nothing(&self, world: &odr_bus::World) -> bool {
        match self.tap() {
            Some(t) => world.log().injection_count(t) == 0,
            None => true,
        }
    }
}
