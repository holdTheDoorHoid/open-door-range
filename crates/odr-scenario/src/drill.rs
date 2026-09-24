//! **What a drill is.**
//!
//! A scenario assembles a world. A drill wraps one with an objective, guidance
//! at three bands, an ordered list of hints, and a flag predicate. Everything
//! here is a plain `'static` table, so the catalogue is data that can be read
//! rather than code that has to be run — which is what `DESIGN.md` §3 means by
//! "drill definitions and flag predicates, **data-driven**".
//!
//! # Bands change the guidance, never the bench
//!
//! `docs/UI.md` is explicit and this type enforces the shape of it:
//!
//! * **Bronze** pre-places the taps in [`Drill::taps`] and gives numbered
//!   steps.
//! * **Silver** places nothing and gives the objective, with hints on request.
//! * **Gold** gives the objective and nothing else — [`Guidance::gold`] is
//!   empty for every drill in the catalogue, and there is a test that says so.
//!
//! The bench is identical in all three. A learner moving up is not learning a
//! new interface, and a practitioner in free play has the same instrument as
//! everybody else.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ids::{Band, Completion, DrillId, ModuleId, TapPlan};
use crate::scenario::ScenarioId;

/// **Per-band guidance.**
///
/// Shaped to match `site/ENGINE-API.md`'s `Drill.guidance`: three lists, of
/// which Gold's is always empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guidance {
    /// Numbered steps. A beginner following these cannot get stuck.
    pub bronze: &'static [&'static str],
    /// The standing line or two Silver shows beside the objective. Not steps.
    pub silver: &'static [&'static str],
    /// Always empty. Gold is the objective and nothing else.
    pub gold: &'static [&'static str],
}

impl Guidance {
    /// The guidance for one band.
    ///
    /// [`Band::Reference`] gets Bronze's list, because a section that completes
    /// by being read has reading instructions rather than difficulty.
    pub fn for_band(&self, band: Band) -> &'static [&'static str] {
        match band {
            Band::Bronze | Band::Reference => self.bronze,
            Band::Silver => self.silver,
            Band::Gold => self.gold,
        }
    }
}

/// **One drill.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drill {
    /// The curriculum number.
    pub id: DrillId,
    /// The title from `docs/CURRICULUM.md`, verbatim.
    pub title: &'static str,
    /// Which module it belongs to.
    pub module: ModuleId,
    /// The band it was *written for*. Shown as "designed for silver"; it is
    /// independent of the band the learner has selected.
    pub band: Band,
    /// How it finishes: a flag, a number, or being read.
    pub completion: Completion,
    /// Which bench it runs on.
    pub scenario: ScenarioId,
    /// What the drill is about. One to three sentences.
    pub summary: &'static str,
    /// What the learner must make happen. One sentence.
    pub objective: &'static str,
    /// The flag predicate in prose, shown verbatim in the flag card.
    ///
    /// This is the *statement* of the predicate. The predicate itself is a
    /// query against engine state in [`crate::flag`]; if the two ever disagree
    /// the prose is wrong, because the engine is what awards the flag.
    pub flag_text: &'static str,
    /// An extra paragraph, usually about what the range cannot show. Empty
    /// when there is nothing to add.
    pub note: &'static str,
    /// Guidance at each band.
    pub guidance: Guidance,
    /// Hints, in the order they should be revealed. Never shown at Gold.
    pub hints: &'static [&'static str],
    /// Where this drill's attack has to sit.
    ///
    /// Bronze pre-places exactly this. Silver and Gold place none.
    pub taps: &'static [TapPlan],
    /// What the learner submits as a **typed claim**, in words, or `None`.
    ///
    /// `None` does not always mean the learner does nothing. The Module 5
    /// drills take a detection *rule set*, which is a list of trait objects
    /// rather than a value, so it is handed to
    /// [`run::score_module_5`](crate::run::score_module_5) and run rather than
    /// compared. This field is about the claims in [`crate::submission`].
    pub submission: Option<&'static str>,
}

impl Drill {
    /// Whether this drill runs a simulation.
    pub fn is_simulated(&self) -> bool {
        self.completion.is_simulated()
    }

    /// The guidance for a band.
    pub fn guidance_for(&self, band: Band) -> &'static [&'static str] {
        self.guidance.for_band(band)
    }

    /// The taps a band starts with: Bronze's are pre-placed, the rest are the
    /// learner's to fit.
    pub fn taps_for(&self, band: Band) -> &'static [TapPlan] {
        if band.pre_places_taps() {
            self.taps
        } else {
            &[]
        }
    }

    /// The hints available at a band. Gold gets none.
    pub fn hints_for(&self, band: Band) -> &'static [&'static str] {
        if band.offers_hints() {
            self.hints
        } else {
            &[]
        }
    }

    /// `"1.3 Replay"`, the title the session strip shows.
    pub fn display_title(&self) -> String {
        alloc::format!("{} {}", self.id, self.title)
    }
}

/// **One module of the course.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Module {
    /// The module id.
    pub id: ModuleId,
    /// Its number, 0 through 5.
    pub number: u8,
    /// Its title.
    pub title: &'static str,
    /// One or two sentences on why it exists.
    pub blurb: &'static str,
}

impl Module {
    /// The drills in this module, in curriculum order.
    pub fn drills(&self) -> Vec<&'static Drill> {
        crate::catalog::drills_in(self.id)
    }
}
