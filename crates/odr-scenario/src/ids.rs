//! The small vocabulary a drill is addressed by: its number, its module, its
//! band, and how it completes.
//!
//! Everything here is a plain value type. `DrillId` in particular is the
//! curriculum number and nothing else — `"1.3"`, `"4.2"` — because that is what
//! `docs/CURRICULUM.md` calls a drill, what `site/ENGINE-API.md` puts in a URL,
//! and what a person says out loud.

use alloc::string::String;

/// **A drill's curriculum number**, as a module and an index inside it.
///
/// Parsed from and rendered as `"<module>.<index>"`, which is the form
/// `site/ENGINE-API.md` uses as an opaque string. Ordering is numeric, so
/// sorting a list of ids gives curriculum order rather than lexical order —
/// `1.10` would sort after `1.9` rather than before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DrillId {
    /// The module number, 0 through 5.
    pub module: u8,
    /// The position inside the module, counting from 1.
    pub index: u8,
}

impl DrillId {
    /// Build an id from its two numbers.
    pub const fn new(module: u8, index: u8) -> DrillId {
        DrillId { module, index }
    }

    /// Parse `"1.3"`.
    ///
    /// Returns `None` for anything that is not two decimal numbers separated
    /// by a single dot; this is fed from a URL fragment and from
    /// `localStorage`, so it has to survive nonsense.
    pub fn parse(s: &str) -> Option<DrillId> {
        let (m, i) = s.split_once('.')?;
        if m.is_empty() || i.is_empty() {
            return None;
        }
        Some(DrillId {
            module: m.parse().ok()?,
            index: i.parse().ok()?,
        })
    }

    /// The id as the string the site uses.
    pub fn as_string(&self) -> String {
        alloc::format!("{}.{}", self.module, self.index)
    }

    /// The module this drill belongs to.
    pub fn module_id(&self) -> ModuleId {
        ModuleId(self.module)
    }
}

impl core::fmt::Display for DrillId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.module, self.index)
    }
}

/// **A module number**, 0 through 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleId(pub u8);

impl ModuleId {
    /// The `'m0'`-style string `site/ENGINE-API.md` uses for module ids.
    pub fn as_string(&self) -> String {
        alloc::format!("m{}", self.0)
    }
}

impl core::fmt::Display for ModuleId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "m{}", self.0)
    }
}

/// **A difficulty band.**
///
/// A band changes the *guidance*, never the bench (`docs/UI.md`). Bronze
/// pre-places the taps and gives numbered steps; Silver gives the objective
/// plus hints on request; Gold gives the objective and nothing else. The
/// instrument is identical in all three, so a learner moving up is not learning
/// a new interface.
///
/// [`Band::Reference`] is not a difficulty. It is what drill 0.6 is: prose that
/// simulates nothing, carried in the same enum so that the catalogue can say so
/// rather than filing it under Bronze and hoping nobody notices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Band {
    /// Guided. A beginner cannot get stuck.
    Bronze,
    /// The sandbox with objectives, hints on request.
    Silver,
    /// An objective and nothing else.
    Gold,
    /// Not simulated. Reference prose.
    Reference,
}

impl Band {
    /// The three bands a learner can actually select.
    pub const SELECTABLE: [Band; 3] = [Band::Bronze, Band::Silver, Band::Gold];

    /// The lower-case name `site/ENGINE-API.md` uses.
    pub fn name(self) -> &'static str {
        match self {
            Band::Bronze => "bronze",
            Band::Silver => "silver",
            Band::Gold => "gold",
            Band::Reference => "reference",
        }
    }

    /// Parse the name back.
    pub fn parse(s: &str) -> Option<Band> {
        match s {
            "bronze" => Some(Band::Bronze),
            "silver" => Some(Band::Silver),
            "gold" => Some(Band::Gold),
            "reference" => Some(Band::Reference),
            _ => None,
        }
    }

    /// Whether this band pre-places the drill's taps.
    ///
    /// Only Bronze does. `site/ENGINE-API.md` §4 depends on it: a Silver bench
    /// that quietly arrives with an inline tap already fitted makes drill 1.4
    /// meaningless.
    pub fn pre_places_taps(self) -> bool {
        matches!(self, Band::Bronze)
    }

    /// Whether hints are offered at this band. Gold gets none.
    pub fn offers_hints(self) -> bool {
        !matches!(self, Band::Gold)
    }
}

/// **How a drill finishes.**
///
/// Most drills finish on a flag predicate. Two do not, and forcing them into
/// that mould would be a lie about what they teach:
///
/// * **1.5** ends on a *number* — the wall-clock cost of sweeping the whole
///   26-bit space at the timing the learner chose. There is nothing to earn;
///   the point is the size of the figure and the comparison with drill 1.3.
/// * **0.6** ends by *being read*. It simulates nothing and `docs/BYPASS.md`
///   says so in its first line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Completion {
    /// A predicate evaluated against engine state.
    Flag,
    /// A measurement the engine reports. Drill 1.5.
    Measurement,
    /// Prose. Drill 0.6.
    Reference,
}

impl Completion {
    /// Whether this drill runs a simulation at all.
    ///
    /// `site/ENGINE-API.md` calls this `simulated`, and renders `false` as
    /// "REFERENCE — no flag".
    pub fn is_simulated(self) -> bool {
        !matches!(self, Completion::Reference)
    }

    /// A short name for the UI.
    pub fn name(self) -> &'static str {
        match self {
            Completion::Flag => "flag",
            Completion::Measurement => "measurement",
            Completion::Reference => "reference",
        }
    }
}

/// **Which link in a bench a tap goes on.**
///
/// The topology strip in `docs/UI.md` draws three links; only two of them can
/// carry a tap, and which one a drill needs is part of the drill rather than
/// something the learner has to infer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkRole {
    /// The air gap between a token and the reader.
    CardToReader,
    /// The reader-to-panel link: a Wiegand pair, a clock-and-data pair, or an
    /// RS-485 bus, depending on the scenario.
    ReaderToController,
}

impl LinkRole {
    /// The link id `site/ENGINE-API.md` §4 uses.
    pub fn name(self) -> &'static str {
        match self {
            LinkRole::CardToReader => "card-reader",
            LinkRole::ReaderToController => "reader-controller",
        }
    }
}

/// **What a tap is allowed to do**, mirroring `odr_bus::TapKind` and
/// `site/ENGINE-API.md` §4's `mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TapMode {
    /// Listens. Cannot transmit, cannot alter. The engine enforces it.
    Sniff,
    /// Listens and transmits, and can collide with a real transmitter.
    Inject,
    /// Cuts the link. Receives on one side and decides what reaches the other.
    Inline,
}

impl TapMode {
    /// The mode name `site/ENGINE-API.md` uses.
    pub fn name(self) -> &'static str {
        match self {
            TapMode::Sniff => "sniff",
            TapMode::Inject => "inject",
            TapMode::Inline => "inline",
        }
    }

    /// The equivalent `odr-bus` tap kind, which is what actually gates the
    /// simulation.
    pub fn tap_kind(self) -> odr_bus::TapKind {
        match self {
            TapMode::Sniff => odr_bus::TapKind::Passive,
            TapMode::Inject => odr_bus::TapKind::Injecting,
            TapMode::Inline => odr_bus::TapKind::Inline,
        }
    }
}

/// **Where a drill needs a tap, and what kind.**
///
/// Bronze pre-places exactly this list; Silver and Gold place none and leave it
/// to the learner. The runner in [`crate::run`] always places it, because an
/// attack that is not clipped onto anything does not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapPlan {
    /// Which link.
    pub link: LinkRole,
    /// What the attack needs to be able to do.
    pub mode: TapMode,
    /// A phrase for the UI: "a sniffer on the D0/D1 pair".
    pub label: &'static str,
}
