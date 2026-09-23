//! The door: strike, lock state, position switch and request-to-exit.
//!
//! Deliberately simple. The door is not where the teaching is — it is the
//! *scoreboard*. What matters is that
//! [`RecordKind::StrikeFired`](crate::RecordKind::StrikeFired) is a first-class
//! log record, because the site treats it as the authoritative record of a
//! successful attack and the drill predicates in `docs/CURRICULUM.md` are
//! written against it.
//!
//! Note what is *not* modelled: everything in curriculum drill 0.6 — the
//! under-door tool, the request-to-exit sensor triggered from outside, the
//! crash bar. The REX input here is an input that can be asserted; how it came
//! to be asserted is exactly the part this project says it does not simulate.

use alloc::string::String;

use crate::ids::{DoorId, Micros};

/// Whether the strike is holding the door shut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// The strike is engaged; the door will not open.
    Locked,
    /// The strike is released.
    Unlocked,
}

impl LockState {
    /// True if locked.
    pub fn is_locked(self) -> bool {
        matches!(self, LockState::Locked)
    }
}

/// What the door position switch reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoorPosition {
    /// The leaf is shut.
    Closed,
    /// The leaf is open.
    Open,
}

impl DoorPosition {
    /// True if open.
    pub fn is_open(self) -> bool {
        matches!(self, DoorPosition::Open)
    }
}

/// A door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Door {
    /// Handle.
    pub id: DoorId,
    /// A name for the UI.
    pub name: String,
    /// Lock state.
    pub lock: LockState,
    /// Position switch.
    pub position: DoorPosition,
    /// Request-to-exit input.
    pub rex: bool,
    /// How long the strike is held when it fires.
    pub strike_time_us: Micros,
    /// Whether asserting REX releases the strike.
    ///
    /// Almost always true in the field, and it is the single most commonly
    /// abused property of a door. The engine models the input, not the ways of
    /// tripping it from the wrong side.
    pub rex_unlocks: bool,
    /// How many times the strike has fired, for a quick assertion in a drill.
    pub strike_count: u32,
    /// Bumped every time the relock timer is (re)started, so a stale timer
    /// firing after a second grant does not relock early.
    pub(crate) relock_token: u64,
}

impl Door {
    /// A locked, closed door with a 3-second strike.
    pub fn new(id: DoorId, name: impl Into<String>) -> Door {
        Door {
            id,
            name: name.into(),
            lock: LockState::Locked,
            position: DoorPosition::Closed,
            rex: false,
            strike_time_us: 3_000_000,
            rex_unlocks: true,
            strike_count: 0,
            relock_token: 0,
        }
    }

    /// Set how long the strike is held.
    pub fn with_strike_time(mut self, us: Micros) -> Door {
        self.strike_time_us = us;
        self
    }

    /// Set whether REX releases the strike.
    pub fn with_rex_unlocks(mut self, yes: bool) -> Door {
        self.rex_unlocks = yes;
        self
    }

    /// True if the strike is currently released.
    pub fn is_unlocked(&self) -> bool {
        self.lock == LockState::Unlocked
    }

    /// True if the leaf is open.
    pub fn is_open(&self) -> bool {
        self.position.is_open()
    }
}
