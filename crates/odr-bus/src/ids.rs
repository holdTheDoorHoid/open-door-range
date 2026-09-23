//! Handles for the things a [`World`](crate::World) contains, and the two
//! enums that say *who* did something.
//!
//! Every handle is a plain index newtype. They are separate types rather than
//! one `NodeId` because a reader, a controller and a door are not
//! interchangeable and the compiler should say so; the two enums
//! ([`Origin`] and [`Endpoint`]) exist for the places where they genuinely are
//! — a byte on a bus was driven by *something*, and received by *something*.
//!
//! Handles are stable for the life of a world. Nothing is ever removed, so an
//! index never changes meaning, which is what lets an event log recorded now be
//! interpreted later.

use core::fmt;

/// Virtual microseconds since the start of the simulation.
///
/// This is the only clock in the project. Nothing here reads wall time; see
/// `DESIGN.md` §3.
pub type Micros = u64;

macro_rules! id_type {
    ($(#[$m:meta])* $name:ident, $label:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u32);

        impl $name {
            /// The index this handle refers to.
            pub fn index(self) -> usize {
                self.0 as usize
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $label, self.0)
            }
        }
    };
}

id_type!(
    /// A reader (an OSDP peripheral device, or a legacy Wiegand/clock-and-data
    /// reader).
    ReaderId,
    "reader#"
);
id_type!(
    /// A controller (an OSDP access control unit, or a legacy panel).
    ControllerId,
    "acu#"
);
id_type!(
    /// A door: strike, position switch and request-to-exit input.
    DoorId,
    "door#"
);
id_type!(
    /// A link: a Wiegand pair, a clock-and-data pair, or an RS-485 bus.
    LinkId,
    "link#"
);
id_type!(
    /// A tap placed on a link.
    TapId,
    "tap#"
);
id_type!(
    /// A credential source — the physical token, not the data on it.
    ///
    /// Two tokens carrying identical bits have different source ids, which is
    /// what makes "a clone was presented and the original never was"
    /// (curriculum drill 0.2) a question the engine can answer.
    SourceId,
    "card#"
);

/// Who drove something onto a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// A reader transmitted.
    Reader(ReaderId),
    /// A controller transmitted.
    Controller(ControllerId),
    /// A tap transmitted. Every frame an attacker put on the wire has this
    /// origin, which is what makes "zero frames injected" checkable.
    Tap(TapId),
}

impl Origin {
    /// The tap that produced this, if any.
    pub fn tap(self) -> Option<TapId> {
        match self {
            Origin::Tap(t) => Some(t),
            _ => None,
        }
    }

    /// True if this traffic came from a tap rather than from a real node.
    pub fn is_injected(self) -> bool {
        matches!(self, Origin::Tap(_))
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Reader(r) => write!(f, "{r}"),
            Origin::Controller(c) => write!(f, "{c}"),
            Origin::Tap(t) => write!(f, "{t}"),
        }
    }
}

/// Who received something from a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Endpoint {
    /// A reader.
    Reader(ReaderId),
    /// A controller.
    Controller(ControllerId),
    /// A tap. Passive taps only ever appear here.
    Tap(TapId),
}

impl Endpoint {
    /// The matching [`Origin`] for this endpoint, for when it answers.
    pub fn as_origin(self) -> Origin {
        match self {
            Endpoint::Reader(r) => Origin::Reader(r),
            Endpoint::Controller(c) => Origin::Controller(c),
            Endpoint::Tap(t) => Origin::Tap(t),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Reader(r) => write!(f, "{r}"),
            Endpoint::Controller(c) => write!(f, "{c}"),
            Endpoint::Tap(t) => write!(f, "{t}"),
        }
    }
}

/// Direction of travel on an RS-485 bus.
///
/// These are the two values `DESIGN.md` §3 fixes for the capture format's
/// `dir` field on an `rs485` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BusDir {
    /// Controller to peripheral: a command.
    AcuToPd,
    /// Peripheral to controller: a reply.
    PdToAcu,
}

impl BusDir {
    /// The opposite direction.
    pub fn flip(self) -> BusDir {
        match self {
            BusDir::AcuToPd => BusDir::PdToAcu,
            BusDir::PdToAcu => BusDir::AcuToPd,
        }
    }

    /// The capture-format spelling of this direction.
    pub fn as_str(self) -> &'static str {
        match self {
            BusDir::AcuToPd => "acu_to_pd",
            BusDir::PdToAcu => "pd_to_acu",
        }
    }
}

impl fmt::Display for BusDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
