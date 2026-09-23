//! **The credential seam.**
//!
//! `odr-bus` deliberately does **not** depend on `odr-credential`. A reader in
//! this crate does not know what a MIFARE sector is, how an EM4100 modulates a
//! carrier, or what a DESFire mutual authentication costs. All it knows is that
//! at some virtual microsecond, a token was held up to it and produced a run of
//! bits.
//!
//! That is the whole seam, and it is deliberately this narrow:
//!
//! ```text
//!   odr-credential                    odr-bus
//!   ──────────────                    ───────
//!   EM4100 / Prox / MIFARE / Seos ──▶ Presentation { source, format, bits }
//!   card-side attacks                 wire-side everything
//! ```
//!
//! # How `odr-credential` plugs in
//!
//! Two ways, and both work without this crate changing:
//!
//! 1. **Push.** Build a [`Presentation`] and hand it to
//!    [`World::present`](crate::World::present) at a chosen time. This is the
//!    path every test and most drills use, because it is the most explicit.
//! 2. **Pull.** Implement [`CredentialSource`] on a card type and attach it to
//!    a reader with
//!    [`World::attach_source`](crate::World::attach_source). The reader asks
//!    the token for bits when it is presented, which is the right shape for a
//!    card that answers differently each time (a DESFire doing a challenge, or
//!    a cloned tag whose emulator gets the parity wrong).
//!
//! # Why `source` exists
//!
//! [`Presentation::source`] identifies the *physical token*, not its data. Two
//! tokens carrying byte-identical bits — an original and a clone — get
//! different [`SourceId`]s. Curriculum drill 0.2 ("a cloned tag presents and
//! the controller grants, where the original tag was never presented") is only
//! answerable because of this field.
//!
//! # Why `format` is an opaque integer
//!
//! A reader on a wire does not know the format either. It shifts out whatever
//! bits the card gave it and the *panel* decides what they mean. [`FormatId`]
//! is therefore a tag for the log and for whoever built the scenario, never
//! something the engine branches on. Well-known values for the formats
//! `odr-wiegand` models are provided as constants so that a log is readable
//! without a lookup table, and everything from `0x8000_0000` up is reserved for
//! `odr-credential` to allocate as it likes.

use alloc::string::String;
use alloc::vec::Vec;

use odr_wiegand::{BitVec, CardFormat, Credential};

use crate::ids::{Micros, SourceId};

/// An opaque tag for "what kind of data is in these bits".
///
/// The engine never branches on this. It is carried through the event log so a
/// drill, a UI or `odr-credential` can say what a run of bits was meant to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FormatId(pub u32);

impl FormatId {
    /// Unknown or unspecified — raw bits with no claimed meaning.
    pub const UNKNOWN: FormatId = FormatId(0);
    /// HID H10301, 26 bits.
    pub const H10301: FormatId = FormatId(26);
    /// HID H10306, 34 bits.
    pub const H10306: FormatId = FormatId(34);
    /// HID Corporate 1000, 35 bits.
    pub const CORPORATE_1000: FormatId = FormatId(35);
    /// HID H10304, 37 bits with a facility code.
    pub const H10304: FormatId = FormatId(37);
    /// HID H10302, 37 bits with no facility code.
    pub const H10302: FormatId = FormatId(137);
    /// ABA track 2, as used on a clock-and-data link.
    pub const ABA_TRACK2: FormatId = FormatId(200);
    /// The first value reserved for `odr-credential`. Everything at or above
    /// this is ours to ignore.
    pub const EXTERNAL_BASE: u32 = 0x8000_0000;

    /// The tag matching one of the card formats `odr-wiegand` models.
    pub fn for_card_format(format: CardFormat) -> FormatId {
        match format {
            CardFormat::H10301 => FormatId::H10301,
            CardFormat::H10306 => FormatId::H10306,
            CardFormat::Corporate1000 => FormatId::CORPORATE_1000,
            CardFormat::H10304 => FormatId::H10304,
            CardFormat::H10302 => FormatId::H10302,
            CardFormat::Raw { bit_len } => FormatId(0x4000_0000 + bit_len as u32),
        }
    }

    /// True if this tag was allocated by something outside this crate.
    pub fn is_external(self) -> bool {
        self.0 >= FormatId::EXTERNAL_BASE
    }
}

/// A credential presentation as a reader experiences it.
///
/// This is the entire vocabulary the world model has for "someone badged in".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation {
    /// Which physical token this was. Distinguishes a clone from its original
    /// even when the bits are identical.
    pub source: SourceId,
    /// What the bits are claimed to be. The engine never branches on it.
    pub format: FormatId,
    /// The bits the token produced, in transmission order.
    pub bits: BitVec,
    /// A human label for the log and the UI. Never affects behaviour.
    pub label: Option<String>,
}

impl Presentation {
    /// A presentation built from raw bits.
    pub fn new(source: SourceId, format: FormatId, bits: BitVec) -> Presentation {
        Presentation {
            source,
            format,
            bits,
            label: None,
        }
    }

    /// A presentation built from an `odr-wiegand` credential, with parity
    /// applied.
    ///
    /// ```
    /// # use odr_bus::{Presentation, SourceId};
    /// # use odr_wiegand::{CardFormat, Credential};
    /// let card = Credential::new(CardFormat::H10301, 42, 1337);
    /// let p = Presentation::from_credential(SourceId(0), &card).unwrap();
    /// assert_eq!(p.bits.len(), 26);
    /// ```
    pub fn from_credential(
        source: SourceId,
        cred: &Credential,
    ) -> core::result::Result<Presentation, odr_wiegand::FormatError> {
        Ok(Presentation {
            source,
            format: FormatId::for_card_format(cred.format),
            bits: cred.encode()?,
            label: None,
        })
    }

    /// Attach a human label, for the log only.
    pub fn labelled(mut self, label: impl Into<String>) -> Presentation {
        self.label = Some(label.into());
        self
    }

    /// How many bits the token produced.
    pub fn bit_len(&self) -> usize {
        self.bits.len()
    }
}

/// A token that can be presented to a reader more than once.
///
/// This is the pull half of the credential seam. `odr-credential` implements
/// it on a card type; `odr-bus` calls it when that card is presented and cares
/// about nothing else.
///
/// Implementations must be deterministic: given the same `at_us` and the same
/// internal state they must return the same bits, because the whole engine is
/// reproducible from a seed (`DESIGN.md` §3). If a card needs randomness it
/// should carry its own [`odr_osdp::rng::SeededRng`].
pub trait CredentialSource {
    /// The token's identity. Two tokens with identical data still have
    /// different ids.
    fn source_id(&self) -> SourceId;

    /// Produce a presentation, or `None` if the token did not answer — a card
    /// out of range, a DESFire that refused, a dead battery.
    fn present(&mut self, at_us: Micros) -> Option<Presentation>;
}

/// The simplest possible [`CredentialSource`]: one token, one fixed answer.
///
/// Enough for every drill that does not need card-layer behaviour, and a
/// worked example of the trait for `odr-credential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticToken {
    presentation: Presentation,
}

impl StaticToken {
    /// Wrap a fixed presentation.
    pub fn new(presentation: Presentation) -> StaticToken {
        StaticToken { presentation }
    }

    /// The presentation this token will produce.
    pub fn presentation(&self) -> &Presentation {
        &self.presentation
    }
}

impl CredentialSource for StaticToken {
    fn source_id(&self) -> SourceId {
        self.presentation.source
    }

    fn present(&mut self, _at_us: Micros) -> Option<Presentation> {
        Some(self.presentation.clone())
    }
}

/// A token that answers with a different presentation each time, then stops.
///
/// Useful for "the emulator got the third read wrong" and for scripted drills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptedToken {
    id: SourceId,
    queue: Vec<Presentation>,
    next: usize,
}

impl ScriptedToken {
    /// Build a token that will produce each presentation in turn.
    pub fn new(id: SourceId, presentations: Vec<Presentation>) -> ScriptedToken {
        ScriptedToken {
            id,
            queue: presentations,
            next: 0,
        }
    }

    /// How many presentations are left.
    pub fn remaining(&self) -> usize {
        self.queue.len().saturating_sub(self.next)
    }
}

impl CredentialSource for ScriptedToken {
    fn source_id(&self) -> SourceId {
        self.id
    }

    fn present(&mut self, _at_us: Micros) -> Option<Presentation> {
        let out = self.queue.get(self.next).cloned();
        if out.is_some() {
            self.next = self.next.saturating_add(1);
        }
        out
    }
}
