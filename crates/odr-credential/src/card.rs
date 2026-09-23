//! Whatever is in the reader's field.
//!
//! One enum over every credential the crate models, so a scenario can swap a prox card
//! for a DESFire without the reader, the bus or the drill machinery caring. The
//! important thing it does *not* carry is any notion of provenance: a cloned tag and
//! an issued tag are the same variant, holding the same bits, and there is no field
//! either the reader or a drill could consult to tell them apart.

use crate::desfire::DesfireEv2;
use crate::em4100::Em4100Tag;
use crate::error::{CredentialError, Result};
use crate::hid_prox::H10301;
use crate::mifare::MifareClassic1k;
use crate::modulation::{CarrierConfig, EventStream, RF_64};
use crate::writable::WritableTag;

/// Which radio a card answers on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Technology {
    /// 125 kHz, no processor, no session, no command set.
    Lf125kHz,
    /// 13.56 MHz, ISO 14443-A: a processor, a command set, and something to
    /// authenticate against.
    Hf13_56MHz,
}

impl Technology {
    /// A short name for logs and the site's UI.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lf125kHz => "125 kHz",
            Self::Hf13_56MHz => "13.56 MHz",
        }
    }
}

/// A credential presented to a reader.
#[derive(Debug, Clone)]
pub enum Card {
    /// A factory EM4100 tag.
    Em4100(Em4100Tag),
    /// An HID Prox H10301 card.
    HidProx(H10301),
    /// A writable 125 kHz blank — blank, or carrying a clone.
    Writable(WritableTag),
    /// A MIFARE Classic 1K.
    MifareClassic(Box<MifareClassic1k>),
    /// A DESFire EV2.
    Desfire(Box<DesfireEv2>),
}

impl Card {
    /// A factory EM4100 tag.
    pub const fn em4100(tag: Em4100Tag) -> Self {
        Self::Em4100(tag)
    }

    /// An HID Prox H10301 card.
    pub const fn hid_prox(card: H10301) -> Self {
        Self::HidProx(card)
    }

    /// A writable 125 kHz tag.
    pub const fn writable(tag: WritableTag) -> Self {
        Self::Writable(tag)
    }

    /// A MIFARE Classic 1K.
    pub fn mifare(card: MifareClassic1k) -> Self {
        Self::MifareClassic(Box::new(card))
    }

    /// A DESFire EV2.
    pub fn desfire(card: DesfireEv2) -> Self {
        Self::Desfire(Box::new(card))
    }

    /// Which radio this card answers on.
    pub const fn technology(&self) -> Technology {
        match self {
            Self::Em4100(_) | Self::HidProx(_) | Self::Writable(_) => Technology::Lf125kHz,
            Self::MifareClassic(_) | Self::Desfire(_) => Technology::Hf13_56MHz,
        }
    }

    /// A human-readable name for the card type.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Em4100(_) => "EM4100",
            Self::HidProx(_) => "HID Prox H10301",
            Self::Writable(_) => "writable 125 kHz tag",
            Self::MifareClassic(_) => "MIFARE Classic 1K",
            Self::Desfire(_) => "DESFire EV2",
        }
    }

    /// What the card emits when a 125 kHz field energises it.
    ///
    /// The reader gets this and nothing else, and demodulates it itself — which is
    /// why a clone is indistinguishable rather than merely declared to be. Returns
    /// [`CredentialError::WrongTechnology`] for a 13.56 MHz card, because a 125 kHz
    /// field does not power one and it says nothing at all.
    pub fn field_response(&self, repeats: usize, cfg: &CarrierConfig) -> Result<EventStream> {
        match self {
            Self::Em4100(tag) => Ok(tag.encode().event_stream(repeats, RF_64, cfg)),
            Self::HidProx(card) => Ok(card.event_stream(repeats, cfg)),
            Self::Writable(tag) => tag.event_stream(repeats, cfg),
            Self::MifareClassic(_) | Self::Desfire(_) => Err(CredentialError::WrongTechnology {
                reader: Technology::Lf125kHz.name(),
                card: Technology::Hf13_56MHz.name(),
            }),
        }
    }

    /// Borrow the MIFARE Classic inside, if that is what this is.
    pub fn as_mifare_mut(&mut self) -> Option<&mut MifareClassic1k> {
        match self {
            Self::MifareClassic(card) => Some(card),
            _ => None,
        }
    }

    /// Borrow the DESFire inside, if that is what this is.
    pub fn as_desfire_mut(&mut self) -> Option<&mut DesfireEv2> {
        match self {
            Self::Desfire(card) => Some(card),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technology_is_what_it_should_be() {
        assert_eq!(
            Card::em4100(Em4100Tag::new(1, 2)).technology(),
            Technology::Lf125kHz
        );
        assert_eq!(
            Card::mifare(MifareClassic1k::new(1, 1)).technology(),
            Technology::Hf13_56MHz
        );
    }

    #[test]
    fn a_high_frequency_card_says_nothing_in_a_low_frequency_field() {
        let card = Card::mifare(MifareClassic1k::new(1, 1));
        assert!(matches!(
            card.field_response(1, &CarrierConfig::default()),
            Err(CredentialError::WrongTechnology { .. })
        ));
    }

    #[test]
    fn a_blank_writable_tag_is_reported_as_blank() {
        let card = Card::writable(WritableTag::blank());
        assert!(matches!(
            card.field_response(1, &CarrierConfig::default()),
            Err(CredentialError::BlankTag)
        ));
    }
}
