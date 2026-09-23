//! The access list: what a controller will open the door for.
//!
//! Matching is on the **bits as received**, not on a decoded facility code and
//! card number, because that is what a panel actually has. A panel is
//! configured to believe one card format and looks up whatever number falls
//! out; if an attacker hands it a different bit pattern that decodes to a
//! number in the list, it opens the door. Modelling the list as bit patterns
//! keeps that honest and makes curriculum drill 1.2 — "a frame that parses
//! cleanly, has valid parity, and carries a different card number than any
//! credential ever presented" — a statement about data rather than about
//! intent.

use alloc::string::String;
use alloc::vec::Vec;

use odr_wiegand::{BitVec, CardFormat, Credential, FormatError};

/// One entry in an access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEntry {
    /// The exact bit pattern that will be granted.
    pub bits: BitVec,
    /// A human label, carried into the decision record.
    pub label: Option<String>,
}

impl AccessEntry {
    /// An entry for an exact bit pattern.
    pub fn new(bits: BitVec) -> AccessEntry {
        AccessEntry { bits, label: None }
    }

    /// An entry for a card, encoded with its format's parity.
    pub fn credential(cred: &Credential) -> Result<AccessEntry, FormatError> {
        Ok(AccessEntry {
            bits: cred.encode()?,
            label: None,
        })
    }

    /// Attach a label.
    pub fn labelled(mut self, label: impl Into<String>) -> AccessEntry {
        self.label = Some(label.into());
        self
    }
}

/// What a controller does with a credential it has read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AccessPolicy {
    /// Grant only bit patterns in the list.
    #[default]
    List,
    /// Grant anything readable. Useful for drills about the wire rather than
    /// about authorisation — the door becomes a plain indicator that a frame
    /// arrived.
    AllowAll,
    /// Grant nothing. Useful for showing that an attack reached the panel and
    /// was still refused.
    DenyAll,
}

/// A controller's authorisation configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessList {
    /// The policy.
    pub policy: AccessPolicy,
    /// The entries consulted under [`AccessPolicy::List`].
    pub entries: Vec<AccessEntry>,
    /// Format the controller is configured to believe, for decoding the bits
    /// it receives into something a log can print. `None` means "infer",
    /// which is what a modern panel's "auto-detect format" setting does and is
    /// exactly as trustworthy as it sounds.
    pub assumed_format: Option<CardFormat>,
    /// Reject a frame whose parity does not check out.
    ///
    /// Real panels vary, and the ones that do not check are not rare. Default
    /// is `true` — check it — so that a drill about forging parity has
    /// something to defeat.
    pub require_valid_parity: bool,
}

impl Default for AccessList {
    fn default() -> AccessList {
        AccessList {
            policy: AccessPolicy::List,
            entries: Vec::new(),
            assumed_format: None,
            require_valid_parity: true,
        }
    }
}

impl AccessList {
    /// An empty list under [`AccessPolicy::List`]: nothing is granted.
    pub fn new() -> AccessList {
        AccessList::default()
    }

    /// A list that grants everything readable.
    pub fn allow_all() -> AccessList {
        AccessList {
            policy: AccessPolicy::AllowAll,
            ..AccessList::default()
        }
    }

    /// A list that grants nothing.
    pub fn deny_all() -> AccessList {
        AccessList {
            policy: AccessPolicy::DenyAll,
            ..AccessList::default()
        }
    }

    /// Add an entry.
    pub fn with_entry(mut self, entry: AccessEntry) -> AccessList {
        self.entries.push(entry);
        self
    }

    /// Add a card, encoded with its format's parity.
    pub fn with_credential(mut self, cred: &Credential) -> Result<AccessList, FormatError> {
        self.entries.push(AccessEntry::credential(cred)?);
        Ok(self)
    }

    /// Add a raw bit pattern.
    pub fn with_bits(mut self, bits: BitVec) -> AccessList {
        self.entries.push(AccessEntry::new(bits));
        self
    }

    /// Set the format the controller believes its readers emit.
    pub fn assuming(mut self, format: CardFormat) -> AccessList {
        self.assumed_format = Some(format);
        self
    }

    /// Set whether parity is checked.
    pub fn checking_parity(mut self, check: bool) -> AccessList {
        self.require_valid_parity = check;
        self
    }

    /// Look up a bit pattern. Returns the matching entry, if any.
    pub fn lookup(&self, bits: &BitVec) -> Option<&AccessEntry> {
        self.entries.iter().find(|e| &e.bits == bits)
    }

    /// True if these exact bits are in the list.
    pub fn contains(&self, bits: &BitVec) -> bool {
        self.lookup(bits).is_some()
    }
}
