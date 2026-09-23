//! **Install mode and keyset capture — the detector that is honest about what
//! it cannot tell you.**
//!
//! Curriculum drill 5.3 asks: *what does install mode look like in a log, and
//! why is it usually indistinguishable from a real commissioning?* This module
//! is the answer, and the answer is uncomfortable.
//!
//! What the wire gives you is unambiguous. `CMD_KEYSET` is a command code; its
//! payload is a key type and a key; a monitor that sees one knows a Secure
//! Channel base key was just pushed to a peripheral, knows which peripheral,
//! and — if the frame was not encrypted, or was encrypted under SCBK-D — knows
//! the key itself.
//!
//! What the wire does not give you is **authorisation**. There is no field in
//! an OSDP frame that says who originated it, no signature over the controller's
//! identity, and no distinction in the protocol between "the installer is
//! commissioning this door" and "somebody put a controller-shaped thing on the
//! bus". A commissioning and an attack produce the same bytes. That is not a
//! limitation of this detector; it is a property of OSDP, and it is why the
//! finding is emitted with [`Confidence::Ambiguous`] however loud the severity.
//!
//! The defensive conclusion a learner should reach is therefore not "detect
//! keysets" but "**know when your commissionings are**". A `CMD_KEYSET` at
//! 14:05 on the Tuesday the installer was booked is expected; the identical
//! frame at 03:00 on a Sunday is not. That comparison happens outside the wire,
//! and no rule in this crate can make it for you.

use alloc::vec::Vec;

use odr_osdp::payload::KeysetCommand;
use odr_osdp::{weak_keys, Command, ScsType};

use crate::detector::Detector;
use crate::finding::{addr_label, Confidence, Evidence, Finding, Severity, Signal};
use crate::observe::{fmt_us, Monitor};

/// Keyset observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeysetDetector {
    /// Include the recovered key bytes in the evidence note when the frame was
    /// readable.
    ///
    /// On by default, because seeing the key written out next to the frame it
    /// came from is the entire lesson of curriculum 3.5. The key material here
    /// is simulated; nothing in this crate ever touches a real one.
    pub show_recovered_key: bool,
}

impl Default for KeysetDetector {
    fn default() -> KeysetDetector {
        KeysetDetector {
            show_recovered_key: true,
        }
    }
}

impl KeysetDetector {
    /// A keyset detector with the default tuning.
    pub fn new() -> KeysetDetector {
        KeysetDetector::default()
    }
}

impl Detector for KeysetDetector {
    fn name(&self) -> &str {
        "keyset"
    }

    fn signals(&self) -> &'static [Signal] {
        &[Signal::KeysetObserved]
    }

    fn rationale(&self) -> &'static str {
        "CMD_KEYSET is unmistakable on the wire and says nothing about who sent it; the finding \
         reports the event and the recoverability of the key, and leaves authorisation to a \
         change record the bus does not have"
    }

    fn run(&self, monitor: &Monitor) -> Vec<Finding> {
        let mut out = Vec::new();
        for o in monitor.bus() {
            if o.command() != Some(Command::Keyset) {
                continue;
            }
            let address = o.address().unwrap_or(0);
            let frame = match o.frame.as_ref() {
                Some(f) => f,
                None => continue,
            };

            // Three cases, in decreasing order of how bad they are.
            let (severity, recoverable, protection) = match o.scs() {
                None => (
                    Severity::Critical,
                    true,
                    "with no security block at all, so the key crossed the bus as plaintext",
                ),
                Some(ScsType::CmdMacOnly) => (
                    Severity::Critical,
                    true,
                    "inside a MAC-only security block (SCS_15), which authenticates and does not \
                     encrypt, so the key crossed the bus as plaintext",
                ),
                Some(_) => (
                    Severity::High,
                    false,
                    "inside an encrypted security block. Whether that protects the key depends \
                     entirely on the session key it was encrypted under: a channel established \
                     with SCBK-D protects nothing, because SCBK-D is published",
                ),
            };

            let mut note = alloc::format!(
                "address {}: a CMD_KEYSET at {} pushed a Secure Channel base key, {protection}.",
                addr_label(address),
                fmt_us(o.t_us)
            );

            if recoverable {
                match KeysetCommand::decode(&frame.payload) {
                    Ok(k) => {
                        note.push_str(&alloc::format!(
                            " The payload decodes: key type {:#04x}, {} bytes.",
                            k.key_type,
                            k.key.len()
                        ));
                        if let Some(key) = k.as_aes128() {
                            if self.show_recovered_key {
                                note.push_str(&alloc::format!(
                                    " The key is {}.",
                                    odr_bus::capture::to_hex(&key)
                                ));
                            }
                            if key == weak_keys::SCBK_D {
                                note.push_str(
                                    " It is SCBK-D, so the peripheral was moved onto the published \
                                     default rather than off it.",
                                );
                            } else if let Some(pattern) = weak_keys::classify(&key) {
                                note.push_str(&alloc::format!(
                                    " It is a member of the published weak-key family ({pattern:?}), \
                                     so it would have been recoverable from a captured handshake \
                                     even without this frame."
                                ));
                            } else {
                                note.push_str(
                                    " Every door commissioned with this key on this site is now \
                                     readable by whoever was on the bus.",
                                );
                            }
                        }
                    }
                    Err(e) => {
                        note.push_str(&alloc::format!(
                            " The payload did not decode as a keyset command ({e}), so the key \
                             length is unknown — but the command code is not in doubt."
                        ));
                    }
                }
            }

            note.push_str(
                " There is nothing in this frame, or in any frame, that says whether it was \
                 authorised. A commissioning and an attacker in install mode produce identical \
                 traffic; the only thing that separates them is whether an installer was booked, \
                 and the bus does not know.",
            );

            out.push(Finding::new(
                o.t_us,
                severity,
                Signal::KeysetObserved,
                Confidence::Ambiguous,
                Evidence::one(o, note),
            ));
        }
        out
    }
}
