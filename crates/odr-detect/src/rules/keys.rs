//! **Weak key in use, and the null ciphers.**
//!
//! Two findings that are *certain* from the wire, which makes them the
//! interesting half of curriculum drill 5.1 — "which of the four attacks in
//! module 3 are visible to a passive monitor at all?". These two are not even
//! attacks; they are settings, and both of them announce themselves in a
//! header byte that is transmitted before any encryption exists.
//!
//! # Default key: one byte, in the clear, every handshake
//!
//! The SCS_11 / SCS_12 / SCS_13 security block carries a key-type byte. `0x00`
//! means SCBK-D, the key printed in the standard. A monitor that sees it knows,
//! with no further work, that every byte of every session on this link is
//! recoverable — and so does anybody else watching.
//!
//! # Null cipher: SCS_15 and SCS_16 are a supported mode
//!
//! Those two block types are authenticated and **not** encrypted. A link
//! running them says "Secure Channel established" in every status display and
//! every audit log, and the card numbers are plaintext.
//!
//! ## The benign case this must not fire on
//!
//! **Every properly encrypted bus in the world**, because an empty payload
//! legitimately uses the MAC-only block even when encryption was requested —
//! there is nothing to encrypt in a `POLL` or an `ACK`. A rule that fired on
//! "SCS_15 seen" would fire continuously on exactly the deployments it is
//! meant to exonerate. The rule is therefore **SCS_15 or SCS_16 carrying a
//! non-empty payload**, and there is a test that an ordinary encrypted bench
//! produces no finding.

use alloc::vec::Vec;

use odr_osdp::payload::PdCapabilities;
use odr_osdp::{KeyType, RawCardRead, Reply};

use crate::detector::Detector;
use crate::finding::{addr_label, Confidence, Evidence, Finding, Severity, Signal};
use crate::observe::{Monitor, Observation};

/// Weak-key and null-cipher detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDetector {
    /// Also report the default key when a `REPLY_PDCAP` admits to it, rather
    /// than waiting to see a handshake use it.
    ///
    /// On by default. A peripheral's capability report has a "uses default key"
    /// bit, and a monitor that catches the capability exchange learns the answer
    /// without waiting for a session to start.
    ///
    /// It is still gated on Secure Channel existing at that address at all. A
    /// peripheral that admits to SCBK-D on a bus that never runs a handshake is
    /// not *using* the default key — it is using no key, which
    /// [`Signal::CleartextBus`] already says, and more usefully.
    pub trust_capability_claim: bool,
}

impl Default for KeyDetector {
    fn default() -> KeyDetector {
        KeyDetector {
            trust_capability_claim: true,
        }
    }
}

impl KeyDetector {
    /// A key detector with the default tuning.
    pub fn new() -> KeyDetector {
        KeyDetector::default()
    }
}

impl Detector for KeyDetector {
    fn name(&self) -> &str {
        "keys"
    }

    fn signals(&self) -> &'static [Signal] {
        &[Signal::DefaultKeyInUse, Signal::NullCipher]
    }

    fn rationale(&self) -> &'static str {
        "the handshake's key-type byte names SCBK-D in the clear, and a security block of type \
         SCS_15/16 with a non-empty payload is an unencrypted frame on a link that believes it \
         is encrypted; empty payloads legitimately use the MAC-only block and are ignored"
    }

    fn run(&self, monitor: &Monitor) -> Vec<Finding> {
        let mut out = Vec::new();
        for address in monitor.addresses() {
            if let Some(f) = self.default_key(monitor, address) {
                out.push(f);
            }
            out.extend(self.null_cipher(monitor, address));
        }
        out
    }
}

impl KeyDetector {
    /// The first evidence at this address that the published default key is in
    /// use.
    fn default_key(&self, monitor: &Monitor, address: u8) -> Option<Finding> {
        // A handshake block naming the default key is the strongest evidence:
        // it is what the two endpoints are about to derive a session from.
        let handshake = monitor.for_address(address).find(|o| {
            o.is_handshake()
                && o.frame
                    .as_ref()
                    .and_then(|f| f.security.as_ref())
                    .and_then(|sb| sb.key_type())
                    == Some(KeyType::Default)
        });
        if let Some(o) = handshake {
            return Some(Finding::new(
                o.t_us,
                Severity::Critical,
                Signal::DefaultKeyInUse,
                Confidence::Certain,
                Evidence::one(
                    o,
                    alloc::format!(
                        "address {}: the security block on this handshake frame carries key type \
                         0x00, which is SCBK-D — the key published in the standard. The session \
                         keys derive from it and from two nonces that are also on the wire, so \
                         every frame of every session on this link is readable by anyone with a \
                         transceiver. This byte is sent before any encryption exists, so the \
                         reconnaissance costs an attacker nothing.",
                        addr_label(address)
                    ),
                ),
            ));
        }

        if !self.trust_capability_claim {
            return None;
        }
        // Only worth saying where a key is actually in play. On a bus with no
        // Secure Channel anywhere, "the reader is on the default key" is a true
        // statement about a key nothing is using.
        if !monitor.for_address(address).any(|o| o.has_security_block()) {
            return None;
        }

        // Failing that, the peripheral's own capability report admits to it.
        let caps = monitor.for_address(address).find(|o| {
            o.reply() == Some(Reply::PdCap)
                && o.frame
                    .as_ref()
                    .and_then(|f| PdCapabilities::decode(&f.payload).ok())
                    .is_some_and(|c| c.uses_default_key())
        })?;
        Some(Finding::new(
            caps.t_us,
            Severity::High,
            Signal::DefaultKeyInUse,
            Confidence::Certain,
            Evidence::one(
                caps,
                alloc::format!(
                    "address {}: this capability reply says the peripheral is still on the \
                     default key. No handshake has been observed yet, so this is the device's own \
                     claim rather than a session about to use it — but it is the device's claim \
                     about itself, and it is sent unauthenticated to anyone listening.",
                    addr_label(address)
                ),
            ),
        ))
    }

    /// Frames using the null ciphers with something in them.
    fn null_cipher(&self, monitor: &Monitor, address: u8) -> Vec<Finding> {
        let hits: Vec<&Observation> = monitor
            .for_address(address)
            .filter(|o| {
                o.scs().is_some_and(|s| s.has_mac() && !s.is_encrypted())
                    && o.frame.as_ref().is_some_and(|f| !f.payload.is_empty())
            })
            .collect();
        let first = match hits.first() {
            Some(f) => *f,
            None => return Vec::new(),
        };

        // A readable card number is the strongest form of the finding; it is
        // exactly curriculum 4.4's flag, seen from the other chair.
        let card = hits.iter().find(|o| {
            o.reply() == Some(Reply::Raw)
                && o.frame
                    .as_ref()
                    .is_some_and(|f| RawCardRead::decode(&f.payload).is_ok())
        });

        let mut note = alloc::format!(
            "address {}: {} frame(s) carry a security block of type SCS_15 or SCS_16 with a \
             non-empty payload. Those two types authenticate and do not encrypt, so the link \
             reports \"secure channel established\" while its payloads are plaintext.",
            addr_label(address),
            hits.len()
        );
        let confidence = match card {
            Some(o) => {
                let bits = o
                    .frame
                    .as_ref()
                    .and_then(|f| RawCardRead::decode(&f.payload).ok())
                    .map(|r| r.bit_count)
                    .unwrap_or(0);
                note.push_str(&alloc::format!(
                    " One of them is a {bits}-bit card read whose payload decodes without a key."
                ));
                Confidence::Certain
            }
            None => {
                note.push_str(
                    " None of them is a card read, so the exposure here is command and status \
                     content rather than credentials — which still includes anything that opens a \
                     door.",
                );
                Confidence::Probable
            }
        };

        alloc::vec![Finding::new(
            first.t_us,
            Severity::High,
            Signal::NullCipher,
            confidence,
            Evidence::new(hits.iter().copied(), note).truncate_evenly(6),
        )]
    }
}
