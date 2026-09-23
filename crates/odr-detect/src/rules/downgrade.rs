//! **Downgrade — the detector curriculum drill 5.2 is about.**
//!
//! The Mellon downgrade rewrites a peripheral's `REPLY_PDCAP` so it claims it
//! cannot do AES-128. A controller that decides whether to run Secure Channel
//! from that unauthenticated reply believes it, declines its own policy, and
//! carries on in the clear. From a monitor's seat, the observable is a
//! peripheral that **stopped claiming** a capability it used to claim.
//!
//! # Drill 5.2's actual question
//!
//! > Build a detection rule that catches the downgrade and does not fire on a
//! > genuine legacy reader being added to the bus.
//!
//! The naive rule — "alert on any peripheral that does not claim AES-128" —
//! catches the downgrade, and also fires on every legacy reader anyone ever
//! adds, and on the perfectly ordinary bus next door. It is useless. Three
//! things make the difference, and all three are in this detector:
//!
//! 1. **A downgrade is a change, not a state.** The rule needs a *prior* claim
//!    from the same address. A reader that has never claimed AES-128 has not
//!    been downgraded; it is just a reader.
//! 2. **Device memory outlives link continuity.** "Address 1 claimed AES-128"
//!    is a fact about a reader, and a monitor may remember it across a silence
//!    — unlike a sequence number, which it may not. A legacy reader added to
//!    the bus appears at a *new* address with no history, so there is nothing
//!    to change from.
//! 3. **`REPLY_PDID` is the tiebreaker for the hard case.** A reader physically
//!    replaced with a legacy model at the same address looks exactly like a
//!    downgrade — same address, capabilities dropped — except that the reported
//!    device identity changes too. With
//!    [`DowngradeDetector::require_same_identity`] set (the default) that case
//!    reports [`Signal::DeviceIdentityChanged`] instead, and the capability
//!    memory for the address is reset.
//!
//! # What point 3 buys, and what it does not
//!
//! It buys quiet. It buys **no security at all**: `REPLY_PDID` is as
//! unauthenticated as `REPLY_PDCAP`, and an attacker already rewriting one
//! frame can rewrite the other for free. The honest framing is that this rule
//! separates a downgrade from a *maintenance visit*, not from a *competent
//! attacker*. [`DowngradeDetector::strict`] turns it off and catches the
//! identity-spoofing variant, at the price of alerting on every reader swap —
//! which is a trade a defender should make consciously rather than inherit.
//!
//! # The second observable
//!
//! [`Signal::SecureChannelLost`] covers the downgrade's *effect* rather than
//! its mechanism: an address that has run Secure Channel is now carrying
//! unsecured traffic and has not re-handshaked. It catches downgrades achieved
//! by means other than a capability rewrite, and it is the rule that must not
//! fire on a **reader power-cycling and resyncing**, which produces a short
//! unsecured burst — `ID`, `CAP`, `CHLNG` — before the channel comes back.
//! [`DowngradeDetector::resync_grace_us`] is that allowance.

use alloc::vec::Vec;

use odr_bus::Micros;
use odr_osdp::payload::{PdCapabilities, PdId};
use odr_osdp::Reply;

use crate::detector::Detector;
use crate::finding::{addr_label, Confidence, Evidence, Finding, Severity, Signal};
use crate::observe::{fmt_us, Monitor, Observation};

/// The identity fields of a `REPLY_PDID` that name the *device*.
///
/// Firmware version is deliberately excluded: an update is not a new reader,
/// and treating it as one would make the detector go quiet every time a site
/// patched its hardware.
type Identity = ([u8; 3], u8, [u8; 4]);

/// Downgrade detection, and the two rules that keep it quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DowngradeDetector {
    /// Require the reported device identity to be unchanged before calling a
    /// capability drop a downgrade.
    ///
    /// `true` by default. See the module docs for what this buys and what it
    /// does not.
    pub require_same_identity: bool,
    /// How long an address may be unsecured, after having been secured, before
    /// it counts as having lost its channel rather than as resynchronising.
    pub resync_grace_us: Micros,
    /// How many unsecured frames before [`Signal::SecureChannelLost`] is worth
    /// saying.
    pub min_unsecured_run: usize,
}

impl Default for DowngradeDetector {
    fn default() -> DowngradeDetector {
        DowngradeDetector {
            require_same_identity: true,
            resync_grace_us: 5_000_000,
            min_unsecured_run: 4,
        }
    }
}

impl DowngradeDetector {
    /// A downgrade detector with the default tuning.
    pub fn new() -> DowngradeDetector {
        DowngradeDetector::default()
    }

    /// The variant that also catches the identity-spoofing downgrade, at the
    /// cost of alerting on every reader replacement.
    pub fn strict() -> DowngradeDetector {
        DowngradeDetector {
            require_same_identity: false,
            ..DowngradeDetector::default()
        }
    }
}

impl Detector for DowngradeDetector {
    fn name(&self) -> &str {
        "downgrade"
    }

    fn signals(&self) -> &'static [Signal] {
        &[
            Signal::CapabilityDowngrade,
            Signal::SecureChannelLost,
            Signal::DeviceIdentityChanged,
        ]
    }

    fn rationale(&self) -> &'static str {
        "a peripheral that stops claiming AES-128 it previously claimed, at an address whose \
         reported identity did not change; a new address with no history is a legacy reader being \
         added and is not reported"
    }

    fn run(&self, monitor: &Monitor) -> Vec<Finding> {
        let mut out = Vec::new();
        for address in monitor.addresses() {
            let frames: Vec<&Observation> = monitor
                .for_address(address)
                .filter(|o| o.frame.is_some())
                .collect();
            out.extend(self.capability_history(&frames, address));
            out.extend(self.secure_channel_lost(&frames, address));
        }
        out
    }
}

/// The identity a `REPLY_PDID` reports, if it decodes.
fn identity_of(o: &Observation) -> Option<Identity> {
    if o.reply() != Some(Reply::PdId) {
        return None;
    }
    let id = o
        .frame
        .as_ref()
        .and_then(|f| PdId::decode(&f.payload).ok())?;
    Some((id.vendor_code, id.model, id.serial_number))
}

/// Whether a `REPLY_PDCAP` claims AES-128, if it decodes.
fn claims_aes(o: &Observation) -> Option<bool> {
    if o.reply() != Some(Reply::PdCap) {
        return None;
    }
    let caps = o
        .frame
        .as_ref()
        .and_then(|f| PdCapabilities::decode(&f.payload).ok())?;
    Some(caps.claims_aes128())
}

impl DowngradeDetector {
    /// Walk one address's capability and identity history.
    fn capability_history<'a>(&self, frames: &[&'a Observation], address: u8) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut identity: Option<Identity> = None;
        let mut last_aes_claim: Option<&'a Observation> = None;
        let mut ever_secure = false;
        let mut reported = false;

        for o in frames {
            if o.is_in_session() {
                ever_secure = true;
            }

            if let Some(id) = identity_of(o) {
                let previous = identity.replace(id);
                if previous.is_some_and(|p| p != id) {
                    // A different device. With `require_same_identity`, what
                    // the monitor knew was about a reader that is no longer
                    // there, so it is forgotten. Without it, the memory is
                    // kept and a swap will be called a downgrade — which is the
                    // trade `DowngradeDetector::strict` exists to make.
                    if self.require_same_identity {
                        last_aes_claim = None;
                        ever_secure = false;
                        reported = false;
                    }
                    out.push(Finding::new(
                        o.t_us,
                        Severity::Info,
                        Signal::DeviceIdentityChanged,
                        Confidence::Certain,
                        Evidence::one(o, identity_note(address, o)),
                    ));
                }
                continue;
            }

            let claims = match claims_aes(o) {
                Some(c) => c,
                None => continue,
            };
            if claims {
                last_aes_claim = Some(o);
                continue;
            }
            let earlier = match last_aes_claim {
                Some(e) if !reported => e,
                // Never claimed it: a legacy reader, not a downgraded one.
                _ => continue,
            };
            reported = true;
            out.push(self.downgrade_finding(address, earlier, o, ever_secure));
        }
        out
    }

    /// Build the capability-downgrade finding, citing both replies.
    fn downgrade_finding(
        &self,
        address: u8,
        earlier: &Observation,
        now: &Observation,
        ever_secure: bool,
    ) -> Finding {
        let mut note = alloc::format!(
            "address {}: this capability reply does not claim AES-128, and the reply at {} from \
             the same address did.",
            addr_label(address),
            fmt_us(earlier.t_us)
        );
        if ever_secure {
            note.push_str(
                " Secure Channel has been observed established at this address, so the capability \
                 was not merely claimed — it was used. A controller that decides from this reply \
                 will now decline its own policy and talk in the clear.",
            );
        }
        if self.require_same_identity {
            note.push_str(
                " REPLY_PDID has reported the same vendor, model and serial throughout, so a \
                 reader replacement does not explain it.",
            );
        }
        note.push_str(
            " The capability exchange is unauthenticated and happens before any key material \
             exists, which is what makes rewriting it possible at all — and which is why this \
             finding is probable rather than certain: nothing on the wire proves the earlier \
             reply was not the forged one.",
        );

        Finding::new(
            now.t_us,
            if ever_secure {
                Severity::Critical
            } else {
                Severity::High
            },
            Signal::CapabilityDowngrade,
            Confidence::Probable,
            Evidence::new([earlier, now], note),
        )
    }

    /// A run of unsecured frames at an address that has run Secure Channel.
    fn secure_channel_lost<'a>(&self, frames: &[&'a Observation], address: u8) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut ever_secure = false;
        let mut identity: Option<Identity> = None;
        let mut run: Vec<&'a Observation> = Vec::new();
        let mut reported = false;

        for o in frames {
            // A device swap resets the premise: the reader that ran Secure
            // Channel is not the reader that is answering now.
            if let Some(id) = identity_of(o) {
                if identity.replace(id).is_some_and(|p| p != id) && self.require_same_identity {
                    ever_secure = false;
                    reported = false;
                    run.clear();
                }
            }

            if o.has_security_block() {
                // An in-session block says the channel is up; a handshake block
                // says it is coming back. Both end the run.
                if o.is_in_session() {
                    ever_secure = true;
                }
                run.clear();
                continue;
            }
            if !ever_secure || reported {
                continue;
            }
            run.push(o);

            if run.len() < self.min_unsecured_run {
                continue;
            }
            let span = run[run.len() - 1].t_us.saturating_sub(run[0].t_us);
            let carries_state = run.iter().any(|r| {
                r.reply().is_some_and(|x| x.is_credential_event())
                    || r.command().is_some_and(|c| c.is_sensitive())
            });
            if span <= self.resync_grace_us && !carries_state {
                continue;
            }

            let mut note = alloc::format!(
                "address {}: {} consecutive frames with no security block, spanning {}, at an \
                 address where Secure Channel has been observed established. No handshake frame \
                 appears in the run, so this is not a resynchronisation.",
                addr_label(address),
                run.len(),
                fmt_us(span)
            );
            if carries_state {
                note.push_str(
                    " The run includes a credential report or a command that changes physical \
                     state, in the clear.",
                );
            } else {
                note.push_str(&alloc::format!(
                    " A reader power-cycling recovers well inside {}; this did not.",
                    fmt_us(self.resync_grace_us)
                ));
            }
            out.push(Finding::new(
                run[run.len() - 1].t_us,
                Severity::High,
                Signal::SecureChannelLost,
                Confidence::Probable,
                Evidence::new(run.iter().copied(), note).truncate_evenly(6),
            ));
            reported = true;
        }
        out
    }
}

/// The note for a device-identity change.
fn identity_note(address: u8, o: &Observation) -> alloc::string::String {
    let id = o.frame.as_ref().and_then(|f| PdId::decode(&f.payload).ok());
    let detail = match id {
        Some(id) => alloc::format!(
            "vendor {:02x?} model {} serial {:02x?}",
            id.vendor_code,
            id.model,
            id.serial_number
        ),
        None => alloc::string::String::from("an identity that did not decode"),
    };
    alloc::format!(
        "address {}: REPLY_PDID now reports {detail}, which is not the device that was answering \
         here before. Usually a reader was replaced. REPLY_PDID is unauthenticated, so an \
         attacker already rewriting the capability reply can rewrite this one too — a changed \
         identity is a reason to stop calling a capability drop an attack, not evidence that it \
         was not one.",
        addr_label(address)
    )
}
