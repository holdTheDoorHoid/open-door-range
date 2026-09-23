//! **The Wiegand layer, where the finding is how little there is to find.**
//!
//! A monitor clipped to a D0/D1 pair sees pulses. That is the entire inventory.
//! There is no address, no sequence number, no checksum beyond two parity bits
//! that were designed to catch a cable fault, no reply channel, and nothing
//! whatsoever to authenticate. So the detector here is deliberately, almost
//! rudely, short — and that is the teaching point of the module, not an
//! omission.
//!
//! What a monitor on a two-wire link **can** say:
//!
//! * The link exists and it is unauthenticated. Every drill in Module 1 works
//!   because of that one fact, so [`Signal::UnauthenticatedWire`] is a posture
//!   finding worth stating once per link.
//! * How many credentials crossed it and when. That is the traffic-analysis
//!   observation, and on Wiegand it is not even a weakness in the interesting
//!   sense — the credential itself is in the clear, so knowing the schedule is
//!   the least of it.
//! * Whether a frame fits any known card format with valid parity
//!   ([`Signal::MalformedCredential`]). This catches a clumsy implant, a failing
//!   driver or a marginal cable run, and it cannot distinguish between them.
//!
//! What it **cannot** say, ever:
//!
//! * Whether the reader or something else drove the pulses. Both look like
//!   pulses. An inline implant that substitutes one credential for another is
//!   invisible from the panel side by construction — the implant is upstream of
//!   the probe, and what the probe records is what the implant chose to send.
//! * Whether a credential was replayed, except by how fast it came back
//!   (see [`ReplayDetector`](crate::rules::ReplayDetector)).
//! * Which card format this is. The wire does not say, and the capture format
//!   does not carry a bit count, so a 26-bit read and a 32-bit read can be the
//!   same four bytes. A monitor guesses from parity, and parity is ambiguous by
//!   construction.
//!
//! The honest defensive answer for a Wiegand door is therefore not a better
//! rule. It is that the link cannot be monitored into safety, and the money goes
//! on replacing it or on watching the door rather than the wire.

use alloc::vec::Vec;

use odr_bus::Micros;
use odr_wiegand::{infer_formats, CardFormat};

use crate::detector::Detector;
use crate::finding::{Confidence, Evidence, Finding, Severity, Signal};
use crate::observe::{fmt_us, Monitor, Observation};
use crate::rules::DEFAULT_GAP_US;

/// What a monitor on a two-wire link can conclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireDetector {
    /// A silence longer than this starts a new run, and a new posture finding.
    pub gap_us: Micros,
    /// Cap on malformed-credential findings.
    pub max_malformed: usize,
}

impl Default for WireDetector {
    fn default() -> WireDetector {
        WireDetector {
            gap_us: DEFAULT_GAP_US,
            max_malformed: 8,
        }
    }
}

impl WireDetector {
    /// A wire detector with the default tuning.
    pub fn new() -> WireDetector {
        WireDetector::default()
    }
}

impl Detector for WireDetector {
    fn name(&self) -> &str {
        "wire"
    }

    fn signals(&self) -> &'static [Signal] {
        &[Signal::UnauthenticatedWire, Signal::MalformedCredential]
    }

    fn rationale(&self) -> &'static str {
        "a two-wire link has no authentication to check, so the finding is the link itself; \
         beyond that a monitor can only say whether the bits fit a known format with valid parity"
    }

    fn run(&self, monitor: &Monitor) -> Vec<Finding> {
        let events: Vec<&Observation> = monitor.wire().collect();
        if events.is_empty() {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut run: Vec<&Observation> = Vec::new();
        for o in &events {
            if run
                .last()
                .is_some_and(|p| o.t_us.saturating_sub(p.t_us) > self.gap_us)
            {
                out.push(self.posture(&run));
                run.clear();
            }
            run.push(o);
        }
        if !run.is_empty() {
            out.push(self.posture(&run));
        }

        let mut malformed = 0usize;
        for o in &events {
            if malformed >= self.max_malformed {
                break;
            }
            let bits = match &o.bits {
                Some(b) if !b.is_empty() => b,
                _ => continue,
            };
            // `infer_formats` always appends a raw passthrough candidate and
            // marks it valid, because a format with no parity rules cannot fail
            // them. That is the right answer for a decoder and the wrong one
            // here: "it is some bits" explains nothing.
            let plausible = infer_formats(bits)
                .into_iter()
                .any(|c| c.parity_valid && !matches!(c.decoded.format, CardFormat::Raw { .. }));
            if plausible {
                continue;
            }
            malformed += 1;
            out.push(Finding::new(
                o.t_us,
                Severity::Medium,
                Signal::MalformedCredential,
                Confidence::Possible,
                Evidence::one(
                    o,
                    alloc::format!(
                        "{} bits that fit no card format this analyser knows with valid parity. \
                         That is a clumsy implant, a reader with a failing line driver, a \
                         marginal cable run, or a format nobody told the analyser about — and \
                         nothing on a D0/D1 pair distinguishes those four. The capture format \
                         carries no bit count either, so the reading itself is an inference.",
                        bits.len()
                    ),
                ),
            ));
        }
        out
    }
}

impl WireDetector {
    /// The posture statement for one run of two-wire traffic.
    fn posture(&self, run: &[&Observation]) -> Finding {
        let span = run
            .last()
            .map(|l| l.t_us.saturating_sub(run[0].t_us))
            .unwrap_or(0);
        Finding::new(
            run[0].t_us,
            Severity::High,
            Signal::UnauthenticatedWire,
            Confidence::Certain,
            Evidence::new(
                run.iter().copied(),
                alloc::format!(
                    "{} credential frame(s) over {} on a two-wire link. There is no encryption \
                     and no authentication on a D0/D1 pair, so anything driven onto it will be \
                     believed by the panel, and a monitor here cannot tell the reader, an inline \
                     implant and an injector apart — all three produce pulses. This is a statement \
                     about the link, not about an event on it.",
                    run.len(),
                    fmt_us(span)
                ),
            )
            .truncate_evenly(6),
        )
    }
}
