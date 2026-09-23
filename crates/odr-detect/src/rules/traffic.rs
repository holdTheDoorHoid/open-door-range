//! **Traffic analysis, from the other chair.**
//!
//! Curriculum drill 4.1 asks a learner to report the times of every badge-in
//! over a simulated day *without ever holding a key*. This module is the same
//! observation made by the defender, and the point of running it from both
//! seats is that the answer is identical. Encryption changes nothing here.
//!
//! The mechanism is a design decision in OSDP: the command and reply id byte
//! sits **outside** the encrypted payload. `REPLY_RAW` is `0x50` on the wire
//! whether or not the card number after it is ciphertext. So a monitor with no
//! key at all can produce:
//!
//! * every moment somebody presented a credential, to the microsecond;
//! * which door, by address;
//! * and by subtraction, when the building is empty.
//!
//! That is a scheduling map of the site, and it is available to anyone who can
//! reach the cable for an afternoon. A defender who has turned on Secure Channel
//! and believes the question is closed should see this finding and understand
//! what it did and did not buy them.
//!
//! # Why this fires on a healthy bus
//!
//! Because a healthy bus has this property. It is [`Severity::Medium`] on an
//! encrypted link — where it is a surprise — and [`Severity::Low`] on a
//! cleartext one, where the schedule is the least of the exposure. It is not an
//! attack and it will never be one; it is a fact about the protocol that a
//! defender should have been told once.

use alloc::vec::Vec;

use odr_osdp::Reply;

use crate::detector::Detector;
use crate::finding::{Confidence, Evidence, Finding, Severity, Signal};
use crate::observe::{fmt_us, Monitor, Observation};

/// One credential presentation, as a monitor with no key sees it.
///
/// This is the list curriculum 4.1 asks for. Note what is in it and what is
/// not: the time and the door are always present; the credential itself is only
/// there when the link was not encrypting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeEvent {
    /// Index into the monitor's stream.
    pub index: usize,
    /// When.
    pub t_us: odr_bus::Micros,
    /// Which peripheral address, for a bus event.
    pub address: Option<u8>,
    /// Whether the payload was encrypted. The event is visible either way.
    pub encrypted: bool,
    /// How many bits of credential, when they were readable.
    pub bit_count: Option<u16>,
}

/// Every credential presentation a monitor could *see*, encrypted or not.
///
/// The defensive answer to curriculum 4.1. Contrast with
/// [`credential_events`](crate::rules::credential_events), which only lists the
/// ones whose contents were legible.
pub fn badge_events(monitor: &Monitor) -> Vec<BadgeEvent> {
    let mut out = Vec::new();
    for o in monitor.observations() {
        if o.is_wire() {
            out.push(BadgeEvent {
                index: o.index,
                t_us: o.t_us,
                address: None,
                encrypted: false,
                bit_count: o.bits.as_ref().map(|b| b.len() as u16),
            });
            continue;
        }
        if !o.reply().is_some_and(|r| r.is_credential_event()) {
            continue;
        }
        let bit_count = if o.is_encrypted() {
            None
        } else {
            o.frame
                .as_ref()
                .filter(|f| f.reply_code() == Some(Reply::Raw))
                .and_then(|f| odr_osdp::RawCardRead::decode(&f.payload).ok())
                .map(|r| r.bit_count)
        };
        out.push(BadgeEvent {
            index: o.index,
            t_us: o.t_us,
            address: o.address(),
            encrypted: o.is_encrypted(),
            bit_count,
        });
    }
    out
}

/// The schedule the encryption did not hide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficDetector {
    /// How many credential events before the schedule is worth reporting.
    ///
    /// One badge-in is not a pattern. Three is a shift.
    pub min_events: usize,
    /// How many times to list in the evidence note.
    pub max_listed: usize,
}

impl Default for TrafficDetector {
    fn default() -> TrafficDetector {
        TrafficDetector {
            min_events: 3,
            max_listed: 12,
        }
    }
}

impl TrafficDetector {
    /// A traffic detector with the default tuning.
    pub fn new() -> TrafficDetector {
        TrafficDetector::default()
    }
}

impl Detector for TrafficDetector {
    fn name(&self) -> &str {
        "traffic"
    }

    fn signals(&self) -> &'static [Signal] {
        &[Signal::TrafficPatternExposed]
    }

    fn rationale(&self) -> &'static str {
        "the command and reply id byte is plaintext inside Secure Channel, so the times of every \
         badge-in are readable with no key; reported once per link because it is a property of \
         the protocol rather than an event"
    }

    fn run(&self, monitor: &Monitor) -> Vec<Finding> {
        let events = badge_events(monitor);
        if events.len() < self.min_events {
            return Vec::new();
        }
        let encrypted = events.iter().filter(|e| e.encrypted).count();
        let span = events
            .last()
            .map(|l| l.t_us.saturating_sub(events[0].t_us))
            .unwrap_or(0);

        let mut note = alloc::format!(
            "{} credential presentations over {}, {} of them with encrypted payloads.",
            events.len(),
            fmt_us(span),
            encrypted
        );
        if encrypted > 0 {
            note.push_str(
                " The card numbers in those are not readable. The times are, because the reply id \
                 byte sits outside the encrypted payload: REPLY_RAW is 0x50 on the wire whether or \
                 not what follows it is ciphertext. Secure Channel bought confidentiality of the \
                 credential and nothing at all of the schedule.",
            );
        } else {
            note.push_str(
                " Nothing here is encrypted, so the schedule is the least of what is exposed — but \
                 it is worth noting separately, because turning on Secure Channel will fix the \
                 card numbers and will not fix this.",
            );
        }
        note.push_str(" Presentations at: ");
        for (i, e) in events.iter().take(self.max_listed).enumerate() {
            if i > 0 {
                note.push_str(", ");
            }
            note.push_str(&fmt_us(e.t_us));
            if let Some(a) = e.address {
                note.push_str(&alloc::format!(" (addr {a:#04x})"));
            }
        }
        if events.len() > self.max_listed {
            note.push_str(&alloc::format!(
                ", and {} more",
                events.len() - self.max_listed
            ));
        }
        note.push('.');

        let cited: Vec<&Observation> = events.iter().filter_map(|e| monitor.get(e.index)).collect();

        alloc::vec![Finding::new(
            events[self.min_events - 1].t_us,
            if encrypted > 0 {
                Severity::Medium
            } else {
                Severity::Low
            },
            Signal::TrafficPatternExposed,
            Confidence::Certain,
            Evidence::new(cited, note).truncate_evenly(8),
        )]
    }
}
