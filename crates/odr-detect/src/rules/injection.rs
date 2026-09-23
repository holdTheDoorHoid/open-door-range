//! **Injected frames — and the honest admission that some of them are
//! invisible.**
//!
//! An attacker's frame on an unsecured bus is, byte for byte, a frame. There is
//! no origin field, no signature, no per-device secret; OSDP outside Secure
//! Channel authenticates nothing at all. So the question is never "is this
//! frame forged" — that is unanswerable — but "**did the conversation stop
//! making sense**".
//!
//! Three things can stop making sense, and all three are protocol facts rather
//! than statistics:
//!
//! * **Sequence numbers.** Two bits, cycling 1, 2, 3, with 0 meaning reset. A
//!   frame whose sequence neither continues the cycle nor legitimately repeats
//!   the last one is [`Signal::SequenceAnomaly`].
//! * **Cadence.** OSDP is strictly half duplex with one master: a command, then
//!   its reply, then the next command. A second command arriving before the
//!   first was answered, far too soon to be a retry, is
//!   [`Signal::CadenceViolation`].
//! * **Who is allowed to speak.** A peripheral may only speak when polled. A
//!   reply with no outstanding command is [`Signal::UnsolicitedReply`]; two
//!   different replies to one command means two devices are answering to one
//!   address, which is [`Signal::DuplicateAddress`] and is the clearest
//!   spoofing signature on the list.
//!
//! # What this detector cannot see, and says so
//!
//! **A well-formed frame injected into a gap, with the sequence number the
//! conversation expected, is indistinguishable from a real one.** Not hard to
//! spot — *indistinguishable*: the bytes a legitimate controller would have
//! sent and the bytes the attacker sent are the same bytes. No confidence
//! level covers this, so the detector emits nothing, and the test suite
//! contains a test that asserts exactly that silence. A rule that fired anyway
//! would be firing on the shape of ordinary traffic.
//!
//! The defensive conclusion is the one the Mellon paper reaches: on an
//! unsecured bus, injection is not a detection problem. It is a "turn on
//! Secure Channel" problem.
//!
//! # The benign cases it must not fire on
//!
//! * **A retransmission.** A controller that times out resends the same frame
//!   with the same sequence number. That is legitimate, and only counts as an
//!   anomaly if the first copy was already answered.
//! * **A sequence reset.** Sequence 0 means "start again" and is how a link
//!   recovers, which is exactly what a reader power-cycling produces.
//! * **A peripheral that has gone offline.** Every poll goes unanswered, at the
//!   poll interval. Only commands arriving *faster* than any retry — inside
//!   [`InjectionDetector::min_command_gap_us`] — count as a cadence violation.
//! * **A silence.** Continuity cannot be asserted across a gap, so all of this
//!   state resets after [`InjectionDetector::gap_us`].

use alloc::vec::Vec;

use odr_bus::Micros;

use crate::detector::Detector;
use crate::finding::{addr_label, Confidence, Evidence, Finding, Severity, Signal};
use crate::observe::{fmt_us, Monitor, Observation};
use crate::rules::DEFAULT_GAP_US;

/// Injection detection from cadence, sequence and who speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InjectionDetector {
    /// Two commands closer together than this, with no reply between them, are
    /// not a controller retrying.
    ///
    /// 20 ms by default: an order of magnitude below any realistic reply
    /// timeout, so a lost reply on a noisy line does not look like an
    /// injection.
    pub min_command_gap_us: Micros,
    /// A silence longer than this resets every continuity rule.
    pub gap_us: Micros,
    /// Cap on findings of each kind, so a thoroughly broken link reports a
    /// problem rather than ten thousand of them.
    pub max_per_kind: usize,
}

impl Default for InjectionDetector {
    fn default() -> InjectionDetector {
        InjectionDetector {
            min_command_gap_us: 20_000,
            gap_us: DEFAULT_GAP_US,
            max_per_kind: 8,
        }
    }
}

impl InjectionDetector {
    /// An injection detector with the default tuning.
    pub fn new() -> InjectionDetector {
        InjectionDetector::default()
    }
}

/// The next sequence number in OSDP's two-bit cycle.
///
/// 1, 2, 3, 1, … — zero is not part of the cycle, it is the reset value.
fn next_sequence(current: u8) -> u8 {
    match current & 0x03 {
        3 => 1,
        other => other + 1,
    }
}

/// What the monitor believes about one address's conversation right now.
#[derive(Debug, Clone, Default)]
struct Conversation<'a> {
    /// The last command seen, and whether anything has answered it.
    pending: Option<&'a Observation>,
    /// The reply to the pending command, once one arrives.
    answered_by: Option<&'a Observation>,
    /// The last command's sequence number.
    last_sequence: Option<u8>,
    /// When the last frame for this address was seen.
    last_t_us: Option<Micros>,
}

impl<'a> Conversation<'a> {
    /// Forget everything. A silence is not evidence.
    fn reset(&mut self) {
        self.pending = None;
        self.answered_by = None;
        self.last_sequence = None;
    }
}

impl Detector for InjectionDetector {
    fn name(&self) -> &str {
        "injection"
    }

    fn signals(&self) -> &'static [Signal] {
        &[
            Signal::SequenceAnomaly,
            Signal::CadenceViolation,
            Signal::UnsolicitedReply,
            Signal::DuplicateAddress,
        ]
    }

    fn rationale(&self) -> &'static str {
        "the sequence cycle, the strict command-then-reply cadence, and the rule that a \
         peripheral only speaks when polled; a frame that fits all three is indistinguishable \
         from a legitimate one and is deliberately not reported"
    }

    fn run(&self, monitor: &Monitor) -> Vec<Finding> {
        let mut out = Vec::new();
        for address in monitor.addresses() {
            out.extend(self.walk(monitor, address));
        }
        out
    }
}

impl InjectionDetector {
    fn walk<'a>(&self, monitor: &'a Monitor, address: u8) -> Vec<Finding> {
        let frames: Vec<&'a Observation> = monitor
            .for_address(address)
            .filter(|o| o.frame.is_some())
            .collect();
        let mut conv = Conversation::default();
        let mut out: Vec<Finding> = Vec::new();
        let mut counts = [0usize; 4];

        for o in frames {
            if conv
                .last_t_us
                .is_some_and(|t| o.t_us.saturating_sub(t) > self.gap_us)
            {
                conv.reset();
            }
            conv.last_t_us = Some(o.t_us);

            if o.is_command() {
                self.on_command(address, o, &mut conv, &mut out, &mut counts);
            } else if o.is_reply() {
                self.on_reply(address, o, &mut conv, &mut out, &mut counts);
            }
        }
        out
    }

    fn on_command<'a>(
        &self,
        address: u8,
        o: &'a Observation,
        conv: &mut Conversation<'a>,
        out: &mut Vec<Finding>,
        counts: &mut [usize; 4],
    ) {
        let seq = o.sequence().unwrap_or(0);

        // Cadence: a second command before the first was answered, sooner than
        // any controller would retry.
        if let Some(previous) = conv.pending {
            if conv.answered_by.is_none() {
                let gap = o.t_us.saturating_sub(previous.t_us);
                let same_frame = previous.bytes == o.bytes;
                if gap < self.min_command_gap_us && !same_frame && counts[1] < self.max_per_kind {
                    counts[1] += 1;
                    out.push(Finding::new(
                        o.t_us,
                        Severity::High,
                        Signal::CadenceViolation,
                        Confidence::Probable,
                        Evidence::new(
                            [previous, o],
                            alloc::format!(
                                "address {}: a second, different command arrived {} after the \
                                 previous one, which nothing had answered. OSDP is half duplex \
                                 with one master: the controller waits for a reply or for its \
                                 timeout, and no realistic timeout is under {}. Either two things \
                                 are driving this bus as a controller, or the reply was destroyed.",
                                addr_label(address),
                                fmt_us(gap),
                                fmt_us(self.min_command_gap_us)
                            ),
                        ),
                    ));
                }
            }
        }

        // Sequence: does this continue the cycle?
        if let Some(last) = conv.last_sequence {
            let expected = next_sequence(last);
            let is_reset = seq == 0;
            let is_retransmission = seq == last && conv.answered_by.is_none();
            if seq != expected && !is_reset && !is_retransmission && counts[0] < self.max_per_kind {
                counts[0] += 1;
                let mut note = alloc::format!(
                    "address {}: sequence {seq} where {expected} was due, following {last}. \
                     Sequence numbers cycle 1, 2, 3 and a repeat is only legitimate as a \
                     retransmission of a command that was never answered.",
                    addr_label(address)
                );
                if seq == last {
                    note.push_str(
                        " This repeats the previous sequence number, and the previous command was \
                         already answered, so it is not a retransmission.",
                    );
                }
                note.push_str(
                    " Two bits of sequence is not an anti-replay measure and was never meant to \
                     be one; this is a consistency check, not a security control.",
                );
                let evidence = match conv.pending {
                    Some(p) => Evidence::new([p, o], note),
                    None => Evidence::one(o, note),
                };
                out.push(Finding::new(
                    o.t_us,
                    Severity::Medium,
                    Signal::SequenceAnomaly,
                    Confidence::Probable,
                    evidence,
                ));
            }
        }

        conv.pending = Some(o);
        conv.answered_by = None;
        conv.last_sequence = Some(seq);
    }

    fn on_reply<'a>(
        &self,
        address: u8,
        o: &'a Observation,
        conv: &mut Conversation<'a>,
        out: &mut Vec<Finding>,
        counts: &mut [usize; 4],
    ) {
        match (conv.pending, conv.answered_by) {
            (Some(command), Some(first)) => {
                // A second answer to one command. If the two answers differ,
                // two devices are talking.
                if first.bytes != o.bytes && counts[3] < self.max_per_kind {
                    counts[3] += 1;
                    out.push(Finding::new(
                        o.t_us,
                        Severity::High,
                        Signal::DuplicateAddress,
                        Confidence::Probable,
                        Evidence::new(
                            [command, first, o],
                            alloc::format!(
                                "address {}: one command drew two different replies, {} apart. A \
                                 peripheral answers a command once. Two different answers means \
                                 two devices believe they are this address — a second reader \
                                 miswired onto the bus, or something impersonating the one that \
                                 is there.",
                                addr_label(address),
                                fmt_us(o.t_us.saturating_sub(first.t_us))
                            ),
                        ),
                    ));
                } else if counts[2] < self.max_per_kind {
                    counts[2] += 1;
                    out.push(Finding::new(
                        o.t_us,
                        Severity::Medium,
                        Signal::UnsolicitedReply,
                        Confidence::Probable,
                        Evidence::new(
                            [command, first, o],
                            alloc::format!(
                                "address {}: this reply repeats an answer that had already been \
                                 given to the same command. A peripheral speaks once per poll.",
                                addr_label(address)
                            ),
                        ),
                    ));
                }
            }
            (Some(_), None) => {
                conv.answered_by = Some(o);
            }
            (None, _) => {
                if counts[2] < self.max_per_kind {
                    counts[2] += 1;
                    out.push(Finding::new(
                        o.t_us,
                        Severity::High,
                        Signal::UnsolicitedReply,
                        Confidence::Probable,
                        Evidence::one(
                            o,
                            alloc::format!(
                                "address {}: a reply with no command outstanding. A peripheral may \
                                 only speak when it is polled, so either the command that asked \
                                 for this was not on this segment of the bus, or nothing asked.",
                                addr_label(address)
                            ),
                        ),
                    ));
                }
            }
        }
    }
}
