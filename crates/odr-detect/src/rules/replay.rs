//! **Replay — where the false positive is a person, and where a promising rule
//! turned out to be wrong.**
//!
//! Replay detection is the rule most likely to be built badly, because the
//! naive version works perfectly on a test bench and is unusable in a building.
//! "The same card number appeared twice" is not an attack. It is Tuesday. People
//! badge in, the door does not open because they pushed instead of pulling,
//! they badge again. A rule that alerts on that will be turned off within a
//! week, and then it will not be there for the real one either.
//!
//! # The rule this module started with, and why it is not here
//!
//! The obvious rule is: *a byte-identical OSDP frame is a replay, because two
//! genuine reads produce different frames — the sequence number advances.* It
//! is wrong, and running it against a generated day is what showed it. **The
//! sequence number is two bits.** It cycles 1, 2, 3, so one badge-in in three
//! lands on the same value as the last one, and two genuine reads of the same
//! card four seconds apart are then byte-for-byte identical, CRC included. The
//! naive rule fires on a third of all re-badges, and a reader power-cycling
//! re-issues an identical `REPLY_PDID` for the same reason.
//!
//! Two bits of sequence was never an anti-replay measure and this is what that
//! costs a defender. So the rule here is narrower and it is about the
//! *conversation* rather than the bytes:
//!
//! # 1. Was the *frame* replayed?
//!
//! [`Signal::ReplayedFrame`] fires on a reply that is byte-identical to an
//! earlier one **and that nothing asked for** — either no command preceded it
//! at that address, or the command that did had already been answered. A
//! peripheral speaks once per poll, so a byte-identical second answer is a
//! recording being played back, and a retransmission or a re-issued `CMD_ID`
//! is not, because each of those answers a command of its own.
//!
//! Commands are deliberately **not** covered. A replayed `CMD_OUT` on an
//! unsecured bus is byte-for-byte what the controller itself sends to open the
//! door, arrives where the controller's own command would arrive, and is
//! answered the same way. There is no observable that separates them, and
//! `README.md` lists it among the things this crate cannot detect.
//!
//! # 2. Was the *credential* replayed?
//!
//! On a Wiegand pair there is no sequence number, no CRC and no frame — just
//! the bits. A replayed badge and a re-badged badge are **the same bits**, and
//! the only thing separating them is time. [`ReplayDetector::human_min_us`] is
//! that threshold, and it is a claim about hands rather than a fact about the
//! protocol, which is why the wire-side finding is only
//! [`Confidence::Possible`].
//!
//! The teaching point is the asymmetry. On OSDP the protocol gives you a
//! conversation to check the frame against. On Wiegand it gives you nothing, so
//! the same attack drops to a judgement call about how fast a person can wave a
//! card twice — and a patient attacker who waits a second is simply not
//! detectable at all.

use alloc::vec::Vec;

use odr_bus::Micros;
use odr_osdp::{RawCardRead, Reply};
use odr_wiegand::BitVec;

use crate::detector::Detector;
use crate::finding::{Confidence, Evidence, Finding, Severity, Signal};
use crate::observe::{fmt_us, Monitor, Observation};

/// One credential seen crossing a link, whichever kind of link it was.
///
/// Public because a drill wants the list as much as the detector does: the
/// defensive half of curriculum 4.1 is exactly "report the times of every
/// badge-in", and this is that list with the bits attached where they were
/// legible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEvent {
    /// Index into the monitor's stream.
    pub index: usize,
    /// When.
    pub t_us: Micros,
    /// The peripheral address, for a bus event.
    pub address: Option<u8>,
    /// The bits, where they were readable. `None` means the payload was
    /// encrypted — the event is still visible, the credential is not.
    pub bits: Option<BitVec>,
}

/// Every credential this monitor could read off the link.
///
/// Encrypted card reads are **not** here; see
/// [`badge_events`](crate::rules::badge_events) for the list that includes
/// them, which is the one curriculum 4.1 is about.
pub fn credential_events(monitor: &Monitor) -> Vec<CredentialEvent> {
    let mut out = Vec::new();
    for o in monitor.observations() {
        if o.is_wire() {
            if let Some(bits) = &o.bits {
                out.push(CredentialEvent {
                    index: o.index,
                    t_us: o.t_us,
                    address: None,
                    bits: Some(bits.clone()),
                });
            }
            continue;
        }
        if o.reply() != Some(Reply::Raw) || o.is_encrypted() {
            continue;
        }
        let bits = o
            .frame
            .as_ref()
            .and_then(|f| RawCardRead::decode(&f.payload).ok())
            .map(|r| BitVec::from_bools(&r.bits()));
        if let Some(bits) = bits {
            out.push(CredentialEvent {
                index: o.index,
                t_us: o.t_us,
                address: o.address(),
                bits: Some(bits),
            });
        }
    }
    out
}

/// For every observation, whether it is a reply that nothing asked for.
///
/// A peripheral may only speak when polled, so a reply is *solicited* if a
/// command to the same address precedes it and has not already been answered.
/// This is the discriminator that separates a played-back recording from a
/// legitimate repeat, and it is the only one that survives two-bit sequence
/// numbers.
pub fn unsolicited_replies(monitor: &Monitor) -> Vec<bool> {
    let mut flags = alloc::vec![false; monitor.len()];
    for address in monitor.addresses() {
        // Before any command has been seen, nothing is outstanding.
        let mut answered = true;
        for o in monitor.for_address(address).filter(|o| o.frame.is_some()) {
            if o.is_command() {
                answered = false;
            } else if o.is_reply() {
                if answered {
                    if let Some(slot) = flags.get_mut(o.index) {
                        *slot = true;
                    }
                }
                answered = true;
            }
        }
    }
    flags
}

/// Replay detection, at the frame level and at the credential level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayDetector {
    /// How far back to look for a byte-identical frame.
    pub frame_window_us: Micros,
    /// How far back to look for the same credential.
    pub credential_window_us: Micros,
    /// Below this interval, two identical credentials were not presented by a
    /// person twice.
    ///
    /// 800 ms by default, which is a claim about hands rather than about
    /// protocols. It is a field because a turnstile, a mantrap and a loading
    /// door all behave differently, and the person running the range knows
    /// their building better than this crate does.
    pub human_min_us: Micros,
    /// Cap on findings of each kind.
    pub max_per_kind: usize,
}

impl Default for ReplayDetector {
    fn default() -> ReplayDetector {
        ReplayDetector {
            frame_window_us: 30_000_000,
            credential_window_us: 30_000_000,
            human_min_us: 800_000,
            max_per_kind: 8,
        }
    }
}

impl ReplayDetector {
    /// A replay detector with the default tuning.
    pub fn new() -> ReplayDetector {
        ReplayDetector::default()
    }
}

impl Detector for ReplayDetector {
    fn name(&self) -> &str {
        "replay"
    }

    fn signals(&self) -> &'static [Signal] {
        &[Signal::ReplayedFrame, Signal::ReplayedCredential]
    }

    fn rationale(&self) -> &'static str {
        "a reply that is byte-identical to an earlier one and that no outstanding command asked \
         for; and the same credential twice inside the time a person needs to present a badge \
         twice — badging twice at a normal pace is not reported, and neither is a replayed command"
    }

    fn run(&self, monitor: &Monitor) -> Vec<Finding> {
        let unsolicited = unsolicited_replies(monitor);
        let mut out = self.repeated_frames(monitor, &unsolicited);
        out.extend(self.repeated_credentials(monitor, &unsolicited));
        out
    }
}

impl ReplayDetector {
    /// Byte-identical replies that nothing asked for.
    fn repeated_frames(&self, monitor: &Monitor, unsolicited: &[bool]) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut count = 0usize;
        for address in monitor.addresses() {
            let replies: Vec<&Observation> = monitor
                .for_address(address)
                .filter(|o| {
                    o.is_reply()
                        && o.frame.as_ref().is_some_and(|f| !f.payload.is_empty())
                        && !is_uninformative(o)
                })
                .collect();
            for (i, later) in replies.iter().enumerate() {
                if !unsolicited.get(later.index).copied().unwrap_or(false) {
                    continue;
                }
                for earlier in replies[..i].iter().rev() {
                    if later.t_us.saturating_sub(earlier.t_us) > self.frame_window_us {
                        break;
                    }
                    if earlier.bytes != later.bytes {
                        continue;
                    }
                    if count >= self.max_per_kind {
                        return out;
                    }
                    count += 1;
                    out.push(Finding::new(
                        later.t_us,
                        Severity::High,
                        Signal::ReplayedFrame,
                        Confidence::Probable,
                        Evidence::new(
                            [*earlier, *later],
                            alloc::format!(
                                "these two replies are byte-identical, {} apart, and nothing \
                                 asked for the second one — the command it should be answering \
                                 had already been answered. A peripheral speaks once per poll, so \
                                 a second, identical answer is the earlier frame put back on the \
                                 wire. Byte-identical on its own would prove nothing: the sequence \
                                 number is two bits, so one genuine repeat in three is identical \
                                 too.",
                                fmt_us(later.t_us.saturating_sub(earlier.t_us))
                            ),
                        ),
                    ));
                    break;
                }
            }
        }
        out
    }

    /// The same credential twice, faster than a person — or in a frame nothing
    /// asked for.
    fn repeated_credentials(&self, monitor: &Monitor, unsolicited: &[bool]) -> Vec<Finding> {
        let events = credential_events(monitor);
        let mut out = Vec::new();
        let mut count = 0usize;

        for (i, later) in events.iter().enumerate() {
            let later_bits = match &later.bits {
                Some(b) => b,
                None => continue,
            };
            for earlier in events[..i].iter().rev() {
                let gap = later.t_us.saturating_sub(earlier.t_us);
                if gap > self.credential_window_us {
                    break;
                }
                if earlier.bits.as_ref() != Some(later_bits) {
                    continue;
                }

                let a = match monitor.get(earlier.index) {
                    Some(o) => o,
                    None => continue,
                };
                let b = match monitor.get(later.index) {
                    Some(o) => o,
                    None => continue,
                };
                let played_back = a.bytes == b.bytes
                    && b.is_bus()
                    && unsolicited.get(b.index).copied().unwrap_or(false);

                // A played-back frame is conclusive whatever the interval.
                // Otherwise the only thing to go on is whether a person could
                // have done it, and a slower repeat is somebody badging twice.
                if !played_back && gap >= self.human_min_us {
                    break;
                }
                if count >= self.max_per_kind {
                    return out;
                }
                count += 1;

                let (severity, confidence, note) = if played_back {
                    (
                        Severity::High,
                        Confidence::Probable,
                        alloc::format!(
                            "the same credential appeared twice, {} apart, in two byte-identical \
                             frames — and nothing polled for the second one. The peripheral had \
                             already answered the outstanding command, so this is a recording of \
                             the first read being played back rather than a second read.",
                            fmt_us(gap)
                        ),
                    )
                } else if b.is_wire() {
                    (
                        Severity::Medium,
                        Confidence::Possible,
                        alloc::format!(
                            "the same {} bits appeared twice, {} apart, on a two-wire link. There \
                             is no sequence number, no CRC and no conversation on a D0/D1 pair, \
                             so a replayed badge and a re-badged badge are the same bits and only \
                             the interval separates them. This is faster than a person presenting \
                             a card twice, which is the whole of the reasoning — a slower repeat \
                             is not reported at all, because it is somebody badging twice, and an \
                             attacker who waits a second is not detectable here.",
                            later_bits.len(),
                            fmt_us(gap)
                        ),
                    )
                } else {
                    (
                        Severity::Medium,
                        Confidence::Possible,
                        alloc::format!(
                            "the same credential appeared twice, {} apart, in two frames that are \
                             not byte-identical. The interval is shorter than a person needs to \
                             present a badge twice, but the frames differ and the second answers \
                             a poll of its own, so this could also be a reader retrying a read it \
                             was not sure of.",
                            fmt_us(gap)
                        ),
                    )
                };

                out.push(Finding::new(
                    later.t_us,
                    severity,
                    Signal::ReplayedCredential,
                    confidence,
                    Evidence::new([a, b], note),
                ));
                break;
            }
        }
        out
    }
}

/// True for replies whose repetition carries no information.
///
/// `ACK` and `BUSY` repeat by design — a polling loop is nothing but repetition
/// — and reporting those would bury every real finding.
fn is_uninformative(o: &Observation) -> bool {
    matches!(o.reply(), Some(Reply::Ack) | Some(Reply::Busy))
}
