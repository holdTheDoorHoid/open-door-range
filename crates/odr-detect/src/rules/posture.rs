//! **Cleartext bus — the finding that is a posture statement, not an event.**
//!
//! Nothing happens here. No attack is in progress. A run of OSDP traffic in
//! which no frame carries a security block simply means every card number, every
//! door command and every status byte on that link is legible to anyone who can
//! reach the cable, and will remain so until somebody changes a setting.
//!
//! That is why the finding's timestamp is not the moment an attack began: it is
//! the moment the monitor had seen enough frames to say the link is like this
//! and not merely quiet.
//!
//! # The benign case it must not fire on
//!
//! **A bus that is secured, with one legacy peripheral on it.** Curriculum 5.2
//! adds a genuinely legacy reader to a hardened bus; the controller talks to it
//! in the clear and to everything else securely. A detector that looked at the
//! link as a whole would either miss the legacy reader entirely or condemn the
//! whole bus. This one works **per address**, so it reports exactly the one
//! peripheral whose traffic is exposed and says nothing about the others.

use alloc::vec::Vec;

use odr_bus::Micros;
use odr_osdp::payload::{ComsetCommand, OutputCommand};
use odr_osdp::Command;

use crate::detector::Detector;
use crate::finding::{addr_label, Confidence, Evidence, Finding, Severity, Signal};
use crate::observe::{fmt_us, Monitor, Observation};
use crate::rules::DEFAULT_GAP_US;

/// How the posture rule is tuned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostureDetector {
    /// How many unsecured frames for one address before the run is called.
    ///
    /// A handshake's own first frames are unsecured, and so are the `ID` and
    /// `CAP` exchange that precedes one, so a threshold of one or two would
    /// report every properly secured link on the planet.
    pub min_frames: usize,
    /// A silence longer than this ends a run.
    pub gap_us: Micros,
    /// How many frames to cite.
    pub max_evidence: usize,
}

impl Default for PostureDetector {
    fn default() -> PostureDetector {
        PostureDetector {
            min_frames: 8,
            gap_us: DEFAULT_GAP_US,
            max_evidence: 6,
        }
    }
}

impl PostureDetector {
    /// A posture detector with the default tuning.
    pub fn new() -> PostureDetector {
        PostureDetector::default()
    }

    /// Every maximal run of unsecured frames for one address.
    ///
    /// A run ends at a secured frame or at a silence longer than
    /// [`PostureDetector::gap_us`].
    fn cleartext_runs<'a>(&self, frames: &[&'a Observation]) -> Vec<Vec<&'a Observation>> {
        let mut runs = Vec::new();
        let mut current: Vec<&Observation> = Vec::new();
        let mut last_t: Option<Micros> = None;
        for o in frames {
            let gapped = last_t.is_some_and(|t| o.t_us.saturating_sub(t) > self.gap_us);
            if o.has_security_block() || gapped {
                if !current.is_empty() {
                    runs.push(core::mem::take(&mut current));
                }
                if !o.has_security_block() {
                    current.push(o);
                }
            } else {
                current.push(o);
            }
            last_t = Some(o.t_us);
        }
        if !current.is_empty() {
            runs.push(current);
        }
        runs
    }
}

impl Detector for PostureDetector {
    fn name(&self) -> &str {
        "posture"
    }

    fn signals(&self) -> &'static [Signal] {
        &[Signal::CleartextBus, Signal::SensitiveCommandInClear]
    }

    fn rationale(&self) -> &'static str {
        "per address, a run of frames with no security block means that peripheral's traffic is \
         readable and forgeable; reported per address so one legacy reader does not condemn a \
         secured bus"
    }

    fn run(&self, monitor: &Monitor) -> Vec<Finding> {
        let mut out = Vec::new();
        for address in monitor.addresses() {
            let frames: Vec<&Observation> = monitor
                .for_address(address)
                .filter(|o| o.frame.is_some())
                .collect();

            for run in self.cleartext_runs(&frames) {
                if run.len() < self.min_frames {
                    continue;
                }
                // The earliest moment the claim could honestly be made.
                let called_at = run[self.min_frames - 1].t_us;
                let span = run[run.len() - 1].t_us.saturating_sub(run[0].t_us);
                let readable_reads = run
                    .iter()
                    .filter(|o| o.reply().is_some_and(|r| r.is_credential_event()))
                    .count();
                let mut note = alloc::format!(
                    "address {}: {} consecutive frames over {} carried no security block, so \
                     nothing on this link is encrypted or authenticated.",
                    addr_label(address),
                    run.len(),
                    fmt_us(span)
                );
                if readable_reads > 0 {
                    note.push_str(&alloc::format!(
                        " {readable_reads} of them report a credential, in the clear."
                    ));
                }
                note.push_str(
                    " Nothing here is an attack; this is what the link is configured to be.",
                );
                out.push(Finding::new(
                    called_at,
                    Severity::High,
                    Signal::CleartextBus,
                    Confidence::Certain,
                    Evidence::new(run.iter().copied(), note).truncate_evenly(self.max_evidence),
                ));
            }

            out.extend(self.sensitive_commands(monitor, address));
        }
        out
    }
}

impl PostureDetector {
    /// `CMD_OUT` and `CMD_COMSET` crossing the bus with no security block.
    ///
    /// `CMD_KEYSET` is the third member of
    /// [`Command::is_sensitive`](odr_osdp::Command::is_sensitive) and is left to
    /// [`KeysetDetector`](crate::rules::KeysetDetector), which has more to say
    /// about it than "this was in the clear".
    ///
    /// One finding per address, citing up to [`PostureDetector::max_evidence`]
    /// instances and counting the rest, because a cleartext bus with a busy door
    /// would otherwise produce one alert per badge-in for ever.
    fn sensitive_commands(&self, monitor: &Monitor, address: u8) -> Vec<Finding> {
        let hits: Vec<&Observation> = monitor
            .for_address(address)
            .filter(|o| {
                !o.has_security_block()
                    && matches!(o.command(), Some(Command::Out) | Some(Command::Comset))
            })
            .collect();
        let first = match hits.first() {
            Some(f) => *f,
            None => return Vec::new(),
        };

        let opens = hits
            .iter()
            .filter(|o| o.command() == Some(Command::Out))
            .count();
        let moves = hits.len() - opens;
        let mut note = alloc::format!(
            "address {}: {} unprotected command(s) that change physical state — {opens} \
             CMD_OUT, {moves} CMD_COMSET.",
            addr_label(address),
            hits.len()
        );
        if let Some(out) = first
            .frame
            .as_ref()
            .filter(|f| f.command_code() == Some(Command::Out))
            .and_then(|f| OutputCommand::decode(&f.payload).ok())
        {
            note.push_str(&alloc::format!(
                " The first drives output {} with control code {:#04x}; an attacker who can \
                 transmit can send exactly these bytes.",
                out.output,
                out.control_code
            ));
        }
        if let Some(com) = first
            .frame
            .as_ref()
            .filter(|f| f.command_code() == Some(Command::Comset))
            .and_then(|f| ComsetCommand::decode(&f.payload).ok())
        {
            note.push_str(&alloc::format!(
                " The first moves the peripheral to address {:#04x} at {} baud.",
                com.address,
                com.baud_rate
            ));
        }

        alloc::vec![Finding::new(
            first.t_us,
            if opens > 0 {
                Severity::Critical
            } else {
                Severity::High
            },
            Signal::SensitiveCommandInClear,
            Confidence::Certain,
            Evidence::new(hits.iter().copied(), note).truncate_evenly(self.max_evidence),
        )]
    }
}
