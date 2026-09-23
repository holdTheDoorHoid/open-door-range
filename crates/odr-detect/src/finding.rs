//! **What a detector says, and how a learner checks it.**
//!
//! A [`Finding`] has five fields and every one of them is load-bearing:
//!
//! ```text
//! Finding { t_us, severity, what, evidence, confidence }
//!             │      │        │      │          └── how sure, and why not surer
//!             │      │        │      └───────────── which frames say so
//!             │      │        └──────────────────── a [`Signal`], not a string
//!             │      └───────────────────────────── how much it matters
//!             └──────────────────────────────────── when it could first be said
//! ```
//!
//! # Evidence is the point
//!
//! Module 5 of the curriculum asks a learner to build a rule set and then asks
//! whether the rules were *right*, not whether they fired. That question is
//! unanswerable unless every finding can be traced back to the specific frames
//! that justify it, so [`Evidence`] carries [`FrameRef`]s — index, timestamp
//! and the octets themselves — and [`Evidence::check`] re-reads them against
//! the monitor to prove the citation still holds.
//!
//! A finding with no evidence is an opinion. This crate does not emit one.
//!
//! # Confidence is where the honesty lives
//!
//! Some of the attacks in `docs/CURRICULUM.md` are visible with certainty:
//! SCBK-D announces itself in a security block byte. Some are visible but
//! ambiguous: a `CMD_KEYSET` on the wire is a fact, and whether it was an
//! installer or an attacker is not on the wire at all. Some are not visible:
//! a well-formed injected frame that fits the polling cadence and the sequence
//! numbering is indistinguishable from a real one, and the honest thing is to
//! say so in [`Confidence`] rather than to invent a rule that fires on benign
//! traffic to cover it.

use alloc::string::String;
use alloc::vec::Vec;

use odr_bus::Micros;

use crate::observe::{fmt_us, Monitor, Observation};

/// How much a finding matters, if it is true.
///
/// Severity is about impact, not about certainty — those are separate axes and
/// a rule set that conflates them cannot be tuned. A `Critical` finding with
/// `Confidence::Ambiguous` is exactly the shape of curriculum drill 5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Worth knowing, not worth waking anyone.
    Info,
    /// A weakness that needs an owner but not a night.
    Low,
    /// A weakness that materially lowers the cost of an attack.
    Medium,
    /// Either an attack in progress or a posture that makes one free.
    High,
    /// Key material or door control is exposed right now.
    Critical,
}

impl Severity {
    /// A short name for the UI.
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl core::fmt::Display for Severity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// How sure the wire allows a detector to be.
///
/// Read these as statements about *the link*, not about the code. `Ambiguous`
/// does not mean the detector is weak; it means the observable genuinely has
/// more than one cause and no amount of cleverness on this side of the
/// transceiver will separate them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// The observable is real and its cause cannot be determined from traffic.
    /// A `CMD_KEYSET` is the canonical case: the frame is unmistakable and the
    /// question "was this authorised?" is not answerable from the wire.
    Ambiguous,
    /// A benign explanation is plausible and was not excluded.
    Possible,
    /// A benign explanation exists but the specific pattern seen is much more
    /// consistent with the finding.
    Probable,
    /// The bytes say so, and nothing benign produces those bytes.
    Certain,
}

impl Confidence {
    /// A short name for the UI.
    pub fn name(self) -> &'static str {
        match self {
            Confidence::Ambiguous => "ambiguous",
            Confidence::Possible => "possible",
            Confidence::Probable => "probable",
            Confidence::Certain => "certain",
        }
    }
}

impl core::fmt::Display for Confidence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// **What was concluded.**
///
/// A closed vocabulary rather than free text, because curriculum Module 5
/// scores a rule set against an answer key and a scorer cannot compare
/// sentences. Everything variable — which address, which key, how many frames
/// — lives in [`Evidence::note`].
///
/// New variants may appear, so match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Signal {
    /// A run of OSDP traffic for one address in which no frame carried a
    /// security block. Nothing is encrypted and nothing is authenticated.
    CleartextBus,
    /// A command whose exposure is a finding in its own right crossed the bus
    /// with no security block — `CMD_OUT`, which opens a door, or `CMD_COMSET`,
    /// which moves a peripheral to another address or baud rate.
    SensitiveCommandInClear,
    /// The published default key, SCBK-D, is in use. Announced in the clear in
    /// the handshake's key-type byte, so this costs an eavesdropper nothing.
    DefaultKeyInUse,
    /// A security block of type SCS_15 or SCS_16 carried a non-empty payload:
    /// the frame is authenticated and **not** encrypted, on a link whose status
    /// display says "secure channel established".
    NullCipher,
    /// A `CMD_KEYSET` crossed the bus. The event is unmistakable; whether it
    /// was a commissioning or an attack is not on the wire.
    KeysetObserved,
    /// A peripheral that previously reported AES-128 support now reports none,
    /// at the same address and with the same reported identity.
    CapabilityDowngrade,
    /// An address that previously ran Secure Channel is now carrying unsecured
    /// traffic, and did not re-handshake.
    SecureChannelLost,
    /// The reported device identity at an address changed. Usually a reader was
    /// replaced; it is also what a downgrade looks like if the attacker
    /// bothered to rewrite `REPLY_PDID` as well.
    DeviceIdentityChanged,
    /// A frame's sequence number does not follow the two-bit cycle, and is not
    /// a legitimate retransmission.
    SequenceAnomaly,
    /// The strict command-then-reply cadence was broken: a second command
    /// arrived before the first was answered, far sooner than any retry.
    CadenceViolation,
    /// A reply arrived that no command asked for.
    UnsolicitedReply,
    /// One command drew two different replies from the same address, so two
    /// devices are answering to it.
    DuplicateAddress,
    /// A byte-identical frame carrying a payload was seen again.
    ReplayedFrame,
    /// The same credential bits were seen twice, too close together to be a
    /// person presenting a badge twice.
    ReplayedCredential,
    /// A two-wire link. There is no authentication of any kind on a D0/D1 pair,
    /// so anything driven onto it is accepted.
    UnauthenticatedWire,
    /// Bits on a two-wire link that fit no known card format with valid parity.
    MalformedCredential,
    /// The times at which people badged in are readable from the traffic,
    /// whether or not the payloads were encrypted, because the command and
    /// reply id byte is plaintext inside Secure Channel.
    TrafficPatternExposed,
}

impl Signal {
    /// Every signal this crate can emit, in declaration order.
    pub const ALL: &'static [Signal] = &[
        Signal::CleartextBus,
        Signal::SensitiveCommandInClear,
        Signal::DefaultKeyInUse,
        Signal::NullCipher,
        Signal::KeysetObserved,
        Signal::CapabilityDowngrade,
        Signal::SecureChannelLost,
        Signal::DeviceIdentityChanged,
        Signal::SequenceAnomaly,
        Signal::CadenceViolation,
        Signal::UnsolicitedReply,
        Signal::DuplicateAddress,
        Signal::ReplayedFrame,
        Signal::ReplayedCredential,
        Signal::UnauthenticatedWire,
        Signal::MalformedCredential,
        Signal::TrafficPatternExposed,
    ];

    /// A stable machine name, also used in the UI.
    pub fn name(self) -> &'static str {
        match self {
            Signal::CleartextBus => "cleartext_bus",
            Signal::SensitiveCommandInClear => "sensitive_command_in_clear",
            Signal::DefaultKeyInUse => "default_key_in_use",
            Signal::NullCipher => "null_cipher",
            Signal::KeysetObserved => "keyset_observed",
            Signal::CapabilityDowngrade => "capability_downgrade",
            Signal::SecureChannelLost => "secure_channel_lost",
            Signal::DeviceIdentityChanged => "device_identity_changed",
            Signal::SequenceAnomaly => "sequence_anomaly",
            Signal::CadenceViolation => "cadence_violation",
            Signal::UnsolicitedReply => "unsolicited_reply",
            Signal::DuplicateAddress => "duplicate_address",
            Signal::ReplayedFrame => "replayed_frame",
            Signal::ReplayedCredential => "replayed_credential",
            Signal::UnauthenticatedWire => "unauthenticated_wire",
            Signal::MalformedCredential => "malformed_credential",
            Signal::TrafficPatternExposed => "traffic_pattern_exposed",
        }
    }

    /// One sentence a learner can read without the rustdoc open.
    pub fn describe(self) -> &'static str {
        match self {
            Signal::CleartextBus => {
                "this address is being talked to with no encryption and no authentication"
            }
            Signal::SensitiveCommandInClear => {
                "a command that opens a door or moves a peripheral crossed the bus unprotected"
            }
            Signal::DefaultKeyInUse => "the secure channel is keyed with the published default key",
            Signal::NullCipher => {
                "secure channel is established and the payloads are not encrypted"
            }
            Signal::KeysetObserved => "a secure channel base key was pushed to a peripheral",
            Signal::CapabilityDowngrade => {
                "a peripheral stopped claiming AES-128 support that it previously claimed"
            }
            Signal::SecureChannelLost => {
                "an address that ran Secure Channel is now in the clear without re-handshaking"
            }
            Signal::DeviceIdentityChanged => "a different device is answering at this address",
            Signal::SequenceAnomaly => "a frame's sequence number does not follow the cycle",
            Signal::CadenceViolation => "a command arrived before the previous one was answered",
            Signal::UnsolicitedReply => "a reply arrived that no command asked for",
            Signal::DuplicateAddress => "two devices answered to the same address",
            Signal::ReplayedFrame => "a byte-identical frame carrying a payload was sent twice",
            Signal::ReplayedCredential => {
                "the same credential appeared twice, faster than a person could present it"
            }
            Signal::UnauthenticatedWire => {
                "this is a two-wire link, so anything driven onto it will be believed"
            }
            Signal::MalformedCredential => {
                "bits on the wire fit no known card format with valid parity"
            }
            Signal::TrafficPatternExposed => {
                "the building's badge-in schedule is readable from the traffic"
            }
        }
    }
}

impl core::fmt::Display for Signal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// A citation of one observation.
///
/// It carries the octets as well as the index so that a finding survives being
/// serialised away from its monitor — a drill can show the bytes next to the
/// claim — and so that [`Evidence::check`] can prove the citation still points
/// at the same traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRef {
    /// Index into the monitor's stream.
    pub index: usize,
    /// When it was seen.
    pub t_us: Micros,
    /// The octets, exactly as cited.
    pub bytes: Vec<u8>,
    /// A one-line description, as [`Observation::summary`] renders it.
    pub summary: String,
}

impl FrameRef {
    /// Cite one observation.
    pub fn of(obs: &Observation) -> FrameRef {
        FrameRef {
            index: obs.index,
            t_us: obs.t_us,
            bytes: obs.bytes.clone(),
            summary: obs.summary(),
        }
    }

    /// True if this citation still names the same bytes in `monitor`.
    pub fn holds(&self, monitor: &Monitor) -> bool {
        monitor
            .get(self.index)
            .is_some_and(|o| o.t_us == self.t_us && o.bytes == self.bytes)
    }
}

/// Why a detector concluded what it did.
///
/// `refs` are the frames that justify the finding and `note` is the reasoning
/// in one or two sentences — including, where it applies, the benign
/// explanation that was considered and why it was or was not excluded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Evidence {
    /// The frames that justify the finding.
    pub refs: Vec<FrameRef>,
    /// The reasoning, for a learner reading the finding on its own.
    pub note: String,
}

impl Evidence {
    /// Evidence from a list of observations and a note.
    pub fn new<'a, I>(observations: I, note: impl Into<String>) -> Evidence
    where
        I: IntoIterator<Item = &'a Observation>,
    {
        Evidence {
            refs: observations.into_iter().map(FrameRef::of).collect(),
            note: note.into(),
        }
    }

    /// Evidence from a single observation.
    pub fn one(obs: &Observation, note: impl Into<String>) -> Evidence {
        Evidence {
            refs: alloc::vec![FrameRef::of(obs)],
            note: note.into(),
        }
    }

    /// True if every citation still holds against `monitor`.
    ///
    /// A finding whose evidence does not check out is a bug in the detector,
    /// and the test suite asserts this for every finding every rule set
    /// produces.
    pub fn check(&self, monitor: &Monitor) -> bool {
        !self.refs.is_empty() && self.refs.iter().all(|r| r.holds(monitor))
    }

    /// Keep at most `n` citations, first and last preferred.
    ///
    /// A posture finding about a four-hour cleartext run should not carry
    /// fourteen thousand frames. It should carry the first, the last, and
    /// enough in between to show the run was continuous.
    pub fn truncate_evenly(mut self, n: usize) -> Evidence {
        if n == 0 || self.refs.len() <= n {
            return self;
        }
        let total = self.refs.len();
        let mut kept = Vec::with_capacity(n);
        for i in 0..n {
            // Spread the kept indices across the range, ends included.
            let pick = if n == 1 { 0 } else { i * (total - 1) / (n - 1) };
            if kept.last().map(|r: &FrameRef| r.index) != Some(self.refs[pick].index) {
                kept.push(self.refs[pick].clone());
            }
        }
        self.refs = kept;
        self
    }
}

/// **One conclusion, with its reasoning attached.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The earliest moment at which this could have been said.
    ///
    /// Not the moment the attack started — the moment the *evidence* was
    /// complete. The difference between the two is what
    /// [`Score::time_to_detect_us`](crate::Score::time_to_detect_us) measures,
    /// and it is the most useful number Module 5 produces.
    pub t_us: Micros,
    /// How much it matters.
    pub severity: Severity,
    /// What was concluded.
    pub what: Signal,
    /// Which frames say so, and the reasoning.
    pub evidence: Evidence,
    /// How sure the wire allows the detector to be.
    pub confidence: Confidence,
}

impl Finding {
    /// Build a finding.
    pub fn new(
        t_us: Micros,
        severity: Severity,
        what: Signal,
        confidence: Confidence,
        evidence: Evidence,
    ) -> Finding {
        Finding {
            t_us,
            severity,
            what,
            evidence,
            confidence,
        }
    }

    /// A one-line rendering, in the register the findings list uses.
    pub fn summary(&self) -> String {
        alloc::format!(
            "{} [{}/{}] {} ({} frames cited)",
            fmt_us(self.t_us),
            self.severity.name(),
            self.confidence.name(),
            self.what.name(),
            self.evidence.refs.len()
        )
    }

    /// The finding and its reasoning, for a drill's findings panel.
    pub fn explain(&self) -> String {
        let mut s = self.summary();
        s.push_str("\n  ");
        s.push_str(self.what.describe());
        if !self.evidence.note.is_empty() {
            s.push_str("\n  ");
            s.push_str(&self.evidence.note);
        }
        for r in &self.evidence.refs {
            s.push_str("\n    ");
            s.push_str(&r.summary);
        }
        s
    }
}

/// Everything a rule set concluded about one capture.
///
/// Findings are sorted by time, then by signal, then by index of the first
/// cited frame, so the same capture always produces the same report — which is
/// what makes a score reproducible from a seed (`DESIGN.md` §3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    findings: Vec<Finding>,
}

impl Report {
    /// Collect findings into a report, in the canonical order.
    pub fn new(mut findings: Vec<Finding>) -> Report {
        findings.sort_by(|a, b| {
            a.t_us
                .cmp(&b.t_us)
                .then(a.what.cmp(&b.what))
                .then(
                    a.evidence
                        .refs
                        .first()
                        .map(|r| r.index)
                        .cmp(&b.evidence.refs.first().map(|r| r.index)),
                )
                .then(b.severity.cmp(&a.severity))
        });
        Report { findings }
    }

    /// Every finding, in order.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// How many findings there are.
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// True if the rule set concluded nothing.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Findings carrying one signal.
    pub fn of(&self, signal: Signal) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.what == signal)
    }

    /// True if any finding carries this signal.
    pub fn fired(&self, signal: Signal) -> bool {
        self.of(signal).next().is_some()
    }

    /// The earliest finding carrying one signal.
    pub fn first_of(&self, signal: Signal) -> Option<&Finding> {
        self.of(signal).next()
    }

    /// Findings at or above a severity.
    pub fn at_least(&self, severity: Severity) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.severity >= severity)
    }

    /// True if every finding's evidence still checks out against `monitor`.
    pub fn evidence_checks(&self, monitor: &Monitor) -> bool {
        self.findings.iter().all(|f| f.evidence.check(monitor))
    }

    /// The whole report, one finding per line with its reasoning indented.
    pub fn explain(&self) -> String {
        let mut s = String::new();
        for f in &self.findings {
            s.push_str(&f.explain());
            s.push('\n');
        }
        if s.is_empty() {
            s.push_str("no findings\n");
        }
        s
    }

    /// Consume the report, handing back the findings.
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

impl core::fmt::Display for Report {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for finding in &self.findings {
            f.write_str(&finding.summary())?;
            f.write_str("\n")?;
        }
        Ok(())
    }
}

/// A short human label for a peripheral address, for evidence notes.
pub(crate) fn addr_label(address: u8) -> String {
    alloc::format!("{address:#04x}")
}
