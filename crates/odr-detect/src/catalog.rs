//! **The rule catalogue: the parts a learner composes a rule set out of.**
//!
//! `docs/CURRICULUM.md` drill 5.2 says *build* a detection rule, not *pick*
//! one:
//!
//! > Build a detection rule that catches the downgrade and does not fire on a
//! > genuine legacy reader being added to the bus.
//!
//! [`RuleSet`] is a list of trait objects, which is the right
//! shape for running detectors and the wrong shape for a learner to hold: it
//! cannot be named, serialised, compared to a preset, or drawn as a form. This
//! module is the shape that can. A [`RuleSpec`] is a **description** of one
//! selectable rule — a stable id, a label, one line on what it catches, one
//! line on what it will false-positive on, and its tunable parameters with
//! their legal ranges. [`RuleSetSpec`] is a learner's composition of them, and
//! [`RuleSetSpec::build`] turns it into the `RuleSet` the engine runs.
//!
//! # The catalogue is data, not code the interface duplicates
//!
//! Everything a rule editor needs to draw a control is in [`RULES`]. The site
//! renders the labels, the help text, the parameter types and the legal ranges
//! out of this table; it hardcodes no rule name, no default and no bound. A
//! rule added here appears in the interface without the interface being
//! touched — and, more to the point, a bound *changed* here cannot drift out of
//! sync with the bound the detector actually enforces.
//!
//! # The presets are built from the same parts
//!
//! [`RuleSetSpec::standard`] produces exactly the detectors
//! [`RuleSet::standard`](crate::RuleSet::standard) produces, and the suite
//! asserts the two give identical reports on a whole generated day. That is
//! what makes "start from standard and change one thing" a real workflow rather
//! than a different code path: the learner's set and the worked answer are the
//! same kind of object.
//!
//! ```
//! use odr_detect::catalog::RuleSetSpec;
//!
//! // Start from the worked answer, and make drill 5.2's one change.
//! let mut mine = RuleSetSpec::standard();
//! mine.set_param("downgrade", "require_same_identity", 0).unwrap();
//!
//! // It round-trips through a string, so a site can hand it back unchanged.
//! let text = mine.encode();
//! assert_eq!(RuleSetSpec::parse(&text).unwrap(), mine);
//! ```
//!
//! # Values are `u64`, deliberately
//!
//! Every parameter in every detector is either a flag, a count or a duration in
//! microseconds, so one integer type carries all of them. `DESIGN.md` §3 wants
//! a score that is identical on every machine, and a parameter that crossed the
//! wasm boundary as a float could come back rounded — which would make a
//! learner's rule set unreproducible from the string they saved.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_bus::Micros;

use crate::detector::{Detector, RuleSet};
use crate::error::{DetectError, Result};
use crate::finding::Signal;
use crate::rules::{self, DEFAULT_GAP_US};

/// What kind of control a parameter is, and what it will accept.
///
/// The range is part of the catalogue rather than part of the interface,
/// because a bound the site invented would be a second opinion about what the
/// detector accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// On or off. `0` and `1` are the only legal values.
    Toggle,
    /// A duration in microseconds.
    Duration {
        /// Smallest accepted value, inclusive.
        min_us: Micros,
        /// Largest accepted value, inclusive.
        max_us: Micros,
    },
    /// A plain count — frames, findings, events.
    Count {
        /// Smallest accepted value, inclusive.
        min: u64,
        /// Largest accepted value, inclusive.
        max: u64,
    },
}

impl ParamKind {
    /// A stable machine name for the kind, for a form the site draws.
    pub fn name(self) -> &'static str {
        match self {
            ParamKind::Toggle => "toggle",
            ParamKind::Duration { .. } => "duration",
            ParamKind::Count { .. } => "count",
        }
    }

    /// The inclusive range this kind accepts.
    pub fn bounds(self) -> (u64, u64) {
        match self {
            ParamKind::Toggle => (0, 1),
            ParamKind::Duration { min_us, max_us } => (min_us, max_us),
            ParamKind::Count { min, max } => (min, max),
        }
    }

    /// True if `value` is inside the range.
    pub fn accepts(self, value: u64) -> bool {
        let (lo, hi) = self.bounds();
        value >= lo && value <= hi
    }
}

/// One tunable parameter of one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleParam {
    /// Stable id. Matches the field name on the detector struct, so a reader of
    /// the interface can find the code.
    pub id: &'static str,
    /// What to call it on screen.
    pub label: &'static str,
    /// What moving it buys, and what it costs. One or two sentences.
    pub help: &'static str,
    /// What it accepts.
    pub kind: ParamKind,
    /// The detector's own default, as `Default::default` sets it. Flags are
    /// `0` or `1`.
    pub default: u64,
}

/// **One selectable rule**, as a learner sees it before running anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSpec {
    /// Stable id — the same string [`Detector::name`] returns.
    pub id: &'static str,
    /// What to call it on screen.
    pub label: &'static str,
    /// What it catches, in one line.
    pub catches: &'static str,
    /// **What it will false-positive on**, in one line.
    ///
    /// Not an apology and not a footnote: the second question every detector in
    /// this crate answers is "can it be seen without firing on benign traffic",
    /// and a learner choosing rules needs that answer before they choose rather
    /// than after they score.
    pub false_positives: &'static str,
    /// The signals it can emit.
    pub signals: &'static [Signal],
    /// Its tunable parameters, in the order a form should draw them.
    pub params: &'static [RuleParam],
    /// Whether [`RuleSetSpec::standard`] includes it.
    pub in_standard: bool,
}

impl RuleSpec {
    /// One parameter by id.
    pub fn param(&self, id: &str) -> Option<&'static RuleParam> {
        self.params.iter().find(|p| p.id == id)
    }
}

/// **Every rule a learner can select**, in the order a form should draw them.
///
/// The order is the order `RuleSet::standard` adds them, which is the order the
/// crate's own README documents them in.
pub const RULES: &[RuleSpec] = &[
    RuleSpec {
        id: "posture",
        label: "Posture — unsecured traffic, per address",
        catches: "a run of frames for one address carrying no security block: that peripheral's \
                  traffic is readable and forgeable, and the door command on it is copyable.",
        false_positives: "nothing benign, but it is loud by design — it reports what a link is \
                          configured to be, so a bus with four legacy readers produces four \
                          findings. Drop the frame threshold to 1 or 2 and every properly secured \
                          link reports too, because a handshake's own first frames are unsecured.",
        signals: &[Signal::CleartextBus, Signal::SensitiveCommandInClear],
        params: &[
            RuleParam {
                id: "min_frames",
                label: "Frames before a run is called",
                help: "A handshake begins in the clear, and so does the ID/CAP exchange before \
                       one. Below about eight this rule starts reporting every secured link on \
                       the bus.",
                kind: ParamKind::Count { min: 1, max: 512 },
                default: 8,
            },
            RuleParam {
                id: "gap_us",
                label: "Silence that ends a run",
                help: "A link that went quiet is not a link that went insecure. Thirty seconds is \
                       far longer than any poll interval and far shorter than a coffee break.",
                kind: ParamKind::Duration {
                    min_us: 100_000,
                    max_us: 600_000_000,
                },
                default: DEFAULT_GAP_US,
            },
            RuleParam {
                id: "max_evidence",
                label: "Frames cited per finding",
                help: "A four-hour cleartext run should cite the first, the last and enough in \
                       between to show it was continuous — not fourteen thousand frames.",
                kind: ParamKind::Count { min: 1, max: 64 },
                default: 6,
            },
        ],
        in_standard: true,
    },
    RuleSpec {
        id: "keys",
        label: "Keys — the default key, and the null ciphers",
        catches: "SCBK-D named in the clear in the handshake's key-type byte, and SCS_15/16 \
                  frames carrying a payload: authenticated, not encrypted, on a link whose status \
                  display says secure channel established.",
        false_positives: "an ordinary encrypted bus is full of SCS_15 frames, because an empty \
                          payload has nothing to encrypt — the rule ignores those, and a version \
                          that did not would fire on every healthy secured link.",
        signals: &[Signal::DefaultKeyInUse, Signal::NullCipher],
        params: &[RuleParam {
            id: "trust_capability_claim",
            label: "Believe a capability reply that admits to SCBK-D",
            help: "On: report the default key as soon as a REPLY_PDCAP admits to it, without \
                   waiting for a handshake to use it. Off: wait for the handshake. Either way it \
                   stays silent on a bus running no Secure Channel at all, where a key nothing \
                   uses is not a key in use.",
            kind: ParamKind::Toggle,
            default: 1,
        }],
        in_standard: true,
    },
    RuleSpec {
        id: "keyset",
        label: "Keyset — a base key pushed to a peripheral",
        catches: "CMD_KEYSET on the bus, and whether the key was recoverable from the capture. \
                  Curriculum 3.4 and 3.5 seen from the other chair.",
        false_positives: "every commissioning, on purpose. The frame is unmistakable and its \
                          authorisation is in no frame, so the finding is reported as ambiguous \
                          and the scorer counts it in neither precision nor recall. This is drill \
                          5.3's whole answer.",
        signals: &[Signal::KeysetObserved],
        params: &[RuleParam {
            id: "show_recovered_key",
            label: "Print the recovered key in the evidence note",
            help: "Seeing the key written out beside the frame it came from is the lesson of \
                   curriculum 3.5. The key material is simulated; nothing in this workspace has \
                   ever seen a real one.",
            kind: ParamKind::Toggle,
            default: 1,
        }],
        in_standard: true,
    },
    RuleSpec {
        id: "downgrade",
        label: "Downgrade — a peripheral that stopped claiming AES-128",
        catches: "an address that used to claim AES-128 and no longer does, and an address that \
                  ran Secure Channel and is now in the clear without re-handshaking. This is the \
                  rule drill 5.2 is about.",
        false_positives: "with the identity check on: nothing in the day. With it off: every \
                          reader swap in the building — the benign reader replacement at 0x04 \
                          becomes a reported attack. A reader that has never claimed AES-128 is \
                          never reported either way, which is why a legacy reader being added is \
                          not a false positive here.",
        signals: &[
            Signal::CapabilityDowngrade,
            Signal::SecureChannelLost,
            Signal::DeviceIdentityChanged,
        ],
        params: &[
            RuleParam {
                id: "require_same_identity",
                label: "Require REPLY_PDID to be unchanged",
                help: "On: a capability drop at an address whose reported identity also changed \
                       is a reader replacement, not a downgrade. Off: it is reported as a \
                       downgrade, which catches an attacker who rewrote REPLY_PDID too — and \
                       alerts on every genuine reader swap. REPLY_PDID is exactly as \
                       unauthenticated as REPLY_PDCAP, so this buys quiet, not security.",
                kind: ParamKind::Toggle,
                default: 1,
            },
            RuleParam {
                id: "resync_grace_us",
                label: "Grace for a reader coming back",
                help: "A reader power-cycling produces a short unsecured burst — ID, CAP, CHLNG — \
                       before the channel returns. Shorter than the real recovery and this rule \
                       calls a reboot an attack.",
                kind: ParamKind::Duration {
                    min_us: 0,
                    max_us: 120_000_000,
                },
                default: 5_000_000,
            },
            RuleParam {
                id: "min_unsecured_run",
                label: "Unsecured frames before the channel is called lost",
                help: "How many frames with no security block, at an address known to have run \
                       one, before it counts as lost rather than as a gap.",
                kind: ParamKind::Count { min: 1, max: 256 },
                default: 4,
            },
        ],
        in_standard: true,
    },
    RuleSpec {
        id: "injection",
        label: "Injection — the conversation broken",
        catches: "the two-bit sequence cycle, the strict command-then-reply cadence, a reply \
                  nothing asked for, and one poll drawing two different answers from one address.",
        false_positives: "a retransmission, a sequence reset and a peripheral that has gone \
                          offline all look like this. A well-formed frame sent in the gap between \
                          polls is deliberately **not** reported at all: it is identical to a \
                          legitimate one, and a rule that claimed to catch it would be claiming \
                          something no defender has.",
        signals: &[
            Signal::SequenceAnomaly,
            Signal::CadenceViolation,
            Signal::UnsolicitedReply,
            Signal::DuplicateAddress,
        ],
        params: &[
            RuleParam {
                id: "min_command_gap_us",
                label: "Two commands closer than this are not a retry",
                help: "Twenty milliseconds is an order of magnitude below any realistic reply \
                       timeout, so a lost reply on a noisy line does not look like an injection. \
                       Raise it past the reply timeout and every retry becomes an alert.",
                kind: ParamKind::Duration {
                    min_us: 0,
                    max_us: 60_000_000,
                },
                default: 20_000,
            },
            RuleParam {
                id: "gap_us",
                label: "Silence that resets continuity",
                help: "A monitor that was not listening has no standing to say the next sequence \
                       number is wrong.",
                kind: ParamKind::Duration {
                    min_us: 100_000,
                    max_us: 600_000_000,
                },
                default: DEFAULT_GAP_US,
            },
            RuleParam {
                id: "max_per_kind",
                label: "Findings per kind",
                help: "A thoroughly broken link should report a problem, not ten thousand of them.",
                kind: ParamKind::Count { min: 1, max: 256 },
                default: 8,
            },
        ],
        in_standard: true,
    },
    RuleSpec {
        id: "replay",
        label: "Replay — a frame or a credential seen twice",
        catches: "a reply byte-identical to an earlier one that no outstanding command asked for, \
                  and the same credential twice inside the time a person needs to present a badge \
                  twice.",
        false_positives: "**a person badging twice.** The sequence number is two bits, so two \
                          genuine reads of the same card seconds apart are byte-for-byte \
                          identical, CRC included — which is why the frame half of this rule is \
                          about the conversation rather than the bytes. Raise the human interval \
                          and the cleartext bus's double badge-in becomes an alert.",
        signals: &[Signal::ReplayedFrame, Signal::ReplayedCredential],
        params: &[
            RuleParam {
                id: "frame_window_us",
                label: "How far back to look for an identical frame",
                help: "Longer sees more replays and more coincidences.",
                kind: ParamKind::Duration {
                    min_us: 1_000,
                    max_us: 600_000_000,
                },
                default: 30_000_000,
            },
            RuleParam {
                id: "credential_window_us",
                label: "How far back to look for the same credential",
                help: "The same as above, for the card rather than the bytes.",
                kind: ParamKind::Duration {
                    min_us: 1_000,
                    max_us: 600_000_000,
                },
                default: 30_000_000,
            },
            RuleParam {
                id: "human_min_us",
                label: "Fastest a person can present a badge twice",
                help: "800 ms, and it is a claim about hands rather than about protocols — a \
                       turnstile, a mantrap and a loading dock all differ. If you have real \
                       badge-in interval data, this is the number to replace first. Set it above \
                       a few seconds and honest double badge-ins are reported as attacks.",
                kind: ParamKind::Duration {
                    min_us: 0,
                    max_us: 60_000_000,
                },
                default: 800_000,
            },
            RuleParam {
                id: "max_per_kind",
                label: "Findings per kind",
                help: "A cap, so one broken link does not fill the console.",
                kind: ParamKind::Count { min: 1, max: 256 },
                default: 8,
            },
        ],
        in_standard: true,
    },
    RuleSpec {
        id: "wire",
        label: "Wire — a two-wire link, and bits that fit no format",
        catches: "the existence of a D0/D1 or clock-and-data pair, which has no authentication to \
                  check, and credential bits that fit no known format with valid parity.",
        false_positives: "none worth the name — there is almost nothing to say about a two-wire \
                          link. What it cannot do is more interesting: it cannot tell a replayed \
                          badge from a re-badged one, and it cannot tell which card format a \
                          frame is, because the wire does not say.",
        signals: &[Signal::UnauthenticatedWire, Signal::MalformedCredential],
        params: &[
            RuleParam {
                id: "gap_us",
                label: "Silence that starts a new run",
                help: "One posture finding per stretch of wire traffic.",
                kind: ParamKind::Duration {
                    min_us: 100_000,
                    max_us: 600_000_000,
                },
                default: DEFAULT_GAP_US,
            },
            RuleParam {
                id: "max_malformed",
                label: "Malformed-credential findings",
                help: "A cap. A reader emitting garbage emits a lot of it, and one finding that \
                       says so is more use than four hundred that each say it once.",
                kind: ParamKind::Count { min: 1, max: 256 },
                default: 8,
            },
        ],
        in_standard: true,
    },
    RuleSpec {
        id: "traffic",
        label: "Traffic analysis — the schedule, through the encryption",
        catches: "the times of every badge-in, readable with no key, because the command and \
                  reply id byte is plaintext inside Secure Channel. Curriculum 4.1's answer.",
        false_positives: "it fires on healthy buses on purpose — that is the finding. Turning on \
                          Secure Channel fixes the card numbers and does not fix this.",
        signals: &[Signal::TrafficPatternExposed],
        params: &[
            RuleParam {
                id: "min_events",
                label: "Presentations before a schedule is a pattern",
                help: "One badge-in is not a pattern. Three is a shift.",
                kind: ParamKind::Count { min: 1, max: 512 },
                default: 3,
            },
            RuleParam {
                id: "max_listed",
                label: "Times listed in the note",
                help: "How many presentation times to write out in the evidence.",
                kind: ParamKind::Count { min: 1, max: 256 },
                default: 12,
            },
        ],
        in_standard: true,
    },
];

/// One rule's description by id.
pub fn rule(id: &str) -> Option<&'static RuleSpec> {
    RULES.iter().find(|r| r.id == id)
}

/// **One rule, as a learner has configured it.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedRule {
    spec: &'static RuleSpec,
    /// One value per entry of `spec.params`, in the same order.
    values: Vec<u64>,
}

impl ComposedRule {
    /// The rule at its defaults.
    pub fn new(spec: &'static RuleSpec) -> ComposedRule {
        ComposedRule {
            spec,
            values: spec.params.iter().map(|p| p.default).collect(),
        }
    }

    /// Its id.
    pub fn id(&self) -> &'static str {
        self.spec.id
    }

    /// Its description.
    pub fn spec(&self) -> &'static RuleSpec {
        self.spec
    }

    /// The value of one parameter.
    pub fn value(&self, param_id: &str) -> Option<u64> {
        let i = self.spec.params.iter().position(|p| p.id == param_id)?;
        self.values.get(i).copied()
    }

    /// Every parameter with its current value, in form order.
    pub fn values(&self) -> impl Iterator<Item = (&'static RuleParam, u64)> + '_ {
        self.spec.params.iter().zip(self.values.iter().copied())
    }

    /// Set one parameter, refusing a value outside the declared range.
    pub fn set(&mut self, param_id: &str, value: u64) -> Result<()> {
        let i = self
            .spec
            .params
            .iter()
            .position(|p| p.id == param_id)
            .ok_or_else(|| {
                DetectError::Rule(alloc::format!(
                    "rule \"{}\" has no parameter \"{param_id}\"",
                    self.spec.id
                ))
            })?;
        let param = &self.spec.params[i];
        if !param.kind.accepts(value) {
            let (lo, hi) = param.kind.bounds();
            return Err(DetectError::Rule(alloc::format!(
                "{}.{param_id} accepts {lo}..={hi}, not {value}",
                self.spec.id
            )));
        }
        self.values[i] = value;
        Ok(())
    }

    /// True if nothing has been changed from the detector's own defaults.
    pub fn is_default(&self) -> bool {
        self.spec
            .params
            .iter()
            .zip(self.values.iter())
            .all(|(p, v)| p.default == *v)
    }

    /// A flag parameter as a `bool`.
    fn flag(&self, param_id: &str) -> bool {
        self.value(param_id).unwrap_or(0) != 0
    }

    /// A parameter as a `usize`, saturating — every bound in [`RULES`] is far
    /// below `usize::MAX` on any target this builds for, so the saturation is
    /// unreachable rather than lossy.
    fn count(&self, param_id: &str) -> usize {
        self.value(param_id).unwrap_or(0).min(usize::MAX as u64) as usize
    }

    /// A parameter as microseconds.
    fn micros(&self, param_id: &str) -> Micros {
        self.value(param_id).unwrap_or(0)
    }

    /// Build the detector this describes.
    ///
    /// Returns `None` only for an id that is in no longer in [`RULES`], which
    /// cannot happen for a `ComposedRule` because its `spec` is a reference
    /// into that table.
    pub fn build(&self) -> Box<dyn Detector> {
        match self.spec.id {
            "keys" => Box::new(rules::KeyDetector {
                trust_capability_claim: self.flag("trust_capability_claim"),
            }),
            "keyset" => Box::new(rules::KeysetDetector {
                show_recovered_key: self.flag("show_recovered_key"),
            }),
            "downgrade" => Box::new(rules::DowngradeDetector {
                require_same_identity: self.flag("require_same_identity"),
                resync_grace_us: self.micros("resync_grace_us"),
                min_unsecured_run: self.count("min_unsecured_run"),
            }),
            "injection" => Box::new(rules::InjectionDetector {
                min_command_gap_us: self.micros("min_command_gap_us"),
                gap_us: self.micros("gap_us"),
                max_per_kind: self.count("max_per_kind"),
            }),
            "replay" => Box::new(rules::ReplayDetector {
                frame_window_us: self.micros("frame_window_us"),
                credential_window_us: self.micros("credential_window_us"),
                human_min_us: self.micros("human_min_us"),
                max_per_kind: self.count("max_per_kind"),
            }),
            "wire" => Box::new(rules::WireDetector {
                gap_us: self.micros("gap_us"),
                max_malformed: self.count("max_malformed"),
            }),
            "traffic" => Box::new(rules::TrafficDetector {
                min_events: self.count("min_events"),
                max_listed: self.count("max_listed"),
            }),
            // "posture", and anything a future catalogue entry forgets to wire,
            // which the suite catches: `every_catalogue_rule_builds_a_detector`
            // asserts the detector's own name matches the spec id.
            _ => Box::new(rules::PostureDetector {
                min_frames: self.count("min_frames"),
                gap_us: self.micros("gap_us"),
                max_evidence: self.count("max_evidence"),
            }),
        }
    }
}

/// The presets a learner can start from.
///
/// Named here rather than in the site so that "start from standard" means the
/// same thing in the browser, in `odr-cli` and in the test suite.
pub const PRESETS: &[(&str, &str, &str)] = &[
    (
        "empty",
        "Nothing at all — the honest floor",
        "No rules. It catches nothing and it cries wolf about nothing, which is the floor every \
         other score should be read against.",
    ),
    (
        "standard",
        "The standard set — the worked answer",
        "All eight rules at their default tuning, configured conservatively where there is a \
         false-positive trade-off. Read its score with suspicion: the answer key and these \
         detectors were written by the same hand.",
    ),
    (
        "strict",
        "Strict downgrade — catches more, cries wolf",
        "Posture, keys, keyset and the downgrade rule with its identity check turned off. It \
         catches the attacker who rewrote REPLY_PDID as well as REPLY_PDCAP, and it alerts on \
         every genuine reader swap. Both halves of that trade are real.",
    ),
];

/// **A learner's rule set**, before it is built.
#[derive(Debug, Clone)]
pub struct RuleSetSpec {
    name: String,
    rules: Vec<ComposedRule>,
}

/// Two compositions are equal when they run the same detectors with the same
/// tuning. **The name is not part of the comparison**: it is a label on a
/// composition rather than part of one, and a learner who starts from the
/// standard set and changes nothing has the standard set whatever the box above
/// it happens to say. It is also what makes
/// [`encode`](RuleSetSpec::encode) — which does not write the name — round-trip.
impl PartialEq for RuleSetSpec {
    fn eq(&self, other: &RuleSetSpec) -> bool {
        self.rules == other.rules
    }
}

impl Eq for RuleSetSpec {}

impl Default for RuleSetSpec {
    fn default() -> RuleSetSpec {
        RuleSetSpec::standard()
    }
}

impl RuleSetSpec {
    /// An empty composition. A learner starts here, or at [`Self::standard`].
    pub fn empty(name: impl Into<String>) -> RuleSetSpec {
        RuleSetSpec {
            name: name.into(),
            rules: Vec::new(),
        }
    }

    /// Every rule in [`RULES`] marked `in_standard`, at its defaults.
    ///
    /// Builds the same detectors as [`RuleSet::standard`], which the suite
    /// asserts by running both over a whole generated day and comparing the
    /// reports.
    pub fn standard() -> RuleSetSpec {
        let mut spec = RuleSetSpec::empty("standard");
        for r in RULES.iter().filter(|r| r.in_standard) {
            spec.rules.push(ComposedRule::new(r));
        }
        spec
    }

    /// The strict-downgrade preset: posture, keys, keyset, and the downgrade
    /// rule with its identity check off.
    pub fn strict() -> RuleSetSpec {
        let mut spec = RuleSetSpec::empty("strict downgrade");
        for id in ["posture", "keys", "keyset", "downgrade"] {
            if let Some(r) = rule(id) {
                spec.rules.push(ComposedRule::new(r));
            }
        }
        // Infallible: the parameter is in the catalogue and 0 is in range.
        let _ = spec.set_param("downgrade", "require_same_identity", 0);
        spec
    }

    /// A preset by the id [`PRESETS`] lists.
    pub fn preset(id: &str) -> Option<RuleSetSpec> {
        match id {
            "empty" => Some(RuleSetSpec::empty("nothing at all")),
            "standard" => Some(RuleSetSpec::standard()),
            "strict" => Some(RuleSetSpec::strict()),
            _ => None,
        }
    }

    /// The preset this composition is identical to, if it is identical to one.
    ///
    /// What it is *for* is telling a learner that they have changed something:
    /// an editor that said "standard" while running a modified set would be the
    /// interface lying about what the engine is doing, which `docs/UI.md`'s
    /// collapse-never-remove rule exists to prevent.
    pub fn matching_preset(&self) -> Option<&'static str> {
        PRESETS
            .iter()
            .map(|(id, _, _)| *id)
            .find(|id| RuleSetSpec::preset(id).is_some_and(|p| &p == self))
    }

    /// The set's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Rename it.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// The rules in it, in catalogue order.
    pub fn rules(&self) -> &[ComposedRule] {
        &self.rules
    }

    /// How many rules are selected.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True if no rule is selected.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// True if this rule is selected.
    pub fn contains(&self, rule_id: &str) -> bool {
        self.rules.iter().any(|r| r.id() == rule_id)
    }

    /// One selected rule.
    pub fn get(&self, rule_id: &str) -> Option<&ComposedRule> {
        self.rules.iter().find(|r| r.id() == rule_id)
    }

    /// Select a rule, at its defaults if it was not already selected.
    ///
    /// Rules are kept in catalogue order however they were added, so two
    /// learners who selected the same rules in different orders hold equal
    /// compositions and produce identical encodings.
    pub fn enable(&mut self, rule_id: &str) -> Result<()> {
        if self.contains(rule_id) {
            return Ok(());
        }
        let spec = rule(rule_id)
            .ok_or_else(|| DetectError::Rule(alloc::format!("no rule called \"{rule_id}\"")))?;
        self.rules.push(ComposedRule::new(spec));
        self.sort();
        Ok(())
    }

    /// Deselect a rule. Deselecting one that is not selected is not an error.
    pub fn disable(&mut self, rule_id: &str) {
        self.rules.retain(|r| r.id() != rule_id);
    }

    /// Set one parameter of one selected rule.
    pub fn set_param(&mut self, rule_id: &str, param_id: &str, value: u64) -> Result<()> {
        let r = self
            .rules
            .iter_mut()
            .find(|r| r.id() == rule_id)
            .ok_or_else(|| {
                DetectError::Rule(alloc::format!(
                    "rule \"{rule_id}\" is not in this set, so its parameters cannot be set"
                ))
            })?;
        r.set(param_id, value)
    }

    /// Put the rules back into catalogue order.
    fn sort(&mut self) {
        self.rules.sort_by_key(|r| {
            RULES
                .iter()
                .position(|s| s.id == r.id())
                .unwrap_or(usize::MAX)
        });
    }

    /// **Build the rule set the engine runs.**
    pub fn build(&self) -> RuleSet {
        let mut set = RuleSet::empty(self.name.clone());
        for r in &self.rules {
            set.push(r.build());
        }
        set
    }

    /// Every signal some selected rule can emit, in [`Signal::ALL`] order.
    pub fn signals(&self) -> Vec<Signal> {
        Signal::ALL
            .iter()
            .copied()
            .filter(|s| self.rules.iter().any(|r| r.spec.signals.contains(s)))
            .collect()
    }

    /// **The composition as one line of text**, which round-trips through
    /// [`RuleSetSpec::parse`].
    ///
    /// `posture;downgrade:require_same_identity=0;traffic:min_events=1`
    ///
    /// Only parameters that differ from the detector's default are written, so
    /// a set that changed one thing reads as one thing changed. The name is not
    /// encoded: it is a label on a composition, not part of one, and two
    /// compositions that run the same detectors should encode identically.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        for r in &self.rules {
            if !out.is_empty() {
                out.push(';');
            }
            out.push_str(r.id());
            let mut first = true;
            for (param, value) in r.values() {
                if value == param.default {
                    continue;
                }
                out.push(if first { ':' } else { ',' });
                first = false;
                out.push_str(param.id);
                out.push('=');
                out.push_str(&alloc::format!("{value}"));
            }
        }
        out
    }

    /// **Parse a composition**, or a preset name.
    ///
    /// `"standard"`, `"strict"` and `"empty"` are accepted as whole-string
    /// preset names, which is what the site's rule-set selector has always
    /// carried; anything else is read as the encoding [`RuleSetSpec::encode`]
    /// produces. An unknown rule id or an out-of-range value is an error rather
    /// than something quietly dropped — a learner whose rule was silently
    /// discarded would be scoring a set they did not build.
    pub fn parse(text: &str) -> Result<RuleSetSpec> {
        let text = text.trim();
        if let Some(preset) = RuleSetSpec::preset(text) {
            return Ok(preset);
        }
        let mut spec = RuleSetSpec::empty("composed");
        if text.is_empty() {
            return Ok(spec);
        }
        for entry in text.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (rule_id, params) = match entry.split_once(':') {
                Some((r, p)) => (r.trim(), p),
                None => (entry, ""),
            };
            spec.enable(rule_id)?;
            for assignment in params.split(',') {
                let assignment = assignment.trim();
                if assignment.is_empty() {
                    continue;
                }
                let (param_id, raw) = assignment.split_once('=').ok_or_else(|| {
                    DetectError::Rule(alloc::format!(
                        "\"{assignment}\" is not a parameter assignment; write name=value"
                    ))
                })?;
                let value: u64 = raw.trim().parse().map_err(|_| {
                    DetectError::Rule(alloc::format!(
                        "{rule_id}.{} was given \"{}\", which is not a whole number",
                        param_id.trim(),
                        raw.trim()
                    ))
                })?;
                spec.set_param(rule_id, param_id.trim(), value)?;
            }
        }
        if let Some(name) = spec.matching_preset() {
            spec.set_name(name.to_string());
        }
        Ok(spec)
    }

    /// The roster, one rule per line with its tuning, for a console or a log.
    pub fn explain(&self) -> String {
        let mut s = alloc::format!(
            "rule set \"{}\" — {} rule(s)\n",
            self.name,
            self.rules.len()
        );
        for r in &self.rules {
            s.push_str("  ");
            s.push_str(r.id());
            if !r.is_default() {
                s.push_str(" (");
                let mut first = true;
                for (param, value) in r.values() {
                    if value == param.default {
                        continue;
                    }
                    if !first {
                        s.push_str(", ");
                    }
                    first = false;
                    s.push_str(&alloc::format!("{}={value}", param.id));
                }
                s.push(')');
            }
            s.push_str(": ");
            s.push_str(r.spec.catches);
            s.push('\n');
        }
        s
    }
}
