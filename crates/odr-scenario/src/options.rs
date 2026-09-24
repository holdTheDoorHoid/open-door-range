//! **The seam that makes the bench a sandbox.**
//!
//! `DESIGN.md` §4 decided "sandbox with drills layered on top": one live bench,
//! always pokeable, with the course driving that same bench. Until this module
//! existed the bench was read-only — [`scenario::build`](crate::scenario::build)
//! took a [`ScenarioId`] and a seed and nothing else, so there was no way to say
//! "the same bench, but with Secure Channel on". The interface said so honestly
//! and offered no control, which is half a product decision.
//!
//! # The three rules this module keeps
//!
//! **1. Defaults are today's benches, byte for byte.** [`BenchOptions`] is a
//! set of *overrides*: every field is an [`Option`], and
//! [`BenchOptions::default()`] sets none of them. Each scenario declares its own
//! resolved settings in [`defaults`], transcribed from what its builder already
//! hardcoded, so an unmodified build draws from the seeded RNG in exactly the
//! order it always did and produces exactly the bytes it always did. There is a
//! test for every scenario.
//!
//! **2. The option list is data.** [`describe`] returns what this scenario
//! accepts — kind, current value, the legal values, and a line saying what the
//! option does. The interface renders that list; it does not carry one of its
//! own. The lists genuinely differ: Secure Channel is meaningless on a Wiegand
//! pair and a card-layer bench has no bus, so those options are simply not in
//! the list, and [`apply`] refuses them with the reason.
//!
//! **3. Refusal is for the impossible; everything else warns.** `docs/UI.md`
//! records the owner's feedback as *prefer warning over blocking*, so a setting
//! that would make the loaded drill unwinnable is **accepted** and comes back
//! carrying a [`OptionSpec::warning`] that says what will stop working. Only a
//! bench that cannot be built that way is refused, and then
//! [`ScenarioError::OptionRefused`] carries the sentence explaining why.
//!
//! That is the answer to "should turning Secure Channel off under drill 3.2 be
//! refused?" — no. It is allowed, and it says plainly that the drill's flag can
//! no longer be earned. Two reasons. The interface document's feedback is
//! explicit about preferring the warning. And `odr-bus`'s own controller docs
//! say both settings of `trust_pdcap` are modelled "so a drill can run the
//! attack and then run the fix and see it hold" — a drill that refused its own
//! defence setting would forbid precisely the exercise the engine was built
//! for. Free play is therefore not a wider *set* of options than a drill, it is
//! the same set with nothing to warn about.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_bus::ScRequirement;
use odr_wiegand::CardFormat;

use crate::error::{Result, ScenarioError};
use crate::ids::DrillId;
use crate::scenario::ScenarioId;

/// **Which key the endpoints were commissioned with.**
///
/// The three cases are the ones the curriculum turns on: the key from the
/// manual, a key from the published sample-code family, and a key that is
/// neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyChoice {
    /// SCBK-D, the default printed in the specification. Everybody has it.
    #[default]
    Default,
    /// A site key drawn from the seed and checked against
    /// [`odr_osdp::weak_keys::is_weak`], so it has to be asked for or captured.
    Site,
    /// A repeated-byte key from the published Mellon sample family. Sweepable.
    Weak,
}

impl KeyChoice {
    /// The stable string id.
    pub fn name(self) -> &'static str {
        match self {
            KeyChoice::Default => "scbk-d",
            KeyChoice::Site => "site",
            KeyChoice::Weak => "weak",
        }
    }

    fn parse(s: &str) -> Option<KeyChoice> {
        match s {
            "scbk-d" => Some(KeyChoice::Default),
            "site" => Some(KeyChoice::Site),
            "weak" => Some(KeyChoice::Weak),
            _ => None,
        }
    }
}

/// **Which two wires run between reader and panel.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkChoice {
    /// Wiegand D0/D1.
    #[default]
    Wiegand,
    /// Clock-and-data, ABA track 2.
    ClockData,
}

impl LinkChoice {
    /// The stable string id.
    pub fn name(self) -> &'static str {
        match self {
            LinkChoice::Wiegand => "wiegand",
            LinkChoice::ClockData => "clockdata",
        }
    }

    fn parse(s: &str) -> Option<LinkChoice> {
        match s {
            "wiegand" => Some(LinkChoice::Wiegand),
            "clockdata" => Some(LinkChoice::ClockData),
            _ => None,
        }
    }
}

fn sc_name(sc: ScRequirement) -> &'static str {
    match sc {
        ScRequirement::Disabled => "off",
        ScRequirement::IfAvailable => "if-available",
        ScRequirement::Required => "required",
    }
}

fn sc_parse(s: &str) -> Option<ScRequirement> {
    match s {
        "off" => Some(ScRequirement::Disabled),
        "if-available" => Some(ScRequirement::IfAvailable),
        "required" => Some(ScRequirement::Required),
        _ => None,
    }
}

/// Every credential format a bench will put on a wire, as ids.
const FORMATS: &[(&str, &str)] = &[
    ("h10301", "H10301 — 26-bit, 8-bit facility code"),
    ("h10306", "H10306 — 34-bit, 16-bit facility code"),
    ("c1k35s", "Corporate 1000 — 35-bit, interleaved parity"),
    ("h10304", "H10304 — 37-bit with a facility code"),
    ("h10302", "H10302 — 37-bit, no facility code"),
];

fn format_name(f: CardFormat) -> &'static str {
    match f {
        CardFormat::H10301 => "h10301",
        CardFormat::H10306 => "h10306",
        CardFormat::Corporate1000 => "c1k35s",
        CardFormat::H10304 => "h10304",
        CardFormat::H10302 => "h10302",
        CardFormat::Raw { .. } => "raw",
    }
}

fn format_parse(s: &str) -> Option<CardFormat> {
    match s {
        "h10301" => Some(CardFormat::H10301),
        "h10306" => Some(CardFormat::H10306),
        "c1k35s" => Some(CardFormat::Corporate1000),
        "h10304" => Some(CardFormat::H10304),
        "h10302" => Some(CardFormat::H10302),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The overrides
// ---------------------------------------------------------------------------

/// **What the learner has changed about a bench.**
///
/// Every field is an override. `None` means "whatever this scenario's own
/// builder chose", which is why [`BenchOptions::default()`] reproduces today's
/// benches exactly rather than approximately.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BenchOptions {
    /// How hard both endpoints insist on Secure Channel.
    pub secure_channel: Option<ScRequirement>,
    /// Which key they were commissioned with.
    pub key: Option<KeyChoice>,
    /// Whether the controller believes the unauthenticated capability reply.
    /// **Drill 3.6's defence and 5.2's lesson.**
    pub trust_pdcap: Option<bool>,
    /// Whether the controller is left in install mode.
    pub acu_install_mode: Option<bool>,
    /// Whether the reader is uncommissioned and will take a key.
    pub pd_install_mode: Option<bool>,
    /// Whether the reader claims AES-128 in its capability reply. This is the
    /// entry the downgrade attack deletes in flight.
    pub pd_claims_aes: Option<bool>,
    /// Run the secure channel as a null cipher: MAC only, payload in the clear.
    pub null_cipher: Option<bool>,
    /// How many MAC bytes carry strength, 1 to 4.
    pub mac_bytes: Option<u8>,
    /// The RS-485 line rate.
    pub baud: Option<u32>,
    /// How long between one poll finishing and the next starting.
    pub poll_ms: Option<u32>,
    /// Which two wires run between reader and panel.
    pub link: Option<LinkChoice>,
    /// The credential format the bench enrols and presents.
    pub format: Option<CardFormat>,
    /// How long the door stays unlocked after a grant.
    pub strike_ms: Option<u32>,
}

impl BenchOptions {
    /// Nothing overridden — the scenario exactly as its builder wrote it.
    pub fn none() -> BenchOptions {
        BenchOptions::default()
    }

    /// True when the learner has changed nothing.
    pub fn is_empty(&self) -> bool {
        *self == BenchOptions::default()
    }

    /// Resolve against a scenario's own settings.
    pub fn resolve(&self, scenario: ScenarioId) -> Resolved {
        let d = defaults(scenario);
        Resolved {
            sc: self.secure_channel.unwrap_or(d.sc),
            key: self.key.unwrap_or(d.key),
            trust_pdcap: self.trust_pdcap.unwrap_or(d.trust_pdcap),
            acu_install_mode: self.acu_install_mode.unwrap_or(d.acu_install_mode),
            pd_install_mode: self.pd_install_mode.unwrap_or(d.pd_install_mode),
            pd_claims_aes: self.pd_claims_aes.unwrap_or(d.pd_claims_aes),
            null_cipher: self.null_cipher.unwrap_or(d.null_cipher),
            mac_bytes: self.mac_bytes.unwrap_or(d.mac_bytes).clamp(1, 4),
            baud: self.baud.unwrap_or(d.baud),
            poll_ms: self.poll_ms.unwrap_or(d.poll_ms).max(1),
            link: self.link.unwrap_or(d.link),
            format: self.format.unwrap_or(d.format),
            strike_ms: self.strike_ms.unwrap_or(d.strike_ms),
        }
    }

    /// Whether a given option id has been overridden.
    pub fn is_set(&self, id: &str) -> bool {
        match id {
            SECURE_CHANNEL => self.secure_channel.is_some(),
            KEY => self.key.is_some(),
            TRUST_PDCAP => self.trust_pdcap.is_some(),
            ACU_INSTALL => self.acu_install_mode.is_some(),
            PD_INSTALL => self.pd_install_mode.is_some(),
            PD_AES => self.pd_claims_aes.is_some(),
            NULL_CIPHER => self.null_cipher.is_some(),
            MAC_BYTES => self.mac_bytes.is_some(),
            BAUD => self.baud.is_some(),
            POLL_MS => self.poll_ms.is_some(),
            LINK => self.link.is_some(),
            FORMAT => self.format.is_some(),
            STRIKE_MS => self.strike_ms.is_some(),
            _ => false,
        }
    }
}

/// **A bench's settings, with nothing left to decide.**
///
/// Produced by [`BenchOptions::resolve`]. The builders in
/// [`crate::scenario`] read this and nothing else, so there is exactly one
/// place a bench's configuration comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resolved {
    /// How hard both endpoints insist on Secure Channel.
    pub sc: ScRequirement,
    /// Which key they hold.
    pub key: KeyChoice,
    /// Whether the controller believes the capability reply.
    pub trust_pdcap: bool,
    /// Controller install mode.
    pub acu_install_mode: bool,
    /// Reader install mode.
    pub pd_install_mode: bool,
    /// Whether the reader claims AES-128.
    pub pd_claims_aes: bool,
    /// Null cipher: MAC only, payload readable.
    pub null_cipher: bool,
    /// MAC bytes that carry strength, 1 to 4.
    pub mac_bytes: u8,
    /// RS-485 line rate.
    pub baud: u32,
    /// Poll interval in milliseconds.
    pub poll_ms: u32,
    /// Which two wires run between reader and panel.
    pub link: LinkChoice,
    /// Credential format.
    pub format: CardFormat,
    /// Strike time in milliseconds.
    pub strike_ms: u32,
}

/// **Each scenario's own settings, transcribed from its builder.**
///
/// This table is the load-bearing half of "defaults reproduce today's benches".
/// If a value here disagrees with what `scenario.rs` used to hardcode, the
/// byte-identity test for that scenario fails.
pub fn defaults(scenario: ScenarioId) -> Resolved {
    let base = Resolved {
        sc: ScRequirement::Disabled,
        key: KeyChoice::Default,
        trust_pdcap: true,
        acu_install_mode: false,
        pd_install_mode: false,
        pd_claims_aes: true,
        null_cipher: false,
        mac_bytes: 4,
        baud: 9600,
        poll_ms: 100,
        link: LinkChoice::Wiegand,
        format: CardFormat::H10301,
        strike_ms: 3000,
    };
    match scenario {
        ScenarioId::ClockDataDoor => Resolved {
            link: LinkChoice::ClockData,
            ..base
        },
        ScenarioId::OsdpDefaultKey => Resolved {
            sc: ScRequirement::IfAvailable,
            key: KeyChoice::Default,
            ..base
        },
        ScenarioId::OsdpWeakKey => Resolved {
            sc: ScRequirement::IfAvailable,
            key: KeyChoice::Weak,
            ..base
        },
        ScenarioId::OsdpInstallMode => Resolved {
            sc: ScRequirement::IfAvailable,
            key: KeyChoice::Site,
            acu_install_mode: true,
            ..base
        },
        ScenarioId::OsdpCommissioning => Resolved {
            sc: ScRequirement::IfAvailable,
            key: KeyChoice::Site,
            acu_install_mode: true,
            ..base
        },
        ScenarioId::OsdpRequiredSc | ScenarioId::OsdpEncryptedDay => Resolved {
            sc: ScRequirement::Required,
            key: KeyChoice::Default,
            ..base
        },
        ScenarioId::OsdpShortMac => Resolved {
            sc: ScRequirement::IfAvailable,
            key: KeyChoice::Default,
            mac_bytes: 1,
            ..base
        },
        ScenarioId::OsdpNullCipher => Resolved {
            sc: ScRequirement::IfAvailable,
            key: KeyChoice::Default,
            null_cipher: true,
            ..base
        },
        _ => base,
    }
}

// ---------------------------------------------------------------------------
// The option catalogue
// ---------------------------------------------------------------------------

/// Option id: Secure Channel and its requirement level.
pub const SECURE_CHANNEL: &str = "secureChannel";
/// Option id: which key the endpoints hold.
pub const KEY: &str = "key";
/// Option id: whether the controller believes the capability reply.
pub const TRUST_PDCAP: &str = "trustPdcap";
/// Option id: controller install mode.
pub const ACU_INSTALL: &str = "acuInstallMode";
/// Option id: reader install mode.
pub const PD_INSTALL: &str = "pdInstallMode";
/// Option id: whether the reader claims AES-128.
pub const PD_AES: &str = "pdClaimsAes";
/// Option id: null cipher.
pub const NULL_CIPHER: &str = "nullCipher";
/// Option id: MAC bytes.
pub const MAC_BYTES: &str = "macBytes";
/// Option id: RS-485 line rate.
pub const BAUD: &str = "baud";
/// Option id: poll interval.
pub const POLL_MS: &str = "pollMs";
/// Option id: link type.
pub const LINK: &str = "linkType";
/// Option id: credential format.
pub const FORMAT: &str = "format";
/// Option id: strike time.
pub const STRIKE_MS: &str = "strikeMs";

/// What kind of control an option needs, and what it will accept.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OptionKind {
    /// On or off.
    Boolean,
    /// One of a closed list of `(value, label)` pairs.
    Choice(&'static [(&'static str, &'static str)]),
    /// A whole number in a range, with a unit for the interface to print.
    Number {
        /// Smallest accepted value.
        min: i64,
        /// Largest accepted value.
        max: i64,
        /// What the number is measured in: `"ms"`, `"bytes"`.
        unit: &'static str,
    },
}

/// An option's current value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OptionValue {
    /// A boolean.
    Bool(bool),
    /// The id of the chosen entry in an [`OptionKind::Choice`].
    Choice(String),
    /// A number.
    Number(i64),
}

impl OptionValue {
    /// Render for a summary line.
    pub fn as_string(&self) -> String {
        match self {
            OptionValue::Bool(v) => {
                if *v {
                    "yes".to_owned()
                } else {
                    "no".to_owned()
                }
            }
            OptionValue::Choice(s) => s.clone(),
            OptionValue::Number(n) => n.to_string(),
        }
    }
}

/// **One option, as the interface should render it.**
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OptionSpec {
    /// Stable id, used with [`apply`].
    pub id: &'static str,
    /// What to call it.
    pub label: &'static str,
    /// Which configuration group it belongs in: `"security"`, `"controller"`,
    /// `"reader"`, `"link"` or `"card"`.
    pub group: &'static str,
    /// What kind of control, and the legal values.
    pub kind: OptionKind,
    /// What it is set to now.
    pub value: OptionValue,
    /// One line on what the option does.
    pub help: &'static str,
    /// Worth drawing attention to at this value — install mode on, a MAC
    /// shorter than the protocol's.
    pub critical: bool,
    /// The learner has changed this away from the bench's own setting.
    pub changed: bool,
    /// What this value breaks about the loaded drill. `None` in free play, and
    /// `None` when the value is fine.
    ///
    /// **The bench still builds.** `docs/UI.md`: warn rather than block.
    pub warning: Option<String>,
}

struct Def {
    id: &'static str,
    label: &'static str,
    group: &'static str,
    help: &'static str,
    kind: OptionKind,
}

fn defs() -> Vec<Def> {
    alloc::vec![
        Def {
            id: SECURE_CHANNEL,
            label: "Secure Channel",
            group: "security",
            help: "Off is how OSDP ships and how most of it is deployed. \"If available\" lets \
                   the reader's own capability reply decide, which is what the downgrade attack \
                   rewrites. \"Required\" still means \"required of readers that say they can\".",
            kind: OptionKind::Choice(&[
                ("off", "Off — everything in the clear"),
                ("if-available", "If available — the reader decides"),
                ("required", "Required"),
            ]),
        },
        Def {
            id: KEY,
            label: "Base key",
            group: "security",
            help: "SCBK-D is printed in the specification, so everybody has it. A weak key is \
                   from the published sample-code family and can be swept for. A site key is \
                   neither, so it has to be asked for or captured.",
            kind: OptionKind::Choice(&[
                ("scbk-d", "SCBK-D — the published default"),
                ("weak", "Weak — from the sample-code family"),
                ("site", "Site key — not in any published list"),
            ]),
        },
        Def {
            id: NULL_CIPHER,
            label: "Null cipher (SCS_15/16)",
            group: "security",
            help: "Authenticate without encrypting. A real, specified mode, and some \
                   deployments run it believing \"secure channel is on\" hides the card number.",
            kind: OptionKind::Boolean,
        },
        Def {
            id: MAC_BYTES,
            label: "MAC bytes",
            group: "security",
            help: "OSDP truncates to four and offers no way to change it, so four is the only \
                   honest value. Shorter is a rig, and drill 4.2 says so out loud.",
            kind: OptionKind::Number {
                min: 1,
                max: 4,
                unit: "bytes",
            },
        },
        Def {
            id: TRUST_PDCAP,
            label: "Trust the capability reply",
            group: "controller",
            help: "Nothing authenticates a capability report. With this on the controller \
                   decides from it whether to run a handshake at all — which is the whole of \
                   the downgrade attack. Turning it off is the defence.",
            kind: OptionKind::Boolean,
        },
        Def {
            id: ACU_INSTALL,
            label: "Controller install mode",
            group: "controller",
            help: "A controller in install mode hands the site key to anything that turns up \
                   claiming the default. Installers leave it on.",
            kind: OptionKind::Boolean,
        },
        Def {
            id: POLL_MS,
            label: "Poll interval",
            group: "link",
            help: "How long the controller waits between polls. Real installations poll hard, \
                   and the amount of idle traffic is exactly what makes traffic analysis work.",
            kind: OptionKind::Number {
                min: 10,
                max: 2000,
                unit: "ms",
            },
        },
        Def {
            id: STRIKE_MS,
            label: "Strike time",
            group: "controller",
            help: "How long the door stays unlocked after a grant.",
            kind: OptionKind::Number {
                min: 200,
                max: 30_000,
                unit: "ms",
            },
        },
        Def {
            id: PD_INSTALL,
            label: "Reader install mode",
            group: "reader",
            help: "An uncommissioned reader takes a key from anything that establishes a \
                   channel under the default key.",
            kind: OptionKind::Boolean,
        },
        Def {
            id: PD_AES,
            label: "Reader claims AES-128",
            group: "reader",
            help: "Function code 0x09 in the PDCAP reply. This is the entry the downgrade \
                   attack deletes in flight; clearing it here is the same bench without the \
                   attacker.",
            kind: OptionKind::Boolean,
        },
        Def {
            id: BAUD,
            label: "Line rate",
            group: "link",
            help: "What the bus clocks at. It is what makes an online MAC forgery cost what \
                   drill 4.2 says it costs.",
            kind: OptionKind::Choice(&[
                ("9600", "9600 baud"),
                ("19200", "19200 baud"),
                ("38400", "38400 baud"),
                ("115200", "115200 baud"),
            ]),
        },
        Def {
            id: LINK,
            label: "Wire protocol",
            group: "link",
            help: "Two legacy pairs, the same absence of cryptography. Clock-and-data is ABA \
                   track 2, which is a magstripe encoding on a door.",
            kind: OptionKind::Choice(&[
                ("wiegand", "Wiegand D0/D1"),
                ("clockdata", "Clock-and-data (ABA track 2)"),
            ]),
        },
        Def {
            id: FORMAT,
            label: "Credential format",
            group: "card",
            help: "Which bit layout the reader emits and the panel is configured to believe. \
                   Nothing on the wire says which one it is.",
            kind: OptionKind::Choice(FORMATS),
        },
    ]
}

/// Which options a scenario accepts, in the order the interface shows them.
///
/// The lists differ because the benches do: a Wiegand pair has no secure
/// channel to configure, and a card-layer bench has no bus.
pub fn accepted(scenario: ScenarioId) -> &'static [&'static str] {
    const OSDP: &[&str] = &[
        SECURE_CHANNEL,
        KEY,
        NULL_CIPHER,
        MAC_BYTES,
        TRUST_PDCAP,
        ACU_INSTALL,
        PD_INSTALL,
        PD_AES,
        BAUD,
        POLL_MS,
        FORMAT,
        STRIKE_MS,
    ];
    const LEGACY: &[&str] = &[LINK, FORMAT, STRIKE_MS];
    const CARD: &[&str] = &[STRIKE_MS];
    const NOTHING: &[&str] = &[];
    match scenario {
        ScenarioId::NoBench | ScenarioId::MonitoredDay => NOTHING,
        ScenarioId::CardEm4100
        | ScenarioId::CardClone
        | ScenarioId::CardHidProx
        | ScenarioId::CardMifare
        | ScenarioId::CardDesfire => CARD,
        ScenarioId::WiegandDoor
        | ScenarioId::WiegandParityFlip
        | ScenarioId::WiegandImplant
        | ScenarioId::WiegandSweep
        | ScenarioId::ClockDataDoor => LEGACY,
        _ => OSDP,
    }
}

/// **Why this scenario cannot accept this option**, or `None` if it can.
///
/// The interface uses this for the fields it still has to *show* — "collapse,
/// never remove" means a Wiegand bench still states that Secure Channel is off,
/// it just cannot be asked to turn it on — so the sentence goes straight to the
/// learner and says what the bench *is* rather than what the code does.
pub fn unsupported_reason(scenario: ScenarioId, id: &str) -> Option<String> {
    (!accepted(scenario).contains(&id)).then(|| why_not(scenario, id))
}

fn why_not(scenario: ScenarioId, id: &str) -> String {
    match scenario {
        ScenarioId::NoBench => {
            return "Drill 0.6 simulates nothing — it is the reference section in docs/BYPASS.md. \
                    There is no bench here to configure."
                .to_owned()
        }
        ScenarioId::MonitoredDay => {
            return "Module 5 scores a generated day of captured traffic rather than driving a \
                    live bench. There is nothing here to reconfigure; the capture already \
                    happened."
                .to_owned()
        }
        _ => {}
    }
    let card = matches!(
        scenario,
        ScenarioId::CardEm4100
            | ScenarioId::CardClone
            | ScenarioId::CardHidProx
            | ScenarioId::CardMifare
            | ScenarioId::CardDesfire
    );
    match id {
        LINK => "This bench is an RS-485 multidrop bus. The Wiegand and clock-and-data pairs are \
                 Module 1's benches — swapping one for the other is not a setting, it is a \
                 different door."
            .to_owned(),
        FORMAT if card => "On a Module 0 bench the credential is the subject, and its format is a \
                           property of the card rather than of the panel. Change it on a Module 1 \
                           bench, where the wire is what carries it."
            .to_owned(),
        SECURE_CHANNEL | KEY | NULL_CIPHER | MAC_BYTES | PD_AES => {
            "There is no Secure Channel on a Wiegand or clock-and-data pair. Neither protocol has \
             any cryptography in its specification — that absence is the whole of Module 1, and \
             there is nothing here to turn on."
                .to_owned()
        }
        TRUST_PDCAP | ACU_INSTALL | PD_INSTALL => {
            "A legacy reader drives two wires and has no way of hearing a reply, so there is no \
             capability report to trust and no key to hand out. This starts at Module 2."
                .to_owned()
        }
        BAUD | POLL_MS => "A Wiegand pair is not a bus: nothing polls it, and its rate is the \
                           reader's own pulse timing rather than a line rate."
            .to_owned(),
        _ => format!("{} does not apply to the {} bench.", id, scenario.name()),
    }
}

/// **The option list for a bench, as data the interface renders.**
///
/// `drill` is the drill currently loaded, or `None` for free play. It changes
/// nothing about which options are accepted — only whether a value comes back
/// carrying a [`OptionSpec::warning`].
pub fn describe(
    scenario: ScenarioId,
    drill: Option<DrillId>,
    opts: &BenchOptions,
) -> Vec<OptionSpec> {
    let r = opts.resolve(scenario);
    let ids = accepted(scenario);
    let all = defs();
    let mut out = Vec::new();
    for id in ids {
        let Some(def) = all.iter().find(|d| d.id == *id) else {
            continue;
        };
        let value = current(&r, def.id);
        out.push(OptionSpec {
            id: def.id,
            label: def.label,
            group: def.group,
            kind: def.kind.clone(),
            critical: is_critical(def.id, &value),
            value,
            help: def.help,
            changed: opts.is_set(def.id),
            warning: drill.and_then(|d| warning(d, def.id, &r)),
        });
    }
    out
}

fn current(r: &Resolved, id: &str) -> OptionValue {
    match id {
        SECURE_CHANNEL => OptionValue::Choice(sc_name(r.sc).to_owned()),
        KEY => OptionValue::Choice(r.key.name().to_owned()),
        TRUST_PDCAP => OptionValue::Bool(r.trust_pdcap),
        ACU_INSTALL => OptionValue::Bool(r.acu_install_mode),
        PD_INSTALL => OptionValue::Bool(r.pd_install_mode),
        PD_AES => OptionValue::Bool(r.pd_claims_aes),
        NULL_CIPHER => OptionValue::Bool(r.null_cipher),
        MAC_BYTES => OptionValue::Number(i64::from(r.mac_bytes)),
        BAUD => OptionValue::Choice(r.baud.to_string()),
        POLL_MS => OptionValue::Number(i64::from(r.poll_ms)),
        LINK => OptionValue::Choice(r.link.name().to_owned()),
        FORMAT => OptionValue::Choice(format_name(r.format).to_owned()),
        STRIKE_MS => OptionValue::Number(i64::from(r.strike_ms)),
        _ => OptionValue::Bool(false),
    }
}

fn is_critical(id: &str, v: &OptionValue) -> bool {
    match (id, v) {
        (SECURE_CHANNEL, OptionValue::Choice(c)) => c == "off",
        (KEY, OptionValue::Choice(c)) => c == "scbk-d" || c == "weak",
        (ACU_INSTALL, OptionValue::Bool(b)) | (PD_INSTALL, OptionValue::Bool(b)) => *b,
        (NULL_CIPHER, OptionValue::Bool(b)) => *b,
        (PD_AES, OptionValue::Bool(b)) => !*b,
        (MAC_BYTES, OptionValue::Number(n)) => *n < 4,
        _ => false,
    }
}

/// **What this setting breaks about the drill that is loaded.**
///
/// A sentence, not a refusal. The bench builds either way; this is the text
/// `docs/UI.md` asks to be printed next to the control.
fn warning(drill: DrillId, id: &str, r: &Resolved) -> Option<String> {
    let sc_off = !r.sc.wants_secure_channel();
    let d = (drill.module, drill.index);
    let msg = match (d, id) {
        // Module 2 is the bus in the clear. Encrypting it removes the lesson.
        ((2, 1..=4), SECURE_CHANNEL) if !sc_off => {
            "Module 2 is about a bus with nothing configured on it. With Secure Channel on, the \
             card read is sealed and this drill's flag cannot be earned."
        }
        // Module 3 and 4 need a channel to attack.
        ((3, _) | (4, 1..=4), SECURE_CHANNEL) if sc_off => {
            "This drill is about attacking a secure channel. With Secure Channel off there is no \
             handshake to capture, and the flag cannot be earned."
        }
        ((3, 1 | 2), KEY) if r.key != KeyChoice::Default => {
            "Drill 3.2 is about recognising SCBK-D — the key printed in the manual — from the \
             handshake and then decrypting everything with it. On any other key there is nothing \
             published to recognise, and the flag cannot be earned."
        }
        ((3, 3), KEY) if r.key != KeyChoice::Weak => {
            "Drill 3.3 sweeps the published sample-key family. On a key that is not from that \
             family there is nothing for the sweep to find, and the flag cannot be earned."
        }
        ((3, 4), ACU_INSTALL) if !r.acu_install_mode => {
            "Drill 3.4 asks a controller in install mode for the key. With install mode off it \
             will not answer, and the flag cannot be earned — which is the fix, and worth seeing."
        }
        ((3, 5) | (4, 3), ACU_INSTALL) if !r.acu_install_mode => {
            "There is no commissioning without install mode, so no CMD_KEYSET crosses the bus and \
             there is nothing to capture."
        }
        ((3, 6), TRUST_PDCAP) if !r.trust_pdcap => {
            "This is the defence. With the capability reply distrusted the controller runs the \
             handshake anyway, the downgrade is refused, and drill 3.6's flag cannot be earned — \
             which is exactly what drill 5.2 asks you to detect."
        }
        ((3, 6), SECURE_CHANNEL) if r.sc != ScRequirement::Required => {
            "Drill 3.6's flag says both endpoints were configured to require Secure Channel. \
             Below that setting a cleartext link is policy, not a downgrade."
        }
        ((3, 6), PD_AES) if !r.pd_claims_aes => {
            "A reader that never claimed AES-128 is a legacy reader, not a downgraded one. \
             Drill 5.2 is about telling those two apart."
        }
        ((4, 1), NULL_CIPHER) if r.null_cipher => {
            "Drill 4.1's lesson is that the schedule is legible *through* encryption. With the \
             null cipher on, the card numbers are legible too and the point is lost."
        }
        ((4, 2), MAC_BYTES) if r.mac_bytes >= 4 => {
            "Four bytes is the honest width, and at four the forgery does not finish — that is \
             drill 4.2's other half and the crawling bar says so. The flag needs the rigged bench."
        }
        ((4, 4), NULL_CIPHER) if !r.null_cipher => {
            "Drill 4.4 reads a payload off a MACed-but-unencrypted link. With encryption on there \
             is nothing in the clear to read."
        }
        ((1, 6), LINK) if r.link != LinkChoice::ClockData => {
            "Drill 1.6 is the clock-and-data twin of 1.3. On a Wiegand pair it is 1.3."
        }
        ((1, 1..=5), LINK) if r.link != LinkChoice::Wiegand => {
            "This drill's guidance and its hand-decoding walk-through are written for a D0/D1 \
             pair. The bench runs on clock-and-data, but the prose beside it will not match."
        }
        ((1, 2), FORMAT) if r.format != CardFormat::H10301 => {
            "Drill 1.2's bench enrols the card number one bit away from the one presented. The \
             flip still works in any format; the guidance counts H10301's twenty-six bits."
        }
        ((2, 1), FORMAT) if r.format != CardFormat::H10301 => {
            "Drill 2.1 asks for byte offsets in the frame the bus actually carried, so the \
             answer moves with the format. The guidance names H10301's."
        }
        ((0, _), _) => return None,
        _ => return None,
    };
    Some(msg.to_owned())
}

// ---------------------------------------------------------------------------
// Setting one
// ---------------------------------------------------------------------------

/// **Set one option, or refuse with a reason.**
///
/// Refuses when the scenario does not accept the option at all, or when the
/// value is not one of the option's declared legal values. It does **not**
/// refuse because a drill is loaded: see the module docs.
pub fn apply(
    scenario: ScenarioId,
    opts: &mut BenchOptions,
    id: &str,
    value: &str,
) -> Result<BenchOptions> {
    let all = defs();
    let Some(def) = all.iter().find(|d| d.id == id) else {
        return Err(ScenarioError::OptionRefused {
            option: id.to_owned(),
            reason: format!("there is no bench option called {id}"),
        });
    };
    if !accepted(scenario).contains(&def.id) {
        return Err(ScenarioError::OptionRefused {
            option: id.to_owned(),
            reason: why_not(scenario, def.id),
        });
    }
    let refuse = |reason: String| ScenarioError::OptionRefused {
        option: id.to_owned(),
        reason,
    };
    match &def.kind {
        OptionKind::Boolean => {
            let v = match value {
                "true" | "yes" | "on" | "1" => true,
                "false" | "no" | "off" | "0" => false,
                other => {
                    return Err(refuse(format!(
                        "{other:?} is not a yes or a no; this option takes true or false"
                    )))
                }
            };
            set_bool(opts, def.id, v);
        }
        OptionKind::Choice(choices) => {
            if !choices.iter().any(|(v, _)| *v == value) {
                let legal: Vec<&str> = choices.iter().map(|(v, _)| *v).collect();
                return Err(refuse(format!(
                    "{value:?} is not one of this option's values: {}",
                    legal.join(", ")
                )));
            }
            set_choice(opts, def.id, value);
        }
        OptionKind::Number { min, max, unit } => {
            let Ok(n) = value.parse::<i64>() else {
                return Err(refuse(format!("{value:?} is not a whole number of {unit}")));
            };
            if n < *min || n > *max {
                return Err(refuse(format!(
                    "{n} {unit} is outside this option's range of {min} to {max}"
                )));
            }
            set_number(opts, def.id, n);
        }
    }
    Ok(opts.clone())
}

fn set_bool(o: &mut BenchOptions, id: &str, v: bool) {
    match id {
        TRUST_PDCAP => o.trust_pdcap = Some(v),
        ACU_INSTALL => o.acu_install_mode = Some(v),
        PD_INSTALL => o.pd_install_mode = Some(v),
        PD_AES => o.pd_claims_aes = Some(v),
        NULL_CIPHER => o.null_cipher = Some(v),
        _ => {}
    }
}

fn set_choice(o: &mut BenchOptions, id: &str, v: &str) {
    match id {
        SECURE_CHANNEL => o.secure_channel = sc_parse(v),
        KEY => o.key = KeyChoice::parse(v),
        LINK => o.link = LinkChoice::parse(v),
        FORMAT => o.format = format_parse(v),
        BAUD => o.baud = v.parse::<u32>().ok(),
        _ => {}
    }
}

fn set_number(o: &mut BenchOptions, id: &str, n: i64) {
    match id {
        MAC_BYTES => o.mac_bytes = Some(n as u8),
        POLL_MS => o.poll_ms = Some(n as u32),
        STRIKE_MS => o.strike_ms = Some(n as u32),
        _ => {}
    }
}
