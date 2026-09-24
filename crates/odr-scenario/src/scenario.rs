//! **The benches.** One scenario per distinct configuration the curriculum
//! needs, and no more.
//!
//! A scenario is a *starting position*, not a script with an attack in it. It
//! assembles a door system with [`odr_bus::WorldBuilder`] — card, reader, link,
//! controller, door — configures the two endpoints the way the drill's lesson
//! requires, and hands back a [`Bench`] that has not yet been interfered with.
//! Pressing Run on an untouched bench produces a day at that door and nothing
//! else: no injected frames, no substituted credentials, no open door that
//! nobody badged for.
//!
//! That separation is what makes the negative half of a flag test meaningful.
//! [`crate::run::baseline`] runs exactly this bench with no actor clipped to it
//! and asserts the flag is *not* earned; [`crate::run::solve`] runs the same
//! bench with the attack performed. If a flag is earnable without the attack,
//! the first of those fails — which is how drill 1.3's originally-free flag was
//! caught.
//!
//! # Where the traffic comes from
//!
//! Each bench carries a [`Script`]: the badge-ins the door sees, at virtual
//! microsecond timestamps, plus how long to run. The credentials in it are
//! derived from the session seed rather than written down here, because drill
//! 1.1's flag is "learner-submitted facility code and card number match what
//! the engine transmitted, **for a credential the engine randomised from the
//! session seed**". A constant in this file would make that flag a lookup.

use alloc::string::String;
use alloc::vec::Vec;

use odr_bus::{
    clock_data_bench, osdp_bench, wiegand_bench, AccessList, AcuConfig, ClockDataConfig,
    ControllerId, DoorId, LinkId, Micros, OsdpBenchSpec, PdConfig, Presentation, ReaderId,
    Rs485Timing, ScRequirement, SourceId, World,
};
use odr_credential::hid_prox::H10301;
use odr_credential::mifare::{AccessBits, MifareClassic1k, DEFAULT_KEY};
use odr_credential::Rng;
use odr_osdp::SCBK_D;
use odr_wiegand::{AbaEncoding, BitVec, CardFormat, Credential};

use crate::error::{Result, ScenarioError};
use crate::ids::LinkRole;

/// The address every single-peripheral OSDP bench polls.
pub const PD_ADDRESS: u8 = 0x01;

/// An address an OSDP controller polls but no real reader answers.
///
/// Drill 3.4 needs one: the harvester answers for an address the installer
/// configured and never fitted, which is the gap install mode is walked through.
pub const SPARE_ADDRESS: u8 = 0x02;

/// **Which bench.**
///
/// The list is derived from `docs/CURRICULUM.md` by taking every drill's
/// required configuration and collapsing the duplicates: drills 1.1, 1.2, 1.3
/// and 1.5 all run on the same Wiegand door, so they share one entry here.
///
/// Additive: new scenarios may appear, so match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ScenarioId {
    /// A 125 kHz EM4100 tag at a reader on a Wiegand door. Drill 0.1.
    CardEm4100,
    /// An HID Prox card whose victim has been brushed past. Drill 0.2.
    CardClone,
    /// An HID Prox card, for the walk from the RF layer to the wire. Drill 0.3.
    CardHidProx,
    /// A MIFARE Classic 1k with one sector still on the transport key.
    /// Drill 0.4.
    CardMifare,
    /// A DESFire EV2 card, as the working contrast. Drill 0.5.
    CardDesfire,
    /// No bench at all. Drill 0.6 is prose (`docs/BYPASS.md`).
    NoBench,
    /// A Wiegand door: reader, D0/D1 pair, panel, strike. Drills 1.1, 1.2, 1.3
    /// and 1.5.
    WiegandDoor,
    /// The same door, with a neighbouring card number enrolled and the
    /// learner's not: one bit apart, and the parity recomputed. Drill 1.2.
    WiegandParityFlip,
    /// The same door, with somebody else's badge on the access list and the
    /// learner's not. Drill 1.4.
    WiegandImplant,
    /// The same door with a low card number enrolled, so an honest sweep from
    /// zero reaches it. Drill 1.5.
    WiegandSweep,
    /// A door on a clock-and-data pair. Drill 1.6.
    ClockDataDoor,
    /// An OSDP link with no Secure Channel configured at either end. Drills
    /// 2.1, 2.2, 2.3 and 2.4.
    OsdpClear,
    /// An OSDP link commissioned with SCBK-D, the published default key.
    /// Drills 3.1 and 3.2.
    OsdpDefaultKey,
    /// An OSDP link whose site key is not SCBK-D but is still from the
    /// sample-code family. Drill 3.3.
    OsdpWeakKey,
    /// A controller left in install mode, polling an address nobody fitted.
    /// Drill 3.4.
    OsdpInstallMode,
    /// An installer commissioning a fresh reader: default key, `CMD_KEYSET`,
    /// re-handshake. Drills 3.5 and 4.3.
    OsdpCommissioning,
    /// Both endpoints configured to require Secure Channel. Drill 3.6.
    OsdpRequiredSc,
    /// A fully encrypted link carrying a day of badge-ins. Drill 4.1.
    OsdpEncryptedDay,
    /// A Secure Channel link with the MAC shortened so a forgery completes
    /// while a learner is watching. Drill 4.2.
    OsdpShortMac,
    /// A Secure Channel link running the null ciphers: authenticated, not
    /// encrypted. Drill 4.4.
    OsdpNullCipher,
    /// Not a bench but a capture: a generated day of mixed traffic seen from a
    /// monitoring position. Drills 5.1, 5.2 and 5.3.
    MonitoredDay,
}

impl ScenarioId {
    /// Every scenario, in curriculum order.
    pub const ALL: &'static [ScenarioId] = &[
        ScenarioId::CardEm4100,
        ScenarioId::CardClone,
        ScenarioId::CardHidProx,
        ScenarioId::CardMifare,
        ScenarioId::CardDesfire,
        ScenarioId::NoBench,
        ScenarioId::WiegandDoor,
        ScenarioId::WiegandParityFlip,
        ScenarioId::WiegandImplant,
        ScenarioId::WiegandSweep,
        ScenarioId::ClockDataDoor,
        ScenarioId::OsdpClear,
        ScenarioId::OsdpDefaultKey,
        ScenarioId::OsdpWeakKey,
        ScenarioId::OsdpInstallMode,
        ScenarioId::OsdpCommissioning,
        ScenarioId::OsdpRequiredSc,
        ScenarioId::OsdpEncryptedDay,
        ScenarioId::OsdpShortMac,
        ScenarioId::OsdpNullCipher,
        ScenarioId::MonitoredDay,
    ];

    /// The stable string id. `site/ENGINE-API.md` reports this as
    /// `Drill.scenario`, informationally.
    pub fn name(self) -> &'static str {
        match self {
            ScenarioId::CardEm4100 => "card-em4100",
            ScenarioId::CardClone => "card-clone",
            ScenarioId::CardHidProx => "card-hid-prox",
            ScenarioId::CardMifare => "card-mifare",
            ScenarioId::CardDesfire => "card-desfire",
            ScenarioId::NoBench => "no-bench",
            ScenarioId::WiegandDoor => "wiegand-door",
            ScenarioId::WiegandParityFlip => "wiegand-parity-flip",
            ScenarioId::WiegandImplant => "wiegand-implant",
            ScenarioId::WiegandSweep => "wiegand-sweep",
            ScenarioId::ClockDataDoor => "clock-data-door",
            ScenarioId::OsdpClear => "osdp-clear",
            ScenarioId::OsdpDefaultKey => "osdp-default-key",
            ScenarioId::OsdpWeakKey => "osdp-weak-key",
            ScenarioId::OsdpInstallMode => "osdp-install-mode",
            ScenarioId::OsdpCommissioning => "osdp-commissioning",
            ScenarioId::OsdpRequiredSc => "osdp-required-sc",
            ScenarioId::OsdpEncryptedDay => "osdp-encrypted-day",
            ScenarioId::OsdpShortMac => "osdp-short-mac",
            ScenarioId::OsdpNullCipher => "osdp-null-cipher",
            ScenarioId::MonitoredDay => "monitored-day",
        }
    }

    /// Parse the string id back.
    pub fn parse(s: &str) -> Option<ScenarioId> {
        ScenarioId::ALL.iter().copied().find(|x| x.name() == s)
    }

    /// One sentence on what this bench is, for the bench strip.
    pub fn summary(self) -> &'static str {
        match self {
            ScenarioId::CardEm4100 => {
                "a 125 kHz EM4100 tag and a reader that will believe anything that answers"
            }
            ScenarioId::CardClone => {
                "an HID Prox badge, a blank, and a door whose panel knows only the number"
            }
            ScenarioId::CardHidProx => {
                "an HID Prox badge on a Wiegand door: the same bits on the air and on the wire"
            }
            ScenarioId::CardMifare => {
                "a MIFARE Classic 1k with one sector still on the factory transport key"
            }
            ScenarioId::CardDesfire => "a DESFire EV2 card, and the same attacks aimed at it",
            ScenarioId::NoBench => "no bench: this section simulates nothing and says so",
            ScenarioId::WiegandDoor => "reader, D0/D1 pair, panel, strike; no crypto anywhere",
            ScenarioId::WiegandParityFlip => {
                "the same door, with the card number one bit away from yours enrolled"
            }
            ScenarioId::WiegandImplant => {
                "the same door, with a manager's badge enrolled and the learner's not"
            }
            ScenarioId::WiegandSweep => {
                "the same door with a low card number enrolled, so a sweep from zero reaches it"
            }
            ScenarioId::ClockDataDoor => "the same door on a clock-and-data pair, ABA track 2",
            ScenarioId::OsdpClear => "an OSDP controller polling one reader, Secure Channel off",
            ScenarioId::OsdpDefaultKey => "OSDP with Secure Channel keyed by the published SCBK-D",
            ScenarioId::OsdpWeakKey => {
                "OSDP under a site key that is not the default and is still from the sample family"
            }
            ScenarioId::OsdpInstallMode => {
                "a controller left in install mode, polling an address nobody ever fitted"
            }
            ScenarioId::OsdpCommissioning => {
                "an installer commissioning a fresh reader, with somebody on the bus"
            }
            ScenarioId::OsdpRequiredSc => {
                "both endpoints configured to require Secure Channel, and a controller that \
                 decides from the capability reply"
            }
            ScenarioId::OsdpEncryptedDay => {
                "a fully encrypted link carrying a day of badge-ins at one door"
            }
            ScenarioId::OsdpShortMac => {
                "Secure Channel with the MAC shortened so a forgery finishes while you watch"
            }
            ScenarioId::OsdpNullCipher => {
                "Secure Channel with encryption off: SCS_15/16, authenticated and readable"
            }
            ScenarioId::MonitoredDay => {
                "not a bench: a generated day of mixed traffic, seen from a probe in the riser"
            }
        }
    }

    /// Whether this scenario builds a [`Bench`] at all.
    pub fn is_bench(self) -> bool {
        !matches!(self, ScenarioId::NoBench | ScenarioId::MonitoredDay)
    }

    /// The transport on the reader-to-controller link, for the topology strip.
    pub fn link_protocol(self) -> &'static str {
        match self {
            ScenarioId::ClockDataDoor => "clockdata",
            ScenarioId::CardEm4100
            | ScenarioId::CardClone
            | ScenarioId::CardHidProx
            | ScenarioId::CardMifare
            | ScenarioId::CardDesfire
            | ScenarioId::WiegandDoor
            | ScenarioId::WiegandParityFlip
            | ScenarioId::WiegandImplant
            | ScenarioId::WiegandSweep => "wiegand",
            ScenarioId::NoBench => "none",
            _ => "osdp",
        }
    }

    /// A per-scenario salt mixed into the session seed.
    ///
    /// Two drills on the same bench should not produce identical nonces just
    /// because they share a seed, and two different benches on the same seed
    /// should not either. The salt is the scenario's position in [`Self::ALL`],
    /// so it is stable and reviewable rather than a magic constant.
    pub fn salt(self) -> u64 {
        let i = ScenarioId::ALL.iter().position(|x| *x == self).unwrap_or(0) as u64;
        0x9E37_79B9_7F4A_7C15u64.wrapping_mul(i + 1)
    }
}

/// **The cards a bench has in it**, as data rather than as live objects.
///
/// `odr-bus` deliberately does not depend on `odr-credential` (see that crate's
/// README, "the credential seam"), so a bench cannot hold a `Card`. It holds
/// the parameters one is built from instead, which keeps a [`Bench`] cheap to
/// clone-in-spirit, keeps it `Debug`, and — more usefully — means the card is
/// rebuilt identically every time from the same seed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CardSetup {
    /// No card layer in this scenario.
    None,
    /// A 125 kHz EM4100 tag, identified by its 40-bit id.
    Em4100 {
        /// The id the engine generated from the seed.
        id40: u64,
    },
    /// A 125 kHz HID Prox card.
    HidProx {
        /// Facility code.
        facility_code: u8,
        /// Card number.
        card_number: u16,
    },
    /// A 13.56 MHz MIFARE Classic 1k.
    MifareClassic {
        /// The card's UID.
        uid: u32,
        /// The seed its own nonce generator runs from.
        card_seed: u64,
        /// Key A per sector, sixteen of them. Sector 0's is the published
        /// transport default, which is the attacker's way in.
        key_a: Vec<u64>,
        /// Which block carries the credential.
        credential_block: u8,
        /// What is in it.
        credential: [u8; 16],
    },
    /// A 13.56 MHz DESFire EV2 card.
    Desfire {
        /// The card's UID.
        uid: u32,
        /// The AES key for application key 0.
        key: [u8; 16],
        /// Which file carries the credential.
        file: u8,
        /// What is in it.
        contents: Vec<u8>,
    },
}

/// One badge-in in a bench's default traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptedBadge {
    /// When, in virtual microseconds.
    pub at_us: Micros,
    /// Which physical token — a clone is not its original, and drill 0.2 turns
    /// entirely on that distinction.
    pub source: SourceId,
    /// What it emits.
    pub credential: Credential,
}

/// **What an untouched bench does when you press Run.**
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Script {
    /// The badge-ins, in time order.
    pub badges: Vec<ScriptedBadge>,
    /// How long the bench runs for.
    pub duration_us: Micros,
}

/// **An assembled bench, before anybody has interfered with it.**
#[derive(Debug)]
pub struct Bench {
    /// Which scenario built it.
    pub scenario: ScenarioId,
    /// The seed it was built from, salted by the scenario.
    pub seed: u64,
    /// The world.
    pub world: World,
    /// The reader or peripheral, when the scenario has one.
    pub reader: Option<ReaderId>,
    /// The panel or controller.
    pub controller: ControllerId,
    /// The door.
    pub door: DoorId,
    /// The reader-to-controller link.
    pub link: LinkId,
    /// The cards, as parameters.
    pub cards: CardSetup,
    /// The default traffic.
    pub script: Script,
    /// The PD address, for the OSDP scenarios.
    pub address: u8,
    /// An address the controller polls that no real reader answers, when the
    /// scenario has one.
    pub spare_address: Option<u8>,
    /// The site key the endpoints were commissioned with, when the scenario
    /// configured one. Ground truth — a predicate compares an attacker's
    /// recovered key against it, and nothing hands it to an attacker.
    pub site_key: Option<[u8; 16]>,
}

impl Bench {
    /// The link role a tap goes on. Every bench here has exactly one tappable
    /// link between reader and controller.
    pub fn link_role(&self) -> LinkRole {
        LinkRole::ReaderToController
    }

    /// Queue the default traffic and run the bench to the end of its script.
    ///
    /// This is what pressing Run does with nothing clipped on. It is also the
    /// first half of every solved drill, because an attacker with nothing to
    /// listen to has nothing to work with.
    pub fn run_script(&mut self) -> Result<()> {
        let target = self.reader.ok_or(ScenarioError::DidNotRun {
            drill: crate::ids::DrillId::new(0, 0),
            detail: String::from("this bench has no reader to present a credential to"),
        })?;
        for badge in &self.script.badges {
            let bits = badge.credential.encode()?;
            let p = Presentation::new(
                badge.source,
                odr_bus::FormatId::for_card_format(badge.credential.format),
                bits,
            );
            self.world.present(target, badge.at_us, p)?;
        }
        self.world.run_until(self.script.duration_us)?;
        Ok(())
    }

    /// Present one extra credential at a chosen time.
    pub fn present(&mut self, at_us: Micros, source: SourceId, cred: &Credential) -> Result<()> {
        let target = self.reader.ok_or(ScenarioError::DidNotRun {
            drill: crate::ids::DrillId::new(0, 0),
            detail: String::from("this bench has no reader to present a credential to"),
        })?;
        let p = Presentation::new(
            source,
            odr_bus::FormatId::for_card_format(cred.format),
            cred.encode()?,
        );
        self.world.present(target, at_us, p)?;
        Ok(())
    }

    /// The first credential in the script, which is the one most drills are
    /// about.
    pub fn primary_credential(&self) -> Option<&Credential> {
        self.script.badges.first().map(|b| &b.credential)
    }
}

/// Derive a credential from a seed.
///
/// H10301 is 26 bits: eight of facility code and sixteen of card number, which
/// is the whole of the format's "security". The values come from the seed so a
/// learner cannot read drill 1.1's answer out of this file.
fn seeded_credential(rng: &mut Rng) -> Credential {
    let fc = u64::from(rng.next_u32() & 0xFF);
    let cn = u64::from(rng.next_u32() & 0xFFFF);
    Credential::new(CardFormat::H10301, fc, cn)
}

/// Build a bench.
///
/// The seed is the session seed; the scenario salts it, so the same session
/// gives every drill different nonces and the same drill the same ones.
pub fn build(scenario: ScenarioId, seed: u64) -> Result<Bench> {
    let salted = seed ^ scenario.salt();
    match scenario {
        ScenarioId::NoBench => Err(ScenarioError::UnknownScenario {
            id: String::from(scenario.name()),
        }),
        ScenarioId::MonitoredDay => Err(ScenarioError::UnknownScenario {
            id: String::from(scenario.name()),
        }),
        ScenarioId::CardEm4100 => build_em4100(salted),
        ScenarioId::CardClone => build_clone(salted),
        ScenarioId::CardHidProx => build_hid_prox(salted),
        ScenarioId::CardMifare => build_mifare(salted),
        ScenarioId::CardDesfire => build_desfire(salted),
        ScenarioId::WiegandDoor => build_wiegand_door(salted),
        ScenarioId::WiegandParityFlip => build_wiegand_parity_flip(salted),
        ScenarioId::WiegandImplant => build_wiegand_implant(salted),
        ScenarioId::WiegandSweep => build_wiegand_sweep(salted),
        ScenarioId::ClockDataDoor => build_clock_data(salted),
        ScenarioId::OsdpClear => build_osdp_clear(salted),
        ScenarioId::OsdpDefaultKey => build_osdp_default_key(salted),
        ScenarioId::OsdpWeakKey => build_osdp_weak_key(salted),
        ScenarioId::OsdpInstallMode => build_osdp_install_mode(salted),
        ScenarioId::OsdpCommissioning => build_osdp_commissioning(salted),
        ScenarioId::OsdpRequiredSc => build_osdp_required_sc(salted),
        ScenarioId::OsdpEncryptedDay => build_osdp_encrypted_day(salted),
        ScenarioId::OsdpShortMac => build_osdp_short_mac(salted),
        ScenarioId::OsdpNullCipher => build_osdp_null_cipher(salted),
    }
}

// ---------------------------------------------------------------------------
// Module 0 — the card layer, on a door
// ---------------------------------------------------------------------------

/// Drill 0.1. The tag's id comes from the seed, so the flag is a comparison
/// against something the engine generated rather than against a constant.
fn build_em4100(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let id40 = rng.next_u64() & 0xFF_FFFF_FFFF;
    let bench = wiegand_bench(seed, AccessList::allow_all())?;
    Ok(Bench {
        scenario: ScenarioId::CardEm4100,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::Em4100 { id40 },
        // The badge-in is driven by the drill, because the credential it puts
        // on the wire is the EM4100 frame rather than a Wiegand card format.
        script: Script {
            badges: Vec::new(),
            duration_us: 4_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

/// Drill 0.2. The panel is configured for whatever the victim's badge emits,
/// which is exactly the configuration every real panel has.
fn build_clone(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let facility_code = (rng.next_u32() & 0xFF) as u8;
    let card_number = (rng.next_u32() & 0xFFFF) as u16;
    let victim = H10301::new(facility_code, card_number);
    let bits = BitVec::from_bools(&odr_credential::h10301_wiegand_bits(&victim));
    let access = AccessList::new()
        .with_bits(bits)
        .assuming(CardFormat::H10301);
    let bench = wiegand_bench(seed, access)?;
    Ok(Bench {
        scenario: ScenarioId::CardClone,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::HidProx {
            facility_code,
            card_number,
        },
        script: Script {
            badges: Vec::new(),
            duration_us: 5_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

/// Drill 0.3. The same card, presented honestly, so the learner can compare
/// what they predicted with what crossed the wire.
fn build_hid_prox(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let facility_code = (rng.next_u32() & 0xFF) as u8;
    let card_number = (rng.next_u32() & 0xFFFF) as u16;
    let cred = Credential::new(
        CardFormat::H10301,
        u64::from(facility_code),
        u64::from(card_number),
    );
    let access = AccessList::new()
        .with_credential(&cred)?
        .assuming(CardFormat::H10301);
    let bench = wiegand_bench(seed, access)?;
    Ok(Bench {
        scenario: ScenarioId::CardHidProx,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::HidProx {
            facility_code,
            card_number,
        },
        script: Script {
            badges: alloc::vec![ScriptedBadge {
                at_us: 1_000_000,
                source: SourceId(0),
                credential: cred,
            }],
            duration_us: 4_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

/// Drill 0.4. Sector 0 is on the published transport key; everything else is
/// seeded. One sector on a factory default is the whole of the attacker's
/// starting position, and it is what a nested attack needs.
fn build_mifare(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let uid = rng.next_u32();
    let card_seed = rng.next_u64();
    let mut key_a = alloc::vec![DEFAULT_KEY];
    for _ in 1..16u8 {
        key_a.push(rng.next_crypto1_key());
    }
    let mut credential = [0u8; 16];
    for (i, b) in credential.iter_mut().enumerate().take(5) {
        *b = (rng.next_u32() >> (i as u32 & 7)) as u8;
    }
    let bench = wiegand_bench(seed, AccessList::allow_all())?;
    Ok(Bench {
        scenario: ScenarioId::CardMifare,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::MifareClassic {
            uid,
            card_seed,
            key_a,
            credential_block: 4,
            credential,
        },
        script: Script {
            badges: Vec::new(),
            duration_us: 4_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

/// Drill 0.5. The contrast card. Its key is seeded and never leaves it — which
/// is the entire lesson.
fn build_desfire(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let uid = rng.next_u32();
    let mut key = [0u8; 16];
    for b in key.iter_mut() {
        *b = (rng.next_u32() & 0xFF) as u8;
    }
    let mut contents = alloc::vec![0u8; 8];
    for b in contents.iter_mut() {
        *b = (rng.next_u32() & 0xFF) as u8;
    }
    let bench = wiegand_bench(seed, AccessList::allow_all())?;
    Ok(Bench {
        scenario: ScenarioId::CardDesfire,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::Desfire {
            uid,
            key,
            file: 1,
            contents,
        },
        script: Script {
            badges: Vec::new(),
            duration_us: 4_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

// ---------------------------------------------------------------------------
// Module 1 — the wire
// ---------------------------------------------------------------------------

/// Drills 1.1, 1.2, 1.3 and 1.5. One enrolled card, one badge-in.
fn build_wiegand_door(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let cred = seeded_credential(&mut rng);
    let access = AccessList::new()
        .with_credential(&cred)?
        .assuming(CardFormat::H10301);
    let bench = wiegand_bench(seed, access)?;
    Ok(Bench {
        scenario: ScenarioId::WiegandDoor,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::None,
        script: Script {
            badges: alloc::vec![ScriptedBadge {
                at_us: 1_000_000,
                source: SourceId(0),
                credential: cred,
            }],
            duration_us: 3_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

/// Drill 1.2. The enrolled card number is one bit away from the one presented
/// at the door, so flipping that bit and recomputing the parity produces a
/// frame the panel is happy with and a person it has never met.
///
/// The neighbour is derived from the presented credential rather than drawn
/// again from the seed, because "one bit away" is the whole lesson: parity
/// covers the bits and says nothing about who they belong to.
fn build_wiegand_parity_flip(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let visitor = seeded_credential(&mut rng);
    let neighbour = Credential::new(
        CardFormat::H10301,
        visitor.facility_code.unwrap_or(0),
        visitor.card_number ^ 1,
    );
    let access = AccessList::new()
        .with_credential(&neighbour)?
        .assuming(CardFormat::H10301);
    let bench = wiegand_bench(seed, access)?;
    Ok(Bench {
        scenario: ScenarioId::WiegandParityFlip,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::None,
        script: Script {
            badges: alloc::vec![ScriptedBadge {
                at_us: 1_000_000,
                source: SourceId(0),
                credential: visitor,
            }],
            duration_us: 3_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

/// Drill 1.4. The learner's badge is **not** on the list and a manager's is,
/// which is what makes a substitution worth performing.
///
/// The manager's credential is not in the script: it never goes near the door.
/// The implant has to produce it.
fn build_wiegand_implant(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let visitor = seeded_credential(&mut rng);
    let mut manager = seeded_credential(&mut rng);
    if manager == visitor {
        manager = Credential::new(
            CardFormat::H10301,
            manager.facility_code.unwrap_or(0),
            manager.card_number ^ 1,
        );
    }
    let access = AccessList::new()
        .with_credential(&manager)?
        .assuming(CardFormat::H10301);
    let bench = wiegand_bench(seed, access)?;
    Ok(Bench {
        scenario: ScenarioId::WiegandImplant,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::None,
        script: Script {
            badges: alloc::vec![ScriptedBadge {
                at_us: 1_000_000,
                source: SourceId(0),
                credential: visitor,
            }],
            duration_us: 3_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

/// Drill 1.5. The enrolled card number is small, so a sweep that starts at zero
/// and counts up reaches it in a plausible number of frames.
///
/// That is a compromise and it is worth naming: a real sweep does not know
/// where in the space to look, and the figure the drill ends on is computed for
/// the **whole** space at this bench's timing rather than for the short range
/// actually swept. Low card numbers are real — sites number from 1 — but the
/// reason this particular bench has one is so the demonstration fits in a
/// browser tab.
fn build_wiegand_sweep(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let facility_code = u64::from(rng.next_u32() & 0xFF);
    let card_number = u64::from(rng.next_u32() & 0x3F);
    let cred = Credential::new(CardFormat::H10301, facility_code, card_number);
    let access = AccessList::new()
        .with_credential(&cred)?
        .assuming(CardFormat::H10301);
    let bench = wiegand_bench(seed, access)?;
    Ok(Bench {
        scenario: ScenarioId::WiegandSweep,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::None,
        script: Script {
            badges: Vec::new(),
            duration_us: 1_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

/// Drill 1.6. A legacy panel matches on the track-2 bits it receives rather
/// than on a decoded card number (`odr-bus` README, "things I was not certain
/// about", point 6), so the access entry is built by running the reader's own
/// encoder through a throwaway world first.
fn build_clock_data(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let cred = seeded_credential(&mut rng);
    let cfg = ClockDataConfig {
        encoding: AbaEncoding::bare(),
        assumed_format: Some(CardFormat::H10301),
    };

    let expected = {
        let mut probe = clock_data_bench(seed, AccessList::allow_all(), cfg.clone())?;
        let p = Presentation::new(
            SourceId(0),
            odr_bus::FormatId::for_card_format(cred.format),
            cred.encode()?,
        );
        probe.world.present(probe.reader, 0, p)?;
        probe.world.run_until(2_000_000)?;
        let bits = probe
            .world
            .log()
            .find(|r| matches!(r.kind, odr_bus::RecordKind::WireTx { .. }))
            .next()
            .and_then(|r| match &r.kind {
                odr_bus::RecordKind::WireTx { bits, .. } => Some(bits.clone()),
                _ => None,
            });
        bits.ok_or(ScenarioError::DidNotRun {
            drill: crate::ids::DrillId::new(1, 6),
            detail: String::from("the probe reader emitted nothing to enrol"),
        })?
    };

    let access = AccessList::new().with_bits(expected).checking_parity(false);
    let bench = clock_data_bench(seed, access, cfg)?;
    Ok(Bench {
        scenario: ScenarioId::ClockDataDoor,
        seed,
        world: bench.world,
        reader: Some(bench.reader),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::None,
        script: Script {
            badges: alloc::vec![ScriptedBadge {
                at_us: 1_000_000,
                source: SourceId(0),
                credential: cred,
            }],
            duration_us: 3_000_000,
        },
        address: PD_ADDRESS,
        spare_address: None,
        site_key: None,
    })
}

// ---------------------------------------------------------------------------
// Module 2 and beyond — OSDP
// ---------------------------------------------------------------------------

/// What one OSDP scenario differs from another by.
///
/// A struct rather than eight positional arguments, because six of these are
/// the lesson and reading them by name at every call site is the difference
/// between a table of configurations and a wall of parameters.
struct OsdpSetup {
    acu: AcuConfig,
    pd: PdConfig,
    access: AccessList,
    script: Script,
    site_key: Option<[u8; 16]>,
    spare_address: Option<u8>,
}

/// The one place an OSDP bench is assembled, so that every scenario below
/// differs only in the two endpoint configurations — which is the point being
/// taught.
fn osdp(scenario: ScenarioId, seed: u64, setup: OsdpSetup) -> Result<Bench> {
    let OsdpSetup {
        acu,
        pd,
        access,
        script,
        site_key,
        spare_address,
    } = setup;
    let spec = OsdpBenchSpec {
        acu,
        pds: alloc::vec![pd],
        timing: Rs485Timing::at_baud(9600),
        access,
        start_polling_at_us: 0,
    };
    let bench = osdp_bench(seed, spec)?;
    let pd_id = bench.pd();
    Ok(Bench {
        scenario,
        seed,
        world: bench.world,
        reader: Some(pd_id),
        controller: bench.controller,
        door: bench.door,
        link: bench.link,
        cards: CardSetup::None,
        script,
        address: PD_ADDRESS,
        spare_address,
        site_key,
    })
}

fn one_badge(rng: &mut Rng, at_us: Micros, duration_us: Micros) -> (Credential, Script) {
    let cred = seeded_credential(rng);
    (
        cred,
        Script {
            badges: alloc::vec![ScriptedBadge {
                at_us,
                source: SourceId(0),
                credential: cred,
            }],
            duration_us,
        },
    )
}

/// Drills 2.1 to 2.4. Nothing is configured, which is how most of these links
/// are actually deployed.
fn build_osdp_clear(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let (cred, script) = one_badge(&mut rng, 1_500_000, 4_000_000);
    osdp(
        ScenarioId::OsdpClear,
        seed,
        OsdpSetup {
            acu: AcuConfig::polling([PD_ADDRESS]),
            pd: PdConfig::at(PD_ADDRESS),
            access: AccessList::new().with_credential(&cred)?,
            script,
            site_key: None,
            spare_address: None,
        },
    )
}

/// Drills 3.1 and 3.2. SCBK-D: the key in the manual, announced in the clear in
/// the handshake's key-type byte.
fn build_osdp_default_key(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let (cred, script) = one_badge(&mut rng, 2_500_000, 6_000_000);
    osdp(
        ScenarioId::OsdpDefaultKey,
        seed,
        OsdpSetup {
            acu: AcuConfig::polling([PD_ADDRESS]).with_default_key(ScRequirement::IfAvailable),
            pd: PdConfig::at(PD_ADDRESS).with_default_key(ScRequirement::IfAvailable),
            access: AccessList::new().with_credential(&cred)?,
            script,
            site_key: Some(SCBK_D),
            spare_address: None,
        },
    )
}

/// Drill 3.3. A repeated byte, straight out of a vendor's example code. The
/// byte comes from the seed so the learner's sweep has to find it rather than
/// recognise it.
fn build_osdp_weak_key(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let byte = (rng.next_u32() & 0xFF) as u8;
    let site_key = [byte; 16];
    let (cred, script) = one_badge(&mut rng, 2_500_000, 6_000_000);
    osdp(
        ScenarioId::OsdpWeakKey,
        seed,
        OsdpSetup {
            acu: AcuConfig::polling([PD_ADDRESS])
                .with_site_key(site_key, ScRequirement::IfAvailable),
            pd: PdConfig::at(PD_ADDRESS).with_site_key(site_key, ScRequirement::IfAvailable),
            access: AccessList::new().with_credential(&cred)?,
            script,
            site_key: Some(site_key),
            spare_address: None,
        },
    )
}

/// Drill 3.4. Two addresses polled, one reader fitted, install mode left on
/// after commissioning — which is the configuration the Mellon paper describes.
fn build_osdp_install_mode(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let site_key = strong_key(&mut rng);
    let script = Script {
        badges: Vec::new(),
        duration_us: 8_000_000,
    };
    osdp(
        ScenarioId::OsdpInstallMode,
        seed,
        OsdpSetup {
            acu: AcuConfig::polling([PD_ADDRESS, SPARE_ADDRESS])
                .with_site_key(site_key, ScRequirement::IfAvailable)
                .in_install_mode(true),
            pd: PdConfig::at(PD_ADDRESS).with_site_key(site_key, ScRequirement::IfAvailable),
            access: AccessList::new(),
            script,
            site_key: Some(site_key),
            spare_address: Some(SPARE_ADDRESS),
        },
    )
}

/// Drills 3.5 and 4.3. A fresh reader on the default key, a controller with the
/// site key and install mode on, and a badge-in afterwards so there is
/// something to read once the key is out.
fn build_osdp_commissioning(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let site_key = strong_key(&mut rng);
    let (cred, mut script) = one_badge(&mut rng, 6_000_000, 10_000_000);
    script.duration_us = 10_000_000;
    osdp(
        ScenarioId::OsdpCommissioning,
        seed,
        OsdpSetup {
            acu: AcuConfig::polling([PD_ADDRESS])
                .with_site_key(site_key, ScRequirement::IfAvailable)
                .in_install_mode(true),
            pd: PdConfig::at(PD_ADDRESS).with_default_key(ScRequirement::IfAvailable),
            access: AccessList::new().with_credential(&cred)?,
            script,
            site_key: Some(site_key),
            spare_address: None,
        },
    )
}

/// Drill 3.6. Both ends say Secure Channel is required, and the controller
/// still decides from the unauthenticated capability reply
/// (`AcuConfig::trust_pdcap`). That sentence is the vulnerability.
fn build_osdp_required_sc(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let (cred, script) = one_badge(&mut rng, 2_000_000, 5_000_000);
    osdp(
        ScenarioId::OsdpRequiredSc,
        seed,
        OsdpSetup {
            acu: AcuConfig::polling([PD_ADDRESS]).with_default_key(ScRequirement::Required),
            pd: PdConfig::at(PD_ADDRESS).with_default_key(ScRequirement::Required),
            access: AccessList::new().with_credential(&cred)?,
            script,
            site_key: Some(SCBK_D),
            spare_address: None,
        },
    )
}

/// Drill 4.1. Everything is encrypted and everything about the building's
/// schedule is still legible.
///
/// Seven badge-ins by two people. Seven, rather than a real day's several
/// hundred, because the bar this has to clear is "the learner can read the
/// times off the traffic and check them", and a browser rendering a quarter of
/// a million polls clears no bar at all. The engine is not the limit here; the
/// screen is.
fn build_osdp_encrypted_day(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let morning = seeded_credential(&mut rng);
    let mut afternoon = seeded_credential(&mut rng);
    if afternoon == morning {
        afternoon = Credential::new(
            CardFormat::H10301,
            afternoon.facility_code.unwrap_or(0),
            afternoon.card_number ^ 1,
        );
    }
    let access = AccessList::new()
        .with_credential(&morning)?
        .with_credential(&afternoon)?;
    let mut badges = Vec::new();
    for i in 0..7u64 {
        badges.push(ScriptedBadge {
            at_us: 3_000_000 + i * 4_000_000,
            source: SourceId(if i % 2 == 0 { 0 } else { 1 }),
            credential: if i % 2 == 0 { morning } else { afternoon },
        });
    }
    osdp(
        ScenarioId::OsdpEncryptedDay,
        seed,
        OsdpSetup {
            acu: AcuConfig::polling([PD_ADDRESS]).with_default_key(ScRequirement::Required),
            pd: PdConfig::at(PD_ADDRESS).with_default_key(ScRequirement::Required),
            access,
            script: Script {
                badges,
                duration_us: 36_000_000,
            },
            site_key: Some(SCBK_D),
            spare_address: None,
        },
    )
}

/// Drill 4.2. **The engine is rigged here and the drill says so.**
///
/// `mac_len` is 1, so the forgery finishes in front of a learner. Four MAC
/// bytes still go on the wire; only the first carries anything, which is why
/// [`odr_attack::MacForger::calibrate`] can *measure* the width it is up
/// against instead of being told. On a real bus that measurement returns 4 and
/// the attack does not finish — which is the other half of the drill.
fn build_osdp_short_mac(seed: u64) -> Result<Bench> {
    // No badge-ins: the forger isolates the peripheral from its controller,
    // which is realistic for an inline implant and loud enough that a card read
    // during it would be a distraction rather than a lesson.
    let script = Script {
        badges: Vec::new(),
        duration_us: 6_000_000,
    };
    osdp(
        ScenarioId::OsdpShortMac,
        seed,
        OsdpSetup {
            acu: AcuConfig::polling([PD_ADDRESS])
                .with_default_key(ScRequirement::IfAvailable)
                .with_mac_len(1),
            pd: PdConfig::at(PD_ADDRESS)
                .with_default_key(ScRequirement::IfAvailable)
                .with_mac_len(1),
            access: AccessList::new(),
            script,
            site_key: Some(SCBK_D),
            spare_address: None,
        },
    )
}

/// Drill 4.4. `AcuConfig::encrypt_payloads = false` is SCS_15/SCS_16:
/// authenticated, and not encrypted.
fn build_osdp_null_cipher(seed: u64) -> Result<Bench> {
    let mut rng = Rng::new(seed);
    let (cred, script) = one_badge(&mut rng, 2_000_000, 6_000_000);
    let mut acu = AcuConfig::polling([PD_ADDRESS]).with_default_key(ScRequirement::IfAvailable);
    acu.encrypt_payloads = false;
    osdp(
        ScenarioId::OsdpNullCipher,
        seed,
        OsdpSetup {
            acu,
            // Both directions run MAC-only. The reply half is what makes the
            // drill's own claim true: the card number crosses an established
            // Secure Channel in plain sight.
            pd: PdConfig::at(PD_ADDRESS)
                .with_default_key(ScRequirement::IfAvailable)
                .with_null_cipher(),
            access: AccessList::new().with_credential(&cred)?,
            script,
            site_key: Some(SCBK_D),
            spare_address: None,
        },
    )
}

/// A key that is not in the published sample family, so it has to be asked for
/// or captured rather than swept.
fn strong_key(rng: &mut Rng) -> [u8; 16] {
    loop {
        let mut key = [0u8; 16];
        for b in key.iter_mut() {
            *b = (rng.next_u32() & 0xFF) as u8;
        }
        if !odr_osdp::weak_keys::is_weak(&key) {
            return key;
        }
    }
}

/// Build the live card object a card-layer scenario describes.
///
/// Returns `None` for a scenario with no card layer. The card is rebuilt from
/// [`CardSetup`] rather than stored, so the same bench always produces the same
/// card.
pub fn build_card(setup: &CardSetup) -> Option<odr_credential::Card> {
    match setup {
        CardSetup::None => None,
        CardSetup::Em4100 { id40 } => odr_credential::em4100::Em4100Tag::from_id40(*id40)
            .ok()
            .map(odr_credential::Card::em4100),
        CardSetup::HidProx {
            facility_code,
            card_number,
        } => Some(odr_credential::Card::hid_prox(H10301::new(
            *facility_code,
            *card_number,
        ))),
        CardSetup::MifareClassic { .. } => {
            build_mifare_card(setup).map(odr_credential::Card::mifare)
        }
        CardSetup::Desfire {
            uid,
            key,
            file,
            contents,
        } => {
            let mut card = odr_credential::desfire::DesfireEv2::new(u64::from(*uid), 0, *key);
            card.set_file(*file, contents.clone());
            Some(odr_credential::Card::desfire(card))
        }
    }
}

/// Build the MIFARE card a [`CardSetup::MifareClassic`] describes.
///
/// Separate from [`build_card`] because drill 0.4's attack needs the card
/// itself rather than the `Card` wrapper around it.
pub fn build_mifare_card(setup: &CardSetup) -> Option<MifareClassic1k> {
    match setup {
        CardSetup::MifareClassic {
            uid,
            card_seed,
            key_a,
            credential_block,
            credential,
        } => {
            let mut card = MifareClassic1k::new(*uid, *card_seed);
            let mut rng = Rng::new(*card_seed ^ 0x5CB8_2A11);
            for (sector, key) in key_a.iter().enumerate() {
                card.force_sector_keys(
                    sector as u8,
                    *key,
                    rng.next_crypto1_key(),
                    AccessBits::transport(),
                );
            }
            card.force_block(*credential_block, *credential);
            Some(card)
        }
        _ => None,
    }
}

/// Build the DESFire card a [`CardSetup::Desfire`] describes.
pub fn build_desfire_card(setup: &CardSetup) -> Option<odr_credential::desfire::DesfireEv2> {
    match setup {
        CardSetup::Desfire {
            uid,
            key,
            file,
            contents,
        } => {
            let mut card = odr_credential::desfire::DesfireEv2::new(u64::from(*uid), 0, *key);
            card.set_file(*file, contents.clone());
            Some(card)
        }
        _ => None,
    }
}
