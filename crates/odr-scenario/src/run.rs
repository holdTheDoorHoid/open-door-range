//! **Driving a drill.**
//!
//! Two entry points, and the pair of them is the point:
//!
//! * [`solve`] builds the drill's bench, clips the attack on, drives it, and
//!   returns everything a predicate needs.
//! * [`baseline`] builds the *same* bench, runs its own traffic, and clips
//!   nothing on.
//!
//! A flag that is earned by [`solve`] and not by [`baseline`] is a flag that
//! measures the attack. A flag earned by both is free, and the test suite fails
//! on it. That is not a hypothetical: drill 1.3's flag was free before `odr-bus`
//! made taps gate the simulation, and the negative half of the suite is what
//! would have caught it.
//!
//! # These are not the only way to reach a flag
//!
//! [`solve`] is one route, written to be the shortest honest one. A learner at
//! the bench takes their own, and the predicate does not care which: it reads
//! the world, the knowledge base and the measurements, and has no idea whether
//! a person or this file produced them.
//!
//! # `engine_answer`
//!
//! For the drills that take a learner submission, [`Outcome::engine_answer`]
//! returns what the engine would accept — **derived from the run**, not stored.
//! It exists because the test suite has to submit a correct answer without
//! writing one down, and because a caller checking its own work needs the same
//! thing. It is a spoiler by construction, so a front end should not put it
//! behind a button that says "hint".

use alloc::string::String;
use alloc::vec::Vec;

use odr_attack::{
    Attacker, BruteForcer, Downgrader, Implant, Injector, InstallModeHarvester, IvReuseExploiter,
    KeysetCapturer, Knowledge, KnowledgeCell, MacForger, NestedAttacker, NullCipherReader,
    PassiveEavesdropper, Replayer, Sniffer, TagCloner, TrafficAnalyst, WeakKeyCracker,
};
use odr_bus::{BusDir, Micros, Origin, ProtocolEvent, RecordKind, SourceId, World};
use odr_credential::desfire;
use odr_credential::mifare::{KeyType as MfKeyType, MifareReader, DEFAULT_KEY};
use odr_credential::modulation::{CarrierConfig, RF_64};
use odr_detect::RuleSet;
use odr_osdp::codes::{Command, Reply};
use odr_osdp::payload::Ccrypt;
use odr_wiegand::{BitVec, CardFormat, Credential, CredentialSweep};

use crate::catalog;
use crate::error::{Result, ScenarioError};
use crate::facts::{
    DesyncTrace, Facts, ForgeryOutcome, FrameLayout, IvReuseOutcome, MifareOutcome,
    TransmittedCredential,
};
use crate::flag::{evaluate, Flag, FlagContext};
use crate::ids::DrillId;
use crate::module5;
use crate::scenario::{self, Bench, ScenarioId};
use crate::submission::Submission;
use crate::tasks::{Task, TaskState};

/// The physical token the victim carries, in the drills that have a victim.
const VICTIM_TOKEN: SourceId = SourceId(0);
/// The attacker's own blank.
const ATTACKER_TOKEN: SourceId = SourceId(7);

/// **What a run produced.**
///
/// Handed straight to [`crate::flag::evaluate`], which is the only thing that
/// decides whether the flag is earned.
#[derive(Debug)]
pub struct Outcome {
    /// Which drill.
    pub drill: DrillId,
    /// The session seed.
    pub seed: u64,
    /// The bench, after running. `None` for drill 0.6 and for Module 5, which
    /// score a capture rather than a bench.
    pub bench: Option<Bench>,
    /// What the attacker ended up knowing, and where each piece came from.
    pub knowledge: Option<Knowledge>,
    /// What the run measured.
    pub facts: Facts,
}

impl Outcome {
    /// The world, if this drill has one.
    pub fn world(&self) -> Option<&World> {
        self.bench.as_ref().map(|b| &b.world)
    }

    /// Evaluate the flag, with an optional learner submission.
    pub fn flag(&self, submission: Option<&Submission>) -> Result<Flag> {
        let drill = catalog::require(self.drill)?;
        let ctx = FlagContext {
            world: self.world(),
            knowledge: self.knowledge.as_ref(),
            facts: &self.facts,
            submission,
        };
        Ok(evaluate(drill, &ctx))
    }

    /// Where the long-running tasks are after this many wall-clock
    /// milliseconds.
    ///
    /// The one place wall-clock time touches this workspace, and it touches
    /// nothing a flag depends on. See [`crate::tasks`].
    pub fn task_states(&self, elapsed_ms: u64) -> Vec<TaskState> {
        self.facts
            .tasks
            .iter()
            .map(|t| t.state(elapsed_ms))
            .collect()
    }

    /// **What the engine would accept**, derived from this run.
    ///
    /// `None` for the drills that ask the learner for nothing. See the module
    /// docs for why this exists and why it is a spoiler.
    pub fn engine_answer(&self) -> Option<Submission> {
        match (self.drill.module, self.drill.index) {
            (0, 1) => self.facts.tag_id40.map(Submission::TagId),
            (0, 3) => self
                .facts
                .transmitted
                .as_ref()
                .map(|t| Submission::Credential {
                    facility_code: t.facility_code.unwrap_or(0),
                    card_number: t.card_number.unwrap_or(0),
                    bits: t.bits.clone(),
                }),
            (0, 5) => {
                if self.facts.diagnoses.is_empty() {
                    None
                } else {
                    Some(Submission::Diagnoses(self.facts.diagnoses.clone()))
                }
            }
            (0, 6) => Some(Submission::Acknowledged),
            (1, 1) => self
                .facts
                .transmitted
                .as_ref()
                .map(|t| Submission::Credential {
                    facility_code: t.facility_code.unwrap_or(0),
                    card_number: t.card_number.unwrap_or(0),
                    bits: Vec::new(),
                }),
            (2, 1) => self
                .facts
                .frame_layout
                .as_ref()
                .map(|l| Submission::FrameLayout(l.required())),
            (3, 1) => self.facts.client_cryptogram.map(Submission::Cryptogram),
            (4, 1) => {
                if self.facts.inferred_badge_times.is_empty() {
                    None
                } else {
                    Some(Submission::BadgeTimes(
                        self.facts.inferred_badge_times.clone(),
                    ))
                }
            }
            // Module 5 is deliberately absent: its input is a rule set, which
            // is run rather than compared. See `Drill::submission`.
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// **Run a drill's bench with nothing clipped to it.**
///
/// The negative control. Whatever this produces, the flag must not be earned
/// by it.
pub fn baseline(drill_id: DrillId, seed: u64) -> Result<Outcome> {
    let drill = catalog::require(drill_id)?;
    if drill.scenario == ScenarioId::MonitoredDay {
        // A rule set that reports nothing. It is quiet on the benign traffic
        // and catches none of the attacks, which is the honest floor.
        let day = module5::day(seed)?;
        let empty = RuleSet::empty("nothing at all");
        return Ok(Outcome {
            drill: drill_id,
            seed,
            bench: None,
            knowledge: None,
            facts: Facts {
                detection: Some(module5::run_ruleset(&day, &empty)?),
                ..Facts::default()
            },
        });
    }
    if drill.scenario == ScenarioId::NoBench {
        return Ok(Outcome {
            drill: drill_id,
            seed,
            bench: None,
            knowledge: None,
            facts: Facts::default(),
        });
    }
    let mut bench = scenario::build(drill.scenario, seed)?;
    bench.run_script()?;
    let facts = Facts {
        site_key: bench.site_key,
        transmitted: first_transmitted(&bench.world),
        frame_layout: first_card_read_layout(&bench.world),
        client_cryptogram: observed_client_cryptogram(&bench.world),
        badge_times: presentation_times(&bench.world),
        ..Facts::default()
    };
    Ok(Outcome {
        drill: drill_id,
        seed,
        bench: Some(bench),
        knowledge: None,
        facts,
    })
}

/// **Run a drill's bench with a probe clipped on and nothing else done.**
///
/// A stronger negative control than [`baseline`] for the drills whose attack
/// is a piece of *analysis* rather than a piece of wire: 3.2, 3.3, 3.5 and 4.4
/// all start with a passive clip, and if the flag were earnable by clipping on
/// and pressing Run then the sweep, the capture and the decryption would all be
/// decoration.
///
/// Returns [`ScenarioError::NotSimulated`] for a drill with no bench.
pub fn observe_only(drill_id: DrillId, seed: u64) -> Result<Outcome> {
    let drill = catalog::require(drill_id)?;
    if !drill.scenario.is_bench() {
        return Err(ScenarioError::NotSimulated { drill: drill_id });
    }
    let mut bench = scenario::build(drill.scenario, seed)?;
    let mut ear = PassiveEavesdropper::new("a clip and no further ideas");
    ear.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    ear.harvest(&bench.world)?;
    let facts = Facts {
        transmitted: first_transmitted(&bench.world),
        frame_layout: first_card_read_layout(&bench.world),
        client_cryptogram: observed_client_cryptogram(&bench.world),
        badge_times: presentation_times(&bench.world),
        ..Facts::default()
    };
    let knowledge = ear.knowledge().snapshot();
    let mut out = finish(seed, bench, Some(knowledge), facts);
    out.drill = drill_id;
    Ok(out)
}

/// **Run a drill to completion, performing its attack.**
pub fn solve(drill_id: DrillId, seed: u64) -> Result<Outcome> {
    let drill = catalog::require(drill_id)?;
    let facts = Facts {
        attack_performed: true,
        ..Facts::default()
    };

    match (drill_id.module, drill_id.index) {
        (0, 1) => solve_0_1(drill.scenario, seed, facts),
        (0, 2) => solve_0_2(drill.scenario, seed, facts),
        (0, 3) => solve_0_3(drill.scenario, seed, facts),
        (0, 4) => solve_0_4(drill.scenario, seed, facts),
        (0, 5) => solve_0_5(drill.scenario, seed, facts),
        (0, 6) => Ok(Outcome {
            drill: drill_id,
            seed,
            bench: None,
            knowledge: None,
            facts,
        }),
        (1, 1) => solve_1_1(drill.scenario, seed, facts),
        (1, 2) => solve_1_2(drill.scenario, seed, facts),
        (1, 3) | (1, 6) => solve_replay(drill.scenario, seed, facts),
        (1, 4) => solve_1_4(drill.scenario, seed, facts),
        (1, 5) => solve_1_5(drill.scenario, seed, facts),
        (2, 1) => solve_2_1(drill.scenario, seed, facts),
        (2, 2) => solve_2_2(drill.scenario, seed, facts),
        (2, 3) => solve_2_3(drill.scenario, seed, facts),
        (2, 4) => solve_2_4(drill.scenario, seed, facts),
        (3, 1) => solve_3_1(drill.scenario, seed, facts),
        (3, 2) | (3, 3) => solve_weak_key(drill.scenario, seed, facts),
        (3, 4) => solve_3_4(drill.scenario, seed, facts),
        (3, 5) => solve_3_5(drill.scenario, seed, facts),
        (3, 6) => solve_3_6(drill.scenario, seed, facts),
        (4, 1) => solve_4_1(drill.scenario, seed, facts),
        (4, 2) => solve_4_2(drill.scenario, seed, facts),
        (4, 3) => solve_4_3(drill.scenario, seed, facts),
        (4, 4) => solve_4_4(drill.scenario, seed, facts),
        (5, _) => solve_module_5(seed, facts),
        _ => Err(ScenarioError::UnknownDrill {
            id: drill_id.as_string(),
        }),
    }
    .map(|mut o| {
        o.drill = drill_id;
        o
    })
}

/// Assemble an outcome from a finished run.
///
/// The drill id is filled in by [`solve`] on the way out rather than threaded
/// through every solver, so the placeholder here is never observable.
fn finish(seed: u64, bench: Bench, knowledge: Option<Knowledge>, mut facts: Facts) -> Outcome {
    facts.site_key = bench.site_key;
    Outcome {
        drill: DrillId::new(0, 0),
        seed,
        bench: Some(bench),
        knowledge,
        facts,
    }
}

// ---------------------------------------------------------------------------
// Shared measurements
// ---------------------------------------------------------------------------

/// The first frame a reader drove onto its own segment, decoded.
fn first_transmitted(world: &World) -> Option<TransmittedCredential> {
    let (t_us, bits) = world.log().records().iter().find_map(|r| match &r.kind {
        RecordKind::WireTx {
            origin: Origin::Reader(_),
            bits,
            ..
        } => Some((r.t_us, bits.clone())),
        _ => None,
    })?;
    let decoded = odr_wiegand::decode(CardFormat::H10301, &bits).ok();
    Some(TransmittedCredential {
        t_us,
        facility_code: decoded.as_ref().and_then(|d| d.facility_code),
        card_number: decoded.as_ref().and_then(|d| d.card_number),
        parity_valid: decoded.as_ref().is_some_and(|d| d.parity_valid()),
        bits: bits.as_slice().to_vec(),
    })
}

/// The layout of the first card read on the bus.
fn first_card_read_layout(world: &World) -> Option<FrameLayout> {
    world
        .log()
        .bus_frames()
        .find(|(_, dir, f)| *dir == BusDir::PdToAcu && f.reply_code() == Some(Reply::Raw))
        .map(|(r, _, f)| FrameLayout::of(f, r.t_us))
}

/// The client cryptogram the peripheral put on the bus, taken off the wire.
fn observed_client_cryptogram(world: &World) -> Option<[u8; 16]> {
    world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.reply_code() == Some(Reply::Ccrypt))
        .and_then(|(_, _, f)| Ccrypt::decode(&f.payload).ok())
        .map(|c| c.client_cryptogram)
}

/// When the engine's own log says credentials were presented.
fn presentation_times(world: &World) -> Vec<Micros> {
    world.log().presentations().map(|r| r.t_us).collect()
}

/// The credentials on the controller's access list, decoded.
///
/// A panel matches on bits rather than on a decoded card number, so this is a
/// reading of what it holds rather than a lookup of what it was configured
/// with — which is also all an attacker standing at the panel would have.
fn enrolled(world: &World) -> Vec<Credential> {
    world
        .controllers()
        .flat_map(|c| c.access.entries.iter())
        .filter_map(|e| {
            odr_wiegand::decode(CardFormat::H10301, &e.bits)
                .ok()
                .and_then(|d| d.credential())
        })
        .collect()
}

fn no_reader(drill: DrillId) -> ScenarioError {
    ScenarioError::DidNotRun {
        drill,
        detail: String::from("this bench has no reader"),
    }
}

// ---------------------------------------------------------------------------
// Module 0
// ---------------------------------------------------------------------------

fn solve_0_1(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let card = scenario::build_card(&bench.cards).ok_or(ScenarioError::DidNotRun {
        drill: DrillId::new(0, 1),
        detail: String::from("this bench has no 125 kHz tag"),
    })?;

    // Everything the learner gets: the field response. Reading the id off it is
    // the drill, and it is also how the engine states its own value — there is
    // no path here that does not go through the carrier.
    let stream = card.field_response(3, &CarrierConfig::default())?;
    let frame = odr_credential::em4100::demodulate(&stream, RF_64)?;
    let read = frame.decode();
    facts.tag_id40 = Some(read.tag.id40());

    let reader = bench.reader.ok_or_else(|| no_reader(DrillId::new(0, 1)))?;
    let credential = read.tag.to_credential();
    let bits = BitVec::from_bools(&credential.bits());
    let presentation = odr_bus::Presentation::new(
        VICTIM_TOKEN,
        odr_attack::format_id_for(credential.format),
        bits,
    );
    bench.world.present(reader, 1_000_000, presentation)?;
    bench.world.run_until(bench.script.duration_us)?;
    Ok(finish(seed, bench, None, facts))
}

fn solve_0_2(scenario: ScenarioId, seed: u64, facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let victim = scenario::build_card(&bench.cards).ok_or(ScenarioError::DidNotRun {
        drill: DrillId::new(0, 2),
        detail: String::from("this bench has no victim card"),
    })?;

    // One brush past a pocket. That is the entire interaction with the victim.
    let mut cloner = TagCloner::new("pocket coil");
    cloner.brush_past(&victim, 0)?;
    cloner.write_blank()?;

    let reader = bench.reader.ok_or_else(|| no_reader(DrillId::new(0, 2)))?;
    let presentation = cloner.presentation(ATTACKER_TOKEN)?;
    bench.world.present(reader, 1_000_000, presentation)?;
    bench.world.run_until(bench.script.duration_us)?;
    let knowledge = cloner.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_0_3(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let card = scenario::build_card(&bench.cards).ok_or(ScenarioError::DidNotRun {
        drill: DrillId::new(0, 3),
        detail: String::from("this bench has no prox card"),
    })?;

    // Step one and two happen before the wire has seen anything, which is the
    // ordering the drill is about.
    let stream = card.field_response(2, &CarrierConfig::default())?;
    let block = odr_credential::hid_prox::demodulate_block(&stream)?;
    let recovered = odr_credential::hid_prox::H10301::from_raw44(block)?;
    let predicted = odr_credential::h10301_wiegand_bits(&recovered);
    facts.predicted_bits = Some(predicted.to_vec());

    bench.run_script()?;
    facts.transmitted = first_transmitted(&bench.world);
    Ok(finish(seed, bench, None, facts))
}

fn solve_0_4(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let bench = scenario::build(scenario, seed)?;
    let mut card = scenario::build_mifare_card(&bench.cards).ok_or(ScenarioError::DidNotRun {
        drill: DrillId::new(0, 4),
        detail: String::from("this bench has no MIFARE card"),
    })?;
    let (configured_keys, credential_block, credential) = match &bench.cards {
        scenario::CardSetup::MifareClassic {
            key_a,
            credential_block,
            credential,
            ..
        } => (key_a.clone(), *credential_block, credential.to_vec()),
        _ => unreachable!("build_mifare_card only answers for a MIFARE setup"),
    };

    let mut reader = MifareReader::new(seed ^ 0x0404);
    // The attacker's starting position: one sector still on the published
    // transport key.
    let mut attacker = NestedAttacker::new("proxmark", 0, MfKeyType::A, DEFAULT_KEY);
    attacker.calibrate(&mut card, &mut reader)?;

    let mut recovered = Vec::new();
    for sector in 1..4u8 {
        let key = attacker.recover_sector(&mut card, &mut reader, sector * 4, MfKeyType::A)?;
        recovered.push((sector, key));
    }
    let first_key = recovered.first().map(|(_, k)| *k).unwrap_or(DEFAULT_KEY);
    let read = attacker.read_block(
        &mut card,
        &mut reader,
        credential_block,
        MfKeyType::A,
        first_key,
    )?;

    facts.mifare = Some(MifareOutcome {
        configured: configured_keys
            .iter()
            .enumerate()
            .map(|(i, k)| (i as u8, *k))
            .collect(),
        recovered,
        credential_block,
        credential,
        read_back: Some(read.data.clone()),
    });
    let knowledge = attacker.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_0_5(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let bench = scenario::build(scenario, seed)?;
    let mut card = scenario::build_desfire_card(&bench.cards).ok_or(ScenarioError::DidNotRun {
        drill: DrillId::new(0, 5),
        detail: String::from("this bench has no DESFire card"),
    })?;
    let key = match &bench.cards {
        scenario::CardSetup::Desfire { key, .. } => *key,
        _ => unreachable!("build_desfire_card only answers for a DESFire setup"),
    };
    let report = desfire::run_contrast(&mut card, key, seed ^ 0x0505);
    facts.all_attacks_failed = report.all_failed();
    facts.diagnoses = report.diagnoses();
    Ok(finish(seed, bench, None, facts))
}

// ---------------------------------------------------------------------------
// Module 1
// ---------------------------------------------------------------------------

fn solve_1_1(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut sniffer = Sniffer::new("ceiling void");
    sniffer.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    sniffer.harvest(&bench.world)?;
    facts.transmitted = first_transmitted(&bench.world);
    let knowledge = sniffer.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_1_2(scenario: ScenarioId, seed: u64, facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let reader = bench.reader.ok_or_else(|| no_reader(DrillId::new(1, 2)))?;
    // The neighbouring number is whatever the panel is holding. An attacker at
    // the door with an implant does not have the access list, but a learner who
    // has watched one badge-in has the facility code, and the bit to flip is
    // the cheapest one there is.
    let target = enrolled(&bench.world)
        .into_iter()
        .next()
        .ok_or(ScenarioError::DidNotRun {
            drill: DrillId::new(1, 2),
            detail: String::from("the panel has nothing enrolled to aim at"),
        })?;

    let mut implant = Implant::new("bit flipper");
    implant.attach_before(&mut bench.world, bench.link, reader)?;
    implant.impersonate_card(
        CardFormat::H10301,
        target.facility_code.unwrap_or(0),
        target.card_number,
    );

    bench.run_script()?;
    let knowledge = implant.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

/// Drills 1.3 and 1.6: capture one badge-in, take the card away, put the bits
/// back.
fn solve_replay(scenario: ScenarioId, seed: u64, facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut replayer = Replayer::new("replay box");
    replayer.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    replayer.harvest(&bench.world)?;

    // Card gone. Well outside the window a grant could be blamed on it.
    let at = bench.script.duration_us + 30_000_000;
    replayer.replay_latest(&mut bench.world, at)?;
    bench.world.run_until(at + 3_000_000)?;
    let knowledge = replayer.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_1_4(scenario: ScenarioId, seed: u64, facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let reader = bench.reader.ok_or_else(|| no_reader(DrillId::new(1, 4)))?;
    let manager = enrolled(&bench.world)
        .into_iter()
        .next()
        .ok_or(ScenarioError::DidNotRun {
            drill: DrillId::new(1, 4),
            detail: String::from("the panel has nobody enrolled to impersonate"),
        })?;
    let visitor = *bench.primary_credential().ok_or(ScenarioError::DidNotRun {
        drill: DrillId::new(1, 4),
        detail: String::from("this bench has no badge-in scripted"),
    })?;

    let mut implant = Implant::new("espkey");
    implant.attach_before(&mut bench.world, bench.link, reader)?;

    // Installed transparent, as it would be. Prove that first.
    bench.run_script()?;

    // Then armed.
    implant.impersonate(manager);
    let at = bench.script.duration_us + 2_000_000;
    bench.present(at, VICTIM_TOKEN, &visitor)?;
    bench.world.run_until(at + 3_000_000)?;

    let knowledge = implant.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_1_5(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let target = enrolled(&bench.world)
        .into_iter()
        .next()
        .ok_or(ScenarioError::DidNotRun {
            drill: DrillId::new(1, 5),
            detail: String::from("the panel has nothing enrolled, so nothing would ever open"),
        })?;
    let fc = target.facility_code.unwrap_or(0);

    // The sweep starts at zero and counts. It does not know where the enrolled
    // number is; the bench is built so that starting at zero reaches it.
    let sweep = CredentialSweep::new(CardFormat::H10301, fc..=fc, 0..=63)?;
    let mut forcer = BruteForcer::new("sweeper", sweep);
    forcer.attach(&mut bench.world, bench.link)?;
    // Up to 128 credentials, sixteen at a time: enough to cover the range the
    // bench enrols in, and bounded so a drill can never hang a browser tab.
    let report = forcer.run_until_granted(&mut bench.world, 128, 16)?;

    facts.tasks.push(sweep_task(&forcer, &report));
    facts.sweep = Some(report);
    let knowledge = forcer.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

/// The bar for drill 1.5: the whole credential space at this bench's timing.
fn sweep_task(forcer: &BruteForcer, report: &odr_attack::SweepReport) -> Task {
    let us = forcer.us_per_credential().max(1);
    let per_second = 1_000_000.0 / us as f64;
    Task {
        id: "wiegand-sweep",
        label: alloc::format!(
            "{}-bit Wiegand sweep — the whole space",
            report.format_space_cost.bits_per_credential
        ),
        short_label: alloc::format!(
            "one facility code ({} credentials) — for the drill",
            report.sweep_space
        ),
        note: alloc::format!(
            "one credential every {us} us: a {}-bit frame at this bench's wire timing plus the \
             inter-frame gap. Nothing throttles a Wiegand input, so this is the real rate.",
            report.format_space_cost.bits_per_credential
        ),
        total: report.format_space_cost.credentials,
        per_second,
        short_done: report.hit.is_some(),
        projected: report.format_space_cost.describe(),
    }
}

// ---------------------------------------------------------------------------
// Module 2
// ---------------------------------------------------------------------------

fn solve_2_1(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut ear = PassiveEavesdropper::new("clip on the pair");
    ear.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    ear.harvest(&bench.world)?;
    facts.frame_layout = first_card_read_layout(&bench.world);
    let knowledge = ear.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_2_2(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut ear = PassiveEavesdropper::new("clip on the pair");
    ear.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    ear.harvest(&bench.world)?;
    facts.recovered_credentials = ear.captures();
    let knowledge = ear.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_2_3(scenario: ScenarioId, seed: u64, facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut injector = Injector::new("laptop and a dongle");
    injector.attach(&mut bench.world, bench.link)?;

    // Listen first: the injector refuses an address it has not heard answering.
    bench.world.run_until(1_000_000)?;
    injector.harvest(&bench.world)?;
    injector.forge_to_any(
        &mut bench.world,
        1_500_000,
        Command::Led,
        alloc::vec![0u8; 14],
    )?;
    bench.world.run_until(bench.script.duration_us)?;

    let knowledge = injector.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_2_4(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    bench.world.run_until(1_000_000)?;
    let before = bench.world.log().len();
    let forced_at_us = bench.world.now();
    bench.world.desynchronise(bench.controller, bench.address)?;
    bench.world.run_until(6_000_000)?;

    let after = &bench.world.log().records()[before..];
    let noticed_at_us = after
        .iter()
        .find(|r| {
            matches!(
                &r.kind,
                RecordKind::Protocol {
                    event: ProtocolEvent::SequenceMismatch { .. },
                    ..
                } | RecordKind::Protocol {
                    event: ProtocolEvent::Nak { error: 0x04, .. },
                    ..
                }
            )
        })
        .map(|r| r.t_us);
    let recovered_at_us = noticed_at_us.and_then(|t| {
        after
            .iter()
            .find(|r| {
                r.t_us > t
                    && matches!(
                        &r.kind,
                        RecordKind::Protocol {
                            event: ProtocolEvent::ReplyReceived { reply, .. },
                            ..
                        } if *reply == Reply::Ack.to_u8()
                    )
            })
            .map(|r| r.t_us)
    });
    let starts = bench
        .world
        .log()
        .records()
        .iter()
        .filter(|r| matches!(r.kind, RecordKind::Started { .. }))
        .count();
    facts.desync = Some(DesyncTrace {
        forced_at_us,
        noticed_at_us,
        recovered_at_us,
        starts,
    });
    Ok(finish(seed, bench, None, facts))
}

// ---------------------------------------------------------------------------
// Module 3
// ---------------------------------------------------------------------------

fn solve_3_1(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut ear = PassiveEavesdropper::new("clip on the pair");
    ear.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    ear.harvest(&bench.world)?;
    facts.client_cryptogram = observed_client_cryptogram(&bench.world);
    let knowledge = ear.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

/// Drills 3.2 and 3.3: one captured handshake, and the published key family.
fn solve_weak_key(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut cracker = WeakKeyCracker::new("analyser");
    cracker.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    cracker.harvest(&bench.world)?;
    cracker.crack()?;
    if let Ok(reads) = cracker.decrypt_card_reads(bench.address) {
        facts.recovered_credentials = reads;
    }
    let knowledge = cracker.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_3_4(scenario: ScenarioId, seed: u64, facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let address = bench.spare_address.ok_or(ScenarioError::DidNotRun {
        drill: DrillId::new(3, 4),
        detail: String::from("this bench polls no unfitted address"),
    })?;
    let mut harvester = InstallModeHarvester::new("a laptop pretending to be a reader", address);
    harvester.attach(&mut bench.world, bench.link)?;
    bench.world.run_until(bench.script.duration_us)?;
    let knowledge = harvester.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_3_5(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut capturer = KeysetCapturer::new("installer's friend");
    capturer.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    capturer.harvest(&bench.world)?;
    capturer.capture_keys()?;

    let address = bench.address;
    if let Ok(after) = capturer.decrypt_after_commissioning(address) {
        for d in after.iter().filter(|d| d.id == Reply::Raw.to_u8()) {
            if let Ok(read) = odr_osdp::RawCardRead::decode(&d.plaintext) {
                facts
                    .recovered_credentials
                    .push(odr_attack::CapturedCredential {
                        bits: BitVec::from_bools(&read.bits()),
                        t_us: d.t_us,
                        link: Some(bench.link),
                        segment: 0,
                        medium: odr_attack::CaptureMedium::OsdpRaw,
                        address: Some(address),
                    });
            }
        }
    }
    let knowledge = capturer.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_3_6(scenario: ScenarioId, seed: u64, facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut downgrader = Downgrader::new("inline implant");
    downgrader.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    let knowledge = downgrader.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

// ---------------------------------------------------------------------------
// Module 4
// ---------------------------------------------------------------------------

fn solve_4_1(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut analyst = TrafficAnalyst::new("a box in the riser");
    analyst.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    analyst.harvest(&bench.world)?;
    let timeline = analyst.analyse();
    facts.badge_times = presentation_times(&bench.world);
    facts.inferred_badge_times = timeline.badge_times();
    let knowledge = analyst.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_4_2(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut forger = MacForger::new("forger", bench.address, seed ^ 0x0402);
    let tap = forger.attach(&mut bench.world, bench.link)?;

    // Let the session come up, so there is something to forge into.
    bench.world.run_until(3_000_000)?;
    let measured = forger.calibrate()?;
    forger.isolate(true);
    let progress = forger.run(&mut bench.world, 1200)?;

    let genuine = forger.genuine_search(&bench.world);
    facts.tasks.push(Task {
        id: "mac-forge",
        label: String::from("32-bit MAC forgery — the real one"),
        short_label: alloc::format!(
            "shortened MAC ({} bits) — for the drill",
            u32::from(measured.effective_bytes) * 8
        ),
        note: alloc::format!(
            "one candidate per round trip on this bus: {} us each, measured from the link rather \
             than assumed. There is no attempt limiter in OSDP and a rejected frame advances \
             neither MAC chain, so this is a sweep — and it still does not finish.",
            genuine.us_per_attempt()
        ),
        total: genuine.space(),
        per_second: 1_000_000.0 / genuine.us_per_attempt().max(1) as f64,
        short_done: progress.accepted,
        projected: genuine.describe(),
    });
    facts.forgery = Some(ForgeryOutcome {
        accepted: progress.accepted,
        attempts: progress.attempts,
        effective_mac_bytes: measured.effective_bytes,
        attributable: odr_attack::osdp_crypto::acceptance_is_attributable(&bench.world, tap),
        genuine_space: genuine.space(),
        genuine_projected: genuine.describe(),
    });
    let knowledge = forger.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_4_3(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;

    // One pooled knowledge base, two boxes: a passive analyser that cracks the
    // commissioning key, and an inline implant that freezes the chain.
    let pooled = KnowledgeCell::new();
    let mut exploiter = IvReuseExploiter::sharing("inline implant", pooled.clone());
    exploiter.attach(&mut bench.world, bench.link)?;
    // The trigger is a plaintext command byte, readable at every security level
    // OSDP offers.
    exploiter.suppress_after_command(Command::Keyset);

    let mut cracker = WeakKeyCracker::sharing("analyser", pooled.clone());
    cracker.attach(&mut bench.world, bench.link)?;

    // The drill's own timeline: no badge-ins, because the implant is swallowing
    // replies and a card read would only add noise.
    bench.world.run_until(10_000_000)?;
    cracker.harvest(&bench.world)?;
    cracker.crack()?;

    let collisions = exploiter.collisions();
    let frames = exploiter.frames();
    if let Ok(mut session) = cracker.shadow(bench.address) {
        exploiter.learn_from_shadow(&mut session, &frames);
    }
    let recovered = exploiter.recover();

    let outcome = collisions.first().and_then(|collision| {
        let at = *collision.at.get(1)?;
        let hit = recovered.iter().find(|p| p.t_us == at)?;
        let repeat = frames.iter().find(|f| {
            !f.frame.is_reply
                && f.frame.is_encrypted()
                && f.t_us == at
                && f.frame.payload == collision.ciphertext
        })?;
        let refused = match cracker.shadow(bench.address) {
            Ok(mut fresh) => {
                fresh.replay(&frames);
                fresh.open(repeat.dir, &repeat.frame).is_err()
            }
            Err(_) => false,
        };
        Some(IvReuseOutcome {
            collisions: collisions.len(),
            suppressed: exploiter.suppressed(),
            recovered_at_us: at,
            recovered_id: hit.id,
            plaintext: hit.bytes.clone(),
            decryptor_refused: refused,
        })
    });
    facts.iv_reuse = outcome.or(Some(IvReuseOutcome {
        collisions: collisions.len(),
        suppressed: exploiter.suppressed(),
        recovered_at_us: 0,
        recovered_id: 0,
        plaintext: Vec::new(),
        decryptor_refused: false,
    }));
    let knowledge = pooled.snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

fn solve_4_4(scenario: ScenarioId, seed: u64, mut facts: Facts) -> Result<Outcome> {
    let mut bench = scenario::build(scenario, seed)?;
    let mut reader = NullCipherReader::new("clip on the pair");
    reader.attach(&mut bench.world, bench.link)?;
    bench.run_script()?;
    reader.harvest(&bench.world)?;
    facts.recovered_credentials = reader.card_reads();
    let knowledge = reader.knowledge().snapshot();
    Ok(finish(seed, bench, Some(knowledge), facts))
}

// ---------------------------------------------------------------------------
// Module 5
// ---------------------------------------------------------------------------

fn solve_module_5(seed: u64, mut facts: Facts) -> Result<Outcome> {
    let day = module5::day(seed)?;
    let rules = RuleSet::standard();
    facts.detection = Some(module5::run_ruleset(&day, &rules)?);
    Ok(Outcome {
        drill: DrillId::new(5, 0),
        seed,
        bench: None,
        knowledge: None,
        facts,
    })
}

/// Run a rule set of the caller's own against a drill's day.
///
/// This is what a learner's answer goes through: the site holds the rule set,
/// this crate holds the key.
pub fn score_module_5(drill_id: DrillId, seed: u64, rules: &RuleSet) -> Result<Outcome> {
    let drill = catalog::require(drill_id)?;
    if drill.scenario != ScenarioId::MonitoredDay {
        return Err(ScenarioError::WrongSubmission {
            drill: drill_id,
            expected: "a drill in Module 5",
        });
    }
    let day = module5::day(seed)?;
    let facts = Facts {
        attack_performed: true,
        detection: Some(module5::run_ruleset(&day, rules)?),
        ..Facts::default()
    };
    Ok(Outcome {
        drill: drill_id,
        seed,
        bench: None,
        knowledge: None,
        facts,
    })
}
