//! **`docs/CURRICULUM.md`, drill by drill, driven to completion.**
//!
//! Two assertions per drill, and the second is the one that matters:
//!
//! 1. **Earned.** The drill's scenario is built, its attack is performed, and
//!    the flag predicate holds against the resulting engine state.
//! 2. **Not earned.** The *same* scenario is built and run with nothing clipped
//!    to it, and the flag predicate does not hold.
//!
//! The second half is what stops a flag being accidentally free. Drill 1.3's
//! was, before `odr-bus` made taps gate the simulation — "the controller
//! granted when no credential was presented" is earnable by pressing Run if
//! anything in the stack produces a spontaneous grant, and only a negative test
//! finds that out.
//!
//! Nothing here compares a typed answer against a constant. Where a drill takes
//! a learner submission, the test submits
//! [`Outcome::engine_answer`](odr_scenario::Outcome::engine_answer), which is
//! derived from the run — and then submits a deliberately wrong one and asserts
//! the flag is refused, so that "the comparison happens at all" is itself
//! tested.

use odr_scenario::submission::{FieldSpan, FrameField};
use odr_scenario::{catalog, run, Band, Completion, DrillId, ScenarioId, Submission};

const SEED: u64 = 0x0D00_5EED;

/// Drive a drill and assert the flag is earned, submitting the engine's own
/// answer where the drill asks for one.
fn earned(module: u8, index: u8) -> odr_scenario::Outcome {
    let id = DrillId::new(module, index);
    let outcome = run::solve(id, SEED).unwrap_or_else(|e| panic!("drill {id} did not run: {e}"));
    let answer = outcome.engine_answer();
    let flag = outcome.flag(answer.as_ref()).unwrap();
    assert!(
        flag.earned,
        "drill {id} was driven to completion and the flag was refused.\n  outstanding: {:#?}\n  \
         evidence: {:#?}",
        flag.outstanding, flag.evidence
    );
    assert!(
        !flag.evidence.is_empty(),
        "drill {id} earned its flag and said nothing about why"
    );
    outcome
}

/// Run the same bench with no attack and assert the flag is refused.
fn not_earned(module: u8, index: u8) {
    let id = DrillId::new(module, index);
    let outcome =
        run::baseline(id, SEED).unwrap_or_else(|e| panic!("drill {id} baseline did not run: {e}"));
    let flag = outcome.flag(None).unwrap();
    assert!(
        !flag.earned,
        "drill {id}'s flag is free: it was earned by a bench with no attack performed and no \
         submission.\n  evidence: {:#?}",
        flag.evidence
    );
    assert!(
        !flag.outstanding.is_empty(),
        "drill {id} refused the flag without saying what it is waiting for"
    );
}

/// Assert a wrong submission is refused on a drill that takes one.
fn wrong_submission_refused(module: u8, index: u8, wrong: Submission) {
    let id = DrillId::new(module, index);
    let outcome = run::solve(id, SEED).unwrap();
    let flag = outcome.flag(Some(&wrong)).unwrap();
    assert!(
        !flag.earned,
        "drill {id} accepted a submission that is not what the engine produced"
    );
}

// ===========================================================================
// Module 0 — the credential
// ===========================================================================

#[test]
fn drill_0_1_the_id_off_the_carrier() {
    let o = earned(0, 1);
    assert!(o.facts.tag_id40.is_some());
    not_earned(0, 1);
    wrong_submission_refused(0, 1, Submission::TagId(0));
}

#[test]
fn drill_0_2_a_clone_opens_the_door_and_the_original_was_never_there() {
    let o = earned(0, 2);
    let world = o.world().unwrap();
    assert_eq!(world.log().grants().count(), 1);
    assert_eq!(world.log().strikes().count(), 1);
    not_earned(0, 2);
}

#[test]
fn drill_0_3_the_prediction_holds_to_the_bit() {
    let o = earned(0, 3);
    // The engine's own reference prediction, made off the RF layer before the
    // wire saw anything, is what the reader went on to emit.
    let predicted = o.facts.predicted_bits.clone().unwrap();
    let transmitted = o.facts.transmitted.clone().unwrap();
    assert_eq!(predicted, transmitted.bits);
    not_earned(0, 3);
    wrong_submission_refused(
        0,
        3,
        Submission::Credential {
            facility_code: 0,
            card_number: 0,
            bits: Vec::new(),
        },
    );
}

#[test]
fn drill_0_4_the_keys_fall_out_of_observed_traffic() {
    let o = earned(0, 4);
    let m = o.facts.mifare.clone().unwrap();
    assert_eq!(m.recovered.len(), 3, "three sectors is enough to show it");
    assert_eq!(m.read_back.unwrap(), m.credential);
    not_earned(0, 4);
}

#[test]
fn drill_0_5_the_attacks_stop_and_the_diagnosis_is_marked() {
    let o = earned(0, 5);
    assert!(o.facts.all_attacks_failed);
    assert_eq!(o.facts.diagnoses.len(), 3);
    not_earned(0, 5);
    wrong_submission_refused(0, 5, Submission::Diagnoses(Vec::new()));
}

#[test]
fn drill_0_6_completes_by_being_read_and_says_so() {
    let id = DrillId::new(0, 6);
    let o = run::solve(id, SEED).unwrap();
    let unread = o.flag(None).unwrap();
    assert_eq!(unread.completion, Completion::Reference);
    assert!(!unread.is_simulated());
    assert!(!unread.earned, "it has not been read yet");

    let read = o.flag(Some(&Submission::Acknowledged)).unwrap();
    assert!(read.earned);
    assert!(
        read.predicate.contains("No flag"),
        "the predicate must say out loud that there is none: {}",
        read.predicate
    );
    assert!(o.world().is_none(), "there is no bench to build");
}

// ===========================================================================
// Module 1 — the wire
// ===========================================================================

#[test]
fn drill_1_1_the_badge_says_what_the_engine_transmitted() {
    let o = earned(1, 1);
    let tx = o.facts.transmitted.clone().unwrap();
    assert_eq!(tx.bits.len(), 26);
    assert!(tx.parity_valid);
    not_earned(1, 1);
    wrong_submission_refused(
        1,
        1,
        Submission::Credential {
            facility_code: tx.facility_code.unwrap() ^ 1,
            card_number: tx.card_number.unwrap(),
            bits: Vec::new(),
        },
    );
}

#[test]
fn drill_1_2_parity_is_not_integrity() {
    earned(1, 2);
    not_earned(1, 2);
}

#[test]
fn drill_1_3_replay_opens_the_door_with_no_card_present() {
    let o = earned(1, 3);
    let world = o.world().unwrap();
    assert_eq!(
        world.log().grants().count(),
        2,
        "one genuine badge-in and one replay"
    );
    not_earned(1, 3);
}

#[test]
fn drill_1_4_the_implant_substitutes_and_the_reader_never_knows() {
    earned(1, 4);
    not_earned(1, 4);
}

#[test]
fn drill_1_5_ends_on_a_number_rather_than_a_flag() {
    let id = DrillId::new(1, 5);
    let o = run::solve(id, SEED).unwrap();
    let flag = o.flag(None).unwrap();
    assert_eq!(flag.completion, Completion::Measurement);
    assert!(flag.earned, "{:?}", flag.outstanding);

    let m = flag.measurement.expect("the drill ends on a figure");
    assert!(m.value.contains("days") || m.value.contains("hours"));
    assert!(m.compare_with.contains("1.3"));

    let sweep = o.facts.sweep.clone().unwrap();
    assert_eq!(sweep.format_space_cost.credentials, 16_777_216);
    assert!(
        sweep.format_space_cost.total_days() > 10.0,
        "{}",
        sweep.format_space_cost.describe()
    );
    assert!(sweep.hit.is_some(), "the sweep reached the enrolled card");

    // And the honest negative: no sweep run, no number.
    not_earned(1, 5);
}

#[test]
fn drill_1_5_the_bar_never_finishes() {
    let o = run::solve(DrillId::new(1, 5), SEED).unwrap();
    // A full day at the keyboard.
    let states = o.task_states(86_400_000);
    let sweep = states.iter().find(|t| t.id == "wiegand-sweep").unwrap();
    assert!(
        !sweep.is_finished(),
        "a day of wall clock should not finish a 24-bit sweep at wire timing: {}/{}",
        sweep.done,
        sweep.total
    );
    assert!(sweep.short_done, "the short sweep did finish");
    assert!(sweep.remaining_seconds > 0.0);
}

#[test]
fn drill_1_6_the_same_attack_on_clock_and_data() {
    earned(1, 6);
    not_earned(1, 6);
}

// ===========================================================================
// Module 2 — OSDP as it is usually deployed
// ===========================================================================

#[test]
fn drill_2_1_the_byte_offsets_of_a_frame_the_engine_made() {
    let o = earned(2, 1);
    let layout = o.facts.frame_layout.clone().unwrap();
    // The layout is derived from the frame, and it has to agree with the
    // encoder: SOM at 0, address at 1, length at 2, control at 4.
    assert_eq!(layout.bytes[0], 0x53);
    assert_eq!(
        layout.span(FrameField::Som),
        Some(FieldSpan::new(FrameField::Som, 0, 1))
    );
    assert_eq!(
        layout.span(FrameField::Length),
        Some(FieldSpan::new(FrameField::Length, 2, 2))
    );
    assert_eq!(
        layout.span(FrameField::Control),
        Some(FieldSpan::new(FrameField::Control, 4, 1))
    );
    not_earned(2, 1);

    // One field in the wrong place is a refusal, not a rounding error.
    let mut wrong = layout.required();
    wrong[0].offset += 1;
    wrong_submission_refused(2, 1, Submission::FrameLayout(wrong));
}

#[test]
fn drill_2_2_a_card_number_off_an_unsecured_bus() {
    earned(2, 2);
    not_earned(2, 2);
}

#[test]
fn drill_2_3_the_pd_acks_a_forged_command() {
    earned(2, 3);
    not_earned(2, 3);
}

#[test]
fn drill_2_4_a_desynchronised_link_recovers_without_a_restart() {
    let o = earned(2, 4);
    let d = o.facts.desync.unwrap();
    assert_eq!(d.starts, 1, "the world was never rebuilt");
    assert!(d.noticed_at_us.unwrap() > d.forced_at_us);
    assert!(d.recovered_at_us.unwrap() > d.noticed_at_us.unwrap());
    not_earned(2, 4);
}

// ===========================================================================
// Module 3 — Secure Channel
// ===========================================================================

#[test]
fn drill_3_1_the_cryptogram_predicted_before_it_was_sent() {
    let o = earned(3, 1);
    assert!(o.facts.client_cryptogram.is_some());
    not_earned(3, 1);
    wrong_submission_refused(3, 1, Submission::Cryptogram([0u8; 16]));
}

#[test]
fn drill_3_2_the_default_key_gives_up_a_card_read() {
    let o = earned(3, 2);
    let k = o.knowledge.clone().unwrap();
    assert!(k.holds_scbk(&odr_osdp::SCBK_D));
    assert!(k.unearned().is_empty());
    not_earned(3, 2);
}

#[test]
fn drill_3_3_a_sample_code_site_key_falls_out_of_one_handshake() {
    let o = earned(3, 3);
    let site_key = o.facts.site_key.unwrap();
    assert_ne!(site_key, odr_osdp::SCBK_D, "this is not drill 3.2");
    assert!(odr_osdp::weak_keys::is_weak(&site_key));
    assert!(o.knowledge.clone().unwrap().holds_scbk(&site_key));
    not_earned(3, 3);
}

#[test]
fn drill_3_4_install_mode_hands_over_the_site_key() {
    let o = earned(3, 4);
    let site_key = o.facts.site_key.unwrap();
    assert!(
        !odr_osdp::weak_keys::is_weak(&site_key),
        "not a sample key: it has to be asked for"
    );
    assert!(o.knowledge.clone().unwrap().holds_scbk(&site_key));
    not_earned(3, 4);
}

#[test]
fn drill_3_5_keyset_capture_during_commissioning() {
    let o = earned(3, 5);
    assert!(o
        .knowledge
        .clone()
        .unwrap()
        .holds_scbk(&o.facts.site_key.unwrap()));
    assert!(!o.facts.recovered_credentials.is_empty());
    not_earned(3, 5);
}

#[test]
fn drill_3_6_the_downgrade_the_controller_believes() {
    let o = earned(3, 6);
    let world = o.world().unwrap();
    assert_eq!(world.log().strikes().count(), 1, "and the door still opens");
    not_earned(3, 6);
}

// ===========================================================================
// Module 4 — the weaknesses nobody mentions
// ===========================================================================

#[test]
fn drill_4_1_the_schedule_of_a_building_through_encryption() {
    let o = earned(4, 1);
    assert_eq!(o.facts.badge_times.len(), 7);
    assert_eq!(o.facts.inferred_badge_times.len(), 7);
    let k = o.knowledge.clone().unwrap();
    assert!(k.keys.is_empty(), "it never held a key");
    assert!(k.frames.is_empty(), "or a payload byte");
    not_earned(4, 1);
    wrong_submission_refused(4, 1, Submission::BadgeTimes(vec![0, 1, 2]));
}

#[test]
fn drill_4_2_a_forged_mac_the_pd_accepts() {
    let o = earned(4, 2);
    let f = o.facts.forgery.clone().unwrap();
    assert!(f.accepted);
    assert!(f.attributable);
    assert_eq!(
        f.effective_mac_bytes, 1,
        "the rigging is measurable off the wire"
    );
    assert_eq!(f.genuine_space, 1u128 << 32);
    not_earned(4, 2);
}

#[test]
fn drill_4_2_the_genuine_search_is_a_bar_that_never_finishes() {
    let o = run::solve(DrillId::new(4, 2), SEED).unwrap();
    // A week at the keyboard.
    let states = o.task_states(7 * 86_400_000);
    let bar = states.iter().find(|t| t.id == "mac-forge").unwrap();
    assert!(!bar.is_finished(), "{}/{}", bar.done, bar.total);
    assert!(bar.fraction < 0.01, "fraction {}", bar.fraction);
    assert!(bar.short_done, "the shortened run completed");
    assert!(
        bar.projected.contains("year"),
        "the projection has to be legible: {}",
        bar.projected
    );
}

#[test]
fn drill_4_3_iv_reuse_reads_a_frame_the_decryptor_cannot() {
    let o = earned(4, 3);
    let iv = o.facts.iv_reuse.clone().unwrap();
    assert!(iv.collisions > 0);
    assert!(iv.decryptor_refused);
    assert!(!iv.plaintext.is_empty());
    not_earned(4, 3);
}

#[test]
fn drill_4_4_the_null_cipher_hides_nothing() {
    let o = earned(4, 4);
    let k = o.knowledge.clone().unwrap();
    assert!(!k.plaintexts.is_empty());
    assert!(k.unearned().is_empty());
    not_earned(4, 4);
}

// ===========================================================================
// Module 5 — the other chair
// ===========================================================================

#[test]
fn drill_5_1_everything_visible_found_and_nothing_invented() {
    let o = earned(5, 1);
    let d = o.facts.detection.clone().unwrap();
    assert!(d.evidence_checks);
    assert_eq!(d.score.precision_pct(), 100);
    assert_eq!(d.score.recall_pct(), 100);
    not_earned(5, 1);
}

#[test]
fn drill_5_2_the_downgrade_caught_and_the_look_alikes_left_alone() {
    earned(5, 2);
    not_earned(5, 2);
}

#[test]
fn drill_5_2_a_louder_rule_set_is_refused() {
    // The strict downgrade rule catches the identity-spoofing variant and
    // alerts on every reader swap. It is not wrong; it is a different trade,
    // and this drill asks for the quiet one.
    let strict = odr_scenario::module5::strict_ruleset();
    let o = run::score_module_5(DrillId::new(5, 2), SEED, &strict).unwrap();
    let flag = o.flag(None).unwrap();
    assert!(
        !flag.earned,
        "a rule set that fires on a reader swap should not earn drill 5.2"
    );
    let d = o.facts.detection.unwrap();
    assert!(
        d.any_finding_during(odr_detect::Episode::ReaderReplaced),
        "and the reason should be the reader swap"
    );
}

#[test]
fn drill_5_3_the_keyset_is_reported_and_reported_as_undecidable() {
    let o = earned(5, 3);
    let d = o.facts.detection.clone().unwrap();
    assert!(d.is_ambiguous(odr_detect::Signal::KeysetObserved));
    assert!(!d.score.ambiguous().is_empty());
    not_earned(5, 3);
}

/// A probe on the pair and no further ideas. The analysis is the attack in
/// these drills, and this asserts that it is.
fn clipping_on_is_not_enough(module: u8, index: u8) {
    let id = DrillId::new(module, index);
    let o = run::observe_only(id, SEED).unwrap();
    let flag = o.flag(o.engine_answer().as_ref()).unwrap();
    assert!(
        !flag.earned,
        "drill {id} is earned by clipping a passive probe on and pressing Run, which makes the \
         rest of the drill decoration.\n  evidence: {:#?}",
        flag.evidence
    );
}

#[test]
fn the_analysis_drills_are_not_earned_by_listening_alone() {
    // 3.2 needs the sweep; 3.3 needs the sweep against a site key; 3.5 needs
    // the keyset payload lifted out of the commissioning channel; 4.4 needs
    // the payloads actually read.
    clipping_on_is_not_enough(3, 2);
    clipping_on_is_not_enough(3, 3);
    clipping_on_is_not_enough(3, 5);
    clipping_on_is_not_enough(4, 4);
}

#[test]
fn a_solved_drill_still_needs_its_submission() {
    for drill in catalog::DRILLS.iter().filter(|d| d.submission.is_some()) {
        let o = run::solve(drill.id, SEED).unwrap();
        let flag = o.flag(None).unwrap();
        assert!(
            !flag.earned,
            "drill {} awards its flag without the learner submitting anything",
            drill.id
        );
    }
}

// ===========================================================================
// The catalogue
// ===========================================================================

#[test]
fn the_curriculum_has_twenty_nine_drills_in_six_modules() {
    assert_eq!(catalog::drill_count(), 29);
    let per_module: Vec<usize> = (0..6)
        .map(|m| catalog::drills_in(odr_scenario::ModuleId(m)).len())
        .collect();
    assert_eq!(per_module, vec![6, 6, 4, 6, 4, 3]);
    assert_eq!(catalog::MODULES.len(), 6);
}

#[test]
fn every_drill_is_addressable_by_its_curriculum_number() {
    for drill in catalog::DRILLS {
        let name = drill.id.as_string();
        assert_eq!(
            catalog::drill_by_name(&name).map(|d| d.id),
            Some(drill.id),
            "{name} is not reachable by name"
        );
        assert_eq!(drill.module.0, drill.id.module);
    }
}

#[test]
fn the_drills_are_in_curriculum_order() {
    let mut previous = None;
    for drill in catalog::DRILLS {
        if let Some(p) = previous {
            assert!(drill.id > p, "{} came after {p}", drill.id);
        }
        previous = Some(drill.id);
    }
}

#[test]
fn gold_gets_the_objective_and_nothing_else() {
    for drill in catalog::DRILLS {
        assert!(
            drill.guidance.gold.is_empty(),
            "drill {} has Gold guidance, which is not what Gold is",
            drill.id
        );
        assert!(
            drill.hints_for(Band::Gold).is_empty(),
            "drill {} offers hints at Gold",
            drill.id
        );
    }
}

#[test]
fn bronze_pre_places_the_taps_and_nothing_else_does() {
    for drill in catalog::DRILLS {
        assert_eq!(drill.taps_for(Band::Bronze), drill.taps, "{}", drill.id);
        assert!(
            drill.taps_for(Band::Silver).is_empty(),
            "drill {} arrives at Silver with a tap already fitted",
            drill.id
        );
        assert!(
            drill.taps_for(Band::Gold).is_empty(),
            "drill {} arrives at Gold with a tap already fitted",
            drill.id
        );
    }
}

#[test]
fn every_simulated_drill_has_guidance_at_bronze_and_silver() {
    for drill in catalog::DRILLS {
        assert!(
            !drill.guidance.bronze.is_empty(),
            "drill {} has no Bronze steps, so a beginner selecting Bronze gets nothing",
            drill.id
        );
        assert!(
            !drill.guidance.silver.is_empty(),
            "drill {} has no Silver standing line",
            drill.id
        );
    }
}

#[test]
fn every_drill_states_its_objective_and_its_predicate() {
    for drill in catalog::DRILLS {
        assert!(!drill.title.is_empty(), "{}", drill.id);
        assert!(drill.summary.len() > 40, "{} has a thin summary", drill.id);
        assert!(
            drill.objective.len() > 20,
            "{} has a thin objective",
            drill.id
        );
        assert!(
            drill.flag_text.len() > 40,
            "{} has a thin flag statement",
            drill.id
        );
    }
}

#[test]
fn only_two_drills_are_not_flag_shaped() {
    let odd: Vec<(String, Completion)> = catalog::DRILLS
        .iter()
        .filter(|d| d.completion != Completion::Flag)
        .map(|d| (d.id.as_string(), d.completion))
        .collect();
    assert_eq!(
        odd,
        vec![
            (String::from("0.6"), Completion::Reference),
            (String::from("1.5"), Completion::Measurement),
        ]
    );
}

#[test]
fn the_reference_section_is_the_only_unsimulated_one() {
    let unsimulated: Vec<String> = catalog::DRILLS
        .iter()
        .filter(|d| !d.is_simulated())
        .map(|d| d.id.as_string())
        .collect();
    assert_eq!(unsimulated, vec![String::from("0.6")]);
    assert_eq!(
        catalog::drill_by_name("0.6").unwrap().scenario,
        ScenarioId::NoBench
    );
}

#[test]
fn every_scenario_the_catalogue_names_can_actually_be_built() {
    for scenario in ScenarioId::ALL {
        if !scenario.is_bench() {
            assert!(odr_scenario::scenario::build(*scenario, SEED).is_err());
            continue;
        }
        let bench = odr_scenario::scenario::build(*scenario, SEED)
            .unwrap_or_else(|e| panic!("{} would not build: {e}", scenario.name()));
        assert_eq!(bench.scenario, *scenario);
        assert!(bench.reader.is_some(), "{}", scenario.name());
    }
}

#[test]
fn no_scenario_in_the_catalogue_is_unreachable() {
    for scenario in ScenarioId::ALL {
        assert!(
            !catalog::drills_using(*scenario).is_empty(),
            "{} is defined and no drill uses it",
            scenario.name()
        );
    }
}

#[test]
fn an_unknown_drill_is_an_error_rather_than_a_panic() {
    assert!(run::solve(DrillId::new(9, 9), SEED).is_err());
    assert!(catalog::drill_by_name("not a drill").is_none());
    assert!(DrillId::parse("1.").is_none());
    assert!(DrillId::parse("").is_none());
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn the_same_seed_gives_the_same_drill() {
    fn run_once(seed: u64) -> (String, bool, String) {
        let o = run::solve(DrillId::new(1, 3), seed).unwrap();
        let flag = o.flag(None).unwrap();
        (
            o.world().unwrap().export_capture(),
            flag.earned,
            format!("{:?}", flag.evidence),
        )
    }
    let a = run_once(0xDEAD_BEEF);
    let b = run_once(0xDEAD_BEEF);
    assert_eq!(a, b);

    let c = run_once(0xFEED_FACE);
    assert!(c.1, "the attack still works under a different seed");
    assert_ne!(a.0, c.0, "but the bytes on the wire are different");
}

#[test]
fn a_different_seed_gives_a_different_answer_to_submit() {
    // The point of the seed: drill 1.1's correct answer is not a constant.
    let a = run::solve(DrillId::new(1, 1), 1).unwrap();
    let b = run::solve(DrillId::new(1, 1), 2).unwrap();
    assert_ne!(a.engine_answer(), b.engine_answer());

    // And one session's answer does not open another's drill.
    let flag = b.flag(a.engine_answer().as_ref()).unwrap();
    assert!(!flag.earned);
}

#[test]
fn every_drill_that_takes_a_submission_says_so() {
    for drill in catalog::DRILLS {
        let o = match run::solve(drill.id, SEED) {
            Ok(o) => o,
            Err(e) => panic!("drill {} did not run: {e}", drill.id),
        };
        assert_eq!(
            drill.submission.is_some(),
            o.engine_answer().is_some(),
            "drill {} disagrees with itself about whether it takes a submission",
            drill.id
        );
    }
}
