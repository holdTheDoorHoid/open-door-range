//! Tests for the bridge.
//!
//! The properties here are the ones that would be invisible if they broke: a
//! decode tree whose offsets have drifted from the bytes still renders, a flag
//! the bridge awarded itself still says FLAG EARNED, and a command byte marked
//! opaque still draws a tree. Each of those would be a lie the interface told
//! confidently, so each has a test.

use alloc::string::{String, ToString};

use odr_scenario::catalog;
use odr_scenario::ids::{Band, TapMode};

use crate::bench::{self, Source, Tap};
use crate::decode::{self, At};
use crate::{seed_for, Engine};

fn tap(id: &str, mode: TapMode) -> Tap {
    Tap {
        id: id.to_string(),
        link_id: String::from("reader-controller"),
        mode,
        pre_placed: false,
    }
}

// ---------------------------------------------------------------------------
// The catalogue crosses intact
// ---------------------------------------------------------------------------

#[test]
fn the_catalogue_is_the_curriculum() {
    let e = Engine::new();
    let cat = e.catalog();
    assert!(cat.contains("\"drillCount\":29"), "{cat}");
    for d in catalog::DRILLS {
        assert!(
            cat.contains(&alloc::format!("\"id\":\"{}\"", d.id)),
            "drill {} missing from the catalogue JSON",
            d.id
        );
    }
}

#[test]
fn every_drill_loads_and_produces_a_session() {
    let mut e = Engine::new();
    for d in catalog::DRILLS {
        let session = e.load_drill(&d.id.as_string(), "bronze");
        assert!(
            e.last_error().is_empty(),
            "drill {} failed to load: {}",
            d.id,
            e.last_error()
        );
        assert!(
            session.contains(&alloc::format!("\"drillId\":\"{}\"", d.id)),
            "drill {} session wrong: {session}",
            d.id
        );
        assert!(e.duration() > 0.0, "drill {} has no duration", d.id);
        // Every drill must be able to answer the accessors the site calls on a
        // render path without panicking.
        let _ = e.topology();
        let _ = e.config_groups();
        let _ = e.state_at(e.duration() / 2.0);
        let _ = e.markers();
        let _ = e.flag();
        let _ = e.submission();
        let _ = e.task_states(1000.0);
        let _ = e.timeline(0.0, e.duration(), 600.0, false);
    }
}

// ---------------------------------------------------------------------------
// Bands change the guidance, never the bench
// ---------------------------------------------------------------------------

#[test]
fn bronze_pre_places_the_taps_and_the_other_bands_do_not() {
    let mut e = Engine::new();
    for d in catalog::DRILLS {
        if d.taps.is_empty() {
            continue;
        }
        e.load_drill(&d.id.as_string(), "bronze");
        assert!(
            e.topology().contains("\"prePlaced\":true"),
            "drill {} at bronze should arrive with its taps fitted",
            d.id
        );
        for band in ["silver", "gold"] {
            e.load_drill(&d.id.as_string(), band);
            assert!(
                !e.topology().contains("\"prePlaced\":true"),
                "drill {} at {band} must arrive with nothing clipped on",
                d.id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Taps gate the simulation
// ---------------------------------------------------------------------------

#[test]
fn a_flag_needing_a_tap_is_not_earned_without_one() {
    let mut e = Engine::new();
    // 1.3 Replay: "the controller granted at a time when no credential was
    // presented". Pressing Run with nothing clipped on must not earn it.
    e.load_drill("1.3", "silver");
    let bare = e.flag();
    assert!(
        bare.contains("\"earned\":false"),
        "1.3 must not be earnable with no tap: {bare}"
    );
    e.add_tap("reader-controller", "inject");
    let armed = e.flag();
    assert!(
        armed.contains("\"earned\":true"),
        "1.3 should be earned once the transmitter is on the pair: {armed}"
    );
}

#[test]
fn a_sniffer_is_not_an_implant() {
    let mut e = Engine::new();
    e.load_drill("1.4", "silver");
    e.add_tap("reader-controller", "sniff");
    let sniffing = e.flag();
    assert!(
        sniffing.contains("\"earned\":false"),
        "1.4 must not be earnable from a passive clip: {sniffing}"
    );
}

#[test]
fn drill_4_3_needs_two_taps_on_one_pair() {
    let d = catalog::drill_by_name("4.3").expect("4.3 is in the catalogue");
    assert_eq!(d.taps.len(), 2, "4.3 is the two-tap drill");
    assert!(
        !bench::plan_satisfied(d, &[tap("t1", TapMode::Inline)]),
        "one inline tap must not stand in for an implant plus an analyser"
    );
    assert!(bench::plan_satisfied(
        d,
        &[tap("t1", TapMode::Inline), tap("t2", TapMode::Sniff)]
    ));
}

#[test]
fn a_second_tap_in_the_same_mode_is_refused() {
    let mut e = Engine::new();
    e.load_drill("4.3", "silver");
    assert!(e
        .add_tap("reader-controller", "inline")
        .contains("\"ok\":true"));
    let again = e.add_tap("reader-controller", "inline");
    assert!(again.contains("\"ok\":false"), "{again}");
    assert!(e
        .add_tap("reader-controller", "sniff")
        .contains("\"ok\":true"));
}

// ---------------------------------------------------------------------------
// The inspector's split
// ---------------------------------------------------------------------------

#[test]
fn offsets_mirror_the_encoder_for_every_bus_frame() {
    for d in catalog::DRILLS {
        let run = match bench::drive(d, seed_for(d.id), &[]) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for f in &run.frames {
            let Source::Osdp(frame) = &f.source else {
                continue;
            };
            let wire = frame.encode();
            assert_eq!(wire, f.bytes, "drill {} frame {} bytes differ", d.id, f.id);
            for field in f.fields() {
                if let At::Bytes(off, len) = field.at {
                    assert!(
                        off + len <= wire.len(),
                        "drill {} field {} runs past the end of the frame",
                        d.id,
                        field.id
                    );
                    assert_eq!(
                        decode::hex_spaced(&wire[off..off + len]),
                        field.value,
                        "drill {} field {} names bytes it does not sit on",
                        d.id,
                        field.id
                    );
                }
            }
        }
    }
}

#[test]
fn the_command_byte_is_readable_on_an_encrypted_frame() {
    let d = catalog::drill_by_name("4.1").expect("4.1 exists");
    let run = bench::drive(d, seed_for(d.id), &[]).expect("4.1 runs");
    let mut seen = 0;
    for f in &run.frames {
        if !f.secure.encrypted {
            continue;
        }
        seen += 1;
        let fields = f.fields();
        let code = fields
            .iter()
            .find(|x| x.id == "code")
            .expect("every OSDP frame has a command or reply code");
        assert_eq!(
            code.visibility, "clear",
            "the command byte is plaintext in every OSDP security mode"
        );
        let payload = fields
            .iter()
            .find(|x| x.id == "payload")
            .expect("an encrypted frame has a payload");
        assert_eq!(payload.visibility, "opaque");
    }
    assert!(
        seen > 0,
        "4.1 is the encrypted-day drill and had no ciphertext"
    );
}

#[test]
fn a_cleartext_frame_seals_nothing() {
    let d = catalog::drill_by_name("2.2").expect("2.2 exists");
    let run = bench::drive(d, seed_for(d.id), &[tap("t1", TapMode::Sniff)]).expect("2.2 runs");
    for f in &run.frames {
        if f.lane != "bus" {
            continue;
        }
        for field in f.fields() {
            assert_eq!(
                field.visibility, "clear",
                "nothing on an unsecured bus is concealed"
            );
        }
    }
}

#[test]
fn a_recovered_key_opens_the_payload_and_nothing_else_does() {
    // 3.2, the default key: the attack recovers the session keys from traffic,
    // so the sealed side fills in with real AES plaintext.
    let d = catalog::drill_by_name("3.2").expect("3.2 exists");
    let solved = bench::drive(d, seed_for(d.id), &[tap("t1", TapMode::Sniff)]).expect("3.2 runs");
    let opened = solved
        .frames
        .iter()
        .filter(|f| f.plaintext.is_some())
        .count();
    assert!(
        opened > 0,
        "the attacker holds the published default key and should have opened traffic"
    );

    // 4.1 insists the attacker held no key at any point, so every payload on
    // that bench stays sealed. That is the drill.
    let d = catalog::drill_by_name("4.1").expect("4.1 exists");
    let analysed = bench::drive(d, seed_for(d.id), &[tap("t1", TapMode::Sniff)]).expect("4.1 runs");
    assert_eq!(
        analysed
            .frames
            .iter()
            .filter(|f| f.plaintext.is_some())
            .count(),
        0,
        "traffic analysis works without a key, and must be shown working without one"
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn the_same_drill_gives_the_same_bytes_twice() {
    let mut a = Engine::new();
    let mut b = Engine::new();
    for id in ["1.1", "2.2", "3.2", "4.1"] {
        a.load_drill(id, "silver");
        b.load_drill(id, "silver");
        assert_eq!(
            a.frames(0.0, f64::INFINITY, false, None, 4000.0),
            b.frames(0.0, f64::INFINITY, false, None, 4000.0),
            "drill {id} is not deterministic across the boundary"
        );
        assert_eq!(a.flag(), b.flag());
    }
}

// ---------------------------------------------------------------------------
// Honest density
// ---------------------------------------------------------------------------

#[test]
fn the_bus_is_drawn_honestly_and_collapses_only_on_request() {
    let mut e = Engine::new();
    e.load_drill("4.1", "silver");
    let honest = e.frames(0.0, f64::INFINITY, false, None, 100_000.0);
    assert!(honest.contains("\"collapsed\":null"));
    let collapsed = e.frames(0.0, f64::INFINITY, true, None, 100_000.0);
    assert!(collapsed.contains("\"hiddenFrames\":"));
    assert!(
        collapsed.contains("\"kind\":\"collapsed\""),
        "a day of polling has runs of four or more to collapse"
    );
}

#[test]
fn a_real_bus_is_hundreds_of_frames_and_the_bridge_hands_them_all_over() {
    let mut e = Engine::new();
    e.load_drill("4.1", "silver");
    let json = e.frames(0.0, f64::INFINITY, false, None, 100_000.0);
    let rows = json.matches("\"tUs\"").count();
    assert!(
        rows > 200,
        "drill 4.1 is the density lesson and produced only {rows} frames"
    );
}

// ---------------------------------------------------------------------------
// Submissions
// ---------------------------------------------------------------------------

#[test]
fn the_submission_drills_ask_for_something_and_refuse_a_wrong_answer() {
    let mut e = Engine::new();
    e.load_drill("1.1", "silver");
    let spec = e.submission();
    assert!(spec.contains("facility_code"), "{spec}");

    let wrong = e.submit_field("facility_code", "999");
    assert!(wrong.contains("\"earned\":false"), "{wrong}");
    e.submit_field("card_number", "999");
    assert!(e.flag().contains("\"earned\":false"));
}

#[test]
fn drill_2_1_composes_its_form_from_the_frame_that_crossed() {
    let mut e = Engine::new();
    e.load_drill("2.1", "bronze");
    let spec = e.submission();
    for field in [
        "off_som",
        "off_address",
        "off_length",
        "off_control",
        "off_id",
        "off_crc",
    ] {
        assert!(
            spec.contains(field),
            "{field} missing from 2.1's form: {spec}"
        );
    }
}

#[test]
fn module_5_scores_the_rule_set_it_is_given() {
    let mut e = Engine::new();
    e.load_drill("5.1", "bronze");
    let floor = e.flag();
    assert!(
        floor.contains("\"earned\":false"),
        "an empty rule set is the floor: {floor}"
    );
    let scored = e.submit_field("ruleset", "standard");
    assert!(
        scored.contains("\"earned\":true"),
        "the standard rule set should earn 5.1: {scored}"
    );
}

// ---------------------------------------------------------------------------
// Configuration reports rather than sets
// ---------------------------------------------------------------------------

#[test]
fn every_group_has_a_summary_line() {
    let mut e = Engine::new();
    for d in catalog::DRILLS {
        e.load_drill(&d.id.as_string(), "bronze");
        let groups = e.config_groups();
        assert!(
            !groups.contains("\"summary\":\"\""),
            "drill {} has a group with an empty summary line",
            d.id
        );
    }
}

#[test]
fn an_option_this_bench_cannot_express_is_refused_with_a_reason() {
    // Drill 1.1 is a Wiegand pair. There is no Secure Channel to turn on, and
    // the refusal has to say so rather than discarding the input.
    let mut e = Engine::new();
    e.load_drill("1.1", "bronze");
    let r = e.set_config("security", "secureChannel", "required");
    assert!(r.contains("\"ok\":false"), "{r}");
    assert!(r.contains("Wiegand"), "{r}");
    assert!(r.contains("cryptography"), "{r}");
}

#[test]
fn setting_an_option_rebuilds_the_bench_and_bumps_the_version() {
    let mut e = Engine::new();
    e.load_sandbox(Some(String::from("osdp-clear")));
    let before = e.version();
    let plain = e.frames(0.0, 1.0e12, false, None, 0.0);
    let r = e.set_config("security", "secureChannel", "if-available");
    assert!(r.contains("\"ok\":true"), "{r}");
    assert!(e.version() > before, "a rebuild has to bump the version");
    assert_ne!(
        plain,
        e.frames(0.0, 1.0e12, false, None, 0.0),
        "turning Secure Channel on changes the bus"
    );
    assert!(
        e.config_groups().contains("\"value\":\"if-available\""),
        "the groups report what the bench was built with"
    );
    // And back again, by the one move that does not require remembering.
    let r = e.reset_config();
    assert!(r.contains("\"ok\":true"), "{r}");
    assert_eq!(
        plain,
        e.frames(0.0, 1.0e12, false, None, 0.0),
        "reset returns the scenario's own bench"
    );
}

#[test]
fn the_same_options_give_the_same_bytes_across_a_rebuild() {
    let mut a = Engine::new();
    a.load_sandbox(Some(String::from("osdp-clear")));
    a.set_config("security", "secureChannel", "required");
    a.set_config("security", "key", "weak");
    a.set_config("link", "baud", "19200");

    let mut b = Engine::new();
    b.load_sandbox(Some(String::from("osdp-clear")));
    // A different order, and the middle one set twice.
    b.set_config("link", "baud", "38400");
    b.set_config("security", "key", "weak");
    b.set_config("link", "baud", "19200");
    b.set_config("security", "secureChannel", "required");

    assert_eq!(
        a.frames(0.0, 1.0e12, false, None, 0.0),
        b.frames(0.0, 1.0e12, false, None, 0.0)
    );
}

#[test]
fn a_setting_that_breaks_the_drill_is_applied_and_warned_about() {
    // docs/UI.md: warn rather than block.
    let mut e = Engine::new();
    e.load_drill("3.2", "bronze");
    let r = e.set_config("security", "secureChannel", "off");
    assert!(r.contains("\"ok\":true"), "{r}");
    assert!(r.contains("\"warning\":"), "{r}");
    assert!(r.contains("cannot be earned"), "{r}");
    assert!(!e.flag().contains("\"earned\":true"));
}

#[test]
fn loading_a_drill_forgets_the_options() {
    let mut e = Engine::new();
    e.load_sandbox(Some(String::from("osdp-clear")));
    e.set_config("security", "secureChannel", "required");
    e.load_drill("2.2", "bronze");
    let groups = e.config_groups();
    assert!(groups.contains("\"value\":\"off\""), "{groups}");
    assert!(!groups.contains("\"changed\":true"));
}

#[test]
fn the_card_panel_does_not_print_drill_1_1s_answer() {
    let mut e = Engine::new();
    e.load_drill("1.1", "bronze");
    let run = bench::drive(
        catalog::drill_by_name("1.1").expect("1.1 exists"),
        seed_for(catalog::drill_by_name("1.1").expect("1.1 exists").id),
        &[],
    )
    .expect("1.1 runs");
    let Some(tx) = &run.outcome.facts.transmitted else {
        return;
    };
    let groups = e.config_groups();
    if let Some(number) = tx.card_number {
        assert!(
            !groups.contains(&number.to_string()),
            "the card number is drill 1.1's answer and must not be printed in a panel"
        );
    }
}

// ---------------------------------------------------------------------------
// Bands
// ---------------------------------------------------------------------------

#[test]
fn gold_gets_the_objective_and_nothing_else() {
    let e = Engine::new();
    for d in catalog::DRILLS {
        let j = e.get_drill(&d.id.as_string());
        assert!(
            j.contains("\"gold\":[]"),
            "drill {} offers gold guidance",
            d.id
        );
    }
    assert!(!Band::Gold.offers_hints());
}

// ---------------------------------------------------------------------------
// Volume, measured
// ---------------------------------------------------------------------------

/// Not an assertion so much as a record: the numbers in `README.md` come from
/// here, and a change that made a drill ten times heavier would show up.
#[test]
fn frame_counts_are_what_the_readme_says() {
    let mut e = Engine::new();
    let mut worst = 0usize;
    let mut worst_id = String::new();
    for d in catalog::DRILLS {
        e.load_drill(&d.id.as_string(), "bronze");
        let json = e.frames(0.0, f64::INFINITY, false, None, 100_000.0);
        let rows = json.matches("\"tUs\"").count();
        if rows > worst {
            worst = rows;
            worst_id = d.id.as_string();
        }
    }
    assert!(
        worst < 20_000,
        "drill {worst_id} produces {worst} rows, which is more than the timeline was measured at"
    );
    std::eprintln!("heaviest drill: {worst_id} with {worst} frames");
}

#[test]
fn free_play_runs_the_bench_untouched() {
    let mut e = Engine::new();
    let session = e.load_sandbox(None);
    assert!(session.contains("\"sandbox\":true"), "{session}");
    assert!(session.contains("Free play"));
    assert!(e.flag().contains("\"drillId\":null"));
    let json = e.frames(0.0, f64::INFINITY, false, None, 4000.0);
    assert!(
        json.matches("\"tUs\"").count() > 0,
        "free play should still carry traffic"
    );
}
