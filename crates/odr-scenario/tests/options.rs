//! **The bench options.**
//!
//! Four things have to be true and are each pinned here.
//!
//! 1. Defaults reproduce every existing bench *byte for byte*, so the whole
//!    curriculum is unaffected by the seam existing.
//! 2. Every option actually changes the simulation in the way it claims, tested
//!    against the capture rather than against the config struct — a field that
//!    is set and never read would pass the second kind of test and fail this
//!    one.
//! 3. An option a bench cannot express is refused, with a reason.
//! 4. The same options plus the same seed give the same bytes, on a rebuild.

use odr_scenario::options::{self, BenchOptions, KeyChoice, LinkChoice, OptionKind};
use odr_scenario::{run, scenario, DrillId, ScenarioId};

const SEED: u64 = 0x0D_C0FF_EE00;

fn capture(scenario: ScenarioId, opts: &BenchOptions) -> String {
    let mut bench = scenario::build_with(scenario, SEED, opts).expect("bench builds");
    bench.run_script().expect("script runs");
    bench.world.export_capture()
}

fn benches() -> impl Iterator<Item = ScenarioId> {
    ScenarioId::ALL.iter().copied().filter(|s| s.is_bench())
}

// ===========================================================================
// 1. Defaults are today's benches
// ===========================================================================

#[test]
fn defaults_reproduce_every_bench_byte_for_byte() {
    for s in benches() {
        let old = {
            let mut b = scenario::build(s, SEED).expect("bench builds");
            b.run_script().expect("script runs");
            b.world.export_capture()
        };
        let new = capture(s, &BenchOptions::default());
        assert_eq!(old, new, "{} changed under default options", s.name());
    }
}

#[test]
fn defaults_reproduce_every_drill_byte_for_byte() {
    for drill in odr_scenario::catalog::DRILLS {
        if !drill.scenario.is_bench() {
            continue;
        }
        let plain = run::solve(drill.id, SEED).expect("solves");
        let opted = run::solve_with(drill.id, SEED, &BenchOptions::default()).expect("solves");
        assert_eq!(
            plain.world().map(|w| w.export_capture()),
            opted.world().map(|w| w.export_capture()),
            "drill {} changed under default options",
            drill.id
        );
        assert_eq!(
            plain.flag(None).unwrap().earned,
            opted.flag(None).unwrap().earned,
            "drill {} flag changed under default options",
            drill.id
        );
    }
}

#[test]
fn every_scenarys_declared_defaults_match_the_bench_it_builds() {
    // The table in `options::defaults` is a transcription of what each builder
    // hardcodes. If it drifts, the bench the options layer describes is not the
    // bench the engine ran, which is the one thing docs/UI.md forbids.
    for s in benches() {
        let r = options::defaults(s);
        let bench = scenario::build(s, SEED).unwrap();
        assert_eq!(
            bench.world.door(bench.door).unwrap().strike_time_us,
            u64::from(r.strike_ms) * 1000,
            "{}",
            s.name()
        );
        let acu = bench
            .world
            .controllers()
            .filter_map(|c| c.mode.acu_config())
            .next()
            .cloned();
        if let Some(acu) = acu {
            assert_eq!(acu.sc, r.sc, "{} sc", s.name());
            assert_eq!(acu.mac_len, r.mac_bytes, "{} mac", s.name());
            assert_eq!(acu.trust_pdcap, r.trust_pdcap, "{} pdcap", s.name());
            assert_eq!(acu.install_mode, r.acu_install_mode, "{} install", s.name());
            assert_eq!(acu.encrypt_payloads, !r.null_cipher, "{} cipher", s.name());
            assert_eq!(
                acu.poll_interval_us,
                u64::from(r.poll_ms) * 1000,
                "{} poll",
                s.name()
            );
        }
    }
}

// ===========================================================================
// 2. Every option changes the simulation
// ===========================================================================

/// The count of Secure Channel handshake frames in a capture.
///
/// `CMD_CHLNG` is 0x76 and it only ever appears as the first byte of a secure
/// channel handshake payload, so counting the string is enough for a test that
/// only asks "did a handshake happen".
fn handshook(capture: &str) -> bool {
    capture.contains("\"sc\"") || capture.contains("scs") || capture_has_chlng(capture)
}

fn capture_has_chlng(capture: &str) -> bool {
    // Every frame line carries `"bytes":"53..."`; a CHLNG command puts 0x76 in
    // the command position of a frame whose control byte has the SCB bit set.
    capture
        .lines()
        .filter_map(|l| l.split("\"bytes\":\"").nth(1))
        .filter_map(|r| r.split('"').next())
        .any(|hex| {
            let b: Vec<u8> = (0..hex.len() / 2)
                .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                .collect();
            b.len() > 6 && b[4] & 0x08 != 0
        })
}

#[test]
fn secure_channel_on_puts_a_handshake_on_a_bus_that_had_none() {
    let plain = capture(ScenarioId::OsdpClear, &BenchOptions::default());
    assert!(!handshook(&plain), "the clear bench should carry no SCB");

    let mut opts = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpClear,
        &mut opts,
        options::SECURE_CHANNEL,
        "if-available",
    )
    .expect("accepted");
    let secured = capture(ScenarioId::OsdpClear, &opts);
    assert!(
        handshook(&secured),
        "turning it on should produce a channel"
    );
    assert_ne!(plain, secured);
}

#[test]
fn secure_channel_off_takes_the_handshake_away_again() {
    let on = capture(ScenarioId::OsdpDefaultKey, &BenchOptions::default());
    assert!(handshook(&on));
    let mut opts = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpDefaultKey,
        &mut opts,
        options::SECURE_CHANNEL,
        "off",
    )
    .unwrap();
    let off = capture(ScenarioId::OsdpDefaultKey, &opts);
    assert!(!handshook(&off));
}

#[test]
fn the_key_option_changes_the_key_the_bench_was_commissioned_with() {
    let default = scenario::build(ScenarioId::OsdpDefaultKey, SEED).unwrap();
    assert_eq!(default.site_key, Some(odr_osdp::SCBK_D));

    let mut weak = BenchOptions::default();
    options::apply(ScenarioId::OsdpDefaultKey, &mut weak, options::KEY, "weak").unwrap();
    let b = scenario::build_with(ScenarioId::OsdpDefaultKey, SEED, &weak).unwrap();
    let key = b.site_key.expect("a keyed bench");
    assert_ne!(key, odr_osdp::SCBK_D);
    assert!(
        odr_osdp::weak_keys::is_weak(&key),
        "the weak choice must produce a key from the published family"
    );

    let mut site = BenchOptions::default();
    options::apply(ScenarioId::OsdpDefaultKey, &mut site, options::KEY, "site").unwrap();
    let b = scenario::build_with(ScenarioId::OsdpDefaultKey, SEED, &site).unwrap();
    let key = b.site_key.expect("a keyed bench");
    assert_ne!(key, odr_osdp::SCBK_D);
    assert!(!odr_osdp::weak_keys::is_weak(&key));
}

#[test]
fn the_key_option_decides_whether_the_key_drills_are_winnable() {
    // 3.3 sweeps the published sample family, and 3.2 recognises the key from
    // the manual. Each is winnable on its own bench and stops being winnable
    // when the key moves — and the predicate says which of the two it is
    // looking at, which is the honest answer rather than a silent failure.
    assert!(
        run::solve(DrillId::new(3, 3), SEED)
            .unwrap()
            .flag(None)
            .unwrap()
            .earned
    );

    let mut site = BenchOptions::default();
    options::apply(ScenarioId::OsdpWeakKey, &mut site, options::KEY, "site").unwrap();
    let flag = run::solve_with(DrillId::new(3, 3), SEED, &site)
        .unwrap()
        .flag(None)
        .unwrap();
    assert!(!flag.earned, "a site key is not sweepable");
    assert!(
        !flag.outstanding.is_empty(),
        "an unearned flag has to say what is missing"
    );

    let mut default = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpWeakKey,
        &mut default,
        options::KEY,
        "scbk-d",
    )
    .unwrap();
    let flag = run::solve_with(DrillId::new(3, 3), SEED, &default)
        .unwrap()
        .flag(None)
        .unwrap();
    assert!(!flag.earned);
    assert!(
        flag.outstanding.iter().any(|o| o.contains("3.2")),
        "the predicate should name the drill this bench has become: {:?}",
        flag.outstanding
    );

    // And the other direction: 3.2 is about the published default, so a weak
    // site key takes its flag away.
    assert!(
        run::solve(DrillId::new(3, 2), SEED)
            .unwrap()
            .flag(None)
            .unwrap()
            .earned
    );
    let mut weak = BenchOptions::default();
    options::apply(ScenarioId::OsdpDefaultKey, &mut weak, options::KEY, "weak").unwrap();
    assert!(
        !run::solve_with(DrillId::new(3, 2), SEED, &weak)
            .unwrap()
            .flag(None)
            .unwrap()
            .earned
    );
}

#[test]
fn distrusting_the_capability_reply_stops_the_downgrade() {
    let attacked = run::solve(DrillId::new(3, 6), SEED).unwrap();
    assert!(
        attacked.flag(None).unwrap().earned,
        "3.6 is earnable as written"
    );

    let mut defended = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpRequiredSc,
        &mut defended,
        options::TRUST_PDCAP,
        "false",
    )
    .unwrap();
    let out = run::solve_with(DrillId::new(3, 6), SEED, &defended).unwrap();
    assert!(
        !out.flag(None).unwrap().earned,
        "with the capability reply distrusted the downgrade must fail"
    );
}

#[test]
fn install_mode_off_stops_the_key_being_handed_out() {
    assert!(
        run::solve(DrillId::new(3, 4), SEED)
            .unwrap()
            .flag(None)
            .unwrap()
            .earned
    );
    let mut shut = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpInstallMode,
        &mut shut,
        options::ACU_INSTALL,
        "false",
    )
    .unwrap();
    let out = run::solve_with(DrillId::new(3, 4), SEED, &shut).unwrap();
    assert!(!out.flag(None).unwrap().earned);
}

#[test]
fn a_reader_that_claims_no_crypto_gets_talked_to_in_the_clear() {
    let mut legacy = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpDefaultKey,
        &mut legacy,
        options::PD_AES,
        "false",
    )
    .unwrap();
    let c = capture(ScenarioId::OsdpDefaultKey, &legacy);
    assert!(
        !handshook(&c),
        "a controller that trusts the capability reply should not attempt a handshake"
    );
}

#[test]
fn the_null_cipher_leaves_the_payload_readable() {
    // 4.4 reads a payload off a MACed-but-unencrypted link. Turning the null
    // cipher off on its own bench takes that away.
    assert!(
        run::solve(DrillId::new(4, 4), SEED)
            .unwrap()
            .flag(None)
            .unwrap()
            .earned
    );
    let mut encrypted = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpNullCipher,
        &mut encrypted,
        options::NULL_CIPHER,
        "false",
    )
    .unwrap();
    let out = run::solve_with(DrillId::new(4, 4), SEED, &encrypted).unwrap();
    assert!(!out.flag(None).unwrap().earned);
}

#[test]
fn the_mac_width_is_what_the_forger_measures_off_the_wire() {
    let rigged = run::solve(DrillId::new(4, 2), SEED).unwrap();
    assert_eq!(
        rigged.facts.forgery.as_ref().map(|f| f.effective_mac_bytes),
        Some(1)
    );
    let mut honest = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpShortMac,
        &mut honest,
        options::MAC_BYTES,
        "4",
    )
    .unwrap();
    let out = run::solve_with(DrillId::new(4, 2), SEED, &honest).unwrap();
    assert_eq!(
        out.facts.forgery.as_ref().map(|f| f.effective_mac_bytes),
        Some(4),
        "at four bytes the forger must measure four"
    );
    assert!(
        !out.flag(None).unwrap().earned,
        "the honest width is the width the forgery does not finish at"
    );
}

#[test]
fn the_line_rate_changes_how_long_a_frame_takes() {
    let slow = capture(ScenarioId::OsdpClear, &BenchOptions::default());
    let mut fast = BenchOptions::default();
    options::apply(ScenarioId::OsdpClear, &mut fast, options::BAUD, "115200").unwrap();
    let quick = capture(ScenarioId::OsdpClear, &fast);
    assert_ne!(slow, quick, "the bus timing has to move with the line rate");
}

#[test]
fn the_poll_interval_changes_how_much_idle_traffic_there_is() {
    let busy = capture(ScenarioId::OsdpClear, &BenchOptions::default());
    let mut lazy = BenchOptions::default();
    options::apply(ScenarioId::OsdpClear, &mut lazy, options::POLL_MS, "500").unwrap();
    let quiet = capture(ScenarioId::OsdpClear, &lazy);
    assert!(
        quiet.lines().count() < busy.lines().count(),
        "polling five times slower must put fewer frames on the bus"
    );
}

#[test]
fn the_wire_protocol_option_moves_a_wiegand_door_onto_clock_and_data() {
    let wiegand = capture(ScenarioId::WiegandDoor, &BenchOptions::default());
    let mut cd = BenchOptions::default();
    options::apply(ScenarioId::WiegandDoor, &mut cd, options::LINK, "clockdata").unwrap();
    let clock_data = capture(ScenarioId::WiegandDoor, &cd);
    assert_ne!(
        wiegand, clock_data,
        "a different encoding is different bytes"
    );

    let plain = scenario::build(ScenarioId::WiegandDoor, SEED).unwrap();
    assert!(matches!(
        plain.world.link(plain.link).unwrap(),
        odr_bus::Link::Wiegand(_)
    ));
    // And the door still opens: the panel was enrolled through the reader's own
    // encoder, which is the only thing a legacy panel can match on.
    let mut b = scenario::build_with(ScenarioId::WiegandDoor, SEED, &cd).unwrap();
    assert!(matches!(
        b.world.link(b.link).unwrap(),
        odr_bus::Link::ClockData(_)
    ));
    b.run_script().unwrap();
    assert_eq!(b.world.door(b.door).unwrap().strike_count, 1);
}

#[test]
fn the_credential_format_changes_the_bits_on_the_wire() {
    fn wire_width(scenario: ScenarioId, opts: &BenchOptions) -> (usize, u32) {
        let mut b = scenario::build_with(scenario, SEED, opts).unwrap();
        b.run_script().unwrap();
        let bits = b
            .world
            .log()
            .records()
            .iter()
            .find_map(|r| match &r.kind {
                odr_bus::RecordKind::WireTx { bits, .. } => Some(bits.len()),
                _ => None,
            })
            .expect("a reader drove the wire");
        (bits, b.world.door(b.door).unwrap().strike_count)
    }

    assert_eq!(
        wire_width(ScenarioId::WiegandDoor, &BenchOptions::default()),
        (26, 1)
    );
    let mut wide = BenchOptions::default();
    options::apply(
        ScenarioId::WiegandDoor,
        &mut wide,
        options::FORMAT,
        "h10302",
    )
    .unwrap();
    assert_eq!(
        wire_width(ScenarioId::WiegandDoor, &wide),
        (37, 1),
        "a 37-bit credential goes on the wire, and still opens a door enrolled for one"
    );
}

#[test]
fn the_strike_time_changes_how_long_the_door_stays_open() {
    let mut opts = BenchOptions::default();
    options::apply(
        ScenarioId::WiegandDoor,
        &mut opts,
        options::STRIKE_MS,
        "8000",
    )
    .unwrap();
    let b = scenario::build_with(ScenarioId::WiegandDoor, SEED, &opts).unwrap();
    assert_eq!(b.world.door(b.door).unwrap().strike_time_us, 8_000_000);
}

// ===========================================================================
// 3. Refusal, with a reason
// ===========================================================================

#[test]
fn secure_channel_is_refused_on_a_wiegand_pair_and_says_why() {
    let mut opts = BenchOptions::default();
    let err = options::apply(
        ScenarioId::WiegandDoor,
        &mut opts,
        options::SECURE_CHANNEL,
        "required",
    )
    .expect_err("a Wiegand pair has no secure channel");
    let text = format!("{err}");
    assert!(text.contains("Wiegand"), "{text}");
    assert!(text.contains("cryptography"), "{text}");
    assert_eq!(opts, BenchOptions::default(), "a refusal changes nothing");
}

#[test]
fn a_wire_protocol_is_refused_on_a_bus() {
    let mut opts = BenchOptions::default();
    let err = options::apply(ScenarioId::OsdpClear, &mut opts, options::LINK, "wiegand")
        .expect_err("an RS-485 bus is not a two-wire pair");
    assert!(format!("{err}").contains("RS-485"));
}

#[test]
fn a_value_outside_the_declared_set_is_refused_and_lists_the_legal_ones() {
    let mut opts = BenchOptions::default();
    let err = options::apply(
        ScenarioId::OsdpClear,
        &mut opts,
        options::SECURE_CHANNEL,
        "maybe",
    )
    .expect_err("not a legal value");
    let text = format!("{err}");
    assert!(text.contains("off"), "{text}");
    assert!(text.contains("required"), "{text}");

    let err = options::apply(ScenarioId::OsdpClear, &mut opts, options::MAC_BYTES, "9")
        .expect_err("out of range");
    assert!(format!("{err}").contains("1 to 4"));
}

#[test]
fn the_two_scenarios_with_no_bench_accept_nothing() {
    for s in [ScenarioId::NoBench, ScenarioId::MonitoredDay] {
        assert!(options::accepted(s).is_empty(), "{}", s.name());
        assert!(options::describe(s, None, &BenchOptions::default()).is_empty());
        let mut opts = BenchOptions::default();
        assert!(options::apply(s, &mut opts, options::STRIKE_MS, "1000").is_err());
    }
}

// ===========================================================================
// The option list is data, and it differs per scenario
// ===========================================================================

#[test]
fn the_option_list_differs_by_scenario_and_is_never_empty_for_a_bench() {
    for s in benches() {
        let list = options::describe(s, None, &BenchOptions::default());
        assert!(!list.is_empty(), "{} offers nothing", s.name());
        for spec in &list {
            assert!(!spec.help.is_empty(), "{} {}", s.name(), spec.id);
            assert!(!spec.label.is_empty());
            // A choice must always report a current value that is in its list.
            if let OptionKind::Choice(choices) = &spec.kind {
                let v = spec.value.as_string();
                assert!(
                    choices.iter().any(|(c, _)| *c == v),
                    "{} {} = {v} is not one of its own choices",
                    s.name(),
                    spec.id
                );
            }
        }
    }
    let bus = options::describe(ScenarioId::OsdpClear, None, &BenchOptions::default());
    let pair = options::describe(ScenarioId::WiegandDoor, None, &BenchOptions::default());
    let card = options::describe(ScenarioId::CardMifare, None, &BenchOptions::default());
    assert!(bus.iter().any(|o| o.id == options::SECURE_CHANNEL));
    assert!(!pair.iter().any(|o| o.id == options::SECURE_CHANNEL));
    assert!(pair.iter().any(|o| o.id == options::LINK));
    assert!(!bus.iter().any(|o| o.id == options::LINK));
    assert!(!card.iter().any(|o| o.id == options::FORMAT));
}

#[test]
fn free_play_warns_about_nothing_and_a_drill_warns_about_the_premise() {
    let mut off = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpDefaultKey,
        &mut off,
        options::SECURE_CHANNEL,
        "off",
    )
    .unwrap();

    let free = options::describe(ScenarioId::OsdpDefaultKey, None, &off);
    assert!(free.iter().all(|o| o.warning.is_none()));

    let under_drill = options::describe(ScenarioId::OsdpDefaultKey, Some(DrillId::new(3, 2)), &off);
    let sc = under_drill
        .iter()
        .find(|o| o.id == options::SECURE_CHANNEL)
        .expect("the option is still offered");
    let warning = sc
        .warning
        .as_ref()
        .expect("a drill warns about its premise");
    assert!(warning.contains("cannot be earned"), "{warning}");
    assert!(sc.changed, "an overridden option says it was changed");
}

#[test]
fn a_setting_that_breaks_a_drill_is_still_applied() {
    // docs/UI.md: warn rather than block. The bench builds, the flag simply is
    // not earned, and the interface says so beside the control.
    let mut off = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpDefaultKey,
        &mut off,
        options::SECURE_CHANNEL,
        "off",
    )
    .unwrap();
    let out = run::solve_with(DrillId::new(3, 2), SEED, &off).expect("the bench still builds");
    assert!(!out.flag(None).unwrap().earned);
}

// ===========================================================================
// 4. Determinism
// ===========================================================================

#[test]
fn the_same_options_and_seed_give_the_same_bytes_on_a_rebuild() {
    let mut opts = BenchOptions::default();
    for (id, value) in [
        (options::SECURE_CHANNEL, "required"),
        (options::KEY, "site"),
        (options::MAC_BYTES, "2"),
        (options::NULL_CIPHER, "true"),
        (options::BAUD, "19200"),
        (options::POLL_MS, "250"),
        (options::PD_INSTALL, "true"),
        (options::FORMAT, "h10306"),
    ] {
        options::apply(ScenarioId::OsdpClear, &mut opts, id, value).unwrap();
    }
    let a = capture(ScenarioId::OsdpClear, &opts);
    let b = capture(ScenarioId::OsdpClear, &opts);
    assert_eq!(a, b);
    // And a different option really is a different bench.
    let mut other = opts.clone();
    options::apply(ScenarioId::OsdpClear, &mut other, options::BAUD, "38400").unwrap();
    assert_ne!(a, capture(ScenarioId::OsdpClear, &other));
}

#[test]
fn resolving_is_order_independent_and_idempotent() {
    let mut a = BenchOptions::default();
    options::apply(ScenarioId::OsdpClear, &mut a, options::KEY, "weak").unwrap();
    options::apply(
        ScenarioId::OsdpClear,
        &mut a,
        options::SECURE_CHANNEL,
        "required",
    )
    .unwrap();
    let mut b = BenchOptions::default();
    options::apply(
        ScenarioId::OsdpClear,
        &mut b,
        options::SECURE_CHANNEL,
        "required",
    )
    .unwrap();
    options::apply(ScenarioId::OsdpClear, &mut b, options::KEY, "weak").unwrap();
    assert_eq!(a, b);
    assert_eq!(
        a.resolve(ScenarioId::OsdpClear),
        b.resolve(ScenarioId::OsdpClear)
    );
    assert_eq!(a.resolve(ScenarioId::OsdpClear).key, KeyChoice::Weak);
    assert_eq!(
        options::defaults(ScenarioId::ClockDataDoor).link,
        LinkChoice::ClockData
    );
}
