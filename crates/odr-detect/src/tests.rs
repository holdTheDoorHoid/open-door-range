//! The suite that says whether the defensive half is honest.
//!
//! It is organised around one question per test, and the questions come in
//! pairs: *does this rule catch the attack* and *does this rule stay quiet on
//! the benign traffic that looks like it*. The second half of every pair is the
//! half that matters. A rule set that catches everything and alerts on
//! everything has answered none of `docs/CURRICULUM.md` Module 5.
//!
//! Three classes of test carry more weight than the rest:
//!
//! * **Provenance.** A scenario is run, its capture is exported, the world is
//!   dropped, and the detectors are run against the re-imported file. If a
//!   detector could only work with the world alive, these fail.
//! * **False positives.** Each detector against the benign case named in its
//!   own rustdoc.
//! * **Admissions of blindness.** Where an attack is genuinely invisible, a
//!   test asserts the silence, so that a later "improvement" that starts firing
//!   has to argue with a test rather than slip through.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_bus::capture::{export_from_tap, CaptureOptions};
use odr_bus::{
    osdp_bench, AccessList, AcuConfig, InlineTap, OsdpBenchSpec, PassiveTap, PdConfig,
    Presentation, Rs485Timing, ScRequirement, SourceId, TapId, World,
};
use odr_osdp::payload::{KeysetCommand, PdCapabilities};
use odr_osdp::{Command, Frame, Reply, SCBK_D};
use odr_wiegand::{CardFormat, Credential};

use crate::rules::{unsolicited_replies, DEFAULT_GAP_US};
use crate::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn card(fc: u64, cn: u64) -> Credential {
    Credential::new(CardFormat::H10301, fc, cn)
}

fn access_for(cards: &[&Credential]) -> AccessList {
    let mut list = AccessList::new();
    for c in cards {
        list = list.with_credential(c).expect("credential encodes");
    }
    list.assuming(CardFormat::H10301)
}

/// A bench with one peripheral and a defender's monitor on the controller end.
struct Bench {
    world: World,
    pd: odr_bus::ReaderId,
    link: odr_bus::LinkId,
    monitor: TapId,
}

fn bench(seed: u64, acu: AcuConfig, pd: PdConfig, access: AccessList) -> Bench {
    bench_with(seed, acu, alloc::vec![pd], access, None)
}

fn bench_with(
    seed: u64,
    acu: AcuConfig,
    pds: Vec<PdConfig>,
    access: AccessList,
    inline: Option<InlineTap>,
) -> Bench {
    let b = osdp_bench(
        seed,
        OsdpBenchSpec {
            acu,
            pds,
            timing: Rs485Timing::default(),
            access,
            start_polling_at_us: 0,
        },
    )
    .expect("bench builds");
    let mut world = b.world;
    if let Some(tap) = inline {
        world.add_tap(b.link, Box::new(tap)).expect("inline tap");
    }
    let monitor = world
        .add_tap(b.link, Box::new(PassiveTap::new("monitor")))
        .expect("monitor");
    Bench {
        world,
        pd: b.pds[0],
        link: b.link,
        monitor,
    }
}

fn present(world: &mut World, reader: odr_bus::ReaderId, at_us: u64, source: u32, c: &Credential) {
    let p = Presentation::from_credential(SourceId(source), c).expect("encodes");
    world.present(reader, at_us, p).expect("presented");
}

/// **The provenance step.** Everything after this call has only the file.
fn capture_of(world: &World, tap: TapId) -> String {
    export_from_tap(world.tap(tap).expect("tap"), &CaptureOptions::default())
}

fn monitor_of(world: &World, tap: TapId) -> Monitor {
    Monitor::from_capture(&capture_of(world, tap)).expect("capture parses")
}

/// A secured peripheral with a site key that is not weak.
fn secure_pd(address: u8) -> PdConfig {
    PdConfig::at(address).with_site_key(scenario::SITE_KEY, ScRequirement::Required)
}

fn secure_acu(addresses: &[u8]) -> AcuConfig {
    AcuConfig::polling(addresses.iter().copied())
        .with_site_key(scenario::SITE_KEY, ScRequirement::Required)
}

/// The downgrade implant, four lines of policy.
fn downgrade_implant() -> InlineTap {
    InlineTap::rewrite_frames("downgrade", |frame: &mut Frame| {
        if frame.reply_code() != Some(Reply::PdCap) {
            return false;
        }
        match PdCapabilities::decode(&frame.payload) {
            Ok(mut caps) => {
                let changed = caps.strip_security_capability();
                frame.payload = caps.encode();
                changed
            }
            Err(_) => false,
        }
    })
}

/// Run one detector over one monitor.
fn run_one(detector: &dyn Detector, monitor: &Monitor) -> Vec<Finding> {
    detector.run(monitor)
}

fn fired(findings: &[Finding], signal: Signal) -> bool {
    findings.iter().any(|f| f.what == signal)
}

// ---------------------------------------------------------------------------
// The governing rule: a detector sees a capture and nothing else
// ---------------------------------------------------------------------------

#[test]
fn a_detector_works_from_a_capture_with_the_world_thrown_away() {
    let c = card(42, 1337);
    let capture = {
        let mut b = bench(
            1,
            AcuConfig::polling([0x01]),
            PdConfig::at(0x01),
            access_for(&[&c]),
        );
        present(&mut b.world, b.pd, 3_000_000, 0, &c);
        b.world.run_until(10_000_000).expect("runs");
        capture_of(&b.world, b.monitor)
        // The world is dropped here. Everything below has a string.
    };

    let monitor = Monitor::from_capture(&capture).expect("parses");
    let report = RuleSet::standard().run(&monitor);
    assert!(report.fired(Signal::CleartextBus));
    assert!(report.evidence_checks(&monitor));
    // And the conclusions survive a second round trip through the format.
    let again = Monitor::from_capture(&monitor.to_capture()).expect("parses");
    assert_eq!(RuleSet::standard().run(&again), report);
}

#[test]
fn a_monitor_from_a_tap_carries_exactly_what_the_capture_carries() {
    // `Monitor::from_tap` is a convenience, not a back door: it must produce
    // the same observations as parsing that tap's exported capture, which is
    // the structural proof that it drops the world's `Origin`.
    let c = card(42, 1337);
    let mut b = bench(
        2,
        AcuConfig::polling([0x01]),
        PdConfig::at(0x01),
        access_for(&[&c]),
    );
    present(&mut b.world, b.pd, 3_000_000, 0, &c);
    b.world.run_until(10_000_000).expect("runs");

    let from_tap = Monitor::from_tap(b.world.tap(b.monitor).expect("tap"));
    let from_file = monitor_of(&b.world, b.monitor);
    assert_eq!(from_tap, from_file);
    assert!(!from_tap.is_empty());
}

#[test]
fn an_injected_frame_is_not_labelled_as_injected_anywhere_in_a_monitor() {
    // The world knows an injecting tap drove this frame. The file does not, and
    // neither does the monitor built from either.
    let c = card(42, 900);
    let mut b = bench(
        3,
        AcuConfig::polling([0x01]),
        PdConfig::at(0x01),
        access_for(&[&c]),
    );
    let link = b.link;
    let attacker = b
        .world
        .add_tap(
            link,
            Box::new(odr_bus::InjectingTap::new("attacker").with_injection(
                odr_bus::Injection::bus_frame(
                    5_050_000,
                    odr_bus::BusDir::PdToAcu,
                    Frame::reply(0x01, 1, Reply::Ack, Vec::new()),
                ),
            )),
        )
        .expect("attacker");
    b.world.run_until(10_000_000).expect("runs");
    assert!(b.world.log().injection_count(attacker) > 0, "it did inject");

    let monitor = monitor_of(&b.world, b.monitor);
    // Nothing in an observation says who transmitted. The only way to reach
    // that conclusion is to infer it from the conversation.
    assert!(monitor
        .observations()
        .iter()
        .all(|o| o.summary().find("tap").is_none()));
}

// ---------------------------------------------------------------------------
// Posture — cleartext bus
// ---------------------------------------------------------------------------

#[test]
fn a_cleartext_bus_is_reported_as_a_posture_with_certainty() {
    let mut b = bench(
        10,
        AcuConfig::polling([0x01]),
        PdConfig::at(0x01),
        AccessList::new(),
    );
    b.world.run_until(10_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let found = run_one(&PostureDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::CleartextBus)
        .expect("a cleartext bus is visible");
    assert_eq!(f.confidence, Confidence::Certain);
    assert_eq!(f.severity, Severity::High);
    assert!(f.evidence.check(&monitor));
    assert!(f.evidence.note.contains("Nothing here is an attack"));
}

#[test]
fn a_secured_bus_is_not_reported_as_cleartext() {
    let mut b = bench(11, secure_acu(&[0x01]), secure_pd(0x01), AccessList::new());
    b.world.run_until(10_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);
    assert!(!fired(
        &run_one(&PostureDetector::default(), &monitor),
        Signal::CleartextBus
    ));
}

#[test]
fn one_legacy_reader_does_not_condemn_the_secured_bus_around_it() {
    // Curriculum 5.2's other half at the posture layer: the finding must name
    // the one exposed peripheral, not the link.
    let mut legacy = PdConfig::at(0x02);
    legacy.capabilities = odr_bus::default_capabilities(false, false);
    legacy.sc = ScRequirement::Disabled;
    let mut b = bench_with(
        12,
        secure_acu(&[0x01, 0x02]),
        alloc::vec![secure_pd(0x01), legacy],
        AccessList::new(),
        None,
    );
    b.world.run_until(15_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let found = run_one(&PostureDetector::default(), &monitor);
    let cleartext: Vec<&Finding> = found
        .iter()
        .filter(|f| f.what == Signal::CleartextBus)
        .collect();
    assert_eq!(cleartext.len(), 1, "exactly one peripheral is exposed");
    assert!(cleartext[0].evidence.note.contains("address 0x02"));
    assert!(!cleartext[0].evidence.note.contains("address 0x01"));
}

#[test]
fn the_door_command_in_the_clear_is_a_finding_of_its_own() {
    let c = card(42, 55);
    let mut b = bench(
        13,
        AcuConfig::polling([0x01]),
        PdConfig::at(0x01),
        access_for(&[&c]),
    );
    present(&mut b.world, b.pd, 3_000_000, 0, &c);
    b.world.run_until(10_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let found = run_one(&PostureDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::SensitiveCommandInClear)
        .expect("CMD_OUT crossed the bus unprotected");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.evidence.note.contains("CMD_OUT"));
}

// ---------------------------------------------------------------------------
// Keys — the default key and the null ciphers
// ---------------------------------------------------------------------------

#[test]
fn the_default_key_announces_itself_in_the_handshake() {
    let mut b = bench(
        20,
        AcuConfig::polling([0x01]).with_default_key(ScRequirement::Required),
        PdConfig::at(0x01).with_default_key(ScRequirement::Required),
        AccessList::new(),
    );
    b.world.run_until(8_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let found = run_one(&KeyDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::DefaultKeyInUse)
        .expect("SCBK-D is visible");
    assert_eq!(f.confidence, Confidence::Certain);
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.evidence.note.contains("SCBK-D"));
}

#[test]
fn a_site_key_is_not_reported_as_the_default_one() {
    let mut b = bench(21, secure_acu(&[0x01]), secure_pd(0x01), AccessList::new());
    b.world.run_until(8_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);
    assert!(!fired(
        &run_one(&KeyDetector::default(), &monitor),
        Signal::DefaultKeyInUse
    ));
}

#[test]
fn an_ordinary_encrypted_bus_is_not_reported_as_a_null_cipher() {
    // The false positive that would have made this rule useless: an empty
    // payload legitimately rides in the MAC-only block even when encryption was
    // requested, so every POLL on every encrypted bus carries an SCS_15.
    let mut b = bench(22, secure_acu(&[0x01]), secure_pd(0x01), AccessList::new());
    b.world.run_until(15_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let mac_only = monitor
        .bus()
        .filter(|o| o.scs().is_some_and(|s| s.has_mac() && !s.is_encrypted()))
        .count();
    assert!(mac_only > 0, "the bus really is full of SCS_15 frames");
    assert!(
        !fired(
            &run_one(&KeyDetector::default(), &monitor),
            Signal::NullCipher
        ),
        "and none of them carries anything"
    );
}

#[test]
fn the_null_ciphers_are_visible_once_a_payload_rides_in_one() {
    let c = card(42, 77);
    let mut acu = secure_acu(&[0x01]);
    acu.encrypt_payloads = false;
    let mut b = bench(23, acu, secure_pd(0x01), access_for(&[&c]));
    b.world.run_until(2_000_000).expect("runs");
    present(&mut b.world, b.pd, 4_000_000, 0, &c);
    b.world.run_until(12_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let found = run_one(&KeyDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::NullCipher)
        .expect("SCS_15 with a payload");
    assert!(f.evidence.note.contains("SCS_15"));
    assert!(f.evidence.check(&monitor));
}

// ---------------------------------------------------------------------------
// Keyset — drill 5.3
// ---------------------------------------------------------------------------

#[test]
fn a_keyset_is_seen_and_its_authorisation_is_not() {
    let acu = AcuConfig::polling([0x01])
        .with_site_key(scenario::SITE_KEY, ScRequirement::IfAvailable)
        .in_install_mode(true);
    let pd = PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable);
    let mut b = bench(30, acu, pd, AccessList::new());
    b.world.run_until(10_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let found = run_one(&KeysetDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::KeysetObserved)
        .expect("a CMD_KEYSET crossed the bus");
    assert_eq!(
        f.confidence,
        Confidence::Ambiguous,
        "the event is certain and the authorisation is not"
    );
    assert!(f.severity >= Severity::High);
    assert!(f.evidence.note.contains("whether it was authorised"));
}

#[test]
fn a_keyset_sent_with_no_security_block_hands_over_the_key() {
    // Hand-built, because the engine's install-mode flow always wraps the
    // keyset in a channel — and a monitor should still be able to read the
    // unwrapped case, which is what a lazy commissioning tool produces.
    let key = [
        0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0,
        0x01,
    ];
    let frame = Frame::command(0x01, 2, Command::Keyset, KeysetCommand::scbk(key).encode());
    let line = alloc::format!(
        "{{\"t_us\":1000,\"line\":\"rs485\",\"dir\":\"acu_to_pd\",\"bytes\":\"{}\"}}",
        odr_bus::capture::to_hex(&frame.encode())
    );
    let monitor = Monitor::from_capture(&line).expect("parses");

    let found = run_one(&KeysetDetector::default(), &monitor);
    let f = &found[0];
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.confidence, Confidence::Ambiguous);
    assert!(
        f.evidence.note.contains("112233445566"),
        "the key itself is recoverable and the finding says so: {}",
        f.evidence.note
    );
}

#[test]
fn a_bus_with_no_keyset_on_it_reports_none() {
    let mut b = bench(31, secure_acu(&[0x01]), secure_pd(0x01), AccessList::new());
    b.world.run_until(10_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);
    assert!(run_one(&KeysetDetector::default(), &monitor).is_empty());
}

// ---------------------------------------------------------------------------
// Downgrade — drill 5.2
// ---------------------------------------------------------------------------

/// A capture in which address 1 first behaves normally and then is downgraded.
///
/// Two worlds and a gap, because that is what a monitor actually sees: an
/// implant is clipped in at some point, and the link is quiet while it happens.
fn downgraded_after_history(seed: u64) -> Monitor {
    let c = card(42, 4001);
    let mut before = bench(
        seed,
        secure_acu(&[0x01]),
        secure_pd(0x01),
        access_for(&[&c]),
    );
    before.world.run_until(12_000_000).expect("runs");

    let mut after = bench_with(
        seed + 1,
        secure_acu(&[0x01]),
        alloc::vec![secure_pd(0x01)],
        access_for(&[&c]),
        Some(downgrade_implant()),
    );
    after.world.run_until(3_000_000).expect("runs");
    present(&mut after.world, after.pd, 5_000_000, 0, &c);
    after.world.run_until(20_000_000).expect("runs");

    let mut events =
        odr_bus::capture::parse_ndjson(&capture_of(&before.world, before.monitor)).expect("parses");
    for mut e in
        odr_bus::capture::parse_ndjson(&capture_of(&after.world, after.monitor)).expect("parses")
    {
        e.t_us += 12_000_000 + DEFAULT_GAP_US * 2;
        events.push(e);
    }
    Monitor::from_events(events)
}

#[test]
fn a_downgrade_at_an_address_with_history_is_caught() {
    let monitor = downgraded_after_history(40);
    let found = run_one(&DowngradeDetector::default(), &monitor);

    let f = found
        .iter()
        .find(|f| f.what == Signal::CapabilityDowngrade)
        .expect("the capability claim changed");
    assert_eq!(f.confidence, Confidence::Probable);
    assert_eq!(
        f.severity,
        Severity::Critical,
        "it had been used, not just claimed"
    );
    assert_eq!(f.evidence.refs.len(), 2, "both replies are cited");
    assert!(f.evidence.check(&monitor));
    assert!(f
        .evidence
        .note
        .contains("reader replacement does not explain it"));

    assert!(
        fired(&found, Signal::SecureChannelLost),
        "and the effect is visible independently of the mechanism"
    );
}

#[test]
fn a_legacy_reader_added_to_the_bus_is_not_a_downgrade() {
    // **Drill 5.2, stated as an assertion.**
    let mut legacy = PdConfig::at(0x02);
    legacy.capabilities = odr_bus::default_capabilities(false, false);
    legacy.sc = ScRequirement::Disabled;
    let mut b = bench_with(
        41,
        secure_acu(&[0x01, 0x02]),
        alloc::vec![secure_pd(0x01), legacy],
        AccessList::new(),
        None,
    );
    b.world.run_until(20_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let found = run_one(&DowngradeDetector::default(), &monitor);
    assert!(
        !fired(&found, Signal::CapabilityDowngrade),
        "0x02 never claimed AES-128, so it has not stopped claiming it"
    );
    assert!(!fired(&found, Signal::SecureChannelLost));
    // And the reader really is the legacy one the drill describes.
    let caps = monitor
        .for_address(0x02)
        .find(|o| o.reply() == Some(Reply::PdCap))
        .and_then(|o| o.frame.as_ref())
        .and_then(|f| PdCapabilities::decode(&f.payload).ok())
        .expect("a capability reply");
    assert!(!caps.claims_aes128());
}

#[test]
fn a_reader_replaced_at_the_same_address_is_a_swap_and_not_an_attack() {
    let day = generate_day(
        9001,
        &DayOptions {
            episodes: alloc::vec![Episode::ReaderReplaced],
            ..DayOptions::default()
        },
    )
    .expect("day");
    let monitor = day.monitor().expect("monitor");

    let found = run_one(&DowngradeDetector::default(), &monitor);
    assert!(
        fired(&found, Signal::DeviceIdentityChanged),
        "the identity change is the observable"
    );
    assert!(
        !fired(&found, Signal::CapabilityDowngrade),
        "and it is the reason not to call the capability drop an attack"
    );
    assert!(!fired(&found, Signal::SecureChannelLost));
}

#[test]
fn the_strict_variant_catches_the_identity_spoofing_downgrade_and_pays_for_it() {
    // The honest version of the trade-off: turning off the identity check
    // catches an attacker who rewrites REPLY_PDID too, and alerts on every
    // reader replacement. Both halves are asserted, because a learner should
    // see the price rather than be told about it.
    let day = generate_day(
        9002,
        &DayOptions {
            episodes: alloc::vec![Episode::ReaderReplaced],
            ..DayOptions::default()
        },
    )
    .expect("day");
    let monitor = day.monitor().expect("monitor");

    assert!(fired(
        &run_one(&DowngradeDetector::strict(), &monitor),
        Signal::CapabilityDowngrade
    ));
    assert!(!fired(
        &run_one(&DowngradeDetector::default(), &monitor),
        Signal::CapabilityDowngrade
    ));
}

#[test]
fn a_reader_power_cycling_has_not_lost_its_secure_channel() {
    let mut b = bench(42, secure_acu(&[0x01]), secure_pd(0x01), AccessList::new());
    b.world.run_until(5_000_000).expect("runs");
    b.world.reader_mut(b.pd).expect("pd").reset_protocol();
    b.world.run_until(25_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    // It really did come back up, so there is something to be quiet about.
    assert!(
        monitor
            .for_address(0x01)
            .filter(|o| o.is_handshake())
            .count()
            >= 4
    );
    let found = run_one(&DowngradeDetector::default(), &monitor);
    assert!(!fired(&found, Signal::SecureChannelLost));
    assert!(!fired(&found, Signal::CapabilityDowngrade));
    assert!(!fired(&found, Signal::DeviceIdentityChanged));
}

// ---------------------------------------------------------------------------
// Injection
// ---------------------------------------------------------------------------

#[test]
fn two_devices_answering_one_address_is_caught() {
    let day = generate_day(
        9003,
        &DayOptions {
            episodes: alloc::vec![Episode::ForgedReply],
            ..DayOptions::default()
        },
    )
    .expect("day");
    let monitor = day.monitor().expect("monitor");

    let found = run_one(&InjectionDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::DuplicateAddress)
        .expect("one poll drew two different replies");
    assert_eq!(f.confidence, Confidence::Probable);
    assert_eq!(f.evidence.refs.len(), 3, "the poll and both answers");
    assert!(f.evidence.check(&monitor));
}

#[test]
fn a_power_cycle_resync_is_not_a_sequence_attack() {
    let mut b = bench(50, secure_acu(&[0x01]), secure_pd(0x01), AccessList::new());
    b.world.run_until(5_000_000).expect("runs");
    b.world.reader_mut(b.pd).expect("pd").reset_protocol();
    b.world.run_until(25_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);
    assert!(run_one(&InjectionDetector::default(), &monitor).is_empty());
}

#[test]
fn a_healthy_polling_loop_produces_no_injection_findings() {
    let mut b = bench(
        51,
        AcuConfig::polling([0x01]),
        PdConfig::at(0x01),
        AccessList::new(),
    );
    b.world.run_until(30_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);
    assert!(run_one(&InjectionDetector::default(), &monitor).is_empty());
}

#[test]
fn a_well_formed_frame_in_the_gap_is_not_detectable_and_the_suite_says_so() {
    // **An admission, pinned by a test.** A capture is built in which one poll
    // was written by the "attacker" and the rest by the "controller". The
    // conversation is consistent, so nothing here can separate them — and
    // nothing here pretends to.
    let mut lines = String::new();
    let mut t = 1_000_000u64;
    let mut seq = 1u8;
    for i in 0..12 {
        let cmd = Frame::command(0x01, seq, Command::Poll, Vec::new());
        let ack = Frame::reply(0x01, seq, Reply::Ack, Vec::new());
        // Frame 6 is the forged one. It differs from its neighbours in nothing
        // a monitor can reach: same address, the sequence the link expected,
        // arriving in the gap where the next poll was due.
        let _forged = i == 6;
        lines.push_str(&alloc::format!(
            "{{\"t_us\":{},\"line\":\"rs485\",\"dir\":\"acu_to_pd\",\"bytes\":\"{}\"}}\n",
            t,
            odr_bus::capture::to_hex(&cmd.encode())
        ));
        lines.push_str(&alloc::format!(
            "{{\"t_us\":{},\"line\":\"rs485\",\"dir\":\"pd_to_acu\",\"bytes\":\"{}\"}}\n",
            t + 12_000,
            odr_bus::capture::to_hex(&ack.encode())
        ));
        t += 100_000;
        seq = if seq == 3 { 1 } else { seq + 1 };
    }
    let monitor = Monitor::from_capture(&lines).expect("parses");
    assert!(
        run_one(&InjectionDetector::default(), &monitor).is_empty(),
        "a forged frame that fits the cadence and the sequence is indistinguishable, and the \
         honest answer is silence rather than a rule that fires on ordinary traffic"
    );
    assert!(run_one(&ReplayDetector::default(), &monitor).is_empty());
    // What *is* reported is the reason the forgery was free in the first place.
    let report = RuleSet::standard().run(&monitor);
    assert_eq!(report.len(), 1);
    assert_eq!(report.findings()[0].what, Signal::CleartextBus);
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

#[test]
fn a_played_back_card_read_is_caught() {
    let day = generate_day(
        9004,
        &DayOptions {
            episodes: alloc::vec![Episode::BusReplay],
            ..DayOptions::default()
        },
    )
    .expect("day");
    let monitor = day.monitor().expect("monitor");

    let found = run_one(&ReplayDetector::default(), &monitor);
    let frame = found
        .iter()
        .find(|f| f.what == Signal::ReplayedFrame)
        .expect("a byte-identical reply nothing asked for");
    assert_eq!(frame.confidence, Confidence::Probable);
    assert!(frame.evidence.note.contains("two bits"));
    assert!(fired(&found, Signal::ReplayedCredential));
    assert!(found.iter().all(|f| f.evidence.check(&monitor)));
}

#[test]
fn a_person_badging_twice_on_a_cleartext_bus_is_not_a_replay() {
    // **The false positive that matters.** Two genuine reads of one card four
    // seconds apart, on a bus where the payload is legible.
    let c = card(42, 2001);
    let mut b = bench(
        60,
        AcuConfig::polling([0x01]),
        PdConfig::at(0x01),
        access_for(&[&c]),
    );
    present(&mut b.world, b.pd, 3_000_000, 0, &c);
    present(&mut b.world, b.pd, 7_000_000, 0, &c);
    b.world.run_until(15_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let reads: Vec<&Observation> = monitor
        .bus()
        .filter(|o| o.reply() == Some(Reply::Raw))
        .collect();
    assert_eq!(reads.len(), 2, "two genuine card reads");
    let found = run_one(&ReplayDetector::default(), &monitor);
    assert!(!fired(&found, Signal::ReplayedCredential));
    assert!(!fired(&found, Signal::ReplayedFrame));
}

#[test]
fn two_bits_of_sequence_make_byte_identical_frames_worthless_on_their_own() {
    // The lesson that shaped this detector, asserted directly: a genuine repeat
    // can be byte-for-byte identical, so "identical" cannot be the rule.
    let c = card(42, 2002);
    let mut b = bench(
        61,
        AcuConfig::polling([0x01]),
        PdConfig::at(0x01),
        access_for(&[&c]),
    );
    // Four presentations walk the whole two-bit cycle, so at least two of the
    // resulting frames must collide.
    for i in 0..4u64 {
        present(&mut b.world, b.pd, 3_000_000 + i * 2_000_000, 0, &c);
    }
    b.world.run_until(20_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    let reads: Vec<&Observation> = monitor
        .bus()
        .filter(|o| o.reply() == Some(Reply::Raw))
        .collect();
    let identical_pair = reads
        .iter()
        .enumerate()
        .any(|(i, a)| reads[..i].iter().any(|b| a.bytes == b.bytes));
    assert!(
        identical_pair,
        "two genuine reads of one card collided on the sequence number"
    );
    assert!(
        !fired(
            &run_one(&ReplayDetector::default(), &monitor),
            Signal::ReplayedFrame
        ),
        "and the detector is not fooled, because each of them answered its own poll"
    );
    // Which is what `unsolicited_replies` is for.
    assert!(reads
        .iter()
        .all(|o| !unsolicited_replies(&monitor)[o.index]));
}

#[test]
fn a_wiegand_replay_is_only_possible_and_the_finding_says_why() {
    let day = generate_day(
        9005,
        &DayOptions {
            episodes: alloc::vec![Episode::WiegandDoor],
            ..DayOptions::default()
        },
    )
    .expect("day");
    let monitor = day.monitor().expect("monitor");

    let found = run_one(&ReplayDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::ReplayedCredential)
        .expect("a fast repeat on the wire");
    assert_eq!(
        f.confidence,
        Confidence::Possible,
        "on a D0/D1 pair there is nothing but the interval to go on"
    );
    assert!(f.evidence.note.contains("not detectable here"));
    assert_eq!(
        found.len(),
        1,
        "and the person badging twice four seconds later is not reported"
    );
}

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

#[test]
fn a_two_wire_link_is_reported_as_unauthenticated() {
    let day = generate_day(
        9006,
        &DayOptions {
            episodes: alloc::vec![Episode::WiegandDoor],
            ..DayOptions::default()
        },
    )
    .expect("day");
    let monitor = day.monitor().expect("monitor");

    let found = run_one(&WireDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::UnauthenticatedWire)
        .expect("the link itself is the finding");
    assert_eq!(f.confidence, Confidence::Certain);
    assert!(f.evidence.note.contains("cannot tell the reader"));
    assert!(!fired(&found, Signal::MalformedCredential));
}

#[test]
fn bits_that_fit_no_known_format_are_reported_as_malformed() {
    let line = "{\"t_us\":5000,\"line\":\"wiegand\",\"dir\":\"wire\",\"bytes\":\"ffffffff\"}";
    let monitor = Monitor::from_capture(line).expect("parses");
    let found = run_one(&WireDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::MalformedCredential)
        .expect("all-ones fails parity in every format we know");
    assert_eq!(f.confidence, Confidence::Possible);
    assert!(f.evidence.note.contains("clumsy implant"));
}

#[test]
fn a_bus_only_capture_produces_no_wire_findings() {
    let mut b = bench(
        70,
        AcuConfig::polling([0x01]),
        PdConfig::at(0x01),
        AccessList::new(),
    );
    b.world.run_until(10_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);
    assert!(run_one(&WireDetector::default(), &monitor).is_empty());
}

// ---------------------------------------------------------------------------
// Traffic analysis — the defensive half of drill 4.1
// ---------------------------------------------------------------------------

#[test]
fn the_badge_in_schedule_is_readable_straight_through_the_encryption() {
    let cards = [card(42, 1001), card(42, 1002), card(42, 1003)];
    let refs: Vec<&Credential> = cards.iter().collect();
    let mut b = bench(80, secure_acu(&[0x01]), secure_pd(0x01), access_for(&refs));
    b.world.run_until(2_000_000).expect("runs");
    for (i, c) in cards.iter().enumerate() {
        present(
            &mut b.world,
            b.pd,
            3_000_000 + i as u64 * 3_000_000,
            i as u32,
            c,
        );
    }
    b.world.run_until(15_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);

    // The credentials are not readable...
    assert!(
        credential_events(&monitor).is_empty(),
        "every card read went out encrypted"
    );
    // ...and the schedule is, exactly.
    let events = badge_events(&monitor);
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|e| e.encrypted && e.bit_count.is_none()));
    assert!(events[0].t_us < events[1].t_us && events[1].t_us < events[2].t_us);

    let found = run_one(&TrafficDetector::default(), &monitor);
    let f = found
        .iter()
        .find(|f| f.what == Signal::TrafficPatternExposed)
        .expect("three presentations is a pattern");
    assert_eq!(
        f.severity,
        Severity::Medium,
        "a surprise on an encrypted bus"
    );
    assert!(f.evidence.note.contains("outside the encrypted payload"));
}

#[test]
fn one_badge_in_is_not_a_pattern() {
    let c = card(42, 1);
    let mut b = bench(81, secure_acu(&[0x01]), secure_pd(0x01), access_for(&[&c]));
    b.world.run_until(2_000_000).expect("runs");
    present(&mut b.world, b.pd, 4_000_000, 0, &c);
    b.world.run_until(10_000_000).expect("runs");
    let monitor = monitor_of(&b.world, b.monitor);
    assert!(run_one(&TrafficDetector::default(), &monitor).is_empty());
}

// ---------------------------------------------------------------------------
// Findings and evidence
// ---------------------------------------------------------------------------

#[test]
fn every_finding_in_a_generated_day_cites_frames_that_check_out() {
    let day = generate_day(0x0D00_5EED, &DayOptions::default()).expect("day");
    let monitor = day.monitor().expect("monitor");
    let report = RuleSet::standard().run(&monitor);
    assert!(!report.is_empty());
    for f in report.findings() {
        assert!(
            f.evidence.check(&monitor),
            "{} cites frames that are not in the capture",
            f.what.name()
        );
        assert!(!f.evidence.note.is_empty(), "{}", f.what.name());
    }
}

#[test]
fn evidence_truncation_keeps_both_ends() {
    let mut lines = String::new();
    for i in 0..40u64 {
        lines.push_str(&alloc::format!(
            "{{\"t_us\":{},\"line\":\"wiegand\",\"dir\":\"wire\",\"bytes\":\"01020304\"}}\n",
            i * 1000
        ));
    }
    let monitor = Monitor::from_capture(&lines).expect("parses");
    let all: Vec<&Observation> = monitor.observations().iter().collect();
    let evidence = Evidence::new(all, "forty frames").truncate_evenly(5);
    assert_eq!(evidence.refs.len(), 5);
    assert_eq!(evidence.refs[0].index, 0);
    assert_eq!(evidence.refs[4].index, 39);
    assert!(evidence.check(&monitor));
}

#[test]
fn a_citation_stops_holding_if_it_is_pointed_at_a_different_capture() {
    let line_a = "{\"t_us\":1,\"line\":\"wiegand\",\"dir\":\"wire\",\"bytes\":\"01020304\"}";
    let line_b = "{\"t_us\":1,\"line\":\"wiegand\",\"dir\":\"wire\",\"bytes\":\"aabbccdd\"}";
    let a = Monitor::from_capture(line_a).expect("parses");
    let b = Monitor::from_capture(line_b).expect("parses");
    let evidence = Evidence::one(&a.observations()[0], "from a");
    assert!(evidence.check(&a));
    assert!(!evidence.check(&b));
}

#[test]
fn a_report_is_in_a_canonical_order_whatever_order_the_rules_ran_in() {
    let day = generate_day(7, &DayOptions::default()).expect("day");
    let monitor = day.monitor().expect("monitor");

    let forwards = RuleSet::empty("a")
        .with(Box::new(PostureDetector::default()))
        .with(Box::new(KeyDetector::default()))
        .with(Box::new(ReplayDetector::default()))
        .run(&monitor);
    let backwards = RuleSet::empty("b")
        .with(Box::new(ReplayDetector::default()))
        .with(Box::new(KeyDetector::default()))
        .with(Box::new(PostureDetector::default()))
        .run(&monitor);
    assert_eq!(forwards, backwards);
}

// ---------------------------------------------------------------------------
// Rule sets
// ---------------------------------------------------------------------------

#[test]
fn the_standard_rule_set_covers_every_signal_this_crate_defines() {
    let rules = RuleSet::standard();
    for signal in Signal::ALL {
        assert!(rules.covers(*signal), "nothing emits {}", signal.name());
    }
    assert_eq!(rules.signals().len(), Signal::ALL.len());
    assert!(rules.explain().contains("8 detectors"));
}

#[test]
fn an_empty_rule_set_finds_nothing_and_is_honest_about_its_coverage() {
    let day = generate_day(11, &DayOptions::default()).expect("day");
    let monitor = day.monitor().expect("monitor");
    let rules = RuleSet::empty("nothing");
    assert!(rules.is_empty());
    assert!(!rules.covers(Signal::CapabilityDowngrade));

    let score = day.key().score(&rules.run(&monitor));
    assert_eq!(score.recall_pct(), 0);
    assert_eq!(score.precision_pct(), 100, "it never cried wolf either");
    assert!(score.is_quiet_on_benign());
    assert_eq!(score.false_negatives().len(), day.key().scored_len());
}

// ---------------------------------------------------------------------------
// Scoring — drills 5.1 to 5.3
// ---------------------------------------------------------------------------

#[test]
fn the_standard_rule_set_scores_the_generated_day() {
    let day = generate_day(0x0D00_5EED, &DayOptions::default()).expect("day");
    let monitor = day.monitor().expect("monitor");
    let score = day.key().score(&RuleSet::standard().run(&monitor));

    assert!(
        score.is_quiet_on_benign(),
        "fired on benign traffic:\n{}",
        score.explain()
    );
    assert!(
        score.false_positives().is_empty(),
        "unexplained findings:\n{}",
        score.explain()
    );
    assert!(
        score.false_negatives().is_empty(),
        "missed:\n{}",
        score.explain()
    );
    assert_eq!(score.precision_pct(), 100);
    assert_eq!(score.recall_pct(), 100);
    assert_eq!(
        score.ambiguous().len(),
        2,
        "the commissioning and the reader swap are observed and undecidable"
    );
    // The number a defender actually cares about.
    assert!(score.worst_time_to_detect_us() < 30_000_000);
}

#[test]
fn a_rule_set_that_alerts_on_everything_scores_badly() {
    // The check on the scorer itself: without benign traffic in the key, this
    // rule set would look fine.
    struct Paranoid;
    impl Detector for Paranoid {
        fn name(&self) -> &str {
            "paranoid"
        }
        fn signals(&self) -> &'static [Signal] {
            &[Signal::ReplayedCredential]
        }
        fn rationale(&self) -> &'static str {
            "alerts on every credential it sees"
        }
        fn run(&self, monitor: &Monitor) -> Vec<Finding> {
            credential_events(monitor)
                .iter()
                .filter_map(|e| monitor.get(e.index))
                .map(|o| {
                    Finding::new(
                        o.t_us,
                        Severity::High,
                        Signal::ReplayedCredential,
                        Confidence::Possible,
                        Evidence::one(o, "a credential was seen, which is suspicious"),
                    )
                })
                .collect()
        }
    }

    let day = generate_day(0x0D00_5EED, &DayOptions::default()).expect("day");
    let monitor = day.monitor().expect("monitor");
    let score = day.key().score(
        &RuleSet::empty("paranoid")
            .with(Box::new(Paranoid))
            .run(&monitor),
    );

    assert!(score.precision_pct() < 40, "{}", score.explain());
    assert!(
        !score.is_quiet_on_benign(),
        "it fires on the person badging twice, which is the point"
    );
    assert!(score.false_positives().iter().any(|f| f
        .benign
        .as_deref()
        .is_some_and(|b| b.contains("badged twice"))));
}

#[test]
fn an_ambiguous_expectation_is_neither_right_nor_wrong() {
    let day = generate_day(
        12,
        &DayOptions {
            episodes: alloc::vec![Episode::Commissioning],
            ..DayOptions::default()
        },
    )
    .expect("day");
    let monitor = day.monitor().expect("monitor");
    let score = day.key().score(&RuleSet::standard().run(&monitor));

    assert_eq!(score.ambiguous().len(), 1);
    assert!(score.false_positives().is_empty());
    assert!(score
        .ambiguous()
        .iter()
        .all(|h| h.expected.verdict == Verdict::Ambiguous));
    // Not finding it is not punished either.
    let quiet = day.key().score(&RuleSet::empty("quiet").run(&monitor));
    assert!(quiet
        .false_negatives()
        .iter()
        .all(|e| e.signal != Signal::KeysetObserved));
}

#[test]
fn time_to_detection_is_measured_from_the_earliest_honest_moment() {
    let day = generate_day(13, &DayOptions::default()).expect("day");
    let monitor = day.monitor().expect("monitor");
    let score = day.key().score(&RuleSet::standard().run(&monitor));
    assert!(score.mean_time_to_detect_us() <= score.worst_time_to_detect_us());
    for hit in score.true_positives() {
        assert!(hit.finding.t_us >= hit.expected.t_us);
        assert_eq!(
            hit.latency_us,
            hit.finding.t_us - hit.expected.t_us,
            "{}",
            hit.expected.label
        );
    }
}

// ---------------------------------------------------------------------------
// The generated day itself
// ---------------------------------------------------------------------------

#[test]
fn the_same_seed_produces_a_byte_identical_day() {
    let a = generate_day(4242, &DayOptions::default()).expect("day");
    let b = generate_day(4242, &DayOptions::default()).expect("day");
    assert_eq!(a.capture(), b.capture());
    assert_eq!(a.key(), b.key());
    assert_eq!(a.timeline(), b.timeline());
}

#[test]
fn a_different_seed_changes_the_bytes_and_not_the_structure() {
    let a = generate_day(1, &DayOptions::default()).expect("day");
    let b = generate_day(2, &DayOptions::default()).expect("day");
    assert_ne!(a.capture(), b.capture(), "the nonces differ");
    assert_eq!(a.key().expected().len(), b.key().expected().len());
    assert_eq!(
        a.timeline().iter().map(|s| s.episode).collect::<Vec<_>>(),
        b.timeline().iter().map(|s| s.episode).collect::<Vec<_>>()
    );
    // And both are still scored perfectly by the standard rules.
    for day in [&a, &b] {
        let score = day
            .key()
            .score(&RuleSet::standard().run(&day.monitor().unwrap()));
        assert!(score.false_positives().is_empty(), "{}", score.explain());
        assert!(score.false_negatives().is_empty(), "{}", score.explain());
    }
}

#[test]
fn a_day_carries_both_attacks_and_benign_events() {
    let day = generate_day(5, &DayOptions::default()).expect("day");
    let key = day.key();
    assert!(key.expected().iter().any(|e| e.verdict == Verdict::Attack));
    assert!(key
        .expected()
        .iter()
        .any(|e| e.verdict == Verdict::Weakness));
    assert!(key
        .expected()
        .iter()
        .any(|e| e.verdict == Verdict::Ambiguous));
    assert!(
        key.benign().len() >= 5,
        "the benign half is not an afterthought"
    );
    // The expectations are in time order, which is what makes scoring stable.
    assert!(key.expected().windows(2).all(|w| w[0].t_us <= w[1].t_us));
}

#[test]
fn a_day_with_no_episodes_is_an_error_rather_than_an_empty_file() {
    let err = generate_day(
        1,
        &DayOptions {
            episodes: Vec::new(),
            ..DayOptions::default()
        },
    )
    .unwrap_err();
    assert!(matches!(err, DetectError::Scenario(_)));
    assert!(err.to_string().contains("at least one episode"));
}

#[test]
fn the_timeline_accounts_for_every_line_of_the_capture() {
    let day = generate_day(6, &DayOptions::default()).expect("day");
    let total: usize = day.timeline().iter().map(|s| s.events).sum();
    assert_eq!(total, day.capture().lines().count());
    assert!(day.explain().contains("downgrade"));
}

// ---------------------------------------------------------------------------
// Robustness — nothing here may panic
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_capture_line_names_itself_rather_than_panicking() {
    let err = Monitor::from_capture("{\"line\":\"rs485\",\"dir\":\"wire\",\"bytes\":\"53\"}")
        .unwrap_err();
    assert!(matches!(err, DetectError::Capture(_)));
    assert!(err.to_string().contains("t_us"));
}

#[test]
fn an_empty_capture_produces_no_findings() {
    let monitor = Monitor::from_capture("").expect("parses");
    assert!(monitor.is_empty());
    assert_eq!(monitor.start_us(), 0);
    assert_eq!(monitor.span_us(), 0);
    assert!(RuleSet::standard().run(&monitor).is_empty());
}

#[test]
fn bytes_that_are_not_frames_are_kept_and_do_not_panic_anything() {
    let mut lines = String::new();
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    for i in 0..300u64 {
        // A deterministic LCG, biased towards things that look like frames.
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = 1 + (state >> 59) as usize;
        let mut bytes = alloc::vec![0x53u8];
        for j in 0..len {
            bytes.push(((state >> (j % 8 * 8)) & 0xFF) as u8);
        }
        let line = if i % 3 == 0 { "wiegand" } else { "rs485" };
        lines.push_str(&alloc::format!(
            "{{\"t_us\":{},\"line\":\"{}\",\"dir\":\"pd_to_acu\",\"bytes\":\"{}\"}}\n",
            i * 7_000,
            line,
            odr_bus::capture::to_hex(&bytes)
        ));
    }
    let monitor = Monitor::from_capture(&lines).expect("parses");
    assert_eq!(monitor.len(), 300);
    let report = RuleSet::standard().run(&monitor);
    assert!(report.evidence_checks(&monitor));
}

#[test]
fn a_frame_that_does_not_decode_is_still_an_observation() {
    let line = "{\"t_us\":9,\"line\":\"rs485\",\"dir\":\"acu_to_pd\",\"bytes\":\"deadbeef\"}";
    let monitor = Monitor::from_capture(line).expect("parses");
    assert_eq!(monitor.len(), 1);
    let o = &monitor.observations()[0];
    assert!(o.frame.is_none());
    assert!(o.address().is_none());
    assert!(o.summary().contains("undecodable"));
    assert!(monitor.addresses().is_empty());
}

#[test]
fn one_capture_line_carrying_several_frames_becomes_several_observations() {
    // A real analyser hands back a buffer, not a frame. Evidence has to cite a
    // frame, so the monitor splits them.
    let mut bytes = Frame::command(0x01, 1, Command::Poll, Vec::new()).encode();
    bytes.extend(Frame::command(0x01, 2, Command::Poll, Vec::new()).encode());
    let line = alloc::format!(
        "{{\"t_us\":1,\"line\":\"rs485\",\"dir\":\"acu_to_pd\",\"bytes\":\"{}\"}}",
        odr_bus::capture::to_hex(&bytes)
    );
    let monitor = Monitor::from_capture(&line).expect("parses");
    assert_eq!(monitor.len(), 2);
    assert_eq!(monitor.observations()[0].sequence(), Some(1));
    assert_eq!(monitor.observations()[1].sequence(), Some(2));
}

// ---------------------------------------------------------------------------
// Small surfaces
// ---------------------------------------------------------------------------

#[test]
fn direction_is_recovered_from_the_frame_rather_than_trusted_from_the_file() {
    // A capture that lies about direction. A real probe on a single pair could
    // not have known it, and the reply bit says otherwise.
    let reply = Frame::reply(0x01, 1, Reply::Ack, Vec::new());
    let line = alloc::format!(
        "{{\"t_us\":1,\"line\":\"rs485\",\"dir\":\"acu_to_pd\",\"bytes\":\"{}\"}}",
        odr_bus::capture::to_hex(&reply.encode())
    );
    let monitor = Monitor::from_capture(&line).expect("parses");
    let o = &monitor.observations()[0];
    assert!(o.is_reply(), "the reply bit wins over the file's claim");
    assert_eq!(o.address(), Some(0x01));
}

#[test]
fn the_severity_and_confidence_scales_are_ordered() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::Info < Severity::Low);
    assert!(Confidence::Certain > Confidence::Probable);
    assert!(Confidence::Ambiguous < Confidence::Possible);
}

#[test]
fn every_signal_has_a_name_and_a_sentence() {
    for s in Signal::ALL {
        assert!(!s.name().is_empty());
        assert!(s.describe().len() > 20, "{}", s.name());
        assert!(!s.name().contains(' '));
    }
    let names: Vec<&str> = Signal::ALL.iter().map(|s| s.name()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "signal names are unique");
}

#[test]
fn a_finding_explains_itself_without_the_rustdoc_open() {
    let day = generate_day(
        14,
        &DayOptions {
            episodes: alloc::vec![Episode::CleartextBus],
            ..DayOptions::default()
        },
    )
    .expect("day");
    let monitor = day.monitor().expect("monitor");
    let report = RuleSet::standard().run(&monitor);
    let text = report.explain();
    assert!(text.contains("cleartext_bus"));
    assert!(text.contains("readable"));
    assert!(text.contains("ACU->PD") || text.contains("PD->ACU"));
}

#[test]
fn the_weak_key_family_is_not_accidentally_the_site_key() {
    // If the generator's "site key" were weak, half the findings in the day
    // would mean something other than what their labels say.
    assert!(odr_osdp::weak_keys::classify(&scenario::SITE_KEY).is_none());
    assert_ne!(scenario::SITE_KEY, SCBK_D);
}
