//! **`docs/CURRICULUM.md`, drill by drill, run rather than described.**
//!
//! Each test here is a flag predicate expressed against engine state. Nothing
//! compares a typed answer and nothing asserts an actor's own claim about
//! itself; every assertion is either the world's event log, a component the
//! world holds, or the attacker's knowledge base together with the provenance
//! of every fact in it.
//!
//! The provenance assertions are the ones that matter most. `Knowledge::unearned`
//! lists facts an actor was handed rather than obtained, and a test that asserts
//! it is empty is a real assertion rather than a tautology, because the variant
//! exists and could be produced.

use odr_attack::knowledge::KeyKind;
use odr_attack::osdp_active::frames_sent_by;
use odr_attack::*;
use odr_bus::*;
use odr_credential::hid_prox::H10301;
use odr_credential::mifare::{
    AccessBits, KeyType as MfKeyType, MifareClassic1k, MifareReader, DEFAULT_KEY,
};
use odr_credential::{Card, Rng};
use odr_osdp::codes::{Command, Reply};
use odr_osdp::payload::KeysetCommand;
use odr_osdp::{weak_keys, SCBK_D};
use odr_wiegand::{BitVec, CardFormat, Credential, CredentialSweep, WiegandTiming};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn card(fc: u64, cn: u64) -> Credential {
    Credential::new(CardFormat::H10301, fc, cn)
}

fn presentation(source: u32, cred: &Credential) -> Presentation {
    Presentation::from_credential(SourceId(source), cred).expect("credential encodes")
}

fn osdp_spec(acu: AcuConfig, pds: Vec<PdConfig>, access: AccessList) -> OsdpBenchSpec {
    OsdpBenchSpec {
        acu,
        pds,
        timing: Rs485Timing::at_baud(9600),
        access,
        start_polling_at_us: 0,
    }
}

/// Every actor in this crate must be able to say that nothing it knows was
/// handed to it.
fn assert_honest(k: &Knowledge) {
    let unearned = k.unearned();
    assert!(
        unearned.is_empty(),
        "the attacker was handed something it could not have had: {:?}",
        unearned.iter().map(|p| p.describe()).collect::<Vec<_>>()
    );
}

// ===========================================================================
// Module 0 — the credential
// ===========================================================================

/// **0.2** — a cloned tag presents to the reader and the controller grants,
/// where the original tag was never presented.
#[test]
fn drill_0_2_a_clone_opens_the_door_and_the_original_was_never_there() {
    let victim_card = H10301::new(123, 4567);
    let victim = Card::hid_prox(victim_card);

    // One brush past a pocket. That is the entire interaction with the victim.
    let mut cloner = TagCloner::new("pocket coil");
    cloner.brush_past(&victim, 0).unwrap();
    cloner.write_blank().unwrap();
    assert!(cloner.is_armed());

    // The panel is configured for whatever the victim's badge emits.
    let bits = BitVec::from_bools(&cloner.read_clone().unwrap().bits());
    let access = AccessList::new()
        .with_bits(bits.clone())
        .assuming(CardFormat::H10301);
    let mut bench = wiegand_bench(0x0002, access).unwrap();

    // At the door, later. The victim's own tag is not in the building.
    const ATTACKER_TOKEN: u32 = 7;
    let p = cloner.presentation(SourceId(ATTACKER_TOKEN)).unwrap();
    bench.world.present(bench.reader, 1_000_000, p).unwrap();
    bench.world.run_until(3_000_000).unwrap();

    // The flag, in two parts.
    assert_eq!(bench.world.log().grants().count(), 1);
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 1);
    let sources: Vec<SourceId> = bench
        .world
        .log()
        .presentations()
        .filter_map(|r| match &r.kind {
            RecordKind::CredentialPresented { source, .. } => Some(*source),
            _ => None,
        })
        .collect();
    assert_eq!(sources, vec![SourceId(ATTACKER_TOKEN)]);
    assert!(
        !sources.contains(&SourceId(0)),
        "the original token never touched the reader"
    );

    assert_honest(&cloner.knowledge().snapshot());
}

/// **0.2, provenance** — everything the cloner holds came off the air.
#[test]
fn drill_0_2_the_clone_came_from_the_air_and_nothing_else() {
    let victim = Card::hid_prox(H10301::new(99, 12345));
    let mut cloner = TagCloner::new("pocket coil");

    // Before the sniff it has nothing to write, and it says so rather than
    // inventing something.
    assert!(matches!(
        cloner.write_blank(),
        Err(AttackError::Unearned { .. })
    ));

    cloner.brush_past(&victim, 500).unwrap();
    cloner.write_blank().unwrap();

    let k = cloner.knowledge().snapshot();
    assert_eq!(k.tag_captures.len(), 1);
    assert!(
        k.tag_captures[0].provenance.is_observation(),
        "the only input was the field response"
    );
    assert_honest(&k);

    // And the clone really is the victim's number, not a guess.
    let read = cloner.read_clone().unwrap();
    assert_eq!(
        read.bits(),
        odr_credential::h10301_wiegand_bits(&H10301::new(99, 12345)).to_vec()
    );
}

/// **0.4** — the attacker recovers sector keys from observed traffic alone,
/// then reads the credential block.
#[test]
fn drill_0_4_nested_recovery_from_observation_then_the_credential() {
    let mut rng = Rng::new(0x0004);
    let credential = [
        0x26u8, 0x00, 0x7B, 0x11, 0xD7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut card = MifareClassic1k::new(0x2A23_4F80, rng.next_u64());
    card.force_sector_keys(0, DEFAULT_KEY, DEFAULT_KEY, AccessBits::transport());
    let mut configured = Vec::new();
    for sector in 1..16u8 {
        let key_a = rng.next_crypto1_key();
        card.force_sector_keys(
            sector,
            key_a,
            rng.next_crypto1_key(),
            AccessBits::transport(),
        );
        configured.push(key_a);
    }
    card.force_block(4, credential);
    let mut reader = MifareReader::new(0x0404);

    // The attacker's starting position: one sector still on the factory
    // default, which is published.
    let mut attacker = NestedAttacker::new("proxmark", 0, MfKeyType::A, DEFAULT_KEY);
    attacker.calibrate(&mut card, &mut reader).unwrap();

    for sector in 1..4u8 {
        let recovered = attacker
            .recover_sector(&mut card, &mut reader, sector * 4, MfKeyType::A)
            .unwrap();
        assert_eq!(
            recovered,
            configured[usize::from(sector) - 1],
            "sector {sector}"
        );
    }

    let read = attacker
        .read_block(&mut card, &mut reader, 4, MfKeyType::A, configured[0])
        .unwrap();
    assert_eq!(read.data, credential.to_vec());
    assert_honest(&attacker.knowledge().snapshot());
}

/// **0.4, provenance** — the recovery step is handed a capture and a measured
/// distance, and cannot see the card at all.
#[test]
fn drill_0_4_the_recovery_never_touches_the_card() {
    let mut rng = Rng::new(0x0414);
    let mut card = MifareClassic1k::new(0x2A23_4F80, rng.next_u64());
    card.force_sector_keys(0, DEFAULT_KEY, DEFAULT_KEY, AccessBits::transport());
    let target = 0x1A98_2C7E_459A;
    card.force_sector_keys(1, target, 0x0102_0304_0506, AccessBits::transport());
    let mut reader = MifareReader::new(0x0415);

    let mut attacker = NestedAttacker::new("proxmark", 0, MfKeyType::A, DEFAULT_KEY);
    attacker.calibrate(&mut card, &mut reader).unwrap();
    let capture = attacker
        .capture(&mut card, &mut reader, 4, MfKeyType::A)
        .unwrap();

    // The probes were abandoned before pass three: the attacker never held a
    // session it could not pay for.
    assert!(!card.has_session());

    // And the key falls out of the capture alone. Nothing below this line can
    // reach the card.
    let recovered = attacker.recover(&capture).unwrap();
    assert_eq!(recovered, target);

    let k = attacker.knowledge().snapshot();
    assert_honest(&k);
    let sector_keys: Vec<&Known<RecoveredKey>> = k
        .keys
        .iter()
        .filter(|x| x.value.kind == KeyKind::MifareSector)
        .collect();
    // The known one is published; the recovered one was searched for.
    assert!(matches!(
        sector_keys[0].provenance,
        Provenance::Published { .. }
    ));
    assert!(matches!(
        sector_keys[1].provenance,
        Provenance::BruteForced { .. }
    ));
}

// ===========================================================================
// Module 1 — the wire
// ===========================================================================

/// **1.1** — the sniffer decodes what the engine transmitted, off the wire.
#[test]
fn drill_1_1_a_sniffer_reads_the_credential_off_the_pair() {
    let cred = card(42, 1337);
    let mut bench = wiegand_bench(0x0101, AccessList::allow_all()).unwrap();
    let mut sniffer = Sniffer::new("ceiling void");
    sniffer.attach(&mut bench.world, bench.link).unwrap();

    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(2_000_000).unwrap();
    assert_eq!(sniffer.harvest(&bench.world).unwrap(), 1);

    let capture = sniffer.latest().unwrap();
    assert_eq!(capture.bit_len(), 26);
    assert_eq!(capture.facility_code(), Some(42));
    assert_eq!(capture.card_number(), Some(1337));
    assert_eq!(capture.medium, CaptureMedium::Wiegand);

    // Passive means passive, and the engine says so rather than the actor.
    assert!(sniffer.transmitted_nothing(&bench.world));
    assert_eq!(sniffer.position(), TapKind::Passive);
    let k = sniffer.knowledge().snapshot();
    assert!(k.credentials.iter().all(|c| c.provenance.is_observation()));
    assert_honest(&k);
}

/// **1.2** — a frame reaches the controller that parses cleanly, has valid
/// parity, and carries a card number no credential ever presented to the reader
/// had.
#[test]
fn drill_1_2_parity_is_not_integrity() {
    let real = card(42, 1337);
    let forged = card(42, 9999);
    // Only the forged number is on the list; the real card is not.
    let access = AccessList::new()
        .with_credential(&forged)
        .unwrap()
        .assuming(CardFormat::H10301);
    let mut bench = wiegand_bench(0x0102, access).unwrap();

    let mut implant = Implant::new("bit flipper");
    implant
        .attach_before(&mut bench.world, bench.link, bench.reader)
        .unwrap();
    // Change one field and recompute the parity the format demands.
    implant.impersonate_card(CardFormat::H10301, 42, 9999);

    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &real))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();

    let arrived = bench
        .world
        .log()
        .find(|r| {
            matches!(
                r.kind,
                RecordKind::WireRx {
                    receiver: Endpoint::Controller(_),
                    ..
                }
            )
        })
        .next()
        .cloned()
        .unwrap();
    let bits = match arrived.kind {
        RecordKind::WireRx { bits, .. } => bits,
        _ => unreachable!(),
    };
    let decoded = odr_wiegand::decode(CardFormat::H10301, &bits).unwrap();
    assert!(decoded.parity_valid(), "the panel has nothing to object to");
    assert_eq!(decoded.card_number, Some(9999));

    // No credential with that number was ever presented.
    let presented: Vec<u64> = bench
        .world
        .log()
        .presentations()
        .filter_map(|r| match &r.kind {
            RecordKind::CredentialPresented { bits, .. } => {
                odr_wiegand::decode(CardFormat::H10301, bits)
                    .ok()
                    .and_then(|d| d.card_number)
            }
            _ => None,
        })
        .collect();
    assert_eq!(presented, vec![1337]);
    assert_eq!(bench.world.log().grants().count(), 1);
}

/// **1.3** — the controller grants at a time when no credential was presented.
#[test]
fn drill_1_3_replay_opens_the_door_with_no_card_present() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = wiegand_bench(0x0103, access).unwrap();

    let mut replayer = Replayer::new("replay box");
    let tap = replayer.attach(&mut bench.world, bench.link).unwrap();

    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(2_000_000).unwrap();
    assert_eq!(replayer.harvest(&bench.world).unwrap(), 1);

    // Card gone. Hours later.
    replayer
        .replay_latest(&mut bench.world, 30_000_000)
        .expect("the box re-emits what it heard");
    bench.world.run_until(31_000_000).unwrap();

    let grants: Vec<_> = bench.world.log().grants().cloned().collect();
    assert_eq!(grants.len(), 2);
    let replay_t = grants[1].t_us;
    assert!(
        !bench
            .world
            .log()
            .presentations()
            .any(|p| p.t_us + 5_000_000 > replay_t && p.t_us <= replay_t),
        "the second grant had no credential behind it"
    );
    assert_eq!(
        bench.world.log().originator(grants[1].seq),
        Some(Origin::Tap(tap)),
        "and the engine attributes it to the attacker"
    );
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 2);
    assert_honest(&replayer.knowledge().snapshot());
}

/// **1.3, provenance** — the replay box refuses to transmit a credential it
/// never heard.
#[test]
fn drill_1_3_a_replayer_cannot_send_what_it_never_captured() {
    let cred = card(42, 1337);
    let never_seen = CapturedCredential {
        bits: card(1, 1).encode().unwrap(),
        t_us: 0,
        link: None,
        segment: 0,
        medium: CaptureMedium::Wiegand,
        address: None,
    };
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = wiegand_bench(0x0113, access).unwrap();
    let mut replayer = Replayer::new("replay box");
    replayer.attach(&mut bench.world, bench.link).unwrap();

    // Nothing captured yet: both entry points refuse.
    assert!(matches!(
        replayer.replay_latest(&mut bench.world, 1_000_000),
        Err(AttackError::Exhausted { .. })
    ));
    assert!(matches!(
        replayer.replay(&mut bench.world, 1_000_000, &never_seen),
        Err(AttackError::Unearned { .. })
    ));
    bench.world.run_until(5_000_000).unwrap();
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 0);
}

/// **1.4** — the tap is inline, the reader's credential was consumed, the
/// controller granted on a substitute, and the reader's own output is
/// unchanged.
#[test]
fn drill_1_4_the_implant_substitutes_and_the_reader_never_knows() {
    let real = card(42, 1337);
    let boss = card(1, 1);
    let access = AccessList::new().with_credential(&boss).unwrap();
    let mut bench = wiegand_bench(0x0104, access).unwrap();

    let mut implant = Implant::new("espkey");
    let tap = implant
        .attach_before(&mut bench.world, bench.link, bench.reader)
        .unwrap();

    // Installed transparent, as it would be. Prove that first.
    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &real))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();
    assert_eq!(bench.world.log().decisions().count(), 1);
    assert_eq!(
        bench.world.log().grants().count(),
        0,
        "the real card is not on the list, so nothing opened"
    );
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 0);
    assert_eq!(implant.swaps(), 0);

    // Then armed.
    implant.impersonate(boss);
    bench
        .world
        .present(bench.reader, 5_000_000, presentation(0, &real))
        .unwrap();
    bench.world.run_until(8_000_000).unwrap();

    assert_eq!(bench.world.tap_kind(tap).unwrap(), TapKind::Inline);
    assert_eq!(implant.swaps(), 1);
    assert_eq!(
        implant.consumed().len(),
        2,
        "both credentials reached the implant"
    );

    // What the reader emitted, both times, was the real card.
    let reader_out: Vec<BitVec> = bench
        .world
        .log()
        .find(|r| {
            matches!(
                r.kind,
                RecordKind::WireTx {
                    origin: Origin::Reader(_),
                    ..
                }
            )
        })
        .filter_map(|r| match &r.kind {
            RecordKind::WireTx { bits, .. } => Some(bits.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(reader_out, vec![real.encode().unwrap(); 2]);

    // What the panel received the second time was somebody else's badge.
    let panel_in: Vec<BitVec> = bench
        .world
        .log()
        .find(|r| {
            matches!(
                r.kind,
                RecordKind::WireRx {
                    receiver: Endpoint::Controller(_),
                    ..
                }
            )
        })
        .filter_map(|r| match &r.kind {
            RecordKind::WireRx { bits, .. } => Some(bits.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(panel_in[0], real.encode().unwrap());
    assert_eq!(panel_in[1], boss.encode().unwrap());
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 1);

    // And the implant kept what it swallowed.
    let k = implant.knowledge().snapshot();
    assert_eq!(k.credentials.len(), 2);
    assert!(k.credentials.iter().all(|c| c.provenance.is_observation()));
    assert_honest(&k);
}

/// **1.5** — not a flag, a number: what the whole space costs at the timing the
/// learner chose.
#[test]
fn drill_1_5_brute_force_reports_an_honest_wall_clock_cost() {
    let enrolled = card(42, 5);
    let access = AccessList::new().with_credential(&enrolled).unwrap();
    let mut bench = wiegand_bench(0x0105, access).unwrap();

    let sweep = CredentialSweep::new(CardFormat::H10301, 42..=42, 0..=40).unwrap();
    let mut forcer = BruteForcer::new("sweeper", sweep);
    forcer.attach(&mut bench.world, bench.link).unwrap();

    let report = forcer.run_until_granted(&mut bench.world, 40, 8).unwrap();

    // It found the enrolled card, because the space it swept contained it.
    assert_eq!(report.hit.as_ref().map(|c| c.card_number), Some(5));
    assert_eq!(bench.world.log().grants().count(), 1);
    assert!(report.attempted >= 6 && report.attempted <= 16);

    // And the number the drill ends on: the honest cost of the whole 26-bit
    // space at this wire timing.
    assert_eq!(report.format_space_cost.credentials, 16_777_216);
    assert!(
        report.format_space_cost.total_days() > 10.0,
        "{}",
        report.format_space_cost.describe()
    );
    assert!(report.format_space_cost.describe().ends_with("days"));

    // A single facility code is a different conversation, and that is the
    // comparison the drill asks for.
    assert!(report.sweep_cost.total_seconds() < 10.0);

    let k = forcer.knowledge().snapshot();
    assert_eq!(k.sweeps.len(), 1);
    assert_honest(&k);
}

/// **1.5** — turning the timing knob changes the answer by an order of
/// magnitude and not the conclusion.
#[test]
fn drill_1_5_the_cost_follows_the_timing_the_learner_chose() {
    let sweep = || CredentialSweep::exhaustive(CardFormat::H10301).unwrap();
    let nominal = BruteForcer::new("a", sweep());
    let fast = BruteForcer::new("b", sweep()).with_timing(WiegandTiming::fast(), 1_000);
    let slow_days = nominal.cost().total_days();
    let fast_days = fast.cost().total_days();
    assert!(fast_days < slow_days);
    assert!(
        fast_days > 0.5,
        "even at the fastest plausible timing it is still days: {fast_days}"
    );
}

/// **1.6** — replay succeeds on a clock-and-data link.
#[test]
fn drill_1_6_replay_works_the_same_on_clock_and_data() {
    let cred = card(7, 4242);
    let cfg = ClockDataConfig {
        encoding: odr_wiegand::AbaEncoding::bare(),
        assumed_format: Some(CardFormat::H10301),
    };
    // The panel matches on the track-2 bits it receives, so build the entry by
    // running the reader's own encoder through a throwaway world.
    let expected = {
        let mut probe = clock_data_bench(1, AccessList::allow_all(), cfg.clone()).unwrap();
        probe
            .world
            .present(probe.reader, 0, presentation(0, &cred))
            .unwrap();
        probe.world.run_until(2_000_000).unwrap();
        let bits = probe
            .world
            .log()
            .find(|r| matches!(r.kind, RecordKind::WireTx { .. }))
            .next()
            .and_then(|r| match &r.kind {
                RecordKind::WireTx { bits, .. } => Some(bits.clone()),
                _ => None,
            });
        bits.unwrap()
    };
    let access = AccessList::new()
        .with_bits(expected.clone())
        .checking_parity(false);
    let mut bench = clock_data_bench(0x0106, access, cfg).unwrap();

    let mut replayer = Replayer::new("replay box");
    replayer.attach(&mut bench.world, bench.link).unwrap();
    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();
    replayer.harvest(&bench.world).unwrap();

    let captured = replayer.knowledge().snapshot();
    assert_eq!(captured.credentials.len(), 1);
    assert_eq!(
        captured.credentials[0].value.medium,
        CaptureMedium::ClockData
    );

    replayer
        .replay_latest(&mut bench.world, 10_000_000)
        .unwrap();
    bench.world.run_until(13_000_000).unwrap();
    assert_eq!(bench.world.log().strikes().count(), 2);
}

// ===========================================================================
// Module 2 — OSDP as it is usually deployed
// ===========================================================================

/// **2.2** — a card number extracted from passive observation only, with zero
/// frames injected.
#[test]
fn drill_2_2_a_card_number_off_an_unsecured_bus() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = osdp_bench(
        0x0202,
        osdp_spec(AcuConfig::polling([0x01]), vec![PdConfig::at(0x01)], access),
    )
    .unwrap();
    let pd = bench.pd();

    let mut ear = PassiveEavesdropper::new("clip on the pair");
    ear.attach(&mut bench.world, bench.link).unwrap();

    bench.world.run_until(1_000_000).unwrap();
    bench
        .world
        .present(pd, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();
    assert_eq!(ear.harvest(&bench.world).unwrap(), 1);

    // The flag, both halves.
    assert_eq!(ear.card_numbers(), vec![1337]);
    assert_eq!(
        ear.captures()[0].bits,
        cred.encode().unwrap(),
        "bit for bit what the reader sent"
    );
    assert!(ear.transmitted_nothing(&bench.world));

    let k = ear.knowledge().snapshot();
    assert!(k.credentials.iter().all(|c| c.provenance.is_observation()));
    assert!(k.keys.is_empty(), "no key was needed and none was invented");
    assert_honest(&k);
}

/// **2.3** — the PD ACKs a command originated by the attacker actor.
#[test]
fn drill_2_3_the_pd_acks_a_forged_command() {
    let mut bench = osdp_bench(
        0x0203,
        osdp_spec(
            AcuConfig::polling([0x01]),
            vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();

    let mut injector = Injector::new("laptop and a dongle");
    let tap = injector.attach(&mut bench.world, bench.link).unwrap();

    // It has heard nothing yet, so it does not know who to talk to — and says
    // so rather than guessing.
    assert!(matches!(
        injector.forge_to_any(&mut bench.world, 0, Command::Led, vec![0; 14]),
        Err(AttackError::Unearned { .. })
    ));

    bench.world.run_until(1_000_000).unwrap();
    injector.harvest(&bench.world).unwrap();
    assert_eq!(injector.observed_addresses(), vec![0x01]);

    // Sequence zero is the protocol's "I have just started", and any PD takes
    // it from anybody.
    let address = injector
        .forge_to_any(&mut bench.world, 1_500_000, Command::Led, vec![0u8; 14])
        .unwrap();
    assert_eq!(address, 0x01);
    bench.world.run_until(2_000_000).unwrap();

    assert!(injector.was_acked(&bench.world));
    assert!(bench.world.log().injected_by(tap).count() > 0);
    let k = injector.knowledge().snapshot();
    assert!(k.addresses.iter().all(|a| a.provenance.is_observation()));
    assert_honest(&k);
}

// ===========================================================================
// Module 3 — Secure Channel
// ===========================================================================

/// **3.2** — the attacker holds the session keys and has decrypted a card read,
/// having been given only the bus traffic.
#[test]
fn drill_3_2_the_default_key_gives_up_a_card_read() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = osdp_bench(
        0x0302,
        osdp_spec(
            AcuConfig::polling([0x01]).with_default_key(ScRequirement::IfAvailable),
            vec![PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();

    let mut cracker = WeakKeyCracker::new("analyser");
    cracker.attach(&mut bench.world, bench.link).unwrap();

    bench.world.run_until(2_000_000).unwrap();
    bench
        .world
        .present(pd, 2_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(5_000_000).unwrap();
    cracker.harvest(&bench.world).unwrap();

    let keys = cracker.crack().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key, SCBK_D);

    // The card read really was encrypted on the wire.
    let raw = bench
        .world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.reply_code() == Some(Reply::Raw))
        .map(|(_, _, f)| f.clone())
        .unwrap();
    assert!(raw.is_encrypted());

    // And the attacker read it anyway.
    let reads = cracker.decrypt_card_reads(0x01).unwrap();
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].bits, cred.encode().unwrap());
    assert_eq!(reads[0].card_number(), Some(1337));

    assert!(cracker.transmitted_nothing(&bench.world));
    let k = cracker.knowledge().snapshot();
    assert!(k.holds_scbk(&SCBK_D));
    assert!(matches!(
        k.keys[0].provenance,
        Provenance::BruteForced { .. }
    ));
    assert!(k.handshakes.iter().all(|h| h.provenance.is_observation()));
    assert_honest(&k);
}

/// **3.3** — attacker-recovered SCBK equals the PD's configured SCBK, recovered
/// from capture alone.
#[test]
fn drill_3_3_a_sample_code_site_key_falls_out_of_one_handshake() {
    // Not SCBK-D, and not random either: a repeated byte, straight out of a
    // vendor's example.
    let site_key = [0x5Au8; 16];
    assert!(weak_keys::is_weak(&site_key));
    assert_ne!(site_key, SCBK_D);

    let mut bench = osdp_bench(
        0x0303,
        osdp_spec(
            AcuConfig::polling([0x01]).with_site_key(site_key, ScRequirement::IfAvailable),
            vec![PdConfig::at(0x01).with_site_key(site_key, ScRequirement::IfAvailable)],
            AccessList::new(),
        ),
    )
    .unwrap();

    let mut cracker = WeakKeyCracker::new("analyser");
    cracker.attach(&mut bench.world, bench.link).unwrap();
    bench.world.run_until(2_000_000).unwrap();
    cracker.harvest(&bench.world).unwrap();

    let keys = cracker.crack().unwrap();
    assert_eq!(keys.len(), 1);

    // The flag: what the attacker recovered is what the PD is configured with.
    assert_eq!(
        Some(keys[0].key),
        bench.world.reader(bench.pd()).unwrap().scbk()
    );
    assert_eq!(
        keys[0].pattern,
        Some(weak_keys::WeakKeyPattern::Repeated { byte: 0x5A })
    );
    assert!(cracker.candidates_tried() > 0 && cracker.candidates_tried() <= 768);
    assert!(cracker.transmitted_nothing(&bench.world));
    assert_honest(&cracker.knowledge().snapshot());
}

/// **3.3, the negative control** — a key outside the published family survives.
#[test]
fn drill_3_3_a_real_key_survives_the_sweep() {
    let mut rng = odr_osdp::SeededRng::new(0x5EED);
    let site_key = rng.key16();
    assert!(!weak_keys::is_weak(&site_key));

    let mut bench = osdp_bench(
        0x0313,
        osdp_spec(
            AcuConfig::polling([0x01]).with_site_key(site_key, ScRequirement::IfAvailable),
            vec![PdConfig::at(0x01).with_site_key(site_key, ScRequirement::IfAvailable)],
            AccessList::new(),
        ),
    )
    .unwrap();
    let mut cracker = WeakKeyCracker::new("analyser");
    cracker.attach(&mut bench.world, bench.link).unwrap();
    bench.world.run_until(2_000_000).unwrap();
    cracker.harvest(&bench.world).unwrap();

    assert!(cracker.crack().unwrap().is_empty());
    assert_eq!(
        cracker.candidates_tried(),
        768,
        "the whole family, and no hit"
    );
    assert!(!cracker.knowledge().snapshot().holds_scbk(&site_key));
    assert!(matches!(
        cracker.shadow(0x01),
        Err(AttackError::Unearned { .. })
    ));
}

/// **3.4** — the attacker holds the SCBK and the only frames it sent were
/// legitimate protocol traffic.
#[test]
fn drill_3_4_a_controller_in_install_mode_hands_over_the_site_key() {
    let site_key = [
        0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x01,
    ];
    assert!(
        !weak_keys::is_weak(&site_key),
        "not a sample key: it has to be asked for"
    );

    // Two addresses polled, one real reader. The attacker answers for the other.
    let acu = AcuConfig::polling([0x01, 0x02])
        .with_site_key(site_key, ScRequirement::IfAvailable)
        .in_install_mode(true);
    let mut bench = osdp_bench(
        0x0304,
        osdp_spec(
            acu,
            vec![PdConfig::at(0x01).with_site_key(site_key, ScRequirement::IfAvailable)],
            AccessList::new(),
        ),
    )
    .unwrap();

    let mut harvester = InstallModeHarvester::new("a laptop pretending to be a reader", 0x02);
    let tap = harvester.attach(&mut bench.world, bench.link).unwrap();
    bench.world.run_until(8_000_000).unwrap();

    // The flag: it holds the site key.
    let outcome = harvester.outcome();
    assert!(harvester.holds_a_site_key(), "outcome: {outcome:?}",);
    assert_eq!(outcome.keys, vec![site_key]);
    assert_eq!(
        outcome.keys[0],
        bench.world.reader(bench.pd()).unwrap().scbk().unwrap(),
        "and it is the key the real reader was commissioned with"
    );

    // And every frame it sent was a well-formed OSDP reply to the command
    // immediately before it. Nothing forged, nothing malformed.
    let sent = frames_sent_by(&bench.world, tap);
    assert!(!sent.is_empty());
    assert!(
        sent.iter().all(|f| f.is_reply && f.address == 0x02),
        "the attacker only ever answered for the address it claimed"
    );
    assert!(
        sent.iter().all(|f| Reply::from_u8(f.id).is_some()),
        "every one of them is a reply code in the standard"
    );
    assert_eq!(
        bench
            .world
            .log()
            .find(|r| matches!(r.kind, RecordKind::BusCollision { .. }))
            .count(),
        0,
        "and it never spoke over anybody"
    );

    let k = harvester.knowledge().snapshot();
    assert!(k.holds_scbk(&site_key));
    assert!(matches!(k.keys[0].provenance, Provenance::Derived { .. }));
    assert_honest(&k);
}

/// **3.4, the negative control** — a controller not in install mode gives
/// nothing away.
#[test]
fn drill_3_4_a_controller_not_in_install_mode_hands_over_nothing() {
    let site_key = [0x11u8; 16];
    let acu = AcuConfig::polling([0x01, 0x02])
        .with_site_key(site_key, ScRequirement::IfAvailable)
        .in_install_mode(false);
    let mut bench = osdp_bench(
        0x0314,
        osdp_spec(
            acu,
            vec![PdConfig::at(0x01).with_site_key(site_key, ScRequirement::IfAvailable)],
            AccessList::new(),
        ),
    )
    .unwrap();
    let mut harvester = InstallModeHarvester::new("laptop", 0x02);
    harvester.attach(&mut bench.world, bench.link).unwrap();
    bench.world.run_until(8_000_000).unwrap();

    assert!(!harvester.holds_a_site_key());
    assert!(harvester.keys().is_empty());
}

/// **3.5** — the attacker captured a `CMD_KEYSET` payload and can decrypt
/// subsequent traffic.
#[test]
fn drill_3_5_keyset_capture_during_commissioning() {
    let site_key = [
        0x0Fu8, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1,
        0xF0,
    ];
    assert!(!weak_keys::is_weak(&site_key));
    let cred = card(9, 4242);
    let access = AccessList::new().with_credential(&cred).unwrap();

    // An installer commissioning a fresh reader, with somebody on the bus.
    let acu = AcuConfig::polling([0x01])
        .with_site_key(site_key, ScRequirement::IfAvailable)
        .in_install_mode(true);
    let mut bench = osdp_bench(
        0x0305,
        osdp_spec(
            acu,
            vec![PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();

    let mut capturer = KeysetCapturer::new("installers friend");
    capturer.attach(&mut bench.world, bench.link).unwrap();
    bench.world.run_until(6_000_000).unwrap();
    bench
        .world
        .present(pd, 6_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(9_000_000).unwrap();
    capturer.harvest(&bench.world).unwrap();

    // Half one: the key.
    let keys = capturer.capture_keys().unwrap();
    assert!(keys.contains(&site_key));
    assert_eq!(
        bench.world.reader(pd).unwrap().scbk(),
        Some(site_key),
        "the reader really was commissioned with it"
    );

    // Half two: it reads what comes afterwards.
    let after = capturer.decrypt_after_commissioning(0x01).unwrap();
    let card_reads: Vec<Vec<u8>> = after
        .iter()
        .filter(|d| d.id == Reply::Raw.to_u8())
        .map(|d| d.plaintext.clone())
        .collect();
    assert_eq!(card_reads.len(), 1, "the badge-in after commissioning");
    let bits = BitVec::from_bools(
        &odr_osdp::RawCardRead::decode(&card_reads[0])
            .unwrap()
            .bits(),
    );
    assert_eq!(bits, cred.encode().unwrap());

    assert!(capturer.transmitted_nothing(&bench.world));
    assert_honest(&capturer.knowledge().snapshot());
}

/// **3.6** — the link reaches a steady state carrying card reads with no
/// security block, where both endpoints were configured to require Secure
/// Channel.
#[test]
fn drill_3_6_the_downgrade_the_controller_believes() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let acu = AcuConfig::polling([0x01]).with_default_key(ScRequirement::Required);
    let pd_cfg = PdConfig::at(0x01).with_default_key(ScRequirement::Required);
    let mut bench = osdp_bench(0x0306, osdp_spec(acu, vec![pd_cfg], access)).unwrap();
    let pd = bench.pd();

    let mut downgrader = Downgrader::new("inline implant");
    downgrader.attach(&mut bench.world, bench.link).unwrap();

    bench.world.run_until(2_000_000).unwrap();
    bench
        .world
        .present(pd, 2_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(4_000_000).unwrap();

    assert!(downgrader.rewrites() >= 1);
    assert_eq!(downgrader.genuinely_downgraded(), downgrader.rewrites());
    let (before, after) = downgrader.rewritten().remove(0);
    assert!(before.claims_aes128());
    assert!(!after.claims_aes128());

    // The flag.
    assert!(!bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));
    assert_eq!(
        bench
            .world
            .controller(bench.controller)
            .unwrap()
            .session(1)
            .unwrap()
            .stage,
        SessionStage::Online
    );
    let raw = bench
        .world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.reply_code() == Some(Reply::Raw))
        .map(|(_, _, f)| f.clone())
        .unwrap();
    assert!(raw.security.is_none(), "no security block at all");
    assert_eq!(bench.world.log().strikes().count(), 1);

    // The PD never changed. Only the wire did.
    assert!(bench
        .world
        .reader(pd)
        .unwrap()
        .pd_config()
        .unwrap()
        .capabilities
        .claims_aes128());
}

// ===========================================================================
// Module 4 — the weaknesses nobody mentions
// ===========================================================================

/// **4.1** — the times of every badge-in over a simulated day, correct to the
/// engine's log, without ever holding a key.
#[test]
fn drill_4_1_the_schedule_of_a_building_through_encryption() {
    let a = card(42, 1001);
    let b = card(42, 1002);
    let access = AccessList::new()
        .with_credential(&a)
        .unwrap()
        .with_credential(&b)
        .unwrap();
    let mut bench = osdp_bench(
        0x0401,
        osdp_spec(
            AcuConfig::polling([0x01]).with_default_key(ScRequirement::Required),
            vec![PdConfig::at(0x01).with_default_key(ScRequirement::Required)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();

    let mut analyst = TrafficAnalyst::new("a box in the riser");
    analyst.attach(&mut bench.world, bench.link).unwrap();

    bench.world.run_until(2_000_000).unwrap();
    let mut expected = Vec::new();
    for (i, cred) in [&a, &b, &a, &b, &a].iter().enumerate() {
        let at = 3_000_000 + (i as u64) * 4_000_000;
        bench.world.present(pd, at, presentation(0, cred)).unwrap();
        expected.push(at);
    }
    bench.world.run_until(30_000_000).unwrap();
    analyst.harvest(&bench.world).unwrap();

    // The bus really was encrypted the whole time.
    assert!(bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));
    let reads: Vec<_> = bench
        .world
        .log()
        .bus_frames()
        .filter(|(_, _, f)| f.reply_code() == Some(Reply::Raw))
        .collect();
    assert_eq!(reads.len(), 5);
    assert!(reads.iter().all(|(_, _, f)| f.is_encrypted()));

    // The flag: the attacker's timeline against the engine's own record.
    let timeline = analyst.analyse();
    assert_eq!(timeline.badge_count(), 5);
    let comparison = timeline.compare(&expected, 1_000_000);
    assert!(
        comparison.is_exact(),
        "every badge-in found, nothing invented: {comparison:?}"
    );
    assert!(timeline
        .badge_events
        .iter()
        .all(|b| b.granted == Some(true)));

    // And it never held a key, or a payload byte.
    let k = analyst.knowledge().snapshot();
    assert!(k.keys.is_empty());
    assert!(k.credentials.is_empty(), "it cannot read a card number");
    assert!(k.frames.is_empty(), "it does not even keep the frames");
    assert_eq!(k.badge_events.len(), 5);
    assert!(analyst.transmitted_nothing(&bench.world));
    assert_honest(&k);
}

/// **4.1, the structural claim** — scramble every payload byte in the capture
/// and the analyst's answer does not move.
#[test]
fn drill_4_1_the_analyst_never_touches_a_payload() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = osdp_bench(
        0x0411,
        osdp_spec(
            AcuConfig::polling([0x01]).with_default_key(ScRequirement::Required),
            vec![PdConfig::at(0x01).with_default_key(ScRequirement::Required)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();
    bench.world.run_until(2_000_000).unwrap();
    bench
        .world
        .present(pd, 3_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(8_000_000).unwrap();

    let capture: Vec<ObservedFrame> = bench
        .world
        .log()
        .bus_frames()
        .map(|(r, dir, f)| ObservedFrame {
            t_us: r.t_us,
            dir,
            frame: f.clone(),
        })
        .collect();
    assert!(capture.len() > 10);

    let mut honest = TrafficAnalyst::new("honest");
    honest.ingest(&capture);

    // Now destroy every payload byte in the world and hand over the wreckage.
    let scrambled: Vec<ObservedFrame> = capture
        .iter()
        .map(|o| {
            let mut f = o.frame.clone();
            for b in f.payload.iter_mut() {
                *b = 0xA5;
            }
            ObservedFrame { frame: f, ..*o }
        })
        .collect();
    let mut blinded = TrafficAnalyst::new("blinded");
    blinded.ingest(&scrambled);

    assert_eq!(
        honest.timeline(),
        blinded.timeline(),
        "the analyst's conclusions cannot depend on bytes it never reads"
    );
    assert_eq!(honest.headers(), blinded.headers());
    assert_eq!(honest.timeline().badge_count(), 1);
}

/// **4.2** — a frame the PD accepts whose MAC was not derived from the session
/// key.
#[test]
fn drill_4_2_a_forged_mac_the_pd_accepts() {
    // The engine is rigged so this completes while a learner is watching. The
    // drill says so out loud, and `MacForger::genuine_search` below is what it
    // says it with.
    let acu = AcuConfig::polling([0x01])
        .with_default_key(ScRequirement::IfAvailable)
        .with_mac_len(1);
    let pd_cfg = PdConfig::at(0x01)
        .with_default_key(ScRequirement::IfAvailable)
        .with_mac_len(1);
    let mut bench = osdp_bench(0x0402, osdp_spec(acu, vec![pd_cfg], AccessList::new())).unwrap();

    let mut forger = MacForger::new("forger", 0x01, 0x0402);
    let tap = forger.attach(&mut bench.world, bench.link).unwrap();

    // Let the session come up, so there is something to forge into.
    bench.world.run_until(3_000_000).unwrap();
    assert!(bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));

    // Measure the target from the wire rather than being told about it.
    let facts = forger.calibrate().unwrap();
    assert_eq!(facts.effective_bytes, 1);
    assert!(facts.samples > 2);
    assert_eq!(facts.search_space(), 256);

    forger.isolate(true);
    let progress = forger.run(&mut bench.world, 1200).unwrap();

    // The flag.
    assert!(progress.accepted, "{progress:?}");
    let forged = forger.accepted().unwrap();
    assert!(forged.mac.is_some());
    assert_eq!(forged.command_code(), Some(Command::Out));
    assert!(
        odr_attack::osdp_crypto::acceptance_is_attributable(&bench.world, tap),
        "the engine attributes the acceptance to the attacker's frame"
    );
    assert!(progress.attempts <= 1200);

    // The honest half of the drill: the genuine computation, as a counter and a
    // rate, on a bar that will never finish.
    let genuine = forger.genuine_search(&bench.world);
    assert_eq!(genuine.space(), 1u128 << 32);
    assert!(genuine.us_per_attempt() > 1_000);
    assert!(genuine.projected_years() > 1.0, "{}", genuine.describe());
    assert!(!genuine.is_finished());

    let k = forger.knowledge().snapshot();
    assert_eq!(k.mac_facts.len(), 1);
    assert!(matches!(
        k.mac_facts[0].provenance,
        Provenance::Calibrated { .. }
    ));
    assert_honest(&k);
}

/// **4.2** — the genuine search is drivable a slice at a time and does not
/// finish.
#[test]
fn drill_4_2_the_genuine_search_is_a_counter_and_a_rate() {
    let mut search = MacSearch::genuine(25_000);
    assert_eq!(search.space(), 4_294_967_296);
    for _ in 0..1000 {
        search.step(1_000_000);
    }
    assert!(!search.is_finished());
    assert!(search.fraction() < 0.25);
    assert!(search.remaining() > 3_000_000_000);
    assert!(search.projected_years() > 3.0, "{}", search.describe());
    assert!(search.describe().contains("years"));
}

/// **4.3** — the attacker recovers a plaintext payload from two frames sharing
/// an IV.
#[test]
fn drill_4_3_iv_reuse_reads_a_frame_the_decryptor_cannot() {
    let site_key = [
        0x0Fu8, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1,
        0xF0,
    ];
    let acu = AcuConfig::polling([0x01])
        .with_site_key(site_key, ScRequirement::IfAvailable)
        .in_install_mode(true);
    let mut bench = osdp_bench(
        0x0403,
        osdp_spec(
            acu,
            vec![PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable)],
            AccessList::new(),
        ),
    )
    .unwrap();

    // One pooled knowledge base, two devices: a passive analyser and an inline
    // implant. The analyser cracks the commissioning key; the implant freezes
    // the chain.
    let pooled = KnowledgeCell::new();
    let mut exploiter = IvReuseExploiter::sharing("inline implant", pooled.clone());
    exploiter.attach(&mut bench.world, bench.link).unwrap();
    // The trigger is a plaintext command byte, which is readable at every
    // security level OSDP offers.
    exploiter.suppress_after_command(Command::Keyset);

    let mut cracker = WeakKeyCracker::sharing("analyser", pooled.clone());
    cracker.attach(&mut bench.world, bench.link).unwrap();

    bench.world.run_until(10_000_000).unwrap();
    cracker.harvest(&bench.world).unwrap();

    // The commissioning channel is keyed with the published default.
    let keys = cracker.crack().unwrap();
    assert!(keys.iter().any(|k| k.key == SCBK_D));
    assert!(exploiter.suppressed() > 0, "replies were swallowed");

    // Identical ciphertext at a frozen IV: same key, same IV, same plaintext,
    // and no key needed to say so.
    let collisions = exploiter.collisions();
    assert!(
        !collisions.is_empty(),
        "epochs: {:?}",
        exploiter
            .epochs()
            .iter()
            .map(|e| e.frames.len())
            .collect::<Vec<_>>()
    );
    let collision = &collisions[0];
    assert!(collision.at.len() >= 2);

    // Anchor the codebook with a session reconstructed under the recovered key.
    let frames = exploiter.frames();
    let mut session = cracker.shadow(0x01).unwrap();
    assert!(exploiter.learn_from_shadow(&mut session, &frames) > 0);

    // The decryptor is chained, and suppressing the replies broke its chain
    // for it: it processed frames the controller never received, so its MAC
    // state is out of step and the retransmissions are out of its reach.
    let repeat = frames
        .iter()
        .find(|f| {
            !f.frame.is_reply
                && f.frame.is_encrypted()
                && f.t_us == collision.at[1]
                && f.frame.payload == collision.ciphertext
        })
        .expect("the retransmission is in the capture");
    let mut fresh = cracker.shadow(0x01).unwrap();
    fresh.replay(&frames);
    assert!(
        fresh.open(repeat.dir, &repeat.frame).is_err(),
        "a chained decryptor cannot read a frame out of order"
    );

    // IV reuse reads it anyway.
    let recovered = exploiter.recover();
    let hit = recovered
        .iter()
        .find(|p| p.t_us == collision.at[1])
        .expect("the repeat's plaintext");
    assert_eq!(hit.id, Command::Keyset.to_u8());
    assert_eq!(
        hit.bytes,
        KeysetCommand::scbk(site_key).encode(),
        "the plaintext of a frame the attacker never decrypted"
    );

    let k = exploiter.knowledge().snapshot();
    assert!(!k.plaintexts.is_empty());
    assert_honest(&k);
}

/// **4.4** — the attacker reads a payload off a MACed-but-unencrypted link.
#[test]
fn drill_4_4_the_null_cipher_hides_nothing() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut acu = AcuConfig::polling([0x01]).with_default_key(ScRequirement::IfAvailable);
    // SCS_15/SCS_16: authenticate, and do not encrypt.
    acu.encrypt_payloads = false;
    let mut bench = osdp_bench(
        0x0404,
        osdp_spec(
            acu,
            vec![PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();

    let mut reader = NullCipherReader::new("clip on the pair");
    reader.attach(&mut bench.world, bench.link).unwrap();
    bench.world.run_until(2_000_000).unwrap();
    bench
        .world
        .present(pd, 2_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(5_000_000).unwrap();
    reader.harvest(&bench.world).unwrap();

    // Secure Channel is up, and the command side is a null cipher.
    assert!(bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));
    let readable = reader.readable();
    assert!(
        !readable.is_empty(),
        "an authenticated payload is still a readable payload"
    );

    // The door-open command, in the clear, inside a Secure Channel session.
    let out = readable
        .iter()
        .find(|p| p.id == Command::Out.to_u8())
        .expect("the controller drove the strike");
    assert_eq!(
        out.bytes,
        odr_osdp::payload::OutputCommand {
            output: 0,
            control_code: 0x01,
            timer_100ms: 30,
        }
        .encode(),
        "the attacker reads exactly what the controller said"
    );

    assert!(reader.transmitted_nothing(&bench.world));
    let k = reader.knowledge().snapshot();
    assert!(k.plaintexts.iter().all(|p| p.provenance.is_observation()));
    assert_honest(&k);
}

/// **4.4, the card-number half** — a PD sealing its card reads MAC-only gives
/// the number away.
///
/// The bench cannot currently produce that frame: `odr-bus`'s PD always asks
/// for encryption on `REPLY_RAW`, so the null-cipher reply shape is unreachable
/// from a scenario. The reader is ready for it, and this test drives it from a
/// session built with `odr-osdp` directly — which is exactly the capture a real
/// null-cipher deployment would hand an analyst.
#[test]
fn drill_4_4_a_null_cipher_card_read_is_simply_readable() {
    use odr_osdp::{KeyType, RawCardRead, SecureChannel};
    let cred = card(42, 1337);

    let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
    let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [0xC0; 8]);
    let chlng = acu.challenge(1, 0, [0x11; 8]).unwrap();
    let ccrypt = pd.handle_challenge(&chlng, [0x22; 8]).unwrap();
    let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
    let rmac = pd.handle_scrypt(&scrypt).unwrap();
    acu.handle_rmac_i(&rmac).unwrap();

    let raw = RawCardRead::from_bits(0, 0, cred.encode().unwrap().as_slice());
    // `encrypt: false` is SCS_16 — authenticated, and not encrypted.
    let reply = pd
        .seal(1, 1, Reply::Raw.to_u8(), &raw.encode(), false)
        .unwrap();
    assert_eq!(reply.scs_type(), Some(odr_osdp::ScsType::ReplyMacOnly));
    assert!(reply.mac.is_some());

    let capture = vec![ObservedFrame {
        t_us: 1_000_000,
        dir: BusDir::PdToAcu,
        frame: reply,
    }];
    let mut reader = NullCipherReader::new("analyst");
    reader.ingest(&capture);

    let reads = reader.card_reads();
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].card_number(), Some(1337));
    assert_eq!(reads[0].facility_code(), Some(42));
    assert_honest(&reader.knowledge().snapshot());
}

// ===========================================================================
// Determinism, and the property the whole range rests on
// ===========================================================================

/// The same seed produces the same attack, byte for byte.
#[test]
fn the_same_seed_produces_the_same_attack() {
    fn run(seed: u64) -> (Vec<u64>, String, usize) {
        let cred = card(42, 1337);
        let access = AccessList::new().with_credential(&cred).unwrap();
        let mut bench = osdp_bench(
            seed,
            osdp_spec(
                AcuConfig::polling([0x01]).with_default_key(ScRequirement::IfAvailable),
                vec![PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable)],
                access,
            ),
        )
        .unwrap();
        let pd = bench.pd();
        let mut cracker = WeakKeyCracker::new("analyser");
        cracker.attach(&mut bench.world, bench.link).unwrap();
        bench.world.run_until(2_000_000).unwrap();
        bench
            .world
            .present(pd, 2_500_000, presentation(0, &cred))
            .unwrap();
        bench.world.run_until(6_000_000).unwrap();
        cracker.harvest(&bench.world).unwrap();
        cracker.crack().unwrap();
        let reads = cracker.decrypt_card_reads(0x01).unwrap();
        (
            reads.iter().filter_map(|r| r.card_number()).collect(),
            bench.world.export_capture(),
            cracker.knowledge().snapshot().frames.len(),
        )
    }
    let a = run(0xDEAD_BEEF);
    let b = run(0xDEAD_BEEF);
    assert_eq!(a, b);
    let c = run(0xFEED_FACE);
    assert_eq!(a.0, c.0, "the attack still works");
    assert_ne!(a.1, c.1, "but the nonces on the wire are different");
}

/// Every actor in the crate reports a position the engine then enforces.
#[test]
fn every_actor_declares_where_it_has_to_sit() {
    assert_eq!(Sniffer::new("a").position(), TapKind::Passive);
    assert_eq!(Replayer::new("a").position(), TapKind::Injecting);
    assert_eq!(Implant::new("a").position(), TapKind::Inline);
    assert_eq!(PassiveEavesdropper::new("a").position(), TapKind::Passive);
    assert_eq!(Injector::new("a").position(), TapKind::Injecting);
    assert_eq!(Downgrader::new("a").position(), TapKind::Inline);
    assert_eq!(
        InstallModeHarvester::new("a", 2).position(),
        TapKind::Injecting
    );
    assert_eq!(WeakKeyCracker::new("a").position(), TapKind::Passive);
    assert_eq!(KeysetCapturer::new("a").position(), TapKind::Passive);
    assert_eq!(TrafficAnalyst::new("a").position(), TapKind::Passive);
    assert_eq!(IvReuseExploiter::new("a").position(), TapKind::Inline);
    assert_eq!(NullCipherReader::new("a").position(), TapKind::Passive);
    assert_eq!(MacForger::new("a", 1, 0).position(), TapKind::Inline);
}

/// An actor that has not been clipped onto anything says so rather than
/// pretending.
#[test]
fn an_unattached_actor_is_an_error_rather_than_a_panic() {
    let bench = osdp_bench(
        1,
        osdp_spec(
            AcuConfig::polling([0x01]),
            vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();
    let mut ear = PassiveEavesdropper::new("unclipped");
    assert!(matches!(
        ear.harvest(&bench.world),
        Err(AttackError::NotAttached { .. })
    ));
    let mut analyst = TrafficAnalyst::new("unclipped");
    assert!(matches!(
        analyst.harvest(&bench.world),
        Err(AttackError::NotAttached { .. })
    ));
}
