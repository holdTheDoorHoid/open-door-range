//! The suite that says whether the world model is honest.
//!
//! Each test is named for the claim it makes, and the claims are the flag
//! predicates in `docs/CURRICULUM.md` wherever one exists. If a drill's flag
//! cannot be written as an assertion here, the API is wrong.

use alloc::boxed::Box;
use alloc::vec::Vec;

use odr_osdp::codes::{Command, Reply};
use odr_osdp::payload::CapabilityFunction;
use odr_osdp::{Frame, KeyType, PdCapabilities, RawCardRead, SCBK_D};
use odr_wiegand::{AbaEncoding, BitVec, CardFormat, Credential};

use crate::*;

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

/// Every OSDP command frame that went onto the bus, in order.
fn commands(world: &World) -> Vec<(u8, u8)> {
    world
        .log()
        .bus_frames()
        .filter(|(_, dir, _)| *dir == BusDir::AcuToPd)
        .map(|(_, _, f)| (f.address, f.id))
        .collect()
}

/// Every reply frame that went onto the bus, in order.
fn replies(world: &World) -> Vec<(u8, u8)> {
    world
        .log()
        .bus_frames()
        .filter(|(_, dir, _)| *dir == BusDir::PdToAcu)
        .map(|(_, _, f)| (f.address, f.id))
        .collect()
}

// ---------------------------------------------------------------------------
// Module 1 — the wire
// ---------------------------------------------------------------------------

#[test]
fn a_clean_wiegand_badge_in_runs_credential_to_strike() {
    let cred = card(42, 1337);
    let access = AccessList::new()
        .with_credential(&cred)
        .unwrap()
        .assuming(CardFormat::H10301);
    let mut bench = wiegand_bench(7, access).unwrap();

    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(2_000_000).unwrap();

    // The five things that had to happen, in order.
    assert_eq!(bench.world.log().presentations().count(), 1);
    let tx: Vec<_> = bench.world.log().transmissions().collect();
    assert_eq!(tx.len(), 1, "one frame on the wire");
    assert!(matches!(
        tx[0].kind,
        RecordKind::WireTx {
            kind: WireKind::Wiegand,
            ..
        }
    ));
    assert_eq!(bench.world.log().grants().count(), 1);
    assert_eq!(bench.world.log().strikes().count(), 1);

    let door = bench.world.door(bench.door).unwrap();
    assert_eq!(door.strike_count, 1);
    assert!(door.is_unlocked());

    // And it relocks on its own.
    bench.world.run_until(6_000_000).unwrap();
    assert!(bench.world.door(bench.door).unwrap().lock.is_locked());
}

#[test]
fn what_reaches_the_panel_is_what_the_reader_sent() {
    let cred = card(1, 2);
    let mut bench = wiegand_bench(1, AccessList::allow_all()).unwrap();
    bench
        .world
        .present(bench.reader, 0, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(1_000_000).unwrap();

    let sent = bench
        .world
        .log()
        .find(|r| matches!(r.kind, RecordKind::WireTx { .. }))
        .next()
        .cloned()
        .unwrap();
    let received = bench
        .world
        .log()
        .find(|r| matches!(r.kind, RecordKind::WireRx { .. }))
        .next()
        .cloned()
        .unwrap();
    match (sent.kind, received.kind) {
        (RecordKind::WireTx { bits: a, .. }, RecordKind::WireRx { bits: b, .. }) => {
            assert_eq!(a, b, "the decoder recovered exactly what was encoded");
            assert_eq!(a, cred.encode().unwrap());
        }
        _ => panic!("wrong record kinds"),
    }
}

#[test]
fn a_card_that_is_not_on_the_list_is_denied_and_the_door_stays_shut() {
    let good = card(42, 1);
    let bad = card(42, 2);
    let access = AccessList::new().with_credential(&good).unwrap();
    let mut bench = wiegand_bench(1, access).unwrap();
    bench
        .world
        .present(bench.reader, 0, presentation(9, &bad))
        .unwrap();
    bench.world.run_until(1_000_000).unwrap();

    assert_eq!(bench.world.log().decisions().count(), 1);
    assert_eq!(bench.world.log().grants().count(), 0);
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 0);
}

#[test]
fn drill_1_3_replay_grants_when_no_credential_was_presented() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = wiegand_bench(3, access).unwrap();

    // A sniffer on the line, and an injector that will re-send what it heard.
    let sniffer = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("sniffer")))
        .unwrap();
    let injector = bench
        .world
        .add_tap(bench.link, Box::new(InjectingTap::new("replay box")))
        .unwrap();

    // One real badge-in.
    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(2_000_000).unwrap();
    assert_eq!(bench.world.log().strikes().count(), 1);

    // Take what the sniffer heard and put it back on the wire, card absent.
    let captured = bench.world.tap(sniffer).unwrap().seen()[0]
        .bits
        .clone()
        .expect("a wire tap records bits");
    bench
        .world
        .inject(injector, Injection::wire_bits(30_000_000, captured))
        .unwrap();
    bench.world.run_until(31_000_000).unwrap();

    // The flag: a grant at a time when nothing was presented to the reader.
    let grants: Vec<_> = bench.world.log().grants().collect();
    assert_eq!(grants.len(), 2);
    let replay_t = grants[1].t_us;
    let presented_near_replay = bench
        .world
        .log()
        .presentations()
        .any(|p| p.t_us + 5_000_000 > replay_t && p.t_us <= replay_t);
    assert!(
        !presented_near_replay,
        "the second grant had no credential behind it"
    );
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 2);

    // And the second one was originated by the tap, not by the reader.
    assert_eq!(
        bench.world.log().originator(grants[1].seq),
        Some(Origin::Tap(injector))
    );
}

#[test]
fn drill_1_4_an_inline_implant_substitutes_one_credential_for_another() {
    let real = card(42, 1337);
    let forged = card(42, 9999);
    // Only the forged card opens the door; the real one does not.
    let access = AccessList::new().with_credential(&forged).unwrap();
    let mut bench = wiegand_bench(4, access).unwrap();

    let forged_bits = forged.encode().unwrap();
    let implant = bench
        .world
        .add_tap_at(
            bench.link,
            Box::new(InlineTap::substitute_bits("implant", move |_seen| {
                Some(forged_bits.clone())
            })),
            TapPosition::BeforeReader(bench.reader),
        )
        .unwrap();

    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &real))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();

    // The flag, in four parts.
    assert_eq!(bench.world.tap_kind(implant).unwrap(), TapKind::Inline);

    let reader_out = bench
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
        .next()
        .cloned()
        .unwrap();
    match reader_out.kind {
        RecordKind::WireTx { bits, .. } => {
            assert_eq!(
                bits,
                real.encode().unwrap(),
                "the reader's own output is untouched"
            )
        }
        _ => unreachable!(),
    }

    let panel_in = bench
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
    match panel_in.kind {
        RecordKind::WireRx { bits, .. } => {
            assert_eq!(
                bits,
                forged.encode().unwrap(),
                "the panel saw the substitute"
            )
        }
        _ => unreachable!(),
    }

    assert_eq!(bench.world.log().grants().count(), 1);
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 1);
    assert!(bench.world.log().actions_by(implant).any(|r| matches!(
        r.kind,
        RecordKind::TapAction {
            action: TapAction::ReplacedBits { .. },
            ..
        }
    )));
}

#[test]
fn an_inline_tap_can_simply_drop_a_credential() {
    let cred = card(42, 1337);
    let access = AccessList::allow_all();
    let mut bench = wiegand_bench(5, access).unwrap();
    bench
        .world
        .add_tap(
            bench.link,
            Box::new(InlineTap::dropping("cut", |_obs| true)),
        )
        .unwrap();
    bench
        .world
        .present(bench.reader, 0, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(1_000_000).unwrap();
    assert_eq!(bench.world.log().decisions().count(), 0);
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 0);
}

#[test]
fn drill_1_6_replay_works_the_same_on_clock_and_data() {
    let cred = card(7, 4242);
    let cfg = ClockDataConfig {
        encoding: AbaEncoding::bare(),
        assumed_format: Some(CardFormat::H10301),
    };
    // The panel matches on the bits it receives, which on this link are the
    // track-2 stream, so build the entry by running the reader's own encoder.
    let expected = crate::reader::clock_data_bits(&cfg, &presentation(0, &cred)).unwrap();
    let access = AccessList::new()
        .with_bits(expected.clone())
        .checking_parity(false);
    let mut bench = clock_data_bench(6, access, cfg).unwrap();

    let sniffer = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("sniffer")))
        .unwrap();
    let injector = bench
        .world
        .add_tap(bench.link, Box::new(InjectingTap::new("replay")))
        .unwrap();

    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();
    assert_eq!(bench.world.log().strikes().count(), 1, "the real badge-in");

    let captured = bench.world.tap(sniffer).unwrap().seen()[0]
        .bits
        .clone()
        .unwrap();
    assert_eq!(captured, expected);
    bench
        .world
        .inject(injector, Injection::wire_bits(10_000_000, captured))
        .unwrap();
    bench.world.run_until(13_000_000).unwrap();

    assert_eq!(bench.world.log().strikes().count(), 2, "and the replay");
}

// ---------------------------------------------------------------------------
// Module 2 — OSDP as it is usually deployed
// ---------------------------------------------------------------------------

#[test]
fn drill_2_1_an_osdp_link_reaches_steady_state_polling() {
    let mut bench = osdp_bench(
        11,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            AccessList::allow_all(),
        ),
    )
    .unwrap();
    bench.world.run_until(2_000_000).unwrap();

    let cmds = commands(&bench.world);
    let reps = replies(&bench.world);
    // Identify, ask for capabilities, then poll for ever.
    assert_eq!(cmds[0].1, Command::Id.to_u8());
    assert_eq!(cmds[1].1, Command::Cap.to_u8());
    assert!(cmds[2..]
        .iter()
        .all(|(a, c)| *a == 0x01 && *c == Command::Poll.to_u8()));
    assert!(
        cmds.len() > 5,
        "the bus keeps polling: {} commands",
        cmds.len()
    );
    assert_eq!(reps[0].1, Reply::PdId.to_u8());
    assert_eq!(reps[1].1, Reply::PdCap.to_u8());
    assert!(reps[2..].iter().all(|(_, r)| *r == Reply::Ack.to_u8()));

    let session = bench
        .world
        .controller(bench.controller)
        .unwrap()
        .session(1)
        .unwrap();
    assert_eq!(session.stage, SessionStage::Online);
    assert!(!session.secure, "no secure channel was configured");
}

#[test]
fn drill_2_2_an_unsecured_card_read_crosses_the_bus_in_the_clear() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = osdp_bench(
        12,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();
    let sniffer = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("sniffer")))
        .unwrap();

    bench.world.run_until(1_000_000).unwrap();
    bench
        .world
        .present(pd, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();

    assert_eq!(bench.world.log().strikes().count(), 1);

    // The flag: the attacker read the card number from observation alone,
    // having injected nothing at all.
    assert_eq!(bench.world.log().injection_count(sniffer), 0);
    let recovered: Vec<BitVec> = bench
        .world
        .tap(sniffer)
        .unwrap()
        .seen()
        .iter()
        .filter_map(|s| s.frame())
        .filter(|f| f.reply_code() == Some(Reply::Raw))
        .filter_map(|f| RawCardRead::decode(&f.payload).ok())
        .map(|raw| BitVec::from_bools(&raw.bits()))
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], cred.encode().unwrap());
    let decoded = odr_wiegand::decode(CardFormat::H10301, &recovered[0]).unwrap();
    assert_eq!(decoded.facility_code, Some(42));
    assert_eq!(decoded.card_number, Some(1337));
}

#[test]
fn drill_2_3_an_injected_command_is_acked_by_the_pd() {
    let mut bench = osdp_bench(
        13,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();
    let attacker = bench
        .world
        .add_tap(bench.link, Box::new(InjectingTap::new("attacker")))
        .unwrap();
    bench.world.run_until(1_000_000).unwrap();

    // Sequence 0 is the protocol's "I have just started", which any PD
    // accepts from anybody. No key, no credential, no cloning.
    let forged = Frame::command(
        0x01,
        0,
        Command::Led,
        alloc::vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    bench
        .world
        .inject(
            attacker,
            Injection::bus_frame(1_500_000, BusDir::AcuToPd, forged),
        )
        .unwrap();
    bench.world.run_until(2_000_000).unwrap();

    // The flag: a reply whose cause chain leads back to the attacker.
    let acked_by_attacker = bench
        .world
        .log()
        .records()
        .iter()
        .filter(|r| {
            matches!(&r.kind, RecordKind::BusTx { frame: Some(f), .. }
                if f.is_reply && f.reply_code() == Some(Reply::Ack))
        })
        .any(|r| bench.world.log().originator(r.seq) == Some(Origin::Tap(attacker)));
    assert!(
        acked_by_attacker,
        "the PD answered a frame the attacker forged"
    );
}

#[test]
fn a_pd_that_does_not_answer_is_marked_offline_and_polling_continues() {
    // Two addresses configured, one peripheral present.
    let mut bench = osdp_bench(
        14,
        osdp_spec(
            AcuConfig {
                max_retries: 1,
                reply_timeout_us: 50_000,
                ..AcuConfig::polling([0x01, 0x02])
            },
            alloc::vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();
    bench.world.run_until(3_000_000).unwrap();

    let c = bench.world.controller(bench.controller).unwrap();
    assert_eq!(c.session(0x01).unwrap().stage, SessionStage::Online);
    assert_eq!(c.session(0x02).unwrap().stage, SessionStage::Offline);
    assert!(bench.world.log().records().iter().any(|r| matches!(
        &r.kind,
        RecordKind::Protocol {
            event: ProtocolEvent::PdOffline { address: 0x02 },
            ..
        }
    )));
    // And 0x01 is still being served.
    assert!(
        commands(&bench.world)
            .iter()
            .filter(|(a, c)| *a == 0x01 && *c == Command::Poll.to_u8())
            .count()
            > 3
    );
}

#[test]
fn drill_2_4_a_busy_reply_is_retried_rather_than_lost() {
    let mut bench = osdp_bench(
        15,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01).with_busy(BusyPolicy::Next(2))],
            AccessList::new(),
        ),
    )
    .unwrap();
    bench.world.run_until(2_000_000).unwrap();

    let busy = replies(&bench.world)
        .iter()
        .filter(|(_, r)| *r == Reply::Busy.to_u8())
        .count();
    assert_eq!(busy, 2);
    assert_eq!(
        bench
            .world
            .controller(bench.controller)
            .unwrap()
            .session(1)
            .unwrap()
            .stage,
        SessionStage::Online,
        "the link recovered without a restart"
    );
}

#[test]
fn drill_2_4_a_desynchronised_link_recovers_without_a_restart() {
    let mut bench = osdp_bench(
        16,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();
    bench.world.run_until(1_000_000).unwrap();
    let before = bench.world.log().len();

    bench.world.desynchronise(bench.controller, 0x01).unwrap();
    bench.world.run_until(3_000_000).unwrap();

    let after = &bench.world.log().records()[before..];
    assert!(
        after.iter().any(|r| matches!(
            &r.kind,
            RecordKind::Protocol {
                event: ProtocolEvent::SequenceMismatch { .. },
                ..
            }
        )),
        "the PD noticed"
    );
    assert!(
        after.iter().any(|r| matches!(
            &r.kind,
            RecordKind::Protocol {
                event: ProtocolEvent::Nak { error: 0x04, .. },
                ..
            }
        )),
        "and NAKed with a sequence error"
    );
    assert_eq!(
        bench
            .world
            .controller(bench.controller)
            .unwrap()
            .session(1)
            .unwrap()
            .stage,
        SessionStage::Online,
        "and the controller resynchronised on its own"
    );
}

#[test]
fn a_multidrop_bus_serves_two_peripherals_at_different_addresses() {
    let a = card(1, 111);
    let b = card(2, 222);
    let access = AccessList::new()
        .with_credential(&a)
        .unwrap()
        .with_credential(&b)
        .unwrap();
    let mut bench = osdp_bench(
        17,
        osdp_spec(
            AcuConfig::polling([0x01, 0x02]),
            alloc::vec![PdConfig::at(0x01), PdConfig::at(0x02)],
            access,
        ),
    )
    .unwrap();
    assert_eq!(bench.pds.len(), 2);
    bench.world.run_until(1_000_000).unwrap();

    let (pd1, pd2) = (bench.pds[0], bench.pds[1]);
    bench
        .world
        .present(pd1, 1_000_000, presentation(0, &a))
        .unwrap();
    bench
        .world
        .present(pd2, 1_500_000, presentation(1, &b))
        .unwrap();
    bench.world.run_until(4_000_000).unwrap();

    // Both addresses are polled, both card reads arrive, both doors fire.
    let cmds = commands(&bench.world);
    assert!(cmds.iter().any(|(addr, _)| *addr == 0x01));
    assert!(cmds.iter().any(|(addr, _)| *addr == 0x02));
    let raws: Vec<u8> = bench
        .world
        .log()
        .bus_frames()
        .filter(|(_, _, f)| f.reply_code() == Some(Reply::Raw))
        .map(|(_, _, f)| f.address)
        .collect();
    assert_eq!(raws, alloc::vec![0x01, 0x02]);
    assert_eq!(bench.world.log().strikes().count(), 2);
    // One pair at a time: the bus never had two transmitters at once.
    assert_eq!(
        bench
            .world
            .log()
            .find(|r| matches!(r.kind, RecordKind::BusCollision { .. }))
            .count(),
        0
    );
}

#[test]
fn two_transmitters_at_once_destroy_each_other() {
    let mut bench = osdp_bench(
        18,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();
    let attacker = bench
        .world
        .add_tap(bench.link, Box::new(InjectingTap::new("jammer")))
        .unwrap();
    // Step to the instant a command starts going out, then talk over it.
    bench.world.run_until(10).unwrap();
    bench
        .world
        .inject(
            attacker,
            Injection::bus_bytes(bench.world.now(), BusDir::AcuToPd, alloc::vec![0x53; 8]),
        )
        .unwrap();
    bench.world.run_until(100_000).unwrap();

    assert!(
        bench
            .world
            .log()
            .find(|r| matches!(r.kind, RecordKind::BusCollision { .. }))
            .count()
            > 0,
        "an injector that does not find the gap simply breaks the bus"
    );
}

// ---------------------------------------------------------------------------
// Module 3 — Secure Channel
// ---------------------------------------------------------------------------

#[test]
fn drill_3_2_secure_channel_under_scbk_d_carries_an_encrypted_card_read() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = osdp_bench(
        21,
        osdp_spec(
            AcuConfig::polling([0x01]).with_default_key(ScRequirement::IfAvailable),
            alloc::vec![PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();
    bench.world.run_until(2_000_000).unwrap();

    // The four-frame handshake happened, in order.
    let cmds = commands(&bench.world);
    assert!(cmds.iter().any(|(_, c)| *c == Command::Chlng.to_u8()));
    assert!(cmds.iter().any(|(_, c)| *c == Command::Scrypt.to_u8()));
    let reps = replies(&bench.world);
    assert!(reps.iter().any(|(_, r)| *r == Reply::Ccrypt.to_u8()));
    assert!(reps.iter().any(|(_, r)| *r == Reply::RmacI.to_u8()));

    assert!(bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));
    assert!(bench.world.reader(pd).unwrap().secure_channel_established());
    assert!(bench.world.log().records().iter().any(|r| matches!(
        &r.kind,
        RecordKind::SecureChannel {
            event: ScEvent::Established {
                key_type: KeyType::Default,
                ..
            },
            ..
        }
    )));

    // Now badge in, and check the card read went out encrypted.
    bench
        .world
        .present(pd, 2_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(4_000_000).unwrap();

    let raw = bench
        .world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.reply_code() == Some(Reply::Raw))
        .map(|(_, _, f)| f.clone())
        .expect("a card read crossed the bus");
    assert!(raw.is_encrypted(), "SCS_18, not plaintext");
    assert!(
        RawCardRead::decode(&raw.payload).is_err()
            || RawCardRead::decode(&raw.payload)
                .map(|r| BitVec::from_bools(&r.bits()) != cred.encode().unwrap())
                .unwrap_or(true),
        "the ciphertext is not the card number"
    );
    // But the command byte is still in the clear, which is drill 4.1's point.
    assert_eq!(raw.id, Reply::Raw.to_u8());
    assert_eq!(bench.world.log().strikes().count(), 1);
}

#[test]
fn drill_3_6_an_inline_tap_downgrades_pdcap_and_the_controller_accepts() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    // BOTH ends are configured to require Secure Channel.
    let acu = AcuConfig::polling([0x01]).with_default_key(ScRequirement::Required);
    let pd_cfg = PdConfig::at(0x01).with_default_key(ScRequirement::Required);
    assert!(
        acu.trust_pdcap,
        "the deployed default, and the vulnerability"
    );
    let mut bench = osdp_bench(22, osdp_spec(acu, alloc::vec![pd_cfg], access)).unwrap();
    let pd = bench.pd();

    // One inline implant, four lines of policy.
    let implant = bench
        .world
        .add_tap(
            bench.link,
            Box::new(InlineTap::rewrite_frames("downgrade", |frame| {
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
            })),
        )
        .unwrap();

    bench.world.run_until(2_000_000).unwrap();
    bench
        .world
        .present(pd, 2_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(4_000_000).unwrap();

    // The controller believed the rewritten reply and declined its own policy.
    assert!(bench.world.log().records().iter().any(|r| matches!(
        &r.kind,
        RecordKind::SecureChannel {
            event: ScEvent::Declined {
                reason: ScDecline::PdDoesNotClaimAes128,
                ..
            },
            ..
        }
    )));
    assert!(!bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));
    assert!(!bench.world.reader(pd).unwrap().secure_channel_established());

    // The flag: steady state, card reads, no security block, both ends set to
    // "required".
    let session = bench
        .world
        .controller(bench.controller)
        .unwrap()
        .session(1)
        .unwrap();
    assert_eq!(session.stage, SessionStage::Online);
    let raw = bench
        .world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.reply_code() == Some(Reply::Raw))
        .map(|(_, _, f)| f.clone())
        .expect("a card read crossed the bus");
    assert!(raw.security.is_none(), "no security block at all");
    assert_eq!(
        BitVec::from_bools(&RawCardRead::decode(&raw.payload).unwrap().bits()),
        cred.encode().unwrap(),
        "and the card number is simply readable"
    );
    assert_eq!(bench.world.log().strikes().count(), 1);

    // The PD's own capability report never changed; only the wire did.
    let real = bench.world.reader(pd).unwrap().pd_config().unwrap();
    assert!(real.capabilities.claims_aes128());
    let seen_by_controller = bench
        .world
        .controller(bench.controller)
        .unwrap()
        .session(1)
        .unwrap()
        .capabilities
        .clone()
        .unwrap();
    assert!(!seen_by_controller.claims_aes128());
    assert!(bench.world.log().actions_by(implant).any(|r| matches!(
        r.kind,
        RecordKind::TapAction {
            action: TapAction::Replaced { .. },
            ..
        }
    )));
}

#[test]
fn the_downgrade_fails_against_a_controller_that_does_not_trust_pdcap() {
    let access = AccessList::new();
    let acu = AcuConfig::polling([0x01])
        .with_default_key(ScRequirement::Required)
        .trusting_pdcap(false);
    let pd_cfg = PdConfig::at(0x01).with_default_key(ScRequirement::Required);
    let mut bench = osdp_bench(23, osdp_spec(acu, alloc::vec![pd_cfg], access)).unwrap();

    bench
        .world
        .add_tap(
            bench.link,
            Box::new(InlineTap::rewrite_frames("downgrade", |frame| {
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
            })),
        )
        .unwrap();

    bench.world.run_until(3_000_000).unwrap();
    assert!(
        bench
            .world
            .controller(bench.controller)
            .unwrap()
            .is_secure(1),
        "the handshake ran anyway, and the rewritten claim bought nothing"
    );
}

#[test]
fn a_genuinely_legacy_reader_is_refused_rather_than_downgraded() {
    // The other half of curriculum 5.2: this is what a real legacy PD being
    // added to a hardened bus looks like, and it must not look like an attack.
    let mut pd_cfg = PdConfig::at(0x01);
    pd_cfg.capabilities = default_capabilities(false, false);
    pd_cfg.sc = ScRequirement::Disabled;
    let acu = AcuConfig::polling([0x01])
        .with_default_key(ScRequirement::Required)
        .trusting_pdcap(false);
    let mut bench = osdp_bench(24, osdp_spec(acu, alloc::vec![pd_cfg], AccessList::new())).unwrap();
    bench.world.run_until(3_000_000).unwrap();

    let session = bench
        .world
        .controller(bench.controller)
        .unwrap()
        .session(1)
        .unwrap();
    assert_eq!(session.stage, SessionStage::Refused);
    assert!(!session.secure);
}

#[test]
fn drill_3_4_and_3_5_install_mode_hands_the_site_key_to_the_bus() {
    let site_key = [0x11u8; 16];
    let acu = AcuConfig::polling([0x01])
        .with_site_key(site_key, ScRequirement::IfAvailable)
        .in_install_mode(true);
    // An uncommissioned reader, still on the published default key.
    let pd_cfg = PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable);
    let mut bench = osdp_bench(25, osdp_spec(acu, alloc::vec![pd_cfg], AccessList::new())).unwrap();
    let pd = bench.pd();
    let sniffer = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("installer's friend")))
        .unwrap();

    bench.world.run_until(4_000_000).unwrap();

    // The key was pushed over the bus, inside a channel keyed with the
    // published default — so "secured" and readable by anyone.
    assert!(bench.world.log().records().iter().any(|r| matches!(
        &r.kind,
        RecordKind::SecureChannel {
            event: ScEvent::KeysetSent { .. },
            ..
        }
    )));
    assert!(bench.world.log().records().iter().any(|r| matches!(
        &r.kind,
        RecordKind::SecureChannel {
            event: ScEvent::KeysetAccepted { .. },
            ..
        }
    )));
    // The PD now holds the site key, and the attacker injected nothing.
    assert_eq!(bench.world.reader(pd).unwrap().scbk(), Some(site_key));
    assert_eq!(
        bench
            .world
            .reader(pd)
            .unwrap()
            .pd_config()
            .unwrap()
            .key_type,
        KeyType::SiteKey
    );
    assert_eq!(bench.world.log().injection_count(sniffer), 0);
    // And the whole exchange is in the sniffer's buffer for odr-attack to crack.
    assert!(bench.world.tap(sniffer).unwrap().seen().len() > 6);
    // The session came back up under the new key.
    assert!(bench
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
            .key_type,
        KeyType::SiteKey
    );
}

#[test]
fn drill_3_3_the_pds_configured_key_is_a_question_the_engine_can_answer() {
    let site_key = [0xABu8; 16];
    let bench = osdp_bench(
        26,
        osdp_spec(
            AcuConfig::polling([0x01]).with_site_key(site_key, ScRequirement::IfAvailable),
            alloc::vec![PdConfig::at(0x01).with_site_key(site_key, ScRequirement::IfAvailable)],
            AccessList::new(),
        ),
    )
    .unwrap();
    // "attacker-recovered SCBK equals the PD's configured SCBK" needs this.
    assert_eq!(
        bench.world.reader(bench.pd()).unwrap().scbk(),
        Some(site_key)
    );
    assert_ne!(bench.world.reader(bench.pd()).unwrap().scbk(), Some(SCBK_D));
}

#[test]
fn drill_4_4_the_null_cipher_authenticates_without_hiding_the_card_number() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut acu = AcuConfig::polling([0x01]).with_default_key(ScRequirement::IfAvailable);
    acu.encrypt_payloads = false; // SCS_15/SCS_16
    let mut bench = osdp_bench(
        27,
        osdp_spec(
            acu,
            alloc::vec![PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();
    bench.world.run_until(2_000_000).unwrap();
    assert!(bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));

    // The PD still encrypts its own replies; what the ACU controls is its own
    // commands. Check the command side is MAC-only and readable.
    let polls: Vec<Frame> = bench
        .world
        .log()
        .bus_frames()
        .filter(|(_, dir, f)| *dir == BusDir::AcuToPd && f.command_code() == Some(Command::Poll))
        .map(|(_, _, f)| f.clone())
        .collect();
    assert!(!polls.is_empty());
    assert!(polls.iter().all(|f| !f.is_encrypted()));
    assert!(
        polls.iter().all(|f| f.mac.is_some()),
        "authenticated, not encrypted"
    );
    let _ = pd;
}

// ---------------------------------------------------------------------------
// Taps
// ---------------------------------------------------------------------------

#[test]
fn a_passive_tap_sees_everything_and_changes_nothing() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();

    // Run once with no tap at all.
    let mut clean = wiegand_bench(31, access.clone()).unwrap();
    clean
        .world
        .present(clean.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    clean.world.run_until(5_000_000).unwrap();
    let clean_capture = clean.world.export_capture();

    // And again with a passive tap that tries, and fails, to interfere.
    let mut tapped = wiegand_bench(31, access).unwrap();
    let tap = tapped
        .world
        .add_tap(
            tapped.link,
            Box::new(FnTap::new(
                "nosey",
                TapKind::Passive,
                |_ctx: &mut TapCtx<'_>, _o: &Observation<'_>| TapVerdict::Drop,
            )),
        )
        .unwrap();
    tapped
        .world
        .present(tapped.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    tapped.world.run_until(5_000_000).unwrap();

    assert_eq!(
        tapped.world.export_capture(),
        clean_capture,
        "the wire is byte-identical with the passive tap present"
    );
    assert_eq!(
        tapped.world.door(tapped.door).unwrap().strike_count,
        clean.world.door(clean.door).unwrap().strike_count
    );
    // And the refusal is recorded rather than silently swallowed.
    assert!(tapped.world.log().actions_by(tap).any(|r| matches!(
        r.kind,
        RecordKind::TapAction {
            action: TapAction::VerdictIgnored { .. },
            ..
        }
    )));
}

#[test]
fn a_passive_tap_cannot_transmit_even_when_told_to() {
    let mut bench = wiegand_bench(32, AccessList::allow_all()).unwrap();
    let tap = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("sniffer")))
        .unwrap();
    let bits = card(1, 1).encode().unwrap();
    bench
        .world
        .inject(tap, Injection::wire_bits(1_000_000, bits))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();
    assert_eq!(bench.world.log().injection_count(tap), 0);
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 0);
}

#[test]
fn a_tap_placement_is_reportable_for_the_topology_strip() {
    let mut bench = osdp_bench(
        33,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();
    bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("probe")))
        .unwrap();
    bench
        .world
        .add_tap(bench.link, Box::new(InlineTap::pass_through("implant")))
        .unwrap();

    let places = bench.world.tap_placements(bench.link).unwrap();
    assert_eq!(places.len(), 2);
    let implant = places.iter().find(|p| p.name == "implant").unwrap();
    assert!(implant.cuts_link());
    assert_eq!(implant.segment_controller_side, 0);
    assert_eq!(implant.segment_reader_side, 1);
    assert!(implant.describe().contains("cuts the link"));
    let probe = places.iter().find(|p| p.name == "probe").unwrap();
    assert!(!probe.cuts_link());
    assert_eq!(probe.segment_controller_side, probe.segment_reader_side);
}

#[test]
fn an_inline_tap_that_passes_everything_through_changes_nothing() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = osdp_bench(
        34,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            access,
        ),
    )
    .unwrap();
    bench
        .world
        .add_tap(bench.link, Box::new(InlineTap::pass_through("transparent")))
        .unwrap();
    let pd = bench.pd();
    bench.world.run_until(1_000_000).unwrap();
    bench
        .world
        .present(pd, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();

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
    assert_eq!(bench.world.log().strikes().count(), 1);
}

#[test]
fn a_tap_can_read_a_capability_reply_at_byte_level_and_at_frame_level() {
    use alloc::rc::Rc;
    use core::cell::RefCell;

    let saw_bytes = Rc::new(RefCell::new(0usize));
    let saw_frames = Rc::new(RefCell::new(0usize));
    let saw_security_entry = Rc::new(RefCell::new(false));
    let (b, f, s) = (
        saw_bytes.clone(),
        saw_frames.clone(),
        saw_security_entry.clone(),
    );

    let mut bench = osdp_bench(
        35,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();
    bench
        .world
        .add_tap(
            bench.link,
            Box::new(FnTap::new(
                "both levels",
                TapKind::Passive,
                move |_ctx: &mut TapCtx<'_>, obs: &Observation<'_>| {
                    if let Some(bytes) = obs.bytes() {
                        *b.borrow_mut() += bytes.len();
                    }
                    if let Some(frame) = obs.frame() {
                        *f.borrow_mut() += 1;
                        if frame.reply_code() == Some(Reply::PdCap) {
                            if let Ok(caps) = PdCapabilities::decode(&frame.payload) {
                                if caps
                                    .get(CapabilityFunction::CommunicationSecurity)
                                    .is_some()
                                {
                                    *s.borrow_mut() = true;
                                }
                            }
                        }
                    }
                    TapVerdict::Pass
                },
            )),
        )
        .unwrap();
    bench.world.run_until(1_000_000).unwrap();

    assert!(*saw_bytes.borrow() > 0, "raw octets were available");
    assert!(*saw_frames.borrow() > 0, "and so were decoded frames");
    assert!(
        *saw_security_entry.borrow(),
        "and typed payloads inside them"
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

fn seeded_run(seed: u64) -> (EventLog, alloc::string::String) {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = osdp_bench(
        seed,
        osdp_spec(
            AcuConfig::polling([0x01, 0x02]).with_default_key(ScRequirement::IfAvailable),
            alloc::vec![
                PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable),
                PdConfig::at(0x02),
            ],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();
    bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("probe")))
        .unwrap();
    bench
        .world
        .present(pd, 2_500_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(6_000_000).unwrap();
    let capture = bench.world.export_capture();
    (bench.world.log().clone(), capture)
}

#[test]
fn the_same_seed_produces_a_byte_identical_event_log() {
    let (log_a, cap_a) = seeded_run(0xDEADBEEF);
    let (log_b, cap_b) = seeded_run(0xDEADBEEF);
    assert_eq!(log_a.len(), log_b.len());
    assert_eq!(log_a, log_b, "the whole log, record for record");
    assert_eq!(cap_a, cap_b, "and therefore the capture, byte for byte");
    assert!(log_a.len() > 50, "a run worth comparing: {}", log_a.len());
}

#[test]
fn a_different_seed_changes_the_nonces_and_nothing_else_structural() {
    let (log_a, cap_a) = seeded_run(1);
    let (log_b, cap_b) = seeded_run(2);
    assert_ne!(cap_a, cap_b, "different nonces reach the wire");
    assert_eq!(
        log_a.records().len(),
        log_b.records().len(),
        "but the shape of the run is the same"
    );
}

// ---------------------------------------------------------------------------
// The capture seam
// ---------------------------------------------------------------------------

#[test]
fn a_capture_exports_imports_and_replays() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();

    // 1. Record a run.
    let mut source = osdp_bench(
        41,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            access.clone(),
        ),
    )
    .unwrap();
    let pd = source.pd();
    source.world.run_until(1_000_000).unwrap();
    source
        .world
        .present(pd, 1_000_000, presentation(0, &cred))
        .unwrap();
    source.world.run_until(3_000_000).unwrap();
    let text = source.world.export_capture();

    // 2. It is the format DESIGN.md fixes.
    let first = text.lines().next().unwrap();
    assert!(first.starts_with("{\"t_us\":"));
    assert!(first.contains("\"line\":\"rs485\""));
    assert!(first.contains("\"dir\":\"acu_to_pd\""));

    // 3. Read it back.
    let replay = CaptureReplay::parse(&text).unwrap();
    assert_eq!(replay.len(), text.lines().count());
    assert_eq!(write_ndjson_roundtrip(&replay), text);

    // 4. What it carries survives the trip.
    let frames = replay.osdp_frames();
    assert!(frames
        .iter()
        .any(|(_, d, f)| *d == BusDir::AcuToPd && f.command_code() == Some(Command::Poll)));
    let reads = replay.card_reads();
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].1, cred.encode().unwrap());

    // 5. And replaying it into a fresh world opens the door with no card.
    let mut target = wiegand_bench(42, access).unwrap();
    let injector = target
        .world
        .add_tap(target.link, Box::new(InjectingTap::new("replay box")))
        .unwrap();
    for bits in reads.iter().map(|(_, b)| b.clone()) {
        target
            .world
            .inject(injector, Injection::wire_bits(1_000_000, bits))
            .unwrap();
    }
    target.world.run_until(3_000_000).unwrap();
    assert_eq!(target.world.log().presentations().count(), 0);
    assert_eq!(target.world.door(target.door).unwrap().strike_count, 1);
}

fn write_ndjson_roundtrip(replay: &CaptureReplay) -> alloc::string::String {
    crate::capture::write_ndjson(replay.events())
}

#[test]
fn a_wiegand_capture_round_trips_through_the_byte_padded_format() {
    let cred = card(42, 1337);
    let mut bench = wiegand_bench(43, AccessList::allow_all()).unwrap();
    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();

    let text = bench.world.export_capture();
    assert!(text.contains("\"line\":\"wiegand\""));
    assert!(text.contains("\"dir\":\"wire\""));
    let replay = CaptureReplay::parse(&text).unwrap();
    // 26 bits became 4 bytes; the importer has to guess the bit count back.
    assert_eq!(replay.events()[0].bytes.len(), 4);
    assert_eq!(replay.card_reads()[0].1, cred.encode().unwrap());
    // And the exact-format path does not have to guess.
    let exact = replay.injections(0, ReplayTarget::WireExact(CardFormat::H10301));
    assert_eq!(exact.len(), 1);
    match &exact[0].payload {
        InjectionPayload::WireBits { bits } => assert_eq!(*bits, cred.encode().unwrap()),
        other => panic!("wrong payload: {other:?}"),
    }
}

#[test]
fn a_capture_taken_from_one_probe_is_that_probes_view() {
    let cred = card(42, 1337);
    let mut bench = osdp_bench(
        44,
        osdp_spec(
            AcuConfig::polling([0x01]),
            alloc::vec![PdConfig::at(0x01)],
            AccessList::allow_all(),
        ),
    )
    .unwrap();
    let probe = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("probe")))
        .unwrap();
    let pd = bench.pd();
    bench.world.run_until(1_000_000).unwrap();
    bench
        .world
        .present(pd, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();

    let whole = bench.world.export_capture();
    let from_probe = export_from_tap(bench.world.tap(probe).unwrap(), &CaptureOptions::default());
    // One segment, one probe: the two agree.
    assert_eq!(whole.lines().count(), from_probe.lines().count());
    assert!(CaptureReplay::parse(&from_probe).is_ok());
}

// ---------------------------------------------------------------------------
// Doors
// ---------------------------------------------------------------------------

#[test]
fn request_to_exit_opens_the_door_without_any_credential() {
    let mut bench = wiegand_bench(51, AccessList::deny_all()).unwrap();
    bench.world.set_rex(bench.door, 1_000_000, true).unwrap();
    bench.world.run_until(2_000_000).unwrap();
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 1);
    assert_eq!(bench.world.log().decisions().count(), 0);
    assert!(bench
        .world
        .log()
        .records()
        .iter()
        .any(|r| matches!(r.kind, RecordKind::RequestToExit { asserted: true, .. })));
}

#[test]
fn the_door_position_switch_is_independent_of_the_lock() {
    let mut bench = wiegand_bench(52, AccessList::deny_all()).unwrap();
    bench
        .world
        .set_door_position(bench.door, 500_000, true)
        .unwrap();
    bench.world.run_until(1_000_000).unwrap();
    let d = bench.world.door(bench.door).unwrap();
    assert!(d.is_open());
    assert!(d.lock.is_locked(), "propped open while still locked");
}

// ---------------------------------------------------------------------------
// Engine invariants
// ---------------------------------------------------------------------------

#[test]
fn stepping_one_event_at_a_time_gives_the_same_result_as_running() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();

    let mut a = wiegand_bench(61, access.clone()).unwrap();
    a.world
        .present(a.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    a.world.run_until(9_000_000).unwrap();

    let mut b = wiegand_bench(61, access).unwrap();
    b.world
        .present(b.reader, 1_000_000, presentation(0, &cred))
        .unwrap();
    while b.world.now() < 9_000_000 {
        if !b.world.step().unwrap() {
            break;
        }
    }
    assert_eq!(a.world.log().records(), b.world.log().records());
}

#[test]
fn the_clock_never_goes_backwards() {
    let cred = card(42, 1337);
    let mut bench = osdp_bench(
        62,
        osdp_spec(
            AcuConfig::polling([0x01]).with_default_key(ScRequirement::IfAvailable),
            alloc::vec![PdConfig::at(0x01).with_default_key(ScRequirement::IfAvailable)],
            AccessList::allow_all(),
        ),
    )
    .unwrap();
    let pd = bench.pd();
    bench
        .world
        .present(pd, 1_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(5_000_000).unwrap();
    let mut last = 0;
    for r in bench.world.log().records() {
        assert!(r.t_us >= last, "record {} went backwards", r.seq);
        last = r.t_us;
    }
}

#[test]
fn unknown_handles_are_errors_rather_than_panics() {
    let mut w = World::new(1);
    assert_eq!(
        w.reader(ReaderId(9)).unwrap_err(),
        BusError::UnknownReader(ReaderId(9))
    );
    assert_eq!(
        w.door(DoorId(9)).unwrap_err(),
        BusError::UnknownDoor(DoorId(9))
    );
    assert_eq!(
        w.link(LinkId(9)).unwrap_err(),
        BusError::UnknownLink(LinkId(9))
    );
    assert_eq!(
        w.tap_kind(TapId(9)).unwrap_err(),
        BusError::UnknownTap(TapId(9))
    );
    assert!(w
        .present(ReaderId(9), 0, presentation(0, &card(1, 1)))
        .is_err());
    assert!(w
        .inject(TapId(9), Injection::wire_bits(0, BitVec::new()))
        .is_err());
    assert_eq!(w.run_until(1_000_000).unwrap(), 0);
}

#[test]
fn a_reader_with_no_link_says_so_instead_of_vanishing() {
    let mut w = World::new(1);
    let r = w.add_reader(Reader::new(ReaderId(0), "loose", ReaderProtocol::Wiegand));
    w.present(r, 0, presentation(0, &card(1, 1))).unwrap();
    w.run_until(1_000_000).unwrap();
    assert!(w
        .log()
        .records()
        .iter()
        .any(|rec| matches!(rec.kind, RecordKind::CredentialRejected { .. })));
}

#[test]
fn the_credential_seam_works_from_the_pull_side_too() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = wiegand_bench(63, access).unwrap();
    bench
        .world
        .attach_source(
            bench.reader,
            Box::new(StaticToken::new(presentation(0, &cred))),
        )
        .unwrap();
    bench
        .world
        .present_attached(bench.reader, 1_000_000)
        .unwrap();
    bench
        .world
        .present_attached(bench.reader, 6_000_000)
        .unwrap();
    bench.world.run_until(9_000_000).unwrap();
    assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 2);
}

#[test]
fn a_scripted_token_runs_out_and_the_reader_reports_it() {
    let cred = card(42, 1337);
    let mut bench = wiegand_bench(64, AccessList::allow_all()).unwrap();
    bench
        .world
        .attach_source(
            bench.reader,
            Box::new(ScriptedToken::new(
                SourceId(3),
                alloc::vec![presentation(3, &cred)],
            )),
        )
        .unwrap();
    bench
        .world
        .present_attached(bench.reader, 1_000_000)
        .unwrap();
    bench
        .world
        .present_attached(bench.reader, 6_000_000)
        .unwrap();
    bench.world.run_until(9_000_000).unwrap();
    assert_eq!(bench.world.log().presentations().count(), 1);
    assert!(bench
        .world
        .log()
        .records()
        .iter()
        .any(|r| matches!(&r.kind, RecordKind::CredentialRejected { .. })));
}

#[test]
fn drill_0_2_a_clone_is_distinguishable_from_its_original() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = wiegand_bench(65, access).unwrap();

    // Identical bits, different physical token.
    let clone = presentation(1, &cred).labelled("cloned tag");
    bench.world.present(bench.reader, 1_000_000, clone).unwrap();
    bench.world.run_until(3_000_000).unwrap();

    assert_eq!(bench.world.log().grants().count(), 1);
    let original_ever_presented = bench.world.log().presentations().any(|r| {
        matches!(&r.kind, RecordKind::CredentialPresented { source, .. } if *source == SourceId(0))
    });
    assert!(
        !original_ever_presented,
        "only the clone was ever presented"
    );
}

#[test]
fn a_note_lands_in_the_log_for_the_drill_narrative() {
    let mut w = World::new(1);
    w.note("about to do something interesting");
    assert!(w
        .log()
        .records()
        .iter()
        .any(|r| matches!(&r.kind, RecordKind::Note { text } if text.contains("interesting"))));
}

#[test]
fn an_endless_scenario_hits_the_step_budget_instead_of_hanging() {
    let mut bench = osdp_bench(
        66,
        osdp_spec(
            AcuConfig {
                poll_interval_us: 0,
                ..AcuConfig::polling([0x01])
            },
            alloc::vec![PdConfig::at(0x01)],
            AccessList::new(),
        ),
    )
    .unwrap();
    bench.world.step_budget = 500;
    let err = bench.world.run_until(u64::MAX).unwrap_err();
    assert!(matches!(err, BusError::Config(_)));
}

#[test]
fn drill_1_2_a_forged_frame_with_valid_parity_reaches_the_panel() {
    // Two cards are on the list; only one is ever presented. An injector puts
    // the other one on the wire, parity recomputed, and the panel takes it.
    let presented = card(42, 1337);
    let never_presented = card(42, 9999);
    let access = AccessList::new()
        .with_credential(&presented)
        .unwrap()
        .with_credential(&never_presented)
        .unwrap()
        .assuming(CardFormat::H10301);
    let mut bench = wiegand_bench(71, access).unwrap();
    let injector = bench
        .world
        .add_tap(bench.link, Box::new(InjectingTap::new("bit flipper")))
        .unwrap();

    bench
        .world
        .present(bench.reader, 1_000_000, presentation(0, &presented))
        .unwrap();
    bench.world.run_until(2_000_000).unwrap();
    bench
        .world
        .inject(
            injector,
            Injection::wire_bits(10_000_000, never_presented.encode().unwrap()),
        )
        .unwrap();
    bench.world.run_until(12_000_000).unwrap();

    // The flag, exactly as the curriculum words it.
    let second = bench.world.log().grants().nth(1).cloned().unwrap();
    let bits = match &second.kind {
        RecordKind::AccessDecision { bits, .. } => bits.clone(),
        _ => unreachable!(),
    };
    let decoded = odr_wiegand::decode(CardFormat::H10301, &bits).unwrap();
    assert!(
        decoded.parity_valid(),
        "it parses cleanly with valid parity"
    );
    assert_eq!(decoded.card_number, Some(9999));
    let ever_presented =
        bench.world.log().presentations().any(
            |r| matches!(&r.kind, RecordKind::CredentialPresented { bits: b, .. } if *b == bits),
        );
    assert!(!ever_presented, "and no such credential was ever presented");
}

#[test]
fn drill_4_1_the_command_byte_is_readable_on_a_fully_encrypted_bus() {
    let cred = card(42, 1337);
    let access = AccessList::new().with_credential(&cred).unwrap();
    let mut bench = osdp_bench(
        72,
        osdp_spec(
            AcuConfig::polling([0x01]).with_default_key(ScRequirement::Required),
            alloc::vec![PdConfig::at(0x01).with_default_key(ScRequirement::Required)],
            access,
        ),
    )
    .unwrap();
    let pd = bench.pd();
    let monitor = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("monitor")))
        .unwrap();
    bench.world.run_until(2_000_000).unwrap();
    assert!(bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));

    bench
        .world
        .present(pd, 3_000_000, presentation(0, &cred))
        .unwrap();
    bench.world.run_until(6_000_000).unwrap();

    // With no key at all, name every frame and time the badge-in.
    let badge_times: Vec<Micros> = bench
        .world
        .tap(monitor)
        .unwrap()
        .seen()
        .iter()
        .filter(|s| {
            s.frame()
                .is_some_and(|f| f.is_reply && f.reply_code() == Some(Reply::Raw))
        })
        .map(|s| s.t_us)
        .collect();
    assert_eq!(
        badge_times.len(),
        1,
        "one badge-in, visible through the crypto"
    );
    let strike = bench.world.log().strikes().next().unwrap();
    assert!(
        strike.t_us >= badge_times[0] && strike.t_us - badge_times[0] < 500_000,
        "and it lines up with the door opening"
    );
    // The card number itself stayed hidden.
    let raw = bench
        .world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.reply_code() == Some(Reply::Raw))
        .map(|(_, _, f)| f.clone())
        .unwrap();
    assert!(raw.is_encrypted());
    assert_ne!(
        raw.payload,
        RawCardRead::from_bits(0, 0, cred.encode().unwrap().as_slice()).encode()
    );
}

#[test]
fn a_pd_that_refuses_clear_text_turns_the_downgrade_into_a_denial_of_service() {
    let acu = AcuConfig::polling([0x01]).with_default_key(ScRequirement::Required);
    let mut pd_cfg = PdConfig::at(0x01).with_default_key(ScRequirement::Required);
    pd_cfg.answer_clear_when_required = false;
    let mut bench = osdp_bench(73, osdp_spec(acu, alloc::vec![pd_cfg], AccessList::new())).unwrap();
    bench
        .world
        .add_tap(
            bench.link,
            Box::new(InlineTap::rewrite_frames("downgrade", |frame| {
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
            })),
        )
        .unwrap();
    bench.world.run_until(3_000_000).unwrap();

    assert!(!bench
        .world
        .controller(bench.controller)
        .unwrap()
        .is_secure(1));
    assert!(
        bench.world.log().records().iter().any(|r| matches!(
            &r.kind,
            RecordKind::Protocol {
                event: ProtocolEvent::Nak { .. },
                ..
            }
        )),
        "the reader refuses every clear-text command instead of serving them"
    );
    assert_eq!(bench.world.log().strikes().count(), 0);
}
