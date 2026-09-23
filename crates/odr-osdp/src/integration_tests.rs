//! Cross-module tests: things that only mean something when the whole crate is
//! wired together.
//!
//! Where the per-module tests check a unit, these check a *claim* the range
//! makes to a learner. If one of these fails, a drill would be teaching
//! something untrue.

use crate::channel::{recover_weak_scbk, ChannelError, SecureChannel};
use crate::codes::{Command, Reply};
use crate::frame::{Frame, ScanEvent, Scanner};
use crate::payload::{
    Capability, CapabilityFunction, Ccrypt, KeysetCommand, Nak, NakError, OutputCommand,
    PdCapabilities, RawCardRead,
};
use crate::rng::SeededRng;
use crate::security::{KeyType, ScsType, SecurityBlock};
use crate::weak_keys::{is_weak, SCBK_D};
use alloc::vec;
use alloc::vec::Vec;

/// Every command code must survive a full encode/parse round trip, with and
/// without a payload, a mark byte, a security block and both trailer kinds.
#[test]
fn every_command_code_round_trips_through_the_wire() {
    let mut rng = SeededRng::new(1);
    for &code in Command::ALL {
        for variant in 0..8u8 {
            let payload: Vec<u8> = (0..(variant as usize * 3)).map(|_| rng.next_u8()).collect();
            let mut f = Frame::command(variant & 0x7F, variant & 0x03, code, payload.clone());
            f.mark = variant & 0x01 != 0;
            f.use_crc = variant & 0x02 == 0;
            if variant & 0x04 != 0 {
                f.security = Some(SecurityBlock::new(ScsType::CmdMacOnly));
                f.mac = Some([1, 2, 3, 4]);
            }
            let wire = f.encode();
            let (parsed, used) = Frame::parse(&wire)
                .unwrap_or_else(|e| panic!("{code} variant {variant} failed to parse: {e}"));
            assert_eq!(used, wire.len(), "{code} variant {variant}");
            assert_eq!(parsed, f, "{code} variant {variant}");
            assert_eq!(parsed.command_code(), Some(code));
            assert_eq!(parsed.payload, payload);
            assert_eq!(parsed.encode(), wire);
        }
    }
}

/// Same, for every reply code.
#[test]
fn every_reply_code_round_trips_through_the_wire() {
    let mut rng = SeededRng::new(2);
    for &code in Reply::ALL {
        for variant in 0..8u8 {
            let payload: Vec<u8> = (0..(variant as usize * 5)).map(|_| rng.next_u8()).collect();
            let mut f = Frame::reply(variant & 0x7F, variant & 0x03, code, payload.clone());
            f.mark = variant & 0x01 != 0;
            f.use_crc = variant & 0x02 == 0;
            if variant & 0x04 != 0 {
                f.security = Some(SecurityBlock::new(ScsType::ReplyEncrypted));
                f.mac = Some([9, 8, 7, 6]);
            }
            let wire = f.encode();
            let (parsed, used) = Frame::parse(&wire)
                .unwrap_or_else(|e| panic!("{code} variant {variant} failed to parse: {e}"));
            assert_eq!(used, wire.len(), "{code} variant {variant}");
            assert_eq!(parsed, f, "{code} variant {variant}");
            assert_eq!(parsed.reply_code(), Some(code));
            assert_eq!(parsed.encode(), wire);
        }
    }
}

/// Every security block type must survive the wire too.
#[test]
fn every_security_block_type_round_trips() {
    for raw in 0x11u8..=0x18 {
        let scs = ScsType::from_u8(raw).unwrap();
        let mut f = if scs.is_command_side() {
            Frame::command(1, 0, Command::Poll, vec![0xAB; 16])
        } else {
            Frame::reply(1, 0, Reply::Ack, vec![0xAB; 16])
        };
        f.security = Some(if scs.is_handshake() {
            SecurityBlock::with_byte(scs, 0x01)
        } else {
            SecurityBlock::new(scs)
        });
        if scs.has_mac() {
            f.mac = Some([0xCA, 0xFE, 0xBA, 0xBE]);
        }
        let wire = f.encode();
        let (parsed, _) = Frame::parse(&wire).unwrap();
        assert_eq!(parsed, f, "SCS 0x{raw:02x}");
        assert_eq!(parsed.scs_type(), Some(scs));
        assert_eq!(parsed.payload.len(), 16, "SCS 0x{raw:02x} payload intact");
    }
}

/// A realistic bus transcript: address, poll, capability exchange, card read,
/// door open. Scanned as one byte stream, exactly as a capture would arrive.
fn quiet_bus_transcript() -> (Vec<u8>, usize) {
    let mut wire = Vec::new();
    let mut count = 0;
    let caps = PdCapabilities {
        entries: vec![
            Capability::new(CapabilityFunction::ContactStatusMonitoring, 1, 2),
            Capability::new(CapabilityFunction::OutputControl, 1, 1),
            Capability::new(CapabilityFunction::CommunicationSecurity, 0x01, 0x01),
            Capability::new(CapabilityFunction::Readers, 1, 1),
        ],
    };
    let card = RawCardRead::from_bits(0, 0, &(0..26).map(|i| i % 4 == 0).collect::<Vec<_>>());

    let frames: Vec<Frame> = vec![
        Frame::command(1, 0, Command::Poll, vec![]),
        Frame::reply(1, 0, Reply::Ack, vec![]),
        Frame::command(1, 1, Command::Cap, vec![0x00]),
        Frame::reply(1, 1, Reply::PdCap, caps.encode()),
        Frame::command(1, 2, Command::Poll, vec![]),
        Frame::reply(1, 2, Reply::Raw, card.encode()),
        Frame::command(
            1,
            3,
            Command::Out,
            OutputCommand {
                output: 0,
                control_code: 1,
                timer_100ms: 50,
            }
            .encode(),
        ),
        Frame::reply(1, 3, Reply::Ack, vec![]),
        Frame::command(1, 0, Command::Poll, vec![]),
        Frame::reply(1, 0, Reply::Nak, Nak::new(NakError::SequenceNumber).encode()),
    ];
    for f in &frames {
        wire.extend(f.encode());
        count += 1;
    }
    (wire, count)
}

#[test]
fn a_whole_transcript_scans_and_decodes() {
    let (wire, expected) = quiet_bus_transcript();
    let frames: Vec<Frame> = Scanner::new(&wire)
        .map(|e| match e {
            ScanEvent::Frame { frame, .. } => *frame,
            other => panic!("unexpected scan event: {other:?}"),
        })
        .collect();
    assert_eq!(frames.len(), expected);

    // The capability reply decodes and claims AES-128 with the default key.
    let caps = PdCapabilities::decode(&frames[3].payload).unwrap();
    assert!(caps.claims_aes128());
    assert!(caps.uses_default_key());

    // The card read decodes to 26 bits.
    let card = RawCardRead::decode(&frames[5].payload).unwrap();
    assert_eq!(card.bit_count, 26);
    assert_eq!(card.bits().len(), 26);

    // The output command opens the door for five seconds.
    let out = OutputCommand::decode(&frames[6].payload).unwrap();
    assert_eq!(out.timer_100ms, 50);

    // The NAK decodes to a sequence error.
    let nak = Nak::decode(&frames[9].payload).unwrap();
    assert_eq!(nak.error(), Some(NakError::SequenceNumber));
}

#[test]
fn a_transcript_with_noise_and_corruption_still_yields_the_good_frames() {
    let (clean, expected) = quiet_bus_transcript();
    // A false start: 0xFF 0x53 looks exactly like mark-plus-SOM, and the bytes
    // after it read as a length far past the end of the capture. An offline
    // scanner must step over this rather than giving up.
    let prefix: &[u8] = &[0x00, 0xFF, 0x53, 0x01];
    let mut noisy = prefix.to_vec();
    noisy.extend_from_slice(&clean);
    noisy.extend_from_slice(&[0x12, 0x34, 0x56]); // trailing junk

    // Corrupt the CRC of the very first real frame (an 8-byte POLL).
    let poll_len = Frame::command(1, 0, Command::Poll, vec![]).wire_len();
    noisy[prefix.len() + poll_len - 2] ^= 0x55;

    let mut good = 0;
    let mut malformed = 0;
    let mut incomplete = 0;
    for event in Scanner::offline(&noisy) {
        match event {
            ScanEvent::Frame { .. } => good += 1,
            ScanEvent::Malformed { .. } => malformed += 1,
            ScanEvent::Incomplete { .. } => incomplete += 1,
            ScanEvent::Garbage { .. } => {}
        }
    }
    assert!(malformed >= 1, "the corrupted CRC was noticed");
    assert!(incomplete >= 1, "the false 0xFF 0x53 start was noticed");
    assert_eq!(
        good,
        expected - 1,
        "every frame but the corrupted one was recovered"
    );
}

/// A streaming scan must stop at a truncation and hand back the tail, so the
/// caller can complete the frame when more bytes arrive.
#[test]
fn streaming_and_offline_scanners_treat_truncation_differently() {
    let whole = Frame::command(1, 0, Command::Id, vec![0xAA; 4]).encode();
    let mut stream = Frame::reply(1, 0, Reply::Ack, vec![]).encode();
    stream.extend_from_slice(&whole[..whole.len() - 3]);

    let mut streaming = Scanner::new(&stream);
    let events: Vec<ScanEvent> = streaming.by_ref().collect();
    assert!(matches!(events.last(), Some(ScanEvent::Incomplete { .. })));
    assert!(!streaming.remaining().is_empty(), "the tail is retained");

    // Offline sees the same truncation but runs to the end of the buffer.
    let offline: Vec<ScanEvent> = Scanner::offline(&stream).collect();
    assert!(offline
        .iter()
        .any(|e| matches!(e, ScanEvent::Incomplete { .. })));
    assert!(offline.len() > events.len());
}

/// Mellon attack 2: rewrite `REPLY_PDCAP` in flight and watch a
/// crypto-capable reader turn into a legacy one. Done entirely with real
/// frames — parse, edit, re-encode, re-parse.
#[test]
fn downgrade_attack_rewrites_a_real_frame() {
    let honest = PdCapabilities {
        entries: vec![
            Capability::new(CapabilityFunction::ContactStatusMonitoring, 1, 2),
            Capability::new(CapabilityFunction::CommunicationSecurity, 0x01, 0x00),
            Capability::new(CapabilityFunction::Readers, 1, 1),
        ],
    };
    let original = Frame::reply(1, 1, Reply::PdCap, honest.encode()).encode();

    // The implant sees the bytes, and only the bytes.
    let (mut frame, _) = Frame::parse(&original).unwrap();
    assert_eq!(frame.reply_code(), Some(Reply::PdCap));
    let mut caps = PdCapabilities::decode(&frame.payload).unwrap();
    assert!(caps.claims_aes128());
    assert!(caps.strip_security_capability());
    frame.payload = caps.encode();
    let tampered = frame.encode();

    // Nothing about the tampered frame is detectable: the length field and CRC
    // are recomputed, and nothing in this exchange is authenticated.
    assert_ne!(tampered, original);
    assert!(tampered.len() < original.len(), "3 bytes shorter");
    let (victim, used) = Frame::parse(&tampered).expect("a perfectly valid frame");
    assert_eq!(used, tampered.len());
    let seen = PdCapabilities::decode(&victim.payload).unwrap();
    assert!(
        !seen.claims_aes128(),
        "the controller now believes the reader cannot do crypto"
    );
    assert_eq!(seen.entries.len(), 2, "the other capabilities are untouched");
}

/// Mellon attack 5: the site key crossing the bus during commissioning, and a
/// sniffer picking it up out of plain wire bytes.
#[test]
fn keyset_capture_recovers_the_site_key_from_the_wire() {
    let mut rng = SeededRng::new(0xC0FFEE);
    let site_key = rng.key16();
    let frame = Frame::command(
        1,
        2,
        Command::Keyset,
        KeysetCommand::scbk(site_key).encode(),
    );
    let wire = frame.encode();

    // The attacker has bytes and nothing else.
    let sniffed: Vec<Frame> = Scanner::new(&wire)
        .filter_map(|e| match e {
            ScanEvent::Frame { frame, .. } => Some(*frame),
            _ => None,
        })
        .collect();
    assert_eq!(sniffed.len(), 1);
    assert_eq!(sniffed[0].command_code(), Some(Command::Keyset));
    assert!(sniffed[0].security.is_none(), "sent with no secure channel");

    let recovered = KeysetCommand::decode(&sniffed[0].payload)
        .unwrap()
        .as_aes128()
        .unwrap();
    assert_eq!(recovered, site_key);
    assert!(!is_weak(&recovered), "a good key, leaked anyway");

    // And the recovered key really does open the session that follows.
    let mut acu = SecureChannel::acu(site_key, KeyType::SiteKey);
    let mut pd = SecureChannel::pd(recovered, KeyType::SiteKey, [5; 8]);
    let chlng = acu.challenge(1, 0, rng.nonce8()).unwrap();
    let ccrypt = pd.handle_challenge(&chlng, rng.nonce8()).unwrap();
    let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
    let rmac = pd.handle_scrypt(&scrypt).unwrap();
    acu.handle_rmac_i(&rmac).unwrap();
    assert!(acu.state().is_established());
}

/// The traffic-analysis claim, stated as a test: on a fully encrypted session,
/// an observer with **no key material at all** can still tell that a card was
/// presented and a door was opened.
#[test]
fn traffic_analysis_works_on_a_fully_encrypted_session() {
    let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
    let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [0x42; 8]);
    let chlng = acu.challenge(1, 0, [0x31; 8]).unwrap();
    let ccrypt = pd.handle_challenge(&chlng, [0x13; 8]).unwrap();
    let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
    let rmac = pd.handle_scrypt(&scrypt).unwrap();
    acu.handle_rmac_i(&rmac).unwrap();

    let card = RawCardRead::from_bits(0, 0, &(0..26).map(|i| i % 5 == 0).collect::<Vec<_>>());
    let mut wire = Vec::new();
    // Two idle poll cycles, then a badge-in.
    for seq in [1u8, 2] {
        wire.extend(acu.seal(1, seq, Command::Poll.to_u8(), &[], true).unwrap().encode());
        wire.extend(pd.seal(1, seq, Reply::Ack.to_u8(), &[], true).unwrap().encode());
    }
    wire.extend(acu.seal(1, 3, Command::Poll.to_u8(), &[], true).unwrap().encode());
    wire.extend(
        pd.seal(1, 3, Reply::Raw.to_u8(), &card.encode(), true)
            .unwrap()
            .encode(),
    );
    wire.extend(
        acu.seal(1, 0, Command::Out.to_u8(), &[0, 1, 50, 0], true)
            .unwrap()
            .encode(),
    );
    wire.extend(pd.seal(1, 0, Reply::Ack.to_u8(), &[], true).unwrap().encode());

    // The observer parses. It has no keys.
    let observed: Vec<Frame> = Scanner::new(&wire)
        .filter_map(|e| match e {
            ScanEvent::Frame { frame, .. } => Some(*frame),
            _ => None,
        })
        .collect();
    assert_eq!(observed.len(), 8);

    // It can name every single frame.
    let story: Vec<&str> = observed
        .iter()
        .map(|f| {
            if f.is_reply {
                f.reply_code().unwrap().name()
            } else {
                f.command_code().unwrap().name()
            }
        })
        .collect();
    assert_eq!(
        story,
        vec!["POLL", "ACK", "POLL", "ACK", "POLL", "RAW", "OUT", "ACK"]
    );

    // It can find the badge-in and the unlock without any key.
    let credential_at = observed
        .iter()
        .position(|f| f.reply_code().is_some_and(Reply::is_credential_event))
        .expect("a card read is visible");
    assert_eq!(credential_at, 5);
    let unlock_at = observed
        .iter()
        .position(|f| f.command_code() == Some(Command::Out))
        .expect("the door opening is visible");
    assert_eq!(unlock_at, 6);

    // What it cannot do is read the card number.
    let raw_frame = &observed[credential_at];
    assert!(raw_frame.is_encrypted());
    assert!(
        !raw_frame
            .payload
            .windows(card.data.len())
            .any(|w| w == card.data.as_slice()),
        "the card bits are not recoverable from the ciphertext"
    );
}

/// The full attack chain: sniff a handshake, crack a weak key, derive the
/// session keys, and decrypt traffic the attacker never participated in.
#[test]
fn a_weak_key_turns_a_passive_capture_into_full_plaintext() {
    let weak_key = [0x41u8; 16]; // "AAAA..." — a repeated-byte sample key
    assert!(is_weak(&weak_key));

    let mut acu = SecureChannel::acu(weak_key, KeyType::SiteKey);
    let mut pd = SecureChannel::pd(weak_key, KeyType::SiteKey, [0x11; 8]);
    let rnd_a = [0x9Au8; 8];

    let mut wire = Vec::new();
    let chlng = acu.challenge(1, 0, rnd_a).unwrap();
    wire.extend(chlng.encode());
    let ccrypt = pd.handle_challenge(&chlng, [0xA9; 8]).unwrap();
    wire.extend(ccrypt.encode());
    let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
    wire.extend(scrypt.encode());
    let rmac = pd.handle_scrypt(&scrypt).unwrap();
    wire.extend(rmac.encode());
    acu.handle_rmac_i(&rmac).unwrap();

    let secret = b"facility 42 card 1337";
    let cmd = acu
        .seal(1, 1, Command::Mfg.to_u8(), secret, true)
        .unwrap();
    wire.extend(cmd.encode());

    // ---- attacker, holding only `wire` ----
    let captured: Vec<Frame> = Scanner::new(&wire)
        .filter_map(|e| match e {
            ScanEvent::Frame { frame, .. } => Some(*frame),
            _ => None,
        })
        .collect();
    assert_eq!(captured.len(), 5);

    let chlng_f = &captured[0];
    assert_eq!(chlng_f.command_code(), Some(Command::Chlng));
    assert_eq!(
        chlng_f.security.as_ref().unwrap().key_type(),
        Some(KeyType::SiteKey),
        "the bus even announces that a real site key is in use"
    );
    let mut sniffed_rnd_a = [0u8; 8];
    sniffed_rnd_a.copy_from_slice(&chlng_f.payload[..8]);

    let body = Ccrypt::decode(&captured[1].payload).unwrap();
    let (cracked, pattern) =
        recover_weak_scbk(&sniffed_rnd_a, &body.rnd_b, &body.client_cryptogram)
            .expect("the key is in the published family");
    assert_eq!(cracked, weak_key);
    assert_eq!(pattern, crate::weak_keys::WeakKeyPattern::Repeated { byte: 0x41 });

    // With the key, the attacker replays the handshake as a PD to reach the
    // same session state, then opens the traffic.
    let mut shadow_acu = SecureChannel::acu(cracked, KeyType::SiteKey);
    let mut shadow_pd = SecureChannel::pd(cracked, KeyType::SiteKey, body.cuid);
    let c = shadow_acu.challenge(1, 0, sniffed_rnd_a).unwrap();
    let cc = shadow_pd.handle_challenge(&c, body.rnd_b).unwrap();
    let sc = shadow_acu.handle_ccrypt(&cc, 1).unwrap();
    let rm = shadow_pd.handle_scrypt(&sc).unwrap();
    shadow_acu.handle_rmac_i(&rm).unwrap();

    let recovered = shadow_pd
        .open(&captured[4])
        .expect("the captured command opens under the cracked key");
    assert_eq!(recovered, secret);
}

/// A strong key defeats the whole chain above, which is the defensive lesson.
#[test]
fn a_strong_key_defeats_the_same_capture() {
    let mut rng = SeededRng::new(0xDEFEA7);
    let good_key = rng.key16();
    assert!(!is_weak(&good_key));

    let mut acu = SecureChannel::acu(good_key, KeyType::SiteKey);
    let mut pd = SecureChannel::pd(good_key, KeyType::SiteKey, [1; 8]);
    let rnd_a = rng.nonce8();
    let chlng = acu.challenge(1, 0, rnd_a).unwrap();
    let ccrypt = pd.handle_challenge(&chlng, rng.nonce8()).unwrap();
    let body = Ccrypt::decode(&ccrypt.payload).unwrap();

    assert_eq!(
        recover_weak_scbk(&rnd_a, &body.rnd_b, &body.client_cryptogram),
        None,
        "768 candidates, none of them right"
    );
}

/// An attacker who forges a session frame without the key is rejected, and the
/// odds are exactly the 32 bits of MAC.
#[test]
fn a_forged_session_frame_is_rejected() {
    let mut acu = SecureChannel::acu(SCBK_D, KeyType::Default);
    let mut pd = SecureChannel::pd(SCBK_D, KeyType::Default, [1; 8]);
    let chlng = acu.challenge(1, 0, [1; 8]).unwrap();
    let ccrypt = pd.handle_challenge(&chlng, [2; 8]).unwrap();
    let scrypt = acu.handle_ccrypt(&ccrypt, 1).unwrap();
    let rmac = pd.handle_scrypt(&scrypt).unwrap();
    acu.handle_rmac_i(&rmac).unwrap();

    let mut forged = Frame::command(1, 1, Command::Out, vec![0x00; 16]);
    forged.security = Some(SecurityBlock::new(ScsType::CmdEncrypted));
    let mut rng = SeededRng::new(13);
    let mut attempts = 0;
    for _ in 0..200 {
        let mut mac = [0u8; 4];
        rng.fill(&mut mac);
        forged.mac = Some(mac);
        attempts += 1;
        assert!(
            matches!(pd.open(&forged), Err(ChannelError::MacMismatch { .. })),
            "guess {attempts} must not succeed"
        );
    }
}

/// The whole crate must never panic on hostile input, whichever door it comes
/// in through.
#[test]
fn nothing_panics_on_random_streams() {
    let mut rng = SeededRng::new(0xFACADE);
    for _ in 0..500 {
        let len = (rng.next_u64() % 256) as usize;
        let mut buf = alloc::vec![0u8; len];
        rng.fill(&mut buf);
        for event in Scanner::new(&buf) {
            if let ScanEvent::Frame { frame, .. } = event {
                let _ = PdCapabilities::decode(&frame.payload);
                let _ = RawCardRead::decode(&frame.payload);
                let _ = KeysetCommand::decode(&frame.payload);
                let _ = Nak::decode(&frame.payload);
                let _ = Ccrypt::decode(&frame.payload);
                let _ = frame.encode();
            }
        }
    }
}
