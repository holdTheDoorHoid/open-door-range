//! Integration tests against known vectors and an independent reference.
//!
//! The unit tests inside the crate check that the code agrees with itself.
//! These check that it agrees with something *outside* itself:
//!
//! * hand-computed bit patterns for H10301 and for an ABA track, written out
//!   bit by bit from the format description rather than from this crate;
//! * a second, deliberately ugly implementation of the two bit-twiddly formats
//!   (H10301 and Corporate 1000) transcribed from the widely reviewed
//!   `wiegand_formats.c` in the RfidResearchGroup Proxmark3 client, compared
//!   against this crate's declarative implementation over the whole
//!   interesting range of inputs.
//!
//! The second is the one that matters. The declarative
//! `ParityRule`/`Coverage` model in this crate is much easier to read than a
//! pile of hex masks, but "easier to read" is not "correct", and Corporate
//! 1000's interleaved parity combs are exactly the sort of thing that is
//! plausible and wrong. Two implementations that disagree about no input is
//! real evidence.

use odr_wiegand::clock_data::{AbaEncoding, AbaTrack2, BITS_PER_CHAR};
use odr_wiegand::{
    decode, decode_aba, decode_transitions, encode, encode_transitions, infer_formats,
    inline_tamper, BitVec, Capture, CardFormat, Credential, CredentialSweep, Level, Line,
    SweepCost, TimingAnomaly, Transition, WiegandTiming,
};

// ---------------------------------------------------------------------------
// Reference implementation, transcribed from Proxmark3 wiegand_formats.c
// ---------------------------------------------------------------------------

/// `evenparity32` from the Proxmark client: 1 when `x` has an odd number of
/// set bits, i.e. the bit that makes the total even.
fn evenparity32(x: u32) -> u32 {
    x.count_ones() % 2
}

/// `oddparity32`: the complement.
fn oddparity32(x: u32) -> u32 {
    evenparity32(x) ^ 1
}

fn render(value: u64, len: usize) -> BitVec {
    BitVec::from_u64_msb(value, len).expect("fits")
}

/// `Pack_H10301`, verbatim in structure.
fn reference_h10301(fc: u32, cn: u32) -> BitVec {
    let mut bot: u32 = 0;
    bot |= (cn & 0xFFFF) << 1;
    bot |= (fc & 0xFF) << 17;
    bot |= oddparity32((bot >> 1) & 0xFFF);
    bot |= evenparity32((bot >> 13) & 0xFFF) << 25;
    render(u64::from(bot), 26)
}

/// `Pack_C1k35s`, verbatim in structure. `Mid` holds the three bits above
/// `Bot`'s 32.
fn reference_c1k35s(fc: u32, cn: u32) -> BitVec {
    let mut bot: u32 = 0;
    let mut mid: u32 = 0;
    bot |= (cn & 0x000F_FFFF) << 1;
    bot |= (fc & 0x0000_07FF) << 21;
    mid |= (fc & 0x0000_0800) >> 11;
    mid |= evenparity32((mid & 0x1) ^ (bot & 0xB6DB_6DB6)) << 1;
    bot |= oddparity32((mid & 0x3) ^ (bot & 0x6DB6_DB6C));
    mid |= oddparity32((mid & 0x3) ^ bot) << 2;
    render((u64::from(mid & 0x7) << 32) | u64::from(bot), 35)
}

/// `Pack_H10306`: two linear fields, two contiguous parity windows.
fn reference_h10306(fc: u32, cn: u32) -> BitVec {
    let mut bits = BitVec::zeros(34);
    bits.set_field(1, 16, u64::from(fc)).unwrap();
    bits.set_field(17, 16, u64::from(cn)).unwrap();
    let lead = bits.extract_u64(1, 16).unwrap() as u32;
    let trail = bits.extract_u64(17, 16).unwrap() as u32;
    bits.set(0, evenparity32(lead) == 1).unwrap();
    bits.set(33, oddparity32(trail) == 1).unwrap();
    bits
}

/// `Pack_H10304`: note both parity windows are 18 bits wide and overlap at
/// bit 18.
fn reference_h10304(fc: u32, cn: u32) -> BitVec {
    let mut bits = BitVec::zeros(37);
    bits.set_field(1, 16, u64::from(fc)).unwrap();
    bits.set_field(17, 19, u64::from(cn)).unwrap();
    let lead = bits.extract_u64(1, 18).unwrap() as u32;
    let trail = bits.extract_u64(18, 18).unwrap() as u32;
    bits.set(0, evenparity32(lead) == 1).unwrap();
    bits.set(36, oddparity32(trail) == 1).unwrap();
    bits
}

// ---------------------------------------------------------------------------
// Known vectors
// ---------------------------------------------------------------------------

#[test]
fn h10301_facility_1_card_1_matches_the_hand_computed_frame() {
    // Written out from the format description, not from this crate:
    //   P  = even parity over the facility code and the top four card bits.
    //        00000001 0000 has one 1 bit, so P = 1.
    //   FC = 1   -> 00000001
    //   CN = 1   -> 0000000000000001
    //   P  = odd parity over the bottom twelve card bits, 000000000001,
    //        which already has one 1 bit, so P = 0.
    let expected = "1 00000001 0000000000000001 0";
    let bits = encode(&Credential::new(CardFormat::H10301, 1, 1)).unwrap();
    assert_eq!(bits, BitVec::from_bin_str(expected).unwrap());
    assert_eq!(bits.to_hex_string(), "2020002");

    let d = decode(CardFormat::H10301, &bits).unwrap();
    assert_eq!(d.facility_code, Some(1));
    assert_eq!(d.card_number, Some(1));
    assert!(d.parity_valid());
}

#[test]
fn h10301_facility_123_card_4567() {
    let bits = encode(&Credential::new(CardFormat::H10301, 123, 4567)).unwrap();
    assert_eq!(
        bits,
        BitVec::from_bin_str("1 01111011 0001000111010111 0").unwrap(),
        "got {}",
        bits.to_bin_string()
    );
}

#[test]
fn h10301_agrees_with_the_reference_over_the_whole_facility_code_space() {
    // Every facility code, and a spread of card numbers including the edges.
    let card_numbers = [
        0u32, 1, 2, 3, 255, 256, 4095, 4096, 12345, 32767, 32768, 65534, 65535,
    ];
    for fc in 0u32..=255 {
        for cn in card_numbers {
            let ours = encode(&Credential::new(CardFormat::H10301, fc.into(), cn.into())).unwrap();
            let theirs = reference_h10301(fc, cn);
            assert_eq!(ours, theirs, "H10301 fc={fc} cn={cn}");
            let back = decode(CardFormat::H10301, &ours).unwrap();
            assert!(back.parity_valid());
            assert_eq!(back.facility_code, Some(u64::from(fc)));
            assert_eq!(back.card_number, Some(u64::from(cn)));
        }
    }
}

#[test]
fn corporate_1000_agrees_with_the_reference() {
    // Corporate 1000's three parity bits cover interleaved combs and one of
    // them covers the other two, so the order of application matters. Sweep a
    // spread that exercises every comb position and both field boundaries.
    let company_codes = [
        0u32, 1, 2, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 2048, 4094, 4095,
    ];
    let card_numbers = [
        0u32, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0x100, 0x5555, 0xAAAA, 0xFFFF, 0x1_0000, 0x7_FFFF,
        0x8_0000, 0xA_AAAA, 0xF_FFFF,
    ];
    for fc in company_codes {
        for cn in card_numbers {
            let ours = encode(&Credential::new(
                CardFormat::Corporate1000,
                fc.into(),
                cn.into(),
            ))
            .unwrap();
            let theirs = reference_c1k35s(fc, cn);
            assert_eq!(ours, theirs, "C1k35s fc={fc} cn={cn}");
            let back = decode(CardFormat::Corporate1000, &ours).unwrap();
            assert!(back.parity_valid(), "C1k35s fc={fc} cn={cn} parity");
            assert_eq!(back.facility_code, Some(u64::from(fc)));
            assert_eq!(back.card_number, Some(u64::from(cn)));
        }
    }
}

#[test]
fn h10306_and_h10304_agree_with_the_reference() {
    let values = [0u32, 1, 2, 0xFF, 0x100, 0x5555, 0xAAAA, 0xFFFF];
    for fc in values {
        for cn in values {
            assert_eq!(
                encode(&Credential::new(CardFormat::H10306, fc.into(), cn.into())).unwrap(),
                reference_h10306(fc, cn),
                "H10306 fc={fc} cn={cn}"
            );
            assert_eq!(
                encode(&Credential::new(CardFormat::H10304, fc.into(), cn.into())).unwrap(),
                reference_h10304(fc, cn),
                "H10304 fc={fc} cn={cn}"
            );
        }
    }
}

#[test]
fn h10302_uses_the_same_parity_windows_as_h10304() {
    // The 37-bit formats differ only in how the body is split into fields, so
    // a given 37-bit frame has the same parity bits either way.
    for cn in [0u64, 1, 0xFFFF, 0x7_FFFF_FFFF, 0x4_0000_0001] {
        let bits = encode(&Credential::without_facility(CardFormat::H10302, cn)).unwrap();
        let as_h10304 = decode(CardFormat::H10304, &bits).unwrap();
        assert!(as_h10304.parity_valid(), "cn={cn}");
    }
}

// ---------------------------------------------------------------------------
// Parity as a diagnostic
// ---------------------------------------------------------------------------

#[test]
fn every_single_bit_flip_in_a_26_bit_frame_is_visible_somewhere() {
    // Not a security property — parity catches single bit errors on a cable,
    // which is all it was ever for. Worth pinning because the range shows it.
    let good = encode(&Credential::new(CardFormat::H10301, 77, 4242)).unwrap();
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad.set(i, !bad.get(i).unwrap()).unwrap();
        let d = decode(CardFormat::H10301, &bad).unwrap();
        assert!(!d.parity_valid(), "flipping bit {i} went unnoticed");
        // The decode still produced fields: that is the point of keeping the
        // parity report separate from the result.
        assert!(d.facility_code.is_some());
        assert!(d.card_number.is_some());
    }
}

#[test]
fn a_two_bit_flip_can_slip_through_which_is_the_limit_of_parity() {
    let good = encode(&Credential::new(CardFormat::H10301, 77, 4242)).unwrap();
    let mut bad = good.clone();
    // Two bits inside the same parity window cancel out.
    bad.set(13, !bad.get(13).unwrap()).unwrap();
    bad.set(14, !bad.get(14).unwrap()).unwrap();
    let d = decode(CardFormat::H10301, &bad).unwrap();
    assert!(
        d.parity_valid(),
        "two flips in one window are invisible to parity"
    );
    assert_ne!(
        d.card_number,
        Some(4242),
        "and the card number really did change"
    );
}

#[test]
fn a_parity_report_names_the_failing_rule() {
    let mut bits = encode(&Credential::new(CardFormat::Corporate1000, 100, 200)).unwrap();
    bits.set(1, !bits.get(1).unwrap()).unwrap();
    let d = decode(CardFormat::Corporate1000, &bits).unwrap();
    let failed: Vec<usize> = d.parity.failures().map(|c| c.bit).collect();
    // Flipping the inner even parity bit breaks that rule and the whole-frame
    // rule that covers it, but not the trailing one, which does not cover bit 1
    // ... except that it does: bit 1 is in the comb 1,2,4,5,...
    assert!(failed.contains(&1));
    assert!(failed.contains(&0));
    assert_eq!(d.parity.len(), 3);
}

// ---------------------------------------------------------------------------
// Format inference
// ---------------------------------------------------------------------------

#[test]
fn a_37_bit_frame_is_genuinely_ambiguous() {
    let bits = encode(&Credential::new(CardFormat::H10304, 1234, 56789)).unwrap();
    let candidates = infer_formats(&bits);

    let named: Vec<CardFormat> = candidates.iter().map(|c| c.decoded.format).collect();
    assert!(named.contains(&CardFormat::H10304));
    assert!(named.contains(&CardFormat::H10302));
    assert!(named
        .iter()
        .any(|f| matches!(f, CardFormat::Raw { bit_len: 37 })));

    // Both named readings have valid parity — the parity rules are identical
    // and only the field split differs. Nothing on the wire can break the tie.
    let h10304 = candidates
        .iter()
        .find(|c| c.decoded.format == CardFormat::H10304)
        .unwrap();
    let h10302 = candidates
        .iter()
        .find(|c| c.decoded.format == CardFormat::H10302)
        .unwrap();
    assert!(h10304.parity_valid);
    assert!(h10302.parity_valid);
    assert_eq!(h10304.decoded.facility_code, Some(1234));
    assert_eq!(h10302.decoded.facility_code, None);
}

#[test]
fn inference_puts_valid_parity_first_and_always_offers_raw() {
    let bits = encode(&Credential::new(CardFormat::H10301, 9, 9)).unwrap();
    let candidates = infer_formats(&bits);
    assert_eq!(candidates[0].decoded.format, CardFormat::H10301);
    assert!(candidates[0].parity_valid);
    assert!(matches!(
        candidates.last().unwrap().decoded.format,
        CardFormat::Raw { bit_len: 26 }
    ));
}

#[test]
fn an_unrecognised_width_still_gets_a_raw_candidate() {
    let bits = BitVec::from_bin_str("110100101").unwrap();
    let candidates = infer_formats(&bits);
    assert_eq!(candidates.len(), 1);
    assert!(matches!(
        candidates[0].decoded.format,
        CardFormat::Raw { bit_len: 9 }
    ));
    assert_eq!(candidates[0].decoded.card_number, Some(0b110100101));
}

#[test]
fn a_frame_with_bad_parity_still_appears_as_a_candidate_just_not_first() {
    let mut bits = encode(&Credential::new(CardFormat::H10301, 9, 9)).unwrap();
    bits.set(0, !bits.get(0).unwrap()).unwrap();
    let candidates = infer_formats(&bits);
    let h10301 = candidates
        .iter()
        .find(|c| c.decoded.format == CardFormat::H10301)
        .unwrap();
    assert!(!h10301.parity_valid);
    assert_eq!(h10301.decoded.facility_code, Some(9));
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

#[test]
fn every_format_survives_a_trip_over_d0_d1() {
    let timing = WiegandTiming::default();
    let creds = [
        Credential::new(CardFormat::H10301, 200, 60_000),
        Credential::new(CardFormat::H10306, 40_000, 60_000),
        Credential::new(CardFormat::Corporate1000, 4_000, 1_000_000),
        Credential::new(CardFormat::H10304, 40_000, 500_000),
        Credential::without_facility(CardFormat::H10302, 30_000_000_000),
    ];
    for cred in creds {
        let bits = encode(&cred).unwrap();
        let edges = encode_transitions(&bits, &timing, 1_000_000);
        assert_eq!(edges.len(), bits.len() * 2);
        let capture = decode_transitions(&edges, &timing);
        assert!(capture.is_clean(), "{cred}: {:?}", capture.anomalies);
        assert_eq!(capture.frames.len(), 1, "{cred}");
        assert_eq!(capture.frames[0].bits, bits, "{cred}");

        let back = decode(cred.format, &capture.frames[0].bits).unwrap();
        assert_eq!(back.credential(), Some(cred), "{cred}");
        assert!(back.parity_valid(), "{cred}");
    }
}

#[test]
fn a_decoder_that_joins_mid_frame_still_gets_the_next_one() {
    let timing = WiegandTiming::default();
    let a = encode(&Credential::new(CardFormat::H10301, 7, 7)).unwrap();
    let b = encode(&Credential::new(CardFormat::H10301, 8, 8)).unwrap();

    let mut edges = encode_transitions(&a, &timing, 0);
    // Throw away the first half of the first frame, as if the tap was clipped
    // on while a badge was already being read.
    edges.drain(..21);
    let gap = timing.frame_duration_us(a.len()) + timing.interframe_gap_us + 5_000;
    edges.extend(encode_transitions(&b, &timing, gap));

    let capture = decode_transitions(&edges, &timing);
    assert_eq!(capture.frames.len(), 2);
    assert!(
        capture.frames[0].bits.len() < 26,
        "the clipped frame is short"
    );
    assert_eq!(capture.frames[1].bits, b, "and the next one is intact");
}

#[test]
fn a_glitch_burst_does_not_stop_the_decoder() {
    let timing = WiegandTiming::default();
    let mut edges = Vec::new();
    // A storm of simultaneous and malformed pulses.
    for i in 0..5u64 {
        let t = i * 500;
        edges.push(Transition {
            t_us: t,
            line: Line::D0,
            level: Level::Low,
        });
        edges.push(Transition {
            t_us: t + 5,
            line: Line::D1,
            level: Level::Low,
        });
        edges.push(Transition {
            t_us: t + 60,
            line: Line::D0,
            level: Level::High,
        });
        edges.push(Transition {
            t_us: t + 70,
            line: Line::D1,
            level: Level::High,
        });
    }
    let good = encode(&Credential::new(CardFormat::H10301, 3, 3)).unwrap();
    edges.extend(encode_transitions(&good, &timing, 100_000));

    let capture = decode_transitions(&edges, &timing);
    assert!(capture
        .anomalies
        .iter()
        .any(|a| matches!(a, TimingAnomaly::SimultaneousPulse { .. })));
    let recovered = capture.frames.last().unwrap();
    assert_eq!(
        recovered.bits, good,
        "the clean frame after the storm is intact"
    );
}

#[test]
fn a_reader_out_of_spec_is_reported_but_still_read() {
    // A reader with 150 us pulses: outside the usual 20-100 us envelope, but
    // a panel will take it, and so does this decoder — loudly.
    let reader = WiegandTiming {
        pulse_width_us: 150,
        ..WiegandTiming::default()
    };
    let panel = WiegandTiming::default();
    let bits = encode(&Credential::new(CardFormat::H10301, 5, 5)).unwrap();
    let capture = decode_transitions(&encode_transitions(&bits, &reader, 0), &panel);
    assert_eq!(capture.frames[0].bits, bits);
    assert_eq!(capture.anomalies.len(), 26);
    assert!(capture
        .anomalies
        .iter()
        .all(|a| matches!(a, TimingAnomaly::PulseTooLong { width_us: 150, .. })));
}

// ---------------------------------------------------------------------------
// Clock-and-data
// ---------------------------------------------------------------------------

#[test]
fn aba_track_123_matches_the_hand_computed_bit_pattern() {
    // Worked by hand from the format description:
    //   ';'  = 0x0B = 1011 -> LSB first 1,1,0,1 (three ones) + parity 0
    //   '1'  = 0x01 = 0001 -> 1,0,0,0          (one one)     + parity 0
    //   '2'  = 0x02 = 0010 -> 0,1,0,0          (one one)     + parity 0
    //   '3'  = 0x03 = 0011 -> 1,1,0,0          (two ones)    + parity 1
    //   '?'  = 0x0F = 1111 -> 1,1,1,1          (four ones)   + parity 1
    //   LRC  = 0xB^1^2^3^0xF = 0x4 = 0100 -> 0,0,1,0 (one one) + parity 0
    let expected = "11010 10000 01000 11001 11111 00100";
    let track = AbaTrack2::from_ascii("123").unwrap();
    assert_eq!(track.lrc(), 0x4);
    let bits = track.encode(&AbaEncoding::bare());
    assert_eq!(
        bits,
        BitVec::from_bin_str(expected).unwrap(),
        "got {}",
        bits.to_bin_string()
    );

    let decoded = decode_aba(&bits).unwrap();
    assert_eq!(decoded.track.to_string(), "123");
    assert_eq!(decoded.lrc_observed, 0x4);
    assert!(decoded.is_clean());
}

#[test]
fn aba_round_trips_with_separators_and_padding() {
    for text in [
        "0",
        "9",
        "1234567890",
        "12=34",
        "=",
        "000000",
        "999999999999999999=",
    ] {
        let track = AbaTrack2::from_ascii(text).unwrap();
        let bits = track.encode(&AbaEncoding::default());
        let decoded = decode_aba(&bits).unwrap();
        assert_eq!(decoded.track.to_string(), text);
        assert!(decoded.is_clean(), "{text}");
        assert_eq!(decoded.characters.len(), text.len() + 3);
        assert_eq!(bits.len(), 10 + (text.len() + 3) * BITS_PER_CHAR + 10);
    }
}

#[test]
fn aba_survives_the_clock_and_data_wire_and_gets_replayed() {
    use odr_wiegand::clock_data::{decode_clock_data, encode_clock_data, ClockDataTiming};

    let timing = ClockDataTiming::default();
    let track = AbaTrack2::from_ascii("6543210=99").unwrap();
    let bits = track.encode(&AbaEncoding::default());

    let edges = encode_clock_data(&bits, &timing, 500);
    let capture = decode_clock_data(&edges, &timing);
    assert!(capture.is_clean(), "{:?}", capture.anomalies);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].bits, bits);

    // Replay: the same bits, sent later, at a different rate.
    let faster = ClockDataTiming {
        bit_period_us: 400,
        ..timing
    };
    let replayed = encode_clock_data(&capture.frames[0].bits, &faster, 9_000_000);
    let heard = decode_clock_data(&replayed, &faster);
    assert_eq!(decode_aba(&heard.frames[0].bits).unwrap().track, track);
}

// ---------------------------------------------------------------------------
// Attacks
// ---------------------------------------------------------------------------

#[test]
fn sniff_then_replay_is_indistinguishable_from_the_card() {
    let timing = WiegandTiming::default();
    let cred = Credential::new(CardFormat::H10301, 42, 1337);
    let bits = encode(&cred).unwrap();

    // The badge is presented at t = 1 s.
    let real = decode_transitions(&encode_transitions(&bits, &timing, 1_000_000), &timing);
    let capture = Capture::from_frame(&real.frames[0]);

    // The attacker sends it again at t = 1 hour, from different hardware.
    let attacker_timing = WiegandTiming::fast();
    let forged = decode_transitions(
        &capture.replay(3_600_000_000, &attacker_timing),
        &attacker_timing,
    );

    assert_eq!(forged.frames[0].bits, real.frames[0].bits);
    assert_eq!(forged.frames[0].bits, bits);
    // The only difference is the timestamp, and the protocol has no field for
    // it.
    assert_ne!(forged.frames[0].start_us, real.frames[0].start_us);
    assert_eq!(capture.interpret().credential(), Some(cred));
}

#[test]
fn an_inline_implant_swaps_the_credential_without_leaving_a_trace() {
    let timing = WiegandTiming::default();
    let victim = Credential::new(CardFormat::H10301, 12, 3456);
    let attacker = Credential::new(CardFormat::H10301, 1, 1);

    let on_the_wire = encode(&victim).unwrap();
    let observed = decode_transitions(&encode_transitions(&on_the_wire, &timing, 0), &timing);
    let tampered = inline_tamper(&observed.frames[0].bits, &attacker).unwrap();

    assert!(tampered.length_preserved);
    assert_eq!(tampered.observed.credential(), Some(victim));

    // What the panel sees downstream of the implant.
    let downstream = decode_transitions(
        &encode_transitions(&tampered.emitted, &timing, 50_000),
        &timing,
    );
    let seen = decode(CardFormat::H10301, &downstream.frames[0].bits).unwrap();
    assert_eq!(seen.credential(), Some(attacker));
    assert!(
        seen.parity_valid(),
        "the forged frame is as valid as any other"
    );
}

#[test]
fn brute_force_cost_is_the_argument_against_brute_force() {
    let whole_space = CredentialSweep::exhaustive(CardFormat::H10301).unwrap();
    assert_eq!(whole_space.credential_count(), 16_777_216);
    let full = SweepCost::nominal(&whole_space);

    let one_facility = CredentialSweep::new(CardFormat::H10301, 42..=42, 0..=65_535).unwrap();
    let narrow = SweepCost::nominal(&one_facility);

    assert_eq!(full.credentials / narrow.credentials, 256);
    assert!(full.total_days() > 10.0, "{}", full.describe());
    assert!(narrow.total_hours() < 2.0, "{}", narrow.describe());
    // Knowing the facility code is worth 256x. That is the practical lesson.
    assert_eq!(full.total_us / narrow.total_us, 256);
}

#[test]
fn a_sweep_produces_encodable_credentials_all_the_way_to_the_edges() {
    let sweep = CredentialSweep::new(CardFormat::H10301, 254..=255, 65_533..=65_535).unwrap();
    let all: Vec<Credential> = sweep.collect();
    assert_eq!(all.len(), 6);
    for cred in all {
        let bits = encode(&cred).unwrap();
        assert_eq!(bits.len(), 26);
        assert!(decode(CardFormat::H10301, &bits).unwrap().parity_valid());
    }
}

#[test]
fn a_sweep_can_be_driven_onto_the_wire_end_to_end() {
    let timing = WiegandTiming::fast();
    let sweep = CredentialSweep::new(CardFormat::H10301, 3..=3, 100..=104).unwrap();
    let settle = timing.interframe_gap_us + 1_000;

    let mut edges = Vec::new();
    let mut t = 0u64;
    let mut sent = Vec::new();
    for cred in sweep {
        let bits = encode(&cred).unwrap();
        edges.extend(encode_transitions(&bits, &timing, t));
        sent.push(bits);
        t += timing.frame_duration_us(26) + settle;
    }

    let capture = decode_transitions(&edges, &timing);
    assert!(capture.is_clean(), "{:?}", capture.anomalies);
    assert_eq!(capture.frames.len(), 5);
    for (frame, expected) in capture.frames.iter().zip(sent.iter()) {
        assert_eq!(&frame.bits, expected);
    }
    let numbers: Vec<u64> = capture
        .frames
        .iter()
        .map(|f| {
            decode(CardFormat::H10301, &f.bits)
                .unwrap()
                .card_number
                .unwrap()
        })
        .collect();
    assert_eq!(numbers, [100, 101, 102, 103, 104]);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn the_same_inputs_always_produce_the_same_bytes() {
    let timing = WiegandTiming::default();
    let cred = Credential::new(CardFormat::Corporate1000, 1234, 987_654);
    let once = encode_transitions(&encode(&cred).unwrap(), &timing, 12_345);
    let twice = encode_transitions(&encode(&cred).unwrap(), &timing, 12_345);
    assert_eq!(once, twice);
    assert_eq!(once[0].t_us, 12_345);
    assert_eq!(
        once.last().unwrap().t_us,
        12_345 + timing.frame_duration_us(35)
    );
}
