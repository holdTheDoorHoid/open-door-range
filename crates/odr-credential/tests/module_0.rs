//! Module 0 of the curriculum, drill by drill.
//!
//! Each test here is the flag predicate from `docs/CURRICULUM.md`, expressed against
//! engine state. Nothing compares a typed answer; every one of them is the simulation
//! actually reaching a condition. If the engine is wrong, these fail rather than lie.
//!
//! Drill 0.6 — mechanical and sensor bypass — is deliberately absent. It is reference
//! prose, it simulates nothing, and it says so.

use odr_credential::crypto1::{prng_successor, Crypto1};
use odr_credential::desfire::{
    self, AttackFailure, AttackOutcome, DesfireEv2, DesfireReader, BLOCK as AES_BLOCK,
};
use odr_credential::em4100::Em4100Tag;
use odr_credential::hid_prox::H10301;
use odr_credential::mifare::{AccessBits, KeyType, MifareClassic1k, MifareReader, DEFAULT_KEY};
use odr_credential::modulation::{CarrierConfig, RF_64};
use odr_credential::nested::{self, NestedAttack};
use odr_credential::writable::{sniff, WritableTag};
use odr_credential::{Card, Credential, CredentialFormat, Reader, Rng};

// ---------------------------------------------------------------------------
// 0.1 — What a prox card is
//
// Flag: the learner reads a tag's ID off the modulated carrier and matches the
// engine's value.
// ---------------------------------------------------------------------------

#[test]
fn drill_0_1_the_id_is_readable_off_the_carrier_alone() {
    let mut rng = Rng::new(0x0001);
    let engine_value = rng.next_u64() & 0xFF_FFFF_FFFF;
    let tag = Em4100Tag::from_id40(engine_value).unwrap();

    // Everything the learner gets: the field response. No decoded value, no side
    // channel, no hint about the format.
    let stream = Card::em4100(tag)
        .field_response(3, &CarrierConfig::default())
        .unwrap();

    let frame = odr_credential::em4100::demodulate(&stream, RF_64).unwrap();
    let read = frame.decode();

    assert!(read.parity.is_valid(), "a clean field gives a clean read");
    assert_eq!(read.tag.id40(), engine_value);
}

#[test]
fn drill_0_1_a_marginal_read_is_reportable_as_one() {
    // The other half of the lesson: the format has error *detection* and nothing else.
    let tag = Em4100Tag::new(0x21, 0x0102_0304);
    let corrupted = tag.encode().with_bit_flipped(9 + 3 * 5 + 1);
    let read = corrupted.decode();

    assert!(!read.parity.is_valid());
    assert_eq!(read.parity.single_error_location(), Some((3, 1)));
    // The bad bit is located exactly — and there is still nothing stopping anyone
    // from writing a different ID with correct parity.
}

// ---------------------------------------------------------------------------
// 0.2 — Cloning 125 kHz
//
// Flag: a cloned tag presents to the reader and is accepted, where the original tag
// was never presented. (The controller's "grant" lives in odr-bus; at this layer the
// predicate is that the reader emits the victim's credential.)
// ---------------------------------------------------------------------------

#[test]
fn drill_0_2_a_clone_is_accepted_and_the_original_never_appeared() {
    let cfg = CarrierConfig::default();
    let victim = Em4100Tag::new(0x2A, 0x0BAD_C0DE);

    // One brush past the victim's pocket.
    let sniffed = Card::em4100(victim).field_response(4, &cfg).unwrap();
    let capture = sniff(&sniffed).unwrap();

    // The attacker's blank.
    let mut blank = WritableTag::blank();
    blank.clone_from_capture(&capture).unwrap();
    let mut clone = Card::writable(blank);

    // At the door, later. The victim's tag is not in the building.
    let mut reader = Reader::lf_125khz();
    let presented = reader.present(&mut clone).unwrap();

    assert_eq!(presented.format, CredentialFormat::Em4100);
    assert_eq!(presented.as_u64(), victim.id40());
}

#[test]
fn drill_0_2_there_is_nothing_for_the_reader_to_detect() {
    // The lesson, asserted: the clone's modulation is equal to the original's, event
    // for event. No property of the signal differs, so no reader could tell.
    let cfg = CarrierConfig::default();
    let victim = H10301::new(77, 31337);

    let genuine = Card::hid_prox(victim).field_response(4, &cfg).unwrap();
    let mut blank = WritableTag::blank();
    blank.clone_from_capture(&sniff(&genuine).unwrap()).unwrap();

    let cloned = Card::writable(blank).field_response(4, &cfg).unwrap();
    assert_eq!(cloned, genuine);
}

// ---------------------------------------------------------------------------
// 0.3 — HID Prox and the format problem
//
// Flag: the learner extracts facility code and card number from the RF layer, then
// predicts the exact Wiegand bit pattern the reader will emit before it emits it.
// ---------------------------------------------------------------------------

#[test]
fn drill_0_3_rf_layer_to_wire_bits_with_nothing_in_between() {
    let cfg = CarrierConfig::default();
    let issued = H10301::new(123, 4567);

    // Step one: pull the credential off the air.
    let stream = Card::hid_prox(issued).field_response(2, &cfg).unwrap();
    let block = odr_credential::hid_prox::demodulate_block(&stream).unwrap();
    let recovered = H10301::from_raw44(block).unwrap();
    assert_eq!(recovered.facility_code, 123);
    assert_eq!(recovered.card_number, 4567);

    // Step two: predict the wire. Hand-verified vector.
    let predicted = odr_credential::h10301_wiegand_bits(&recovered);
    assert_eq!(
        predicted.iter().fold(0u32, |a, &b| (a << 1) | u32::from(b)),
        0x02F6_23AE
    );

    // Step three: the reader emits it. Identical, because there is no step in
    // between where anything could be checked.
    let mut reader = Reader::lf_125khz();
    let emitted = reader.present(&mut Card::hid_prox(issued)).unwrap();
    assert_eq!(emitted.bit_len, 26);
    assert_eq!(emitted.bits(), predicted.to_vec());
}

#[test]
fn drill_0_3_prediction_holds_for_arbitrary_credentials() {
    let cfg = CarrierConfig::default();
    let mut rng = Rng::new(0x0303);
    let mut reader = Reader::lf_125khz();

    for _ in 0..32 {
        let card = H10301::new(rng.next_u32() as u8, rng.next_u32() as u16);
        let stream = Card::hid_prox(card).field_response(1, &cfg).unwrap();
        let off_the_air =
            H10301::from_raw44(odr_credential::hid_prox::demodulate_block(&stream).unwrap())
                .unwrap();
        let predicted = odr_credential::h10301_wiegand_bits(&off_the_air);
        let emitted = reader.present(&mut Card::hid_prox(card)).unwrap();
        assert_eq!(emitted.bits(), predicted.to_vec());
    }
}

// ---------------------------------------------------------------------------
// 0.4 — 13.56 MHz: the upgrade that mostly was not
//
// Flag: attacker recovers sector keys from a simulated card given only observed
// traffic, then reads the credential block.
// ---------------------------------------------------------------------------

fn provisioned_card(rng: &mut Rng) -> (MifareClassic1k, Vec<u64>, [u8; 16]) {
    let credential = [
        0x26, 0x00, 0x7B, 0x11, 0xD7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let mut card = MifareClassic1k::new(0x2A23_4F80, rng.next_u64());
    let mut keys = Vec::new();
    // Sector 0 is the one the attacker already has: a factory default nobody changed.
    card.force_sector_keys(0, DEFAULT_KEY, DEFAULT_KEY, AccessBits::transport());
    keys.push(DEFAULT_KEY);
    for sector in 1..16u8 {
        let key_a = rng.next_crypto1_key();
        card.force_sector_keys(
            sector,
            key_a,
            rng.next_crypto1_key(),
            AccessBits::transport(),
        );
        keys.push(key_a);
    }
    card.force_block(4, credential);
    (card, keys, credential)
}

#[test]
fn drill_0_4_nested_attack_recovers_keys_and_reads_the_credential() {
    let mut rng = Rng::new(0x0004);
    let (mut card, keys, credential) = provisioned_card(&mut rng);
    let mut reader = MifareReader::new(0x0404);

    let attack = NestedAttack::new(0, KeyType::A, DEFAULT_KEY);
    let distance = attack.calibrate(&mut card, &mut reader).unwrap();

    // Four sectors is enough to show it is not a fluke; recover_all does all sixteen
    // at about the same cost per sector.
    for sector in 1..5u8 {
        let block = sector * 4;
        let recovered = attack
            .run_with_distance(&mut card, &mut reader, block, KeyType::A, distance)
            .unwrap();

        // The flag predicate: the attacker's key equals the card's configured key,
        // derived from observation alone.
        assert_eq!(
            recovered.key,
            keys[usize::from(sector)],
            "sector {sector} key must match"
        );
        assert_eq!(recovered.stats.recoveries, 1, "one search per sector");
    }

    // ... then reads the credential block, which is the second half of the flag.
    let read = nested::prove(&mut card, &mut reader, 4, KeyType::A, keys[1]).unwrap();
    assert_eq!(read.format, CredentialFormat::MifareClassicBlock);
    assert_eq!(read.data, credential.to_vec());
}

#[test]
fn drill_0_4_the_attack_never_completes_an_authentication_it_could_not_afford() {
    // The honest part of the attack: the probes it uses are abandoned before pass
    // three, so at no point does the attacker hold a session it did not pay for.
    let mut rng = Rng::new(0x0414);
    let (mut card, keys, _) = provisioned_card(&mut rng);
    let mut reader = MifareReader::new(0x0415);
    let attack = NestedAttack::new(0, KeyType::A, DEFAULT_KEY);

    let distance = attack.calibrate(&mut card, &mut reader).unwrap();
    let capture = attack
        .capture(&mut card, &mut reader, 8, KeyType::A)
        .unwrap();
    assert!(!card.has_session(), "the probe granted nothing");

    let (key, _) = attack.recover(&capture, distance).unwrap();
    assert_eq!(key, keys[2]);
}

#[test]
fn drill_0_4_a_recovered_key_really_is_the_key() {
    // Independent check of the same fact through the cipher rather than the card:
    // running the authentication forward from the recovered key reproduces the
    // observed ciphertext exactly.
    let mut rng = Rng::new(0x0424);
    let (mut card, _, _) = provisioned_card(&mut rng);
    let mut reader = MifareReader::new(0x0425);
    let attack = NestedAttack::new(0, KeyType::A, DEFAULT_KEY);

    let recovered = attack.run(&mut card, &mut reader, 4, KeyType::A).unwrap();

    let uid = card.uid();
    let (_, trace) = reader
        .authenticate(&mut card, 4, KeyType::A, recovered.key, None)
        .unwrap();
    let mut cipher = Crypto1::from_key(recovered.key);
    cipher.word(uid ^ trace.nt_enc, false);
    cipher.word(trace.nr_enc, true);
    assert_eq!(
        cipher.word(0, false) ^ trace.ar_enc,
        prng_successor(trace.nt_enc, 64)
    );
}

// ---------------------------------------------------------------------------
// 0.5 — The ones that hold up
//
// Flag: the learner runs 0.2 and 0.4's attacks against a DESFire card and records why
// each one stops. The drill passes on correct diagnosis, not on a successful attack.
// ---------------------------------------------------------------------------

const DESFIRE_KEY: [u8; AES_BLOCK] = [
    0x5A, 0x1C, 0x77, 0x03, 0x9B, 0xE2, 0x48, 0xD1, 0x6F, 0x30, 0xAC, 0x55, 0x11, 0x8E, 0x24, 0xF7,
];

fn desfire_card() -> DesfireEv2 {
    let mut card = DesfireEv2::new(0x0505_0505, 0, DESFIRE_KEY);
    card.set_file(1, b"\x01\x23\x45\x67\x89\xab\xcd\xef".to_vec());
    card
}

#[test]
fn drill_0_5_the_card_itself_works_perfectly_well() {
    // Before the attacks: show that nothing is broken. A legitimate reader with the
    // key gets the credential, and both ends derive the same session key without
    // either of them sending it.
    let mut card = desfire_card();
    let mut reader = DesfireReader::new(0x0501, DESFIRE_KEY);
    let (mut session, transcript) = reader.authenticate(&mut card, 0).unwrap();

    assert_eq!(card.session_keys().unwrap().key, session.key);
    assert_ne!(transcript.enc_rnd_b, [0u8; AES_BLOCK]);

    let credential: Credential = reader.read_credential(&mut card, &mut session, 1).unwrap();
    assert_eq!(credential.format, CredentialFormat::DesfireFile);
    assert_eq!(
        &credential.data[..8],
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    );
}

#[test]
fn drill_0_5_all_three_attacks_stop_and_the_engine_says_why() {
    let mut card = desfire_card();
    let report = desfire::run_contrast(&mut card, DESFIRE_KEY, 0x0502);

    assert!(report.all_failed(), "no Module 0 attack may succeed here");
    assert_eq!(
        report.diagnoses(),
        vec![
            AttackFailure::NoStaticSecretToCopy,
            AttackFailure::ChallengeIsFreshEachExchange,
            AttackFailure::KeyNeverTransmitted,
        ]
    );

    // Each diagnosis carries the explanation the drill marks against.
    for reason in report.diagnoses() {
        assert!(reason.explanation().len() > 80, "{}", reason.name());
    }

    // The third diagnosis is a measurement, not a label: the card's challenges do not
    // lie on the 16-bit LFSR orbit the nested attack needs.
    assert_eq!(report.nonce_probe.pairs_on_orbit, 0);
    assert!(report.nonce_probe.pairs_tested >= 7);
}

#[test]
fn drill_0_5_cloning_specifically() {
    let mut card = desfire_card();
    assert_eq!(
        desfire::attempt_clone(&mut card, DESFIRE_KEY, 0x0503),
        AttackOutcome::Failed(AttackFailure::NoStaticSecretToCopy)
    );
}

#[test]
fn drill_0_5_replay_specifically() {
    let mut card = desfire_card();
    assert_eq!(
        desfire::attempt_replay(&mut card, DESFIRE_KEY, 0x0504),
        AttackOutcome::Failed(AttackFailure::ChallengeIsFreshEachExchange)
    );
}

#[test]
fn drill_0_5_key_recovery_specifically() {
    let mut card = desfire_card();
    let (outcome, probe) = desfire::attempt_crypto1_recovery(&mut card, 0, 12);
    assert_eq!(
        outcome,
        AttackOutcome::Failed(AttackFailure::KeyNeverTransmitted)
    );
    assert!(!probe.is_predictable());
}

// ---------------------------------------------------------------------------
// The property the whole range rests on
// ---------------------------------------------------------------------------

#[test]
fn the_same_seed_produces_the_same_bytes() {
    fn run(seed: u64) -> (Vec<u8>, u32, u64) {
        let mut rng = Rng::new(seed);
        let (mut card, _, _) = provisioned_card(&mut rng);
        let mut reader = MifareReader::new(seed);
        let (_, trace) = reader
            .authenticate(&mut card, 0, KeyType::A, DEFAULT_KEY, None)
            .unwrap();

        let mut desfire = DesfireEv2::new(seed, 0, DESFIRE_KEY);
        desfire.set_file(1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let mut dreader = DesfireReader::new(seed, DESFIRE_KEY);
        let (session, _) = dreader.authenticate(&mut desfire, 0).unwrap();

        (session.key.to_vec(), trace.nt_enc, trace.nr_enc as u64)
    }

    assert_eq!(run(12345), run(12345));
    assert_ne!(run(12345), run(12346));
}

#[test]
fn drill_0_6_is_not_simulated() {
    // There is no API here for request-to-exit tampering, door position switches,
    // crash bars or under-door tools, and there should not be. Module 0.6 is
    // reference prose in docs/, and the curriculum says so out loud. This test exists
    // only so that the absence is deliberate and visible rather than an oversight.
}
