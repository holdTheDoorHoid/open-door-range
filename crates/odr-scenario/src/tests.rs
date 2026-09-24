//! Unit tests for the small pieces.
//!
//! The curriculum itself is tested in `tests/curriculum.rs`, drill by drill,
//! against a running engine. What is left here is the arithmetic and the
//! vocabulary: things that are wrong in a way an integration test would not
//! notice because every drill would still pass.

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::ids::{Band, Completion, DrillId, ModuleId};
use crate::submission::{FieldSpan, FrameField};
use crate::tasks::Task;

#[test]
fn a_drill_id_round_trips_through_its_string() {
    for drill in crate::catalog::DRILLS {
        let s = drill.id.as_string();
        assert_eq!(DrillId::parse(&s), Some(drill.id));
        assert_eq!(drill.id.to_string(), s);
    }
}

#[test]
fn drill_ids_sort_numerically_rather_than_lexically() {
    // "1.10" sorts before "1.9" as a string and after it as an id, which is
    // the whole reason DrillId is two numbers.
    assert!(DrillId::new(1, 10) > DrillId::new(1, 9));
    assert!(DrillId::new(2, 1) > DrillId::new(1, 6));
}

#[test]
fn a_band_round_trips_through_its_name() {
    for band in [Band::Bronze, Band::Silver, Band::Gold, Band::Reference] {
        assert_eq!(Band::parse(band.name()), Some(band));
    }
    assert_eq!(Band::parse("platinum"), None);
}

#[test]
fn only_bronze_pre_places_taps_and_only_gold_refuses_hints() {
    assert!(Band::Bronze.pre_places_taps());
    assert!(!Band::Silver.pre_places_taps());
    assert!(!Band::Gold.pre_places_taps());
    assert!(Band::Bronze.offers_hints());
    assert!(Band::Silver.offers_hints());
    assert!(!Band::Gold.offers_hints());
}

#[test]
fn only_the_reference_completion_is_unsimulated() {
    assert!(Completion::Flag.is_simulated());
    assert!(Completion::Measurement.is_simulated());
    assert!(!Completion::Reference.is_simulated());
}

#[test]
fn a_module_id_renders_the_way_the_site_expects() {
    assert_eq!(ModuleId(0).as_string(), "m0");
    assert_eq!(ModuleId(5).as_string(), "m5");
}

#[test]
fn the_frame_layout_agrees_with_the_encoder() {
    // A plain command frame: SOM, address, two length bytes, control, id,
    // payload, two-byte CRC. If this ever disagrees with `Frame::encode`, drill
    // 2.1 marks a correct answer wrong.
    let frame = odr_osdp::Frame::command(0x01, 2, odr_osdp::Command::Led, alloc::vec![0u8; 14]);
    let layout = crate::facts::FrameLayout::of(&frame, 1_000);
    assert_eq!(layout.bytes, frame.encode());
    assert_eq!(layout.bytes.len(), frame.wire_len());
    assert_eq!(
        layout.span(FrameField::Som),
        Some(FieldSpan::new(FrameField::Som, 0, 1))
    );
    assert_eq!(
        layout.span(FrameField::Crc),
        Some(FieldSpan::new(FrameField::Crc, frame.wire_len() - 2, 2))
    );
    assert_eq!(layout.sequence, 2);

    // Every span is contiguous and together they cover the frame exactly.
    let mut at = 0usize;
    for span in &layout.spans {
        assert_eq!(span.offset, at, "{:?} is not contiguous", span.field);
        at += span.length;
    }
    assert_eq!(at, layout.bytes.len());
}

#[test]
fn the_frame_layout_places_a_security_block_and_a_mac() {
    let mut frame = odr_osdp::Frame::command(0x01, 1, odr_osdp::Command::Out, alloc::vec![0u8; 4]);
    frame.security = Some(odr_osdp::SecurityBlock::new(
        odr_osdp::ScsType::CmdEncrypted,
    ));
    frame.mac = Some([1, 2, 3, 4]);
    let layout = crate::facts::FrameLayout::of(&frame, 0);
    assert!(layout.span(FrameField::SecurityBlock).is_some());
    assert_eq!(
        layout.span(FrameField::Mac).map(|s| s.length),
        Some(4),
        "four MAC bytes go on the wire whatever the teaching length is"
    );
    assert_eq!(layout.bytes.len(), frame.encode().len());
}

#[test]
fn the_required_fields_exclude_the_mark_byte_and_nothing_else() {
    let mut frame = odr_osdp::Frame::reply(0x01, 1, odr_osdp::Reply::Ack, Vec::new());
    frame.mark = true;
    let layout = crate::facts::FrameLayout::of(&frame, 0);
    assert!(layout.span(FrameField::Mark).is_some());
    assert!(layout
        .required()
        .iter()
        .all(|s| s.field != FrameField::Mark));
    assert_eq!(layout.required().len(), layout.spans.len() - 1);
}

fn a_task(total: u128, per_second: f64) -> Task {
    Task {
        id: "test",
        label: "a long computation".to_string(),
        short_label: "a short one".to_string(),
        note: "for the arithmetic".to_string(),
        total,
        per_second,
        short_done: true,
        projected: "a while".to_string(),
    }
}

#[test]
fn a_task_bar_advances_at_the_rate_it_was_given() {
    let task = a_task(1_000, 10.0);
    assert_eq!(task.state(0).done, 0);
    assert_eq!(task.state(1_000).done, 10);
    assert_eq!(task.state(10_000).done, 100);
    assert!((task.state(10_000).fraction - 0.1).abs() < 1e-9);
    assert!((task.state(10_000).remaining_seconds - 90.0).abs() < 1e-6);
}

#[test]
fn a_task_bar_never_runs_past_its_own_total() {
    let task = a_task(100, 10.0);
    let far_future = task.state(u64::MAX / 2);
    assert_eq!(far_future.done, 100);
    assert!(far_future.is_finished());
    assert_eq!(far_future.remaining_seconds, 0.0);
}

#[test]
fn a_year_of_wall_clock_barely_dents_a_32_bit_mac() {
    // Not a claim about this crate so much as a claim about 32 bits. One
    // candidate per round trip at 9600 baud is of the order of sixteen a
    // second, so the space is a few years' work — and a year of it is about an
    // eighth. That is the figure drill 4.2 is built to make unforgettable, and
    // it is also why the drill does not pretend a century is needed: the
    // honest number is years, and years is bad enough.
    let task = a_task(1u128 << 32, 16.0);
    let year_ms = 365u64 * 86_400 * 1000;
    let state = task.state(year_ms);
    assert!(!state.is_finished(), "{}/{}", state.done, state.total);
    assert!(
        state.fraction > 0.05 && state.fraction < 0.2,
        "a year should be a noticeable but small slice: {}",
        state.fraction
    );
    assert!(state.remaining_seconds > 2.0 * 365.0 * 86_400.0);
}

#[test]
fn every_scenario_name_round_trips_and_is_unique() {
    let mut seen: Vec<&str> = Vec::new();
    for scenario in crate::ScenarioId::ALL {
        let name = scenario.name();
        assert!(!seen.contains(&name), "duplicate scenario id {name}");
        seen.push(name);
        assert_eq!(crate::ScenarioId::parse(name), Some(*scenario));
        assert!(!scenario.summary().is_empty());
    }
    assert_eq!(crate::ScenarioId::parse("not a bench"), None);
}
