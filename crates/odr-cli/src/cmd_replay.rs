//! **`odr replay` — drive the engine over recorded bytes and report the gaps.**
//!
//! `verify` checks documented assumptions. This runs the engine's own code over
//! the capture and reports every place the two part company:
//!
//! * **Re-encoding.** Every frame is parsed and then encoded again with
//!   [`Frame::encode`](odr_osdp::Frame::encode), and the result is compared byte for byte with what was
//!   on the wire. This is the sharpest test in the tool, because it exercises
//!   the header, the security block, the MAC placement and the trailer at once.
//!   A frame that does not round-trip is a frame this engine cannot produce.
//! * **The conversation.** OSDP has one master. A reply nobody asked for, a
//!   command sent before the previous one was answered, a reply whose sequence
//!   number does not match its command: the engine's ACU and PD state machines
//!   produce none of these, so each is a divergence.
//! * **The handshake.** Where a capture contains `CMD_CHLNG` and
//!   `REPLY_CCRYPT`, the client cryptogram is recomputed under the published
//!   default key and — if that fails — the whole Mellon weak-key family. A
//!   cryptogram that verifies is direct evidence that the engine's session-key
//!   derivation matches this hardware, which is `odr-osdp`'s single-source
//!   ledger entry #4. One that does not is either a site key, which is normal
//!   and reported as such, or a derivation mismatch.
//!
//! # A divergence is not necessarily your hardware's fault
//!
//! On a capture from real equipment it is more likely an assumption in this
//! engine. That is the whole point of the command, and it is what the output
//! says.

use std::collections::BTreeMap;

use odr_osdp::channel::{recover_weak_scbk, scbk_matches_handshake};
use odr_osdp::payload::Ccrypt;
use odr_osdp::weak_keys::SCBK_D;
use odr_osdp::{Command, Reply};

use crate::args::{parse_u64, Flags};
use crate::capture::{Capture, Item};
use crate::json::Json;
use crate::out::{code_name, fmt_bytes, fmt_dur, fmt_us, heading, pad_right, wrap};
use crate::{Run, EXIT_FINDINGS, EXIT_OK};

/// Flags on this command that take a value.
pub const VALUE_FLAGS: &[&str] = &["limit"];

/// One place the engine and the capture disagree.
#[derive(Debug, Clone)]
struct Divergence {
    t_us: u64,
    index: usize,
    kind: &'static str,
    expected: String,
    observed: String,
    note: &'static str,
}

/// Something the replay learned that is not a disagreement.
#[derive(Debug, Clone)]
struct Note {
    t_us: u64,
    text: String,
}

/// Run `odr replay`.
pub fn run(mut flags: Flags) -> Run {
    let json = match flags.has("json") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let limit = match flags.value("limit") {
        Ok(Some(v)) => match parse_u64("limit", &v) {
            Ok(n) => n as usize,
            Err(e) => return Run::usage(e),
        },
        Ok(None) => 50,
        Err(e) => return Run::usage(e),
    };
    let path = match flags.one_positional("capture") {
        Ok(p) => p,
        Err(e) => return Run::usage(e),
    };
    if let Err(e) = flags.finish() {
        return Run::usage(e);
    }

    let capture = match Capture::load(&path) {
        Ok(c) => c,
        Err(e) => return Run::failure(e),
    };

    let (divergences, notes, replayed) = replay(&capture);
    let diverged = !divergences.is_empty();

    Run {
        out: if json {
            render_json(&capture, &divergences, &notes, replayed, limit)
        } else {
            render_text(&capture, &divergences, &notes, replayed, limit)
        },
        err: String::new(),
        code: if diverged { EXIT_FINDINGS } else { EXIT_OK },
    }
}

/// Walk the capture through the engine.
fn replay(capture: &Capture) -> (Vec<Divergence>, Vec<Note>, usize) {
    let mut divergences = Vec::new();
    let mut notes = Vec::new();
    let mut replayed = 0usize;

    // Per-address conversation state, as an ACU would hold it.
    let mut awaiting: BTreeMap<u8, (u64, u8, u8)> = BTreeMap::new();
    // The most recent CMD_CHLNG per address, for the handshake check.
    let mut challenge: BTreeMap<u8, (u64, [u8; 8])> = BTreeMap::new();

    for event in &capture.events {
        for item in &event.items {
            let (offset, len, frame) = match item {
                Item::Frame { offset, len, frame } => (*offset, *len, frame),
                _ => continue,
            };
            replayed += 1;
            let addr = frame.address & 0x7F;

            // 1. Re-encode.
            let reencoded = frame.encode();
            let original = event.bytes.get(offset..offset + len).unwrap_or(&[]);
            if reencoded != original {
                divergences.push(Divergence {
                    t_us: event.t_us,
                    index: event.index,
                    kind: "re-encode",
                    expected: fmt_bytes(&reencoded),
                    observed: fmt_bytes(original),
                    note: "the engine cannot reproduce these bytes from its own parse of them",
                });
            }

            // 2. The conversation.
            if frame.is_reply {
                match awaiting.remove(&addr) {
                    None => divergences.push(Divergence {
                        t_us: event.t_us,
                        index: event.index,
                        kind: "unsolicited-reply",
                        expected: format!("a command to address {addr:#04x} first"),
                        observed: format!("{} with nothing outstanding", code_name(frame)),
                        note: "OSDP has one master; a peripheral speaks only when polled",
                    }),
                    Some((_, seq, _)) if seq != frame.sequence & 0x03 => {
                        divergences.push(Divergence {
                            t_us: event.t_us,
                            index: event.index,
                            kind: "reply-sequence",
                            expected: format!("sequence {seq}, matching the command"),
                            observed: format!("sequence {}", frame.sequence & 0x03),
                            note: "odr-bus answers on the sequence number the command carried",
                        })
                    }
                    Some(_) => {}
                }
            } else {
                if let Some((asked_at, _, id)) = awaiting.get(&addr) {
                    let previous = *id;
                    let since = event.t_us.saturating_sub(*asked_at);
                    divergences.push(Divergence {
                        t_us: event.t_us,
                        index: event.index,
                        kind: "unanswered-command",
                        expected: format!(
                            "a reply to {:#04x} within odr-bus's 200.000ms reply timeout",
                            previous
                        ),
                        observed: format!(
                            "a second command {} after {}",
                            code_name(frame),
                            fmt_dur(since)
                        ),
                        note: "either the probe missed a reply, or this bus does not wait",
                    });
                }
                awaiting.insert(addr, (event.t_us, frame.sequence & 0x03, frame.id));

                if frame.command_code() == Some(Command::Chlng) && frame.payload.len() >= 8 {
                    let mut rnd_a = [0u8; 8];
                    rnd_a.copy_from_slice(&frame.payload[0..8]);
                    challenge.insert(addr, (event.t_us, rnd_a));
                }
            }

            // 3. The handshake.
            if frame.reply_code() == Some(Reply::Ccrypt) {
                if let (Some((_, rnd_a)), Ok(ccrypt)) = (
                    challenge.get(&addr).copied(),
                    Ccrypt::decode(&frame.payload),
                ) {
                    notes.push(Note {
                        t_us: event.t_us,
                        text: handshake_note(addr, &rnd_a, &ccrypt),
                    });
                }
            }
        }
    }

    // Anything still outstanding at the end of the capture.
    for (addr, (asked_at, _, id)) in awaiting {
        notes.push(Note {
            t_us: asked_at,
            text: format!(
                "address {addr:#04x} was left with command {id:#04x} unanswered when the \
                 capture ended — normal at a capture boundary, not counted as a divergence"
            ),
        });
    }

    divergences.sort_by_key(|d| (d.t_us, d.index));
    notes.sort_by_key(|n| n.t_us);
    (divergences, notes, replayed)
}

/// Try the engine's own key derivation against an observed handshake.
fn handshake_note(addr: u8, rnd_a: &[u8; 8], ccrypt: &Ccrypt) -> String {
    if scbk_matches_handshake(&SCBK_D, rnd_a, &ccrypt.rnd_b, &ccrypt.client_cryptogram) {
        return format!(
            "address {addr:#04x}: the client cryptogram verifies under SCBK-D, the published \
             default key. Two things follow — this bus is keyed with a key anyone can look \
             up, and odr-osdp's session-key derivation agrees with this equipment (ledger \
             entry #3 and #4)."
        );
    }
    match recover_weak_scbk(rnd_a, &ccrypt.rnd_b, &ccrypt.client_cryptogram) {
        Some((_, pattern)) => format!(
            "address {addr:#04x}: the client cryptogram verifies under a key from the \
             published Mellon weak-key family ({pattern:?}). The derivation agrees with this \
             equipment, and the key is one of ~768 anybody can try offline from one captured \
             handshake."
        ),
        None => format!(
            "address {addr:#04x}: the client cryptogram does not verify under SCBK-D or any \
             weak key. That is the expected and healthy result for a site key — it is also \
             what a mismatch in odr-osdp's key derivation would look like, and the two \
             cannot be told apart without the key."
        ),
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_text(
    capture: &Capture,
    divergences: &[Divergence],
    notes: &[Note],
    replayed: usize,
    limit: usize,
) -> String {
    let mut s = String::new();
    s.push_str(&format!("odr replay — {}\n", capture.label));
    s.push_str(&format!(
        "{replayed} frames replayed through the engine, {} divergence(s)\n",
        divergences.len()
    ));

    if divergences.is_empty() {
        s.push_str(
            "\nThe engine reproduced every frame in this capture, and the conversation \
             followed\nthe shape its state machines produce. That is a real result: it \
             means a drill\nbuilt on these bytes teaches the same thing the bus does.\n",
        );
    } else {
        heading(&mut s, "divergences");
        for d in divergences.iter().take(limit) {
            s.push_str(&format!(
                "{}  #{}  {}\n",
                fmt_us(d.t_us),
                d.index,
                pad_right(d.kind, 20)
            ));
            s.push_str(&format!("    engine expected  {}\n", d.expected));
            s.push_str(&format!("    capture had      {}\n", d.observed));
            s.push_str(&format!("    reading          {}\n\n", d.note));
        }
        if divergences.len() > limit {
            s.push_str(&format!(
                "... and {} more; raise --limit to see them\n",
                divergences.len() - limit
            ));
        }
        s.push_str(
            "\nA divergence on a capture from real equipment is more likely an assumption \
             in this\nengine than a fault in your hardware. Please open a hardware \
             correction.\n",
        );
    }

    if !notes.is_empty() {
        heading(&mut s, "notes");
        for n in notes {
            s.push_str(&format!(
                "{}  {}\n",
                fmt_us(n.t_us),
                wrap(&n.text, 60, "             ")
            ));
        }
    }
    s
}

fn render_json(
    capture: &Capture,
    divergences: &[Divergence],
    notes: &[Note],
    replayed: usize,
    limit: usize,
) -> String {
    Json::obj()
        .with("command", Json::str("replay"))
        .with("capture", Json::str(&capture.label))
        .with("frames_replayed", Json::Num(replayed as u64))
        .with("divergences_total", Json::Num(divergences.len() as u64))
        .with(
            "divergences",
            Json::arr(divergences.iter().take(limit).map(|d| {
                Json::obj()
                    .with("t_us", Json::Num(d.t_us))
                    .with("event", Json::Num(d.index as u64))
                    .with("kind", Json::str(d.kind))
                    .with("expected", Json::str(&d.expected))
                    .with("observed", Json::str(&d.observed))
                    .with("note", Json::str(d.note))
            })),
        )
        .with(
            "notes",
            Json::arr(notes.iter().map(|n| {
                Json::obj()
                    .with("t_us", Json::Num(n.t_us))
                    .with("text", Json::str(&n.text))
            })),
        )
        .render()
}
