//! **`odr stats` — the summary somebody pastes into an issue.**
//!
//! No judgements. Counts, cadence, latency and posture: the shape of the
//! traffic, so that two people looking at two different buses can tell whether
//! they are looking at the same thing.
//!
//! Timing is reported as a five-number summary — minimum, median, 90th
//! percentile, maximum and count — rather than a mean, because a bus is not
//! normally distributed. One retry after a timeout moves a mean and does not
//! move a median, and it is exactly the event somebody wants to see in the
//! maximum.
//!
//! Percentiles are nearest-rank over integers. Every number printed here is a
//! measurement that actually occurred, which matters when it is being compared
//! against a hardware capture byte for byte.

use std::collections::BTreeMap;

use odr_osdp::{Frame, KeyType};

use crate::args::Flags;
use crate::capture::Capture;
use crate::json::Json;
use crate::out::{fmt_dur, fmt_us, heading, pad_left, pad_right, percentile};
use crate::Run;

/// Flags on this command that take a value.
pub const VALUE_FLAGS: &[&str] = &[];

/// Run `odr stats`.
pub fn run(mut flags: Flags) -> Run {
    let json = match flags.has("json") {
        Ok(v) => v,
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
    let stats = Stats::of(&capture);
    Run::ok(if json {
        stats.to_json(&capture)
    } else {
        stats.to_text(&capture)
    })
}

/// A five-number summary of a set of intervals.
#[derive(Debug, Clone, Default)]
struct Spread {
    values: Vec<u64>,
}

impl Spread {
    fn push(&mut self, v: u64) {
        self.values.push(v);
    }

    fn finish(&mut self) {
        self.values.sort_unstable();
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn line(&self) -> String {
        if self.values.is_empty() {
            return "no samples".to_string();
        }
        format!(
            "n={}  min {}  median {}  p90 {}  max {}",
            self.values.len(),
            fmt_dur(self.values[0]),
            fmt_dur(percentile(&self.values, 50).unwrap_or(0)),
            fmt_dur(percentile(&self.values, 90).unwrap_or(0)),
            fmt_dur(*self.values.last().unwrap_or(&0)),
        )
    }

    fn to_json(&self) -> Json {
        if self.values.is_empty() {
            return Json::obj().with("samples", Json::Num(0));
        }
        Json::obj()
            .with("samples", Json::Num(self.values.len() as u64))
            .with("min_us", Json::Num(self.values[0]))
            .with(
                "median_us",
                Json::Num(percentile(&self.values, 50).unwrap_or(0)),
            )
            .with(
                "p90_us",
                Json::Num(percentile(&self.values, 90).unwrap_or(0)),
            )
            .with("max_us", Json::Num(*self.values.last().unwrap_or(&0)))
    }
}

/// What one peripheral address looked like.
#[derive(Debug, Clone, Default)]
struct AddressStats {
    commands: usize,
    replies: usize,
    cleartext: usize,
    handshake: usize,
    mac_only: usize,
    encrypted: usize,
    unknown_block: usize,
    key_type: Option<KeyType>,
    sequences: [usize; 4],
    poll_gaps: Spread,
    reply_latency: Spread,
}

impl AddressStats {
    /// One sentence about where this address sits on the posture ladder.
    fn posture(&self) -> &'static str {
        if self.encrypted > 0 {
            "secure channel, payloads encrypted"
        } else if self.mac_only > 0 {
            "secure channel, MAC only — payloads are NOT encrypted"
        } else if self.handshake > 0 {
            "secure channel attempted; no in-session frames seen"
        } else if self.unknown_block > 0 {
            "carries security blocks this build does not recognise"
        } else {
            "cleartext: nothing encrypted, nothing authenticated"
        }
    }
}

/// Everything `stats` reports.
#[derive(Debug, Default)]
struct Stats {
    events: usize,
    bus_events: usize,
    wire_events: usize,
    by_line: BTreeMap<String, usize>,
    frames: usize,
    undecodable: usize,
    commands: BTreeMap<u8, usize>,
    replies: BTreeMap<u8, usize>,
    addresses: BTreeMap<u8, AddressStats>,
    frame_gaps: Spread,
    card_reads: Vec<(u64, usize, String)>,
    checksum_frames: usize,
    mark_frames: usize,
}

impl Stats {
    fn of(capture: &Capture) -> Stats {
        let mut s = Stats {
            events: capture.events.len(),
            undecodable: capture.problem_count(),
            ..Stats::default()
        };

        for event in &capture.events {
            *s.by_line
                .entry(event.line.as_str().to_string())
                .or_default() += 1;
            if event.is_bus() {
                s.bus_events += 1;
            } else if event.is_wire() {
                s.wire_events += 1;
                let readings = event.wiegand_readings();
                if let Some(bits) = readings.first() {
                    let name = odr_wiegand::infer_formats(bits)
                        .first()
                        .map(|c| {
                            format!(
                                "{}{}",
                                c.decoded.format.name(),
                                if c.parity_valid {
                                    ""
                                } else {
                                    " (parity FAILED)"
                                }
                            )
                        })
                        .unwrap_or_else(|| "unrecognised".to_string());
                    s.card_reads.push((event.t_us, bits.len(), name));
                }
            }
        }

        // One pass over the frames in time order builds the code histograms,
        // the per-address posture and both timing spreads.
        let frames: Vec<(u64, &Frame)> = capture.frames().map(|(e, f)| (e.t_us, f)).collect();
        s.frames = frames.len();

        let mut last_frame_us: Option<u64> = None;
        let mut last_poll: BTreeMap<u8, u64> = BTreeMap::new();
        let mut open_command: BTreeMap<u8, u64> = BTreeMap::new();

        for (t_us, frame) in &frames {
            let addr = frame.address & 0x7F;
            if let Some(prev) = last_frame_us {
                s.frame_gaps.push(t_us.saturating_sub(prev));
            }
            last_frame_us = Some(*t_us);

            if !frame.use_crc {
                s.checksum_frames += 1;
            }
            if frame.mark {
                s.mark_frames += 1;
            }

            let entry = s.addresses.entry(addr).or_default();
            entry.sequences[(frame.sequence & 0x03) as usize] += 1;

            match &frame.security {
                None => entry.cleartext += 1,
                Some(block) => match block.scs_type {
                    Some(t) if t.is_handshake() => {
                        entry.handshake += 1;
                        if entry.key_type.is_none() {
                            entry.key_type = block.key_type();
                        }
                    }
                    Some(t) if t.is_encrypted() => entry.encrypted += 1,
                    Some(_) => entry.mac_only += 1,
                    None => entry.unknown_block += 1,
                },
            }

            if frame.is_reply {
                entry.replies += 1;
                *s.replies.entry(frame.id).or_default() += 1;
                if let Some(asked) = open_command.remove(&addr) {
                    entry.reply_latency.push(t_us.saturating_sub(asked));
                }
            } else {
                entry.commands += 1;
                *s.commands.entry(frame.id).or_default() += 1;
                open_command.insert(addr, *t_us);
                if frame.command_code() == Some(odr_osdp::Command::Poll) {
                    if let Some(prev) = last_poll.insert(addr, *t_us) {
                        entry.poll_gaps.push(t_us.saturating_sub(prev));
                    }
                }
            }
        }

        s.frame_gaps.finish();
        for entry in s.addresses.values_mut() {
            entry.poll_gaps.finish();
            entry.reply_latency.finish();
        }
        s
    }

    fn to_text(&self, capture: &Capture) -> String {
        let mut s = String::new();
        s.push_str(&format!("odr stats — {}\n", capture.label));
        s.push_str(&format!(
            "{} events, {} to {} ({})\n",
            self.events,
            fmt_us(capture.start_us()),
            fmt_us(capture.end_us()),
            fmt_dur(capture.end_us().saturating_sub(capture.start_us())),
        ));
        for (line, count) in &self.by_line {
            s.push_str(&format!("  {} {}\n", pad_right(line, 12), count));
        }
        s.push_str(&format!(
            "{} OSDP frames, {} undecodable\n",
            self.frames, self.undecodable
        ));
        if self.checksum_frames > 0 {
            s.push_str(&format!(
                "  {} frames used the one-byte checksum rather than CRC-16\n",
                self.checksum_frames
            ));
        }
        if self.mark_frames > 0 {
            s.push_str(&format!(
                "  {} frames were preceded by a 0xFF mark byte\n",
                self.mark_frames
            ));
        }

        if !self.commands.is_empty() || !self.replies.is_empty() {
            heading(&mut s, "codes");
            for (id, count) in &self.commands {
                s.push_str(&format!(
                    "  {}  {}  {}\n",
                    pad_left(&count.to_string(), 5),
                    format_args!("{id:#04x}"),
                    name_of(*id, false)
                ));
            }
            if !self.commands.is_empty() && !self.replies.is_empty() {
                s.push('\n');
            }
            for (id, count) in &self.replies {
                s.push_str(&format!(
                    "  {}  {}  {}\n",
                    pad_left(&count.to_string(), 5),
                    format_args!("{id:#04x}"),
                    name_of(*id, true)
                ));
            }
        }

        if !self.addresses.is_empty() {
            heading(&mut s, "per address");
            for (addr, a) in &self.addresses {
                s.push_str(&format!(
                    "  {:#04x}  {} commands, {} replies\n",
                    addr, a.commands, a.replies
                ));
                s.push_str(&format!("        posture   {}\n", a.posture()));
                s.push_str(&format!(
                    "        blocks    {} cleartext, {} handshake, {} MAC-only, {} encrypted\
                     {}\n",
                    a.cleartext,
                    a.handshake,
                    a.mac_only,
                    a.encrypted,
                    if a.unknown_block > 0 {
                        format!(", {} unrecognised", a.unknown_block)
                    } else {
                        String::new()
                    }
                ));
                if let Some(kt) = a.key_type {
                    s.push_str(&format!(
                        "        key       {}\n",
                        match kt {
                            KeyType::Default =>
                                "SCBK-D, the published default — announced in the clear",
                            KeyType::SiteKey => "a site key (SCBK)",
                        }
                    ));
                }
                s.push_str(&format!(
                    "        sequence  0:{} 1:{} 2:{} 3:{}\n",
                    a.sequences[0], a.sequences[1], a.sequences[2], a.sequences[3]
                ));
                if !a.poll_gaps.is_empty() {
                    s.push_str(&format!("        poll gap  {}\n", a.poll_gaps.line()));
                }
                if !a.reply_latency.is_empty() {
                    s.push_str(&format!("        reply in  {}\n", a.reply_latency.line()));
                }
                s.push('\n');
            }
        }

        if !self.frame_gaps.is_empty() {
            heading(&mut s, "bus timing");
            s.push_str(&format!("  frame to frame  {}\n", self.frame_gaps.line()));
            s.push_str(
                "  (start to start. A capture records when a transmission began, not how \
                 long it\n   occupied the line, so this is an upper bound on the idle gap an \
                 injector\n   would have to hit.)\n",
            );
        }

        if !self.card_reads.is_empty() {
            heading(&mut s, "two-wire card reads");
            for (t_us, bits, name) in &self.card_reads {
                s.push_str(&format!("  {}  {} bits  {}\n", fmt_us(*t_us), bits, name));
            }
        }
        s
    }

    fn to_json(&self, capture: &Capture) -> String {
        let mut root = Json::obj()
            .with("command", Json::str("stats"))
            .with("capture", Json::str(&capture.label))
            .with("events", Json::Num(self.events as u64))
            .with("bus_events", Json::Num(self.bus_events as u64))
            .with("wire_events", Json::Num(self.wire_events as u64))
            .with("frames", Json::Num(self.frames as u64))
            .with("undecodable", Json::Num(self.undecodable as u64))
            .with("checksum_frames", Json::Num(self.checksum_frames as u64))
            .with("mark_frames", Json::Num(self.mark_frames as u64))
            .with("start_us", Json::Num(capture.start_us()))
            .with("end_us", Json::Num(capture.end_us()));

        root.set(
            "by_line",
            Json::Obj(
                self.by_line
                    .iter()
                    .map(|(k, v)| (k.clone(), Json::Num(*v as u64)))
                    .collect(),
            ),
        );
        root.set(
            "commands",
            Json::arr(self.commands.iter().map(|(id, count)| {
                Json::obj()
                    .with("id", Json::Num(*id as u64))
                    .with("name", Json::str(name_of(*id, false)))
                    .with("count", Json::Num(*count as u64))
            })),
        );
        root.set(
            "replies",
            Json::arr(self.replies.iter().map(|(id, count)| {
                Json::obj()
                    .with("id", Json::Num(*id as u64))
                    .with("name", Json::str(name_of(*id, true)))
                    .with("count", Json::Num(*count as u64))
            })),
        );
        root.set(
            "addresses",
            Json::arr(self.addresses.iter().map(|(addr, a)| {
                Json::obj()
                    .with("address", Json::Num(*addr as u64))
                    .with("commands", Json::Num(a.commands as u64))
                    .with("replies", Json::Num(a.replies as u64))
                    .with("posture", Json::str(a.posture()))
                    .with("cleartext_frames", Json::Num(a.cleartext as u64))
                    .with("handshake_frames", Json::Num(a.handshake as u64))
                    .with("mac_only_frames", Json::Num(a.mac_only as u64))
                    .with("encrypted_frames", Json::Num(a.encrypted as u64))
                    .with(
                        "key_type",
                        match a.key_type {
                            Some(KeyType::Default) => Json::str("scbk_d"),
                            Some(KeyType::SiteKey) => Json::str("scbk"),
                            None => Json::Null,
                        },
                    )
                    .with(
                        "sequences",
                        Json::arr(a.sequences.iter().map(|n| Json::Num(*n as u64))),
                    )
                    .with("poll_gap", a.poll_gaps.to_json())
                    .with("reply_latency", a.reply_latency.to_json())
            })),
        );
        root.set("frame_gap", self.frame_gaps.to_json());
        root.set(
            "card_reads",
            Json::arr(self.card_reads.iter().map(|(t, bits, name)| {
                Json::obj()
                    .with("t_us", Json::Num(*t))
                    .with("bits", Json::Num(*bits as u64))
                    .with("best_format", Json::str(name))
            })),
        );
        root.render()
    }
}

/// The engine's name for a code, or a marker that it has none.
fn name_of(id: u8, reply: bool) -> String {
    if reply {
        match odr_osdp::Reply::from_u8(id) {
            Some(r) => r.name().to_string(),
            None => format!("unknown reply {id:#04x}"),
        }
    } else {
        match odr_osdp::Command::from_u8(id) {
            Some(c) => c.name().to_string(),
            None => format!("unknown command {id:#04x}"),
        }
    }
}
