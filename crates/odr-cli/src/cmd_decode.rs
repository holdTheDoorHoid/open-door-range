//! **`odr decode` — the site's frame inspector, in text.**
//!
//! One line per event, with a second and third line for anything that needs
//! them. The two things this command exists to get right:
//!
//! **Encrypted frames get an honest split.** A frame under SCS_17 or SCS_18 is
//! not opaque — the address, the sequence number, the security block type, the
//! MAC and *the command byte itself* are all in the clear. That last one is the
//! reason traffic analysis works on an encrypted bus (`DESIGN.md` §2, Track 3),
//! and a decoder that printed "encrypted" and stopped would be hiding the
//! lesson. So every secured frame lists what is readable without a key and what
//! is not, separately.
//!
//! **A frame that did not decode gets a reason.** Bad CRC, bad checksum, a
//! truncated tail, an impossible length field, bytes before the first SOM: all
//! of them are printed with an offset. On a capture from real hardware these
//! are the interesting lines.

use odr_bus::capture::{CaptureDir, CaptureLine};
use odr_osdp::{Frame, ScsType};

use crate::args::{parse_address, parse_time, parse_u64, Flags, UsageError};
use crate::capture::{Capture, Event, Item};
use crate::json::Json;
use crate::out::{
    code_name, fmt_bytes, fmt_us, hex, pad_right, resolve_code, scs_name, scs_purpose,
};
use crate::{Run, EXIT_FINDINGS, EXIT_OK};

/// Flags on this command that take a value.
pub const VALUE_FLAGS: &[&str] = &["line", "address", "from", "to", "code", "limit"];

/// Which events to show.
#[derive(Debug, Clone, Default)]
struct Filter {
    line: Option<CaptureLine>,
    address: Option<u8>,
    from: Option<u64>,
    to: Option<u64>,
    codes: Vec<u8>,
    limit: Option<u64>,
}

impl Filter {
    /// True if the event is in range at all, before looking at its frames.
    fn allows_event(&self, event: &Event) -> bool {
        if let Some(line) = &self.line {
            if &event.line != line {
                return false;
            }
        }
        if let Some(from) = self.from {
            if event.t_us < from {
                return false;
            }
        }
        if let Some(to) = self.to {
            if event.t_us >= to {
                return false;
            }
        }
        true
    }

    /// True if this frame passes the address and code filters.
    fn allows_frame(&self, frame: &Frame) -> bool {
        if let Some(a) = self.address {
            if frame.address & 0x7F != a {
                return false;
            }
        }
        if !self.codes.is_empty() && !self.codes.contains(&frame.id) {
            return false;
        }
        true
    }

    /// True if a filter that only makes sense for bus traffic was given.
    fn is_frame_specific(&self) -> bool {
        self.address.is_some() || !self.codes.is_empty()
    }
}

/// Run `odr decode`.
pub fn run(mut flags: Flags) -> Run {
    let json = match flags.has("json") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let show_bytes = match flags.has("bytes") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let filter = match build_filter(&mut flags) {
        Ok(f) => f,
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

    let selected: Vec<&Event> = select(&capture, &filter);
    let problems = selected
        .iter()
        .flat_map(|e| e.items.iter())
        .filter(|i| i.is_problem())
        .count();

    let text = if json {
        render_json(&capture, &selected, problems)
    } else {
        render_text(&capture, &selected, problems, show_bytes)
    };

    Run {
        out: text,
        err: String::new(),
        code: if problems > 0 { EXIT_FINDINGS } else { EXIT_OK },
    }
}

fn build_filter(flags: &mut Flags) -> Result<Filter, UsageError> {
    let mut filter = Filter::default();
    if let Some(v) = flags.value("line")? {
        let line = CaptureLine::parse(v.trim());
        if matches!(line, CaptureLine::Other(_)) {
            return Err(UsageError::BadValue {
                flag: "line".to_string(),
                value: v,
                expected: "one of rs485, wiegand, clock_data".to_string(),
            });
        }
        filter.line = Some(line);
    }
    if let Some(v) = flags.value("address")? {
        filter.address = Some(parse_address("address", &v)?);
    }
    if let Some(v) = flags.value("from")? {
        filter.from = Some(parse_time("from", &v)?);
    }
    if let Some(v) = flags.value("to")? {
        filter.to = Some(parse_time("to", &v)?);
    }
    for v in flags.values("code")? {
        match resolve_code(&v) {
            Some(code) => filter.codes.push(code),
            None => {
                return Err(UsageError::BadValue {
                    flag: "code".to_string(),
                    value: v,
                    expected: "a command or reply name such as POLL or REPLY_ACK, or 0xNN"
                        .to_string(),
                })
            }
        }
    }
    if let Some(v) = flags.value("limit")? {
        filter.limit = Some(parse_u64("limit", &v)?);
    }
    Ok(filter)
}

/// Apply the filter, in time order.
fn select<'a>(capture: &'a Capture, filter: &Filter) -> Vec<&'a Event> {
    let mut out = Vec::new();
    for event in &capture.events {
        if !filter.allows_event(event) {
            continue;
        }
        if event.is_bus() {
            if !event.items.iter().any(|i| match i.frame() {
                Some(f) => filter.allows_frame(f),
                None => !filter.is_frame_specific(),
            }) {
                continue;
            }
        } else if filter.is_frame_specific() {
            // An address or a code filter is a statement about OSDP, and a
            // D0/D1 pair has neither. Dropping the event is more honest than
            // showing it under a filter it cannot satisfy.
            continue;
        }
        out.push(event);
        if let Some(limit) = filter.limit {
            if out.len() as u64 >= limit {
                break;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

fn render_text(capture: &Capture, selected: &[&Event], problems: usize, bytes: bool) -> String {
    let mut s = String::new();
    s.push_str(&format!("odr decode — {}\n", capture.label));
    s.push_str(&format!(
        "{} events shown of {}, {} frames, {} undecodable, {} to {}\n\n",
        selected.len(),
        capture.events.len(),
        capture.frames().count(),
        capture.problem_count(),
        fmt_us(capture.start_us()),
        fmt_us(capture.end_us()),
    ));

    if selected.is_empty() {
        s.push_str("nothing matched the filter\n");
        return s;
    }

    for event in selected {
        render_event_text(&mut s, event, bytes);
    }

    if problems > 0 {
        s.push_str(&format!(
            "\n{problems} of the shown events did not decode. Those lines start with `!`.\n"
        ));
    }
    s
}

fn render_event_text(s: &mut String, event: &Event, show_bytes: bool) {
    let stamp = format!("#{:<4} {}", event.index, fmt_us(event.t_us));
    if event.is_bus() {
        for item in &event.items {
            match item {
                Item::Frame { frame, .. } => {
                    s.push_str(&format!("{}  {}\n", stamp, frame_line(frame)));
                    if let Some(extra) = secure_note(frame) {
                        s.push_str(&extra);
                    }
                    if show_bytes {
                        s.push_str(&format!("       bytes {}\n", fmt_bytes(&frame.encode())));
                    }
                }
                Item::Malformed { offset, error } => {
                    s.push_str(&format!(
                        "! {}  rs485  not a frame at offset {}: {}\n",
                        stamp, offset, error
                    ));
                }
                Item::Incomplete { offset, error } => {
                    s.push_str(&format!(
                        "! {}  rs485  truncated at offset {}: {}\n",
                        stamp, offset, error
                    ));
                }
                Item::Garbage { offset, len } => {
                    s.push_str(&format!(
                        "  {}  rs485  {} byte(s) of non-frame data at offset {}\n",
                        stamp, len, offset
                    ));
                }
            }
        }
        if event.items.is_empty() {
            s.push_str(&format!(
                "! {}  rs485  {} bytes, nothing frame-shaped\n",
                stamp,
                event.bytes.len()
            ));
        }
        if show_bytes {
            s.push_str(&format!("       line  {}\n", fmt_bytes(&event.bytes)));
        }
        return;
    }

    // Two-wire.
    let dir = match event.dir {
        CaptureDir::Wire => "wire",
        _ => event.dir.as_str(),
    };
    let readings = event.wiegand_readings();
    s.push_str(&format!(
        "{}  {}  {}  {} bytes{}\n",
        stamp,
        pad_right(event.line.as_str(), 10),
        dir,
        event.bytes.len(),
        match event.declared_bits {
            Some(n) => format!(", {n} bits declared"),
            None => String::new(),
        }
    ));
    for (i, bits) in readings.iter().enumerate() {
        let label = if readings.len() == 1 && event.declared_bits.is_some() {
            "       ".to_string()
        } else {
            format!("       reading {}: ", i + 1)
        };
        s.push_str(&format!("{}{}\n", label, describe_bits(bits, &event.line)));
    }
    if readings.len() > 1 {
        s.push_str(
            "       (no declared bit count, so the wire does not say which reading is right)\n",
        );
    }
    if show_bytes {
        s.push_str(&format!("       bytes {}\n", fmt_bytes(&event.bytes)));
    }
}

/// One frame, as a single line.
fn frame_line(frame: &Frame) -> String {
    let mut s = format!(
        "{}  {}  addr {:#04x}  seq {}  {}",
        pad_right("rs485", 7),
        if frame.is_reply { "PD->ACU" } else { "ACU->PD" },
        frame.address & 0x7F,
        frame.sequence & 0x03,
        pad_right(&code_name(frame), 16),
    );
    s.push_str(&format!(
        "  {} payload byte{}",
        frame.payload.len(),
        if frame.payload.len() == 1 { "" } else { "s" }
    ));
    if let Some(name) = scs_name(frame) {
        s.push_str(&format!("  [{name}]"));
    }
    if !frame.use_crc {
        s.push_str("  [checksum trailer]");
    }
    if frame.mark {
        s.push_str("  [mark]");
    }
    s.trim_end().to_string()
}

/// The readable/unreadable split for a frame carrying a security block.
///
/// Returns `None` for an ordinary cleartext frame, where the split would be
/// noise: everything is readable.
fn secure_note(frame: &Frame) -> Option<String> {
    let scs = frame.security.as_ref()?.scs_type;
    let mut s = String::new();
    let mac = frame
        .mac
        .map(|m| hex(&m))
        .unwrap_or_else(|| "none".to_string());

    match scs {
        Some(t) if t.is_encrypted() => {
            s.push_str(&format!("       purpose  {}\n", scs_purpose(t)));
            s.push_str(&format!(
                "       clear    {} ({:#04x}), address {:#04x}, sequence {}, MAC {}\n",
                code_name(frame),
                frame.id,
                frame.address & 0x7F,
                frame.sequence & 0x03,
                mac
            ));
            s.push_str(&format!(
                "       opaque   the {} payload bytes, AES-128-CBC under S-ENC\n",
                frame.payload.len()
            ));
            s.push_str(
                "       note     the command byte above is NOT encrypted, which is what \
                 makes\n                traffic analysis work on an encrypted bus\n",
            );
        }
        Some(t @ (ScsType::CmdMacOnly | ScsType::ReplyMacOnly)) => {
            s.push_str(&format!("       purpose  {}\n", scs_purpose(t)));
            s.push_str(&format!(
                "       clear    everything, including the {} payload bytes — this block \
                 authenticates\n                but does not encrypt (MAC {})\n",
                frame.payload.len(),
                mac
            ));
        }
        Some(t) => {
            s.push_str(&format!("       purpose  {}\n", scs_purpose(t)));
            s.push_str(&format!(
                "       clear    everything: a handshake frame carries no session \
                 ciphertext ({} bytes)\n",
                frame.payload.len()
            ));
        }
        None => {
            s.push_str(&format!(
                "       purpose  unknown security block type {:#04x}; the frame still \
                 decodes\n",
                frame.security.as_ref().map(|b| b.raw_type).unwrap_or(0)
            ));
        }
    }
    Some(s)
}

/// The best reading of a bit stream, named.
///
/// A clock-and-data pair carries ABA track 2 rather than a card format, so it
/// gets the track-2 decoder. Everything else goes through
/// `odr_wiegand::infer_formats`, and a stream that fits no named format is
/// reported as raw **without** a parity claim — `CardFormat::Raw` has no parity
/// rules, so "parity ok" on one would be a statement about nothing.
fn describe_bits(bits: &odr_wiegand::BitVec, line: &CaptureLine) -> String {
    if matches!(line, CaptureLine::ClockData) {
        return match odr_wiegand::decode_aba(bits) {
            Ok(aba) => format!(
                "{} bits  ABA track 2  \"{}\"  LRC {}  parity {}",
                bits.len(),
                aba.track
                    .data
                    .iter()
                    // Track-2 nibbles 0x0..0xF map to ASCII '0'..'?'.
                    .map(|n| char::from(b'0'.saturating_add(*n & 0x0F)))
                    .collect::<String>(),
                if aba.lrc_valid { "ok" } else { "FAILED" },
                if aba.parity_valid() { "ok" } else { "FAILED" },
            ),
            Err(e) => format!("{} bits  not ABA track 2: {e}", bits.len()),
        };
    }
    let candidates = odr_wiegand::infer_formats(bits);
    match candidates.first() {
        Some(c) if !matches!(c.decoded.format, odr_wiegand::CardFormat::Raw { .. }) => {
            let d = &c.decoded;
            let fields = match (d.facility_code, d.card_number) {
                (Some(fc), Some(cn)) => format!("FC {fc} CN {cn}"),
                (None, Some(cn)) => format!("CN {cn}"),
                _ => format!("0x{}", bits.to_hex_string()),
            };
            format!(
                "{} bits  {}  {}  parity {}",
                bits.len(),
                pad_right(d.format.name(), 8),
                fields,
                if c.parity_valid { "ok" } else { "FAILED" }
            )
        }
        _ => format!(
            "{} bits  {}  0x{}  (no named card format of this width; no parity to check)",
            bits.len(),
            pad_right("raw", 8),
            bits.to_hex_string()
        ),
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn render_json(capture: &Capture, selected: &[&Event], problems: usize) -> String {
    let mut root = Json::obj()
        .with("command", Json::str("decode"))
        .with("capture", Json::str(&capture.label))
        .with("events_total", Json::Num(capture.events.len() as u64))
        .with("events_shown", Json::Num(selected.len() as u64))
        .with("frames", Json::Num(capture.frames().count() as u64))
        .with("undecodable", Json::Num(problems as u64))
        .with("start_us", Json::Num(capture.start_us()))
        .with("end_us", Json::Num(capture.end_us()));

    let events: Vec<Json> = selected.iter().map(|e| event_json(e)).collect();
    root.set("events", Json::arr(events));
    root.render()
}

fn event_json(event: &Event) -> Json {
    let mut obj = Json::obj()
        .with("index", Json::Num(event.index as u64))
        .with("source_line", Json::Num(event.source_line as u64))
        .with("t_us", Json::Num(event.t_us))
        .with("line", Json::str(event.line.as_str()))
        .with("dir", Json::str(event.dir.as_str()))
        .with("bytes", Json::str(hex(&event.bytes)));

    if event.is_bus() {
        let items: Vec<Json> = event.items.iter().map(item_json).collect();
        obj.set("items", Json::arr(items));
    } else {
        if let Some(n) = event.declared_bits {
            obj.set("declared_bits", Json::Num(n as u64));
        }
        let readings: Vec<Json> = event
            .wiegand_readings()
            .iter()
            .map(|bits| {
                let best = odr_wiegand::infer_formats(bits);
                let mut r = Json::obj()
                    .with("bits", Json::Num(bits.len() as u64))
                    .with("hex", Json::str(bits.to_hex_string()));
                if let Some(c) = best.first() {
                    r.set("format", Json::str(c.decoded.format.name()));
                    r.set("parity_valid", Json::Bool(c.parity_valid));
                    if let Some(fc) = c.decoded.facility_code {
                        r.set("facility_code", Json::Num(fc));
                    }
                    if let Some(cn) = c.decoded.card_number {
                        r.set("card_number", Json::Num(cn));
                    }
                }
                r
            })
            .collect();
        obj.set("readings", Json::arr(readings));
    }
    obj
}

fn item_json(item: &Item) -> Json {
    match item {
        Item::Frame { offset, len, frame } => {
            let mut f = Json::obj()
                .with("kind", Json::str("frame"))
                .with("offset", Json::Num(*offset as u64))
                .with("len", Json::Num(*len as u64))
                .with(
                    "direction",
                    Json::str(if frame.is_reply {
                        "pd_to_acu"
                    } else {
                        "acu_to_pd"
                    }),
                )
                .with("address", Json::Num((frame.address & 0x7F) as u64))
                .with("sequence", Json::Num((frame.sequence & 0x03) as u64))
                .with("id", Json::Num(frame.id as u64))
                .with("name", Json::str(code_name(frame)))
                .with("payload_len", Json::Num(frame.payload.len() as u64))
                .with("use_crc", Json::Bool(frame.use_crc))
                .with("mark", Json::Bool(frame.mark));
            if let Some(sec) = &frame.security {
                let mut s = Json::obj().with("raw_type", Json::Num(sec.raw_type as u64));
                if let Some(t) = sec.scs_type {
                    s.set("scs", Json::str(format!("SCS_{:02X}", t.to_u8())));
                    s.set("encrypted", Json::Bool(t.is_encrypted()));
                    s.set("handshake", Json::Bool(t.is_handshake()));
                    s.set("purpose", Json::str(scs_purpose(t)));
                }
                s.set("len", Json::Num(sec.encoded_len() as u64));
                f.set("security", s);
            }
            if let Some(mac) = frame.mac {
                f.set("mac", Json::str(hex(&mac)));
            }
            f.set("payload", Json::str(hex(&frame.payload)));
            f
        }
        Item::Garbage { offset, len } => Json::obj()
            .with("kind", Json::str("garbage"))
            .with("offset", Json::Num(*offset as u64))
            .with("len", Json::Num(*len as u64)),
        Item::Malformed { offset, error } => Json::obj()
            .with("kind", Json::str("malformed"))
            .with("offset", Json::Num(*offset as u64))
            .with("error", Json::str(error.to_string())),
        Item::Incomplete { offset, error } => Json::obj()
            .with("kind", Json::str("incomplete"))
            .with("offset", Json::Num(*offset as u64))
            .with("error", Json::str(error.to_string())),
    }
}
