//! **`odr verify` — the reason this crate is worth building.**
//!
//! `CONTRIBUTING.md`: *the contribution that matters most is not a feature. It
//! is: I ran this against a real reader and here is where it differs.* Every
//! protocol crate in this workspace ships a ledger of what it was unsure about,
//! because the OSDP specification is paywalled and the open implementations
//! disagree with each other in places. This command turns those ledger entries
//! into checks and runs them against real bytes.
//!
//! # What a check is
//!
//! A [`Check`] is an assumption the engine makes, the ledger entry it came
//! from, and a verdict against one capture. There are four verdicts and the
//! useful one is not `pass`:
//!
//! | Verdict | Meaning |
//! |---|---|
//! | `pass` | the capture agrees with what the engine assumes |
//! | `differs` | the capture disagrees. **This is the finding. File it.** |
//! | `inconclusive` | the capture does not contain the traffic this check needs |
//! | `n/a` | the check does not apply to this kind of capture |
//!
//! `inconclusive` is deliberately loud rather than hidden. "Your capture does
//! not settle this, and here is the traffic that would" is a useful thing to
//! tell somebody who has the hardware in front of them and five minutes left.
//!
//! # The output is an issue body
//!
//! The run ends with a block sized and shaped for
//! `.github/ISSUE_TEMPLATE/hardware-correction.yml`, naming the ledger entries
//! any differing check relates to, because that template asks for exactly that
//! and nobody should have to work it out by hand at the end of a long day.

use std::collections::{BTreeMap, BTreeSet};

use odr_osdp::{Command, Frame, Reply, ScsType};

use crate::args::Flags;
use crate::capture::{Capture, Item};
use crate::json::Json;
use crate::out::{fmt_dur, fmt_us, heading, pad_right, percentile, wrap};
use crate::{Run, EXIT_FINDINGS, EXIT_OK};

/// Flags on this command that take a value.
pub const VALUE_FLAGS: &[&str] = &[];

/// AES block size, and therefore the granularity of an encrypted payload.
const BLOCK: usize = 16;

/// What one check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The capture agrees with the engine.
    Pass,
    /// The capture disagrees. The useful outcome.
    Differs,
    /// The capture does not contain the traffic this check needs.
    Inconclusive,
    /// The check does not apply to this kind of capture.
    NotApplicable,
}

impl Verdict {
    /// The spelling used in output, machine and human alike.
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Differs => "differs",
            Verdict::Inconclusive => "inconclusive",
            Verdict::NotApplicable => "n/a",
        }
    }
}

/// One assumption, checked.
#[derive(Debug, Clone)]
pub struct Check {
    /// A stable machine name.
    pub id: &'static str,
    /// What is being checked, in a phrase.
    pub title: &'static str,
    /// Which uncertainty ledger entry this relates to, written so it can be
    /// pasted into the issue template's "ledger entry" field unchanged.
    pub ledger: &'static str,
    /// What was concluded.
    pub verdict: Verdict,
    /// One line of result.
    pub summary: String,
    /// Supporting lines: the specific frames, offsets and numbers.
    pub detail: Vec<String>,
}

impl Check {
    fn new(id: &'static str, title: &'static str, ledger: &'static str) -> Check {
        Check {
            id,
            title,
            ledger,
            verdict: Verdict::Inconclusive,
            summary: String::new(),
            detail: Vec::new(),
        }
    }

    fn conclude(mut self, verdict: Verdict, summary: impl Into<String>) -> Check {
        self.verdict = verdict;
        self.summary = summary.into();
        self
    }

    fn note(mut self, line: impl Into<String>) -> Check {
        self.detail.push(line.into());
        self
    }
}

/// Run `odr verify`.
pub fn run(mut flags: Flags) -> Run {
    let json = match flags.has("json") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    let list = match flags.has("list") {
        Ok(v) => v,
        Err(e) => return Run::usage(e),
    };
    if list {
        if let Err(e) = flags.finish() {
            return Run::usage(e);
        }
        return Run::ok(if json { list_json() } else { list_text() });
    }
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

    let checks = run_checks(&capture);
    let differs = checks.iter().any(|c| c.verdict == Verdict::Differs);

    Run {
        out: if json {
            render_json(&capture, &checks)
        } else {
            render_text(&capture, &checks)
        },
        err: String::new(),
        code: if differs { EXIT_FINDINGS } else { EXIT_OK },
    }
}

/// Every check, against one capture, in a fixed order.
pub fn run_checks(capture: &Capture) -> Vec<Check> {
    let frames: Vec<(u64, &Frame)> = capture.frames().map(|(e, f)| (e.t_us, f)).collect();
    vec![
        check_trailers(capture),
        check_command_codes(&frames),
        check_reply_codes(&frames),
        check_abort_code(&frames),
        check_single_source_codes(&frames),
        check_handshake_lengths(&frames),
        check_security_block_lengths(&frames),
        check_mac_and_padding(&frames),
        check_null_cipher_selection(&frames),
        check_mac_chain_iv(&frames),
        check_sequence_cycle(&frames),
        check_timing_model(&frames),
        check_wiegand_bit_counts(capture),
    ]
}

// ---------------------------------------------------------------------------
// 1. Trailers
// ---------------------------------------------------------------------------

fn check_trailers(capture: &Capture) -> Check {
    let c = Check::new(
        "frame-trailers",
        "every frame's CRC-16/AUG-CCITT or one-byte checksum verifies",
        "odr-osdp \"Things I was not certain about\", preamble — the whole crate was \
         cross-referenced against three implementations rather than the standard. The CRC \
         itself is pinned by its catalogue check value, crc16(\"123456789\") == 0xE5CC.",
    );

    let mut ok = 0usize;
    let mut bad: Vec<String> = Vec::new();
    let mut truncated = 0usize;
    for event in &capture.events {
        for item in &event.items {
            match item {
                Item::Frame { .. } => ok += 1,
                Item::Malformed { offset, error } => bad.push(format!(
                    "#{} {} offset {}: {}",
                    event.index,
                    fmt_us(event.t_us),
                    offset,
                    error
                )),
                Item::Incomplete { .. } => truncated += 1,
                Item::Garbage { .. } => {}
            }
        }
    }

    if ok == 0 && bad.is_empty() {
        return c.conclude(
            Verdict::NotApplicable,
            "no OSDP frames in this capture".to_string(),
        );
    }
    let total = ok + bad.len();
    let mut c = if bad.is_empty() {
        c.conclude(
            Verdict::Pass,
            format!("{ok}/{total} frames carried a valid trailer"),
        )
    } else {
        let mut c = c.conclude(
            Verdict::Differs,
            format!("{}/{} frames failed their trailer check", bad.len(), total),
        );
        for line in bad.iter().take(10) {
            c = c.note(line.clone());
        }
        if bad.len() > 10 {
            c = c.note(format!("... and {} more", bad.len() - 10));
        }
        c.note(
            "A trailer failure is corruption or tampering, not a protocol disagreement — \
             but if a whole capture fails, the polynomial or the initial value is the thing \
             to check.",
        )
    };
    if truncated > 0 {
        c = c.note(format!(
            "{truncated} frames ran off the end of their capture line. That is usually the \
             capture tool's buffering rather than the bus."
        ));
    }
    c
}

// ---------------------------------------------------------------------------
// 2 and 3. Code sets
// ---------------------------------------------------------------------------

fn check_command_codes(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "command-codes",
        "every command code is in the set odr-osdp claims for v2.2.2",
        "odr-osdp \"Things I was not certain about\", preamble — the command set came from \
         libosdp, jeff and go-osdp, not from IEC 60839-11-5.",
    );
    let mut unknown: BTreeMap<u8, usize> = BTreeMap::new();
    let mut total = 0usize;
    for (_, f) in frames.iter().filter(|(_, f)| !f.is_reply) {
        total += 1;
        if Command::from_u8(f.id).is_none() {
            *unknown.entry(f.id).or_default() += 1;
        }
    }
    if total == 0 {
        return c.conclude(Verdict::Inconclusive, "no commands in this capture");
    }
    if unknown.is_empty() {
        return c.conclude(
            Verdict::Pass,
            format!(
                "{total} commands, all {} known",
                distinct_ids(frames, false)
            ),
        );
    }
    let mut c = c.conclude(
        Verdict::Differs,
        format!(
            "{} command code(s) not in odr-osdp's set, over {} frames",
            unknown.len(),
            unknown.values().sum::<usize>()
        ),
    );
    for (id, count) in &unknown {
        c = c.note(format!(
            "{id:#04x} seen {count} time(s){}",
            match Reply::from_u8(*id) {
                Some(r) => format!(" — note {:#04x} is {} in the reply direction", id, r.name()),
                None => String::new(),
            }
        ));
    }
    c.note("Each of these is a code this project does not model. That is the finding.")
}

fn check_reply_codes(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "reply-codes",
        "every reply code is in the set odr-osdp claims for v2.2.2",
        "odr-osdp \"Things I was not certain about\", preamble — as for commands.",
    );
    let mut unknown: BTreeMap<u8, usize> = BTreeMap::new();
    let mut total = 0usize;
    for (_, f) in frames.iter().filter(|(_, f)| f.is_reply) {
        total += 1;
        if Reply::from_u8(f.id).is_none() {
            *unknown.entry(f.id).or_default() += 1;
        }
    }
    if total == 0 {
        return c.conclude(Verdict::Inconclusive, "no replies in this capture");
    }
    if unknown.is_empty() {
        return c.conclude(
            Verdict::Pass,
            format!("{total} replies, all {} known", distinct_ids(frames, true)),
        );
    }
    let mut c = c.conclude(
        Verdict::Differs,
        format!("{} reply code(s) not in odr-osdp's set", unknown.len()),
    );
    for (id, count) in &unknown {
        c = c.note(format!("{id:#04x} seen {count} time(s)"));
    }
    c
}

fn distinct_ids(frames: &[(u64, &Frame)], replies: bool) -> usize {
    frames
        .iter()
        .filter(|(_, f)| f.is_reply == replies)
        .map(|(_, f)| f.id)
        .collect::<BTreeSet<u8>>()
        .len()
}

// ---------------------------------------------------------------------------
// 4. CMD_ABORT
// ---------------------------------------------------------------------------

fn check_abort_code(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "abort-code",
        "CMD_ABORT is 0xA2, not 0x7A",
        "odr-osdp \"Things I was not certain about\" #1 — genuinely contested. libosdp and \
         jeff say 0xA2; go-osdp says 0x7A, which is REPLY_FTSTAT in the other direction. \
         odr-osdp uses 0xA2 on two sources to one.",
    );
    let a2: Vec<&(u64, &Frame)> = frames
        .iter()
        .filter(|(_, f)| !f.is_reply && f.id == 0xA2)
        .collect();
    let seven_a: Vec<&(u64, &Frame)> = frames
        .iter()
        .filter(|(_, f)| !f.is_reply && f.id == 0x7A)
        .collect();

    match (a2.is_empty(), seven_a.is_empty()) {
        (true, true) => c
            .conclude(Verdict::Inconclusive, "no command used either 0xA2 or 0x7A")
            .note(
                "To settle this: make a controller abort a file transfer or a smart-card \
                 exchange while capturing, and look at which byte the command carries.",
            ),
        (false, true) => c
            .conclude(
                Verdict::Pass,
                format!(
                    "{} command(s) used 0xA2, which is what odr-osdp assigns to CMD_ABORT",
                    a2.len()
                ),
            )
            .note(format!(
                "first at {}, address {:#04x}",
                fmt_us(a2[0].0),
                a2[0].1.address & 0x7F
            ))
            .note(
                "This is evidence for the two-source reading. Worth reporting even though \
                 it agrees — the ledger entry says \"check this against a capture from real \
                 v2.2 gear\".",
            ),
        (true, false) => c
            .conclude(
                Verdict::Differs,
                format!(
                    "{} command(s) used 0x7A, which odr-osdp does not assign to any command",
                    seven_a.len()
                ),
            )
            .note(format!(
                "first at {}, address {:#04x}, {} payload bytes",
                fmt_us(seven_a[0].0),
                seven_a[0].1.address & 0x7F,
                seven_a[0].1.payload.len()
            ))
            .note(
                "If this equipment means CMD_ABORT by 0x7A, go-osdp is right and this \
                 project is wrong. That is exactly the correction ledger entry #1 asks for.",
            ),
        (false, false) => c
            .conclude(
                Verdict::Differs,
                "commands used both 0xA2 and 0x7A".to_string(),
            )
            .note(
                "Both byte values appear as commands, which neither reading predicts. \
                 Please include the surrounding frames in the issue.",
            ),
    }
}

// ---------------------------------------------------------------------------
// 5. Single-source codes
// ---------------------------------------------------------------------------

fn check_single_source_codes(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "single-source-codes",
        "CMD_DIAG 0x63, CMD_RMODE 0x6C and CMD_TDSET 0x6D exist at all",
        "odr-osdp \"Things I was not certain about\" #2 — each of these appears in exactly \
         one of the three cross-referenced implementations, and two are marked deprecated. \
         They may not be in v2.2.2 at all.",
    );
    let watched: [(u8, &str); 3] = [(0x63, "CMD_DIAG"), (0x6C, "CMD_RMODE"), (0x6D, "CMD_TDSET")];
    let mut seen: Vec<String> = Vec::new();
    for (id, name) in watched {
        let count = frames
            .iter()
            .filter(|(_, f)| !f.is_reply && f.id == id)
            .count();
        if count > 0 {
            seen.push(format!("{name} ({id:#04x}) seen {count} time(s)"));
        }
    }
    if seen.is_empty() {
        return c
            .conclude(Verdict::Inconclusive, "none of the three appeared")
            .note(
                "Absence is not evidence either way — these are diagnostic and \
                 commissioning commands that a running door never sends.",
            );
    }
    let mut c = c.conclude(
        Verdict::Pass,
        format!("{} of the three appeared on this bus", seen.len()),
    );
    for line in seen {
        c = c.note(line);
    }
    c.note("Observing one of these is direct evidence it is real. Please report it.")
}

// ---------------------------------------------------------------------------
// 6. Handshake payload lengths
// ---------------------------------------------------------------------------

fn check_handshake_lengths(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "handshake-payload-lengths",
        "CHLNG 8, CCRYPT 32, SCRYPT 16, RMAC_I 16",
        "odr-osdp \"Things I was not certain about\" #3 and #4 — the session-key derivation \
         constants are two-source and the initial R-MAC construction is single-source. The \
         payload lengths are the visible consequence of both.",
    );
    // (is_reply, id, name, expected payload length, what it carries)
    let expected: [(bool, u8, &str, usize, &str); 4] = [
        (false, 0x76, "CMD_CHLNG", 8, "RND.A"),
        (
            true,
            0x76,
            "REPLY_CCRYPT",
            32,
            "cUID(8) RND.B(8) cryptogram(16)",
        ),
        (false, 0x77, "CMD_SCRYPT", 16, "the server cryptogram"),
        (true, 0x78, "REPLY_RMAC_I", 16, "the initial R-MAC"),
    ];

    let mut seen = 0usize;
    let mut wrong: Vec<String> = Vec::new();
    let mut right: Vec<String> = Vec::new();
    for (is_reply, id, name, want, carries) in expected {
        for (t_us, f) in frames
            .iter()
            .filter(|(_, f)| f.is_reply == is_reply && f.id == id)
        {
            seen += 1;
            if f.payload.len() == want {
                if right.iter().all(|l: &String| !l.starts_with(name)) {
                    right.push(format!("{name} {want} bytes ({carries}) — as expected"));
                }
            } else {
                wrong.push(format!(
                    "{} at {}: {} payload bytes, expected {} ({})",
                    name,
                    fmt_us(*t_us),
                    f.payload.len(),
                    want,
                    carries
                ));
            }
        }
    }

    if seen == 0 {
        return c
            .conclude(
                Verdict::Inconclusive,
                "no secure channel handshake in this capture",
            )
            .note(
                "To settle this: power-cycle a reader on a bus that runs Secure Channel and \
                 capture the four frames that follow.",
            );
    }
    if wrong.is_empty() {
        let mut c = c.conclude(
            Verdict::Pass,
            format!("{seen} handshake frames, every payload the expected length"),
        );
        for line in right {
            c = c.note(line);
        }
        return c;
    }
    let mut c = c.conclude(
        Verdict::Differs,
        format!(
            "{} handshake frame(s) had an unexpected payload length",
            wrong.len()
        ),
    );
    for line in wrong.iter().take(8) {
        c = c.note(line.clone());
    }
    c.note(
        "A different length here means the cryptogram or nonce layout differs from what \
         odr-osdp builds, which would change every secure-channel drill in the range.",
    )
}

// ---------------------------------------------------------------------------
// 7. Security block lengths
// ---------------------------------------------------------------------------

fn check_security_block_lengths(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "security-block-lengths",
        "SCS_11-14 are 3 bytes and SCS_15-18 are 2",
        "odr-osdp \"Things I was not certain about\" #5 — libosdp sends the key-type byte on \
         SCS_13 as well as SCS_11/12, and 0x01 on SCS_14, so odr-osdp encodes all four \
         handshake blocks as 3 bytes. The parser accepts 2, so a peer that sends 2 is read \
         correctly and is a genuine disagreement about what to *send*.",
    );
    let mut observed: BTreeMap<(u8, usize), usize> = BTreeMap::new();
    for (_, f) in frames {
        if let Some(block) = &f.security {
            observed
                .entry((block.raw_type, block.encoded_len()))
                .and_modify(|n| *n += 1)
                .or_insert(1);
        }
    }
    if observed.is_empty() {
        return c.conclude(Verdict::Inconclusive, "no security blocks in this capture");
    }

    let mut differs: Vec<String> = Vec::new();
    let mut agrees: Vec<String> = Vec::new();
    for ((raw, len), count) in &observed {
        let name = match ScsType::from_u8(*raw) {
            Some(t) => format!("SCS_{:02X}", t.to_u8()),
            None => format!("type {raw:#04x}"),
        };
        match ScsType::from_u8(*raw) {
            Some(t) if *len as u8 == t.standard_len() => {
                agrees.push(format!("{name}: {len} bytes, {count} frame(s)"))
            }
            Some(t) => differs.push(format!(
                "{name}: {len} bytes over {count} frame(s), odr-osdp encodes {}",
                t.standard_len()
            )),
            None => differs.push(format!(
                "{name}: {len} bytes over {count} frame(s), a block type this build does not know"
            )),
        }
    }

    if differs.is_empty() {
        let mut c = c.conclude(
            Verdict::Pass,
            format!("{} block shape(s), all the expected length", agrees.len()),
        );
        for line in agrees {
            c = c.note(line);
        }
        return c;
    }
    let mut c = c.conclude(
        Verdict::Differs,
        format!(
            "{} security block shape(s) differ from what odr-osdp encodes",
            differs.len()
        ),
    );
    for line in differs {
        c = c.note(line);
    }
    for line in agrees {
        c = c.note(format!("(agrees) {line}"));
    }
    c
}

// ---------------------------------------------------------------------------
// 8. MAC and padding
// ---------------------------------------------------------------------------

fn check_mac_and_padding(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "mac-and-padding",
        "a 4-byte wire MAC, and encrypted payloads that are whole AES blocks",
        "odr-osdp \"Things I was not certain about\" #11, and crypto::WIRE_MAC_LEN — the MAC \
         is truncated to the first four bytes of sixteen, and padding is 0x80 0x00... except \
         when the input is already block-aligned, which is libosdp's behaviour and single-\
         source. Both are visible in the length arithmetic of a sealed frame.",
    );
    let mut in_session = 0usize;
    let mut missing_mac: Vec<String> = Vec::new();
    let mut ragged: Vec<String> = Vec::new();
    for (t_us, f) in frames {
        let scs = match f.security.as_ref().and_then(|b| b.scs_type) {
            Some(t) if t.has_mac() => t,
            _ => continue,
        };
        in_session += 1;
        if f.mac.is_none() {
            missing_mac.push(format!("{} SCS_{:02X}", fmt_us(*t_us), scs.to_u8()));
        }
        if scs.is_encrypted() && (f.payload.is_empty() || f.payload.len() % BLOCK != 0) {
            ragged.push(format!(
                "{} SCS_{:02X} addr {:#04x}: {} ciphertext bytes, not a multiple of {}",
                fmt_us(*t_us),
                scs.to_u8(),
                f.address & 0x7F,
                f.payload.len(),
                BLOCK
            ));
        }
    }

    if in_session == 0 {
        return c
            .conclude(
                Verdict::Inconclusive,
                "no in-session secure channel frames in this capture",
            )
            .note(
                "To settle this: capture a card read on a bus running Secure Channel with \
                 encryption on, and count the payload bytes.",
            );
    }
    if missing_mac.is_empty() && ragged.is_empty() {
        return c
            .conclude(
                Verdict::Pass,
                format!(
                    "{in_session} in-session frames, every one with a 4-byte MAC and \
                     block-aligned ciphertext"
                ),
            )
            .note(
                "This is stronger than it looks: a wire MAC of any length other than four \
                 would have left the ciphertext ragged.",
            );
    }
    let mut c = c.conclude(
        Verdict::Differs,
        format!(
            "{} frames with no MAC, {} with ciphertext that is not a whole number of blocks",
            missing_mac.len(),
            ragged.len()
        ),
    );
    for line in missing_mac.iter().chain(ragged.iter()).take(10) {
        c = c.note(line.clone());
    }
    c.note(
        "The likeliest explanations are a wire MAC that is not four bytes, or a padding \
         rule that differs from libosdp's. Either changes odr-osdp's crypto module.",
    )
}

// ---------------------------------------------------------------------------
// 9. Null cipher selection
// ---------------------------------------------------------------------------

fn check_null_cipher_selection(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "null-cipher-selection",
        "an empty payload uses the MAC-only block even when encryption is on",
        "odr-osdp \"Things I was not certain about\" #6 — odr-osdp follows libosdp: SCS_15/16 \
         rather than SCS_17/18 when there is nothing to encrypt. It is visible on the wire \
         and worth confirming against real equipment.",
    );
    let mut encrypted = 0usize;
    let mut mac_only_empty = 0usize;
    let mut mac_only_with_payload: Vec<String> = Vec::new();
    for (t_us, f) in frames {
        match f.security.as_ref().and_then(|b| b.scs_type) {
            Some(t) if t.is_encrypted() => encrypted += 1,
            Some(t @ (ScsType::CmdMacOnly | ScsType::ReplyMacOnly)) => {
                if f.payload.is_empty() {
                    mac_only_empty += 1;
                } else {
                    mac_only_with_payload.push(format!(
                        "{} SCS_{:02X} addr {:#04x} {}: {} plaintext payload bytes",
                        fmt_us(*t_us),
                        t.to_u8(),
                        f.address & 0x7F,
                        crate::out::code_name(f),
                        f.payload.len()
                    ));
                }
            }
            _ => {}
        }
    }

    if encrypted == 0 && mac_only_empty == 0 && mac_only_with_payload.is_empty() {
        return c.conclude(Verdict::Inconclusive, "no in-session secure channel frames");
    }
    if encrypted == 0 {
        return c
            .conclude(
                Verdict::Inconclusive,
                format!(
                    "{} MAC-only frames and no encrypted ones — this link runs the null \
                     cipher throughout",
                    mac_only_empty + mac_only_with_payload.len()
                ),
            )
            .note(
                "That is a configuration, not a disagreement: SCS_15/16 are a specified \
                 mode. `odr detect` reports it as null_cipher, which is the finding that \
                 matters here.",
            );
    }
    if mac_only_with_payload.is_empty() {
        return c.conclude(
            Verdict::Pass,
            format!(
                "{encrypted} encrypted frames and {mac_only_empty} MAC-only frames, every \
                 MAC-only one with an empty payload"
            ),
        );
    }
    let mut c = c.conclude(
        Verdict::Differs,
        format!(
            "{} MAC-only frame(s) carried a payload on a link that also encrypts",
            mac_only_with_payload.len()
        ),
    );
    for line in mac_only_with_payload.iter().take(8) {
        c = c.note(line.clone());
    }
    c.note(
        "This equipment does not choose the block type by \"is there anything to encrypt\". \
         Please say which command or reply it was, and whether it is consistent.",
    )
}

// ---------------------------------------------------------------------------
// 10. The MAC chain IV
// ---------------------------------------------------------------------------

fn check_mac_chain_iv(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "mac-chain-iv",
        "the MAC chain in one direction only advances when the other direction speaks",
        "odr-osdp, \"One finding worth a second opinion\" — the IV for a command MAC is the \
         R-MAC, which changes only when a reply is processed. Two commands back to back \
         therefore encrypt under the same CBC IV, so identical plaintext gives identical \
         ciphertext. odr-osdp reproduces this faithfully rather than repairing it, and the \
         README says it is the first thing to check against hardware.",
    );

    // The observable: two secured commands to one address with no reply from
    // that address in between.
    let mut last_command: BTreeMap<u8, (u64, &Frame)> = BTreeMap::new();
    let mut pairs = 0usize;
    let mut identical: Vec<String> = Vec::new();
    let mut differing: Vec<String> = Vec::new();

    for (t_us, f) in frames {
        let addr = f.address & 0x7F;
        let secured = f
            .security
            .as_ref()
            .and_then(|b| b.scs_type)
            .is_some_and(|t| t.is_encrypted());
        if f.is_reply {
            last_command.remove(&addr);
            continue;
        }
        if !secured {
            last_command.remove(&addr);
            continue;
        }
        if let Some((prev_t, prev)) = last_command.get(&addr) {
            if prev.id == f.id && prev.payload.len() == f.payload.len() {
                pairs += 1;
                let line = format!(
                    "{} then {}: addr {:#04x} {} twice with no reply between",
                    fmt_us(*prev_t),
                    fmt_us(*t_us),
                    addr,
                    crate::out::code_name(f)
                );
                if prev.payload == f.payload {
                    identical.push(line);
                } else {
                    differing.push(line);
                }
            }
        }
        last_command.insert(addr, (*t_us, f));
    }

    if pairs == 0 {
        return c
            .conclude(
                Verdict::Inconclusive,
                "no two secured commands to one address with no reply between them",
            )
            .note(
                "The strict poll/response cadence hides this weakness, so a healthy \
                 capture will not settle it.",
            )
            .note(
                "To settle it: suppress or delay one reply — pull the reader's TX pair for \
                 a moment — so the controller sends two commands in a row, and compare the \
                 two ciphertexts.",
            );
    }
    if differing.is_empty() {
        let mut c = c.conclude(
            Verdict::Pass,
            format!(
                "{} back-to-back secured command pair(s), identical plaintext giving \
                 identical ciphertext",
                identical.len()
            ),
        );
        for line in identical.iter().take(5) {
            c = c.note(line.clone());
        }
        return c.note(
            "The chain did not advance without a reply, which is what odr-osdp models. \
             This confirms the weakness rather than clearing it.",
        );
    }
    let mut c = c.conclude(
        Verdict::Differs,
        format!(
            "{} back-to-back command pair(s) produced different ciphertext from the same \
             plaintext shape",
            differing.len()
        ),
    );
    for line in differing.iter().take(5) {
        c = c.note(line.clone());
    }
    c.note(
        "If this hardware advances the chain without waiting for a reply, the IV-reuse \
         weakness is narrower than this project teaches, and several drills need reworking. \
         This is the single most valuable disagreement on this list.",
    )
}

// ---------------------------------------------------------------------------
// 11. Sequence numbering
// ---------------------------------------------------------------------------

fn check_sequence_cycle(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "sequence-cycle",
        "commands cycle 1, 2, 3, 1 and only use 0 after a reset",
        "odr-bus's ACU and PD both advance 3 -> 1, never back to 0, and odr-detect's replay \
         rule depends on it: two bits of sequence means one repeat in three collides, which \
         is why byte-identical frames are worthless as replay evidence on their own.",
    );
    let mut last: BTreeMap<u8, (u8, u8, Vec<u8>)> = BTreeMap::new();
    let mut checked = 0usize;
    let mut resets = 0usize;
    let mut retransmits = 0usize;
    let mut breaks: Vec<String> = Vec::new();

    for (t_us, f) in frames.iter().filter(|(_, f)| !f.is_reply) {
        let addr = f.address & 0x7F;
        let seq = f.sequence & 0x03;
        if let Some((prev_seq, prev_id, prev_payload)) = last.get(&addr) {
            checked += 1;
            let expected = if *prev_seq == 3 { 1 } else { prev_seq + 1 };
            if seq == 0 {
                resets += 1;
            } else if seq == *prev_seq && f.id == *prev_id && &f.payload == prev_payload {
                retransmits += 1;
            } else if seq != expected {
                breaks.push(format!(
                    "{} addr {:#04x}: {} on sequence {}, expected {} after {}",
                    fmt_us(*t_us),
                    addr,
                    crate::out::code_name(f),
                    seq,
                    expected,
                    prev_seq
                ));
            }
        }
        last.insert(addr, (seq, f.id, f.payload.clone()));
    }

    if checked == 0 {
        return c.conclude(Verdict::Inconclusive, "fewer than two commands per address");
    }
    let mut c = if breaks.is_empty() {
        c.conclude(
            Verdict::Pass,
            format!("{checked} command transitions, all following the cycle"),
        )
    } else {
        let mut c = c.conclude(
            Verdict::Differs,
            format!(
                "{} of {} command transitions broke the cycle",
                breaks.len(),
                checked
            ),
        );
        for line in breaks.iter().take(10) {
            c = c.note(line.clone());
        }
        if breaks.len() > 10 {
            c = c.note(format!("... and {} more", breaks.len() - 10));
        }
        c.note(
            "On a real bus this is usually a frame the probe missed rather than a protocol \
             difference. If the sequence genuinely cycles through 0, say so — odr-bus \
             assumes it does not.",
        )
    };
    if resets > 0 {
        c = c.note(format!(
            "{resets} frames used sequence 0, the \"I have just reset\" value"
        ));
    }
    if retransmits > 0 {
        c = c.note(format!("{retransmits} were byte-identical retransmissions"));
    }
    c
}

// ---------------------------------------------------------------------------
// 12. Timing
// ---------------------------------------------------------------------------

/// The standard OSDP line rates, for the implied-baud check.
const BAUDS: [u64; 6] = [9600, 19200, 38400, 57600, 115200, 230400];

fn check_timing_model(frames: &[(u64, &Frame)]) -> Check {
    let c = Check::new(
        "timing-model",
        "the bus timing model's fixed overhead is plausible for this capture",
        "odr-bus \"Things I was not certain about\" #10 — Rs485Timing::turnaround_us defaults \
         to 1 ms and PdConfig::reply_delay_us to 2 ms, both plausible rather than sourced; \
         and #3, that RS-485 is modelled per transmission rather than per byte. \
         odr-detect's #2 inherits both.",
    );

    // The model says a reply begins turnaround + reply_delay after the command
    // finished, and the command took bytes x 10 / baud. Measure the first and
    // solve for the second: an implied line rate near a standard one means the
    // fixed overhead is about right.
    const FIXED_OVERHEAD_US: u64 = 3_000; // 1 ms turnaround + 2 ms reply delay

    let mut latencies: Vec<u64> = Vec::new();
    let mut implied: Vec<u64> = Vec::new();
    let mut too_fast = 0usize;
    let mut open: BTreeMap<u8, (u64, usize)> = BTreeMap::new();
    let mut polls: BTreeMap<u8, u64> = BTreeMap::new();
    let mut poll_gaps: Vec<u64> = Vec::new();

    for (t_us, f) in frames {
        let addr = f.address & 0x7F;
        if f.is_reply {
            if let Some((asked_at, wire_len)) = open.remove(&addr) {
                let latency = t_us.saturating_sub(asked_at);
                latencies.push(latency);
                if latency > FIXED_OVERHEAD_US {
                    let airtime = latency - FIXED_OVERHEAD_US;
                    if let Some(rate) = (wire_len as u64 * 10 * 1_000_000).checked_div(airtime) {
                        implied.push(rate);
                    }
                } else {
                    too_fast += 1;
                }
            }
        } else {
            open.insert(addr, (*t_us, f.wire_len()));
            if f.command_code() == Some(Command::Poll) {
                if let Some(prev) = polls.insert(addr, *t_us) {
                    poll_gaps.push(t_us.saturating_sub(prev));
                }
            }
        }
    }

    if latencies.len() < 3 {
        return c
            .conclude(
                Verdict::Inconclusive,
                format!(
                    "only {} command/reply pairs; three is the minimum",
                    latencies.len()
                ),
            )
            .note("A few seconds of ordinary polling is enough.");
    }

    latencies.sort_unstable();
    implied.sort_unstable();
    poll_gaps.sort_unstable();

    let median_latency = percentile(&latencies, 50).unwrap_or(0);
    let median_implied = percentile(&implied, 50).unwrap_or(0);
    let nearest = BAUDS
        .iter()
        .copied()
        .min_by_key(|b| b.abs_diff(median_implied))
        .unwrap_or(9600);
    let off_by_percent = (nearest.abs_diff(median_implied) * 100)
        .checked_div(nearest)
        .unwrap_or(100);

    let mut c = c
        .note(format!(
            "reply latency: n={} min {} median {} p90 {} max {}",
            latencies.len(),
            fmt_dur(latencies[0]),
            fmt_dur(median_latency),
            fmt_dur(percentile(&latencies, 90).unwrap_or(0)),
            fmt_dur(*latencies.last().unwrap_or(&0)),
        ))
        .note(format!(
            "implied line rate, taking the model's {} of fixed overhead: {} baud median, \
             nearest standard rate {} ({}% away)",
            fmt_dur(FIXED_OVERHEAD_US),
            median_implied,
            nearest,
            off_by_percent
        ));
    if !poll_gaps.is_empty() {
        c = c.note(format!(
            "poll interval: n={} median {} (odr-bus's AcuConfig default is 100.000ms, but \
             this is a site setting rather than an assumption)",
            poll_gaps.len(),
            fmt_dur(percentile(&poll_gaps, 50).unwrap_or(0))
        ));
    }

    if too_fast > 0 {
        return c
            .conclude(
                Verdict::Differs,
                format!(
                    "{too_fast} replies arrived within the model's {} of fixed overhead",
                    fmt_dur(FIXED_OVERHEAD_US)
                ),
            )
            .note(
                "turnaround_us + reply_delay_us is too large for this equipment. The \
                 observed minimum latency is the number to report.",
            );
    }
    if off_by_percent > 15 {
        return c
            .conclude(
                Verdict::Differs,
                format!(
                    "implied line rate {median_implied} baud is {off_by_percent}% from the \
                     nearest standard rate"
                ),
            )
            .note(
                "Either the line is not running at a standard rate, or the model's fixed \
                 overhead is wrong for this equipment. Report the actual configured baud \
                 rate and the median latency together — that pair is enough to correct the \
                 defaults.",
            );
    }
    c.conclude(
        Verdict::Pass,
        format!(
            "median reply latency {} is consistent with {} baud and the model's fixed \
             overhead",
            fmt_dur(median_latency),
            nearest
        ),
    )
}

// ---------------------------------------------------------------------------
// 13. Wiegand bit counts
// ---------------------------------------------------------------------------

fn check_wiegand_bit_counts(capture: &Capture) -> Check {
    let c = Check::new(
        "wiegand-bit-counts",
        "two-wire events carry an authoritative bit count",
        "DESIGN.md section 3, second amendment, and odr-bus capture's \"what the format does \
         not carry\" #1 — a 26-bit read and a 32-bit read are the same four bytes, so without \
         `bits` an importer has to guess from parity, which is ambiguous by construction.",
    );
    let wire: Vec<&crate::capture::Event> = capture.events.iter().filter(|e| e.is_wire()).collect();
    if wire.is_empty() {
        return c.conclude(Verdict::NotApplicable, "no two-wire events in this capture");
    }
    let declared = wire.iter().filter(|e| e.declared_bits.is_some()).count();

    let mut bad_parity: Vec<String> = Vec::new();
    let mut ambiguous: Vec<String> = Vec::new();
    for e in &wire {
        let readings = e.wiegand_readings();
        match e.declared_bits {
            Some(n) => {
                let valid = readings
                    .first()
                    .map(|b| {
                        odr_wiegand::infer_formats(b).iter().any(|c| {
                            c.parity_valid
                                && !matches!(c.decoded.format, odr_wiegand::CardFormat::Raw { .. })
                        })
                    })
                    .unwrap_or(false);
                if !valid {
                    bad_parity.push(format!(
                        "#{} {}: {} bits declared, no known format decodes it with valid parity",
                        e.index,
                        fmt_us(e.t_us),
                        n
                    ));
                }
            }
            None => {
                let counts: Vec<String> = readings.iter().map(|b| b.len().to_string()).collect();
                ambiguous.push(format!(
                    "#{} {}: {} bytes, readings of {} bits all fit",
                    e.index,
                    fmt_us(e.t_us),
                    e.bytes.len(),
                    counts.join(" or ")
                ));
            }
        }
    }

    if declared == 0 {
        let mut c = c.conclude(
            Verdict::Inconclusive,
            format!("{} two-wire events, none carrying a bit count", wire.len()),
        );
        for line in ambiguous.iter().take(6) {
            c = c.note(line.clone());
        }
        return c.note(
            "This is the capture's limitation rather than the engine's. If your capture \
             tool knows the pulse count, emit it as \"bits\" — DESIGN.md section 3 makes \
             that field authoritative when present.",
        );
    }
    if bad_parity.is_empty() {
        let mut c = c.conclude(
            Verdict::Pass,
            format!(
                "{declared} of {} two-wire events declared a bit count, and every declared \
                 reading has valid parity in a known format",
                wire.len()
            ),
        );
        for line in ambiguous.iter().take(4) {
            c = c.note(format!("(not declared) {line}"));
        }
        return c;
    }
    let mut c = c.conclude(
        Verdict::Differs,
        format!(
            "{} declared reading(s) do not decode with valid parity in any format this \
             project knows",
            bad_parity.len()
        ),
    );
    for line in bad_parity.iter().take(8) {
        c = c.note(line.clone());
    }
    c.note(
        "Either the format is one odr-wiegand does not model, or its parity layout here \
         differs from the Proxmark3 client's, which is where odr-wiegand's layouts came \
         from. Both are worth an issue.",
    )
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn list_text() -> String {
    let mut s = String::from("odr verify — the checks, and the ledger entries behind them\n");
    for check in run_checks(&Capture {
        label: String::new(),
        events: Vec::new(),
    }) {
        s.push_str(&format!("\n  {}\n", check.id));
        s.push_str(&format!("    {}\n", check.title));
        s.push_str(&format!(
            "    ledger: {}\n",
            wrap(check.ledger, 74, "            ")
        ));
    }
    s
}

fn list_json() -> String {
    Json::obj()
        .with("command", Json::str("verify"))
        .with(
            "checks",
            Json::arr(
                run_checks(&Capture {
                    label: String::new(),
                    events: Vec::new(),
                })
                .iter()
                .map(|c| {
                    Json::obj()
                        .with("id", Json::str(c.id))
                        .with("title", Json::str(c.title))
                        .with("ledger", Json::str(c.ledger))
                }),
            ),
        )
        .render()
}

fn render_text(capture: &Capture, checks: &[Check]) -> String {
    let mut s = String::new();
    s.push_str(&format!("odr verify — {}\n", capture.label));
    s.push_str(&format!(
        "{} events, {} frames, {} to {}\n",
        capture.events.len(),
        capture.frames().count(),
        fmt_us(capture.start_us()),
        fmt_us(capture.end_us()),
    ));

    heading(&mut s, "checks");
    for check in checks {
        s.push_str(&format!(
            "{}  {}\n",
            pad_right(check.verdict.name(), 13),
            check.id
        ));
        s.push_str(&format!("               {}\n", check.summary));
        for line in &check.detail {
            s.push_str(&format!(
                "               · {}\n",
                wrap(line, 62, "                 ")
            ));
        }
        if check.verdict == Verdict::Differs {
            s.push_str(&format!(
                "               ledger: {}\n",
                wrap(check.ledger, 62, "                 ")
            ));
        }
        s.push('\n');
    }

    s.push_str(&summary_block(capture, checks));
    s
}

/// The copy-pasteable block. This is what the command is for.
fn summary_block(capture: &Capture, checks: &[Check]) -> String {
    let rule = "-".repeat(76);
    let mut s = String::new();
    s.push_str(&format!(
        "{rule}\ncopy from here into .github/ISSUE_TEMPLATE/hardware-correction.yml\n{rule}\n\n"
    ));
    s.push_str(&format!(
        "odr verify {} — capture {}\n{} events, {} frames, {} to {}\n\n",
        crate::help::VERSION,
        capture.label,
        capture.events.len(),
        capture.frames().count(),
        fmt_us(capture.start_us()),
        fmt_us(capture.end_us()),
    ));

    for check in checks {
        s.push_str(&format!(
            "  {}  {}  {}\n",
            pad_right(check.verdict.name(), 13),
            pad_right(check.id, 26),
            check.summary
        ));
    }

    let differing: Vec<&Check> = checks
        .iter()
        .filter(|c| c.verdict == Verdict::Differs)
        .collect();
    s.push_str("\nWhich uncertainty ledger entry this resolves:\n");
    if differing.is_empty() {
        s.push_str(
            "  Nothing in this capture disagrees with the engine.\n  \
             That is still worth reporting for any check above that says `pass` on a \
             ledger\n  entry the README asks to have confirmed — a confirmation retires an \
             uncertainty\n  just as a contradiction does.\n",
        );
    } else {
        for check in differing {
            s.push_str(&format!(
                "  [{}] {}\n",
                check.id,
                wrap(check.ledger, 70, "      ")
            ));
        }
    }
    s.push_str(&format!("\n{rule}\n"));
    s
}

fn render_json(capture: &Capture, checks: &[Check]) -> String {
    Json::obj()
        .with("command", Json::str("verify"))
        .with("version", Json::str(crate::help::VERSION))
        .with("capture", Json::str(&capture.label))
        .with("events", Json::Num(capture.events.len() as u64))
        .with("frames", Json::Num(capture.frames().count() as u64))
        .with("start_us", Json::Num(capture.start_us()))
        .with("end_us", Json::Num(capture.end_us()))
        .with(
            "differs",
            Json::Num(
                checks
                    .iter()
                    .filter(|c| c.verdict == Verdict::Differs)
                    .count() as u64,
            ),
        )
        .with(
            "checks",
            Json::arr(checks.iter().map(|c| {
                Json::obj()
                    .with("id", Json::str(c.id))
                    .with("title", Json::str(c.title))
                    .with("ledger", Json::str(c.ledger))
                    .with("verdict", Json::str(c.verdict.name()))
                    .with("summary", Json::str(&c.summary))
                    .with(
                        "detail",
                        Json::arr(c.detail.iter().map(|d| Json::str(d.as_str()))),
                    )
            })),
        )
        .render()
}
