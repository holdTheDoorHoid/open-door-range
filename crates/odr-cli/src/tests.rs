//! The suite. Each test is named for the claim it makes.
//!
//! The captures are not fixtures. Every one of them is produced by
//! `odr export`, which runs the engine, so a change in `odr-bus` that alters
//! what goes on the wire shows up here rather than being papered over by a
//! hand-written byte string that nothing keeps honest.
//!
//! Three classes carry the weight:
//!
//! * **Every command against a real capture**, asserting the thing that command
//!   exists to say.
//! * **Malformed and missing input**, asserting a diagnostic and exit code 2
//!   rather than a panic. `DESIGN.md`'s no-panic rule is a promise about a
//!   browser tab; here it is a promise about somebody's terminal at two in the
//!   morning.
//! * **`--json` on every command**, checked with a JSON parser written here so
//!   that "it is valid JSON" is an assertion rather than a hope. This crate has
//!   no dependencies and that includes its tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use odr_osdp::Frame;

use crate::{run, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn argv(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Run the tool as the binary would.
fn odr(args: &[&str]) -> crate::Run {
    run(&argv(args))
}

/// A capture from one of `odr export`'s scenarios, as text.
fn capture_text(scenario: &str) -> String {
    let result = odr(&["export", "--scenario", scenario]);
    assert_eq!(result.code, EXIT_OK, "export failed: {}", result.err);
    assert!(!result.out.is_empty(), "{scenario} exported nothing");
    result.out
}

/// Write text to a uniquely named scratch file and hand back the path.
///
/// No temporary-directory crate, for the same reason there is no argument
/// parser: a counter and the process id are enough, and the workspace has one
/// dependency.
fn scratch(name: &str, text: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "odr-cli-test-{}-{}-{}.ndjson",
        std::process::id(),
        n,
        name
    ));
    std::fs::write(&path, text).expect("scratch file is writable");
    path
}

/// A scenario capture on disk.
fn capture_file(scenario: &str) -> PathBuf {
    scratch(scenario, &capture_text(scenario))
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Read a `1.234567s` stamp back into microseconds.
fn parse_stamp(text: &str) -> u64 {
    let t = text.trim_end_matches('s');
    let (whole, frac) = t.split_once('.').unwrap_or((t, "0"));
    whole.parse::<u64>().unwrap_or(0) * 1_000_000 + frac.parse::<u64>().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// A minimal JSON parser, so "valid JSON" is checked and not assumed
// ---------------------------------------------------------------------------

/// Parse a complete JSON document, returning `Err` with a byte offset.
///
/// Structural only: it proves the document is well formed, which is exactly
/// what `--json` promises. It is not a general-purpose parser and is not used
/// anywhere but here.
fn json_is_valid(text: &str) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut at = skip_ws(bytes, 0);
    at = json_value(bytes, at)?;
    at = skip_ws(bytes, at);
    if at != bytes.len() {
        return Err(format!("trailing bytes at {at}"));
    }
    Ok(())
}

fn skip_ws(b: &[u8], mut at: usize) -> usize {
    while matches!(b.get(at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        at += 1;
    }
    at
}

fn json_value(b: &[u8], at: usize) -> Result<usize, String> {
    match b.get(at) {
        Some(b'{') => json_object(b, at),
        Some(b'[') => json_array(b, at),
        Some(b'"') => json_string(b, at),
        Some(b't') => json_literal(b, at, "true"),
        Some(b'f') => json_literal(b, at, "false"),
        Some(b'n') => json_literal(b, at, "null"),
        Some(c) if c.is_ascii_digit() || *c == b'-' => json_number(b, at),
        Some(c) => Err(format!("unexpected byte {:?} at {}", *c as char, at)),
        None => Err(format!("input ended at {at}")),
    }
}

fn json_literal(b: &[u8], at: usize, word: &str) -> Result<usize, String> {
    if b[at..].starts_with(word.as_bytes()) {
        Ok(at + word.len())
    } else {
        Err(format!("expected {word} at {at}"))
    }
}

fn json_number(b: &[u8], mut at: usize) -> Result<usize, String> {
    let start = at;
    if b.get(at) == Some(&b'-') {
        at += 1;
    }
    while matches!(b.get(at), Some(c) if c.is_ascii_digit() || *c == b'.' || *c == b'e' || *c == b'E' || *c == b'+' || *c == b'-')
    {
        at += 1;
    }
    if at == start {
        return Err(format!("empty number at {start}"));
    }
    Ok(at)
}

fn json_string(b: &[u8], mut at: usize) -> Result<usize, String> {
    if b.get(at) != Some(&b'"') {
        return Err(format!("expected a string at {at}"));
    }
    at += 1;
    loop {
        match b.get(at) {
            None => return Err(format!("unterminated string from {at}")),
            Some(b'"') => return Ok(at + 1),
            Some(b'\\') => at += 2,
            Some(c) if *c < 0x20 => {
                return Err(format!("raw control byte {:#04x} in a string at {}", c, at))
            }
            Some(_) => at += 1,
        }
    }
}

fn json_object(b: &[u8], mut at: usize) -> Result<usize, String> {
    at = skip_ws(b, at + 1);
    if b.get(at) == Some(&b'}') {
        return Ok(at + 1);
    }
    loop {
        at = skip_ws(b, at);
        at = json_string(b, at)?;
        at = skip_ws(b, at);
        if b.get(at) != Some(&b':') {
            return Err(format!("expected ':' at {at}"));
        }
        at = skip_ws(b, at + 1);
        at = json_value(b, at)?;
        at = skip_ws(b, at);
        match b.get(at) {
            Some(b',') => at += 1,
            Some(b'}') => return Ok(at + 1),
            _ => return Err(format!("expected ',' or '}}' at {at}")),
        }
    }
}

fn json_array(b: &[u8], mut at: usize) -> Result<usize, String> {
    at = skip_ws(b, at + 1);
    if b.get(at) == Some(&b']') {
        return Ok(at + 1);
    }
    loop {
        at = skip_ws(b, at);
        at = json_value(b, at)?;
        at = skip_ws(b, at);
        match b.get(at) {
            Some(b',') => at += 1,
            Some(b']') => return Ok(at + 1),
            _ => return Err(format!("expected ',' or ']' at {at}")),
        }
    }
}

#[test]
fn the_test_suites_own_json_parser_rejects_broken_documents() {
    assert!(json_is_valid("{\"a\": [1, 2, {\"b\": null}], \"c\": \"x\"}").is_ok());
    assert!(json_is_valid("{}").is_ok());
    assert!(json_is_valid("{\"a\": 1,}").is_err());
    assert!(json_is_valid("{\"a\" 1}").is_err());
    assert!(json_is_valid("[1, 2").is_err());
    assert!(json_is_valid("{} trailing").is_err());
    assert!(json_is_valid("{\"a\": \"raw\nnewline\"}").is_err());
}

// ---------------------------------------------------------------------------
// Export: everything else is built on it
// ---------------------------------------------------------------------------

#[test]
fn every_scenario_exports_a_capture_the_tool_can_read_back() {
    for scenario in [
        "wiegand-badge-in",
        "clock-data-badge-in",
        "osdp-clear",
        "osdp-secure",
        "osdp-replay",
    ] {
        let path = capture_file(scenario);
        let result = odr(&["stats", &path_str(&path)]);
        assert_eq!(
            result.code, EXIT_OK,
            "{scenario} did not read back: {}",
            result.err
        );
    }
}

#[test]
fn a_scenario_is_deterministic_and_the_seed_changes_it() {
    let a = capture_text("osdp-secure");
    let b = capture_text("osdp-secure");
    assert_eq!(a, b, "the same seed must give byte-identical output");

    let seeded = odr(&["export", "--scenario", "osdp-secure", "--seed", "99"]);
    assert_eq!(seeded.code, EXIT_OK);
    assert_ne!(
        seeded.out, a,
        "a different seed changes the nonces, and therefore the bytes"
    );
}

#[test]
fn a_two_wire_scenario_declares_its_bit_count() {
    let text = capture_text("wiegand-badge-in");
    assert!(
        text.contains("\"bits\":26"),
        "DESIGN.md section 3's second amendment: a writer that knows the true length says \
         so. Got: {text}"
    );
}

#[test]
fn the_clock_and_data_scenario_says_which_protocol_it_recorded() {
    let text = capture_text("clock-data-badge-in");
    assert!(
        text.contains("\"line\":\"clock_data\""),
        "folding this into \"wiegand\" would lose the one thing an importer needs"
    );
}

#[test]
fn an_unknown_scenario_is_a_usage_error_that_lists_the_real_ones() {
    let result = odr(&["export", "--scenario", "nope"]);
    assert_eq!(result.code, EXIT_USAGE);
    assert!(result.err.contains("osdp-secure"));
}

#[test]
fn export_writes_to_a_file_when_asked() {
    let mut path = std::env::temp_dir();
    path.push(format!("odr-cli-export-{}.ndjson", std::process::id()));
    let result = odr(&[
        "export",
        "--scenario",
        "osdp-clear",
        "-o",
        &path.to_string_lossy(),
    ]);
    assert_eq!(result.code, EXIT_OK, "{}", result.err);
    let written = std::fs::read_to_string(&path).expect("the file was written");
    assert!(written.contains("\"line\":\"rs485\""));
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

#[test]
fn decode_names_every_frame_of_the_handshake_in_order() {
    let path = capture_file("osdp-secure");
    let result = odr(&["decode", &path_str(&path)]);
    assert_eq!(result.code, EXIT_OK, "{}", result.err);
    for name in ["CHLNG", "CCRYPT", "SCRYPT", "RMAC_I"] {
        assert!(result.out.contains(name), "no {name} in the decode");
    }
    let chlng = result.out.find("CHLNG").expect("CHLNG");
    let rmac = result.out.find("RMAC_I").expect("RMAC_I");
    assert!(chlng < rmac, "the handshake must print in wire order");
}

#[test]
fn decode_splits_an_encrypted_frame_into_what_is_readable_and_what_is_not() {
    let path = capture_file("osdp-secure");
    let result = odr(&["decode", &path_str(&path)]);
    assert!(result.out.contains("[SCS_17]") || result.out.contains("[SCS_18]"));
    assert!(result.out.contains("opaque"));
    assert!(
        result.out.contains("NOT encrypted"),
        "the plaintext command byte is the lesson, not a footnote"
    );
}

#[test]
fn decode_reads_a_declared_bit_count_rather_than_guessing() {
    let path = capture_file("wiegand-badge-in");
    let result = odr(&["decode", &path_str(&path)]);
    assert_eq!(result.code, EXIT_OK);
    assert!(result.out.contains("26 bits declared"));
    assert!(result.out.contains("H10301"));
    assert!(result.out.contains("FC 42 CN 1337"));
    assert!(result.out.contains("parity ok"));
    assert!(
        !result.out.contains("reading 2"),
        "a declared count leaves nothing to guess between"
    );
}

#[test]
fn decode_reads_clock_and_data_as_aba_track_two() {
    let path = capture_file("clock-data-badge-in");
    let result = odr(&["decode", &path_str(&path)]);
    assert!(result.out.contains("ABA track 2"));
    assert!(result.out.contains("LRC ok"));
}

#[test]
fn decode_filters_by_code_address_line_and_time() {
    let path = capture_file("osdp-clear");
    let p = path_str(&path);

    let raw = odr(&["decode", "--code", "RAW", &p]);
    assert_eq!(raw.code, EXIT_OK);
    assert!(raw.out.contains("1 events shown"));

    let by_hex = odr(&["decode", "--code", "0x50", &p]);
    assert_eq!(
        by_hex.out, raw.out,
        "a name and its byte select the same thing"
    );

    let wrong_address = odr(&["decode", "--address", "0x7e", &p]);
    assert!(wrong_address.out.contains("nothing matched the filter"));

    let early = odr(&["decode", "--to", "0.5s", &p]);
    let shown: Vec<u64> = early
        .out
        .lines()
        .filter(|l| l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(1).map(parse_stamp))
        .collect();
    assert!(!shown.is_empty(), "the filter removed everything");
    assert!(
        shown.iter().all(|t| *t < 500_000),
        "an event after the --to bound was shown: {shown:?}"
    );

    let limited = odr(&["decode", "--limit", "3", &p]);
    assert!(limited.out.contains("3 events shown"));
}

#[test]
fn decode_reports_a_broken_frame_as_a_finding_and_not_a_crash() {
    let path = scratch("bad-crc", &corrupt_one_trailer(&capture_text("osdp-clear")));
    let result = odr(&["decode", &path_str(&path)]);
    assert_eq!(
        result.code, EXIT_FINDINGS,
        "a capture with an undecodable frame is exit 1"
    );
    assert!(result.out.contains("CRC mismatch"));
    assert!(result.out.starts_with("odr decode"));
}

// ---------------------------------------------------------------------------
// Detect
// ---------------------------------------------------------------------------

#[test]
fn detect_finds_the_replayed_reply_and_cites_it() {
    let path = capture_file("osdp-replay");
    let result = odr(&["detect", &path_str(&path)]);
    assert_eq!(result.code, EXIT_FINDINGS);
    assert!(result.out.contains("replayed_frame"));
    assert!(
        result.out.contains("cited"),
        "a finding with no evidence is an opinion"
    );
    assert!(result.out.contains("evidence citations all re-checked"));
}

#[test]
fn detect_calls_a_cleartext_bus_what_it_is() {
    let path = capture_file("osdp-clear");
    let result = odr(&["detect", &path_str(&path)]);
    assert!(result.out.contains("cleartext_bus"));
    assert_eq!(
        result.code, EXIT_FINDINGS,
        "a cleartext bus is a high finding"
    );
}

#[test]
fn detect_min_severity_moves_the_threshold_and_the_exit_code() {
    let path = capture_file("osdp-clear");
    let p = path_str(&path);
    let all = odr(&["detect", &p]);
    let critical = odr(&["detect", "--min-severity", "critical", &p]);
    assert!(critical.out.len() < all.out.len());

    let bad = odr(&["detect", "--min-severity", "loud", &p]);
    assert_eq!(bad.code, EXIT_USAGE);
    assert!(bad.err.contains("info, low, medium, high, critical"));
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[test]
fn stats_reports_posture_cadence_and_codes() {
    let path = capture_file("osdp-secure");
    let result = odr(&["stats", &path_str(&path)]);
    assert_eq!(result.code, EXIT_OK, "{}", result.err);
    assert!(result.out.contains("POLL"));
    assert!(result.out.contains("per address"));
    assert!(result.out.contains("secure channel, payloads encrypted"));
    assert!(
        result.out.contains("SCBK-D"),
        "a bus on the published default key should say so"
    );
    assert!(result.out.contains("poll gap"));
    assert!(result.out.contains("reply in"));
}

#[test]
fn stats_on_a_two_wire_capture_reports_the_card_read() {
    let path = capture_file("wiegand-badge-in");
    let result = odr(&["stats", &path_str(&path)]);
    assert!(result.out.contains("two-wire card reads"));
    assert!(result.out.contains("26 bits"));
    assert!(result.out.contains("H10301"));
}

// ---------------------------------------------------------------------------
// Verify — the command this crate exists for
// ---------------------------------------------------------------------------

#[test]
fn verify_passes_a_capture_the_engine_produced() {
    let path = capture_file("osdp-secure");
    let result = odr(&["verify", &path_str(&path)]);
    assert_eq!(
        result.code, EXIT_OK,
        "the engine must agree with its own output:\n{}",
        result.out
    );
    assert!(result.out.contains("pass           frame-trailers"));
    assert!(result
        .out
        .contains("pass           handshake-payload-lengths"));
    assert!(result.out.contains("pass           mac-and-padding"));
    assert!(result.out.contains("Nothing in this capture disagrees"));
}

#[test]
fn verify_flags_a_deliberately_corrupted_capture_and_names_the_ledger_entry() {
    let path = scratch("corrupt", &corrupt_for_verify(&capture_text("osdp-clear")));
    let result = odr(&["verify", &path_str(&path)]);
    assert_eq!(
        result.code, EXIT_FINDINGS,
        "a corrupted capture must exit 1"
    );

    // The broken trailer.
    assert!(result.out.contains("differs        frame-trailers"));
    assert!(result.out.contains("CRC mismatch"));
    // The contested CMD_ABORT byte, with a valid trailer so it reaches the
    // code checks rather than being thrown out as corruption.
    assert!(result.out.contains("differs        command-codes"));
    assert!(result.out.contains("differs        abort-code"));
    assert!(
        result.out.contains("go-osdp says 0x7A"),
        "the whole point is to name the ledger entry"
    );
    // And the issue body at the end lists them.
    assert!(result
        .out
        .contains("Which uncertainty ledger entry this resolves"));
    assert!(result.out.contains("[abort-code]"));
}

#[test]
fn verify_says_which_checks_the_capture_could_not_settle() {
    let path = capture_file("osdp-clear");
    let result = odr(&["verify", &path_str(&path)]);
    assert!(result
        .out
        .contains("inconclusive   handshake-payload-lengths"));
    assert!(
        result.out.contains("To settle this"),
        "an inconclusive check must say what traffic would settle it"
    );
}

#[test]
fn verify_ends_with_a_block_shaped_for_the_issue_template() {
    let path = capture_file("osdp-secure");
    let result = odr(&["verify", &path_str(&path)]);
    let marker = "copy from here into .github/ISSUE_TEMPLATE/hardware-correction.yml";
    let at = result.out.find(marker).expect("the copy block");
    let tail = &result.out[at..];
    assert!(tail.contains("odr verify"));
    assert!(tail.contains("Which uncertainty ledger entry this resolves"));
    for id in ["frame-trailers", "mac-chain-iv", "timing-model"] {
        assert!(tail.contains(id), "the block must list every check: {id}");
    }
}

#[test]
fn verify_list_names_a_ledger_entry_for_every_check() {
    let result = odr(&["verify", "--list"]);
    assert_eq!(result.code, EXIT_OK);
    assert_eq!(
        result.out.matches("ledger:").count(),
        crate::cmd_verify::run_checks(&crate::capture::Capture {
            label: String::new(),
            events: Vec::new(),
        })
        .len(),
        "a check with no ledger entry has nothing to tell a contributor"
    );
}

#[test]
fn verify_checks_the_wiegand_bit_count_amendment() {
    let path = capture_file("wiegand-badge-in");
    let with_bits = odr(&["verify", &path_str(&path)]);
    assert!(with_bits.out.contains("pass           wiegand-bit-counts"));

    // The same capture with the amendment's field taken away.
    let stripped = capture_text("wiegand-badge-in").replace(",\"bits\":26", "");
    let path = scratch("no-bits", &stripped);
    let without = odr(&["verify", &path_str(&path)]);
    assert!(without.out.contains("inconclusive   wiegand-bit-counts"));
    assert!(without.out.contains("readings of"));
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

#[test]
fn replay_reproduces_every_frame_of_a_capture_the_engine_made() {
    let path = capture_file("osdp-secure");
    let result = odr(&["replay", &path_str(&path)]);
    assert_eq!(result.code, EXIT_OK, "{}", result.out);
    assert!(result.out.contains("0 divergence(s)"));
}

#[test]
fn replay_verifies_the_handshake_cryptogram_under_the_default_key() {
    let path = capture_file("osdp-secure");
    let result = odr(&["replay", &path_str(&path)]);
    assert!(
        result.out.contains("verifies under SCBK-D"),
        "this is the evidence that odr-osdp's key derivation matches the traffic:\n{}",
        result.out
    );
}

#[test]
fn replay_notices_a_reply_nobody_asked_for() {
    let path = capture_file("osdp-replay");
    let result = odr(&["replay", &path_str(&path)]);
    assert_eq!(result.code, EXIT_FINDINGS);
    assert!(result.out.contains("unsolicited-reply"));
    assert!(result.out.contains("engine expected"));
    assert!(result.out.contains("capture had"));
}

// ---------------------------------------------------------------------------
// --json, everywhere
// ---------------------------------------------------------------------------

#[test]
fn every_command_emits_valid_json() {
    let secure = capture_file("osdp-secure");
    let replayed = capture_file("osdp-replay");
    let wiegand = capture_file("wiegand-badge-in");
    let corrupt = scratch(
        "corrupt-json",
        &corrupt_for_verify(&capture_text("osdp-clear")),
    );

    let cases: Vec<Vec<String>> = vec![
        argv(&["decode", "--json", &path_str(&secure)]),
        argv(&["decode", "--json", &path_str(&wiegand)]),
        argv(&["detect", "--json", &path_str(&replayed)]),
        argv(&["stats", "--json", &path_str(&secure)]),
        argv(&["verify", "--json", &path_str(&corrupt)]),
        argv(&["verify", "--json", "--list"]),
        argv(&["replay", "--json", &path_str(&replayed)]),
        argv(&["export", "--json", "--list"]),
        argv(&["export", "--json", "--scenario", "osdp-clear"]),
    ];

    for args in cases {
        let result = run(&args);
        let label = args.join(" ");
        assert!(
            !result.out.is_empty(),
            "{label} produced no output: {}",
            result.err
        );
        json_is_valid(&result.out).unwrap_or_else(|e| panic!("{label} emitted invalid JSON: {e}"));
    }
}

#[test]
fn json_output_carries_the_same_conclusion_as_the_text() {
    let path = capture_file("osdp-replay");
    let text = odr(&["replay", &path_str(&path)]);
    let json = odr(&["replay", "--json", &path_str(&path)]);
    assert_eq!(text.code, json.code);
    assert!(json.out.contains("\"kind\": \"unsolicited-reply\""));
}

// ---------------------------------------------------------------------------
// Malformed and missing input
// ---------------------------------------------------------------------------

#[test]
fn a_missing_file_is_a_diagnostic_and_exit_two() {
    for command in ["decode", "detect", "stats", "verify", "replay"] {
        let result = odr(&[command, "/definitely/not/here.ndjson"]);
        assert_eq!(result.code, EXIT_USAGE, "{command} on a missing file");
        assert!(result.out.is_empty(), "{command} must print no results");
        assert!(result.err.contains("not/here.ndjson"));
    }
}

#[test]
fn a_malformed_capture_line_is_a_diagnostic_naming_the_line() {
    let text = "{\"t_us\":1,\"line\":\"rs485\",\"dir\":\"wire\",\"bytes\":\"53\"}\n\
                {\"line\":\"rs485\",\"dir\":\"wire\",\"bytes\":\"53\"}\n";
    let path = scratch("malformed", text);
    for command in ["decode", "detect", "stats", "verify", "replay"] {
        let result = odr(&[command, &path_str(&path)]);
        assert_eq!(result.code, EXIT_USAGE, "{command} on a malformed capture");
        assert!(result.err.contains("line 2"), "{command}: {}", result.err);
        assert!(result.err.contains("t_us"));
    }
}

#[test]
fn rubbish_that_is_not_a_capture_at_all_is_a_diagnostic() {
    for text in [
        "this is not JSON\n",
        "\u{0}\u{1}\u{2}\n",
        "{\"t_us\":\"soon\",\"line\":\"rs485\",\"dir\":\"wire\",\"bytes\":\"53\"}\n",
        "{\"t_us\":1,\"line\":\"rs485\",\"dir\":\"wire\",\"bytes\":\"nothex\"}\n",
    ] {
        let path = scratch("rubbish", text);
        let result = odr(&["verify", &path_str(&path)]);
        assert_eq!(result.code, EXIT_USAGE, "on {text:?}");
        assert!(!result.err.is_empty());
    }
}

#[test]
fn an_empty_capture_runs_every_command_without_a_panic() {
    let path = scratch("empty", "\n\n");
    for command in ["decode", "detect", "stats", "verify", "replay"] {
        let result = odr(&[command, &path_str(&path)]);
        assert_eq!(result.code, EXIT_OK, "{command} on an empty capture");
        assert!(!result.out.is_empty(), "{command} said nothing at all");
    }
}

#[test]
fn a_capture_of_bytes_that_are_not_frames_is_reported_rather_than_rejected() {
    let text = "{\"t_us\":1,\"line\":\"rs485\",\"dir\":\"acu_to_pd\",\"bytes\":\"deadbeef\"}\n";
    let path = scratch("garbage-frames", text);
    let decode = odr(&["decode", &path_str(&path)]);
    assert_eq!(
        decode.code, EXIT_OK,
        "non-frame bytes are not a decode failure"
    );
    assert!(decode.out.contains("non-frame data") || decode.out.contains("nothing frame-shaped"));

    let verify = odr(&["verify", &path_str(&path)]);
    assert!(verify.out.contains("n/a            frame-trailers"));
}

// ---------------------------------------------------------------------------
// The command line itself
// ---------------------------------------------------------------------------

#[test]
fn help_and_version_are_always_available() {
    assert!(odr(&["--version"]).out.starts_with("odr "));
    assert_eq!(odr(&["--version"]).code, EXIT_OK);
    assert!(odr(&["help"]).out.contains("COMMANDS"));
    assert!(run(&[]).out.contains("COMMANDS"));
    for command in ["decode", "detect", "stats", "verify", "replay", "export"] {
        let by_help = odr(&["help", command]);
        let by_flag = odr(&[command, "--help"]);
        assert_eq!(by_help.code, EXIT_OK, "help {command}");
        assert_eq!(by_help.out, by_flag.out, "{command} --help must match");
        assert!(by_help.out.contains("USAGE"));
    }
}

#[test]
fn an_unknown_command_or_option_is_exit_two_and_says_what_to_type() {
    let unknown = odr(&["wat"]);
    assert_eq!(unknown.code, EXIT_USAGE);
    assert!(unknown.err.contains("try `odr help`"));

    let path = capture_file("osdp-clear");
    let bad_flag = odr(&["stats", "--colour", &path_str(&path)]);
    assert_eq!(bad_flag.code, EXIT_USAGE);
    assert!(bad_flag.err.contains("colour"));
}

#[test]
fn a_missing_capture_argument_is_exit_two() {
    for command in ["decode", "detect", "stats", "verify", "replay"] {
        let result = odr(&[command]);
        assert_eq!(result.code, EXIT_USAGE, "{command} with no capture");
        assert!(result.err.contains("<capture>"));
    }
}

#[test]
fn a_second_capture_argument_is_rejected_rather_than_ignored() {
    let path = capture_file("osdp-clear");
    let p = path_str(&path);
    let result = odr(&["stats", &p, &p]);
    assert_eq!(result.code, EXIT_USAGE);
    assert!(result.err.contains("unexpected argument"));
}

// ---------------------------------------------------------------------------
// Corrupting a capture, on purpose
// ---------------------------------------------------------------------------

/// Flip the last byte of the third capture line's frame.
///
/// The trailer stops matching, which is what a real line fault looks like.
fn corrupt_one_trailer(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let line = lines.get_mut(2).expect("the capture has three lines");
    *line = map_bytes(line, |bytes| {
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xFF;
        }
    });
    lines.join("\n") + "\n"
}

/// A capture with three deliberate disagreements in it, each aimed at one check.
///
/// 1. A broken trailer, for `frame-trailers`.
/// 2. `0x7A` as a command **with its CRC recomputed**, so it survives the frame
///    parser and reaches `command-codes` and `abort-code`. That byte is
///    go-osdp's `CMD_ABORT` and `REPLY_FTSTAT` in the other direction, which is
///    exactly `odr-osdp`'s contested ledger entry #1.
/// 3. `0xF3`, a command byte nothing assigns.
fn corrupt_for_verify(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    assert!(lines.len() > 8, "need a capture with some traffic in it");

    if let Some(line) = lines.get_mut(2) {
        *line = map_bytes(line, |bytes| {
            if let Some(last) = bytes.last_mut() {
                *last ^= 0xFF;
            }
        });
    }
    for (index, id) in [(4usize, 0x7Au8), (6usize, 0xF3u8)] {
        if let Some(line) = lines.get_mut(index) {
            *line = map_bytes(line, |bytes| reid(bytes, id));
        }
    }
    lines.join("\n") + "\n"
}

/// Re-stamp a frame's id byte, recomputing the trailer through the engine so
/// that the result is a *valid* frame carrying a code the engine does not know.
fn reid(bytes: &mut Vec<u8>, id: u8) {
    if let Ok((mut frame, _)) = Frame::parse(bytes) {
        if frame.is_reply {
            return;
        }
        frame.id = id;
        *bytes = frame.encode();
    }
}

/// Rewrite the `bytes` field of one capture line through a closure.
fn map_bytes(line: &str, f: impl FnOnce(&mut Vec<u8>)) -> String {
    let key = "\"bytes\":\"";
    let start = match line.find(key) {
        Some(i) => i + key.len(),
        None => return line.to_string(),
    };
    let end = match line[start..].find('"') {
        Some(i) => start + i,
        None => return line.to_string(),
    };
    let mut bytes = odr_bus::capture::from_hex(&line[start..end]).expect("valid hex");
    f(&mut bytes);
    format!(
        "{}{}{}",
        &line[..start],
        odr_bus::capture::to_hex(&bytes),
        &line[end..]
    )
}
