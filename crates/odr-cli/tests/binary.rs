//! **The binary, as a process.**
//!
//! The library suite covers what every command says. This one covers the thing
//! a library test structurally cannot: that `main` turns a [`Run`] into the
//! right process exit code, on the right stream, and that a closed pipe does
//! not take the program down with it.
//!
//! Exit codes are the interface a script sees. `odr verify && deploy` is a
//! reasonable thing for somebody to write, and it is only reasonable if the
//! codes are right.
//!
//! [`Run`]: odr_cli::Run

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// The binary cargo just built.
const ODR: &str = env!("CARGO_BIN_EXE_odr");

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn odr(args: &[&str]) -> Output {
    let out = Command::new(ODR)
        .args(args)
        .output()
        .expect("the binary runs");
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Export a scenario to a scratch file and hand back the path.
fn capture(scenario: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "odr-cli-bin-{}-{scenario}.ndjson",
        std::process::id()
    ));
    let result = odr(&[
        "export",
        "--scenario",
        scenario,
        "-o",
        &path.to_string_lossy(),
    ]);
    assert_eq!(result.code, 0, "export failed: {}", result.stderr);
    path
}

#[test]
fn a_clean_capture_exits_zero_on_every_command() {
    let path = capture("osdp-secure");
    let p = path.to_string_lossy().into_owned();
    // `detect` is deliberately not in this list. This bus runs its secure
    // channel on SCBK-D, the published default key, which is a critical finding
    // and exits 1 — correctly. "The engine produced it" is not the same as
    // "there is nothing wrong with it", and conflating the two is exactly the
    // mistake the defensive half exists to prevent.
    for command in ["decode", "stats", "verify", "replay"] {
        let result = odr(&[command, &p]);
        assert_eq!(
            result.code, 0,
            "{command} exited {}: {}",
            result.code, result.stdout
        );
        assert!(result.stderr.is_empty(), "{command} wrote to stderr");
    }

    let detect = odr(&["detect", &p]);
    assert_eq!(detect.code, 1, "a bus keyed with SCBK-D is a finding");
    assert!(detect.stdout.contains("default_key_in_use"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_capture_with_something_in_it_exits_one() {
    let path = capture("osdp-replay");
    let p = path.to_string_lossy().into_owned();
    for command in ["detect", "replay"] {
        let result = odr(&[command, &p]);
        assert_eq!(result.code, 1, "{command} should have found something");
        assert!(!result.stdout.is_empty());
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_usage_error_exits_two_with_nothing_on_stdout() {
    let result = odr(&["verify", "/no/such/capture.ndjson"]);
    assert_eq!(result.code, 2);
    assert!(result.stdout.is_empty(), "a diagnostic is not a result");
    assert!(result.stderr.starts_with("odr: "));
}

#[test]
fn a_capture_can_arrive_on_standard_input() {
    let text = odr(&["export", "--scenario", "osdp-clear"]).stdout;
    let mut child = Command::new(ODR)
        .args(["stats", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(text.as_bytes())
        .expect("the child takes the capture");
    let out = child.wait_with_output().expect("the child finishes");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("<stdin>"));
    assert!(stdout.contains("POLL"));
}

#[test]
fn version_and_help_exit_zero() {
    assert_eq!(odr(&["--version"]).code, 0);
    assert_eq!(odr(&["-V"]).code, 0);
    assert_eq!(odr(&["help"]).code, 0);
    assert_eq!(odr(&["help", "verify"]).code, 0);
    assert!(odr(&["help", "verify"])
        .stdout
        .contains("hardware-correction"));
}
