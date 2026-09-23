//! **`odr` — the Open Door Range at the command line.**
//!
//! `DESIGN.md` §3 decides that there is one engine: the browser range and the
//! real-capture analyser are literally the same Rust crates, so a drill can
//! never teach something the analyser disagrees with. This crate is the other
//! consumer of that engine. It reads a capture in the format §3 fixes and runs
//! the same `odr-osdp`, `odr-wiegand`, `odr-bus` and `odr-detect` code the
//! WebAssembly build runs, with nothing of its own in between.
//!
//! ```text
//!   capture.ndjson ──▶ odr-bus::capture ──▶ odr-osdp / odr-wiegand ──▶ output
//!                                       └──▶ odr-detect::Monitor ────┘
//! ```
//!
//! # Why it exists
//!
//! `CONTRIBUTING.md` says the most valuable contribution this project can
//! receive is a correction from real hardware, and every protocol crate ships a
//! ledger of what it was unsure about because the OSDP specification is
//! paywalled and the open implementations disagree. [`verify`](cmd_verify) is
//! this crate's reason to exist: it turns those ledger entries into checks, runs
//! them against real bytes, and ends with a block that goes straight into the
//! hardware-correction issue template.
//!
//! # The rules this crate keeps
//!
//! * **The only crate here that may use `std`**, and the only one excluded from
//!   the workspace's `wasm32-unknown-unknown` build. Everything it analyses with
//!   is still `no_std`.
//! * **`#![forbid(unsafe_code)]`.**
//! * **No argument-parsing dependency.** See [`args`]. The workspace has kept to
//!   `aes` alone and six subcommands do not justify breaking that.
//! * **No panics on input.** A malformed capture is a diagnostic. Every command
//!   returns an exit code rather than unwinding, and there is a test that feeds
//!   each one rubbish.
//! * **Plain text by default, `--json` everywhere.** No colour at all, so there
//!   is nothing to strip when output is pasted into an issue.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | it ran and found nothing wrong |
//! | 1 | it ran and the analysis found something |
//! | 2 | the command line, or the file, could not be read |
//!
//! # Using it as a library
//!
//! [`run`] takes an argument list and hands back what would have been printed,
//! which is how the test suite exercises every command without a subprocess.
//!
//! ```
//! let args: Vec<String> = ["export", "--list"].iter().map(|s| s.to_string()).collect();
//! let result = odr_cli::run(&args);
//! assert_eq!(result.code, odr_cli::EXIT_OK);
//! assert!(result.out.contains("osdp-secure"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod args;
pub mod capture;
pub mod cmd_decode;
pub mod cmd_detect;
pub mod cmd_export;
pub mod cmd_replay;
pub mod cmd_stats;
pub mod cmd_verify;
pub mod help;
pub mod json;
pub mod out;

#[cfg(test)]
mod tests;

use args::{Flags, UsageError};

/// It ran and found nothing wrong.
pub const EXIT_OK: u8 = 0;
/// It ran and the analysis found something.
pub const EXIT_FINDINGS: u8 = 1;
/// The command line, or the file, could not be read.
pub const EXIT_USAGE: u8 = 2;

/// What a command would have printed, and what it would have exited with.
///
/// Returned rather than written so that the whole tool is testable in-process.
/// `main` does nothing but hand this to the two streams and exit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Run {
    /// Everything for standard output.
    pub out: String,
    /// Everything for standard error: diagnostics only, never results.
    pub err: String,
    /// The exit code.
    pub code: u8,
}

impl Run {
    /// A successful run with this output.
    pub fn ok(out: impl Into<String>) -> Run {
        Run {
            out: out.into(),
            err: String::new(),
            code: EXIT_OK,
        }
    }

    /// A run that produced output and found something worth an exit code of 1.
    pub fn findings(out: impl Into<String>) -> Run {
        Run {
            out: out.into(),
            err: String::new(),
            code: EXIT_FINDINGS,
        }
    }

    /// A diagnostic on standard error, with exit code 2.
    ///
    /// The `try odr help` line is always appended, because the single most
    /// useful thing an error message can do is say what to type next.
    pub fn usage(message: impl std::fmt::Display) -> Run {
        Run {
            out: String::new(),
            err: format!("odr: {message}\ntry `odr help`\n"),
            code: EXIT_USAGE,
        }
    }

    /// A diagnostic on standard error with exit code 2 and no advice, for a
    /// file that could not be read — where "try odr help" is not the problem.
    pub fn failure(message: impl std::fmt::Display) -> Run {
        Run {
            out: String::new(),
            err: format!("odr: {message}\n"),
            code: EXIT_USAGE,
        }
    }
}

impl From<UsageError> for Run {
    fn from(e: UsageError) -> Run {
        Run::usage(e)
    }
}

/// Run the tool.
///
/// `args` is the argument list **without** the program name. Nothing here
/// touches the process: no exit, no direct printing, no environment beyond what
/// a command explicitly reads.
pub fn run(args: &[String]) -> Run {
    let first = match args.first() {
        Some(a) => a.as_str(),
        None => return Run::ok(help::overview()),
    };

    match first {
        "-V" | "--version" => return Run::ok(help::version()),
        "-h" | "--help" => return Run::ok(help::overview()),
        "help" => {
            return match args.get(1) {
                None => Run::ok(help::overview()),
                Some(name) => match help::command(name) {
                    Some(text) => Run::ok(text),
                    None => Run::usage(UsageError::UnknownCommand(name.clone())),
                },
            }
        }
        _ => {}
    }

    let rest = &args[1..];
    // `odr decode --help` is the same as `odr help decode`, which is what
    // everyone types first.
    if rest.iter().any(|a| a == "--help" || a == "-h") {
        if let Some(text) = help::command(first) {
            return Run::ok(text);
        }
    }

    match first {
        "decode" => dispatch(rest, cmd_decode::VALUE_FLAGS, cmd_decode::run),
        "detect" => dispatch(rest, cmd_detect::VALUE_FLAGS, cmd_detect::run),
        "stats" => dispatch(rest, cmd_stats::VALUE_FLAGS, cmd_stats::run),
        "verify" => dispatch(rest, cmd_verify::VALUE_FLAGS, cmd_verify::run),
        "replay" => dispatch(rest, cmd_replay::VALUE_FLAGS, cmd_replay::run),
        "export" => dispatch(rest, cmd_export::VALUE_FLAGS, cmd_export::run),
        other => Run::usage(UsageError::UnknownCommand(other.to_string())),
    }
}

/// Parse this command's flags and hand them over, turning any usage error into
/// exit code 2.
fn dispatch(args: &[String], value_flags: &[&str], f: fn(Flags) -> Run) -> Run {
    match Flags::parse(args, value_flags) {
        Ok(flags) => f(flags),
        Err(e) => Run::usage(e),
    }
}
