//! The `odr` binary. Everything it does is in the library beside it; this file
//! exists to move bytes to the two streams and to choose an exit code.
//!
//! Writes are deliberately ignoring their result. A closed pipe — `odr decode
//! big.ndjson | head` — is a normal thing for somebody to do and it is not an
//! error worth a message, let alone a panic.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = odr_cli::run(&args);

    if !result.out.is_empty() {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(result.out.as_bytes());
        let _ = lock.flush();
    }
    if !result.err.is_empty() {
        let stderr = std::io::stderr();
        let mut lock = stderr.lock();
        let _ = lock.write_all(result.err.as_bytes());
        let _ = lock.flush();
    }
    ExitCode::from(result.code)
}
