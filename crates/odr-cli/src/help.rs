//! **Help text, kept in one place so it cannot drift from the parser.**
//!
//! Written for someone who has a capture and a problem, not for someone
//! browsing. Each command's help says what it is *for* in the first line,
//! because "decode" and "replay" both mean about four things in this field.

/// The tool's version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `odr --version`.
pub fn version() -> String {
    format!("odr {VERSION} (Open Door Range)\n")
}

/// `odr help`.
pub fn overview() -> String {
    format!(
        "\
odr {VERSION} — Open Door Range, at the command line.

The same engine the browser range runs, pointed at a real capture. Use it to
find out where the range disagrees with your hardware; that disagreement is the
most valuable thing this project can be given (see CONTRIBUTING.md).

USAGE
  odr <command> [options] <capture>

COMMANDS
  decode    frame-by-frame decode of a capture, as the site's inspector would
  detect    run the standard defensive rule set and print findings with evidence
  stats     polling cadence, frame counts, secure channel posture, timing
  verify    check the engine's own documented assumptions against a capture
  replay    feed a capture through the engine and report where they diverge
  export    write a reference capture from a named scenario
  help      this, or `odr help <command>`

CAPTURE FORMAT
  Newline-delimited JSON, one object per observed event, as DESIGN.md section 3
  fixes it:

    {{\"t_us\":12345,\"line\":\"rs485\",\"dir\":\"acu_to_pd\",\"bytes\":\"53000e00...\"}}

  `line` is rs485, wiegand or clock_data. `dir` is acu_to_pd, pd_to_acu or wire.
  `bits` is optional and believed when present, which is the only way to tell a
  26-bit card read from a 32-bit one. A capture of `-` reads standard input.

COMMON OPTIONS
  --json          machine-readable output, on every command
  -h, --help      help for a command
  -V, --version   version

EXIT CODES
  0  it ran and found nothing wrong
  1  it ran and the analysis found something
  2  the command line or the file could not be read

Start with:  odr export --list
"
    )
}

/// Per-command help, or `None` for a name this tool does not have.
pub fn command(name: &str) -> Option<String> {
    Some(
        match name {
            "decode" => "\
odr decode — frame-by-frame decode of a capture.

The site's inspector in text form. Every event gets a timestamp, a direction and
a decode; every frame that did not decode gets a reason. Encrypted frames get
the honest split: what is readable without a key, and what is not — which is
more than people expect, because the command byte is plaintext even inside a
secure channel.

USAGE
  odr decode [options] <capture>

OPTIONS
  --line <name>      only rs485, wiegand or clock_data
  --address <n>      only this peripheral address (decimal or 0x01)
  --from <time>      only at or after this timestamp
  --to <time>        only before this timestamp
  --code <name>      only this command or reply code; repeatable.
                     POLL, CMD_POLL, ACK, REPLY_ACK and 0x60 all work
  --limit <n>        stop after this many events
  --bytes            show the raw octets of every event
  --json             machine-readable output

  Times take a suffix: 1500000, 1.5s, 250ms, 900us.

EXIT
  1 if any frame in the capture failed to decode, 0 otherwise."
                .to_string(),

            "detect" => "\
odr detect — what a passive monitor on this link could conclude.

Runs odr-detect's standard rule set: posture, keys, keyset, downgrade,
injection, replay, wire and traffic analysis. Every finding cites the frames
that justify it and states how sure the wire permits a detector to be. This is
the command a defender points at their own bus.

A finding is not a verdict. Read the confidence: `ambiguous` means the
observable is real and its cause cannot be determined from traffic by anyone.

USAGE
  odr detect [options] <capture>

OPTIONS
  --min-severity <level>  info, low, medium, high or critical (default: info)
  --quiet                 one line per finding, no evidence
  --json                  machine-readable output

EXIT
  1 if any printed finding is high or critical, 0 otherwise."
                .to_string(),

            "stats" => "\
odr stats — the summary somebody pastes into an issue.

Counts by code, polling cadence, reply latency, secure channel posture per
address, and what the two-wire side looks like. Nothing here is a judgement;
it is the shape of the traffic.

USAGE
  odr stats [options] <capture>

OPTIONS
  --json    machine-readable output

EXIT
  0 unless the capture could not be read."
                .to_string(),

            "verify" => "\
odr verify — check the engine's own assumptions against your capture.

This is the command this crate exists for. Every protocol crate in this
workspace ships a ledger of what it was unsure about, because the OSDP
specification is paywalled and the open implementations disagree with each
other. This turns those ledger entries into checks and runs them against real
bytes.

Each check names the ledger entry it relates to, and the run ends with a block
you can paste straight into a hardware-correction issue.

USAGE
  odr verify [options] <capture>

OPTIONS
  --list    list the checks and the ledger entries they relate to, and stop
  --json    machine-readable output

VERDICTS
  pass          the capture agrees with what the engine assumes
  differs       the capture disagrees. This is the useful outcome; file it
  inconclusive  the capture does not contain the traffic this check needs
  n/a           the check does not apply to this kind of capture

EXIT
  1 if any check differs, 0 otherwise."
                .to_string(),

            "replay" => "\
odr replay — feed a capture through the engine and report the divergences.

Where `verify` checks documented assumptions, this drives the engine's own code
over the recorded bytes and reports every place the two part company: a frame
that does not re-encode to the bytes that were on the wire, a sequence number
the state machine did not expect, a reply nobody asked for, a handshake whose
cryptogram does not verify under any key this project knows.

A divergence is not necessarily a bug in your hardware. On a capture from real
equipment it is more likely a bug — or an assumption — in this engine.

USAGE
  odr replay [options] <capture>

OPTIONS
  --limit <n>  stop after this many divergences (default: 50)
  --json       machine-readable output

EXIT
  1 if the engine and the capture diverged anywhere, 0 otherwise."
                .to_string(),

            "export" => "\
odr export — write a reference capture from a named scenario.

So that somebody with a bench has something to compare against: this is what
the range believes a clean badge-in, a cleartext OSDP bus, or a secure channel
under the published default key looks like, byte for byte. Run the same traffic
on your hardware, capture it, and point `odr verify` at both.

Every scenario is deterministic: the same seed gives the same bytes on every
machine.

USAGE
  odr export --scenario <name> [options]
  odr export --list

OPTIONS
  --scenario <name>  which scenario
  --list             list the scenarios and stop
  --seed <n>         the world seed (default: 1)
  -o, --out <path>   write here instead of standard output
  --json             describe the export rather than emitting the capture

EXIT
  0 unless the scenario is unknown or the file could not be written."
                .to_string(),

            _ => return None,
        } + "\n",
    )
}
