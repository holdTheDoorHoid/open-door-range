//! **A hand-rolled argument parser, and the value types it produces.**
//!
//! There is no argument-parsing dependency here on purpose. The workspace has
//! kept to `aes` alone (`DESIGN.md` §3 is about one engine, not about a rich
//! dependency tree), and the surface this tool needs — six subcommands, a
//! handful of long flags, one short flag that takes a path — is genuinely
//! smaller than the code it would take to configure a parser library.
//!
//! # The one thing a hand-rolled parser has to be told
//!
//! `--json` is a boolean and `--line rs485` is not, and nothing in the argument
//! vector says which is which. Rather than guess, every command hands
//! [`Flags::parse`] the list of flags that take a value. `--flag=value` is
//! always accepted; `--flag value` is accepted only for a flag on that list.
//! Anything else is a usage error naming the flag, which is the failure mode a
//! tired person can act on.
//!
//! # Never a panic
//!
//! Every parse returns [`UsageError`]. A bad `--from` is a diagnostic and exit
//! code 2, not a stack trace.

use std::fmt;

/// Something wrong with the command line.
///
/// Always exit code 2 — this is the "you typed something I could not read"
/// class, kept separate from "I read your capture and found problems".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// No subcommand at all.
    NoCommand,
    /// A subcommand this tool does not have.
    UnknownCommand(String),
    /// A flag this subcommand does not take.
    UnknownFlag(String),
    /// A flag that takes a value was given none.
    MissingValue(String),
    /// A flag that takes no value was given one.
    UnexpectedValue(String),
    /// A value that did not parse.
    BadValue {
        /// Which flag.
        flag: String,
        /// What was offered.
        value: String,
        /// What was expected.
        expected: String,
    },
    /// A required positional argument was not there.
    MissingArgument(&'static str),
    /// More positional arguments than the subcommand takes.
    ExtraArgument(String),
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::NoCommand => write!(f, "no command given"),
            UsageError::UnknownCommand(c) => write!(f, "unknown command \"{c}\""),
            UsageError::UnknownFlag(flag) => write!(f, "unknown option \"{flag}\""),
            UsageError::MissingValue(flag) => write!(f, "option \"{flag}\" needs a value"),
            UsageError::UnexpectedValue(flag) => write!(f, "option \"{flag}\" takes no value"),
            UsageError::BadValue {
                flag,
                value,
                expected,
            } => write!(f, "option \"{flag}\": \"{value}\" is not {expected}"),
            UsageError::MissingArgument(name) => write!(f, "missing argument <{name}>"),
            UsageError::ExtraArgument(a) => write!(f, "unexpected argument \"{a}\""),
        }
    }
}

impl std::error::Error for UsageError {}

/// Parsed flags and positional arguments, before any command has claimed them.
///
/// Commands pull what they want with [`Flags::has`], [`Flags::value`] and
/// [`Flags::values`], then call [`Flags::finish`], which fails on anything left
/// over. Claiming rather than matching is what keeps each command's option list
/// in one place instead of two.
#[derive(Debug, Clone, Default)]
pub struct Flags {
    seen: Vec<(String, Option<String>)>,
    positionals: Vec<String>,
}

impl Flags {
    /// Split an argument list into flags and positionals.
    ///
    /// `value_flags` are the long names (without dashes) that consume the next
    /// argument when they are not written as `--name=value`. `--` ends flag
    /// parsing; everything after it is positional, which is how a capture
    /// called `--weird.ndjson` is still openable.
    pub fn parse(args: &[String], value_flags: &[&str]) -> Result<Flags, UsageError> {
        let mut out = Flags::default();
        let mut only_positional = false;
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            i += 1;
            if only_positional {
                out.positionals.push(arg.clone());
                continue;
            }
            if arg == "--" {
                only_positional = true;
                continue;
            }
            let name = match short_or_long(arg) {
                Some(n) => n,
                None => {
                    out.positionals.push(arg.clone());
                    continue;
                }
            };
            if let Some((n, v)) = name.split_once('=') {
                out.seen.push((n.to_string(), Some(v.to_string())));
                continue;
            }
            if value_flags.contains(&name.as_str()) {
                let value = args
                    .get(i)
                    .cloned()
                    .ok_or_else(|| UsageError::MissingValue(name.clone()))?;
                i += 1;
                out.seen.push((name, Some(value)));
            } else {
                out.seen.push((name, None));
            }
        }
        Ok(out)
    }

    /// Claim a boolean flag. Errors if it was given a value.
    pub fn has(&mut self, name: &str) -> Result<bool, UsageError> {
        let mut found = false;
        for (n, v) in self.seen.iter() {
            if n == name {
                if v.is_some() {
                    return Err(UsageError::UnexpectedValue(name.to_string()));
                }
                found = true;
            }
        }
        self.seen.retain(|(n, _)| n != name);
        Ok(found)
    }

    /// Claim a flag that takes a value, keeping the last occurrence.
    pub fn value(&mut self, name: &str) -> Result<Option<String>, UsageError> {
        let all = self.values(name)?;
        Ok(all.into_iter().next_back())
    }

    /// Claim every occurrence of a repeatable flag, in the order given.
    pub fn values(&mut self, name: &str) -> Result<Vec<String>, UsageError> {
        let mut out = Vec::new();
        for (n, v) in self.seen.iter() {
            if n == name {
                match v {
                    Some(v) => out.push(v.clone()),
                    None => return Err(UsageError::MissingValue(name.to_string())),
                }
            }
        }
        self.seen.retain(|(n, _)| n != name);
        Ok(out)
    }

    /// The positional arguments, in order.
    pub fn positionals(&self) -> &[String] {
        &self.positionals
    }

    /// Claim the one positional argument this command expects.
    pub fn one_positional(&mut self, name: &'static str) -> Result<String, UsageError> {
        match self.positionals.len() {
            0 => Err(UsageError::MissingArgument(name)),
            1 => Ok(self.positionals.remove(0)),
            _ => Err(UsageError::ExtraArgument(self.positionals[1].clone())),
        }
    }

    /// Fail if any flag or positional was not claimed.
    pub fn finish(self) -> Result<(), UsageError> {
        if let Some((n, _)) = self.seen.first() {
            return Err(UsageError::UnknownFlag(n.clone()));
        }
        if let Some(a) = self.positionals.first() {
            return Err(UsageError::ExtraArgument(a.clone()));
        }
        Ok(())
    }
}

/// Strip one or two leading dashes, rejecting a bare `-` and a negative number.
fn short_or_long(arg: &str) -> Option<String> {
    if let Some(rest) = arg.strip_prefix("--") {
        if rest.is_empty() {
            return None;
        }
        return Some(rest.to_string());
    }
    let rest = arg.strip_prefix('-')?;
    let first = rest.chars().next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    // Short flags expand to their long spelling, so a command only ever has to
    // know one name for each option.
    Some(
        match first {
            'h' => "help",
            'V' => "version",
            'o' => "out",
            'j' => "json",
            _ => return Some(rest.to_string()),
        }
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Value parsing
// ---------------------------------------------------------------------------

/// Parse a duration or instant into virtual microseconds.
///
/// Accepts a bare integer of microseconds, or a decimal with a `us`, `ms` or
/// `s` suffix: `1500000`, `1.5s`, `1500ms`, `1500000us`. Integer arithmetic
/// throughout — there is no float in this workspace and a capture timestamp is
/// exact.
pub fn parse_time(flag: &str, text: &str) -> Result<u64, UsageError> {
    let bad = |what: &str| UsageError::BadValue {
        flag: flag.to_string(),
        value: text.to_string(),
        expected: what.to_string(),
    };
    let t = text.trim();
    let (number, scale) = if let Some(n) = t.strip_suffix("ms") {
        (n, 1_000u64)
    } else if let Some(n) = t.strip_suffix("us") {
        (n, 1u64)
    } else if let Some(n) = t.strip_suffix('s') {
        (n, 1_000_000u64)
    } else {
        (t, 1u64)
    };
    let number = number.trim();
    if number.is_empty() {
        return Err(bad("a time such as 1500000, 1.5s, 250ms or 900us"));
    }
    let (whole, frac) = match number.split_once('.') {
        Some((w, f)) => (w, f),
        None => (number, ""),
    };
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| bad("a time such as 1500000, 1.5s, 250ms or 900us"))?
    };
    if !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(bad("a time such as 1500000, 1.5s, 250ms or 900us"));
    }
    // Scale the fraction by hand so nothing here needs a float.
    let mut micros = whole.saturating_mul(scale);
    let mut place = scale;
    for c in frac.chars() {
        place /= 10;
        if place == 0 {
            break;
        }
        let digit = (c as u8 - b'0') as u64;
        micros = micros.saturating_add(digit.saturating_mul(place));
    }
    Ok(micros)
}

/// Parse a peripheral address: decimal, or `0x`-prefixed hex.
pub fn parse_address(flag: &str, text: &str) -> Result<u8, UsageError> {
    let bad = UsageError::BadValue {
        flag: flag.to_string(),
        value: text.to_string(),
        expected: "an OSDP address 0..=127, decimal or 0x-prefixed".to_string(),
    };
    let t = text.trim();
    let value = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16).map_err(|_| bad.clone())?,
        None => t.parse::<u16>().map_err(|_| bad.clone())?,
    };
    if value > 0x7F {
        return Err(bad);
    }
    Ok(value as u8)
}

/// Parse a plain non-negative integer.
pub fn parse_u64(flag: &str, text: &str) -> Result<u64, UsageError> {
    text.trim()
        .parse::<u64>()
        .map_err(|_| UsageError::BadValue {
            flag: flag.to_string(),
            value: text.to_string(),
            expected: "a non-negative integer".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_boolean_flag_and_a_value_flag_are_told_apart_by_the_command() {
        let mut f = Flags::parse(
            &args(&["--json", "--line", "rs485", "cap.ndjson"]),
            &["line"],
        )
        .expect("parses");
        assert!(f.has("json").unwrap());
        assert_eq!(f.value("line").unwrap().as_deref(), Some("rs485"));
        assert_eq!(f.one_positional("capture").unwrap(), "cap.ndjson");
        f.finish().unwrap();
    }

    #[test]
    fn equals_form_works_without_the_command_declaring_the_flag() {
        let mut f = Flags::parse(&args(&["--line=rs485"]), &[]).expect("parses");
        assert_eq!(f.value("line").unwrap().as_deref(), Some("rs485"));
    }

    #[test]
    fn an_unclaimed_flag_is_a_usage_error_naming_itself() {
        let f = Flags::parse(&args(&["--wat"]), &[]).expect("parses");
        assert_eq!(f.finish(), Err(UsageError::UnknownFlag("wat".to_string())));
    }

    #[test]
    fn a_repeatable_flag_keeps_every_occurrence_in_order() {
        let mut f =
            Flags::parse(&args(&["--code", "POLL", "--code", "ACK"]), &["code"]).expect("parses");
        assert_eq!(f.values("code").unwrap(), vec!["POLL", "ACK"]);
    }

    #[test]
    fn double_dash_lets_a_file_be_called_something_flag_shaped() {
        let mut f = Flags::parse(&args(&["--", "--weird.ndjson"]), &[]).expect("parses");
        assert_eq!(f.one_positional("capture").unwrap(), "--weird.ndjson");
    }

    #[test]
    fn times_parse_in_every_spelling_a_tired_person_might_use() {
        assert_eq!(parse_time("from", "1500000").unwrap(), 1_500_000);
        assert_eq!(parse_time("from", "1.5s").unwrap(), 1_500_000);
        assert_eq!(parse_time("from", "1500ms").unwrap(), 1_500_000);
        assert_eq!(parse_time("from", "900us").unwrap(), 900);
        assert_eq!(parse_time("from", "0.000001s").unwrap(), 1);
        assert_eq!(parse_time("from", ".5s").unwrap(), 500_000);
        assert!(parse_time("from", "later").is_err());
        assert!(parse_time("from", "1.2.3s").is_err());
    }

    #[test]
    fn addresses_parse_in_hex_and_decimal_and_reject_the_reply_bit() {
        assert_eq!(parse_address("address", "0x01").unwrap(), 1);
        assert_eq!(parse_address("address", "1").unwrap(), 1);
        assert_eq!(parse_address("address", "127").unwrap(), 0x7F);
        assert!(parse_address("address", "0x81").is_err());
        assert!(parse_address("address", "nope").is_err());
    }
}
