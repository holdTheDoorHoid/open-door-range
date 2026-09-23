//! **Plain text for someone standing in a plant room.**
//!
//! Everything here is deliberately boring. No colour — not "colour off by
//! default", none at all, so there is no terminal detection to get wrong and
//! nothing to strip when the output is piped into an issue. No box drawing
//! beyond a run of hyphens. Fixed-width columns, because the reader is scanning
//! for one line among several hundred and a ragged left edge makes that slower.
//!
//! Anything that needs to be machine-read has `--json` instead.

use odr_osdp::{Command, Frame, Reply, ScsType};

/// Virtual microseconds as seconds with six decimal places.
///
/// The same rendering `odr_detect::observe::fmt_us` uses, so a finding and a
/// decode line put the same timestamp on the page.
pub fn fmt_us(t_us: u64) -> String {
    format!("{}.{:06}s", t_us / 1_000_000, t_us % 1_000_000)
}

/// A duration, in whatever unit keeps it readable.
pub fn fmt_dur(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{}.{:03}s", us / 1_000_000, (us % 1_000_000) / 1_000)
    } else if us >= 1_000 {
        format!("{}.{:03}ms", us / 1_000, us % 1_000)
    } else {
        format!("{us}us")
    }
}

/// Lowercase hex, space-separated, so a byte can be counted off by eye.
pub fn fmt_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Lowercase hex with no separators, as the capture format writes it.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The name of whatever a frame carries, falling back to the raw byte.
///
/// A code this crate does not know is shown rather than hidden — an unknown
/// command byte is the single most interesting thing a real capture can contain
/// (see `odr verify`'s `command-codes` check).
pub fn code_name(frame: &Frame) -> String {
    if frame.is_reply {
        match frame.reply_code() {
            Some(r) => r.name().to_string(),
            None => format!("REPLY_{:#04x}", frame.id),
        }
    } else {
        match frame.command_code() {
            Some(c) => c.name().to_string(),
            None => format!("CMD_{:#04x}", frame.id),
        }
    }
}

/// Resolve a `--code` filter value to a raw id byte.
///
/// Accepts `POLL`, `CMD_POLL`, `ACK`, `REPLY_ACK` or `0x60`, case-insensitively,
/// so nobody has to remember which spelling this tool prefers.
pub fn resolve_code(text: &str) -> Option<u8> {
    let t = text.trim();
    if let Some(hexpart) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u8::from_str_radix(hexpart, 16).ok();
    }
    let upper = t.to_ascii_uppercase();
    let bare = upper
        .strip_prefix("CMD_")
        .or_else(|| upper.strip_prefix("REPLY_"))
        .unwrap_or(&upper);
    for c in Command::ALL {
        if c.name() == upper || c.name() == bare {
            return Some(c.to_u8());
        }
    }
    for r in Reply::ALL {
        if r.name() == upper || r.name() == bare {
            return Some(r.to_u8());
        }
    }
    None
}

/// `SCS_17` and the like, or the raw byte for a type this crate does not know.
pub fn scs_name(frame: &Frame) -> Option<String> {
    let sec = frame.security.as_ref()?;
    Some(match sec.scs_type {
        Some(t) => format!("SCS_{:02X}", t.to_u8()),
        None => format!("security block {:#04x}", sec.raw_type),
    })
}

/// What a secure-channel block type is for, in one clause.
pub fn scs_purpose(scs: ScsType) -> &'static str {
    match scs {
        ScsType::Chlng => "handshake: the controller's challenge, RND.A",
        ScsType::Ccrypt => "handshake: the peripheral's cryptogram, cUID and RND.B",
        ScsType::Scrypt => "handshake: the controller's cryptogram",
        ScsType::RmacI => "handshake: the peripheral's initial R-MAC",
        ScsType::CmdMacOnly => "in session, authenticated, payload NOT encrypted",
        ScsType::ReplyMacOnly => "in session, authenticated, payload NOT encrypted",
        ScsType::CmdEncrypted => "in session, authenticated and encrypted",
        ScsType::ReplyEncrypted => "in session, authenticated and encrypted",
    }
}

/// A heading with a rule under it.
pub fn heading(out: &mut String, text: &str) {
    out.push('\n');
    out.push_str(text);
    out.push('\n');
    for _ in 0..text.chars().count() {
        out.push('-');
    }
    out.push('\n');
}

/// The value at a percentile of an already-sorted slice.
///
/// Nearest-rank, integer arithmetic, no interpolation: the number printed is a
/// measurement that actually occurred rather than an average of two that did
/// not. `None` for an empty slice.
pub fn percentile(sorted: &[u64], pct: u64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (pct.saturating_mul(sorted.len() as u64)).div_ceil(100);
    let idx = rank.max(1) as usize - 1;
    sorted.get(idx.min(sorted.len() - 1)).copied()
}

/// A left-padded count column, so a list of counts lines up.
pub fn pad_left(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.to_string();
    }
    let mut s = String::with_capacity(width);
    for _ in 0..width - len {
        s.push(' ');
    }
    s.push_str(text);
    s
}

/// Wrap at a width, indenting continuation lines.
///
/// No hyphenation and no cleverness: this exists so that a long ledger
/// reference does not run off the right of an 80-column terminal in a riser,
/// and for nothing else.
pub fn wrap(text: &str, width: usize, indent: &str) -> String {
    let mut out = String::new();
    let mut column = 0usize;
    for word in text.split_whitespace() {
        let len = word.chars().count();
        if column > 0 && column + 1 + len > width {
            out.push('\n');
            out.push_str(indent);
            column = 0;
        } else if column > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += len;
    }
    out
}

/// A right-padded label column.
pub fn pad_right(text: &str, width: usize) -> String {
    let len = text.chars().count();
    let mut s = String::with_capacity(width.max(len));
    s.push_str(text);
    for _ in len..width {
        s.push(' ');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_match_the_engines_own_rendering() {
        assert_eq!(fmt_us(0), "0.000000s");
        assert_eq!(fmt_us(1_234_567), "1.234567s");
        assert_eq!(fmt_us(999), "0.000999s");
    }

    #[test]
    fn durations_pick_a_readable_unit() {
        assert_eq!(fmt_dur(900), "900us");
        assert_eq!(fmt_dur(2_500), "2.500ms");
        assert_eq!(fmt_dur(1_500_000), "1.500s");
    }

    #[test]
    fn code_filters_accept_every_spelling() {
        assert_eq!(resolve_code("POLL"), Some(0x60));
        assert_eq!(resolve_code("cmd_poll"), Some(0x60));
        assert_eq!(resolve_code("0x60"), Some(0x60));
        assert_eq!(resolve_code("ACK"), Some(0x40));
        assert_eq!(resolve_code("reply_ack"), Some(0x40));
        assert_eq!(resolve_code("nonsense"), None);
    }

    #[test]
    fn percentiles_are_nearest_rank_and_never_index_out_of_range() {
        let sorted = [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile(&sorted, 50), Some(5));
        assert_eq!(percentile(&sorted, 90), Some(9));
        assert_eq!(percentile(&sorted, 100), Some(10));
        assert_eq!(percentile(&sorted, 0), Some(1));
        assert_eq!(percentile(&[], 50), None);
    }
}
