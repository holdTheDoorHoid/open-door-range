//! **A tiny JSON writer, so `--json` is available on every command.**
//!
//! Hand-rolled for the same reason the argument parser is: this workspace has
//! one dependency and a serialiser for six flat report shapes does not justify
//! a second. [`Json`] is a value tree rather than a string builder, which is
//! what makes the output valid by construction — there is no way to forget a
//! comma or to interpolate an unescaped byte string into a field.
//!
//! `odr-bus`'s capture writer is deliberately *not* used here. That one emits
//! the interchange format of `DESIGN.md` §3 and must keep emitting exactly
//! that; this one emits report objects, which are this crate's own shape.

use std::fmt::Write as _;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A non-negative integer. Every number this tool emits is a count, a
    /// microsecond timestamp or a byte value, so there are no floats.
    Num(u64),
    /// A string, escaped on the way out.
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object, in insertion order — the same capture always renders the
    /// same bytes, which is the determinism rule of `DESIGN.md` §3 applied to
    /// this crate's own output.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// A string value.
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    /// An empty object, ready for [`Json::set`].
    pub fn obj() -> Json {
        Json::Obj(Vec::new())
    }

    /// An array from anything iterable.
    pub fn arr(items: impl IntoIterator<Item = Json>) -> Json {
        Json::Arr(items.into_iter().collect())
    }

    /// Add a field. A no-op on anything that is not an object, which cannot
    /// happen in this crate and is not worth a panic if it ever did.
    pub fn set(&mut self, key: impl Into<String>, value: Json) {
        if let Json::Obj(fields) = self {
            fields.push((key.into(), value));
        }
    }

    /// Add a field, fluently.
    pub fn with(mut self, key: impl Into<String>, value: Json) -> Json {
        self.set(key, value);
        self
    }

    /// Render, with two-space indentation and a trailing newline.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, depth: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => {
                let _ = write!(out, "{n}");
            }
            Json::Str(s) => write_string(out, s),
            Json::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    indent(out, depth + 1);
                    item.write(out, depth + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent(out, depth);
                out.push(']');
            }
            Json::Obj(fields) => {
                if fields.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (i, (key, value)) in fields.iter().enumerate() {
                    indent(out, depth + 1);
                    write_string(out, key);
                    out.push_str(": ");
                    value.write(out, depth + 1);
                    if i + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent(out, depth);
                out.push('}');
            }
        }
    }
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// Escape per RFC 8259: the two mandatory escapes, the five shorthands, and
/// `\u00XX` for everything else below `0x20`.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_renders_its_fields_in_insertion_order() {
        let j = Json::obj()
            .with("b", Json::Num(2))
            .with("a", Json::Num(1))
            .with(
                "c",
                Json::arr([Json::str("x"), Json::Bool(true), Json::Null]),
            );
        let text = j.render();
        assert!(text.starts_with("{\n  \"b\": 2,\n  \"a\": 1,"));
        assert!(text.contains("\"x\""));
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn control_characters_and_quotes_are_escaped() {
        let j = Json::str("a\"b\\c\nd\u{1}e");
        assert_eq!(j.render(), "\"a\\\"b\\\\c\\nd\\u0001e\"\n");
    }

    #[test]
    fn empty_containers_render_compactly() {
        assert_eq!(Json::obj().render(), "{}\n");
        assert_eq!(Json::arr([]).render(), "[]\n");
    }
}
