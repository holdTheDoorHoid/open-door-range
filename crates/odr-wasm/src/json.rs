//! **A JSON writer, hand-rolled.**
//!
//! The workspace has held to one dependency per crate and this one is the
//! boundary, so it takes `wasm-bindgen` and nothing else. Everything the site
//! asks for is a tree of objects, arrays, strings and numbers — no dates, no
//! maps with non-string keys, no cycles — so a writer is about eighty lines and
//! costs less than `serde` plus `serde-wasm-bindgen` would.
//!
//! Every accessor on [`crate::Engine`] returns a JSON **string**, which
//! `site/js/engine-wasm.js` hands to `JSON.parse`. That is deliberate: a string
//! crosses the wasm boundary once as a length-prefixed copy, and the browser's
//! own parser builds the object graph in native code. Building the same graph
//! with `js_sys` reflection calls would cross the boundary once per property.

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number. Non-finite values are written as `null`.
    Num(f64),
    /// A string.
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object, in insertion order.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// An empty object, ready for [`Json::set`].
    pub fn obj() -> Json {
        Json::Obj(Vec::new())
    }

    /// Add a key. Silently ignored on a non-object, which cannot happen the way
    /// this is used.
    pub fn set(&mut self, key: &str, value: Json) -> &mut Json {
        if let Json::Obj(v) = self {
            v.push((key.to_owned(), value));
        }
        self
    }

    /// Render to a JSON string.
    pub fn render(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Num(n) => write_num(*n, out),
            Json::Str(s) => write_str(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// A number. `NaN` and the infinities are not JSON, so they become `null`
/// rather than producing a document the browser refuses to parse.
fn write_num(n: f64, out: &mut String) {
    if !n.is_finite() {
        out.push_str("null");
        return;
    }
    if n == n.trunc() && n.abs() < 9.007_199_254_740_992e15 {
        // Integral values print without a fractional part, which keeps frame
        // times and byte values looking like what they are.
        out.push_str(&itoa(n as i64));
        return;
    }
    out.push_str(&n.to_string());
}

/// `i64` to decimal without pulling in a formatter that allocates twice.
fn itoa(mut v: i64) -> String {
    if v == 0 {
        return String::from("0");
    }
    let neg = v < 0;
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    while v != 0 {
        i -= 1;
        let d = (v % 10).unsigned_abs() as u8;
        digits[i] = b'0' + d;
        v /= 10;
    }
    let mut s = String::with_capacity(digits.len() - i + 1);
    if neg {
        s.push('-');
    }
    for b in &digits[i..] {
        s.push(*b as char);
    }
    s
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                for shift in [12, 8, 4, 0] {
                    let nibble = ((c as u32) >> shift) & 0xF;
                    out.push(char::from_digit(nibble, 16).unwrap_or('0'));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `Json::Str` from anything string-like.
pub fn s(v: impl Into<String>) -> Json {
    Json::Str(v.into())
}

/// `Json::Num` from anything that fits an `f64`.
pub fn n(v: impl Into<f64>) -> Json {
    Json::Num(v.into())
}

/// `Json::Num` from a `u64`, which does not implement `Into<f64>`.
pub fn nu(v: u64) -> Json {
    Json::Num(v as f64)
}

/// `Json::Num` from a `usize`.
pub fn nz(v: usize) -> Json {
    Json::Num(v as f64)
}

/// `Json::Bool`.
pub fn b(v: bool) -> Json {
    Json::Bool(v)
}

/// A list of strings.
pub fn strs<I, T>(items: I) -> Json
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    Json::Arr(items.into_iter().map(s).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_what_json_requires() {
        assert_eq!(s("a\"b\\c\nd").render(), r#""a\"b\\c\nd""#);
        assert_eq!(s("\u{1}").render(), "\"\\u0001\"");
    }

    #[test]
    fn integral_numbers_lose_their_fraction() {
        assert_eq!(n(4.0f64).render(), "4");
        assert_eq!(nu(20_000_000).render(), "20000000");
        assert_eq!(n(-7.0f64).render(), "-7");
    }

    #[test]
    fn non_finite_becomes_null() {
        assert_eq!(n(f64::INFINITY).render(), "null");
        assert_eq!(n(f64::NAN).render(), "null");
    }

    #[test]
    fn objects_keep_insertion_order() {
        let mut o = Json::obj();
        o.set("z", n(1.0f64)).set("a", b(true));
        assert_eq!(o.render(), r#"{"z":1,"a":true}"#);
    }
}
