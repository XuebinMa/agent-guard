//! RFC 8785 JSON Canonicalization Scheme.
//!
//! Verifying a hash-chained ledger means recomputing the exact bytes the
//! producer hashed, so canonicalization is part of the security boundary
//! rather than a formatting convenience. This is a from-scratch
//! implementation of RFC 8785 against the published specification.
//!
//! One deliberate restriction: non-integer numbers are refused instead of
//! serialized. RFC 8785 defers number formatting to ECMAScript
//! `Number::toString`, whose exponent and rounding rules differ from Rust
//! float formatting in ways that would silently produce different preimage
//! bytes. Refusing is a verification failure a caller can see; guessing is
//! a wrong hash a caller cannot.

use serde_json::{Map, Value};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum JcsError {
    /// A non-integer number was encountered; see the module note.
    UnsupportedNumber(String),
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JcsError::UnsupportedNumber(n) => write!(
                f,
                "JCS canonicalization of non-integer number {n} is not supported"
            ),
        }
    }
}

impl std::error::Error for JcsError {}

/// Serialize `value` into its RFC 8785 canonical form.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), JcsError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_number(number: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), JcsError> {
    if let Some(i) = number.as_i64() {
        out.extend_from_slice(i.to_string().as_bytes());
        return Ok(());
    }
    if let Some(u) = number.as_u64() {
        out.extend_from_slice(u.to_string().as_bytes());
        return Ok(());
    }
    Err(JcsError::UnsupportedNumber(number.to_string()))
}

/// RFC 8785 section 3.2.2.2: escape only what JSON requires, using the
/// two-character forms where they exist and `\u00xx` for the rest.
fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{9}' => out.extend_from_slice(b"\\t"),
            '\u{a}' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\u{d}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Object members are ordered by their key's UTF-16 code units, which is not
/// the same as Rust byte ordering for code points above the BMP.
fn write_object(map: &Map<String, Value>, out: &mut Vec<u8>) -> Result<(), JcsError> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| utf16_cmp(a, b));
    out.push(b'{');
    for (index, key) in keys.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        write_string(key, out);
        out.push(b':');
        write_value(&map[key.as_str()], out)?;
    }
    out.push(b'}');
    Ok(())
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}
