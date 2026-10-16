//! Strict readers over a decoded CBOR map, shared by the disk-tier wire
//! types (`disk_stats`, `storage_report`). Every reader fails closed: a
//! missing key, an extra key, a wrong CBOR type or an out-of-range
//! integer is an error, never a default.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use ciborium::value::Value;

/// The entries of `v`, which must be a CBOR map whose text keys are
/// EXACTLY `keys` (any order, no duplicates). `what` names the map in the
/// error.
pub(crate) fn exact_map<'a>(
    v: &'a Value,
    keys: &[&str],
    what: &str,
) -> core::result::Result<&'a [(Value, Value)], String> {
    let Value::Map(entries) = v else {
        return Err(format!("{what}: not a map"));
    };
    if entries.len() != keys.len() {
        return Err(format!(
            "{what}: expected {} keys, got {}",
            keys.len(),
            entries.len()
        ));
    }
    for (k, _) in entries {
        let Value::Text(name) = k else {
            return Err(format!("{what}: non-text key"));
        };
        if !keys.contains(&name.as_str()) {
            return Err(format!("{what}: unknown key"));
        }
    }
    for key in keys {
        if entries
            .iter()
            .filter(|(k, _)| matches!(k, Value::Text(n) if n == key))
            .count()
            != 1
        {
            return Err(format!("{what}: missing or duplicate {key}"));
        }
    }
    Ok(entries)
}

/// The value under `key` (present by [`exact_map`]).
pub(crate) fn get<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> core::result::Result<&'a Value, String> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(n) if n == key))
        .map(|(_, v)| v)
        .ok_or_else(|| format!("missing {key}"))
}

pub(crate) fn u64_at(entries: &[(Value, Value)], key: &str) -> core::result::Result<u64, String> {
    match get(entries, key)? {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| format!("{key}: not a u64")),
        _ => Err(format!("{key}: not an integer")),
    }
}

pub(crate) fn u32_at(entries: &[(Value, Value)], key: &str) -> core::result::Result<u32, String> {
    u32::try_from(u64_at(entries, key)?).map_err(|_| format!("{key}: not a u32"))
}

pub(crate) fn text_at(
    entries: &[(Value, Value)],
    key: &str,
) -> core::result::Result<String, String> {
    match get(entries, key)? {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(format!("{key}: not text")),
    }
}

pub(crate) fn bool_at(entries: &[(Value, Value)], key: &str) -> core::result::Result<bool, String> {
    match get(entries, key)? {
        Value::Bool(b) => Ok(*b),
        _ => Err(format!("{key}: not a bool")),
    }
}

pub(crate) fn bytes_at<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> core::result::Result<&'a [u8], String> {
    match get(entries, key)? {
        Value::Bytes(b) => Ok(b.as_slice()),
        _ => Err(format!("{key}: not bytes")),
    }
}

pub(crate) fn array_at<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> core::result::Result<&'a [Value], String> {
    match get(entries, key)? {
        Value::Array(items) => Ok(items.as_slice()),
        _ => Err(format!("{key}: not an array")),
    }
}

/// `true` when `s` is `min..=max` bytes, every one accepted by `ok`.
pub(crate) fn charset(s: &str, min: usize, max: usize, ok: impl Fn(u8) -> bool) -> bool {
    s.len() >= min && s.len() <= max && s.bytes().all(ok)
}

/// `[a-z0-9-]` — pool ids and error codes.
pub(crate) fn is_slug_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
}

/// `0..=48` bytes of `[a-z0-9-]` — a machine error code, `""` for none.
pub(crate) fn is_valid_error_code(s: &str) -> bool {
    charset(s, 0, 48, is_slug_byte)
}

/// Helper for building map entries.
pub(crate) fn kv(key: &str, value: Value) -> (Value, Value) {
    (Value::Text(key.to_string()), value)
}
