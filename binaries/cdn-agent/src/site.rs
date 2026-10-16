//! A zone serving a static site or a single-page app: the three keys of
//! its `settings` (contract C.4 "Zone settings", feed schema 3), checked
//! before the settings reach OpenResty.
//!
//! - `index_document`: `null` or one file name, 1-128 of `[A-Za-z0-9._-]`,
//!   never `.` and no `..`. `/` and every path ending in `/` fetch
//!   `<prefix><path><index_document>`.
//! - `spa_fallback`: bool, only with an `index_document`. An origin 404 on
//!   GET/HEAD, on a path under none of the excludes, serves the index
//!   document with 200.
//! - `spa_fallback_exclude`: 0 to 16 directory prefixes (absent: the data
//!   plane's default `["/assets/"]`), each a request path that starts and
//!   ends with `/`, at most 256 bytes, without `?` or `#`.
//!
//! `settings` stays opaque otherwise: a feed without these keys (an older
//! backend) passes unchanged, and so do keys this agent does not know. A
//! value that fails its check is never fatal: the zone serves, with the
//! feature turned off (an unusable index turns off both, an unusable
//! exclude list turns off the fallback, which must never answer 200 where
//! the customer asked for a 404). OpenResty (`site.lua`) applies the same
//! rules again.

use std::borrow::Cow;

use serde_json::Value;

use crate::feed::is_request_path;

const INDEX_MAX: usize = 128;
const MAX_EXCLUDES: usize = 16;
const EXCLUDE_MAX_BYTES: usize = 256;

const INDEX: &str = "index_document";
const FALLBACK: &str = "spa_fallback";
const EXCLUDE: &str = "spa_fallback_exclude";

/// One file name: no `/`, never `.`, no `..` anywhere.
pub fn is_valid_index(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= INDEX_MAX
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && v != "."
        && !v.contains("..")
}

/// A directory prefix the fallback leaves alone.
pub fn is_valid_exclude(v: &str) -> bool {
    v.len() <= EXCLUDE_MAX_BYTES
        && v.ends_with('/')
        && !v.contains(['?', '#'])
        && is_request_path(v)
}

fn valid_excludes(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Array(items) => {
            items.len() <= MAX_EXCLUDES
                && items
                    .iter()
                    .all(|e| e.as_str().is_some_and(is_valid_exclude))
        }
        _ => false,
    }
}

/// `settings` as OpenResty should receive it, and the classes of the
/// values that were turned off (empty: unchanged, borrowed).
pub fn sanitize(settings: &Value) -> (Cow<'_, Value>, Vec<&'static str>) {
    let Value::Object(map) = settings else {
        return (Cow::Borrowed(settings), Vec::new());
    };
    let mut problems = Vec::new();
    let index_ok = match map.get(INDEX) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if is_valid_index(s) => Some(true),
        Some(_) => {
            problems.push("index-document-invalid");
            Some(false)
        }
    };
    let fallback = match map.get(FALLBACK) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            problems.push("spa-fallback-invalid");
            false
        }
    };
    let excludes_ok = map.get(EXCLUDE).is_none_or(valid_excludes);
    if !excludes_ok {
        problems.push("spa-fallback-exclude-invalid");
    }
    if fallback && index_ok != Some(true) {
        problems.push("spa-fallback-without-index");
    }
    if problems.is_empty() {
        return (Cow::Borrowed(settings), problems);
    }
    let mut out = map.clone();
    if index_ok == Some(false) {
        out.insert(INDEX.into(), Value::Null);
    }
    if map.contains_key(FALLBACK) {
        let keep = fallback && index_ok == Some(true) && excludes_ok;
        out.insert(FALLBACK.into(), Value::Bool(keep));
    }
    if !excludes_ok {
        out.remove(EXCLUDE);
    }
    (Cow::Owned(Value::Object(out)), problems)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_feed_without_the_keys_passes_unchanged() {
        for s in [
            json!(null),
            json!({}),
            json!({"rules": [], "redirect_https": true, "limits": {"max_rps": 3}}),
            json!({"index_document": null, "spa_fallback": null, "spa_fallback_exclude": null}),
            json!({"future_key": {"anything": [1, 2]}}),
        ] {
            let (out, problems) = sanitize(&s);
            assert!(matches!(out, Cow::Borrowed(_)), "{s}");
            assert!(problems.is_empty(), "{s}");
        }
    }

    #[test]
    fn valid_site_settings_pass_unchanged() {
        for s in [
            json!({"index_document": "index.html"}),
            json!({"index_document": "index.html", "spa_fallback": true}),
            json!({"index_document": "index.html", "spa_fallback": false, "spa_fallback_exclude": []}),
            json!({"index_document": "i.htm", "spa_fallback": true,
                   "spa_fallback_exclude": ["/assets/", "/api/v1/", "/a%20b/"], "rules": []}),
            json!({"spa_fallback": false}),
        ] {
            let (out, problems) = sanitize(&s);
            assert_eq!(*out, s);
            assert!(matches!(out, Cow::Borrowed(_)), "{s}");
            assert!(problems.is_empty(), "{s}: {problems:?}");
        }
        let excludes: Vec<String> = (0..16).map(|i| format!("/p{i}/")).collect();
        let s = json!({"index_document": "index.html", "spa_fallback": true,
                       "spa_fallback_exclude": excludes});
        assert!(sanitize(&s).1.is_empty(), "16 excludes");
        assert!(is_valid_index(&"a".repeat(128)));
        assert!(is_valid_index(".well-known.html"));
        assert!(is_valid_exclude(&format!("/{}/", "a".repeat(254))));
    }

    #[test]
    fn an_unusable_index_turns_off_both_and_keeps_the_rest() {
        let long = "a".repeat(129);
        for bad in [
            json!(""),
            json!("a/b.html"),
            json!("../index.html"),
            json!(".."),
            json!("."),
            json!("a..b"),
            json!("x y"),
            json!("index.html?x"),
            json!("%2e%2e"),
            json!("é.html"),
            json!(long),
            json!(7),
            json!(["index.html"]),
        ] {
            let s = json!({"index_document": bad, "spa_fallback": true, "rules": [{"x": 1}]});
            let (out, problems) = sanitize(&s);
            assert_eq!(out["index_document"], Value::Null, "{bad}");
            assert_eq!(out["spa_fallback"], false, "{bad}");
            assert_eq!(out["rules"], json!([{"x": 1}]), "{bad}");
            assert_eq!(
                problems,
                ["index-document-invalid", "spa-fallback-without-index"],
                "{bad}"
            );
        }
    }

    #[test]
    fn an_unusable_exclude_list_turns_off_the_fallback_only() {
        let long = format!("/{}/", "a".repeat(255));
        let many: Vec<String> = (0..17).map(|i| format!("/p{i}/")).collect();
        for bad in [
            json!(["assets/"]),
            json!(["/assets"]),
            json!(["/a/../b/"]),
            json!(["/a/./"]),
            json!(["/%2e%2e/"]),
            json!(["/a?b/"]),
            json!(["/a#/"]),
            json!(["/a b/"]),
            json!(["/a%00/"]),
            json!(["/a\\b/"]),
            json!([long]),
            json!([1]),
            json!("/assets/"),
            json!({"a": "/x/"}),
            json!(many),
        ] {
            let s = json!({"index_document": "index.html", "spa_fallback": true,
                           "spa_fallback_exclude": bad});
            let (out, problems) = sanitize(&s);
            assert_eq!(out["spa_fallback"], false, "{bad}");
            assert_eq!(out["index_document"], "index.html", "{bad}");
            assert!(out.get("spa_fallback_exclude").is_none(), "{bad}");
            assert_eq!(problems, ["spa-fallback-exclude-invalid"], "{bad}");
        }
    }

    #[test]
    fn a_fallback_needs_a_boolean_and_an_index() {
        let no_index = json!({"spa_fallback": true});
        let (out, problems) = sanitize(&no_index);
        assert_eq!(out["spa_fallback"], false);
        assert_eq!(problems, ["spa-fallback-without-index"]);
        let not_bool = json!({"index_document": "index.html", "spa_fallback": "yes"});
        let (out, problems) = sanitize(&not_bool);
        assert_eq!(out["spa_fallback"], false);
        assert_eq!(out["index_document"], "index.html");
        assert_eq!(problems, ["spa-fallback-invalid"]);
    }
}
