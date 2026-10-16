//! A zone's CORS policy (`settings.cors`, contract C.4 "Zone settings"),
//! checked before the settings reach OpenResty (`cors.lua` applies the
//! same rules again and serves it).
//!
//! - `allow_origins`: 1 to 32, `["*"]` or origins `scheme://host[:port]`
//!   (http or https, lower case, no path, no default port), or
//!   `scheme://*.suffix[:port]` (one label in place of `*`, a suffix of at
//!   least two labels);
//! - `allow_methods`: a non-empty subset of `GET`, `HEAD` (absent: both);
//! - `allow_headers`, `expose_headers`: up to 32 header names of at most 64
//!   bytes, or `["*"]`;
//! - `max_age`: seconds, 0 to 86400;
//! - `allow_credentials`: bool, never with a `*`.
//!
//! Unknown keys are ignored. A policy that fails a check is removed whole
//! and reported: the zone serves, without CORS. A zone without one passes
//! unchanged.

use std::borrow::Cow;

use serde_json::Value;

const MAX_ORIGINS: usize = 32;
const MAX_HEADERS: usize = 32;
const MAX_HEADER_LEN: usize = 64;
const MAX_AGE: f64 = 86_400.0;

/// Lower-case LDH labels, at least `min_labels` of them.
fn is_valid_host(h: &str, min_labels: usize) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    labels.len() >= min_labels
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// One `allow_origins` entry other than `*`.
pub fn is_valid_origin(o: &str) -> bool {
    let Some((scheme, rest)) = o.split_once("://") else {
        return false;
    };
    if scheme != "http" && scheme != "https" || o.len() > 300 {
        return false;
    }
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if let Some(p) = port {
        let digits = !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && !p.starts_with('0');
        let n: u32 = if digits { p.parse().unwrap_or(0) } else { 0 };
        let default = (scheme == "https" && n == 443) || (scheme == "http" && n == 80);
        if !(1..=65_535).contains(&n) || default {
            return false;
        }
    }
    match host.strip_prefix("*.") {
        Some(suffix) => is_valid_host(suffix, 2),
        None => is_valid_host(host, 1),
    }
}

fn is_token(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= MAX_HEADER_LEN
        && h != "*"
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
}

fn valid_header_list(v: Option<&Value>, credentials: bool) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::Array(items)) => {
            let star = items.len() == 1 && items[0].as_str() == Some("*");
            items.len() <= MAX_HEADERS
                && (star && !credentials || items.iter().all(|i| i.as_str().is_some_and(is_token)))
        }
        _ => false,
    }
}

/// `Ok` for a usable policy, else the field that is not.
pub fn check(cors: &Value) -> Result<(), &'static str> {
    let Value::Object(c) = cors else {
        return Err("cors-invalid");
    };
    let credentials = match c.get("allow_credentials") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("cors-allow-credentials-invalid"),
    };
    let Some(Value::Array(origins)) = c.get("allow_origins") else {
        return Err("cors-allow-origins-invalid");
    };
    let star = origins.len() == 1 && origins[0].as_str() == Some("*");
    if star && credentials {
        return Err("cors-star-with-credentials");
    }
    let origins_ok = (1..=MAX_ORIGINS).contains(&origins.len())
        && (star
            || origins
                .iter()
                .all(|o| o.as_str().is_some_and(is_valid_origin)));
    if !origins_ok {
        return Err("cors-allow-origins-invalid");
    }
    let methods_ok = match c.get("allow_methods") {
        None | Some(Value::Null) => true,
        Some(Value::Array(m)) => {
            (1..=2).contains(&m.len())
                && m.iter().all(|x| matches!(x.as_str(), Some("GET" | "HEAD")))
        }
        _ => false,
    };
    if !methods_ok {
        return Err("cors-allow-methods-invalid");
    }
    if !valid_header_list(c.get("allow_headers"), credentials) {
        return Err("cors-allow-headers-invalid");
    }
    if !valid_header_list(c.get("expose_headers"), credentials) {
        return Err("cors-expose-headers-invalid");
    }
    let max_age_ok = match c.get("max_age") {
        None | Some(Value::Null) => true,
        Some(Value::Number(n)) => n
            .as_f64()
            .is_some_and(|f| (0.0..=MAX_AGE).contains(&f) && f.fract() == 0.0),
        _ => false,
    };
    if !max_age_ok {
        return Err("cors-max-age-invalid");
    }
    Ok(())
}

/// `settings` without an unusable `cors` (removed whole), and why it was.
pub fn sanitize(settings: Cow<'_, Value>) -> (Cow<'_, Value>, Option<&'static str>) {
    let problem = match settings.as_object().and_then(|m| m.get("cors")) {
        None | Some(Value::Null) => return (settings, None),
        Some(cors) => match check(cors) {
            Ok(()) => return (settings, None),
            Err(class) => class,
        },
    };
    let mut owned = settings.into_owned();
    if let Value::Object(map) = &mut owned {
        map.remove("cors");
    }
    (Cow::Owned(owned), Some(problem))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(s: &Value) -> (Value, Option<&'static str>, bool) {
        let (out, problem) = sanitize(Cow::Borrowed(s));
        let borrowed = matches!(out, Cow::Borrowed(_));
        (out.into_owned(), problem, borrowed)
    }

    #[test]
    fn no_policy_or_a_usable_one_passes_unchanged() {
        for s in [
            json!(null),
            json!({}),
            json!({"rules": [], "cors": null}),
            json!({"cors": {"allow_origins": ["*"]}}),
            json!({"cors": {"allow_origins": ["https://a.com", "https://*.b.com", "http://localhost:3000",
                                             "https://a.com:8443"],
                            "allow_methods": ["GET"], "allow_headers": ["X-Custom", "content-type"],
                            "expose_headers": ["ETag"], "max_age": 600, "allow_credentials": true,
                            "future_key": 1}}),
            json!({"cors": {"allow_origins": ["*"], "allow_headers": ["*"], "expose_headers": ["*"],
                            "max_age": 0}}),
        ] {
            let (out, problem, borrowed) = run(&s);
            assert_eq!(out, s);
            assert!(borrowed && problem.is_none(), "{s}");
        }
        let many: Vec<String> = (0..32).map(|i| format!("https://o{i}.com")).collect();
        assert!(check(&json!({"allow_origins": many})).is_ok());
    }

    /// The shape the backend feeds (cdn/cors.py, FEED_SCHEMA 4): every key
    /// present, `max_age` always set, empty lists allowed.
    #[test]
    fn the_backend_feed_shape_passes_unchanged() {
        let s = json!({"rules": [], "cors": {
            "allow_origins": ["https://app.example", "https://*.tenant.example"],
            "allow_methods": ["GET", "HEAD"], "allow_headers": [], "expose_headers": [],
            "max_age": 600, "allow_credentials": false}});
        let (out, problem, borrowed) = run(&s);
        assert_eq!(out, s);
        assert!(borrowed && problem.is_none());
    }

    #[test]
    fn an_unusable_policy_is_removed_whole_and_the_rest_kept() {
        let many: Vec<String> = (0..33).map(|i| format!("https://o{i}.com")).collect();
        let cases = [
            (json!([]), "cors-invalid"),
            (json!({}), "cors-allow-origins-invalid"),
            (json!({"allow_origins": []}), "cors-allow-origins-invalid"),
            (json!({"allow_origins": many}), "cors-allow-origins-invalid"),
            (
                json!({"allow_origins": ["*"], "allow_credentials": true}),
                "cors-star-with-credentials",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "allow_credentials": "yes"}),
                "cors-allow-credentials-invalid",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "allow_methods": ["POST"]}),
                "cors-allow-methods-invalid",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "allow_methods": []}),
                "cors-allow-methods-invalid",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "allow_headers": ["bad header"]}),
                "cors-allow-headers-invalid",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "allow_headers": ["*"], "allow_credentials": true}),
                "cors-allow-headers-invalid",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "expose_headers": {"a": 1}}),
                "cors-expose-headers-invalid",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "max_age": 86_401}),
                "cors-max-age-invalid",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "max_age": 1.5}),
                "cors-max-age-invalid",
            ),
            (
                json!({"allow_origins": ["https://a.com"], "max_age": -1}),
                "cors-max-age-invalid",
            ),
        ];
        for (cors, class) in cases {
            let s = json!({"rules": [{"x": 1}], "cors": cors.clone()});
            let (out, problem, _) = run(&s);
            assert_eq!(problem, Some(class), "{cors}");
            assert_eq!(out, json!({"rules": [{"x": 1}]}), "{cors}");
        }
        for o in [
            "https://A.com",
            "https://a.com/",
            "https://a.com/x",
            "ftp://a.com",
            "a.com",
            "https://a.com:443",
            "http://a.com:80",
            "https://a.com:0",
            "https://a.com:65536",
            "https://a.com:08",
            "null",
            "https://*.com",
            "https://*.*.b.com",
            "https://a.*.com",
            "https://-a.com",
            "https://a_b.com",
            "https://a..com",
            "https://a.com?x",
            "https://user@a.com",
            "https://a.com:",
        ] {
            assert!(!is_valid_origin(o), "{o}");
            let (_, problem, _) = run(&json!({"cors": {"allow_origins": ["https://ok.com", o]}}));
            assert_eq!(problem, Some("cors-allow-origins-invalid"), "{o}");
        }
    }
}
