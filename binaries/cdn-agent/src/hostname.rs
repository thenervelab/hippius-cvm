//! Hostname validation and certificate name matching.
//!
//! Hostnames reach the agent from the backend feed and end up as keys in
//! OpenResty's certificate store, so they are checked here rather than
//! trusted: lower-case LDH labels, at most 253 bytes, at least two
//! labels, and an optional single leading `*.` wildcard label.

/// Whether `h` is an acceptable hostname (see module docs).
pub fn is_valid_hostname(h: &str) -> bool {
    let name = h.strip_prefix("*.").unwrap_or(h);
    if name.is_empty() || h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| is_valid_label(l))
}

fn is_valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether a certificate name (`san`, from a dNSName SAN) covers the
/// hostname `host` (itself possibly a wildcard), per RFC 6125: a
/// wildcard SAN matches exactly one left-most label; a wildcard host is
/// covered only by the identical wildcard SAN.
pub fn san_covers(san: &str, host: &str) -> bool {
    let san = san.to_ascii_lowercase();
    if san == host {
        return true;
    }
    if host.starts_with("*.") {
        return false;
    }
    match (san.strip_prefix("*."), host.split_once('.')) {
        (Some(san_rest), Some((first, host_rest))) => !first.is_empty() && san_rest == host_rest,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_and_wildcard_names() {
        assert!(is_valid_hostname("cdn.example.com"));
        assert!(is_valid_hostname("*.cdn.hippius.com"));
        assert!(is_valid_hostname("a1-b.example.co"));
    }

    #[test]
    fn rejects_bad_names() {
        for bad in [
            "",
            "localhost",
            "UPPER.example.com",
            "-a.example.com",
            "a..example.com",
            "*.*.example.com",
            "a*.example.com",
            "exa mple.com",
            "example.com.",
            "*.com.",
        ] {
            assert!(!is_valid_hostname(bad), "{bad}");
        }
        let long = format!("{}.com", "a".repeat(64));
        assert!(!is_valid_hostname(&long));
    }

    #[test]
    fn san_matching_follows_rfc6125() {
        assert!(san_covers("www.example.com", "www.example.com"));
        assert!(san_covers("*.example.com", "www.example.com"));
        assert!(!san_covers("*.example.com", "a.b.example.com"));
        assert!(!san_covers("*.example.com", "example.com"));
        assert!(san_covers("*.example.com", "*.example.com"));
        assert!(!san_covers("www.example.com", "*.example.com"));
        assert!(san_covers("WWW.Example.com", "www.example.com"));
    }
}
