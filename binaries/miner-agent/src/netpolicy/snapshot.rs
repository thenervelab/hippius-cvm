//! The drift compare's view of the loaded tables: what `nft list`
//! prints, minus what changes without anyone editing our rules.
//!
//! [`normalise`] is applied to the reading taken right after a load and
//! to every later one, so only a real edit tells them apart. It removes:
//!
//! - **NetBird's injected accepts.** NetBird inserts allow rules for its
//!   overlay into every foreign `input` / `forward` base chain on the
//!   host, ours included, and inserts them again after each reload. Only
//!   the two forms it is known to add are ignored (see
//!   [`is_netbird_accept`]); any other foreign rule is drift and is
//!   removed by the reload.
//! - **Dynamic meter state.** The DNS meters' `elements` and the
//!   `# count N` comment change with guest traffic.
//! - **Element order.** An anonymous set (`{ "a", "b" }`) may be printed
//!   in another order than it was written; its elements are sorted.
//!
//! ## Why NetBird's accepts may stay (instead of moving hooks)
//!
//! The edge agent moved its filtering to `prerouting` so NetBird would
//! leave it alone. The guest rules cannot: they decide on the output
//! interface (`oifname != <uplink>`), which `prerouting` does not know
//! yet, and on packets addressed to the host, which only `input` sees.
//! The two accepts cannot let a guest past those rules, wherever in the
//! chain NetBird puts them:
//!
//! - `iifname "wt0" accept` only matches packets that came in on the
//!   overlay. Every guest rule matches `iifname "virbr0"`, and `input`
//!   already accepts anything not from `virbr0` first.
//! - `oifname "wt0" ct state established,related accept` matches a guest
//!   packet towards the overlay only on a flow already in conntrack. A
//!   guest's new connection to the overlay is dropped in `forward`, so
//!   its entry is never confirmed. A flow opened from the overlay to a
//!   guest is refused by libvirt's NAT rules. Entries left from `count`
//!   mode are flushed when a stricter policy loads
//!   (`conntrack -D -s 192.168.122.0/24`).

/// `text` as the drift compare sees it (see the module docs).
pub fn normalise(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    // The `set … {` block being read, kept whole until its `}` so a
    // dynamic set's elements can be dropped.
    let mut set_block: Option<Vec<String>> = None;
    for raw in text.lines() {
        let line = strip_count_comment(raw.trim_end());
        if let Some(block) = set_block.as_mut() {
            block.push(line.to_string());
            if line.trim() == "}" && braces_balanced(block) {
                let block = set_block.take().unwrap_or_default();
                out.extend(normalise_set(block));
            }
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("set ") && trimmed.ends_with('{') {
            set_block = Some(vec![line.to_string()]);
            continue;
        }
        if is_netbird_accept(trimmed) {
            continue;
        }
        out.push(sort_anonymous_sets(line));
    }
    // An unterminated block (a truncated listing) is kept as read.
    if let Some(block) = set_block {
        out.extend(block);
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

/// Whether `rule` is one of the allow rules NetBird inserts into
/// foreign base chains: `iifname "wt<N>" accept`, or `oifname "wt<N>" ct
/// state established,related accept`, each with or without a counter.
pub fn is_netbird_accept(rule: &str) -> bool {
    let tokens: Vec<&str> = without_counter(rule);
    match tokens.as_slice() {
        ["iifname", ifname, "accept"] => is_overlay(ifname),
        ["oifname", ifname, "ct", "state", states, "accept"] => {
            is_overlay(ifname) && matches!(*states, "established,related" | "related,established")
        }
        _ => false,
    }
}

/// `rule`'s tokens without `counter` and its `packets N bytes M`.
fn without_counter(rule: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut tokens = rule.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if token == "counter" {
            if tokens.peek() == Some(&"packets") {
                // packets N bytes M
                for _ in 0..4 {
                    tokens.next();
                }
            }
            continue;
        }
        out.push(token);
    }
    out
}

/// `"wt<digits>"`, NetBird's interface.
fn is_overlay(quoted: &str) -> bool {
    quoted
        .strip_prefix("\"wt")
        .and_then(|rest| rest.strip_suffix('"'))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// `line` without a trailing `# count N` (a dynamic set's fill).
fn strip_count_comment(line: &str) -> &str {
    match line.rfind("# count ") {
        Some(at)
            if line[at + "# count ".len()..]
                .bytes()
                .all(|b| b.is_ascii_digit()) =>
        {
            line[..at].trim_end()
        }
        _ => line,
    }
}

fn braces_balanced(block: &[String]) -> bool {
    let (open, close) = block.iter().fold((0usize, 0usize), |(o, c), l| {
        (o + l.matches('{').count(), c + l.matches('}').count())
    });
    open == close
}

/// A whole `set` block: a dynamic set loses its `elements`; any other
/// keeps them, sorted.
fn normalise_set(block: Vec<String>) -> Vec<String> {
    let dynamic = block
        .iter()
        .any(|l| l.trim_start().starts_with("flags ") && l.contains("dynamic"));
    let mut out = Vec::new();
    let mut in_elements = false;
    let mut depth = 0i64;
    for line in block {
        if !in_elements && line.trim_start().starts_with("elements = {") {
            in_elements = true;
            depth = 0;
        }
        if in_elements {
            depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
            if !dynamic {
                out.push(sort_anonymous_sets(&line));
            }
            if depth <= 0 {
                in_elements = false;
            }
            continue;
        }
        out.push(line);
    }
    out
}

/// Sort the elements of every one-line `{ a, b, … }` in `line`.
fn sort_anonymous_sets(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(open) = rest.find("{ ") {
        let after = &rest[open + 2..];
        let Some(close) = after.find(" }") else {
            break;
        };
        let inner = &after[..close];
        out.push_str(&rest[..open + 2]);
        if inner.contains('{') || !inner.contains(", ") {
            out.push_str(inner);
        } else {
            let mut items: Vec<&str> = inner.split(", ").collect();
            items.sort_unstable();
            out.push_str(&items.join(", "));
        }
        out.push_str(" }");
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `nft list table inet hippius_guest` on a live host after NetBird
    /// re-injected its accepts (counters as `nft -s` prints them).
    pub(crate) const LIVE_INET: &str = "\
table inet hippius_guest {
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		oifname \"wt0\" ct state established,related counter accept
		iifname \"wt0\" counter accept
		iifname \"virbr0\" meta nfproto ipv6 counter comment \"guest-ipv6\"
		iifname \"virbr0\" oifname != { \"virbr0\", \"bond_public\" } counter comment \"guest-not-uplink\"
	}
	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname \"wt0\" counter accept
		iifname != \"virbr0\" accept
		ct direction reply accept
		meta nfproto ipv6 counter comment \"guest-host-ipv6\"
		udp dport 67 accept comment \"guest-dhcp\"
		ip daddr 192.168.122.1 meta l4proto { tcp, udp } th dport 53 accept comment \"guest-dns\"
		counter comment \"guest-host\"
	}
}
";

    /// The same table right after the agent loaded it.
    pub(crate) const LOADED_INET: &str = "\
table inet hippius_guest {
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname \"virbr0\" meta nfproto ipv6 counter comment \"guest-ipv6\"
		iifname \"virbr0\" oifname != { \"bond_public\", \"virbr0\" } counter comment \"guest-not-uplink\"
	}
	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname != \"virbr0\" accept
		ct direction reply accept
		meta nfproto ipv6 counter comment \"guest-host-ipv6\"
		udp dport 67 accept comment \"guest-dhcp\"
		ip daddr 192.168.122.1 meta l4proto { tcp, udp } th dport 53 accept comment \"guest-dns\"
		counter comment \"guest-host\"
	}
}
";

    pub(crate) const LOADED_METER: &str = "\
table bridge hippius_guest_br {
	set dns_pps {
		type ifname
		size 4096
		flags dynamic,timeout
		timeout 1m
	}
}
";

    /// The meter once a guest has asked for DNS.
    pub(crate) const LIVE_METER: &str = "\
table bridge hippius_guest_br {
	set dns_pps {
		type ifname
		size 4096 # count 1
		flags dynamic,timeout
		timeout 1m
		elements = { \"vnet33\" limit rate over 20/second timeout 1m expires 35s409ms }
	}
}
";

    #[test]
    fn the_live_tables_compare_equal_to_the_loaded_ones() {
        assert_eq!(normalise(LIVE_INET), normalise(LOADED_INET));
        assert_eq!(normalise(LIVE_METER), normalise(LOADED_METER));
    }

    #[test]
    fn a_real_edit_is_still_drift() {
        let loaded = normalise(LOADED_INET);
        // Our rule removed.
        assert_ne!(
            normalise(&LIVE_INET.replace("\t\tcounter comment \"guest-host\"\n", "")),
            loaded
        );
        // A foreign accept that is not NetBird's known form.
        assert_ne!(
            normalise(&LIVE_INET.replace(
                "iifname \"wt0\" counter accept",
                "oifname \"wt0\" counter accept"
            )),
            loaded
        );
        assert_ne!(
            normalise(&LIVE_INET.replace(
                "iifname \"wt0\" counter accept",
                "ip saddr 192.168.122.0/24 accept"
            )),
            loaded
        );
        // A different uplink.
        assert_ne!(normalise(&LIVE_INET.replace("bond_public", "eno1")), loaded);
    }

    #[test]
    fn a_static_sets_elements_count_and_are_order_free() {
        let set = |elements: &str| {
            format!(
                "table bridge t {{\n\tset smtp_allowed {{\n\t\ttype ifname . ether_addr\n\
                 \t\telements = {{ {elements} }}\n\t}}\n}}\n"
            )
        };
        let a = "\"vnet4\" . 52:54:00:12:34:56, \"hvt9\" . 52:54:00:12:34:57";
        let b = "\"hvt9\" . 52:54:00:12:34:57, \"vnet4\" . 52:54:00:12:34:56";
        assert_eq!(normalise(&set(a)), normalise(&set(b)));
        assert_ne!(
            normalise(&set(a)),
            normalise(&set("\"vnet4\" . 52:54:00:12:34:56"))
        );
    }

    #[test]
    fn netbird_forms() {
        for rule in [
            "iifname \"wt0\" accept",
            "iifname \"wt0\" counter accept",
            "iifname \"wt1\" counter packets 12 bytes 3456 accept",
            "oifname \"wt0\" ct state established,related counter accept",
            "oifname \"wt0\" ct state related,established accept",
        ] {
            assert!(is_netbird_accept(rule), "{rule}");
        }
        for rule in [
            "oifname \"wt0\" accept",
            "oifname \"wt0\" ct state new accept",
            "iifname \"virbr0\" accept",
            "iifname \"wtx\" accept",
            "iifname \"wt0\" drop",
            "iifname \"wt0\" accept comment \"guest-x\"",
        ] {
            assert!(!is_netbird_accept(rule), "{rule}");
        }
    }
}
