//! The nft ruleset of a local-mode policy (`docs/design/egress-and-bandwidth.md`
//! §6.2), rendered as text for one `nft -f` transaction. Pure: the
//! caller resolves the uplink and the exempt taps.
//!
//! Two tables, both owned by the agent and replaced whole on every load.
//! Each is created empty, deleted and redefined in the same transaction,
//! so a load works whether or not the table exists and never touches
//! another table (libvirt's, NetBird's, UFW's).
//!
//! - `inet hippius_guest` sees routed traffic. `forward` drops IPv6 from
//!   the guest bridge and anything routed from it to an interface other
//!   than the uplink (the host's `wt0`, docker or other bridges). `input`
//!   lets guests reach the host only for DHCP and DNS on the bridge
//!   address; host sshd and the agent's `:9700` on `wt0` are dropped.
//! - `bridge hippius_guest_br` sees each frame on its tap (§6.1 without
//!   the mark: a bridge-family chain matches the tap as `iifname`). It
//!   drops outbound TCP 25 except from exempt `(tap, MAC)` pairs, and
//!   meters DNS to the bridge address per tap.
//!
//! Every base chain has policy accept and only drops, so the order
//! against other tables' chains does not matter: a drop in any base
//! chain is final, and an accept here is not. With `local_action =
//! count` the same rules only count.
//!
//! An exemption is keyed on the tap and the MAC libvirt gave the VM's
//! NIC: tap names are reused after a VM stops, and the MAC keeps the
//! next VM on that tap from inheriting the exemption until the next
//! re-render.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::error::{MinerAgentError, Result};
use crate::orders::types::{NetPolicyLocalAction, NetPolicyMode, NetPolicyOrder};

/// The agent's routed-traffic table, `inet` family.
pub const INET_TABLE: &str = "hippius_guest";
/// The agent's per-tap table, `bridge` family.
pub const BRIDGE_TABLE: &str = "hippius_guest_br";
/// The libvirt `default` network's bridge (`networking-bridge.yml`).
pub const GUEST_BRIDGE: &str = "virbr0";
/// The bridge's own address: guests' gateway, DHCP server and resolver.
pub const GUEST_BRIDGE_ADDR: &str = "192.168.122.1";
/// Tenant tap name patterns: libvirt's automatic `vnetN` and the
/// deterministic `hvt<cid>`.
pub const GUEST_TAP_PATTERNS: [&str; 2] = ["vnet*", "hvt*"];
/// The bridge table's set of exempt `(tap, MAC)` pairs.
pub const SMTP_SET: &str = "smtp_allowed";
/// Per-tap DNS byte budget, KB/s (§6.2).
pub const DNS_LIMIT_KBYTES: u32 = 16;

/// A tap whose VM may send TCP 25, with the MAC of the VM's NIC.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SmtpTap {
    ifname: String,
    mac: String,
}

impl SmtpTap {
    /// Check `ifname` (a tenant tap name) and `mac` (lower-case
    /// colon-separated hex, as libvirt writes it).
    pub fn new(ifname: &str, mac: &str) -> Result<Self> {
        let tap_ok = super::is_ifname(ifname)
            && GUEST_TAP_PATTERNS
                .iter()
                .any(|p| ifname.starts_with(p.trim_end_matches('*')));
        let mac_ok = mac.len() == 17
            && mac.bytes().enumerate().all(|(i, b)| {
                if i % 3 == 2 {
                    b == b':'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            });
        if !tap_ok || !mac_ok {
            return Err(MinerAgentError::NetPolicyApply("tap"));
        }
        Ok(Self {
            ifname: ifname.to_string(),
            mac: mac.to_string(),
        })
    }
}

/// Refuse what this agent cannot render, before the order is persisted.
pub fn check_supported(order: &NetPolicyOrder) -> Result<()> {
    match order.mode {
        NetPolicyMode::Local => Ok(()),
        NetPolicyMode::Edge => Err(MinerAgentError::NetPolicyUnsupported("edge-mode")),
    }
}

/// The ruleset for `order` (persisted with `content_sha256`), with
/// `uplink` the interface guests may be routed to and `smtp_taps` the
/// exempt taps that exist right now. `order.enforce` and the edge-mode
/// lists are not used in local mode.
pub fn render(
    order: &NetPolicyOrder,
    content_sha256: &str,
    uplink: &str,
    smtp_taps: &[SmtpTap],
) -> Result<String> {
    check_supported(order)?;
    if !super::is_uplink_name(uplink) {
        return Err(MinerAgentError::NetPolicyApply("uplink"));
    }
    if content_sha256.len() != 64 || !content_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(MinerAgentError::NetPolicyStore("parse"));
    }
    let verdict = match order.local_action {
        NetPolicyLocalAction::Count => "",
        NetPolicyLocalAction::Drop => " drop",
    };
    let action = match order.local_action {
        NetPolicyLocalAction::Count => "count",
        NetPolicyLocalAction::Drop => "drop",
    };
    let taps: BTreeSet<&SmtpTap> = smtp_taps.iter().collect();
    let br = GUEST_BRIDGE;
    let addr = GUEST_BRIDGE_ADDR;
    let pps = order.dns_limit_pps;

    let mut out = String::new();
    // `fmt::Write` for a `String` never fails.
    let mut line = |text: String| {
        let _ = writeln!(out, "{text}");
    };
    line(format!(
        "# hippius-miner-agent net policy: revision {}, local mode, {action}.",
        order.revision
    ));
    line(format!(
        "# content sha256 {content_sha256}. Generated, do not edit."
    ));
    line(format!("table inet {INET_TABLE}"));
    line(format!("delete table inet {INET_TABLE}"));
    line(format!("table inet {INET_TABLE} {{"));
    line("\tchain forward {".into());
    line("\t\ttype filter hook forward priority filter - 10; policy accept;".into());
    line(format!(
        "\t\tiifname \"{br}\" meta nfproto ipv6 counter{verdict} comment \"guest-ipv6\""
    ));
    line(format!(
        "\t\tiifname \"{br}\" oifname != {{ \"{uplink}\", \"{br}\" }} counter{verdict} comment \"guest-not-uplink\""
    ));
    line("\t}".into());
    line("\tchain input {".into());
    line("\t\ttype filter hook input priority filter - 10; policy accept;".into());
    line(format!("\t\tiifname != \"{br}\" accept"));
    line("\t\tct direction reply accept".into());
    line(format!(
        "\t\tmeta nfproto ipv6 counter{verdict} comment \"guest-host-ipv6\""
    ));
    line("\t\tudp dport 67 accept comment \"guest-dhcp\"".into());
    line(format!(
        "\t\tip daddr {addr} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"guest-dns\""
    ));
    line(format!("\t\tcounter{verdict} comment \"guest-host\""));
    line("\t}".into());
    line("}".into());
    line(format!("table bridge {BRIDGE_TABLE}"));
    line(format!("delete table bridge {BRIDGE_TABLE}"));
    line(format!("table bridge {BRIDGE_TABLE} {{"));
    line(format!("\tset {SMTP_SET} {{"));
    line("\t\ttype ifname . ether_addr".into());
    if !taps.is_empty() {
        let elements: Vec<String> = taps
            .iter()
            .map(|t| format!("\"{}\" . {}", t.ifname, t.mac))
            .collect();
        line(format!("\t\telements = {{ {} }}", elements.join(", ")));
    }
    line("\t}".into());
    for meter in ["dns_pps", "dns_bytes"] {
        line(format!("\tset {meter} {{"));
        line("\t\ttype ifname".into());
        line("\t\tsize 4096".into());
        line("\t\tflags dynamic,timeout".into());
        line("\t\ttimeout 1m".into());
        line("\t}".into());
    }
    line("\tchain prerouting {".into());
    line("\t\ttype filter hook prerouting priority filter - 10; policy accept;".into());
    for pattern in GUEST_TAP_PATTERNS {
        line(format!("\t\tiifname \"{pattern}\" jump guest"));
    }
    line("\t}".into());
    line("\tchain guest {".into());
    line(format!(
        "\t\tmeta l4proto tcp th dport 25 iifname . ether saddr != @{SMTP_SET} counter{verdict} comment \"guest-smtp\""
    ));
    line(format!(
        "\t\tip daddr {addr} meta l4proto {{ tcp, udp }} th dport 53 update @dns_pps {{ iifname limit rate over {pps}/second }} counter{verdict} comment \"guest-dns-pps\""
    ));
    line(format!(
        "\t\tip daddr {addr} meta l4proto {{ tcp, udp }} th dport 53 update @dns_bytes {{ iifname limit rate over {DNS_LIMIT_KBYTES} kbytes/second }} counter{verdict} comment \"guest-dns-bytes\""
    ));
    line("\t}".into());
    line("}".into());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netpolicy::tests::policy;

    const SHA: &str = "3b4668ab7a5a55b7e53a78e8fcbca74431bc2947354643f1e0100c83f01d14ec";

    /// Compare with `tests/data/netpolicy/<name>.nft`, which CI also
    /// loads with `nft -c`. `NETPOLICY_UPDATE_GOLDEN=1` rewrites it.
    fn assert_golden(name: &str, actual: &str) {
        let path = format!(
            "{}/tests/data/netpolicy/{name}.nft",
            env!("CARGO_MANIFEST_DIR")
        );
        if std::env::var_os("NETPOLICY_UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, actual).unwrap();
        }
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(actual, expected, "{path}");
    }

    #[test]
    fn count_mode_matches_its_golden() {
        let p = policy(7);
        assert_golden("local-count", &render(&p, SHA, "eth0", &[]).unwrap());
    }

    #[test]
    fn drop_mode_with_exemptions_matches_its_golden() {
        let mut p = policy(8);
        p.local_action = NetPolicyLocalAction::Drop;
        let taps = [
            SmtpTap::new("vnet7", "52:54:00:aa:bb:07").unwrap(),
            SmtpTap::new("hvt12", "52:54:00:aa:bb:0c").unwrap(),
        ];
        assert_golden(
            "local-drop-smtp",
            &render(&p, SHA, "enp1s0f0", &taps).unwrap(),
        );
    }

    #[test]
    fn exemption_order_and_duplicates_do_not_change_the_text() {
        let a = SmtpTap::new("vnet1", "52:54:00:00:00:01").unwrap();
        let b = SmtpTap::new("vnet2", "52:54:00:00:00:02").unwrap();
        let p = policy(1);
        assert_eq!(
            render(&p, SHA, "eth0", &[a.clone(), b.clone()]).unwrap(),
            render(&p, SHA, "eth0", &[b, a.clone(), a]).unwrap()
        );
    }

    #[test]
    fn count_mode_drops_nothing_and_drop_mode_drops_every_rule() {
        let count = render(&policy(1), SHA, "eth0", &[]).unwrap();
        assert!(!count.contains(" drop"), "{count}");
        let mut p = policy(1);
        p.local_action = NetPolicyLocalAction::Drop;
        let dropping = render(&p, SHA, "eth0", &[]).unwrap();
        assert_eq!(dropping.matches("counter drop").count(), 7, "{dropping}");
        assert_eq!(count.matches("counter").count(), 7);
    }

    #[test]
    fn edge_mode_is_refused() {
        let mut p = policy(1);
        p.mode = NetPolicyMode::Edge;
        assert_eq!(
            check_supported(&p).unwrap_err().to_string(),
            "net-policy-unsupported/edge-mode"
        );
        assert_eq!(
            render(&p, SHA, "eth0", &[]).unwrap_err().to_string(),
            "net-policy-unsupported/edge-mode"
        );
    }

    #[test]
    fn unsafe_inputs_are_refused() {
        let p = policy(1);
        for uplink in ["", "wt0", "virbr0", "vnet0", "lo", "eth0\"", "a b"] {
            assert_eq!(
                render(&p, SHA, uplink, &[]).unwrap_err().to_string(),
                "net-policy-apply/uplink",
                "{uplink:?}"
            );
        }
        assert!(render(&p, "zz", "eth0", &[]).is_err());
        for (tap, mac) in [
            ("eth0", "52:54:00:00:00:01"),
            ("vnet1\"", "52:54:00:00:00:01"),
            ("vnet1", "52:54:00:00:00:0G"),
            ("vnet1", "52:54:00:00:00:0A"),
            ("vnet1", "52-54-00-00-00-01"),
            ("vnet1", "52:54:00:00:00:01 "),
        ] {
            assert_eq!(
                SmtpTap::new(tap, mac).unwrap_err().to_string(),
                "net-policy-apply/tap",
                "{tap:?} {mac:?}"
            );
        }
    }

    #[test]
    fn the_dns_budget_comes_from_the_policy() {
        let mut p = policy(1);
        p.dns_limit_pps = 50;
        let text = render(&p, SHA, "eth0", &[]).unwrap();
        assert!(text.contains("limit rate over 50/second"), "{text}");
    }
}
