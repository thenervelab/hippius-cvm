//! Host-wide guest network policy — the `net-policy` order
//! (`docs/design/egress-and-bandwidth.md` §7).
//!
//! This module checks an order's shape, computes its content hash,
//! persists it with monotonic replay refusal ([`store`]), renders the
//! local-mode nft rules ([`render`]), keeps them loaded ([`apply`]) and
//! sets the per-VM caps on the guests' NICs ([`caps`]). Edge-mode rules
//! come in a later change. With no persisted policy nothing is
//! installed.
//!
//! ## Content hash
//!
//! `content_sha256` is SHA-256 over the deterministic CBOR (RFC 8949
//! §4.2.1) of the order payload map **without** `not_after_unix`. vali
//! re-sends the same revision with a later expiry, which must not count
//! as other content. The ticket-validator `net-policy-digest` subcommand
//! computes the same value from vali's JSON, and the order response
//! `applied:<revision>:<content_sha256 hex>` echoes it back as the ack.

pub mod apply;
pub mod caps;
pub mod render;
pub mod snapshot;
pub mod store;

use std::net::Ipv4Addr;

use ciborium::value::Value;
use sha2::{Digest, Sha256};

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::VmId;
use crate::orders::types::{NetEndpoint, NetPolicyOrder};

pub use apply::{
    GuestTaps, LibvirtGuestTaps, MockNft, NetPolicyEnforcer, NftCommand, NftRunner,
    DRIFT_CHECK_INTERVAL, RULESET_FILE,
};
pub use caps::{IfaceTuner, Rate, VirshTuner, VmCaps};
pub use render::{SmtpTap, BRIDGE_TABLE, INET_TABLE};
pub use store::{AppliedNetPolicy, NetPolicyStore, DEFAULT_NET_POLICY_DIR};

/// Longest validity window an order may claim. vali re-signs about every
/// 10 minutes with a 24 h window; a week is room for skew, not a lease.
pub const MAX_NET_POLICY_TTL_SECS: u64 = 7 * 24 * 3600;

/// Cap on every list and on `vm_caps`. The 64 KiB order body bounds the
/// total anyway; this keeps the rule set a later change renders bounded.
pub const MAX_NET_POLICY_ENTRIES: usize = 1024;

/// Highest per-VM cap accepted, Mbit/s.
pub const MAX_VM_CAP_MBPS: u32 = 100_000;

/// Highest per-tap DNS budget accepted, packets per second.
pub const MAX_DNS_LIMIT_PPS: u32 = 10_000;

/// `IFNAMSIZ - 1`.
const MAX_IFNAME_LEN: usize = 15;

/// Interfaces that are never the uplink: loopback, the guest bridge and
/// taps, and the NetBird overlay. Naming one would turn the "only out of
/// the uplink" rule into an allow for the path it closes.
const NOT_AN_UPLINK_PREFIXES: [&str; 5] = ["lo", "virbr", "vnet", "hvt", "wt"];

/// Check every field of `order` against `now` (Unix seconds).
///
/// Every string that a later change renders into a ruleset is held to a
/// strict charset here, and every IP to its canonical dotted-quad form,
/// so the hash and the rendering see one spelling. Allowed destinations
/// must be public unicast addresses, and `nb_control` (metered) must not
/// overlap `infra` or `region_miners` (not metered).
pub fn validate(order: &NetPolicyOrder, now: u64) -> Result<()> {
    let invalid = MinerAgentError::NetPolicyInvalid;
    if order.revision == 0 {
        return Err(invalid("revision"));
    }
    if now > order.not_after_unix {
        return Err(MinerAgentError::NetPolicyExpired);
    }
    if order.not_after_unix - now > MAX_NET_POLICY_TTL_SECS {
        return Err(invalid("not-after"));
    }
    // ISO 3166-1 alpha-2, upper case: vali's region key.
    if order.region.len() != 2 || !order.region.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(invalid("region"));
    }
    if let Some(ifname) = &order.uplink_hint {
        if !is_uplink_name(ifname) {
            return Err(invalid("uplink-hint"));
        }
    }
    check_endpoints(&order.infra, "infra")?;
    check_endpoints(&order.nb_control, "nb-control")?;
    if order.region_miners.len() > MAX_NET_POLICY_ENTRIES {
        return Err(invalid("region-miners"));
    }
    if !order.region_miners.iter().all(|ip| is_public_ipv4(ip)) {
        return Err(invalid("ip"));
    }
    let unmetered: std::collections::HashSet<&str> = order
        .infra
        .iter()
        .map(|ep| ep.ip.as_str())
        .chain(order.region_miners.iter().map(String::as_str))
        .collect();
    if order
        .nb_control
        .iter()
        .any(|ep| unmetered.contains(ep.ip.as_str()))
    {
        return Err(invalid("nb-control-overlap"));
    }
    if !(1..=MAX_DNS_LIMIT_PPS).contains(&order.dns_limit_pps) {
        return Err(invalid("dns-limit-pps"));
    }
    if order.smtp_allowed_vms.len() > MAX_NET_POLICY_ENTRIES {
        return Err(invalid("smtp-allowed-vms"));
    }
    if order.vm_caps.len() > MAX_NET_POLICY_ENTRIES {
        return Err(invalid("vm-caps"));
    }
    for (vm_id, mbps) in &order.vm_caps {
        if VmId::new(vm_id).is_err() || !(1..=MAX_VM_CAP_MBPS).contains(mbps) {
            return Err(invalid("vm-caps"));
        }
    }
    Ok(())
}

/// An interface name safe to render into a ruleset (`IFNAMSIZ`, a
/// strict charset, no leading `-`).
pub(crate) fn is_ifname(name: &str) -> bool {
    (1..=MAX_IFNAME_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name.bytes().any(|b| b.is_ascii_alphanumeric())
        && !name.starts_with('-')
}

/// [`is_ifname`], and not one of the interfaces that are never the
/// uplink. Holds for `uplink_hint` and for the default-route interface.
pub(crate) fn is_uplink_name(name: &str) -> bool {
    is_ifname(name) && !NOT_AN_UPLINK_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn check_endpoints(endpoints: &[NetEndpoint], field: &'static str) -> Result<()> {
    if endpoints.len() > MAX_NET_POLICY_ENTRIES {
        return Err(MinerAgentError::NetPolicyInvalid(field));
    }
    for ep in endpoints {
        if !is_public_ipv4(&ep.ip) {
            return Err(MinerAgentError::NetPolicyInvalid("ip"));
        }
        if ep.port == 0 {
            return Err(MinerAgentError::NetPolicyInvalid("port"));
        }
    }
    Ok(())
}

/// Canonical dotted-quad spelling of a public unicast IPv4 address: not
/// `0/8`, private, shared (`100.64/10`, the NetBird overlay), loopback,
/// link-local, IETF protocol assignments (`192.0.0/24`), 6to4 relay
/// anycast (`192.88.99/24`), documentation, benchmarking (`198.18/15`),
/// multicast, reserved or broadcast.
fn is_public_ipv4(text: &str) -> bool {
    let Ok(ip) = text.parse::<Ipv4Addr>() else {
        return false;
    };
    let [a, b, c, _] = ip.octets();
    ip.to_string() == text
        && a != 0
        && a < 224
        && !(a == 100 && (64..128).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 192 && b == 88 && c == 99)
        && !(a == 198 && (b == 18 || b == 19))
        && !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_documentation()
}

/// The order's content hash (see the module docs).
pub fn content_sha256(order: &NetPolicyOrder) -> Result<[u8; 32]> {
    let encode = || MinerAgentError::NetPolicyStore("encode");
    let Value::Map(entries) = Value::serialized(order).map_err(|_| encode())? else {
        return Err(encode());
    };
    let content = Value::Map(
        entries
            .into_iter()
            .filter(|(key, _)| key.as_text() != Some("not_after_unix"))
            .collect(),
    );
    let bytes = hippius_types::cbor::to_canonical_vec(&content).map_err(|_| encode())?;
    Ok(Sha256::digest(bytes).into())
}

/// [`content_sha256`] as lower-case hex.
pub fn content_sha256_hex(order: &NetPolicyOrder) -> Result<String> {
    content_sha256(order).map(hex::encode)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::orders::types::{NetPolicyLocalAction, NetPolicyMode, NetProto};

    pub(crate) const NOW: u64 = 1_770_000_000;

    pub(crate) fn policy(revision: u64) -> NetPolicyOrder {
        NetPolicyOrder {
            revision,
            not_after_unix: NOW + 86_400,
            region: "FR".to_string(),
            mode: NetPolicyMode::Local,
            enforce: false,
            local_action: NetPolicyLocalAction::Count,
            uplink_hint: None,
            infra: vec![NetEndpoint {
                ip: "1.1.1.1".to_string(),
                proto: NetProto::Udp,
                port: 51820,
            }],
            region_miners: vec!["8.8.4.4".to_string()],
            nb_control: Vec::new(),
            dns_limit_pps: 20,
            smtp_allowed_vms: Vec::new(),
            vm_caps: [("tenant-1".to_string(), 100)].into_iter().collect(),
        }
    }

    #[test]
    fn a_well_formed_policy_validates() {
        validate(&policy(1), NOW).unwrap();
        let mut p = policy(1);
        p.uplink_hint = Some("enp1s0f0".to_string());
        p.nb_control = vec![NetEndpoint {
            ip: "100.128.0.1".to_string(),
            proto: NetProto::Udp,
            port: 3478,
        }];
        validate(&p, NOW).unwrap();
    }

    #[test]
    fn each_bad_field_is_refused_with_its_class() {
        let refused = |mutate: &dyn Fn(&mut NetPolicyOrder)| {
            let mut p = policy(1);
            mutate(&mut p);
            validate(&p, NOW).unwrap_err().to_string()
        };
        assert_eq!(refused(&|p| p.revision = 0), "net-policy-invalid/revision");
        assert_eq!(
            refused(&|p| p.not_after_unix = NOW - 1),
            "net-policy-expired"
        );
        assert_eq!(
            refused(&|p| p.not_after_unix = NOW + MAX_NET_POLICY_TTL_SECS + 1),
            "net-policy-invalid/not-after"
        );
        for region in ["fr", "FRA", "", "F1"] {
            assert_eq!(
                refused(&|p| p.region = region.into()),
                "net-policy-invalid/region",
                "{region:?}"
            );
        }
        for hint in [
            "",
            "eth0;drop",
            "a-very-long-ifname",
            "-x",
            "eth 0",
            ".",
            "..",
            "lo",
            "wt0",
            "virbr0",
            "vnet3",
            "hvt12",
        ] {
            assert_eq!(
                refused(&|p| p.uplink_hint = Some(hint.into())),
                "net-policy-invalid/uplink-hint",
                "{hint:?}"
            );
        }
        // Non-canonical spellings would hash and render differently, and
        // only public unicast destinations may be allowed.
        for ip in [
            "010.0.0.1",
            "1.2.3",
            "::1",
            "1.2.3.4 ",
            "1.2.3.4/32",
            "0.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.122.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.169.254",
            "192.0.0.8",
            "192.88.99.2",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert_eq!(
                refused(&|p| p.region_miners = vec![ip.into()]),
                "net-policy-invalid/ip",
                "{ip:?}"
            );
            assert_eq!(
                refused(&|p| p.infra[0].ip = ip.into()),
                "net-policy-invalid/ip",
                "{ip:?}"
            );
        }
        assert_eq!(refused(&|p| p.infra[0].port = 0), "net-policy-invalid/port");
        for overlap in ["1.1.1.1", "8.8.4.4"] {
            assert_eq!(
                refused(&|p| {
                    p.nb_control = vec![NetEndpoint {
                        ip: overlap.into(),
                        proto: NetProto::Tcp,
                        port: 443,
                    }]
                }),
                "net-policy-invalid/nb-control-overlap"
            );
        }
        assert_eq!(
            refused(&|p| p.dns_limit_pps = 0),
            "net-policy-invalid/dns-limit-pps"
        );
        assert_eq!(
            refused(&|p| {
                p.vm_caps.insert("Bad_Id".into(), 100);
            }),
            "net-policy-invalid/vm-caps"
        );
        assert_eq!(
            refused(&|p| {
                p.vm_caps.insert("tenant-2".into(), 0);
            }),
            "net-policy-invalid/vm-caps"
        );
        assert_eq!(
            refused(&|p| p.region_miners = vec!["8.8.8.8".into(); MAX_NET_POLICY_ENTRIES + 1]),
            "net-policy-invalid/region-miners"
        );
    }

    #[test]
    fn the_content_hash_ignores_only_the_expiry() {
        let base = content_sha256(&policy(1)).unwrap();
        let mut renewed = policy(1);
        renewed.not_after_unix += 600;
        assert_eq!(content_sha256(&renewed).unwrap(), base);

        let mut other = policy(1);
        other.enforce = true;
        assert_ne!(content_sha256(&other).unwrap(), base);
        assert_ne!(content_sha256(&policy(2)).unwrap(), base);
        let mut hinted = policy(1);
        hinted.uplink_hint = Some("eth0".into());
        assert_ne!(content_sha256(&hinted).unwrap(), base);
    }
}
