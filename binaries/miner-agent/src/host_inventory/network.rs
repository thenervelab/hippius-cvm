//! The `network` section: the physical NICs from `/sys/class/net`, the
//! NetBird interface, a count of everything virtual.
//!
//! Privacy (§18.10.3): no MAC address is read, and no address leaves this
//! module — an interface's IPv4 (`ip -o -4 addr show`) and IPv6
//! (`/proc/net/if_inet6`) addresses are read only to classify its role
//! ([`NicRole`]). Virtual interfaces (bridges, taps, `virbr*`, `vnet*`,
//! `veth*`, `docker*`) are counted, never named: a tap's name can carry a
//! VM id.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use hippius_host_inventory::{
    is_pci_address, Duplex, LinkState, NetbirdInterface, NetworkSection, Nic, NicRole,
    MAX_NAME_LEN, MAX_NICS, MAX_TEXT_LEN,
};

use super::pci::id16;
use super::{
    clean_text, dir_names, link_name, pci_ids, read_trimmed, CommandRunner, HostPaths, Source,
    Tally,
};

/// Names that are never a physical NIC, whatever sysfs links.
const VIRTUAL_PREFIXES: [&str; 14] = [
    "lo", "virbr", "vnet", "veth", "docker", "br-", "tap", "tun", "wt", "wg", "macvtap", "vxlan",
    "cni", "flannel",
];

/// The NetBird interface's default name.
const NETBIRD_NAME: &str = "wt0";

/// The names a NetBird interface goes by. An address in 100.64/10 alone
/// says nothing: Docker and libvirt bridges, Tailscale, an ISP's CGNAT
/// sit there too.
const NETBIRD_PREFIXES: [&str; 2] = ["wt", "netbird"];

/// How far the `master` / `upper_*` links are followed from a NIC
/// (port → bond → bridge → VLAN).
const MAX_LINK_DEPTH: usize = 4;

fn virtual_by_name(name: &str) -> bool {
    VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// `wt0`, or a non-physical `wt*` / `netbird*` interface holding a
/// 100.64/10 address.
fn is_netbird(name: &str, netbird_v4: &BTreeSet<String>) -> bool {
    name == NETBIRD_NAME
        || (netbird_v4.contains(name) && NETBIRD_PREFIXES.iter().any(|p| name.starts_with(p)))
}

/// The most telling class of `nic` and of every interface stacked on it —
/// its `master` (a bond, a bridge) and its `upper_*` links (a VLAN), then
/// theirs, at most [`MAX_LINK_DEPTH`] deep — so a port whose address sits
/// on `br0` / `bond0` / `eno1.100` takes that interface's role.
fn stacked_class(net: &std::path::Path, nic: &str, classes: &Classes) -> Option<AddrClass> {
    let mut seen = BTreeSet::from([nic.to_string()]);
    let mut level = vec![nic.to_string()];
    let mut best = classes.get(nic).copied();
    for _ in 0..MAX_LINK_DEPTH {
        let mut next = Vec::new();
        for name in &level {
            let dir = net.join(name);
            let uppers = dir_names(&dir)
                .into_iter()
                .filter_map(|n| n.strip_prefix("upper_").map(str::to_string));
            for up in link_name(&dir.join("master")).into_iter().chain(uppers) {
                if seen.insert(up.clone()) {
                    best = best.max(classes.get(&up).copied());
                    next.push(up);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        level = next;
    }
    best
}

/// What one address says about its interface, most telling last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AddrClass {
    Private,
    Netbird,
    Public,
}

/// 100.64.0.0/10.
fn is_netbird_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

fn classify_v4(a: Ipv4Addr) -> Option<AddrClass> {
    if a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_broadcast() {
        None
    } else if is_netbird_v4(a) {
        Some(AddrClass::Netbird)
    } else if a.is_private() || a.is_link_local() {
        Some(AddrClass::Private)
    } else {
        Some(AddrClass::Public)
    }
}

/// Global unicast (2000::/3) is public, ULA (fc00::/7) private. Link-local
/// (fe80::/10) is not counted: every interface with IPv6 on has one, so it
/// says nothing about its use.
fn classify_v6(a: Ipv6Addr) -> Option<AddrClass> {
    let first = a.segments()[0];
    if first & 0xE000 == 0x2000 {
        Some(AddrClass::Public)
    } else if first & 0xFE00 == 0xFC00 {
        Some(AddrClass::Private)
    } else {
        None
    }
}

/// Per interface, the most telling class of its addresses.
type Classes = BTreeMap<String, AddrClass>;

fn note(classes: &mut Classes, name: &str, class: Option<AddrClass>) {
    if let Some(c) = class {
        let e = classes.entry(name.to_string()).or_insert(c);
        *e = (*e).max(c);
    }
}

/// `ip -o -4 addr show`: `2: eno1    inet 192.0.2.7/24 brd … scope global eno1…`.
/// Also returns which interfaces hold a 100.64/10 address.
fn ipv4_classes(output: &str, classes: &mut Classes) -> BTreeSet<String> {
    let mut netbird = BTreeSet::new();
    for line in output.lines() {
        let mut tokens = line.split_ascii_whitespace();
        let Some(name) = tokens.nth(1) else { continue };
        let name = name.split('@').next().unwrap_or(name).trim_end_matches(':');
        let Some(addr) = tokens
            .skip_while(|t| *t != "inet")
            .nth(1)
            .and_then(|a| a.split('/').next())
            .and_then(|a| a.parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        if is_netbird_v4(addr) {
            netbird.insert(name.to_string());
        }
        note(classes, name, classify_v4(addr));
    }
    netbird
}

/// `/proc/net/if_inet6`: `<32 hex> <ifindex> <plen> <scope> <flags> <name>`.
fn ipv6_classes(content: &str, classes: &mut Classes) {
    for line in content.lines() {
        let t: Vec<&str> = line.split_ascii_whitespace().collect();
        let (Some(hex), Some(name)) = (t.first(), t.get(5)) else {
            continue;
        };
        let Some(addr) = (hex.len() == 32)
            .then(|| u128::from_str_radix(hex, 16).ok())
            .flatten()
        else {
            continue;
        };
        note(classes, name, classify_v6(Ipv6Addr::from(addr)));
    }
}

fn role(class: Option<AddrClass>) -> NicRole {
    match class {
        Some(AddrClass::Public) => NicRole::Public,
        Some(AddrClass::Netbird) => NicRole::Netbird,
        Some(AddrClass::Private) => NicRole::Private,
        None => NicRole::Unused,
    }
}

/// `operstate`, with `carrier` deciding for the `unknown` a tun device
/// (NetBird's `wt0`) always reports.
fn link_state(dir: &std::path::Path) -> LinkState {
    match read_trimmed(&dir.join("operstate")).as_deref() {
        Some("up") => LinkState::Up,
        Some("down" | "lowerlayerdown" | "notpresent") => LinkState::Down,
        _ => match read_trimmed(&dir.join("carrier")).as_deref() {
            Some("1") => LinkState::Up,
            Some("0") => LinkState::Down,
            _ => LinkState::Unknown,
        },
    }
}

fn duplex(s: Option<String>) -> Duplex {
    match s.as_deref() {
        Some("full") => Duplex::Full,
        Some("half") => Duplex::Half,
        _ => Duplex::Unknown,
    }
}

fn mtu(dir: &std::path::Path) -> u32 {
    read_trimmed(&dir.join("mtu"))
        .and_then(|m| m.parse().ok())
        .unwrap_or(0)
}

/// `ethtool -i`'s `firmware-version:` value.
fn firmware(output: &str) -> Option<String> {
    let v = output
        .lines()
        .find_map(|l| l.strip_prefix("firmware-version:"))?
        .trim();
    clean_text(v.as_bytes(), MAX_TEXT_LEN)
}

pub fn collect_network(paths: &HostPaths, runner: &dyn CommandRunner) -> NetworkSection {
    let mut tally = Tally::default();
    let net = paths.sys.join("class/net");
    tally.note(net.is_dir());

    let mut classes = Classes::new();
    let ip = runner.run("ip", &["-o", "-4", "addr", "show"]);
    let netbird_v4 = match &ip {
        Ok(out) => ipv4_classes(out, &mut classes),
        // Without `ip` the IPv4 roles are unknown.
        Err(_) => {
            tally.failed();
            BTreeSet::new()
        }
    };
    if let Some(v6) = tally.optional(Source::read(&paths.proc.join("net/if_inet6"))) {
        ipv6_classes(&v6, &mut classes);
    }

    let mut nics = Vec::new();
    let mut netbird: Option<(String, NetbirdInterface)> = None;
    let mut virtual_interfaces: u32 = 0;
    for name in dir_names(&net) {
        if name == "lo" {
            continue;
        }
        let dir = net.join(&name);
        // An SR-IOV virtual function's netdev is a VM's, not the host's.
        let physical = dir.join("device").exists()
            && !dir.join("device/physfn").exists()
            && !virtual_by_name(&name);
        if !physical {
            // `wt0` wins over any other candidate; the rest are counted.
            if is_netbird(&name, &netbird_v4)
                && netbird.as_ref().is_none_or(|(n, _)| n != NETBIRD_NAME)
            {
                if netbird.is_some() {
                    virtual_interfaces = virtual_interfaces.saturating_add(1);
                }
                netbird = Some((
                    name.clone(),
                    NetbirdInterface {
                        state: link_state(&dir),
                        mtu: mtu(&dir),
                    },
                ));
            } else {
                virtual_interfaces = virtual_interfaces.saturating_add(1);
            }
            continue;
        }
        let Some(clean_name) = clean_text(name.as_bytes(), MAX_NAME_LEN).filter(|n| *n == name)
        else {
            // A name the crate cannot carry: counted, not named.
            virtual_interfaces = virtual_interfaces.saturating_add(1);
            continue;
        };
        let device = dir.join("device");
        let pci = link_name(&device).filter(|a| is_pci_address(a));
        let ids = pci
            .as_ref()
            .and_then(|_| Some((id16(&device.join("vendor"))?, id16(&device.join("device"))?)));
        // A name ethtool would read as an option is not passed to it.
        let fw = if name.starts_with('-') {
            Err(super::CommandError::NotFound)
        } else {
            runner.run("ethtool", &["-i", &name])
        };
        tally.command(&fw);
        nics.push((
            ids,
            Nic {
                name: clean_name,
                pci,
                model: None,
                driver: link_name(&device.join("driver"))
                    .and_then(|d| clean_text(d.as_bytes(), MAX_NAME_LEN)),
                firmware: fw.ok().as_deref().and_then(firmware),
                state: link_state(&dir),
                speed_mbps: read_trimmed(&dir.join("speed"))
                    .and_then(|s| s.parse::<i64>().ok())
                    .and_then(|s| u32::try_from(s).ok())
                    .filter(|&s| s > 0),
                duplex: duplex(read_trimmed(&dir.join("duplex"))),
                mtu: mtu(&dir),
                role: role(stacked_class(&net, &name, &classes)),
            },
        ));
    }
    nics.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    if nics.len() > MAX_NICS {
        nics.truncate(MAX_NICS);
        tally.failed();
    }
    let wanted: BTreeSet<(u16, u16)> = nics.iter().filter_map(|(ids, _)| *ids).collect();
    let models = pci_ids::names(&paths.pci_ids, &wanted);
    let nics = nics
        .into_iter()
        .map(|(ids, mut nic)| {
            nic.model = ids.and_then(|i| models.get(&i).cloned());
            nic
        })
        .collect();
    NetworkSection {
        status: tally.status(),
        nics,
        netbird: netbird.map(|(_, n)| n),
        virtual_interfaces,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture::{Host, Runner};
    use super::super::pci::tests::device;
    use super::super::pci_ids::tests::EXCERPT;
    use super::super::CommandError;
    use super::*;
    use hippius_host_inventory::SectionStatus;

    const IP_OUTPUT: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eno1    inet 198.51.100.27/24 metric 100 brd 198.51.100.255 scope global dynamic eno1\\       valid_lft 85000sec preferred_lft 85000sec
3: eno2    inet 192.168.10.5/24 brd 192.168.10.255 scope global eno2\\       valid_lft forever preferred_lft forever
5: virbr0    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0\\       valid_lft forever preferred_lft forever
9: wt0    inet 100.92.14.3/16 brd 100.92.255.255 scope global wt0\\       valid_lft forever preferred_lft forever
";

    const IF_INET6: &str = "\
00000000000000000000000000000001 01 80 10 80       lo
200141d0030200000000000000001234 02 40 00 00     eno1
fe80000000000000aabbccfffeddeeff 02 40 20 80     eno1
fe80000000000000aabbccfffeddee00 04 40 20 80     eno3
fd00000000000000000000000000abcd 06 40 00 80   vnet3
";

    const MAC: &str = "aa:bb:cc:dd:ee:ff";

    /// One interface dir; `pci` makes it physical (a `device` link).
    fn iface(h: &Host, name: &str, pci: Option<&str>, operstate: &str, mtu: u32) {
        let d = format!("sys/class/net/{name}");
        h.write(&format!("{d}/operstate"), format!("{operstate}\n"));
        h.write(&format!("{d}/mtu"), format!("{mtu}\n"));
        h.write(&format!("{d}/address"), format!("{MAC}\n"));
        if let Some(addr) = pci {
            h.symlink(
                &format!("{d}/device"),
                &format!("../../../bus/pci/devices/{addr}"),
            );
        }
    }

    /// eno1 (physical, 0000:41:00.0, bnxt_en, public), wt0, virbr0,
    /// vnet3, lo — plus the PCI device eno1 sits on and `pci.ids`.
    pub(crate) fn nic_tree(h: &Host) {
        h.write("pci.ids", EXCERPT);
        device(
            h,
            "0000:41:00.0",
            "0x020000",
            "0x14e4",
            "0x16d8",
            Some("bnxt_en"),
        );
        iface(h, "eno1", Some("0000:41:00.0"), "up", 1500);
        h.write("sys/class/net/eno1/speed", "10000\n");
        h.write("sys/class/net/eno1/duplex", "full\n");
        iface(h, "wt0", None, "unknown", 1280);
        h.write("sys/class/net/wt0/carrier", "1\n");
        iface(h, "virbr0", None, "up", 1500);
        iface(h, "vnet3", None, "unknown", 1500);
        iface(h, "lo", None, "unknown", 65536);
        h.write("proc/net/if_inet6", IF_INET6);
    }

    fn runner() -> Runner {
        Runner::default()
            .with("ip -o -4 addr show", Ok(IP_OUTPUT))
            .with(
            "ethtool -i eno1",
            Ok(
                "driver: bnxt_en\nversion: 6.8.0\nfirmware-version: 230.0.156.0/pkg 23.21.13.80\n\
                    bus-info: 0000:41:00.0\n",
            ),
        )
    }

    #[test]
    fn reads_physical_nics_netbird_and_counts_the_rest() {
        let h = Host::new();
        nic_tree(&h);
        let n = collect_network(&h.paths(), &runner());
        assert_eq!(n.status, SectionStatus::Ok);
        assert_eq!(
            n.nics,
            [Nic {
                name: "eno1".into(),
                pci: Some("0000:41:00.0".into()),
                model: Some(
                    "Broadcom Inc. and subsidiaries BCM57416 NetXtreme-E Dual-Media 10G RDMA Ethernet Controller"
                        .into()
                ),
                driver: Some("bnxt_en".into()),
                firmware: Some("230.0.156.0/pkg 23.21.13.80".into()),
                state: LinkState::Up,
                speed_mbps: Some(10000),
                duplex: Duplex::Full,
                mtu: 1500,
                role: NicRole::Public,
            }]
        );
        assert_eq!(
            n.netbird,
            Some(NetbirdInterface {
                state: LinkState::Up,
                mtu: 1280
            })
        );
        assert_eq!(n.virtual_interfaces, 2, "virbr0 + vnet3, lo not counted");
    }

    #[test]
    fn no_mac_no_ip_no_virtual_name_in_the_json() {
        let h = Host::new();
        nic_tree(&h);
        let json = serde_json::to_string(&collect_network(&h.paths(), &runner())).unwrap();
        for leak in [
            MAC, "aa:bb", "51.195", "192.168", "100.92", "2001", "fe80", "fd00", "virbr", "vnet",
            "wt0", "\"lo\"", "docker",
        ] {
            assert!(!json.contains(leak), "{leak} in {json}");
        }
    }

    #[test]
    fn roles_follow_the_addresses() {
        let h = Host::new();
        nic_tree(&h);
        // eno2: private v4 only; eno3: a link-local v6 only (unused);
        // eno4: a v4 in 100.64/10 on a physical NIC.
        device(&h, "0000:42:00.0", "0x020000", "0x14e4", "0x16d8", None);
        iface(&h, "eno2", Some("0000:42:00.0"), "up", 9000);
        iface(&h, "eno3", Some("0000:42:00.0"), "down", 1500);
        h.write("sys/class/net/eno3/speed", "-1\n");
        iface(&h, "eno4", Some("0000:42:00.0"), "dormant", 1500);
        let ip = format!("{IP_OUTPUT}12: eno4    inet 100.70.0.1/10 scope global eno4\n");
        let r = runner().with("ip -o -4 addr show", Ok(&ip));
        let n = collect_network(&h.paths(), &r);
        let by_name: BTreeMap<&str, &Nic> = n.nics.iter().map(|n| (n.name.as_str(), n)).collect();
        assert_eq!(by_name["eno1"].role, NicRole::Public);
        assert_eq!(by_name["eno2"].role, NicRole::Private);
        assert_eq!(by_name["eno3"].role, NicRole::Unused);
        assert_eq!(by_name["eno3"].state, LinkState::Down);
        assert_eq!(by_name["eno3"].speed_mbps, None, "-1 is none");
        assert_eq!(by_name["eno3"].duplex, Duplex::Unknown);
        assert_eq!(by_name["eno4"].role, NicRole::Netbird);
        assert_eq!(by_name["eno4"].state, LinkState::Unknown);
        // A physical NIC is never taken for the NetBird interface.
        assert_eq!(n.netbird.as_ref().unwrap().mtu, 1280);
        assert_eq!(
            by_name["eno2"].firmware, None,
            "ethtool knows nothing of it"
        );
        assert_eq!(
            by_name["eno2"]
                .model
                .as_deref()
                .map(|m| m.starts_with("Broadcom")),
            Some(true)
        );
    }

    #[test]
    fn netbird_under_another_name_is_found_by_its_address() {
        let h = Host::new();
        iface(&h, "netbird0", None, "unknown", 1280);
        iface(&h, "docker0", None, "up", 1500);
        // A Docker bridge and Tailscale in 100.64/10 are no NetBird.
        iface(&h, "br-d8c80b497502", None, "down", 1500);
        iface(&h, "tailscale0", None, "unknown", 1280);
        let r = Runner::default().with(
            "ip -o -4 addr show",
            Ok("4: netbird0    inet 100.92.1.1/16 scope global netbird0\n\
                6: docker0    inet 172.17.0.1/16 scope global docker0\n\
                7: br-d8c80b497502    inet 100.64.5.1/24 scope global br-d8c80b497502\n\
                8: tailscale0    inet 100.101.2.3/32 scope global tailscale0\n"),
        );
        let n = collect_network(&h.paths(), &r);
        assert_eq!(n.netbird.as_ref().map(|n| n.mtu), Some(1280));
        assert_eq!(n.virtual_interfaces, 3);
        assert!(n.nics.is_empty());
        // Tailscale alone is counted, not taken for NetBird.
        let h = Host::new();
        iface(&h, "tailscale0", None, "unknown", 1280);
        let r = Runner::default().with(
            "ip -o -4 addr show",
            Ok("8: tailscale0    inet 100.101.2.3/32 scope global tailscale0\n"),
        );
        let n = collect_network(&h.paths(), &r);
        assert_eq!(n.netbird, None);
        assert_eq!(n.virtual_interfaces, 1);
    }

    #[test]
    fn a_port_takes_the_role_of_what_is_stacked_on_it() {
        let h = Host::new();
        device(&h, "0000:41:00.0", "0x020000", "0x14e4", "0x16d8", None);
        // eno1 → bond0 → br0 (public v4).
        iface(&h, "eno1", Some("0000:41:00.0"), "up", 1500);
        h.symlink("sys/class/net/eno1/master", "../bond0");
        iface(&h, "bond0", None, "up", 1500);
        h.symlink("sys/class/net/bond0/master", "../br0");
        iface(&h, "br0", None, "up", 1500);
        // eno2 carries a VLAN with a private v4.
        iface(&h, "eno2", Some("0000:41:00.0"), "up", 1500);
        h.symlink("sys/class/net/eno2/upper_eno2.100", "../eno2.100");
        iface(&h, "eno2.100", None, "up", 1500);
        // eno3: nothing stacked, nothing on it.
        iface(&h, "eno3", Some("0000:41:00.0"), "up", 1500);
        // A master loop is harmless.
        h.symlink("sys/class/net/eno3/master", "../eno3");
        let r = Runner::default().with(
            "ip -o -4 addr show",
            Ok("5: br0    inet 198.51.100.27/24 scope global br0\n\
                6: eno2.100@eno2    inet 10.1.1.2/24 scope global eno2.100\n"),
        );
        let n = collect_network(&h.paths(), &r);
        let by_name: BTreeMap<&str, &Nic> = n.nics.iter().map(|n| (n.name.as_str(), n)).collect();
        assert_eq!(by_name["eno1"].role, NicRole::Public);
        assert_eq!(by_name["eno2"].role, NicRole::Private);
        assert_eq!(by_name["eno3"].role, NicRole::Unused);
        assert_eq!(n.virtual_interfaces, 3, "bond0, br0, eno2.100");
        let json = serde_json::to_string(&n).unwrap();
        for leak in ["bond0", "br0", "eno2.100", "51.195", "10.1.1"] {
            assert!(!json.contains(leak), "{leak} in {json}");
        }
    }

    #[test]
    fn an_sriov_vf_netdev_is_counted_not_named() {
        let h = Host::new();
        nic_tree(&h);
        device(
            &h,
            "0000:41:00.4",
            "0x020000",
            "0x14e4",
            "0x16dc",
            Some("bnxt_en"),
        );
        h.symlink("sys/bus/pci/devices/0000:41:00.4/physfn", "../0000:41:00.0");
        iface(&h, "eno1v0", Some("0000:41:00.4"), "up", 1500);
        let n = collect_network(&h.paths(), &runner());
        let names: Vec<&str> = n.nics.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["eno1"]);
        assert_eq!(n.virtual_interfaces, 3);
    }

    #[test]
    fn an_option_like_name_is_not_passed_to_ethtool() {
        let h = Host::new();
        device(&h, "0000:41:00.0", "0x020000", "0x14e4", "0x16d8", None);
        iface(&h, "-x", Some("0000:41:00.0"), "up", 1500);
        // Any ethtool call would time out and make the section `timeout`.
        let r = Runner::default()
            .with("ip -o -4 addr show", Ok(""))
            .with("ethtool -i -x", Err(CommandError::Timeout));
        let n = collect_network(&h.paths(), &r);
        assert_eq!(n.status, SectionStatus::Ok);
        assert_eq!(n.nics[0].firmware, None);
    }

    #[test]
    fn nics_past_the_cap_make_the_section_partial() {
        let h = Host::new();
        device(&h, "0000:41:00.0", "0x020000", "0x14e4", "0x16d8", None);
        for i in 0..(MAX_NICS + 2) {
            iface(&h, &format!("eth{i:02}"), Some("0000:41:00.0"), "up", 1500);
        }
        let n = collect_network(
            &h.paths(),
            &Runner::default().with("ip -o -4 addr show", Ok("")),
        );
        assert_eq!(n.nics.len(), MAX_NICS);
        assert_eq!(n.status, SectionStatus::Partial);
    }

    #[test]
    fn classifiers() {
        let v4 = |s: &str| classify_v4(s.parse().unwrap());
        assert_eq!(v4("10.0.0.1"), Some(AddrClass::Private));
        assert_eq!(v4("172.16.5.1"), Some(AddrClass::Private));
        assert_eq!(v4("169.254.1.1"), Some(AddrClass::Private));
        assert_eq!(v4("100.64.0.1"), Some(AddrClass::Netbird));
        assert_eq!(v4("100.127.255.254"), Some(AddrClass::Netbird));
        assert_eq!(v4("100.128.0.1"), Some(AddrClass::Public));
        assert_eq!(v4("8.8.8.8"), Some(AddrClass::Public));
        assert_eq!(v4("127.0.0.1"), None);
        let v6 = |s: &str| classify_v6(s.parse().unwrap());
        assert_eq!(v6("2001:db8::1"), Some(AddrClass::Public));
        assert_eq!(v6("fd12::1"), Some(AddrClass::Private));
        assert_eq!(v6("fe80::1"), None);
        assert_eq!(v6("::1"), None);
        assert_eq!(v6("ff02::1"), None);
    }

    #[test]
    fn missing_tools_and_sources_degrade() {
        let h = Host::new();
        nic_tree(&h);
        // No `ip`: v4 roles unknown, partial.
        let n = collect_network(&h.paths(), &Runner::default());
        assert_eq!(n.status, SectionStatus::Partial);
        assert_eq!(n.nics[0].role, NicRole::Public, "its global v6 still tells");
        assert_eq!(n.nics[0].firmware, None);
        let r = runner().with("ethtool -i eno1", Err(CommandError::Timeout));
        assert_eq!(
            collect_network(&h.paths(), &r).status,
            SectionStatus::Timeout
        );
        let n = collect_network(&Host::new().paths(), &Runner::default());
        assert_eq!(n.status, SectionStatus::Unavailable);
        assert!(n.nics.is_empty() && n.netbird.is_none());
    }

    #[test]
    fn parsers_ignore_junk() {
        let mut c = Classes::new();
        let nb = ipv4_classes("garbage\n1:\n2: x inet\n3: y inet 999.1.1.1/8\n", &mut c);
        assert!(c.is_empty() && nb.is_empty());
        ipv6_classes("zz 1 2 3 4 eth0\n2001 01\n", &mut c);
        assert!(c.is_empty());
        assert_eq!(firmware("firmware-version: N/A\n"), None);
        assert_eq!(firmware("driver: x\n"), None);
    }
}
