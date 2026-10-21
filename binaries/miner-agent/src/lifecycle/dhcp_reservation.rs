//! Per-VM **static DHCP reservation** on the libvirt `default` network,
//! for a tenant NIC launched with a [`crate::orders::types::NetSpec`].
//!
//! ## Why
//! Such a NIC carries `clean-traffic`, which drops every frame whose
//! source IP is not the guest's. Left to learn that IP from DHCP, the
//! filter keeps the FIRST lease it sees — and a golden guest does DHCP
//! twice with two client identifiers (the initramfs, then the booted
//! OS), so dnsmasq hands out two addresses and the OS's one is dropped:
//! the VM is network-dead (live canary, 2026-10-21).
//!
//! So the agent decides the address itself, before the domain exists:
//! - a deterministic MAC ([`derive_mac`], in the locally-administered
//!   [`MAC_PREFIX`] block, which libvirt never generates) goes into the
//!   domain XML, and a `<host mac ip/>` entry for it into the network's
//!   `<dhcp>`. dnsmasq matches that entry on the MAC whatever client id
//!   the guest sends, so both exchanges get the same address, and it
//!   never hands a reserved address to another client;
//! - the same address is pinned as the filter's `IP` parameter, so the
//!   filter learns nothing.
//!
//! ## Lifetime
//! - The record (`<state_root>/net-lease/<vm_id>`, `{mac, ip}`) is
//!   written durably BEFORE the network entry is added, so every entry
//!   carrying [`MAC_PREFIX`] has a record — one that has none is an
//!   orphan [`reconcile`] deletes.
//! - Reused on every later launch of the VM here (relaunch, a §25
//!   arrival back on this host, a resize): same MAC, same address while
//!   it is free. Kept across stop and a failed launch, like the VM's
//!   pool record ([`super::vm_pool`]).
//! - Released by §24 destroy ([`release`]).
//! - The entry is added `--live --config`, so it survives a libvirtd or
//!   host restart; [`reconcile`] re-adds a missing one at agent start.
//!
//! Every failure is a static code: `net/ip-range-exhausted` (no free
//! address in the network's DHCP range) or `net/dhcp-reservation-failed`.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::adopt::{attr, sections};
use super::cvm_handle::VmId;
use super::libvirt_driver::{DhcpHostOp, LibvirtDriver};
use crate::error::{MinerAgentError, Result};

/// The libvirt network tenant NICs are on.
pub const NETWORK: &str = "default";

/// Under the agent's state root.
pub const DIR: &str = "net-lease";

/// The first three bytes of every reserved MAC: locally administered,
/// unicast, and never one libvirt picks itself (`52:54:00`). An entry
/// with this prefix on the network is the agent's.
pub const MAC_PREFIX: &str = "02:68:76";

/// `net/ip-range-exhausted`.
const EXHAUSTED: MinerAgentError = MinerAgentError::NetReservation("ip-range-exhausted");
/// `net/dhcp-reservation-failed`.
const FAILED: MinerAgentError = MinerAgentError::NetReservation("dhcp-reservation-failed");

/// One VM's reserved MAC and address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpReservation {
    /// Lower-case, `MAC_PREFIX:xx:xx:xx`.
    pub mac: String,
    /// Inside the network's DHCP range.
    pub ip: Ipv4Addr,
}

impl DhcpReservation {
    /// The `<host/>` element `virsh net-update … ip-dhcp-host` takes. Both
    /// values are checked shapes (a MAC, a dotted quad): nothing to escape.
    pub fn host_xml(&self) -> String {
        format!("<host mac='{}' ip='{}'/>", self.mac, self.ip)
    }

    fn is_valid(&self) -> bool {
        is_mac(&self.mac) && self.mac.starts_with(MAC_PREFIX)
    }
}

/// A `<host/>` entry or an active lease: a MAC (lower-case, absent for
/// an entry keyed on a name or client id) and its IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub mac: Option<String>,
    pub ip: Ipv4Addr,
}

/// What the network's XML says about its IPv4 DHCP service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDhcp {
    /// Index of its `<ip>` among the network's `<ip>` elements — the
    /// `--parent-index` of a `net-update` (without it libvirt refuses a
    /// network that also serves DHCPv6).
    pub parent_index: usize,
    /// The dynamic ranges, inclusive, in document order.
    pub ranges: Vec<(Ipv4Addr, Ipv4Addr)>,
    /// The static `<host/>` entries.
    pub hosts: Vec<Binding>,
}

/// The attributes of every `<tag …>` opening tag in `xml`.
fn all_tag_attrs<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    xml.split(open.as_str())
        .skip(1)
        .filter(|rest| rest.starts_with(|c: char| c.is_ascii_whitespace() || c == '/'))
        .filter_map(|rest| rest.split('>').next())
        .collect()
}

/// The body of every `<ip>` element of a network, in document order — a
/// self-closing `<ip …/>` (an address without DHCP) is an empty one, so
/// the index of each is libvirt's `--parent-index`. (`<ip>` elements do
/// not nest.)
fn ip_elements(xml: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find("<ip") {
        let after = &rest[at + 3..];
        if !after.starts_with(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>') {
            rest = after;
            continue;
        }
        let Some(gt) = after.find('>') else {
            break;
        };
        let body = &after[gt + 1..];
        if after[..gt].ends_with('/') {
            out.push("");
            rest = body;
        } else {
            let end = body.find("</ip>").unwrap_or(body.len());
            out.push(&body[..end]);
            rest = &body[end..];
        }
    }
    out
}

/// The first `<ip>` of `virsh net-dumpxml` whose `<dhcp>` has an IPv4
/// `<range/>`: its index, every IPv4 range and every `<host/>`. A network
/// without one cannot hold a reservation.
pub fn parse_network(xml: &str) -> Result<NetworkDhcp> {
    for (parent_index, ip) in ip_elements(xml).into_iter().enumerate() {
        let Some(dhcp) = sections(ip, "dhcp").into_iter().next() else {
            continue;
        };
        let mut ranges = Vec::new();
        for range in all_tag_attrs(&dhcp, "range") {
            let ipv4 = |name| attr(range, name).and_then(|v| v.parse::<Ipv4Addr>().ok());
            if let (Some(start), Some(end)) = (ipv4("start"), ipv4("end")) {
                if u32::from(start) > u32::from(end) {
                    return Err(FAILED);
                }
                ranges.push((start, end));
            }
        }
        if ranges.is_empty() {
            continue;
        }
        let hosts = all_tag_attrs(&dhcp, "host")
            .into_iter()
            .filter_map(|attrs| {
                Some(Binding {
                    mac: attr(attrs, "mac").map(|m| m.to_ascii_lowercase()),
                    ip: attr(attrs, "ip")?.parse().ok()?,
                })
            })
            .collect();
        return Ok(NetworkDhcp {
            parent_index,
            ranges,
            hosts,
        });
    }
    Err(FAILED)
}

/// The IPv4 leases of a `virsh net-dhcp-leases` table: on each row, the
/// MAC column and the `a.b.c.d/nn` address column. Header, separator and
/// IPv6 rows carry no such pair and are skipped.
pub fn parse_leases(table: &str) -> Vec<Binding> {
    table
        .lines()
        .filter_map(|line| {
            let mut mac = None;
            let mut ip = None;
            for token in line.split_whitespace() {
                let lower = token.to_ascii_lowercase();
                if mac.is_none() && is_mac(&lower) {
                    mac = Some(lower);
                } else if let Some((addr, _prefix)) = token.split_once('/') {
                    ip = ip.or_else(|| addr.parse::<Ipv4Addr>().ok());
                }
            }
            Some(Binding {
                mac: Some(mac?),
                ip: ip?,
            })
        })
        .collect()
}

/// The MAC for `vm_id`: the first of `MAC_PREFIX:<sha256(vm_id, n)[..3]>`,
/// `n = 0, 1, …`, that no other reservation holds. Stable for a VM as
/// long as nothing collides, and recorded once picked.
pub fn derive_mac(vm_id: &VmId, taken: &HashSet<String>) -> String {
    (0u32..)
        .map(|n| {
            let mut h = Sha256::new();
            h.update(b"hippius-dhcp-mac\0");
            h.update(vm_id.as_str().as_bytes());
            h.update(n.to_be_bytes());
            let d = h.finalize();
            format!("{MAC_PREFIX}:{:02x}:{:02x}:{:02x}", d[0], d[1], d[2])
        })
        .find(|mac| !taken.contains(mac))
        .unwrap_or_default()
}

/// What [`ensure`] does to the network for one VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub reservation: DhcpReservation,
    /// Entries for the VM's MAC on another address (a previous
    /// reservation whose address was taken meanwhile): deleted first.
    pub stale: Vec<DhcpReservation>,
    /// `Add` when the entry is not on the network yet; `Modify` (the
    /// same entry again) when it is: libvirt changes its live definition
    /// before it saves it and reloads dnsmasq, so an entry that is there
    /// may come from an update that failed half-way, and only a
    /// successful update proves dnsmasq serves it.
    pub apply: DhcpHostOp,
}

/// Choose `vm_id`'s MAC and address.
///
/// `current` is the VM's own record, `others` every other VM's. An
/// address is taken when another reservation, another `<host/>` entry
/// or another MAC's active lease holds it. The VM keeps its recorded
/// address while that is free and in range; otherwise it gets the first
/// free one from a start point derived from its id, so concurrent hosts
/// and relaunches do not all crowd the bottom of the range.
pub fn plan(
    vm_id: &VmId,
    current: Option<&DhcpReservation>,
    others: &[DhcpReservation],
    net: &NetworkDhcp,
    leases: &[Binding],
) -> Result<Plan> {
    let mac = match current {
        Some(r) => r.mac.clone(),
        None => derive_mac(vm_id, &others.iter().map(|r| r.mac.clone()).collect()),
    };
    let foreign = |b: &Binding| b.mac.as_deref() != Some(mac.as_str());
    let taken: HashSet<Ipv4Addr> = others
        .iter()
        .map(|r| r.ip)
        .chain(net.hosts.iter().filter(|b| foreign(b)).map(|b| b.ip))
        .chain(leases.iter().filter(|b| foreign(b)).map(|b| b.ip))
        .collect();
    let in_range = |ip: Ipv4Addr| {
        net.ranges
            .iter()
            .any(|(s, e)| (u32::from(*s)..=u32::from(*e)).contains(&u32::from(ip)))
    };
    let ip = match current {
        Some(r) if in_range(r.ip) && !taken.contains(&r.ip) => r.ip,
        _ => {
            // Every address of every range, in order (ranges may overlap:
            // a repeat is harmless).
            let all: Vec<Ipv4Addr> = net
                .ranges
                .iter()
                .flat_map(|(s, e)| (u32::from(*s)..=u32::from(*e)).map(Ipv4Addr::from))
                .collect();
            let size = all.len() as u64;
            let first = start_offset(vm_id) % size.max(1);
            (0..size)
                .filter_map(|i| all.get(((first + i) % size) as usize).copied())
                .find(|ip| !taken.contains(ip))
                .ok_or(EXHAUSTED)?
        }
    };
    let ours = |b: &&Binding| !foreign(b);
    let stale = net
        .hosts
        .iter()
        .filter(ours)
        .filter(|b| b.ip != ip)
        .map(|b| DhcpReservation {
            mac: mac.clone(),
            ip: b.ip,
        })
        .collect();
    let apply = if net.hosts.iter().filter(ours).any(|b| b.ip == ip) {
        DhcpHostOp::Modify
    } else {
        DhcpHostOp::Add
    };
    Ok(Plan {
        reservation: DhcpReservation { mac, ip },
        stale,
        apply,
    })
}

fn start_offset(vm_id: &VmId) -> u64 {
    let mut h = Sha256::new();
    h.update(b"hippius-dhcp-ip\0");
    h.update(vm_id.as_str().as_bytes());
    let d = h.finalize();
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

pub fn dir(state_root: &Path) -> PathBuf {
    state_root.join(DIR)
}

pub fn record_path(state_root: &Path, vm_id: &VmId) -> PathBuf {
    dir(state_root).join(vm_id.as_str())
}

/// `Ok(None)`: no record. A record that cannot be read or parsed, or
/// names a MAC outside [`MAC_PREFIX`], is an error, never "absent".
pub fn read(state_root: &Path, vm_id: &VmId) -> Result<Option<DhcpReservation>> {
    match std::fs::read(record_path(state_root, vm_id)) {
        Ok(bytes) => match serde_json::from_slice::<DhcpReservation>(&bytes) {
            Ok(r) if r.is_valid() => Ok(Some(r)),
            _ => Err(FAILED),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FAILED),
    }
}

/// Every VM's record on this host.
pub fn list(state_root: &Path) -> Result<Vec<(VmId, DhcpReservation)>> {
    let entries = match std::fs::read_dir(dir(state_root)) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(FAILED),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| FAILED)?;
        let Some(vm) = entry.file_name().to_str().and_then(|n| VmId::new(n).ok()) else {
            // A temp file of an interrupted write.
            continue;
        };
        if let Some(r) = read(state_root, &vm)? {
            out.push((vm, r));
        }
    }
    out.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    Ok(out)
}

fn write(state_root: &Path, vm_id: &VmId, r: &DhcpReservation) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(r).map_err(|_| FAILED)?;
    super::vm_pool::write_durable(&dir(state_root), &record_path(state_root, vm_id), &bytes)
        .map_err(|_| FAILED)
}

fn remove(state_root: &Path, vm_id: &VmId) -> Result<()> {
    match std::fs::remove_file(record_path(state_root, vm_id)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FAILED),
    }
}

async fn network(driver: &dyn LibvirtDriver) -> Result<NetworkDhcp> {
    let xml = driver.network_xml(NETWORK).await.map_err(|_| FAILED)?;
    parse_network(&xml)
}

async fn update(
    driver: &dyn LibvirtDriver,
    net: &NetworkDhcp,
    op: DhcpHostOp,
    r: &DhcpReservation,
) -> Result<()> {
    driver
        .network_update_dhcp_host(NETWORK, op, net.parent_index, &r.host_xml())
        .await
        .map_err(|_| FAILED)
}

async fn leases(driver: &dyn LibvirtDriver) -> Result<Vec<Binding>> {
    let table = driver
        .network_dhcp_leases(NETWORK)
        .await
        .map_err(|_| FAILED)?;
    Ok(parse_leases(&table))
}

/// How many times [`ensure`] re-plans when a dynamic client took the
/// chosen address between the lease read and the entry landing.
const ENSURE_ATTEMPTS: usize = 3;

/// Reserve (or re-confirm) `vm_id`'s MAC and address and make sure the
/// network carries its entry. Idempotent. The caller serialises calls:
/// two concurrent plans could pick the same address.
///
/// The agent's lock does not hold dnsmasq back: a client launched without
/// a spec can lease the chosen address before the entry lands (and
/// dnsmasq then keeps it leased to that client). So the leases are read
/// again once the entry is on: an address now leased to another MAC is
/// given up and the plan run again, which deletes that entry.
pub async fn ensure(
    driver: &dyn LibvirtDriver,
    state_root: &Path,
    vm_id: &VmId,
) -> Result<DhcpReservation> {
    for _ in 0..ENSURE_ATTEMPTS {
        let mut others = list(state_root)?;
        let current = others
            .iter()
            .position(|(vm, _)| vm == vm_id)
            .map(|i| others.remove(i).1);
        let others: Vec<DhcpReservation> = others.into_iter().map(|(_, r)| r).collect();
        let net = network(driver).await?;
        let plan = plan(
            vm_id,
            current.as_ref(),
            &others,
            &net,
            &leases(driver).await?,
        )?;
        if current.as_ref() != Some(&plan.reservation) {
            write(state_root, vm_id, &plan.reservation)?;
        }
        for stale in &plan.stale {
            update(driver, &net, DhcpHostOp::Delete, stale).await?;
        }
        update(driver, &net, plan.apply, &plan.reservation).await?;
        let r = plan.reservation;
        let raced = leases(driver)
            .await?
            .iter()
            .any(|b| b.ip == r.ip && b.mac.as_deref() != Some(r.mac.as_str()));
        if !raced {
            return Ok(r);
        }
    }
    Err(FAILED)
}

/// Drop `vm_id`'s reservation (§24 destroy): its network entry, then its
/// record. The record goes even if the entry could not be deleted: an
/// entry without a record is an orphan the next [`reconcile`] deletes,
/// and it keeps its address taken until then.
pub async fn release(driver: &dyn LibvirtDriver, state_root: &Path, vm_id: &VmId) -> Result<()> {
    let Some(r) = read(state_root, vm_id)? else {
        return Ok(());
    };
    let entry = match network(driver).await {
        Ok(net) => {
            let mut result = Ok(());
            for b in net.hosts.iter().filter(|b| b.mac.as_ref() == Some(&r.mac)) {
                let entry = DhcpReservation {
                    mac: r.mac.clone(),
                    ip: b.ip,
                };
                if let Err(err) = update(driver, &net, DhcpHostOp::Delete, &entry).await {
                    result = Err(err);
                }
            }
            result
        }
        Err(err) => Err(err),
    };
    remove(state_root, vm_id)?;
    entry
}

/// What [`reconcile`] changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Reconciled {
    /// Records whose entry was missing and was added back.
    pub readded: usize,
    /// [`MAC_PREFIX`] entries no record names, deleted.
    pub orphans_deleted: usize,
    /// Records of VMs `gone` said no longer exist here, released.
    pub released: usize,
    /// Records whose address another MAC holds a lease on: dnsmasq keeps
    /// it with that client until the lease ends, and the VM (its filter
    /// pinned to the address) has no network until then. Reported only —
    /// a running VM cannot change address.
    pub leased_to_another: usize,
}

/// At agent start: release the records of VMs `gone` says no longer
/// exist here, put every remaining record's entry back on the network
/// if it is missing, and delete the agent's entries no record names.
///
/// An entry is only deleted as an orphan when its MAC is in none of
/// `domain_macs`, the MACs of every domain libvirt has: a record lost
/// while its domain survives must not cut that VM off. `None` (the
/// domains could not all be read) deletes no orphan.
///
/// Each step is attempted for every VM; the first error is returned
/// once all were tried.
pub async fn reconcile(
    driver: &dyn LibvirtDriver,
    state_root: &Path,
    gone: &HashSet<VmId>,
    domain_macs: Option<&HashSet<String>>,
) -> Result<Reconciled> {
    let mut done = Reconciled::default();
    let mut first_err = None;
    let mut keep = |result: Result<()>| match result {
        Ok(()) => true,
        Err(err) => {
            first_err.get_or_insert(err);
            false
        }
    };
    for (vm, _) in list(state_root)?.iter().filter(|(vm, _)| gone.contains(vm)) {
        if keep(release(driver, state_root, vm).await) {
            done.released += 1;
        }
    }
    let records = list(state_root)?;
    let net = network(driver).await?;
    let leases = leases(driver).await?;
    for (_, r) in &records {
        if leases
            .iter()
            .any(|b| b.ip == r.ip && b.mac.as_deref() != Some(r.mac.as_str()))
        {
            done.leased_to_another += 1;
        }
        let present = net
            .hosts
            .iter()
            .any(|b| b.mac.as_ref() == Some(&r.mac) && b.ip == r.ip);
        if !present && keep(update(driver, &net, DhcpHostOp::Add, r).await) {
            done.readded += 1;
        }
    }
    let Some(domain_macs) = domain_macs else {
        return first_err.map_or(Ok(done), Err);
    };
    let known: HashSet<&str> = records.iter().map(|(_, r)| r.mac.as_str()).collect();
    for b in &net.hosts {
        let Some(mac) = b.mac.as_deref() else {
            continue;
        };
        if !mac.starts_with(MAC_PREFIX) || known.contains(mac) || domain_macs.contains(mac) {
            continue;
        }
        let orphan = DhcpReservation {
            mac: mac.to_string(),
            ip: b.ip,
        };
        if keep(update(driver, &net, DhcpHostOp::Delete, &orphan).await) {
            done.orphans_deleted += 1;
        }
    }
    first_err.map_or(Ok(done), Err)
}

fn is_mac(mac: &str) -> bool {
    crate::netpolicy::caps::is_mac(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::libvirt_driver::MockLibvirtDriver;

    fn vm(s: &str) -> VmId {
        VmId::new(s).unwrap()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn res(mac: &str, addr: &str) -> DhcpReservation {
        DhcpReservation {
            mac: mac.to_string(),
            ip: ip(addr),
        }
    }

    fn bind(mac: &str, addr: &str) -> Binding {
        Binding {
            mac: Some(mac.to_string()),
            ip: ip(addr),
        }
    }

    fn net(start: &str, end: &str, hosts: Vec<Binding>) -> NetworkDhcp {
        NetworkDhcp {
            parent_index: 0,
            ranges: vec![(ip(start), ip(end))],
            hosts,
        }
    }

    /// `virsh net-dumpxml default` on a stock Ubuntu host, plus two
    /// static entries (one keyed on a name only) and the NAT port range
    /// that must not be read as the DHCP range.
    const NET_XML: &str = "\
<network>
  <name>default</name>
  <uuid>3b5d0a3c-9a8c-4c63-9c9c-111111111111</uuid>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:1f:2e:3d'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'>
        <lease expiry='1' unit='hours'/>
      </range>
      <host mac='02:68:76:AA:BB:CC' ip='192.168.122.40'/>
      <host name='printer' ip='192.168.122.41'/>
    </dhcp>
  </ip>
  <ip family='ipv6' address='fd00::1' prefix='64'>
    <dhcp>
      <range start='fd00::10' end='fd00::ff'/>
    </dhcp>
  </ip>
</network>
";

    /// `virsh net-dhcp-leases default`, the live canary's two leases of
    /// one guest (initramfs then OS) plus an IPv6 row.
    const LEASES: &str = "\
 Expiry Time           MAC address         Protocol   IP address           Hostname   Client ID or DUID
------------------------------------------------------------------------------------------------------------------------------------------------
 2026-10-21 10:00:01   52:54:00:6b:3c:58   ipv4       192.168.122.122/24   -          ff:00:6b:3c:58:00:01:00:01:2e:9b:aa:01:52:54:00:6b:3c:58
 2026-10-21 10:00:09   52:54:00:6b:3c:58   ipv4       192.168.122.123/24   ubuntu     01:52:54:00:6b:3c:58
 2026-10-21 10:00:09   52:54:00:6b:3c:58   ipv6       fd00::17/64          ubuntu     00:04:aa
";

    #[test]
    fn parses_the_ipv4_dhcp_range_and_static_hosts() {
        let net = parse_network(NET_XML).unwrap();
        assert_eq!(net.parent_index, 0);
        assert_eq!(
            net.ranges,
            vec![(ip("192.168.122.2"), ip("192.168.122.254"))]
        );
        assert_eq!(
            net.hosts,
            vec![
                bind("02:68:76:aa:bb:cc", "192.168.122.40"),
                Binding {
                    mac: None,
                    ip: ip("192.168.122.41")
                },
            ]
        );
    }

    /// DHCPv6 first: the IPv4 `<ip>` is index 1, and every IPv4 range
    /// counts.
    #[test]
    fn a_dual_stack_network_names_its_ipv4_parent_and_every_range() {
        let xml = "\
<network><name>default</name>
  <ip family='ipv6' address='fd00::1' prefix='64'>
    <dhcp><range start='fd00::10' end='fd00::ff'/></dhcp>
  </ip>
  <ip address='10.0.0.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='10.0.0.2' end='10.0.0.3'/>
      <range start='10.0.0.100' end='10.0.0.101'/>
      <host mac='02:68:76:00:00:01' ip='10.0.0.100'/>
    </dhcp>
  </ip>
</network>";
        let net = parse_network(xml).unwrap();
        assert_eq!(net.parent_index, 1);
        assert_eq!(net.ranges.len(), 2);
        assert_eq!(net.hosts, vec![bind("02:68:76:00:00:01", "10.0.0.100")]);
        // The first range full, the second still has room.
        let others = [
            res("02:68:76:00:00:02", "10.0.0.2"),
            res("02:68:76:00:00:03", "10.0.0.3"),
        ];
        let p = plan(&vm("a"), None, &others, &net, &[]).unwrap();
        assert_eq!(p.reservation.ip, ip("10.0.0.101"));
    }

    /// A self-closing `<ip/>` (no DHCP) still counts as a parent.
    #[test]
    fn a_self_closing_ip_counts_toward_the_parent_index() {
        let xml = "<network>\
<ip family='ipv6' address='fd00::1' prefix='64'/>\
<ip address='10.0.0.1' netmask='255.255.255.0'><dhcp>\
<range start='10.0.0.2' end='10.0.0.9'/></dhcp></ip>\
<ipv4-unrelated/></network>";
        assert_eq!(parse_network(xml).unwrap().parent_index, 1);
    }

    #[test]
    fn a_network_without_ipv4_dhcp_cannot_hold_a_reservation() {
        for xml in [
            "<network><name>default</name></network>",
            "<network><ip address='192.168.122.1'><dhcp><range start='x' end='y'/></dhcp></ip></network>",
            "<network><ip><dhcp><range start='10.0.0.9' end='10.0.0.2'/></dhcp></ip></network>",
        ] {
            assert_eq!(parse_network(xml).unwrap_err().to_string(), "net/dhcp-reservation-failed");
        }
    }

    #[test]
    fn parses_the_ipv4_leases_and_skips_header_and_ipv6_rows() {
        assert_eq!(
            parse_leases(LEASES),
            vec![
                bind("52:54:00:6b:3c:58", "192.168.122.122"),
                bind("52:54:00:6b:3c:58", "192.168.122.123"),
            ]
        );
        assert!(parse_leases("").is_empty());
    }

    #[test]
    fn the_mac_is_deterministic_prefixed_and_steps_over_a_collision() {
        let a = derive_mac(&vm("tenant-a"), &HashSet::new());
        assert_eq!(a, derive_mac(&vm("tenant-a"), &HashSet::new()));
        assert!(a.starts_with("02:68:76:") && is_mac(&a), "{a}");
        assert_ne!(a, derive_mac(&vm("tenant-b"), &HashSet::new()));
        let next = derive_mac(&vm("tenant-a"), &HashSet::from([a.clone()]));
        assert!(next != a && next.starts_with(MAC_PREFIX), "{next}");
    }

    #[test]
    fn a_first_reservation_is_deterministic_and_inside_the_range() {
        let n = net("192.168.122.2", "192.168.122.254", vec![]);
        let p = plan(&vm("tenant-a"), None, &[], &n, &[]).unwrap();
        assert_eq!(p, plan(&vm("tenant-a"), None, &[], &n, &[]).unwrap());
        let o = u32::from(p.reservation.ip);
        let (start, end) = n.ranges[0];
        assert!((u32::from(start)..=u32::from(end)).contains(&o));
        assert!(p.apply == DhcpHostOp::Add && p.stale.is_empty());
        assert_eq!(
            p.reservation.mac,
            derive_mac(&vm("tenant-a"), &HashSet::new())
        );
    }

    #[test]
    fn an_address_held_by_anyone_else_is_never_picked() {
        // A 4-address range: three taken three different ways.
        let n = net(
            "10.0.0.2",
            "10.0.0.5",
            vec![Binding {
                mac: None,
                ip: ip("10.0.0.2"),
            }],
        );
        let others = [res("02:68:76:00:00:01", "10.0.0.3")];
        let leases = [bind("52:54:00:00:00:09", "10.0.0.4")];
        for id in ["a", "b", "c", "d", "e"] {
            let p = plan(&vm(id), None, &others, &n, &leases).unwrap();
            assert_eq!(p.reservation.ip, ip("10.0.0.5"), "{id}");
        }
    }

    #[test]
    fn a_full_range_is_refused_with_a_static_code() {
        let n = net("10.0.0.2", "10.0.0.3", vec![]);
        let others = [
            res("02:68:76:00:00:01", "10.0.0.2"),
            res("02:68:76:00:00:02", "10.0.0.3"),
        ];
        let err = plan(&vm("a"), None, &others, &n, &[]).unwrap_err();
        assert_eq!(err.to_string(), "net/ip-range-exhausted");
    }

    #[test]
    fn a_vm_keeps_its_address_and_its_own_lease_does_not_block_it() {
        let mine = res("02:68:76:12:34:56", "10.0.0.7");
        let n = net("10.0.0.2", "10.0.0.254", vec![bind(&mine.mac, "10.0.0.7")]);
        // The guest's own leases (both client ids) are not "someone else".
        let leases = [bind(&mine.mac, "10.0.0.7"), bind(&mine.mac, "10.0.0.7")];
        let p = plan(&vm("a"), Some(&mine), &[], &n, &leases).unwrap();
        assert_eq!(p.reservation, mine);
        // Already there: applied again as is (proves dnsmasq has it),
        // nothing deleted.
        assert!(p.apply == DhcpHostOp::Modify && p.stale.is_empty());
    }

    #[test]
    fn a_vm_whose_address_was_taken_moves_and_its_old_entry_is_stale() {
        let mine = res("02:68:76:12:34:56", "10.0.0.7");
        let n = net("10.0.0.2", "10.0.0.254", vec![bind(&mine.mac, "10.0.0.7")]);
        let leases = [bind("52:54:00:00:00:09", "10.0.0.7")];
        let p = plan(&vm("a"), Some(&mine), &[], &n, &leases).unwrap();
        assert_eq!(p.reservation.mac, mine.mac, "the MAC never changes");
        assert_ne!(p.reservation.ip, mine.ip);
        assert_eq!(p.stale, vec![mine]);
        assert_eq!(p.apply, DhcpHostOp::Add);
    }

    #[test]
    fn a_recorded_address_outside_a_changed_range_is_replaced() {
        let mine = res("02:68:76:12:34:56", "10.0.0.7");
        let n = net("10.0.1.2", "10.0.1.254", vec![]);
        let p = plan(&vm("a"), Some(&mine), &[], &n, &[]).unwrap();
        assert_eq!(p.reservation.ip.octets()[2], 1);
    }

    #[test]
    fn host_xml_is_what_net_update_takes() {
        assert_eq!(
            res("02:68:76:12:34:56", "192.168.122.9").host_xml(),
            "<host mac='02:68:76:12:34:56' ip='192.168.122.9'/>"
        );
    }

    #[test]
    fn a_record_with_a_foreign_mac_is_unreadable_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(super::dir(dir.path())).unwrap();
        std::fs::write(
            record_path(dir.path(), &vm("a")),
            br#"{"mac":"52:54:00:00:00:01","ip":"10.0.0.2"}"#,
        )
        .unwrap();
        assert!(read(dir.path(), &vm("a")).is_err());
        assert_eq!(read(dir.path(), &vm("b")).unwrap(), None);
    }

    #[tokio::test]
    async fn ensure_reserves_once_and_is_idempotent() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        let r = ensure(&driver, dir.path(), &vm("a")).await.unwrap();
        assert_eq!(read(dir.path(), &vm("a")).unwrap(), Some(r.clone()));
        assert_eq!(driver.dhcp_hosts(), vec![(r.mac.clone(), r.ip)]);
        // Again (a relaunch, an agent restart): same answer, no new entry
        // (the mock, like libvirt, refuses a duplicate MAC).
        assert_eq!(ensure(&driver, dir.path(), &vm("a")).await.unwrap(), r);
        assert_eq!(driver.dhcp_hosts().len(), 1);
        assert_eq!(
            driver.net_update_log(),
            vec![DhcpHostOp::Add, DhcpHostOp::Modify]
        );
        // A second VM gets another MAC and address.
        let b = ensure(&driver, dir.path(), &vm("b")).await.unwrap();
        assert!(b.mac != r.mac && b.ip != r.ip);
        assert_eq!(driver.dhcp_hosts().len(), 2);
    }

    #[tokio::test]
    async fn ensure_avoids_an_address_leased_to_a_vm_launched_without_a_spec() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        // Pin the range to two addresses: the first is leased out.
        driver.set_dhcp_range(ip("192.168.122.2"), ip("192.168.122.3"));
        driver.seed_dhcp_lease("52:54:00:00:00:09", ip("192.168.122.2"));
        driver.seed_dhcp_lease("52:54:00:00:00:0a", ip("192.168.122.3"));
        let err = ensure(&driver, dir.path(), &vm("a")).await.unwrap_err();
        assert_eq!(err.to_string(), "net/ip-range-exhausted");
        assert_eq!(
            read(dir.path(), &vm("a")).unwrap(),
            None,
            "nothing recorded"
        );
        driver.clear_dhcp_leases();
        driver.seed_dhcp_lease("52:54:00:00:00:09", ip("192.168.122.2"));
        let r = ensure(&driver, dir.path(), &vm("a")).await.unwrap();
        assert_eq!(r.ip, ip("192.168.122.3"));
    }

    #[tokio::test]
    async fn a_failed_network_update_is_a_static_reservation_failure() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        driver.fail_net_updates(true);
        let err = ensure(&driver, dir.path(), &vm("a")).await.unwrap_err();
        assert_eq!(err.to_string(), "net/dhcp-reservation-failed");
        // The record stays (an entry never exists without one); the retry
        // adds the same reservation.
        let recorded = read(dir.path(), &vm("a")).unwrap().unwrap();
        driver.fail_net_updates(false);
        assert_eq!(
            ensure(&driver, dir.path(), &vm("a")).await.unwrap(),
            recorded
        );
        assert_eq!(driver.dhcp_hosts(), vec![(recorded.mac, recorded.ip)]);
    }

    /// libvirt changed its live definition, then failed to save it or to
    /// reload dnsmasq: the entry shows, yet dnsmasq may not serve it. The
    /// retry applies it again instead of trusting what it sees.
    #[tokio::test]
    async fn an_entry_left_by_a_half_failed_update_is_applied_again() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        driver.fail_after_next_net_update();
        assert!(ensure(&driver, dir.path(), &vm("a")).await.is_err());
        assert_eq!(driver.dhcp_hosts().len(), 1, "the live entry is there");
        let r = ensure(&driver, dir.path(), &vm("a")).await.unwrap();
        assert_eq!(driver.dhcp_hosts(), vec![(r.mac, r.ip)]);
        assert_eq!(driver.net_update_log(), vec![DhcpHostOp::Modify]);
    }

    /// A client launched without a spec leases the chosen address between
    /// the lease read and the entry landing: the address is given up and
    /// the VM moves to another one.
    #[tokio::test]
    async fn an_address_a_client_leased_meanwhile_is_given_up() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        driver.lease_on_next_add("52:54:00:00:00:09");
        let r = ensure(&driver, dir.path(), &vm("a")).await.unwrap();
        let raced = parse_leases(&driver.network_dhcp_leases(NETWORK).await.unwrap());
        assert_eq!(raced.len(), 1);
        assert_ne!(r.ip, raced[0].ip);
        assert_eq!(driver.dhcp_hosts(), vec![(r.mac.clone(), r.ip)]);
        assert_eq!(read(dir.path(), &vm("a")).unwrap(), Some(r));
        assert_eq!(
            driver.net_update_log(),
            vec![DhcpHostOp::Add, DhcpHostOp::Delete, DhcpHostOp::Add]
        );
    }

    #[tokio::test]
    async fn release_deletes_the_entry_and_the_record_and_is_idempotent() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        let a = ensure(&driver, dir.path(), &vm("a")).await.unwrap();
        let b = ensure(&driver, dir.path(), &vm("b")).await.unwrap();
        release(&driver, dir.path(), &vm("a")).await.unwrap();
        assert_eq!(read(dir.path(), &vm("a")).unwrap(), None);
        assert_eq!(driver.dhcp_hosts(), vec![(b.mac.clone(), b.ip)]);
        release(&driver, dir.path(), &vm("a")).await.unwrap();
        // The freed address can be handed out again.
        assert!(!driver.dhcp_hosts().iter().any(|(_, ip)| *ip == a.ip));
    }

    #[tokio::test]
    async fn a_failed_release_drops_the_record_and_reconcile_deletes_the_orphan() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        ensure(&driver, dir.path(), &vm("a")).await.unwrap();
        let b = ensure(&driver, dir.path(), &vm("b")).await.unwrap();
        driver.fail_net_updates(true);
        assert!(release(&driver, dir.path(), &vm("a")).await.is_err());
        assert_eq!(read(dir.path(), &vm("a")).unwrap(), None);
        assert_eq!(driver.dhcp_hosts().len(), 2, "the entry is still there");
        driver.fail_net_updates(false);
        // A domain still carries the orphan's MAC (its record was lost):
        // kept. Domains unreadable: kept.
        let a_mac = driver
            .dhcp_hosts()
            .into_iter()
            .find(|(m, _)| *m != b.mac)
            .unwrap()
            .0;
        let live = HashSet::from([a_mac]);
        let done = reconcile(&driver, dir.path(), &HashSet::new(), Some(&live))
            .await
            .unwrap();
        assert_eq!(done.orphans_deleted, 0);
        let done = reconcile(&driver, dir.path(), &HashSet::new(), None)
            .await
            .unwrap();
        assert_eq!(done.orphans_deleted, 0);
        assert_eq!(driver.dhcp_hosts().len(), 2);
        let done = reconcile(&driver, dir.path(), &HashSet::new(), Some(&HashSet::new()))
            .await
            .unwrap();
        assert_eq!(done.orphans_deleted, 1);
        assert_eq!(driver.dhcp_hosts(), vec![(b.mac, b.ip)]);
    }

    /// While the entry was gone a client leased the VM's address: it is
    /// put back anyway (dnsmasq returns the address once that lease ends)
    /// and the conflict reported.
    #[tokio::test]
    async fn reconcile_reports_a_reserved_address_leased_to_another_mac() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        let a = ensure(&driver, dir.path(), &vm("a")).await.unwrap();
        driver.clear_dhcp_hosts();
        driver.seed_dhcp_lease("52:54:00:00:00:09", a.ip);
        let done = reconcile(&driver, dir.path(), &HashSet::new(), Some(&HashSet::new()))
            .await
            .unwrap();
        assert_eq!((done.readded, done.leased_to_another), (1, 1));
        assert_eq!(driver.dhcp_hosts(), vec![(a.mac, a.ip)]);
    }

    #[tokio::test]
    async fn reconcile_readds_a_lost_entry_and_releases_gone_vms_only() {
        let driver = MockLibvirtDriver::new();
        let dir = tempfile::tempdir().unwrap();
        let a = ensure(&driver, dir.path(), &vm("a")).await.unwrap();
        ensure(&driver, dir.path(), &vm("b")).await.unwrap();
        // The network was redefined meanwhile: every entry is gone. A
        // foreign entry (not our prefix) is left alone.
        driver.clear_dhcp_hosts();
        driver.seed_dhcp_host("52:54:00:00:00:09", ip("192.168.122.250"));
        let done = reconcile(
            &driver,
            dir.path(),
            &HashSet::from([vm("b")]),
            Some(&HashSet::new()),
        )
        .await
        .unwrap();
        assert_eq!(
            done,
            Reconciled {
                readded: 1,
                orphans_deleted: 0,
                released: 1,
                leased_to_another: 0,
            }
        );
        let mut hosts = driver.dhcp_hosts();
        hosts.sort();
        let mut want = vec![
            ("52:54:00:00:00:09".to_string(), ip("192.168.122.250")),
            (a.mac, a.ip),
        ];
        want.sort();
        assert_eq!(hosts, want);
        assert_eq!(read(dir.path(), &vm("b")).unwrap(), None);
        // Nothing left to do.
        assert_eq!(
            reconcile(&driver, dir.path(), &HashSet::new(), Some(&HashSet::new()))
                .await
                .unwrap(),
            Reconciled::default()
        );
    }
}
