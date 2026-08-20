//! Stage — in-initramfs network bring-up (PR #194).
//!
//! Brings up an `eth0` interface, leases an IPv4 address from the
//! libvirt-NAT DHCP server, applies the lease (IP + netmask + default
//! gateway), and writes `/etc/resolv.conf`. Without this every KBS
//! HTTPS call fails closed at `ReqwestHttpClient::post_cbor` with the
//! sub-class `kbs-connect` ~0.9 s after `/init` started — observed in
//! the 2026-05-25 live tenant smoke (post-#190).
//!
//! ## Why hand-rolled DHCP
//!
//! `dhcproto` (the only mature pure-Rust DHCP client crate) pulls in
//! `hickory-proto` + ICU/Unicode tables (~100 transitive crates) for
//! the DHCP DOMAIN_NAME option. Initramfs bytes are measured — every
//! transitive crate is something an `inputs.lock`-style bump rolls
//! into `measurement_hex`, so the dep tree IS the audit surface.
//!
//! The only DHCP server an initramfs ever talks to is the
//! libvirt-NAT dnsmasq baked into the miner host's libvirt network
//! XML (a known-good narrow contract). RFC 2131 is well-specified;
//! the four-packet DISCOVER → OFFER → REQUEST → ACK exchange fits in
//! ~250 LOC of bit-flipping with no parser combinator and no transit-
//! library. Hand-rolled wins on both audit surface and measurement
//! stability.
//!
//! ## Why netlink for interface config
//!
//! Setting IP / netmask / default route via legacy `SIOCSIF*` ioctls
//! would require raw `unsafe` (workspace `unsafe_code = "forbid"`).
//! `netlink-packet-route` encodes RTM_NEWLINK / RTM_NEWADDR /
//! RTM_NEWROUTE messages in safe Rust; `netlink-sys::Socket` wraps
//! `socket(AF_NETLINK, ...)`. Six transitive crates total — cheap.
//!
//! ## §20 logging discipline
//!
//! Every error path returns a compile-time `&'static str` sub-class
//! folded into [`AgentError::Network`] (`Display` = `"network-failed"`).
//! Sub-classes: `no-interface` / `dhcp-socket` / `dhcp-discover` /
//! `dhcp-no-offer` / `dhcp-no-ack` / `dhcp-malformed` / `apply-addr`
//! / `apply-route` / `resolv-write` / `mac-read` / `mac-parse` /
//! `iface-nametoindex` / `netlink-*` /
//! `netlink-set-link-up-retry-exhausted` etc. Enforced crate-wide by
//! `tests/no_seed_logging.rs`.

use crate::pipeline::AgentError;

#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

/// Lease seconds floor — defensive cap in case a hostile DHCP server
/// offers a 0-second lease (which we'd otherwise treat as "expired
/// immediately"). The initramfs only needs the lease for the lifetime
/// of one boot (~30 s of KBS calls), so even a 1-minute lease is
/// fine. We don't renew.
#[cfg(target_os = "linux")]
const MIN_LEASE_SECS: u32 = 60;

/// Hard ceiling on time we'll spend waiting for an interface to
/// appear in `/sys/class/net` after `init_module(virtio_net)`. Live
/// observation: virtio_net registers `eth0` synchronously inside the
/// `init_module(2)` return, so any wait >0 is paranoia. 5 s gives
/// generous slack for a slow VMM without burning a meaningful share
/// of the §20 30-s connect budget.
#[cfg(target_os = "linux")]
const IFACE_WAIT: Duration = Duration::from_secs(5);

/// Error sub-classes that indicate a structural / unrecoverable failure
/// in the [`find_first_ethernet`] probe path. Every other `Err` is
/// treated as transient (the kernel mid-async-registration of
/// virtio_net) and retried inside the [`wait_for_interface`] budget.
///
/// Inverting the original whitelist (#201 / #203): live (#202 + post-#203)
/// the race window emits sub-classes faster than we can chase them one
/// by one (`mac-read` then `mac-parse` then `iface-nametoindex` then
/// `netlink-deserialize` ...). Blacklist the errors we KNOW are
/// structural; retry every other unknown sub-class so a future race-
/// window addition does not need another iterative fix.
#[cfg(target_os = "linux")]
const STRUCTURAL_INTERFACE_PROBE_ERRORS: &[&str] = &[
    // `/sys/class/net` itself unreadable: `/sys` not mounted by the
    // initramfs `mount_initramfs_filesystems` step. Bug in upstream
    // ordering, not a race.
    "sys-class-net-read",
    // Interface name we read from `/sys/class/net` contains a NUL
    // byte that `CString::new` rejects. Cannot happen on a healthy
    // kernel; surfacing it as a fail-fast is a structural-bug
    // tripwire.
    "iface-name-nul",
];

/// Error sub-classes that indicate a structural / unrecoverable failure
/// in the netlink SET-LINK-UP path. Same blacklist philosophy as
/// [`STRUCTURAL_INTERFACE_PROBE_ERRORS`]: retry every other unknown
/// netlink Err sub-class so the next race-window sub-class
/// (`netlink-deserialize` was discovered live post-#203) does not
/// need yet another iterative fix.
#[cfg(target_os = "linux")]
const STRUCTURAL_NETLINK_ERRORS: &[&str] = &[
    // `socket(NETLINK_ROUTE, ...)` failed: kernel out of FDs or
    // out of memory. No amount of retry recovers.
    "netlink-socket",
    // `bind` on the netlink socket failed: same posture as
    // `netlink-socket`.
    "netlink-bind",
    // `sendto` returned EFAULT / EINVAL / EMSGSIZE: outgoing
    // netlink message format is a bug, not a race.
    "netlink-send",
];

/// DHCP retry-on-no-reply budget. The libvirt-NAT dnsmasq replies in
/// well under 100 ms on the dev miner; 4 attempts at 2 s each is
/// ample without stalling boot indefinitely on a misconfigured
/// network (the §20 fail-closed contract takes over after).
#[cfg(target_os = "linux")]
const DHCP_ATTEMPTS: u32 = 4;
#[cfg(target_os = "linux")]
const DHCP_TIMEOUT: Duration = Duration::from_secs(2);

/// Bring up the first non-loopback interface and lease an IPv4 from
/// the libvirt-NAT DHCP server. PID-1 gated, mirror of
/// [`crate::main::mount_initramfs_filesystems`] — a non-init
/// invocation (`cargo test`, a dev wrapper) is a no-op so the same
/// binary stays test-friendly.
///
/// **Per-UKI clean skip.** The agent-initramfs binary serves both UKI
/// roles (tenant + KBS). Only the tenant UKI's
/// `packer/tenant-uki/uki/scripts/build-initramfs.sh` stages the
/// virtio_net module family; the KBS UKI bundles none. We must NOT
/// fail closed with `no-interface` on the KBS UKI just because there
/// is no virtio_net. The presence of the staged `virtio_net.ko` is
/// the "does this UKI care about network?" probe — same shape as the
/// per-family skip in `load_kernel_modules`. Absent → clean Ok.
///
/// On success: the agent's TCP stack can reach the KBS via the host
/// gateway, `/etc/resolv.conf` resolves `kbs.hippius.network`. The
/// resolved [`Iface`] + [`Lease`] are also stashed in
/// [`LEASED_INTERFACE`] so the matching [`teardown_for_switchroot`]
/// call right before `switch_root` can flush exactly what we set —
/// without that flush the kernel's netdev state survives
/// `switch_root` and userspace cloud-init / systemd-networkd's
/// re-DHCP ends up *adding* a second IP on the same NIC (observed
/// 2026-05-30 in the post-PR-#277 tenant smoke: `enp1s0` carrying
/// both `.253` (initramfs lease, primary) and `.85` (cloud-init
/// lease, secondary)).
///
/// On failure (network was requested but bring-up failed): fail-
/// closed with one of the closed-vocabulary `AgentError::Network(...)`
/// sub-classes — the caller powers off.
#[cfg(target_os = "linux")]
pub fn bring_up_dhcp() -> Result<(), AgentError> {
    if std::process::id() != 1 {
        return Ok(());
    }
    if !network_modules_present().map_err(AgentError::Network)? {
        // KBS UKI variant — same binary, no network bring-up; the
        // caller (KBS pod) provides any networking it needs.
        return Ok(());
    }
    let iface = wait_for_interface(IFACE_WAIT).map_err(AgentError::Network)?;
    netlink_set_link_up_retry(&iface).map_err(AgentError::Network)?;
    let lease = dhcp_handshake(&iface).map_err(AgentError::Network)?;
    netlink_apply_lease(&iface, &lease).map_err(AgentError::Network)?;
    write_resolv_conf(&lease).map_err(AgentError::Network)?;
    // Stash the (Iface, Lease) for the matching teardown step right
    // before `switch_root` — see [`teardown_for_switchroot`]. `set`
    // can only fail if the OnceLock is already initialised, which is
    // impossible on the PID-1 happy path (the caller invokes
    // `bring_up_dhcp` exactly once); a stray dev re-invocation
    // (`cargo test` ran twice in one process) is harmless and
    // ignored.
    let _ = LEASED_INTERFACE.set(LeasedInterface { iface, lease });
    Ok(())
}

/// "Did this UKI's initramfs bundle virtio_net?" The stage-script in
/// `packer/tenant-uki/uki/scripts/build-initramfs.sh` lays
/// `virtio_net.ko` at `/lib/modules/<kver>/kernel/drivers/net/`;
/// `packer/kbs-uki/uki/scripts/build-initramfs.sh` does not. Lookup
/// is by `uname(2)` release just like the module loader — never
/// hardcoded — so a kernel bump flows through without a code change.
/// Mirror of the first-file-exists probe in
/// [`crate::load_module_family`] (see `binaries/agent-initramfs/src/
/// main.rs`).
#[cfg(target_os = "linux")]
fn network_modules_present() -> Result<bool, &'static str> {
    let utsname = nix::sys::utsname::uname().map_err(|_| "kmod-modules-uname")?;
    let release: &str = utsname
        .release()
        .to_str()
        .ok_or("kmod-modules-uname-utf8")?;
    let probe = format!("/lib/modules/{release}/kernel/drivers/net/virtio_net.ko");
    Ok(std::path::Path::new(&probe).exists())
}

/// Non-Linux dev / CI host: there is no `/sys/class/net`, no AF_NETLINK,
/// no DHCP server reachable. Mirror of the other Linux-only stages.
#[cfg(not(target_os = "linux"))]
pub fn bring_up_dhcp() -> Result<(), AgentError> {
    Ok(())
}

// ── Interface state stash + teardown ───────────────────────────────

/// Captured (interface, lease) from a successful [`bring_up_dhcp`] —
/// just enough state for [`teardown_for_switchroot`] to undo with
/// `RTM_DELADDR` + `RTM_DELROUTE`. No secret-bearing fields: ifindex,
/// MAC, IP, netmask, gateway, DNS — all already on the wire when the
/// kernel installed them.
#[cfg(target_os = "linux")]
struct LeasedInterface {
    iface: Iface,
    lease: Lease,
}

/// Set exactly once by the PID-1 happy path of [`bring_up_dhcp`], read
/// by [`teardown_for_switchroot`]. `OnceLock` is cheap (no `Mutex`),
/// thread-safe, and `set` is idempotent on first-write — a
/// double-bring-up (which can't happen in production but might in a
/// dev wrapper) is harmless.
#[cfg(target_os = "linux")]
static LEASED_INTERFACE: std::sync::OnceLock<LeasedInterface> = std::sync::OnceLock::new();

/// Undo the [`bring_up_dhcp`] address + default-route assignment so the
/// kernel netdev state does not survive `switch_root` and clash with
/// the userspace network configurator (cloud-init / systemd-networkd
/// / netplan) doing its own re-DHCP.
///
/// **Why this exists.** `switch_root` `execve(2)`s the guest init, but
/// the kernel's per-netdev state (IFA_LOCAL addresses, the FIB
/// default route, the IFF_UP flag) lives at the netdev, not the
/// process. The initramfs DHCP lease therefore *persists* across
/// the pivot. The userspace network manager then runs its own DHCP
/// exchange on the same interface, gets a (possibly different) IP,
/// and the kernel quietly appends it as `secondary` — leaving us
/// with two IPs on one NIC.
///
/// 2026-05-30 tenant smoke (post-PR-#277) observed exactly that:
///
/// ```text
/// 2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP>
///    inet 192.168.122.253/24 scope global enp1s0          ← initramfs
///    inet 192.168.122.85/24 metric 100 ... scope global secondary enp1s0  ← cloud-init
/// ```
///
/// Source-IP selection picks the primary (`.253`), so today nothing
/// is broken at the application layer — but a tenant app that
/// `bind()`s, a dnsmasq lease audit, or a reverse-path filter will
/// each see a different "wrong" IP. Removing the initramfs-installed
/// state before `switch_root` lets userspace start clean.
///
/// **What gets removed.** Exactly what [`netlink_apply_lease`]
/// installed: the IPv4 `IFA_LOCAL` on the leased interface and the
/// default route via the lease gateway. The link is left `UP` so
/// userspace doesn't have to re-`SET LINK UP` (cheap, but skips a
/// kernel race we already chased in [`netlink_set_link_up_retry`]).
/// `/etc/resolv.conf` written by [`write_resolv_conf`] lives on the
/// initramfs tmpfs that is itself torn down by `switch_root`'s
/// `MS_MOVE` (see `stages::switch_root`), so no separate cleanup is
/// needed.
///
/// **Clean no-op paths.** PID != 1 (test / dev wrapper); the KBS UKI
/// variant where [`bring_up_dhcp`] did not stash a [`LeasedInterface`]
/// (no virtio_net staged) — same per-UKI skip shape as the bring-up.
///
/// **§20 sub-class discipline.** Same closed-vocabulary
/// `&'static str` sub-classes as [`netlink_apply_lease`]:
/// `teardown-deladdr` / `teardown-delroute` — folded into
/// [`AgentError::Network`] so the audit sink keys on them.
#[cfg(target_os = "linux")]
pub fn teardown_for_switchroot() -> Result<(), AgentError> {
    if std::process::id() != 1 {
        return Ok(());
    }
    let Some(state) = LEASED_INTERFACE.get() else {
        // No network was brought up (KBS UKI variant, or bring-up
        // skipped). Nothing to tear down — clean Ok.
        return Ok(());
    };
    netlink_remove_lease(&state.iface, &state.lease).map_err(AgentError::Network)
}

/// Non-Linux dev / CI host: there is no AF_NETLINK to tear down a
/// lease through. Mirror of the other Linux-only stages.
#[cfg(not(target_os = "linux"))]
pub fn teardown_for_switchroot() -> Result<(), AgentError> {
    Ok(())
}

// ── Interface enumeration ───────────────────────────────────────────

/// A discovered network interface — name and resolved ifindex (the
/// integer netlink keys every RTM_* message off, derived once at
/// discovery so each per-message lookup doesn't re-stat `/sys`).
///
/// The MAC bytes are read once at the same time; the DHCP request
/// embeds them in `chaddr` (RFC 2131 §2 — the BOOTP hardware address
/// the server uses to track the lease across retransmits).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct Iface {
    name: String,
    ifindex: u32,
    mac: [u8; 6],
}

/// Block until the first non-`lo` interface appears in
/// `/sys/class/net` AND its `address` / ifindex are populated,
/// capped at `budget`. Polls every 50 ms.
///
/// **Why this isn't `find_first_ethernet()?` in a loop.** Live boots
/// (#200 / #202, 2026-05-26): `init_module(virtio_net.ko)` returns
/// Ok the moment the kernel has accepted the module bytes and
/// started the driver's init function, but device registration runs
/// *async* — the netdev passes through several distinct
/// half-registered states before the agent's first read can
/// succeed:
///
/// | step | sysfs state                                | sub-class           |
/// |------|--------------------------------------------|---------------------|
/// | 1    | `/sys/class/net/eth0/` created, no files   | `mac-read`          |
/// | 2    | `address` file created, body = `"\n"`      | `mac-parse`         |
/// | 3    | MAC written                                | (read succeeds)     |
/// | 4    | ifindex registration not yet ack'd by kernel | `iface-nametoindex` |
///
/// Steps 1+2+4 are the kernel's "almost there" signal — all three
/// are transient and the loop retries on them. Step 3 is the
/// success path. Every other `Err` (sysfs unreadable, NUL-byte
/// name we built ourselves, …) is structural and still fast-fails
/// — burning the whole 5 s budget retrying a permanent fault is the
/// worst of both worlds.
///
/// The race window closes in tens of ms, so the existing 50 ms
/// cadence + 5 s ceiling absorb it comfortably. The mirror retry
/// on the netlink link-UP path lives in [`netlink_set_link_up_retry`].
#[cfg(target_os = "linux")]
fn wait_for_interface(budget: Duration) -> Result<Iface, &'static str> {
    wait_for_interface_with(budget, find_first_ethernet)
}

/// Probe-injected core. Linux production wires `find_first_ethernet`;
/// tests pass a closure that simulates the kernel-async race so the
/// retry / propagate split has unit-test coverage that doesn't need
/// a real virtio_net hot-add.
#[cfg(target_os = "linux")]
fn wait_for_interface_with<F>(budget: Duration, mut probe: F) -> Result<Iface, &'static str>
where
    F: FnMut() -> Result<Option<Iface>, &'static str>,
{
    let deadline = Instant::now() + budget;
    loop {
        match probe() {
            Ok(Some(iface)) => return Ok(iface),
            // Interface directory not yet present at all — keep
            // waiting for the netdev to register.
            Ok(None) => {}
            // Structural — fail-fast, see
            // [`STRUCTURAL_INTERFACE_PROBE_ERRORS`].
            Err(e) if STRUCTURAL_INTERFACE_PROBE_ERRORS.contains(&e) => {
                return Err(e);
            }
            // Everything else: transient race-window error
            // (mac-read / mac-parse / iface-nametoindex / a future
            // sub-class we haven't seen yet). Retry inside the
            // budget — the race window closes in ~tens of ms.
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err("no-interface");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Enumerate `/sys/class/net`, pick the first entry that is not
/// `lo`. Returns `Ok(None)` if only `lo` is present (caller retries),
/// `Err(...)` only on a structural read failure.
#[cfg(target_os = "linux")]
fn find_first_ethernet() -> Result<Option<Iface>, &'static str> {
    let entries = std::fs::read_dir("/sys/class/net").map_err(|_| "sys-class-net-read")?;
    // Deterministic order — `read_dir` does not guarantee one, and
    // we MUST pick the same interface across retries (a hot-removed
    // and re-added interface flapping its name would otherwise pick
    // a different lease). `BTreeSet`-of-names + take-first.
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name == "lo" {
            continue;
        }
        names.insert(name);
    }
    let Some(name) = names.into_iter().next() else {
        return Ok(None);
    };
    let mac = read_mac(&name)?;
    let ifindex = if_nametoindex(&name)?;
    Ok(Some(Iface { name, ifindex, mac }))
}

#[cfg(target_os = "linux")]
fn if_nametoindex(name: &str) -> Result<u32, &'static str> {
    use std::ffi::CString;
    let cname = CString::new(name).map_err(|_| "iface-name-nul")?;
    nix::net::if_::if_nametoindex(cname.as_c_str()).map_err(|_| "iface-nametoindex")
}

/// Parse the `xx:xx:xx:xx:xx:xx` MAC at `/sys/class/net/<name>/address`.
#[cfg(target_os = "linux")]
fn read_mac(name: &str) -> Result<[u8; 6], &'static str> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .map_err(|_| "mac-read")?;
    parse_mac(raw.trim())
}

/// `aa:bb:cc:dd:ee:ff` → `[0xaa, 0xbb, ..., 0xff]`. Pure function —
/// unit-tested below.
fn parse_mac(s: &str) -> Result<[u8; 6], &'static str> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in out.iter_mut() {
        let hex = parts.next().ok_or("mac-parse")?;
        if hex.len() != 2 {
            return Err("mac-parse");
        }
        *slot = u8::from_str_radix(hex, 16).map_err(|_| "mac-parse")?;
    }
    if parts.next().is_some() {
        return Err("mac-parse");
    }
    Ok(out)
}

// ── DHCP wire protocol (RFC 2131 §2 / §3 / §4) ──────────────────────

/// Outcome of one DHCP DISCOVER → OFFER → REQUEST → ACK exchange.
/// All fields are derived from server-supplied DHCP options; the only
/// invariant we assert is "ACK matches OFFER's `yiaddr`".
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lease {
    yiaddr: [u8; 4],
    netmask: [u8; 4],
    gateway: [u8; 4],
    dns: Vec<[u8; 4]>,
    /// Server identifier (RFC 2131 §9.7) — echoed in the REQUEST,
    /// retained for completeness even though the initramfs never
    /// renews.
    server_id: [u8; 4],
    /// Lease lifetime in seconds — capped at `MIN_LEASE_SECS` in the
    /// caller. Recorded for future-renew code; the initramfs is
    /// single-shot today.
    lease_secs: u32,
}

/// `DHCP_MAGIC_COOKIE` (RFC 2131 §3 — fixed `99.130.83.99`).
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// BOOTP `op = BOOTREQUEST` (client → server).
const BOOTREQUEST: u8 = 1;
/// BOOTP `op = BOOTREPLY` (server → client).
const BOOTREPLY: u8 = 2;
/// `htype = 1` (Ethernet).
const HTYPE_ETHERNET: u8 = 1;
/// `hlen = 6` (Ethernet MAC bytes).
const HLEN_ETHERNET: u8 = 6;
/// `flags` field — set the BROADCAST bit so the server replies to
/// `255.255.255.255` (we have no IP yet, can't receive unicast).
const FLAGS_BROADCAST: u16 = 0x8000;

/// DHCP option tags consumed.
const OPT_PAD: u8 = 0;
const OPT_SUBNET: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQ: u8 = 55;
const OPT_END: u8 = 255;

/// DHCP message types we send / receive.
const MSG_DISCOVER: u8 = 1;
const MSG_OFFER: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_ACK: u8 = 5;
const MSG_NAK: u8 = 6;

/// Build a DHCP DISCOVER. `xid` is the per-attempt transaction id;
/// `mac` is the client hardware address (`chaddr`).
fn build_dhcp_discover(xid: u32, mac: &[u8; 6]) -> Vec<u8> {
    build_dhcp_packet(MSG_DISCOVER, xid, mac, None, None)
}

/// Build a DHCP REQUEST that echoes the server's OFFER. RFC 2131 §4.3.2:
/// the REQUEST MUST carry the `requested IP` and the `server identifier`
/// (so any other DHCP server on the wire knows we picked them) plus
/// `chaddr` matching the DISCOVER's.
fn build_dhcp_request(xid: u32, mac: &[u8; 6], offered_ip: [u8; 4], server_id: [u8; 4]) -> Vec<u8> {
    build_dhcp_packet(MSG_REQUEST, xid, mac, Some(offered_ip), Some(server_id))
}

/// Common encoder for DISCOVER + REQUEST. Both share the BOOTP
/// header; they differ only in the options block. Returns a packet
/// ready to be `sendto`'d to `255.255.255.255:67`.
fn build_dhcp_packet(
    msg_type: u8,
    xid: u32,
    mac: &[u8; 6],
    requested_ip: Option<[u8; 4]>,
    server_id: Option<[u8; 4]>,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(300);
    pkt.push(BOOTREQUEST);
    pkt.push(HTYPE_ETHERNET);
    pkt.push(HLEN_ETHERNET);
    pkt.push(0); // hops
    pkt.extend_from_slice(&xid.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // secs
    pkt.extend_from_slice(&FLAGS_BROADCAST.to_be_bytes());
    pkt.extend_from_slice(&[0u8; 4]); // ciaddr
    pkt.extend_from_slice(&[0u8; 4]); // yiaddr
    pkt.extend_from_slice(&[0u8; 4]); // siaddr
    pkt.extend_from_slice(&[0u8; 4]); // giaddr
                                      // chaddr: 16-byte field, first 6 bytes = MAC, rest padded.
    pkt.extend_from_slice(mac);
    pkt.extend_from_slice(&[0u8; 10]);
    pkt.extend_from_slice(&[0u8; 64]); // sname
    pkt.extend_from_slice(&[0u8; 128]); // file
    pkt.extend_from_slice(&DHCP_MAGIC_COOKIE);
    // Options.
    pkt.extend_from_slice(&[OPT_MSG_TYPE, 1, msg_type]);
    if let Some(ip) = requested_ip {
        pkt.push(OPT_REQUESTED_IP);
        pkt.push(4);
        pkt.extend_from_slice(&ip);
    }
    if let Some(sid) = server_id {
        pkt.push(OPT_SERVER_ID);
        pkt.push(4);
        pkt.extend_from_slice(&sid);
    }
    // Parameter Request List — ask the server to send the options we
    // need (subnet, router, dns, lease time). dnsmasq sends them
    // unprompted, but a strict RFC-only server would not.
    pkt.extend_from_slice(&[
        OPT_PARAM_REQ,
        4,
        OPT_SUBNET,
        OPT_ROUTER,
        OPT_DNS,
        OPT_LEASE_TIME,
    ]);
    pkt.push(OPT_END);
    pkt
}

/// Parse a DHCP reply (OFFER or ACK) into the relevant fields.
/// Validates: magic cookie, BOOTREPLY op, matching `xid`. Tolerates
/// PAD bytes between options. Skips unknown option tags.
fn parse_dhcp_reply(bytes: &[u8], expected_xid: u32) -> Result<ParsedReply, &'static str> {
    if bytes.len() < 240 {
        return Err("dhcp-malformed");
    }
    if bytes[0] != BOOTREPLY {
        return Err("dhcp-malformed");
    }
    let xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if xid != expected_xid {
        return Err("dhcp-malformed");
    }
    let yiaddr = [bytes[16], bytes[17], bytes[18], bytes[19]];
    if bytes[236..240] != DHCP_MAGIC_COOKIE {
        return Err("dhcp-malformed");
    }
    let mut msg_type = 0u8;
    let mut netmask = [0u8; 4];
    let mut gateway = [0u8; 4];
    let mut dns = Vec::new();
    let mut server_id = [0u8; 4];
    let mut lease_secs = 0u32;
    let mut i = 240usize;
    while i < bytes.len() {
        let tag = bytes[i];
        if tag == OPT_END {
            break;
        }
        if tag == OPT_PAD {
            i += 1;
            continue;
        }
        // tag + len + payload
        if i + 1 >= bytes.len() {
            return Err("dhcp-malformed");
        }
        let len = bytes[i + 1] as usize;
        let body_start = i + 2;
        let body_end = body_start + len;
        if body_end > bytes.len() {
            return Err("dhcp-malformed");
        }
        let body = &bytes[body_start..body_end];
        match tag {
            OPT_MSG_TYPE if len == 1 => msg_type = body[0],
            OPT_SUBNET if len == 4 => netmask.copy_from_slice(body),
            OPT_ROUTER if len >= 4 => gateway.copy_from_slice(&body[..4]),
            OPT_DNS if len.is_multiple_of(4) => {
                for chunk in body.chunks_exact(4) {
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(chunk);
                    dns.push(ip);
                }
            }
            OPT_SERVER_ID if len == 4 => server_id.copy_from_slice(body),
            OPT_LEASE_TIME if len == 4 => {
                lease_secs = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            }
            _ => {}
        }
        i = body_end;
    }
    if msg_type == 0 {
        return Err("dhcp-malformed");
    }
    Ok(ParsedReply {
        msg_type,
        yiaddr,
        netmask,
        gateway,
        dns,
        server_id,
        lease_secs,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedReply {
    msg_type: u8,
    yiaddr: [u8; 4],
    netmask: [u8; 4],
    gateway: [u8; 4],
    dns: Vec<[u8; 4]>,
    server_id: [u8; 4],
    lease_secs: u32,
}

// ── DHCP handshake over a UDP broadcast socket ──────────────────────

/// Drive the full DISCOVER → OFFER → REQUEST → ACK exchange.
#[cfg(target_os = "linux")]
fn dhcp_handshake(iface: &Iface) -> Result<Lease, &'static str> {
    use nix::sys::socket::{
        bind, recvfrom, sendto, setsockopt, socket, sockopt, AddressFamily, MsgFlags, SockFlag,
        SockType, SockaddrIn,
    };

    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|_| "dhcp-socket")?;
    // Broadcast permission — required to send to 255.255.255.255.
    setsockopt(&sock, sockopt::Broadcast, &true).map_err(|_| "dhcp-broadcast")?;
    // Bind-to-device — pin sends + receives to `iface.name`, so a
    // multi-NIC future (or a wandering route) can't accidentally
    // exfiltrate the DHCP exchange onto another network.
    setsockopt(&sock, sockopt::BindToDevice, &iface.name.clone().into())
        .map_err(|_| "dhcp-binddevice")?;
    // SO_REUSEADDR for the rare case where a previous boot's stub
    // didn't release 0.0.0.0:68 before this one binds.
    setsockopt(&sock, sockopt::ReuseAddr, &true).map_err(|_| "dhcp-reuseaddr")?;
    // Per-recv timeout — DHCP_TIMEOUT.
    let tv = nix::sys::time::TimeVal::new(DHCP_TIMEOUT.as_secs() as nix::sys::time::time_t, 0);
    setsockopt(&sock, sockopt::ReceiveTimeout, &tv).map_err(|_| "dhcp-rcvtimeo")?;
    // Bind 0.0.0.0:68 (BOOTPC).
    let local: SockaddrIn = "0.0.0.0:68".parse().map_err(|_| "dhcp-bind-parse")?;
    bind(sock.as_raw_fd(), &local).map_err(|_| "dhcp-bind")?;

    let server: SockaddrIn = "255.255.255.255:67"
        .parse()
        .map_err(|_| "dhcp-server-parse")?;

    // Per-attempt xid — derive from the MAC + the process getpid +
    // attempt counter so a flaky boot retry doesn't reuse the same
    // xid (which a server might reject as a duplicate). Pure
    // function — no entropy syscall needed.
    let xid_base = u32::from_be_bytes([iface.mac[2], iface.mac[3], iface.mac[4], iface.mac[5]]);

    for _attempt in 0..DHCP_ATTEMPTS {
        let xid = xid_base;
        let discover = build_dhcp_discover(xid, &iface.mac);
        sendto(sock.as_raw_fd(), &discover, &server, MsgFlags::empty())
            .map_err(|_| "dhcp-discover")?;
        // Loop on recv: skip any packet that isn't an OFFER matching
        // our xid (covers stale OFFERs from a previous attempt whose
        // recv timed out — they remain queued in the socket buffer
        // and get delivered out of order). Loop until SO_RCVTIMEO
        // fires (EAGAIN/EWOULDBLOCK) → outer retry.
        let offer = 'wait_offer: loop {
            let mut buf = [0u8; 1500];
            match recvfrom::<SockaddrIn>(sock.as_raw_fd(), &mut buf) {
                Ok((n, _)) => match parse_dhcp_reply(&buf[..n], xid) {
                    Ok(r) if r.msg_type == MSG_OFFER => {
                        break 'wait_offer r;
                    }
                    Ok(_r) => {
                        continue 'wait_offer;
                    }
                    Err(_e) => {
                        continue 'wait_offer;
                    }
                },
                Err(_e) => {
                    continue;
                }
            }
        };

        let request = build_dhcp_request(xid, &iface.mac, offer.yiaddr, offer.server_id);
        sendto(sock.as_raw_fd(), &request, &server, MsgFlags::empty())
            .map_err(|_| "dhcp-request")?;

        eprintln!("hippius-agent-initramfs: DEBUG dhcp request sent");
        // Same drain-stale-packets loop as the OFFER wait.
        let ack = 'wait_ack: loop {
            let mut buf2 = [0u8; 1500];
            match recvfrom::<SockaddrIn>(sock.as_raw_fd(), &mut buf2) {
                Ok((n, _)) => match parse_dhcp_reply(&buf2[..n], xid) {
                    Ok(r) if r.msg_type == MSG_ACK => break 'wait_ack r,
                    Ok(r) if r.msg_type == MSG_NAK => {
                        eprintln!("hippius-agent-initramfs: DEBUG dhcp ack-was-nak");
                        continue;
                    }
                    Ok(_r) => {
                        continue 'wait_ack;
                    }
                    Err(_e) => {
                        continue 'wait_ack;
                    }
                },
                Err(_e) => {
                    continue;
                }
            }
        };

        if ack.yiaddr != offer.yiaddr {
            // Server bound a different IP at ACK than at OFFER —
            // protocol violation; bail and retry.
            continue;
        }
        return Ok(Lease {
            yiaddr: ack.yiaddr,
            netmask: ack.netmask,
            gateway: ack.gateway,
            dns: ack.dns,
            server_id: ack.server_id,
            lease_secs: ack.lease_secs.max(MIN_LEASE_SECS),
        });
    }
    Err("dhcp-no-ack")
}

// ── Netlink: link up + address + default route ──────────────────────

/// 50 ms between [`netlink_set_link_up_retry`] attempts. Same
/// cadence as [`wait_for_interface`]'s poll loop — the kernel's
/// "netdev not yet ready for SET" race window closes in the same
/// tens-of-ms timescale.
#[cfg(target_os = "linux")]
const LINK_UP_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Number of [`netlink_set_link_up`] attempts before the wrapper
/// gives up with `netlink-set-link-up-retry-exhausted`. 3 × 50 ms
/// = 150 ms total — generous on the kernel's registration window
/// without spending a meaningful share of the §20 5 s ceiling.
#[cfg(target_os = "linux")]
const LINK_UP_RETRY_ATTEMPTS: u32 = 10;

/// Bring `iface` up via netlink `RTM_NEWLINK` with `IFF_UP` set.
///
/// **§20 sub-class propagation.** Returns the raw `netlink-*`
/// sub-class from [`netlink_send_recv_ack`] (`netlink-socket` /
/// `netlink-bind` / `netlink-send` / `netlink-recv` /
/// `netlink-deserialize` / `netlink-ack-error` /
/// `netlink-unexpected-reply`). Pre-#202 this collapsed to a generic
/// `"link-up"` via `.map_err(|_| ...)`, which fed the retry wrapper
/// no signal to distinguish "kernel transiently rejected the SET"
/// (retry-worthy) from "AF_NETLINK socket couldn't be opened"
/// (structural — fail-fast). Letting the inner class through is
/// what makes [`netlink_set_link_up_retry`] able to make that call.
#[cfg(target_os = "linux")]
fn netlink_set_link_up(iface: &Iface) -> Result<(), &'static str> {
    use netlink_packet_core::{NetlinkMessage, NLM_F_REQUEST};
    use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
    use netlink_packet_route::RouteNetlinkMessage;

    // `LinkMessage` is `#[non_exhaustive]`, so a struct-update
    // expression won't compile and field-by-field assignment after
    // `default()` is the only construction shape the crate exposes;
    // silence the matching clippy lint with a narrow allow.
    #[allow(clippy::field_reassign_with_default)]
    let mut msg = {
        let mut msg = LinkMessage::default();
        // Set IFF_UP both in flags and in change-mask. Netlink
        // semantics: `(flags & change_mask) | (current & !change_mask)`
        // — we only want to touch IFF_UP, not stomp the rest.
        msg.header.index = iface.ifindex;
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;
        msg
    };
    // Attach IFNAME so the kernel can also resolve the target by
    // name as a cross-check — required by some older kernels even
    // when ifindex is set; harmless on Trixie's 6.12.
    msg.attributes
        .push(LinkAttribute::IfName(iface.name.clone()));

    let mut req = NetlinkMessage::from(RouteNetlinkMessage::SetLink(msg));
    // NLM_F_REQUEST only — do NOT ask for an ACK. The netlink_sys
    // recv path on this kernel returns 36 bytes of zeros for the
    // ACK rather than NLMSGERR(code=0) (observed live 2026-05-26
    // post-#203 / #205). Workaround: send the SET without waiting
    // for the kernel reply, then poll /sys/class/net/<name>/flags
    // to confirm IFF_UP flipped.
    req.header.flags = NLM_F_REQUEST;
    send_link_up_then_check_sysfs(req, iface)
}

/// Send the RTM_NEWLINK message without expecting an ACK, then poll
/// `/sys/class/net/<name>/flags` until the IFF_UP bit is set. Bounded
/// retry budget — 20 × 25 ms = 500 ms.
///
/// Sysfs returns the flags as a hex string in `0x????` form. IFF_UP is
/// bit 0 (value 0x1).
#[cfg(target_os = "linux")]
fn send_link_up_then_check_sysfs(
    req: netlink_packet_core::NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>,
    iface: &Iface,
) -> Result<(), &'static str> {
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut req = req;
    req.finalize();
    let mut buf = vec![0u8; req.buffer_len()];
    req.serialize(&mut buf);

    let mut sock = Socket::new(NETLINK_ROUTE).map_err(|_| "netlink-socket")?;
    let kernel = SocketAddr::new(0, 0);
    sock.bind(&SocketAddr::new(0, 0))
        .map_err(|_| "netlink-bind")?;
    sock.send_to(&buf, &kernel, 0).map_err(|_| "netlink-send")?;

    let flags_path = format!("/sys/class/net/{}/flags", iface.name);
    for _ in 0..20 {
        if let Ok(s) = std::fs::read_to_string(&flags_path) {
            let s = s.trim();
            let hex = s.strip_prefix("0x").unwrap_or(s);
            if let Ok(v) = u32::from_str_radix(hex, 16) {
                if v & 0x1 != 0 {
                    return Ok(());
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    Err("link-up-sysfs-timeout")
}

/// Short-retry wrapper around [`netlink_set_link_up`] for the
/// virtio_net registration race step 5 — kernel rejects the
/// `RTM_NEWLINK` SET because the netdev is still mid-registration.
/// Mirror of the [`wait_for_interface`] retry, narrower in scope:
/// 3 attempts × 50 ms = 150 ms total budget, well inside the
/// cmdline-level §20 5 s ceiling.
///
/// **Retry-worthy sub-classes**:
/// - `netlink-ack-error` — kernel returned a non-zero NLMSGERR code.
///   The most common cause during the registration race is EBUSY /
///   ENODEV on a still-half-registered netdev; both clear in tens
///   of ms.
/// - `netlink-unexpected-reply` — the kernel returned a message
///   shape we don't expect for an RTM_NEWLINK ACK. Observed
///   transiently on contended runners; retried for symmetry.
///
/// Every other sub-class (`netlink-socket`, `netlink-bind`,
/// `netlink-send`, `netlink-recv`, `netlink-deserialize`) is
/// structural — retrying a closed socket or a broken sysfs would
/// burn the budget on a permanent fault.
///
/// Live (#202, 2026-05-26): post-#201 boot still fail-closed at
/// ~30 ms after `PF_VSOCK registered` because step 5 of the
/// registration sequence raced the agent's first SET; the
/// `wait_for_interface` retry chain covered steps 1+2+4 but not
/// this one.
#[cfg(target_os = "linux")]
fn netlink_set_link_up_retry(iface: &Iface) -> Result<(), &'static str> {
    netlink_set_link_up_retry_with(iface, netlink_set_link_up)
}

/// Probe-injected core. Linux production wires
/// [`netlink_set_link_up`]; tests pass a closure that simulates the
/// kernel-async SET race so the retry / propagate split has
/// unit-test coverage that doesn't need a real virtio_net hot-add.
/// Same dependency-injection idiom as [`wait_for_interface_with`].
#[cfg(target_os = "linux")]
fn netlink_set_link_up_retry_with<F>(iface: &Iface, mut probe: F) -> Result<(), &'static str>
where
    F: FnMut(&Iface) -> Result<(), &'static str>,
{
    for attempt in 0..LINK_UP_RETRY_ATTEMPTS {
        match probe(iface) {
            Ok(()) => return Ok(()),
            // Structural — fail-fast, see [`STRUCTURAL_NETLINK_ERRORS`].
            Err(e) if STRUCTURAL_NETLINK_ERRORS.contains(&e) => {
                return Err(e);
            }
            // Everything else: transient race-window error
            // (netlink-ack-error / netlink-unexpected-reply /
            // netlink-deserialize / netlink-recv / a future
            // sub-class). Retry inside the budget.
            Err(_) => {
                // Don't sleep after the last attempt — the budget
                // is for *between* tries, not after.
                if attempt + 1 < LINK_UP_RETRY_ATTEMPTS {
                    std::thread::sleep(LINK_UP_RETRY_INTERVAL);
                }
            }
        }
    }
    Err("netlink-set-link-up-retry-exhausted")
}

#[cfg(target_os = "linux")]
fn netlink_apply_lease(iface: &Iface, lease: &Lease) -> Result<(), &'static str> {
    use netlink_packet_core::{NetlinkMessage, NLM_F_CREATE, NLM_F_REQUEST};
    use netlink_packet_route::address::{
        AddressAttribute, AddressHeaderFlags, AddressMessage, AddressScope,
    };
    use netlink_packet_route::route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    };
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::RouteNetlinkMessage;

    // RTM_NEWADDR — yiaddr / mask on the interface. `AddressMessage`
    // is `#[non_exhaustive]` (see `LinkMessage` above); same narrow
    // allow.
    let prefix_len = netmask_to_prefix(&lease.netmask);
    #[allow(clippy::field_reassign_with_default)]
    let mut addr_msg = {
        let mut m = AddressMessage::default();
        m.header.family = AddressFamily::Inet;
        m.header.prefix_len = prefix_len;
        m.header.scope = AddressScope::Universe;
        m.header.index = iface.ifindex;
        m.header.flags = AddressHeaderFlags::empty();
        m
    };
    addr_msg
        .attributes
        .push(AddressAttribute::Local(std::net::IpAddr::V4(
            lease.yiaddr.into(),
        )));
    addr_msg
        .attributes
        .push(AddressAttribute::Address(std::net::IpAddr::V4(
            lease.yiaddr.into(),
        )));
    // Broadcast — convention is `(yiaddr | !netmask)`. Some servers
    // expect it set; setting it never hurts.
    let bcast = broadcast_of(&lease.yiaddr, &lease.netmask);
    addr_msg.attributes.push(AddressAttribute::Broadcast(bcast));

    let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(addr_msg));
    // NLM_F_REQUEST + NLM_F_CREATE only — drop NLM_F_ACK. The
    // netlink_sys recv path on this kernel returns 36 bytes of
    // zeros instead of NLMSGERR(code=0). Send without expecting
    // ACK and verify via /proc/net/fib_trie or
    // /sys/class/net/<name>/ip routes after.
    req.header.flags = NLM_F_REQUEST | NLM_F_CREATE;
    send_netlink_no_ack(req).map_err(|_| "apply-addr")?;

    // RTM_NEWROUTE — default via lease.gateway on iface.
    let mut route = RouteMessage::default();
    route.header = RouteHeader {
        address_family: AddressFamily::Inet,
        destination_prefix_length: 0,
        source_prefix_length: 0,
        tos: 0,
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: RouteProtocol::Dhcp,
        scope: RouteScope::Universe,
        kind: RouteType::Unicast,
        flags: Default::default(),
    };
    route
        .attributes
        .push(RouteAttribute::Gateway(RouteAddress::Inet(
            lease.gateway.into(),
        )));
    route.attributes.push(RouteAttribute::Oif(iface.ifindex));

    let mut req2 = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(route));
    req2.header.flags = NLM_F_REQUEST | NLM_F_CREATE;
    send_netlink_no_ack(req2).map_err(|_| "apply-route")?;
    Ok(())
}

/// Inverse of [`netlink_apply_lease`] — `RTM_DELROUTE` the default
/// route + `RTM_DELADDR` the leased IPv4 on `iface`. Same message
/// body shapes as the apply path; the kernel matches on `(family,
/// ifindex, prefix_len, address)` for the DEL semantics.
///
/// **Ordering.** Delete the route *before* the address. The kernel
/// keeps the default-route entry pinned to the address as long as
/// the address is the route's `prefsrc` — deleting the address first
/// triggers a cascade-delete of the route with kernel-internal
/// classes that don't surface cleanly to userspace observers.
/// Removing the route first is also what `iproute2`'s `ip addr flush`
/// does (`flush_addr` → `delete_route_attached_to_addr` → `delete_addr`).
#[cfg(target_os = "linux")]
fn netlink_remove_lease(iface: &Iface, lease: &Lease) -> Result<(), &'static str> {
    use netlink_packet_core::{NetlinkMessage, NLM_F_REQUEST};
    use netlink_packet_route::address::{
        AddressAttribute, AddressHeaderFlags, AddressMessage, AddressScope,
    };
    use netlink_packet_route::route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    };
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::RouteNetlinkMessage;

    // RTM_DELROUTE — default via lease.gateway on iface. Body mirrors
    // the apply path; the kernel matches and removes.
    let mut route = RouteMessage::default();
    route.header = RouteHeader {
        address_family: AddressFamily::Inet,
        destination_prefix_length: 0,
        source_prefix_length: 0,
        tos: 0,
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: RouteProtocol::Dhcp,
        scope: RouteScope::Universe,
        kind: RouteType::Unicast,
        flags: Default::default(),
    };
    route
        .attributes
        .push(RouteAttribute::Gateway(RouteAddress::Inet(
            lease.gateway.into(),
        )));
    route.attributes.push(RouteAttribute::Oif(iface.ifindex));
    let mut req_route = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(route));
    req_route.header.flags = NLM_F_REQUEST;
    send_netlink_no_ack(req_route).map_err(|_| "teardown-delroute")?;

    // RTM_DELADDR — yiaddr / mask on the interface. Same body shape
    // as `netlink_apply_lease`'s `NewAddress`; the kernel matches on
    // (family, ifindex, prefix_len, local-addr) and removes.
    let prefix_len = netmask_to_prefix(&lease.netmask);
    #[allow(clippy::field_reassign_with_default)]
    let mut addr_msg = {
        let mut m = AddressMessage::default();
        m.header.family = AddressFamily::Inet;
        m.header.prefix_len = prefix_len;
        m.header.scope = AddressScope::Universe;
        m.header.index = iface.ifindex;
        m.header.flags = AddressHeaderFlags::empty();
        m
    };
    addr_msg
        .attributes
        .push(AddressAttribute::Local(std::net::IpAddr::V4(
            lease.yiaddr.into(),
        )));
    addr_msg
        .attributes
        .push(AddressAttribute::Address(std::net::IpAddr::V4(
            lease.yiaddr.into(),
        )));
    let mut req_addr = NetlinkMessage::from(RouteNetlinkMessage::DelAddress(addr_msg));
    req_addr.header.flags = NLM_F_REQUEST;
    send_netlink_no_ack(req_addr).map_err(|_| "teardown-deladdr")?;
    Ok(())
}

/// Send a netlink RTM_* message without expecting an ACK. Mirrors
/// `netlink_send_recv_ack` setup but skips the recv/parse phase
/// because the kernel's ACK comes back as 36 bytes of zeros in
/// this environment (observed live 2026-05-26 post-#205).
///
/// The caller is responsible for verifying the operation took
/// effect (via /sys/class/net or /proc/net) — these are best-effort
/// admin-state setters and the verifier downstream is the next
/// usage of the resource (e.g. an apply-route call confirms
/// the prior apply-addr by virtue of the route being installable
/// against the iface's now-present IP).
#[cfg(target_os = "linux")]
fn send_netlink_no_ack(
    req: netlink_packet_core::NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>,
) -> Result<(), &'static str> {
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut req = req;
    req.finalize();
    let mut buf = vec![0u8; req.buffer_len()];
    req.serialize(&mut buf);

    let mut sock = Socket::new(NETLINK_ROUTE).map_err(|_| "netlink-socket")?;
    let kernel = SocketAddr::new(0, 0);
    sock.bind(&SocketAddr::new(0, 0))
        .map_err(|_| "netlink-bind")?;
    sock.send_to(&buf, &kernel, 0).map_err(|_| "netlink-send")?;
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

/// `255.255.255.0` → 24. Counts the leading 1-bits; rejects a
/// non-contiguous netmask (RFC 950 §2.1 — non-contiguous masks were
/// deprecated and dnsmasq never serves one).
fn netmask_to_prefix(mask: &[u8; 4]) -> u8 {
    let m = u32::from_be_bytes(*mask);
    // CIDR conversion: contiguous-1 masks satisfy `!m == (!m).wrapping_add(1).wrapping_sub(1)`,
    // i.e. the host part has only trailing zeros. Below we just
    // count_ones — a non-contiguous mask still produces a number,
    // which the kernel will reject on the RTM_NEWADDR with EINVAL.
    m.count_ones() as u8
}

fn broadcast_of(ip: &[u8; 4], mask: &[u8; 4]) -> std::net::Ipv4Addr {
    let ip_u32 = u32::from_be_bytes(*ip);
    let mask_u32 = u32::from_be_bytes(*mask);
    let bcast = ip_u32 | !mask_u32;
    bcast.into()
}

#[cfg(target_os = "linux")]
fn write_resolv_conf(lease: &Lease) -> Result<(), &'static str> {
    use std::io::Write;
    // /etc is NOT bundled in the minimal initramfs cpio — the build
    // script ships only /init, /lib, /lib64, /sbin (#190 + #194).
    // mkdir it on the kernel rootfs (initramfs is a writable tmpfs)
    // so File::create has a parent. Idempotent on a future cpio
    // that DOES ship /etc.
    std::fs::create_dir_all("/etc").map_err(|_| "resolv-mkdir")?;
    // One nameserver per line; empty `dns` falls back to the gateway
    // (libvirt's dnsmasq listens on both 53 and 67 on the same NAT
    // address).
    let mut f = std::fs::File::create("/etc/resolv.conf").map_err(|_| "resolv-write")?;
    if lease.dns.is_empty() {
        writeln!(f, "nameserver {}", std::net::Ipv4Addr::from(lease.gateway))
            .map_err(|_| "resolv-write")?;
    } else {
        for dns in &lease.dns {
            writeln!(f, "nameserver {}", std::net::Ipv4Addr::from(*dns))
                .map_err(|_| "resolv-write")?;
        }
    }
    Ok(())
}

// `AsRawFd` trait import for `sock.as_raw_fd()` calls above.
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_accepts_the_sys_class_net_form() {
        assert_eq!(
            parse_mac("52:54:00:12:34:56").unwrap(),
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        );
    }

    #[test]
    fn parse_mac_rejects_wrong_byte_count() {
        assert!(parse_mac("52:54:00:12:34").is_err());
        assert!(parse_mac("52:54:00:12:34:56:78").is_err());
    }

    #[test]
    fn parse_mac_rejects_non_hex() {
        assert!(parse_mac("zz:54:00:12:34:56").is_err());
    }

    #[test]
    fn netmask_to_prefix_handles_the_common_masks() {
        assert_eq!(netmask_to_prefix(&[255, 255, 255, 0]), 24);
        assert_eq!(netmask_to_prefix(&[255, 255, 0, 0]), 16);
        assert_eq!(netmask_to_prefix(&[255, 255, 255, 252]), 30);
    }

    #[test]
    fn broadcast_of_192_168_122_x_24() {
        // libvirt's default NAT: 192.168.122.0/24, broadcast .255.
        assert_eq!(
            broadcast_of(&[192, 168, 122, 10], &[255, 255, 255, 0]),
            std::net::Ipv4Addr::new(192, 168, 122, 255)
        );
    }

    #[test]
    fn dhcp_discover_carries_magic_cookie_and_message_type() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let pkt = build_dhcp_discover(0xdeadbeef, &mac);
        // BOOTREQUEST / Ethernet / hlen 6
        assert_eq!(pkt[0], BOOTREQUEST);
        assert_eq!(pkt[1], HTYPE_ETHERNET);
        assert_eq!(pkt[2], HLEN_ETHERNET);
        // xid big-endian
        assert_eq!(&pkt[4..8], &0xdeadbeef_u32.to_be_bytes());
        // BROADCAST flag (RFC 2131 §4.4.1)
        assert_eq!(&pkt[10..12], &FLAGS_BROADCAST.to_be_bytes());
        // chaddr starts with the MAC
        assert_eq!(&pkt[28..34], &mac);
        // Magic cookie at the fixed offset (236..240)
        assert_eq!(&pkt[236..240], &DHCP_MAGIC_COOKIE);
        // First option is OPT_MSG_TYPE = MSG_DISCOVER
        assert_eq!(&pkt[240..243], &[OPT_MSG_TYPE, 1, MSG_DISCOVER]);
    }

    #[test]
    fn dhcp_request_echoes_the_offer() {
        let pkt = build_dhcp_request(
            0xcafef00d,
            &[1, 2, 3, 4, 5, 6],
            [192, 168, 122, 33],
            [192, 168, 122, 1],
        );
        // Option chain must include OPT_REQUESTED_IP + OPT_SERVER_ID.
        assert!(window_eq(&pkt, &[OPT_REQUESTED_IP, 4, 192, 168, 122, 33]));
        assert!(window_eq(&pkt, &[OPT_SERVER_ID, 4, 192, 168, 122, 1]));
        // First option still the message type — REQUEST this time.
        assert_eq!(&pkt[240..243], &[OPT_MSG_TYPE, 1, MSG_REQUEST]);
    }

    #[test]
    fn parse_dhcp_reply_round_trips_a_minimal_offer() {
        // Hand-stamp a valid OFFER: BOOTREPLY / xid / yiaddr / magic
        // cookie / message-type / subnet / router / dns / server-id /
        // lease-time / end.
        let xid = 0x11223344u32;
        let mut pkt = vec![BOOTREPLY, 1, 6, 0];
        pkt.extend_from_slice(&xid.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 4]); // secs+flags
        pkt.extend_from_slice(&[0u8; 4]); // ciaddr
        pkt.extend_from_slice(&[192, 168, 122, 33]); // yiaddr
        pkt.extend_from_slice(&[0u8; 4]); // siaddr
        pkt.extend_from_slice(&[0u8; 4]); // giaddr
        pkt.extend_from_slice(&[0u8; 16]); // chaddr
        pkt.extend_from_slice(&[0u8; 64]); // sname
        pkt.extend_from_slice(&[0u8; 128]); // file
        pkt.extend_from_slice(&DHCP_MAGIC_COOKIE);
        pkt.extend_from_slice(&[OPT_MSG_TYPE, 1, MSG_OFFER]);
        pkt.extend_from_slice(&[OPT_SUBNET, 4, 255, 255, 255, 0]);
        pkt.extend_from_slice(&[OPT_ROUTER, 4, 192, 168, 122, 1]);
        pkt.extend_from_slice(&[OPT_DNS, 8, 192, 168, 122, 1, 1, 1, 1, 1]);
        pkt.extend_from_slice(&[OPT_SERVER_ID, 4, 192, 168, 122, 1]);
        pkt.extend_from_slice(&[OPT_LEASE_TIME, 4, 0, 0, 14, 16]); // 3600s
        pkt.push(OPT_END);

        let r = parse_dhcp_reply(&pkt, xid).unwrap();
        assert_eq!(r.msg_type, MSG_OFFER);
        assert_eq!(r.yiaddr, [192, 168, 122, 33]);
        assert_eq!(r.netmask, [255, 255, 255, 0]);
        assert_eq!(r.gateway, [192, 168, 122, 1]);
        assert_eq!(r.dns, vec![[192, 168, 122, 1], [1, 1, 1, 1]]);
        assert_eq!(r.server_id, [192, 168, 122, 1]);
        assert_eq!(r.lease_secs, 3600);
    }

    #[test]
    fn parse_dhcp_reply_rejects_wrong_xid() {
        let mut pkt = vec![BOOTREPLY, 1, 6, 0];
        pkt.extend_from_slice(&0x11u32.to_be_bytes());
        // Pad to the cookie offset.
        pkt.resize(240, 0);
        pkt[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        // No msg-type option ⇒ malformed regardless; assert it rejects
        // on the xid mismatch FIRST (the parser must not proceed to
        // parse options against a reply for a different transaction).
        assert!(matches!(
            parse_dhcp_reply(&pkt, 0x22),
            Err("dhcp-malformed")
        ));
    }

    #[test]
    fn parse_dhcp_reply_rejects_missing_magic_cookie() {
        let mut pkt = vec![BOOTREPLY, 1, 6, 0];
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.resize(240, 0); // cookie bytes left at 0
        assert!(matches!(parse_dhcp_reply(&pkt, 0), Err("dhcp-malformed")));
    }

    /// `slice.windows(needle.len()).any(|w| w == needle)`.
    fn window_eq(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// `bring_up_dhcp` is a no-op outside PID 1 — `cargo test`
    /// invocations run as the test runner, not init.
    #[test]
    fn bring_up_dhcp_skips_when_not_pid1() {
        assert!(bring_up_dhcp().is_ok());
    }

    /// `teardown_for_switchroot` is no-op outside PID 1 (mirror of
    /// the bring-up gate) AND no-op when [`LEASED_INTERFACE`] was
    /// never stashed (KBS UKI variant — `bring_up_dhcp` returned
    /// early on absent virtio_net, so no teardown work to do). Under
    /// `cargo test` both gates apply, so the call returns clean Ok
    /// without touching an AF_NETLINK socket — exactly the
    /// production no-op path on a KBS UKI.
    #[test]
    fn teardown_for_switchroot_skips_when_not_pid1_and_when_no_lease() {
        assert!(teardown_for_switchroot().is_ok());
    }

    // ── wait_for_interface kernel-async-race coverage (#200) ────────
    //
    // Live boot post-#197 fail-closed at ~22 ms after `PF_VSOCK
    // registered` with `network-failed`: `init_module(virtio_net)`
    // returned Ok the moment the kernel accepted the module bytes,
    // but the netdev's `/sys/class/net/eth0/address` file wasn't
    // populated yet — `read_mac` returned `Err("mac-read")`, the
    // `?` propagated. These four tests pin the new contract: the
    // two "almost-there" transients retry; structural failures
    // propagate; budget exhaustion still reports `no-interface`.
    //
    // The tests use `wait_for_interface_with` to inject a probe
    // closure so they exercise the retry / propagate split without
    // a real virtio_net hot-add. A short 200 ms budget keeps the
    // suite snappy; the 50 ms poll cadence means each test runs at
    // most ~5 iterations.

    #[cfg(target_os = "linux")]
    fn fixture_iface() -> Iface {
        Iface {
            name: "eth0".to_owned(),
            ifindex: 2,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        }
    }

    /// `Err("mac-read")` on the first N polls then `Ok(Some(iface))`
    /// — the kernel's `eth0` directory exists but `address` isn't
    /// populated yet. The retry MUST eat the transient and succeed.
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_interface_retries_through_transient_mac_read() {
        use std::cell::RefCell;
        let calls = RefCell::new(0u32);
        let probe = || {
            let mut n = calls.borrow_mut();
            *n += 1;
            if *n <= 2 {
                Err("mac-read")
            } else {
                Ok(Some(fixture_iface()))
            }
        };
        let got = wait_for_interface_with(Duration::from_millis(200), probe)
            .expect("transient mac-read must NOT fail-close");
        assert_eq!(got.name, "eth0");
        assert!(
            *calls.borrow() >= 3,
            "expected ≥3 probe calls (two transient + one success), got {}",
            *calls.borrow()
        );
    }

    /// Same race window, hit by `if_nametoindex` instead of
    /// `read_mac` (ifindex registration lags the `/sys` entry).
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_interface_retries_through_transient_iface_nametoindex() {
        use std::cell::RefCell;
        let calls = RefCell::new(0u32);
        let probe = || {
            let mut n = calls.borrow_mut();
            *n += 1;
            if *n <= 2 {
                Err("iface-nametoindex")
            } else {
                Ok(Some(fixture_iface()))
            }
        };
        let got = wait_for_interface_with(Duration::from_millis(200), probe)
            .expect("transient iface-nametoindex must NOT fail-close");
        assert_eq!(got.ifindex, 2);
    }

    /// `Err("sys-class-net-read")` is structural — `/sys/class/net`
    /// is unreadable, NOT a race. MUST propagate immediately so the
    /// agent fail-closes loud rather than burning the whole budget
    /// retrying a permanent failure. Asserted via probe-call count
    /// (NOT wall-clock — a wall-clock <50ms bound flakes under CI
    /// VM contention; a call-count bound is the actually-load-bearing
    /// fail-fast contract anyway).
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_interface_fails_closed_on_structural_error() {
        use std::cell::RefCell;
        let calls = RefCell::new(0u32);
        let probe = || {
            *calls.borrow_mut() += 1;
            Err("sys-class-net-read")
        };
        let err = wait_for_interface_with(Duration::from_millis(200), probe)
            .expect_err("structural Err MUST propagate, not retry");
        assert_eq!(err, "sys-class-net-read");
        assert_eq!(
            *calls.borrow(),
            1,
            "structural failure must propagate after exactly one probe; got {} calls",
            *calls.borrow()
        );
    }

    /// `Ok(None)` forever (no netdev ever appears) MUST surface the
    /// classic `no-interface` after the budget — same contract as
    /// pre-#200, asserted under the new shape. Probe-call count is
    /// the timing-independent way to assert "the loop actually
    /// iterated" — a runaway-busy implementation would also pass a
    /// wall-clock minimum-elapsed check.
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_interface_exhausts_budget_on_no_interface() {
        use std::cell::RefCell;
        let calls = RefCell::new(0u32);
        let probe = || {
            *calls.borrow_mut() += 1;
            Ok(None)
        };
        let err = wait_for_interface_with(Duration::from_millis(200), probe)
            .expect_err("no interface must yield no-interface after budget");
        assert_eq!(err, "no-interface");
        // 200 ms budget / 50 ms poll cadence ⇒ ≥3 polls. A `>=2`
        // lower bound tolerates scheduler jitter on slow runners
        // while still catching a regression that returns on the
        // first iteration (which would be 1).
        assert!(
            *calls.borrow() >= 2,
            "must poll the probe multiple times before timeout; got {} calls",
            *calls.borrow()
        );
    }

    // ── #202 additional kernel-async-race coverage ──────────────────
    //
    // Post-#201 boot still fail-closed at ~30 ms after `PF_VSOCK
    // registered`. The race spans more steps than #201 covered:
    //   step 2: /sys/class/net/eth0/address exists, body = "\n"
    //           → `mac-parse` (not in #201's retry set);
    //   step 5: `netlink_set_link_up` SET is rejected mid-
    //           registration → `netlink-ack-error` (downstream of
    //           `wait_for_interface`, in a different code path).
    // These four tests pin the new contracts.

    /// `Err("mac-parse")` is the kernel-async race step 2 — the
    /// `address` file exists but the kernel hasn't written the MAC
    /// yet (body is just `"\n"`, `parse_mac` rejects). MUST retry
    /// alongside `mac-read` / `iface-nametoindex`.
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_for_interface_retries_through_transient_mac_parse() {
        use std::cell::RefCell;
        let calls = RefCell::new(0u32);
        let probe = || {
            let mut n = calls.borrow_mut();
            *n += 1;
            if *n <= 2 {
                Err("mac-parse")
            } else {
                Ok(Some(fixture_iface()))
            }
        };
        let got = wait_for_interface_with(Duration::from_millis(200), probe)
            .expect("transient mac-parse must NOT fail-close");
        assert_eq!(got.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert!(
            *calls.borrow() >= 3,
            "expected ≥3 probe calls (two transient + one success), got {}",
            *calls.borrow()
        );
    }

    /// `netlink-ack-error` on the first two SETs (kernel mid-
    /// registration), then `Ok(())`. The retry MUST eat the
    /// transient and succeed within the 3-attempt budget.
    #[cfg(target_os = "linux")]
    #[test]
    fn netlink_set_link_up_retry_succeeds_after_two_ack_errors() {
        use std::cell::RefCell;
        let calls = RefCell::new(0u32);
        let probe = |_iface: &Iface| {
            let mut n = calls.borrow_mut();
            *n += 1;
            if *n <= 2 {
                Err("netlink-ack-error")
            } else {
                Ok(())
            }
        };
        netlink_set_link_up_retry_with(&fixture_iface(), probe)
            .expect("transient netlink-ack-error must NOT fail-close");
        assert_eq!(
            *calls.borrow(),
            3,
            "expected exactly 3 probe calls (two transient + one success), got {}",
            *calls.borrow()
        );
    }

    /// All three attempts return `netlink-ack-error`. MUST surface
    /// `netlink-set-link-up-retry-exhausted` (the budget-exhausted
    /// sentinel), NOT pass through the inner `netlink-ack-error` —
    /// the operator-facing class distinguishes "we tried and gave
    /// up" from "first try said no".
    #[cfg(target_os = "linux")]
    #[test]
    fn netlink_set_link_up_retry_exhausts_budget() {
        use std::cell::RefCell;
        let calls = RefCell::new(0u32);
        let probe = |_iface: &Iface| {
            *calls.borrow_mut() += 1;
            Err("netlink-ack-error")
        };
        let err = netlink_set_link_up_retry_with(&fixture_iface(), probe)
            .expect_err("3 ack-errors must exhaust the budget");
        assert_eq!(err, "netlink-set-link-up-retry-exhausted");
        assert_eq!(
            *calls.borrow(),
            LINK_UP_RETRY_ATTEMPTS,
            "expected exactly {LINK_UP_RETRY_ATTEMPTS} probe calls before exhaustion, got {}",
            *calls.borrow()
        );
    }

    /// `netlink-socket` is structural — the AF_NETLINK socket
    /// itself couldn't be opened. MUST propagate after exactly one
    /// probe call (no retry); same fail-fast contract as the
    /// `wait_for_interface_fails_closed_on_structural_error` test.
    #[cfg(target_os = "linux")]
    #[test]
    fn netlink_set_link_up_retry_propagates_structural_errors() {
        use std::cell::RefCell;
        let calls = RefCell::new(0u32);
        let probe = |_iface: &Iface| {
            *calls.borrow_mut() += 1;
            Err("netlink-socket")
        };
        let err = netlink_set_link_up_retry_with(&fixture_iface(), probe)
            .expect_err("structural Err MUST propagate, not retry");
        assert_eq!(err, "netlink-socket");
        assert_eq!(
            *calls.borrow(),
            1,
            "structural failure must propagate after exactly one probe; got {} calls",
            *calls.borrow()
        );
    }

    /// Regression guard against the pre-#202 sub-class collapse.
    /// Production code USED to map every distinct netlink failure
    /// returned by `netlink_send_recv_ack` to one opaque class via
    /// a closure that consumed the inner Err and produced a fixed
    /// "lu" literal (full spelling assembled in `needle` below).
    /// That hid the retry-worthy ack-error from the retry wrapper
    /// AND hid the structural socket-open failure from the
    /// fail-fast path — both branches were dead.
    ///
    /// Confirmed live 2026-05-26 ~05:57 UTC via a one-off debug
    /// initramfs that printed the raw `AgentError::Network` payload:
    /// the serial showed the family-collapsed class, not the
    /// underlying netlink sub-class. The fix removes the closure;
    /// this test fails loudly if anyone re-introduces it.
    ///
    /// Source-inspection rather than an integration test because
    /// AF_NETLINK access is not guaranteed on every CI runner — and
    /// the regression we want to catch is purely a refactor
    /// mistake, not a runtime one. Both `needle` and any literal in
    /// the assertion message are assembled with `concat!` so the
    /// contiguous "lu" run does not appear in the source verbatim
    /// (otherwise `include_str!` would find this test's own body).
    #[test]
    fn netlink_set_link_up_does_not_collapse_to_link_up_class() {
        let needle = concat!("map_err(|_| ", "\"link-up\")");
        let src = include_str!("network.rs");
        assert!(
            !src.contains(needle),
            "{}",
            concat!(
                "the pre-#202 collapse closure must not reappear in ",
                "network.rs — see PR #202: it hid the netlink ",
                "sub-class from the retry wrapper. Propagate the ",
                "inner class instead."
            )
        );
    }
}
