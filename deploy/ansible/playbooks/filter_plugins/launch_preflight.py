"""`miner_launch_preflight` — can this host start a TENANT domain?

The host-attestor (play 05's infra domain) has no disk and no NIC, so a
host can run it and still fail every tenant launch at `virsh start`
(`libvirt-driver/create`). What a tenant domain adds is exactly what this
judges, after libvirt and the agent are installed (play 09):

- the libvirt `default` network: defined, active, autostarted, and the
  one the agent assumes (`virbr0`, 192.168.122.1/24 — `netpolicy::render`
  hard-codes both); its `clean-traffic` nwfilter;
- QEMU (`user =` in qemu.conf, `libvirt-qemu` by default) can traverse
  every directory down to the disk roots: libvirt chowns the disk FILE
  to it, never the parents;
- `O_DIRECT` works there: every tenant disk but the data disk is
  `cache='none'`, which QEMU opens with `O_DIRECT`;
- the agent's systemd sandbox (`ProtectSystem=strict` + `ReadWritePaths`)
  can write both roots the agent's config names;
- a paused, transient, non-SNP smoke domain with a raw `cache='none'`
  disk under the data root and a NIC on `default` starts.

The play runs one probe (files/launch-preflight-probe.sh, `key=value`
lines) and hands it here:

    {"summary": {...}, "failures": [finding], "warnings": [finding]}
    finding = {"code": "...", "detail": "...", "fix": "..."}

Play 03 uses `miner_libvirt_net_info` + `miner_libvirt_net_clash` to
refuse a `virsh net-start` that would collide with an existing route.

Pure functions, stdlib only (tests/test_launch_preflight.py).
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import Any

# What the miner-agent assumes of the `default` network
# (binaries/miner-agent/src/netpolicy/render.rs: GUEST_BRIDGE,
# GUEST_BRIDGE_ADDR; the guests' `clean-traffic` DHCPSERVER).
GUEST_BRIDGE = "virbr0"
GUEST_BRIDGE_ADDR = "192.168.122.1"
GUEST_BRIDGE_PREFIX = 24

# Route types `ip route` prints before the destination.
_ROUTE_TYPES = {"unicast", "local", "broadcast", "multicast", "unreachable",
                "blackhole", "prohibit", "throw", "nat", "anycast"}


def parse_probe(stdout: str) -> dict[str, str]:
    """`key=value` lines -> dict. The value keeps any further `=`."""
    probe: dict[str, str] = {}
    for line in str(stdout).splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            probe[key.strip()] = value.strip()
    return probe


def libvirt_net_info(xml: str) -> dict[str, Any]:
    """`virsh net-dumpxml` -> {"bridge", "ip", "prefix"} ("" / 0 if absent)."""
    info: dict[str, Any] = {"bridge": "", "ip": "", "prefix": 0}
    try:
        root = ET.fromstring(str(xml))
    except ET.ParseError:
        return info
    bridge = root.find("bridge")
    if bridge is not None:
        info["bridge"] = bridge.get("name", "")
    for ip in root.findall("ip"):
        if ip.get("family", "ipv4") != "ipv4" or not ip.get("address"):
            continue
        info["ip"] = ip.get("address", "")
        if ip.get("prefix"):
            info["prefix"] = int(ip.get("prefix", "0"))
        elif ip.get("netmask"):
            info["prefix"] = ipaddress.IPv4Network(f"0.0.0.0/{ip.get('netmask')}").prefixlen
        break
    return info


def _iface_networks(routes: str, addrs: str) -> list[tuple[str, ipaddress.IPv4Network]]:
    """(dev, network) from `ip -4 route show` and `ip -o -4 addr show`."""
    found: list[tuple[str, ipaddress.IPv4Network]] = []
    for line in str(routes).splitlines():
        tokens = line.split()
        if tokens and tokens[0] in _ROUTE_TYPES:
            tokens = tokens[1:]
        if not tokens or tokens[0] == "default" or "dev" not in tokens[:-1]:
            continue
        dev = tokens[tokens.index("dev") + 1]
        try:
            found.append((dev, ipaddress.IPv4Network(tokens[0], strict=False)))
        except ValueError:
            continue
    for line in str(addrs).splitlines():
        tokens = line.split()
        # `3: eth1    inet 10.0.0.5/24 brd ... scope global eth1`
        if len(tokens) < 4 or tokens[2] != "inet":
            continue
        try:
            found.append((tokens[1], ipaddress.IPv4Network(tokens[3], strict=False)))
        except ValueError:
            continue
    return found


def libvirt_net_clash(routes: str, addrs: str, net_ip: str, net_prefix: Any, bridge: str) -> list[str]:
    """`dev cidr` of every route / address overlapping the network.

    Only meaningful while the network is INACTIVE: once it runs, its own
    `virbr0` route is the one that overlaps. The bridge is excluded so a
    stale address on a downed `virbr0` is not taken for a clash.
    """
    if not net_ip:
        return []
    net = ipaddress.IPv4Network(f"{net_ip}/{int(net_prefix or 32)}", strict=False)
    clashes = []
    for dev, other in _iface_networks(routes, addrs):
        if dev == bridge or not net.overlaps(other):
            continue
        entry = f"{dev} {other}"
        if entry not in clashes:
            clashes.append(entry)
    return clashes


class _Report:
    def __init__(self) -> None:
        self.failures: list[dict[str, str]] = []
        self.warnings: list[dict[str, str]] = []

    def fail(self, code: str, detail: str, fix: str) -> None:
        self.failures.append({"code": code, "detail": detail, "fix": fix})


def _indexed(probe: dict[str, str], prefix: str, fields: int) -> list[list[str]]:
    """`<prefix>_0=a|b`, `<prefix>_1=...` -> [[a, b], ...] in order, each
    row padded to `fields`; the last field keeps any further `|`."""
    rows = []
    index = 0
    while f"{prefix}_{index}" in probe:
        row = probe[f"{prefix}_{index}"].split("|", fields - 1)
        rows.append(row + [""] * (fields - len(row)))
        index += 1
    return rows


def _covered(path: str, roots: list[str]) -> bool:
    """`path` is one of `roots` or below one (whole path components)."""
    path = path.rstrip("/") or "/"
    for root in roots:
        root = root.lstrip("-+").rstrip("/") or "/"
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def _check_network(probe: dict[str, str], report: _Report) -> None:
    rerun = "rerun the play with `--tags launch_preflight` (play 03 defines, starts and autostarts it)"
    if probe.get("net_defined") != "1":
        report.fail(
            "LIBVIRT_DEFAULT_NET_INACTIVE",
            "the libvirt `default` network is not defined: tenant NICs attach to it",
            rerun[0].upper() + rerun[1:] + ".",
        )
        return
    if probe.get("net_active") != "1":
        report.fail(
            "LIBVIRT_DEFAULT_NET_INACTIVE",
            "the libvirt `default` network is defined but not active: every tenant "
            "`virsh start` fails on its NIC",
            f"`virsh net-start default && virsh net-autostart default`, or {rerun}.",
        )
    elif probe.get("net_autostart") != "1":
        report.fail(
            "LIBVIRT_DEFAULT_NET_NO_AUTOSTART",
            "the libvirt `default` network is active but not autostarted: after a "
            "reboot every tenant launch fails",
            f"`virsh net-autostart default`, or {rerun}.",
        )
    net = libvirt_net_info(probe.get("net_xml", ""))
    bridge, ip, prefix = net["bridge"], net["ip"], net["prefix"]
    if (bridge, ip, prefix) != (GUEST_BRIDGE, GUEST_BRIDGE_ADDR, GUEST_BRIDGE_PREFIX):
        report.fail(
            "LIBVIRT_DEFAULT_NET_WRONG_SUBNET",
            f"the `default` network is bridge {bridge or '?'} {ip or '?'}/{prefix or '?'}; the "
            f"miner-agent's guest firewall and DHCP filter assume {GUEST_BRIDGE} "
            f"{GUEST_BRIDGE_ADDR}/{GUEST_BRIDGE_PREFIX}",
            "Redefine `default` as the stock libvirt network (192.168.122.1/24 on virbr0). "
            "If that range is taken on this host, renumber the other interface instead.",
        )
    if probe.get("nwfilter_clean_traffic") != "1":
        report.fail(
            "LIBVIRT_NWFILTER_MISSING",
            "libvirt has no `clean-traffic` nwfilter: tenant NICs reference it, so "
            "`virsh start` fails",
            "`apt install --reinstall libvirt-daemon-config-nwfilter`, then "
            "`systemctl restart libvirtd` (running domains keep running).",
        )


def _check_traversal(probe: dict[str, str], report: _Report) -> None:
    user = probe.get("qemu_user", "") or "libvirt-qemu"
    for path, blocked, perm in _indexed(probe, "traverse", 3):
        if not blocked:
            continue
        if blocked == "-missing-":
            # A root that does not exist is play 00 / 05's refusal; a
            # subdir the agent creates on its first launch is fine.
            continue
        report.fail(
            "QEMU_CANNOT_TRAVERSE_DATA_ROOT",
            f"QEMU runs as `{user}`, which cannot enter {blocked} ({perm}) on the way to "
            f"{path}: libvirt chowns each disk file to it, never the parent directories",
            f"`chmod o+x {blocked}` (or `setfacl -m u:{user}:x {blocked}`). "
            "The play does not change directories it did not create.",
        )


def _check_sandbox(probe: dict[str, str], facts: dict[str, Any], report: _Report) -> None:
    unit = facts.get("unit_name", "hippius-miner-agent")
    if probe.get("unit_present") != "1":
        report.fail(
            "AGENT_SANDBOX_CANNOT_WRITE",
            f"{unit}.service is not installed, so its sandbox cannot be checked",
            "Run the whole play (play 05 installs the unit), not only this tag.",
        )
        return
    roots = [r for r in (probe.get("config_data_root", ""), probe.get("config_state_root", "")) if r]
    if not roots:
        report.fail(
            "AGENT_SANDBOX_CANNOT_WRITE",
            "the installed agent config names no `[storage] data_disk_root` / `state_disk_root`",
            "Rerun the play: play 05 renders the config.",
        )
    rw_paths = probe.get("unit_rw_paths", "").split()
    if probe.get("unit_protect_system") == "strict":
        for root in roots:
            if not _covered(root, rw_paths):
                report.fail(
                    "AGENT_SANDBOX_CANNOT_WRITE",
                    f"the agent config's storage root {root} is not in {unit}.service "
                    f"ReadWritePaths ({' '.join(rw_paths) or 'none'}): with ProtectSystem=strict "
                    "every launch fails creating its disks",
                    "Set miner_data_disk_root / miner_state_disk_root in host_vars to what the "
                    "config should say and rerun the play (it renders both the config and the "
                    "unit); do not edit config.toml by hand.",
                )
    for path, verdict in _indexed(probe, "sandbox", 2):
        if verdict.startswith("fail"):
            report.fail(
                "AGENT_SANDBOX_CANNOT_WRITE",
                f"a file could not be created in {path} under {unit}.service's sandbox "
                f"({verdict.partition(':')[2] or 'no detail'})",
                "Check the path is a writable mount (`findmnt`, not read-only) and listed in the "
                f"unit's ReadWritePaths (`systemctl show {unit} -p ReadWritePaths`), including any "
                "drop-in under /etc/systemd/system/" + unit + ".service.d/.",
            )


def _check_odirect(probe: dict[str, str], report: _Report) -> None:
    user = probe.get("qemu_user", "") or "libvirt-qemu"
    for path, verdict in _indexed(probe, "odirect", 2):
        reason = verdict.partition(":")[2] or "no detail"
        if verdict.startswith("fail-user"):
            report.fail(
                "QEMU_CANNOT_OPEN_DATA_ROOT",
                f"root can do O_DIRECT I/O in {path} but `{user}` cannot, on a file it owns ({reason})",
                "Look for an ACL, a mount option (root-squash, nosuid on NFS) or a security module "
                "denying it: `getfacl`, `findmnt`, `journalctl -k | grep -i denied`.",
            )
        elif verdict.startswith("fail"):
            report.fail(
                "DATA_ROOT_NO_ODIRECT",
                f"the filesystem holding {path} refuses O_DIRECT I/O ({reason}): tenant disks are "
                "`cache='none'`, which QEMU opens with O_DIRECT",
                "Put the storage roots on ext4, xfs or btrfs (not tmpfs, overlayfs, or a network or "
                "FUSE filesystem without direct I/O).",
            )


_SMOKE_HINTS: tuple[tuple[str, str], ...] = (
    ("clean-traffic", "LIBVIRT_NWFILTER_MISSING"),
    ("network 'default' is not active", "LIBVIRT_DEFAULT_NET_INACTIVE"),
    ("Network not found", "LIBVIRT_DEFAULT_NET_INACTIVE"),
    ("Permission denied", "QEMU_CANNOT_OPEN_DATA_ROOT"),
    ("Invalid argument", "DATA_ROOT_NO_ODIRECT"),
)


def _check_smoke(probe: dict[str, str], report: _Report) -> None:
    if probe.get("smoke", "skipped") != "fail":
        return
    err = probe.get("smoke_err", "") or "no error output"
    hint = next((code for marker, code in _SMOKE_HINTS if marker in err), "")
    report.fail(
        "LAUNCH_SMOKE_FAILED",
        f"a paused smoke domain (raw cache='none' disk under the data root, NIC on `default`) "
        f"did not start: {err}" + (f" (looks like {hint})" if hint else ""),
        "Fix the cause libvirt names (the codes above usually say which); "
        "`journalctl -u libvirtd` and /var/log/libvirt/qemu/hippius-preflight-smoke-*.log have the rest. "
        "Skip only this test with `-e miner_launch_smoke_enabled=false`.",
    )


def miner_launch_preflight(probe: Any, facts: dict[str, Any]) -> dict[str, Any]:
    """Judge whether this host can start a tenant domain (see module doc)."""
    if isinstance(probe, str):
        probe = parse_probe(probe)
    report = _Report()
    if probe.get("virsh") != "1":
        report.fail(
            "LIBVIRT_NOT_INSTALLED",
            "virsh is not available, so nothing about tenant launches can be checked",
            "Run the whole play: play 02 installs libvirt.",
        )
    else:
        if probe.get("qemu_user_ok") != "1":
            report.fail(
                "QEMU_USER_UNKNOWN",
                f"qemu.conf names QEMU user `{probe.get('qemu_user', '')}`, which does not exist",
                "Restore `user` in /etc/libvirt/qemu.conf to the packaged default "
                "(commented out = libvirt-qemu) and restart libvirtd.",
            )
        _check_network(probe, report)
        _check_traversal(probe, report)
        _check_sandbox(probe, facts, report)
        _check_odirect(probe, report)
        _check_smoke(probe, report)

    summary = {
        "result": "fail" if report.failures else "pass",
        "qemu_user": probe.get("qemu_user", ""),
        "default_net": "active" if probe.get("net_active") == "1" else "inactive",
        "smoke": probe.get("smoke", "skipped"),
        "failures": sorted({f["code"] for f in report.failures}),
        "warnings": sorted({w["code"] for w in report.warnings}),
    }
    return {"summary": summary, "failures": report.failures, "warnings": report.warnings}


class FilterModule:
    def filters(self) -> dict:
        return {
            "miner_launch_preflight": miner_launch_preflight,
            "miner_libvirt_net_info": libvirt_net_info,
            "miner_libvirt_net_clash": libvirt_net_clash,
        }
