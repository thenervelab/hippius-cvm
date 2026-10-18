"""`miner_host_preflight` — the generic hardware / host check of play 00.

A miner host is judged from what it IS, not from what a per-host
host_vars file says it should be, so a third-party operator gets the same
refusal we would: a code, what was found, and how to fix it — before the
playbook installs anything.

Play 00 runs one read-only shell probe on the host (`key=value` lines,
`parse_probe`) and hands it, with the gathered Ansible facts, to
`miner_host_preflight`, which returns:

    {"snp_generation": "genoa" | "turin" | "milan" | None,
     "summary": {...},          # printed as one JSON line for the backend
     "failures": [finding],     # any one of them stops the run
     "warnings": [finding]}     # printed, never fatal
    finding = {"code": "...", "detail": "...", "fix": "..."}

Pure functions, stdlib only: the logic is unit-tested off a real SNP
host (tests/test_host_preflight.py).
"""

from __future__ import annotations

import re
from typing import Any

# The CPU family/model -> SEV-SNP generation table of the miner-agent's
# vendored `sev` crate (`Generation::identify_cpu`), which picks the vCPU
# model folded into every launch measurement. A host the agent cannot
# map fails every launch closed, so it is refused here with the same map.
_EPYC_GENERATIONS: tuple[tuple[int, int, int, str], ...] = (
    (0x19, 0x00, 0x0F, "milan"),
    (0x19, 0x10, 0x1F, "genoa"),
    (0x19, 0xA0, 0xAF, "genoa"),  # Bergamo / Siena: Genoa SNP firmware
    (0x1A, 0x00, 0x11, "turin"),
)

# Kernel cmdline tokens that take CPUs offline (or never bring them up)
# after the firmware counted them at SNP_INIT: SNP_DF_FLUSH then fails
# with WBINVD_REQUIRED (0xe) and ASIDs stop being recycled.
_CPU_LIMIT_TOKENS = ("nosmt", "maxcpus", "nr_cpus")

# smt/control values meaning the SMT siblings were offlined by the OS
# (`nosmt`, `echo off`). `notsupported` = SMT disabled in the BIOS, fine.
_SMT_RUNTIME_OFF = ("off", "forceoff")

_GIB = 1024**3


def epyc_snp_generation(family: int, model: int) -> str | None:
    """`milan` | `genoa` | `turin` for an SEV-SNP EPYC, else None."""
    for fam, lo, hi, gen in _EPYC_GENERATIONS:
        if family == fam and lo <= model <= hi:
            return gen
    return None


def parse_probe(stdout: str) -> dict[str, str]:
    """`key=value` lines -> dict. The value keeps any further `=`."""
    probe: dict[str, str] = {}
    for line in stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            probe[key.strip()] = value.strip()
    return probe


def _version_tuple(text: str) -> tuple[int, ...]:
    """Leading dotted numbers: `7.0.0-15-generic` -> (7, 0, 0)."""
    match = re.match(r"\d+(?:\.\d+)*", str(text).strip())
    if not match:
        return ()
    return tuple(int(part) for part in match.group(0).split("."))


def _int(text: Any, default: int = -1) -> int:
    """Decimal or 0x-hex int; `default` when unparsable."""
    try:
        return int(str(text).strip(), 0)
    except ValueError:
        return default


def _cmdline_keys(cmdline: str) -> set[str]:
    """Token names of a kernel cmdline: `maxcpus=8` -> `maxcpus`."""
    return {token.split("=", 1)[0] for token in cmdline.split()}


def statfs_usable_gib(statfs: Any) -> int:
    """The GiB of a filesystem the agent (not root) can fill, from
    `stat -f -c '%S %b %f %a' <mount>` (fundamental block size, blocks,
    free, available): (blocks − free + available) × size — every block but
    the root-reserved ones (ext4: 5% by default). `ansible_mounts` cannot
    give it: it carries no f_bfree (its `block_used` is f_blocks − f_bavail,
    so used + available is the whole filesystem, reserve included). 0 for
    anything unreadable: every caller treats 0 as "too small", never as
    "unbounded"."""
    try:
        size, blocks, free, available = (int(x) for x in str(statfs).split())
    except (TypeError, ValueError):
        return 0
    if min(size, blocks, free, available) < 0 or free > blocks:
        return 0
    return (blocks - free + available) * size // _GIB


def disk_reserve_gib(mount_point: str, reserve_gb: Any, root_extra_gb: Any) -> int:
    """What the agent keeps off the tenants on the data filesystem:
    `reserve_disk_gb`, plus `reserve_disk_root_extra_gb` when that
    filesystem is `/` (the OS, the image cache and the base-image staging
    live there too)."""
    extra = _int(root_extra_gb, 0) if str(mount_point).rstrip("/") == "" else 0
    return _int(reserve_gb, 0) + extra


def mount_point_for(path: str, mounts: list[dict[str, Any]]) -> str:
    """The mount point holding `path` ("" when none does)."""
    mount = _mount_for(path, list(mounts or []))
    return str(mount.get("mount", "")) if mount else ""


def _mount_for(path: str, mounts: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The longest mount point that is a path prefix of `path` (the same
    rule miner-agent-install.yml uses for the disk budget)."""
    target = path.rstrip("/") + "/"
    best: dict[str, Any] | None = None
    for mount in mounts:
        point = str(mount.get("mount", "")).rstrip("/") + "/"
        if target.startswith(point) and (
            best is None or len(point) > len(str(best["mount"]).rstrip("/") + "/")
        ):
            best = mount
    return best


class _Report:
    def __init__(self, installed: bool = False) -> None:
        self.failures: list[dict[str, str]] = []
        self.warnings: list[dict[str, str]] = []
        self.installed = installed

    def fail(self, code: str, detail: str, fix: str) -> None:
        self.failures.append({"code": code, "detail": detail, "fix": fix})

    def warn(self, code: str, detail: str, fix: str) -> None:
        self.warnings.append({"code": code, "detail": detail, "fix": fix})

    def fail_first_install(self, code: str, detail: str, fix: str) -> None:
        """Fatal on a new host; a warning on one already running the agent.

        For floors and transient conditions (disk space, clock, network
        reachability): refusing them on a live host would block the very
        re-run meant to update or repair it.
        """
        if self.installed:
            self.warn(code, detail + " (the miner-agent is already installed)", fix)
        else:
            self.fail(code, detail, fix)


def _check_cpu(probe: dict[str, str], facts: dict[str, Any], report: _Report) -> str | None:
    model_name = probe.get("cpu_model_name", "")
    if facts.get("architecture") != "x86_64" or probe.get("cpu_vendor") != "AuthenticAMD":
        report.fail(
            "CPU_NOT_AMD_X86",
            f"arch={facts.get('architecture')} vendor={probe.get('cpu_vendor') or '?'} ({model_name})",
            "SEV-SNP needs an AMD EPYC host (Milan 7003, Genoa 9004, Turin 9005).",
        )
        return None

    family = _int(probe.get("cpu_family"))
    model = _int(probe.get("cpu_model"))
    generation = epyc_snp_generation(family, model) if "EPYC" in model_name else None
    if generation is None:
        report.fail(
            "CPU_UNSUPPORTED",
            f"{model_name or '?'} (family {family:#x}, model {model:#x}) is not an "
            "SEV-SNP EPYC generation the miner-agent can measure",
            "Use an AMD EPYC Milan (7003), Genoa (9004) or Turin (9005) host.",
        )
        return None

    declared = facts.get("snp_generation_declared")
    if declared and declared != generation:
        report.fail(
            "SNP_GENERATION_MISMATCH",
            f"host_vars says snp_generation={declared}, the CPU is {generation} ({model_name})",
            f"Set `snp_generation: {generation}` in host_vars, or remove it: the "
            "preflight derives it from the CPU.",
        )

    expected_model = facts.get("cpu_model_expected")
    if expected_model and expected_model not in model_name:
        report.fail(
            "CPU_MODEL_MISMATCH",
            f'host_vars expects "{expected_model}", the host reports "{model_name}"',
            "Fix cpu_model_expected in host_vars, or check this is the right box.",
        )
    return generation


def _check_bare_metal(probe: dict[str, str], report: _Report) -> None:
    virt = probe.get("virt", "") or "unknown"
    if virt != "none" or probe.get("flag_hypervisor") == "1":
        report.fail(
            "VIRTUALIZED",
            f"systemd-detect-virt --vm = {virt}, cpuinfo hypervisor flag = "
            f"{probe.get('flag_hypervisor', '?')}",
            "A miner must be a bare-metal host: tenant CVMs cannot run nested "
            "inside a VM. Use a dedicated server.",
        )


def _check_os(facts: dict[str, Any], limits: dict[str, Any], report: _Report) -> None:
    supported = [str(v) for v in limits.get("supported_ubuntu_versions", [])]
    distro = facts.get("distribution")
    version = str(facts.get("distribution_version"))
    if distro != "Ubuntu" or version not in supported:
        report.fail(
            "OS_UNSUPPORTED",
            f"{distro} {version}; supported: Ubuntu {' / '.join(supported)}",
            "Install Ubuntu 26.04 LTS (server). An older Ubuntu can be upgraded in "
            "place with do-release-upgrade; its libvirt/QEMU cannot boot an SEV-SNP guest.",
        )

    kernel = str(facts.get("kernel", ""))
    min_kernel = str(limits.get("min_kernel", "6.11"))
    if _version_tuple(kernel) < _version_tuple(min_kernel):
        report.fail(
            "KERNEL_TOO_OLD",
            f"kernel {kernel} < {min_kernel} (SEV-SNP host support)",
            "Boot the distro's default kernel of a supported release "
            "(`apt full-upgrade`, then reboot into it).",
        )


def _check_snp(probe: dict[str, str], limits: dict[str, Any], report: _Report) -> None:
    param = probe.get("sev_snp_param", "absent")
    cmdline = probe.get("cmdline", "").split()
    required = [str(t) for t in limits.get("snp_cmdline_tokens", [])]
    # What play 01 changes: it adds the SEV-SNP tokens and drops iommu=pt
    # (which keeps SNP off), then reboots. Anything else it cannot fix.
    play_01_pending = "iommu=pt" in cmdline or not all(t in cmdline for t in required)
    bios_ok = probe.get("flag_sev_snp") == "1"

    if not bios_ok:
        report.fail(
            "SNP_BIOS_DISABLED",
            "the CPU does not advertise sev_snp: the BIOS has not enabled SEV-SNP",
            "In the BIOS (AMD CBS / NBIO): SMEE = Enabled, SEV-SNP Support = Enabled, "
            "SNP Memory (RMP Table) Coverage = Enabled, SEV-ES ASID Space Limit = 100, "
            "IOMMU = Enabled. Then reboot.",
        )
    if param == "absent":
        report.fail(
            "SNP_KERNEL_UNSUPPORTED",
            "/sys/module/kvm_amd/parameters/sev_snp is absent (kvm_amd not loaded, "
            "or built without SEV-SNP)",
            "Enable SVM Mode (AMD-V) in the BIOS, boot the distro kernel of a supported "
            "release, and check `modprobe kvm_amd`.",
        )
        return
    if not bios_ok:
        return

    # Independent of whether SNP is on yet: without these it never will be.
    if probe.get("dev_sev") != "1":
        report.fail(
            "SEV_DEVICE_MISSING",
            "/dev/sev is absent (the ccp driver did not bring up the AMD Secure Processor)",
            "Check `dmesg | grep -i ccp` and `lsmod | grep ccp`; update the BIOS / "
            "SEV firmware if the PSP fails to initialise.",
        )
    # The kernel omits a zero-capacity line: absent = no ES/SNP ASID.
    if _int(probe.get("sev_es_asids")) <= 0:
        report.fail(
            "SNP_NO_ES_ASIDS",
            f"SEV-ES/SNP ASID capacity = {probe.get('sev_es_asids') or 'none'} "
            "(sev_es in /sys/fs/cgroup/misc.capacity)",
            "In the BIOS (AMD CBS > CPU Common Options): SEV-ES ASID Space Limit = 100 "
            "(a limit of 1 leaves no ASID for an SNP guest). Then reboot.",
        )

    if param != "Y":
        if play_01_pending:
            report.warn(
                "SNP_PENDING_REBOOT",
                f"kvm_amd.sev_snp={param}; the SEV-SNP kernel cmdline is not active yet",
                "Play 01 sets the SEV-SNP GRUB cmdline and reboots once; if SEV-SNP is "
                "still off after that, its assert fails with what to check.",
            )
        else:
            report.fail(
                "SNP_NOT_ENABLED",
                f"kvm_amd.sev_snp={param} although /proc/cmdline carries {' '.join(required)}",
                "SEV-SNP failed to initialise: check `dmesg | grep -iE 'sev|snp|rmp|ccp'` "
                "and the BIOS settings of SNP_BIOS_DISABLED; update the BIOS / AMD "
                "SEV firmware if the SNP API version is old.",
            )
        return

    if not probe.get("snp_fw"):
        report.warn(
            "SNP_FIRMWARE_UNKNOWN",
            "no `SEV-SNP API:` line in the kernel log (rotated)",
            "Informational: read it with `journalctl -k -b | grep 'SEV-SNP API'`.",
        )


def _check_iommu(probe: dict[str, str], report: _Report) -> None:
    keys = dict(t.split("=", 1) if "=" in t else (t, "") for t in probe.get("cmdline", "").split())
    disabled_by_cmdline = keys.get("amd_iommu") == "off" or keys.get("iommu") == "off"
    if _int(probe.get("iommu_units"), 0) <= 0 or disabled_by_cmdline:
        report.fail(
            "IOMMU_DISABLED",
            f"{probe.get('iommu_units', '0')} IOMMU unit(s) in /sys/class/iommu; "
            f"cmdline amd_iommu={keys.get('amd_iommu', '-')} iommu={keys.get('iommu', '-')}",
            "Enable the IOMMU in the BIOS (AMD CBS / NBIO: IOMMU = Enabled) and drop "
            "any amd_iommu=off / iommu=off from GRUB_CMDLINE_LINUX. SEV-SNP needs it.",
        )
    elif keys.get("iommu") == "pt":
        report.warn(
            "IOMMU_PASSTHROUGH",
            "iommu=pt on the kernel cmdline",
            "Play 01 removes it from GRUB_CMDLINE_LINUX (SEV-SNP refuses passthrough).",
        )


def _check_cpu_online(probe: dict[str, str], report: _Report) -> None:
    keys = _cmdline_keys(probe.get("cmdline", ""))
    limiting = sorted(k for k in keys if k in _CPU_LIMIT_TOKENS)
    if limiting:
        report.fail(
            "CMDLINE_CPU_LIMIT",
            f"kernel cmdline carries {', '.join(limiting)}",
            "Remove nosmt / maxcpus= / nr_cpus= from GRUB_CMDLINE_LINUX, update-grub, "
            "reboot. To run without SMT, disable it in the BIOS instead.",
        )

    # SMT disabled in the BIOS reads `notsupported` (or `notimplemented`)
    # with every present CPU online: the firmware never counted the
    # siblings, so that is a PASS. What is fatal is the OS taking a CPU
    # the firmware counted offline: smt/control off|forceoff, an offline
    # present CPU, or online != present. `present`, not `possible`:
    # `possible` also lists hotplug slots no CPU sits in, which the
    # firmware never counted either.
    offline = probe.get("cpus_offline", "").split()
    smt = probe.get("smt_control", "absent")
    online = probe.get("cpus_online", "")
    present = probe.get("cpus_present", "")
    online_gap = bool(online and present and online != present)
    if offline or online_gap or smt in _SMT_RUNTIME_OFF:
        detail = (
            f"{len(offline)} CPU(s) offline ({' '.join(offline[:8])}"
            f"{' ...' if len(offline) > 8 else ''}); online = {online or '?'}, "
            f"present = {present or '?'}; smt/control = {smt}"
        )
        if probe.get("smt_off_unit") == "1" and not limiting:
            report.warn(
                "CPU_OFFLINE",
                detail + "; hippius-smt-off.service is installed",
                "Play 01 removes hippius-smt-off.service; reboot when its offline "
                "assert asks for it.",
            )
        else:
            report.fail(
                "CPU_OFFLINE",
                detail,
                "Bring every CPU online (`echo on > /sys/devices/system/cpu/smt/control`, "
                "or reboot) and remove whatever offlined it. An offline CPU makes the "
                "firmware refuse SNP_DF_FLUSH (0xe): the host stops launching VMs after "
                "~99 launches since boot. To run without SMT, disable it in the BIOS.",
            )
    elif smt == "on":
        report.warn(
            "SMT_ON",
            "SMT is on",
            "Supported today. If you turn it off, do it ONLY in the BIOS (AMD CBS > "
            "CPU Common Options > SMT Control = Disable), never from the OS.",
        )


def _check_size(facts: dict[str, Any], limits: dict[str, Any], report: _Report) -> None:
    vcpus = _int(facts.get("vcpus"), 0)
    min_cpus = _int(limits.get("min_cpus"), 0)
    if vcpus < min_cpus:
        report.fail(
            "CPU_TOO_FEW",
            f"{vcpus} online CPU threads < the {min_cpus} minimum",
            "Use a larger host: the miner keeps a host reserve and sells the rest.",
        )

    mem_mb = _int(facts.get("memtotal_mb"), 0)
    # 90% floor — firmware reserves a few percent of installed RAM.
    min_ram_gb = _int(limits.get("min_ram_gb"), 0)
    if mem_mb < min_ram_gb * 1024 * 0.9:
        report.fail(
            "RAM_TOO_LOW",
            f"{mem_mb / 1024:.1f} GiB < the {min_ram_gb} GiB minimum",
            "Use a host with more RAM: SEV-SNP guest memory is pinned, never overcommitted.",
        )
    expected_gb = facts.get("ram_gb_expected")
    if expected_gb not in (None, "") and mem_mb < _int(expected_gb, 0) * 1024 * 0.9:
        report.fail(
            "RAM_MISMATCH",
            f"host_vars expects ~{expected_gb} GiB, the host reports {mem_mb / 1024:.1f} GiB",
            "Fix ram_gb_expected in host_vars, or check this is the right box.",
        )


def _check_storage(facts: dict[str, Any], limits: dict[str, Any], report: _Report) -> None:
    mounts = list(facts.get("mounts") or [])
    data_root = str(facts.get("data_root", ""))
    state_dir = str(facts.get("state_dir", ""))

    for root, exists in (
        (data_root, facts.get("data_root_exists")),
        (str(facts.get("state_root", "")), facts.get("state_root_exists")),
    ):
        # The agent's own state dir is created by play 05; any other root
        # is a dedicated mount the operator prepares (play 05 refuses it
        # missing — say so before anything is installed).
        if root and root.rstrip("/") != state_dir.rstrip("/") and not exists:
            report.fail(
                "DATA_ROOT_MISSING",
                f"storage root {root} does not exist",
                "Mount (or create) it before the run, or drop miner_data_disk_root / "
                "miner_state_disk_root from host_vars to use the default.",
            )

    min_tenant_gb = _int(limits.get("min_tenant_disk_gb"), 0)
    data_mount = _mount_for(data_root, mounts)
    data_gb = statfs_usable_gib(facts.get("data_fs_statfs"))
    reserve_gb = disk_reserve_gib(
        str(data_mount.get("mount", "")) if data_mount else "",
        limits.get("reserve_disk_gb"),
        limits.get("reserve_disk_root_extra_gb"),
    )
    if data_gb < reserve_gb + min_tenant_gb:
        size = (
            f"{data_gb} GiB usable"
            if data_gb
            else "unreadable (`stat -f` gave no answer)"
        )
        report.fail_first_install(
            "DATA_ROOT_TOO_SMALL",
            f"the filesystem holding {data_root} "
            f"({data_mount['mount'] if data_mount else 'not found'}) is {size}; "
            f"needs >= {reserve_gb + min_tenant_gb} GiB ({reserve_gb} reserve + "
            f"{min_tenant_gb} for tenant disks)",
            "Point miner_data_disk_root at a larger filesystem (a dedicated NVMe / RAID "
            "mounted before the run).",
        )

    if (
        data_mount
        and data_root.rstrip("/") != state_dir.rstrip("/")
        and data_mount.get("mount") == "/"
    ):
        report.warn(
            "DATA_ROOT_ON_SYSTEM_FS",
            f"{data_root} is on the root filesystem, not on a mount of its own",
            "If it should be a dedicated disk, it is not mounted (check /etc/fstab and "
            "`findmnt`): VM disks would land on the system disk and be hidden by the "
            "mount later.",
        )

    staging_root = str(facts.get("staging_root", ""))
    staging_mount = _mount_for(staging_root, mounts)
    free_gb = _int(staging_mount.get("size_available"), 0) // _GIB if staging_mount else 0
    min_free_gb = _int(limits.get("min_staging_free_gb"), 0)
    if free_gb < min_free_gb:
        report.fail_first_install(
            "STAGING_ROOT_LOW",
            f"{free_gb} GiB free on the filesystem holding {staging_root} "
            f"({staging_mount['mount'] if staging_mount else 'not found'}); needs >= {min_free_gb}",
            "Free space on (or grow) that filesystem: base images are staged there and "
            "its location is fixed.",
        )


def _check_services(probe: dict[str, str], facts: dict[str, Any], report: _Report) -> None:
    synced = probe.get("ntp_synced", "") or "unknown"
    if synced != "yes":
        report.fail_first_install(
            "CLOCK_NOT_SYNCED",
            f"timedatectl NTPSynchronized = {synced}",
            "Enable time sync (`timedatectl set-ntp true`, systemd-timesyncd or chrony) "
            "and wait for it: TLS, attestation and signed orders are time-checked.",
        )

    status = _int(facts.get("netbird_mgmt_status"), -1)
    url = facts.get("netbird_mgmt_url", "")
    if status <= 0:
        report.fail_first_install(
            "NETBIRD_MGMT_UNREACHABLE",
            f"no HTTPS answer from {url} ({facts.get('netbird_mgmt_error') or 'connection failed'})",
            "Allow outbound HTTPS (TCP 443) and UDP from the host, and check its DNS.",
        )
    if probe.get("netbird_installed") == "1" and probe.get("netbird_mgmt") != "Connected":
        report.warn(
            "NETBIRD_DISCONNECTED",
            f"netbird is installed, management = {probe.get('netbird_mgmt') or 'unknown'}",
            "Play 04 (re)joins with the setup key; check `netbird status` afterwards.",
        )


def miner_host_preflight(
    probe: dict[str, str], facts: dict[str, Any], limits: dict[str, Any]
) -> dict[str, Any]:
    """Judge a miner host. See the module docstring for the shapes."""
    if isinstance(probe, str):
        probe = parse_probe(probe)
    report = _Report(installed=probe.get("agent_installed") == "1")
    generation = _check_cpu(probe, facts, report)
    _check_bare_metal(probe, report)
    _check_os(facts, limits, report)
    _check_snp(probe, limits, report)
    _check_iommu(probe, report)
    _check_cpu_online(probe, report)
    _check_size(facts, limits, report)
    _check_storage(facts, limits, report)
    _check_services(probe, facts, report)

    summary = {
        "result": "fail" if report.failures else "pass",
        "snp_generation": generation,
        "cpu": probe.get("cpu_model_name", ""),
        "cpu_family": probe.get("cpu_family", ""),
        "cpu_model": probe.get("cpu_model", ""),
        "cpus": _int(facts.get("vcpus"), 0),
        "memory_gb": round(_int(facts.get("memtotal_mb"), 0) / 1024, 1),
        "smt": probe.get("smt_control", ""),
        "cpus_online": probe.get("cpus_online", ""),
        "snp_firmware": probe.get("snp_fw", ""),
        "sev_es_asids": _int(probe.get("sev_es_asids")),
        "os": f"{facts.get('distribution')} {facts.get('distribution_version')}",
        "kernel": facts.get("kernel", ""),
        "agent_installed": report.installed,
        "failures": [f["code"] for f in report.failures],
        "warnings": [w["code"] for w in report.warnings],
    }
    return {
        "snp_generation": generation,
        "summary": summary,
        "failures": report.failures,
        "warnings": report.warnings,
    }


def preflight_line(finding: dict[str, str], level: str) -> str:
    """One printable line: `FAIL [CODE] detail -- fix: ...`."""
    return f"{level} [{finding['code']}] {finding['detail']} -- fix: {finding['fix']}"


class FilterModule:
    def filters(self) -> dict:
        return {
            "miner_host_preflight": miner_host_preflight,
            "miner_preflight_line": preflight_line,
            "miner_statfs_usable_gib": statfs_usable_gib,
            "miner_mount_for": mount_point_for,
            "miner_disk_reserve_gib": disk_reserve_gib,
            "parse_host_probe": parse_probe,
        }
