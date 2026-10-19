"""Unit tests for the generic miner host preflight filter.

Run: python3 deploy/ansible/tests/test_host_preflight.py
(stdlib only — no Ansible install needed).
"""

import copy
import importlib.util
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PLUGIN = _ROOT / "playbooks" / "filter_plugins" / "host_preflight.py"
_spec = importlib.util.spec_from_file_location("host_preflight_filter", _PLUGIN)
assert _spec is not None and _spec.loader is not None
host_preflight = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(host_preflight)

GIB = 1024**3


def mnt(point: str, total_gib: int, available_gib: int) -> dict:
    """An `ansible_mounts` entry as Ansible builds it: no f_bfree, so its
    `block_used` is f_blocks − f_bavail (the root-reserved blocks hide in
    it) — the reason the usable size comes from `stat -f` instead."""
    bs = 4096
    total = total_gib * GIB // bs
    available = available_gib * GIB // bs
    return {
        "mount": point,
        "size_total": total_gib * GIB,
        "size_available": available_gib * GIB,
        "block_size": bs,
        "block_total": total,
        "block_available": available,
        "block_used": total - available,
    }


def statfs(total_gib: int, available_gib: int, reserved_gib: int = 0) -> str:
    """`stat -f -c '%S %b %f %a'`: free = available + root-reserved."""
    bs = 4096
    return " ".join(
        str(x)
        for x in (
            bs,
            total_gib * GIB // bs,
            (available_gib + reserved_gib) * GIB // bs,
            available_gib * GIB // bs,
        )
    )


# A healthy Genoa host, as the play 00 probe prints it.
GOOD_PROBE = """\
cpu_vendor=AuthenticAMD
cpu_family=25
cpu_model=17
cpu_model_name=AMD EPYC 9254 24-Core Processor
flag_sev_snp=1
flag_hypervisor=0
virt=none
cmdline=BOOT_IMAGE=/vmlinuz-7.0.0-15-generic root=/dev/md3 ro kvm_amd.sev=1 kvm_amd.sev_es=1 kvm_amd.sev_snp=1 mem_encrypt=on
smt_control=notsupported
smt_active=0
cpus_online=0-23
cpus_present=0-23
cpus_possible=0-23
cpus_offline=
smt_off_unit=0
agent_installed=0
sev_snp_param=Y
dev_sev=1
sev_es_asids=99
snp_fw=1.55 build:21
iommu_units=8
ntp_synced=yes
netbird_installed=0
"""

GOOD_FACTS = {
    "architecture": "x86_64",
    "distribution": "Ubuntu",
    "distribution_version": "26.04",
    "kernel": "7.0.0-15-generic",
    "vcpus": 24,
    "memtotal_mb": 386000,
    "mounts": [
        mnt("/", 800, 700),
        mnt("/boot", 1, 1),
    ],
    "data_fs_statfs": statfs(800, 700, reserved_gib=40),
    "snp_generation_declared": "",
    "cpu_model_expected": "",
    "ram_gb_expected": "",
    "data_root": "/var/lib/hippius-miner",
    "data_root_exists": False,
    "state_root": "/var/lib/hippius-miner",
    "state_root_exists": False,
    "state_dir": "/var/lib/hippius-miner",
    "staging_root": "/var/lib/hippius-miner/staging",
    "netbird_mgmt_url": "https://netbird.example",
    "netbird_mgmt_status": 200,
    "netbird_mgmt_error": "",
}

LIMITS = {
    "supported_ubuntu_versions": ["25.10", "26.04"],
    "min_kernel": "6.11",
    "min_cpus": 16,
    "min_ram_gb": 64,
    "min_tenant_disk_gb": 200,
    "min_staging_free_gb": 30,
    "reserve_disk_gb": 100,
    "reserve_disk_root_extra_gb": 50,
    "snp_cmdline_tokens": [
        "kvm_amd.sev=1",
        "kvm_amd.sev_es=1",
        "kvm_amd.sev_snp=1",
        "mem_encrypt=on",
    ],
}


def run(probe=None, facts=None, limits=None):
    merged_probe = host_preflight.parse_probe(GOOD_PROBE)
    merged_probe.update(probe or {})
    merged_facts = copy.deepcopy(GOOD_FACTS)
    merged_facts.update(facts or {})
    merged_limits = dict(LIMITS, **(limits or {}))
    return host_preflight.miner_host_preflight(merged_probe, merged_facts, merged_limits)


def codes(result, kind="failures"):
    return [f["code"] for f in result[kind]]


class GenerationTest(unittest.TestCase):
    def test_real_silicon(self) -> None:
        # The (family, model) pairs read off the fleet's CPUs
        # (binaries/miner-agent/src/lifecycle/launch_digest.rs tests).
        self.assertEqual(host_preflight.epyc_snp_generation(0x19, 0x01), "milan")
        self.assertEqual(host_preflight.epyc_snp_generation(0x19, 0x11), "genoa")
        self.assertEqual(host_preflight.epyc_snp_generation(0x1A, 0x02), "turin")

    def test_range_edges(self) -> None:
        cases = {
            (0x19, 0x00): "milan",
            (0x19, 0x0F): "milan",
            (0x19, 0x10): "genoa",
            (0x19, 0x1F): "genoa",
            (0x19, 0xA0): "genoa",
            (0x19, 0xAF): "genoa",
            (0x1A, 0x00): "turin",
            (0x1A, 0x11): "turin",
            (0x19, 0x20): None,  # Zen 3 desktop
            (0x19, 0x61): None,  # Zen 4 desktop
            (0x1A, 0x12): None,
            (0x17, 0x31): None,  # Rome: no SNP
            (0x06, 0x8F): None,
        }
        for (family, model), want in cases.items():
            with self.subTest(family=hex(family), model=hex(model)):
                self.assertEqual(host_preflight.epyc_snp_generation(family, model), want)

    def test_matches_the_vendored_sev_crate(self) -> None:
        # The agent measures with vendor/sev's `Generation::identify_cpu`;
        # the preflight must accept exactly the hosts it can measure.
        src = (_ROOT.parent.parent / "vendor" / "sev" / "src" / "lib.rs").read_text()
        body = src[src.index("pub fn identify_cpu") :]
        body = body[: body.index("pub fn identify_host_generation")]
        table = []
        for fam_block in re.finditer(r"(0x[0-9A-Fa-f]+) => match model \{(.*?)\n\s*\},", body, re.S):
            family = int(fam_block.group(1), 16)
            for arm in re.finditer(r"([0-9xA-Fa-f.= |]+?) => Ok\(Self::(\w+)\)", fam_block.group(2)):
                for rng in arm.group(1).split("|"):
                    lo, hi = (int(x, 16) for x in rng.strip().split("..="))
                    table.append((family, lo, hi, arm.group(2).lower()))
        self.assertEqual(sorted(table), sorted(host_preflight._EPYC_GENERATIONS))


class ProbeParseTest(unittest.TestCase):
    def test_value_keeps_equals(self) -> None:
        probe = host_preflight.parse_probe("cmdline=a=b c=d\nempty=\nnoise\n")
        self.assertEqual(probe, {"cmdline": "a=b c=d", "empty": ""})


class GoodHostTest(unittest.TestCase):
    def test_passes_and_derives_generation(self) -> None:
        result = run()
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["snp_generation"], "genoa")
        self.assertEqual(result["summary"]["result"], "pass")
        self.assertEqual(result["summary"]["snp_firmware"], "1.55 build:21")

    def test_accepts_raw_probe_text(self) -> None:
        result = host_preflight.miner_host_preflight(GOOD_PROBE, GOOD_FACTS, LIMITS)
        self.assertEqual(result["failures"], [])

    def test_milan_and_turin(self) -> None:
        milan = run({"cpu_model": "1", "cpu_model_name": "AMD EPYC 7543 32-Core Processor"})
        self.assertEqual((milan["snp_generation"], milan["failures"]), ("milan", []))
        turin = run({"cpu_family": "26", "cpu_model": "2", "cpu_model_name": "AMD EPYC 9255 24-Core Processor"})
        self.assertEqual((turin["snp_generation"], turin["failures"]), ("turin", []))

    def test_every_finding_has_code_detail_fix(self) -> None:
        result = run(
            {"flag_sev_snp": "0", "ntp_synced": "no", "smt_control": "on", "iommu_units": "0"},
            {"vcpus": 4},
        )
        for finding in result["failures"] + result["warnings"]:
            self.assertRegex(finding["code"], r"^[A-Z0-9_]+$")
            self.assertTrue(finding["detail"])
            self.assertTrue(finding["fix"])
        line = host_preflight.preflight_line(result["failures"][0], "FAIL")
        self.assertRegex(line, r"^FAIL \[[A-Z0-9_]+\] .+ -- fix: .+")


class FailureTest(unittest.TestCase):
    def assertFails(self, code, probe=None, facts=None, limits=None) -> None:
        result = run(probe, facts, limits)
        self.assertIn(code, codes(result), result["failures"])
        self.assertEqual(result["summary"]["result"], "fail")

    def assertWarnsOnly(self, code, probe=None, facts=None) -> None:
        result = run(probe, facts)
        self.assertEqual(result["failures"], [])
        self.assertIn(code, codes(result, "warnings"))

    def test_cpu(self) -> None:
        self.assertFails("CPU_NOT_AMD_X86", {"cpu_vendor": "GenuineIntel"})
        self.assertFails("CPU_NOT_AMD_X86", facts={"architecture": "aarch64"})
        self.assertFails("CPU_UNSUPPORTED", {"cpu_family": "23", "cpu_model": "49"})
        # Right family/model, not an EPYC (a Threadripper/Ryzen part).
        self.assertFails("CPU_UNSUPPORTED", {"cpu_model_name": "AMD Ryzen Threadripper PRO 7995WX"})
        self.assertEqual(run({"cpu_vendor": "GenuineIntel"})["snp_generation"], None)

    def test_declared_generation(self) -> None:
        self.assertFails("SNP_GENERATION_MISMATCH", facts={"snp_generation_declared": "turin"})
        self.assertEqual(run(facts={"snp_generation_declared": "genoa"})["failures"], [])

    def test_host_vars_overrides(self) -> None:
        self.assertFails("CPU_MODEL_MISMATCH", facts={"cpu_model_expected": "AMD EPYC 9124"})
        self.assertEqual(run(facts={"cpu_model_expected": "AMD EPYC 9254"})["failures"], [])
        self.assertFails("RAM_MISMATCH", facts={"ram_gb_expected": 512})
        self.assertEqual(run(facts={"ram_gb_expected": 384})["failures"], [])

    def test_virtualized(self) -> None:
        self.assertFails("VIRTUALIZED", {"virt": "kvm"})
        self.assertFails("VIRTUALIZED", {"flag_hypervisor": "1"})
        self.assertFails("VIRTUALIZED", {"virt": ""})

    def test_os_and_kernel(self) -> None:
        self.assertFails("OS_UNSUPPORTED", facts={"distribution_version": "24.04"})
        self.assertFails("OS_UNSUPPORTED", facts={"distribution": "Debian", "distribution_version": "13"})
        self.assertFails("KERNEL_TOO_OLD", facts={"kernel": "6.8.0-110-generic"})
        self.assertEqual(run(facts={"kernel": "6.11.0-1-generic"})["failures"], [])

    def test_snp(self) -> None:
        self.assertFails("SNP_BIOS_DISABLED", {"flag_sev_snp": "0"})
        self.assertFails("SNP_KERNEL_UNSUPPORTED", {"sev_snp_param": "absent"})
        self.assertFails("SNP_NOT_ENABLED", {"sev_snp_param": "N"})
        self.assertFails("SEV_DEVICE_MISSING", {"dev_sev": "0"})
        self.assertFails("SNP_NO_ES_ASIDS", {"sev_es_asids": "0"})
        self.assertFails("SNP_NO_ES_ASIDS", {"sev_es_asids": ""})

    def test_snp_pending_cmdline_is_a_warning(self) -> None:
        # Play 01 adds the tokens and reboots: not a reason to refuse.
        self.assertWarnsOnly(
            "SNP_PENDING_REBOOT",
            {"sev_snp_param": "N", "cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro"},
        )
        # iommu=pt keeps SNP off; play 01 drops it, so it is pending too.
        self.assertWarnsOnly(
            "SNP_PENDING_REBOOT",
            {"sev_snp_param": "N", "cmdline": GOOD_FACTS_CMDLINE + " iommu=pt"},
        )

    def test_snp_blockers_reported_before_the_reboot(self) -> None:
        # A BIOS ASID limit of 1 keeps SNP off whatever the cmdline: say so
        # now rather than after play 01's reboot.
        pending = {"sev_snp_param": "N", "cmdline": "BOOT_IMAGE=/vmlinuz ro"}
        self.assertFails("SNP_NO_ES_ASIDS", dict(pending, sev_es_asids=""))
        self.assertFails("SEV_DEVICE_MISSING", dict(pending, dev_sev="0"))

    def test_svm_off_hint(self) -> None:
        result = run({"sev_snp_param": "absent"})
        self.assertIn("SVM", result["failures"][0]["fix"])

    def test_snp_firmware_unknown_is_a_warning(self) -> None:
        self.assertWarnsOnly("SNP_FIRMWARE_UNKNOWN", {"snp_fw": ""})

    def test_iommu(self) -> None:
        self.assertFails("IOMMU_DISABLED", {"iommu_units": "0"})
        self.assertFails("IOMMU_DISABLED", {"cmdline": GOOD_FACTS_CMDLINE + " amd_iommu=off"})
        self.assertWarnsOnly("IOMMU_PASSTHROUGH", {"cmdline": GOOD_FACTS_CMDLINE + " iommu=pt"})

    def test_cpu_offline(self) -> None:
        for token in ("nosmt", "nosmt=force", "maxcpus=8", "nr_cpus=8"):
            with self.subTest(token=token):
                self.assertFails("CMDLINE_CPU_LIMIT", {"cmdline": GOOD_FACTS_CMDLINE + " " + token})
        self.assertFails("CPU_OFFLINE", {"cpus_offline": " cpu24 cpu25", "smt_control": "off"})
        self.assertFails("CPU_OFFLINE", {"cpus_offline": " cpu7", "smt_control": "notsupported"})
        self.assertFails("CPU_OFFLINE", {"smt_control": "forceoff"})

    def test_bios_smt_off_passes(self) -> None:
        # A real host's reading, SMT disabled in the BIOS: control
        # notsupported, active 0, online = possible = 0-23, nothing offline,
        # no nosmt / maxcpus on the cmdline. A healthy host: no fatal.
        host = {
            "smt_control": "notsupported",
            "smt_active": "0",
            "cpus_online": "0-23",
            "cpus_possible": "0-23",
            "cpus_present": "0-23",
            "cpus_offline": "",
        }
        result = run(host)
        self.assertEqual(result["failures"], [])
        self.assertNotIn("SMT_ON", codes(result, "warnings"))
        self.assertEqual(run(dict(host, smt_control="notimplemented"))["failures"], [])
        # Empty hotplug slots (possible > present) are not offline CPUs.
        self.assertEqual(run(dict(host, cpus_possible="0-31"))["failures"], [])

    def test_online_gap_is_fatal(self) -> None:
        # A present CPU missing from `online` (e.g. no per-CPU online file
        # to report it) is still an offline CPU the firmware counted.
        self.assertFails("CPU_OFFLINE", {"cpus_online": "0-22", "cpus_present": "0-23"})

    def test_legacy_smt_off_unit_is_left_to_play_01(self) -> None:
        self.assertWarnsOnly(
            "CPU_OFFLINE", {"cpus_offline": " cpu24", "smt_control": "off", "smt_off_unit": "1"}
        )
        # ...but not when the cmdline offlines CPUs too: play 01 keeps it.
        self.assertFails(
            "CMDLINE_CPU_LIMIT",
            {"cpus_offline": " cpu24", "smt_control": "off", "smt_off_unit": "1",
             "cmdline": GOOD_FACTS_CMDLINE + " nosmt"},
        )

    def test_smt_on_is_a_warning(self) -> None:
        # SMT on is supported (SNP policy bit 16 = 1); only runtime
        # offlining is fatal.
        self.assertWarnsOnly("SMT_ON", {"smt_control": "on"})

    def test_size(self) -> None:
        self.assertFails("CPU_TOO_FEW", facts={"vcpus": 8})
        self.assertFails("RAM_TOO_LOW", facts={"memtotal_mb": 32 * 1024})
        # 90% floor: 64 GiB installed reads ~62 GiB.
        self.assertEqual(run(facts={"memtotal_mb": 62 * 1024})["failures"], [])

    def test_storage(self) -> None:
        self.assertFails(
            "DATA_ROOT_TOO_SMALL",
            facts={"mounts": [mnt("/", 250, 200)], "data_fs_statfs": statfs(250, 200)},
        )
        # The longest mount prefix holds the root: a big /srv does not
        # rescue a small / when the root is under /var.
        self.assertFails(
            "DATA_ROOT_TOO_SMALL",
            facts={
                "mounts": [mnt("/", 250, 200), mnt("/srv/data", 7000, 7000)],
                "data_fs_statfs": statfs(250, 200),
            },
        )
        dedicated = {
            "data_root": "/srv/data/vms",
            "data_root_exists": True,
            "mounts": [mnt("/", 100, 60), mnt("/srv/data", 7000, 7000)],
            "data_fs_statfs": statfs(7000, 7000),
        }
        self.assertEqual(run(facts=dedicated)["failures"], [])
        self.assertFails("DATA_ROOT_MISSING", facts=dict(dedicated, data_root_exists=False))
        self.assertFails(
            "STAGING_ROOT_LOW",
            facts=dict(dedicated, mounts=[mnt("/", 100, 10), mnt("/srv/data", 7000, 7000)]),
        )

    def test_storage_counts_only_what_the_agent_can_fill(self) -> None:
        # 400 GiB on `/`, 20 GiB root-reserved: 380 usable covers 100 + 50
        # (root extra) + 200 (tenant floor); with 120 reserved, 280 does not
        # — though `ansible_mounts` says 400 either way.
        root = {"mounts": [mnt("/", 400, 250)]}
        ok = dict(root, data_fs_statfs=statfs(400, 250, reserved_gib=20))
        self.assertEqual(run(facts=ok)["failures"], [])
        self.assertFails(
            "DATA_ROOT_TOO_SMALL", facts=dict(root, data_fs_statfs=statfs(400, 150, reserved_gib=120))
        )
        # On `/` the root extra counts (340 < 350); on a dedicated mount not.
        self.assertFails(
            "DATA_ROOT_TOO_SMALL",
            facts={"mounts": [mnt("/", 340, 300)], "data_fs_statfs": statfs(340, 300)},
        )
        dedicated = {
            "data_root": "/srv/data/vms",
            "data_root_exists": True,
            "mounts": [mnt("/", 100, 60), mnt("/srv/data", 310, 300)],
            "data_fs_statfs": statfs(310, 300),
        }
        self.assertEqual(run(facts=dedicated)["failures"], [])
        # No `stat -f` answer: refused, never taken as unbounded.
        self.assertFails("DATA_ROOT_TOO_SMALL", facts=dict(ok, data_fs_statfs=""))

    def test_usable_gib_and_reserve(self) -> None:
        # A host: 892 GiB, 44 GiB root-reserved, 4 GiB available ⇒ 848 usable.
        self.assertEqual(host_preflight.statfs_usable_gib(statfs(892, 4, reserved_gib=44)), 848)
        # What `ansible_mounts` would have said: the whole 892.
        host = mnt("/", 892, 4)
        self.assertEqual((host["block_used"] + host["block_available"]) * 4096 // GIB, 892)
        for bad in ("", None, "4096 10 20 5", "a b c d", "4096 10 5"):
            self.assertEqual(host_preflight.statfs_usable_gib(bad), 0, bad)
        self.assertEqual(host_preflight.disk_reserve_gib("/", 100, 50), 150)
        self.assertEqual(host_preflight.disk_reserve_gib("/srv/data", 100, 50), 100)
        self.assertEqual(host_preflight.disk_reserve_gib("/", "100", "0"), 100)
        self.assertEqual(
            host_preflight.mount_point_for("/var/lib/hippius-miner", [mnt("/", 1, 1)]), "/"
        )
        self.assertEqual(host_preflight.mount_point_for("/x", []), "")

    def test_clock_and_netbird(self) -> None:
        self.assertFails("CLOCK_NOT_SYNCED", {"ntp_synced": "no"})
        self.assertFails("CLOCK_NOT_SYNCED", {"ntp_synced": ""})
        self.assertFails("NETBIRD_MGMT_UNREACHABLE", facts={"netbird_mgmt_status": -1})
        self.assertWarnsOnly("NETBIRD_DISCONNECTED", {"netbird_installed": "1", "netbird_mgmt": "Disconnected"})
        self.assertEqual(run({"netbird_installed": "1", "netbird_mgmt": "Connected"})["warnings"], [])

    def test_installed_host_is_not_blocked_by_floors_or_outages(self) -> None:
        # A re-run on a live host (agent upgrade, repair) must not be
        # refused for disk space, the clock or a management outage...
        live = {"agent_installed": "1", "ntp_synced": "no"}
        small = {
            "netbird_mgmt_status": -1,
            "mounts": [mnt("/", 250, 10)],
            "data_fs_statfs": statfs(250, 10),
        }
        result = run(live, small)
        self.assertEqual(result["failures"], [])
        self.assertEqual(
            set(codes(result, "warnings")),
            {"CLOCK_NOT_SYNCED", "NETBIRD_MGMT_UNREACHABLE", "DATA_ROOT_TOO_SMALL", "STAGING_ROOT_LOW"},
        )
        self.assertTrue(result["summary"]["agent_installed"])
        # ...but a fresh host is, and the hardware checks stay fatal.
        self.assertEqual(len(run({"ntp_synced": "no"}, small)["failures"]), 4)
        self.assertIn("SNP_BIOS_DISABLED", codes(run(dict(live, flag_sev_snp="0"))))

    def test_dedicated_root_on_system_fs_warns(self) -> None:
        self.assertWarnsOnly(
            "DATA_ROOT_ON_SYSTEM_FS",
            facts={"data_root": "/srv/data", "data_root_exists": True},
        )

    def test_all_failures_reported_at_once(self) -> None:
        result = run({"flag_sev_snp": "0", "ntp_synced": "no"}, {"vcpus": 4})
        self.assertEqual(
            set(codes(result)) & {"SNP_BIOS_DISABLED", "CLOCK_NOT_SYNCED", "CPU_TOO_FEW"},
            {"SNP_BIOS_DISABLED", "CLOCK_NOT_SYNCED", "CPU_TOO_FEW"},
        )


GOOD_FACTS_CMDLINE = host_preflight.parse_probe(GOOD_PROBE)["cmdline"]


class FilterRegistrationTest(unittest.TestCase):
    def test_registered(self) -> None:
        filters = host_preflight.FilterModule().filters()
        self.assertIs(filters["miner_host_preflight"], host_preflight.miner_host_preflight)
        self.assertIs(filters["parse_host_probe"], host_preflight.parse_probe)
        self.assertIs(filters["miner_preflight_line"], host_preflight.preflight_line)


class PlaybookWiringTest(unittest.TestCase):
    """The play feeds the filter every key it reads."""

    def test_play_passes_every_fact_and_limit(self) -> None:
        play = (_ROOT / "playbooks" / "miner-tasks" / "host-preflight.yml").read_text()
        for key in list(GOOD_FACTS) + list(LIMITS):
            with self.subTest(key=key):
                self.assertRegex(play, rf"\n\s+{key}: ")

    def test_probe_prints_every_key(self) -> None:
        play = (_ROOT / "playbooks" / "06-miner-bootstrap.yml").read_text()
        for key in host_preflight.parse_probe(GOOD_PROBE):
            with self.subTest(key=key):
                self.assertRegex(play, rf"echo \"?{key}=")


if __name__ == "__main__":
    unittest.main()
