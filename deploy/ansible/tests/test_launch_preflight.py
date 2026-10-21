"""Unit tests for the tenant-launch preflight (play 09): the verdict
filter, and the probe script run against stub `virsh` / `systemctl` /
`systemd-run` / `runuser` in a scratch dir (no libvirt, no root, no
host contacted), its output fed to the filter. Its O_DIRECT probe does
real I/O in that scratch dir, which must be on a filesystem that
supports O_DIRECT (ext4 / xfs / btrfs; not tmpfs).

Run: python3 deploy/ansible/tests/test_launch_preflight.py
(stdlib + bash only — no Ansible install needed).
"""

import importlib.util
import os
import pathlib
import mmap
import stat
import subprocess
import sys
import tempfile
import time
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PLUGIN = _ROOT / "playbooks" / "filter_plugins" / "launch_preflight.py"
_PROBE = _ROOT / "playbooks" / "miner-tasks" / "files" / "launch-preflight-probe.sh"
_spec = importlib.util.spec_from_file_location("launch_preflight_filter", _PLUGIN)
assert _spec is not None and _spec.loader is not None
lpf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lpf)

NET_XML = (
    "<network><name>default</name><forward mode='nat'/>"
    "<bridge name='virbr0' stp='on' delay='0'/>"
    "<ip address='192.168.122.1' netmask='255.255.255.0'>"
    "<dhcp><range start='192.168.122.2' end='192.168.122.254'/></dhcp></ip></network>"
)

GOOD = {
    "virsh": "1",
    "qemu_user": "libvirt-qemu",
    "qemu_user_ok": "1",
    "net_defined": "1",
    "net_active": "1",
    "net_autostart": "1",
    "net_xml": NET_XML,
    "nwfilter_clean_traffic": "1",
    "traverse_0": "/var/lib/hippius-miner||",
    "traverse_1": "/var/lib/hippius-miner/staging|-missing-|",
    "unit_present": "1",
    "unit_protect_system": "strict",
    "unit_rw_paths": "/var/lib/hippius-miner",
    "config_data_root": "/var/lib/hippius-miner",
    "config_state_root": "/var/lib/hippius-miner",
    "sandbox_0": "/var/lib/hippius-miner|ok",
    "odirect_0": "/var/lib/hippius-miner|ok",
    "smoke": "ok",
}
FACTS = {"unit_name": "hippius-miner-agent"}


def judge(**overrides: str) -> dict:
    probe = dict(GOOD)
    for key, value in overrides.items():
        if value is None:
            probe.pop(key, None)
        else:
            probe[key] = value
    return lpf.miner_launch_preflight(probe, FACTS)


def codes(verdict: dict) -> list:
    return [f["code"] for f in verdict["failures"]]


class VerdictTest(unittest.TestCase):
    def test_a_healthy_host_passes(self) -> None:
        verdict = judge()
        self.assertEqual(verdict["failures"], [])
        self.assertEqual(verdict["summary"]["result"], "pass")

    def test_no_libvirt_is_one_finding(self) -> None:
        self.assertEqual(codes(lpf.miner_launch_preflight({"virsh": "0"}, FACTS)), ["LIBVIRT_NOT_INSTALLED"])

    def test_network_states(self) -> None:
        self.assertEqual(codes(judge(net_defined="0")), ["LIBVIRT_DEFAULT_NET_INACTIVE"])
        self.assertEqual(codes(judge(net_active="0")), ["LIBVIRT_DEFAULT_NET_INACTIVE"])
        self.assertEqual(codes(judge(net_autostart="0")), ["LIBVIRT_DEFAULT_NET_NO_AUTOSTART"])

    def test_the_network_must_be_the_one_the_agent_assumes(self) -> None:
        moved = NET_XML.replace("192.168.122.1", "10.77.0.1")
        self.assertEqual(codes(judge(net_xml=moved)), ["LIBVIRT_DEFAULT_NET_WRONG_SUBNET"])
        prefix = NET_XML.replace("netmask='255.255.255.0'", "prefix='16'")
        self.assertEqual(codes(judge(net_xml=prefix)), ["LIBVIRT_DEFAULT_NET_WRONG_SUBNET"])
        bridge = NET_XML.replace("virbr0", "br-tenant")
        self.assertEqual(codes(judge(net_xml=bridge)), ["LIBVIRT_DEFAULT_NET_WRONG_SUBNET"])

    def test_missing_nwfilter(self) -> None:
        self.assertEqual(codes(judge(nwfilter_clean_traffic="0")), ["LIBVIRT_NWFILTER_MISSING"])

    def test_unknown_qemu_user(self) -> None:
        self.assertIn("QEMU_USER_UNKNOWN", codes(judge(qemu_user="qemu", qemu_user_ok="0")))

    def test_traversal_names_the_dir_and_the_chmod(self) -> None:
        verdict = judge(traverse_0="/srv/tenants/vms|/srv/tenants|drwx------ root:root")
        self.assertEqual(codes(verdict), ["QEMU_CANNOT_TRAVERSE_DATA_ROOT"])
        self.assertIn("/srv/tenants (drwx------ root:root)", verdict["failures"][0]["detail"])
        self.assertIn("chmod o+x /srv/tenants", verdict["failures"][0]["fix"])

    def test_a_missing_agent_subdir_is_not_a_finding(self) -> None:
        self.assertEqual(codes(judge(traverse_1="/var/lib/hippius-miner/data|-missing-|")), [])

    def test_sandbox(self) -> None:
        self.assertEqual(codes(judge(unit_present="0")), ["AGENT_SANDBOX_CANNOT_WRITE"])
        uncovered = judge(config_data_root="/srv/vms", sandbox_0=None)
        self.assertEqual(codes(uncovered), ["AGENT_SANDBOX_CANNOT_WRITE"])
        self.assertIn("/srv/vms is not in", uncovered["failures"][0]["detail"])
        # ReadWritePaths entries cover whole path components only.
        self.assertEqual(
            codes(judge(config_data_root="/var/lib/hippius-miner-data", sandbox_0=None)),
            ["AGENT_SANDBOX_CANNOT_WRITE"],
        )
        self.assertEqual(codes(judge(config_data_root="/var/lib/hippius-miner/pools/a")), [])
        self.assertEqual(codes(judge(unit_rw_paths="-/var/lib/hippius-miner")), [])
        # Without ProtectSystem=strict the path list is not the gate.
        self.assertEqual(codes(judge(unit_protect_system="no", unit_rw_paths="")), [])
        failed = judge(sandbox_0="/var/lib/hippius-miner|fail:mktemp: Read-only file system|x")
        self.assertEqual(codes(failed), ["AGENT_SANDBOX_CANNOT_WRITE"])
        self.assertIn("Read-only file system|x", failed["failures"][0]["detail"])

    def test_odirect(self) -> None:
        self.assertEqual(
            codes(judge(odirect_0="/var/lib/hippius-miner|fail:O_DIRECT open for write: Invalid argument")),
            ["DATA_ROOT_NO_ODIRECT"],
        )
        self.assertEqual(
            codes(judge(odirect_0="/var/lib/hippius-miner|fail-user:O_DIRECT open for write: Permission denied")),
            ["QEMU_CANNOT_OPEN_DATA_ROOT"],
        )
        for quiet in ("skipped:missing", "skipped:traverse"):
            self.assertEqual(codes(judge(odirect_0=f"/x|{quiet}")), [])

    def test_smoke_failure_carries_libvirt_error_and_hint(self) -> None:
        verdict = judge(smoke="fail", smoke_err="error: referenced filter 'clean-traffic' is missing")
        self.assertEqual(codes(verdict), ["LAUNCH_SMOKE_FAILED"])
        self.assertIn("looks like LIBVIRT_NWFILTER_MISSING", verdict["failures"][0]["detail"])
        self.assertEqual(codes(judge(smoke="skipped")), [])

    def test_every_problem_at_once(self) -> None:
        verdict = judge(net_active="0", nwfilter_clean_traffic="0", odirect_0="/x|fail:EINVAL")
        self.assertEqual(
            verdict["summary"]["failures"],
            sorted(["LIBVIRT_DEFAULT_NET_INACTIVE", "LIBVIRT_NWFILTER_MISSING", "DATA_ROOT_NO_ODIRECT"]),
        )


class NetworkClashTest(unittest.TestCase):
    ROUTES = (
        "default via 203.0.113.1 dev eno1 proto static\n"
        "203.0.113.0/24 dev eno1 proto kernel scope link src 203.0.113.10\n"
    )
    ADDRS = "2: eno1    inet 203.0.113.10/24 brd 203.0.113.255 scope global eno1\\       valid_lft forever\n"

    def test_net_info_reads_netmask_or_prefix(self) -> None:
        self.assertEqual(lpf.libvirt_net_info(NET_XML), {"bridge": "virbr0", "ip": "192.168.122.1", "prefix": 24})
        self.assertEqual(lpf.libvirt_net_info("not xml"), {"bridge": "", "ip": "", "prefix": 0})

    def test_no_clash(self) -> None:
        self.assertEqual(lpf.libvirt_net_clash(self.ROUTES, self.ADDRS, "192.168.122.1", 24, "virbr0"), [])

    def test_a_route_or_an_address_in_the_range_clashes(self) -> None:
        routes = self.ROUTES + "192.168.0.0/16 dev wg0 scope link\n"
        addrs = self.ADDRS + "5: br-x    inet 192.168.122.7/24 brd 192.168.122.255 scope global br-x\n"
        self.assertEqual(
            lpf.libvirt_net_clash(routes, addrs, "192.168.122.1", 24, "virbr0"),
            ["wg0 192.168.0.0/16", "br-x 192.168.122.0/24"],
        )

    def test_the_bridge_itself_and_typed_routes(self) -> None:
        routes = "192.168.122.0/24 dev virbr0 proto kernel scope link linkdown\nunreachable 192.168.122.0/25 dev lo\n"
        self.assertEqual(lpf.libvirt_net_clash(routes, "", "192.168.122.1", 24, "virbr0"), ["lo 192.168.122.0/25"])


# ── The probe script, against stubs ─────────────────────────────────

STUBS = {
    # `virsh --connect URI <cmd> ...`; state in $FAKE_DIR.
    "virsh": r"""#!/bin/bash
shift 2
case "$1" in
  net-info)
    [ "${FAKE_NET_DEFINED:-1}" = 1 ] || exit 1
    echo "Name:           default"
    echo "Active:         ${FAKE_NET_ACTIVE:-yes}"
    echo "Autostart:      ${FAKE_NET_AUTOSTART:-yes}" ;;
  net-dumpxml) printf '%s\n' "$FAKE_NET_XML" ;;
  nwfilter-dumpxml) [ "${FAKE_NWFILTER:-1}" = 1 ] ;;
  create)
    cp "$2" "$FAKE_DIR/created.xml"
    if [ -n "${FAKE_CREATE_ERR:-}" ]; then echo "$FAKE_CREATE_ERR" >&2; exit 1; fi
    if [ -n "${FAKE_CREATE_LATE:-}" ]; then
      # libvirtd finishes the create after the client gave up.
      # (Its own session: `timeout` signals its whole process group.)
      setsid sh -c 'sleep 2; touch "$FAKE_DIR/running"' >/dev/null 2>&1 &
      exec sleep 30
    fi
    touch "$FAKE_DIR/running" ;;
  domstate) [ -e "$FAKE_DIR/running" ] || exit 1; echo paused ;;
  domiflist)
    echo " Interface   Type      Source    Model    MAC"
    echo " vnet9       network   default   virtio   52:54:00:00:00:01" ;;
  destroy)
    echo destroy >>"$FAKE_DIR/destroyed"
    [ -n "${FAKE_DESTROY_STUCK:-}" ] || rm -f "$FAKE_DIR/running" ;;
esac
""",
    "systemctl": r"""#!/bin/bash
case "$1" in
  cat) [ "${FAKE_UNIT:-1}" = 1 ] ;;
  show)
    case "$4" in
      ProtectSystem) echo strict ;;
      ReadWritePaths) echo "$FAKE_RW" ;;
      *) echo "" ;;
    esac ;;
esac
""",
    # Drop the sandbox options, run the command, record the properties.
    "systemd-run": r"""#!/bin/bash
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p) echo "$2" >>"$FAKE_DIR/sandbox-props"; shift 2 ;;
    --*) shift ;;
    *) break ;;
  esac
done
[ -z "${FAKE_SANDBOX_RO:-}" ] || { echo "mktemp: Read-only file system" >&2; exit 1; }
exec "$@"
""",
    # `runuser -u USER -- cmd`: a `test -x` on $FAKE_BLOCKED fails.
    "runuser": r"""#!/bin/bash
shift 3
if [ "$1" = test ] && [ "$3" = "${FAKE_BLOCKED:-}" ]; then exit 1; fi
case "$1" in
  *python3) [ -z "${FAKE_ODIRECT_USER_FAIL:-}" ] || { echo "O_DIRECT open for write: Permission denied" >&2; exit 1; } ;;
esac
exec "$@"
""",
    # A filesystem without O_DIRECT, or the real interpreter.
    "python3": r"""#!/bin/bash
echo "$*" >>"$FAKE_DIR/python3-calls"
if [ -n "${FAKE_NO_ODIRECT:-}" ]; then echo "O_DIRECT open for write: Invalid argument" >&2; exit 1; fi
exec "$FAKE_REAL_PYTHON" "$@"
""",
    # Ubuntu 26.04's uutils dd: `oflag=direct` works, `iflag=direct` reads
    # into an unaligned buffer and fails on every filesystem. The probe
    # must not depend on dd at all.
    "dd": r"""#!/bin/bash
echo "$*" >>"$FAKE_DIR/dd-calls"
case " $* " in *" iflag=direct "*) echo "dd: IO error: Invalid input" >&2; exit 1 ;; esac
""",
    "id": "#!/bin/bash\necho 64055\n",
    "chown": "#!/bin/bash\nexit 0\n",
}


def _odirect_ok(directory: str) -> bool:
    """Whether an aligned O_DIRECT write + read works in `directory`."""
    fd, path = tempfile.mkstemp(dir=directory)
    os.close(fd)
    try:
        buf = mmap.mmap(-1, 4096)
        fd = os.open(path, os.O_WRONLY | os.O_DIRECT)
        try:
            os.write(fd, buf)
        finally:
            os.close(fd)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
        try:
            os.readv(fd, [buf])
        finally:
            os.close(fd)
        return True
    except OSError:
        return False
    finally:
        os.unlink(path)


_SCRATCH_BASE = next(
    (d for d in (tempfile.gettempdir(), os.path.expanduser("~")) if _odirect_ok(d)), None
)


@unittest.skipIf(_SCRATCH_BASE is None, "no O_DIRECT-capable scratch filesystem")
class ProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(dir=_SCRATCH_BASE)
        base = pathlib.Path(self.tmp.name)
        self.fake = base / "fake"
        self.bin = base / "bin"
        self.data = base / "data"
        for d in (self.fake, self.bin, self.data):
            d.mkdir()
        os.chmod(self.data, 0o755)
        for name, body in STUBS.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
        self.config = base / "config.toml"
        self.config.write_text(
            f'[host]\ndata_disk_root = "/nope"\n\n[storage]\n# a comment\n'
            f'data_disk_root = "{self.data}"  # trailing\nstate_disk_root = "{self.data}"\n'
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_probe(self, *flags: str, **env: str) -> dict:
        full_env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "FAKE_DIR": str(self.fake),
            "FAKE_NET_XML": NET_XML,
            "FAKE_RW": str(self.data),
            "FAKE_REAL_PYTHON": sys.executable,
            **env,
        }
        out = subprocess.run(
            ["bash", str(_PROBE), "--data-root", str(self.data), "--state-root", str(self.data),
             "--staging-root", str(self.data / "staging"), "--unit", "hippius-miner-agent",
             "--config", str(self.config), *flags],
            env=full_env, capture_output=True, text=True, check=True, timeout=120,
        )
        return lpf.parse_probe(out.stdout)

    def leftovers(self) -> list:
        return sorted(p.name for p in self.data.iterdir())

    def test_read_only_probe_on_a_healthy_host(self) -> None:
        probe = self.run_probe()
        self.assertEqual(probe["config_data_root"], str(self.data))
        self.assertEqual(probe["qemu_user"], "libvirt-qemu")
        self.assertNotIn("odirect_0", probe)
        self.assertNotIn("smoke", probe)
        self.assertEqual(codes(lpf.miner_launch_preflight(probe, FACTS)), [])

    def test_full_probe_cleans_up_and_passes(self) -> None:
        probe = self.run_probe("--write", "--smoke")
        self.assertEqual(probe["smoke"], "ok")
        self.assertEqual(probe["sandbox_0"], f"{self.data}|ok")
        self.assertEqual(probe["odirect_0"], f"{self.data}|ok")
        self.assertEqual(probe["odirect_1"], f"{self.data / 'staging'}|skipped:missing")
        self.assertEqual(codes(lpf.miner_launch_preflight(probe, FACTS)), [])
        self.assertEqual(self.leftovers(), [])
        self.assertFalse((self.fake / "running").exists())
        xml = (self.fake / "created.xml").read_text()
        self.assertIn("cache='none'", xml)
        self.assertIn(f"<source file='{self.data}/.hippius-preflight-smoke.", xml)
        self.assertIn("<source network='default'/>", xml)
        self.assertIn("<name>hippius-preflight-smoke-", xml)
        self.assertNotIn("launchSecurity", xml)
        self.assertNotIn("vsock", xml)
        self.assertIn("ProtectSystem=strict", (self.fake / "sandbox-props").read_text())
        self.assertIn("O_DIRECT", (self.fake / "python3-calls").read_text())

    def test_the_odirect_probe_does_not_use_dd(self) -> None:
        # Regression: with the uutils dd stub first in PATH (its
        # `iflag=direct` read fails), every root still passes, on real
        # O_DIRECT I/O, and dd is never run.
        probe = self.run_probe("--write")
        self.assertEqual(probe["odirect_0"], f"{self.data}|ok")
        self.assertEqual(codes(lpf.miner_launch_preflight(probe, FACTS)), [])
        self.assertFalse((self.fake / "dd-calls").exists())

    def test_every_failure_is_reported_and_nothing_is_left_behind(self) -> None:
        probe = self.run_probe(
            "--write", "--smoke",
            FAKE_NET_ACTIVE="no", FAKE_NWFILTER="0", FAKE_NO_ODIRECT="1", FAKE_SANDBOX_RO="1",
            FAKE_BLOCKED=str(self.data.parent),
            FAKE_CREATE_ERR="error: Failed to start domain: network 'default' is not active",
        )
        verdict = lpf.miner_launch_preflight(probe, FACTS)
        self.assertEqual(
            verdict["summary"]["failures"],
            sorted([
                "LIBVIRT_DEFAULT_NET_INACTIVE", "LIBVIRT_NWFILTER_MISSING",
                "QEMU_CANNOT_TRAVERSE_DATA_ROOT", "AGENT_SANDBOX_CANNOT_WRITE",
                "DATA_ROOT_NO_ODIRECT", "LAUNCH_SMOKE_FAILED",
            ]),
        )
        self.assertEqual(self.leftovers(), [])
        # The failed create is still destroyed, in case libvirtd finished it.
        self.assertTrue((self.fake / "destroyed").exists())

    def test_a_create_that_completes_after_the_timeout_is_still_destroyed(self) -> None:
        probe = self.run_probe("--write", "--smoke", "--smoke-timeout", "1", FAKE_CREATE_LATE="1")
        self.assertEqual(probe["smoke"], "fail")
        self.assertIn("timed out after 1s", probe["smoke_err"])
        time.sleep(3)  # past the late completion, had the probe not waited for it
        self.assertFalse((self.fake / "running").exists())
        self.assertEqual(self.leftovers(), [])

    def test_a_smoke_domain_that_will_not_die_is_a_failure(self) -> None:
        probe = self.run_probe("--write", "--smoke", FAKE_DESTROY_STUCK="1")
        self.assertEqual(probe["smoke"], "fail")
        self.assertIn("could not be destroyed", probe["smoke_err"])
        self.assertEqual(codes(lpf.miner_launch_preflight(probe, FACTS)), ["LAUNCH_SMOKE_FAILED"])

    def test_the_agent_subdirs_are_probed_once_they_exist(self) -> None:
        (self.data / "overlay").mkdir()
        probe = self.run_probe("--write")
        rows = [v for k, v in probe.items() if k.startswith("odirect_")]
        self.assertIn(f"{self.data / 'overlay'}|ok", rows)
        self.assertIn(f"{self.data / 'data'}|skipped:missing", rows)
        self.assertEqual(sorted(p.name for p in (self.data / "overlay").iterdir()), [])

    def test_a_qemu_only_odirect_failure_is_a_permission(self) -> None:
        probe = self.run_probe("--write", FAKE_ODIRECT_USER_FAIL="1")
        self.assertTrue(probe["odirect_0"].startswith(f"{self.data}|fail-user:"))
        self.assertEqual(codes(lpf.miner_launch_preflight(probe, FACTS)), ["QEMU_CANNOT_OPEN_DATA_ROOT"])

    def test_no_virsh(self) -> None:
        # A PATH with only the probe's own tools and no virsh.
        (self.bin / "virsh").unlink()
        probe = self.run_probe(PATH=f"{self.bin}:/usr/bin:/bin")
        if probe.get("virsh") == "1":
            self.skipTest("virsh installed on this machine")
        self.assertEqual(probe, {"virsh": "0"})


if __name__ == "__main__":
    unittest.main()
