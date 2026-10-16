"""The miner-agent config template's storage rendering
(`miner_storage_pools`, `miner_storage_dedicated_disks`,
`miner_heartbeat_emit_pools`).

Renders `templates/miner-agent-config.toml.j2` the way Ansible does
(Jinja2, `trim_blocks`, the `bool` filter) and checks the TOML. With
`AGENT_BIN` set to a built `hippius-miner-agent`, the rendered file is also
read by the agent itself (`storage-check`): its own rules (the `default`
pool is `data_disk_root`, budgeted as `[host]`) decide, not a copy of them.

Run: python3 deploy/ansible/tests/test_miner_agent_config_storage.py
(needs jinja2).
"""

import json
import os
import pathlib
import subprocess
import tempfile
import tomllib
import unittest

import jinja2

_TEMPLATE = (
    pathlib.Path(__file__).resolve().parent.parent
    / "playbooks"
    / "miner-tasks"
    / "templates"
    / "miner-agent-config.toml.j2"
)


def _bool(value: object) -> bool:
    """Ansible's `bool` filter."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def render(**overrides: object) -> str:
    env = jinja2.Environment(
        trim_blocks=True,
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = _bool
    variables: dict[str, object] = {
        "miner_agent_miner_id": "m-0123456789abcdef",
        "network": {"edge_endpoint": "edge.example.invalid:443"},
        "mtls": {"cert_dir": "/var/lib/hippius-miner/mtls"},
        "edge_order_signing_pubkey": "11" * 32,
        "miner_agent": {"state_dir": "/var/lib/hippius-miner"},
        "image": {"s3_endpoint": "https://s3.example.invalid", "s3_bucket": "b"},
        "orders": {"port": 9700},
        "orders_bind_ip": "100.64.0.10",
        "ansible_processor_vcpus": 32,
        "ansible_memtotal_mb": 131072,
        "miner_data_fs_gb": 1000,
        "miner_data_fs_mount": "/",
        "host_cvm": {
            "reserve_cpus": 2,
            "cpu_ratio_pct": 100,
            "reserve_memory_mb": 8192,
            "reserve_disk_gb": 100,
        },
        "miner_data_disk_root": "/var/lib/hippius-miner",
        "miner_state_disk_root": "/var/lib/hippius-miner",
        "miner_heartbeat_schema_capacity": True,
        "miner_heartbeat_schema_disk": True,
        "miner_heartbeat_schema_host_health": True,
        "miner_heartbeat_schema_agent_version": True,
    }
    variables.update(overrides)
    return env.from_string(_TEMPLATE.read_text()).render(**variables)


NVME0 = {"id": "nvme0", "class": "nvme", "budget_gb": 3200, "source": "/mnt/hippius-data"}


class StorageRenderingTest(unittest.TestCase):
    def test_nothing_declared_renders_no_pool_no_disk_no_v7(self) -> None:
        cfg = tomllib.loads(render())
        self.assertNotIn("pools", cfg["storage"])
        self.assertNotIn("dedicated_disks", cfg["storage"])
        self.assertNotIn("emit_pools", cfg["heartbeat"])

    def test_pools_render_default_first_budgeted_as_the_host(self) -> None:
        cfg = tomllib.loads(
            render(
                miner_storage_pools=[
                    NVME0,
                    {"id": "hdd0", "class": "hdd", "budget_gb": 8000, "os_disks": False,
                     "state": "draining"},
                ],
                miner_heartbeat_emit_pools=True,
            )
        )
        pools = cfg["storage"]["pools"]
        self.assertEqual(
            pools[0],
            {
                "id": "default",
                "path": "/var/lib/hippius-miner",
                "class": "nvme",
                "budget_gb": cfg["host"]["cvm_disk_gb_budget"],
            },
        )
        self.assertEqual(
            pools[1],
            {
                "id": "nvme0",
                "path": "/var/lib/hippius-miner/pools/nvme0",
                "class": "nvme",
                "budget_gb": 3200,
            },
        )
        self.assertEqual(
            pools[2],
            {
                "id": "hdd0",
                "path": "/var/lib/hippius-miner/pools/hdd0",
                "class": "hdd",
                "budget_gb": 8000,
                "os_disks": False,
                "state": "draining",
            },
        )
        self.assertIs(cfg["heartbeat"]["emit_pools"], True)

    def test_the_default_budget_follows_a_host_override(self) -> None:
        cfg = tomllib.loads(
            render(miner_storage_pools=[NVME0], host_cvm_overrides={"disk_gb_budget_max": 500})
        )
        self.assertEqual(cfg["host"]["cvm_disk_gb_budget"], 500)
        self.assertEqual(cfg["storage"]["pools"][0]["budget_gb"], 500)

    def test_dedicated_disks_render_without_pools(self) -> None:
        cfg = tomllib.loads(
            render(
                miner_storage_dedicated_disks=[
                    {"id": "wwn-0x5000c500deadbeef"},
                    {"id": "ata-SAMSUNG_X", "state": "draining"},
                ]
            )
        )
        self.assertNotIn("pools", cfg["storage"])
        self.assertEqual(
            cfg["storage"]["dedicated_disks"],
            [{"id": "wwn-0x5000c500deadbeef"}, {"id": "ata-SAMSUNG_X", "state": "draining"}],
        )

    @unittest.skipUnless(os.environ.get("AGENT_BIN"), "AGENT_BIN not set")
    def test_the_agent_accepts_the_rendered_declaration(self) -> None:
        text = render(
            miner_storage_pools=[NVME0],
            miner_storage_dedicated_disks=[{"id": "wwn-0x5000c500deadbeef"}],
            miner_heartbeat_emit_pools=True,
        )
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "config.toml"
            config.write_text(text)
            facts = pathlib.Path(tmp) / "facts.json"
            subprocess.run(
                [os.environ["AGENT_BIN"], "storage-collect", "--out", str(facts)],
                check=True,
            )
            out = subprocess.run(
                [os.environ["AGENT_BIN"], "storage-check", "--config", str(config),
                 "--facts", str(facts)],
                check=True,
                capture_output=True,
                text=True,
            )
        report = json.loads(out.stdout)
        self.assertIsNone(report["storage_error"], report)
        self.assertEqual([p["id"] for p in report["pools"]], ["default", "nvme0"])


if __name__ == "__main__":
    unittest.main()
