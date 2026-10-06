"""The NetBird userdata purges cloud-init's copies of itself.

cloud-init keeps the whole userdata, the NetBird setup key in it, under
/run/cloud-init and /var/lib/cloud/instances/*. The shipped template
(docs/operator/userdata-templates/netbird-enabled.yaml.example) and the
synthetic monitor's copy of it remove them, and the setup-key file, once
the boot's cloud-init is done. Pins: both carry the SAME purge; it removes
exactly those copies (every instance dir) and nothing cloud-init or NetBird
needs later; it is the last step, queued behind cloud-final without
blocking on it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from apps.synthetic import e2e

REPO_ROOT = Path(__file__).resolve().parents[4]
TEMPLATE = REPO_ROOT / "docs/operator/userdata-templates/netbird-enabled.yaml.example"

#: The setup-key file and cloud-init's copies of the userdata — all must go.
COPIES = (
    "var/lib/cloud/seed/nocloud/netbird-setup-key",
    "run/cloud-init/seed/user-data",
    "run/cloud-init/combined-cloud-config.json",
    "var/lib/cloud/instances/iid-a/user-data.txt",
    "var/lib/cloud/instances/iid-a/user-data.txt.i",
    "var/lib/cloud/instances/iid-a/cloud-config.txt",
    "var/lib/cloud/instances/iid-a/obj.pkl",
    # an earlier boot's instance (M0 gets a fresh instance-id every boot)
    "var/lib/cloud/instances/iid-b/user-data.txt",
    "var/lib/cloud/instances/iid-b/obj.pkl",
)
#: What the next boot, cloud-init or NetBird still need.
KEPT = (
    "run/cloud-init/seed/meta-data",
    "run/cloud-init/status.json",
    "var/lib/cloud/data/instance-id",
    "var/lib/cloud/instances/iid-a/sem/config_runcmd",
    "var/lib/netbird/config.json",
)


def _parsed(text: str) -> dict:
    text = text.replace("{{NETBIRD_SETUP_KEY}}", "key").replace("{{NETBIRD_HOSTNAME}}", "host")
    return yaml.safe_load(text)


SOURCES = {
    "template": lambda: _parsed(TEMPLATE.read_text()),
    "synthetic": lambda: _parsed(e2e._DEFAULT_USERDATA),
}


def _purge(doc: dict) -> list[str]:
    (step,) = [s for s in doc["runcmd"] if isinstance(s, list) and s[:1] == ["systemd-run"]]
    return step


def test_the_synthetic_monitor_purges_like_the_template() -> None:
    assert _purge(SOURCES["synthetic"]()) == _purge(SOURCES["template"]())


@pytest.mark.parametrize("source", sorted(SOURCES))
def test_the_purge_removes_every_copy_and_nothing_else(tmp_path, source) -> None:
    script = _purge(SOURCES[source]())[-1]
    rooted = script.replace("/run/", f"{tmp_path}/run/").replace("/var/", f"{tmp_path}/var/")
    for rel in COPIES + KEPT:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")

    subprocess.run(["sh", "-c", rooted], check=True)

    assert [rel for rel in COPIES if (tmp_path / rel).exists()] == []
    assert [rel for rel in KEPT if not (tmp_path / rel).exists()] == []


@pytest.mark.parametrize("source", sorted(SOURCES))
def test_the_purge_is_last_and_queued_behind_cloud_final(source) -> None:
    runcmd = SOURCES[source]()["runcmd"]
    assert runcmd[-1] == _purge(SOURCES[source]())
    # `--no-block`: waiting for the unit from inside cloud-final deadlocks.
    assert runcmd[-1][:-1] == [
        "systemd-run",
        "--no-block",
        "-pAfter=cloud-final.service",
        "sh",
        "-c",
    ]
    assert not any(isinstance(s, list) and s[:1] == ["shred"] for s in runcmd)
