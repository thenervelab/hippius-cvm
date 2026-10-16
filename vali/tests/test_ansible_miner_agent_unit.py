"""Guard the miner-agent systemd unit that Ansible installs
(`deploy/ansible/playbooks/miner-tasks/miner-agent-install.yml`).

A HARD dependency (`Requires=` / `BindsTo=` / `PartOf=` / `Requisite=`) on
netbird or libvirtd means stopping or restarting either one also stops the
agent: a netbird apt upgrade, a libvirt postinst or an operator restart
takes it down, and a stopped agent tears down every tenant domain unless
`skip_shutdown_teardown` happens to be loaded. Observed 2026-09-28
(`systemctl stop netbird` stopped the agent). Only soft `Wants=` + ordering
`After=` are allowed.

Hermetic: it reads the task file from the repo; no Ansible run.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
TASKS = REPO / "deploy/ansible/playbooks/miner-tasks/miner-agent-install.yml"
HARD = ("Requires", "BindsTo", "PartOf", "Requisite")
SOFT_DEPS = ("libvirtd.service", "netbird.service")


def _unit_section() -> dict[str, list[str]]:
    tasks = yaml.safe_load(TASKS.read_text())
    (task,) = [t for t in tasks if t.get("name") == "Install the miner-agent systemd unit"]
    content: str = task["ansible.builtin.copy"]["content"]
    section = content.split("[Unit]", 1)[1].split("[Service]", 1)[0]
    directives: dict[str, list[str]] = {}
    for line in section.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        directives.setdefault(key.strip(), []).extend(value.split())
    return directives


def test_the_agent_has_no_hard_dependency_on_anything() -> None:
    unit = _unit_section()
    for key in HARD:
        assert key not in unit, f"{key}={unit[key]} would stop the agent with its target"


def test_netbird_and_libvirtd_are_wanted_and_ordered_before_the_agent() -> None:
    unit = _unit_section()
    for dep in SOFT_DEPS:
        assert dep in unit.get("Wants", []), f"{dep} must be pulled in (Wants=)"
        assert dep in unit.get("After", []), f"the agent must start after {dep}"


def _content(name: str) -> str:
    tasks = yaml.safe_load(TASKS.read_text())
    (task,) = [t for t in tasks if t.get("name") == name]
    return task["ansible.builtin.copy"]["content"]


def test_the_agent_keeps_its_device_sandbox_and_writes_the_pools_root() -> None:
    service = _content("Install the miner-agent systemd unit").split("[Service]", 1)[1]
    assert "PrivateDevices=true" in service
    assert "ProtectSystem=strict" in service
    (rw,) = [line for line in service.splitlines() if line.strip().startswith("ReadWritePaths=")]
    # Pools live under the state dir (`/var/lib/hippius-miner/pools/<id>`),
    # which must stay writable.
    assert "miner_agent.state_dir" in rw


def test_the_play_pins_the_state_dir_to_the_agents_pools_root() -> None:
    """The agent's pools root is a constant; the play must refuse an
    inventory whose state dir would not contain it."""
    source = (REPO / "binaries/miner-agent/src/storage/pools.rs").read_text()
    (line,) = [x for x in source.splitlines() if x.startswith("pub const POOLS_ROOT")]
    pools_root = line.split('"')[1]
    state_dir = str(Path(pools_root).parent)
    tasks = yaml.safe_load(TASKS.read_text())
    pin_name = "Assert the miner-agent state dir is the agent's fixed layout"
    (pin,) = [t for t in tasks if t.get("name") == pin_name]
    assert pin["ansible.builtin.assert"]["that"] == [f'miner_agent.state_dir == "{state_dir}"']
    group_vars = yaml.safe_load((REPO / "deploy/ansible/group_vars/miner_nodes.yml").read_text())
    assert group_vars["miner_agent"]["state_dir"] == state_dir
    names = [t.get("name") for t in tasks]
    assert names.index("Assert the miner-agent state dir is not a symlink") < names.index(
        "Ensure the miner-agent state directory exists"
    )


def test_the_storage_collector_reads_devices_and_has_no_network() -> None:
    unit = _content("Install the storage collector (dedicated-disk facts) service")
    assert "storage-collect --out /run/hippius-miner/disk-facts.json" in unit
    assert "PrivateDevices" not in unit
    assert "PrivateNetwork=true" in unit
    assert "Type=oneshot" in unit
    timer = _content("Install the storage collector timer")
    assert "OnUnitActiveSec=5min" in timer
