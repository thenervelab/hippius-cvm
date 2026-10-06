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
