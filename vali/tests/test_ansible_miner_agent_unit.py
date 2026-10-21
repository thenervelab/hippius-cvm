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


def test_storage_pools_are_bind_mounted_durably_under_the_pools_root() -> None:
    """A pool with a `source` gets an fstab bind at <state_dir>/pools/<id>,
    ordered after its source mount, so a reboot brings it back before the
    agent (a pool missing at boot reports `pool-unbound`)."""
    tasks = yaml.safe_load(TASKS.read_text())
    (bind,) = [
        t
        for t in tasks
        if t.get("name") == "Bind-mount each storage pool's filesystem at its pool path (fstab)"
    ]
    mount = bind["ansible.posix.mount"]
    assert mount["path"] == "{{ miner_agent.state_dir }}/pools/{{ item.id }}"
    assert mount["fstype"] == "none"
    assert mount["opts"] == (
        "bind,nofail,x-systemd.requires-mounts-for={{ item.source }},"
        "x-systemd.before=hippius-miner-agent.service"
    )
    assert mount["state"] == "mounted"
    names = [t.get("name") for t in tasks]
    assert names.index(bind["name"]) < names.index("Render the miner-agent config")


def test_the_play_builds_from_source_only_when_asked() -> None:
    """A missing or foreign binary is replaced by the verified release
    (`hippius-miner-update --install`, miner-agent-binary.yml) unless the
    host opts in to the source build: the published group_vars cannot
    clone a repository only we can read, and the release install never
    runs on a source-build host."""
    group_vars = yaml.safe_load((REPO / "deploy/ansible/group_vars/miner_nodes.yml").read_text())
    assert group_vars["miner_agent_build_from_source"] is False
    tasks = yaml.safe_load(TASKS.read_text())
    names = [t.get("name") for t in tasks]
    binary = "Install the miner-agent release binary unless it is in place"
    (task,) = [t for t in tasks if t.get("name") == binary]
    assert task["ansible.builtin.import_tasks"] == "miner-agent-binary.yml"
    (gate,) = [
        t
        for t in tasks
        if t.get("name") == "Set whether the miner-agent is built from source on this host"
    ]
    assert gate["ansible.builtin.set_fact"]["miner_agent_source_build"] == (
        "{{ (miner_agent_install_needed | bool) and (miner_agent_build_from_source | bool) }}"
    )
    builds = [i for i, t in enumerate(tasks) if t.get("when") == "miner_agent_source_build | bool"]
    assert len(builds) == 6 and names.index(binary) < names.index(gate["name"]) < min(builds)

    release = yaml.safe_load((TASKS.parent / "miner-agent-binary.yml").read_text())
    (install,) = [
        t
        for t in release
        if t.get("name") == "Install the miner-agent release, verified as an auto-update is"
    ]
    assert install["ansible.builtin.command"]["argv"] == (
        "{{ [miner_agent_updater] + miner_agent_updater_args }}"
    )
    assert install["when"] == ["miner_agent_release_runs | bool", "not ansible_check_mode"]
    (choose,) = [t for t in release if t.get("name") == "Choose the updater run"]
    facts = choose["ansible.builtin.set_fact"]
    # A missing or foreign binary goes to the release only without the
    # source build; an explicit `miner_agent_version` always does.
    assert "not (miner_agent_build_from_source | bool)" in facts["miner_agent_release_runs"]
    assert "(miner_agent_pin_needed | bool)" in facts["miner_agent_release_runs"]
    # Only a running agent is swapped (`--tag` alone); otherwise `--install`.
    assert "== 'active'" in facts["miner_agent_updater_args"]
    assert "['--install']" in facts["miner_agent_updater_args"]


def test_placeholders_are_refused_before_the_config_is_rendered() -> None:
    tasks = yaml.safe_load(TASKS.read_text())
    names = [t.get("name") for t in tasks]
    check = "Refuse an unfilled placeholder before rendering the config"
    (task,) = [t for t in tasks if t.get("name") == check]
    assert task["ansible.builtin.import_tasks"] == "placeholder-check.yml"
    assert names.index(check) < names.index("Render the miner-agent config")


def test_the_play_expects_the_crate_version_the_releases_report() -> None:
    """Play 05 reinstalls a binary whose `--version` lacks
    `versions.miner_agent`, and refuses a release that still lacks it, so a
    crate bump without the group_vars one would stop every re-run."""
    group_vars = yaml.safe_load((REPO / "deploy/ansible/group_vars/miner_nodes.yml").read_text())
    cargo = (REPO / "binaries/miner-agent/Cargo.toml").read_text()
    (crate_version,) = [
        line.split("=", 1)[1].strip().strip('"')
        for line in cargo.split("[package]", 1)[1].split("\n[", 1)[0].splitlines()
        if line.startswith("version")
    ]
    assert group_vars["versions"]["miner_agent"] == crate_version
