"""Chart pin for the guest NIC launch spec (`net_policy.launch_net_spec`).

`VALI_NET_LAUNCH_SPEC` is read at order-build time, in whichever process
builds the launch, relaunch or §25 activation order. Three do:

  * `vali` (web) — power start / reboot (`power.start_vm`), the
    guest-upgrade recover endpoint, and the operator CLIs exec'd there
    (`vali_create_vm`, `vali_guest_upgrade --recover`);
  * `vali-launch-tick` — `launch_jobs.run_job` → `launch.launch_vm`;
  * `vali-orchestration-tick` — reboot-recovery, resize, guest upgrade,
    userdata restage and `effects.dispatch_migrate_activate` (§25).

If one of them rendered a different value, a VM would get a capped,
filtered NIC or not depending on which process happened to dispatch it.
So these tests assert the RENDERED Deployments: the same keys, the same
values, in exactly those three, and nowhere the code default changes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[4]
CHART_DIR = REPO_ROOT / "deploy" / "gitops" / "apps" / "vali"
VALUES = CHART_DIR / "values.yaml"
TEMPLATES = CHART_DIR / "templates"
VALI_SRC = REPO_ROOT / "vali"

PREFIXES = ("VALI_NET_LAUNCH_", "VALI_NET_CAP_")
SPEC = "VALI_NET_LAUNCH_SPEC"
MINERS = "VALI_NET_LAUNCH_SPEC_MINERS"
ISOLATE = "VALI_NET_LAUNCH_ISOLATE"
CAP_BY_FLAVOR = "VALI_NET_CAP_MBPS_BY_FLAVOR"
CAP_DEFAULT = "VALI_NET_CAP_DEFAULT_MBPS"
CAP_PUBLIC_IP = "VALI_NET_CAP_PUBLIC_IP_MBPS"
#: The isolation-only flip: caps high enough not to limit anything.
NO_LIMIT_MBPS = 10000

#: Every workload whose process builds a launch / relaunch / §25 order.
DISPATCHERS = {
    "Deployment/vali": "deployment-vali.yaml",
    "Deployment/vali-launch-tick": "deployment-launch-tick.yaml",
    "Deployment/vali-orchestration-tick": "deployment-orchestration-tick.yaml",
}

_HELM = shutil.which("helm")
# Skippable on a dev box without helm, never in CI (same rule as
# test_vault_auth_chart.py).
_needs_helm = pytest.mark.skipif(
    _HELM is None and not os.environ.get("CI"),
    reason="helm is not installed (local run)",
)


def _docs(*extra: str) -> list[dict[str, Any]]:
    proc = subprocess.run(
        [str(_HELM), "template", "vali", str(CHART_DIR), *extra],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return [d for d in yaml.safe_load_all(proc.stdout) if isinstance(d, dict)]


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    spec = doc.get("spec") or {}
    if doc.get("kind") == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec")


def _launch_env(*extra: str) -> dict[str, dict[str, str]]:
    """`<kind>/<name>[<container>]` -> its VALI_NET_LAUNCH_* / VALI_NET_CAP_* env, for every
    rendered container that carries at least one of them."""
    out: dict[str, dict[str, str]] = {}
    for doc in _docs(*extra):
        pod = _pod_spec(doc)
        if not pod:
            continue
        label = f"{doc['kind']}/{doc['metadata']['name']}"
        for container in pod.get("containers") or []:
            env = {
                e["name"]: e.get("value")
                for e in container.get("env") or []
                if e.get("name", "").startswith(PREFIXES)
            }
            if env:
                out[f"{label}[{container['name']}]"] = env
    return out


def _by_workload(env: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {label.split("[", 1)[0]: values for label, values in env.items()}


@_needs_helm
def test_disabled_render_is_the_code_default_in_every_dispatcher() -> None:
    env = _by_workload(_launch_env("--set-string", "netLaunchSpec.enabled=false"))
    assert set(env) == set(DISPATCHERS)
    for label, values in env.items():
        # "false" exactly: the code default (`_env_bool(..., False)`), and
        # neither the miner list, isolate nor a cap override leaks into a
        # disabled render.
        assert values == {SPEC: "false"}, label


@_needs_helm
def test_enabled_render_is_identical_in_every_dispatcher() -> None:
    env = _by_workload(
        _launch_env(
            "--set", "netLaunchSpec.enabled=true",
            "--set", "netLaunchSpec.miners=miner-a\\,miner-b",
        )
    )
    assert set(env) == set(DISPATCHERS)
    first = next(iter(env.values()))
    assert {k: first[k] for k in (SPEC, MINERS, ISOLATE)} == {
        SPEC: "true",
        MINERS: "miner-a,miner-b",
        ISOLATE: "true",
    }
    assert set(first) == {SPEC, MINERS, ISOLATE, CAP_BY_FLAVOR, CAP_DEFAULT, CAP_PUBLIC_IP}
    for label, values in env.items():
        assert values == first, label


@_needs_helm
def test_enabled_caps_do_not_limit_any_flavor(settings: Any) -> None:
    """Isolation-only flip: every cap the rendered env yields is the
    no-limit value, within what vali and the agent accept (edge room
    included), for every catalogue flavor and runner flavor."""
    from apps.network import net_policy
    from apps.network.models import EgressMode
    from apps.orchestration.services import flavors

    env = next(iter(_launch_env("--set", "netLaunchSpec.enabled=true").values()))
    settings.VALI_NET_CAP_MBPS_BY_FLAVOR = json.loads(env[CAP_BY_FLAVOR])
    settings.VALI_NET_CAP_DEFAULT_MBPS = int(env[CAP_DEFAULT])
    settings.VALI_NET_CAP_PUBLIC_IP_MBPS = int(env[CAP_PUBLIC_IP])
    names = [*flavors._CATALOGUE, *flavors._RUNNER_CATALOGUE, "not-a-flavor"]
    for name in names:
        for public_ip in (False, True):
            cap = net_policy.effective_cap_mbps(name, has_public_ip=public_ip)
            assert cap == NO_LIMIT_MBPS, (name, public_ip)
            for mode in EgressMode.values:
                assert net_policy.miner_cap_mbps(cap, mode) <= net_policy.MAX_VM_CAP_MBPS
    assert set(settings.VALI_NET_CAP_MBPS_BY_FLAVOR) == set(flavors._CATALOGUE)


@_needs_helm
def test_isolate_false_is_not_swallowed_by_a_default() -> None:
    """A bool `false` from `--set` is "empty" to `| default`; the helper
    must still render it as "false"."""
    env = _by_workload(
        _launch_env("--set", "netLaunchSpec.enabled=true", "--set", "netLaunchSpec.isolate=false")
    )
    assert {values[ISOLATE] for values in env.values()} == {"false"}
    assert set(env) == set(DISPATCHERS)


# ─── helm-free guards ─


def test_values_ship_a_canary_within_the_net_policy_miners() -> None:
    """The spec is either off, or on for miners that also get the
    net-policy push (launch_net_spec needs an acked policy), isolated and
    with the no-limit caps."""
    values = yaml.safe_load(VALUES.read_text())
    spec = values["netLaunchSpec"]
    caps = spec.pop("caps")
    assert spec["enabled"] in {"true", "false"}
    assert spec["isolate"] == "true"
    if spec["enabled"] == "true":
        listed = set(spec["miners"].split(","))
        push = values["orchestrationTick"]["netPolicy"]
        assert push["push"] == "true"
        assert "*" not in listed
        assert listed <= set(push["miners"].split(","))
    assert caps["defaultMbps"] == caps["publicIpMbps"] == str(NO_LIMIT_MBPS)
    assert set(json.loads(caps["byFlavor"]).values()) == {NO_LIMIT_MBPS}


def test_every_dispatcher_includes_the_shared_helper() -> None:
    for label, template in DISPATCHERS.items():
        text = (TEMPLATES / template).read_text()
        assert text.count('include "vali.netLaunchSpecEnv"') == 1, label
    for template in TEMPLATES.glob("*.yaml"):
        if template.name in DISPATCHERS.values():
            continue
        # A hand-written key elsewhere would drift from the helper.
        text = template.read_text()
        assert not any(prefix in text for prefix in PREFIXES), template.name


def test_launch_net_spec_call_sites_are_the_known_ones() -> None:
    """A new caller of `launch_net_spec` may run in a process not listed in
    DISPATCHERS. Revisit that list (and the chart) before updating this."""
    callers = set()
    for path in (VALI_SRC / "apps").rglob("*.py"):
        if "tests" in path.parts:
            continue
        if re.search(r"\blaunch_net_spec\(", path.read_text()):
            callers.add(path.relative_to(VALI_SRC).as_posix())
    assert callers == {
        "apps/network/net_policy.py",
        "apps/orchestration/effects.py",
        "apps/orchestration/services/launch.py",
    }
