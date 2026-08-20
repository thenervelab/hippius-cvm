"""Chart-vs-code agreement for the §23 uptime-liveness gate.

Chart-vs-code disagreement has bitten this repo twice, so these tests
assert the RENDERED value — not the Python default. A Rust/Python
default that says "safe" is worthless if the ConfigMap the cluster
actually reads says something else, or says nothing at all.

Three properties:

  1. the chart renders `VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION`
     EXPLICITLY as `"true"` — the ARMED state is stated, never inferred;
  2. rendering FAILS when the value is unset (`required`, not
     `| default`) — an operator cannot silently drop into either regime;
  3. the COMPILED DEFAULT stays conservative (`False`), so a missing or
     unreadable ConfigMap key can never arm the gate by accident. Only
     an explicit chart value arms it.

ARMED 2026-08-13 (P1). Property 3 used to read "the rendered value
agrees with the compiled default, so deploying this chart changes
nothing about accrual". That could only hold while the gate was OFF —
arming it is precisely the act of making the chart say something the
conservative code default does not. What was worth keeping from it is
the half that still has teeth: config ABSENCE must fail safe, never
arm. That is now property 3, and `test_chart_can_still_render_the_
disabled_state` keeps the armed value from becoming a hardcode in the
other direction.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[4]
CHART_DIR = REPO_ROOT / "deploy" / "gitops" / "apps" / "vali"
VALUES = CHART_DIR / "values.yaml"
CONFIGMAP_TPL = CHART_DIR / "templates" / "configmap-vali.yaml"

FLAG = "VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION"

_HELM = shutil.which("helm")
_needs_helm = pytest.mark.skipif(_HELM is None, reason="helm is not installed")


def _render(*extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(_HELM), "template", "vali", str(CHART_DIR), *extra],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _rendered_configmap_data() -> dict[str, str]:
    proc = _render()
    assert proc.returncode == 0, proc.stderr
    for doc in yaml.safe_load_all(proc.stdout):
        if (
            isinstance(doc, dict)
            and doc.get("kind") == "ConfigMap"
            and FLAG in (doc.get("data") or {})
        ):
            return doc["data"]
    raise AssertionError(f"no rendered ConfigMap carries {FLAG}")


@_needs_helm
def test_chart_renders_the_gate_explicitly_armed() -> None:
    data = _rendered_configmap_data()
    # The exact rendered string, not a truthiness check: "" or a missing
    # key would read as DISABLED while saying nothing — and silently
    # un-arming a gate is the failure this whole file exists to catch.
    assert data[FLAG] == "true"


@_needs_helm
def test_chart_render_fails_when_the_flag_is_unset() -> None:
    """`required`, not `| default` — the operator must SAY which regime
    is live. A mutant that swaps `required` for a default makes this
    render succeed."""
    proc = _render("--set", "uptimeLiveness.requireAttestation=null")
    assert proc.returncode != 0
    assert "must be set explicitly" in proc.stderr


@_needs_helm
def test_config_absence_can_never_arm_the_gate() -> None:
    """The compiled default must stay CONSERVATIVE. The chart arms the
    gate explicitly; if the ConfigMap key ever goes missing or unreadable,
    the code must fall back to NOT crediting-by-default rather than
    silently enforcing — an absent config must never be load-bearing in
    either direction, and here the safe direction is `False`."""
    from apps.scheduler import usage
    from vali.settings import _env_bool

    assert _env_bool("X", False) is False  # sanity: the parser exists
    # `usage` reads the flag through `getattr(settings, ..., False)`; with
    # the test settings carrying no value, that default is what answers.
    assert usage._require_liveness_attestation() is False
    # ...while the CHART, which is what production actually reads, arms it.
    assert _rendered_configmap_data()[FLAG] == "true"


@_needs_helm
def test_chart_can_still_render_the_disabled_state() -> None:
    """The armed value must not be a hardcode either — an operator can
    still pause the gate (e.g. for a fleet that genuinely cannot attest)."""
    proc = _render("--set", "uptimeLiveness.requireAttestation=false")
    assert proc.returncode == 0, proc.stderr
    assert f'{FLAG}: "false"' in proc.stdout


# ─── helm-free guards (so a CI image without helm still catches drift) ─


def test_values_yaml_ships_the_gate_armed() -> None:
    values = yaml.safe_load(VALUES.read_text())
    assert values["uptimeLiveness"]["requireAttestation"] is True


def test_configmap_template_uses_required_not_default() -> None:
    line = next(
        ln for ln in CONFIGMAP_TPL.read_text().splitlines() if ln.strip().startswith(FLAG)
    )
    assert "required " in line, "the flag must be `required`, never defaulted"
    assert not re.search(r"\|\s*default", line), (
        "a `| default` fallback would let an absent key silently pick a regime"
    )


def test_values_yaml_documents_the_arming_sequence() -> None:
    """The imperative lives beside the flag — a future operator must not
    have to reconstruct the order from the code."""
    text = VALUES.read_text()
    assert "ARMING SEQUENCE" in text
    assert "VALI_KBS_L0_VERIFYING_KEY" in text
