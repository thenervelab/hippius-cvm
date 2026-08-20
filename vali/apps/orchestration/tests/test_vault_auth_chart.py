"""Chart-level pin for the Vault k8s-auth (jwt) credential (M-k8sauth, #94).

WHY THIS FILE EXISTS (P4, 2026-08-12). Every FULL synthetic-monitor run
from 2026-08-09 failed at exactly one stage:

    synthetic stage crypto_erase failed: vault-jwt-login: no projected SA token

The live `synthetic-monitor-full` CronJob carried the jwt ENV
(`VALI_VAULT_JWT_TOKEN_PATH=/var/run/secrets/vault/token`) and the
`vault-sa-token` projected VOLUME — but the container had no
`volumeMounts` entry for it, so the file was never there. The five vali
Deployments had all three. That asymmetry is invisible in review: the
volume is present, the env is present, and nothing reads the mount.

So these tests assert the RENDERED manifests, sweeping EVERY pod spec in
the chart rather than naming the two CronJobs: the invariant is
"any container told to authenticate with a projected token must actually
be given one, AT the path it was told to read", which must hold for the
next workload too.

The strong assertions need `helm` (present on GitHub's ubuntu runners);
the helm-free guards below still catch the template-level drift on a host
without it.
"""

from __future__ import annotations

import os
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

TOKEN_PATH_ENV = "VALI_VAULT_JWT_TOKEN_PATH"
# The Vault `vali` role pins `bound_audiences=["vault"]`. A drift here is
# an HTTP 400 at login that reads like a broken deployment.
EXPECTED_AUDIENCE = "vault"

_HELM = shutil.which("helm")
# Skippable on a dev box without helm — NEVER in CI. A pin that silently
# skips is not a pin, and "the volumeMount cannot vanish again" is the
# whole point of this file. GitHub's ubuntu runners ship helm; if that
# ever stops being true these ERROR rather than quietly passing.
_needs_helm = pytest.mark.skipif(
    _HELM is None and not os.environ.get("CI"),
    reason="helm is not installed (local run)",
)


def _render(*extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(_HELM), "template", "vali", str(CHART_DIR), *extra],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _docs(*extra: str) -> list[dict[str, Any]]:
    proc = _render(*extra)
    assert proc.returncode == 0, proc.stderr
    return [d for d in yaml.safe_load_all(proc.stdout) if isinstance(d, dict)]


def _pod_specs(docs: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """(`<kind>/<name>`, podSpec) for every workload the chart renders."""
    out: list[tuple[str, dict[str, Any]]] = []
    for doc in docs:
        kind = doc.get("kind")
        name = (doc.get("metadata") or {}).get("name", "?")
        spec = doc.get("spec") or {}
        if kind in {"Deployment", "StatefulSet", "ReplicaSet", "DaemonSet"}:
            pod = ((spec.get("template") or {}).get("spec")) or None
        elif kind == "Job":
            pod = ((spec.get("template") or {}).get("spec")) or None
        elif kind == "CronJob":
            job = (spec.get("jobTemplate") or {}).get("spec") or {}
            pod = ((job.get("template") or {}).get("spec")) or None
        else:
            pod = None
        if pod:
            out.append((f"{kind}/{name}", pod))
    return out


def _env_map(container: dict[str, Any]) -> dict[str, Any]:
    return {e.get("name"): e for e in (container.get("env") or [])}


def _jwt_containers(docs: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """(label, podSpec, container) for every container told to use jwt auth."""
    found = []
    for label, pod in _pod_specs(docs):
        for container in pod.get("containers") or []:
            if TOKEN_PATH_ENV in _env_map(container):
                found.append((f"{label}[{container.get('name')}]", pod, container))
    return found


def _projected_sa_volumes(pod: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """volume-name -> the `serviceAccountToken` source, for projected volumes."""
    out: dict[str, dict[str, Any]] = {}
    for vol in pod.get("volumes") or []:
        for source in ((vol.get("projected") or {}).get("sources")) or []:
            sat = source.get("serviceAccountToken")
            if sat:
                out[vol["name"]] = sat
    return out


# ── the invariant: env ⇒ a real token at that exact path ────────────────


@_needs_helm
def test_every_jwt_container_actually_mounts_a_projected_token() -> None:
    """CLAIM: a container that carries `VALI_VAULT_JWT_TOKEN_PATH` also has
    a volumeMount of a projected `serviceAccountToken` volume AT the
    directory of that path. This is the exact assertion the production
    CronJobs failed: volume yes, mount no."""
    containers = _jwt_containers(_docs())
    assert containers, "no rendered container uses jwt auth — the sweep is inert"
    for label, pod, container in containers:
        token_path = _env_map(container)[TOKEN_PATH_ENV]["value"]
        sa_volumes = _projected_sa_volumes(pod)
        mounts = {m["name"]: m for m in (container.get("volumeMounts") or [])}
        backing = [n for n in sa_volumes if n in mounts]
        assert backing, (
            f"{label} is told to read {token_path!r} but mounts no projected "
            f"ServiceAccount token (pod volumes: {sorted(sa_volumes)}, "
            f"container mounts: {sorted(mounts)})"
        )
        name = backing[0]
        rendered = f"{mounts[name]['mountPath'].rstrip('/')}/{sa_volumes[name]['path']}"
        assert rendered == token_path, (
            f"{label}: the token is projected to {rendered!r} but the process "
            f"is told to read {token_path!r}"
        )


@_needs_helm
def test_every_jwt_container_projects_the_audience_vault_pins() -> None:
    """CLAIM: the projected token's audience is the one the Vault role
    binds. A mismatch is an HTTP 400 at login — a failure that reads
    exactly like a missing token, which is why it is pinned here."""
    for label, pod, container in _jwt_containers(_docs()):
        sa_volumes = _projected_sa_volumes(pod)
        mounts = {m["name"] for m in (container.get("volumeMounts") or [])}
        for name in mounts & set(sa_volumes):
            assert sa_volumes[name].get("audience") == EXPECTED_AUDIENCE, (
                f"{label}: audience {sa_volumes[name].get('audience')!r} != "
                f"{EXPECTED_AUDIENCE!r} (the role's bound_audiences)"
            )


@_needs_helm
def test_every_jwt_workload_runs_as_the_dedicated_subject() -> None:
    """CLAIM: the identity is the dedicated `vali` ServiceAccount, never
    the namespace default — a Vault role bound to `default` would admit
    any pod in the namespace."""
    values = yaml.safe_load(VALUES.read_text())
    expected = values["vaultAuth"]["serviceAccountName"]
    for label, pod, _container in _jwt_containers(_docs()):
        assert pod.get("serviceAccountName") == expected, label


@_needs_helm
def test_the_sweep_covers_both_synthetic_monitor_cronjobs() -> None:
    """CLAIM: the two workloads that actually broke are IN the sweep. A
    rename or an `enabled: false` that drops them from the render would
    otherwise make every assertion above vacuously true for them."""
    labels = [label for label, _pod, _c in _jwt_containers(_docs())]
    joined = " ".join(labels)
    assert "CronJob/synthetic-monitor-full" in joined
    assert "CronJob/synthetic-monitor-light" in joined
    # …and the deployments that always had it, so the sweep is broad.
    assert "Deployment/vali[" in joined
    assert len(labels) >= 7, labels


# ── the chart must be APPLYABLE: no reference to a revoked secret key ───


@_needs_helm
def test_no_workload_references_the_revoked_static_token_key() -> None:
    """CLAIM: with jwt auth ON, nothing references `vali-vault` key
    `token`. That key was removed when the static `vali-orchestrator`
    token was revoked, and a `secretKeyRef` to an absent key is a hard
    `CreateContainerConfigError` — a chart that keeps it cannot be applied
    at all, which is how the live objects came to be hand-patched (and how
    the CronJobs lost their volumeMount)."""
    for label, pod in _pod_specs(_docs()):
        for container in pod.get("containers") or []:
            for entry in container.get("env") or []:
                ref = (entry.get("valueFrom") or {}).get("secretKeyRef") or {}
                assert not (ref.get("name") == "vali-vault" and ref.get("key") == "token"), (
                    f"{label} still reads the revoked static token key"
                )


@_needs_helm
def test_disabling_jwt_restores_the_static_token_path() -> None:
    """CLAIM: the removal is a GATE, not a deletion — the documented
    rollback (`vaultAuth.jwt.enabled=false`) still renders `VAULT_TOKEN`
    and stops rendering the jwt env. Without this, "fix the monitor" would
    have quietly become "there is no way back"."""
    docs = _docs("--set", "vaultAuth.jwt.enabled=false")
    saw_static = False
    for _label, pod in _pod_specs(docs):
        for container in pod.get("containers") or []:
            assert TOKEN_PATH_ENV not in _env_map(container)
            for entry in container.get("env") or []:
                ref = (entry.get("valueFrom") or {}).get("secretKeyRef") or {}
                if ref.get("name") == "vali-vault" and ref.get("key") == "token":
                    saw_static = True
    assert saw_static, "the rollback path renders no static VAULT_TOKEN at all"


# ── helm-free guards (drift caught even without a helm binary) ──────────


def _workload_templates() -> list[Path]:
    return sorted(p for p in TEMPLATES.glob("*.yaml") if p.name != "_helpers.tpl")


def test_the_three_jwt_snippets_are_never_split_up() -> None:
    """CLAIM: no template wires the jwt ENV without ALSO wiring the volume
    AND the volumeMount. Env-without-mount is the production failure; it
    must not be reachable by editing one template."""
    for path in _workload_templates():
        text = path.read_text()
        if "vali.vaultAuthEnv" not in text:
            continue
        assert "vali.vaultTokenVolume" in text, f"{path.name}: jwt env without the volume"
        assert "vali.vaultTokenVolumeMount" in text, f"{path.name}: jwt env without the volumeMount"


def test_no_template_hardcodes_the_static_vault_token() -> None:
    """CLAIM: `VAULT_TOKEN` is rendered ONLY through the gated helper, so a
    single values flag decides whether the chart references the revoked
    Secret key."""
    for path in _workload_templates():
        for line in path.read_text().splitlines():
            assert line.strip() != "- name: VAULT_TOKEN", (
                f"{path.name}: use `vali.vaultStaticTokenEnv`, which is gated "
                "on `not vaultAuth.jwt.enabled`"
            )


def test_values_pin_the_audience_and_the_token_path_directory() -> None:
    """CLAIM: the two silent-failure surfaces are stated in values —
    the audience Vault binds, and the mountPath that must be the DIRECTORY
    of the token path the env advertises."""
    values = yaml.safe_load(VALUES.read_text())
    jwt = values["vaultAuth"]["jwt"]
    assert jwt["enabled"] is True
    assert jwt["audience"] == EXPECTED_AUDIENCE
    assert jwt["mountPath"] == "/var/run/secrets/vault"
    assert values["vaultAuth"]["serviceAccountName"] == "vali"


def test_the_env_helper_derives_the_token_path_from_the_mount_path() -> None:
    """CLAIM: the path the process reads is DERIVED from the mountPath, so
    the two cannot drift apart via values. (A hardcoded path in some future
    template is caught by the rendered sweep above.)"""
    helpers = (TEMPLATES / "_helpers.tpl").read_text()
    assert 'printf "%s/token" .Values.vaultAuth.jwt.mountPath' in helpers


def test_the_code_default_agrees_with_the_chart() -> None:
    """CLAIM: chart and code agree on where the credential lives — a
    settings default pointing elsewhere would make an off-chart deployment
    fail with the very error this PR made legible."""
    values = yaml.safe_load(VALUES.read_text())
    from vali import settings as vali_settings

    expected = f"{values['vaultAuth']['jwt']['mountPath']}/token"
    assert vali_settings.VALI_VAULT_JWT_TOKEN_PATH == expected
