"""Anti-rot guards for the `deploy/gitops/apps/vali` chart.

WHY THIS FILE EXISTS (P7 Phase 0, 2026-08-12). Argo CD's `automated` sync
was stripped from the live Applications by hand on 2026-07-06, and in the
five weeks that followed git and the cluster diverged silently. The class
of drift this file defends against is the one nothing errors on:

  ELEVEN ConfigMap keys existed ONLY in the cluster. Absent from the
  chart, each falls back to a `settings.py` default — and for
  `VALI_HOST_ATTESTOR_GATE_ENFORCE` that default is `False`, so a sync
  would have DISARMED the §23 dispatchability gate armed on 2026-07-20
  and let tenant VMs start landing on unattested hardware. Nothing
  raises. Nothing alerts. Two `VALI_SCHEDULER_*` values would likewise
  have halved every miner's advertised slots and doubled the per-host RAM
  reservation, and an empty `VALI_TENANT_BAKE_VAULT_JWT_ROLE` would have
  reverted the baker to a Secret this namespace no longer has.

Companion to `apps/orchestration/tests/test_vault_auth_chart.py` (P4,
#922), which owns the Vault-credential invariants — that no workload
references the revoked `vali-vault:token` under jwt auth, that disabling
jwt restores it, and that the three jwt snippets are never split up.
Those are NOT re-asserted here. What IS here and depends on that work is
the #885 token renewer, which must follow the same credential regime.

WHAT THESE TESTS CANNOT DO. They are hermetic. They cannot compare the
chart to the cluster, because CI has no credentials for it (and giving a
public-runner workflow a kubeconfig for the control plane that holds
every tenant KEK is not a trade worth making). So the STALE-DIGEST class
— `image.digest`, `epochClose.image.digest`, `tenantBake.image.digest` drifting
behind what is deployed — is checked here only for SHAPE (still pinned by
digest, never a bare tag). Catching staleness itself needs a
render-and-diff against the live objects, which belongs in the operator's
periodic synthetic-monitor run, not in `ci.yml`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = REPO_ROOT / "deploy" / "gitops" / "apps" / "vali"
VALUES = CHART_DIR / "values.yaml"
SETTINGS = REPO_ROOT / "vali" / "vali" / "settings.py"

_HELM = shutil.which("helm")
# Skippable on a dev box without helm — NEVER in CI, where a silent skip
# would turn every assertion below into a no-op. Same idiom as
# `test_vault_auth_chart.py`.
_needs_helm = pytest.mark.skipif(
    _HELM is None and not os.environ.get("CI"),
    reason="helm is not installed (local run)",
)

# Settings the OPERATOR owns and the chart must therefore STATE, even
# where the value currently equals the settings.py default.
#
# This list is human-maintained and cannot be derived: a hermetic test
# has no way to know which of vali's ~200 env knobs were tuned in the
# cluster. It is still the cheap half of the fix — every entry here is a
# key that was, at some point, set live and missing from git. Add to it
# whenever you set a knob in the cluster.
REQUIRED_CONFIGMAP_KEYS = (
    # Blackbox host-attestor: the trust anchor and its two gates. Absent
    # ⇒ settings.py disarms all three.
    "VALI_KBS_L0_VERIFYING_KEY",
    "VALI_HOST_ATTESTOR_GATE_ENFORCE",
    "VALI_REWARD_REQUIRE_ATTESTOR",
    # §23 fit gate + slot accounting (#668). Two of the four disagree
    # with the code default; all four are stated so none can drift.
    "VALI_SCHEDULER_HOST_RESERVE_CPUS",
    "VALI_SCHEDULER_HOST_RESERVE_MEMORY_MB",
    "VALI_SCHEDULER_SLOT_REF_CPUS",
    "VALI_SCHEDULER_SLOT_REF_MEMORY_MB",
    # Bake-Job Vault auth. Empty role ⇒ the baker falls back to a static
    # Secret this namespace no longer has.
    "VALI_TENANT_BAKE_VAULT_JWT_ROLE",
    "VALI_TENANT_BAKE_VAULT_JWT_AUTH_PATH",
    "VALI_TENANT_BAKE_VAULT_JWT_AUDIENCE",
    "VALI_TENANT_BAKE_VAULT_JWT_MOUNT_PATH",
    "VALI_TENANT_BAKE_VAULT_TOKEN_SECRET",
    # §23 reward regime + uptime-liveness arming.
    "VALI_EPOCH_WEIGHT_SOURCE",
    "VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION",
)

# ConfigMap keys that are NOT vali settings: Django/boto/upstream names
# read straight from the environment.
NON_VALI_KEY_PREFIXES = ("DJANGO_", "HIPPIUS_", "AWS_")


def _render(*extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(_HELM), "template", "vali", str(CHART_DIR), "--namespace", "vali", *extra],
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def _docs(*extra: str) -> list[dict]:
    proc = _render(*extra)
    assert proc.returncode == 0, proc.stderr
    return [d for d in yaml.safe_load_all(proc.stdout) if isinstance(d, dict)]


def _pod_specs(docs: list[dict]) -> list[tuple[str, dict]]:
    """(label, podSpec) for every workload the chart renders."""
    out: list[tuple[str, dict]] = []
    for doc in docs:
        kind = doc.get("kind")
        name = (doc.get("metadata") or {}).get("name", "?")
        spec = doc.get("spec") or {}
        if kind in {"Deployment", "StatefulSet", "Job"}:
            pod = (spec.get("template") or {}).get("spec")
        elif kind == "CronJob":
            job = (spec.get("jobTemplate") or {}).get("spec") or {}
            pod = (job.get("template") or {}).get("spec")
        else:
            continue
        if pod:
            out.append((f"{kind}/{name}", pod))
    return out


def _containers(pod: dict) -> list[dict]:
    return list(pod.get("initContainers") or []) + list(pod.get("containers") or [])


def _configmap_data(docs: list[dict]) -> dict[str, str]:
    for doc in docs:
        if doc.get("kind") == "ConfigMap" and doc["metadata"]["name"] == "vali-config":
            return doc.get("data") or {}
    raise AssertionError("the chart renders no ConfigMap/vali-config")


# ── D3/D5/D6/D7: operator-owned knobs are STATED, not inherited ───────


@_needs_helm
def test_operator_owned_settings_are_rendered_explicitly() -> None:
    data = _configmap_data(_docs())
    missing = [k for k in REQUIRED_CONFIGMAP_KEYS if k not in data]
    assert missing == [], (
        "these knobs are set in the cluster and MUST be stated in the chart — "
        f"absent, they silently inherit the settings.py default: {missing}"
    )


@_needs_helm
def test_every_rendered_configmap_key_is_a_setting_vali_reads() -> None:
    """A typo'd key is invisible: the ConfigMap applies cleanly and the
    setting keeps its default. Catch it at render time instead."""
    settings_src = SETTINGS.read_text()
    unknown = [
        k
        for k in _configmap_data(_docs())
        if not k.startswith(NON_VALI_KEY_PREFIXES) and f'"{k}"' not in settings_src
    ]
    assert unknown == [], f"ConfigMap keys no vali setting reads (typo?): {unknown}"


@_needs_helm
def test_an_armed_attestor_gate_requires_the_verifying_key() -> None:
    """Arming the §23 dispatchability gate with no L0 verifying key makes
    every cert `pending`, which the gate never accepts — i.e. NO miner is
    dispatchable. The chart refuses to render that combination."""
    proc = _render("--set", "hostAttestor.kbsL0VerifyingKey=")
    assert proc.returncode != 0
    assert "NO miner would be dispatchable" in proc.stderr


@_needs_helm
def test_the_attestor_gates_are_required_not_defaulted() -> None:
    """A `| default false` would let an absent key silently disarm a
    security gate — the exact shape of drift D3."""
    for key in ("gateEnforce", "rewardRequireAttestor"):
        proc = _render("--set", f"hostAttestor.{key}=null")
        assert proc.returncode != 0, f"hostAttestor.{key} renders without being set"
        assert "must be set explicitly" in proc.stderr


# ── D9: the #885 renewer follows the credential regime ────────────────


@_needs_helm
def test_the_token_renewer_follows_the_static_regime() -> None:
    """#885's renewer must render exactly when there is a static token to
    renew — never for a Secret that no longer exists (a green weekly Job
    history that renews nothing is a renewal you BELIEVE is happening),
    and never absent when a rollback brings a periodic 32-day token back
    unrenewed."""
    assert "vali-vault-token-renew" not in _render().stdout

    both = _render("--set", "vaultAuth.jwt.enabled=false", "--set", "tenantBake.vault.jwtRole=")
    assert "vali-vault-token-renew" in both.stdout
    assert "renew /vali-token/token" in both.stdout
    assert "renew /bake-token/token" in both.stdout

    bake_only = _render("--set", "tenantBake.vault.jwtRole=")
    assert "vali-vault-token-renew" in bake_only.stdout
    assert "renew /vali-token/token" not in bake_only.stdout
    assert "renew /bake-token/token" in bake_only.stdout


@_needs_helm
def test_no_workload_mounts_a_retired_static_token_secret() -> None:
    """The env-var half of this is `test_vault_auth_chart.py`'s. The
    VOLUME half is the renewer's: it mounted both dead token Secrets, and
    `optional: true` meant it would have run forever logging 'skipping'."""
    offenders = []
    for label, pod in _pod_specs(_docs()):
        for vol in pod.get("volumes") or []:
            secret = (vol.get("secret") or {}).get("secretName")
            if secret in {"vali-vault", "bake-vault-token"}:
                offenders.append(f"{label}:{vol['name']}->{secret}")
    assert offenders == [], f"static Vault-token volumes under the JWT regime: {offenders}"


# ── D2/D8: every image is digest-pinned (shape only — see module docs) ─


@_needs_helm
def test_every_rendered_image_is_digest_pinned() -> None:
    offenders = []
    for label, pod in _pod_specs(_docs()):
        for c in _containers(pod):
            image = c.get("image", "")
            if "@sha256:" not in image:
                offenders.append(f"{label}:{c['name']} -> {image}")
    assert offenders == [], f"tag-only image references (§F supply chain): {offenders}"


@_needs_helm
def test_the_bake_job_image_is_digest_pinned() -> None:
    """The bake image reaches the Job through the ConfigMap, not a
    container spec, so the check above cannot see it."""
    image = _configmap_data(_docs())["VALI_TENANT_BAKE_IMAGE"]
    assert "@sha256:" in image, f"VALI_TENANT_BAKE_IMAGE is not digest-pinned: {image}"


# ── helm-free guards ─────────────────────────────────────────────────


def test_values_pin_every_image_by_digest() -> None:
    values = yaml.safe_load(VALUES.read_text())
    pins = {
        "image.digest": values["image"]["digest"],
        "tenantBake.image.digest": values["tenantBake"]["image"]["digest"],
        "epochClose.image.digest": values["epochClose"]["image"]["digest"],
        "backup.awsCliImage": values["backup"]["awsCliImage"],
        "postgres.image": values["postgres"]["image"],
        "tokenRenew.image": values["tokenRenew"]["image"],
    }
    for name, pin in pins.items():
        assert re.search(r"sha256:[0-9a-f]{64}", pin), f"{name} is not digest-pinned: {pin}"


def test_values_ship_the_attestor_gate_armed_with_a_key() -> None:
    values = yaml.safe_load(VALUES.read_text())
    attestor = values["hostAttestor"]
    assert attestor["gateEnforce"] is True, "the §23 host-attestor gate was armed on 2026-07-20"
    assert re.fullmatch(r"[0-9a-f]{64}", attestor["kbsL0VerifyingKey"]), (
        "kbsL0VerifyingKey must be a 32-byte Ed25519 PUBLIC key in hex"
    )


def test_values_keep_the_baker_on_the_jwt_path() -> None:
    values = yaml.safe_load(VALUES.read_text())
    assert values["tenantBake"]["vault"]["jwtRole"], (
        "an empty jwtRole reverts the baker to `bake-vault-token`, a Secret "
        "this namespace no longer has"
    )


# ── KBS admin mTLS: the material must reach every admin caller ────────
#
# The gate is only as strong as the workload that skips it, and the
# failure mode of a missed mount is runtime-only: the pod starts fine,
# then `kbs_admin_tls` refuses to dial at the first admin call — which
# for `launch-tick` means every launch, and for `orchestration-tick`
# means every migration. That is exactly the shape of the Vault-token
# mount asymmetry that ran unnoticed in production for days, so it is
# asserted at render time here.

# Workloads that reach the KBS lifecycle admin API.
#   vali                  — GET …/evidence (the tenant attestation view)
#   launch-tick           — §24 register-vm + the §22 allowlist auto-pin
#   orchestration-tick    — §25 activate / §24 crypto-erase / seed-boot-counter
#   synthetic-monitor-*   — the KBS reachability probe
KBS_ADMIN_WORKLOADS = (
    "Deployment/vali",
    "Deployment/vali-launch-tick",
    "Deployment/vali-orchestration-tick",
    "CronJob/synthetic-monitor-light",
    "CronJob/synthetic-monitor-full",
)

_MTLS_ON = (
    "--set", "kbsAdminMtls.secretName=vali-kbs-admin-tls",
    "--set", "kbsAdminMtls.vaultPath=hippius-compute/vali/kbs-admin-mtls",
    "--set", "config.kbsAdminUrl=https://kbs-server-admin.kbs.svc.cluster.local:8001",
    "--set", "config.kbsAdminClientCert=/etc/hippius/kbs-admin-tls/tls.crt",
    "--set", "config.kbsAdminClientKey=/etc/hippius/kbs-admin-tls/tls.key",
    "--set", "config.kbsAdminCacert=/etc/hippius/kbs-admin-tls/ca.crt",
)


@_needs_helm
def test_the_transport_and_the_material_agree() -> None:
    """This guard has now fired twice, and both times it was right.

    Its first form asserted "the chart ships with no admin material".
    That failed on the §3 staging commit, so it was re-pointed at
    "staging cannot by itself flip the transport" — shipped URL must be
    `http://`. That form then failed on THIS commit, the §4 cutover,
    which is exactly the moment a silent https flip would have been
    catastrophic and the moment a deliberate one is correct. A guard
    that has to be looked at to be moved is doing its job; the failure
    is the point.

    Post-cutover, the invariant is the biconditional vali actually
    enforces at runtime: `services/kbs_admin_tls.py` picks the transport
    from the URL SCHEME alone, and on `https://` it REFUSES to dial
    without complete material rather than falling back to system roots.
    So an https URL with a missing or half-configured cert triple is not
    a degraded mode — it is every admin call failing closed, discovered
    at runtime. Conversely `http://` with material is the inert staging
    state, which `admin_client_tls_argv()` keeps safe by returning `[]`.

    Either way the three paths must sit under `kbsAdminMtls.mountPath`:
    that mismatch is invisible until an admin call tries to read them.
    """
    data = _configmap_data(_docs())
    url = data["VALI_KBS_ADMIN_URL"]
    assert url.startswith(("http://", "https://")), f"unusable scheme: {url!r}"
    values = yaml.safe_load(VALUES.read_text())
    if url.startswith("https://"):
        assert values["kbsAdminMtls"]["secretName"], (
            "https without kbsAdminMtls.secretName — nothing mounts the client "
            "identity, so vali fails closed on EVERY admin call"
        )
        assert values["kbsAdminMtls"]["vaultPath"], (
            "https with secretName but no vaultPath — the ExternalSecret is "
            "gated on both, so the Secret would never be populated"
        )
    mount_path = yaml.safe_load(VALUES.read_text())["kbsAdminMtls"]["mountPath"]
    for key, filename in (
        ("VALI_KBS_ADMIN_CLIENT_CERT", "tls.crt"),
        ("VALI_KBS_ADMIN_CLIENT_KEY", "tls.key"),
        ("VALI_KBS_ADMIN_CACERT", "ca.crt"),
    ):
        assert data[key] == f"{mount_path}/{filename}", (
            f"{key} must be staged at <mountPath>/{filename}; got {data[key]!r}"
        )


@_needs_helm
def test_every_admin_caller_mounts_the_client_identity() -> None:
    """A workload that dials the admin API without the material fails
    closed at its FIRST admin call — a launch outage discovered at
    runtime, not at deploy time."""
    docs = _docs(*_MTLS_ON)
    mount_path = yaml.safe_load(VALUES.read_text())["kbsAdminMtls"]["mountPath"]
    rendered = dict(_pod_specs(docs))
    missing = []
    for label in KBS_ADMIN_WORKLOADS:
        pod = rendered.get(label)
        assert pod is not None, f"{label} is not rendered by this chart"
        if not any(v["name"] == "kbs-admin-tls" for v in pod.get("volumes") or []):
            missing.append(f"{label}: no volume")
            continue
        mounted = [
            m
            for c in _containers(pod)
            for m in (c.get("volumeMounts") or [])
            if m["name"] == "kbs-admin-tls"
        ]
        if not mounted:
            missing.append(f"{label}: volume but no volumeMount")
        elif any(m["mountPath"] != mount_path for m in mounted):
            missing.append(f"{label}: mounted at {[m['mountPath'] for m in mounted]}")
    assert missing == [], f"admin callers without a usable client identity: {missing}"


@_needs_helm
def test_the_configmap_paths_point_inside_the_mount() -> None:
    """The env vars and the volumeMount are set in two different files.
    Point them at different directories and every admin call fails with
    "does not point at a readable file" — at runtime, in production."""
    values = yaml.safe_load(VALUES.read_text())
    mount_path = values["kbsAdminMtls"]["mountPath"]
    data = _configmap_data(_docs(*_MTLS_ON))
    for key, filename in (
        ("VALI_KBS_ADMIN_CLIENT_CERT", "tls.crt"),
        ("VALI_KBS_ADMIN_CLIENT_KEY", "tls.key"),
        ("VALI_KBS_ADMIN_CACERT", "ca.crt"),
    ):
        assert data[key] == f"{mount_path}/{filename}", (
            f"{key} must be <kbsAdminMtls.mountPath>/{filename}; got {data[key]}"
        )


@_needs_helm
def test_the_client_secret_needs_a_vault_path_to_be_populated() -> None:
    """`secretName` without `vaultPath` would mount a Secret nothing
    creates. The ExternalSecret is gated on BOTH so the half-configured
    state cannot silently produce empty material."""
    # `vaultPath=` is set EXPLICITLY rather than inherited from values.yaml:
    # the shipped values now carry a real path (runbook §3), so a test that
    # relied on the default being empty was testing the deployment, not the
    # gate. The gate is "secretName without vaultPath renders nothing".
    out = _render(
        "--set",
        "kbsAdminMtls.secretName=vali-kbs-admin-tls",
        "--set",
        "kbsAdminMtls.vaultPath=",
    ).stdout
    assert "external-secret-kbs-admin-mtls.yaml" not in out, (
        "an ExternalSecret rendered without a Vault path to read from"
    )
    both = _render(*_MTLS_ON).stdout
    assert "external-secret-kbs-admin-mtls.yaml" in both


# ── the public Ingress must not publish the UNFILTERED schema ─────────


@_needs_helm
def test_public_ingress_never_exposes_the_unfiltered_schema() -> None:
    """`/v1/schema` and `/v1/docs` describe all 45 routes, including the
    miner-plane endpoints whose own descriptions state they carry no
    service-token auth. Publishing either turns the public hostname into a
    labelled map of the internal control plane — no access granted, but no
    reason to hand it over. `/v1/public/*` is the filtered pair; this test
    exists so a future edit cannot quietly swap one for the other.
    """
    paths = [
        p.get("path")
        for doc in _docs()
        if (doc or {}).get("kind") == "Ingress"
        for rule in doc["spec"]["rules"]
        for p in rule["http"]["paths"]
    ]
    for forbidden in ("/v1/schema", "/v1/docs", "/v1/redoc"):
        assert forbidden not in paths, (
            f"{forbidden} is the UNFILTERED schema — publish /v1/public/docs instead"
        )
    assert "/v1/public/docs" in paths and "/v1/public/schema" in paths, (
        "Swagger UI fetches its schema over HTTP: both public paths are required"
    )


@_needs_helm
def test_public_schema_filter_tracks_the_ingress_allow_list() -> None:
    """The filter and the Ingress are rendered from ONE list, so the docs
    cannot describe a route the Ingress does not serve. Guard the wiring:
    every filtered prefix must be an actually-published path."""
    data = _configmap_data(_docs())
    published = {
        p.get("path")
        for doc in _docs()
        if (doc or {}).get("kind") == "Ingress"
        for rule in doc["spec"]["rules"]
        for p in rule["http"]["paths"]
    }
    for prefix in filter(None, data.get("VALI_PUBLIC_API_PATHS", "").split(",")):
        assert prefix in published, (
            f"the public schema documents {prefix}, which the Ingress does not serve"
        )


@_needs_helm
def test_no_public_path_swallows_the_admin_surface() -> None:
    """`pathType: Prefix` means a published `/v1/admin` would expose EVERY
    admin route — miner registration, host-attestor release, quarantine.
    Exactly one admin path is published on purpose, and it is the full
    exact path. Refuse any prefix that would take siblings with it."""
    paths = [
        p.get("path")
        for doc in _docs()
        if (doc or {}).get("kind") == "Ingress"
        for rule in doc["spec"]["rules"]
        for p in rule["http"]["paths"]
    ]
    admin = [p for p in paths if p.rstrip("/").startswith("/v1/admin")]
    assert admin == ["/v1/admin/audit/measurements"], (
        "only the exact measurement-ledger path may be public; "
        f"a broader admin prefix publishes the control plane: {admin}"
    )
