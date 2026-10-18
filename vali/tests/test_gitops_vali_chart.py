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
import sys
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
    # The disk-tier probe's no-leak fallback teardown (the synthetic one).
    "CronJob/disktier-probe",
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
        if p.get("pathType") == "Prefix"
    ]
    admin = sorted(p for p in paths if p.rstrip("/").startswith("/v1/admin"))
    # The one admin regex (`/v1/admin/miner/{id}/approval`) lives on its own
    # Ingress and is pinned by `test_the_miner_approval_route_is_published_narrowly`.
    # Each entry is an EXACT route and carries its own reason in values.yaml:
    #   - the measurement ledger, root-only, needed by the SDK;
    #   - the miner declaration, behind the single `IsMinerAdmin` principal,
    #     needed by the console-driven onboarding (hippius-backend makes it).
    # `/v1/admin/miner` (a prefix) would also publish `/{id}/quarantine`.
    assert admin == ["/v1/admin/audit/measurements", "/v1/admin/miner/register"], (
        "only these two exact admin paths may be public; "
        f"a broader admin prefix publishes the control plane: {admin}"
    )


@_needs_helm
def test_public_ingress_publishes_the_network_prefix() -> None:
    """The layer above sells public IPs and feeds the ingress edges their
    desired state through the public hostname — `/v1/network` must be
    served, and documented by the filtered public schema. Safe as a prefix
    only because every route under it is root-only, which
    `apps/network/tests/test_views.py` pins."""
    paths = {
        p.get("path")
        for doc in _docs()
        if (doc or {}).get("kind") == "Ingress"
        for rule in doc["spec"]["rules"]
        for p in rule["http"]["paths"]
    }
    assert "/v1/network" in paths
    public = _configmap_data(_docs()).get("VALI_PUBLIC_API_PATHS", "").split(",")
    assert "/v1/network" in public


@_needs_helm
def test_public_ingress_publishes_the_cdn_prefix() -> None:
    """The layer above reads the CDN fleet and acks DNS releases through the
    public hostname — `/v1/cdn` must be served and documented. Safe as a
    prefix only because every route under it is root-only, which
    `apps/cdn/tests/test_views.py` pins."""
    paths = {
        p.get("path")
        for doc in _docs()
        if (doc or {}).get("kind") == "Ingress"
        for rule in doc["spec"]["rules"]
        for p in rule["http"]["paths"]
    }
    assert "/v1/cdn" in paths
    public = _configmap_data(_docs()).get("VALI_PUBLIC_API_PATHS", "").split(",")
    assert "/v1/cdn" in public


@_needs_helm
def test_public_ingress_publishes_the_operator_paths_exactly() -> None:
    """The backend's support views reach vali through the public hostname,
    so each operator read is published — one EXACT path at a time, never
    the `/v1/operator` prefix (it would publish every future route there).
    The one prefix, `/v1/operator/miners`, is pinned route by route in
    `apps/disktier/tests/test_public_prefix.py`."""
    paths = {
        p.get("path")
        for doc in _docs()
        if (doc or {}).get("kind") == "Ingress"
        for rule in doc["spec"]["rules"]
        for p in rule["http"]["paths"]
    }
    operator = sorted(p for p in paths if p.rstrip("/").startswith("/v1/operator"))
    assert operator == [
        "/v1/operator/disk-profiles",
        "/v1/operator/fleet",
        "/v1/operator/miners",
        "/v1/operator/nodes",
        "/v1/operator/regions",
    ]
    # No broader operator prefix: `/v1/operator` (or `/v1/operator/`) would
    # publish everything under it.
    assert not any(p.rstrip("/") == "/v1/operator" for p in paths)
    public = _configmap_data(_docs()).get("VALI_PUBLIC_API_PATHS", "").split(",")
    assert "/v1/operator/fleet" in public


@_needs_helm
def test_orchestration_tick_gets_netbird_without_reboot_recovery() -> None:
    """The public-IP reconcile and the post-§25 overlay check run on every
    tick; they must not lose the NetBird credentials when reboot-recovery
    is switched off."""
    docs = _docs("--set", "orchestrationTick.rebootRecovery.enabled=false")
    [tick] = [
        d for d in docs
        if (d or {}).get("kind") == "Deployment"
        and d["metadata"]["name"] == "vali-orchestration-tick"
    ]
    env = {e["name"] for c in tick["spec"]["template"]["spec"]["containers"] for e in c["env"]}
    assert {"VALI_NETBIRD_API_BASE", "VALI_NETBIRD_API_TOKEN"} <= env
    assert "VALI_REBOOT_RECOVERY_ENABLED" not in env


def _env_by_workload(docs: list[dict]) -> dict[str, dict[str, str]]:
    return {
        label: {e["name"]: e.get("value") for c in _containers(pod) for e in c.get("env") or []}
        for label, pod in _pod_specs(docs)
    }


@_needs_helm
def test_net_policy_push_reaches_only_the_orchestration_tick() -> None:
    """The push runs in the orchestration tick; no other pod gets the
    net-policy switches, and the egress feed / launch-spec flags stay
    unset everywhere (their settings.py defaults are off)."""
    docs = _docs()
    egress = {"VALI_EGRESS_FEED_ENABLED", "VALI_NET_LAUNCH_SPEC", "VALI_EGRESS_VMS"}
    assert not egress & set(_configmap_data(docs))
    for label, env in _env_by_workload(docs).items():
        assert not egress & set(env), label
        if label != "Deployment/vali-orchestration-tick":
            assert not any(k.startswith("VALI_NET_POLICY_") for k in env), label
    tick = _env_by_workload(docs)["Deployment/vali-orchestration-tick"]
    assert tick["VALI_NET_POLICY_PUSH"] == "true"
    assert tick["VALI_NET_POLICY_MINERS"] == "*"
    assert tick["VALI_NET_POLICY_LOCAL_ACTION"] == "drop"


@_needs_helm
def test_the_kbs_audit_ingest_runs_in_the_orchestration_tick_and_is_alerted() -> None:
    """The ingest only runs where the flag is set: the orchestration tick.
    Off, vali's copy of the KBS audit chains silently fell ~10k records
    behind; the lag and staleness alerts make that loud."""
    docs = _docs()
    env = _env_by_workload(docs)
    assert env["Deployment/vali-orchestration-tick"]["VALI_KBS_AUDIT_INGEST_ENABLED"] == "true"
    for label, workload in env.items():
        if label != "Deployment/vali-orchestration-tick":
            assert "VALI_KBS_AUDIT_INGEST_ENABLED" not in workload, label
    rules = {
        r["alert"]: r["expr"]
        for d in docs
        if d.get("kind") == "PrometheusRule"
        for g in d["spec"]["groups"]
        for r in g["rules"]
        if "alert" in r
    }
    assert "hippius_kbs_audit_lag_records" in rules["KbsAuditIngestLagging"]
    # A catch-up shrinking report over report must not page.
    assert "offset 1h" in rules["KbsAuditIngestLagging"]
    assert "hippius_kbs_audit_checked_timestamp_seconds" in rules["KbsAuditIngestStale"]
    # "Never checked" (0) is not stale: a report pushed before the first run
    # after a roll must not page; it has its own two-report rule.
    assert "hippius_kbs_audit_checked_timestamp_seconds > 0" in rules["KbsAuditIngestStale"]
    assert "== 0" in rules["KbsAuditIngestNeverChecked"]


@_needs_helm
def test_power_policy_min_agent_version_is_one_shared_value() -> None:
    """The web pods (VM views, launch intake), the launch tick and the
    scheduler paths all judge which miners support the guest-poweroff
    policy: one ConfigMap key, never a per-pod override."""
    docs = _docs()
    assert _configmap_data(docs)["VALI_POWER_POLICY_MIN_AGENT_VERSION"] == "v2026.10.09"
    for label, env in _env_by_workload(docs).items():
        assert "VALI_POWER_POLICY_MIN_AGENT_VERSION" not in env, label


@_needs_helm
def test_the_auto_failover_worker_is_on_with_its_alerts_and_egress() -> None:
    """The worker runs in the orchestration tick; the web pod reads the same
    flag for a policy's failover_auto_eligible. Its alerts and the egress its
    dead-miner proof needs render with it, and only with it."""
    docs = _docs()
    env = _env_by_workload(docs)
    for label in ("Deployment/vali", "Deployment/vali-orchestration-tick"):
        assert env[label]["VALI_FAILOVER_AUTO_ENABLED"] == "true", label
    assert "VALI_FAILOVER_AUTO_AFTER_S" not in env["Deployment/vali-orchestration-tick"]
    rules = {
        d["metadata"]["name"] for d in docs if d.get("kind") == "PrometheusRule"
    }
    assert "hippius-failover-auto" in rules
    off = _docs("--set", "vmBackup.failoverAutoEnabled=false")
    for label, workload in _env_by_workload(off).items():
        assert "VALI_FAILOVER_AUTO_ENABLED" not in workload, label
    assert "hippius-failover-auto" not in {
        d["metadata"]["name"] for d in off if d.get("kind") == "PrometheusRule"
    }


_CROSS_GEN_KEYS = (
    "VALI_FAILOVER_CROSS_GEN_ENABLED",
    "VALI_FAILOVER_CROSS_GEN_GENERATIONS",
    "VALI_FAILOVER_CROSS_GEN_VM_IDS",
)


def _import_settings_with(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Import vali's settings in a fresh interpreter with `env` on top of
    this one's — what a pod does at start."""
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import django; django.setup(); from django.conf import settings; "
            "print(settings.VALI_FAILOVER_CROSS_GEN_ENABLED, "
            "','.join(settings.VALI_FAILOVER_CROSS_GEN_GENERATIONS))",
        ],
        cwd=REPO_ROOT / "vali",
        env={
            **os.environ,
            "DJANGO_SETTINGS_MODULE": os.environ.get(
                "DJANGO_SETTINGS_MODULE", "vali.settings_test"
            ),
            **env,
        },
        capture_output=True,
        text=True,
        check=False,
    )


@_needs_helm
def test_cross_gen_failover_renders_off_with_the_known_generations() -> None:
    """#1577 reads three variables on the pods that carry vali.backupEnv.
    The flag stays off, and the generations are exactly the vCPU models
    settings.py accepts: any other entry makes vali refuse to start."""
    env = _env_by_workload(_docs())
    for label in ("Deployment/vali", "Deployment/vali-orchestration-tick"):
        assert env[label]["VALI_FAILOVER_CROSS_GEN_ENABLED"] == "false", label
        assert env[label]["VALI_FAILOVER_CROSS_GEN_GENERATIONS"] == "EpycGenoa,EpycTurin", label
        assert env[label]["VALI_FAILOVER_CROSS_GEN_VM_IDS"] == "", label
    for label, workload in env.items():
        if label not in ("Deployment/vali", "Deployment/vali-orchestration-tick"):
            assert not set(_CROSS_GEN_KEYS) & set(workload), label


@_needs_helm
def test_the_rendered_cross_gen_env_lets_vali_start() -> None:
    """The rendered values pass settings.py's start-time check; a typo does
    not (the check this test leans on is real)."""
    tick = _env_by_workload(_docs())["Deployment/vali-orchestration-tick"]
    ok = _import_settings_with({k: tick[k] for k in _CROSS_GEN_KEYS})
    assert ok.returncode == 0, ok.stderr
    assert ok.stdout.split()[-2:] == ["False", "EpycGenoa,EpycTurin"]
    bad = _import_settings_with({"VALI_FAILOVER_CROSS_GEN_GENERATIONS": "genoa,EpycTurin"})
    assert bad.returncode != 0
    assert "VALI_FAILOVER_CROSS_GEN_GENERATIONS names no vCPU model" in bad.stderr


@_needs_helm
def test_operator_config_writers_are_one_shared_value() -> None:
    """The operator storage-config writers are read wherever the operator
    API is served: one ConfigMap key, never a per-pod override. Unset, it
    renders empty, which refuses every write."""
    docs = _docs()
    assert _configmap_data(docs)["VALI_OPERATOR_CONFIG_PRINCIPALS"] == "backend-operator-config"
    for label, env in _env_by_workload(docs).items():
        assert "VALI_OPERATOR_CONFIG_PRINCIPALS" not in env, label
    off = _configmap_data(_docs("--set", "operatorConfig.principals="))
    assert off["VALI_OPERATOR_CONFIG_PRINCIPALS"] == ""


@_needs_helm
def test_storage_config_push_is_one_shared_value_and_renders_only_when_set() -> None:
    """The push loop (orchestration tick) and the operator API (web pods)
    read the same three keys from the shared ConfigMap. Unset, none renders
    and settings.py keeps the loop off for every miner."""
    data = _configmap_data(_docs())
    assert data["VALI_STORAGE_CONFIG_PUSH"] == "true"
    assert data["VALI_STORAGE_CONFIG_MINERS"] == "*"
    assert data["VALI_STORAGE_CONFIG_MIN_AGENT_VERSION"] == "v2026.10.16"
    for label, env in _env_by_workload(_docs()).items():
        assert not any(k.startswith("VALI_STORAGE_CONFIG_") for k in env), label
    off = _configmap_data(_docs("--set", "storageConfig=null"))
    assert not any(k.startswith("VALI_STORAGE_CONFIG_") for k in off)


@_needs_helm
def test_pool_routing_min_agent_version_is_one_shared_value() -> None:
    """Every process that builds a launch order (web, launch tick,
    orchestration tick for §25) judges `os_pool` support the same way: one
    ConfigMap key, never a per-pod override. Unset, it renders empty and
    no miner qualifies."""
    docs = _docs()
    assert _configmap_data(docs)["VALI_POOL_ROUTING_MIN_AGENT_VERSION"] == "v2026.10.16.2"
    for label, env in _env_by_workload(docs).items():
        assert "VALI_POOL_ROUTING_MIN_AGENT_VERSION" not in env, label
    off = _configmap_data(_docs("--set", "scheduler.poolRoutingMinAgentVersion="))
    assert off["VALI_POOL_ROUTING_MIN_AGENT_VERSION"] == ""


@_needs_helm
def test_storage_move_canary_is_one_shared_value_and_renders_only_when_set() -> None:
    """The move driver (orchestration tick) and the operator command (web
    pod) read the same three keys from the shared ConfigMap. Unset, none
    renders and settings.py keeps every move off."""
    data = _configmap_data(_docs())
    assert data["VALI_STORAGE_MOVE_ENABLED"] == "true"
    assert data["VALI_STORAGE_MOVE_MINERS"] == "*"
    assert data["VALI_STORAGE_MOVE_MIN_AGENT_VERSION"] == "v2026.10.17"
    for label, env in _env_by_workload(_docs()).items():
        assert not any(k.startswith("VALI_STORAGE_MOVE_") for k in env), label
    off = _configmap_data(
        _docs(
            "--set", "storageMove.enabled=",
            "--set", "storageMove.miners=",
            "--set", "storageMove.minAgentVersion=",
        )
    )
    assert not any(k.startswith("VALI_STORAGE_MOVE_") for k in off)


@_needs_helm
def test_miner_approval_flag_is_one_shared_value_and_off() -> None:
    """Every process that admits a miner (chain refresh in the ticks, the
    web API, the launch tick) reads one ConfigMap key, never a per-pod
    override. It stays "false" until flipped on purpose; unset renders
    "false" too."""
    docs = _docs()
    assert _configmap_data(docs)["VALI_MINER_APPROVAL_REQUIRED"] == "false"
    for label, env in _env_by_workload(docs).items():
        assert "VALI_MINER_APPROVAL_REQUIRED" not in env, label
    unset = _configmap_data(_docs("--set", "scheduler.minerApprovalRequired=null"))
    assert unset["VALI_MINER_APPROVAL_REQUIRED"] == "false"
    on = _configmap_data(_docs("--set-string", "scheduler.minerApprovalRequired=true"))
    assert on["VALI_MINER_APPROVAL_REQUIRED"] == "true"


def _public_ingresses(docs: list[dict]) -> dict[str, dict]:
    return {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "Ingress" and d["metadata"]["name"].startswith("vali-public-api")
    }


def _ingress_paths(ingress: dict) -> list[dict]:
    return [p for rule in ingress["spec"]["rules"] for p in rule["http"]["paths"]]


def _vali_routes() -> list[str]:
    """Every vali URL route, as `/v1/...` with each converter replaced by a
    sample value (a path element that matches `[A-Za-z0-9._-]+`)."""
    from django.urls import URLPattern, URLResolver, get_resolver

    out: list[str] = []

    def walk(patterns, at: str = "") -> None:
        for p in patterns:
            if isinstance(p, URLResolver):
                walk(p.url_patterns, at + str(p.pattern))
            elif isinstance(p, URLPattern):
                out.append("/" + re.sub(r"<[^>]+>", "miner-a", at + str(p.pattern)))

    walk(get_resolver().url_patterns)
    return out


@_needs_helm
def test_the_miner_approval_route_is_published_narrowly() -> None:
    """`/v1/admin/miner/{id}/approval` is published through an anchored
    regex on its own Ingress — never a prefix that takes `/quarantine`,
    `/drain`, the bare miner or the list with it."""
    ingress = _public_ingresses(_docs())["vali-public-api-regex"]
    assert ingress["metadata"]["annotations"]["nginx.ingress.kubernetes.io/use-regex"] == "true"
    paths = _ingress_paths(ingress)
    assert [p["path"] for p in paths] == ["/v1/admin/miner/[A-Za-z0-9._-]+/approval$"]
    assert all(p["pathType"] == "ImplementationSpecific" for p in paths)
    # What ingress-nginx serves: `location ~* "^<path>"`.
    served = re.compile("^" + paths[0]["path"], re.IGNORECASE)
    for ok in (
        "/v1/admin/miner/miner-a/approval",
        "/v1/admin/miner/" + "ab" * 32 + "/approval",
    ):
        assert served.search(ok), ok
    for hidden in (
        "/v1/admin/miner/miner-a/drain",
        "/v1/admin/miner/miner-a/quarantine",
        "/v1/admin/miner/miner-a",
        "/v1/admin/miner/list",
        "/v1/admin/miner/register",
        "/v1/admin/miner/a/b/approval",
        "/v1/admin/miner/miner-a/approval/x",
        "/v1/admin/miner//approval",
    ):
        assert not served.search(hidden), hidden


@_needs_helm
def test_no_vali_route_leaks_through_a_regex_prefix() -> None:
    """With `use-regex` on the host, ingress-nginx serves every Prefix path
    as `~* "^<path>"`: case-insensitive, no path-element boundary. No vali
    route may start with a published prefix without being AT or UNDER it,
    and the regex paths may match no route but the approval one."""
    docs = _docs()
    ingresses = _public_ingresses(docs)
    prefixes = [p["path"] for p in _ingress_paths(ingresses["vali-public-api"])]
    regexes = [
        re.compile("^" + p["path"], re.IGNORECASE)
        for p in _ingress_paths(ingresses["vali-public-api-regex"])
    ]
    routes = _vali_routes()
    assert routes
    for route in routes:
        for prefix in prefixes:
            if route.lower().startswith(prefix.lower()):
                assert route == prefix or route.startswith(prefix + "/"), (
                    f"{route} would be published by the regex form of {prefix}"
                )
    matched = sorted({r for r in routes for rx in regexes if rx.search(r)})
    assert matched == ["/v1/admin/miner/miner-a/approval"], matched


@_needs_helm
def test_miner_auto_approve_is_one_shared_value_and_off() -> None:
    """The reeval pass (approval) and the web pods (heartbeat soak) read the
    same two keys from the shared ConfigMap; off by default, 1800 s soak."""
    docs = _docs()
    data = _configmap_data(docs)
    assert data["VALI_MINER_AUTO_APPROVE"] == "false"
    assert data["VALI_MINER_AUTO_APPROVE_SOAK_S"] == "1800"
    env = _env_by_workload(docs)
    for label, workload in env.items():
        assert "VALI_MINER_AUTO_APPROVE" not in workload, label
        assert "VALI_MINER_AUTO_APPROVE_SOAK_S" not in workload, label
    unset = _configmap_data(
        _docs(
            "--set", "scheduler.minerAutoApprove=null",
            "--set", "scheduler.minerAutoApproveSoakS=null",
        )
    )
    assert (unset["VALI_MINER_AUTO_APPROVE"], unset["VALI_MINER_AUTO_APPROVE_SOAK_S"]) == (
        "false",
        "1800",
    )


@_needs_helm
def test_net_policy_push_off_renders_no_miner_list() -> None:
    tick = _env_by_workload(_docs("--set", "orchestrationTick.netPolicy.push=false"))[
        "Deployment/vali-orchestration-tick"
    ]
    assert tick["VALI_NET_POLICY_PUSH"] == "false"
    assert "VALI_NET_POLICY_MINERS" not in tick
    assert "VALI_NET_POLICY_LOCAL_ACTION" not in tick


@_needs_helm
def test_feed_address_region_is_one_shared_value() -> None:
    """The web pods serve the edge feed and the orchestration tick bumps
    the edge revisions from the same content: one ConfigMap key, never a
    per-pod override that could make them disagree."""
    docs = _docs()
    assert _configmap_data(docs)["VALI_FEED_ADDRESS_REGION"] == "true"
    for label, env in _env_by_workload(docs).items():
        assert "VALI_FEED_ADDRESS_REGION" not in env, label
    off = _configmap_data(_docs("--set", "config.feedAddressRegion=false"))
    assert off["VALI_FEED_ADDRESS_REGION"] == "false"


@_needs_helm
def test_feed_block_smtp_is_one_shared_value() -> None:
    """The edge feed's top-level block_smtp is read by the web pods serving
    the feed and by the orchestration tick bumping the edge revisions: one
    ConfigMap key, never a per-pod override that could make them disagree."""
    docs = _docs()
    assert _configmap_data(docs)["VALI_FEED_BLOCK_SMTP"] == "true"
    for label, env in _env_by_workload(docs).items():
        assert "VALI_FEED_BLOCK_SMTP" not in env, label
    off = _configmap_data(_docs("--set", "config.feedBlockSmtp=false"))
    assert off["VALI_FEED_BLOCK_SMTP"] == "false"


@_needs_helm
def test_the_launch_path_pods_mount_a_cache_volume_big_enough_for_the_cap() -> None:
    """The C2 recompute caches its sha-pinned inputs under
    VALI_ARTIFACT_CACHE_DIR. Every pod that runs launches must mount that
    path on its own emptyDir, sized above the cache cap: the 100 Mi /tmp
    would get the pod evicted mid-launch."""
    docs = _docs()
    data = _configmap_data(docs)
    path = data["VALI_ARTIFACT_CACHE_DIR"]
    cap = int(data["VALI_ARTIFACT_CACHE_MAX_BYTES"])
    units = {"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30}
    pods = dict(_pod_specs(docs))
    launch_path = ("vali", "vali-launch-tick", "vali-orchestration-tick")
    for name in (f"Deployment/{d}" for d in launch_path):
        pod = pods[name]
        mounts = [
            m
            for c in pod["containers"]
            for m in c.get("volumeMounts", [])
            if m["mountPath"] == path
        ]
        assert len(mounts) == 1, f"{name}: nothing mounted at {path}"
        vol = next(v for v in pod["volumes"] if v["name"] == mounts[0]["name"])
        limit = vol["emptyDir"]["sizeLimit"]
        size = int(limit[:-2]) * units[limit[-2:]]
        assert size >= cap + (100 << 20), f"{name}: {limit} leaves no room over the {cap}-byte cap"


#: The workloads that read VALI_CDN_BACKEND_URL: the bake POST
#: (`tenant_bake.views._parse_create`, web), the bake spawner, the scheduled
#: re-bake (`images.rebake`), the launch path (`cdn.identity.
#: check_launch_spec`, launch tick) and the CDN reconciler (orchestration
#: tick).
_CDN_BACKEND_URL_READERS = (
    "Deployment/vali",
    "Deployment/vali-bake-spawner",
    "Deployment/vali-launch-tick",
    "Deployment/vali-orchestration-tick",
    # Rendered only while goldenRebake.enabled (off in values.yaml today).
    "CronJob/golden-rebake",
)


def _env_from_configmaps(pod: dict) -> set[str]:
    return {
        (ref.get("configMapRef") or {}).get("name", "")
        for c in _containers(pod)
        for ref in c.get("envFrom") or []
        if ref.get("configMapRef")
    }


@_needs_helm
def test_cdn_backend_url_is_one_shared_value() -> None:
    """It is measured into every cdn-node image and named by every node's
    user-data: one ConfigMap key every reader takes, never a per-pod value.
    Empty renders nothing."""
    docs = _docs("--set", "goldenRebake.enabled=true")
    # Confirmed by the backend 2026-10-07; a bare origin.
    assert _configmap_data(docs)["VALI_CDN_BACKEND_URL"] == "https://api.hippius.com"
    empty = _configmap_data(_docs("--set", "cdn.backendUrl="))
    assert "VALI_CDN_BACKEND_URL" not in empty
    pods = dict(_pod_specs(docs))
    for label in _CDN_BACKEND_URL_READERS:
        assert label in pods, label
        assert "vali-config" in _env_from_configmaps(pods[label]), label
    for label, env in _env_by_workload(docs).items():
        assert "VALI_CDN_BACKEND_URL" not in env, label

    url = "https://backend.example.test"
    on = _configmap_data(_docs("--set", f"cdn.backendUrl={url}"))
    assert on["VALI_CDN_BACKEND_URL"] == url


@_needs_helm
def test_the_pinned_kbs_response_key_reaches_the_fleet_mint() -> None:
    """`vali_cdn_fleet mint` verifies the KBS signature under this pin; it
    must be the key the guest UKI pins (binaries/agent-initramfs
    trust_anchors), never a per-pod value."""
    docs = _docs()
    data = _configmap_data(docs)
    assert data["VALI_CDN_KBS_RESPONSE_VK_HEX"] == (
        "24e6a730dc24e1bfba1e6d21d943924d3ab6f311ea0f2e0b3e585458393bc803"
    )
    for label, env in _env_by_workload(docs).items():
        assert "VALI_CDN_KBS_RESPONSE_VK_HEX" not in env, label
    for label, env in _env_by_workload(docs).items():
        assert not {k for k in env if k.startswith("VALI_CDN_")}, label
    assert "VALI_CDN_KBS_RESPONSE_VK_HEX" not in _configmap_data(
        _docs("--set", "cdn.kbsResponseVkHex=")
    )


_CDN_SWITCHES = ("VALI_CDN_ENABLED", "VALI_CDN_LAUNCH_ROLE", "VALI_CDN_RECONCILE_ENABLED")


@_needs_helm
def test_the_cdn_switches_are_on_and_shared() -> None:
    """One shared value per switch: the web pods, the launch tick, the
    orchestration tick and the scheduler paths read them together."""
    docs = _docs()
    data = _configmap_data(docs)
    for key in _CDN_SWITCHES:
        assert data[key] == "true", key
    pods = dict(_pod_specs(docs))
    for label in (
        "Deployment/vali",
        "Deployment/vali-launch-tick",
        "Deployment/vali-orchestration-tick",
        "Deployment/vali-scheduler-reeval",
    ):
        assert "vali-config" in _env_from_configmaps(pods[label]), label


@_needs_helm
def test_the_cdn_switches_default_off() -> None:
    sets = ("cdn.enabled=false", "cdn.launchRole=false", "cdn.reconcile=false")
    off = _configmap_data(_docs(*(arg for s in sets for arg in ("--set", s))))
    for key in _CDN_SWITCHES:
        assert off[key] == "false", key


@_needs_helm
def test_the_disktier_cronjobs_ship_suspended_with_the_vali_identity() -> None:
    """P1/P2: the passive evaluator and the GC render, SUSPENDED (Argo
    deploys a chart merge at once, with whatever image is pinned), on the
    vali pod identity the Postgres policy admits, and add no ConfigMap key
    (`VALI_DISK_IO_INGEST` keeps its code default, off)."""
    docs = _docs()
    jobs = {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "CronJob" and d["metadata"]["name"].startswith("disktier-")
    }
    assert set(jobs) == {"disktier-evaluate", "disktier-gc", "disktier-probe"}
    commands = {
        "disktier-evaluate": "vali_disktier_evaluate",
        "disktier-gc": "vali_disktier_gc",
        "disktier-probe": "vali_disk_probe",
    }
    for name, job in jobs.items():
        assert job["spec"]["suspend"] is True, name
        template = job["spec"]["jobTemplate"]["spec"]["template"]
        assert template["metadata"]["labels"]["app.kubernetes.io/name"] == "vali", name
        (container,) = template["spec"]["containers"]
        assert container["command"] == ["python", "manage.py", commands[name]]
    assert not [k for k in _configmap_data(docs) if k.startswith("VALI_DISK")]


@_needs_helm
def test_the_disk_probe_alerts_cannot_fire_while_the_probe_is_off() -> None:
    """R1/R2: the probe's alert rules render, but every one is guarded on
    a FRESH push with `hippius_disk_probe_enabled == 1` (the command pushes
    nothing while VALI_DISK_PROBE_ENABLED is off, and its CronJob ships
    suspended). `alerts.enabled=false` drops the rule object."""
    docs = _docs()
    (rule,) = [
        d
        for d in docs
        if d.get("kind") == "PrometheusRule"
        and d["metadata"]["name"] == "hippius-disktier-probe"
    ]
    alerts = {r["alert"]: r["expr"] for g in rule["spec"]["groups"] for r in g["rules"]}
    assert set(alerts) == {
        "DiskProbeFailing",
        "DiskProbeSuspectCache",
        "DiskProbeStale",
        "MinerDiskSevere",
    }
    for name, expr in alerts.items():
        assert "and on() (hippius_disk_probe_enabled == 1)" in expr, name
        assert "time() - hippius_disk_probe_push_timestamp_seconds < 3600" in expr, name
    (probe,) = [
        d for d in docs if d.get("kind") == "CronJob" and d["metadata"]["name"] == "disktier-probe"
    ]
    assert probe["spec"]["suspend"] is True
    off = _docs("--set", "disktierProbe.alerts.enabled=false")
    assert not [d for d in off if d["metadata"].get("name") == "hippius-disktier-probe"]


def test_the_stale_threshold_clears_the_longest_healthy_gap() -> None:
    """A healthy node's next verified probe can land period + jitter +
    start delay + timeout + linger after its last one; `DiskProbeStale`
    must not fire inside that window."""
    from django.conf import settings

    values = yaml.safe_load(VALUES.read_text())
    stale_s = values["disktierProbe"]["alerts"]["staleDays"] * 86400
    gap = (
        settings.VALI_DISK_PROBE_PERIOD_S
        + settings.VALI_DISK_PROBE_PERIOD_JITTER_S
        + settings.VALI_DISK_PROBE_START_DELAY_MAX_S
        + settings.VALI_DISK_PROBE_LAUNCH_TIMEOUT_S
        + settings.VALI_DISK_PROBE_TIMEOUT_S
        + settings.VALI_DISK_PROBE_LINGER_MAX_S
    )
    assert stale_s > gap


# ── §23 price keeper ─────────────────────────────────────────────────


_PRICE_KEEPER_ARMED = (
    "--set",
    "priceKeeper.suspend=false",
    "--set",
    "priceKeeper.image.digest=sha256:" + "0" * 64,
    "--set",
    "priceKeeper.forbiddenAccounts={0x" + "11" * 32 + "}",
)


def _price_keeper_docs(*extra: str) -> list[dict]:
    return [
        d
        for d in _docs("--set", "priceKeeper.enabled=true", *extra)
        if "price-keeper" in (d.get("metadata") or {}).get("name", "")
    ]


@_needs_helm
def test_the_price_keeper_is_off_by_default() -> None:
    names = [(d.get("metadata") or {}).get("name", "") for d in _docs()]
    assert not [n for n in names if "price-keeper" in n]


@_needs_helm
def test_an_enabled_price_keeper_is_suspended_and_signs_with_its_own_key() -> None:
    docs = _price_keeper_docs()
    kinds = {d["kind"]: d for d in docs}
    assert set(kinds) == {"CronJob", "ExternalSecret", "PrometheusRule"}

    cron = kinds["CronJob"]
    assert cron["spec"]["suspend"] is True
    (_, pod), = _pod_specs([cron])
    (container,) = pod["containers"]
    assert container["command"] == ["node", "apply-prices.mjs"]
    assert "@sha256:" in container["image"]
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["PRICE_KEEPER_KEY_FILE"] == "/etc/price-keeper/mnemonic"
    assert "EPOCH_CLOSE_KEY_FILE" not in env
    (volume,) = pod["volumes"]
    values = yaml.safe_load(VALUES.read_text())
    assert volume["secret"]["secretName"] == "price-keeper-key"
    assert volume["secret"]["secretName"] != values["epochClose"]["keySecretName"]

    secret = kinds["ExternalSecret"]
    assert secret["spec"]["target"]["name"] == "price-keeper-key"
    assert secret["spec"]["data"][0]["remoteRef"]["property"] == "mnemonic"

    alerts = {
        r["alert"] for g in kinds["PrometheusRule"]["spec"]["groups"] for r in g["rules"]
    }
    # Suspended: the run-staleness alerts would fire on a job that is
    # not meant to run, so only the state alerts render.
    assert alerts == {"PriceKeeperBalanceLow", "PriceKeeperFailing", "PriceKeeperBacklog"}
    armed = _price_keeper_docs(*_PRICE_KEEPER_ARMED)
    (rule,) = [d for d in armed if d["kind"] == "PrometheusRule"]
    armed_alerts = {r["alert"] for g in rule["spec"]["groups"] for r in g["rules"]}
    assert {"PriceKeeperStale", "PriceKeeperNeverReported"} <= armed_alerts


@_needs_helm
def test_the_price_keeper_refuses_the_epoch_close_key() -> None:
    values = yaml.safe_load(VALUES.read_text())
    proc = _render(
        "--set",
        "priceKeeper.enabled=true",
        "--set",
        f"priceKeeper.keySecretName={values['epochClose']['keySecretName']}",
    )
    assert proc.returncode != 0
    assert "must not be the epoch-close key" in proc.stderr


@_needs_helm
def test_an_unsuspended_price_keeper_needs_its_own_pin_and_a_forbidden_list() -> None:
    """The epochClose pin predates apply-prices.mjs, and the audit
    authority is not sudo on production, so neither default is safe to run."""
    no_pin = _render("--set", "priceKeeper.enabled=true", "--set", "priceKeeper.suspend=false")
    assert no_pin.returncode != 0
    assert "priceKeeper.image.digest is empty" in no_pin.stderr
    no_list = _render(
        "--set",
        "priceKeeper.enabled=true",
        *_PRICE_KEEPER_ARMED[:4],
    )
    assert no_list.returncode != 0
    assert "priceKeeper.forbiddenAccounts is empty" in no_list.stderr
    (cron,) = [d for d in _price_keeper_docs(*_PRICE_KEEPER_ARMED) if d["kind"] == "CronJob"]
    (_, pod), = _pod_specs([cron])
    env = {e["name"]: e.get("value") for e in pod["containers"][0]["env"]}
    assert env["PRICE_KEEPER_FORBIDDEN_ACCOUNTS"] == "0x" + "11" * 32


@_needs_helm
def test_the_price_keeper_state_alerts_only_read_fresh_gauges() -> None:
    """A Pushgateway gauge outlives its job: without the freshness guard a
    keeper suspended after a bad run would alert forever."""
    (rule,) = [d for d in _price_keeper_docs() if d["kind"] == "PrometheusRule"]
    rules = {r["alert"]: r["expr"] for g in rule["spec"]["groups"] for r in g["rules"]}
    for name in ("PriceKeeperBalanceLow", "PriceKeeperFailing", "PriceKeeperBacklog"):
        assert "and on() (time() - hippius_price_keeper_last_run_timestamp_seconds <" in rules[name]
