"""Tests for `apps.tenant_bake.k8s_jobs` — the Job manifest renderer
+ the `spawn_bake_job` orchestration layer.

The renderer is pure (dict → dict) so its tests assert manifest
shape directly. The orchestration layer is mocked at the
`kubernetes` SDK import boundary so the tests run without a cluster
+ without `kubernetes` installed at all.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest
from django.test import override_settings

from apps.tenant_bake.k8s_jobs import (
    JobSpec,
    K8sUnavailable,
    render_job,
    spawn_bake_job,
    spec_from_settings,
)
from apps.tenant_bake.models import TenantBake

pytestmark = pytest.mark.django_db


# ─── render_job() — pure manifest shape ────────────────────────────


def _sample_spec() -> JobSpec:
    return JobSpec(
        bake_id="deadbeef" * 4,
        vm_id="myvm-1",
        base_image_url="https://example.com/cloud.img",
        base_image_sha256="a" * 64,
        size_gb=10,
        kek_vault_path="secret/x/luks-kek",
        s3_output_bucket="bucket",
        s3_output_prefix="tenant/myvm-1/",
        namespace="vali",
        image="registry.example.com/baker:0.0.1",
        image_pull_secret="regcred",
        service_account="hippius-tenant-baker",
        vali_internal_url="http://vali:8000",
        worker_token_secret_name="vali-tenant-baker-worker-token",
        worker_token_secret_key="token",
        vault_addr_secret_name="vali-vault",
        vault_addr_secret_key="address",
        vault_token_secret_name="vali-vault",
        vault_token_secret_key="token",
        aws_creds_secret_name="vali-s3",
        s3_endpoint_url="https://s3.example.com",
        work_dir_size="32Gi",
        backoff_limit=0,
    )


def test_render_job_uses_deterministic_name() -> None:
    m = render_job(_sample_spec())
    assert m["metadata"]["name"] == "tenant-bake-" + "deadbeef" * 4
    assert m["metadata"]["namespace"] == "vali"


def test_render_job_labels_carry_bake_and_vm_id() -> None:
    m = render_job(_sample_spec())
    md_labels = m["metadata"]["labels"]
    assert md_labels["hippius.network/bake-id"] == "deadbeef" * 4
    assert md_labels["hippius.network/vm-id"] == "myvm-1"
    # Same labels propagate to the pod template so a `kubectl get pods
    # -l hippius.network/bake-id=…` lookup works without leafing
    # through Job → ReplicaSet → Pod.
    pod_labels = m["spec"]["template"]["metadata"]["labels"]
    assert pod_labels["hippius.network/bake-id"] == "deadbeef" * 4
    assert pod_labels["hippius.network/vm-id"] == "myvm-1"


def test_render_job_one_shot_semantics() -> None:
    m = render_job(_sample_spec())
    assert m["spec"]["backoffLimit"] == 0
    assert m["spec"]["template"]["spec"]["restartPolicy"] == "Never"


def test_render_job_container_is_privileged() -> None:
    m = render_job(_sample_spec())
    container = m["spec"]["template"]["spec"]["containers"][0]
    assert container["securityContext"]["privileged"] is True


def test_render_job_env_carries_bake_inputs() -> None:
    m = render_job(_sample_spec())
    env = {e["name"]: e for e in m["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["BAKE_BAKE_ID"]["value"] == "deadbeef" * 4
    assert env["BAKE_VM_ID"]["value"] == "myvm-1"
    assert env["BAKE_BASE_IMAGE_URL"]["value"] == "https://example.com/cloud.img"
    assert env["BAKE_BASE_IMAGE_SHA256"]["value"] == "a" * 64
    assert env["BAKE_SIZE_GB"]["value"] == "10"
    assert env["BAKE_KEK_VAULT_PATH"]["value"] == "secret/x/luks-kek"
    assert env["BAKE_S3_OUTPUT_BUCKET"]["value"] == "bucket"
    assert env["BAKE_S3_OUTPUT_PREFIX"]["value"] == "tenant/myvm-1/"
    assert env["BAKE_VALI_INTERNAL_URL"]["value"] == "http://vali:8000"
    # The bake is told the guest's KBS transport so it skips `IP=dhcp`
    # for vsock images (the #289 double-IP). Defaults to the vsock
    # authority the launch also bakes into the cmdline.
    assert env["BAKE_KBS_URL"]["value"].startswith("vsock://")
    # golden-bake PR6 — the packaging mode drives the entrypoint's
    # --disk-mode + golden upload branch. Default JobSpec ⇒ legacy.
    assert env["BAKE_DISK_MODE"]["value"] == "legacy_luks"


def test_render_job_env_carries_golden_disk_mode() -> None:
    import dataclasses

    spec = dataclasses.replace(_sample_spec(), disk_mode="golden_verity_overlay")
    m = render_job(spec)
    env = {e["name"]: e for e in m["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["BAKE_DISK_MODE"]["value"] == "golden_verity_overlay"


def test_render_job_env_package_refresh_only_when_set() -> None:
    """F6 — the stamp reaches the baker as BAKE_PACKAGE_REFRESH; an
    unstamped bake renders no such var (byte-identical pre-F6 env)."""
    import dataclasses

    def env_of(spec: object) -> dict:
        m = render_job(spec)
        return {e["name"]: e for e in m["spec"]["template"]["spec"]["containers"][0]["env"]}

    assert "BAKE_PACKAGE_REFRESH" not in env_of(_sample_spec())
    stamped = dataclasses.replace(_sample_spec(), package_refresh="20261101")
    assert env_of(stamped)["BAKE_PACKAGE_REFRESH"]["value"] == "20261101"


def test_render_job_aws_creds_keys_match_externalsecret() -> None:
    # The `vali-s3` ExternalSecret materialises `access-key` /
    # `secret-key` (external-secret-s3.yaml). Referencing any other
    # key name makes every bake pod die at
    # CreateContainerConfigError — pin the names.
    m = render_job(_sample_spec())
    env = {e["name"]: e for e in m["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["AWS_ACCESS_KEY_ID"]["valueFrom"]["secretKeyRef"]["key"] == "access-key"
    assert env["AWS_SECRET_ACCESS_KEY"]["valueFrom"]["secretKeyRef"]["key"] == ("secret-key")
    # Hippius S3 endpoint travels as AWS_ENDPOINT_URL so the
    # entrypoint's `aws s3 cp` never targets amazonaws.com.
    assert env["AWS_ENDPOINT_URL"]["value"] == "https://s3.example.com"
    assert env["AWS_DEFAULT_REGION"]["value"] == "us-east-1"


def test_render_job_secrets_are_secretkeyref_never_inlined() -> None:
    m = render_job(_sample_spec())
    env = {e["name"]: e for e in m["spec"]["template"]["spec"]["containers"][0]["env"]}
    for secret_var in (
        "BAKE_VALI_WORKER_TOKEN",
        "VAULT_ADDR",
        "VAULT_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ):
        entry = env[secret_var]
        assert "value" not in entry, f"{secret_var} must come from secretKeyRef, never inlined"
        assert "valueFrom" in entry
        assert "secretKeyRef" in entry["valueFrom"]


def test_render_job_mounts_devkvm_and_loop_control() -> None:
    m = render_job(_sample_spec())
    volumes = {v["name"]: v for v in m["spec"]["template"]["spec"]["volumes"]}
    assert volumes["dev-kvm"]["hostPath"]["path"] == "/dev/kvm"
    assert volumes["dev-loop-control"]["hostPath"]["path"] == "/dev/loop-control"
    work = volumes["work"]
    assert work["emptyDir"]["sizeLimit"] == "32Gi"


def test_render_job_mounts_vault_ca_optional() -> None:
    # The entrypoint's Vault KEK fetch needs the private CA bundle;
    # the ConfigMap is optional so public-cert deploys still render.
    m = render_job(_sample_spec())
    pod = m["spec"]["template"]["spec"]
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["vault-ca"]["configMap"] == {"name": "vault-ca", "optional": True}
    mounts = {vm["name"]: vm for vm in pod["containers"][0]["volumeMounts"]}
    assert mounts["vault-ca"]["mountPath"] == "/etc/hippius/vault-ca"
    assert mounts["vault-ca"]["readOnly"] is True


def test_render_job_ttl_after_finished_is_set() -> None:
    # GC succeeded Jobs after the configured TTL; failed Jobs stick
    # around for debugging.
    m = render_job(_sample_spec())
    assert m["spec"]["ttlSecondsAfterFinished"] == 3600


def test_render_job_no_cache_volume_by_default() -> None:
    # Empty `cache_pvc_name` must render the pre-cache manifest shape:
    # no stage1-cache volume, no /cache mount, no env knob.
    m = render_job(_sample_spec())
    pod = m["spec"]["template"]["spec"]
    assert "stage1-cache" not in {v["name"] for v in pod["volumes"]}
    container = pod["containers"][0]
    assert "/cache" not in {vm["mountPath"] for vm in container["volumeMounts"]}
    assert "HCC_BAKE_STAGE1_CACHE_DIR" not in {e["name"] for e in container["env"]}


def test_render_job_cache_pvc_renders_volume_mount_and_env() -> None:
    import dataclasses

    spec = dataclasses.replace(_sample_spec(), cache_pvc_name="bake-stage1-cache")
    m = render_job(spec)
    pod = m["spec"]["template"]["spec"]
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["stage1-cache"]["persistentVolumeClaim"]["claimName"] == ("bake-stage1-cache")
    container = pod["containers"][0]
    mounts = {vm["name"]: vm for vm in container["volumeMounts"]}
    assert mounts["stage1-cache"]["mountPath"] == "/cache"
    env = {e["name"]: e for e in container["env"]}
    assert env["HCC_BAKE_STAGE1_CACHE_DIR"]["value"] == "/cache/stage1"


# ─── spec_from_settings() ──────────────────────────────────────────


def _create_bake(vm_id: str = "myvm-1") -> TenantBake:
    from apps.identity.models import PrincipalScope, ServiceClient

    sc = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name=f"orch-{vm_id}")
    return TenantBake.objects.create(
        bake_id="abc" * 8 + "abcdef01",
        vm_id=vm_id,
        base_image_url="https://example.com/img",
        base_image_sha256="b" * 64,
        size_gb=10,
        kek_vault_path="secret/x/luks-kek",
        s3_output_bucket="bucket",
        s3_output_prefix=f"tenant/{vm_id}/",
        requested_by=sc,
    )


def test_spec_from_settings_carries_package_refresh() -> None:
    bake = _create_bake()
    assert spec_from_settings(bake).package_refresh == ""
    bake.package_refresh = "20261101"
    bake.save()
    assert spec_from_settings(bake).package_refresh == "20261101"


def test_spec_from_settings_pulls_settings_defaults() -> None:
    bake = _create_bake()
    spec = spec_from_settings(bake)
    assert spec.bake_id == bake.bake_id
    assert spec.vm_id == bake.vm_id
    # The default pull secret is `ghcr-pull-secret` — the baker image
    # lives on GHCR. A private registry needs its own secret name.
    assert spec.image_pull_secret == "ghcr-pull-secret"
    assert spec.service_account == "hippius-tenant-baker"
    # Default image is the GHCR pinned-by-digest URL. The settings
    # module is the source of truth for the digest pin; assert the
    # registry prefix here so a stale untested override surfaces.
    assert spec.image.startswith("ghcr.io/thenervelab/hippius-tenant-baker@sha256:")


@override_settings(
    VALI_TENANT_BAKE_NAMESPACE="custom-ns",
    VALI_TENANT_BAKE_IMAGE="custom.example.com/baker:1.2.3",
    VALI_TENANT_BAKE_BACKOFF_LIMIT=2,
)
def test_spec_from_settings_honours_overrides() -> None:
    bake = _create_bake()
    spec = spec_from_settings(bake)
    assert spec.namespace == "custom-ns"
    assert spec.image == "custom.example.com/baker:1.2.3"
    assert spec.backoff_limit == 2


# ─── spawn_bake_job() — disabled / enabled / API failure ──────────


@override_settings(VALI_TENANT_BAKE_K8S_ENABLED=False)
def test_spawn_disabled_is_noop() -> None:
    bake = _create_bake()
    # Should not raise even though no `kubernetes` module is loaded
    # at any point — the disabled short-circuit returns before the
    # deferred import.
    spawn_bake_job(bake)


@override_settings(VALI_TENANT_BAKE_K8S_ENABLED=True)
def test_spawn_calls_k8s_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock the entire `kubernetes` SDK at import time + assert that
    `BatchV1Api.create_namespaced_job` is called with our rendered
    manifest in the configured namespace."""
    bake = _create_bake()
    fake_module = _install_fake_kubernetes(monkeypatch, behaviour="ok")
    # Re-direct in-cluster path so load_incluster_config is exercised.
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    spawn_bake_job(bake)
    fake_module["BatchV1Api"]._instance.create_namespaced_job.assert_called_once()
    call = fake_module["BatchV1Api"]._instance.create_namespaced_job.call_args
    assert call.kwargs["namespace"] == "vali"
    assert call.kwargs["body"]["metadata"]["name"] == f"tenant-bake-{bake.bake_id}"


@override_settings(VALI_TENANT_BAKE_K8S_ENABLED=True)
def test_spawn_409_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 409 from the API (Job already exists) is treated as
    idempotent success — same row may legally re-trigger if the
    operator re-POSTs after a 503."""
    bake = _create_bake()
    _install_fake_kubernetes(monkeypatch, behaviour="conflict")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    spawn_bake_job(bake)  # no raise


@override_settings(VALI_TENANT_BAKE_K8S_ENABLED=True)
def test_spawn_500_raises_k8s_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    bake = _create_bake()
    _install_fake_kubernetes(monkeypatch, behaviour="server-error")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    with pytest.raises(K8sUnavailable):
        spawn_bake_job(bake)


# ─── helper: replace `kubernetes.*` with controllable mocks ────────


def _install_fake_kubernetes(monkeypatch: pytest.MonkeyPatch, *, behaviour: str) -> dict:
    """Insert fake `kubernetes`, `kubernetes.client`, `kubernetes.config`
    + `kubernetes.client.exceptions` modules into `sys.modules` so the
    deferred imports inside `spawn_bake_job` resolve to controllable
    mocks.

    `behaviour`:
      - "ok": `create_namespaced_job` returns a mock object.
      - "conflict": raises `ApiException(status=409)`.
      - "server-error": raises `ApiException(status=500)`.
    """
    fake_pkg = types.ModuleType("kubernetes")
    fake_client = types.ModuleType("kubernetes.client")
    fake_config = types.ModuleType("kubernetes.config")
    fake_exceptions = types.ModuleType("kubernetes.client.exceptions")

    class ApiException(Exception):
        def __init__(self, *, status: int, reason: str = "") -> None:
            super().__init__(f"{status} {reason}")
            self.status = status
            self.reason = reason

    fake_exceptions.ApiException = ApiException
    fake_client.exceptions = fake_exceptions

    batch_v1_instance = MagicMock(name="BatchV1Api()")
    if behaviour == "ok":
        batch_v1_instance.create_namespaced_job.return_value = MagicMock()
    elif behaviour == "conflict":
        batch_v1_instance.create_namespaced_job.side_effect = ApiException(
            status=409, reason="AlreadyExists"
        )
    elif behaviour == "server-error":
        batch_v1_instance.create_namespaced_job.side_effect = ApiException(
            status=500, reason="InternalServerError"
        )
    else:
        raise AssertionError(f"unknown behaviour {behaviour!r}")

    class _BatchV1Stub:
        _instance = batch_v1_instance

        def __new__(cls) -> MagicMock:
            return cls._instance

    fake_client.BatchV1Api = _BatchV1Stub
    fake_config.load_incluster_config = MagicMock()
    fake_config.load_kube_config = MagicMock()
    fake_pkg.client = fake_client
    fake_pkg.config = fake_config

    monkeypatch.setitem(sys.modules, "kubernetes", fake_pkg)
    monkeypatch.setitem(sys.modules, "kubernetes.client", fake_client)
    monkeypatch.setitem(sys.modules, "kubernetes.config", fake_config)
    monkeypatch.setitem(sys.modules, "kubernetes.client.exceptions", fake_exceptions)

    return {
        "kubernetes": fake_pkg,
        "BatchV1Api": _BatchV1Stub,
        "ApiException": ApiException,
        "create_mock": batch_v1_instance.create_namespaced_job,
    }


# ─── Vault jwt auth for the bake Job (M-k8sauth, #94) ───────────────────


def _jwt_spec() -> JobSpec:
    import dataclasses

    return dataclasses.replace(_sample_spec(), vault_jwt_role="tenant-baker")


def _pod_spec(manifest: dict) -> dict:
    return manifest["spec"]["template"]["spec"]


def test_jwt_role_adds_the_projected_vault_audience_volume() -> None:
    """CLAIM: the credential is a PROJECTED token with audience `vault`.

    Not the default API-audience token: the bake Job is a privileged pod
    (hostPath /dev/kvm), so a token it could replay against the Kubernetes
    API would be a far worse leak than a Vault-only one.
    """
    pod = _pod_spec(render_job(_jwt_spec()))
    vol = next(v for v in pod["volumes"] if v["name"] == "vault-sa-token")
    sat = vol["projected"]["sources"][0]["serviceAccountToken"]
    assert sat["audience"] == "vault"
    assert sat["path"] == "token"
    mount = next(m for m in pod["containers"][0]["volumeMounts"] if m["name"] == "vault-sa-token")
    assert mount["readOnly"] is True


def test_jwt_role_exports_the_login_env() -> None:
    """CLAIM: the entrypoint is told the role, mount and token path."""
    env = {
        e["name"]: e.get("value")
        for e in _pod_spec(render_job(_jwt_spec()))["containers"][0]["env"]
    }
    assert env["VAULT_JWT_ROLE"] == "tenant-baker"
    assert env["VAULT_JWT_AUTH_PATH"] == "jwt"
    assert env["VAULT_JWT_TOKEN_PATH"] == "/var/run/secrets/vault/token"


def test_no_jwt_role_renders_no_projected_volume_or_env() -> None:
    """CLAIM: an empty role is byte-for-byte the pre-migration Job."""
    pod = _pod_spec(render_job(_sample_spec()))
    assert not [v for v in pod["volumes"] if v["name"] == "vault-sa-token"]
    assert not [m for m in pod["containers"][0]["volumeMounts"] if m["name"] == "vault-sa-token"]
    env = {e["name"] for e in pod["containers"][0]["env"]}
    assert "VAULT_JWT_ROLE" not in env


def test_vault_token_secret_ref_is_optional() -> None:
    """CLAIM: VAULT_TOKEN is `optional`, so the Job still SCHEDULES once
    Phase 5 deletes the Secret.

    Without this the kubelet fails the pod with
    CreateContainerConfigError and every bake dies before running — the
    exact failure mode that bit the bake pipeline after the 2026-07-06
    secrets incident.
    """
    env = {e["name"]: e for e in _pod_spec(render_job(_jwt_spec()))["containers"][0]["env"]}
    ref = env["VAULT_TOKEN"]["valueFrom"]["secretKeyRef"]
    assert ref["optional"] is True


def test_jwt_job_still_runs_as_the_dedicated_baker_service_account() -> None:
    """CLAIM: the Vault role is bound to THIS subject. If the Job ever ran
    as `default`, the role would admit any pod in the namespace."""
    assert _pod_spec(render_job(_jwt_spec()))["serviceAccountName"] == (
        _sample_spec().service_account
    )


def test_render_job_env_profile_only_for_cdn_node() -> None:
    """CDN plan I3 — a standard bake renders no BAKE_PROFILE (byte-identical
    env); a cdn-node bake carries the profile and the backend URL."""
    import dataclasses

    names = lambda m: [e["name"] for e in m["spec"]["template"]["spec"]["containers"][0]["env"]]  # noqa: E731
    std = render_job(_sample_spec())
    assert "BAKE_PROFILE" not in names(std)
    assert "BAKE_CDN_BACKEND_URL" not in names(std)
    spec = dataclasses.replace(
        _sample_spec(),
        disk_mode="golden_verity_overlay",
        profile="cdn-node",
        cdn_backend_url="https://api.example.invalid",
    )
    container = render_job(spec)["spec"]["template"]["spec"]["containers"][0]
    env = {e["name"]: e for e in container["env"]}
    assert env["BAKE_PROFILE"]["value"] == "cdn-node"
    assert env["BAKE_CDN_BACKEND_URL"]["value"] == "https://api.example.invalid"
