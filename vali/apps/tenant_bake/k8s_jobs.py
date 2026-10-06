"""Spawn a `hippius-tenant-baker` k8s Job for a queued `TenantBake` row.

Mirror — at the Kubernetes API layer — of what `apps.packer` will do
when its PR-K10 worker side lands. The Job runs in vali's own
namespace, mounts the bake parameters as env vars, the Vault token
+ S3 creds as projected secrets, and POSTs back to
`/v1/tenant-bakes/<bake_id>/finalize` over the in-cluster Service
once the bake completes.

`apps.tenant_bake.views.TenantBakeCreateView` calls
[`spawn_bake_job`] AFTER the row INSERT commits, so a successful
HTTP 202 carries the guarantee that the Job has been created. If
the k8s API rejects the create (RBAC, ResourceQuota, …), the view
catches `K8sUnavailable` and surfaces it to the caller as 503.

## Why no `kubernetes` import at module load time

`apps.tenant_bake` ships in builds where the operator hasn't yet
opted into the in-cluster bake path (Phase 2 follow-up: PR #335 just
shipped the API surface; Phase 3 archives the workstation script).
Importing `kubernetes` unconditionally at module load would force
every dev / test environment to install the SDK + its cryptography
stack even when they only run the legacy flow. The import is
deferred into the call site so a deployment with
`VALI_TENANT_BAKE_K8S_ENABLED=false` never touches the SDK.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.conf import settings

if TYPE_CHECKING:  # pragma: no cover — type-only import
    from .models import TenantBake

log = logging.getLogger("apps.tenant_bake.k8s_jobs")


class K8sUnavailable(Exception):
    """The k8s API is not reachable, or the Job create was rejected.

    The view surfaces this as HTTP 503 — the row is still committed
    (the operator can retry the create via a delete + re-POST).
    """


@dataclass(frozen=True)
class JobSpec:
    """Materialised inputs for a single bake-Job rendering.

    Builds a `kubernetes.client.V1Job` from these without ever
    touching `TenantBake` directly so the renderer is testable
    without a Django request.
    """

    bake_id: str
    vm_id: str
    base_image_url: str
    base_image_sha256: str
    size_gb: int
    kek_vault_path: str
    s3_output_bucket: str
    s3_output_prefix: str

    namespace: str
    image: str
    image_pull_secret: str
    service_account: str
    vali_internal_url: str
    worker_token_secret_name: str
    worker_token_secret_key: str
    vault_addr_secret_name: str
    vault_addr_secret_key: str
    vault_token_secret_name: str
    vault_token_secret_key: str
    aws_creds_secret_name: str
    # Object-store endpoint the bake's `aws s3 cp` uploads target
    # (rendered as AWS_ENDPOINT_URL). Path-style addressing is forced
    # by the entrypoint — S3-compatible endpoints generally have no
    # `*.<endpoint>` virtual-host DNS. Empty ⇒ the aws CLI default
    # (real AWS S3).
    s3_endpoint_url: str
    work_dir_size: str
    backoff_limit: int
    # Stage-1 bake cache (perf). When non-empty: the name of a PVC in
    # `namespace` that the Job mounts at /cache; the container env
    # gets HCC_BAKE_STAGE1_CACHE_DIR=/cache/stage1 so
    # `tenant-image-bake.sh` reuses the tenant-independent half of
    # the bake (download + chroot customise + initramfs) across
    # bakes. Empty (the default) renders no volume + no env — the
    # pre-cache manifest shape, byte-identical.
    cache_pvc_name: str = ""
    # Boot-disk packaging mode (golden-bake PR6). Rendered as
    # BAKE_DISK_MODE so the entrypoint drives `tenant-image-bake.sh
    # --disk-mode` + the golden upload/finalize branch. Defaults to
    # `legacy_luks` so a pre-golden JobSpec renders a byte-identical env.
    disk_mode: str = "legacy_luks"
    # F6 package-refresh stamp (`TenantBake.package_refresh`). Rendered as
    # BAKE_PACKAGE_REFRESH only when non-empty, so every other bake renders
    # a byte-identical env.
    package_refresh: str = ""

    # Vault `jwt` auth (M-k8sauth, #94). Defaulted so an empty role keeps
    # the pre-migration static-token behaviour and no existing caller has
    # to change.
    vault_jwt_role: str = ""
    vault_jwt_auth_path: str = "jwt"
    vault_jwt_audience: str = "vault"
    vault_jwt_mount_path: str = "/var/run/secrets/vault"


def render_job(spec: JobSpec) -> dict[str, Any]:
    """Render the Job manifest as a plain Python dict.

    Returning a dict (not a `V1Job`) keeps this function importable
    + testable without the `kubernetes` SDK installed — the test
    suite can pin the manifest shape directly with
    `assert manifest['spec']['template']['spec'][...] == ...`.
    The caller (`spawn_bake_job`) converts to the SDK type only at
    the API boundary.

    Layout:
    - Job name = `tenant-bake-<bake_id>` — deterministic so an
      idempotent re-spawn can dedupe via the namespace's existing
      Jobs (a 409 from the API means we already spawned).
    - Single container `bake`, image = `spec.image` (digest-pinned
      by the helm chart at deploy time).
    - `privileged: true` — required for `losetup` + `cryptsetup`
      + `mount` + `chroot`. NetworkPolicy + RBAC narrow what this
      privileged pod can actually reach to "Vault + S3 + the
      cloud-image origin + vali's own API".
    - Env vars carry the bake parameters (BAKE_*) and the worker
      token (mounted from a k8s secret, never inlined in the
      manifest).
    - `restartPolicy: Never` + `backoffLimit: 0` — the bake is
      one-shot. A retry is a NEW `TenantBake` row + a new Job.
      (Phase 3 may revisit this if transient-fault rates warrant.)
    """
    container_env = [
        {"name": "BAKE_BAKE_ID", "value": spec.bake_id},
        {"name": "BAKE_VM_ID", "value": spec.vm_id},
        {"name": "BAKE_BASE_IMAGE_URL", "value": spec.base_image_url},
        {"name": "BAKE_BASE_IMAGE_SHA256", "value": spec.base_image_sha256},
        {"name": "BAKE_SIZE_GB", "value": str(spec.size_gb)},
        {"name": "BAKE_KEK_VAULT_PATH", "value": spec.kek_vault_path},
        {"name": "BAKE_S3_OUTPUT_BUCKET", "value": spec.s3_output_bucket},
        {"name": "BAKE_S3_OUTPUT_PREFIX", "value": spec.s3_output_prefix},
        # golden-bake PR6 — the entrypoint reads this to pick the
        # `tenant-image-bake.sh --disk-mode` + the golden upload/finalize
        # branch. `legacy_luks` (the default) is the pre-golden path.
        {"name": "BAKE_DISK_MODE", "value": spec.disk_mode},
        {"name": "BAKE_VALI_INTERNAL_URL", "value": spec.vali_internal_url},
        # The KBS transport the baked guest will use. We pass the SAME
        # vsock authority the launch bakes into the cmdline
        # (`VALI_GUEST_VSOCK_URL`) so the bake knows the initramfs needs
        # NO network and skips `IP=dhcp` — otherwise the initramfs DHCP
        # client leaves a second, lingering lease on the tenant NIC
        # (the #289 double-IP). Every miner in this fleet is vsock-KBS.
        {
            "name": "BAKE_KBS_URL",
            "value": str(getattr(settings, "VALI_GUEST_VSOCK_URL", "vsock://2:19266")),
        },
        # The worker token + Vault token + AWS creds are mounted
        # from k8s secrets via `valueFrom.secretKeyRef`, NEVER as
        # plain `value` (which would render in the manifest YAML
        # operators can `kubectl get -o yaml` see).
        {
            "name": "BAKE_VALI_WORKER_TOKEN",
            "valueFrom": {
                "secretKeyRef": {
                    "name": spec.worker_token_secret_name,
                    "key": spec.worker_token_secret_key,
                }
            },
        },
        {
            "name": "VAULT_ADDR",
            "valueFrom": {
                "secretKeyRef": {
                    "name": spec.vault_addr_secret_name,
                    "key": spec.vault_addr_secret_key,
                }
            },
        },
        # Transition fallback only (M-k8sauth, #94): when a jwt role is
        # configured the entrypoint logs in and OVERWRITES this. Marked
        # `optional` so the Job still schedules once Phase 5 deletes the
        # Secret — without it every bake would CreateContainerConfigError.
        {
            "name": "VAULT_TOKEN",
            "valueFrom": {
                "secretKeyRef": {
                    "name": spec.vault_token_secret_name,
                    "key": spec.vault_token_secret_key,
                    "optional": True,
                }
            },
        },
        # Key names match the `vali-s3` ExternalSecret's `secretKey`
        # fields (external-secret-s3.yaml: `access-key` /
        # `secret-key`). A previous revision referenced
        # `access_key_id` / `secret_access_key` — keys that never
        # existed in the materialised secret — so every bake pod
        # died at CreateContainerConfigError before the entrypoint
        # ran a single line.
        {
            "name": "AWS_ACCESS_KEY_ID",
            "valueFrom": {
                "secretKeyRef": {
                    "name": spec.aws_creds_secret_name,
                    "key": "access-key",
                }
            },
        },
        {
            "name": "AWS_SECRET_ACCESS_KEY",
            "valueFrom": {
                "secretKeyRef": {
                    "name": spec.aws_creds_secret_name,
                    "key": "secret-key",
                }
            },
        },
        # awscli ≥2.13 honors AWS_ENDPOINT_URL, so the entrypoint's
        # `aws s3 cp` targets the configured object store instead of
        # amazonaws.com. The region is a required-but-arbitrary
        # constant for S3-compatible endpoints (sigv4 scope component
        # only).
        {"name": "AWS_ENDPOINT_URL", "value": spec.s3_endpoint_url},
        {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
    ]
    if spec.package_refresh:
        container_env.append(
            {"name": "BAKE_PACKAGE_REFRESH", "value": spec.package_refresh}
        )

    # Vault `jwt` auth (M-k8sauth, #94) — the Job exchanges its projected
    # ServiceAccount token for a short Vault token on the `tenant-baker`
    # policy. A bake is short-lived, so one login at start covers the run.
    if spec.vault_jwt_role:
        container_env.extend(
            [
                {"name": "VAULT_JWT_ROLE", "value": spec.vault_jwt_role},
                {"name": "VAULT_JWT_AUTH_PATH", "value": spec.vault_jwt_auth_path},
                {
                    "name": "VAULT_JWT_TOKEN_PATH",
                    "value": f"{spec.vault_jwt_mount_path}/token",
                },
            ]
        )

    volume_mounts: list[dict[str, Any]] = [
        {"name": "work", "mountPath": "/work"},
        # Private-CA bundle for the Vault KEK fetch — the same
        # `vault-ca` ConfigMap the vali pod mounts. The entrypoint
        # passes `--cacert /etc/hippius/vault-ca/ca.crt` when the
        # file exists; without it curl exits 60 on Vault's TLS.
        {
            "name": "vault-ca",
            "mountPath": "/etc/hippius/vault-ca",
            "readOnly": True,
        },
        # /dev/kvm is HOST kvm — the bake needs it for the in-chroot
        # `update-initramfs` to compile the `linux-image-generic`
        # module post-install. hostPath devices are kept read-only
        # beyond the explicit /dev/kvm + /dev/loop-control entries
        # the deploy ships.
        {"name": "dev-kvm", "mountPath": "/dev/kvm"},
        {"name": "dev-loop-control", "mountPath": "/dev/loop-control"},
    ]
    if spec.vault_jwt_role:
        volume_mounts.append(
            {
                "name": "vault-sa-token",
                "mountPath": spec.vault_jwt_mount_path,
                "readOnly": True,
            }
        )
    volumes: list[dict[str, Any]] = [
        {
            "name": "work",
            "emptyDir": {"sizeLimit": spec.work_dir_size},
        },
        # `optional: True` — a deploy whose Vault carries a public
        # cert ships no `vault-ca` ConfigMap; the mount then renders
        # an empty dir and the entrypoint's --cacert conditional
        # falls through to the system trust store.
        {
            "name": "vault-ca",
            "configMap": {"name": "vault-ca", "optional": True},
        },
        {"name": "dev-kvm", "hostPath": {"path": "/dev/kvm"}},
        {
            "name": "dev-loop-control",
            "hostPath": {"path": "/dev/loop-control"},
        },
    ]
    if spec.vault_jwt_role:
        # audience `vault`, NOT the default API audience: the Vault role
        # pins `bound_audiences`, so this token is useless against the
        # Kubernetes API even though the bake Job is a privileged pod.
        volumes.append(
            {
                "name": "vault-sa-token",
                "projected": {
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "path": "token",
                                "audience": spec.vault_jwt_audience,
                                "expirationSeconds": 600,
                            }
                        }
                    ]
                },
            }
        )
    if spec.cache_pvc_name:
        # Stage-1 bake cache (perf): a PVC shared across bake Jobs
        # carries the tenant-independent half of the bake (customised
        # raw + kernel + initrd, content-addressed + sha-verified by
        # `tenant-image-bake.sh`). RWO is fine on the single-node
        # deployment; a multi-node cluster needs an RWX storage class
        # or accepts node-affinity serialisation of bakes.
        volume_mounts.append({"name": "stage1-cache", "mountPath": "/cache"})
        volumes.append(
            {
                "name": "stage1-cache",
                "persistentVolumeClaim": {"claimName": spec.cache_pvc_name},
            }
        )
        container_env.append({"name": "HCC_BAKE_STAGE1_CACHE_DIR", "value": "/cache/stage1"})

    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": f"tenant-bake-{spec.bake_id}",
            "namespace": spec.namespace,
            "labels": {
                "app.kubernetes.io/name": "hippius-tenant-baker",
                "app.kubernetes.io/component": "bake",
                "hippius.network/bake-id": spec.bake_id,
                "hippius.network/vm-id": spec.vm_id,
            },
        },
        "spec": {
            "backoffLimit": spec.backoff_limit,
            # Job retention — the controller GCs successful runs
            # after 1 hour (operator-tunable in helm). Failed Jobs
            # stick around longer for debugging via the
            # `ttlSecondsAfterFinished` knob.
            "ttlSecondsAfterFinished": 3600,
            "template": {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/name": "hippius-tenant-baker",
                        "app.kubernetes.io/component": "bake",
                        "hippius.network/bake-id": spec.bake_id,
                        "hippius.network/vm-id": spec.vm_id,
                    },
                },
                "spec": {
                    "restartPolicy": "Never",
                    "serviceAccountName": spec.service_account,
                    "imagePullSecrets": [{"name": spec.image_pull_secret}],
                    "containers": [
                        {
                            "name": "bake",
                            "image": spec.image,
                            "imagePullPolicy": "IfNotPresent",
                            "securityContext": {
                                # losetup + mount + cryptsetup +
                                # chroot need root in the kernel
                                # namespace. The NetworkPolicy on
                                # the pod label restricts egress to
                                # Vault + S3 + vali's API only.
                                "privileged": True,
                            },
                            "env": container_env,
                            "volumeMounts": volume_mounts,
                            "resources": {
                                "requests": {
                                    "cpu": "2",
                                    "memory": "4Gi",
                                },
                                "limits": {
                                    "cpu": "4",
                                    "memory": "8Gi",
                                },
                            },
                        },
                    ],
                    "volumes": volumes,
                },
            },
        },
    }


def spec_from_settings(bake: TenantBake) -> JobSpec:
    """Build a [`JobSpec`] for `bake` from `django.conf.settings`.

    Every k8s-side knob (image digest, secret name pairs, SA name,
    work-dir sizeLimit, …) is settings-driven so deploy ops can flip
    them via env vars without code changes — same posture as
    `apps.packer.views`.
    """
    return JobSpec(
        bake_id=bake.bake_id,
        vm_id=bake.vm_id,
        base_image_url=bake.base_image_url,
        base_image_sha256=bake.base_image_sha256,
        size_gb=bake.size_gb,
        kek_vault_path=bake.kek_vault_path,
        s3_output_bucket=bake.s3_output_bucket,
        s3_output_prefix=bake.s3_output_prefix,
        disk_mode=bake.disk_mode,
        package_refresh=bake.package_refresh,
        namespace=getattr(settings, "VALI_TENANT_BAKE_NAMESPACE", "vali"),
        image=getattr(
            settings,
            "VALI_TENANT_BAKE_IMAGE",
            # Pinned to the PR #348 GHCR build (sha-0d58da407a09).
            # If `settings.VALI_TENANT_BAKE_IMAGE` is absent we still
            # land a digest-pinned default so a misconfigured deploy
            # cannot silently spawn jobs against an unpinned tag.
            "ghcr.io/thenervelab/hippius-tenant-baker"
            "@sha256:344a156b02558451eea985249e0e0be8e2a3a771cec9588f2de2ee592b76349a",
        ),
        image_pull_secret=getattr(
            settings,
            "VALI_TENANT_BAKE_IMAGE_PULL_SECRET",
            # `ghcr-pull-secret` authenticates GHCR pulls; a private
            # registry needs its own imagePullSecret name here.
            "ghcr-pull-secret",
        ),
        vault_jwt_role=str(getattr(settings, "VALI_TENANT_BAKE_VAULT_JWT_ROLE", "") or "").strip(),
        vault_jwt_auth_path=str(
            getattr(settings, "VALI_TENANT_BAKE_VAULT_JWT_AUTH_PATH", "jwt") or "jwt"
        ).strip(),
        vault_jwt_audience=str(
            getattr(settings, "VALI_TENANT_BAKE_VAULT_JWT_AUDIENCE", "vault") or "vault"
        ).strip(),
        vault_jwt_mount_path=str(
            getattr(
                settings,
                "VALI_TENANT_BAKE_VAULT_JWT_MOUNT_PATH",
                "/var/run/secrets/vault",
            )
            or "/var/run/secrets/vault"
        ).strip(),
        service_account=getattr(
            settings,
            "VALI_TENANT_BAKE_SERVICE_ACCOUNT",
            "hippius-tenant-baker",
        ),
        vali_internal_url=getattr(
            settings,
            "VALI_TENANT_BAKE_VALI_INTERNAL_URL",
            "http://vali.vali.svc.cluster.local:8000",
        ),
        worker_token_secret_name=getattr(
            settings,
            "VALI_TENANT_BAKE_WORKER_TOKEN_SECRET",
            "vali-tenant-baker-worker-token",
        ),
        worker_token_secret_key=getattr(settings, "VALI_TENANT_BAKE_WORKER_TOKEN_KEY", "token"),
        vault_addr_secret_name=getattr(
            settings, "VALI_TENANT_BAKE_VAULT_ADDR_SECRET", "vali-vault"
        ),
        vault_addr_secret_key=getattr(settings, "VALI_TENANT_BAKE_VAULT_ADDR_KEY", "address"),
        vault_token_secret_name=getattr(
            # KEK-HSM Phase 4 part 2 — the dedicated scoped `tenant-baker` token,
            # never vali's (which can't read luks-kek since Phase 1 anyway).
            settings,
            "VALI_TENANT_BAKE_VAULT_TOKEN_SECRET",
            "bake-vault-token",
        ),
        vault_token_secret_key=getattr(settings, "VALI_TENANT_BAKE_VAULT_TOKEN_KEY", "token"),
        aws_creds_secret_name=getattr(settings, "VALI_TENANT_BAKE_AWS_CREDS_SECRET", "vali-s3"),
        s3_endpoint_url=str(getattr(settings, "VALI_S3_ENDPOINT_URL", "") or ""),
        work_dir_size=getattr(settings, "VALI_TENANT_BAKE_WORK_DIR_SIZE", "32Gi"),
        backoff_limit=int(getattr(settings, "VALI_TENANT_BAKE_BACKOFF_LIMIT", 0)),
        # Empty default = no cache volume rendered (pre-cache manifest
        # shape). The helm chart sets this to the PVC name when
        # `tenantBake.cache.enabled`.
        cache_pvc_name=getattr(settings, "VALI_TENANT_BAKE_CACHE_PVC", ""),
    )


def spawn_bake_job(bake: TenantBake) -> None:
    """Create a k8s Job that bakes `bake` end-to-end.

    Caller pattern (the create view):

        row = TenantBake.objects.create(...)
        try:
            spawn_bake_job(row)
        except K8sUnavailable as exc:
            return Response(503, {"error": str(exc), ...})

    Returning silently on success keeps the view layer thin; the
    Job's progress is observable via `kubectl -n vali get jobs` and
    via the `TenantBake.state` flips the worker token POSTs.

    A `VALI_TENANT_BAKE_K8S_ENABLED=false` deploy short-circuits
    here (the test settings module sets that) so the API + DB layer
    is testable without the k8s SDK installed.
    """
    if not getattr(settings, "VALI_TENANT_BAKE_K8S_ENABLED", False):
        log.info(
            "tenant_bake: VALI_TENANT_BAKE_K8S_ENABLED=false; skipping Job spawn for bake_id=%s",
            bake.bake_id,
        )
        return

    # Deferred import — see module docstring.
    try:
        from kubernetes import client as k8s_client  # type: ignore[import-not-found]
        from kubernetes import config as k8s_config  # type: ignore[import-not-found]
        from kubernetes.client.exceptions import (  # type: ignore[import-not-found]
            ApiException,
        )
    except ImportError as exc:  # pragma: no cover
        raise K8sUnavailable(
            "kubernetes SDK not installed; rebuild vali image with kubernetes>=30"
        ) from exc

    # `incluster` when running as a Pod with a mounted SA;
    # `kubeconfig` when running on a developer workstation
    # (vali_create_vm --in-cluster-bake against an in-cluster vali
    # is handled by the proxying logic, not by this module).
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        k8s_config.load_incluster_config()
    else:
        # In a non-test, non-cluster context (e.g. local CLI run
        # without the env), this would normally find a kubeconfig
        # in $HOME/.kube/config. We let the SDK raise its own
        # `ConfigException` here — the operator's local error
        # surface is informative; we wrap it as `K8sUnavailable`.
        try:
            k8s_config.load_kube_config()
        except Exception as exc:  # pragma: no cover - operator path
            raise K8sUnavailable(f"no in-cluster + no kubeconfig: {exc}") from exc

    spec = spec_from_settings(bake)
    manifest = render_job(spec)
    batch_v1 = k8s_client.BatchV1Api()
    try:
        batch_v1.create_namespaced_job(namespace=spec.namespace, body=manifest)
    except ApiException as exc:
        if exc.status == 409:
            # Re-spawn for a row we've already created a Job for —
            # idempotent. The existing Job will drive the row.
            log.info(
                "tenant_bake: Job tenant-bake-%s already exists; treating spawn as idempotent",
                spec.bake_id,
            )
            return
        raise K8sUnavailable(
            f"k8s rejected Job create: status={exc.status} reason={exc.reason}"
        ) from exc
    except Exception as exc:
        raise K8sUnavailable(f"k8s API error: {exc}") from exc

    log.info(
        "tenant_bake: spawned Job tenant-bake-%s in namespace %s",
        spec.bake_id,
        spec.namespace,
    )
