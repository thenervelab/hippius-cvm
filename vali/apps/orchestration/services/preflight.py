"""Vali → miner `tenant-preflight` orchestration.

Generates short-TTL S3 presigned URLs for the operator's already-uploaded
`{qcow2, vmlinuz, initrd}` triple, dispatches the new
`tenant-preflight` order through the existing Edge sign + miner-verify
chain, and parses the miner's JSON response for the SNP launch_digest.

The preflight order replaces the manual `scp artifacts to miner` +
`ssh miner -- hippius-miner-agent launch-test --digest-only` chain
operators ran before this PR. Vali still does NOT see the artifact
bytes — the miner downloads them itself from S3 via the presigned URL,
sha256-verifies, and stages them.

§20 discipline:
- The presigned URLs are treated as secrets (they carry a signed
  query string + short TTL). They cross one subprocess boundary into
  `aws s3 presign` and one HTTP boundary into the Edge → miner-agent
  POST, and are never logged.
- The response body is JSON — `json.loads` from stdlib, no third-party
  CBOR / JSON parsers.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Any

from django.conf import settings

from apps.orchestration import order_dispatch
from apps.orchestration.effects import EffectError, EffectUnavailable

# Bounds on the presigned URL TTL — short enough that an intercepted URL
# is useless within minutes, long enough to absorb the miner's fetch
# round trip (~50 MB tenant initrd over ~10 MB/s = 5 s, qcow2 ~7 GB over
# the same link = 11 min; the qcow2 dominates, so the default has to
# clear that). Configurable via env.
DEFAULT_PRESIGN_TTL_SECS = 1800

# Bounded timeout on the `aws s3 presign` subprocess. The CLI emits a
# URL on stdout and exits; 10 s is generous for a local STS call.
DEFAULT_AWS_PRESIGN_TIMEOUT_S = 10.0

# How long vali waits for the miner's preflight response. The miner has
# to fetch + sha-verify ~7 GB of qcow2 + ~50 MB of initrd + 15 MB of
# kernel; on a 100 Mbit link that's about 10 minutes worst-case. The
# default mirrors the Edge gateway's `PREFLIGHT_REQUEST_TIMEOUT`
# (30 min) so the vali side doesn't time out first; override via
# VALI_PREFLIGHT_TIMEOUT_SECS.
DEFAULT_PREFLIGHT_DISPATCH_TIMEOUT_S = 30 * 60.0


@dataclass(frozen=True)
class S3Artifact:
    """One operator-uploaded artifact's S3 location + pinned sha256."""

    bucket: str
    key: str
    sha256_hex: str


@dataclass(frozen=True)
class PreflightArtifacts:
    """The artifacts a launch-baked tenant image is broken into.

    LEGACY: `luks_disk` = the per-VM `tenant.qcow2`; `rootfs_hash` unset.
    GOLDEN (golden-bake PR4): `luks_disk` = the SHARED golden `rootfs.img`
    and `rootfs_hash` = the golden `rootfs.verity` — there is no per-VM
    qcow2, and both golden artifacts flow through the miner's
    content-addressed cache (#823) so a same-distro relaunch HITs.
    """

    luks_disk: S3Artifact
    kernel: S3Artifact
    initrd: S3Artifact
    # GOLDEN-mode only: the golden dm-verity hash tree (`/dev/vdc`).
    rootfs_hash: S3Artifact | None = None


@dataclass(frozen=True)
class PreflightResult:
    """Decoded miner reply on success — the digest vali pins into the
    `OrderTicket.allowed_measurement_hex` + the staged paths the launch
    order references."""

    launch_digest_hex: str
    luks_disk_path: str
    kernel_path: str
    initrd_path: str
    # GOLDEN-mode only: the staged golden base paths the launch order
    # attaches at vdb/vdc. `None` on the LEGACY path.
    rootfs_data_path: str | None = None
    rootfs_hash_path: str | None = None


# ─── presigned URL generation ────────────────────────────────────────


def _aws_bin() -> str:
    return str(getattr(settings, "VALI_AWS_CLI_BIN", "") or "").strip() or "aws"


def _endpoint() -> str:
    return str(getattr(settings, "VALI_S3_ENDPOINT_URL", "") or "").strip()


def presign_one(artifact: S3Artifact, ttl_secs: int = DEFAULT_PRESIGN_TTL_SECS) -> str:
    """Subprocess `aws s3 presign s3://<bucket>/<key> --expires-in <ttl>`
    and return the URL. Fails closed on any non-zero exit."""
    if ttl_secs < 60 or ttl_secs > 7 * 24 * 3600:
        raise EffectError(
            f"presign-ttl-out-of-range: {ttl_secs} (must be 60s..7d)"
        )
    aws = _aws_bin()
    endpoint = _endpoint()
    argv = [aws]
    if endpoint:
        argv.extend(["--endpoint-url", endpoint])
    argv.extend(
        [
            "s3",
            "presign",
            f"s3://{artifact.bucket}/{artifact.key}",
            "--expires-in",
            str(ttl_secs),
        ]
    )
    try:
        proc = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            timeout=DEFAULT_AWS_PRESIGN_TIMEOUT_S,
            check=False,
            env=os.environ.copy(),
        )
    except FileNotFoundError as exc:
        raise EffectUnavailable("aws-s3-presign: binary not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise EffectError("aws-s3-presign: timeout") from exc
    if proc.returncode != 0:
        stderr_tail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise EffectError(
            f"aws-s3-presign: exit={proc.returncode} stderr={stderr_tail!r}"
        )
    url = proc.stdout.decode("utf-8", errors="replace").strip()
    if not url.startswith(("https://", "http://")):
        # aws s3 presign emits "https://…" — anything else is a sign
        # that we read the wrong stream (e.g. a debug banner).
        raise EffectError("aws-s3-presign: output is not a URL")
    return url


# ─── preflight order dispatch ────────────────────────────────────────


def _required_setting(name: str) -> str:
    value = str(getattr(settings, name, "") or "").strip()
    if not value:
        raise EffectUnavailable(f"{name} is not configured")
    return value


def build_preflight_payload(
    *,
    vm_id: str,
    ovmf_path: str,
    cmdline: str,
    cpu_count: int,
    luks_disk_url: str,
    luks_disk_sha256_hex: str,
    kernel_url: str,
    kernel_sha256_hex: str,
    initrd_url: str,
    initrd_sha256_hex: str,
    rootfs_hash_url: str | None = None,
    rootfs_hash_sha256_hex: str | None = None,
) -> dict[str, Any]:
    """JSON payload that the ticket-validator's `encode-order` shapes
    into the canonical-CBOR `TenantPreflightOrder` the miner-agent
    decodes.

    `rootfs_hash` is emitted only in GOLDEN mode (both url + sha given);
    the LEGACY payload is byte-shape-identical (no `rootfs_hash` key), so
    the encode-order + miner CBOR are unchanged for legacy launches.
    """
    payload: dict[str, Any] = {
        "vm_id": vm_id,
        "ovmf_path": ovmf_path,
        "cmdline": cmdline,
        "cpu_count": int(cpu_count),
        "luks_disk": {"url": luks_disk_url, "sha256_hex": luks_disk_sha256_hex},
        "kernel": {"url": kernel_url, "sha256_hex": kernel_sha256_hex},
        "initrd": {"url": initrd_url, "sha256_hex": initrd_sha256_hex},
    }
    if rootfs_hash_url and rootfs_hash_sha256_hex:
        payload["rootfs_hash"] = {
            "url": rootfs_hash_url,
            "sha256_hex": rootfs_hash_sha256_hex,
        }
    return payload


def dispatch_preflight(
    *,
    miner_id: str,
    netbird_ip: str,
    order_id: str,
    vm_id: str,
    ovmf_path: str,
    cmdline: str,
    cpu_count: int,
    artifacts: PreflightArtifacts,
    timeout_s: float | None = None,
) -> PreflightResult:
    """Generate presigned URLs + dispatch the `tenant-preflight` order
    via the existing Edge sign + miner-verify chain + parse the JSON
    reply. Returns the decoded digest + staged paths.

    Vali's `order_dispatch.dispatch_order` returns a `(status,
    classifier)` pair. For `tenant-preflight` the `classifier` is the
    miner's JSON response body verbatim — we json.loads it here.
    """
    luks_url = presign_one(artifacts.luks_disk)
    kernel_url = presign_one(artifacts.kernel)
    initrd_url = presign_one(artifacts.initrd)
    # GOLDEN-mode: presign the golden rootfs.verity too (absent ⇒ legacy).
    rootfs_hash_url: str | None = None
    rootfs_hash_sha: str | None = None
    if artifacts.rootfs_hash is not None:
        rootfs_hash_url = presign_one(artifacts.rootfs_hash)
        rootfs_hash_sha = artifacts.rootfs_hash.sha256_hex

    payload = build_preflight_payload(
        vm_id=vm_id,
        ovmf_path=ovmf_path,
        cmdline=cmdline,
        cpu_count=cpu_count,
        luks_disk_url=luks_url,
        luks_disk_sha256_hex=artifacts.luks_disk.sha256_hex,
        kernel_url=kernel_url,
        kernel_sha256_hex=artifacts.kernel.sha256_hex,
        initrd_url=initrd_url,
        initrd_sha256_hex=artifacts.initrd.sha256_hex,
        rootfs_hash_url=rootfs_hash_url,
        rootfs_hash_sha256_hex=rootfs_hash_sha,
    )
    payload_bytes = json.dumps(payload).encode("utf-8")

    timeout = float(
        timeout_s
        if timeout_s is not None
        else float(
            getattr(
                settings,
                "VALI_PREFLIGHT_TIMEOUT_SECS",
                DEFAULT_PREFLIGHT_DISPATCH_TIMEOUT_S,
            )
        )
    )

    result = order_dispatch.dispatch_order(
        miner_id=miner_id,
        netbird_ip=netbird_ip,
        order_id=order_id,
        kind="tenant-preflight",
        payload_json=payload_bytes,
        timeout_s=timeout,
    )
    if not result.ok:
        raise EffectError(
            f"preflight-dispatch: miner-rejected status={result.status} "
            f"classifier={result.classifier!r}"
        )

    return _parse_preflight_response(result.classifier)


def _parse_preflight_response(body: str) -> PreflightResult:
    """The miner returns the `PreflightOutput` JSON envelope verbatim
    in the response body. `dispatch_order` decodes UTF-8 and trims —
    we just json.loads + shape-check it here."""
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise EffectError(f"preflight-decode: {exc}") from exc
    if not isinstance(parsed, dict):
        raise EffectError("preflight-decode: response is not a JSON object")
    classifier = parsed.get("classifier")
    if classifier != "preflight-ok":
        raise EffectError(
            f"preflight-classifier: expected 'preflight-ok', got {classifier!r}"
        )
    digest = parsed.get("launch_digest_hex")
    if not (isinstance(digest, str) and len(digest) == 96):
        raise EffectError("preflight-digest-shape: launch_digest_hex not 96 hex")
    if not all(c in "0123456789abcdef" for c in digest):
        raise EffectError("preflight-digest-shape: not lower-hex")
    luks = parsed.get("luks_disk_path")
    kernel = parsed.get("kernel_path")
    initrd = parsed.get("initrd_path")
    for label, value in (
        ("luks_disk_path", luks),
        ("kernel_path", kernel),
        ("initrd_path", initrd),
    ):
        if not isinstance(value, str) or not value:
            raise EffectError(f"preflight-shape: missing {label}")
    # GOLDEN-mode staged base paths (vdb/vdc). Optional: absent on the
    # legacy reply. When present they must be non-empty strings.
    rootfs_data = parsed.get("rootfs_data_path")
    rootfs_hash = parsed.get("rootfs_hash_path")
    for label, value in (("rootfs_data_path", rootfs_data), ("rootfs_hash_path", rootfs_hash)):
        if value is not None and (not isinstance(value, str) or not value):
            raise EffectError(f"preflight-shape: bad {label}")
    return PreflightResult(
        launch_digest_hex=digest,
        luks_disk_path=luks,
        kernel_path=kernel,
        initrd_path=initrd,
        rootfs_data_path=rootfs_data,
        rootfs_hash_path=rootfs_hash,
    )


def fresh_order_id(prefix: str = "ord-preflight") -> str:
    """`ord-preflight-<unix>-<pid>` is unique enough for the smoke
    paths; production callers supply their own."""
    return f"{prefix}-{int(time.time())}-{os.getpid()}"
