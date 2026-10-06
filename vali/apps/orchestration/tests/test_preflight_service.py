"""Tests for `services.preflight` — presigned URL subprocess shape +
JSON response parsing. The dispatch wire is mocked at
`order_dispatch.dispatch_order`.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

import pytest

from apps.orchestration import order_dispatch
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.services import preflight as preflight_svc

# ── presigned URL subprocess ─────────────────────────────────────────


def _make_fake_subprocess(
    *,
    stdout: bytes = b"https://s3.test/bucket/key?sig=abc\n",
    stderr: bytes = b"",
    returncode: int = 0,
) -> Any:
    @dataclass
    class _FakeCompleted:
        stdout: bytes
        stderr: bytes
        returncode: int

    def _fake_run(*_args: object, **_kwargs: object) -> _FakeCompleted:
        return _FakeCompleted(stdout=stdout, stderr=stderr, returncode=returncode)

    return _fake_run


def test_presign_one_returns_url_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", _make_fake_subprocess())
    artifact = preflight_svc.S3Artifact(bucket="b", key="k", sha256_hex="a" * 64)
    assert preflight_svc.presign_one(artifact) == "https://s3.test/bucket/key?sig=abc"


def test_presign_one_rejects_non_url_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        _make_fake_subprocess(stdout=b"oops not a url\n"),
    )
    artifact = preflight_svc.S3Artifact(bucket="b", key="k", sha256_hex="a" * 64)
    with pytest.raises(EffectError, match="not a URL"):
        preflight_svc.presign_one(artifact)


def test_presign_one_rejects_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        _make_fake_subprocess(
            stdout=b"",
            stderr=b"InvalidAccessKeyId\n",
            returncode=255,
        ),
    )
    artifact = preflight_svc.S3Artifact(bucket="b", key="k", sha256_hex="a" * 64)
    with pytest.raises(EffectError, match="exit=255"):
        preflight_svc.presign_one(artifact)


def test_presign_one_rejects_out_of_range_ttl() -> None:
    artifact = preflight_svc.S3Artifact(bucket="b", key="k", sha256_hex="a" * 64)
    with pytest.raises(EffectError, match="ttl-out-of-range"):
        preflight_svc.presign_one(artifact, ttl_secs=10)
    with pytest.raises(EffectError, match="ttl-out-of-range"):
        preflight_svc.presign_one(artifact, ttl_secs=8 * 24 * 3600)


def test_presign_one_missing_binary_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError("aws")

    monkeypatch.setattr(subprocess, "run", _raise)
    artifact = preflight_svc.S3Artifact(bucket="b", key="k", sha256_hex="a" * 64)
    with pytest.raises(EffectUnavailable, match="binary not found"):
        preflight_svc.presign_one(artifact)


# ── JSON response parsing ────────────────────────────────────────────


_HAPPY_BODY = json.dumps(
    {
        "classifier": "preflight-ok",
        "launch_digest_hex": "0" * 96,
        "luks_disk_path": "/var/lib/hippius-miner/staging/vm-x/tenant.qcow2",
        "kernel_path": "/var/lib/hippius-miner/staging/vm-x/tenant.vmlinuz",
        "initrd_path": "/var/lib/hippius-miner/staging/vm-x/tenant.initrd.img",
    }
)


def test_parse_preflight_response_happy_path() -> None:
    result = preflight_svc._parse_preflight_response(_HAPPY_BODY)
    assert result.launch_digest_hex == "0" * 96
    assert result.luks_disk_path.endswith("tenant.qcow2")


def test_parse_preflight_response_legacy_has_no_rootfs_paths() -> None:
    # golden-bake PR4: the legacy reply carries no rootfs_{data,hash}_path.
    result = preflight_svc._parse_preflight_response(_HAPPY_BODY)
    assert result.rootfs_data_path is None
    assert result.rootfs_hash_path is None


def test_parse_preflight_response_golden_carries_rootfs_paths() -> None:
    body = json.dumps(
        {
            **json.loads(_HAPPY_BODY),
            "luks_disk_path": "/var/lib/hippius-miner/staging/vm-g/rootfs.img",
            "rootfs_data_path": "/var/lib/hippius-miner/staging/vm-g/rootfs.img",
            "rootfs_hash_path": "/var/lib/hippius-miner/staging/vm-g/rootfs.verity",
        }
    )
    result = preflight_svc._parse_preflight_response(body)
    assert result.rootfs_data_path.endswith("rootfs.img")
    assert result.rootfs_hash_path.endswith("rootfs.verity")


def test_parse_preflight_response_rejects_empty_rootfs_path() -> None:
    body = json.dumps({**json.loads(_HAPPY_BODY), "rootfs_data_path": ""})
    with pytest.raises(EffectError, match="rootfs_data_path"):
        preflight_svc._parse_preflight_response(body)


def test_build_preflight_payload_omits_rootfs_hash_for_legacy() -> None:
    payload = preflight_svc.build_preflight_payload(
        vm_id="vm-x",
        ovmf_path="/o",
        cmdline="ro hippius.luks_header_sha256=" + "0" * 64,
        cpu_count=2,
        luks_disk_url="https://s3/tenant.qcow2",
        luks_disk_sha256_hex="0" * 64,
        kernel_url="https://s3/k",
        kernel_sha256_hex="1" * 64,
        initrd_url="https://s3/i",
        initrd_sha256_hex="2" * 64,
    )
    assert "rootfs_hash" not in payload


def test_build_preflight_payload_emits_rootfs_hash_for_golden() -> None:
    payload = preflight_svc.build_preflight_payload(
        vm_id="vm-g",
        ovmf_path="/o",
        cmdline="ro dm-verity.root=" + "0" * 64,
        cpu_count=2,
        luks_disk_url="https://s3/rootfs.img",
        luks_disk_sha256_hex="0" * 64,
        kernel_url="https://s3/k",
        kernel_sha256_hex="1" * 64,
        initrd_url="https://s3/i",
        initrd_sha256_hex="2" * 64,
        rootfs_hash_url="https://s3/rootfs.verity",
        rootfs_hash_sha256_hex="3" * 64,
    )
    assert payload["rootfs_hash"] == {
        "url": "https://s3/rootfs.verity",
        "sha256_hex": "3" * 64,
    }


def test_parse_preflight_response_rejects_wrong_classifier() -> None:
    body = json.dumps({**json.loads(_HAPPY_BODY), "classifier": "preflight-fail"})
    with pytest.raises(EffectError, match="classifier"):
        preflight_svc._parse_preflight_response(body)


def test_parse_preflight_response_rejects_short_digest() -> None:
    body = json.dumps({**json.loads(_HAPPY_BODY), "launch_digest_hex": "00"})
    with pytest.raises(EffectError, match="digest-shape"):
        preflight_svc._parse_preflight_response(body)


def test_parse_preflight_response_rejects_uppercase_digest() -> None:
    body = json.dumps({**json.loads(_HAPPY_BODY), "launch_digest_hex": "A" * 96})
    with pytest.raises(EffectError, match="digest-shape"):
        preflight_svc._parse_preflight_response(body)


def test_parse_preflight_response_rejects_missing_path() -> None:
    body = json.dumps({**json.loads(_HAPPY_BODY), "luks_disk_path": ""})
    with pytest.raises(EffectError, match="missing luks_disk_path"):
        preflight_svc._parse_preflight_response(body)


def test_parse_preflight_response_rejects_non_json() -> None:
    with pytest.raises(EffectError, match="preflight-decode"):
        preflight_svc._parse_preflight_response("not json {{")


# ── dispatch_preflight integration with mocked URL gen + dispatch ────


def test_dispatch_preflight_passes_decoded_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def _fake_presign(artifact: preflight_svc.S3Artifact, ttl_secs: int = 0) -> str:
        return f"https://s3.test/{artifact.bucket}/{artifact.key}"

    def _fake_dispatch(
        *,
        miner_id: str,
        netbird_ip: str,
        order_id: str,
        kind: str,
        payload_json: bytes,
        timeout_s: float | None = None,
    ) -> order_dispatch.DispatchResult:
        captured["kind"] = kind
        captured["payload"] = json.loads(payload_json)
        return order_dispatch.DispatchResult(
            ok=True,
            status=200,
            classifier=_HAPPY_BODY,
        )

    monkeypatch.setattr(preflight_svc, "presign_one", _fake_presign)
    monkeypatch.setattr(order_dispatch, "dispatch_order", _fake_dispatch)

    artifacts = preflight_svc.PreflightArtifacts(
        luks_disk=preflight_svc.S3Artifact("b", "k1.qcow2", "a" * 64),
        kernel=preflight_svc.S3Artifact("b", "k2.vmlinuz", "b" * 64),
        initrd=preflight_svc.S3Artifact("b", "k3.initrd.img", "c" * 64),
    )
    result = preflight_svc.dispatch_preflight(
        miner_id="miner-a",
        netbird_ip="100.64.0.10",
        order_id="ord-x",
        vm_id="vm-x",
        ovmf_path="/var/lib/hippius-miner/ovmf.fd",
        cmdline="ro ds=nocloud;s=/run/cloud-init/seed/",
        cpu_count=1,
        artifacts=artifacts,
    )
    assert result.launch_digest_hex == "0" * 96
    assert captured["kind"] == "tenant-preflight"
    # The payload shape must match what the ticket-validator encoder
    # consumes — all three artifacts + the static order fields.
    payload = captured["payload"]
    assert payload["vm_id"] == "vm-x"
    assert payload["cpu_count"] == 1
    assert payload["luks_disk"]["sha256_hex"] == "a" * 64
    assert payload["kernel"]["sha256_hex"] == "b" * 64
    assert payload["initrd"]["sha256_hex"] == "c" * 64


def test_dispatch_preflight_surfaces_miner_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(preflight_svc, "presign_one", lambda *_a, **_k: "https://x")

    def _fake_dispatch(**_kwargs: object) -> order_dispatch.DispatchResult:
        return order_dispatch.DispatchResult(
            ok=False,
            status=500,
            classifier="tenant-preflight/fetch-network",
        )

    monkeypatch.setattr(order_dispatch, "dispatch_order", _fake_dispatch)

    artifacts = preflight_svc.PreflightArtifacts(
        luks_disk=preflight_svc.S3Artifact("b", "k1", "a" * 64),
        kernel=preflight_svc.S3Artifact("b", "k2", "b" * 64),
        initrd=preflight_svc.S3Artifact("b", "k3", "c" * 64),
    )
    with pytest.raises(EffectError, match="miner-rejected"):
        preflight_svc.dispatch_preflight(
            miner_id="miner-a",
            netbird_ip="100.64.0.10",
            order_id="ord-y",
            vm_id="vm-y",
            ovmf_path="/var/lib/hippius-miner/ovmf.fd",
            cmdline="ro",
            cpu_count=1,
            artifacts=artifacts,
        )
