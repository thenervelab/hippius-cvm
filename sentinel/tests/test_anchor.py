"""PR-S2: signed audit-anchor publisher tests.

Vault transit is replaced by an in-memory fake `VaultSigner`. S3 is
provided by `moto` (mock_aws) so the Object Lock contract is exercised
without a real bucket.

Coverage:

  - Happy path: chain verifies → envelope built canonical-CBOR →
    Vault-signed → PUT to S3 with COMPLIANCE retention and the right
    metadata.
  - Refusal: a tampered chain causes `publish_anchor` to raise
    `AuditVerifyError` BEFORE any Vault call — the side-effect path
    must be reachable only after verification succeeds.
  - Idempotence: re-publishing the same `(timestamp, head)` writes to
    the same object key.
  - Envelope contents: decoded artefact contains the canonical-CBOR
    envelope with the documented domain, head, record_count.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import boto3
import cbor2
import pytest
from moto import mock_aws

from sentinel.tools.anchor import (
    ANCHOR_DOMAIN,
    TRANSIT_KEY_NAME,
    AnchorConfig,
    publish_anchor,
)
from sentinel.tools.kbs_audit import AuditVerifyError
from tests._audit_builder import build_chain


class _FakeVaultSigner:
    """In-memory `VaultSigner` stand-in.

    Tracks the calls made so the test can assert the contract: key
    ensured, sign called exactly twice (probe + real envelope), and
    the second sign matches the canonical-CBOR envelope embedded in
    the published artefact.
    """

    def __init__(self, version: int = 7) -> None:
        self.version = version
        self.ensured: list[str] = []
        self.signed: list[tuple[str, bytes]] = []

    def ensure_key(self, name: str) -> None:
        self.ensured.append(name)

    def sign(self, name: str, payload: bytes) -> tuple[str, int]:
        self.signed.append((name, payload))
        # Deterministic dummy signature payload — covers the prefix
        # format parsed by the production HvacVaultSigner.
        b64 = "Zm9vYmFy" + str(len(self.signed))
        return f"vault:v{self.version}:{b64}", self.version


@pytest.fixture
def bucket_name() -> str:
    return "hippius-audit-anchors-test"


@pytest.fixture
def s3_client(bucket_name: str, monkeypatch: pytest.MonkeyPatch):
    # Isolate the test from any host AWS state so moto can intercept
    # cleanly. Without this a real `~/.aws/credentials` or `AWS_PROFILE`
    # env var causes boto3 to sign with creds the mock doesn't know
    # about, producing SignatureDoesNotMatch.
    for var in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_S3",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # Force the credentials/config provider chain off the user's home
    # files so the mock owns the credential surface.
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/dev/null")

    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(
            Bucket=bucket_name,
            ObjectLockEnabledForBucket=True,
        )
        yield s3


@pytest.fixture
def anchor_config(bucket_name: str, tmp_path: Path) -> AnchorConfig:
    return AnchorConfig(
        vault_addr="http://vault.test:8200",
        vault_token="root-test-token",
        transit_mount="transit",
        bucket=bucket_name,
        region="us-east-1",
        endpoint_url=None,
        retention_days=7,
        sentinel_id="sentinel-test-pod",
    )


def test_publish_anchor_happy_path(
    tmp_path: Path, anchor_config: AnchorConfig, s3_client: Any, bucket_name: str
) -> None:
    audit_dir = tmp_path / "audit"
    chain = build_chain(audit_dir)
    signer = _FakeVaultSigner(version=4)

    fixed_ts = 1_700_000_500
    result = publish_anchor(
        config=anchor_config,
        signer=signer,
        s3_client=s3_client,
        audit_dir=audit_dir,
        now_unix=fixed_ts,
    )

    # Vault contract: key ensured exactly once; two sign calls
    # (probe + real envelope with embedded key_version).
    assert signer.ensured == [TRANSIT_KEY_NAME]
    assert len(signer.signed) == 2
    assert all(name == TRANSIT_KEY_NAME for name, _ in signer.signed)
    probe_payload = signer.signed[0][1]
    real_payload = signer.signed[1][1]
    probe = cbor2.loads(probe_payload)
    real = cbor2.loads(real_payload)
    assert probe["key_version"] == 0
    assert real["key_version"] == signer.version

    # Result mirrors the chain we built.
    assert result.bucket == bucket_name
    assert result.record_count == len(chain)
    assert result.head_hex == chain[-1].hash_.hex()
    assert result.timestamp_unix == fixed_ts
    assert result.key_version == signer.version
    assert result.retain_until == dt.datetime.fromtimestamp(fixed_ts, tz=dt.UTC) + dt.timedelta(
        days=7
    )

    # Object key encodes timestamp + head — idempotent under re-publish
    # of the same (ts, head).
    expected_key = f"anchors/{fixed_ts:010d}-{chain[-1].hash_.hex()}.cbor"
    assert result.key == expected_key

    # Read back: artefact is canonical CBOR with envelope + signature.
    obj = s3_client.get_object(Bucket=bucket_name, Key=result.key)
    body = obj["Body"].read()
    artefact = cbor2.loads(body)
    assert set(artefact) == {"envelope", "signature", "signature_alg"}
    assert artefact["signature_alg"] == "ed25519"
    assert artefact["signature"].startswith(f"vault:v{signer.version}:")
    envelope = cbor2.loads(artefact["envelope"])
    assert envelope["domain"] == ANCHOR_DOMAIN
    assert envelope["record_count"] == len(chain)
    assert envelope["head_sha256"] == chain[-1].hash_
    assert envelope["timestamp_unix"] == fixed_ts
    assert envelope["sentinel_id"] == "sentinel-test-pod"
    assert envelope["key_version"] == signer.version

    # Object Lock contract: HEAD response carries the retention.
    head = s3_client.head_object(Bucket=bucket_name, Key=result.key)
    assert head.get("ObjectLockMode") == "COMPLIANCE"
    assert head.get("ObjectLockRetainUntilDate") is not None
    metadata = head.get("Metadata", {})
    assert metadata.get("anchor-head") == chain[-1].hash_.hex()
    assert metadata.get("anchor-record-count") == str(len(chain))
    assert metadata.get("anchor-signature") == artefact["signature"]
    assert metadata.get("anchor-key-version") == str(signer.version)
    assert metadata.get("sentinel-id") == "sentinel-test-pod"


def test_publish_anchor_refuses_when_chain_tampered(
    tmp_path: Path, anchor_config: AnchorConfig, s3_client: Any, bucket_name: str
) -> None:
    audit_dir = tmp_path / "audit"
    build_chain(audit_dir)
    # Patch head.sha256 to a fake value — verify_chain will refuse.
    (audit_dir / "head.sha256").write_bytes(b"\xde" * 32)

    signer = _FakeVaultSigner()
    with pytest.raises(AuditVerifyError):
        publish_anchor(
            config=anchor_config,
            signer=signer,
            s3_client=s3_client,
            audit_dir=audit_dir,
            now_unix=1_700_000_500,
        )

    # Critical: no Vault interaction happened. The chain check MUST run
    # before any side effect (signing, S3 PUT). Otherwise an attacker
    # who breaks the chain could still publish a fake anchor.
    assert signer.ensured == []
    assert signer.signed == []
    # And no objects were written to the bucket.
    listed = s3_client.list_objects_v2(Bucket=bucket_name)
    assert listed.get("KeyCount", 0) == 0


def test_publish_anchor_is_idempotent_under_replay(
    tmp_path: Path, anchor_config: AnchorConfig, s3_client: Any, bucket_name: str
) -> None:
    audit_dir = tmp_path / "audit"
    build_chain(audit_dir)
    signer = _FakeVaultSigner(version=3)
    fixed_ts = 1_700_000_500

    first = publish_anchor(
        config=anchor_config,
        signer=signer,
        s3_client=s3_client,
        audit_dir=audit_dir,
        now_unix=fixed_ts,
    )
    second = publish_anchor(
        config=anchor_config,
        signer=signer,
        s3_client=s3_client,
        audit_dir=audit_dir,
        now_unix=fixed_ts,
    )

    # Same (ts, head) → same object key. A real bucket under COMPLIANCE
    # mode would reject the second PUT; moto's mock_aws accepts it.
    # The important contract is that the key collides so retention
    # protects history at the storage layer.
    assert first.key == second.key
    listed = s3_client.list_objects_v2(Bucket=bucket_name)
    assert listed["KeyCount"] == 1


def test_publish_anchor_empty_chain_publishes_zero_head(
    tmp_path: Path, anchor_config: AnchorConfig, s3_client: Any
) -> None:
    """An empty audit directory anchors `(0, all-zeros)` cleanly.

    This is useful at first boot — the sentinel can publish a baseline
    `(0, 0)` anchor to prove it was alive before any KBS activity
    started, defending against a "we deleted the log AND backdated
    the sentinel pod" attack.
    """

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    signer = _FakeVaultSigner()
    result = publish_anchor(
        config=anchor_config,
        signer=signer,
        s3_client=s3_client,
        audit_dir=audit_dir,
        now_unix=1_700_000_500,
    )
    assert result.record_count == 0
    assert result.head_hex == "00" * 32
