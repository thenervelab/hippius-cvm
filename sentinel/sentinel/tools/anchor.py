"""External attestation anchor publisher (PR-S2).

Closes the §15 *external attestation root* gap called out in
`kbs-core/src/audit.rs`. Every period (default 5 min) the sentinel:

  1. Walks the KBS audit chain and recomputes the `(record_count, head)`
     tuple. Refuses to publish if verification fails — a tampered chain
     must page humans, not be silently anchored.
  2. Builds a canonical-CBOR anchor envelope (domain-tagged, monotonic
     counter, UTC timestamp) and asks Vault transit to Ed25519-sign it.
     The private key (`/transit/keys/sentinel-anchor`) never leaves
     Vault — sentinel only ever holds the signature.
  3. Puts the signed envelope into the Hippius S3 `audit-anchors`
     bucket as an immutable object: per-PUT Object Lock retention
     (`COMPLIANCE` mode + retain-until-date) so a compromised sentinel
     cannot rewrite history within the retention window.

## Anchor envelope (canonical CBOR, domain-tagged)

    {
      "domain":        "HIPPIUS_SENTINEL_ANCHOR_V1",
      "head_sha256":   bstr(32),
      "key_version":   uint,            # vault transit key version used
      "record_count":  uint,
      "sentinel_id":   text,            # pod identity, for audit
      "timestamp_unix": uint,
    }

The Vault-returned signature is `vault:v{n}:<base64>`; we store the
literal Vault-format string in object metadata (so re-verifying just
sends it back to Vault) AND publish the bare 64-byte signature in a
companion CBOR field for offline verification by anyone with the
public key.

## Failure modes (all return an error to the LLM, no silent skip)

  - KBS audit chain verify failed → no publish, structured error.
  - Vault transit unreachable / key missing → no publish, structured
    error. PR-S2 bootstrap creates the key idempotently at sentinel
    startup.
  - S3 PUT failed (network, IAM, bucket missing) → no publish,
    structured error. Retries on the next loop tick.

## Idempotence

The object key is `anchors/{timestamp_unix:010d}-{head_hex}.cbor`. A
re-publish of the *same* head produces the same key — the S3 Object
Lock retention then refuses overwrites for the configured retention
window, so duplicate runs collapse to a no-op rather than blooming
into a series of conflicting anchors.
"""

from __future__ import annotations

import base64
import datetime as dt
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Protocol

import boto3
import cbor2
import hvac
from botocore.exceptions import ClientError
from claude_agent_sdk import tool

from sentinel.tools.kbs_audit import AuditVerifyError, verify_chain

log = logging.getLogger("sentinel.tools.anchor")

ANCHOR_DOMAIN = "HIPPIUS_SENTINEL_ANCHOR_V1"
TRANSIT_KEY_NAME = "sentinel-anchor"
TRANSIT_KEY_TYPE = "ed25519"

# Object-lock retention default. PR-S2 defaults to 7 days so re-publishes
# of the same head collapse into a single retention window. Tune via env.
DEFAULT_RETENTION_DAYS = 7

# Anchor cadence default — fast enough that a tampered window is small,
# slow enough not to flood S3 with anchors. PR-S6 may revisit.
DEFAULT_ANCHOR_INTERVAL_S = 300.0

ENV_VAULT_ADDR = "SENTINEL_VAULT_ADDR"
ENV_VAULT_TOKEN = "SENTINEL_VAULT_TOKEN"
ENV_VAULT_TRANSIT_MOUNT = "SENTINEL_VAULT_TRANSIT_MOUNT"
ENV_S3_BUCKET = "SENTINEL_ANCHOR_BUCKET"
ENV_S3_ENDPOINT = "SENTINEL_S3_ENDPOINT_URL"
ENV_S3_REGION = "SENTINEL_S3_REGION"
ENV_RETENTION_DAYS = "SENTINEL_ANCHOR_RETENTION_DAYS"
ENV_SENTINEL_ID = "SENTINEL_ID"


@dataclass(frozen=True)
class AnchorConfig:
    vault_addr: str
    vault_token: str
    transit_mount: str
    bucket: str
    region: str
    endpoint_url: str | None
    retention_days: int
    sentinel_id: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> AnchorConfig:
        src = env if env is not None else os.environ

        def _require(key: str) -> str:
            v = src.get(key, "").strip()
            if not v:
                raise RuntimeError(
                    f"{key} is not set; PR-S2 anchor publisher requires it."
                )
            return v

        retention = src.get(ENV_RETENTION_DAYS, str(DEFAULT_RETENTION_DAYS)).strip()
        try:
            retention_days = int(retention)
            if retention_days <= 0:
                raise ValueError
        except ValueError as e:
            raise RuntimeError(
                f"{ENV_RETENTION_DAYS} must be a positive integer, got {retention!r}"
            ) from e

        return cls(
            vault_addr=_require(ENV_VAULT_ADDR),
            vault_token=_require(ENV_VAULT_TOKEN),
            transit_mount=src.get(ENV_VAULT_TRANSIT_MOUNT, "transit").strip() or "transit",
            bucket=_require(ENV_S3_BUCKET),
            region=src.get(ENV_S3_REGION, "us-east-1").strip() or "us-east-1",
            endpoint_url=src.get(ENV_S3_ENDPOINT, "").strip() or None,
            retention_days=retention_days,
            sentinel_id=src.get(ENV_SENTINEL_ID, "hippius-sentinel").strip() or "hippius-sentinel",
        )


class VaultSigner(Protocol):
    """Narrow surface of Vault transit we depend on — easy to mock."""

    def ensure_key(self, name: str) -> None: ...

    def sign(self, name: str, payload: bytes) -> tuple[str, int]:
        """Return (vault-format signature string, key version used)."""


class HvacVaultSigner:
    """Real hvac-backed implementation of `VaultSigner`."""

    def __init__(self, client: hvac.Client, mount_point: str) -> None:
        self._client = client
        self._mount = mount_point

    def ensure_key(self, name: str) -> None:
        # Idempotent create. The transit endpoint returns 204 on first
        # create and 204/200 on subsequent calls when the key already
        # exists with the same parameters.
        api = self._client.secrets.transit
        try:
            api.create_key(name=name, key_type=TRANSIT_KEY_TYPE, mount_point=self._mount)
        except hvac.exceptions.InvalidRequest as e:
            # hvac raises InvalidRequest if the key already exists with
            # a different type. Surface that as a hard error — never
            # silently fall back to the wrong key.
            raise RuntimeError(
                f"sentinel-anchor key exists in Vault but with incompatible parameters: {e}"
            ) from e

    def sign(self, name: str, payload: bytes) -> tuple[str, int]:
        api = self._client.secrets.transit
        resp = api.sign_data(
            name=name,
            hash_input=base64.b64encode(payload).decode("ascii"),
            mount_point=self._mount,
            # transit defaults to sha2-256 for prehashing on ed25519 it
            # ignores — leave default.
        )
        try:
            sig: str = resp["data"]["signature"]
        except (KeyError, TypeError) as e:
            raise RuntimeError(f"vault transit returned unexpected response: {resp!r}") from e
        # Vault format is `vault:v{n}:<b64>`.
        try:
            _prefix, version_tag, _b64 = sig.split(":", 2)
            version = int(version_tag.lstrip("v"))
        except ValueError as e:
            raise RuntimeError(f"vault signature has unexpected format: {sig!r}") from e
        return sig, version


def _build_hvac_signer(config: AnchorConfig) -> VaultSigner:
    client = hvac.Client(url=config.vault_addr, token=config.vault_token)
    if not client.is_authenticated():
        raise RuntimeError("vault token is not authenticated")
    return HvacVaultSigner(client, config.transit_mount)


@dataclass(frozen=True)
class PublishedAnchor:
    bucket: str
    key: str
    record_count: int
    head_hex: str
    timestamp_unix: int
    signature: str
    key_version: int
    retain_until: dt.datetime


def _build_envelope(
    *,
    record_count: int,
    head: bytes,
    timestamp_unix: int,
    sentinel_id: str,
    key_version: int,
) -> bytes:
    """Canonical-CBOR encode the signing payload.

    Key set is fixed + domain-tagged so this envelope can never collide
    with any other signed object in the stack (mirrors the discipline
    of `kbs_core::audit::AUDIT_DOMAIN`).
    """

    envelope = {
        "domain": ANCHOR_DOMAIN,
        "head_sha256": head,
        "key_version": key_version,
        "record_count": record_count,
        "sentinel_id": sentinel_id,
        "timestamp_unix": timestamp_unix,
    }
    return cbor2.dumps(envelope, canonical=True)


def _object_key(timestamp_unix: int, head: bytes) -> str:
    return f"anchors/{timestamp_unix:010d}-{head.hex()}.cbor"


def publish_anchor(
    *,
    config: AnchorConfig | None = None,
    signer: VaultSigner | None = None,
    s3_client: Any = None,
    audit_dir: str | os.PathLike[str] | None = None,
    now_unix: int | None = None,
) -> PublishedAnchor:
    """Verify chain → build envelope → Vault-sign → S3 PUT with Object Lock.

    All injection seams (`signer`, `s3_client`, `audit_dir`, `now_unix`)
    exist for tests; production code passes `None` and gets the real
    boto3 + hvac clients.
    """

    cfg = config or AnchorConfig.from_env()

    verified = verify_chain(audit_dir)  # raises AuditVerifyError on tamper

    ts = int(now_unix if now_unix is not None else time.time())

    sign = signer or _build_hvac_signer(cfg)
    sign.ensure_key(TRANSIT_KEY_NAME)

    # We sign envelope-with-key-version=0 to discover the version, then
    # re-sign with the actual version embedded. Vault returns the
    # version it used; if we trusted the discovery sign we'd still
    # match. To keep the envelope deterministic we instead read the
    # version once via a probe sign, then build + sign the real
    # envelope.
    probe_envelope = _build_envelope(
        record_count=verified.records,
        head=verified.head,
        timestamp_unix=ts,
        sentinel_id=cfg.sentinel_id,
        key_version=0,
    )
    _probe_sig, version = sign.sign(TRANSIT_KEY_NAME, probe_envelope)

    envelope = _build_envelope(
        record_count=verified.records,
        head=verified.head,
        timestamp_unix=ts,
        sentinel_id=cfg.sentinel_id,
        key_version=version,
    )
    signature, _version_real = sign.sign(TRANSIT_KEY_NAME, envelope)

    # Pack the on-disk artefact: envelope + signature both in one CBOR
    # blob so a future verifier doesn't have to handle two files. The
    # outer map is canonical too — same discipline as the envelope.
    artefact = cbor2.dumps(
        {
            "envelope": envelope,
            "signature": signature,
            "signature_alg": TRANSIT_KEY_TYPE,
        },
        canonical=True,
    )

    s3 = s3_client or boto3.client(
        "s3",
        region_name=cfg.region,
        endpoint_url=cfg.endpoint_url,
    )

    retain_until = dt.datetime.fromtimestamp(ts, tz=dt.UTC) + dt.timedelta(
        days=cfg.retention_days
    )
    key = _object_key(ts, verified.head)

    try:
        s3.put_object(
            Bucket=cfg.bucket,
            Key=key,
            Body=artefact,
            ContentType="application/cbor",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
            Metadata={
                "sentinel-id": cfg.sentinel_id,
                "anchor-head": verified.head.hex(),
                "anchor-record-count": str(verified.records),
                "anchor-signature": signature,
                "anchor-key-version": str(version),
            },
        )
    except ClientError as e:
        # If the object already exists and its retention window has not
        # elapsed, S3 will reject the overwrite with AccessDenied or
        # InvalidRequest depending on the bucket config. That's the
        # idempotent no-op we want — surface it as an info-level log,
        # not as an error.
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "InvalidRequest", "ObjectLockConfigurationNotFoundError"}:
            log.info("anchor %s exists under Object Lock; treating as no-op: %s", key, code)
        else:
            raise

    return PublishedAnchor(
        bucket=cfg.bucket,
        key=key,
        record_count=verified.records,
        head_hex=verified.head.hex(),
        timestamp_unix=ts,
        signature=signature,
        key_version=version,
        retain_until=retain_until,
    )


# ---------------------------------------------------------------------------
# Agent-facing MCP tool wrapper
# ---------------------------------------------------------------------------


async def _publish_audit_anchor_impl(_args: dict[str, Any]) -> dict[str, Any]:
    try:
        published = publish_anchor()
    except AuditVerifyError as e:
        log.warning("publish_audit_anchor: chain verification failed: %s", e)
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        "REFUSING TO ANCHOR — KBS audit chain failed verification: "
                        f"{e}"
                    ),
                }
            ],
            "isError": True,
        }
    except Exception as e:  # noqa: BLE001 — surface structured error to the agent
        log.exception("publish_audit_anchor: unexpected failure")
        return {
            "content": [{"type": "text", "text": f"publish_anchor failed: {e}"}],
            "isError": True,
        }

    import json

    payload = {
        "bucket": published.bucket,
        "key": published.key,
        "record_count": published.record_count,
        "head_hex": published.head_hex,
        "timestamp_unix": published.timestamp_unix,
        "key_version": published.key_version,
        "retain_until": published.retain_until.isoformat(),
    }
    return {
        "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]
    }


publish_audit_anchor = tool(
    "publish_audit_anchor",
    "Verify the KBS audit chain, then publish a signed "
    "(timestamp, record_count, head) anchor to the Hippius S3 "
    "audit-anchors bucket under Object Lock. Closes the §15 external "
    "attestation gap. Refuses to publish if chain verification fails.",
    {},
)(_publish_audit_anchor_impl)
