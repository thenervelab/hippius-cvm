"""The CDN fleet keys, as vali sees them (contract §B.1 `fleet_keys`).

Custody (user decision, plan G.1 option a): vali never holds a fleet secret,
not even wrapped. Vault Transit makes each version's key and the KBS — the
only component that can unwrap it — derives its X25519 public half and signs
it with its response key over

    "HIPPIUS_CDN_FLEET_PUB_V1" ‖ version ‖ x25519_public

so the backend can check that the KBS, not just vali, vouched for the key it
seals to. vali stores and publishes that public metadata (`CdnFleetKey`).

Minting a version (`KbsFleetKeySource`, `vali_cdn_fleet mint`;
`docs/operator/cdn-fleet-keyring.md`):

1. Transit generates the key and returns only its ciphertext
   (`transit/datakey/wrapped/cdn-fleet`); vali stores that once, `cas=0`,
   at `secret/<VALI_CDN_FLEET_KV_PREFIX>/v<N>` — its policy has `create`
   there and nothing else, and no decrypt on the key;
2. the KBS (admin route `cdn-fleet/public`, through `hippius-kbs-admin-client
   cdn-fleet-public`) unwraps it, derives the public half and signs it;
3. vali checks that signature again under the KBS response key it pins
   (`VALI_CDN_KBS_RESPONSE_VK_HEX`) and records the version `pending`.

A version's public key is recorded once and never changes.

`kbs_kid_hex` is NOT covered by the KBS signature: it is informational (which
KBS key signed), never an input to any check — the check is the signature
under the pinned key.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.db import transaction
from django.db.models import Max

from .models import CdnFleetKey, CdnFleetKeyState, CdnRevision

#: The states the backend sees; `retired` keys are out of the keyring.
PUBLISHED_STATES = (
    CdnFleetKeyState.PENDING,
    CdnFleetKeyState.ACTIVE,
    CdnFleetKeyState.RETIRING,
)


class FleetKeyError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SignedFleetKey:
    version: int
    x25519_public: bytes
    kbs_kid_hex: str
    kbs_signature: bytes


class FleetKeySource(Protocol):
    def mint(self) -> SignedFleetKey:
        """Have a new version made and its public half signed by the KBS."""
        ...


#: `kbs_core::cdn_fleet::CDN_FLEET_PUB_DOMAIN`.
PUB_DOMAIN = b"HIPPIUS_CDN_FLEET_PUB_V1"
#: Versions are `1..=u32::MAX` (`kbs_core::cdn_fleet`).
MAX_VERSION = 2**32 - 1


def public_key_message(version: int, x25519_public: bytes) -> bytes:
    """What the KBS signs: `"HIPPIUS_CDN_FLEET_PUB_V1" ‖ u64be(version) ‖ pub`."""
    return PUB_DOMAIN + version.to_bytes(8, "big") + x25519_public


def _pinned_kbs_key() -> bytes:
    raw = str(getattr(settings, "VALI_CDN_KBS_RESPONSE_VK_HEX", "") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", raw):
        raise FleetKeyError(
            "fleet-keys-unconfigured",
            "VALI_CDN_KBS_RESPONSE_VK_HEX must pin the KBS response key (32-byte hex)",
        )
    return bytes.fromhex(raw)


def verify_kbs_answer(body: dict[str, Any], *, version: int) -> SignedFleetKey:
    """The KBS's `cdn-fleet/public` answer for `version`, checked under the
    pinned KBS response key. Raises `FleetKeyError` (`fleet-key-unverified`)."""
    pinned = _pinned_kbs_key()

    def bad(why: str) -> FleetKeyError:
        return FleetKeyError("fleet-key-unverified", f"v{version}: {why}")

    if body.get("v") != 1 or body.get("version") != version:
        raise bad("the answer is not for this version")
    if str(body.get("kbs_public_key_hex") or "").lower() != pinned.hex():
        raise bad("the KBS signs with another key than the pinned one (rotated?)")
    try:
        public = base64.b64decode(str(body.get("x25519_public_b64")), validate=True)
        signature = base64.b64decode(str(body.get("kbs_signature_b64")), validate=True)
    except ValueError as exc:
        raise bad("not base64") from exc
    kid = str(body.get("kbs_kid_hex") or "")
    if len(public) != 32 or len(signature) != 64 or not re.fullmatch(r"[0-9a-f]{2,128}", kid):
        raise bad("malformed")
    try:
        Ed25519PublicKey.from_public_bytes(pinned).verify(
            signature, public_key_message(version, public)
        )
    except InvalidSignature as exc:
        raise bad("the signature does not verify under the pinned KBS key") from exc
    return SignedFleetKey(
        version=version, x25519_public=public, kbs_kid_hex=kid, kbs_signature=signature
    )


class KbsFleetKeySource:
    """Mint through Vault Transit and the KBS (module doc)."""

    def mint(self) -> SignedFleetKey:
        """Mint version `max recorded + 1`, or adopt it if a mint that never
        got recorded here (a crash between store and record, or the operator
        script) already stored it: the KBS answers for whatever is stored.

        The KBS is asked BEFORE anything is written, and again after a
        refused write. vali's policy is create-only on the version path, so
        Vault answers the rewrite of an existing version 403 (checked on
        Vault 1.18: the ACL check comes before the KV-v2 check-and-set,
        which would answer 400); both are handled. A KBS that does not
        release the keyring yet (`cdn-fleet-disabled`) refuses the mint: an
        unanswered version is never taken for a free one."""
        from apps.orchestration.services import vault_kv

        _pinned_kbs_key()  # before anything is stored
        version = int(CdnFleetKey.objects.aggregate(m=Max("version"))["m"] or 0) + 1
        if version > MAX_VERSION:
            raise FleetKeyError("fleet-key-shape", "no fleet key version left")
        adopted = self.probe(version)
        if adopted is not None:
            return adopted
        transit_key = str(getattr(settings, "VALI_CDN_FLEET_TRANSIT_KEY", "cdn-fleet"))
        prefix = str(getattr(settings, "VALI_CDN_FLEET_KV_PREFIX", "hippius-compute/kbs/cdn-fleet"))
        mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
        wrapped = vault_kv.transit_datakey_wrapped(transit_key)
        refused = ""
        try:
            vault_kv.put_kv(mount, f"{prefix}/v{version}", wrapped, cas=0)
        except vault_kv.VaultPermissionDenied:
            refused = "403"
        except vault_kv.VaultCasConflict:
            refused = "a check-and-set conflict"
        key = self.probe(version)
        if key is None:
            why = (
                f"Vault refused to store it ({refused}) and the KBS cannot unwrap what is there"
                if refused
                else "the KBS cannot unwrap the version just stored"
            )
            raise FleetKeyError("fleet-key-not-minted", f"v{version}: {why}")
        return key

    def probe(self, version: int) -> SignedFleetKey | None:
        """The KBS-signed public key of `version`, or `None` when the KBS has
        no key it can unwrap there (`cdn-fleet-unwrap-failed`: never stored,
        or unreadable). Raises `FleetKeyError` (`fleet-keys-disabled`) when
        the KBS does not release the keyring, and on any other failure."""
        from apps.orchestration.effects import EffectError

        try:
            return self.public(version)
        except EffectError as exc:
            if "cdn-fleet-unwrap-failed" in str(exc):
                return None
            if "cdn-fleet-disabled" in str(exc):
                raise FleetKeyError(
                    "fleet-keys-disabled",
                    "the KBS does not release the cdn-fleet keyring ([cdn_fleet] enabled = false)",
                ) from exc
            raise

    def public(self, version: int) -> SignedFleetKey:
        from apps.orchestration.effects import EffectError, EffectUnavailable
        from apps.orchestration.services.kbs_admin_tls import (
            KbsAdminTlsMisconfigured,
            admin_client_tls_argv,
        )

        kbs_url = str(getattr(settings, "VALI_KBS_ADMIN_URL", "") or "")
        client_bin = str(getattr(settings, "VALI_KBS_ADMIN_CLIENT_BIN", "") or "")
        if not kbs_url or not client_bin or not os.path.exists(client_bin):
            raise EffectUnavailable("VALI_KBS_ADMIN_URL / VALI_KBS_ADMIN_CLIENT_BIN not usable")
        try:
            tls_argv = admin_client_tls_argv()
        except KbsAdminTlsMisconfigured as exc:
            raise EffectUnavailable(str(exc)) from exc
        argv = [
            client_bin,
            "cdn-fleet-public",
            "--kbs-url",
            kbs_url,
            "--version",
            str(version),
            "--kbs-vk-hex",
            _pinned_kbs_key().hex(),
            *tls_argv,
        ]
        try:
            done = subprocess.run(  # noqa: S603 — argv list, no shell.
                argv, capture_output=True, timeout=30, check=False
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise EffectUnavailable(f"kbs-admin-client cdn-fleet-public: {exc}") from exc
        if done.returncode != 0:
            stderr = done.stderr.decode("utf-8", errors="replace").strip()[-500:]
            raise EffectError(f"kbs-admin-client cdn-fleet-public exit {done.returncode}: {stderr}")
        try:
            body = json.loads(done.stdout.decode("utf-8").strip().splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise EffectError("kbs-admin-client cdn-fleet-public: no JSON answer") from exc
        return verify_kbs_answer(body, version=version)


def source() -> FleetKeySource:
    return KbsFleetKeySource()


def record(key: SignedFleetKey) -> CdnFleetKey:
    """Store a freshly minted version as `pending`: published, so the nodes
    rebooted onto the keyring can be checked against it, but nobody seals to
    it until `set_state(..., active)`."""
    from .identity import MAX_FLEET_VERSIONS

    if len(key.x25519_public) != 32 or len(key.kbs_signature) != 64 or not key.kbs_kid_hex:
        raise FleetKeyError("fleet-key-shape", f"v{key.version}: malformed public metadata")
    with transaction.atomic():
        if CdnFleetKey.objects.filter(version=key.version).exists():
            raise FleetKeyError("fleet-key-exists", f"v{key.version} is already recorded")
        if CdnFleetKey.objects.filter(state__in=PUBLISHED_STATES).count() >= MAX_FLEET_VERSIONS:
            raise FleetKeyError(
                "fleet-key-too-many",
                f"{MAX_FLEET_VERSIONS} versions are published: retire one first",
            )
        row = CdnFleetKey.objects.create(
            version=key.version,
            x25519_public=key.x25519_public,
            kbs_kid_hex=key.kbs_kid_hex,
            kbs_signature=key.kbs_signature,
            state=CdnFleetKeyState.PENDING,
        )
        CdnRevision.bump()
    return row


_TRANSITIONS = {
    CdnFleetKeyState.PENDING: {CdnFleetKeyState.ACTIVE},
    CdnFleetKeyState.ACTIVE: {CdnFleetKeyState.RETIRING},
    CdnFleetKeyState.RETIRING: {CdnFleetKeyState.RETIRED},
    CdnFleetKeyState.RETIRED: set(),
}


def set_state(version: int, state: str) -> CdnFleetKey:
    """Move version `version` along pending → active → retiring → retired.
    Activating one moves the active one to `retiring` (unseal only).

    Exactly one version is ever `active` (the backend and the cdn-agent
    refuse a feed with two). Every transition first locks all published
    rows, in version order, so two concurrent activations serialize — the
    later one demotes the earlier — and the DB constraint
    `cdn_fleet_one_active` backs it: a violation surfaces as
    `fleet-key-concurrent-activation`, never as two actives."""
    from django.db import IntegrityError

    try:
        return _set_state(version, state)
    except IntegrityError as exc:
        raise FleetKeyError(
            "fleet-key-concurrent-activation",
            f"v{version}: another version became active concurrently; retry",
        ) from exc


def _set_state(version: int, state: str) -> CdnFleetKey:
    with transaction.atomic():
        list(
            CdnFleetKey.objects.select_for_update()
            .filter(state__in=PUBLISHED_STATES)
            .order_by("version")
            .values_list("version", flat=True)
        )
        row = CdnFleetKey.objects.select_for_update().filter(version=version).first()
        if row is None:
            raise FleetKeyError("fleet-key-not-found", f"no fleet key v{version}")
        current = CdnFleetKeyState(row.state)
        target = CdnFleetKeyState(state)
        if target not in _TRANSITIONS[current]:
            raise FleetKeyError(
                "fleet-key-transition", f"v{version} cannot go {current.value} → {target.value}"
            )
        if target == CdnFleetKeyState.ACTIVE:
            CdnFleetKey.objects.select_for_update().filter(state=CdnFleetKeyState.ACTIVE).update(
                state=CdnFleetKeyState.RETIRING
            )
        row.state = target
        row.save(update_fields=["state", "updated_at"])
        CdnRevision.bump()
    return row


def pending() -> CdnFleetKey | None:
    return CdnFleetKey.objects.filter(state=CdnFleetKeyState.PENDING).order_by("version").first()


def published() -> list[dict[str, Any]]:
    """`fleet_keys` of `GET /v1/cdn/nodes`, oldest first."""
    return [
        {
            "version": row.version,
            "x25519_public_b64": base64.b64encode(bytes(row.x25519_public)).decode("ascii"),
            "state": row.state,
            "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
            "kbs_kid_hex": row.kbs_kid_hex,
            "kbs_signature_b64": base64.b64encode(bytes(row.kbs_signature)).decode("ascii"),
        }
        for row in CdnFleetKey.objects.filter(state__in=PUBLISHED_STATES).order_by("version")
    ]
