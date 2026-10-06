"""The KBS admin routes of an authorized rollback (restore to an earlier
boot) — the vali client side. See `docs/design/backup-failover.md`
§"Restore to an earlier boot".

  POST   /v1/admin/vm/{vm_id}/rollback-checkpoint                 `fetch_checkpoint`
  POST   /v1/admin/vm/{vm_id}/authorize-rollback                  `authorize_rollback`
  DELETE /v1/admin/vm/{vm_id}/authorize-rollback/{restore_id}     `disarm`
  GET    /v1/admin/vm/{vm_id}/rollback                            `rollback_status`

All four ride the mTLS admin listener (`services.kbs_admin_tls`), like
every other lifecycle write: no miner holds an admin identity, so no miner
can create, extend or read an arm.

Success bodies are JSON. Refusals are the KBS's `AdminErrorResponse`
(CBOR `{reason, ...}`; JSON is accepted too), decoded here far enough to
read `reason` and `retry_after_s` — the refusal vocabulary is what the
restore turns into its failure reason.

§20: nothing secret crosses these calls. A checkpoint is a KBS-signed
statement of public anti-rollback metadata (a boot counter, a volume
stamp); an arm is an authorization record.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any

from apps.orchestration import effects
from apps.orchestration.effects import EffectError, KbsRouteMissing

#: The signed checkpoint's domain separator (C-4), before stamp protocol v2.
#: Still parsed (backups taken before V2 carry one), never armed by the KBS
#: (`checkpoint-not-timeline-bound`), so never rollback-restorable.
CHECKPOINT_DOMAIN = "HIPPIUS_KBS_ROLLBACK_CHECKPOINT_V1"
#: The V2 checkpoint (every checkpoint the KBS signs now): the V1 fields
#: plus the VM's volume-stamp TIMELINE — the timeline a rollback to the
#: point expects, so an abandoned-timeline disk can never pass for it.
CHECKPOINT_DOMAIN_V2 = "HIPPIUS_KBS_ROLLBACK_CHECKPOINT_V2"
#: V2 checkpoint JSON: the timeline, 64 lowercase hex chars.
WIRE_CHECKPOINT_TIMELINE = "volume_stamp_timeline_id_hex"
#: V2 signed CBOR: the timeline, 32 bytes.
_SIGNED_CHECKPOINT_TIMELINE = "volume_stamp_timeline_id"
#: 409 on `authorize-rollback`: a V1 checkpoint (no timeline) — terminal.
REASON_CHECKPOINT_NOT_TIMELINE_BOUND = "checkpoint-not-timeline-bound"

# ─── C-4 wire names, in ONE place ────────────────────────────────────
#: `authorize-rollback`: the point's exact `manifest.json` bytes (standard
#: base64). The KBS hashes them against `point_manifest_sha256_hex` and
#: reads the checkpoint they embed.
WIRE_MANIFEST_B64 = "point_manifest_b64"
#: Where a point's manifest embeds its checkpoint (`Checkpoint.wire()`).
MANIFEST_CHECKPOINT_KEY = "kbs_rollback_checkpoint"
#: `GET .../rollback` → `last_rollback.delivered`: the release that consumed
#: the arm was DELIVERED to the guest (the rollback really happened).
WIRE_DELIVERED = "delivered"
#: `last_rollback.reverted`: the KBS undid a consumed-but-undelivered
#: rollback (its authorisation is gone; nothing was delivered).
#: `delivered == false && reverted == false` ⇒ the release is IN FLIGHT.
WIRE_REVERTED = "reverted"
#: `GET .../rollback` → `last_clear: {restore_id, reason, at}`: which arm
#: the KBS last cleared without it being consumed, why and when.
WIRE_LAST_CLEAR = "last_clear"
WIRE_LAST_CLEAR_RESTORE_ID = "restore_id"
WIRE_LAST_CLEAR_REASON = "reason"
WIRE_LAST_CLEAR_AT = "at"
#: `GET .../rollback` → `rollback_capable`: the KBS owns the VM's volume
#: stamp AND its guest speaks the rollback-capable stamp protocol (v2). When
#: false, every `authorize-rollback` is refused (`guest-not-rollback-capable`).
WIRE_ROLLBACK_CAPABLE = "rollback_capable"
#: 409 on `authorize-rollback`: the guest cannot be rolled back (see
#: `WIRE_ROLLBACK_CAPABLE`). Terminal, and a pre-commit failure of a restore.
REASON_GUEST_NOT_ROLLBACK_CAPABLE = "guest-not-rollback-capable"
#: How long `rollback_capable_cached` trusts one KBS read.
ROLLBACK_CAPABLE_CACHE_S = 60.0
#: The KBS's bound on the decoded `point_manifest_b64`
#: (`MAX_POINT_MANIFEST_LEN`): a larger manifest is refused
#: (`bad-point-manifest`), so such a point is not rollback-capable.
MAX_POINT_MANIFEST_BYTES = 256 * 1024
#: `last_clear.reason` of an arm cleared because the VM's normal (not
#: rolled-back) boot committed: the arm can never be consumed any more.
CLEARED_BY_BOOT = "rollback-cleared-by-boot"
#: The admin gateway's shared limiter (429, `retry_after_s`): transient.
REASON_GATEWAY_RATE_LIMITED = "rate-limited"
#: 503: the KBS runs without its rollback context — no rollback at all.
REASON_ROLLBACK_UNAVAILABLE = "rollback-unavailable"
#: Arm lifetime vali asks for. The KBS refuses anything outside 60..=3600.
ARM_TTL_S = 3600
#: A checkpoint is fetched on the backup tick's path: never wait long on it.
CHECKPOINT_TIMEOUT_S = 5.0

_VM_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_RESTORE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z0-9-]{1,64}$")
#: Bound on a checkpoint's canonical CBOR: seven small fields.
_MAX_CHECKPOINT_CBOR = 1024
#: Ed25519: a 64-byte signature, a 32-byte public key.
_SIG_HEX_LEN = 128
_PUBKEY_HEX_LEN = 64


class RollbackRefused(EffectError):
    """The KBS answered a 4xx refusal (other than a missing route).
    `reason` is its stable code (`not-a-rollback`, `row-not-activated`, …),
    or `http-<status>` when the body carried none. Nothing was written, and
    re-sending the same request cannot change the answer."""

    def __init__(self, label: str, *, status: int, reason: str, retry_after_s: int | None):
        super().__init__(f"{label}: KBS refused ({status} {reason})")
        self.status = status
        self.reason = reason
        self.retry_after_s = retry_after_s


class KbsRateLimited(EffectError):
    """The KBS admin GATEWAY limiter refused the call (429 `rate-limited`,
    `retry_after_s`): nothing was looked at, and the same call a moment
    later may pass. Retryable — unlike the per-VM `rollback-rate-limited`
    refusal, which is a `RollbackRefused`."""

    def __init__(self, label: str, *, retry_after_s: int | None):
        super().__init__(f"{label}: KBS admin gateway busy (429 rate-limited)")
        self.retry_after_s = retry_after_s


class RollbackUnavailable(KbsRouteMissing):
    """503 `rollback-unavailable`: the deployed KBS runs without its
    rollback context. For every caller exactly a missing route: no arm can
    exist, none can be created, and asking again does not change that."""


class PointManifestInvalid(EffectError):
    """vali's own copy of a point's manifest bytes does not hash to the
    point's `manifest_sha256`, or does not embed the checkpoint being
    presented: the arm would bind to something else than the point. Never
    sent; terminal."""


class CheckpointMalformed(EffectError):
    """The KBS's 200 checkpoint does not parse, or its signed CBOR does not
    say what its JSON says (C-4 drift between vali and the KBS)."""


# ─── a minimal CBOR reader (the KBS's error bodies, the checkpoint) ──


class CborError(ValueError):
    pass


def decode_cbor(data: bytes, *, canonical: bool = False) -> Any:
    """Decode one definite-length CBOR item (RFC 8949: integers, byte and
    text strings, arrays, maps, tags (unwrapped), simple values, floats).
    Raises `CborError` on anything else, on trailing bytes, or past a small
    nesting depth — the inputs are a KBS error body and a checkpoint.

    `canonical` (the signed checkpoint) additionally refuses what a
    canonical encoder never emits: a non-shortest integer or length, a tag,
    a float."""
    value, end = _cbor_item(bytes(data), 0, 0, canonical)
    if end != len(data):
        raise CborError("trailing bytes")
    return value


def _cbor_arg(data: bytes, pos: int, info: int, canonical: bool) -> tuple[int, int]:
    if info < 24:
        return info, pos
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if width is None:
        raise CborError("indefinite or reserved length")
    if pos + width > len(data):
        raise CborError("truncated")
    value = int.from_bytes(data[pos : pos + width], "big")
    if canonical and value < (24 if width == 1 else 1 << (4 * width)):
        raise CborError("non-shortest encoding")
    return value, pos + width


def _cbor_item(data: bytes, pos: int, depth: int, canonical: bool) -> tuple[Any, int]:
    if depth > 16:
        raise CborError("nested too deep")
    if pos >= len(data):
        raise CborError("truncated")
    head = data[pos]
    major, info = head >> 5, head & 0x1F
    pos += 1
    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info in (22, 23):
            return None, pos
        fmt = {25: ">e", 26: ">f", 27: ">d"}.get(info)
        if fmt is None or canonical:
            raise CborError("unsupported simple value")
        width = struct.calcsize(fmt)
        if pos + width > len(data):
            raise CborError("truncated")
        return struct.unpack(fmt, data[pos : pos + width])[0], pos + width
    arg, pos = _cbor_arg(data, pos, info, canonical)
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if pos + arg > len(data):
            raise CborError("truncated")
        raw = data[pos : pos + arg]
        if major == 2:
            return bytes(raw), pos + arg
        try:
            return raw.decode("utf-8"), pos + arg
        except UnicodeDecodeError as exc:
            raise CborError("bad utf-8") from exc
    if major == 4:
        items = []
        for _ in range(arg):
            item, pos = _cbor_item(data, pos, depth + 1, canonical)
            items.append(item)
        return items, pos
    if major == 5:
        out: dict[Any, Any] = {}
        for _ in range(arg):
            key, pos = _cbor_item(data, pos, depth + 1, canonical)
            if not isinstance(key, (str, int)) or isinstance(key, bool):
                raise CborError("unsupported map key")
            if key in out:
                raise CborError("duplicate map key")
            out[key], pos = _cbor_item(data, pos, depth + 1, canonical)
        return out, pos
    # major 6: a tag — the tagged value is what matters here.
    if canonical:
        raise CborError("tag in a canonical item")
    return _cbor_item(data, pos, depth + 1, canonical)


def _refusal(body: bytes) -> tuple[str, int | None]:
    """`(reason, retry_after_s)` from a KBS error body (CBOR or JSON), or
    `("", None)` when it carries neither."""
    parsed: Any = None
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        try:
            parsed = decode_cbor(body)
        except CborError:
            parsed = None
    if not isinstance(parsed, dict):
        return "", None
    raw = parsed.get("reason", parsed.get("error"))
    reason = raw if isinstance(raw, str) and _REASON_RE.fullmatch(raw) else ""
    retry = parsed.get("retry_after_s")
    retry_after = retry if isinstance(retry, int) and not isinstance(retry, bool) else None
    return reason, (max(0, retry_after) if retry_after is not None else None)


# ─── the checkpoint ──────────────────────────────────────────────────


@dataclass(frozen=True)
class Checkpoint:
    """A KBS-signed statement of a VM's anti-rollback state at one instant.
    `wire()` is what vali stores on a backup run and in its manifest, and
    hands back to the KBS verbatim in `authorize-rollback`."""

    vm_id: str
    boot_counter: int
    volume_stamp: int
    unconfirmed_releases: int
    generation: int
    issued_at_unix: int
    checkpoint_cbor_hex: str
    signature_hex: str
    signer_pubkey_hex: str
    #: V2 only: the VM's volume-stamp timeline (64 lowercase hex). None ⇔ a
    #: V1 checkpoint.
    volume_stamp_timeline_id_hex: str | None = None

    @property
    def timeline_bound(self) -> bool:
        """A V2 checkpoint: the only kind the KBS arms a rollback to."""
        return self.volume_stamp_timeline_id_hex is not None

    def wire(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "domain": CHECKPOINT_DOMAIN_V2 if self.timeline_bound else CHECKPOINT_DOMAIN,
            "vm_id": self.vm_id,
            "boot_counter": self.boot_counter,
            "volume_stamp": self.volume_stamp,
        }
        if self.timeline_bound:
            body[WIRE_CHECKPOINT_TIMELINE] = self.volume_stamp_timeline_id_hex
        body.update(
            {
                "unconfirmed_releases": self.unconfirmed_releases,
                "generation": self.generation,
                "issued_at_unix": self.issued_at_unix,
            }
        )
        return {
            "checkpoint": body,
            "checkpoint_cbor_hex": self.checkpoint_cbor_hex,
            "signature_hex": self.signature_hex,
            "signer_pubkey_hex": self.signer_pubkey_hex,
        }


def checkpoint_is_timeline_bound(cp: dict[str, Any]) -> bool:
    """A stored checkpoint (`Checkpoint.wire()` shape) is V2 — the only
    kind `authorize-rollback` arms (a V1 one is refused
    `checkpoint-not-timeline-bound`)."""
    body = cp.get("checkpoint")
    return (
        isinstance(body, dict)
        and body.get("domain") == CHECKPOINT_DOMAIN_V2
        and isinstance(body.get(WIRE_CHECKPOINT_TIMELINE), str)
    )


_CHECKPOINT_UINTS = (
    "boot_counter",
    "volume_stamp",
    "unconfirmed_releases",
    "generation",
    "issued_at_unix",
)


def parse_checkpoint(raw: Any, *, vm_id: str) -> Checkpoint:
    """Type-check a checkpoint (the KBS's 200 body, or what vali stored
    from one). Raises `ValueError` on anything off-shape, a checkpoint of
    another VM or domain, or a signed CBOR that does not say what the JSON
    says — the boot counter vali compares is the one the KBS signed."""
    if not isinstance(raw, dict):
        raise ValueError("checkpoint response must be an object")
    body = raw.get("checkpoint")
    if not isinstance(body, dict):
        raise ValueError("checkpoint must be an object")
    domain = body.get("domain")
    if domain not in (CHECKPOINT_DOMAIN, CHECKPOINT_DOMAIN_V2):
        raise ValueError("checkpoint domain mismatch")
    timeline_hex: str | None = None
    if domain == CHECKPOINT_DOMAIN_V2:
        t = body.get(WIRE_CHECKPOINT_TIMELINE)
        if not isinstance(t, str) or not _SHA256_RE.fullmatch(t):
            raise ValueError(f"checkpoint.{WIRE_CHECKPOINT_TIMELINE} must be 64 lower-case hex")
        timeline_hex = t
    elif WIRE_CHECKPOINT_TIMELINE in body:
        raise ValueError("a V1 checkpoint carries no timeline")
    if body.get("vm_id") != vm_id:
        raise ValueError("checkpoint is about another vm")
    fields: dict[str, int] = {}
    for name in _CHECKPOINT_UINTS:
        v = body.get(name)
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError(f"checkpoint.{name} must be a non-negative integer")
        fields[name] = v
    if fields["boot_counter"] < 1:
        raise ValueError("checkpoint.boot_counter must be >= 1")

    def hex_field(name: str, *, cap: int = 0, exact: int = 0) -> str:
        v = raw.get(name)
        if (
            not isinstance(v, str)
            or not _HEX_RE.fullmatch(v)
            or (cap and len(v) > cap)
            or (exact and len(v) != exact)
        ):
            raise ValueError(f"{name} must be lower-case hex of the right length")
        return v

    cbor_hex = hex_field("checkpoint_cbor_hex", cap=2 * _MAX_CHECKPOINT_CBOR)
    signature_hex = hex_field("signature_hex", exact=_SIG_HEX_LEN)
    pubkey_hex = hex_field("signer_pubkey_hex", exact=_PUBKEY_HEX_LEN)
    try:
        signed = decode_cbor(bytes.fromhex(cbor_hex), canonical=True)
    except CborError as exc:
        raise ValueError(f"checkpoint_cbor_hex is not canonical CBOR: {exc}") from exc
    if not isinstance(signed, dict):
        raise ValueError("the signed checkpoint is not a map")
    expected: dict[str, Any] = {"domain": domain, "vm_id": vm_id, **fields}
    if timeline_hex is not None:
        expected[_SIGNED_CHECKPOINT_TIMELINE] = bytes.fromhex(timeline_hex)
    if set(signed) != set(expected):
        raise ValueError("the signed checkpoint disagrees on its field set")
    for name, value in expected.items():
        got = signed.get(name)
        if got != value or type(got) is not type(value):
            raise ValueError(f"the signed checkpoint disagrees on {name}")
    return Checkpoint(
        vm_id=vm_id,
        checkpoint_cbor_hex=cbor_hex,
        signature_hex=signature_hex,
        signer_pubkey_hex=pubkey_hex,
        volume_stamp_timeline_id_hex=timeline_hex,
        **fields,
    )


# ─── a point's manifest ──────────────────────────────────────────────


def _manifest_doc(manifest: bytes) -> dict[str, Any] | None:
    try:
        doc = json.loads(manifest)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def manifest_checkpoint_cbor_hex(manifest: bytes) -> str | None:
    """The `checkpoint_cbor_hex` a point's `manifest.json` bytes embed
    (`MANIFEST_CHECKPOINT_KEY`), or None when they embed none / do not
    parse."""
    doc = _manifest_doc(manifest)
    cp = doc.get(MANIFEST_CHECKPOINT_KEY) if doc is not None else None
    raw = cp.get("checkpoint_cbor_hex") if isinstance(cp, dict) else None
    return raw if isinstance(raw, str) else None


def check_point_manifest(
    manifest: bytes, *, vm_id: str, sha256_hex: str, checkpoint_cbor_hex: str
) -> None:
    """Raise `PointManifestInvalid` unless `manifest` is what the KBS arms
    against (`manifest-mismatch` / `bad-point-manifest`): 1 to
    `MAX_POINT_MANIFEST_BYTES` bytes hashing to `sha256_hex`, a JSON object
    naming `vm_id` at top level and embedding exactly
    `checkpoint_cbor_hex`."""
    if not manifest or len(manifest) > MAX_POINT_MANIFEST_BYTES:
        raise PointManifestInvalid(
            f"the point's manifest is {len(manifest)} bytes (the KBS takes 1.."
            f"{MAX_POINT_MANIFEST_BYTES})"
        )
    if hashlib.sha256(manifest).hexdigest() != sha256_hex:
        raise PointManifestInvalid("the point's manifest bytes do not hash to its manifest_sha256")
    doc = _manifest_doc(manifest)
    if doc is None or doc.get("vm_id") != vm_id:
        raise PointManifestInvalid("the point's manifest does not name the vm at top level")
    if manifest_checkpoint_cbor_hex(manifest) != checkpoint_cbor_hex:
        raise PointManifestInvalid("the point's manifest does not embed the presented checkpoint")


# ─── the routes ──────────────────────────────────────────────────────


def _url(vm_id: str, path: str) -> tuple[str, Any]:
    if not isinstance(vm_id, str) or not _VM_ID_RE.fullmatch(vm_id):
        # Charset-locked FIRST, so a 404 can only mean what the KBS says.
        raise EffectError("kbs-admin: vm_id failed the charset lock")
    transport = effects._kbs_admin_transport()
    return transport.url(f"/v1/admin/vm/{vm_id}/{path}"), transport.context


def refusal_error(label: str, status: int, body: bytes, *, route_404: bool = True) -> EffectError:
    """The error a non-2xx answer maps to:

    - a 404 without a KBS reason is a route the deployed KBS does not serve
      (`KbsRouteMissing`), and a 503 `rollback-unavailable` a KBS without
      its rollback context (`RollbackUnavailable`, a `KbsRouteMissing`);
    - a 429 `rate-limited` is the admin gateway's shared limiter
      (`KbsRateLimited`, retried);
    - any other 4xx is a `RollbackRefused` (terminal, the per-VM
      `rollback-rate-limited` included);
    - 5xx (and anything else) an `EffectError` (retried)."""
    reason, retry_after = _refusal(body)
    if status == 404 and route_404 and not reason:
        return KbsRouteMissing(f"{label}: KBS returned 404 — the route is not served")
    if status == 503 and reason == REASON_ROLLBACK_UNAVAILABLE:
        return RollbackUnavailable(f"{label}: KBS returned 503 {reason} — no rollback context")
    if status == 429 and reason == REASON_GATEWAY_RATE_LIMITED:
        return KbsRateLimited(label, retry_after_s=retry_after)
    if 400 <= status < 500:
        return RollbackRefused(
            label, status=status, reason=reason or f"http-{status}", retry_after_s=retry_after
        )
    return EffectError(f"{label}: KBS returned HTTP {status}")


def _raise_for(label: str, status: int, body: bytes, *, route_404: bool = True) -> None:
    raise refusal_error(label, status, body, route_404=route_404)


def fetch_checkpoint(vm_id: str, *, timeout: float = CHECKPOINT_TIMEOUT_S) -> Checkpoint:
    """`POST .../rollback-checkpoint` — the KBS's signed checkpoint of the
    VM's CURRENT stored boot counter and volume stamp.

    Raises `KbsRouteMissing` (the KBS predates A2), `RollbackRefused`
    (`no-vm-row`, `no-boot-counter`, …), `EffectUnavailable` (the admin
    listener is unreachable or unconfigured), `EffectError` otherwise
    (5xx, an off-shape body)."""
    label = "kbs-admin:rollback-checkpoint"
    url, context = _url(vm_id, "rollback-checkpoint")
    status, body = effects._http(
        "POST", url, label=label, json_body={}, context=context, timeout=timeout
    )
    if not 200 <= status < 300:
        _raise_for(label, status, body)
    try:
        return parse_checkpoint(effects._json(body, label=label), vm_id=vm_id)
    except (ValueError, EffectError) as exc:
        raise CheckpointMalformed(f"{label}: {exc}") from exc


def authorize_request_body(
    *,
    checkpoint_cbor_hex: str,
    signature_hex: str,
    manifest_sha256_hex: str,
    manifest: bytes,
    new_gen: int,
    dest_platform_id_hex: str,
    restore_id: str,
    requested_by: str,
    ttl_s: int,
) -> dict[str, Any]:
    """The C-4 `authorize-rollback` request body (pinned against the KBS's
    wire fixture). `manifest` travels as its exact bytes, standard base64
    with padding. Validation is `authorize_rollback`'s."""
    return {
        "checkpoint_cbor_hex": checkpoint_cbor_hex,
        "signature_hex": signature_hex,
        "point_manifest_sha256_hex": manifest_sha256_hex,
        WIRE_MANIFEST_B64: base64.b64encode(manifest).decode("ascii"),
        "new_gen": new_gen,
        "dest_platform_id_hex": dest_platform_id_hex,
        "restore_id": restore_id,
        "ttl_s": int(ttl_s),
        "requested_by": requested_by,
    }


def authorize_rollback(
    vm_id: str,
    *,
    checkpoint_cbor_hex: str,
    signature_hex: str,
    manifest_sha256_hex: str,
    manifest: bytes,
    new_gen: int,
    dest_platform_id_hex: str,
    restore_id: str,
    requested_by: str,
    ttl_s: int = ARM_TTL_S,
) -> dict[str, Any]:
    """`POST .../authorize-rollback` — arm ONE release of the VM at
    `new_gen` on `dest_platform_id_hex` to accept the checkpoint's boot
    counter + 1 (a rollback). `manifest` is the point's EXACT
    `manifest.json` bytes: they must hash to `manifest_sha256_hex` and
    embed this checkpoint (checked here first — `PointManifestInvalid` —
    and again by the KBS). Returns the KBS's arm (201, or 200 when this
    `restore_id` is already armed).

    Raises `RollbackRefused` for every C-4 refusal (`bad-checkpoint-
    signature`, `checkpoint-vm-mismatch`, `checkpoint-unstamped`,
    `manifest-mismatch`, `not-a-rollback`, `row-not-activated`,
    `arm-exists`, `rollback-rate-limited`, `ttl-out-of-range`),
    `KbsRouteMissing` on a KBS without the route (or without its rollback
    context), `KbsRateLimited` when the admin gateway is busy,
    `EffectUnavailable` / `EffectError` as `fetch_checkpoint`."""
    label = "kbs-admin:authorize-rollback"
    if not _RESTORE_ID_RE.fullmatch(restore_id or ""):
        raise EffectError(f"{label}: restore_id must be 32 lower-case hex characters")
    if not _SHA256_RE.fullmatch(manifest_sha256_hex or ""):
        raise EffectError(f"{label}: manifest sha256 must be 64 lower-case hex characters")
    check_point_manifest(
        manifest,
        vm_id=vm_id,
        sha256_hex=manifest_sha256_hex,
        checkpoint_cbor_hex=checkpoint_cbor_hex,
    )
    if not isinstance(new_gen, int) or isinstance(new_gen, bool) or new_gen < 1:
        raise EffectError(f"{label}: new_gen must be an integer >= 1")
    if not _HEX_RE.fullmatch(dest_platform_id_hex or ""):
        raise EffectError(f"{label}: dest_platform_id_hex must be lower-case hex")
    url, context = _url(vm_id, "authorize-rollback")
    status, body = effects._http(
        "POST",
        url,
        label=label,
        json_body=authorize_request_body(
            checkpoint_cbor_hex=checkpoint_cbor_hex,
            signature_hex=signature_hex,
            manifest_sha256_hex=manifest_sha256_hex,
            manifest=manifest,
            new_gen=new_gen,
            dest_platform_id_hex=dest_platform_id_hex,
            restore_id=restore_id,
            requested_by=requested_by,
            ttl_s=ttl_s,
        ),
        context=context,
    )
    if not 200 <= status < 300:
        _raise_for(label, status, body)
    parsed = effects._json(body, label=label)
    arm = parsed.get("arm")
    if not isinstance(arm, dict):
        raise EffectError(f"{label}: 2xx body carries no arm")
    return arm


def disarm(vm_id: str, restore_id: str) -> None:
    """`DELETE .../authorize-rollback/{restore_id}` — drop the arm if it is
    still there. Idempotent (204 whether or not it existed). A KBS without
    the route has no arms: that is a success too."""
    label = "kbs-admin:disarm-rollback"
    if not _RESTORE_ID_RE.fullmatch(restore_id or ""):
        raise EffectError(f"{label}: restore_id must be 32 lower-case hex characters")
    url, context = _url(vm_id, f"authorize-rollback/{restore_id}")
    status, body = effects._http("DELETE", url, label=label, context=context)
    if 200 <= status < 300:
        return
    try:
        _raise_for(label, status, body)
    except KbsRouteMissing:
        return


def rollback_status(vm_id: str) -> dict[str, Any]:
    """`GET .../rollback` — `{arm: {...} | None, last_rollback: {restore_id,
    manifest_sha256_hex, from_counter, to_counter, stamp, consumed_at_unix,
    requested_by, delivered, reverted} | None, last_clear: {restore_id,
    reason, at} | None, rollback_capable: bool}`. Raises as
    `fetch_checkpoint`, and `EffectError` on a `last_rollback` that does not
    say whether it was delivered and whether it was reverted: those are the
    facts every commit decision reads, so a KBS that omits them is never
    read as "not delivered". A missing or non-boolean `rollback_capable` is
    an `EffectError` too: every KBS that serves this route sends it, and it
    is never guessed."""
    label = "kbs-admin:rollback"
    url, context = _url(vm_id, "rollback")
    status, body = effects._http("GET", url, label=label, context=context)
    if not 200 <= status < 300:
        _raise_for(label, status, body)
    parsed = effects._json(body, label=label)
    arm = parsed.get("arm")
    last = parsed.get("last_rollback")
    clear = parsed.get(WIRE_LAST_CLEAR)
    if arm is not None and (
        not isinstance(arm, dict) or not isinstance(arm.get("restore_id"), str)
    ):
        raise EffectError(f"{label}: arm must be an object with a restore_id, or null")
    if last is not None:
        if not isinstance(last, dict):
            raise EffectError(f"{label}: last_rollback must be an object or null")
        consumed = last.get("consumed_at_unix")
        if (
            not isinstance(last.get("restore_id"), str)
            or isinstance(consumed, bool)
            or not isinstance(consumed, int)
            or consumed < 0
        ):
            # The arm correlation and the KBS-side rate limit read these.
            raise EffectError(
                f"{label}: last_rollback must carry restore_id and consumed_at_unix"
            )
        if not isinstance(last.get(WIRE_DELIVERED), bool):
            raise EffectError(f"{label}: last_rollback.{WIRE_DELIVERED} must be a boolean")
        if not isinstance(last.get(WIRE_REVERTED), bool):
            raise EffectError(f"{label}: last_rollback.{WIRE_REVERTED} must be a boolean")
    if clear is not None:
        if not isinstance(clear, dict):
            raise EffectError(f"{label}: {WIRE_LAST_CLEAR} must be an object or null")
        rid = clear.get(WIRE_LAST_CLEAR_RESTORE_ID)
        reason, at = clear.get(WIRE_LAST_CLEAR_REASON), clear.get(WIRE_LAST_CLEAR_AT)
        if (
            not isinstance(rid, str)
            or not isinstance(reason, str)
            or isinstance(at, bool)
            or not isinstance(at, int)
            or at < 0
        ):
            raise EffectError(f"{label}: {WIRE_LAST_CLEAR} must be {{restore_id, reason, at}}")
    capable = parsed.get(WIRE_ROLLBACK_CAPABLE)
    if not isinstance(capable, bool):
        raise EffectError(f"{label}: {WIRE_ROLLBACK_CAPABLE} must be a boolean")
    return {
        "arm": arm,
        "last_rollback": last,
        WIRE_LAST_CLEAR: clear,
        WIRE_ROLLBACK_CAPABLE: capable,
    }


def _capable_cache_key(vm_id: str) -> str:
    return f"kbs-rollback-capable:{vm_id}"


def note_rollback_capable(vm_id: str, capable: bool | None) -> None:
    """Remember what the KBS last said about `vm_id`'s `rollback_capable`
    (None: it could not be read) for `rollback_capable_cached`."""
    from django.conf import settings
    from django.core.cache import cache

    ttl = float(getattr(settings, "VALI_KBS_ROLLBACK_CAPABLE_CACHE_S", ROLLBACK_CAPABLE_CACHE_S))
    cache.set(_capable_cache_key(vm_id), {"capable": capable}, timeout=ttl)


def rollback_capable_cached(vm_id: str) -> bool | None:
    """The KBS's `rollback_capable` for `vm_id`, read at most once per
    `VALI_KBS_ROLLBACK_CAPABLE_CACHE_S` (a listing view reads it, and must
    not hammer the KBS). None when the KBS does not answer, does not serve
    the route, or answers off-shape — also remembered, so a KBS that is
    down is not asked again on every read. Display only: the restore intake
    reads the KBS afresh."""
    from django.core.cache import cache

    hit = cache.get(_capable_cache_key(vm_id))
    if isinstance(hit, dict) and "capable" in hit:
        return hit["capable"]
    capable: bool | None
    try:
        capable = rollback_status(vm_id)[WIRE_ROLLBACK_CAPABLE]
    except EffectError:
        # KbsRouteMissing / EffectUnavailable / an off-shape body: unknown.
        capable = None
    note_rollback_capable(vm_id, capable)
    return capable


def delivered(last: dict[str, Any] | None) -> bool:
    """A `last_rollback` (as `rollback_status` returns it) whose release
    was DELIVERED to the guest and not reverted: the rollback happened."""
    return (
        isinstance(last, dict)
        and last.get(WIRE_DELIVERED) is True
        and last.get(WIRE_REVERTED) is not True
    )


def in_flight(last: dict[str, Any] | None) -> bool:
    """A consumed `last_rollback` neither delivered nor reverted yet: its
    release is being processed right now, and may still deliver."""
    return (
        isinstance(last, dict)
        and last.get(WIRE_DELIVERED) is not True
        and last.get(WIRE_REVERTED) is not True
    )


def cleared_by_boot(clear: dict[str, Any] | None, restore_id: str) -> bool:
    """`last_clear` says arm `restore_id` was cleared, unconsumed, because
    the VM's normal (not rolled-back) boot committed."""
    return (
        isinstance(clear, dict)
        and clear.get(WIRE_LAST_CLEAR_RESTORE_ID) == restore_id
        and clear.get(WIRE_LAST_CLEAR_REASON) == CLEARED_BY_BOOT
    )


__all__ = [
    "ARM_TTL_S",
    "CHECKPOINT_DOMAIN",
    "Checkpoint",
    "CheckpointMalformed",
    "KbsRateLimited",
    "PointManifestInvalid",
    "RollbackRefused",
    "RollbackUnavailable",
    "authorize_request_body",
    "authorize_rollback",
    "check_point_manifest",
    "cleared_by_boot",
    "decode_cbor",
    "delivered",
    "disarm",
    "in_flight",
    "manifest_checkpoint_cbor_hex",
    "fetch_checkpoint",
    "parse_checkpoint",
    "note_rollback_capable",
    "refusal_error",
    "rollback_capable_cached",
    "rollback_status",
]
