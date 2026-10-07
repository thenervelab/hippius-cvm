"""Minimal Vault KV v2 client for `vali_create_vm`.

Scope: just the two verbs the create-vm flow needs — `put` (write the
plaintext bytes of one secret + return the new version) and
`metadata` (read the current latest version). No background polling,
no token renewal, no AppRole login: the caller passes the token as
an env var.

Transport: stdlib `urllib` so we don't pull a third-party dependency
into vali. mTLS to Vault would need `ssl.SSLContext` plumbing — for
the dev-mode flow we accept a CA bundle path (`VALI_VAULT_CACERT`)
and verify the server cert against it.

Auth (M-k8sauth, #94): when `VALI_VAULT_JWT_ROLE` is set and the
projected ServiceAccount token is present, each process logs in to
`auth/<mount>/login` and caches the SHORT-lived Vault token it gets
back, re-logging in at 2/3 of the lease. Otherwise — the operator CLI,
tests, anything off-cluster — it falls back to the static `VAULT_TOKEN`
env. While both are configured the static token is a FALLBACK ONLY, and
taking it is logged at ERROR.

A jwt-login failure NAMES ITS PRECONDITION (P4). "no projected SA token"
told the reader nothing: not which path was looked at, not which role or
auth mount was configured, not whether the file was absent, unreadable or
empty — and an audience that does not match the role's `bound_audiences`
failed in a way that read exactly the same from the outside. Every branch
below states the missing thing, because the failure surfaces hours away
from the deploy that caused it (the full synthetic monitor's Vault use is
its LAST stage).

§20 discipline:
- The token is resolved per call and never logged or
  exception-attached; a jwt-login failure reports the HTTP status, the
  configured identity and — at most — the `aud` CLAIM of the submitted
  JWT, never the JWT itself, because some Vault versions echo the
  submitted JWT in the error body.
- The plaintext bytes are written exactly once (in the POST body) and
  never echoed back; callers retain their own zeroizing buffer.
- Errors include the static label of the operation, never the URL or
  the body.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from django.conf import settings

from apps.orchestration.effects import EffectError, EffectUnavailable

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 10.0


class VaultNotFound(EffectError):
    """KV v2 read hit a 404 — the path (or version) does not exist.
    Subclasses `EffectError` so existing broad handlers still work;
    callers that need to branch on absence (e.g. the first-write-wins
    lifecycle-key staging) catch this precisely."""


class VaultCasConflict(EffectError):
    """KV v2 write with a Check-And-Set option was refused because the
    path's current version did not match. With `cas=0` this means
    "another writer already created the secret" — the first-write-wins
    loser reads version 1 back instead of overwriting."""


class VaultPermissionDenied(EffectError):
    """Vault answered 403 to a write. On a create-only path (no `update`)
    that is also how an existing secret answers a rewrite: Vault checks the
    capability before the check-and-set."""


@dataclass(frozen=True)
class VaultWriteResult:
    """Outcome of one KV v2 put. `version` is the integer Vault assigned
    to the new write (monotonic per path); callers fold it into the
    OrderTicket so the KBS reads the exact bytes that backed the
    digest the L1 ticket binds."""

    version: int


def _addr() -> str:
    addr = str(getattr(settings, "VALI_VAULT_ADDR", "") or "").strip()
    if not addr:
        raise EffectUnavailable("VALI_VAULT_ADDR is not configured")
    return addr.rstrip("/")


def _static_token() -> str:
    return (os.environ.get("VAULT_TOKEN") or "").strip()


def _jwt_role() -> str:
    return str(getattr(settings, "VALI_VAULT_JWT_ROLE", "") or "").strip()


def _jwt_mount() -> str:
    return str(getattr(settings, "VALI_VAULT_JWT_AUTH_PATH", "jwt") or "jwt").strip("/")


def _sa_token_path() -> str:
    return str(getattr(settings, "VALI_VAULT_JWT_TOKEN_PATH", "") or "").strip()


def _jwt_identity() -> str:
    """The configured k8s-auth identity, as a short NON-SECRET string:
    role, login mount, token path. Appended to every jwt-login failure so
    the reader does not have to open this file to learn which of the three
    is wrong. None of it is secret — the role and mount are chart values
    and the path is a filesystem location."""
    return (
        f"role={_jwt_role()!r}, login=auth/{_jwt_mount()}/login, "
        f"token_path={_sa_token_path()!r}"
    )


def _unverified_jwt_audience(token: str) -> str:
    """Best-effort `aud` claim of an UNVERIFIED JWT, for diagnostics only.

    An audience that does not match the Vault role's `bound_audiences` is
    refused with an HTTP 400 whose body says nothing useful (and which we
    must not echo — §20). Naming the audience we actually presented turns
    that into a one-line diagnosis.

    §20: reads EXACTLY ONE claim and returns nothing else — never the
    token, never another claim. Anything unparseable ⇒ `"unreadable"`,
    because a projected token is a JWT and a non-JWT here is itself the
    finding.
    """
    try:
        payload_b64 = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    except (ValueError, IndexError, TypeError):
        return "unreadable"
    aud = claims.get("aud") if isinstance(claims, dict) else None
    if isinstance(aud, str) and aud:
        return aud
    if isinstance(aud, list) and aud and all(isinstance(a, str) for a in aud):
        return ",".join(aud)
    return "unreadable"


def _read_sa_jwt() -> str:
    """Read the projected ServiceAccount token.

    Raises `EffectUnavailable` NAMING the missing precondition — which
    path was looked at, and whether it is unconfigured, absent (the pod
    spec is missing the projected-token volumeMount — the P4 production
    failure), unreadable, or present-but-empty. The caller
    (`_token`) still treats the raise as "fall back to the static token if
    there is one", so absent remains non-fatal off-cluster (the operator
    CLI, tests) — it is only the MESSAGE that got specific.
    """
    path = _sa_token_path()
    if not path:
        raise EffectUnavailable(
            "vault-jwt-login: VALI_VAULT_JWT_TOKEN_PATH is not configured, so "
            f"there is no ServiceAccount token to present ({_jwt_identity()})"
        )
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as exc:
        raise EffectUnavailable(
            f"vault-jwt-login: no projected ServiceAccount token at {path!r} "
            f"({type(exc).__name__}) — the pod spec must mount a projected "
            f"`serviceAccountToken` volume at {os.path.dirname(path)!r} whose "
            "audience matches the Vault role's bound_audiences (chart: "
            f"vali.vaultTokenVolume + vali.vaultTokenVolumeMount) [{_jwt_identity()}]"
        ) from exc
    token = raw.strip()
    if not token:
        raise EffectUnavailable(
            f"vault-jwt-login: the projected ServiceAccount token at {path!r} is "
            f"EMPTY — the volume is mounted but carries no credential ({_jwt_identity()})"
        )
    return token


def _urlopen_login(request: urllib.request.Request) -> bytes:
    """The one network call of the login, isolated so it can be exercised
    without also stubbing out the parsing and caching around it."""
    with urllib.request.urlopen(  # noqa: S310 — https-pinned via CACERT
        request, timeout=DEFAULT_TIMEOUT_S, context=_ssl_context()
    ) as resp:
        return resp.read()


def _jwt_login() -> tuple[str, float]:
    """Exchange the projected SA JWT for a short-lived Vault token.

    Returns `(client_token, lease_seconds)`. Raises `EffectUnavailable`
    on any failure so the caller can fall back while both credentials
    coexist (the transition window).

    Deliberately does NOT go through `_round_trip` — that would recurse
    through `_token()`, and the login is the one call that carries no
    Vault token of its own.
    """
    sa_jwt = _read_sa_jwt()  # raises, naming the missing precondition
    mount = _jwt_mount()
    body = json.dumps({"role": _jwt_role(), "jwt": sa_jwt}).encode("utf-8")
    request = urllib.request.Request(
        f"{_addr()}/v1/auth/{mount}/login",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        payload = json.loads(_urlopen_login(request) or b"{}")
    except urllib.error.HTTPError as exc:
        # NEVER attach the body: a login error echoes back the submitted
        # JWT in some Vault versions. The `aud` CLAIM is safe and is the
        # single most useful fact here — 400 is almost always an audience
        # that does not match the role's `bound_audiences`, and that
        # failure is otherwise indistinguishable from a missing token.
        raise EffectUnavailable(
            f"vault-jwt-login: Vault refused the ServiceAccount token, HTTP "
            f"{exc.code} ({_jwt_identity()}, presented aud="
            f"{_unverified_jwt_audience(sa_jwt)!r}) — a 400 here is usually an "
            "audience that does not match the role's bound_audiences, a 403 a "
            "subject the role does not bind"
        ) from exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise EffectUnavailable(f"vault-jwt-login: vault unreachable ({_jwt_identity()})") from exc
    auth = payload.get("auth") or {}
    token = str(auth.get("client_token") or "").strip()
    if not token:
        raise EffectUnavailable(
            f"vault-jwt-login: response carried no client_token ({_jwt_identity()})"
        )
    try:
        lease = float(auth.get("lease_duration") or 0.0)
    except (TypeError, ValueError):
        lease = 0.0
    return token, lease


# Process-local cache of the jwt-login token. Guarded by a lock because
# gunicorn runs threaded workers — without it, N concurrent requests on a
# cold cache each mint a token and N-1 are leaked (they are never
# revoked, just left to expire).
_JWT_CACHE: dict[str, Any] = {"token": "", "expires_at": 0.0}
_JWT_LOCK = threading.Lock()

# Refresh at 2/3 of the lease rather than at expiry, so a call that
# starts just before the boundary cannot land after it.
_JWT_REFRESH_RATIO = 2.0 / 3.0
# Floor for a lease Vault reports as 0/absent (root-ish or misconfigured
# role). WITHOUT it `expires_at` lands on `now`, the cache never hits, and
# vali logs in again on EVERY Vault call — a hot loop against Vault, not a
# stale token. The floor turns that into one login per 5 min.
_JWT_FALLBACK_LEASE_S = 300.0


def _cached_jwt_token(*, force_refresh: bool = False) -> str:
    now = time.monotonic()
    with _JWT_LOCK:
        if not force_refresh and _JWT_CACHE["token"] and now < float(_JWT_CACHE["expires_at"]):
            return str(_JWT_CACHE["token"])
        token, lease = _jwt_login()
        if lease <= 0:
            lease = _JWT_FALLBACK_LEASE_S
        _JWT_CACHE["token"] = token
        _JWT_CACHE["expires_at"] = now + (lease * _JWT_REFRESH_RATIO)
        return token


def _token(*, force_refresh: bool = False) -> str:
    """Resolve the Vault token for one call.

    Order: `jwt` login when a role is configured, else the static
    `VAULT_TOKEN`. While both are configured the static token is a
    FALLBACK — if the login fails we log loudly and keep serving, so a
    half-finished migration degrades instead of breaking. Phase 5 of
    #94 removes the static half.
    """
    if _jwt_role():
        try:
            return _cached_jwt_token(force_refresh=force_refresh)
        except EffectUnavailable:
            static = _static_token()
            if not static:
                raise
            # Loud on purpose: a silent fallback would hide a broken jwt
            # setup for as long as the static token happens to live.
            log.error(
                "vault auth: jwt login failed, falling back to the static "
                "VAULT_TOKEN — the jwt setup needs attention (%s)",
                _jwt_identity(),
                exc_info=True,
            )
            return static
    static = _static_token()
    if not static:
        raise EffectUnavailable("VAULT_TOKEN env is not set")
    return static


def _ssl_context() -> ssl.SSLContext | None:
    """Return an `SSLContext` honoring `VALI_VAULT_CACERT`, or `None`
    when the addr is plain HTTP (dev-mode catch-all).
    """
    addr = _addr()
    if not addr.startswith("https://"):
        return None
    ca_path = str(getattr(settings, "VALI_VAULT_CACERT", "") or "").strip()
    if ca_path:
        return ssl.create_default_context(cafile=ca_path)
    return ssl.create_default_context()


def _round_trip(
    method: str,
    path: str,
    *,
    label: str,
    json_body: dict[str, Any] | None = None,
) -> tuple[int, bytes]:
    status, body = _round_trip_once(method, path, label=label, json_body=json_body)
    # A cached jwt token can expire between two calls (or be revoked), and
    # Vault answers that with the SAME 403 as a genuine policy denial. Only
    # ONE retry, and only when we hold a cached jwt token: re-login and
    # replay. A real denial simply 403s again — one wasted login, no loop.
    if status == 403 and _jwt_role() and _JWT_CACHE["token"]:
        status, body = _round_trip_once(
            method, path, label=label, json_body=json_body, force_refresh=True
        )
    return status, body


def _round_trip_once(
    method: str,
    path: str,
    *,
    label: str,
    json_body: dict[str, Any] | None = None,
    force_refresh: bool = False,
) -> tuple[int, bytes]:
    url = f"{_addr()}{path}"
    data: bytes | None = None
    headers = {"X-Vault-Token": _token(force_refresh=force_refresh)}
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(
            request,
            timeout=DEFAULT_TIMEOUT_S,
            context=_ssl_context(),
        ) as resp:  # noqa: S310 — vali-internal, https-pinned via CACERT
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise EffectUnavailable(f"{label}: vault unreachable") from exc


def put_kv(
    mount: str, secret_path: str, value: bytes, *, cas: int | None = None
) -> VaultWriteResult:
    """Write `value` (raw bytes) to KV v2 at `<mount>/data/<path>` as
    a single-field secret `{"value": base64(value)}`. Returns the new
    version Vault assigned.

    When `cas` is given it is passed as the KV v2 Check-And-Set option:
    `cas=0` means "write only if the secret does not exist yet" (the
    first-write-wins primitive); Vault refuses a mismatched write with
    HTTP 400, surfaced as :class:`VaultCasConflict`.

    The KBS reads the same path + same field shape on release; the
    base64 wrapper is the same one `scripts/tenant-secrets-stage.sh`
    uses.
    """
    label = f"vault-kv-put:{mount}"
    body: dict[str, Any] = {"data": {"value": base64.b64encode(value).decode("ascii")}}
    if cas is not None:
        body["options"] = {"cas": int(cas)}
    status, raw = _round_trip(
        "POST",
        f"/v1/{mount}/data/{secret_path}",
        label=label,
        json_body=body,
    )
    if status == 400 and cas is not None and b"check-and-set" in raw.lower():
        raise VaultCasConflict(f"{label}: check-and-set conflict (cas={cas})")
    if status == 403:
        raise VaultPermissionDenied(f"{label}: vault returned HTTP 403")
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    version = (
        ((parsed or {}).get("data") or {}).get("version") if isinstance(parsed, dict) else None
    )
    if not isinstance(version, int) or version < 1:
        raise EffectError(f"{label}: response missing data.version")
    return VaultWriteResult(version=version)


def get_kv(mount: str, secret_path: str, *, version: int | None = None) -> bytes:
    """Read the raw bytes of the single-field secret `put_kv` wrote at
    `<mount>/data/<path>` — base64-decoding the `value` field. When
    `version` is given, reads that exact KV-v2 version (the worker reads
    back the precise bytes the POST staged); otherwise the latest.

    §20: the returned bytes are secret-bearing — the caller must zeroize.
    Never logged; errors carry only the static label.
    """
    label = f"vault-kv-get:{mount}"
    path = f"/v1/{mount}/data/{secret_path}"
    if version is not None:
        path = f"{path}?version={int(version)}"
    status, raw = _round_trip("GET", path, label=label)
    if status == 404:
        raise VaultNotFound(f"{label}: not-found")
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    # KV v2 read shape: {"data": {"data": {"value": "<b64>"}, "metadata": …}}
    value_b64 = (
        (((parsed or {}).get("data") or {}).get("data") or {}).get("value")
        if isinstance(parsed, dict)
        else None
    )
    if not isinstance(value_b64, str):
        raise EffectError(f"{label}: response missing data.data.value")
    try:
        return base64.b64decode(value_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise EffectError(f"{label}: value is not valid base64") from exc


def get_kv_field(mount: str, secret_path: str, field: str, *, version: int | None = None) -> str:
    """Read a single NAMED string field from the KV v2 secret at
    `<mount>/data/<path>` (shape `{"<field>": "<str>"}`), as opposed to
    `get_kv`'s base64-`value` convention. Used for human-readable hex
    secrets staged as `<field>=<hex>` — e.g. the §22 allowlist-root /
    L1 signing seeds in `secret/hippius-compute/vali/*`.

    §20: the returned string is secret-bearing — the caller must NOT log
    it and must drop it (and zeroize any derived bytes) promptly. Errors
    carry only the static label, never the value.
    """
    label = f"vault-kv-get:{mount}"
    path = f"/v1/{mount}/data/{secret_path}"
    if version is not None:
        path = f"{path}?version={int(version)}"
    status, raw = _round_trip("GET", path, label=label)
    if status == 404:
        raise EffectError(f"{label}: not-found")
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    val = (
        (((parsed or {}).get("data") or {}).get("data") or {}).get(field)
        if isinstance(parsed, dict)
        else None
    )
    if not isinstance(val, str) or not val:
        raise EffectError(f"{label}: response missing data.data.{field}")
    return val


def kv_exists(mount: str, secret_path: str) -> bool:
    """Whether ANY KV v2 metadata exists at `<mount>/metadata/<path>` —
    i.e. a secret (current, deleted or destroyed version history) was ever
    written there. Reads metadata only, never the value. 404 ⇒ `False`;
    any other non-2xx fails loudly (`EffectError`)."""
    label = f"vault-kv-metadata:{mount}"
    status, _raw = _round_trip("GET", f"/v1/{mount}/metadata/{secret_path}", label=label)
    if status == 404:
        return False
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    return True


def latest_version(mount: str, secret_path: str) -> int:
    """Read the metadata of the KV v2 secret at `<mount>/metadata/<path>`
    and return the current latest integer version. Useful when a caller
    wants to mint a ticket binding the latest in-Vault bytes without
    re-uploading them."""
    label = f"vault-kv-metadata:{mount}"
    status, raw = _round_trip(
        "GET",
        f"/v1/{mount}/metadata/{secret_path}",
        label=label,
    )
    if status == 404:
        raise EffectError(f"{label}: not-found")
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    version = (
        ((parsed or {}).get("data") or {}).get("current_version")
        if isinstance(parsed, dict)
        else None
    )
    if not isinstance(version, int) or version < 1:
        raise EffectError(f"{label}: response missing data.current_version")
    return version


# ── §KEK-HSM Phase 2 — Vault Transit (HSM-back the KEK) ───────────────
#
# The tenant disk KEK is stored WRAPPED (Vault Transit ciphertext,
# `vault:v1:…`), never plaintext, so a vali/broker/node compromise that
# reads the KV path gets only ciphertext. The plaintext KEK exists in the
# clear ONLY transiently inside the attested SNP KBS CVM, which
# `transit/decrypt`s it (scoped by the broker to `kek-<vm_id>`) before
# HPKE-wrapping to the guest. vali holds `transit/encrypt` (wrap) + create
# on `transit/keys/kek-*` but NOT `transit/decrypt` — so a vali RCE can
# overwrite a KEK (DoS) but can never recover a plaintext KEK.


def transit_key_name(vm_id: str) -> str:
    """The PER-VM Transit key name — must match the KBS (`kek-<vm_id>`,
    `kbs-core::release`) and the broker cap grant."""
    return f"kek-{vm_id}"


def userdata_transit_key_name(vm_id: str) -> str:
    """The per-VM Transit key for vali's OWN working copy of the
    cloud-init userdata (`ud-<vm_id>`) — deliberately NOT `kek-<vm_id>`.

    Two keys because the two copies answer to different readers:

    - `{vm}/userdata` — what the ticket binds and the KBS releases. Wrapped
      under `kek-<vm_id>`, which vali may encrypt with and never decrypt.
      Only the attested SNP KBS opens it.
    - `{vm}/userdata-pending` — vali's working copy. Wrapped under this
      key, which vali MAY decrypt, because three vali paths still need the
      cloud-init PLAINTEXT after intake: the NetBird setup-key
      substitution at launch, and the §6 digest re-derivation on a §25
      migration or a KBS-state recovery (the digest is over the plaintext
      and binds a FRESH ticket_id each time, so it cannot be precomputed).

    What this buys, precisely: the userdata is CIPHERTEXT at rest in both
    copies — a Vault storage / etcd-snapshot / backup compromise, or a
    token with KV read but no Transit grant, yields nothing — and §24
    destroys both keys, so decommission is a real crypto-erase. What it
    does NOT buy: protection against an RCE holding vali's own Vault
    credentials, which can call `transit/decrypt/ud-<vm_id>`. Closing that
    requires removing the ticket_id from the §6 digest preimage, which the
    GUEST also computes (`hippius_guest::release`) — i.e. a fleet-wide
    image re-bake. Tracked as the follow-up; deliberately not smuggled in
    here.
    """
    return f"ud-{vm_id}"


def transit_decrypt(name: str, ciphertext: bytes) -> bytes:
    """Unwrap `ciphertext` with the Transit key `name`.

    Granted ONLY for `ud-*` (vali's userdata working copy) — the policy
    denies `transit/decrypt/kek-*`, so this can never recover a tenant
    disk KEK or the canonical userdata the KBS releases. §20: the
    plaintext is returned to the caller and never logged.
    """
    label = "vault-transit-decrypt"
    body = {"ciphertext": ciphertext.decode("ascii", errors="strict")}
    status, raw = _round_trip("POST", f"/v1/transit/decrypt/{name}", label=label, json_body=body)
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    b64 = ((parsed or {}).get("data") or {}).get("plaintext") if isinstance(parsed, dict) else None
    if not isinstance(b64, str):
        raise EffectError(f"{label}: response missing data.plaintext")
    try:
        return base64.b64decode(b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise EffectError(f"{label}: data.plaintext is not valid base64") from exc


def ensure_transit_key(name: str) -> None:
    """Create the per-VM Transit key `name` (idempotent — Vault returns
    204 whether or not it already existed). Default type aes256-gcm96."""
    label = "vault-transit-key"
    status, _ = _round_trip("POST", f"/v1/transit/keys/{name}", label=label, json_body={})
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")


def transit_encrypt(name: str, plaintext: bytes) -> bytes:
    """Wrap `plaintext` with the Transit key `name`. Returns the Vault
    Transit CIPHERTEXT (`vault:v1:…`) as ASCII bytes — the exact bytes to
    `put_kv` at the luks-kek path, so the KBS `read_exact` + `vault:`-prefix
    detection round-trips. §20: the plaintext is sent once and never logged.
    """
    label = "vault-transit-encrypt"
    body = {"plaintext": base64.b64encode(plaintext).decode("ascii")}
    status, raw = _round_trip("POST", f"/v1/transit/encrypt/{name}", label=label, json_body=body)
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    ct = ((parsed or {}).get("data") or {}).get("ciphertext") if isinstance(parsed, dict) else None
    if not isinstance(ct, str) or not ct.startswith("vault:"):
        raise EffectError(f"{label}: response missing data.ciphertext")
    return ct.encode("ascii")


def _transit_key_missing(status: int, body: bytes | None) -> bool:
    """True iff a Transit response means "this key does not exist".

    Vault does NOT 404 a missing Transit key — it answers **400** with an
    error body, and the wording DIFFERS per endpoint:

      * ``…/config``          → ``no existing key named <name> could be found``
      * ``DELETE …/keys/…``   → ``could not delete key; not found``
      * ``…/datakey/wrapped`` → ``encryption key not found``

    Note the first phrasing does NOT contain the substring ``not found``, so
    matching that alone silently fails closed on the config call.

    A **404 is NEVER accepted** here. On these routes it does not mean "no
    such key" — it means the ROUTE does not exist: the transit engine is
    unmounted or remounted elsewhere, the Vault namespace or ``VAULT_ADDR``
    is wrong, or a proxy rewrote the path. Vault answers
    ``no handler for route "transit/keys/…". route entry not found.`` and
    the key is fully INTACT. Treating that as "already erased" would tombstone
    every VM decommissioned during the misconfiguration as crypto-erased with
    its KEK completely unwrappable-by-anyone-but-intact — a false data-death
    claim, the exact inversion this path exists to prevent. Note that body
    also CONTAINS ``not found``, so it is excluded explicitly in case a proxy
    ever normalises the status to 400.
    """
    if status != 400:
        return False
    text = (body or b"").lower()
    if b"no handler for route" in text:
        return False  # wrong route ⇒ the key is intact, NOT erased
    return b"not found" in text or b"no existing key" in text


def transit_key_delete(name: str) -> None:
    """§24 golden crypto-erase — DESTROY the per-VM Transit key `name`.

    Once the Transit key is gone, the WRAPPED per-VM KEK (`vault:v1:…`
    staged at the luks-kek path by `_provision_golden_overlay_kek`) can
    NEVER be unwrapped again ⇒ the golden overlay upper's in-guest LUKS
    master key is cryptographically unrecoverable ⇒ TRUE crypto-erase.
    This is the golden counterpart of the KBS admin `crypto-erase` a
    LEGACY VM uses (a golden KEK has NO KBS record).

    Vault refuses to delete a Transit key unless `deletion_allowed=true`
    is set in its config, so this first POSTs that config then DELETEs the
    key.

    Idempotent: a key that is already gone ⇒ SUCCESS — the erase goal is
    already met. This matters for MORE than a re-run: the caller deletes the
    wrapped-KEK KV blob AFTER this, so if that second step fails (a Vault
    blip) the next tick re-enters here with the key already destroyed. Vault
    signals that with a **400** (not a 404) whose wording differs per
    endpoint — see `_transit_key_missing`. Treating it as failure would wedge
    the decommission forever with the data already dead.

    Fail-closed: any OTHER status (403 permission-denied, 5xx) or a transport
    failure raises so the caller keeps the decommission retryable and the VM
    is NEVER marked Destroyed as if erased. `name` is derived STRICTLY from
    the vm_id by the caller, so a sibling / other-tenant key can never be hit.
    """
    label = "vault-transit-key-delete"
    # 1. Allow deletion (Vault refuses the DELETE otherwise). A 404 here
    #    means the key never existed / was already deleted ⇒ idempotent.
    status, raw = _round_trip(
        "POST",
        f"/v1/transit/keys/{name}/config",
        label=label,
        json_body={"deletion_allowed": True},
    )
    if _transit_key_missing(status, raw):
        return  # already gone ⇒ idempotent success
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status} (config)")
    # 2. Delete the key material — irreversible.
    status, raw = _round_trip("DELETE", f"/v1/transit/keys/{name}", label=label)
    if status in (200, 204) or _transit_key_missing(status, raw):
        return  # deleted, or already gone ⇒ idempotent success
    raise EffectError(f"{label}: vault returned HTTP {status} (delete)")


def transit_key_gone(name: str) -> bool:
    """§24 crypto-erase VERIFY — probe whether the per-VM Transit key
    `name` is DESTROYED. This is the STRONGEST cryptographic-death signal:
    once the key is gone the wrapped datakey (`vault:v1:…`) can NEVER be
    unwrapped again, so the golden overlay's in-guest LUKS master key is
    irrecoverable ⇒ TRUE crypto-erase.

    Probes via `transit/datakey/wrapped/<name>` — a STATELESS derive that
    vali is permitted to make (`transit/datakey/wrapped/kek-*`) and that
    neither rotates nor mutates the key. Returns:
      * True  — the key is gone: Vault answers 404, or 400 with an
        "encryption key not found" body ⇒ irrecoverable, erase proven.
      * False — a clean 2xx: the key still EXISTS and could still unwrap
        the tenant KEK ⇒ NOT erased.
    Fail-closed: any OTHER status (403 permission, 5xx) or a 400 whose
    body is NOT the not-found error raises so a verify can never be
    spoofed by a denied / ambiguous probe.
    """
    label = "vault-transit-key-probe"
    status, raw = _round_trip(
        "POST", f"/v1/transit/datakey/wrapped/{name}", label=label, json_body={}
    )
    if _transit_key_missing(status, raw):
        return True
    if 200 <= status < 300:
        return False
    raise EffectError(f"{label}: vault returned HTTP {status}")


def delete_kv_all_versions(mount: str, secret_path: str) -> None:
    """§24 golden crypto-erase — permanently delete ALL versions +
    metadata of the KV v2 secret at `<mount>/metadata/<path>`.

    A DELETE on the KV-v2 METADATA endpoint destroys the whole secret
    (every version + its metadata), not merely soft-deleting the latest
    version — so the wrapped-KEK ciphertext is gone. (Defence-in-depth:
    the ciphertext is already inert once `transit_key_delete` destroyed
    the key that could unwrap it.)

    Idempotent: a 404 (already gone) ⇒ SUCCESS. Fail-closed: any other
    non-2xx raises so a genuine failure keeps the decommission retryable.
    """
    label = f"vault-kv-delete:{mount}"
    status, _ = _round_trip("DELETE", f"/v1/{mount}/metadata/{secret_path}", label=label)
    if status in (200, 204, 404):
        return
    raise EffectError(f"{label}: vault returned HTTP {status}")


def transit_datakey_wrapped(name: str) -> bytes:
    """KEK-HSM Phase 4 — generate a fresh KEK ENTIRELY inside Vault Transit
    and return ONLY the wrapped ciphertext, never the plaintext.

    POST `transit/datakey/wrapped/<name>` makes Vault's Transit engine
    generate 256 bits of key material and return JUST the `vault:v1:…`
    ciphertext (the `/wrapped/` variant, unlike `/plaintext/`, withholds the
    raw key). So vali NEVER holds a plaintext KEK — not even transiently at
    generation: a vali/node RCE that intercepts this call gets ciphertext
    only. The plaintext exists ONLY where it must (the attested SNP KBS on
    release, and — for a NEW disk — the transient bake `luksFormat`), each
    obtaining it via a per-VM-scoped `transit/decrypt`. Returns the exact
    `vault:v1:…` bytes to `put_kv` at the luks-kek path (same round-trip as
    `transit_encrypt`). The policy grants `transit/datakey/wrapped/kek-*`
    (NOT `/plaintext/`), so the never-plaintext property is ENFORCED by
    Vault, not merely by vali's code path.
    """
    label = "vault-transit-datakey"
    status, raw = _round_trip(
        "POST", f"/v1/transit/datakey/wrapped/{name}", label=label, json_body={}
    )
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    data = (parsed or {}).get("data") if isinstance(parsed, dict) else None
    ct = data.get("ciphertext") if isinstance(data, dict) else None
    # Defence-in-depth: the `/wrapped/` endpoint MUST NOT return a plaintext;
    # if a misconfig ever surfaced one, refuse rather than let vali touch it.
    if isinstance(data, dict) and data.get("plaintext"):
        raise EffectError(f"{label}: refused — datakey response carried a plaintext")
    if not isinstance(ct, str) or not ct.startswith("vault:"):
        raise EffectError(f"{label}: response missing data.ciphertext")
    return ct.encode("ascii")


def transit_read_key(name: str) -> dict[str, Any]:
    """GET `transit/keys/<name>`: the key's PUBLIC metadata — its type, its
    `exportable` / `allow_plaintext_backup` flags and, for an asymmetric
    key, each version's public key. Never key material: Transit only hands
    a private key out through `transit/export`, which no vali policy
    grants. Returns the response's `data` object."""
    label = "vault-transit-read-key"
    status, raw = _round_trip("GET", f"/v1/transit/keys/{name}", label=label)
    if status == 404 or _transit_key_missing(status, raw):
        raise VaultNotFound(f"{label}: no transit key {name!r}")
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    data = (parsed or {}).get("data") if isinstance(parsed, dict) else None
    if not isinstance(data, dict):
        raise EffectError(f"{label}: response missing data")
    return data


def transit_sign(name: str, message: bytes, *, key_version: int) -> bytes:
    """Sign `message` with version `key_version` of the Transit key `name`
    and return the raw signature bytes. For an `ed25519` key Transit signs
    the message itself (pure Ed25519, no prehash). The response must name
    the version asked for: a signature by any other version is refused."""
    label = "vault-transit-sign"
    body = {
        "input": base64.b64encode(message).decode("ascii"),
        "key_version": key_version,
    }
    status, raw = _round_trip("POST", f"/v1/transit/sign/{name}", label=label, json_body=body)
    if not 200 <= status < 300:
        raise EffectError(f"{label}: vault returned HTTP {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    data = (parsed or {}).get("data") if isinstance(parsed, dict) else None
    sig = data.get("signature") if isinstance(data, dict) else None
    prefix = f"vault:v{key_version}:"
    if not isinstance(sig, str) or not sig.startswith(prefix):
        raise EffectError(f"{label}: response is not a v{key_version} signature")
    try:
        return base64.b64decode(sig[len(prefix) :], validate=True)
    except (ValueError, TypeError) as exc:
        raise EffectError(f"{label}: signature is not base64") from exc
