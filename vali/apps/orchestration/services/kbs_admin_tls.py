"""One decision point for how vali dials the KBS **admin** listener.

## Why this module exists

The lifecycle admin API (`register-vm`, `activate`, `seed-boot-counter`,
`allowlist/reload`, `reset-volume-stamp-suppression`) mutates the state
that decides *which host may unlock a tenant's encrypted disk*, and it
carries no per-request credential — mTLS at the listener IS its
authentication (`binaries/kbs-server/src/admin_tls.rs`). vali reaches
that API from FIVE places written at different times:

- `kbs_admin.register_vm_active_with_vm_id` (Rust subprocess),
- `services.allowlist_pin._reload_kbs_allowlist` (stdlib urllib),
- `services.kbs_evidence.fetch_evidence` (stdlib urllib),
- `effects._kbs_post` / `effects.seed_boot_counter` (stdlib urllib),
- `apps.synthetic.checks.check_kbs` (stdlib urllib).

If each of those decided independently whether to present a client
certificate, the gate would be exactly as strong as the sloppiest one,
and a sixth caller added next month would default to unauthenticated.
So the decision lives here, once, and every caller asks this module.

## The decision (mirror of both halves of the gate)

`AdminClientMode::decide` in `binaries/kbs-admin-client/src/mtls.rs` and
`AdminListenerMode::decide` in `kbs-server/src/admin_tls.rs` are the
other two copies of this table; all three must agree or the cutover
sequence has a hole:

| `VALI_KBS_ADMIN_URL` | material | outcome |
|---|---|---|
| `https://` | complete + loadable | mTLS: pinned CA + client identity |
| `https://` | absent / partial / broken | `EffectUnavailable` — REFUSE to dial |
| `http://`  | absent | plaintext — the pre-cutover state |
| `http://`  | present | plaintext + a loud WARNING, after VALIDATING the material |

The `https` + missing-material refusal is the one that matters: falling
back to "TLS with the system trust store and no client cert" would look
encrypted, would authenticate nothing, and would be invisible in a URL.

The `http` + present arm is not sloppiness, it is the rollout's
verification step. Staging the certs onto the vali pods must be
possible BEFORE the KBS starts demanding them (the KBS enforces mTLS the
moment its material is mounted — `require_mtls=false` only covers ABSENT
material), otherwise the only available cutover is a simultaneous flip of
two workloads with no way to check the first half. So this arm loads and
validates the material anyway and logs whether it is usable: that log
line is the runbook's gate between "certs staged" and "flip the URL".

## §20 discipline

The private key is read by OpenSSL inside `load_cert_chain` and never
enters a Python string. No exception raised here interpolates a path or
key bytes — only the SETTING NAME, so an operator can find the knob
without the log naming the filesystem layout.
"""

from __future__ import annotations

import logging
import os
import ssl
from dataclasses import dataclass

from django.conf import settings

log = logging.getLogger("apps.orchestration.kbs_admin_tls")

# Settings that carry the three PEM paths. Named here so error messages
# can point at the knob without quoting its value.
_CERT_SETTING = "VALI_KBS_ADMIN_CLIENT_CERT"
_KEY_SETTING = "VALI_KBS_ADMIN_CLIENT_KEY"
_CA_SETTING = "VALI_KBS_ADMIN_CACERT"


class KbsAdminTlsMisconfigured(Exception):
    """The admin transport cannot be built as configured.

    Callers translate this to `EffectUnavailable` (transient/operator
    fault, retry after a fix) rather than `EffectError`; it is raised
    BEFORE any connection is attempted, so nothing has been sent.
    """


@dataclass(frozen=True)
class KbsAdminTransport:
    """How to dial the admin listener, decided once."""

    #: Base URL, trailing slash stripped.
    base_url: str
    #: `ssl.SSLContext` for the https/mTLS path; `None` for plaintext.
    #: Passing `None` to `urllib.request.urlopen(context=…)` is exactly
    #: the pre-existing plaintext behaviour.
    context: ssl.SSLContext | None

    @property
    def is_mtls(self) -> bool:
        return self.context is not None

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"


def _setting(name: str) -> str:
    return str(getattr(settings, name, "") or "").strip()


def _build_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    """Pinned-CA client context with our identity loaded.

    `create_default_context(cafile=…)` deliberately does NOT also load
    the system trust store — CPython only calls `load_default_certs()`
    when no CA file/path/data is supplied. So the KBS admin cert must
    chain to the operator's CA and nothing else: a public CA cannot
    satisfy this hop, which is the whole point of pinning an internal
    service (see #776 for what coupling an internal hop to public ACME
    cost us).
    """
    for name, path in ((_CERT_SETTING, cert), (_KEY_SETTING, key), (_CA_SETTING, ca)):
        if not os.path.isfile(path):
            raise KbsAdminTlsMisconfigured(
                f"kbs-admin-tls: {name} does not point at a readable file"
            )
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    except (ssl.SSLError, OSError) as exc:
        raise KbsAdminTlsMisconfigured(
            f"kbs-admin-tls: {_CA_SETTING} is not a loadable PEM CA bundle"
        ) from exc
    # Explicit rather than inherited: `create_default_context` already
    # sets both, and a future CPython default change must not silently
    # relax the hop that authenticates lifecycle mutations.
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # The KBS admin listener is TLS 1.3 ONLY (pinned at the rustls
    # config level). Matching it here turns a version mismatch into a
    # clear local failure instead of a handshake alert.
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    try:
        context.load_cert_chain(certfile=cert, keyfile=key)
    except (ssl.SSLError, OSError) as exc:
        raise KbsAdminTlsMisconfigured(
            f"kbs-admin-tls: {_CERT_SETTING}/{_KEY_SETTING} did not load as a "
            "client identity (mismatched pair, or an encrypted key)"
        ) from exc
    return context


def admin_transport(url: str | None = None) -> KbsAdminTransport:
    """Resolve `VALI_KBS_ADMIN_URL` (or `url`) + the TLS material into a
    single decided transport. Raises [`KbsAdminTlsMisconfigured`] rather
    than returning a downgraded one.
    """
    base = (url if url is not None else _setting("VALI_KBS_ADMIN_URL")).strip()
    if not base:
        raise KbsAdminTlsMisconfigured("VALI_KBS_ADMIN_URL is not configured")
    base = base.rstrip("/")

    cert = _setting(_CERT_SETTING)
    key = _setting(_KEY_SETTING)
    ca = _setting(_CA_SETTING)
    complete = bool(cert and key and ca)
    any_material = bool(cert or key or ca)

    if base.startswith("https://"):
        if not complete:
            # NEVER degrade to system roots + anonymous client: that is
            # an unauthenticated admin call wearing an https URL.
            raise KbsAdminTlsMisconfigured(
                f"kbs-admin-tls: VALI_KBS_ADMIN_URL is https but "
                f"{_CERT_SETTING}/{_KEY_SETTING}/{_CA_SETTING} are not all set — "
                "refusing to dial the lifecycle admin API without a pinned "
                "server CA and a client identity"
            )
        return KbsAdminTransport(base_url=base, context=_build_context(cert, key, ca))

    if not base.startswith("http://"):
        raise KbsAdminTlsMisconfigured(
            "kbs-admin-tls: VALI_KBS_ADMIN_URL must start with http:// or https://"
        )

    if any_material:
        # Pre-cutover staging state. Validate what was staged so the
        # operator learns NOW — not during the cutover — whether the
        # material is usable, then continue in plaintext.
        if not complete:
            log.warning(
                "kbs-admin-tls: PARTIAL client material staged (%s/%s/%s) while "
                "VALI_KBS_ADMIN_URL is plaintext — the admin hop is "
                "UNAUTHENTICATED and flipping the URL to https would fail closed",
                _CERT_SETTING if cert else "-",
                _KEY_SETTING if key else "-",
                _CA_SETTING if ca else "-",
            )
        else:
            try:
                _build_context(cert, key, ca)
            except KbsAdminTlsMisconfigured as exc:
                log.warning(
                    "kbs-admin-tls: staged client material is NOT usable (%s) and "
                    "VALI_KBS_ADMIN_URL is plaintext — the admin hop is "
                    "UNAUTHENTICATED; fix this before flipping the URL",
                    exc,
                )
            else:
                log.warning(
                    "kbs-admin-tls: client material staged and VALID, but "
                    "VALI_KBS_ADMIN_URL is still plaintext — the admin hop is "
                    "UNAUTHENTICATED until the URL is flipped to https"
                )
    return KbsAdminTransport(base_url=base, context=None)


def admin_ssl_context(url: str | None = None) -> ssl.SSLContext | None:
    """Just the context — for callers that already hold the URL."""
    return admin_transport(url).context


def admin_client_tls_argv() -> list[str]:
    """The `--client-cert/--client-key/--ca-cert` flags for the
    `hippius-kbs-admin-client` subprocess, or `[]` on the plaintext path.

    Deliberately empty for an `http://` URL even when material is
    configured: the Rust client REFUSES that combination outright
    (`DecideError::PlaintextWithMaterial`), which is right for a
    hand-run CLI but would break every launch during the staging step.
    vali owns the staging state, so vali is the layer that resolves it —
    and it resolves it by not claiming an authentication it is not
    getting. `admin_transport` has already logged the warning.
    """
    transport = admin_transport()
    if not transport.is_mtls:
        return []
    return [
        "--client-cert",
        _setting(_CERT_SETTING),
        "--client-key",
        _setting(_KEY_SETTING),
        "--ca-cert",
        _setting(_CA_SETTING),
    ]
