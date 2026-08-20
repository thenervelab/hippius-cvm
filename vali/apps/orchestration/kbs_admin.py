"""Vali → KBS admin endpoint client (ARCHITECTURE.md §24 lifecycle
pre-registration).

Wraps the `hippius-kbs-admin-client` Rust subprocess: takes a
byte-exact COSE_Sign1 OrderTicket, POSTs it to the KBS admin endpoint
on the cluster-internal `kbs-server-admin.kbs.svc:8001` Service, and
returns a structured outcome.

## Why a subprocess

vali has no in-process Ed25519 signer for L1 (tickets are minted
externally by L1 / `order-ticket-mint` and arrive as opaque blobs
from upstream). The KBS admin endpoint demands a signed ticket as the
request body — the natural client is a small Rust binary that links
the same `kbs-core::ticket::verify_order_ticket` shape on the
producer side, so the same crypto stack signs and verifies. Subprocess
isolation also bounds vali's blast radius if the client ever has a
parser bug — vali never decodes COSE itself.

## Idempotency

The KBS keys admin idempotency by the ticket's `ticket_id`. A retry
with the SAME ticket bytes returns 200 (cached). A retry with the
SAME `ticket_id` but DIFFERENT body returns 409 (state drift —
operator must reconcile). The caller does not need to manage an
idempotency key — the verified ticket IS the key.

## §20 logging discipline

The COSE ticket bytes are NEVER logged here. The subprocess emits a
single JSON line on stdout (`{outcome, ticket_id, vm_id, …}`); we
parse it back into typed results, dropping the bytes.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass

from django.conf import settings

from .effects import EffectError, EffectUnavailable, _required_setting

log = logging.getLogger("orchestration.kbs_admin")


# Exit codes mirror `binaries/kbs-admin-client/src/main.rs::CliError::exit_code`.
_EXIT_OK = 0
_EXIT_CONFLICT = 2
_EXIT_TERMINAL = 3
_EXIT_MISCONFIGURED = 64
_EXIT_NETWORK = 65
_EXIT_SERVER_5XX = 66
_EXIT_DECODE = 67


class KbsAdminConflict(EffectError):
    """KBS returned 409 — the vm-state already differs from what this
    ticket would write, OR the same ticket_id was previously applied
    with different body bytes. Operator must reconcile.
    """


class KbsAdminTerminal(EffectError):
    """KBS returned 400/401/403/413/415/429 — terminal client error.
    Retry will NOT help.
    """


@dataclass(frozen=True)
class KbsAdminRegisterOk:
    """Echoed fields from the KBS-verified ticket. The KBS derived
    these — they should match what vali had locally, but we trust the
    KBS's view as authoritative."""

    ticket_id: str
    vm_id: str
    vm_generation: int
    cached: bool


def register_vm_active(*, cose_ticket: bytes) -> KbsAdminRegisterOk:
    """Pre-register `VmState::Active` with the KBS before dispatching
    the launch.

    Phase A is one-shot — no retries inside this helper. The caller
    (`vali_dispatch_launch`) treats network/5xx failures as
    `EffectUnavailable` and surfaces them to the operator. The KBS
    admin path is single-replica + in-memory; the operator's natural
    response to a transient is to re-invoke the dispatch command (the
    KBS will idempotently cache the prior register).

    Raises:
        EffectUnavailable: misconfiguration (no admin URL, missing
            binary), or transient (network, 5xx).
        KbsAdminConflict: terminal 409 — operator must reconcile.
        KbsAdminTerminal: terminal 4xx other than 409.
        EffectError: any other unexpected failure.
    """
    # Reserved overload: the KBS URL is keyed by `vm_id`, which must be
    # extracted from the verified ticket on the caller side (the
    # `OrderTicketIntake` row the validator populated). All callers use
    # `register_vm_active_with_vm_id`; this signature is kept for a
    # future flow that decodes the vm_id here. No preamble — it always
    # raises, so config/validation is the concrete overload's job.
    raise NotImplementedError(
        "Use register_vm_active_with_vm_id; this overload reserved for future."
    )


def register_vm_active_with_vm_id(
    *, vm_id: str, cose_ticket: bytes
) -> KbsAdminRegisterOk:
    """Same as `register_vm_active` but the caller passes the URL's
    `vm_id` path component explicitly (already extracted from the
    parsed ticket on the caller side). The KBS will reject 400 with
    `url-vm-id-mismatch` if this does not equal the verified
    ticket's `vm_id`.
    """
    from apps.orchestration.services.kbs_admin_tls import (
        KbsAdminTlsMisconfigured,
        admin_client_tls_argv,
    )

    kbs_url = _required_setting("VALI_KBS_ADMIN_URL")
    # The `--client-cert/--client-key/--ca-cert` triple, or `[]` on the
    # pre-cutover plaintext hop. Resolved through the SAME decision
    # `_reload_kbs_allowlist` and `effects._kbs_post` use, so a launch
    # cannot end up authenticated on one admin call and anonymous on the
    # next. A misconfiguration is fail-closed here: the subprocess is
    # never spawned, the dispatch fails `EffectUnavailable`, and no
    # lifecycle mutation crosses an unauthenticated hop.
    try:
        tls_argv = admin_client_tls_argv()
    except KbsAdminTlsMisconfigured as exc:
        raise EffectUnavailable(str(exc)) from exc
    client_bin = getattr(settings, "VALI_KBS_ADMIN_CLIENT_BIN", "") or ""
    if not client_bin:
        raise EffectUnavailable("VALI_KBS_ADMIN_CLIENT_BIN is not configured")
    if not os.path.exists(client_bin):
        raise EffectUnavailable(
            f"VALI_KBS_ADMIN_CLIENT_BIN points at non-existent path: {client_bin}"
        )
    timeout = int(getattr(settings, "VALI_KBS_ADMIN_TIMEOUT_SECS", 5) or 5)
    if not cose_ticket:
        raise EffectError("kbs_admin: cose_ticket is empty")
    if not vm_id:
        raise EffectError("kbs_admin: vm_id is empty")

    # Stage the ticket bytes to a temp file the subprocess reads.
    # The COSE blob is non-secret (the L1 signature anchors it) but
    # we still use a fd that's wiped on close — defence-in-depth.
    with tempfile.NamedTemporaryFile(
        prefix="kbs-admin-ticket-",
        suffix=".cose",
        delete=True,
    ) as fh:
        fh.write(cose_ticket)
        fh.flush()
        ticket_path = fh.name

        argv = [
            client_bin,
            "register-vm",
            "--kbs-url",
            kbs_url,
            "--vm-id",
            vm_id,
            "--ticket",
            ticket_path,
            "--timeout-secs",
            str(timeout),
            *tls_argv,
        ]
        log.info(
            "kbs-admin: register-vm vm_id=%s kbs_url=%s transport=%s",
            vm_id,
            kbs_url,
            "mtls" if tls_argv else "plaintext",
        )
        try:
            result = subprocess.run(  # noqa: S603 — argv list, no shell.
                argv,
                capture_output=True,
                timeout=timeout + 2,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise EffectUnavailable(
                f"kbs-admin-client timeout after {timeout}s"
            ) from exc
        except OSError as exc:
            raise EffectUnavailable(f"kbs-admin-client spawn failed: {exc}") from exc

    rc = result.returncode
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    if rc == _EXIT_OK:
        return _parse_ok(result.stdout)
    if rc == _EXIT_CONFLICT:
        raise KbsAdminConflict(f"kbs-admin: 409 conflict — {stderr}")
    if rc == _EXIT_TERMINAL:
        raise KbsAdminTerminal(f"kbs-admin: terminal 4xx — {stderr}")
    if rc in (_EXIT_NETWORK, _EXIT_SERVER_5XX):
        raise EffectUnavailable(f"kbs-admin: transient (rc={rc}) — {stderr}")
    if rc == _EXIT_MISCONFIGURED:
        raise EffectUnavailable(f"kbs-admin: misconfigured — {stderr}")
    if rc == _EXIT_DECODE:
        raise EffectError(f"kbs-admin: response decode failure — {stderr}")
    raise EffectError(f"kbs-admin: unexpected exit {rc} — {stderr}")


def _parse_ok(stdout: bytes) -> KbsAdminRegisterOk:
    """Parse the single JSON line `kbs-admin-client` emits on success."""
    line = stdout.decode("utf-8", errors="replace").strip()
    if not line:
        raise EffectError("kbs-admin: success but no stdout line")
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise EffectError(
            f"kbs-admin: success but stdout is not JSON: {line!r}"
        ) from exc
    try:
        return KbsAdminRegisterOk(
            ticket_id=str(payload["ticket_id"]),
            vm_id=str(payload["vm_id"]),
            vm_generation=int(payload["vm_generation"]),
            cached=bool(payload["cached"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EffectError(f"kbs-admin: success stdout missing fields: {payload!r}") from exc
