"""Fetch a VM's KBS-signed attestation evidence (the read side of #280).

`GET {VALI_KBS_ADMIN_URL}/v1/admin/vm/<vm_id>/evidence` returns the latest
`SignedEvidenceBundle` (measurement, raw SNP report, VCEK chain, boot
counter, KBS L0 signature) — already-public attestation data, KBS-signed
so a tenant verifies it offline. The KBS admin endpoint is the same
in-cluster service `kbs_admin` registers through, so the transport
(plaintext, or mTLS with a pinned CA + vali's client identity) is
resolved by `services.kbs_admin_tls` rather than decided here — one
decision point for all five admin callers.

§20: no secrets here — the bundle carries only public attestation bytes.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from apps.orchestration.effects import EffectError, EffectUnavailable

_DEFAULT_TIMEOUT_S = 10.0


def fetch_evidence(vm_id: str) -> dict[str, Any] | None:
    """Return the VM's latest KBS attestation evidence, or `None` if the
    KBS returned no bundle for it.

    `None` does NOT mean "the VM never attested". The KBS records a bundle
    only when its §280 evidence sink is configured
    (`storage.evidence_dir`) — otherwise `NullEvidenceSink` discards it —
    and the archive does not survive a KBS restart. So absence is
    genuinely AMBIGUOUS between "never attested" and "attested but
    unrecorded", and callers must not render it as a negative attestation
    verdict. The VM's live attestations are the restart-proof source
    (see `apps.lifecycle.attestation`).

    Raises [`EffectUnavailable`] if the KBS admin endpoint is unreachable
    / unconfigured, [`EffectError`] on a non-200/404 status or a malformed
    body. `vm_id` is path-segment-safe (charset-validated by the caller +
    the KBS re-checks), so it is interpolated directly.
    """
    from apps.orchestration.services.kbs_admin_tls import (
        KbsAdminTlsMisconfigured,
        admin_transport,
    )

    try:
        transport = admin_transport()
    except KbsAdminTlsMisconfigured as exc:
        raise EffectUnavailable(str(exc)) from exc
    url = transport.url(f"/v1/admin/vm/{vm_id}/evidence")

    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(  # noqa: S310 — in-cluster, NetworkPolicy-gated + mTLS
            req, timeout=_DEFAULT_TIMEOUT_S, context=transport.context
        ) as resp:
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise EffectError(f"kbs-evidence: HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise EffectUnavailable("kbs-evidence: KBS admin unreachable") from exc

    if status != 200:
        raise EffectError(f"kbs-evidence: unexpected status {status}")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError("kbs-evidence: non-JSON response") from exc
    if not isinstance(parsed, dict):
        raise EffectError("kbs-evidence: response is not a JSON object")
    return parsed
