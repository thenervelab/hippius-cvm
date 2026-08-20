"""Keyless cosign verification of a blackbox host-attestor UKI release
(blackbox host-attestor chantier PR-9, security must-have #4).

The admin-release endpoint (`POST /v1/admin/host-attestor/release`) is a
FLEET-WIDE trust root: a measurement it admits becomes the image every
miner boots as its host attestor. So a release is admitted ONLY after a
keyless cosign verification of the CI-signed UKI blob, with the signing
identity (SAN) + OIDC issuer PINNED — an unsigned or identity-unpinned
release is refused fail-closed.

vali has no existing in-process cosign verifier, so this shells out to the
`cosign verify-blob` CLI (the same tool + keyless posture PR-6's
`blackbox-uki-build.yml` uses to `sign-blob` the artifact: GitHub OIDC →
Fulcio cert + Rekor transparency log). Keyless verification enforces Rekor
inclusion by default — this wrapper NEVER passes `--insecure-ignore-tlog`,
so a signature absent from the transparency log is rejected.

Fail-closed rules:
- No `--certificate-identity` pin configured ⇒ reject (never verify an
  unpinned identity — any Fulcio-issued cert would otherwise pass).
- No `--certificate-oidc-issuer` pin configured ⇒ reject.
- Any non-zero `cosign` exit ⇒ `CosignVerifyFailed`.
- Missing binary / transport ⇒ `CosignUnavailable`.

§20: the cert + signature are materialized into a per-call tmpfs workdir
(removed on exit); the artifact bytes are written to the same workdir. None
of it is logged.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass

from django.conf import settings

log = logging.getLogger("apps.telemetry.cosign")

DEFAULT_COSIGN_TIMEOUT_S = 60.0


class CosignError(Exception):
    """Base class for cosign-verify failures."""


class CosignUnavailable(CosignError):
    """cosign could not run (binary missing, transport, timeout). 503."""


class CosignVerifyFailed(CosignError):
    """cosign ran and REJECTED the release, or the inputs were malformed.

    Carries a stable `category` the view surfaces without leaking cert /
    signature bytes.
    """

    def __init__(self, message: str, category: str = "verify-failed") -> None:
        super().__init__(message)
        self.message = message
        self.category = category


@dataclass(frozen=True)
class CosignPins:
    """The pinned keyless-verification identity. Both fields fail-closed
    when empty — an unpinned identity/issuer is refused."""

    identity: str
    issuer: str


def resolve_pins() -> CosignPins:
    """Resolve the pinned cosign identity (SAN) + OIDC issuer from
    settings. Empty either ⇒ `CosignVerifyFailed` (the release path is
    unusable until the operator pins the CI workflow identity)."""
    identity = str(
        getattr(settings, "VALI_HOST_ATTESTOR_COSIGN_IDENTITY", "") or ""
    ).strip()
    issuer = str(
        getattr(settings, "VALI_HOST_ATTESTOR_COSIGN_ISSUER", "") or ""
    ).strip()
    if not identity:
        raise CosignVerifyFailed(
            "VALI_HOST_ATTESTOR_COSIGN_IDENTITY is not pinned "
            "(refusing to verify an unpinned signing identity)",
            category="identity-unpinned",
        )
    if not issuer:
        raise CosignVerifyFailed(
            "VALI_HOST_ATTESTOR_COSIGN_ISSUER is not pinned "
            "(refusing to verify an unpinned OIDC issuer)",
            category="issuer-unpinned",
        )
    return CosignPins(identity=identity, issuer=issuer)


def _cosign_bin() -> str:
    return str(getattr(settings, "VALI_COSIGN_BIN", "") or "").strip() or "cosign"


def verify_blob(
    *,
    artifact: bytes,
    signature_b64: str,
    certificate_pem: str,
) -> CosignPins:
    """Keyless-verify `artifact` against `signature_b64` + `certificate_pem`
    with the pinned identity + issuer. Returns the pins it verified against
    (the caller records them as release provenance).

    Raises `CosignVerifyFailed` on rejection / malformed input,
    `CosignUnavailable` when cosign cannot run.
    """
    pins = resolve_pins()

    if not artifact:
        raise CosignVerifyFailed("empty release artifact", category="wire")
    sig = (signature_b64 or "").strip()
    cert = (certificate_pem or "").strip()
    if not sig:
        raise CosignVerifyFailed("empty cosign signature", category="wire")
    if not cert:
        raise CosignVerifyFailed("empty cosign certificate", category="wire")
    # The signature file cosign emits is base64 — validate it decodes so a
    # malformed value fails as `wire`, not an opaque cosign error.
    try:
        base64.b64decode(sig, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CosignVerifyFailed(
            "cosign signature is not valid base64", category="wire"
        ) from exc
    if "-----BEGIN CERTIFICATE-----" not in cert:
        raise CosignVerifyFailed(
            "cosign certificate is not PEM", category="wire"
        )

    cosign_bin = _cosign_bin()
    timeout_s = float(
        getattr(settings, "VALI_COSIGN_TIMEOUT_S", DEFAULT_COSIGN_TIMEOUT_S)
    )

    with tempfile.TemporaryDirectory(prefix="hippius-cosign-") as workdir:
        blob_path = os.path.join(workdir, "artifact.bin")
        sig_path = os.path.join(workdir, "artifact.sig")
        cert_path = os.path.join(workdir, "artifact.cert")
        with open(blob_path, "wb") as fh:
            fh.write(artifact)
        with open(sig_path, "w", encoding="utf-8") as fh:
            fh.write(sig)
        with open(cert_path, "w", encoding="utf-8") as fh:
            fh.write(cert)

        argv = [
            cosign_bin,
            "verify-blob",
            "--certificate",
            cert_path,
            "--signature",
            sig_path,
            # Pin the keyless signing identity — WITHOUT these two a cert
            # from ANY Fulcio-issued OIDC identity would satisfy the check.
            "--certificate-identity",
            pins.identity,
            "--certificate-oidc-issuer",
            pins.issuer,
            blob_path,
        ]
        # Rekor inclusion is enforced by default (we never pass
        # --insecure-ignore-tlog); cosign fetches its trust roots via the
        # embedded TUF client over vali's egress.
        env = {**os.environ, "COSIGN_EXPERIMENTAL": "0"}
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, no shell.
                argv,
                capture_output=True,
                timeout=timeout_s,
                check=False,
                env=env,
            )
        except FileNotFoundError as exc:
            raise CosignUnavailable("cosign binary not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise CosignUnavailable(
                f"cosign verify-blob timed out after {timeout_s:.0f}s"
            ) from exc

        if proc.returncode != 0:
            # cosign writes the reason to stderr; surface a truncated,
            # cert/sig-free tail for triage (verification-rejected vs
            # transport). A non-verification transport failure (e.g. Rekor
            # unreachable) also lands here — treat it as fail-closed reject.
            stderr_tail = proc.stderr.decode("utf-8", errors="replace").strip()[:400]
            log.warning(
                "cosign verify-blob rejected the release (rc=%s): %s",
                proc.returncode,
                stderr_tail,
            )
            raise CosignVerifyFailed(
                f"cosign verify-blob failed (rc={proc.returncode})",
                category="cosign-rejected",
            )

    log.info(
        "cosign verify-blob OK — identity=%s issuer=%s",
        pins.identity,
        pins.issuer,
    )
    return pins
