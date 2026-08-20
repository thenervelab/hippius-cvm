"""Direct unit tests for the fleet-wide cosign trust root
(`apps.telemetry.cosign_verify`, blackbox host-attestor PR-9).

`verify_blob` is the ONLY gate between an operator-supplied UKI release and
a measurement every miner boots, so its fail-closed contract is exercised
directly here (the release-endpoint tests mock it at the boundary): the
identity/issuer pins fail closed when unset, the argv carries both keyless
pins and NEVER `--insecure-ignore-tlog`, no `shell=True`, and a missing /
timed-out / rejecting cosign maps to the right typed error.
"""

from __future__ import annotations

import base64
import subprocess
from typing import Any

import pytest
from django.conf import settings

from apps.telemetry import cosign_verify

_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
_SIG_B64 = base64.b64encode(b"a-detached-signature").decode()
_IDENTITY = "https://github.com/thenervelab/hippius-compute/.github/workflows/blackbox-uki-build.yml@refs/heads/main"
_ISSUER = "https://token.actions.githubusercontent.com"


def _pin(monkeypatch: pytest.MonkeyPatch, *, identity: str, issuer: str) -> None:
    monkeypatch.setattr(settings, "VALI_HOST_ATTESTOR_COSIGN_IDENTITY", identity)
    monkeypatch.setattr(settings, "VALI_HOST_ATTESTOR_COSIGN_ISSUER", issuer)


class _FakeCompleted:
    def __init__(self, returncode: int, stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = b""
        self.stderr = stderr


# ─── resolve_pins fail-closed ────────────────────────────────────────


def test_resolve_pins_rejects_unset_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, identity="", issuer=_ISSUER)
    with pytest.raises(cosign_verify.CosignVerifyFailed) as exc:
        cosign_verify.resolve_pins()
    assert exc.value.category == "identity-unpinned"


def test_resolve_pins_rejects_unset_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, identity=_IDENTITY, issuer="")
    with pytest.raises(cosign_verify.CosignVerifyFailed) as exc:
        cosign_verify.resolve_pins()
    assert exc.value.category == "issuer-unpinned"


def test_verify_blob_rejects_before_running_cosign_when_unpinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unpinned identity must reject WITHOUT ever spawning cosign."""
    _pin(monkeypatch, identity="", issuer=_ISSUER)
    called = False

    def _boom(*_a: Any, **_k: Any) -> Any:  # pragma: no cover - must not run
        nonlocal called
        called = True
        raise AssertionError("cosign must not run when identity is unpinned")

    monkeypatch.setattr(cosign_verify.subprocess, "run", _boom)
    with pytest.raises(cosign_verify.CosignVerifyFailed):
        cosign_verify.verify_blob(
            artifact=b"uki", signature_b64=_SIG_B64, certificate_pem=_CERT_PEM
        )
    assert called is False


# ─── malformed wire inputs ───────────────────────────────────────────


@pytest.mark.parametrize(
    "artifact,sig,cert",
    [
        (b"", _SIG_B64, _CERT_PEM),
        (b"uki", "", _CERT_PEM),
        (b"uki", _SIG_B64, ""),
        (b"uki", "!!!not-base64!!!", _CERT_PEM),
        (b"uki", _SIG_B64, "not-a-pem-blob"),
    ],
)
def test_verify_blob_wire_rejects(
    monkeypatch: pytest.MonkeyPatch, artifact: bytes, sig: str, cert: str
) -> None:
    _pin(monkeypatch, identity=_IDENTITY, issuer=_ISSUER)
    monkeypatch.setattr(
        cosign_verify.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("cosign must not run on malformed wire input")
        ),
    )
    with pytest.raises(cosign_verify.CosignVerifyFailed) as exc:
        cosign_verify.verify_blob(
            artifact=artifact, signature_b64=sig, certificate_pem=cert
        )
    assert exc.value.category == "wire"


# ─── argv shape (the keyless-pin teeth) ──────────────────────────────


def test_verify_blob_argv_pins_identity_and_enforces_rekor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, identity=_IDENTITY, issuer=_ISSUER)
    seen: dict[str, Any] = {}

    def _capture(argv: list[str], **kwargs: Any) -> _FakeCompleted:
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _FakeCompleted(0)

    monkeypatch.setattr(cosign_verify.subprocess, "run", _capture)
    pins = cosign_verify.verify_blob(
        artifact=b"uki", signature_b64=_SIG_B64, certificate_pem=_CERT_PEM
    )
    argv = seen["argv"]
    assert argv[0].endswith("cosign") or argv[0] == "cosign"
    assert argv[1] == "verify-blob"
    # Both keyless pins present with the resolved values.
    assert "--certificate-identity" in argv
    assert argv[argv.index("--certificate-identity") + 1] == _IDENTITY
    assert "--certificate-oidc-issuer" in argv
    assert argv[argv.index("--certificate-oidc-issuer") + 1] == _ISSUER
    # Rekor inclusion is NEVER disabled.
    assert "--insecure-ignore-tlog" not in argv
    # No shell — argv list, shell not enabled.
    assert seen["kwargs"].get("shell", False) is False
    assert pins.identity == _IDENTITY and pins.issuer == _ISSUER


# ─── cosign process outcomes ─────────────────────────────────────────


def test_verify_blob_nonzero_exit_is_fail_closed_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, identity=_IDENTITY, issuer=_ISSUER)
    monkeypatch.setattr(
        cosign_verify.subprocess,
        "run",
        lambda *_a, **_k: _FakeCompleted(1, stderr=b"no matching signatures"),
    )
    with pytest.raises(cosign_verify.CosignVerifyFailed) as exc:
        cosign_verify.verify_blob(
            artifact=b"uki", signature_b64=_SIG_B64, certificate_pem=_CERT_PEM
        )
    assert exc.value.category == "cosign-rejected"


def test_verify_blob_missing_binary_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, identity=_IDENTITY, issuer=_ISSUER)

    def _missing(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("cosign")

    monkeypatch.setattr(cosign_verify.subprocess, "run", _missing)
    with pytest.raises(cosign_verify.CosignUnavailable):
        cosign_verify.verify_blob(
            artifact=b"uki", signature_b64=_SIG_B64, certificate_pem=_CERT_PEM
        )


def test_verify_blob_timeout_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, identity=_IDENTITY, issuer=_ISSUER)

    def _timeout(*_a: Any, **_k: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="cosign", timeout=60)

    monkeypatch.setattr(cosign_verify.subprocess, "run", _timeout)
    with pytest.raises(cosign_verify.CosignUnavailable):
        cosign_verify.verify_blob(
            artifact=b"uki", signature_b64=_SIG_B64, certificate_pem=_CERT_PEM
        )
