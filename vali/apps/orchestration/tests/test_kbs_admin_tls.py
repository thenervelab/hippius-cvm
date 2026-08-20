"""vali's half of the KBS admin mTLS gate.

Two groups of claims:

1. **The decision table** (`admin_transport`) — pure, dependency-free,
   and the thing that must agree byte-for-byte with the Rust client's
   `AdminClientMode::decide` and the server's `AdminListenerMode::decide`.
   A disagreement between the three is what makes a cutover strand the
   cluster, so these run unconditionally.
2. **The material actually being pinned** — needs a real PKI, minted
   with `openssl` so no new Python dependency is added for a test. The
   cryptographic end-to-end behaviour (a handshake really failing for an
   unpinned CA, on both sides) is proven against real rustls sockets in
   `binaries/kbs-server/tests/admin_mtls_client_interop.rs`; what is
   asserted here is that vali BUILDS the context that gets those
   properties — in particular that the system trust store is not loaded.

3. **The wiring** — every one of vali's five admin callers actually
   carries the decided transport. A gate that one caller bypasses is
   not a gate.
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import ssl
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration.services import kbs_admin_tls
from apps.orchestration.services.kbs_admin_tls import (
    KbsAdminTlsMisconfigured,
    admin_client_tls_argv,
    admin_transport,
)

HTTPS = "https://kbs-server-admin.kbs.svc.cluster.local:8001"
HTTP = "http://kbs-server-admin.kbs.svc.cluster.local:8001"


def _material(monkeypatch: pytest.MonkeyPatch, cert: str, key: str, ca: str) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CLIENT_CERT", cert)
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CLIENT_KEY", key)
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CACERT", ca)


@contextlib.contextmanager
def _captured_warnings() -> Iterator[list[str]]:
    """Collect this module's WARNING records.

    Attached directly to the named logger rather than using `caplog`,
    because the project's logging config does not propagate `apps.*` to
    the root logger that caplog installs its handler on — so caplog sees
    nothing even when the record is emitted.
    """
    messages: list[str] = []

    class _Sink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    logger = logging.getLogger("apps.orchestration.kbs_admin_tls")
    handler = _Sink(level=logging.WARNING)
    logger.addHandler(handler)
    try:
        yield messages
    finally:
        logger.removeHandler(handler)


class _Pki:
    def __init__(self, ca: Path, cert: Path, key: Path, rogue_ca: Path) -> None:
        self.ca = ca
        self.cert = cert
        self.key = key
        self.rogue_ca = rogue_ca


def _openssl(*args: str) -> None:
    subprocess.run(  # noqa: S603 — argv list, fixed args, test-only
        ["openssl", *args], check=True, capture_output=True
    )


def _mint_pki(tmp_path: Path) -> _Pki:
    """Throwaway CA + client leaf, via the `openssl` CLI.

    Deliberately NOT `cryptography`: it is not one of vali's declared
    dependencies, and adding a runtime dep for a test is a bad trade.
    """
    if shutil.which("openssl") is None:  # pragma: no cover — CI has openssl
        pytest.skip("openssl CLI unavailable")
    ca_key = tmp_path / "ca.key"
    ca_crt = tmp_path / "ca.crt"
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(ca_key), "-out", str(ca_crt),
        "-subj", "/CN=hippius-kbs-admin-ca",
    )
    rogue_key = tmp_path / "rogue-ca.key"
    rogue_crt = tmp_path / "rogue-ca.crt"
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(rogue_key), "-out", str(rogue_crt),
        "-subj", "/CN=rogue-ca",
    )
    key = tmp_path / "vali.key"
    csr = tmp_path / "vali.csr"
    crt = tmp_path / "vali.crt"
    _openssl(
        "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr), "-subj", "/CN=vali",
    )
    _openssl(
        "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
        "-CAcreateserial", "-out", str(crt), "-days", "1",
    )
    return _Pki(ca=ca_crt, cert=crt, key=key, rogue_ca=rogue_crt)


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> _Pki:
    """One throwaway PKI for the whole module — minting RSA keys with
    the openssl CLI is slow enough that per-test minting dominated the
    suite's runtime."""
    return _mint_pki(tmp_path_factory.mktemp("kbs-admin-pki"))


@pytest.fixture(scope="module")
def other_pki(tmp_path_factory: pytest.TempPathFactory) -> _Pki:
    """A SECOND, unrelated PKI — the source of the wrong key / unpinned
    CA in the negative tests."""
    return _mint_pki(tmp_path_factory.mktemp("kbs-admin-pki-other"))


# ── 1. the decision table ────────────────────────────────────────────


def test_https_without_material_refuses_to_dial(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE fail-closed claim on vali's side.

    A degrade-to-`ssl.create_default_context()` here would produce a
    connection that is encrypted, authenticates NOTHING about us, and
    looks perfectly healthy in a URL. It must refuse instead — before any
    socket is opened, so no lifecycle mutation has been sent.
    """
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, "", "", "")
    with pytest.raises(KbsAdminTlsMisconfigured, match="not all set"):
        admin_transport()


@pytest.mark.parametrize(
    ("cert", "key", "ca"),
    [
        ("/c", "/k", ""),
        ("/c", "", "/a"),
        ("", "/k", "/a"),
        ("/c", "", ""),
        ("", "", "/a"),
    ],
)
def test_https_with_partial_material_refuses(
    monkeypatch: pytest.MonkeyPatch, cert: str, key: str, ca: str
) -> None:
    """A client identity with no pinned CA, or a pinned CA with no
    identity, is half a gate. Neither counts as configured."""
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, cert, key, ca)
    with pytest.raises(KbsAdminTlsMisconfigured):
        admin_transport()


def test_http_without_material_is_the_pre_cutover_plaintext_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The DEPLOYED state today. It must keep working unchanged, or this
    PR takes production down on merge rather than on cutover."""
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTP)
    _material(monkeypatch, "", "", "")
    transport = admin_transport()
    assert transport.context is None
    assert transport.is_mtls is False
    assert transport.url("/v1/admin/allowlist/reload") == (
        f"{HTTP}/v1/admin/allowlist/reload"
    )


def test_http_with_material_stays_reachable_and_says_so_loudly(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki
) -> None:
    """Rollout step "certs staged, URL not yet flipped".

    This is the arm that makes the cutover ORDERABLE: the certs reach the
    vali pods and are validated while the KBS is still plaintext, so the
    operator learns they work BEFORE both sides have to move. It must
    (a) keep vali able to reach the admin API — otherwise staging the
    certs is itself an outage — and (b) be impossible to mistake for a
    secured state in the logs.
    """
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTP)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))

    with _captured_warnings() as warnings:
        transport = admin_transport()

    assert transport.context is None, "an http URL must not be dialled over TLS"
    joined = "\n".join(warnings)
    assert "UNAUTHENTICATED" in joined
    assert "staged and VALID" in joined


def test_http_with_unusable_material_warns_that_it_is_unusable(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """The staging step is only a real check if broken material is
    reported as broken. Silence here would let the operator flip the URL
    into a total admin-API outage."""
    bad = tmp_path / "not-a-cert.pem"
    bad.write_text("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTP)
    _material(monkeypatch, str(bad), str(bad), str(bad))

    with _captured_warnings() as warnings:
        transport = admin_transport()

    assert transport.context is None
    assert "NOT usable" in "\n".join(warnings)


def test_a_non_http_url_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", "kbs-server-admin:8001")
    _material(monkeypatch, "", "", "")
    with pytest.raises(KbsAdminTlsMisconfigured, match="http:// or https://"):
        admin_transport()


def test_unconfigured_url_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", "")
    with pytest.raises(KbsAdminTlsMisconfigured, match="VALI_KBS_ADMIN_URL"):
        admin_transport()


# ── 2. the material is actually pinned ───────────────────────────────


def test_https_with_valid_material_pins_the_ca_and_loads_our_identity(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """The context must trust EXACTLY the operator's CA — not the system
    store plus it.

    The mutation this kills is a one-word change to
    `ssl.create_default_context(...)` (dropping `cafile`, or adding a
    `load_default_certs()`): the hop would then be satisfiable by any
    public CA, and an attacker who can answer on the admin ClusterIP with
    a Let's Encrypt cert for that name collects vali's client
    presentation. `get_ca_certs()` counting exactly one anchor is what
    makes that mutation visible.
    """
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))

    transport = admin_transport()
    assert transport.is_mtls
    context = transport.context
    assert context is not None
    anchors = context.get_ca_certs()
    assert len(anchors) == 1, (
        "the admin hop must trust ONLY the pinned CA; "
        f"{len(anchors)} anchors means the system store leaked in"
    )
    assert "hippius-kbs-admin-ca" in str(anchors[0]["subject"])
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3


def test_https_with_a_key_that_does_not_match_the_cert_refuses(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, other_pki: _Pki
) -> None:
    """A mismatched pair must fail at build time, in vali's logs, rather
    than as an unattributable handshake alert during the cutover."""
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, str(pki.cert), str(other_pki.key), str(pki.ca))
    with pytest.raises(KbsAdminTlsMisconfigured, match="client identity"):
        admin_transport()


def test_https_with_a_missing_file_refuses(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """The Secret failed to mount (a very ordinary k8s outcome). Fail
    closed and name the setting, not the path."""
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(tmp_path / "gone.crt"))
    with pytest.raises(KbsAdminTlsMisconfigured, match="VALI_KBS_ADMIN_CACERT"):
        admin_transport()


# ── 3. every caller carries the transport ────────────────────────────


def test_client_tls_argv_is_empty_on_the_plaintext_hop(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """The Rust client REFUSES `http://` + material outright. vali owns
    the staging state, so vali is what must not pass the flags there —
    otherwise every launch fails during the staging step."""
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTP)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))
    assert admin_client_tls_argv() == []


def test_client_tls_argv_passes_all_three_flags_on_the_mtls_hop(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))
    assert admin_client_tls_argv() == [
        "--client-cert", str(pki.cert),
        "--client-key", str(pki.key),
        "--ca-cert", str(pki.ca),
    ]


def test_register_vm_subprocess_receives_the_client_certificate(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """§24 `register-vm` — the hot path on EVERY launch. A mutation that
    forgets to append `tls_argv` leaves the one admin call that runs most
    often as the only anonymous one."""
    import subprocess as sp

    from apps.orchestration import kbs_admin

    fake_bin = tmp_path / "hippius-kbs-admin-client"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CLIENT_BIN", str(fake_bin))
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))

    captured: dict[str, object] = {}

    class _Done:
        returncode = 0
        stdout = (
            b'{"outcome":"ok","status":200,"ticket_id":"t","vm_id":"v",'
            b'"vm_generation":1,"cached":false}'
        )
        stderr = b""

    def _fake_run(argv: list[str], **_kw: object) -> _Done:
        captured["argv"] = argv
        return _Done()

    monkeypatch.setattr(sp, "run", _fake_run)
    monkeypatch.setattr(kbs_admin.subprocess, "run", _fake_run)

    kbs_admin.register_vm_active_with_vm_id(vm_id="v", cose_ticket=b"\xaa")

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert "--client-cert" in argv and str(pki.cert) in argv
    assert "--client-key" in argv and str(pki.key) in argv
    assert "--ca-cert" in argv and str(pki.ca) in argv


def test_register_vm_fails_closed_when_the_admin_hop_is_misconfigured(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """https with no material must stop the launch with a retryable
    `EffectUnavailable` — never spawn the client and hope."""
    from apps.orchestration import kbs_admin
    from apps.orchestration.effects import EffectUnavailable

    fake_bin = tmp_path / "hippius-kbs-admin-client"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CLIENT_BIN", str(fake_bin))
    _material(monkeypatch, "", "", "")

    with pytest.raises(EffectUnavailable, match="not all set"):
        kbs_admin.register_vm_active_with_vm_id(vm_id="v", cose_ticket=b"\xaa")


def test_allowlist_reload_carries_the_context(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """§22 auto-pin — the OTHER hot-path admin call. It POSTs the signed
    allowlist that gates every KEK release; an unauthenticated hop here
    is the highest-value target on the admin API."""
    import urllib.request

    from apps.orchestration.services import allowlist_pin

    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))

    captured: dict[str, object] = {}

    class _Resp:
        status = 200

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

    def _fake_urlopen(req: object, **kwargs: object) -> _Resp:
        captured["url"] = req.full_url  # type: ignore[attr-defined]
        captured["context"] = kwargs.get("context")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    allowlist_pin._reload_kbs_allowlist(b"\xaa")

    assert captured["url"] == f"{HTTPS}/v1/admin/allowlist/reload"
    assert isinstance(captured["context"], ssl.SSLContext)


def test_evidence_fetch_carries_the_context(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    import urllib.request

    from apps.orchestration.services import kbs_evidence

    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))

    captured: dict[str, object] = {}

    class _Resp:
        status = 200

        def read(self) -> bytes:
            return b"{}"

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

    def _fake_urlopen(_req: object, **kwargs: object) -> _Resp:
        captured["context"] = kwargs.get("context")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    assert kbs_evidence.fetch_evidence("vm-1") == {}
    assert isinstance(captured["context"], ssl.SSLContext)


def test_seed_boot_counter_carries_the_context(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """The §24/§25 admin effects (`activate`, `crypto-erase`,
    `seed-boot-counter`) all funnel through `effects._http`."""
    import urllib.request

    from apps.orchestration import effects

    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", HTTPS)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))

    captured: dict[str, object] = {}

    class _Resp:
        status = 200

        def read(self) -> bytes:
            return b'{"counter": 3, "previous": 0}'

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

    def _fake_urlopen(_req: object, **kwargs: object) -> _Resp:
        captured["context"] = kwargs.get("context")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    effects.seed_boot_counter("vm-1", counter=3)
    assert isinstance(captured["context"], ssl.SSLContext)


def test_effects_http_does_not_impose_the_admin_identity_on_other_peers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_http` is shared with the Edge + NetBird. Making the admin
    context a module default would hand vali's admin client certificate
    to every peer it talks to."""
    import urllib.request

    from apps.orchestration import effects

    captured: dict[str, object] = {}

    class _Resp:
        status = 200

        def read(self) -> bytes:
            return b"{}"

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

    def _fake_urlopen(_req: object, **kwargs: object) -> _Resp:
        captured["context"] = kwargs.get("context")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    effects._http("GET", "http://edge.test/v1/thing", label="edge")
    assert captured["context"] is None


def test_synthetic_kbs_check_dials_with_the_admin_transport(
    monkeypatch: pytest.MonkeyPatch, pki: _Pki, tmp_path: Path
) -> None:
    """Once the listener is mTLS, a bare probe gets a handshake rejection
    that looks exactly like "the KBS is down" — the monitor would page
    for a healthy cluster. The probe must dial the way the control plane
    dials."""
    import urllib.request

    from apps.synthetic import checks

    monkeypatch.setattr(settings, "VALI_SYNTHETIC_KBS_URL", HTTPS)
    monkeypatch.setattr(settings, "VALI_SYNTHETIC_HTTP_TIMEOUT_S", 1.0)
    _material(monkeypatch, str(pki.cert), str(pki.key), str(pki.ca))

    captured: dict[str, object] = {}

    class _Resp:
        status = 404

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

    def _fake_urlopen(_url: object, **kwargs: object) -> _Resp:
        captured["context"] = kwargs.get("context")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    result = checks.check_kbs()
    assert result.ok
    assert isinstance(captured["context"], ssl.SSLContext)


def test_module_exposes_one_decision_for_every_caller() -> None:
    """Guard against a sixth admin caller quietly rolling its own
    transport: these are the entry points the rest of the codebase is
    allowed to use."""
    assert hasattr(kbs_admin_tls, "admin_transport")
    assert hasattr(kbs_admin_tls, "admin_ssl_context")
    assert hasattr(kbs_admin_tls, "admin_client_tls_argv")
