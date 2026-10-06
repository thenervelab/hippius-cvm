"""Tests for the §H phase-2 order-dispatch effect (``order_dispatch.py``).

The dispatch path is exercised end-to-end at the Python layer with:

- the ``encode-order`` subprocess mocked (test must not depend on the
  Rust binary being built in CI's pytest container — that integration
  lives in the Rust test in ``binaries/edge-gateway/tests/``);
- the ``urlopen`` call mocked so no real socket is opened.

What we DO verify here is the contract surface the orchestrator
relies on: headers (target addr + kind), body bytes (passed through
verbatim), exit codes mapped to ``DispatchResult``, and the
fail-loud paths on misconfiguration.
"""

from __future__ import annotations

import io
import subprocess
import urllib.error
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from apps.orchestration import order_dispatch

# ── helpers ─────────────────────────────────────────────────────────


def _completed(stdout: bytes = b"signed-cbor-body", returncode: int = 0, stderr: bytes = b""):
    """Fake ``subprocess.run`` result."""
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _resp(status: int = 200, body: bytes = b""):
    """Fake ``urlopen`` context manager returning a response."""
    mock = MagicMock()
    mock.status = status
    mock.read.return_value = body
    mock.__enter__ = lambda self: self
    mock.__exit__ = lambda self, *a: False
    return mock


# ── happy-path contract ────────────────────────────────────────────


@override_settings(
    VALI_EDGE_ORDER_URL="http://edge-gateway:8444",
    VALI_TICKET_VALIDATOR_BIN="/usr/local/bin/hippius-ticket-validator",
)
def test_dispatch_order_posts_to_edge_with_correct_headers() -> None:
    """Vali → Edge POST carries the two routing headers + opaque CBOR."""
    with (
        patch.object(
            order_dispatch.subprocess, "run", return_value=_completed(b"cbor-bytes")
        ) as run_mock,
        patch.object(
            order_dispatch.urllib.request, "urlopen", return_value=_resp(200, b"")
        ) as url_mock,
    ):
        result = order_dispatch.dispatch_order(
            miner_id="miner-a",
            netbird_ip="100.64.0.10",
            order_id="ord-1",
            kind="launch",
            payload_json=b'{"vm_id":"t1"}',
        )

    # The validator was invoked with the closed-vocabulary CLI args —
    # never composed from caller text without escape. The
    # `--target-miner-id` value MUST equal `miner_id` (the trusted
    # routing source) and `--issued-at-unix` MUST be a decimal-encoded
    # unix-seconds value (review r1 High — cross-miner + long-term
    # replay closures).
    args, kwargs = run_mock.call_args
    cli = args[0]
    assert cli[:8] == [
        "/usr/local/bin/hippius-ticket-validator",
        "encode-order",
        "--order-id",
        "ord-1",
        "--kind",
        "launch",
        "--target-miner-id",
        "miner-a",
    ]
    # Last two args: --issued-at-unix <decimal-seconds>. The actual
    # value is `int(time.time())` at call time, so just shape-check it.
    assert cli[8] == "--issued-at-unix"
    assert cli[9].isdigit() and len(cli[9]) >= 10  # at least 2001-09-09
    assert kwargs["input"] == b'{"vm_id":"t1"}'

    # The Edge URL is composed from the setting only — never from the
    # caller's miner_id. The two routing headers carry the trusted IP +
    # closed-vocabulary kind.
    request = url_mock.call_args.args[0]
    assert request.full_url == "http://edge-gateway:8444/v1/edge/order"
    assert request.get_method() == "POST"
    assert request.headers["X-hippius-target-addr"] == "100.64.0.10:9700"
    assert request.headers["X-hippius-order-kind"] == "launch"
    assert request.headers["Content-type"] == "application/cbor"
    # Body bytes from the validator are passed through verbatim — no
    # re-encoding (the Edge will sign these EXACT bytes; any
    # re-encoding here would break the signature on the miner side).
    assert request.data == b"cbor-bytes"

    assert result.ok is True
    assert result.status == 200


@override_settings(
    VALI_EDGE_ORDER_URL="http://edge-gateway:8444",
    VALI_TICKET_VALIDATOR_BIN="/usr/local/bin/hippius-ticket-validator",
)
def test_dispatch_returns_classifier_on_miner_rejection() -> None:
    """The miner's 4xx body (static classifier) is surfaced verbatim."""
    # urlopen raises HTTPError on non-2xx; the effect catches it and
    # returns the status + body so the caller can branch on the class.
    http_err = urllib.error.HTTPError(
        url="http://edge-gateway:8444/v1/edge/order",
        code=400,
        msg="Bad Request",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(b"bad-signature"),
    )
    with (
        patch.object(
            order_dispatch.subprocess, "run", return_value=_completed(b"cbor")
        ),
        patch.object(
            order_dispatch.urllib.request, "urlopen", side_effect=http_err
        ),
    ):
        result = order_dispatch.dispatch_order(
            miner_id="miner-a",
            netbird_ip="100.64.0.10",
            order_id="ord-2",
            kind="launch",
            payload_json=b'{}',
        )
    assert result.ok is False
    assert result.status == 400
    assert result.classifier == "bad-signature"


@override_settings(
    VALI_EDGE_ORDER_URL="http://edge-gateway:8444",
    VALI_TICKET_VALIDATOR_BIN="/usr/local/bin/hippius-ticket-validator",
)
def test_dispatch_raises_on_transport_failure() -> None:
    """An Edge that is unreachable raises ``OrderDispatchUnavailable``."""
    with (
        patch.object(
            order_dispatch.subprocess, "run", return_value=_completed(b"cbor")
        ),
        patch.object(
            order_dispatch.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ),
    ):
        with pytest.raises(order_dispatch.OrderDispatchUnavailable) as ei:
            order_dispatch.dispatch_order(
                miner_id="miner-a",
                netbird_ip="100.64.0.10",
                order_id="ord-3",
                kind="launch",
                payload_json=b'{}',
            )
    # The URL must NEVER appear in the exception text. Review r1 Low —
    # the message is now a fully STATIC classifier (the underlying
    # exception lives on `__cause__` for traceback debugging, never in
    # the message). Pin the exact string so a future regression that
    # re-interpolates `exc` is caught.
    assert "edge-gateway" not in str(ei.value)
    assert str(ei.value) == "edge-order: peer unreachable"
    # The original exception is still chained for debugging.
    assert isinstance(ei.value.__cause__, urllib.error.URLError)


# ── misconfig paths ────────────────────────────────────────────────


@override_settings(VALI_EDGE_ORDER_URL="", VALI_TICKET_VALIDATOR_BIN="/x")
def test_unset_edge_url_raises_misconfigured() -> None:
    with pytest.raises(order_dispatch.OrderDispatchMisconfigured):
        order_dispatch.dispatch_order(
            miner_id="m",
            netbird_ip="100.64.0.1",
            order_id="o",
            kind="launch",
            payload_json=b'{}',
        )


@override_settings(VALI_EDGE_ORDER_URL="http://e", VALI_TICKET_VALIDATOR_BIN="")
def test_unset_validator_bin_raises_misconfigured() -> None:
    with pytest.raises(order_dispatch.OrderDispatchMisconfigured):
        order_dispatch.dispatch_order(
            miner_id="m",
            netbird_ip="100.64.0.1",
            order_id="o",
            kind="launch",
            payload_json=b'{}',
        )


@override_settings(VALI_EDGE_ORDER_URL="http://e", VALI_TICKET_VALIDATOR_BIN="/x")
def test_missing_netbird_ip_raises_misconfigured() -> None:
    with pytest.raises(order_dispatch.OrderDispatchMisconfigured) as ei:
        order_dispatch.dispatch_order(
            miner_id="miner-no-ip",
            netbird_ip="",
            order_id="o",
            kind="launch",
            payload_json=b'{}',
        )
    assert "miner-no-ip" in str(ei.value)


@override_settings(
    VALI_EDGE_ORDER_URL="http://edge",
    VALI_TICKET_VALIDATOR_BIN="/usr/local/bin/hippius-ticket-validator",
)
def test_validator_nonzero_exit_raises_error() -> None:
    """An ``encode-order`` failure (e.g. ``bad-kind``) raises distinctly
    so the orchestrator can branch on misconfig vs transient.
    """
    with patch.object(
        order_dispatch.subprocess,
        "run",
        return_value=_completed(b"", returncode=2, stderr=b"encode-order: bad-kind"),
    ):
        with pytest.raises(order_dispatch.OrderDispatchError) as ei:
            order_dispatch.dispatch_order(
                miner_id="m",
                netbird_ip="100.64.0.1",
                order_id="o",
                kind="explode",
                payload_json=b'{}',
            )
    assert "bad-kind" in str(ei.value)


@override_settings(
    VALI_EDGE_ORDER_URL="http://edge",
    VALI_TICKET_VALIDATOR_BIN="/usr/local/bin/hippius-ticket-validator",
)
def test_validator_empty_stdout_raises_error() -> None:
    """A validator that exits 0 but writes nothing would otherwise post
    an empty body to the Edge — guard against it loud.
    """
    with patch.object(order_dispatch.subprocess, "run", return_value=_completed(b"")):
        with pytest.raises(order_dispatch.OrderDispatchError) as ei:
            order_dispatch.dispatch_order(
                miner_id="m",
                netbird_ip="100.64.0.1",
                order_id="o",
                kind="launch",
                payload_json=b'{}',
            )
    assert "empty body" in str(ei.value)


# ── payload-builder helpers ───────────────────────────────────────


def test_build_launch_payload_coerces_ints() -> None:
    p = order_dispatch.build_launch_payload(
        vm_id="t1",
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        cmdline="x",
        luks_disk_path="/l",
        luks_disk_size_gb="10",  # str coerces to int
        rootfs_data_path="/var/lib/hippius-miner/rootfs.img",
        rootfs_hash_path="/var/lib/hippius-miner/rootfs.verity",
        cpu_count="2",
        memory_mb="2048",
        cose_ticket=b"\x00\x01\x02fake-cose",
        data_disk_size_gb="64",  # str coerces to int (#365)
    )
    assert p["luks_disk_size_gb"] == 10
    assert p["cpu_count"] == 2
    assert p["memory_mb"] == 2048
    assert p["data_disk_size_gb"] == 64


def test_build_launch_payload_data_disk_defaults_to_zero() -> None:
    """#365 — backward-compat: an older caller that omits
    ``data_disk_size_gb`` produces 0 (no data disk). The Rust
    ``LaunchOrder`` reads it via ``#[serde(default)]``."""
    p = order_dispatch.build_launch_payload(
        vm_id="t1",
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        cmdline="x",
        luks_disk_path="/l",
        luks_disk_size_gb=10,
        rootfs_data_path="/var/lib/hippius-miner/rootfs.img",
        rootfs_hash_path="/var/lib/hippius-miner/rootfs.verity",
        cpu_count=1,
        memory_mb=2048,
        cose_ticket=b"\x00\x01\x02fake-cose",
    )
    assert p["data_disk_size_gb"] == 0


def test_build_launch_payload_carries_base64_cose_ticket() -> None:
    """The COSE bytes round-trip through base64 to the JSON wire — the
    Rust ``LaunchOrder.cose_ticket: ByteBuf`` decodes that back to the
    SAME bytes the L1 mint produced (byte-identical end-to-end).
    """
    import base64 as _b64

    cose = b"the-cose-ticket-bytes\xff\x00\x42"
    p = order_dispatch.build_launch_payload(
        vm_id="t1",
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        cmdline="x",
        luks_disk_path="/l",
        luks_disk_size_gb=10,
        rootfs_data_path="/var/lib/hippius-miner/rootfs.img",
        rootfs_hash_path="/var/lib/hippius-miner/rootfs.verity",
        cpu_count=1,
        memory_mb=2048,
        cose_ticket=cose,
    )
    assert isinstance(p["cose_ticket"], str)
    assert _b64.b64decode(p["cose_ticket"]) == cose


def test_build_launch_payload_rejects_empty_cose_ticket() -> None:
    """An empty COSE blob would stall the §21 ticket-load stage on
    every guest. Fail loud at the producer.
    """
    import pytest

    with pytest.raises(ValueError, match="cose_ticket is empty"):
        order_dispatch.build_launch_payload(
            vm_id="t1",
            ovmf_path="/o",
            kernel_path="/k",
            initrd_path="/i",
            cmdline="x",
            luks_disk_path="/l",
            luks_disk_size_gb=10,
            rootfs_data_path="/var/lib/hippius-miner/rootfs.img",
            rootfs_hash_path="/var/lib/hippius-miner/rootfs.verity",
            cpu_count=1,
            memory_mb=2048,
            cose_ticket=b"",
        )


def test_build_launch_payload_rejects_non_bytes_cose_ticket() -> None:
    """Defensive: a string slipping through (someone forgot the
    ``b""`` prefix) is structurally rejected at the boundary rather
    than silently base64-encoding the str's bytes.
    """
    import pytest

    with pytest.raises(TypeError, match="must be bytes"):
        order_dispatch.build_launch_payload(  # type: ignore[arg-type]
            vm_id="t1",
            ovmf_path="/o",
            kernel_path="/k",
            initrd_path="/i",
            cmdline="x",
            luks_disk_path="/l",
            luks_disk_size_gb=10,
            rootfs_data_path="/var/lib/hippius-miner/rootfs.img",
            rootfs_hash_path="/var/lib/hippius-miner/rootfs.verity",
            cpu_count=1,
            memory_mb=2048,
            cose_ticket="not-bytes",  # type: ignore[arg-type]
        )


# ── URL-shape validation (review r2 Low) ──────────────────────────


@override_settings(
    VALI_EDGE_ORDER_URL="http://user:pass@edge-gateway:8444",
    VALI_TICKET_VALIDATOR_BIN="/usr/local/bin/hippius-ticket-validator",
)
def test_url_with_embedded_credentials_is_rejected() -> None:
    """An operator who pasted creds into the URL must fail closed with
    a STATIC classifier — never an exception that interpolates the
    `user:pass@...` half of the URL.
    """
    with pytest.raises(order_dispatch.OrderDispatchMisconfigured) as ei:
        order_dispatch.dispatch_order(
            miner_id="m",
            netbird_ip="100.64.0.1",
            order_id="o",
            kind="launch",
            payload_json=b'{}',
        )
    msg = str(ei.value)
    # Static class only — no fragment of the URL value in the message.
    assert msg == "VALI_EDGE_ORDER_URL must not embed credentials"
    assert "user" not in msg
    assert "pass" not in msg


@override_settings(
    VALI_EDGE_ORDER_URL="not-a-url",
    VALI_TICKET_VALIDATOR_BIN="/usr/local/bin/hippius-ticket-validator",
)
def test_url_without_scheme_is_rejected() -> None:
    with pytest.raises(order_dispatch.OrderDispatchMisconfigured) as ei:
        order_dispatch.dispatch_order(
            miner_id="m",
            netbird_ip="100.64.0.1",
            order_id="o",
            kind="launch",
            payload_json=b'{}',
        )
    msg = str(ei.value)
    # The exact string — not "not-a-url" anywhere.
    assert msg == "VALI_EDGE_ORDER_URL must be http(s)://"
    assert "not-a-url" not in msg


@override_settings(
    VALI_EDGE_ORDER_URL="http://",
    VALI_TICKET_VALIDATOR_BIN="/usr/local/bin/hippius-ticket-validator",
)
def test_url_without_hostname_is_rejected() -> None:
    with pytest.raises(order_dispatch.OrderDispatchMisconfigured) as ei:
        order_dispatch.dispatch_order(
            miner_id="m",
            netbird_ip="100.64.0.1",
            order_id="o",
            kind="launch",
            payload_json=b'{}',
        )
    assert str(ei.value) == "VALI_EDGE_ORDER_URL is missing a hostname"


def test_build_stop_payload_coerces_bool() -> None:
    assert order_dispatch.build_stop_payload(vm_id="t1", graceful=1)["graceful"] is True
    assert order_dispatch.build_stop_payload(vm_id="t1", graceful=0)["graceful"] is False


def test_migrate_activate_payload_omits_an_empty_state_get_url() -> None:
    """Deploy-order safety. The ticket-validator bridge rejects an empty
    optional string outright, and a miner-agent that predates the field is
    `deny_unknown_fields` — so a migration carrying no state disk must
    produce a payload with the key ABSENT, byte-identical to the pre-#876
    wire, not present-and-empty."""
    common = {
        "vm_id": "tenant-x",
        "get_url": "https://s3/snap",
        "new_gen": 6,
        "ovmf_path": "/o",
        "kernel_path": "/k",
        "initrd_path": "/i",
        "cmdline": "ro",
        "luks_disk_path": "/d",
        "luks_disk_size_gb": 10,
        "rootfs_data_path": "/r",
        "rootfs_hash_path": "/h",
        "cpu_count": 2,
        "memory_mb": 2048,
        "cose_ticket": b"fake-cose-ticket",
        "boot_artifacts": None,
    }
    absent = order_dispatch.build_migrate_activate_payload(**common)
    assert "state_get_url" not in absent

    carried = order_dispatch.build_migrate_activate_payload(
        **common, state_get_url="https://s3/state?sig=y"
    )
    assert carried["state_get_url"] == "https://s3/state?sig=y"
    # Nothing else moves — the only difference is the one key.
    assert {k: v for k, v in carried.items() if k != "state_get_url"} == absent


def test_migrate_activate_payload_carries_the_snapshot_digest_only_when_known() -> None:
    """A multipart snapshot's length + sha256 go to the dest, which verifies
    its download against them; a single-PUT one has none to carry."""
    common = {
        "vm_id": "tenant-x",
        "get_url": "https://s3/snap",
        "new_gen": 6,
        "ovmf_path": "/o",
        "kernel_path": "/k",
        "initrd_path": "/i",
        "cmdline": "ro",
        "luks_disk_path": "/d",
        "luks_disk_size_gb": 10,
        "rootfs_data_path": "/r",
        "rootfs_hash_path": "/h",
        "cpu_count": 2,
        "memory_mb": 2048,
        "cose_ticket": b"fake-cose-ticket",
        "boot_artifacts": None,
    }
    absent = order_dispatch.build_migrate_activate_payload(**common)
    assert "snapshot_size" not in absent and "snapshot_sha256_hex" not in absent
    carried = order_dispatch.build_migrate_activate_payload(
        **common, snapshot_size=40 * 1024**3, snapshot_sha256_hex="ab" * 32
    )
    assert carried["snapshot_size"] == 40 * 1024**3
    assert carried["snapshot_sha256_hex"] == "ab" * 32


def test_migrate_activate_payload_carries_settle_by_only_when_set() -> None:
    """vali's phase deadline goes to the dest so a retry cannot outlive it;
    not carried (0) leaves the body exactly as before."""
    common = {
        "vm_id": "tenant-x",
        "get_url": "https://s3/snap",
        "new_gen": 6,
        "ovmf_path": "/o",
        "kernel_path": "/k",
        "initrd_path": "/i",
        "cmdline": "ro",
        "luks_disk_path": "/d",
        "luks_disk_size_gb": 10,
        "rootfs_data_path": "/r",
        "rootfs_hash_path": "/h",
        "cpu_count": 2,
        "memory_mb": 2048,
        "cose_ticket": b"fake-cose-ticket",
        "boot_artifacts": None,
    }
    absent = order_dispatch.build_migrate_activate_payload(**common)
    assert "settle_by_unix" not in absent
    assert order_dispatch.build_migrate_activate_payload(**common, settle_by_unix=0) == absent
    carried = order_dispatch.build_migrate_activate_payload(
        **common, settle_by_unix=1_790_000_000
    )
    assert carried["settle_by_unix"] == 1_790_000_000
    assert {k: v for k, v in carried.items() if k != "settle_by_unix"} == absent
