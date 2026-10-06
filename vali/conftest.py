"""Shared pytest fixtures + early env setup for the vali test suite.

The DB switch lives in `vali/settings_test.py` (see its docstring for
why a settings module is more reliable than env mutation). This
conftest sets the validator-binary path so tests that exercise the
Rust shell-out can find it, and installs the no-live-network guard
(see the section at the bottom).
"""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key-not-for-prod")
os.environ.setdefault(
    "VALI_TICKET_VALIDATOR_BIN",
    str(REPO_ROOT / "target" / "release" / "hippius-ticket-validator"),
)


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    """DRF rate-limit counters live in the process-global LocMemCache,
    which pytest-django does NOT roll back between tests (audit
    M-ratelimit). Clear it before each test so a scoped-throttle view's
    request count can't leak across tests and cause a spurious 429."""
    from django.core.cache import cache

    cache.clear()
    yield


# ─── no live network ─────────────────────────────────────────────────
#
# The suite must never reach a real host: NetBird, the edge gateway,
# the KBS admin API, S3, the chain RPC, RIPEstat... A live call makes a
# test slow, flaky, and dependent on CI's egress (a 401 from
# api.netbird.io or a DNS failure looks just as "green" as a mock when
# the effect swallows errors). Any DNS resolution of, or socket connect
# to, a non-loopback address raises `LiveNetworkError`, and the attempt
# is recorded so the test FAILS at teardown even when the code under
# test catches the exception and carries on.
#
# A test that genuinely needs a non-loopback socket opts out with
# `@pytest.mark.allow_network`. Loopback (a local test server) and
# AF_UNIX sockets are always allowed.

_LOOPBACK_NAMES = frozenset({"", "localhost", "localhost.localdomain", "ip6-localhost"})


class LiveNetworkError(RuntimeError):
    """A test tried to reach a real network host."""


_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_violations: list[str] = []
_network_allowed = False


def _is_loopback(host: object) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", errors="replace")
    if not isinstance(host, str):
        return False
    name = host.strip("[]").split("%", 1)[0].lower()
    if name in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _refuse(what: str) -> None:
    msg = (
        f"test attempted a live network call: {what}. Mock the effect at "
        "its seam (or mark the test `allow_network` if it truly needs it)."
    )
    _violations.append(msg)
    raise LiveNetworkError(msg)


def _guarded_getaddrinfo(host: object, *args: Any, **kwargs: Any) -> Any:
    if not _network_allowed and not _is_loopback(host):
        _refuse(f"DNS resolution of {host!r}")
    return _real_getaddrinfo(host, *args, **kwargs)


def _check_address(sock: socket.socket, address: object) -> None:
    if _network_allowed or sock.family not in (socket.AF_INET, socket.AF_INET6):
        return
    host = address[0] if isinstance(address, tuple) and address else address
    if not _is_loopback(host):
        _refuse(f"socket connect to {address!r}")


def _guarded_connect(self: socket.socket, address: Any) -> None:
    _check_address(self, address)
    return _real_connect(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    _check_address(self, address)
    return _real_connect_ex(self, address)


socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore[assignment]
socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[method-assign]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "allow_network: let this test reach non-loopback hosts (opt-out of the "
        "no-live-network guard in vali/conftest.py)",
    )


@pytest.fixture(autouse=True)
def _no_live_network(request: pytest.FixtureRequest) -> Iterator[None]:
    """Fail any test that tried to reach a real host, even if the code
    under test swallowed the `LiveNetworkError`."""
    global _network_allowed
    _network_allowed = request.node.get_closest_marker("allow_network") is not None
    _violations.clear()
    yield
    _network_allowed = False
    attempts = list(_violations)
    _violations.clear()
    if attempts:
        pytest.fail(
            f"{len(attempts)} live network attempt(s):\n  " + "\n  ".join(attempts[:5]),
            pytrace=False,
        )
