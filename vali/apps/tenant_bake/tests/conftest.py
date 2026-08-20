"""Shared fixtures for the tenant_bake test suite.

The `base_image_url` SSRF guard (`views._assert_base_image_url_safe`,
audit M-SSRF) resolves the URL host via `socket.getaddrinfo`. Stub it so
the suite is hermetic (no real DNS) — an IP literal resolves to itself
(so private/metadata literals are still caught), any hostname resolves to
a fixed PUBLIC IP. A test that needs a private-resolving hostname
overrides this with its own `monkeypatch.setattr`.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest


def _fake_getaddrinfo_public(host, port, *args, **kwargs):
    try:
        ipaddress.ip_address(host)
        ip = host
    except ValueError:
        ip = "93.184.216.34"  # public
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0))
    ]


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)
