"""Tests for the healthz + /metrics HTTP server."""

from __future__ import annotations

import urllib.error
import urllib.request

from sentinel.healthz import serve_healthz


def _get(port: int, path: str) -> tuple[int, str]:
    with urllib.request.urlopen(  # noqa: S310 — fixed localhost URL
        f"http://127.0.0.1:{port}{path}", timeout=5
    ) as resp:
        return resp.status, resp.read().decode("utf-8")


def test_healthz_endpoint_reports_ok() -> None:
    server = serve_healthz(port=0)  # port 0 → OS assigns a free port
    try:
        port = server.server_address[1]
        status, body = _get(port, "/healthz")
        assert status == 200
        assert "ok" in body
    finally:
        server.shutdown()


def test_metrics_endpoint_serves_prometheus_text() -> None:
    server = serve_healthz(port=0)
    try:
        port = server.server_address[1]
        status, body = _get(port, "/metrics")
        assert status == 200
        assert "# TYPE sentinel_llm_calls_total counter" in body
        assert "sentinel_llm_calls_total" in body
    finally:
        server.shutdown()


def test_unknown_path_is_404() -> None:
    server = serve_healthz(port=0)
    try:
        port = server.server_address[1]
        try:
            _get(port, "/does-not-exist")
            raise AssertionError("expected HTTP 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        server.shutdown()
