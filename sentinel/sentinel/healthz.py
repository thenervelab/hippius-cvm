"""Minimal HTTP server for the k8s probe + Prometheus scrape.

Exposes two `GET` endpoints on the configured port (default 8080),
using the stdlib `http.server` so the sentinel ships with zero
web-framework deps — the runtime is deliberately small.

  * `/healthz` — liveness only: a healthy response means "the python
    process is up and the event loop is responsive." It is *not* a
    readiness probe for external dependencies.
  * `/metrics` — Prometheus text exposition of the PR-S6 agent
    observability registry (Anthropic API call count, token usage,
    latency, rate-limiter activity). Rendered from `sentinel.metrics`.

The server runs on a `ThreadingHTTPServer`, so each request is handled
on its own thread; `MetricsRegistry` is thread-safe for that reason.
"""

from __future__ import annotations

import asyncio
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from sentinel.metrics import REGISTRY

DEFAULT_HEALTHZ_PORT = 8080

# Prometheus text exposition format version — the conventional
# Content-Type for a `/metrics` endpoint.
_PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

log = logging.getLogger("sentinel.healthz")


class _HealthzHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — stdlib API requires this name
        if self.path == "/healthz":
            self._respond(HTTPStatus.OK, "text/plain; charset=utf-8", b"ok\n")
            return
        if self.path == "/metrics":
            self._respond(
                HTTPStatus.OK,
                _PROMETHEUS_CONTENT_TYPE,
                REGISTRY.render().encode("utf-8"),
            )
            return
        self.send_error(HTTPStatus.NOT_FOUND, "not found")

    def _respond(self, status: HTTPStatus, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        log.debug(format, *args)


def serve_healthz(port: int = DEFAULT_HEALTHZ_PORT) -> ThreadingHTTPServer:
    """Start the healthz HTTP server on a background thread.

    Returns the server handle so the caller can `shutdown()` it on exit
    (used by tests; the production process just lets it ride along
    until the pod is killed).
    """

    server = ThreadingHTTPServer(("0.0.0.0", port), _HealthzHandler)  # noqa: S104 — pod-local
    thread = Thread(target=server.serve_forever, name="sentinel-healthz", daemon=True)
    thread.start()
    log.info("healthz listening on :%d", port)
    return server


async def serve_healthz_async(port: int = DEFAULT_HEALTHZ_PORT) -> ThreadingHTTPServer:
    """Async wrapper for `serve_healthz` — handy from an asyncio entrypoint."""

    return await asyncio.to_thread(serve_healthz, port)
