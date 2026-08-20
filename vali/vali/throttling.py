"""DRF throttle keyed on the Edge-stamped mTLS identity (RA-N4/RA-N5).

vali is Edge-only (the vali `CiliumNetworkPolicy` admits ingress *only*
from the edge-gateway pod), and for every relayed request the Edge builds
a FRESH upstream request stamping the connection's mTLS-verified identity
into the ``x-hippius-peer-id`` header (it does not copy inbound client
headers). So on the anonymous, signed-envelope ingress endpoints
(heartbeat / telemetry / graceful-exit / stopped-ack) the peer-id is a
trusted, per-miner identity a caller CANNOT rotate.

DRF's stock ``ScopedRateThrottle`` keys anonymous requests on
``get_ident`` = the client IP, which (with ``NUM_PROXIES`` unset) reads
the client-supplied ``X-Forwarded-For`` verbatim — an attacker rotates
the header and gets a fresh bucket every request, defeating the cap and
re-opening the verifier-subprocess amplification RA-M2 set out to bound
(RA-N4). Keying on the un-spoofable peer-id closes that: one bucket per
miner, no matter how the request is dressed.
"""

from __future__ import annotations

from typing import Any

from rest_framework.throttling import ScopedRateThrottle

#: Kept byte-identical to the Edge's `vali_forward::HEARTBEAT_PEER_ID_HEADER`
#: and `apps.telemetry.views._PEER_ID_HEADER` (grep anchor).
PEER_ID_HEADER = "x-hippius-peer-id"


class PeerIdScopedRateThrottle(ScopedRateThrottle):
    """``ScopedRateThrottle`` that buckets anonymous requests per
    Edge-stamped ``x-hippius-peer-id`` instead of the spoofable client IP.

    Authenticated requests are unchanged — still keyed on
    ``request.user.pk`` (a per-principal quota). Anonymous requests key on
    the peer-id when present, else fall back to ``get_ident`` (which, with
    ``NUM_PROXIES = 0``, is the Edge pod's address — a non-spoofable global
    bucket rather than a client-controlled value).
    """

    def get_cache_key(self, request: Any, view: Any) -> str | None:
        if request.user and request.user.is_authenticated:
            ident: Any = request.user.pk
        else:
            # Edge-stamped mTLS identity (trusted; see module docstring),
            # falling back to the direct-peer IP when a route carries none.
            ident = request.headers.get(PEER_ID_HEADER) or self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}
