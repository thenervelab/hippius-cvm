"""The PUBLIC OpenAPI schema — filtered to the routes that are actually
reachable from outside the cluster.

WHY THIS EXISTS. `/v1/schema` documents all 45 vali routes, which is
correct for an in-cluster reader. Serving that same document on
`api.hippius.network` would publish a map of the internal control plane —
`/v1/admin/miner/register`, `/v1/admin/host-attestor/release`,
`/v1/admin/miner/{id}/quarantine`, `/v1/edge/registry`,
`/v1/miner/{id}/graceful-exit` — and five of those descriptions state in
plain words that the endpoint carries no service-token auth (they are
signed-body or CNP-gated miner-plane routes, sound by design *on the
mesh*).

None of it is reachable: the Ingress path allow-list 404s everything
outside `publicApiIngress.allowedPaths`, so disclosure here is not
access. But handing an anonymous reader a labelled diagram of the
unauthenticated internal surface is a gift with no upside, and the reader
this is FOR — whoever wires an interface against the public API — is
actively hindered by 44 routes they cannot call.

So the public document is generated from the same code but filtered to
the public prefixes, and the unfiltered `/v1/schema` stays private
exactly as before.

⚠️ The filter list is `VALI_PUBLIC_API_PATHS`, which the chart renders
from `publicApiIngress.allowedPaths` — the SAME value that builds the
Ingress. They cannot drift: a path added to the public route appears in
the public docs, and a path removed disappears from both. Do not
hard-code a second list here.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework.permissions import AllowAny


def public_api_prefixes() -> tuple[str, ...]:
    """The path prefixes the Ingress publishes, normalised.

    Empty ⇒ nothing is public, and the filter below drops EVERY path.
    That is deliberate: a misconfigured or absent setting must yield an
    empty document, never the full internal one. Fail closed — the whole
    point of this module is that the public default cannot be "expose
    everything".
    """
    raw = getattr(settings, "VALI_PUBLIC_API_PATHS", "") or ""
    out = []
    for part in str(raw).split(","):
        p = part.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        out.append(p.rstrip("/") or "/")
    return tuple(out)


def filter_to_public_paths(endpoints: list[Any], **_kwargs: Any) -> list[Any]:
    """drf-spectacular preprocessing hook: keep only public endpoints.

    `endpoints` is a list of `(path, path_regex, method, callback)`. A
    path qualifies when it equals a configured prefix or sits underneath
    it, so `/v1/vm` also publishes `/v1/vm/{id}` and `/v1/vm/launch` —
    matching how an nginx prefix rule actually routes. Substring matching
    is deliberately NOT used: `/v1/vm` must not pull in a hypothetical
    `/v1/vmadmin`.
    """
    prefixes = public_api_prefixes()
    kept = []
    for endpoint in endpoints:
        path = endpoint[0]
        if any(path == p or path.startswith(p + "/") for p in prefixes):
            kept.append(endpoint)
    return kept


_PUBLIC_SETTINGS = {
    "TITLE": "Hippius VM API",
    "DESCRIPTION": (
        "The public Hippius confidential-compute VM API. Launch, inspect and "
        "decommission confidential VMs. Auth: bearer `ServiceToken`.\n\n"
        "This document is filtered to the routes published at "
        "`api.hippius.network`; the validator exposes further internal "
        "endpoints that are not reachable from outside the cluster."
    ),
    "PREPROCESSING_HOOKS": ["vali.public_schema.filter_to_public_paths"],
}


class PublicSchemaView(SpectacularAPIView):
    permission_classes = [AllowAny]
    custom_settings = _PUBLIC_SETTINGS
    # A dedicated view attribute, NOT a `custom_settings` key —
    # drf-spectacular raises `SERVE_PUBLIC not allowed in custom_settings`.
    # True because this document is written FOR anonymous readers: it must
    # describe the whole public surface, not be pruned again by whatever
    # permissions the particular viewer happens to hold.
    serve_public = True


class PublicSwaggerView(SpectacularSwaggerView):
    permission_classes = [AllowAny]
    url_name = "public-schema"
