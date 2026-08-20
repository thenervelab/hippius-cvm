"""The PUBLIC OpenAPI document must describe the public API and NOTHING else.

The value here is the negative assertions. A filter that keeps `/v1/vm`
is easy to get right and easy to test; the failure that matters is the
one where the filter silently stops filtering — a renamed setting, a
default that falls back to "everything", a hook that is configured but
never runs — and the document quietly starts publishing
`/v1/admin/miner/register` to anonymous readers. Every test below that
asserts an ABSENCE is guarding that.
"""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.urls import reverse

from vali.public_schema import filter_to_public_paths, public_api_prefixes

# Routes that must never appear in the public document. Not an arbitrary
# sample: these are the control-plane and miner-plane paths, and the last
# four are the ones whose own schema descriptions state in plain words
# that they carry no service-token auth.
INTERNAL_PATHS = (
    "/v1/admin/miner/register",
    "/v1/admin/miner/list",
    "/v1/admin/host-attestor/release",
    "/v1/admin/audit/measurements",
    "/v1/packer/build",
    "/v1/order_ticket",
    "/v1/admin/epoch-weights",
    "/v1/edge/registry",
    "/v1/lifecycle/stopped",
    "/v1/miner/{miner_id}/graceful-exit",
)


def _endpoint(path: str) -> tuple[str, str, str, object]:
    return (path, path, "GET", object())


class TestPrefixParsing:
    def test_unset_yields_no_prefixes(self) -> None:
        """Fail closed. An unset variable must not mean 'publish all'."""
        with override_settings(VALI_PUBLIC_API_PATHS=""):
            assert public_api_prefixes() == ()

    def test_whitespace_and_trailing_slashes_are_normalised(self) -> None:
        with override_settings(VALI_PUBLIC_API_PATHS=" /v1/vm/ , v1/public/docs "):
            assert public_api_prefixes() == ("/v1/vm", "/v1/public/docs")


class TestFilter:
    def test_no_prefixes_drops_everything(self) -> None:
        """The load-bearing fail-closed case: a missing setting yields an
        EMPTY document, never the full internal one."""
        with override_settings(VALI_PUBLIC_API_PATHS=""):
            kept = filter_to_public_paths([_endpoint(p) for p in INTERNAL_PATHS])
        assert kept == []

    def test_keeps_the_prefix_and_everything_under_it(self) -> None:
        with override_settings(VALI_PUBLIC_API_PATHS="/v1/vm"):
            kept = filter_to_public_paths(
                [_endpoint("/v1/vm"), _endpoint("/v1/vm/{vm_id}"), _endpoint("/v1/vm/launch")]
            )
        assert [e[0] for e in kept] == ["/v1/vm", "/v1/vm/{vm_id}", "/v1/vm/launch"]

    def test_drops_every_internal_path(self) -> None:
        with override_settings(VALI_PUBLIC_API_PATHS="/v1/vm"):
            kept = filter_to_public_paths([_endpoint(p) for p in INTERNAL_PATHS])
        assert kept == [], f"internal paths leaked into the public schema: {kept}"

    def test_an_exact_admin_path_does_not_publish_its_siblings(self) -> None:
        """`/v1/admin/audit/measurements` is published deliberately. It must
        stay EXACT: were it ever shortened to `/v1/admin`, both this filter
        and the Ingress (`pathType: Prefix`) would swallow the whole control
        plane. This asserts the filter itself does not generalise."""
        with override_settings(VALI_PUBLIC_API_PATHS="/v1/admin/audit/measurements"):
            kept = filter_to_public_paths(
                [
                    _endpoint("/v1/admin/audit/measurements"),
                    _endpoint("/v1/admin/miner/register"),
                    _endpoint("/v1/admin/host-attestor/release"),
                    _endpoint("/v1/admin/miner/{miner_id}/quarantine"),
                ]
            )
        assert [e[0] for e in kept] == ["/v1/admin/audit/measurements"]

    def test_prefix_match_is_path_segmented_not_substring(self) -> None:
        """`/v1/vm` must not drag in a sibling that merely starts with the
        same characters — the difference between a path prefix and a
        string prefix is exactly how an allow-list turns into a leak."""
        with override_settings(VALI_PUBLIC_API_PATHS="/v1/vm"):
            kept = filter_to_public_paths(
                [_endpoint("/v1/vmadmin"), _endpoint("/v1/vm-internal"), _endpoint("/v1/vm/ok")]
            )
        assert [e[0] for e in kept] == ["/v1/vm/ok"]


@pytest.mark.django_db
class TestServedDocument:
    """End-to-end through the real view, so a misconfigured
    PREPROCESSING_HOOKS (declared but never applied) is caught."""

    @override_settings(VALI_PUBLIC_API_PATHS="/v1/vm")
    def test_public_schema_serves_only_public_paths(self, client) -> None:
        resp = client.get(reverse("public-schema"))
        assert resp.status_code == 200
        body = resp.content.decode()
        assert "/v1/vm" in body
        for internal in INTERNAL_PATHS:
            stem = internal.split("{")[0].rstrip("/")
            assert f"\n  {stem}" not in body, f"{internal} is exposed publicly"

    @override_settings(VALI_PUBLIC_API_PATHS="/v1/vm")
    def test_private_schema_still_describes_everything(self, client) -> None:
        """The filter must not leak into the in-cluster document — an
        operator reading `/v1/schema` still needs the whole API."""
        resp = client.get(reverse("schema"))
        assert resp.status_code == 200
        assert "/v1/admin/miner/register" in resp.content.decode()
