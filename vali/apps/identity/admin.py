"""Django admin registrations for `apps.identity` (#152).

Ops eyeball surface only — the admin lives on the cluster-internal
`/admin/` route (vali Service is ClusterIP, never Ingress-exposed).

Secrets discipline: a `ServiceToken.token_sha256` is a SHA-256 digest
of the plaintext bearer token, but it is still the value the auth
backend looks up by — a leaked digest is enough to brute-force-search
a database dump for a matching token. Treat it as sensitive: the
admin **never** exposes it via `list_display`, and it is forced
read-only on the change form so an operator can't accidentally rewrite
it from the UI. Token rotation goes through
`vali_identity_seed_miner_admin --rotate` (or, eventually, an
operator-facing service); the admin is read-mostly.
"""

from __future__ import annotations

from django.contrib import admin

from .models import ServiceClient, ServiceToken


@admin.register(ServiceClient)
class ServiceClientAdmin(admin.ModelAdmin):
    # `scope` is surfaced FIRST-CLASS (list column + filter): it is the
    # difference between a credential that sees one tenant and one that
    # sees the whole fleet, so an operator must be able to audit it at a
    # glance. See `PrincipalScope` for how the operator grant is issued —
    # this admin and `manage.py vali_identity_issue_token` are the only
    # two paths; no HTTP endpoint can create or re-scope a principal.
    list_display = ("name", "scope", "tenant_id", "is_active", "created_at", "updated_at")
    list_filter = ("scope", "is_active")
    search_fields = ("name", "description", "tenant_id")
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("name",)


@admin.register(ServiceToken)
class ServiceTokenAdmin(admin.ModelAdmin):
    list_display = (
        "client",
        "name",
        "is_active",
        "expires_at",
        "last_used_at",
        "created_at",
    )
    list_filter = ("is_active", "client")
    search_fields = ("name", "client__name")
    # `token_sha256` is sensitive (see module docstring): readonly on
    # the change form, and excluded from `list_display` so the
    # changelist page never renders it.
    readonly_fields = (
        "id",
        "token_sha256",
        "created_at",
        "last_used_at",
    )
    ordering = ("-created_at",)

    def has_add_permission(self, _request) -> bool:
        """The admin is NOT a mint path (#32).

        `token_sha256` is read-only here, so an admin "add" could only
        ever produce a row with an empty digest — a token nobody holds.
        More importantly, minting belongs to `ServiceToken.issue`, which
        is where the lifetime policy lives; a second door into the table
        is a door that policy does not cover. Mint with
        `manage.py vali_identity_issue_token`.
        """
        return False
