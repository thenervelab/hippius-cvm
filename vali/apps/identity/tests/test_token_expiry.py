"""#32 — bounded service-token lifetimes, proven end to end.

Four properties, in the order they matter:

1. a token cannot be minted without an expiry (call site AND database);
2. an EXPIRED token is REFUSED at authentication — this is the
   load-bearing one, because a stored-but-unchecked `expires_at` is
   security theatre;
3. a valid unexpired token still authenticates (the anti-overshoot
   direction: a gate that refuses everything "passes" property 2);
4. migration `0004` leaves EXISTING rows in a defined state — the
   question that decides whether this is safe to deploy, since
   backfilling the three live control-plane credentials as
   already-expired would be an instant outage.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import IntegrityError, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import RequestFactory
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed

from apps.identity.authentication import (
    ServiceTokenAuthentication,
    resolve_principal,
)
from apps.identity.models import (
    TOKEN_LIFETIME_DAYS,
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)

pytestmark = pytest.mark.django_db


def _client(name: str = "ops") -> ServiceClient:
    return ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value, name=name
    )


# ────────────────────────────────────────────────────────────────────
# 1. A token cannot be minted without an expiry
# ────────────────────────────────────────────────────────────────────


def test_issue_requires_an_explicit_lifetime() -> None:
    """`lifetime` has NO default — a caller that does not choose one
    does not get a token at all. This is the call-site half of the
    guarantee; the DB half is `test_database_refuses_a_null_expiry`."""
    client = _client()
    with pytest.raises(TypeError, match="lifetime"):
        ServiceToken.issue(client=client, name="no-lifetime")  # type: ignore[call-arg]
    assert not ServiceToken.objects.filter(name="no-lifetime").exists()


@pytest.mark.parametrize("lifetime", sorted(TOKEN_LIFETIME_DAYS))
def test_issue_always_sets_an_expiry_from_the_lifetime_class(lifetime: str) -> None:
    client = _client()
    before = timezone.now()
    row, _plaintext = ServiceToken.issue(
        client=client, name=f"t-{lifetime}", lifetime=lifetime
    )
    assert row.expires_at is not None
    expected = before + timedelta(days=TOKEN_LIFETIME_DAYS[lifetime])
    # Within a second of the class TTL — `issue` reads the clock itself.
    assert abs((row.expires_at - expected).total_seconds()) < 5


def test_issue_rejects_an_unknown_lifetime() -> None:
    """An unrecognised class must NOT silently fall back to anything —
    a fallback is how a typo becomes a long-lived credential."""
    client = _client()
    with pytest.raises(ValueError, match="unknown token lifetime"):
        ServiceToken.issue(client=client, name="t", lifetime="forever")
    assert not ServiceToken.objects.filter(name="t").exists()


def test_issue_rejects_an_expiry_in_the_past() -> None:
    client = _client()
    with pytest.raises(ValueError, match="must be in the future"):
        ServiceToken.issue(
            client=client,
            name="t",
            lifetime=TokenLifetime.OPS.value,
            expires_at=timezone.now() - timedelta(hours=1),
        )


def test_issue_rejects_a_naive_expiry() -> None:
    """A naive datetime is ambiguous under USE_TZ; guessing at a
    credential's lifetime is worse than refusing."""
    from datetime import datetime

    client = _client()
    with pytest.raises(ValueError, match="timezone-aware"):
        ServiceToken.issue(
            client=client,
            name="t",
            lifetime=TokenLifetime.OPS.value,
            expires_at=datetime(2099, 1, 1),  # noqa: DTZ001 — deliberately naive
        )


def test_explicit_expiry_may_shorten_but_never_extend() -> None:
    """The lifetime class is a CEILING, not a suggestion — otherwise
    `--expires-days 36500` re-creates the skeleton key this closes."""
    client = _client()
    short = timezone.now() + timedelta(hours=1)
    row, _ = ServiceToken.issue(
        client=client, name="short", lifetime=TokenLifetime.OPS.value, expires_at=short
    )
    assert row.expires_at == short

    too_long = timezone.now() + timedelta(days=TOKEN_LIFETIME_DAYS["ops"] + 1)
    with pytest.raises(ValueError, match="lifetime ceiling"):
        ServiceToken.issue(
            client=client,
            name="long",
            lifetime=TokenLifetime.OPS.value,
            expires_at=too_long,
        )
    assert not ServiceToken.objects.filter(name="long").exists()


def test_database_refuses_a_null_expiry() -> None:
    """The rule, not the convention. `issue()` can be bypassed — by a
    `manage.py shell` insert, a data migration or raw SQL, which is how
    the three non-expiring production tokens came to exist. NOT NULL
    binds all of them."""
    client = _client()
    with pytest.raises(IntegrityError):
        ServiceToken.objects.create(
            client=client,
            name="null-expiry",
            token_sha256="0" * 64,
            expires_at=None,
        )


def test_admin_is_not_a_mint_path() -> None:
    """The Django admin can inspect and revoke tokens, never create
    them — minting belongs to `issue()`, which is where the lifetime
    policy lives."""
    from django.contrib import admin as django_admin

    from apps.identity.admin import ServiceTokenAdmin

    site_admin = ServiceTokenAdmin(ServiceToken, django_admin.site)
    assert site_admin.has_add_permission(None) is False


# ────────────────────────────────────────────────────────────────────
# 2 + 3. Enforcement at authentication — both directions
# ────────────────────────────────────────────────────────────────────


def _bearer(plaintext: str):
    return RequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {plaintext}")


def _expire(row: ServiceToken) -> None:
    row.expires_at = timezone.now() - timedelta(seconds=1)
    row.save(update_fields=["expires_at"])


def test_expired_token_is_refused_by_the_drf_backend() -> None:
    """LOAD-BEARING. A bounded lifetime that authentication ignores is
    a comment, not a control."""
    client = _client()
    row, plaintext = ServiceToken.issue(
        client=client, name="t", lifetime=TokenLifetime.SERVICE.value
    )
    _expire(row)
    with pytest.raises(AuthenticationFailed, match="expired"):
        ServiceTokenAuthentication().authenticate(_bearer(plaintext))


def test_expired_token_is_refused_by_resolve_principal() -> None:
    """The SECOND enforcement point. `PrincipalScopeMiddleware` resolves
    the principal itself, before DRF runs — if only the DRF backend
    checked expiry, an expired token would still carry its scope
    through the middleware's decisions."""
    client = _client()
    row, plaintext = ServiceToken.issue(
        client=client, name="t", lifetime=TokenLifetime.SERVICE.value
    )
    assert resolve_principal(_bearer(plaintext)) is not None  # sanity: it resolves
    _expire(row)
    assert resolve_principal(_bearer(plaintext)) is None


def test_expired_token_is_refused_even_though_the_row_is_still_active() -> None:
    """Expiry must bite on its own. `is_active` stays True here — the
    whole point of #32 is not needing anyone to remember to flip it."""
    client = _client()
    row, plaintext = ServiceToken.issue(
        client=client, name="t", lifetime=TokenLifetime.INFRA.value
    )
    _expire(row)
    row.refresh_from_db()
    assert row.is_active is True
    assert row.is_usable is False
    with pytest.raises(AuthenticationFailed, match="expired"):
        ServiceTokenAuthentication().authenticate(_bearer(plaintext))


def test_valid_unexpired_token_still_authenticates() -> None:
    """ANTI-OVERSHOOT. A gate that refuses everything also passes the
    expired-token test; this is the half that says the gate is a gate
    and not a wall."""
    client = _client()
    row, plaintext = ServiceToken.issue(
        client=client, name="t", lifetime=TokenLifetime.SERVICE.value
    )
    assert row.expires_at > timezone.now()
    principal, token = ServiceTokenAuthentication().authenticate(_bearer(plaintext))
    assert principal.pk == client.pk
    assert token.pk == row.pk
    assert resolve_principal(_bearer(plaintext)).pk == client.pk


def test_a_token_one_second_from_expiry_still_authenticates() -> None:
    """The boundary, in the permissive direction: expiry is `<= now`
    refused, not "expiring soon" refused."""
    client = _client()
    row, plaintext = ServiceToken.issue(
        client=client,
        name="t",
        lifetime=TokenLifetime.OPS.value,
        expires_at=timezone.now() + timedelta(seconds=30),
    )
    assert row.is_usable is True
    principal, _ = ServiceTokenAuthentication().authenticate(_bearer(plaintext))
    assert principal.pk == client.pk


# ────────────────────────────────────────────────────────────────────
# 4. What the migration does to rows that already exist
# ────────────────────────────────────────────────────────────────────

_IDENTITY_0003 = ("identity", "0003_serviceclient_authorization_scope")
_IDENTITY_0004 = ("identity", "0004_servicetoken_expires_at_required")


@pytest.mark.django_db(transaction=True)
def test_migration_0004_defines_every_pre_existing_row() -> None:
    """The merge-safety question, answered against the REAL migration.

    Rewinds the identity app to 0003 (where `expires_at` is nullable),
    creates the two populations production actually has — live
    credentials with a NULL expiry, and already-revoked ones — then
    runs 0004 forward and asserts each landed where the migration's
    docstring says.

    The assertion that matters for deploy safety is the FIRST one: a
    live credential must still be usable after the migration. Dating it
    at `now()` would 401 the synthetic monitor, the bake path and the
    Edge relay the moment the migration Job completed.
    """
    executor = MigrationExecutor(connection)
    executor.migrate([_IDENTITY_0003])

    old_apps = executor.loader.project_state([_IDENTITY_0003]).apps
    OldClient = old_apps.get_model("identity", "ServiceClient")
    OldToken = old_apps.get_model("identity", "ServiceToken")

    principal = OldClient.objects.create(name="orchestration-root-ish", scope="operator")
    live = OldToken.objects.create(
        client=principal,
        name="live-non-expiring",
        token_sha256="a" * 64,
        is_active=True,
        expires_at=None,
    )
    revoked = OldToken.objects.create(
        client=principal,
        name="already-revoked",
        token_sha256="b" * 64,
        is_active=False,
        expires_at=None,
    )
    # A row that already HAD an expiry must be left alone.
    untouched_at = timezone.now() + timedelta(days=3)
    untouched = OldToken.objects.create(
        client=principal,
        name="already-bounded",
        token_sha256="c" * 64,
        is_active=True,
        expires_at=untouched_at,
    )

    before = timezone.now()
    try:
        executor.loader.build_graph()
        executor.migrate([_IDENTITY_0004])

        live.refresh_from_db()
        revoked.refresh_from_db()
        untouched.refresh_from_db()

        # 1. LIVE credential: still usable, with a real deadline.
        #    NOT `now()` — that is the instant-outage mutant.
        assert live.expires_at is not None
        assert live.expires_at > before + timedelta(days=80), (
            "a live credential was backfilled with a near-term expiry — "
            "deploying this would 401 the control plane"
        )
        assert live.expires_at < before + timedelta(days=100)

        # 2. ALREADY-REVOKED: dated in the past. It could not
        #    authenticate before (auth filters is_active=True) and it
        #    cannot be resurrected into a usable credential by mistake.
        assert revoked.expires_at is not None
        assert revoked.expires_at <= before

        # 3. Rows that already had an expiry are NOT rewritten.
        assert abs((untouched.expires_at - untouched_at).total_seconds()) < 1

        # 4. And the column is now NOT NULL for everything after.
        with pytest.raises(IntegrityError):
            ServiceToken.objects.create(
                client=ServiceClient.objects.get(pk=principal.pk),
                name="post-migration-null",
                token_sha256="d" * 64,
                expires_at=None,
            )
    finally:
        # Leave the schema where the rest of the suite expects it: EVERY
        # leaf, not just identity 0004 — going back to 0003 also unapplied
        # the migrations of other apps that depend on 0004.
        executor.loader.build_graph()
        executor.migrate(executor.loader.graph.leaf_nodes())
