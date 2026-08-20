"""#32 — the operator surfaces: minting with a lifetime, and revoking
the old credential WITHOUT taking the principal offline.

`vali_identity_issue_token` is the only production mint path, so the
lifetime must be unavoidable there. `vali_identity_deactivate_token` is
step 3 of the rotation runbook
(`docs/operator/vali-service-token-rotation-runbook.md`), and the thing
it has to make hard is doing step 3 before step 2 has landed.
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.identity.models import (
    TOKEN_LIFETIME_DAYS,
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)

pytestmark = pytest.mark.django_db


def _issue(*args: str) -> str:
    buf = StringIO()
    call_command("vali_identity_issue_token", *args, stdout=buf)
    return buf.getvalue()


def _deactivate(*args: str) -> str:
    buf = StringIO()
    call_command("vali_identity_deactivate_token", *args, stdout=buf)
    return buf.getvalue()


# ────────────────────────────────────────────────────────────────────
# Minting
# ────────────────────────────────────────────────────────────────────


def test_issue_command_requires_lifetime() -> None:
    """argparse `required=True` — the command cannot be driven into
    minting something unbounded, not even by omission."""
    with pytest.raises((CommandError, SystemExit)):
        call_command(
            "vali_identity_issue_token",
            "--client",
            "svc",
            "--token-name",
            "t",
            "--operator",
        )
    assert not ServiceClient.objects.filter(name="svc").exists()


@pytest.mark.parametrize("lifetime", sorted(TOKEN_LIFETIME_DAYS))
def test_issue_command_stamps_the_class_expiry(lifetime: str) -> None:
    before = timezone.now()
    out = _issue(
        "--client", f"svc-{lifetime}",
        "--token-name", "t",
        "--operator",
        "--lifetime", lifetime,
    )
    row = ServiceToken.objects.get(client__name=f"svc-{lifetime}", name="t")
    assert row.expires_at is not None
    assert row.expires_at > before + timedelta(
        days=TOKEN_LIFETIME_DAYS[lifetime] - 1
    )
    # The operator is told the deadline, not left to infer it.
    assert row.expires_at.isoformat() in out


def test_issue_command_expires_days_may_only_shorten() -> None:
    with pytest.raises(CommandError, match="exceeds the 'ops' lifetime"):
        _issue(
            "--client", "svc",
            "--token-name", "t",
            "--operator",
            "--lifetime", "ops",
            "--expires-days", str(TOKEN_LIFETIME_DAYS["ops"] + 1),
        )
    _issue(
        "--client", "svc",
        "--token-name", "t",
        "--operator",
        "--lifetime", "ops",
        "--expires-days", "1",
    )
    row = ServiceToken.objects.get(client__name="svc", name="t")
    assert row.expires_at < timezone.now() + timedelta(days=1, minutes=1)


def test_seed_miner_admin_issues_an_expiring_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.conf import settings

    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "miner-admin-32")
    call_command("vali_identity_seed_miner_admin", stdout=StringIO())
    row = ServiceToken.objects.get(client__name="miner-admin-32")
    assert row.expires_at is not None
    # Defaults to `service`, NOT to the shortest class — a bootstrap
    # credential that dies a week after deploy is the failure this
    # command exists to avoid.
    assert row.expires_at > timezone.now() + timedelta(
        days=TOKEN_LIFETIME_DAYS[TokenLifetime.SERVICE.value] - 1
    )


# ────────────────────────────────────────────────────────────────────
# Revoking — the step that causes outages when it runs too early
# ────────────────────────────────────────────────────────────────────


def _principal_with(*names: str) -> ServiceClient:
    client = ServiceClient.objects.create(
        name="rot", scope=PrincipalScope.OPERATOR.value
    )
    for n in names:
        ServiceToken.issue(client=client, name=n, lifetime=TokenLifetime.SERVICE.value)
    return client


def test_deactivate_refuses_the_last_usable_credential() -> None:
    """The guard. Deactivating the only working credential of a hot
    principal is a revocation wearing a rotation's clothes."""
    _principal_with("only")
    with pytest.raises(CommandError, match="LAST usable credential"):
        _deactivate("--client", "rot", "--token-name", "only")
    assert ServiceToken.objects.get(name="only").is_active is True


def test_deactivate_allows_the_last_one_when_the_operator_says_revoke() -> None:
    _principal_with("only")
    _deactivate("--client", "rot", "--token-name", "only", "--revoke-last")
    assert ServiceToken.objects.get(name="only").is_active is False


def test_deactivate_succeeds_once_a_successor_exists() -> None:
    """The rotation shape: mint new, then retire old. Both are valid
    at once (`client` is a ForeignKey, auth resolves by digest), which
    is what makes the overlap zero-downtime."""
    _principal_with("old", "new")
    _deactivate("--client", "rot", "--token-name", "old")
    assert ServiceToken.objects.get(name="old").is_active is False
    assert ServiceToken.objects.get(name="new").is_active is True


def test_deactivate_does_not_count_an_expired_successor() -> None:
    """`is_usable`, not `is_active`. A successor that is itself already
    expired is not a successor — counting it would let the guard wave
    through the exact outage it exists to prevent."""
    client = _principal_with("old", "new")
    dead = ServiceToken.objects.get(client=client, name="new")
    dead.expires_at = timezone.now() - timedelta(seconds=1)
    dead.save(update_fields=["expires_at"])
    with pytest.raises(CommandError, match="LAST usable credential"):
        _deactivate("--client", "rot", "--token-name", "old")


def test_deactivate_dry_run_changes_nothing_and_reports_usability() -> None:
    _principal_with("old", "new")
    out = _deactivate("--client", "rot", "--dry-run")
    assert "2 usable credential(s)" in out
    assert "'old'" in out and "'new'" in out
    assert ServiceToken.objects.filter(is_active=True).count() == 2


def test_deactivate_never_prints_a_digest() -> None:
    """Secrets discipline: the inventory an operator reads during a
    rotation must not carry the value that indexes the auth lookup."""
    client = _principal_with("old", "new")
    out = _deactivate("--client", "rot", "--dry-run")
    for row in client.tokens.all():
        assert row.token_sha256 not in out
