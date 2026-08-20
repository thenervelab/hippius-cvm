"""Tests for `vali_identity_seed_miner_admin` — the miner-admin
bootstrap management command.

The command is the operator surface that seeds the `ServiceClient` the
`apps.miners.permissions.IsMinerAdmin` permission gates on. These tests
freeze the contract:

- it FAILS CLOSED when `settings.VALI_MINER_ADMIN_PRINCIPAL` is unset;
- a first run creates the principal AND issues a token plaintext;
- a re-run with the same `--token-name` is a no-op success (the token
  plaintext was shown ONCE; nothing fresh is minted);
- `--rotate` issues a new token under an auto-generated name, leaving
  the previous tokens active;
- the issued token actually authenticates as the seeded principal.
"""

from __future__ import annotations

import hashlib
from io import StringIO

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command

from apps.identity.models import PrincipalScope, ServiceClient, ServiceToken

pytestmark = pytest.mark.django_db


_PRINCIPAL = "miner-admin"


@pytest.fixture(autouse=True)
def _pin_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin `VALI_MINER_ADMIN_PRINCIPAL` for every test in this file."""
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", _PRINCIPAL)


def _run(*args: str) -> str:
    """Run the command and return its captured stdout."""
    buf = StringIO()
    call_command("vali_identity_seed_miner_admin", *args, stdout=buf)
    return buf.getvalue()


# ────────────────────────────────────────────────────────────────────
# Fail-closed guards
# ────────────────────────────────────────────────────────────────────


def test_unset_principal_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a pinned principal the command refuses to seed an
    anonymous client — `IsMinerAdmin` would deny every request anyway."""
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "")
    with pytest.raises(CommandError, match="VALI_MINER_ADMIN_PRINCIPAL is unset"):
        _run()


def test_whitespace_only_principal_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A whitespace-only value (e.g. a ConfigMap with a stray newline)
    normalises to empty after `.strip()` and is refused — never seeded
    as an anonymous client. Pairs with the symmetric `.strip()` in
    `apps.miners.permissions.IsMinerAdmin` (see `test_permissions.py`)."""
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "   \n\t ")
    with pytest.raises(CommandError, match="VALI_MINER_ADMIN_PRINCIPAL is unset"):
        _run()


def test_inactive_principal_fails_loud() -> None:
    """An operator who disabled the client out of band must re-enable
    it explicitly — the command never silently issues against an
    inactive principal."""
    ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name=_PRINCIPAL,
        is_active=False,
    )
    with pytest.raises(CommandError, match="is_active=False"):
        _run()


def test_empty_token_name_fails_loud() -> None:
    with pytest.raises(CommandError, match="--token-name must not be empty"):
        _run("--token-name", "   ")


def test_rotate_with_explicit_token_name_is_rejected() -> None:
    """`--rotate` and `--token-name` are mutually exclusive — a silent
    ignore would mint a token under a name the operator didn't ask for."""
    with pytest.raises(
        CommandError, match="--rotate and --token-name are mutually exclusive"
    ):
        _run("--rotate", "--token-name", "ops-2026q2")


# ────────────────────────────────────────────────────────────────────
# Happy path: first run seeds + issues a usable token
# ────────────────────────────────────────────────────────────────────


def test_first_run_seeds_principal_and_issues_token() -> None:
    out = _run()
    # The principal is created.
    client = ServiceClient.objects.get(name=_PRINCIPAL)
    assert client.is_active
    # Exactly one token, named `bootstrap` by default.
    tokens = ServiceToken.objects.filter(client=client)
    assert tokens.count() == 1
    assert tokens.get().name == "bootstrap"
    # The plaintext is on a line of its own — a `tail -1` capture works.
    last_line = out.strip().splitlines()[-1]
    assert last_line  # non-empty
    # ...and its SHA-256 matches the stored hash.
    digest = hashlib.sha256(last_line.encode("ascii")).hexdigest()
    assert tokens.get().token_sha256 == digest


def test_issued_token_authenticates_as_the_admin_principal() -> None:
    """End-to-end: the printed plaintext, used as a Bearer header,
    resolves to the seeded admin principal via `ServiceTokenAuthentication`."""
    from rest_framework.test import APIRequestFactory

    from apps.identity.authentication import ServiceTokenAuthentication

    plaintext = _run().strip().splitlines()[-1]
    request = APIRequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    auth_user, _row = ServiceTokenAuthentication().authenticate(request)
    assert isinstance(auth_user, ServiceClient)
    assert auth_user.name == _PRINCIPAL


# ────────────────────────────────────────────────────────────────────
# Idempotency
# ────────────────────────────────────────────────────────────────────


def test_rerun_with_same_token_name_is_a_noop_success() -> None:
    _run()
    token_count_before = ServiceToken.objects.count()
    out = _run()
    # The principal + token are not duplicated.
    assert ServiceClient.objects.filter(name=_PRINCIPAL).count() == 1
    assert ServiceToken.objects.count() == token_count_before
    # The operator gets a clear message + the recovery hint.
    assert "already seeded" in out
    assert "--rotate" in out


def test_different_token_name_issues_a_second_token() -> None:
    _run()
    out = _run("--token-name", "ops-2026q2")
    assert ServiceToken.objects.count() == 2
    names = set(ServiceToken.objects.values_list("name", flat=True))
    assert names == {"bootstrap", "ops-2026q2"}
    # The new plaintext is printed on its own line.
    assert out.strip().splitlines()[-1]


def test_rotate_mints_a_fresh_token_under_a_new_name() -> None:
    _run()
    out = _run("--rotate")
    # Original token survives — rotation is non-destructive.
    tokens = list(ServiceToken.objects.all())
    assert len(tokens) == 2
    assert all(t.is_active for t in tokens)
    # The new token's name carries the `bootstrap-<random>` prefix.
    new_name = next(t.name for t in tokens if t.name != "bootstrap")
    assert new_name.startswith("bootstrap-")
    # ...and the fresh plaintext is printed (different from any previous).
    assert out.strip().splitlines()[-1]


def test_back_to_back_rotates_do_not_collide_on_name() -> None:
    """The rotation suffix is random-hex (32 bits of entropy), NOT a
    wall-clock second — two `--rotate` invocations back to back issue
    distinct tokens, never collide on the `(client, name)` unique
    constraint."""
    _run()
    _run("--rotate")
    _run("--rotate")
    tokens = list(ServiceToken.objects.all())
    assert len(tokens) == 3
    # Three distinct names: `bootstrap`, plus two random-suffix entries.
    assert len({t.name for t in tokens}) == 3
