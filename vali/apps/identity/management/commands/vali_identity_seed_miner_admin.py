"""`vali_identity_seed_miner_admin` — bootstrap the miner-admin principal.

`POST /v1/admin/miner/register` is gated by `apps.miners.permissions.
IsMinerAdmin`, which only accepts the single `ServiceClient` named by
`settings.VALI_MINER_ADMIN_PRINCIPAL`. This command is the operator
surface that seeds that principal AND issues its bearer token — the
runbook is `vali/apps/miners/README.md`.

Idempotent by design: a re-run finds the principal already present,
finds the named token already issued, and EXITS SUCCESS without
issuing anything new (the plaintext was shown ONCE — the operator
captured it, and vali has no recovery path; rotation = a fresh
``--token-name`` or `--rotate`).

    manage.py vali_identity_seed_miner_admin             # bootstrap
    manage.py vali_identity_seed_miner_admin --token-name ops-2026q2
    manage.py vali_identity_seed_miner_admin --rotate    # mint a fresh token

`--rotate` is non-destructive: it issues a *new* token under an
auto-generated `bootstrap-<random>` name (random hex suffix, not a
wall-clock second — so two back-to-back rotations never collide on the
`(client, name)` unique constraint) and leaves the previous tokens
active so a running ops script does not break mid-rotation. Disable old
tokens in Django admin or via SQL once the new one is in use.

`--rotate` and `--token-name` are mutually exclusive: passing both is
rejected (a quiet ignore would mint a token under a name the operator
did not ask for, which is the kind of surprise an ops runbook must
not have).

#32 — the issued token EXPIRES. `--lifetime` defaults to `service`
(90 days) here, unlike `vali_identity_issue_token` where it is
required: this command mints exactly one kind of credential (the
long-lived in-cluster miner-admin principal), so the class is known by
construction and a required flag would only be ceremony. Defaulting to
the shortest class (`ops`, 7 days) would be the worse mistake — a
bootstrap credential that dies a week after a deploy is precisely the
silently-broken-credential failure this command exists to avoid.
"""

from __future__ import annotations

import secrets
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.identity.models import (
    TOKEN_LIFETIME_DAYS,
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)

# Default token label — matches the runbook in vali/apps/miners/README.md.
_DEFAULT_TOKEN_NAME = "bootstrap"


class Command(BaseCommand):
    help = (
        "Seed the miner-admin ServiceClient + issue its bearer token. "
        "Idempotent: a re-run is a no-op unless --rotate is passed."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--token-name",
            default=_DEFAULT_TOKEN_NAME,
            help=(
                "Human label for the issued ServiceToken row (not a "
                "secret). A re-run with the SAME name is a no-op; a "
                "different name issues a second active token."
            ),
        )
        parser.add_argument(
            "--rotate",
            action="store_true",
            help=(
                "Mint a fresh token under an auto-generated name "
                "(`bootstrap-<random>`). Previous tokens stay active — "
                "disable them out of band once the new one is in use. "
                "Mutually exclusive with `--token-name`."
            ),
        )
        parser.add_argument(
            "--lifetime",
            default=TokenLifetime.SERVICE.value,
            choices=sorted(TOKEN_LIFETIME_DAYS),
            help=(
                "Token lifetime class (default: service = "
                f"{TOKEN_LIFETIME_DAYS[TokenLifetime.SERVICE.value]} days). "
                "See apps.identity.models.TokenLifetime."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        principal = (settings.VALI_MINER_ADMIN_PRINCIPAL or "").strip()
        if not principal:
            # Fail closed: without a pinned principal `IsMinerAdmin`
            # denies every request, so seeding a nameless client would
            # never serve as the admin. The deploy must set the env var
            # (see deploy/gitops/apps/vali/values.yaml config block).
            raise CommandError(
                "VALI_MINER_ADMIN_PRINCIPAL is unset — refusing to seed "
                "an anonymous principal. Set it in the vali ConfigMap "
                "and re-run."
            )

        rotate: bool = options["rotate"]
        # `--rotate` and `--token-name` are mutually exclusive — a
        # silent ignore would mint a token under a name the operator
        # did not ask for. Detect a non-default `--token-name` via the
        # parser's default sentinel.
        if rotate and options["token_name"] != _DEFAULT_TOKEN_NAME:
            raise CommandError(
                "--rotate and --token-name are mutually exclusive; "
                "--rotate always mints under `bootstrap-<random>`."
            )
        # The rotation suffix is a 4-byte hex string (8 chars, 32 bits
        # of entropy), NOT a wall-clock second — two `--rotate` calls
        # back to back can never collide on the `(client, name)`
        # unique constraint.
        token_name: str = (
            f"bootstrap-{secrets.token_hex(4)}"
            if rotate
            else options["token_name"].strip()
        )
        if not token_name:
            raise CommandError("--token-name must not be empty")

        with transaction.atomic():
            client, created = ServiceClient.objects.get_or_create(
                name=principal,
                defaults={
                    "description": (
                        "Miner-admin principal — registers / quarantines "
                        "compute miners. Seeded by "
                        "`manage.py vali_identity_seed_miner_admin`."
                    ),
                    # P2: miner administration is a fleet-wide (therefore
                    # cross-tenant) power, and `IsMinerAdmin` now requires
                    # the explicit operator scope. Seed it here so the
                    # command keeps producing a WORKING credential.
                    "scope": PrincipalScope.OPERATOR.value,
                },
            )
            if not client.is_active:
                # An operator disabled the principal out of band — fail
                # loud rather than silently re-issue against an inactive
                # client (its tokens would authenticate to nothing).
                raise CommandError(
                    f"ServiceClient {principal!r} exists but is_active=False — "
                    "re-enable it in Django admin before re-running."
                )

            existing = ServiceToken.objects.filter(
                client=client, name=token_name
            ).first()
            if existing is not None and not rotate:
                # Idempotent no-op: the plaintext was shown once on the
                # original run; remind the operator how to recover.
                self.stdout.write(
                    f"miner-admin principal {principal!r} already seeded "
                    f"(token {token_name!r} present). The plaintext was "
                    f"shown ONCE at issuance; if lost, re-run with "
                    f"--rotate to mint a fresh token."
                )
                return

            row, plaintext = ServiceToken.issue(
                client=client,
                name=token_name,
                lifetime=str(options["lifetime"]),
            )

        verb = "seeded" if created else "updated"
        self.stdout.write(
            f"miner-admin principal {verb}: name={principal!r} "
            f"token_name={token_name!r} lifetime={options['lifetime']!r} "
            f"expires_at={row.expires_at.isoformat()}"
        )
        self.stdout.write(
            "Token plaintext (shown ONCE — capture it now; vali has no recovery path):"
        )
        # The plaintext on its OWN line, so a shell capture (e.g.
        # `... | tail -1`) gets exactly the token, no ornamentation.
        self.stdout.write(plaintext)
