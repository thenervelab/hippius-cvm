"""`vali_identity_deactivate_token` — the last step of a rotation (#32).

Rotation without an outage is three moves, in this order:

    1. mint the NEW token      `vali_identity_issue_token --lifetime …`
    2. update the consumer     (Vault / Secret) and roll it
    3. deactivate the OLD one  ← this command

Step 3 is the one that breaks things when it is done too early, so this
command is built to make "too early" hard:

- `--dry-run` prints the client's full token inventory (names,
  `is_active`, `expires_at`, `last_used_at`) and changes nothing. That
  inventory is how step 2 is verified: the NEW token's `last_used_at`
  must have advanced past the roll, and the OLD one's must have stopped
  moving. Never revoke a credential you have not watched go idle.
- deactivating the LAST usable credential of a principal is REFUSED
  unless `--revoke-last` is passed. That is the difference between a
  rotation (there is a successor) and a revocation (there deliberately
  is not), and it is exactly the mistake that takes a hot path down.

`ServiceToken.client` is a ForeignKey, not OneToOne, and authentication
resolves by the PRESENTED token's digest — so old and new authenticate
simultaneously and the overlap is genuinely zero-downtime.

No plaintext is read, printed or recoverable here; only the row's
metadata is touched.

    manage.py vali_identity_deactivate_token --client orchestration-root --dry-run
    manage.py vali_identity_deactivate_token --client orchestration-root \\
        --token-name synthetic-monitor-2026q3
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.identity.models import ServiceClient, ServiceToken


def _fmt(row: ServiceToken) -> str:
    return (
        f"  {row.name!r:40} active={str(row.is_active):5} "
        f"usable={str(row.is_usable):5} "
        f"expires_at={row.expires_at.isoformat()} "
        f"last_used_at={row.last_used_at.isoformat() if row.last_used_at else '-'}"
    )


class Command(BaseCommand):
    help = (
        "Deactivate a ServiceToken (rotation step 3). Refuses to leave a "
        "principal with zero usable credentials unless --revoke-last."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--client", required=True, help="ServiceClient name.")
        parser.add_argument(
            "--token-name",
            default="",
            help="Token label to deactivate. Not needed with --dry-run.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print the client's token inventory and change nothing.",
        )
        parser.add_argument(
            "--revoke-last",
            action="store_true",
            help=(
                "Allow deactivating the principal's LAST usable credential. "
                "This is a revocation, not a rotation — the principal stops "
                "authenticating the moment it completes."
            ),
        )

    @transaction.atomic
    def handle(self, *_args: Any, **opts: Any) -> None:
        client_name = (opts["client"] or "").strip()
        token_name = (opts["token_name"] or "").strip()
        if not client_name:
            raise CommandError("--client must not be empty")

        try:
            client = ServiceClient.objects.get(name=client_name)
        except ServiceClient.DoesNotExist as exc:
            raise CommandError(f"no ServiceClient named {client_name!r}") from exc

        rows = list(client.tokens.select_related("client").all())
        self.stdout.write(
            f"client {client_name!r} (scope={client.scope}, "
            f"is_active={client.is_active}) — {len(rows)} token(s):"
        )
        for row in rows:
            self.stdout.write(_fmt(row))

        if opts["dry_run"]:
            usable = [r for r in rows if r.is_usable]
            self.stdout.write(
                self.style.SUCCESS(
                    f"dry-run: {len(usable)} usable credential(s); nothing changed."
                )
            )
            return

        if not token_name:
            raise CommandError("--token-name is required unless --dry-run")
        target = next((r for r in rows if r.name == token_name), None)
        if target is None:
            raise CommandError(
                f"client {client_name!r} has no token named {token_name!r}"
            )
        if not target.is_active:
            self.stdout.write(
                f"token {token_name!r} is already is_active=False — no-op."
            )
            return

        # The guard: would this leave the principal with nothing that
        # authenticates? Computed from the SAME predicate the auth path
        # uses (`ServiceToken.is_usable`), not from `is_active` alone —
        # a successor that is itself already expired is not a successor.
        survivors = [r for r in rows if r.pk != target.pk and r.is_usable]
        if not survivors and not opts["revoke_last"]:
            raise CommandError(
                f"refusing: {token_name!r} is the LAST usable credential of "
                f"{client_name!r}. Mint and roll a successor first "
                "(vali_identity_issue_token → update the consumer → re-run "
                "--dry-run and confirm the new token's last_used_at has "
                "advanced). Pass --revoke-last if you genuinely intend to "
                "revoke this principal's access."
            )

        target.is_active = False
        target.save(update_fields=["is_active"])
        self.stdout.write(
            self.style.SUCCESS(
                f"deactivated {client_name!r}:{token_name!r}; "
                f"{len(survivors)} usable credential(s) remain."
            )
        )
