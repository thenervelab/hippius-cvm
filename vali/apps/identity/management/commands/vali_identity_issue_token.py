"""Issue a `ServiceToken` with an EXPLICIT authorization scope (P2).

This is the operator path for minting a vali credential. The scope is
REQUIRED — exactly one of:

    --operator              cross-tenant reach (the upstream product API)
    --tenant-id <TENANT>    confined to one tenant

There is deliberately no default. A credential whose reach nobody chose
is `unclassified`, and `PrincipalScopeMiddleware` refuses those on the
whole non-public `/v1/` surface, so the failure mode of forgetting is a
loud 403 rather than a silent god-token.

vali exposes NO HTTP endpoint that creates or re-scopes a
`ServiceClient` (`apps.identity` has no urls/views), so this command and
the cluster-internal Django admin are the only ways to grant `--operator`
— both require exec/port-forward access to the cluster. A tenant-scoped
principal therefore cannot promote itself: it has no API to call, and the
`identity_serviceclient_tenant_scope_consistent` DB constraint refuses
the `operator + tenant_id` combination outright.

`--lifetime` is REQUIRED for the same reason (#32) and takes the same
shape. Every token expires; what the operator chooses is the CLASS, and
the class decides the duration (`TOKEN_LIFETIME_DAYS`):

    --lifetime ops       7 days    human-held, incident/one-off
    --lifetime service  90 days    in-cluster machine principal
    --lifetime infra   365 days    unattended cross-namespace relay

`--expires-days` may SHORTEN a token below its class, never extend it.

Examples:

    manage.py vali_identity_issue_token --client upstream-api \\
        --token-name prod-2026q3 --operator --lifetime service

    manage.py vali_identity_issue_token --client acme-portal \\
        --token-name prod --tenant-id acme --lifetime service

    manage.py vali_identity_issue_token --client oncall-jdb \\
        --token-name incident-4471 --operator --lifetime ops \\
        --expires-days 1

The plaintext token is printed ONCE and never persisted (only its
SHA-256). Rotation = issue a new token and deactivate the old one; the
procedure that does that WITHOUT an outage is
`docs/operator/vali-service-token-rotation-runbook.md`.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.identity.models import (
    TOKEN_LIFETIME_DAYS,
    PrincipalScope,
    ServiceClient,
    ServiceToken,
)


class Command(BaseCommand):
    help = (
        "Issue a ServiceToken with an explicit authorization scope "
        "(--operator XOR --tenant-id). Prints the plaintext ONCE."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--client",
            required=True,
            help="ServiceClient name (created if absent).",
        )
        parser.add_argument(
            "--token-name",
            required=True,
            help="Human label for this token (e.g. 'prod-2026q3'). Not a secret.",
        )
        parser.add_argument(
            "--description",
            default="",
            help="Optional description, recorded on a newly created client.",
        )
        # #32 — REQUIRED, no default, for the same reason the scope has
        # none: the value that is safe for a throwaway ops token is the
        # value that silently kills an unattended relay a week later.
        parser.add_argument(
            "--lifetime",
            required=True,
            choices=sorted(TOKEN_LIFETIME_DAYS),
            help=(
                "Token lifetime class — "
                + ", ".join(
                    f"{k}={TOKEN_LIFETIME_DAYS[k]}d"
                    for k in sorted(TOKEN_LIFETIME_DAYS, key=TOKEN_LIFETIME_DAYS.get)
                )
                + ". See apps.identity.models.TokenLifetime."
            ),
        )
        parser.add_argument(
            "--expires-days",
            type=int,
            default=None,
            help=(
                "Optional: expire in N days instead of the class default. "
                "May only SHORTEN the class lifetime, never extend it."
            ),
        )
        scope = parser.add_mutually_exclusive_group(required=True)
        scope.add_argument(
            "--operator",
            action="store_true",
            help="Grant CROSS-TENANT reach. Use only for the upstream API / infra.",
        )
        scope.add_argument(
            "--tenant-id",
            default="",
            help="Confine the credential to this tenant.",
        )

    @transaction.atomic
    def handle(self, *_args: Any, **opts: Any) -> None:
        name = (opts["client"] or "").strip()
        token_name = (opts["token_name"] or "").strip()
        tenant_id = (opts["tenant_id"] or "").strip()
        if not name:
            raise CommandError("--client must not be empty")
        if not token_name:
            raise CommandError("--token-name must not be empty")
        lifetime = str(opts["lifetime"])
        expires_days = opts["expires_days"]
        expires_at = None
        if expires_days is not None:
            if expires_days < 1:
                raise CommandError("--expires-days must be >= 1")
            if expires_days > TOKEN_LIFETIME_DAYS[lifetime]:
                raise CommandError(
                    f"--expires-days {expires_days} exceeds the {lifetime!r} "
                    f"lifetime ({TOKEN_LIFETIME_DAYS[lifetime]} days); pick a "
                    "longer-lived --lifetime class deliberately instead."
                )
            expires_at = timezone.now() + timedelta(days=expires_days)
        if opts["operator"]:
            scope, tenant_id = PrincipalScope.OPERATOR.value, ""
        else:
            if not tenant_id:
                raise CommandError("--tenant-id must not be empty")
            scope = PrincipalScope.TENANT.value

        client, created = ServiceClient.objects.get_or_create(
            name=name,
            defaults={
                "description": opts["description"],
                "scope": scope,
                "tenant_id": tenant_id,
            },
        )
        if not created:
            if not client.is_active:
                raise CommandError(
                    f"ServiceClient {name!r} exists but is_active=False — "
                    "re-enable it before issuing a token."
                )
            if (client.scope, client.tenant_id) != (scope, tenant_id):
                # Re-scoping an EXISTING principal silently would change the
                # reach of every token already issued against it. Refuse.
                raise CommandError(
                    f"ServiceClient {name!r} is already scope={client.scope!r} "
                    f"tenant_id={client.tenant_id!r}; refusing to re-scope it to "
                    f"scope={scope!r} tenant_id={tenant_id!r} while issuing a "
                    "token (that would silently change every existing token's "
                    "reach). Change the scope deliberately in the Django admin."
                )

        if ServiceToken.objects.filter(client=client, name=token_name).exists():
            raise CommandError(
                f"token {token_name!r} already exists for client {name!r} — "
                "pick another --token-name (the plaintext cannot be recovered)."
            )

        row, plaintext = ServiceToken.issue(
            client=client,
            name=token_name,
            lifetime=lifetime,
            expires_at=expires_at,
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"issued token {token_name!r} for {name!r} "
                f"(scope={scope}"
                + (f", tenant_id={tenant_id}" if tenant_id else "")
                + f", lifetime={lifetime}, expires_at={row.expires_at.isoformat()})"
            )
        )
        self.stdout.write("token (shown ONCE, not recoverable):")
        self.stdout.write(plaintext)
