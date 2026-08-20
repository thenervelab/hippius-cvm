"""`seed_admin_user` — bootstrap the Django-admin superuser (#152).

The Django admin (`/admin/`, see `vali.urls`) authenticates against
the standard `django.contrib.auth.User` table — separate from the
`ServiceClient` / `ServiceToken` registry that gates the API surface.
This command is the operator entrypoint for creating that first
superuser inside a fresh vali deployment.

Idempotent by design: a re-run finds the named user already present
AND already flagged superuser, then EXITS SUCCESS without touching
anything. The first run mints a password from either an explicit env
var (CI / non-interactive deploys) or an interactive prompt
(`getpass`, never echoed — operator's terminal).

    # CI / scripted (Kubernetes Job, ansible, …):
    DJANGO_SUPERUSER_PASSWORD=… \\
        manage.py seed_admin_user --username ops

    # Interactive (a human runs it under `kubectl exec`):
    manage.py seed_admin_user --username ops

A name collision with an EXISTING NON-superuser is rejected
(`CommandError`) — silently promoting some unrelated `User` row to
superuser is exactly the kind of surprise a privilege-escalation
audit chases. The fix is to pick a different `--username`.
"""

from __future__ import annotations

import getpass
import os
import sys
from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

# Env var name the Django convention uses for this — kept identical
# so deploy YAML written for `createsuperuser --no-input` does not
# need a rename to point at this command.
_PASSWORD_ENV = "DJANGO_SUPERUSER_PASSWORD"


class Command(BaseCommand):
    help = (
        "Seed the Django-admin superuser. Idempotent: a re-run on a "
        "pre-existing superuser of the same name is a no-op."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--username",
            required=True,
            help=(
                "The superuser's username (Django auth.User.username). "
                "Pick a stable handle — re-runs key off this value."
            ),
        )
        parser.add_argument(
            "--email",
            default="",
            help=(
                "Optional email recorded on the User row. Not used "
                "for login — the admin uses username + password only."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        username = options["username"].strip()
        if not username:
            raise CommandError("--username must not be empty")
        email = options["email"].strip()

        User = get_user_model()
        with transaction.atomic():
            existing = User.objects.filter(username=username).first()
            if existing is not None:
                if not (existing.is_superuser and existing.is_staff and existing.is_active):
                    # A non-superuser of the same name already exists.
                    # Silently flipping is_superuser=True would be a
                    # privilege escalation an audit could not trace —
                    # fail loud and let the operator pick a new name.
                    raise CommandError(
                        f"user {username!r} exists but is NOT an active "
                        "superuser (is_superuser / is_staff / is_active "
                        "not all True). Refusing to promote — pick a "
                        "different --username or fix the existing row "
                        "by hand."
                    )
                self.stdout.write(
                    f"superuser {username!r} already exists — no-op."
                )
                self.stdout.write(self._login_hint())
                return

            password = self._resolve_password(username=username)
            User.objects.create_superuser(
                username=username,
                email=email,
                password=password,
            )

        self.stdout.write(self.style.SUCCESS(f"superuser {username!r} created."))
        self.stdout.write(self._login_hint())

    # ─── Helpers ──────────────────────────────────────────────────

    def _resolve_password(self, *, username: str) -> str:
        """Read the password from the env var if set, else prompt.

        Interactive prompt uses `getpass.getpass` so it is NEVER
        echoed to the operator's terminal. The env-var path is for
        deploy automation; setting an empty value is a configuration
        error (not "use an empty password").
        """
        env_value = os.environ.get(_PASSWORD_ENV)
        if env_value is not None:
            env_value = env_value.strip()
            if not env_value:
                raise CommandError(
                    f"{_PASSWORD_ENV} is set but empty — refusing to "
                    "create a superuser without a password."
                )
            return env_value

        if not sys.stdin.isatty():
            # No env var AND no TTY (e.g. running inside a CronJob
            # spec that forgot the secret) — fail loud rather than
            # block forever on stdin.
            raise CommandError(
                f"no TTY and {_PASSWORD_ENV} unset — cannot prompt for "
                "a password. Set the env var (e.g. via a Kubernetes "
                "Secret) or run interactively."
            )

        first = getpass.getpass(f"Password for {username!r}: ")
        if not first:
            raise CommandError("empty password — aborting.")
        second = getpass.getpass("Confirm: ")
        if first != second:
            raise CommandError("password mismatch — aborting.")
        return first

    def _login_hint(self) -> str:
        """One-line operator hint pointing at the local-port URL the
        `kubectl port-forward` runbook reaches. See `vali/README.md`.
        """
        return (
            "Admin is cluster-internal — reach it with "
            "`kubectl port-forward -n vali svc/vali 8000:8000` "
            "and open http://localhost:8000/admin/."
        )
