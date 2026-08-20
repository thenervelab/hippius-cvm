"""Service-client identity model.

Locked decision (issue #1 comment 4496539510, Q5): vali runs its own
minimal auth — NOT hippius-backend SSO. Two credential paths:

1. **mTLS** (canonical for the L1 → vali hop, over whatever private
   control-plane subnet the deployment uses): the reverse
   proxy verifies the client cert and forwards the subject DN in
   `X-SSL-Client-S-DN`. Django matches the CN against
   `ServiceClient.name`.
2. **Service tokens** (for ops scripts and intra-cluster callers
   without an mTLS cert): bearer token in `Authorization: Bearer
   <token>`. Stored as SHA-256 hashes — the plaintext is shown ONCE
   at issuance, never persisted.

Both paths resolve to a [`ServiceClient`] principal which is what the
intake view records as `received_from`.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta

from django.db import models
from django.utils import timezone


class PrincipalScope(models.TextChoices):
    """The authorization scope a [`ServiceClient`] carries (P2).

    This is the EXPLICIT property that decides whether a credential may
    act across tenants. It is deliberately NOT a boolean with a
    convenient default — a principal that nobody classified is
    `UNCLASSIFIED`, and `UNCLASSIFIED` is DENIED on the whole
    non-public `/v1/` surface. Forgetting to classify a new client
    therefore produces a loud 403, never a silent god-token.

    - `UNCLASSIFIED` — the model default. Authenticates, but is refused
      every non-`PUBLIC` `/v1/` endpoint. Fail-closed.
    - `OPERATOR` — acts for ALL tenants (the upstream product API, the
      Edge, sentinel, the epoch-close worker, the bake/packer job
      principals). Must be granted out-of-band (see below).
    - `TENANT` — bound to exactly one `tenant_id`; may only see and
      touch objects owned by that tenant.

    **How a principal becomes an OPERATOR, and what stops it happening
    by accident:** only `manage.py vali_identity_issue_token
    --operator`, the cluster-internal Django admin, or a direct DB
    write. vali exposes NO HTTP endpoint that creates or mutates a
    `ServiceClient` — `apps.identity` has no `urls.py` and no `views.py`
    — so no bearer token, however privileged, can mint or re-scope a
    principal over the API. A `TENANT` principal additionally cannot
    become an operator by mutating its own row, because the DB CHECK
    constraint below forbids the `OPERATOR + tenant_id` combination
    outright: promotion requires first clearing `tenant_id`, which the
    same out-of-band paths gate.
    """

    UNCLASSIFIED = "unclassified", "Unclassified (denied)"
    OPERATOR = "operator", "Operator (all tenants)"
    TENANT = "tenant", "Tenant-scoped"


class ServiceClient(models.Model):
    """A named principal that vali accepts as an authenticated caller.

    `name` is matched against the mTLS subject CN OR the
    `ServiceToken.client.name` on the token path. Disabling a client
    (`is_active=False`) immediately rejects all of its credentials
    without needing to delete tokens / revoke certs.

    `scope` + `tenant_id` carry the object-level authorization identity
    (P2). See [`PrincipalScope`] for the semantics and for how the
    `OPERATOR` grant is issued.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    # P2 — object-level authorization scope. Default is UNCLASSIFIED
    # (denied), NOT operator: a caller only ever acts across tenants
    # because an operator explicitly said so.
    scope = models.CharField(
        max_length=16,
        choices=PrincipalScope.choices,
        default=PrincipalScope.UNCLASSIFIED,
        db_index=True,
    )
    # The single tenant a `scope=tenant` principal is bound to. Empty for
    # every other scope (enforced by the CHECK constraint below), so the
    # field can never be a half-set "sort of scoped" state.
    tenant_id = models.CharField(max_length=256, blank=True, default="", db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            # scope=tenant ⇔ tenant_id != "". Both halves matter:
            #  - a `tenant` principal with a blank tenant_id would match
            #    every object whose owner is also blank (legacy rows).
            #  - an `operator`/`unclassified` principal carrying a
            #    tenant_id is an ambiguous grant; refuse it at the DB so
            #    a partial UPDATE cannot manufacture a cross-tenant
            #    principal that still looks tenant-bound in the admin.
            models.CheckConstraint(
                name="identity_serviceclient_tenant_scope_consistent",
                condition=(
                    models.Q(scope="tenant") & ~models.Q(tenant_id="")
                )
                | (~models.Q(scope="tenant") & models.Q(tenant_id="")),
            ),
        ]

    def __str__(self) -> str:
        return self.name

    # ── P2 authorization helpers ─────────────────────────────────────
    #
    # Read these, never `scope` directly, so the semantics live in one
    # place. `is_operator_principal` is the ONLY thing that grants
    # cross-tenant reach.

    @property
    def is_operator_principal(self) -> bool:
        """True iff this principal may act for every tenant."""
        return self.scope == PrincipalScope.OPERATOR.value

    @property
    def is_tenant_scoped(self) -> bool:
        """True iff this principal is bound to a single tenant."""
        return self.scope == PrincipalScope.TENANT.value and bool(self.tenant_id)

    @property
    def is_unclassified(self) -> bool:
        """True iff nobody classified this principal — denied by default."""
        return not self.is_operator_principal and not self.is_tenant_scoped

    @property
    def scoped_tenant_id(self) -> str:
        """The tenant this principal is confined to, or `""` if it isn't
        confined (operator) / isn't allowed anywhere (unclassified)."""
        return self.tenant_id if self.is_tenant_scoped else ""

    # DRF authentication backends return a principal object. Django's
    # auth framework expects an `is_authenticated` attribute — a plain
    # `True` is enough because `permission_classes = [IsAuthenticated]`
    # only inspects truthiness.
    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False


class TokenLifetime(models.TextChoices):
    """The lifetime CLASS a [`ServiceToken`] is minted under (#32).

    A bearer token that never expires stops working only if somebody
    remembers to deactivate it — i.e. its revocation is a human habit,
    not a property. `expires_at` is `NOT NULL` (migration 0004) so
    "never" is not representable; this enum is where the *duration* is
    decided, once, instead of at each call site.

    The three classes are deliberately coarse — they name WHO HOLDS the
    credential, because that is what determines how it leaks and how
    expensive rotating it is:

    - `OPS` (**7 days**) — held by a human. Pasted into shells, captured
      in scrollback and `~/.bash_history`, minted during an incident and
      then forgotten. A week outlives any single incident and expires
      well before the next one, and nothing automated depends on it, so
      expiry costs an operator one command.
    - `SERVICE` (**90 days**) — a machine principal whose secret lives in
      Vault/`Secret` inside the cluster and which a human rotates
      alongside a deploy (`orchestration-root`, `tenant-baker-worker`).
      One quarter: long enough to be a scheduled chore rather than
      interrupt work, short enough that a credential leaked at the start
      of a quarter is dead by the end of it.
    - `INFRA` (**365 days**) — an unattended relay whose rotation touches
      a component OUTSIDE the vali namespace and cannot be driven from
      the control plane alone (`edge-telemetry-relay`, whose secret is
      consumed by ns `edge-gateway`). A year is still a real bound, and
      the point of bounding it is not that we expect a 300-day-old
      credential to leak — it is that an annual forced rotation keeps the
      rotation path EXERCISED. A path that has never run is a path that
      will not run during the incident that needs it.

    ⛔ There is no `NEVER`. The best argument for one is `INFRA`'s —
    cross-namespace rotation is genuinely awkward — and it is an argument
    for making that rotation cheap, not for making the credential
    immortal.
    """

    OPS = "ops", "Ops — human-held (7 days)"
    SERVICE = "service", "Service — in-cluster machine principal (90 days)"
    INFRA = "infra", "Infra — unattended relay, cross-namespace (365 days)"


#: Maximum age, in days, a freshly minted token of each class may reach.
#: This is BOTH the default expiry and the ceiling: an explicit
#: `expires_at` passed to [`ServiceToken.issue`] may only SHORTEN the
#: class's lifetime, never extend it (see `issue`).
TOKEN_LIFETIME_DAYS: dict[str, int] = {
    TokenLifetime.OPS.value: 7,
    TokenLifetime.SERVICE.value: 90,
    TokenLifetime.INFRA.value: 365,
}


class ServiceToken(models.Model):
    """Bearer token tied to a [`ServiceClient`].

    The plaintext token is generated by [`ServiceToken.issue`] and
    surfaced ONCE to the caller; only the SHA-256 hash is persisted.
    Authentication looks up by hash so a database leak does not yield
    usable bearer tokens.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client = models.ForeignKey(
        ServiceClient,
        on_delete=models.CASCADE,
        related_name="tokens",
    )
    name = models.CharField(
        max_length=128,
        help_text="Human label for this token (e.g. 'l1-prod-2026q2'). Not a secret.",
    )
    # SHA-256 hex digest of the bearer token. 64 ASCII chars; unique.
    token_sha256 = models.CharField(max_length=64, unique=True, db_index=True)
    is_active = models.BooleanField(default=True)
    # #32 — NOT NULL, deliberately. `null=True` with a disciplined
    # `issue()` would be a convention; the column constraint is a rule,
    # and it is the only one that also binds a `manage.py shell` insert,
    # a data migration, the Django admin add form and raw SQL — which is
    # how the three non-expiring production tokens were minted in the
    # first place. See migration 0004 for what it did to existing rows.
    expires_at = models.DateTimeField(
        help_text=(
            "Hard expiry. Enforced at authentication "
            "(apps.identity.authentication), NOT NULL at the database."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["client", "name"],
                name="identity_servicetoken_client_name_unique",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.client.name}:{self.name}"

    @property
    def is_expired(self) -> bool:
        """True iff this token is past its expiry RIGHT NOW."""
        return self.expires_at is not None and self.expires_at < timezone.now()

    @property
    def is_usable(self) -> bool:
        """True iff this token would authenticate — active, unexpired,
        and belonging to an active client. Mirrors the filter in
        `apps.identity.authentication`; used by the rotation tooling to
        refuse leaving a principal with zero working credentials."""
        return self.is_active and not self.is_expired and self.client.is_active

    @staticmethod
    def expiry_for(lifetime: str, *, now=None) -> datetime:
        """The expiry a token of `lifetime` gets if the caller does not
        shorten it. Raises `ValueError` on an unknown class rather than
        silently falling back to anything."""
        try:
            days = TOKEN_LIFETIME_DAYS[str(lifetime)]
        except KeyError:
            raise ValueError(
                f"unknown token lifetime {lifetime!r}; expected one of "
                f"{sorted(TOKEN_LIFETIME_DAYS)}"
            ) from None
        return (now or timezone.now()) + timedelta(days=days)

    @classmethod
    def issue(
        cls,
        *,
        client: ServiceClient,
        name: str,
        lifetime: str,
        expires_at: datetime | None = None,
    ) -> tuple[ServiceToken, str]:
        """Mint a fresh token. Returns (model, plaintext).

        The plaintext is 32 URL-safe bytes (~43 chars). Callers MUST
        surface it to the operator immediately and discard their copy
        — vali has no recovery path; rotation = issue a new token.

        `lifetime` is REQUIRED and has no default (#32). Every value
        that would be a sane default for one caller is a dangerous one
        for another — 7 days silently kills an unattended relay, 365
        days is a skeleton key in a shell history — so the parameter has
        no default and the per-class defaults live in
        `TOKEN_LIFETIME_DAYS`, which is the operator-facing knob.

        `expires_at` is an optional override that may only SHORTEN the
        class lifetime. That keeps the ceiling by construction: no call
        site, and no `--expires-days` on the CLI, can mint something
        longer-lived than its class allows.
        """
        import hashlib  # local import: keeps the module hash-free at import time.

        now = timezone.now()
        ceiling = cls.expiry_for(lifetime, now=now)
        if expires_at is None:
            expires_at = ceiling
        else:
            if timezone.is_naive(expires_at):
                # A naive datetime is ambiguous under USE_TZ and would be
                # interpreted against the current default timezone —
                # refuse rather than guess at a credential's lifetime.
                raise ValueError("expires_at must be timezone-aware")
            if expires_at <= now:
                # Minting an already-dead credential is never intended;
                # it fails at the consumer, minutes or hours later, as an
                # opaque 401. Fail here instead.
                raise ValueError("expires_at must be in the future")
            if expires_at > ceiling:
                raise ValueError(
                    f"expires_at exceeds the {lifetime!r} lifetime ceiling "
                    f"({TOKEN_LIFETIME_DAYS[str(lifetime)]} days); an explicit "
                    "expiry may only shorten a token's life, never extend it"
                )

        plaintext = secrets.token_urlsafe(32)
        digest = hashlib.sha256(plaintext.encode("ascii")).hexdigest()
        row = cls.objects.create(
            client=client,
            name=name,
            token_sha256=digest,
            expires_at=expires_at,
        )
        return row, plaintext
