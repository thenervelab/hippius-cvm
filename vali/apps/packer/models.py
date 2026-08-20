"""PackerBuild model — vali's view of an image-build job.

Spec: ARCHITECTURE.md §F / issue #41 (Packer factory). vali does NOT
execute the build itself; it only exposes the **trigger surface** so
the L1 minter (or an ops caller) can request a build, the actual
Packer Kubernetes Job picks the request up, builds the image,
uploads to the Hippius S3 bucket, and POSTs `/finalize` to close
the request out.

Each row therefore represents a single build *intent + outcome*
record. The state machine is intentionally narrow:

    Queued  ──► Running  ──► Succeeded
                    │
                    └─────► Failed

Other transitions are illegal (no Queued→Succeeded shortcut, no
Running→Queued retry — a retry is a new row).

Optimistic concurrency mirrors the lifecycle app (PR-G2): every row
carries a `version` counter, transitions filter on the pre-image
version, and a stale `if_version` returns 409. No row lock; the CAS
UPDATE is the boundary.

The four `image_kind` discriminants correspond to the four artifact
families the Packer factory produces:

  - `kbs`        — kbs-server image (the §B Tier-0 broker).
  - `edge`       — Edge / Miner gateway image (§H).
  - `guest`      — confidential VM guest base image (§7).
  - `audit-vm`   — Audit-VM image (§I).

These map 1:1 to the `image_kind` field on the Packer Job spec; vali
never inspects what they mean, only that the caller's value is one
of the recognized literals so the wire contract stays tight.
"""

from __future__ import annotations

import uuid

from django.db import models


class PackerImageKind(models.TextChoices):
    """Allowed `image_kind` values. Mirrors the Packer factory's
    per-job spec — vali rejects anything outside this set at intake.
    Pinned strings (not auto-numbered) so the DB value matches the
    on-wire string the Packer Job consumes.
    """

    KBS = "kbs", "KBS server"
    EDGE = "edge", "Edge gateway"
    GUEST = "guest", "Guest VM base image"
    AUDIT_VM = "audit-vm", "Audit-VM image"


class PackerBuildState(models.TextChoices):
    """Build lifecycle.

    `Queued` is the row's initial state on `POST /build`. The
    Packer Job worker flips it to `Running` when it picks the build
    up (PR-F* will wire that side), then to `Succeeded` or `Failed`
    via the `finalize` endpoint when the build completes. Terminal
    states are immutable — a retry is a new row.
    """

    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"


# In-flight states for the "one active build per image_kind" rule —
# `POST /build` returns 409 if a row with the same `image_kind` is in
# either of these states. Kept here (not in views) so the test for
# the constraint reads the same source the view does.
IN_FLIGHT_STATES: frozenset[str] = frozenset(
    {PackerBuildState.QUEUED.value, PackerBuildState.RUNNING.value}
)


class PackerBuild(models.Model):
    """A single Packer build request + outcome.

    Field-by-field:

    - `build_id`           public stable identifier (UUID hex). The
                           PK column (`id`) is also a UUID; we keep
                           a separate `build_id` so the wire name
                           never leaks the row's primary key, which
                           matters for URLs the Packer Job receives.
    - `image_kind`         one of `PackerImageKind` — what the Job
                           should produce.
    - `state`              one of `PackerBuildState` — current
                           lifecycle position.
    - `requested_by`       `ServiceClient` that POSTed `/build`.
                           Audit trail per §15.
    - `requested_at`       creation timestamp.
    - `started_at`         set on Queued→Running.
    - `finished_at`        set on terminal transitions.
    - `artifact_sha256`    64-hex-char digest of the produced image
                           — populated only on Succeeded. NULL for
                           every other state.
    - `provenance_signed_url`
                           presigned GET URL pointing at the SLSA
                           provenance attestation that accompanies
                           the artifact. NULL for non-Succeeded
                           states. The TTL is set by the finalize
                           caller; vali stores the URL verbatim and
                           does not re-presign it (callers re-fetch
                           via `/presign-image-get` once they need
                           the artifact itself).
    - `failure_reason`     short operator-facing string on Failed
                           (`""` otherwise). NOT echoed verbatim
                           outside the API surface — see §20.
    - `version`            optimistic-concurrency counter. Starts at
                           1, +1 on each successful transition.

    Constraints:

    - `(build_id)` unique.
    - `Succeeded ⇒ artifact_sha256 != ""` (DB CHECK).
    - `Succeeded ⇒ provenance_signed_url != ""` (DB CHECK).
    - Partial unique index on `image_kind` for `state ∈ {queued,
      running}` — enforces "one active build per image_kind" at
      the database level so two concurrent POSTs can't both insert.
      The view catches the resulting `IntegrityError` and surfaces
      a 409 with the existing row attached.

    Note on representation: `artifact_sha256`, `provenance_signed_url`,
    and `failure_reason` use the empty string (not NULL) as their
    "not set yet" sentinel. CharField with `default=""` keeps the
    column NOT NULL — simpler invariants, no two-value (NULL vs "")
    distinction to keep straight. The serializer maps "" → None at
    the wire boundary.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Public identifier — separate from the PK so the wire form is
    # stable even if we ever re-key the table.
    build_id = models.CharField(max_length=64, unique=True)
    image_kind = models.CharField(max_length=32, choices=PackerImageKind.choices)
    state = models.CharField(
        max_length=32,
        choices=PackerBuildState.choices,
        default=PackerBuildState.QUEUED,
    )
    requested_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="packer_builds",
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # 64-char SHA-256 hex digest. Stored as char to keep the wire
    # representation byte-exact and to use the standard CHECK.
    artifact_sha256 = models.CharField(max_length=64, blank=True, default="")
    # Presigned URL — bounded by the cap on what the Hippius S3
    # presigner emits (a few hundred chars in practice). 2048 leaves
    # generous headroom for query-string-heavy presigners.
    provenance_signed_url = models.CharField(max_length=2048, blank=True, default="")
    failure_reason = models.CharField(max_length=256, blank=True, default="")
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-requested_at"]
        indexes = [
            # The "active build per image_kind" check filters by
            # `image_kind` + `state` — index supports it without a
            # sequential scan as the table grows.
            models.Index(fields=["image_kind", "state"]),
            models.Index(fields=["state"]),
        ]
        constraints = [
            # Succeeded rows MUST carry an artifact digest. Postgres
            # enforces; SQLite (test backend) also honours `CHECK`.
            models.CheckConstraint(
                name="packer_succeeded_requires_sha",
                condition=(
                    ~models.Q(state=PackerBuildState.SUCCEEDED)
                    | ~models.Q(artifact_sha256="")
                ),
            ),
            models.CheckConstraint(
                name="packer_succeeded_requires_provenance",
                condition=(
                    ~models.Q(state=PackerBuildState.SUCCEEDED)
                    | ~models.Q(provenance_signed_url="")
                ),
            ),
            # Partial unique index: at most one row per `image_kind`
            # in an in-flight (Queued/Running) state. Postgres + SQLite
            # (the test backend) both honour `UniqueConstraint(condition=…)`.
            # The view catches the resulting `IntegrityError` and
            # returns 409 with the conflicting row attached — defends
            # against the TOCTOU race that a pure filter-then-create
            # would have under READ COMMITTED isolation.
            models.UniqueConstraint(
                fields=["image_kind"],
                condition=models.Q(state__in=["queued", "running"]),
                name="packer_one_active_build_per_image_kind",
            ),
        ]

    def __str__(self) -> str:
        return f"PackerBuild {self.build_id} ({self.image_kind}, {self.state})"
