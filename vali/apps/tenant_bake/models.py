"""Per-tenant encrypted-qcow2 bake state, mirrored 1:1 on the wire.

Spec of record: issue #334. This is Phase 1 of moving the per-tenant
qcow2 bake out of `scripts/tenant-image-bake.sh` (which runs on the
operator workstation, requires root + qemu-img + cryptsetup +
losetup + chroot) and into a vali-triggered k8s Job (which runs
inside the cluster, no operator workstation involvement).

The lifecycle here mirrors `apps.packer.PackerBuild` deliberately:
the worker contract `POST /finalize` follows the same wire shape,
the optimistic-concurrency CAS via `version` follows the same
discipline, and the test suite reuses the same assertion patterns
so a reviewer who knows `apps.packer` reads this in O(1).

The key difference is the unique-active constraint key:

- `apps.packer.PackerBuild` has ONE active build per `image_kind`
  (all four kinds — KBS / Edge / Guest / Audit-VM — are shared
  fleet images; there's exactly one in flight at a time).
- `apps.tenant_bake.TenantBake` has ONE active bake per `vm_id`
  (per-tenant artefacts; many bakes can be in flight in parallel,
  but at most one per VM).

Field-by-field:

- `bake_id`                public stable identifier (UUID hex). PK
                           column (`id`) is a separate UUID; we keep
                           a distinct `bake_id` so the wire name
                           never leaks the row's primary key (matters
                           for URLs the k8s Job receives).
- `vm_id`                  the tenant VM the bake produces an image
                           for. Same value the OrderTicket carries.
- `base_image_url`         URL of the vanilla cloud image (Ubuntu /
                           Debian) to bake. The baker fetches +
                           sha-verifies before any chroot work.
- `base_image_sha256`      Expected sha256 of `base_image_url`. The
                           baker MUST byte-equal this before the
                           bake proceeds (defence-in-depth on top of
                           the URL).
- `size_gb`                Target raw image size in GiB (integer,
                           > 0). The encrypted plaintext device is
                           smaller by ~7 % — the LUKS2 header +
                           `--integrity hmac-sha256` tags take
                           that. Operators size `int(N * 0.93) GiB`
                           usable plaintext.
- `kek_vault_path`         KV-v2 path the baker reads the KEK from.
                           Vali writes the KEK there before posting
                           `/v1/tenant-bakes`; the baker has its own
                           Vault token mounted as a k8s secret.
- `s3_output_bucket`,
  `s3_output_prefix`       Where the three artefacts (qcow2 +
                           vmlinuz + initrd) land on success.
- `state`                  Queued → Running → {Succeeded | Failed}.
                           Same shape as `PackerBuildState`.
- `requested_by`           `ServiceClient` that POSTed `/v1/tenant-
                           bakes`. Audit trail per §15.
- `requested_at`           creation timestamp.
- `started_at`             set on Queued→Running.
- `finished_at`            set on terminal transitions.
- `qcow2_sha256`,
  `kernel_sha256`,
  `initrd_sha256`          64-hex digests the baker emits on
                           success. NULL for non-Succeeded.
- `measurement_hex`        96-hex SNP launch digest — OPTIONAL even
                           on Succeeded: it folds OVMF + vcpus,
                           which only the miner's tenant-preflight
                           knows; vali pins THAT value at launch.
                           A baker that can compute it (UKI-style
                           flows) may still report it.
- `failure_reason`         short operator-facing string on Failed
                           (`""` otherwise). Not echoed verbatim
                           outside the API surface — §20.
- `version`                optimistic-concurrency counter. Starts
                           at 1, +1 on each successful transition.

Constraints:

- `(bake_id)` unique.
- `Succeeded ⇒ qcow2_sha256 != ""` (DB CHECK).
- `Succeeded ⇒ kernel_sha256 != ""` (DB CHECK).
- `Succeeded ⇒ initrd_sha256 != ""` (DB CHECK).
- (measurement_hex is NOT required on Succeeded: the digest folds
OVMF + vcpus, which only the miner preflight knows.)
- Partial unique index on `vm_id` for `state ∈ {queued, running}`
  — enforces "one active bake per vm_id" at the database level so
  two concurrent POSTs can't both insert. The view catches the
  resulting `IntegrityError` and surfaces 409 with the existing
  row attached.

Representation: `qcow2_sha256`, `kernel_sha256`, `initrd_sha256`,
`measurement_hex`, `failure_reason` use empty string (not NULL) as
their "not set yet" sentinel. CharField with `default=""` keeps the
column NOT NULL — simpler invariants, no two-value (NULL vs "")
distinction to keep straight. The serializer maps "" → None at the
wire boundary.
"""

from __future__ import annotations

import uuid

from django.db import models


class TenantBakeState(models.TextChoices):
    """Bake lifecycle.

    Mirrors `apps.packer.PackerBuildState`. `Queued` is the row's
    initial state on `POST /v1/tenant-bakes`. The baker k8s Job
    flips it to `Running` when it picks the row up (via the worker
    `/finalize` endpoint), then to `Succeeded` or `Failed`.
    Terminal states are immutable — a retry is a new row with a
    new `bake_id`.
    """

    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"


class TenantBakeDiskMode(models.TextChoices):
    """How the bake packages the customised root (golden-bake PR6).

    - `legacy_luks` (default): a per-VM `tenant.qcow2` LUKS2+integrity
      root. Byte-identical to every pre-golden bake.
    - `golden_verity_overlay`: a SHARED, read-only dm-verity base
      (`rootfs.img` + `rootfs.verity`) reused across same-distro VMs —
      the base is UNKEYED (non-confidential public distro), so the bake
      produces NO qcow2 + consumes NO KEK. Per-VM writes land on a
      guest-keyed overlay upper the miner allocates blank at launch.
    """

    LEGACY_LUKS = "legacy_luks", "Legacy LUKS"
    GOLDEN_VERITY_OVERLAY = "golden_verity_overlay", "Golden dm-verity overlay"


# In-flight states for the "one active bake per vm_id" rule —
# `POST /v1/tenant-bakes` returns 409 if a row with the same `vm_id`
# is in either of these states. Kept here (not in views) so the
# test for the constraint reads the same source the view does.
IN_FLIGHT_STATES: frozenset[str] = frozenset(
    {TenantBakeState.QUEUED.value, TenantBakeState.RUNNING.value}
)


class TenantBake(models.Model):
    """A single per-tenant encrypted-qcow2 bake request + outcome."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Public identifier — separate from the PK so the wire form is
    # stable even if we ever re-key the table.
    bake_id = models.CharField(max_length=64, unique=True)

    # ── Bake inputs ────────────────────────────────────────────────
    # `vm_id` length matches the OrderTicket's `vm_id` upper bound
    # (`hippius_types::ticket::OrderTicket::vm_id` is a `String`, but
    # production tenant ids are short — 64 is generous).
    vm_id = models.CharField(max_length=64)
    base_image_url = models.URLField(max_length=2048)
    base_image_sha256 = models.CharField(max_length=64)
    size_gb = models.PositiveIntegerField()
    # KV-v2 path. Same shape as
    # `apps.orchestration.services.vault_kv.put_kv` writes.
    kek_vault_path = models.CharField(max_length=512)
    s3_output_bucket = models.CharField(max_length=256)
    s3_output_prefix = models.CharField(max_length=512)

    # Boot-disk packaging mode (golden-bake PR6). Set at create, MEASURED
    # into the launch cmdline downstream — the bake→launch resolver copies
    # it onto the launch spec. `legacy_luks` keeps every pre-golden bake
    # byte-identical; `golden_verity_overlay` swaps the per-VM qcow2 for a
    # shared dm-verity base (no qcow2, no KEK).
    disk_mode = models.CharField(
        max_length=32,
        choices=TenantBakeDiskMode.choices,
        default=TenantBakeDiskMode.LEGACY_LUKS,
    )

    # ── Bake state ─────────────────────────────────────────────────
    state = models.CharField(
        max_length=32,
        choices=TenantBakeState.choices,
        default=TenantBakeState.QUEUED,
    )
    requested_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="tenant_bakes",
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    # ── Bake outputs (populated on Succeeded) ──────────────────────
    qcow2_sha256 = models.CharField(max_length=64, blank=True, default="")
    kernel_sha256 = models.CharField(max_length=64, blank=True, default="")
    initrd_sha256 = models.CharField(max_length=64, blank=True, default="")
    # #296 LUKS2-header MAC — vali pins it into the measured cmdline at
    # launch (`hippius.luks_header_sha256`). Empty for bakers that predate
    # the #587 Phase 1C finalize field; the bake→launch resolver then
    # falls back to requiring it on the launch intent.
    luks_header_sha256 = models.CharField(max_length=64, blank=True, default="")
    # ── Golden-bake outputs (populated on Succeeded, golden mode only) ─
    # The SHARED dm-verity base artifacts (golden-bake PR6). In golden
    # mode there is NO `qcow2_sha256`; instead the bake emits the squashfs
    # `rootfs.img` sha (fetched by the miner via the #823 cache), the
    # `rootfs.verity` hash-tree sha, and the UNKEYED dm-verity root hash
    # (vali folds this into the MEASURED `dm-verity.root=` cmdline). Empty
    # on legacy bakes. The bake→launch resolver copies these onto the
    # launch spec's `rootfs_img_sha256_hex` / `rootfs_verity_sha256_hex` /
    # `verity_root_hash_hex`.
    rootfs_img_sha256 = models.CharField(max_length=64, blank=True, default="")
    rootfs_verity_sha256 = models.CharField(max_length=64, blank=True, default="")
    verity_root_hash = models.CharField(max_length=64, blank=True, default="")
    # 48-byte SNP launch digest — 96 hex chars. NOT the final launch
    # measurement (the measured cmdline gains per-launch tokens — the
    # miner preflight computes the real digest); informational.
    measurement_hex = models.CharField(max_length=96, blank=True, default="")

    failure_reason = models.CharField(max_length=256, blank=True, default="")
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-requested_at"]
        indexes = [
            # The "active bake per vm_id" check filters by `vm_id` +
            # `state` — index supports it without a sequential scan
            # as the table grows.
            models.Index(fields=["vm_id", "state"]),
            models.Index(fields=["state"]),
        ]
        constraints = [
            # A Succeeded LEGACY bake requires the qcow2 sha. A golden bake
            # produces no qcow2, so the requirement is gated on the mode —
            # legacy rows behave exactly as before (byte-identical).
            models.CheckConstraint(
                name="tenant_bake_succeeded_requires_qcow2_sha",
                condition=(
                    ~models.Q(state=TenantBakeState.SUCCEEDED)
                    | ~models.Q(disk_mode=TenantBakeDiskMode.LEGACY_LUKS)
                    | ~models.Q(qcow2_sha256="")
                ),
            ),
            # A Succeeded GOLDEN bake requires the shared dm-verity base
            # artifacts (rootfs.img sha + rootfs.verity sha + the UNKEYED
            # verity root hash). Inert for legacy rows.
            models.CheckConstraint(
                name="tenant_bake_succeeded_golden_requires_verity",
                condition=(
                    ~models.Q(state=TenantBakeState.SUCCEEDED)
                    | ~models.Q(disk_mode=TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY)
                    | (
                        ~models.Q(rootfs_img_sha256="")
                        & ~models.Q(rootfs_verity_sha256="")
                        & ~models.Q(verity_root_hash="")
                    )
                ),
            ),
            models.CheckConstraint(
                name="tenant_bake_succeeded_requires_kernel_sha",
                condition=(
                    ~models.Q(state=TenantBakeState.SUCCEEDED)
                    | ~models.Q(kernel_sha256="")
                ),
            ),
            models.CheckConstraint(
                name="tenant_bake_succeeded_requires_initrd_sha",
                condition=(
                    ~models.Q(state=TenantBakeState.SUCCEEDED)
                    | ~models.Q(initrd_sha256="")
                ),
            ),
            models.UniqueConstraint(
                fields=["vm_id"],
                condition=models.Q(state__in=["queued", "running"]),
                name="tenant_bake_one_active_per_vm_id",
            ),
        ]

    def __str__(self) -> str:
        return f"TenantBake {self.bake_id} (vm_id={self.vm_id}, {self.state})"
