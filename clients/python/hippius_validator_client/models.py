"""Typed request/response models shared by the sync and async clients.

Every field name mirrors the validator wire contract exactly (see the
enriched serializers under ``vali/apps/*/schemas.py``). Request dataclasses
expose ``to_body()`` which drops ``None`` fields so the server applies its
own defaults; response dataclasses expose ``from_dict()`` and keep the raw
payload under ``raw`` for forward compatibility.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any


def _drop_none(body: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in body.items() if v is not None}


# ─── Bakes ──────────────────────────────────────────────────────────────

# Wire state values (lowercase) — see ``TenantBakeState`` / ``VmState``.
BAKE_TERMINAL_STATES = frozenset({"succeeded", "failed"})
LAUNCH_TERMINAL_STATES = frozenset({"succeeded", "failed"})
# A ``DecommissionJob`` reaches ``done`` (crypto-erased + NetBird revoked) or
# ``failed`` — see ``TERMINAL_DECOMMISSION_STATES`` on the server.
DECOMMISSION_TERMINAL_STATES = frozenset({"done", "failed"})
# A ``MigrationJob`` reaches ``done`` (the VM is Active on the destination at
# the new generation) or ``failed`` — see ``TERMINAL_MIGRATION_STATES`` on the
# server. The non-terminal progression is
# ``draining → quiescing → snapshotting → uploading → fencing →
# awaiting_source_ack → dest_activating``.
MIGRATION_TERMINAL_STATES = frozenset({"done", "failed"})

# ``TenantBake.disk_mode`` values (golden-bake PR6).
DISK_MODE_LEGACY_LUKS = "legacy_luks"
DISK_MODE_GOLDEN_VERITY_OVERLAY = "golden_verity_overlay"


@dataclass
class BakeRequest:
    """``POST /v1/tenant-bakes`` body — request a new per-tenant bake.

    Every field except ``disk_mode`` is required by the server; a bake is
    per-VM (the KEK is scoped to ``vm_id``). ``disk_mode`` selects the
    boot-disk packaging (golden-bake PR6) and defaults server-side to
    ``legacy_luks`` (per-VM LUKS qcow2) when omitted; pass
    ``golden_verity_overlay`` to bake a shared, non-confidential dm-verity
    base (no qcow2, no per-VM KEK).
    """

    vm_id: str
    base_image_url: str
    base_image_sha256: str
    size_gb: int
    kek_vault_path: str
    s3_output_bucket: str
    s3_output_prefix: str
    disk_mode: str | None = None

    def to_body(self) -> dict[str, Any]:
        # ``disk_mode`` is optional on the wire; drop it when unset so the
        # server applies its own ``legacy_luks`` default.
        return _drop_none(
            {
                "vm_id": self.vm_id,
                "base_image_url": self.base_image_url,
                "base_image_sha256": self.base_image_sha256,
                "size_gb": self.size_gb,
                "kek_vault_path": self.kek_vault_path,
                "s3_output_bucket": self.s3_output_bucket,
                "s3_output_prefix": self.s3_output_prefix,
                "disk_mode": self.disk_mode,
            }
        )


@dataclass
class Bake:
    """A ``TenantBake`` row (``GET``/``POST /v1/tenant-bakes``)."""

    bake_id: str
    vm_id: str
    state: str
    version: int
    base_image_url: str | None = None
    base_image_sha256: str | None = None
    size_gb: int | None = None
    kek_vault_path: str | None = None
    s3_output_bucket: str | None = None
    s3_output_prefix: str | None = None
    # Boot-disk packaging (golden-bake PR6): ``legacy_luks`` (per-VM LUKS
    # qcow2) or ``golden_verity_overlay`` (shared dm-verity base). ``None``
    # here on an older validator that omits the key.
    disk_mode: str | None = None
    requested_by: str | None = None
    requested_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    # Legacy-LUKS artefact digest — the baked per-VM qcow2. ``None`` for a
    # golden bake (mutually exclusive with the rootfs/verity digests below).
    qcow2_sha256: str | None = None
    # Golden-bake artefact digests (``disk_mode == golden_verity_overlay``):
    # the shared ``rootfs.img`` squashfs, its ``rootfs.verity`` hash-tree, and
    # the UNKEYED dm-verity root hash vali folds into the measured cmdline.
    # ``None`` for a legacy bake.
    rootfs_img_sha256: str | None = None
    rootfs_verity_sha256: str | None = None
    verity_root_hash: str | None = None
    kernel_sha256: str | None = None
    initrd_sha256: str | None = None
    measurement_hex: str | None = None
    failure_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> Bake:
        return _build(cls, body)

    @property
    def is_terminal(self) -> bool:
        return self.state in BAKE_TERMINAL_STATES

    @property
    def is_succeeded(self) -> bool:
        return self.state == "succeeded"

    @property
    def is_failed(self) -> bool:
        return self.state == "failed"

    @property
    def is_golden(self) -> bool:
        """Whether this is a golden (dm-verity overlay) bake.

        Golden-ness is transparent at launch — the server resolves the disk
        mode from the ``bake_id``; the tenant never sets it on the launch
        intent. Exposed here only for display / diagnostics.
        """
        return self.disk_mode == DISK_MODE_GOLDEN_VERITY_OVERLAY


# ─── Images (golden-image catalog) ──────────────────────────────────────


@dataclass
class Image:
    """One ``GET /v1/images`` catalog row — a launchable golden image.

    The catalog is OPERATOR-controlled: ``image_name`` is the value you pass
    as :attr:`LaunchRequest.image`, and it maps (server-side) to the current
    blessed golden ``bake_id``. ``is_golden`` reflects whether the referenced
    bake is a Succeeded golden bake (normally always true).
    """

    image_name: str
    distro: str | None = None
    bake_id: str | None = None
    is_golden: bool | None = None
    blessed_at: str | None = None
    blessed_by: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> Image:
        return _build(cls, body)


# ─── Pre-sale feasibility ───────────────────────────────────────────────


@dataclass
class HostFit:
    """One host's contribution to a :class:`Feasibility` answer."""

    node_id: str = ""
    #: Is the HARDWARE big enough, ignoring what is placed on it?
    big_enough: bool = False
    #: The validator has no trusted hardware anchor for this host, so
    #: neither :attr:`big_enough` nor :attr:`fits` is an answer. The host
    #: does not count towards a ``never`` verdict.
    size_unknown: bool = False
    #: Is there room right now? Implies :attr:`big_enough`.
    fits: bool = False
    free_memory_mb: int | None = None
    free_cpus: int | None = None
    budget_memory_mb: int | None = None
    budget_cpus: int | None = None
    #: Which dimension fell short, and by how much. Empty when it fits.
    shortfall: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> HostFit:
        return _build(cls, body)


@dataclass
class Feasibility:
    """Can a VM of this flavor be placed right now — asked BEFORE selling.

    Branch on :attr:`verdict`. The distinction that matters commercially
    is ``not-now`` versus ``never``:

    - ``"yes"``      a miner would be chosen and the flavor fits it.
    - ``"not-now"``  the fleet CAN run this flavor but has no room or no
                     eligible host at this instant. Retryable.
    - ``"never"``    no reachable host is big enough. Retrying cannot
                     help — this is the answer that must stop a sale.

    ``never`` is only ever returned when the validator actually KNOWS
    every reachable host's size. Where an anchor is missing the answer is
    ``not-now`` with reason ``host-size-unknown`` — missing data must not
    take a flavor off the shelf.

    :attr:`headroom` is advisory, not a reservation: it is a snapshot and
    a concurrent launch consumes it.

    ⚠️ :attr:`disk_checked` is always ``False``. The validator has no
    mirror of any host's free disk (miner heartbeats report memory and
    CPU only), so the DATA-disk dimension stays gated by the miner at
    dispatch. The field exists so this limit is visible rather than
    assumed away.
    """

    flavor: str = ""
    verdict: str = ""
    placeable_now: bool = False
    fits_any_host: bool = False
    headroom: int = 0
    cpu_count: int = 0
    memory_mb: int = 0
    data_disk_size_gb: int = 0
    reason: str = ""
    scheduler_error: str = ""
    disk_checked: bool = False
    hosts: list[HostFit] = field(default_factory=list)
    #: The region the answer was computed for (``""`` = fleet-wide). With a
    #: region, ``reason`` can also be ``region-unknown`` (probe not run;
    #: retry), ``no-miner-in-region`` (``never``) or ``region-unverified``
    #: (miners detected there but not yet proven; retry). An older
    #: validator omits the key and this reads ``""``.
    region: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> Feasibility:
        obj = _build(cls, body)
        obj.hosts = [HostFit.from_dict(h) for h in body.get("hosts", [])]
        return obj

    @property
    def sellable(self) -> bool:
        """Shorthand for "take the money": the flavor is placeable now."""
        return self.verdict == "yes"


# ─── Regions ────────────────────────────────────────────────────────────


@dataclass
class RegionCapacity:
    """Admission units summed over the miners counted in a :class:`Region`."""

    total_units: int = 0
    committed_units: int = 0
    free_units: int = 0
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> RegionCapacity:
        return _build(cls, body)


@dataclass
class Region:
    """One row of ``GET /v1/operator/regions`` — a country the validator has
    DETECTED miners in. Nothing here is declared by a miner: the validator
    measures each miner's location (server-observed IP, GeoIP, round-trip
    latency, the egress of its own tenant VMs) and grades it.

    :attr:`region` is the ISO 3166-1 alpha-2 code to pass as
    :attr:`LaunchRequest.region` / ``feasibility(region=)``.
    :attr:`miners_total` / :attr:`miners_verified` always count every
    located miner; :attr:`node_ids`, :attr:`miners_dispatchable`,
    :attr:`hosted_vm_count` and :attr:`capacity` count only those the
    scheduler would actually place in (verified, unless the report was
    asked with ``verified_only=False``).
    """

    region: str = ""
    country_code: str = ""
    miners_total: int = 0
    miners_verified: int = 0
    miners_dispatchable: int = 0
    hosted_vm_count: int = 0
    #: ``None`` when no counted miner has a capacity mirror row yet.
    capacity: RegionCapacity | None = None
    node_ids: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> Region:
        obj = _build(cls, body)
        cap = body.get("capacity")
        obj.capacity = RegionCapacity.from_dict(cap) if isinstance(cap, dict) else None
        obj.node_ids = list(body.get("node_ids") or [])
        return obj

    @property
    def placeable(self) -> bool:
        """Could a launch constrained to this region land right now — at
        least one counted miner is dispatchable AND a free unit is KNOWN.
        Unknown capacity (``None``) reads as not placeable: this is a
        sales hint, and a hint must not be built on missing data. The
        authoritative answer is ``can_place(flavor, region=...)``."""
        return (
            self.miners_dispatchable > 0
            and self.capacity is not None
            and self.capacity.free_units > 0
        )


@dataclass
class RegionsReport:
    """``GET /v1/operator/regions`` — the regions miners exist in, with
    capacity. Sorted by :attr:`Region.region`."""

    regions: list[Region] = field(default_factory=list)
    #: Bridged miners the probe has not located yet (no row, or no
    #: country). They are in NO region for placement purposes.
    unlocated_miners: int = 0
    #: Whether the per-region counts include only ``verified`` miners.
    require_verified: bool = True
    #: Where the latency bound is measured from (``name`` / ``latitude`` /
    #: ``longitude``).
    vantage: dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> RegionsReport:
        obj = _build(cls, body)
        obj.regions = [Region.from_dict(r) for r in body.get("regions", [])]
        obj.vantage = dict(body.get("vantage") or {})
        return obj

    def get(self, region: str) -> Region | None:
        """The row for ``region`` (case-insensitive), or ``None``."""
        code = region.strip().upper()
        for row in self.regions:
            if row.region.upper() == code:
                return row
        return None


# ─── Launch ─────────────────────────────────────────────────────────────


@dataclass
class LaunchRequest:
    """``POST /v1/vm/launch`` body — the launch intent + cloud-init userdata.

    Three ways to name the disk artefacts (in order of convenience):

    - ``image`` — the **fast default**: an operator-blessed golden image NAME
      (e.g. ``ubuntu``). The server maps it to the current blessed golden
      ``bake_id`` so every fresh launch reuses the shared golden base
      (cache-HIT → ~2-3 min). Discover names with :meth:`list_images`.
    - ``bake_id`` — a Succeeded ``TenantBake`` you baked yourself.
    - the raw artefact fields (``s3_bucket`` / ``*_sha256_hex`` / …).

    ``image`` and ``bake_id`` are mutually exclusive. When ``bake_id`` (or a
    resolved ``image``) is set the server fills the artefact SHAs, LUKS-header
    MAC, KEK Vault path and S3 location, so those fields may be left ``None``
    (caller-supplied values win). ``userdata`` is the cloud-init plaintext and
    is required by the server; it may be passed here or as the ``userdata``
    argument to ``launch_vm``.
    """

    userdata: str | None = None
    tenant_id: str | None = None
    user_id: str | None = None
    vm_id: str | None = None
    lease_id: str | None = None
    flavor: str | None = None
    cmdline: str | None = None
    # Launch-by-image (the fast default path): an operator-blessed golden image
    # NAME (e.g. ``ubuntu``, discoverable via :meth:`list_images`). The server
    # resolves it to the CURRENT blessed golden ``bake_id`` for that image, so
    # every fresh launch reuses the shared golden base (cache-HIT on the miner
    # → ~2-3 min). **Mutually exclusive with** ``bake_id`` (supplying both is
    # rejected); an unknown image is rejected (fail closed).
    image: str | None = None
    bake_id: str | None = None
    s3_bucket: str | None = None
    s3_key_prefix: str | None = None
    luks_disk_sha256_hex: str | None = None
    kernel_sha256_hex: str | None = None
    initrd_sha256_hex: str | None = None
    luks_header_sha256_hex: str | None = None
    kek_vault_path: str | None = None
    platform_id: str | None = None
    ticket_id: str | None = None
    order_id: str | None = None
    rootfs_sha256_hex: str | None = None
    measurement_hex: str | None = None
    # REQUIRED for EVERY launch through this API, golden or self-baked. Each
    # launch bakes per-launch values into the measured cmdline (fresh EOL and
    # validator nonces, the telemetry challenge, and for a legacy disk the
    # per-VM LUKS-header MAC), so every VM has its OWN launch measurement, and
    # the KBS releases a key only for an allowlisted one. Without this the
    # guest is refused (403), never unlocks and never reaches `kek_released` —
    # while the LaunchJob still reports `succeeded`, because it is CAS'd on the
    # miner accepting the order. Defaults to False server-side; the SDK will
    # not flip it for you.
    auto_pin_allowlist: bool | None = None
    enable_netbird: bool | None = None
    netbird_group: str | None = None
    netbird_key_ttl_seconds: int | None = None
    netbird_hostname_template: str | None = None
    ovmf_path: str | None = None
    rootfs_data_path: str | None = None
    rootfs_hash_path: str | None = None
    kid: str | None = None
    expiry_seconds: int | None = None
    max_price_per_unit: int | None = None
    # Region constraint: an ISO 3166-1 alpha-2 country code (``FR``,
    # case-insensitive). The VM is placed ONLY on a miner the validator has
    # DETECTED and verified there; when none is eligible the launch fails
    # ``no-miner-in-region`` rather than landing elsewhere. Discover codes
    # with :meth:`HippiusValidatorClient.regions`, pre-check with
    # :meth:`HippiusValidatorClient.can_place`\ ``(…, region=)``. ``None``
    # (the default) places anywhere.
    region: str | None = None

    def to_body(self, userdata: str | None = None) -> dict[str, Any]:
        """Render the request body. ``userdata`` overrides ``self.userdata``."""
        body = {f.name: getattr(self, f.name) for f in fields(self)}
        resolved = userdata if userdata is not None else self.userdata
        body["userdata"] = resolved
        return _drop_none(body)


@dataclass
class LaunchJob:
    """A ``LaunchJob`` row (``POST``/``GET /v1/vm/launch``)."""

    job_id: str
    vm_id: str
    state: str
    version: int
    # Fine-grained progress WITHIN `state` (queued/staging/placing/
    # dispatching/launched/failed). ``None`` on an older server that does
    # not populate it — callers fall back to ``state`` + ``miner_id``.
    phase: str | None = None
    tenant_id: str | None = None
    flavor: str | None = None
    miner_id: str | None = None
    placement_id: str | None = None
    reason: str | None = None
    result: dict[str, Any] | None = None
    decided_by: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> LaunchJob:
        return _build(cls, body)

    @property
    def is_terminal(self) -> bool:
        return self.state in LAUNCH_TERMINAL_STATES

    @property
    def is_succeeded(self) -> bool:
        return self.state == "succeeded"

    @property
    def is_failed(self) -> bool:
        return self.state == "failed"


# ─── Lifecycle ──────────────────────────────────────────────────────────


@dataclass
class Vm:
    """A ``Vm`` lifecycle row (``GET``/``POST /v1/vm/<vm_id>/…``)."""

    vm_id: str
    state: str
    version: int
    tenant_id: str | None = None
    lease_id: str | None = None
    generation: int | None = None
    new_generation: int | None = None
    host: str | None = None
    #: ISO 3166-1 alpha-2 country the VM runs in (its host's verified,
    #: detected location); ``None`` when unknown or on an older validator.
    region: str | None = None
    #: The public IPv4 attached to the VM, as ``{address, edge, region}``;
    #: ``None`` when it has none or on an older validator.
    public_ip: dict[str, str] | None = None
    migration_dest: str | None = None
    # In-guest boot progress, recorded by vali on the VM lifecycle row and
    # surfaced on ``GET /v1/vm/<vm_id>``. ``boot_phase`` is one of ``""``
    # (unset), ``booting``, ``kek_released``, ``running``; ``boot_phase_at`` is
    # the iso8601 timestamp of the last transition (or ``None``). Both are
    # ``None`` here on an older validator that omits the keys entirely.
    boot_phase: str | None = None
    boot_phase_at: str | None = None
    # The tenant's NetBird overlay IP, surfaced on ``GET /v1/vm/<vm_id>/state``.
    # ``""`` until the overlay peer resolves, then a ``100.x.y.z`` address —
    # the SSH-reachable IP for the guest. ``None`` here on an older validator
    # that omits the key entirely (see :func:`reports_netbird_ip`).
    netbird_ip: str | None = None
    # Overlay verdict: ``""`` (nothing to verify) | ``pending`` | ``ok`` |
    # ``lost``. ``lost`` means the VM is running but OFF the overlay (after a
    # §25 migration, or its peer record deleted) and CANNOT re-enrol itself.
    # With ``netbird_ip == ""`` the validator CLEARED the address (NetBird may
    # recycle it to another peer) — drop any copy; with an address, that
    # address is stale and unreachable. ``None`` here on an older validator
    # that omits the key entirely.
    netbird_status: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> Vm:
        return _build(cls, body)

    @property
    def netbird_lost(self) -> bool:
        """True iff the validator reports this VM as OFF the overlay.

        Explicitly False on an older validator that does not report the
        field — absence of the signal is not evidence of loss.
        """
        return self.netbird_status == "lost"


@dataclass
class MigrationJob:
    """A ``MigrationJob`` row (``POST``/``GET /v1/vm/<vm_id>/migrate``)."""

    job_id: str
    vm_id: str
    state: str
    version: int
    source_node_id: str | None = None
    dest_node_id: str | None = None
    source_gen: int | None = None
    new_gen: int | None = None
    source_ack_verified: bool | None = None
    snapshot_bucket: str | None = None
    snapshot_key: str | None = None
    quarantine_node_id: str | None = None
    reason: str | None = None
    decided_by: str | None = None
    phase_started_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> MigrationJob:
        return _build(cls, body)

    @property
    def is_terminal(self) -> bool:
        return self.state in MIGRATION_TERMINAL_STATES

    @property
    def is_done(self) -> bool:
        """The VM is Active on ``dest_node_id`` at ``new_gen``.

        The §25 split-brain fence guarantees the source can no longer unlock
        its disk once the migration commits: the destination is activated
        ONLY after a verified guest-signed source-stopped ack, and the KBS
        denies the old generation forever after.
        """
        return self.state == "done"

    @property
    def is_failed(self) -> bool:
        """The migration failed closed — the destination was NOT activated.

        Where the job failed decides the compensation: a ``draining`` failure
        leaves the VM untouched (still Active on the source), while a failure
        from ``quiescing`` on leaves it fenced (``Migrating``) — §25 recovery
        is forward-only. ``quarantine_node_id`` names a §13-quarantined source
        when the failure was an unproduced source ack.
        """
        return self.state == "failed"


@dataclass
class DecommissionJob:
    """A ``DecommissionJob`` row (``POST``/``GET /v1/vm/<vm_id>/decommission``)."""

    job_id: str
    vm_id: str
    state: str
    version: int
    eol_ack_verified: bool | None = None
    forced: bool | None = None
    quarantine_node_id: str | None = None
    reason: str | None = None
    decided_by: str | None = None
    phase_started_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> DecommissionJob:
        return _build(cls, body)

    @property
    def is_terminal(self) -> bool:
        return self.state in DECOMMISSION_TERMINAL_STATES

    @property
    def is_done(self) -> bool:
        """The VM's disk was crypto-erased and its NetBird peer revoked."""
        return self.state == "done"

    @property
    def is_failed(self) -> bool:
        return self.state == "failed"


@dataclass
class VmListPage:
    """``GET /v1/vm`` paginated response."""

    vms: list[Vm]
    limit: int
    offset: int
    total: int

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> VmListPage:
        return cls(
            vms=[Vm.from_dict(v) for v in body.get("vms", [])],
            limit=int(body.get("limit", 0)),
            offset=int(body.get("offset", 0)),
            total=int(body.get("total", 0)),
        )


# ─── Progress streaming ─────────────────────────────────────────────────


class ProvisionPhase(str, Enum):
    """A lifecycle phase for a VM provision.

    The bake half is coarse (bake ``state``: queued/running/succeeded/
    failed). The launch half is now **fine-grained**: when the validator
    populates the launch job's ``phase`` field (staging → placing →
    dispatching → launched/failed) the SDK maps it 1:1 so a frontend can
    show *where inside the launch* the worker is — secret staging, the §23
    scheduler choosing a miner, or the miner dispatch. Against an older
    server that omits ``phase`` the SDK falls back to the coarse launch
    ``state`` + ``miner_id`` derivation (``LAUNCH_QUEUED`` / ``RUNNING`` /
    ``PLACED``). In-guest boot / KEK-release remain miner+guest-side and are
    still not observable here.

    Values are lowercase wire-ish slugs so a frontend can serialise them
    (``str`` mix-in — ``ProvisionPhase.BAKING == "baking"``).
    """

    BAKING = "baking"
    BAKE_SUCCEEDED = "bake_succeeded"
    BAKE_FAILED = "bake_failed"
    LAUNCH_QUEUED = "launch_queued"
    # Fine-grained launch phases (server ``phase`` field). ``STAGING`` /
    # ``PLACING`` / ``DISPATCHING`` map from the launch job's ``phase``.
    STAGING = "staging"
    PLACING = "placing"
    DISPATCHING = "dispatching"
    # Coarse fallbacks kept for older servers (derived from state+miner_id).
    PLACED = "placed"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    # In-guest boot progress (server ``Vm.boot_phase``), polled AFTER the
    # launch is accepted: booting → kek_released → running. ``RUNNING`` is
    # reused as the terminal "the guest is up" phase (the launch-succeeded /
    # ``SUCCEEDED`` milestone now precedes it when the server reports boot).
    BOOTING = "booting"
    KEK_RELEASED = "kek_released"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


# Wire ``LaunchJob.phase`` (server) → the SDK's :class:`ProvisionPhase`.
# ``launched``/``failed`` are terminal and coincide with the launch
# ``state`` succeeded/failed. Absent from a row ⇒ fall back to the coarse
# state+miner_id derivation in :meth:`ProvisionStep.from_launch`.
_LAUNCH_PHASE_MAP: dict[str, ProvisionPhase] = {
    "queued": ProvisionPhase.LAUNCH_QUEUED,
    "staging": ProvisionPhase.STAGING,
    "placing": ProvisionPhase.PLACING,
    "dispatching": ProvisionPhase.DISPATCHING,
    "launched": ProvisionPhase.SUCCEEDED,
    "failed": ProvisionPhase.FAILED,
}


# Wire ``Vm.boot_phase`` (server) → the SDK's :class:`ProvisionPhase`. Empty /
# absent ⇒ an older validator that does not report guest-boot progress (the
# boot-wait ends gracefully at launch-succeeded). ``running`` is terminal.
_BOOT_PHASE_MAP: dict[str, ProvisionPhase] = {
    "booting": ProvisionPhase.BOOTING,
    "kek_released": ProvisionPhase.KEK_RELEASED,
    "running": ProvisionPhase.RUNNING,
}

# Monotonic ordering so the boot-wait yields a step ONLY when the guest
# advances (never regresses across polls / duplicate reads).
_BOOT_PHASE_ORDER: dict[ProvisionPhase, int] = {
    ProvisionPhase.BOOTING: 1,
    ProvisionPhase.KEK_RELEASED: 2,
    ProvisionPhase.RUNNING: 3,
}


# Phases that end the whole provisioning lifecycle. ``BAKE_SUCCEEDED`` is a
# milestone (the launch still follows), so it is intentionally NOT terminal.
# ``SUCCEEDED`` (launch accepted) stays terminal for backward compatibility
# against a validator with no boot reporting; when the server DOES report
# boot, the terminal moves on to ``RUNNING`` (the guest is up).
_TERMINAL_PHASES = frozenset(
    {
        ProvisionPhase.BAKE_FAILED,
        ProvisionPhase.SUCCEEDED,
        ProvisionPhase.RUNNING,
        ProvisionPhase.FAILED,
        ProvisionPhase.TIMED_OUT,
    }
)

# A rough 0-100 progress hint per phase. This is an ESTIMATE mapped from the
# coarse phase — the API exposes no real percentage. Terminal-failure phases
# report 100 to mean "the operation concluded" (not "succeeded"); branch on
# ``phase`` / ``terminal`` to distinguish success from failure.
_PHASE_PCT: dict[ProvisionPhase, int] = {
    ProvisionPhase.BAKING: 20,
    ProvisionPhase.BAKE_SUCCEEDED: 45,
    ProvisionPhase.LAUNCH_QUEUED: 55,
    # Fine-grained launch progression (monotonic non-decreasing so a
    # single provision's pct never regresses): staging → placing →
    # dispatching. ``RUNNING`` (coarse fallback) sits between queued and
    # placing; ``PLACED`` (coarse fallback) sits just after dispatching.
    ProvisionPhase.STAGING: 60,
    ProvisionPhase.RUNNING: 65,
    ProvisionPhase.PLACING: 70,
    ProvisionPhase.DISPATCHING: 80,
    ProvisionPhase.PLACED: 85,
    ProvisionPhase.SUCCEEDED: 100,
    ProvisionPhase.BAKE_FAILED: 100,
    ProvisionPhase.FAILED: 100,
    ProvisionPhase.TIMED_OUT: 100,
}

# Boot sub-progress rides at the top of the bar (launch-succeeded is already
# 100). A frontend distinguishes booting / kek_released / running by ``phase``
# and ``detail`` rather than by pct; kept at 100 so a single provision's pct
# never regresses once the launch has been accepted.
_BOOT_PHASE_PCT: dict[ProvisionPhase, int] = {
    ProvisionPhase.BOOTING: 100,
    ProvisionPhase.KEK_RELEASED: 100,
    ProvisionPhase.RUNNING: 100,
}


def boot_phase_of(vm: Vm) -> ProvisionPhase | None:
    """Map a ``Vm.boot_phase`` wire string to a :class:`ProvisionPhase`.

    Returns ``None`` when the row carries no (or an unknown / empty)
    ``boot_phase`` — i.e. an older validator that never reports guest-boot
    progress, or a newer one that has not observed the first boot event yet.
    """
    if not vm.boot_phase:
        return None
    return _BOOT_PHASE_MAP.get(vm.boot_phase)


def reports_boot_phase(vm: Vm) -> bool:
    """Whether the server populated the ``boot_phase`` key at all.

    Distinguishes a newer validator (key present, possibly ``""``) from an
    older one that omits it, so the boot-wait can stop immediately against an
    older server instead of polling to its timeout.
    """
    return "boot_phase" in vm.raw


def reports_netbird_ip(vm: Vm) -> bool:
    """Whether the server populated the ``netbird_ip`` key at all.

    Distinguishes a newer validator (key present, possibly ``""`` until the
    overlay peer resolves) from an older one that omits it, so the NetBird-IP
    wait can stop immediately against an older server instead of polling to
    its timeout.
    """
    return "netbird_ip" in vm.raw


def boot_advanced(last: ProvisionPhase | None, phase: ProvisionPhase) -> bool:
    """Whether ``phase`` is strictly past ``last`` in boot ordering."""
    return last is None or _BOOT_PHASE_ORDER[phase] > _BOOT_PHASE_ORDER[last]


def _boot_detail(phase: ProvisionPhase, vm: Vm) -> str:
    """Human-readable detail for a boot-derived :class:`ProvisionStep`."""
    if phase is ProvisionPhase.KEK_RELEASED:
        return "kek released — unlocking encrypted disk"
    if phase is ProvisionPhase.RUNNING:
        base = f"guest running on {vm.host}" if vm.host else "guest running"
        return f"{base} — netbird {vm.netbird_ip}" if vm.netbird_ip else base
    return "guest booting"


def _launch_detail(phase: ProvisionPhase, job: LaunchJob) -> str:
    """Human-readable detail for a launch-derived :class:`ProvisionStep`."""
    if phase is ProvisionPhase.SUCCEEDED:
        return f"vm running on {job.miner_id}" if job.miner_id else "launch succeeded"
    if phase is ProvisionPhase.FAILED:
        return f"launch failed: {job.reason}"
    if phase is ProvisionPhase.LAUNCH_QUEUED:
        return "launch queued"
    if phase is ProvisionPhase.STAGING:
        return "staging launch secrets"
    if phase is ProvisionPhase.PLACING:
        return "scheduler placing on a miner"
    if phase is ProvisionPhase.DISPATCHING:
        return (
            f"dispatching to {job.miner_id}" if job.miner_id else "dispatching to miner"
        )
    if phase is ProvisionPhase.PLACED:
        return f"placed on {job.miner_id}"
    return "launch running"


@dataclass
class ProvisionStep:
    """One progress event emitted per poll while provisioning a VM.

    Built from the current bake / launch row, so it never claims more detail
    than the API provides. ``raw`` carries the full parsed API dict for a
    frontend that wants any other field.
    """

    phase: ProvisionPhase
    state: str
    detail: str
    pct: int
    miner_id: str | None = None
    reason: str | None = None
    # The tenant's NetBird overlay IP (``100.x.y.z``), carried on the boot
    # steps once the server reports it — so a frontend rendering the
    # ``booting → kek_released → running`` stream can surface the SSH-reachable
    # IP. ``None`` on non-boot steps and until the overlay peer resolves.
    netbird_ip: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def terminal(self) -> bool:
        """Whether this phase ends the whole provisioning lifecycle.

        ``BAKE_SUCCEEDED`` is a milestone, not terminal — the launch follows.
        """
        return self.phase in _TERMINAL_PHASES

    @classmethod
    def from_bake(cls, bake: Bake) -> ProvisionStep:
        """Derive a step from a ``Bake`` row (bake state → BAKING / *)."""
        if bake.is_succeeded:
            phase = ProvisionPhase.BAKE_SUCCEEDED
            detail = "bake succeeded"
        elif bake.is_failed:
            phase = ProvisionPhase.BAKE_FAILED
            detail = f"bake failed: {bake.failure_reason}"
        else:
            phase = ProvisionPhase.BAKING
            detail = f"bake {bake.state}"
        return cls(
            phase=phase,
            state=bake.state,
            detail=detail,
            pct=_PHASE_PCT[phase],
            reason=bake.failure_reason if phase is ProvisionPhase.BAKE_FAILED else None,
            raw=bake.raw,
        )

    @classmethod
    def from_launch(cls, job: LaunchJob) -> ProvisionStep:
        """Derive a step from a ``LaunchJob`` row.

        Prefers the server's fine-grained ``phase`` (staging/placing/
        dispatching/launched/failed → the matching :class:`ProvisionPhase`)
        when the row carries one. Falls back to the coarse state+miner_id
        derivation for an older server that omits ``phase``: queued →
        LAUNCH_QUEUED; running & ``miner_id`` set → PLACED; running &
        unplaced → RUNNING; succeeded → SUCCEEDED; failed → FAILED.
        """
        server_phase = _LAUNCH_PHASE_MAP.get(job.phase) if job.phase else None
        if server_phase is not None:
            phase = server_phase
        elif job.is_succeeded:
            phase = ProvisionPhase.SUCCEEDED
        elif job.is_failed:
            phase = ProvisionPhase.FAILED
        elif job.state == "queued":
            phase = ProvisionPhase.LAUNCH_QUEUED
        elif job.miner_id:
            phase = ProvisionPhase.PLACED
        else:
            phase = ProvisionPhase.RUNNING
        return cls(
            phase=phase,
            state=job.state,
            detail=_launch_detail(phase, job),
            pct=_PHASE_PCT[phase],
            miner_id=job.miner_id,
            reason=job.reason if phase is ProvisionPhase.FAILED else None,
            raw=job.raw,
        )

    @classmethod
    def from_boot(cls, vm: Vm) -> ProvisionStep:
        """Derive a step from a ``Vm`` row's guest ``boot_phase``.

        Maps ``booting`` / ``kek_released`` / ``running`` to the matching
        :class:`ProvisionPhase`. The caller must ensure the row carries a
        known boot phase (see :func:`boot_phase_of`).
        """
        phase = _BOOT_PHASE_MAP[vm.boot_phase or ""]
        return cls(
            phase=phase,
            state=vm.state,
            detail=_boot_detail(phase, vm),
            pct=_BOOT_PHASE_PCT[phase],
            netbird_ip=vm.netbird_ip or None,
            raw=vm.raw,
        )

    @classmethod
    def timed_out(cls, *, state: str, detail: str, raw: dict[str, Any]) -> ProvisionStep:
        """A step for a poll loop that exceeded its ``timeout`` budget."""
        return cls(
            phase=ProvisionPhase.TIMED_OUT,
            state=state,
            detail=detail,
            pct=_PHASE_PCT[ProvisionPhase.TIMED_OUT],
            raw=raw,
        )


# A progress callback fires once per poll (including the first and terminal
# poll) with the current :class:`ProvisionStep`. Exceptions it raises are
# swallowed so a bad UI callback never crashes the poll loop.
OnProgress = Callable[[ProvisionStep], None]


def _build(cls: type, body: dict[str, Any]) -> Any:
    """Instantiate a response dataclass from a wire dict.

    Only known fields are mapped; the full payload is retained under ``raw``
    so a server that adds a field never breaks the client.
    """
    known = {f.name for f in fields(cls)} - {"raw"}
    kwargs = {k: v for k, v in body.items() if k in known}
    return cls(raw=dict(body), **kwargs)


#: Power states a VM can be in. Orthogonal to :attr:`VmState.state` — a
#: stopped VM stays ``active`` there, because that field is the KBS release
#: gate and the VM must still be able to unlock when it starts again.
VM_POWER_RUNNING = "running"
VM_POWER_STOPPING = "stopping"
VM_POWER_STOPPED = "stopped"
VM_POWER_STARTING = "starting"
#: Terminal: the VM is ``destroyed``; no guest can run again.
VM_POWER_OFF = "off"


@dataclass
class VmPower:
    """The result of a power operation (``stop`` / ``start`` / ``reboot``).

    ``state`` is the LIFECYCLE state and stays ``active`` across a stop —
    only ``power_state`` moves. ``host`` is the miner holding this VM's
    encrypted overlay; ``start`` always relaunches there, never elsewhere.
    """

    vm_id: str
    state: str
    power_state: str
    host: str | None = None
    power_state_at: str | None = None

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> VmPower:
        return _build(cls, body)

    @property
    def is_stopped(self) -> bool:
        return self.power_state == VM_POWER_STOPPED

    @property
    def is_running(self) -> bool:
        return self.power_state == VM_POWER_RUNNING

    @property
    def is_settled(self) -> bool:
        """False while a stop/start is still in flight on the miner."""
        return self.power_state in (VM_POWER_RUNNING, VM_POWER_STOPPED, VM_POWER_OFF)
