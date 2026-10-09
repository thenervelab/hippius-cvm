"""VM lifecycle state model.

Spec: ARCHITECTURE.md §24 (decommission) / §25 (migration). The
on-chain authoritative state for a VM lives in
`kbs_core::lifecycle::VmState` (Rust enum); this Django model is the
vali-side mirror used by the orchestrator to drive transitions —
NOT the KBS gate. The KBS still re-checks every release independently
against its own durable state store; vali's row is the *intent* + the
audit trail.

Optimistic concurrency: every row carries a `version` counter that is
bumped on each transition. The transition endpoint takes
`if_version` from the caller and updates `WHERE version =
if_version`; a concurrent writer that already bumped the version
sees zero rows updated and 409s. No row-level lock; no serializable
transaction; the CAS is enough for the §24/§25 happy paths.

Mapping to the Rust `VmState` enum:

  VmState::Active { gen, host, lease_id }
      → state="active"   generation=gen   host=host
        migration_dest="" new_generation=NULL
  VmState::Migrating { old_gen, new_gen, source, dest, lease_id }
      → state="migrating" generation=old_gen host=source
        migration_dest=dest new_generation=new_gen
  VmState::Decommissioning
      → state="decommissioning" (other fields preserve last Active values)
  VmState::Destroyed { gen }
      → state="destroyed" generation=gen

PR-G2 ships the model + GET/POST endpoints. The orchestration that
mutates this row from outside (e.g. the §25 migration driver that
issues NetBird commands) is PR-G5.
"""

from __future__ import annotations

import secrets
import uuid

from django.db import models
from django.utils import timezone


class VmState(models.TextChoices):
    """Mirror of `kbs_core::lifecycle::VmState` discriminants.

    Pinned strings (not auto-numbered) so the value in Postgres
    is stable across renames AND mirrors the canonical CBOR
    discriminator the KBS uses on the wire.
    """

    ACTIVE = "active", "Active"
    MIGRATING = "migrating", "Migrating"
    DECOMMISSIONING = "decommissioning", "Decommissioning"
    DESTROYED = "destroyed", "Destroyed"


class VmPowerState(models.TextChoices):
    """Whether the guest is meant to be RUNNING right now.

    Deliberately NOT part of [`VmState`]: that enum mirrors the KBS's
    lifecycle discriminants, which gate every KEK release. A stopped VM
    must still unlock when it starts again, so it stays `active` there.

    `stopping` / `starting` are the in-flight states an operator sees
    between the API accepting the request and the miner confirming it.
    They exist so a second stop on an already-stopping VM is refused
    rather than dispatched twice.
    """

    RUNNING = "running", "Running"
    STOPPING = "stopping", "Stopping"
    STOPPED = "stopped", "Stopped"
    STARTING = "starting", "Starting"
    # Terminal: the VM is `destroyed` (§24), so no guest can run again.
    # Set in the same CAS as the tombstone; nothing moves it afterwards.
    OFF = "off", "Off"


class VmBootPhase(models.TextChoices):
    """Guest-boot progress milestones the miner-agent reports post-launch.

    A launch that is `phase=launched` boots asynchronously on the miner;
    the miner-agent POSTs signed `verify-vm-progress` milestones (relayed
    by the Edge, exactly like graceful-exit) which advance this field
    MONOTONICALLY through `booting → kek_released → running`.

    NOTE the value/wire split: the Python (DB) values use UNDERSCORES
    (`kek_released`) while the on-the-wire milestone the verifier emits
    uses HYPHENS (`kek-released`). `Vm.advance_boot_phase` maps the wire
    value to the choice.
    """

    BOOTING = "booting", "Booting"
    KEK_RELEASED = "kek_released", "KEK released"
    RUNNING = "running", "Running"


class VmGuestLiveness(models.TextChoices):
    """Is there POSITIVE evidence from inside the guest, recently?

    The answer `boot_phase` cannot give. `boot_phase` is monotonic — once
    a VM has ever reached `running` it stays `running` forever — and
    `orchestration.effects.poll_domain_running` only proves a QEMU process
    exists. A guest wedged in its initramfs (KEK release refused, corrupt
    overlay, unreachable KBS, boot-counter refusal) satisfies BOTH while
    serving nothing. See `apps.lifecycle.guest_liveness` for the live
    proof and the signal choice.

    - `alive`   — an in-guest-originated signal landed within
                  `VALI_GUEST_LIVENESS_STALE_S`.
    - `wedged`  — this VM HAS emitted before, but nothing inside the
                  staleness bound. The silent-green case.
    - `unknown` — this VM has NEVER emitted an in-guest signal (no
                  telemetry agent in its image, still on its first boot,
                  or a row that predates the watermark). NOT `wedged`:
                  absence of evidence is not evidence of death, and
                  `unknown` MUST NEVER drive an automated action.

    Derived at read time from `guest_signal_at` — never stored, so it can
    never go stale against the watermark it summarises.
    """

    ALIVE = "alive", "Alive"
    WEDGED = "wedged", "Wedged"
    UNKNOWN = "unknown", "Unknown"


class VmNetbirdStatus(models.TextChoices):
    """Post-§25 NetBird overlay reachability verdict for a tenant VM.

    A §25 COLD migration moves the guest-keyed overlay intact, so the
    guest's own NetBird identity (`/var/lib/netbird/config.json`) survives
    the move. What did NOT survive is the MANAGEMENT-SIDE peer record:
    `effects.mint_netbird_setup_key` minted every tenant key
    `ephemeral: True` until tenant peers became persistent (VMs launched
    since keep their record across any downtime; older ones still carry
    the ephemeral peer), and NetBird deletes an ephemeral peer after ~10 min
    offline — a window a cold migration (quiesce → snapshot → upload →
    download → boot; the dest-activation poll alone budgets 20 min)
    routinely exceeds. The destination cannot re-enrol either: cloud-init
    re-runs `netbird up` on every boot (the initramfs writes a per-boot
    instance-id) but with the LAUNCH-time key, which is `usage_limit=1`
    and already consumed.

    So a migration can complete, report Done, unlock the disk and run —
    with the tenant permanently unable to reach the machine. This field
    is the SIGNAL for that; §25 does not re-enrol today.

    - `""`       — nothing to verify (netbird-disabled VM, or a VM that
                   has never been migrated).
    - `pending`  — a migration just activated; the sweep is waiting for
                   the peer to come back CONNECTED, until
                   `netbird_verify_deadline`.
    - `ok`       — the peer was observed connected after the migration.
    - `lost`     — the peer record is gone from NetBird management (or
                   never reconnected before the deadline). The tenant is
                   OFF the overlay and cannot self-heal. Also set, with
                   `netbird_ip` cleared, for any `active` VM whose peer
                   record disappears (`netbird_binding.refresh_overlay_ips`),
                   and back to `ok` once its peer is seen connected.
    """

    PENDING = "pending", "Verification pending"
    OK = "ok", "On the overlay"
    LOST = "lost", "Off the overlay"


# The monotonic order of the boot phases — a milestone may only advance
# to a strictly-higher rank (a late/replayed lower milestone never
# regresses the recorded phase). Keyed by the underscore CHOICE value.
_BOOT_PHASE_RANK: dict[str, int] = {
    VmBootPhase.BOOTING.value: 1,
    VmBootPhase.KEK_RELEASED.value: 2,
    VmBootPhase.RUNNING.value: 3,
}

# The wire (hyphen) milestone → the underscore `VmBootPhase` choice value.
_BOOT_PHASE_WIRE_TO_CHOICE: dict[str, str] = {
    "booting": VmBootPhase.BOOTING.value,
    "kek-released": VmBootPhase.KEK_RELEASED.value,
    "running": VmBootPhase.RUNNING.value,
}


def _fresh_eol_nonce() -> bytes:
    """Default-factory for `Vm.eol_nonce`: 32 cryptographically random
    bytes from `secrets.token_bytes`. The guest signs THIS exact value
    inside its StoppedAck; a new nonce is minted each time vali asks
    for an EOL ack (set when transitioning to Decommissioning or
    Migrating).
    """
    return secrets.token_bytes(32)


def destroyed_power_fields() -> dict:
    """What a `Destroyed` tombstone sets on the power axis, in the same CAS
    as the state: terminal `off`, and no stop proof (it described a boot
    that can never run again). A tombstone left reading `running` looks
    like a zombie to anyone reading the row."""
    return {
        "power_state": VmPowerState.OFF.value,
        "power_state_at": timezone.now(),
        "power_stop_proof": None,
        "power_stop_ordered_at": None,
    }


class VmQuerySet(models.QuerySet):
    """`update()` stamps `updated_at`: a queryset update skips `auto_now`,
    and the §24/§25 transitions are CAS updates — without this a row
    destroyed on 09-27 read `updated_at` from 09-25."""

    def update(self, **kwargs):
        kwargs.setdefault("updated_at", timezone.now())
        return super().update(**kwargs)


class Vm(models.Model):
    """Single source of intent for a VM's lifecycle position.

    Field-by-field:

    - `vm_id`              §6 ticket identifier (unique).
    - `lease_id`           §6 lease the VM is bound to. Indexed —
                           lookups by lease are routine in §25.
    - `state`              one of `VmState`.
    - `generation`         `kbs_core::VmState::Active{gen}` /
                           `Migrating{old_gen}` / `Destroyed{gen}`.
                           For Migrating, `new_generation` is the
                           `new_gen` half; for the others it's NULL.
    - `host`               currently-bound host. In Migrating this
                           is the `source`; PR-G5 uses it to address
                           the NetBird peer for the EOL command.
    - `migration_dest`     destination host during Migrating. Empty
                           otherwise.
    - `new_generation`     `Migrating{new_gen}` half. NULL outside
                           Migrating.
    - `lifecycle_vk`       guest's Ed25519 lifecycle pubkey (32 bytes,
                           binary). Provisioned via the §7 attested
                           release; vali stores it for the stopped-
                           ack verifier. NOT secret — the matching
                           private half lives in mlocked guest RAM.
    - `eol_nonce`          single-use 32-byte nonce vali issues when
                           it asks the guest to stop. Set whenever
                           the row transitions to Decommissioning OR
                           Migrating. Consumed (cleared) on the
                           Destroyed / migration-complete transition.
    - `version`            optimistic-concurrency counter. Starts at
                           1, +1 per successful transition.
    - `created_at`,
      `updated_at`         auditing.

    Constraints:

    - `(vm_id)` unique.
    - `Migrating ⇒ new_generation IS NOT NULL` (DB CHECK).
    - `Migrating ⇒ migration_dest != ""` (DB CHECK).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=256, unique=True)
    lease_id = models.CharField(max_length=256, db_index=True)
    # #587 Phase 2 — the owning tenant, stamped at launch from the spec
    # (the upstream product API already authorized it). Indexed so the
    # `GET /v1/vm?tenant_id=` list can filter for DISPLAY; this is NOT an
    # authz boundary (the upstream owns end-user access control). Blank
    # for pre-Phase-2 rows.
    tenant_id = models.CharField(max_length=256, blank=True, default="", db_index=True)
    # Anti-affinity: never two VMs of one (tenant, group) on a miner
    # (`scheduler.service.group_nodes`). Set at launch, never changed.
    placement_group = models.CharField(max_length=64, blank=True, default="")
    state = models.CharField(max_length=32, choices=VmState.choices)
    # `kbs_core::lifecycle::VmState` uses `u64`. Postgres BIGINT is
    # signed — `binaries/ticket-validator` pre-rejects u64 > i64::MAX
    # at intake (the value couldn't have reached vali if it didn't fit).
    generation = models.BigIntegerField()
    new_generation = models.BigIntegerField(null=True, blank=True)
    # The generation the GUEST signs its EOL `stopped{}` acks at — the
    # value baked into the MEASURED cmdline (`hippius.vm_generation`) at
    # launch. It is IMMUTABLE for the VM's life: a §25 COLD migration bumps
    # `generation` (the KBS anti-rollback fence) but NEVER re-bakes the
    # guest, so the guest keeps signing at this launch value. vali verifies
    # the ack ingest + `_verify_ack` at `signing_generation`, NOT the live
    # `generation` — else a migrated VM's §24 / re-migration ack mismatches
    # the guest (guest signs launch-gen, vali would check the bumped gen).
    # Defaults to 1 (== `_LAUNCH_GENERATION`, the value every launch bakes)
    # so existing rows backfill correctly.
    signing_generation = models.BigIntegerField(default=1)
    host = models.CharField(max_length=256, blank=True)
    migration_dest = models.CharField(max_length=256, blank=True)
    # 32-byte Ed25519 lifecycle vk. BinaryField rather than hex CharField
    # to keep the wire/storage byte-exact (the verifier accepts hex
    # because subprocess argv is text).
    lifecycle_vk = models.BinaryField(max_length=32)
    eol_nonce = models.BinaryField(max_length=32, null=True, blank=True)
    # Tenant-agreed max price per resource-unit (USD ×1e6, same scale as
    # the on-chain `MinerPrice`). A vali-side POLICY field — NOT part of
    # the L1-signed order ticket. `NULL` ⇒ the tenant accepts any miner
    # price, so the VM is never migrated on a price change. The
    # price-watch (§3.2) migrates the VM off a miner whose announced price
    # would exceed this. Set at launch; survives migration (the row is
    # keyed by the stable `vm_id`).
    max_price_per_unit = models.BigIntegerField(null=True, blank=True)
    # ── Customer-held disk keys — pinned at first launch, IMMUTABLE ──
    # Who holds the disk key: `hippius` (M0, every VM before this column),
    # `split` (M1) or `customer` (M2), plus the guardian the measured
    # cmdline names. Written ONCE by `launch._ensure_vm_row` when it
    # creates the row; every relaunch / re-mint / §25 / restore path
    # compares against it (`services.customer_keys`) and refuses a
    # difference, so an M1/M2 VM is never re-minted as M0. Mode switching
    # is launch-time only.
    key_mode = models.CharField(max_length=16, default="hippius", db_default="hippius")
    guardian_endpoint = models.CharField(
        max_length=259, blank=True, default="", db_default=""
    )
    guardian_pubkey = models.CharField(
        max_length=64, blank=True, default="", db_default=""
    )
    version = models.PositiveBigIntegerField(default=1)
    # Guest-boot progress mirror (miner-agent → Edge → vali). Blank until
    # the first signed `verify-vm-progress` milestone lands; advanced
    # MONOTONICALLY by `advance_boot_phase`. Display-only (NOT a KBS/
    # lifecycle gate) — a purely informational readout for the tenant.
    boot_phase = models.CharField(
        max_length=16,
        blank=True,
        default="",
        choices=VmBootPhase.choices,
    )
    # When `boot_phase` was last advanced. NULL until the first milestone.
    boot_phase_at = models.DateTimeField(null=True, blank=True)
    # When `running` was INFERRED from a live attestation of the current
    # launch (`apps.telemetry.vm_liveness`) because nothing else set it. In
    # practice `running` comes only from a served receipt: the miner-agent
    # reports `booting` and `kek-released` but never `running`. NULL when a
    # receipt set it, or nothing did. Observability only.
    boot_phase_inferred_at = models.DateTimeField(null=True, blank=True)
    # When the VM's CURRENT boot began: the first host bind of a launch, a
    # §25 dest activation, or a reboot-recovery / power-start relaunch. The
    # clock for the boot-stall verdict (`apps.lifecycle.boot_stall`): no
    # in-guest signal since this instant, past a per-flavor deadline, reads
    # stalled. NULL on rows from before the column; the verdict falls back
    # to `created_at`.
    boot_started_at = models.DateTimeField(null=True, blank=True)
    # ── Power state — ORTHOGONAL to `state`, deliberately ─────────────
    # `state` mirrors `kbs_core::lifecycle::VmState`, which the KBS checks
    # serializably before EVERY release. A stopped VM must still be able to
    # unlock when it starts again, so it stays `state=active` there; a
    # `Stopped` lifecycle variant would make the KBS refuse the guest its
    # own KEK. Powering a VM off is therefore not a lifecycle transition —
    # it is a separate axis, and this field is that axis.
    #
    # A stopped VM KEEPS its reservation: the encrypted overlay, the
    # Vault-Transit KEK, the anti-rollback counter and its slot on a
    # specific miner all persist, which is what makes `start` able to
    # succeed on the same host. That retention is what the tenant-billing
    # layer charges for (billing itself lives above this repo).
    #
    # ⚠️ It does NOT make the miner paid. `UsageAccrual` accrues only from
    # guest-attested served-receipts, and a stopped guest emits none — a
    # miner is paid for VM time genuinely UP, never for parked VMs. Do not
    # "fix" that to follow tenant billing; the two ledgers answer different
    # questions.
    power_state = models.CharField(
        max_length=16,
        default=VmPowerState.RUNNING,
        choices=VmPowerState.choices,
        db_index=True,
    )
    # When `power_state` last changed. NULL until the first stop/start —
    # the billing layer reads it to know how long the reservation has been
    # held idle.
    power_state_at = models.DateTimeField(null=True, blank=True)
    # The `eol_nonce` of the boot a power stop shut down, recorded when that
    # guest's signed stopped-ack verified at ingest (while `stopping`).
    # Cleared by every power transition other than to `stopped`. §24 of a
    # stopped VM takes it as its EOL ack: the ack itself cannot verify then,
    # its signed time being out of skew by the time anyone decommissions.
    power_stop_proof = models.BinaryField(max_length=32, null=True, blank=True)
    # The `power_state_at` of a `stopped` reached by a COMPLETED power stop
    # order (`power.stop_vm`): the miner then holds the domain as stopped by
    # the agent and never restarts it on its own. It describes the CURRENT
    # stop only while it EQUALS `power_state_at` — every power write stamps
    # `power_state_at` (including those of an older image during a rollout,
    # which does not know this column), so any later transition, an
    # abandoned marker settled from one "down" poll, a refused start, a
    # restore abort, makes it stale without having to clear it. What
    # `vali_swap_vm_initrd --revert` needs before it rewrites a relaunched
    # VM's recorded boot (`Vm.stopped_by_order`).
    power_stop_ordered_at = models.DateTimeField(null=True, blank=True)
    # The `power_state_at` of a `stopped` reached because the GUEST powered
    # itself off and the VM's guest-poweroff policy is `stop`
    # (`apps.orchestration.power_policy`). Same "current only while it
    # EQUALS `power_state_at`" rule as `power_stop_ordered_at`: any later
    # power write makes it stale without clearing it. Read as
    # `stop_reason: guest-poweroff` (`Vm.stopped_by_guest`).
    power_stopped_by_guest_at = models.DateTimeField(null=True, blank=True)
    # When a VM under the `stop` guest-poweroff policy last delivered a
    # VERIFIED stopped-ack while vali still had it `running` — the ack its
    # guest's EOL hook signs on any in-guest shutdown. When the miner then
    # reports the guest powered off, an ack this recent becomes the stop's
    # `power_stop_proof` (`power_policy.settle_guest_poweroff`), so a §24 of
    # the stopped VM is a clean, non-quarantining one like after an API stop.
    power_guest_ack_at = models.DateTimeField(null=True, blank=True)
    # ── Guest-poweroff policy (`apps.orchestration.power_policy`) ─────
    # What the miner does when the guest powers ITSELF off: start it again
    # (`restart`, the historic behaviour) or leave it stopped (`stop`). A
    # crash is restarted either way. `on_guest_poweroff` is what the tenant
    # asked for; `_effective` is what a miner ACKNOWLEDGED (a launch that
    # carried it, or an accepted `power-policy` order), and only for the
    # host in `_effective_host` — a VM that moved since reads `restart`
    # there until the new host acknowledges. `db_default`s keep an older
    # image's INSERTs valid during a roll.
    on_guest_poweroff = models.CharField(
        max_length=8,
        choices=[("restart", "restart"), ("stop", "stop")],
        default="restart",
        db_default="restart",
    )
    on_guest_poweroff_effective = models.CharField(
        max_length=8,
        choices=[("restart", "restart"), ("stop", "stop")],
        default="restart",
        db_default="restart",
    )
    on_guest_poweroff_effective_host = models.CharField(
        max_length=256, blank=True, default="", db_default=""
    )
    # ── In-guest liveness watermark ──────────────────────────────────
    # Wall-clock of the newest signal that could ONLY have come from
    # inside a running guest: a §23 `served_receipt` (universal across
    # the live fleet) or a §322 `VmLiveAttestation` (newer images only).
    # Advanced MONOTONICALLY by `guest_liveness.record_signal` from the
    # telemetry-ingest path; NULL means this VM has never emitted one —
    # `unknown`, NOT dead. Indexed: the orchestration tick sweeps Active
    # VMs on it every cycle.
    #
    # Unlike `boot_phase` (monotonic, so permanently `running` once
    # reached) this value GOES STALE — that staleness is the whole point:
    # it is what distinguishes a booted-and-alive guest from one wedged in
    # its initramfs behind a libvirt domain that is still `running`.
    guest_signal_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # Which signal set the watermark (`served_receipt` | `live_attestation`
    # | "" when never). Display/diagnostic only — the verdict depends on
    # the timestamp, not on which agent produced it.
    guest_signal_kind = models.CharField(max_length=32, blank=True, default="")
    # ── Customer-held keys: waiting on the tenant's key guardian ──────
    # The latest signed `awaiting-guardian` vm-progress milestone for an
    # M1/M2 VM (`apps.lifecycle.guardian_wait`): the guest sits in its
    # initramfs until the customer's guardian answers, BEFORE any KBS
    # release (design §6). DISPLAY-only and weak (the miner derives it from
    # the traffic it relays, so it can suppress or forge it); its one
    # automated use is to hold back timers that would otherwise read the
    # wait as a failure — bounded by `VALI_GUARDIAN_WAIT_MAX_PAUSE_S`.
    #
    # `guardian_wait_reason` — the closed-vocabulary reason
    # (`unreachable`, `timeout`, `refused:<reason>`, `bad-response`), ""
    # once a later milestone (`kek-released` / `running`) proves the guest
    # got past its guardian. `guardian_wait_since` — when this wait began.
    # `guardian_wait_at` — the newest report (freshness), kept after the
    # clear so a timer can credit the time the guest spent waiting.
    guardian_wait_reason = models.CharField(
        max_length=64, blank=True, default="", db_default=""
    )
    guardian_wait_since = models.DateTimeField(null=True, blank=True)
    guardian_wait_at = models.DateTimeField(null=True, blank=True)
    # Ordering on the SIGNED timestamps (delivery is fire-and-forget and can
    # reorder): the newest recorded wait report's, and the newest clearing
    # milestone's (`kek-released` / `running`). A wait report no newer than
    # the latter is dropped, so a late report never re-arms a cleared wait.
    guardian_wait_signed_at = models.DateTimeField(null=True, blank=True)
    guardian_wait_cleared_at = models.DateTimeField(null=True, blank=True)
    # Tenant NetBird overlay IP (`100.x.y.z`). Resolved OPPORTUNISTICALLY
    # from the NetBird management API on the first served-receipt ingest
    # after the guest enrols (see telemetry `service.
    # _advance_tenant_vm_boot_progress`), then cached here. Blank until
    # resolved. DISPLAY-only — surfaced on `GET /state`; the read path
    # NEVER makes an outbound NetBird call (the value is populated on the
    # receipt-ingest worker path so `/state` reads are a pure DB lookup).
    netbird_ip = models.CharField(max_length=64, blank=True, default="")
    # The NetBird peer id of THIS VM's peer: the peer that last enrolled
    # with a setup key vali minted for it (`VmNetbirdKey`, bound by
    # `orchestration.netbird_binding`). Blank until bound, and forever for a
    # VM launched before keys were recorded. When set it is AUTHORITATIVE:
    # the resolvers find the peer by this id, not by its name (a name is
    # whatever hostname the guest sent — a claim), and §24 deletes it by id.
    netbird_peer_id = models.CharField(max_length=64, blank=True, default="")
    # Post-§25 overlay reachability verdict — see `VmNetbirdStatus` for the
    # failure it exists to make visible. Set to `pending` by the §25
    # dest-activation CAS (only for a VM that HAD a resolved `netbird_ip`,
    # i.e. one we know was on the overlay and can resolve by peer name), then
    # driven to `ok` / `lost` by `orchestration.service.
    # verify_netbird_enrolments()` on the tick. DISPLAY + alerting only —
    # never a lifecycle/KBS gate.
    netbird_status = models.CharField(
        max_length=16,
        blank=True,
        default="",
        choices=VmNetbirdStatus.choices,
        db_index=True,
    )
    # Deadline for the `pending` verification. NULL unless pending. A peer
    # that is present but not yet connected is given until this instant to
    # come back before it is declared `lost` — so a slow-booting guest that
    # DOES rejoin is not falsely flagged.
    netbird_verify_deadline = models.DateTimeField(null=True, blank=True)
    # ── Abandoned-launch marker (the PHANTOM leak) ────────────────────
    # `launch_on_miner` creates this row at step 0 — BEFORE the Vault
    # stage, the KBS register and the dispatch — precisely so a VM that
    # boots is never invisible to the control plane. The mirror hazard is
    # a launch that dies AFTER those effects and never binds a host: the
    # row is left `state=active host=""` with a LIVE per-VM Vault-Transit
    # KEK and no VM anywhere. Seen in production 2026-08-13 (three
    # consecutive `dispatch-failed-after-register` onto a miner that
    # could not start a CVM). Such a row is counted LIVE by every sweep
    # that filters `exclude(state='destroyed')`, and nothing ever reaps it.
    #
    # These three columns are that marker — written by `launch.launch_vm` /
    # `launch_on_named_miner` when a launch terminates without binding a
    # host, and CLEARED by `launch._bind_vm_host` the instant one does.
    #
    # - `launch_abandoned_at`         when the last launch for this row gave
    #                                 up (NULL ⇒ no abandoned launch; the
    #                                 grace window is measured from here).
    # - `launch_abandoned_outcome`    the `LaunchResult.outcome` it gave up
    #                                 with — operator-facing only.
    # - `launch_abandoned_registered` TRUE iff the launch got PAST the §24
    #                                 KBS `register-vm` (step 8). This is
    #                                 the reap gate: a registered vm_id is
    #                                 permanently bound at the KBS to a host
    #                                 it never ran on, so it can never be
    #                                 re-launched anywhere (the anti-migration
    #                                 CAS fence → `kbs-admin-conflict`) and
    #                                 reaping it forfeits nothing. A
    #                                 PRE-register abandonment is only
    #                                 SURFACED — that vm_id is still
    #                                 theoretically launchable, and erasing a
    #                                 KEK is not a thing to do to a VM an
    #                                 operator may still be able to save.
    #
    # ⚠️ That hold-back has ONE exception, and it is not a weakening of it:
    # a launch that never baked a measured cmdline at all (`eol_nonce` is
    # NULL — `service.cmdline_was_baked`) never dispatched, so no guest ever
    # `luksFormat`ed an overlay under this VM's KEK. There is no tenant data
    # to save, only a live per-VM Vault-Transit key with no VM. It is also
    # the class §24 itself REFUSED (`_decommission_vm`'s no-nonce
    # precondition), so it had no automated path whatsoever — live on
    # 2026-08-13, `stamp-fedora-3` (`no-eligible-miner`, refused at
    # PLACEMENT, `failed` DecommissionJob, KEK alive). Those ARE reaped.
    launch_abandoned_at = models.DateTimeField(null=True, blank=True, db_index=True)
    launch_abandoned_outcome = models.CharField(max_length=64, blank=True, default="")
    launch_abandoned_registered = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = VmQuerySet.as_manager()

    class Meta:
        ordering = ["-updated_at"]
        indexes = [
            # Explicit names matching migration 0001 so a fresh
            # makemigrations does not propose a spurious RenameIndex
            # (the model Meta had unnamed indexes; 0001 named them).
            models.Index(fields=["state"], name="lifecycle_v_state_idx"),
            models.Index(fields=["host"], name="lifecycle_v_host_idx"),
            models.Index(
                fields=["tenant_id", "placement_group"], name="lifecycle_v_tenant_group_idx"
            ),
        ]
        constraints = [
            # Migrating rows MUST carry the destination and the new
            # generation. Postgres enforces; SQLite (test backend)
            # also honours `CHECK` constraints.
            models.CheckConstraint(
                name="lifecycle_vm_migrating_requires_dest",
                condition=(~models.Q(state=VmState.MIGRATING) | ~models.Q(migration_dest="")),
            ),
            models.CheckConstraint(
                name="lifecycle_vm_migrating_requires_new_generation",
                condition=(
                    ~models.Q(state=VmState.MIGRATING) | models.Q(new_generation__isnull=False)
                ),
            ),
        ]

    def __str__(self) -> str:
        return f"Vm {self.vm_id} ({self.state}, gen={self.generation})"

    def save(self, *args, **kwargs):
        """`auto_now` only fires for a field in `update_fields`: every
        partial save stamps `updated_at` too."""
        fields = kwargs.get("update_fields")
        # An empty list stays Django's no-op.
        if fields and "updated_at" not in fields:
            kwargs["update_fields"] = [*fields, "updated_at"]
        super().save(*args, **kwargs)

    @property
    def stopped_by_guest(self) -> bool:
        """`stopped` because the guest powered itself off under the `stop`
        guest-poweroff policy — see `power_stopped_by_guest_at`."""
        return (
            self.power_state == VmPowerState.STOPPED
            and self.power_state_at is not None
            and self.power_stopped_by_guest_at == self.power_state_at
        )

    @property
    def stopped_by_order(self) -> bool:
        """`stopped`, and by a completed stop order — see
        `power_stop_ordered_at`."""
        return (
            self.power_state == VmPowerState.STOPPED
            and self.power_state_at is not None
            and self.power_stop_ordered_at == self.power_state_at
        )

    # ─── Helpers ──────────────────────────────────────────────────

    def lifecycle_vk_hex(self) -> str:
        """Hex-encode the lifecycle vk for subprocess argv."""
        return bytes(self.lifecycle_vk).hex()

    def eol_nonce_hex(self) -> str | None:
        if self.eol_nonce is None:
            return None
        return bytes(self.eol_nonce).hex()

    def advance_boot_phase(self, milestone_wire: str) -> bool:
        """Advance `boot_phase` to `milestone_wire` iff it is monotonically
        newer than the recorded phase.

        `milestone_wire` is the HYPHEN wire value (`booting` |
        `kek-released` | `running`); it is mapped to the underscore
        `VmBootPhase` choice. Returns `True` when the in-memory
        `boot_phase` was set/advanced (the caller then persists +
        stamps `boot_phase_at`); `False` when the milestone is unknown
        or would regress an equal/newer recorded phase (idempotent
        replay / out-of-order delivery). Does NOT save — the caller owns
        the write so it can stamp `boot_phase_at` in the same UPDATE.
        """
        target = _BOOT_PHASE_WIRE_TO_CHOICE.get(milestone_wire)
        if target is None:
            return False
        new_rank = _BOOT_PHASE_RANK[target]
        current_rank = _BOOT_PHASE_RANK.get(self.boot_phase, 0)
        if new_rank <= current_rank:
            return False
        self.boot_phase = target
        return True

    def guest_liveness(self, now=None):
        """The three-way in-guest liveness `Verdict` for this row.

        DERIVED from `guest_signal_at` at read time (never a stored
        mirror, which could disagree with the watermark). Import is lazy
        so `models` carries no import-time dependency on the classifier.
        """
        from . import guest_liveness as _guest_liveness

        return _guest_liveness.verdict_for(self, now=now)

    def boot_stall(self, now=None, disk_gb_by_vm_id=None):
        """The boot-stall `BootStall` readout, derived at read time.

        `disk_gb_by_vm_id` lets a list resolve every row's flavor in one
        query; omitted, this row's is looked up.
        """
        from . import boot_stall as _boot_stall

        if disk_gb_by_vm_id is None:
            disk_gb_by_vm_id = _boot_stall.disk_gb_by_vm_id([self.vm_id])
        return _boot_stall.classify(self, disk_gb=disk_gb_by_vm_id.get(self.vm_id), now=now)

    @classmethod
    def issue_eol_nonce(cls) -> bytes:
        """Mint a fresh 32-byte single-use EOL nonce.

        Public + classmethod so the views + tests can mint without
        instantiating a model. Each call returns a brand new value —
        `secrets.token_bytes` is the standard CSPRNG path.
        """
        return _fresh_eol_nonce()


class StoppedAckIngest(models.Model):
    """The guest-pushed `SignedStoppedAck` landing pad (§24/§25).

    When a measured guest shuts down cleanly (tenant cancel, lease
    expiry, or a §25 cold-migration quiesce, which ACPI-poweroffs the
    domain) its baked shutdown hook runs `hippius-agent-initramfs eol`,
    which signs a `StoppedAck` from the guest's in-SNP lifecycle key and
    POSTs the opaque canonical-CBOR `SignedStoppedAck` to
    `{vali_url}/v1/lifecycle/stopped?vm_id=…&generation=…` — the SAME
    public ingress the KBS / heartbeat path uses.

    vali is an opaque relay here too: it does NOT decode the CBOR body
    (the parser-hardened Rust verifier does, later, in
    `_verify_ack` / `verify_stopped_ack`). The `vm_id` + `generation`
    that key this row ride the URL query (the guest reads both from its
    measured cmdline), NOT the body, so the store can be keyed without a
    Python-side CBOR decode (§5.6 opacity).

    The orchestrator's `effects.poll_source_ack` (§25) /
    `poll_eol_ack` (§24) read the latest raw bytes for
    `(vm_id, generation)` from here and hand them to `_verify_ack`,
    which cryptographically verifies the signature + nonce + generation
    before any dest activation / destroy. A wrong / forged / stale ack
    simply fails that verification (fail-closed) — storing it is inert.

    Keyed by `(vm_id, generation)` so:

    - a §25 migration's SOURCE ack (signed at `source_gen`) and a later
      decommission ack (signed at a higher gen) never collide; and
    - a replayed ack at an already-migrated generation lands on a row
      vali no longer polls (the KBS fence forever denies that gen).

    The latest push for a `(vm_id, generation)` wins (`update_or_create`)
    — a re-driven quiesce that re-signs overwrites the prior bytes.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=256, db_index=True)
    # The generation the guest signed the ack at (its measured
    # `hippius.vm_generation` cmdline token). For a §25 source ack this
    # is `source_gen`; for a §24 decommission ack it is the live gen.
    generation = models.BigIntegerField()
    # The opaque canonical-CBOR `SignedStoppedAck` bytes, verbatim. NOT
    # decoded vali-side — piped to the Rust verifier on poll.
    signed_ack = models.BinaryField()
    received_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["vm_id", "generation"],
                name="lifecycle_stopped_ack_vm_generation_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["vm_id", "generation"]),
        ]

    def __str__(self) -> str:
        return f"StoppedAckIngest {self.vm_id} gen={self.generation}"


class VmBaseImage(models.Model):
    """WHICH base image a VM actually boots — recorded per VM, at dispatch,
    identified by CONTENT (P9/#16).

    ## The defect this replaces

    The launch spec carried the base as a PATH with a fixed, shared,
    mutable default (`/var/lib/hippius-miner/rootfs.img`). A path is not
    an identity: on 2026-08-13 that same path was a SYMLINK into the
    shared legacy base on one miner and a real 709 MB
    2026-07-29 file on another. One spec, two miners, two
    different operating systems — and no way, from vali, to tell which
    bytes a live tenant was running. That is what kept
    `VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION` unarmable: nothing recorded
    that `tenant-vm-1` was on a base predating the
    `hippius-agent-keepalive` shim.

    ## What a row means

    "At `recorded_at`, vali dispatched `vm_id`'s launch against a base
    whose bytes hash to `rootfs_img_sha256_hex` (+ `rootfs_verity_
    sha256_hex`), staged at `rootfs_data_path` — a path INSIDE that VM's
    own per-VM staging directory."

    The hashes are the identity and are host-independent: a §25 migration
    moves the VM but not its base content, so a row stays true across
    hosts. The paths are recorded as evidence of the per-VM layout (the
    launch REFUSES to dispatch a golden VM against a shared path), not as
    the thing that identifies the image.

    ## Deliberately NOT here

    - No `miner_id`. `Vm.host` is the single source of truth for where a
      VM runs and §25 maintains it; a second copy would rot.
    - No path is ever READ BACK to reclaim anything. §24's reclaim
      re-derives a VM's footprint from `vm_id` alone, miner-side, with no
      lifecycle record to consult — which is exactly what keeps VMs
      staged by older agents (i.e. the entire live fleet) reclaimable.
      This model is an OBSERVATION, never an input to a delete.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=256, unique=True)
    # `legacy_luks` | `golden_verity_overlay` — which anchor binds the
    # base. Golden VMs are content-pinned end to end; legacy ones boot an
    # operator-pre-staged rootfs the miner never fetched, so their row
    # records the path honestly and leaves the hashes blank.
    disk_mode = models.CharField(max_length=32, blank=True, default="")
    # The bake this base came from, and the operator-blessed catalog name
    # it was launched by (`image=ubuntu`), when the launch used one. These
    # are what an operator needs to answer "move this VM to the current
    # blessed base" — the P1 prerequisite.
    bake_id = models.CharField(max_length=256, blank=True, default="", db_index=True)
    image_name = models.CharField(max_length=64, blank=True, default="", db_index=True)
    # CONTENT identity of the shared read-only dm-verity base. Indexed:
    # "which live VMs boot a base older than X" is a scan over this.
    rootfs_img_sha256_hex = models.CharField(max_length=64, blank=True, default="")
    rootfs_verity_sha256_hex = models.CharField(max_length=64, blank=True, default="")
    # The dm-verity ROOT hash folded into the SNP-measured cmdline — the
    # value the guest itself enforces the base against.
    verity_root_hash_hex = models.CharField(max_length=64, blank=True, default="")
    # The per-VM staged paths the miner resolved and the domain booted
    # from. Evidence, not identity (see the class docstring).
    rootfs_data_path = models.CharField(max_length=512, blank=True, default="")
    rootfs_hash_path = models.CharField(max_length=512, blank=True, default="")
    recorded_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["rootfs_img_sha256_hex"], name="lifecycle_base_img_idx"),
        ]

    def __str__(self) -> str:
        return f"VmBaseImage {self.vm_id} img={self.rootfs_img_sha256_hex[:12]}"


class ZombieObservation(models.Model):
    """A guest frame from a VM whose data vali has already killed.

    Once a §24 crypto-erase has run (or the VM is `destroyed`), the guest
    has no business running: its disk key is gone from Vault and the next
    boot can never unlock. If a served receipt, a live attestation or a
    boot milestone for it still arrives, some miner is still running it —
    the destroy never reached the domain (miner unreachable, 502, or a
    miner that ignores the order). That is a data-death gap: the guest
    keeps its LUKS master key in memory for as long as the domain lives.

    One row per `(vm_id, miner_id)` — the relaying miner when the Edge
    stamped its mTLS peer, else vali's own record of where the destroy
    was aimed. `apps.lifecycle.zombie` derives the miner quarantine from
    the FRESH rows; nothing here is ever flipped by hand.
    """

    vm_id = models.CharField(max_length=64, db_index=True)
    # `MinerIdentity.miner_id` / `chain_node_id` of the miner the frame is
    # attributed to. `miner_node_id` is the key placement and epoch
    # weights use; blank when the miner has no chain identity (the row is
    # still recorded — and alerted on — but can quarantine nobody).
    miner_id = models.CharField(max_length=128, blank=True, default="")
    miner_node_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    # `peer` (the Edge-stamped relaying miner) or `destroy-target` (vali's
    # own record, used when the frame carried no relay identity).
    attribution = models.CharField(max_length=16, default="peer")
    last_kind = models.CharField(max_length=32, default="")
    count = models.PositiveBigIntegerField(default=0)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField(db_index=True)
    # Last UNFORGEABLE frame — a KBS-signed live attestation (needs the real
    # SNP guest) or a miner-signed boot milestone. Only these quarantine a
    # miner: a served receipt is signed by a guest key root can extract, so
    # a former tenant could forge one to grief its old host. Receipts are
    # still refused, alerted on and counted.
    strong_last_seen_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # Last time this row raised its ERROR — once per VM per window.
    alerted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["vm_id", "miner_id"], name="lifecycle_zombie_vm_miner_uniq"
            ),
        ]

    def __str__(self) -> str:
        return f"ZombieObservation {self.vm_id} on {self.miner_id or '?'} x{self.count}"


class VmNetbirdKey(models.Model):
    """One NetBird setup key vali minted for a VM, and the peer that used it.

    Recorded by `launch.launch_on_miner` right after the mint, BEFORE the
    key leaves vali (it rides the userdata to the guest), so every peer that
    can ever enrol with a vali-minted tenant key is traceable to its VM.

    The key→peer binding comes from NetBird's own audit log: when a peer
    registers with a setup key, the management server records a
    `peer.setupkey.add` event whose `initiator_id` is the setup key's id and
    whose `target_id` is the new peer's id (`AddPeer`,
    `management/server/peer.go`). Neither is tenant-controlled — unlike the
    peer's NAME, which is the hostname the guest sends. Whoever enrolled with
    the key held a credential minted for this VM, so its peer is this VM's
    to revoke, whatever it calls itself.

    - `peer_id`    the peer that enrolled with the key; blank until bound, and
                   blank forever for a key that expired unused.
    - `settled_at` when the binding concluded (bound, or expired unused). A
                   NULL row is still being looked for — the only rows that
                   cost a NetBird audit-log read.
    """

    vm = models.ForeignKey(Vm, on_delete=models.CASCADE, related_name="netbird_keys")
    setup_key_id = models.CharField(max_length=64, unique=True)
    persistent = models.BooleanField()
    expires_at = models.DateTimeField()
    peer_id = models.CharField(max_length=64, blank=True, default="", db_index=True)
    settled_at = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "id"]

    def __str__(self) -> str:
        return f"VmNetbirdKey({self.vm_id}, key={self.setup_key_id}, peer={self.peer_id or '-'})"
