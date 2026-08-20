"""OrderTicket RE-MINT — one implementation, two callers.

1. **§25 cold-migration** ([`remint_dest_ticket`]) — the destination ticket
   at `new_gen`, bound to the destination miner. Everything below describes
   this path; it is unchanged.
2. **KBS-state recovery** ([`remint_current_ticket`], `vali_kbs_recover`) —
   the KBS runs as an SNP Kata CVM whose `state_dir` is an emptyDir sealed
   inside the CVM, so a pod restart WIPES `vm-states.json` and nothing can
   preserve it. Recovery re-registers the VM state from outside through the
   admin API, which needs a ticket at the VM's CURRENT generation bound to
   its CURRENT host. Same measurement, same digest re-derivation, same
   persistence — only `(node_id, generation)` and the fresh-mint policy
   differ, so it delegates here rather than growing a second copy of
   ticket-minting (a divergent copy is exactly how the empty-`platform_id`
   defect reached production).

   That path MUST mint fresh: tickets carry a 24h expiry, so the stored
   launch-time ticket for the current generation cannot be replayed (the
   live KBS answers 400).

## §25 cold-migration — re-mint the destination OrderTicket at `new_gen`

The KBS releases the rootfs KEK ONLY to a ticket whose `vm_generation`
matches the KBS-recorded generation (`kbs_core::lifecycle::check_releasable`).
During a `Migrating{new_gen, dest}` state the KBS demands a ticket at
`new_gen` AND denies the source's `source_gen` ticket forever after — that
is the §25 split-brain fence. So before the destination can unlock its
migrated disk, vali must mint a FRESH OrderTicket bound to `new_gen`.

## What changes at `new_gen` (and what MUST NOT)

The destination boots the SAME measured guest as the source — identical
OVMF / kernel / initrd / cmdline / vcpus — so its SNP launch_digest is
**byte-identical** to the source's. The generation is carried by the
OrderTicket (`vm_generation`), NOT by the measured cmdline (the boot
pipeline reads `order.vm_generation`, never a cmdline token —
`agent-initramfs::stages::verify`). So the re-mint reuses the SAME
`allowed_measurement_hex` recorded at launch; it does NOT run a dest
preflight, and it does NOT rewrite the cmdline.

Only three fields change for the dest ticket:

- `vm_generation` → `new_gen` (the fence),
- `node_id`       → the destination miner (the bound host the KBS checks),
- `ticket_id`     → a fresh id (the KBS keys admin idempotency by it; and
  the §6 userdata digest binds it, so it must be re-derived — below).

## The userdata digest re-derivation (§6 / §19)

`allowed_userdata_digest_hex` binds `(tenant_id, vm_id, ticket_id,
secret_type, vault_path, version, plaintext)`. A fresh `ticket_id`
changes the preimage, so the digest MUST be recomputed for the new ticket.
The plaintext + current version are read back from Vault (the SAME
deterministic per-vm path the launch staged), so the dest ticket asserts a
digest the KBS will reproduce byte-for-byte on release. Reading the
userdata plaintext is a §20 secret op: it is held only long enough to
frame the digest, then zeroized.

## Persistence

The re-minted COSE blob is stored as a new `OrderTicketIntake` row (keyed
at `(vm_id, new_gen)`), exactly as the launch-time ticket is — so
`dispatch_migrate_activate`'s `order_by("-vm_generation").first()` resolves
the new_gen ticket, and a tick re-drive is idempotent (the same ticket_id
re-intakes byte-identically).

§20: the COSE blob, the userdata plaintext, and the vault refs are never
logged. Only the static classifier + the `(vm_id, new_gen, ticket_id)`
triple (non-secret) reach the log.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from django.conf import settings

from apps.orders.models import OrderTicketIntake

from ..effects import EffectError, EffectUnavailable
from ..models import LaunchJob, LaunchJobState
from . import ticket_mint, userdata_digest, vault_kv

log = logging.getLogger("apps.orchestration.migration_ticket")

# Secret-type tag the §6 userdata digest frames (mirrors the launch path).
_SECRET_TYPE_USERDATA = userdata_digest.SECRET_TYPE_USERDATA

#: `ticket_id` namespace prefixes. The §25 dest re-mint keeps `tk-mig`
#: (unchanged wire behaviour); the KBS-state RECOVERY re-mint uses `tk-rec`
#: so an audit can tell a recovery ticket from a migration one at a glance.
#: Both are non-secret identifiers.
TICKET_PREFIX_MIGRATION = "tk-mig"
TICKET_PREFIX_RECOVERY = "tk-rec"

#: `OrderTicketIntake.received_from` audit string per ticket namespace. The
#: §25 value is pinned to its historical string so migration rows are
#: byte-identical to the ones written before the generalisation.
_RECEIVED_FROM = {
    TICKET_PREFIX_MIGRATION: "system:migration-remint",
    TICKET_PREFIX_RECOVERY: "system:kbs-recover-remint",
}


@dataclass(frozen=True)
class TicketInputs:
    """Everything a re-mint needs that is resolvable WITHOUT touching Vault
    or minting anything — i.e. the read-only, fail-closed half of a re-mint.

    Split out so a dry-run (`vali_kbs_recover --dry-run`) validates EXACTLY
    the same preconditions the committing path enforces, from the same code,
    without reading a §20 secret or writing a row. Every field here is
    non-secret (identifiers + the public measurement + Vault PATHS, never
    Vault CONTENT), so a caller may print them.
    """

    vm_id: str
    lease_id: str
    node_id: str
    generation: int
    measurement_hex: str
    flavor: str
    tenant_id: str
    user_id: str
    kid: str
    platform_id: str
    luks_path: str
    userdata_path: str
    vault_mount: str
    expiry_seconds: int


def _zeroize(buf: bytes) -> None:
    """Best-effort wipe of a mutable secret buffer (no-op on immutable
    bytes — the caller still drops its reference). Kept tiny + total so a
    §20 secret never lingers longer than the digest framing needs it.
    """
    try:
        view = memoryview(bytearray(buf))
        for i in range(len(view)):
            view[i] = 0
    except (TypeError, ValueError):  # pragma: no cover — defensive
        pass


def remint_dest_ticket(vm: object, *, dest_node_id: str, new_gen: int) -> bytes:
    """§25 — re-mint the DESTINATION OrderTicket at `new_gen` for `vm` and
    return its byte-exact COSE_Sign1 blob.

    Resolves the measured launch tuple from the VM's most recent successful
    launch record (same measurement), re-derives the userdata digest for a
    fresh ticket_id from the Vault-staged secret, mints at `new_gen` bound
    to `dest_node_id`, and persists the COSE blob as an `OrderTicketIntake`.

    Idempotent: a re-drive finds the already-persisted new_gen row (same
    ticket_id → byte-identical re-mint is unnecessary) and returns it.

    Fail-closed: `EffectUnavailable` (Vault / mint binary unreachable —
    the orchestrator retries) or `EffectError` (no usable launch record /
    intake — the migration fails closed at its deadline; the dest is never
    activated with a stale-gen ticket).

    Thin wrapper over [`remint_ticket`] pinned to the §25 defaults (reuse an
    existing same-gen intake, `tk-mig` ticket namespace) — the §25 call site
    is behaviourally unchanged by the generalisation.
    """
    return remint_ticket(vm, node_id=dest_node_id, generation=new_gen)


def remint_ticket(
    vm: object,
    *,
    node_id: str,
    generation: int,
    reuse_existing: bool = True,
    ticket_id_prefix: str = TICKET_PREFIX_MIGRATION,
) -> bytes:
    """Mint a fresh OrderTicket for `vm` bound to `(node_id, generation)`,
    persist it as an `OrderTicketIntake`, and return its COSE_Sign1 blob.

    Two callers, one implementation (a second copy of ticket-minting is how
    the empty-`platform_id` defect happened):

    - §25 cold migration — `generation = new_gen`, `node_id` = the
      DESTINATION miner, `reuse_existing=True` (the fence ticket is minted
      once per migration and re-driven idempotently).
    - KBS-state RECOVERY (`vali_kbs_recover`) — `generation` = the VM's
      CURRENT generation, `node_id` = the VM's CURRENT host,
      `reuse_existing=False`.

    `reuse_existing=False` is REQUIRED for recovery: tickets carry a 24h
    expiry, so the stored launch-time / prior-recovery ticket for the current
    generation is (almost always) EXPIRED and the KBS rejects it with a 400.
    A recovery must therefore always mint fresh — reusing the stored blob
    would look successful locally and fail at the KBS.
    """
    vm_id = vm.vm_id  # type: ignore[attr-defined]

    # Idempotent fast-path: a prior tick already minted + persisted the
    # ticket at this generation. Reuse its byte-exact blob (a fresh mint
    # would carry a different ticket_id + nonce, breaking the §14 dedup the
    # dispatch relies on).
    #
    # EXCEPT when the stored ticket has an EMPTY platform_id: those were
    # minted before `_node_platform_id` bound the destination chip, and the
    # KBS denies them unconditionally (`id_len == 0`). Returning one here
    # would bypass this fix for exactly the VMs it exists to repair — a
    # retried migration recomputes the same `new_gen`, so it would hand back
    # the poisoned blob and 403 at the key release again while still
    # reporting success. Fall through and re-mint instead: the discarded
    # ticket_id was never releasable, `check_releasable` gates on the
    # generation rather than the ticket_id, and release-once dedup is keyed
    # per ticket_id, so nothing is lost by replacing it.
    if reuse_existing:
        existing = (
            OrderTicketIntake.objects.filter(vm_id=vm_id, vm_generation=generation)
            .order_by("-received_at")
            .first()
        )
        if existing is not None and existing.platform_id:
            return bytes(existing.cose_blob)
        if existing is not None:
            log.warning(
                "remint: discarding an unreleasable ticket for vm_id=%s "
                "gen=%s (empty platform_id — minted before the dest-chip binding)",
                vm_id,
                generation,
            )

    inputs = resolve_ticket_inputs(vm, node_id=node_id, generation=generation)
    return _mint_from(inputs, ticket_id_prefix=ticket_id_prefix)


def current_placement(vm: object) -> tuple[str, int]:
    """The VM's CURRENT `(host, generation)` — what a KBS-state recovery
    re-registers, as opposed to a §25 `(dest, new_gen)`.

    Fail-closed: a row with no `host` has no bound miner to mint against, and
    minting at a guessed host produces a ticket the KBS can never release
    (the attested chip_id would not match). Refuse instead.
    """
    vm_id = str(getattr(vm, "vm_id", "") or "")
    host = str(getattr(vm, "host", "") or "")
    if not host:
        raise EffectError(
            f"remint: vm {vm_id!r} has no bound host — refusing to mint against a guess"
        )
    return host, int(vm.generation)  # type: ignore[attr-defined]


def remint_current_ticket(vm: object) -> bytes:
    """KBS-state recovery — re-mint at the VM's CURRENT generation and its
    CURRENT host (never a new generation, never a destination).

    Always mints fresh (`reuse_existing=False`): the stored ticket for this
    generation has a 24h expiry and cannot be replayed.
    """
    node_id, generation = current_placement(vm)
    return remint_ticket(
        vm,
        node_id=node_id,
        generation=generation,
        reuse_existing=False,
        ticket_id_prefix=TICKET_PREFIX_RECOVERY,
    )


def resolve_ticket_inputs(vm: object, *, node_id: str, generation: int) -> TicketInputs:
    """Resolve — READ-ONLY, no Vault content, no mint, no write — every
    input a re-mint needs, or raise fail-closed.

    Shared by the committing re-mint and by `vali_kbs_recover --dry-run`, so
    a dry-run's verdict is the real path's verdict rather than a second
    approximation of it.
    """
    vm_id = vm.vm_id  # type: ignore[attr-defined]
    lease_id = vm.lease_id  # type: ignore[attr-defined]

    record = (
        LaunchJob.objects.filter(vm_id=vm_id, state=LaunchJobState.SUCCEEDED)
        .order_by("-finished_at")
        .first()
    )
    if record is None:
        raise EffectError(f"remint: vm {vm_id!r} has no successful launch record")
    spec = record.spec_json or {}
    # The launch path echoes the FINAL measurement (operator-pinned or
    # preflight-computed) into `result_json["emit"]["measurement_hex"]` — the
    # spec's own `measurement_hex` is "" in the common preflight-auto case.
    emit = (record.result_json or {}).get("emit") or {}

    # Non-secret binding metadata the dest ticket must echo
    # (tenant/user/platform). The launch record's spec_json is authoritative
    # (the pipeline path does not persist an OrderTicketIntake); a stored
    # source intake row, when present, is a supplemental fallback only.
    src_ticket = (
        OrderTicketIntake.objects.filter(vm_id=vm_id)
        .order_by("-vm_generation", "-received_at")
        .first()
    )

    measurement_hex = str(spec.get("measurement_hex") or emit.get("measurement_hex") or "")
    if not measurement_hex:
        # The launch record did not persist the measurement. Without it we
        # cannot mint a ticket the KBS will gate — fail closed rather than
        # mint against a guessed measurement (the dest would attest a digest
        # the allowlist never pinned, and the KBS would refuse the KEK).
        raise EffectError(f"remint: launch record for {vm_id!r} has no measurement_hex")

    flavor = str(spec.get("flavor") or "")
    if not flavor:
        raise EffectError(f"remint: launch record for {vm_id!r} has no flavor")

    tenant_id = str(spec.get("tenant_id") or _attr(src_ticket, "tenant_id"))
    user_id = str(spec.get("user_id") or _attr(src_ticket, "user_id"))
    if not tenant_id or not user_id:
        raise EffectError(f"remint: launch record for {vm_id!r} missing tenant/user id")

    # The Vault PATHS (not their content) the ticket binds. Resolving them
    # here keeps the dry-run honest about a missing prefix.
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", "") or "")
    if not prefix:
        raise EffectUnavailable("VALI_VAULT_KV_PREFIX is not configured")

    return TicketInputs(
        vm_id=vm_id,
        lease_id=lease_id,
        node_id=node_id,
        generation=int(generation),
        measurement_hex=measurement_hex,
        flavor=flavor,
        tenant_id=tenant_id,
        user_id=user_id,
        # The mint binary's `--kid` takes the ASCII kid STRING; the intake
        # row stores only `kid_hex` (the COSE header bytes), so the kid is
        # resolved from the launch spec, never re-derived from the source
        # intake.
        kid=_spec_kid(spec),
        platform_id=_node_platform_id(node_id),
        luks_path=f"{prefix}/{vm_id}/luks-kek",
        userdata_path=f"{prefix}/{vm_id}/userdata",
        vault_mount=mount,
        expiry_seconds=int(spec.get("expiry_seconds") or 86400),
    )


def _mint_from(inputs: TicketInputs, *, ticket_id_prefix: str) -> bytes:
    """Mint + persist the ticket described by `inputs`. Everything that
    touches Vault CONTENT or writes a row lives here — never on the
    read-only resolution path.
    """
    vm_id = inputs.vm_id
    generation = inputs.generation

    # ── Re-derive the §6 userdata digest for a FRESH ticket_id ──────────
    fresh_ticket_id = f"{ticket_id_prefix}-{vm_id}-{generation}-{uuid.uuid4().hex[:8]}"

    luks_version = vault_kv.latest_version(inputs.vault_mount, inputs.luks_path)
    ud_version = vault_kv.latest_version(inputs.vault_mount, inputs.userdata_path)
    userdata = vault_kv.get_kv(inputs.vault_mount, inputs.userdata_path, version=ud_version)
    try:
        digest_hex = userdata_digest.userdata_digest_hex(
            tenant_id=inputs.tenant_id,
            vm_id=vm_id,
            ticket_id=fresh_ticket_id,
            secret_type=_SECRET_TYPE_USERDATA,
            path=inputs.userdata_path,
            version=ud_version,
            plaintext=userdata,
        )
    finally:
        _zeroize(userdata)
        del userdata

    # ── Mint at `generation` (same measurement as the launch) ───────────
    cose_ticket = ticket_mint.mint(
        ticket_mint.MintArgs(
            kid=inputs.kid,
            ticket_id=fresh_ticket_id,
            tenant_id=inputs.tenant_id,
            user_id=inputs.user_id,
            vm_id=vm_id,
            lease_id=inputs.lease_id,
            node_id=inputs.node_id,
            platform_id=inputs.platform_id,
            allowed_measurement_hex=inputs.measurement_hex,
            userdata_vault_path=inputs.userdata_path,
            userdata_vault_version=ud_version,
            luks_vault_path=inputs.luks_path,
            luks_vault_version=luks_version,
            allowed_userdata_digest_hex=digest_hex,
            flavor=inputs.flavor,
            vm_generation=generation,
            lifecycle_perm=("launch",),
            expiry_seconds=inputs.expiry_seconds,
        )
    )

    _persist_intake(
        cose_ticket,
        vm_id=vm_id,
        new_gen=generation,
        ticket_id=fresh_ticket_id,
        received_from=_RECEIVED_FROM.get(ticket_id_prefix, "system:remint"),
    )
    log.info(
        "remint: minted ticket vm=%s gen=%d ticket_id=%s node=%s",
        vm_id,
        generation,
        fresh_ticket_id,
        inputs.node_id,
    )
    return cose_ticket


def _attr(obj: object | None, name: str) -> str:
    """Read a string attribute off an optional model row (the source
    OrderTicketIntake fallback), `""` when the row is absent.
    """
    if obj is None:
        return ""
    return str(getattr(obj, name, "") or "")


def _spec_kid(spec: dict) -> str:
    """The L1 kid the dest ticket is signed under — the launch spec's
    `kid` (operator-pinned), defaulting to the prod kid the mint binary +
    `LaunchSpec` agree on (#587 Phase 1A).
    """
    return str(spec.get("kid") or "l1-order-ticket-v1")


def _node_platform_id(node_id: str) -> str:
    """The platform_id the ticket binds to — the BOUND miner's registered SNP
    chip identity, resolved from its `MinerIdentity`. For §25 that is the
    DESTINATION miner; for a KBS-state recovery it is the VM's CURRENT host.

    This is a HARD gate, not a cosmetic field: `kbs_core::release` compares
    the attested chip_id against the ticket's `platform_id` and fails closed
    when it is empty (`id_len == 0` → "attested platform_id != ticket
    placement" → 403). A ticket minted without it can NEVER release the KEK,
    so the destination guest boots and then hangs unable to unlock — a
    migration that reports success while the workload is dead.

    Neither of the two values this used to fall back to is correct:

    - the LAUNCH spec's `platform_id` pins whichever miner the LAUNCH landed
      on (it is supplied before placement), and a migration by definition
      targets a DIFFERENT machine with a different chip;
    - the SOURCE ticket's `platform_id` is the source miner's chip for the
      same reason. (And on the async launch path neither is even populated —
      the pipeline persists no source `OrderTicketIntake` — which is how this
      silently minted an EMPTY platform_id in production.)

    Mirrors the launch path's `spec.platform_id or miner.platform_id`
    (`launch.launch_on_miner`), resolved against the destination. Fails
    closed rather than minting an unreleasable ticket — `start_migration`
    already validated the destination's identity at intake (`miner-unknown` /
    `platform-id-invalid`), so an unresolvable one here is a real fault.
    """
    from apps.miners.models import MinerIdentity

    try:
        pid = str(MinerIdentity.objects.get(miner_id=node_id).platform_id or "")
    except MinerIdentity.DoesNotExist as exc:
        raise EffectError(
            f"remint: miner {node_id!r} has no MinerIdentity — "
            "cannot bind the ticket to its SNP chip identity"
        ) from exc
    if not pid:
        raise EffectError(
            f"remint: miner {node_id!r} has an empty platform_id — "
            "the KBS would refuse the KEK release (attested chip_id != ticket)"
        )
    # Total the gate: the KBS truncates the attested chip_id to the ticket's
    # own byte-length and compares, so a registered value that is not hex, or
    # not a valid CHIP_ID length, would mint cleanly and then 403 at release —
    # the same silent failure this fix exists to remove.
    # `_vcpu_type_for_platform` is the shared parser `start_migration`'s
    # same-gen gate already uses.
    #
    # NOT covered here: CASE. `bytes.fromhex` accepts uppercase, but the KBS
    # compares against `hex::encode(...)` which emits LOWERCASE, so an
    # uppercase-registered chip id still 403s. Normalising only here would
    # just move the failure — `effects.kbs_activate_dest` sends the same raw
    # registered value as the KBS lifecycle `dest` — so the real fix is to
    # lower-case at miner REGISTRATION, which closes both consumers at once.
    # Tracked as a follow-up.
    from .launch_digest import _vcpu_type_for_platform

    try:
        _vcpu_type_for_platform(pid)
    except EffectError as exc:
        raise EffectError(
            f"remint: miner {node_id!r} has a malformed platform_id "
            f"({exc}) — the KBS would refuse the KEK release"
        ) from exc
    return pid


def _persist_intake(
    cose_ticket: bytes,
    *,
    vm_id: str,
    new_gen: int,
    ticket_id: str,
    received_from: str = "system:migration-remint",
) -> None:
    """Store the re-minted COSE blob as an `OrderTicketIntake` so the
    dispatch resolves the new_gen ticket + a re-drive is idempotent. A
    racing duplicate (same ticket_id) is benign — keep the first.
    """
    from django.db import IntegrityError, transaction

    from apps.orders import validator

    try:
        parsed = validator.validate_ticket(cose_ticket)
    except validator.ValidatorFailed as exc:
        # Our own freshly-minted ticket failed the validator — a mint /
        # schema drift bug. Fail closed loudly (never persist an unparseable
        # ticket the dispatch would carry blind).
        raise EffectError(f"remint: self-minted ticket rejected: {exc}") from exc
    except validator.ValidatorUnavailable as exc:
        raise EffectUnavailable(f"remint: validator unavailable: {exc}") from exc

    try:
        with transaction.atomic():
            OrderTicketIntake.objects.create(
                ticket_id=parsed.ticket_id,
                vm_id=parsed.vm_id,
                tenant_id=parsed.tenant_id,
                user_id=parsed.user_id,
                lease_id=parsed.lease_id,
                vm_generation=parsed.vm_generation,
                issue_time=parsed.issue_time,
                expiry=parsed.expiry,
                node_id=parsed.node_id,
                platform_id=parsed.platform_id,
                resource_class=parsed.resource_class,
                kid_hex=parsed.kid_hex,
                cose_blob=cose_ticket,
                received_from=received_from,
            )
    except IntegrityError:
        # A concurrent tick persisted the same ticket_id — benign idempotent
        # race. The existing row is byte-identical (same mint inputs), so
        # there is nothing to reconcile.
        log.info(
            "remint: intake race vm=%s gen=%d ticket_id=%s (benign)",
            vm_id,
            new_gen,
            ticket_id,
        )
