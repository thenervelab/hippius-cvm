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
from . import customer_keys, ticket_mint, userdata_digest, vault_kv

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
    #: vali's own WORKING COPY of the userdata (`…/userdata-pending`),
    #: wrapped under `ud-<vm_id>` — the only copy vali can open. The
    #: canonical `userdata_path` above is wrapped under the KBS-only
    #: `kek-<vm_id>`, so re-deriving the §6 digest reads THIS one.
    userdata_working_path: str
    vault_mount: str
    expiry_seconds: int
    #: Customer-held keys — the VM's PINNED mode (`hippius` / `split` /
    #: `customer`), checked against the binding its measured cmdline
    #: carries (`customer_keys.resolve_for_remint`). Never defaulted from a
    #: record: an M1/M2 VM re-minted as M0 would be refused by the KBS at
    #: best and would un-bind the guardian at worst.
    key_mode: str = "hippius"


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
        # The guest components floor holds for a reused ticket too: it
        # replays the boot on record, which a raised floor may now forbid.
        from . import guest_components
        from .launch_record import booted_artifacts

        record = _latest_launch_record(vm_id)
        if record is not None:
            epoch_refusal = guest_components.launch_epoch_refusal(
                vm_id, booted_artifacts(record)[1]
            )
            if epoch_refusal:
                raise EffectError(f"remint: {epoch_refusal}")
        existing = (
            OrderTicketIntake.objects.filter(vm_id=vm_id, vm_generation=generation)
            .order_by("-received_at")
            .first()
        )
        if existing is not None and existing.platform_id:
            # Customer-held keys: the reuse shortcut is held to the same
            # pin + recorded-cmdline check a fresh re-mint applies (binding,
            # cloud-init markers), BEFORE any stored blob is handed back.
            _check_recorded_binding(vm)
            if _stored_ticket_has_pinned_mode(vm, bytes(existing.cose_blob)):
                return bytes(existing.cose_blob)
            # Customer-held keys: a stored ticket whose signed key_mode is
            # not the VM's pinned mode (ingested from elsewhere, or minted
            # before a pin) would be refused by the KBS at release. Re-mint
            # — the re-mint path checks the pin against the measured cmdline.
            log.warning(
                "remint: discarding a stored ticket for vm_id=%s gen=%s whose "
                "key_mode is not the VM's pinned mode",
                vm_id,
                generation,
            )
            existing = None
        if existing is not None:
            log.warning(
                "remint: discarding an unreleasable ticket for vm_id=%s "
                "gen=%s (empty platform_id — minted before the dest-chip binding)",
                vm_id,
                generation,
            )

    inputs = resolve_ticket_inputs(vm, node_id=node_id, generation=generation)
    return _mint_from(inputs, ticket_id_prefix=ticket_id_prefix)


def _latest_launch_record(vm_id: str) -> LaunchJob | None:
    return (
        LaunchJob.objects.filter(vm_id=vm_id, state=LaunchJobState.SUCCEEDED)
        .order_by("-finished_at")
        .first()
    )


def _recorded_measured_cmdline(record: LaunchJob | None) -> str | None:
    emit = ((record.result_json if record is not None else None) or {}).get("emit") or {}
    return str(emit.get("measured_cmdline") or "") or None


def _check_recorded_binding(
    vm: object, record: LaunchJob | None = None
) -> customer_keys.GuardianBinding | None:
    """`customer_keys.resolve_for_remint` on the VM's recorded measured
    cmdline, as an `EffectError`. Every re-mint path runs it, the stored-
    ticket reuse included."""
    vm_id = vm.vm_id  # type: ignore[attr-defined]
    try:
        return customer_keys.resolve_for_remint(
            vm, _recorded_measured_cmdline(record or _latest_launch_record(vm_id))
        )
    except customer_keys.CustomerKeysError as exc:
        raise EffectError(f"remint: vm {vm_id!r}: {exc}") from exc


def _stored_ticket_has_pinned_mode(vm: object, cose_ticket: bytes) -> bool:
    """Whether a stored ticket's SIGNED `key_mode` (read back by the Rust
    decoder) is the VM's pinned mode. An undecodable blob is not reusable."""
    from apps.orders import validator

    try:
        pinned = customer_keys.ticket_key_mode(customer_keys.binding_of(vm))
    except customer_keys.CustomerKeysError as exc:
        raise EffectError(f"remint: vm {vm.vm_id!r}: {exc}") from exc  # type: ignore[attr-defined]
    try:
        parsed = validator.validate_ticket(cose_ticket)
    except validator.ValidatorFailed:
        return False
    except validator.ValidatorUnavailable as exc:
        raise EffectUnavailable(f"remint: validator unavailable: {exc}") from exc
    return parsed.key_mode == pinned


def current_placement(vm: object) -> tuple[str, int]:
    """The VM's CURRENT `(host, generation)` — what a KBS-state recovery
    re-registers, as opposed to a §25 `(dest, new_gen)`.

    Fail-closed: a row with no `host` has no bound miner to mint against, and
    minting at a guessed host produces a ticket the KBS can never release
    (the attested chip_id would not match). Refuse instead.
    """
    vm_id = str(getattr(vm, "vm_id", "") or "")
    # Only an ACTIVE VM has a "current placement" the KBS may hold as
    # `Active{gen, host}`. Re-registering a decommissioning/destroyed VM would
    # re-open its release after a KBS wipe; a migrating one would be pinned
    # back to `Active{old_gen, source}` — the split-brain §25 fences out.
    state = str(getattr(vm, "state", "") or "")
    if state != "active":
        raise EffectError(
            f"remint: vm {vm_id!r} is {state!r}, not 'active' — refusing to mint a "
            "current-placement ticket for it"
        )
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

    record = _latest_launch_record(vm_id)
    if record is None:
        raise EffectError(f"remint: vm {vm_id!r} has no successful launch record")
    spec = record.spec_json or {}
    # The launch path echoes the FINAL measurement (operator-pinned or
    # preflight-computed) into `result_json["emit"]["measurement_hex"]` — the
    # spec's own `measurement_hex` is "" in the common preflight-auto case.
    emit = (record.result_json or {}).get("emit") or {}

    # Non-secret binding metadata the dest ticket must echo
    # (tenant/user/platform). The launch record's spec_json is authoritative
    # (launches before `launch_on_miner` recorded its ticket have no intake
    # row); a stored source intake row is a supplemental fallback only.
    src_ticket = (
        OrderTicketIntake.objects.filter(vm_id=vm_id)
        .order_by("-vm_generation", "-received_at")
        .first()
    )

    measurement_hex = str(spec.get("measurement_hex") or emit.get("measurement_hex") or "")
    # The guest components floor (G3): a re-mint replays the boot on
    # record, so it is refused when that boot's set is below the VM's
    # required epoch (a §25 hop or a KBS recovery must not bring a VM back
    # onto the release an upgrade is moving it off).
    from . import guest_components
    from .launch_record import booted_artifacts

    epoch_refusal = guest_components.launch_epoch_refusal(vm_id, booted_artifacts(record)[1])
    if epoch_refusal:
        raise EffectError(f"remint: {epoch_refusal}")
    if not measurement_hex:
        # The launch record did not persist the measurement. Without it we
        # cannot mint a ticket the KBS will gate — fail closed rather than
        # mint against a guessed measurement (the dest would attest a digest
        # the allowlist never pinned, and the KBS would refuse the KEK).
        raise EffectError(f"remint: launch record for {vm_id!r} has no measurement_hex")

    # The flavor the measured boot ran at (a stopped VM resized on the
    # books has the spec's ahead of it): the ticket's flavor and vCPU count
    # must be the measurement's.
    from .launch_record import booted_flavor

    flavor = booted_flavor(record)
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

    # Customer-held keys: the mode is the Vm pin, and the cmdline the VM
    # actually boots (the one this ticket's measurement covers) must carry
    # exactly that binding. Any disagreement fails closed — this path must
    # never re-mint an M1/M2 VM as M0.
    binding = _check_recorded_binding(vm, record)

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
        userdata_working_path=f"{prefix}/{vm_id}/userdata-pending",
        vault_mount=mount,
        expiry_seconds=int(spec.get("expiry_seconds") or 86400),
        key_mode=customer_keys.ticket_key_mode(binding),
    )


def _mint_from(inputs: TicketInputs, *, ticket_id_prefix: str) -> bytes:
    """Mint + persist the ticket described by `inputs`. Everything that
    touches Vault CONTENT or writes a row lives here — never on the
    read-only resolution path.
    """
    vm_id = inputs.vm_id
    generation = inputs.generation

    # ── Re-derive the §6 userdata digest for a FRESH ticket_id ──────────
    #
    # The digest binds the ticket_id, and this is a NEW ticket, so the
    # launch's digest cannot be reused — it has to be recomputed over the
    # cloud-init PLAINTEXT (the KBS recomputes it over what it unwraps and
    # the GUEST re-derives it a third time over what it receives, so the
    # preimage is not ours to change).
    #
    # Which means reading a copy vali can actually OPEN. The canonical
    # `userdata_path` is wrapped under the KBS-only `kek-<vm_id>`: hashing
    # what a read of it returns — which is what this did the moment the
    # canonical copy started being wrapped — produces a digest over
    # ciphertext and a ticket that denies at release, i.e. a §25 migration
    # that reports Done and leaves a VM that cannot unlock. vali's working
    # copy is wrapped under `ud-<vm_id>` and unwraps here.
    # Full UUID, not a truncation: the ticket_id keys the KBS register's
    # idempotency, which refuses a DIFFERENT body under an id it has seen
    # (`kbs_core::admin::process_admin_register`). A collision would
    # surface as a re-mint that cannot be registered.
    fresh_ticket_id = f"{ticket_id_prefix}-{vm_id}-{generation}-{uuid.uuid4().hex}"

    if inputs.key_mode == customer_keys.KEY_MODE_CUSTOMER:
        # M2: there is no KEK at `luks_path` (none was ever staged) and the
        # KBS never reads it; the ref only names the path, at the constant
        # version every M2 ticket uses. See `customer_keys.M2_LUKS_REF_VERSION`.
        luks_version = customer_keys.M2_LUKS_REF_VERSION
    else:
        luks_version = vault_kv.latest_version(inputs.vault_mount, inputs.luks_path)
    ud_version = vault_kv.latest_version(inputs.vault_mount, inputs.userdata_path)
    userdata = _read_userdata_plaintext(inputs, ud_version)
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
            key_mode=inputs.key_mode,
        )
    )

    persist_intake(
        cose_ticket,
        vm_id=vm_id,
        generation=generation,
        ticket_id=fresh_ticket_id,
        received_from=_RECEIVED_FROM.get(ticket_id_prefix, "system:remint"),
        expected_key_mode=inputs.key_mode,
    )
    log.info(
        "remint: minted ticket vm=%s gen=%d ticket_id=%s node=%s",
        vm_id,
        generation,
        fresh_ticket_id,
        inputs.node_id,
    )
    return cose_ticket


class UserdataNotRebindable(EffectError):
    """The §6 userdata digest for a NEW ticket could not be re-derived for
    this VM — raised by [`assert_userdata_rebindable`] at §25 intake, and
    ONLY for that verdict. Any other failure of the probe (Vault down,
    unconfigured, permission) is not this class: those are not statements
    about the VM, and the paths that need Vault will report them anyway.
    """


def assert_userdata_rebindable(vm: object) -> None:
    """Raise unless a dest/recovery ticket for `vm` could have its §6
    userdata digest re-derived — WITHOUT reading a secret.

    Called at §25 intake, while the source is still running. The mint
    itself happens after the source is quiesced, stopped and KBS-fenced,
    and recovery from there is forward-only, so "vali cannot obtain the
    plaintext for this VM" has to surface here or not at all.

    Deliberately narrow: it reads the canonical value's PREFIX (plaintext
    ⇒ usable as-is) and, when that is wrapped, applies the mint's own
    pairing check to the working copy — opened under `ud-<vm_id>`, stamp
    required, stamp == this canonical version — and zeroizes what it
    opened. It never touches the canonical copy's plaintext (vali cannot:
    that is `kek-<vm_id>`, KBS-only). A VM with nothing staged at all is
    NOT judged here — that is a different failure with its own message
    on the mint path.
    """
    vm_id = str(getattr(vm, "vm_id", "") or "")
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", "") or "")
    if not vm_id or not prefix:
        return
    # No Vault ADDRESS configured at all is a deployment with no Vault —
    # the dev/test shape. Distinct from a configured Vault that fails to
    # answer, which IS a reason to refuse (below): there, secrets exist
    # and the probe simply could not read them.
    if not str(getattr(settings, "VALI_VAULT_ADDR", "") or "").strip():
        return
    # The re-mint reads its non-secret binding metadata off the last
    # SUCCEEDED launch record. Without one it raises — and it raises at
    # `DestActivating`, after the fence. `vali_create_vm` writes no such
    # record, which is why a CLI-launched VM could be quiesced, stopped,
    # fenced, and only then found unmigratable.
    if not LaunchJob.objects.filter(vm_id=vm_id, state=LaunchJobState.SUCCEEDED).exists():
        raise UserdataNotRebindable(
            f"vm {vm_id!r} has no successful launch record — a destination "
            "ticket cannot be minted for it (the re-mint reads the launch's "
            "measurement, flavor and identity from that row). VMs launched "
            "with `vali_create_vm` are in this state; relaunch through the "
            "launch API to make one migratable."
        )
    canonical_path = f"{prefix}/{vm_id}/userdata"
    working_path = f"{prefix}/{vm_id}/userdata-pending"
    try:
        version = vault_kv.latest_version(mount, canonical_path)
        canonical = vault_kv.get_kv(mount, canonical_path, version=version)
    except vault_kv.VaultNotFound as exc:
        # Nothing staged at the canonical path at all. The mint would read
        # it and fail — after the fence.
        raise UserdataNotRebindable(
            f"vm {vm_id!r} has no canonical userdata staged ({exc}) — a "
            "destination ticket's §6 digest could not be re-derived"
        ) from exc
    wrapped = canonical.startswith(b"vault:")
    _zeroize(canonical)
    if not wrapped:
        return  # legacy plaintext canonical — the digest re-derives from it
    # The SAME check the mint will apply, run now rather than after the
    # fence: open the working copy under `ud-<vm_id>` and require its
    # stamp to name this canonical version. A shape-only probe (is there a
    # `vault:`-prefixed value at the working path?) admitted an unstamped
    # copy, or one stamped for another version, and the strict check at
    # `DestActivating` then refused it — with the source already quiesced,
    # stopped and KBS-fenced. The plaintext this opens is zeroized at once;
    # the mint will open it again later on the same path anyway.
    from apps.orchestration.services import launch

    try:
        opened = launch.open_userdata_working_copy(mount, working_path, vm_id, version)
    except (vault_kv.VaultNotFound, launch.UserdataPairingError) as exc:
        raise UserdataNotRebindable(
            f"vm {vm_id!r} has a Transit-wrapped canonical userdata and no "
            f"working copy paired to version {version} ({exc}) — a "
            "destination ticket's §6 digest could not be re-derived (vali "
            "holds no `transit/decrypt` for the KBS key). Re-stage the "
            "userdata, which writes both copies, before migrating this VM."
        ) from exc
    _zeroize(opened)


def _read_userdata_plaintext(inputs: TicketInputs, canonical_version: int) -> bytes:
    """The cloud-init PLAINTEXT the §6 digest for this VM must be taken
    over — the bytes that live at the canonical `path@canonical_version`
    the ticket is about to bind.

    Two ways to obtain them, and which one applies is decided by the
    canonical value's own form:

    - **Plaintext at rest** (a VM staged before the wrapping): the
      canonical value IS the plaintext. Use it.
    - **Wrapped** (every VM since): vali cannot open the canonical copy —
      it is wrapped under the KBS-only `kek-<vm_id>`. `launch_on_miner`
      therefore writes vali's working copy of the SAME bytes, under
      `ud-<vm_id>`, in the same step, so the two paths share a version
      number. Read it at that same version, which is what makes "these
      are the bytes that canonical version holds" provable rather than
      assumed.

    Anything else fails closed. Hashing the wrong bytes mints a ticket
    that passes every local check and denies at release — a §25 migration
    that reports Done and a tenant VM that never unlocks.
    """
    from apps.orchestration.services import launch

    canonical = vault_kv.get_kv(inputs.vault_mount, inputs.userdata_path, version=canonical_version)
    if not canonical.startswith(b"vault:"):
        return canonical
    _zeroize(canonical)
    try:
        return launch.open_userdata_working_copy(
            inputs.vault_mount,
            inputs.userdata_working_path,
            inputs.vm_id,
            canonical_version,
        )
    except (vault_kv.VaultNotFound, launch.UserdataPairingError) as exc:
        raise EffectError(
            f"remint: vm {inputs.vm_id!r} has a Transit-wrapped canonical "
            f"userdata and no usable working copy for version "
            f"{canonical_version} ({exc}) — vali cannot recover the plaintext "
            "the §6 digest is taken over (it holds no `transit/decrypt` for "
            "the KBS key). Re-stage the userdata, or relaunch, so both paths "
            "describe the same bytes."
        ) from exc


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
        miner = MinerIdentity.objects.get(miner_id=node_id)
    except MinerIdentity.DoesNotExist as exc:
        raise EffectError(
            f"remint: miner {node_id!r} has no MinerIdentity — "
            "cannot bind the ticket to its SNP chip identity"
        ) from exc
    pid = str(miner.platform_id or "")
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
        _vcpu_type_for_platform(pid, miner.snp_generation)
    except EffectError as exc:
        raise EffectError(
            f"remint: miner {node_id!r} has a malformed platform_id "
            f"({exc}) — the KBS would refuse the KEK release"
        ) from exc
    return pid


def persist_intake(
    cose_ticket: bytes,
    *,
    vm_id: str,
    generation: int,
    ticket_id: str,
    received_from: str = "system:migration-remint",
    expected_key_mode: str | None = None,
) -> None:
    """Store a ticket vali minted as an `OrderTicketIntake` — vali's record
    of every ticket it can have been granted a release against (the KBS
    evidence names only the ticket_id). For a re-mint it also lets the
    dispatch resolve the new_gen ticket and a re-drive stay idempotent. A
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
    # Customer-held keys: read the mode back out of the ticket we just
    # signed (the Rust decoder, not our argv) — a mint that dropped or
    # changed it is never persisted, never dispatched.
    if expected_key_mode is not None and parsed.key_mode != expected_key_mode:
        raise EffectError(
            f"remint: self-minted ticket for {vm_id!r} carries key_mode="
            f"{parsed.key_mode!r}, the VM is {expected_key_mode!r} — refusing it"
        )

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
        # The same ticket_id is already on record — a concurrent tick's
        # re-mint, or a launch re-using a caller-supplied ticket_id. Keep
        # the first row; a veto reading it only ever fails closed.
        log.info(
            "remint: intake race vm=%s gen=%d ticket_id=%s (benign)",
            vm_id,
            generation,
            ticket_id,
        )
