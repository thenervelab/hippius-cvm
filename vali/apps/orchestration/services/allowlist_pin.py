"""§22 allowlist pin orchestration (production control-plane path).

vali is the trusted §22 signing authority: it holds the allowlist-root
Ed25519 seed in Vault and signs a fresh allowlist artifact whenever a
launch needs a new measurement pinned. The KBS pins the matching root
PUBKEY and verifies every artifact (COSE_Sign1 signature + monotonic
epoch) — so the miner stays untrusted and vali's signature is the trust
anchor. This is a normal authenticated control-plane operation; there is
no dev gate (the per-launch `auto_pin_allowlist` intent flag is the
control).

Pipeline:
  1. Read the current manifest TOML (the in-cluster copy at
     `VALI_ALLOWLIST_MANIFEST_PATH`).
  2. Increment `epoch` (only the integer line is touched).
  3. Append one `[[entries]]` block per measurement that must be
     allowed AFTER this pin — the CARRY-FORWARD set (every live VM's
     measurement + every active host-attestor release) plus the new
     one. See `_carry_forward_classes`.
  4. Subprocess `hippius-kbs-allowlist-tool` to sign with the root seed
     (fetched from Vault) and emit a fresh COSE.
  5. Subprocess `aws s3 cp` to overwrite the S3 object the KBS init
     container fetches on restart.
  6. POST the bytes to the KBS `/v1/admin/allowlist/reload` so the live
     in-memory allowlist advances immediately.

CUMULATIVE, not incremental — the artifact is a full REPLACEMENT:
`kbs_core::allowlist::InstalledAllowlist::install` swaps the whole
active body (`*g = Some(Active{..})`); it does NOT merge with what was
installed before. The static base manifest is a read-only ConfigMap
that no pin ever writes back to, so building `base + 1 entry` EVICTS
every previously auto-pinned measurement. The same allowlist gates the
§21 KEK release (`kbs-core/src/release.rs` `pre_release_validate` +
`offline.contains(&report.measurement)`), so an evicted VM cannot
unlock its LUKS overlay on its next boot. Every pin therefore rebuilds
`base ∪ carry-forward ∪ {new}`.

SERIALIZED, because it is a read-modify-write of one shared artifact:
the carry-forward is read from `MeasurementLedger`, whose row for a pin
used to be written by the caller AFTER the install. Three power-API
starts landing within a second (#1340) each read the same carry-forward,
each appended only its own measurement, and each install REPLACED the
previous one — the last pin won, the other two VMs were denied their KEK
(`measurement not in offline KBS allowlist`) and never booted. So the
whole read → sign → install → ledger-row sequence runs under
`pin_lock()` (a Postgres advisory lock, cluster-wide across gunicorn
workers and tick pods), and the ledger row is written INSIDE it: the
next pin cannot read the carry-forward until the previous measurement is
recorded there. The lock is held for ONE attempt: a 409 retry releases
it and re-reads the carry-forward under the next hold, so a burst of
pins queues behind one sign + upload + reload each, not behind another
pin's whole retry loop.

§20 discipline:
- The signing seed is fetched from Vault and materialized only into a
  0600 file inside a per-attempt tmpfs workdir, removed with the dir.
- AWS credentials come from the process env.
- The TOML manipulations are pure string rewrites.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
import tomllib
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.db import OperationalError, connection, transaction

from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.services import s3_artifacts

log = logging.getLogger("apps.orchestration.allowlist_pin")

DEFAULT_SIGN_TIMEOUT_S = 30.0
DEFAULT_S3_TIMEOUT_S = 60.0

#: Pauses between attempts of the allowlist upload on a TRANSIENT S3 error
#: (three attempts in all). The upload sits on the launch path: a single
#: `SlowDown` used to fail the whole launch as `allowlist-pin-failure`.
S3_UPLOAD_RETRY_PAUSES_S: tuple[float, ...] = s3_artifacts.RETRY_PAUSES_S

#: What counts as a transient S3 error — shared with the launch-digest
#: fetches (`s3_artifacts`).
_S3_TRANSIENT = s3_artifacts.TRANSIENT_S3_ERROR
DEFAULT_KBS_RELOAD_TIMEOUT_S = 30.0

# `l1-order-ticket-v1` hex — the PRODUCTION L1 OrderTicket kid (#587
# Phase 1A). Its pubkey `4f8a1eb8…` is pinned in the KBS `l1Keys`
# keyring; the auto-pin records this kid in every entry's
# `accepted_l1_kids_hex` so a measurement only accepts prod-kid tickets.
DEFAULT_L1_KID_HEX = "6c312d6f726465722d7469636b65742d7631"
# `kbs-cc-1-response-v1` hex
DEFAULT_KBS_RESPONSE_KID_HEX = "6b62732d63632d312d726573706f6e73652d7631"


class AllowlistEpochConflict(EffectError):
    """KBS rejected the reload with 409 — the most common cause is the
    epoch HWM CAS (the installed epoch is ≥ the one we tried). The pin
    loop catches this to retry at a higher epoch; a non-epoch 409
    (signature / schema) re-raises the same way and exhausts the
    bounded retries, surfacing the error after the attempts."""


# How many times `pin_measurement` re-bumps the epoch + retries when
# the KBS reload 409s. The static manifest ConfigMap's `epoch = N`
# drifts behind the installed HWM after every successful pin (the
# manifest is read-only; the bump lives only in the signed artifact),
# so a fresh pin can start several epochs behind. 16 covers a long
# run of un-resynced pins without masking a genuine sig/schema 409.
_MAX_EPOCH_RETRIES = 16


class AllowlistPinBusy(EffectUnavailable):
    """Another pin held `pin_lock()` for longer than `PIN_LOCK_TIMEOUT_S`.
    Nothing was signed or installed, so the caller may retry: a launch
    maps it to `RETRIABLE` (pre-register — a re-place is safe), a
    reboot-recovery relaunch retries on its backoff, a power start is
    refused and can be re-asked."""


#: How long a pin waits for the lock before giving up with the RETRIABLE
#: `AllowlistPinBusy`. Sized from the live logs, not from the worst case:
#: over 72 h of production launches (2026-09-26..29, n=43) the span from
#: the carry-forward read to the KBS register that FOLLOWS the pin (so an
#: upper bound on one lock hold) was p50 1.6 s, p90 1.8 s, max 2.3 s, with
#: no 409 retry at all. 30 s therefore queues ~12+ normal pins. The worst
#: case of ONE attempt (sign 30 s + three S3 tries at 60 s + reload 30 s,
#: ~4 min) cannot fit any wait the power API's 60 s worker allows, so a
#: slow pin is absorbed by the retry — the launch re-places, reboot-
#: recovery retries on its backoff, a power start answers a re-askable
#: `allowlist-pin-busy` — never by a longer wait.
PIN_LOCK_TIMEOUT_S = 30.0

#: `pg_advisory_xact_lock` key — any fixed int64 unique to this purpose
#: ("allowlst" in ASCII).
_PIN_LOCK_KEY = 0x616C6C6F776C7374

#: The non-Postgres stand-in (tests run on SQLite, which has no advisory
#: locks): serializes the pins of ONE process. Re-entrant, like the
#: Postgres lock is within a session.
_PROCESS_PIN_LOCK = threading.RLock()


@contextmanager
def pin_lock() -> Iterator[None]:
    """Hold the §22 pin lock for the enclosed block, inside a transaction.

    Postgres: a transaction-scoped advisory lock, so it is released by the
    COMMIT that also publishes the ledger row written under it — and by
    the server if the process dies holding it. Waiting longer than
    `PIN_LOCK_TIMEOUT_S` raises `EffectUnavailable`.

    `pin_measurement` takes it itself; a caller that also writes state the
    carry-forward reads (the host-attestor release row) wraps both.

    Nested use is re-entrant, but a NESTED hold is a savepoint: if the
    inner block raises, the savepoint rollback releases the advisory lock
    taken inside it (only the outer hold survives). Never take this lock
    for the first time inside an `atomic()` block whose failure you catch
    and continue from — the "locked" code after it would run unlocked.
    """
    if connection.vendor != "postgresql":
        if not _PROCESS_PIN_LOCK.acquire(timeout=PIN_LOCK_TIMEOUT_S):
            raise AllowlistPinBusy(
                f"allowlist pin: another pin held the lock for over {PIN_LOCK_TIMEOUT_S:.0f}s"
            )
        try:
            with transaction.atomic():
                yield
        finally:
            _PROCESS_PIN_LOCK.release()
        return
    with transaction.atomic():
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('lock_timeout', %s, true)",
                    [f"{int(PIN_LOCK_TIMEOUT_S * 1000)}ms"],
                )
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", [_PIN_LOCK_KEY])
        except OperationalError as exc:
            raise AllowlistPinBusy(
                f"allowlist pin: another pin held the lock for over {PIN_LOCK_TIMEOUT_S:.0f}s"
            ) from exc
        yield


@dataclass(frozen=True)
class PinLedger:
    """The `MeasurementLedger` row a pin records for its measurement —
    written under `pin_lock()`, so the next pin's carry-forward sees it."""

    vm_id: str
    platform_id: str = ""
    node_id: str = ""
    # The launch the measurement is for — see `MeasurementLedger`.
    flavor: str = ""
    attests_resources: bool = False
    accepts_memory_eagerly: bool = False
    # See `MeasurementLedger.recomputed` / `.launch_ref`.
    recomputed: bool = False
    launch_ref: str = ""


@dataclass(frozen=True)
class PinResult:
    """One epoch-bump + measurement-append + S3 upload + KBS reload."""

    new_epoch: int
    new_cose_sha256_hex: str
    s3_url: str


def _resolve_seed_hex() -> str:
    """Resolve the §22 allowlist-root signing seed as a 64-hex string.

    PRODUCTION: `VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH` → fetch the
    `seed` field from Vault (vali holds the root seed online — the
    trusted control-plane signing authority).
    TEST/dev affordance: `VALI_KBS_ALLOWLIST_ROOT_SEED_PATH` → read a
    64-hex seed file.
    Neither set ⇒ fail closed.

    §20: the returned string is secret-bearing — the caller materializes
    it into a 0600 tmpfs file and drops it promptly; never logged.
    """
    vault_path = getattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH", "")
    if vault_path:
        # Local import to avoid a module-load cycle (vault_kv imports settings).
        from apps.orchestration.services.vault_kv import get_kv_field

        mount = getattr(settings, "VALI_VAULT_KV_MOUNT", "secret")
        seed_hex = get_kv_field(mount, vault_path, "seed").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", seed_hex):
            raise EffectError(
                "allowlist-root Vault seed is not 64 lower-case hex chars"
            )
        return seed_hex
    seed_file = getattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_PATH", "")
    if seed_file:
        if not os.path.isfile(seed_file):
            raise EffectUnavailable(
                "VALI_KBS_ALLOWLIST_ROOT_SEED_PATH does not exist"
            )
        with open(seed_file, encoding="utf-8") as fh:
            return fh.read().strip().lower()
    raise EffectUnavailable(
        "no allowlist-root signing seed configured "
        "(set VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH)"
    )


# ─── TOML manipulation (string-level) ────────────────────────────────


_EPOCH_LINE_RE = re.compile(r"(?m)^epoch\s*=\s*(\d+)\s*$")


def _bump_epoch_text(text: str, floor: int | None = None) -> tuple[str, int]:
    """Return `(new_text, new_epoch)`. Raises if `epoch = N` is absent
    or appears more than once at the top level.

    `new_epoch = max(current + 1, floor)`. The `floor` lets the pin
    loop force the epoch above a just-rejected value when the static
    manifest ConfigMap lags the KBS's installed HWM (every successful
    pin advances the HWM but the read-only manifest stays put, so a
    fresh pin can start several epochs behind)."""
    matches = list(_EPOCH_LINE_RE.finditer(text))
    if len(matches) != 1:
        raise EffectError(
            f"allowlist-manifest: expected exactly one top-level "
            f"`epoch = N` line, found {len(matches)}"
        )
    m = matches[0]
    current = int(m.group(1))
    new = current + 1
    if floor is not None and floor > new:
        new = floor
    new_text = text[: m.start()] + f"epoch = {new}" + text[m.end():]
    return new_text, new


# §22 trust classes the pin may write into a manifest entry (mirrors the
# Rust `kbs_core::snp::AllowlistClass` snake_case wire form). `tenant` is
# the default and is written by OMITTING the `class` key (byte-identical to
# every legacy entry — no golden/KAT drift); `host_attestor` writes an
# explicit `class = "host_attestor"` so the KBS `class_of` gate namespaces
# the blackbox host-attestor measurement APART from every tenant image (it
# can never satisfy a tenant release, and vice-versa — blackbox host-
# attestor security must-have #1). Any other value is refused fail-closed.
ALLOWLIST_CLASS_TENANT = "tenant"
ALLOWLIST_CLASS_HOST_ATTESTOR = "host_attestor"
# A CDN node's launch (CDN plan V2, `apps.cdn.identity`): the KBS releases
# the CDN fleet keyring only to this class. A KBS that predates the class
# rejects the whole artifact (`deny_unknown_fields`), so a NEW `cdn_node`
# pin is refused until `VALI_CDN_LAUNCH_ROLE` is on — which goes on only
# once a KBS that knows it is live. Entries already in a manifest, or carried
# forward for a live CDN VM, are always accepted and re-emitted: refusing
# them would stop every pin fleet-wide.
ALLOWLIST_CLASS_CDN_NODE = "cdn_node"
_VALID_CLASSES = frozenset(
    {ALLOWLIST_CLASS_TENANT, ALLOWLIST_CLASS_HOST_ATTESTOR, ALLOWLIST_CLASS_CDN_NODE}
)


def _append_entry(
    text: str,
    *,
    measurement_hex: str,
    l1_kids: Sequence[str],
    kbs_kids: Sequence[str],
    measurement_class: str = ALLOWLIST_CLASS_TENANT,
) -> str:
    """Append one `[[entries]]` block at the end of the manifest. The
    Rust `dev-manifest.toml` ends with arrays of accepted kids; one
    blank line + `[[entries]]` block parses cleanly.

    `measurement_class` writes the §22 trust class: `tenant` (default)
    OMITS the `class` key (byte-identical to legacy entries + the golden
    `dev.cose`), while `host_attestor` and `cdn_node` write an explicit
    `class = "…"` line so the KBS namespaces the measurement out of the
    tenant set."""
    if measurement_class not in _VALID_CLASSES:
        raise EffectError(
            f"pin_measurement: unknown allowlist class {measurement_class!r}"
        )
    block = ["", "[[entries]]"]
    block.append(f'measurement_hex = "{measurement_hex}"')
    block.append(
        "accepted_l1_kids_hex = ["
        + ", ".join(f'"{k}"' for k in l1_kids)
        + "]"
    )
    block.append(
        "accepted_kbs_response_kids_hex = ["
        + ", ".join(f'"{k}"' for k in kbs_kids)
        + "]"
    )
    # Emit `class` ONLY for a non-default class — a tenant
    # entry omits it (the KBS back-fills the `Tenant` default), keeping the
    # signed CBOR byte-identical to legacy tenant pins.
    if measurement_class != ALLOWLIST_CLASS_TENANT:
        block.append(f'class = "{measurement_class}"')
    sep = "" if text.endswith("\n") else "\n"
    return text + sep + "\n".join(block) + "\n"


# ─── Subprocess + I/O helpers ────────────────────────────────────────


def _run(
    argv: Sequence[str],
    *,
    label: str,
    timeout_s: float,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(  # noqa: S603 — argv list, no shell
            list(argv),
            capture_output=True,
            timeout=timeout_s,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        raise EffectUnavailable(f"{label}: binary not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise EffectError(f"{label}: timeout after {timeout_s}s") from exc


def _required_setting(name: str) -> str:
    value = str(getattr(settings, name, "") or "").strip()
    if not value:
        raise EffectUnavailable(f"{name} is not configured")
    return value


def _installed_epoch_floor() -> int | None:
    """The epoch to START the pin at — one past the highest epoch vali
    has already installed, or `None` when vali has pinned nothing yet.

    The static manifest's `epoch = N` line is FROZEN (it is a read-only
    ConfigMap), while every successful reload advances the live KBS HWM
    by one. So after more than `_MAX_EPOCH_RETRIES` successful pins the
    whole `manifest_epoch + 1 … + _MAX_EPOCH_RETRIES` window falls at or
    below the HWM and EVERY reload 409s (anti-rollback) — the +1 retry
    loop can never climb far enough. vali holds the sole §22 allowlist
    signing seed, so the highest epoch it has recorded in the
    `MeasurementLedger` IS the live HWM; starting one past it lands the
    first attempt strictly above the HWM. The retry loop then only has
    to cover residual drift (e.g. a best-effort ledger write that lost
    the last success), not the full accumulated gap.

    Best-effort: a query failure returns `None` and the pin falls back
    to the manifest-epoch behaviour + retry loop. The savepoint keeps that
    failure from aborting the `pin_lock()` transaction it runs in (which
    would silently drop the ledger row written later in it).
    """
    try:
        from django.db.models import Max

        from apps.orchestration.models import MeasurementLedger

        with transaction.atomic():
            agg = MeasurementLedger.objects.aggregate(
                pinned=Max("allowlist_epoch"), evicted=Max("evicted_epoch")
            )
        # A refresh (`evict_superseded_measurements`) installs an epoch no
        # pin row records; the rows it evicted do.
        mx = max((int(v) for v in agg.values() if v), default=None)
        return (mx + 1) if mx else None
    except Exception:  # noqa: BLE001 — floor is an optimisation, never load-bearing
        return None


# ─── Carry-forward: the measurements a re-pin must NOT evict ─────────


_MEASUREMENT_RE = re.compile(r"[0-9a-f]{96}")

# `lifecycle.VmState` values (LOWER-CASE in the DB) that mean "this VM
# will never boot again" — the only rows whose measurement may be
# dropped from the artifact. Everything else (active, migrating,
# decommissioning) still has to be able to unlock its overlay.
# `failed` is not a `VmState` today; listed so a future terminal state
# with that name is treated as dead rather than carried forever.
_DEAD_VM_STATES = frozenset({"destroyed", "failed"})

# Hard ceiling on how many entries a single pin may CARRY (the base
# manifest's own entries are on top of this). The carry set is bounded
# by the live fleet, so blowing through this means the "live" filter
# stopped filtering — fail closed rather than sign a multi-megabyte
# artifact that quietly re-admits the whole history.
_MAX_CARRY_FORWARD_ENTRIES = 512


def _normalise_measurement(value: object) -> str | None:
    """Lower-case a candidate measurement and return it iff it is a
    well-formed 96-hex digest, else `None`.

    Dropping a MALFORMED value is safe (not a silent eviction): a
    measurement that is not 96 hex chars could never have been pinned —
    `pin_measurement` rejects those before signing — so it cannot be in
    the installed allowlist to begin with.
    """
    text = str(value or "").strip().lower()
    return text if _MEASUREMENT_RE.fullmatch(text) else None


def _manifest_entry_classes(text: str) -> dict[str, str]:
    """`measurement_hex → §22 class` for every entry ALREADY in the base
    manifest. Those entries are preserved verbatim by the rewrite, so the
    map is what the appender must dedup against (the signing tool refuses
    a manifest with a duplicate measurement — a duplicate would abort the
    pin, not merely bloat it).

    Fail-closed: an unparseable manifest, a malformed `measurement_hex`
    or an unknown `class` raises.
    """
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise EffectError("allowlist-manifest: base manifest is not valid TOML") from exc
    out: dict[str, str] = {}
    for raw in parsed.get("entries") or []:
        if not isinstance(raw, dict):
            raise EffectError("allowlist-manifest: [[entries]] item is not a table")
        measurement = _normalise_measurement(raw.get("measurement_hex"))
        if measurement is None:
            raise EffectError(
                "allowlist-manifest: an entry has a malformed measurement_hex"
            )
        cls = str(raw.get("class") or ALLOWLIST_CLASS_TENANT).strip().lower()
        if cls not in _VALID_CLASSES:
            raise EffectError(
                f"allowlist-manifest: entry {measurement[:16]}… has unknown "
                f"class {cls!r}"
            )
        out[measurement] = cls
    return out


def _carry_forward_classes() -> dict[str, str]:
    """`measurement_hex → §22 class` for every measurement that MUST stay
    allowed after this pin.

    Because `install` REPLACES the active allowlist, anything missing
    from the artifact is evicted — and an evicted measurement can no
    longer satisfy `pre_release_validate`, i.e. that VM cannot unlock its
    LUKS overlay on its next boot. Two POSITIVELY-CLASSED sources, each
    enumerated from a table that also determines the class (the class is
    never guessed and never defaults to `tenant`):

    - TENANT / CDN_NODE — the measurements recorded for every
      `lifecycle.Vm` that is not in a dead state, from `MeasurementLedger.launch_digest_hex`
      (whose write is best-effort, so it has holes) UNIONED with the
      latest `LaunchJob.result_json['emit']['measurement_hex']` for that
      `vm_id` (which is how the live measurements were recovered when
      this bug was diagnosed). Each keeps the tenant/cdn_node class its
      pin recorded; one with none is `cdn_node` when a CDN node is bound to
      the VM (`apps.cdn.identity.is_cdn_vm`, the rule its launch pinned
      under) and `tenant` otherwise.
    - HOST_ATTESTOR — `telemetry.HostAttestorRelease` rows that are still
      `is_active` (the {current, previous} rolling-update grace window).
      `release_service.admit_release` is the ONLY writer of a
      `host_attestor`-class pin and it always records that row, so this
      table IS the registry of host-attestor-class measurements. Rows
      that have been trimmed OUT of the grace window are not carried but
      are still a BLOCKLIST for the tenant class.

    Two independent vetoes back the derivation up, both fail-closed: a
    measurement that a live VM claims AND a host-attestor release
    (active or trimmed) claims — or that both a CDN node's VM and another
    VM claim — and a measurement whose
    `MeasurementLedger.measurement_class` (the class the pin actually
    used) disagrees with the derived one.

    Scoping to LIVE VMs is the growth bound: carrying every measurement
    ever pinned would grow the trusted set forever and keep destroyed
    VMs' images admissible.

    Fail-closed, deliberately UNLIKE `_installed_epoch_floor`: if the set
    cannot be computed we RAISE. Falling back to "base + 1" is exactly
    the eviction bug this function exists to prevent, so a DB outage must
    stop the pin, not silently narrow the allowlist. A measurement that
    appears under BOTH classes also raises — re-emitting a host-attestor
    measurement as `tenant` would let it satisfy a tenant release, which
    is strictly worse than the availability bug.
    """
    try:
        return _query_carry_forward_classes()
    except EffectError:
        raise
    except Exception as exc:  # noqa: BLE001 — mapped to a fail-closed EffectError
        raise EffectError(
            "allowlist carry-forward: could not compute the live measurement "
            f"set ({type(exc).__name__}) — refusing to sign an allowlist that "
            "would evict live VMs"
        ) from exc


def _current_launch_pins(ledger_model: Any, vm_ids: set[str]) -> dict[str, tuple[str, Any]]:
    """`vm_id → (measurement, launched_at)` of each VM's CURRENT launch: its
    newest pin whose launch the miner ACCEPTED (`launched_at`, stamped by
    `launch._mark_measurement_launched`, or when an `already-launched`
    record settled on it, `launch_record.resolve_unverified_boot`). Absent
    for a VM with no accepted pin on record (rows written before the stamp
    existed) — such a VM keeps every measurement it ever pinned, as before.

    `launched_at`, not `pinned_at`, is the line: a launch is stamped right
    after its own pin, so only a relaunch pinned since is kept — and a
    record settled late on an earlier dispatch drops the dispatches pinned
    after that one, which never ran."""
    out: dict[str, tuple[str, Any]] = {}
    for vm_id, digest, launched_at in (
        ledger_model.objects.filter(vm_id__in=vm_ids, launched_at__isnull=False)
        .order_by("vm_id", "-launched_at", "-pinned_at")
        .values_list("vm_id", "launch_digest_hex", "launched_at")
    ):
        measurement = _normalise_measurement(digest)
        if vm_id not in out and measurement is not None:
            out[vm_id] = (measurement, launched_at)
    return out


def _superseded(current: tuple[str, Any] | None, measurement: str, at: Any) -> bool:
    """Is `measurement` (pinned / launched at `at`) a launch the VM's
    current accepted launch replaced?

    The KBS releases only to a measurement that is in BOTH the ticket's
    `allowed_measurements` (exactly one: its own launch's) and this
    allowlist. Dropping a superseded measurement here is therefore what
    makes every ticket of an earlier launch unusable — a pre-resize ticket
    can no longer boot the pre-resize size — and stops that guest's
    keepalives. Kept: the current launch, and anything pinned AFTER it (a
    relaunch in flight, or one that failed before the miner accepted it:
    until a later launch is accepted, the current one must stay bootable —
    the rollback case)."""
    if current is None:
        return False
    current_measurement, current_launched_at = current
    if measurement == current_measurement:
        return False
    return at is None or at <= current_launched_at


def _query_carry_forward_classes() -> dict[str, str]:
    """The DB half of `_carry_forward_classes` (separated so the caller
    can map ANY failure to a fail-closed `EffectError`)."""
    from django.apps import apps as django_apps

    vm_model = django_apps.get_model("lifecycle", "Vm")
    ledger_model = django_apps.get_model("orchestration", "MeasurementLedger")
    launch_model = django_apps.get_model("orchestration", "LaunchJob")
    release_model = django_apps.get_model("telemetry", "HostAttestorRelease")
    cdn_node_model = django_apps.get_model("cdn", "CdnNode")

    # Live VMs. The state values are lower-case in the DB; normalise
    # rather than trusting the case so a mixed-case row is not silently
    # treated as dead (which would evict a live VM).
    live_vm_ids = {
        vm_id
        for vm_id, state in vm_model.objects.values_list("vm_id", "state")
        if str(state or "").strip().lower() not in _DEAD_VM_STATES
    }
    # The live VMs that are CDN nodes (`apps.cdn.identity.is_cdn_vm`): a node
    # is BOUND to the VM row, which only a CDN node's launch does. A durable
    # fact of the VM — no setting or flag moves it.
    cdn_vm_ids = {
        node_id
        for node_id, bound in cdn_node_model.objects.filter(
            node_id__in=live_vm_ids, vm__isnull=False
        ).values_list("node_id", "vm__vm_id")
        if node_id == bound
    }
    # A live VM's measurement keeps the tenant/cdn_node class its pin
    # recorded: a CDN VM pinned `tenant` (before its node was bound) stays
    # `tenant` — it never asks for the fleet keyring, and reclassing it would
    # trip the veto below for every pin. Only a measurement with no recorded
    # class (the ledger write is best-effort) is classed by the binding.
    recorded: dict[tuple[str, str], str] = {}
    if live_vm_ids:
        for vm_id, digest, cls in ledger_model.objects.filter(
            vm_id__in=live_vm_ids,
            measurement_class__in=(ALLOWLIST_CLASS_TENANT, ALLOWLIST_CLASS_CDN_NODE),
        ).values_list("vm_id", "launch_digest_hex", "measurement_class"):
            measurement = _normalise_measurement(digest)
            if measurement is not None:
                recorded[(vm_id, measurement)] = cls

    tenant: set[str] = set()
    cdn: set[str] = set()

    def _carry(vm_id: str, measurement: str) -> None:
        derived = (
            ALLOWLIST_CLASS_CDN_NODE if vm_id in cdn_vm_ids else ALLOWLIST_CLASS_TENANT
        )
        cls = recorded.get((vm_id, measurement), derived)
        (cdn if cls == ALLOWLIST_CLASS_CDN_NODE else tenant).add(measurement)

    if live_vm_ids:
        current = _current_launch_pins(ledger_model, live_vm_ids)
        rows = ledger_model.objects.filter(vm_id__in=live_vm_ids).values_list(
            "vm_id", "launch_digest_hex", "pinned_at"
        )
        for vm_id, digest, pinned_at in rows:
            measurement = _normalise_measurement(digest)
            if measurement is None:
                continue
            if _superseded(current.get(vm_id), measurement, pinned_at):
                continue
            _carry(vm_id, measurement)

        # Latest launch job per vm_id that actually carries a measurement
        # (the ledger write is best-effort, so this is the belt to its
        # braces). Ordered newest-first per vm_id; the first hit wins —
        # unless the ledger knows that measurement as a superseded launch.
        # A measurement the ledger does NOT know (its row was lost) is kept:
        # it may be the launch running now. (The job's `started_at` says
        # nothing here: a relaunch rewrites the job it came from in place.)
        superseded = {
            (vm_id, measurement)
            for vm_id, digest, pinned_at in rows
            if (measurement := _normalise_measurement(digest)) is not None
            and _superseded(current.get(vm_id), measurement, pinned_at)
        }
        seen_vm_ids: set[str] = set()
        job_rows = (
            launch_model.objects.filter(vm_id__in=live_vm_ids)
            .order_by("vm_id", "-started_at")
            .values_list("vm_id", "result_json")
        )
        for vm_id, result_json in job_rows:
            if vm_id in seen_vm_ids:
                continue
            emit = (result_json or {}).get("emit") or {}
            measurement = _normalise_measurement(emit.get("measurement_hex"))
            if measurement is None:
                continue
            seen_vm_ids.add(vm_id)
            if (vm_id, measurement) in superseded:
                continue
            _carry(vm_id, measurement)

    # EVERY host-attestor release ever admitted, active or not. The
    # ACTIVE ones are carried; the inactive ones still matter as a
    # blocklist — a trimmed release's measurement must never come back
    # as a TENANT entry (that is exactly the "auto-pinned from a miner
    # report" bleed the class namespace exists to stop).
    host_known: set[str] = set()
    host_carried: set[str] = set()
    for raw, is_active in release_model.objects.values_list(
        "measurement", "is_active"
    ):
        measurement = _normalise_measurement(raw)
        if measurement is None:
            continue
        host_known.add(measurement)
        if is_active:
            host_carried.add(measurement)

    # A measurement can only be in ONE §22 trust class. An overlap means
    # a host-attestor image is also attributed to a tenant VM — refuse
    # rather than pick one (picking `tenant` is the security regression).
    overlap = (tenant | cdn) & host_known
    if overlap:
        raise EffectError(
            "allowlist carry-forward: measurement "
            f"{sorted(overlap)[0][:16]}… is claimed by BOTH a live VM and a "
            "host-attestor release — refusing to guess its §22 class"
        )
    overlap = tenant & cdn
    if overlap:
        raise EffectError(
            "allowlist carry-forward: measurement "
            f"{sorted(overlap)[0][:16]}… is claimed by BOTH a CDN node and "
            "another VM — refusing to guess its §22 class"
        )

    carried: dict[str, str] = {m: ALLOWLIST_CLASS_TENANT for m in tenant}
    carried.update({m: ALLOWLIST_CLASS_CDN_NODE for m in cdn})
    carried.update({m: ALLOWLIST_CLASS_HOST_ATTESTOR for m in host_carried})

    # Veto: the ledger records the class each pin actually USED. Any row —
    # for any VM, live or not, including the `host-attestor-release`
    # audit sentinel — that recorded a different class than the one we
    # derived fails the pin. This is what stops a derivation drift from
    # silently re-emitting a `host_attestor` measurement as `tenant`.
    # (Blank on rows written before the column existed ⇒ no veto, the
    # derivation stands.)
    if carried:
        recorded_rows = ledger_model.objects.filter(
            launch_digest_hex__in=sorted(carried)
        ).values_list("launch_digest_hex", "measurement_class")
        for digest, cls in recorded_rows:
            measurement = _normalise_measurement(digest)
            recorded = str(cls or "").strip().lower()
            if measurement is None or not recorded:
                continue
            derived = carried.get(measurement)
            if derived is not None and recorded != derived:
                raise EffectError(
                    f"allowlist carry-forward: measurement {measurement[:16]}… "
                    f"was pinned as {recorded!r} but resolves to {derived!r} — "
                    "refusing to re-pin it under a different §22 class"
                )

    if len(carried) > _MAX_CARRY_FORWARD_ENTRIES:
        raise EffectError(
            f"allowlist carry-forward: {len(carried)} measurements exceeds the "
            f"{_MAX_CARRY_FORWARD_ENTRIES} cap — refusing to sign"
        )
    return carried


# ─── Public entry point ──────────────────────────────────────────────


def pin_measurement(
    *,
    measurement_hex: str,
    l1_kids_hex: Sequence[str] = (DEFAULT_L1_KID_HEX,),
    kbs_response_kids_hex: Sequence[str] = (DEFAULT_KBS_RESPONSE_KID_HEX,),
    measurement_class: str = ALLOWLIST_CLASS_TENANT,
    ledger: PinLedger | None = None,
) -> PinResult:
    """Rebuild the allowlist as `base ∪ carry-forward ∪ {measurement}`,
    sign, upload, reload. Returns the new epoch + the sha256 of the
    signed COSE bytes (the KBS init container compares against this
    exact value).

    CUMULATIVE by construction: the KBS REPLACES its active allowlist on
    install, so the artifact must re-state every measurement that has to
    stay releasable — the base manifest's entries (preserved verbatim)
    plus `_carry_forward_classes()` (every live VM + every active
    host-attestor release), deduped. Emitting `base + 1` instead evicts
    every earlier auto-pin and strands those VMs' LUKS overlays at their
    next boot.

    `measurement_class` selects the §22 trust class of the pinned entry
    (`tenant` default / `host_attestor`). A `host_attestor` pin is
    class-namespaced so it can NEVER alias a tenant measurement — the
    blackbox host-attestor release path (PR-9) passes it; every existing
    tenant launch keeps the default and its byte-identical output.

    SERIALIZED under `pin_lock()` from the carry-forward read to the
    `ledger` row, which is recorded before the lock is released — pass it
    for every measurement that must survive later pins (see the module
    docstring, #1340)."""
    if measurement_class not in _VALID_CLASSES:
        raise EffectError(
            f"pin_measurement: unknown allowlist class {measurement_class!r}"
        )
    if measurement_class == ALLOWLIST_CLASS_CDN_NODE:
        from apps.cdn.identity import launch_role_enabled

        if not launch_role_enabled():
            raise EffectError(
                "pin_measurement: a cdn_node pin needs VALI_CDN_LAUNCH_ROLE (a KBS "
                "that predates the class would reject the whole allowlist)"
            )

    return _install(
        measurement_hex=measurement_hex,
        measurement_class=measurement_class,
        l1_kids_hex=l1_kids_hex,
        kbs_response_kids_hex=kbs_response_kids_hex,
        ledger=ledger,
    )


def pending_superseded_pins() -> list[Any]:
    """Ledger rows of live VMs whose launch a later ACCEPTED launch
    replaced, still waiting for an install that drops them."""
    from django.apps import apps as django_apps

    vm_model = django_apps.get_model("lifecycle", "Vm")
    ledger_model = django_apps.get_model("orchestration", "MeasurementLedger")
    live_vm_ids = {
        vm_id
        for vm_id, state in vm_model.objects.values_list("vm_id", "state")
        if str(state or "").strip().lower() not in _DEAD_VM_STATES
    }
    if not live_vm_ids:
        return []
    current = _current_launch_pins(ledger_model, live_vm_ids)
    pending = []
    for row in ledger_model.objects.filter(
        vm_id__in=set(current), evicted_at__isnull=True
    ).order_by("pinned_at"):
        measurement = _normalise_measurement(row.launch_digest_hex)
        if measurement is not None and _superseded(current[row.vm_id], measurement, row.pinned_at):
            pending.append(row)
    return pending


def evict_superseded_measurements() -> int:
    """Drop every superseded launch from the KBS allowlist NOW: if any live
    VM has a pin a later accepted launch replaced (a resize, a
    reboot-recovery or power-start relaunch), install `base ∪
    carry-forward` — which no longer carries it — and stamp those rows
    `evicted_at` / `evicted_epoch`. Returns how many rows were evicted
    (0 = nothing pending, no install).

    Defence in depth: the KBS itself refuses a superseded launch's ticket
    once the later launch registered or released
    (`kbs_core::lifecycle::check_current_launch`). This keeps the trusted
    set to the launches that may still boot, and stops a stale guest's
    keepalives on a KBS that predates that gate.

    Called right after a launch is accepted, and from the orchestration
    tick (a busy lock, an S3 or KBS error there is retried next tick; any
    other pin evicts them too, since every install rebuilds the same
    carry-forward). The stamp is written under the same `pin_lock()` hold
    as the install, from the carry-forward that install was built from."""
    if not pending_superseded_pins():
        return 0
    stamped: list[int] = []

    def _stamp(result: PinResult) -> None:
        from django.utils import timezone

        from apps.orchestration.models import MeasurementLedger

        rows = pending_superseded_pins()
        MeasurementLedger.objects.filter(pk__in=[r.pk for r in rows]).update(
            evicted_at=timezone.now(), evicted_epoch=result.new_epoch
        )
        stamped.extend(r.pk for r in rows)
        log.warning(
            "allowlist: evicted %d superseded launch measurement(s) at epoch %d (vms=%s)",
            len(rows),
            result.new_epoch,
            ",".join(sorted({r.vm_id for r in rows}))[:200],
        )

    _install(
        measurement_hex=None,
        measurement_class=ALLOWLIST_CLASS_TENANT,
        l1_kids_hex=(DEFAULT_L1_KID_HEX,),
        kbs_response_kids_hex=(DEFAULT_KBS_RESPONSE_KID_HEX,),
        ledger=None,
        on_installed=_stamp,
    )
    return len(stamped)


def refresh_allowlist() -> PinResult:
    """Re-sign and install `base ∪ carry-forward` with nothing new — what
    evicts a measurement the carry-forward stopped carrying (a superseded
    launch, `evict_superseded_measurements`). Same lock, same epoch
    discipline as a pin."""
    return _install(
        measurement_hex=None,
        measurement_class=ALLOWLIST_CLASS_TENANT,
        l1_kids_hex=(DEFAULT_L1_KID_HEX,),
        kbs_response_kids_hex=(DEFAULT_KBS_RESPONSE_KID_HEX,),
        ledger=None,
    )


def _install(
    *,
    measurement_hex: str | None,
    measurement_class: str,
    l1_kids_hex: Sequence[str],
    kbs_response_kids_hex: Sequence[str],
    ledger: PinLedger | None,
    on_installed: Callable[[PinResult], None] | None = None,
) -> PinResult:
    """The serialized sign → upload → reload loop shared by a pin and a
    refresh (see `pin_measurement`). `on_installed` runs under the same
    `pin_lock()` hold, right after a successful install (a savepoint keeps
    a failure in it from poisoning the lock's transaction; it is logged,
    the install stands)."""
    manifest_path = _required_setting("VALI_ALLOWLIST_MANIFEST_PATH")
    s3_url = _required_setting("VALI_KBS_ALLOWLIST_S3_URL")
    sign_bin = _required_setting("VALI_KBS_ALLOWLIST_TOOL_BIN")
    seed_hex = _resolve_seed_hex()
    if not os.path.isfile(manifest_path):
        raise EffectUnavailable("VALI_ALLOWLIST_MANIFEST_PATH does not exist")
    if not (os.path.isabs(sign_bin) and os.access(sign_bin, os.X_OK)):
        raise EffectUnavailable(
            "VALI_KBS_ALLOWLIST_TOOL_BIN must be an absolute path to "
            "an executable file"
        )
    if measurement_hex is not None and not re.fullmatch(r"[0-9a-f]{96}", measurement_hex):
        raise EffectError(
            "pin_measurement: measurement_hex must be exactly 96 lower-case "
            "hex chars (48 bytes)"
        )

    with open(manifest_path, encoding="utf-8") as fh:
        original = fh.read()

    floor: int | None = None
    last_conflict: AllowlistEpochConflict | None = None
    for _attempt in range(_MAX_EPOCH_RETRIES):
        # One attempt per lock hold (module docstring): a 409 leaves the
        # lock, and the next attempt re-reads the carry-forward under it.
        with pin_lock():
            attempt = _pin_once(
                original,
                floor=floor,
                measurement_hex=measurement_hex,
                measurement_class=measurement_class,
                l1_kids_hex=l1_kids_hex,
                kbs_response_kids_hex=kbs_response_kids_hex,
                seed_hex=seed_hex,
                s3_url=s3_url,
                sign_bin=sign_bin,
            )
            if isinstance(attempt, PinResult):
                if ledger is not None and measurement_hex is not None:
                    _record_ledger(ledger, measurement_hex, measurement_class, attempt)
                if on_installed is not None:
                    try:
                        with transaction.atomic():
                            on_installed(attempt)
                    except Exception:  # noqa: BLE001 — the install already stands
                        log.exception("allowlist: post-install bookkeeping failed")
                return attempt
        # The installed HWM is ≥ the epoch just tried: retry one past it.
        last_conflict, floor = attempt

    # Retries exhausted — surface the last 409. Either the installed
    # HWM raced ahead faster than we could climb (operationally
    # implausible) or the 409 was never about the epoch (signature /
    # schema), in which case re-bumping could never have helped.
    raise last_conflict or EffectError(
        "kbs-admin-reload: epoch retries exhausted with no recorded conflict"
    )


def _record_ledger(
    ledger: PinLedger, measurement_hex: str, measurement_class: str, result: PinResult
) -> None:
    """Record the pinned measurement in `MeasurementLedger` (#587 Phase 3,
    `GET /v1/admin/audit/measurements`). The KBS install is the
    authoritative record, so a failed write does not fail the pin — but the
    carry-forward and the live-attestation ingest both read this table: a
    lost row means the next pin evicts this measurement and the VM's uptime
    is not credited. A savepoint keeps a failed INSERT from poisoning the
    `pin_lock()` transaction."""
    from apps.orchestration.models import MeasurementLedger

    try:
        with transaction.atomic():
            MeasurementLedger.objects.create(
                vm_id=ledger.vm_id,
                launch_digest_hex=measurement_hex,
                platform_id=ledger.platform_id,
                node_id=ledger.node_id,
                allowlist_epoch=result.new_epoch,
                allowlist_sha256=result.new_cose_sha256_hex,
                # Recorded so the carry-forward can veto a class flip.
                measurement_class=measurement_class,
                flavor=ledger.flavor,
                attests_resources=ledger.attests_resources,
                accepts_memory_eagerly=ledger.accepts_memory_eagerly,
                recomputed=ledger.recomputed,
                launch_ref=ledger.launch_ref,
            )
    except Exception as exc:  # noqa: BLE001 — must not fail an installed pin
        log.error(
            "measurement-ledger write failed vm=%s: %s — the pin is installed, "
            "but the next pin will not carry it and its live attestations will "
            "be refused (measurement-unpinned) until a ledger row is written",
            ledger.vm_id,
            exc,
        )


def _pin_once(
    original: str,
    *,
    floor: int | None,
    measurement_hex: str | None,
    measurement_class: str,
    l1_kids_hex: Sequence[str],
    kbs_response_kids_hex: Sequence[str],
    seed_hex: str,
    s3_url: str,
    sign_bin: str,
) -> PinResult | tuple[AllowlistEpochConflict, int]:
    """ONE read-modify-write attempt of `pin_measurement` — only ever run
    under `pin_lock()`. Returns the installed `PinResult`, or on a KBS 409
    the conflict and the epoch floor to retry at (`floor` is the previous
    attempt's; `None` on the first). `measurement_hex=None` re-signs the
    carry-forward alone (`refresh_allowlist`)."""
    # Build the FULL entry set this artifact must carry. `install`
    # replaces the active allowlist wholesale, so every measurement that
    # must remain releasable has to be in these bytes — see
    # `_carry_forward_classes` (fail-closed: it raises rather than let a
    # DB hiccup degrade back to "base + 1", which is the eviction bug).
    base_classes = _manifest_entry_classes(original)
    to_pin = dict(_carry_forward_classes())
    carried_count = len(to_pin)
    if measurement_hex is not None:
        prior_class = to_pin.get(measurement_hex)
        if prior_class is not None and prior_class != measurement_class:
            raise EffectError(
                f"pin_measurement: {measurement_hex[:16]}… is already carried as "
                f"{prior_class!r}; refusing to re-pin it as {measurement_class!r}"
            )
        to_pin[measurement_hex] = measurement_class

    # Dedup against the base manifest, whose entries survive the rewrite
    # verbatim. `hippius-kbs-allowlist-tool` ABORTS on a duplicate
    # measurement (and `into_indexed` demands strictly-ascending unique
    # entries), so an un-deduped rebuild would fail the pin outright.
    appended: list[tuple[str, str]] = []
    for measurement in sorted(to_pin):
        entry_class = to_pin[measurement]
        base_class = base_classes.get(measurement)
        if base_class is not None:
            if base_class != entry_class:
                raise EffectError(
                    f"pin_measurement: {measurement[:16]}… is in the base "
                    f"manifest as {base_class!r} but resolves to "
                    f"{entry_class!r} — refusing to sign a class-ambiguous "
                    "allowlist"
                )
            continue
        appended.append((measurement, entry_class))
    log.info(
        "allowlist pin: base=%d carried=%d appended=%d (new=%s… class=%s)",
        len(base_classes),
        carried_count,
        len(appended),
        measurement_hex[:16] if measurement_hex else "<refresh>",
        measurement_class,
    )

    # Epoch. The static manifest ConfigMap's `epoch = N` only ever
    # advances in the SIGNED artifact, never on disk, so a fresh pin
    # starts at `manifest_epoch + 1` even after several successful pins
    # already pushed the KBS's installed HWM higher. On a 409
    # (install-rejected, almost always the HWM CAS) the caller retries
    # one past this attempt; a genuine signature/schema 409 exhausts the
    # bounded retries and surfaces the same error.
    #
    # Seed the floor from the highest epoch vali has already installed
    # (`MeasurementLedger`) so a manifest whose frozen `epoch = N` has
    # drifted many pins behind the live HWM still lands its FIRST attempt
    # above the HWM instead of burning all `_MAX_EPOCH_RETRIES` at or
    # below it — see `_installed_epoch_floor`.
    installed_floor = _installed_epoch_floor()
    if installed_floor is not None and (floor is None or installed_floor > floor):
        floor = installed_floor
    # 1+2: read, bump epoch, append entry. Write to a tmpfs
    # intermediary so we can sign without mutating the operator's
    # source TOML on disk (the dev manifest may be a git checkout).
    bumped, new_epoch = _bump_epoch_text(original, floor=floor)
    new_manifest = bumped
    for entry_measurement, entry_class in appended:
        # Carried entries re-use the module DEFAULT kids: every pin
        # this control plane has ever emitted (tenant launches and
        # host-attestor releases alike) used them, so re-emitting the
        # defaults reproduces what was installed. Explicit kids only
        # ever apply to the measurement being pinned NOW.
        is_new = entry_measurement == measurement_hex
        new_manifest = _append_entry(
            new_manifest,
            measurement_hex=entry_measurement,
            l1_kids=l1_kids_hex if is_new else (DEFAULT_L1_KID_HEX,),
            kbs_kids=(
                kbs_response_kids_hex
                if is_new
                else (DEFAULT_KBS_RESPONSE_KID_HEX,)
            ),
            measurement_class=entry_class,
        )

    with tempfile.TemporaryDirectory(prefix="hippius-allowlist-") as workdir:
        manifest_out = os.path.join(workdir, "manifest.toml")
        cose_out = os.path.join(workdir, "dev.cose")
        seed_out = os.path.join(workdir, "seed.hex")
        with open(manifest_out, "w", encoding="utf-8") as fh:
            fh.write(new_manifest)
        # Materialize the seed 0600 inside the (tmpfs) workdir; removed
        # with the TemporaryDirectory. §20: never logged, never on a
        # persistent volume.
        seed_fd = os.open(seed_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(seed_fd, "w", encoding="utf-8") as fh:
            fh.write(seed_hex)

        # 3: sign.
        sign_proc = _run(
            [sign_bin, "--manifest", manifest_out, "--seed", seed_out, "--out", cose_out],
            label="kbs-allowlist-tool",
            timeout_s=DEFAULT_SIGN_TIMEOUT_S,
        )
        if sign_proc.returncode != 0:
            stderr_tail = sign_proc.stderr.decode("utf-8", errors="replace").strip()
            raise EffectError(
                f"kbs-allowlist-tool: exit={sign_proc.returncode} stderr={stderr_tail!r}"
            )
        with open(cose_out, "rb") as fh:
            cose_bytes = fh.read()
        if not cose_bytes:
            raise EffectError("kbs-allowlist-tool: empty COSE output")
        new_sha = hashlib.sha256(cose_bytes).hexdigest()

        # 4: upload to S3 so the KBS init container's startup-replay
        #    path picks up the same bytes on the next pod restart.
        #    The runtime swap below does not require this — kbs-admin's
        #    `/v1/admin/allowlist/reload` accepts the bytes from the
        #    request body directly — but the S3 mirror keeps the
        #    startup path + the helm chart's `allowlist.url` reference
        #    in sync with what the live KBS is serving.
        _s3_upload(cose_out, s3_url)

        # 5: in-memory swap via kbs-admin. The handler runs the SAME
        #    `InstalledAllowlist::install` the file-fed startup path
        #    uses — signature verify + epoch-HWM CAS + atomic active
        #    swap. No kubectl, no RBAC concentration in vali, no pod
        #    restart.
        try:
            _reload_kbs_allowlist(cose_bytes)
        except AllowlistEpochConflict as conflict:
            # The installed HWM is ≥ new_epoch: the caller retries one
            # past this attempt. The S3 object we just wrote is harmlessly
            # overwritten by the next one.
            return conflict, new_epoch + 1

    return PinResult(
        new_epoch=new_epoch,
        new_cose_sha256_hex=new_sha,
        s3_url=s3_url,
    )


def _s3_upload(local_path: str, s3_url: str) -> None:
    """Subprocess `aws s3 cp <local> s3://<bucket>/<key>`. The chart's
    `VALI_KBS_ALLOWLIST_S3_URL` is the HTTPS URL the KBS init container
    `curl`s; `aws s3 cp` requires the `s3://bucket/key` form, so we
    translate by stripping the endpoint scheme + host. The operator's
    AWS_* env (access key, secret, region) MUST be set before invoking
    `vali_create_vm`; we propagate the env verbatim."""
    aws_bin = str(getattr(settings, "VALI_AWS_CLI_BIN", "") or "").strip() or "aws"
    endpoint = str(getattr(settings, "VALI_S3_ENDPOINT_URL", "") or "").strip()
    s3_uri = _https_to_s3_uri(s3_url, endpoint)
    argv: list[str] = [aws_bin]
    if endpoint:
        argv.extend(["--endpoint-url", endpoint])
    argv.extend(["s3", "cp", local_path, s3_uri])
    pauses = list(S3_UPLOAD_RETRY_PAUSES_S)
    while True:
        proc = _run(
            argv,
            label="aws-s3-cp",
            timeout_s=DEFAULT_S3_TIMEOUT_S,
            env=os.environ.copy(),
        )
        if proc.returncode == 0:
            return
        stderr_tail = proc.stderr.decode("utf-8", errors="replace").strip()
        if not pauses or not _S3_TRANSIENT.search(stderr_tail):
            raise EffectError(
                f"aws-s3-cp: exit={proc.returncode} stderr={stderr_tail!r}"
            )
        pause = pauses.pop(0)
        log.warning(
            "allowlist-pin: transient S3 error on upload (%s) — retrying in %.0f s",
            stderr_tail[-160:],
            pause,
        )
        time.sleep(pause)


def _https_to_s3_uri(https_url: str, endpoint: str) -> str:
    """Translate `https://<endpoint-host>/<bucket>/<key>` (the form the
    KBS init-container fetches) → `s3://<bucket>/<key>` (the form
    `aws s3 cp` requires). Already-`s3://` URLs pass through. A URL
    whose host doesn't match the endpoint host fails-closed — the
    operator likely pointed at the wrong bucket.
    """
    if https_url.startswith("s3://"):
        return https_url
    if not https_url.startswith(("https://", "http://")):
        raise EffectError(
            f"aws-s3-cp: VALI_KBS_ALLOWLIST_S3_URL must be https:// or s3://, "
            f"got {https_url[:20]!r}"
        )
    # Strip scheme + netloc; what's left is `/<bucket>/<key>`.
    from urllib.parse import urlparse

    parsed = urlparse(https_url)
    if endpoint:
        ep_host = urlparse(endpoint).netloc
        if parsed.netloc != ep_host:
            raise EffectError(
                f"aws-s3-cp: VALI_KBS_ALLOWLIST_S3_URL host {parsed.netloc!r} "
                f"does not match VALI_S3_ENDPOINT_URL host {ep_host!r}"
            )
    path = parsed.path.lstrip("/")
    if "/" not in path:
        raise EffectError(
            f"aws-s3-cp: VALI_KBS_ALLOWLIST_S3_URL path {path!r} lacks <bucket>/<key>"
        )
    return f"s3://{path}"


def _reload_kbs_allowlist(cose_bytes: bytes) -> None:
    """POST the freshly-signed COSE artifact to
    `VALI_KBS_ADMIN_URL/v1/admin/allowlist/reload` so the live KBS
    runs the same `InstalledAllowlist::install` it ran at startup —
    signature verify + epoch HWM CAS + atomic active-body swap, all
    without a pod restart.

    Fails closed:
    - `EffectUnavailable` on transport failure, and on ANY admin-TLS
      misconfiguration — `kbs_admin_tls.admin_transport` refuses to
      hand back a downgraded transport, so a broken client identity
      stops the pin instead of pinning over an unauthenticated hop.
    - `EffectError` on any non-200 response. The kbs-admin handler
      classifies via the `reason` field of `AdminErrorResponse`; we
      surface the HTTP status + the static reason without leaking the
      URL or body bytes.
    """
    import urllib.error
    import urllib.request

    # Local import: `kbs_admin_tls` imports `settings`, and importing it
    # at module load would tighten this module's import graph for a
    # dependency only this function needs.
    from apps.orchestration.services.kbs_admin_tls import (
        KbsAdminTlsMisconfigured,
        admin_transport,
    )

    try:
        transport = admin_transport()
    except KbsAdminTlsMisconfigured as exc:
        raise EffectUnavailable(str(exc)) from exc
    url = transport.url("/v1/admin/allowlist/reload")
    context = transport.context

    request = urllib.request.Request(
        url,
        data=cose_bytes,
        headers={"Content-Type": "application/cbor"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=DEFAULT_KBS_RELOAD_TIMEOUT_S,
            context=context,
        ) as resp:  # noqa: S310 — vali-internal, mTLS-pinned ClusterIP service
            status = resp.status
    except urllib.error.HTTPError as exc:
        # kbs-admin returned a 4xx/5xx — surface the HTTP status. The
        # `reason` field lives in the CBOR response body; we don't
        # parse CBOR in Python (no stdlib + no project dep), but
        # status-only is enough to triage:
        #   409 → install-rejected (signature, schema, or HWM)
        #   415 → wrong-content-type
        #   429 → rate-limited
        #   413 → body-too-large
        # The kbs-admin pod logs carry the verbose classifier.
        if exc.code == 409:
            # Retriable at a higher epoch (HWM CAS) — see
            # `AllowlistEpochConflict` + the pin_measurement loop.
            raise AllowlistEpochConflict(
                "kbs-admin-reload: kbs returned status=409 (install-rejected)"
            ) from exc
        raise EffectError(
            f"kbs-admin-reload: kbs returned status={exc.code}"
        ) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise EffectUnavailable("kbs-admin-reload: peer unreachable") from exc
    if not 200 <= status < 300:
        raise EffectError(f"kbs-admin-reload: unexpected status={status}")
