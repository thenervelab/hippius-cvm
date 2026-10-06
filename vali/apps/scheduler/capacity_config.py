"""Capacity v2 tunables — one getter per setting, read at call time.

Every number the resource-true admission, the earned-capacity tick and
the operator command share lives here, so the three cannot disagree on a
default. Getters (not module constants) so `override_settings` in tests
and a `vali-config` ConfigMap roll both take effect without a re-import.

Validation is deliberately loud: a malformed setting raises at the first
read (`ImproperlyConfigured`) instead of silently falling back to a
default — a capacity knob that quietly ignores its value is exactly how a
fleet ends up sized from a number nobody chose.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

#: The accepted range for a vCPU:thread overcommit ratio, global or per
#: miner. 1.0 = no overcommit. Above 4.0 a shared vCPU stops being worth
#: selling as one. There is NO ratio for RAM: SEV-SNP guest memory is
#: pinned and encrypted, so RAM is a hard 1:1 reservation by design.
CPU_RATIO_MIN = Decimal("1.00")
CPU_RATIO_MAX = Decimal("4.00")


def _int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = getattr(settings, name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured(f"{name}={raw!r} is not an integer") from exc
    if value < minimum:
        raise ImproperlyConfigured(f"{name}={value} is below the minimum {minimum}")
    return value


def _decimal(name: str, default: str, *, minimum: Decimal, maximum: Decimal) -> Decimal:
    raw = getattr(settings, name, default)
    try:
        value = Decimal(str(raw))
    except InvalidOperation as exc:
        raise ImproperlyConfigured(f"{name}={raw!r} is not a number") from exc
    if not value.is_finite():
        raise ImproperlyConfigured(f"{name}={raw!r} is not a finite number")
    if not minimum <= value <= maximum:
        raise ImproperlyConfigured(f"{name}={value} is outside [{minimum}, {maximum}]")
    return value


def parse_cpu_ratio(raw: str) -> Decimal:
    """Parse an operator-supplied ratio; `ValueError` names the problem."""
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise ValueError(f"{raw!r} is not a number") from exc
    if not value.is_finite():
        raise ValueError(f"{raw!r} is not a finite number")
    # Range BEFORE quantize: quantizing a huge finite value raises.
    if not CPU_RATIO_MIN <= value <= CPU_RATIO_MAX:
        raise ValueError(f"{value} is outside [{CPU_RATIO_MIN}, {CPU_RATIO_MAX}]")
    return value.quantize(Decimal("0.01"))


# ─── resource-true admission ────────────────────────────────────────


_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})


def parse_flag(name: str, raw: object) -> bool:
    """Strict boolean: a typo (`ture`) raises instead of reading as False —
    this flag decides which admission model places VMs."""
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ImproperlyConfigured(f"{name}={raw!r} is not a boolean (1/0/true/false/yes/no/on/off)")


def resource_admission_enabled() -> bool:
    """`VALI_SCHEDULER_RESOURCE_ADMISSION` — when False (the default) the
    v1 slot admission decides and v2 runs in SHADOW only (computed and
    diff-logged, never acted on)."""
    name = "VALI_SCHEDULER_RESOURCE_ADMISSION"
    return parse_flag(name, getattr(settings, name, False))


def cpu_overcommit_default() -> Decimal:
    """Fleet-wide vCPU:thread ratio (`VALI_SCHEDULER_CPU_OVERCOMMIT`),
    applied to `total_cpus − reserve`. A miner's `cpu_ratio` overrides it."""
    return _decimal(
        "VALI_SCHEDULER_CPU_OVERCOMMIT", "2.0", minimum=CPU_RATIO_MIN, maximum=CPU_RATIO_MAX
    )


def per_vm_overhead_mb() -> int:
    """RAM (MiB) one SNP guest costs OUTSIDE its own memory — QEMU,
    page tables, vhost. Charged per placement on top of the flavor RAM."""
    return _int("VALI_SCHEDULER_PER_VM_OVERHEAD_MB", 256)


def asid_reserve() -> int:
    """SEV-ES ASIDs kept back from tenant VMs: the host-attestor plus the
    overlap of a §25 migration destination / reboot-recovery relaunch."""
    return _int("VALI_SCHEDULER_ASID_RESERVE", 3)


def operator_vm_hard_cap() -> int:
    """VM-count ceiling for `operator` miners when the host has not
    declared its ASID capacity: the SEV-ES pool of our SKUs (99) less the
    reserve."""
    return _int("VALI_SCHEDULER_OPERATOR_VM_HARD_CAP", 96, minimum=1)


# ─── disk (the DATA-disk dimension) ─────────────────────────────────

DISK_GATE_MODES: tuple[str, ...] = ("off", "record", "enforce")
DISK_UNKNOWN_POLICIES: tuple[str, ...] = ("allow", "deny")


def _choice(name: str, default: str, choices: tuple[str, ...]) -> str:
    raw = getattr(settings, name, default)
    value = str(raw).strip().lower()
    if value not in choices:
        raise ImproperlyConfigured(
            f"{name}={raw!r} is not one of: {', '.join(choices)}"
        )
    return value


def disk_gate_mode() -> str:
    """`VALI_SCHEDULER_DISK_GATE` — `off` (disk ignored), `record` (the
    default: computed, and every placement enforce would have refused is
    logged, but nothing is refused) or `enforce` (a flavor whose disk does
    not fit is refused). Applies under both admission models."""
    return _choice("VALI_SCHEDULER_DISK_GATE", "record", DISK_GATE_MODES)


def disk_unknown_policy() -> str:
    """`VALI_SCHEDULER_DISK_UNKNOWN` — what `enforce` does with a host vali
    has NO disk figure for (no anchor, no fresh v4 heartbeat): `allow` (the
    default — the miner's own statvfs gate is the backstop, and a pre-v4
    fleet must keep placing) or `deny`. NOT a trust boundary: any disk
    term makes a host "known", including a v4 self-report — `deny` filters
    out hosts that send no disk figure at all (pre-v4 agents, a broken
    statvfs), while a lying report is bounded only by the operator anchor
    (`total_disk_gb`) and, after a refusal, the earned disk ceiling."""
    return _choice("VALI_SCHEDULER_DISK_UNKNOWN", "allow", DISK_UNKNOWN_POLICIES)


def disk_reserve_gb() -> int:
    """`VALI_DISK_RESERVE_GB` — GiB of the data fs never handed to tenant
    disks: the staging dir / content-addressed image cache (four distros'
    golden bases, ~10 GiB each, when they share the fs), one inbound §25
    snapshot download (a 40 GiB disk measured ~40 GiB multipart) and
    backup-chain work. 100 GiB covers those with ~20 GiB of slack for
    logs and fs metadata. Subtracted from the operator anchor and the
    reported fs total, never from the declared budget (already net)."""
    return _int("VALI_DISK_RESERVE_GB", 100)


def disk_overclaim_slack_gb() -> int:
    """`VALI_DISK_OVERCLAIM_SLACK_GB` — tolerance of the disk over-claim
    ALARM (`reported available < committed − slack`). 50 GiB absorbs
    statvfs rounding, fs metadata/journal and a guest's first writes
    without flapping; the alarm is observability, never a gate."""
    return _int("VALI_DISK_OVERCLAIM_SLACK_GB", 50)


def slot_ref_disk_gb() -> int:
    """`VALI_SCHEDULER_SLOT_REF_DISK_GB` — the DATA-disk GiB an unknown /
    legacy `resource_class` is charged (the `large` flavor's 160), the disk
    twin of `VALI_SCHEDULER_SLOT_REF_MEMORY_MB`; also the unit disk of the
    reference-flavor `units`."""
    return _int("VALI_SCHEDULER_SLOT_REF_DISK_GB", 160, minimum=1)


# ─── earned capacity (permissionless miners) ────────────────────────


def _at_most_cap(name: str, floor: int, cap: int) -> int:
    """A floor above its hard cap is a contradiction nobody can satisfy."""
    if floor > cap:
        raise ImproperlyConfigured(f"{name}={floor} is above its hard cap {cap}")
    return floor


def earn_floor_vms() -> int:
    name = "VALI_CAPACITY_EARN_FLOOR_VMS"
    return _at_most_cap(name, _int(name, 4, minimum=1), earn_hard_cap_vms())


def earn_floor_vcpus() -> int:
    name = "VALI_CAPACITY_EARN_FLOOR_VCPUS"
    return _at_most_cap(name, _int(name, 8, minimum=1), earn_hard_cap_vcpus())


def earn_floor_memory_mb() -> int:
    name = "VALI_CAPACITY_EARN_FLOOR_MEMORY_MB"
    return _at_most_cap(name, _int(name, 32768, minimum=1024), earn_hard_cap_memory_mb())


def earn_hard_cap_vms() -> int:
    return _int("VALI_CAPACITY_EARN_HARD_CAP_VMS", 64, minimum=1)


def earn_hard_cap_vcpus() -> int:
    return _int("VALI_CAPACITY_EARN_HARD_CAP_VCPUS", 256, minimum=1)


def earn_hard_cap_memory_mb() -> int:
    return _int("VALI_CAPACITY_EARN_HARD_CAP_MEMORY_MB", 1024 * 1024, minimum=1024)


def earn_growth() -> Decimal:
    """Multiplicative increase applied to a held proof."""
    return _decimal(
        "VALI_CAPACITY_EARN_GROWTH", "1.5", minimum=Decimal("1.0"), maximum=Decimal("4.0")
    )


def earn_min_step_vms() -> int:
    return _int("VALI_CAPACITY_EARN_MIN_STEP_VMS", 2)


def earn_min_step_vcpus() -> int:
    return _int("VALI_CAPACITY_EARN_MIN_STEP_VCPUS", 4)


def earn_min_step_memory_mb() -> int:
    return _int("VALI_CAPACITY_EARN_MIN_STEP_MEMORY_MB", 16384)


def earn_util_trigger() -> Decimal:
    """A ceiling only grows once the proven concurrency reaches this
    fraction of it (in any dimension) — growth follows real fill."""
    return _decimal(
        "VALI_CAPACITY_EARN_UTIL_TRIGGER", "0.8", minimum=Decimal("0.1"), maximum=Decimal("1.0")
    )


def earn_hold_s() -> int:
    """How long a concurrency must be HELD before it counts as proven."""
    return _int("VALI_CAPACITY_EARN_HOLD_S", 1800, minimum=60)


def earn_penalty_factor() -> Decimal:
    """Multiplicative decrease on a vali-attributed miner fault."""
    return _decimal(
        "VALI_CAPACITY_EARN_PENALTY_FACTOR", "0.5", minimum=Decimal("0.1"), maximum=Decimal("0.9")
    )


def earned_inflight_max() -> int:
    """Max PENDING (unbound) placements an `earned` miner may hold."""
    return _int("VALI_CAPACITY_EARNED_INFLIGHT_MAX", 2, minimum=1)


def earn_decay_after_s() -> int:
    """A proof not renewed for this long is stale: the next tick re-proves
    from what is running now instead of keeping the old peak."""
    return _int("VALI_CAPACITY_EARN_DECAY_AFTER_S", 14 * 86400, minimum=3600)


def validate_all() -> None:
    """Read every knob once; the first malformed one raises."""
    for getter in (
        resource_admission_enabled,
        cpu_overcommit_default,
        disk_gate_mode,
        disk_unknown_policy,
        disk_reserve_gb,
        disk_overclaim_slack_gb,
        slot_ref_disk_gb,
        per_vm_overhead_mb,
        asid_reserve,
        operator_vm_hard_cap,
        earn_floor_vms,
        earn_floor_vcpus,
        earn_floor_memory_mb,
        earn_hard_cap_vms,
        earn_hard_cap_vcpus,
        earn_hard_cap_memory_mb,
        earn_growth,
        earn_min_step_vms,
        earn_min_step_vcpus,
        earn_min_step_memory_mb,
        earn_util_trigger,
        earn_hold_s,
        earn_penalty_factor,
        earned_inflight_max,
        earn_decay_after_s,
    ):
        getter()
    from .capacity_earn import proof_source

    proof_source()
