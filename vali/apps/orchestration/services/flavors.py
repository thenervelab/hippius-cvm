"""The tenant-VM size catalogue — single Python source of truth.

Spec of record: `hippius_types::flavor::Flavor` (#312). Mirrors that
Rust enum's per-variant `vcpus()` / `memory_mb()` / `disk_gb()` numbers
exactly; the L1-mint / KBS-verify surface is the Rust table, this is the
operator-facing surface. Drift between the two is the kind of bug
`test_flavor_catalogue_matches_rust_enum` is meant to catch.

Extracted from `vali_create_vm` so the CLI and the `launch` service
resolve a flavor identically — one table, no copy.

#365: the flavor's `disk_gb` sizes the tenant **DATA** disk (`/dev/vde`,
formatted fresh in the guest), NOT the rootfs. The rootfs is the fixed
minimal `ROOTFS_DISK_GB` image (`/dev/vda`).

Runner flavors (`runner-*`) are a second, unlisted table for single-use
CI VMs: the compute size of a public flavor with a small data disk, so
the first-boot integrity wipe (it writes every sector) is short. They
are not Rust `Flavor` variants: the signed ticket carries their compute
class (`ticket_flavor`) — the ticket's flavor only fixes vCPU/RAM, the
disk is anchored separately by the measured `hippius.disk_gb=` token —
so adding one needs no KBS / guest / miner-agent rebuild. They launch
and place like any flavor but stay out of every catalogue enumeration
(`FLAVOR_NAMES`: feasibility board, fleet, capacity, resize targets).
"""

from __future__ import annotations

from dataclasses import dataclass

# Per-variant (vcpus, memory_mb, disk_gb). `disk_gb` is the DATA disk.
_CATALOGUE: dict[str, dict[str, int]] = {
    "small": {"cpu_count": 1, "memory_mb": 4096, "disk_gb": 40},
    "medium": {"cpu_count": 2, "memory_mb": 8192, "disk_gb": 80},
    "large": {"cpu_count": 4, "memory_mb": 16384, "disk_gb": 160},
    "xlarge": {"cpu_count": 8, "memory_mb": 32768, "disk_gb": 320},
    "2xlarge": {"cpu_count": 16, "memory_mb": 65536, "disk_gb": 640},
    "4xlarge": {"cpu_count": 32, "memory_mb": 131072, "disk_gb": 1280},
}

# The fixed minimal rootfs size (`/dev/vda`). Tracks the bake's
# `--output-qcow2-gb` / `HCC_BAKE_QCOW2_GB` default. NOT measured (the
# launch digest covers ovmf/kernel/initrd/cmdline/vcpus only), so it is
# a sanity value, not a security anchor — the DATA-disk size IS anchored
# via the measured `hippius.disk_gb=` cmdline token.
ROOTFS_DISK_GB = 10

# The ordered set of valid flavor names — for argparse `choices=` and
# wire validation. Tuple so it stays an immutable, ordered surface.
FLAVOR_NAMES: tuple[str, ...] = tuple(_CATALOGUE)

# Unlisted runner flavors: `ticket_flavor` (a `_CATALOGUE` name, hence a
# Rust variant) MUST have the same cpu_count / memory_mb — the ticket's
# flavor is what the miner checks `cpu_count` against and what the KBS
# verifies; only `disk_gb` differs.
_RUNNER_CATALOGUE: dict[str, dict[str, int | str]] = {
    "runner-small": {"cpu_count": 1, "memory_mb": 4096, "disk_gb": 20, "ticket_flavor": "small"},
    "runner-medium": {"cpu_count": 2, "memory_mb": 8192, "disk_gb": 20, "ticket_flavor": "medium"},
    "runner-large": {"cpu_count": 4, "memory_mb": 16384, "disk_gb": 30, "ticket_flavor": "large"},
}

RUNNER_FLAVOR_NAMES: tuple[str, ...] = tuple(_RUNNER_CATALOGUE)

# Every name a launch may ask for: the listed catalogue, then the runners.
LAUNCHABLE_FLAVOR_NAMES: tuple[str, ...] = FLAVOR_NAMES + RUNNER_FLAVOR_NAMES


@dataclass(frozen=True)
class FlavorSize:
    """The scalars a flavor name resolves to.

    `cpu_count` / `memory_mb` size the guest; `data_disk_size_gb` is the
    flavor's `disk_gb` (the tenant DATA disk); `luks_disk_size_gb` is the
    fixed minimal rootfs (`ROOTFS_DISK_GB`), flavor-independent.
    """

    cpu_count: int
    memory_mb: int
    data_disk_size_gb: int
    luks_disk_size_gb: int


class UnknownFlavor(ValueError):
    """`name` is not in the catalogue."""


def max_offered_flavor() -> str:
    """The largest flavor a tenant may launch.

    `VALI_SCHEDULER_MAX_FLAVOR` empty or unset (the default) ⇒ NO cap:
    every catalogue flavor is offered, and a size is sold wherever a host
    can hold it (feasibility answers per host). Set it to a flavor name to
    withdraw every larger size from sale — a commercial decision, not a
    hardware one. A value outside the catalogue raises
    `ImproperlyConfigured`: a cap that silently falls back is how a sales
    decision gets lost."""
    from django.conf import settings
    from django.core.exceptions import ImproperlyConfigured

    name = "VALI_SCHEDULER_MAX_FLAVOR"
    value = str(getattr(settings, name, "") or "").strip().lower()
    if not value:
        return FLAVOR_NAMES[-1]
    if value not in _CATALOGUE:
        raise ImproperlyConfigured(
            f"{name}={value!r} is not a flavor (expected one of: {', '.join(FLAVOR_NAMES)}, "
            "or empty for no cap)"
        )
    return value


def is_offered(name: str) -> bool:
    """Is `name` in the catalogue AND at or below the offered maximum?
    The catalogue is ordered by size, so "at or below" is by position. A
    runner flavor is offered iff its compute class (`ticket_flavor`) is."""
    if name in _RUNNER_CATALOGUE:
        name = ticket_flavor(name)
    if name not in _CATALOGUE:
        return False
    return FLAVOR_NAMES.index(name) <= FLAVOR_NAMES.index(max_offered_flavor())


def resolve_flavor(name: str) -> FlavorSize:
    """Expand a flavor name to its `FlavorSize`. Raises `UnknownFlavor`.

    The single resolution path shared by the CLI (`vali_create_vm`) and
    the `launch` service.
    """
    spec = _CATALOGUE.get(name) or _RUNNER_CATALOGUE.get(name)
    if spec is None:
        raise UnknownFlavor(
            f"unknown flavor {name!r} (expected one of: {', '.join(LAUNCHABLE_FLAVOR_NAMES)})"
        )
    return FlavorSize(
        cpu_count=int(spec["cpu_count"]),
        memory_mb=int(spec["memory_mb"]),
        data_disk_size_gb=int(spec["disk_gb"]),
        luks_disk_size_gb=ROOTFS_DISK_GB,
    )


def ticket_flavor(name: str) -> str:
    """The `hippius_types::flavor::Flavor` name the OrderTicket carries
    for `name`: itself for a catalogue flavor, its compute class for a
    runner flavor. Raises `UnknownFlavor`."""
    if name in _CATALOGUE:
        return name
    spec = _RUNNER_CATALOGUE.get(name)
    if spec is None:
        raise UnknownFlavor(
            f"unknown flavor {name!r} (expected one of: {', '.join(LAUNCHABLE_FLAVOR_NAMES)})"
        )
    return str(spec["ticket_flavor"])
