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
"""

from __future__ import annotations

from dataclasses import dataclass

# Per-variant (vcpus, memory_mb, disk_gb). `disk_gb` is the DATA disk.
_CATALOGUE: dict[str, dict[str, int]] = {
    "small": {"cpu_count": 1, "memory_mb": 2048, "disk_gb": 8},
    "medium": {"cpu_count": 2, "memory_mb": 4096, "disk_gb": 16},
    "large": {"cpu_count": 4, "memory_mb": 8192, "disk_gb": 32},
    "xlarge": {"cpu_count": 8, "memory_mb": 16384, "disk_gb": 64},
    "2xlarge": {"cpu_count": 16, "memory_mb": 32768, "disk_gb": 128},
    "4xlarge": {"cpu_count": 32, "memory_mb": 65536, "disk_gb": 256},
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


def resolve_flavor(name: str) -> FlavorSize:
    """Expand a flavor name to its `FlavorSize`. Raises `UnknownFlavor`.

    The single resolution path shared by the CLI (`vali_create_vm`) and
    the `launch` service.
    """
    spec = _CATALOGUE.get(name)
    if spec is None:
        raise UnknownFlavor(
            f"unknown flavor {name!r} (expected one of: {', '.join(FLAVOR_NAMES)})"
        )
    return FlavorSize(
        cpu_count=spec["cpu_count"],
        memory_mb=spec["memory_mb"],
        data_disk_size_gb=spec["disk_gb"],
        luks_disk_size_gb=ROOTFS_DISK_GB,
    )
