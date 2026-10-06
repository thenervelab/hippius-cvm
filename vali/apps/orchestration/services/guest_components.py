"""Guest components releases and the per-VM security floor
(docs/design/guest-component-rollout.md).

A guest components release is appended to a golden base's initrd by
`scripts/guest/guest-initrd-build.sh`, which publishes the result under a
new S3 prefix with a `golden.measurement.json` carrying a `guest_release`
object. [`register_build`] records that build (and its release) from that
document; the guest upgrade job moves VMs onto it.

THE FLOOR (design G3). Every release carries a `security_epoch`. When an
upgrade onto a release is decided, the VM's `required_epoch` is raised to
that release's epoch ([`raise_required_epoch`]) — before anything is stopped
or launched — and every path that mints a launch ticket for the VM refuses
a build below it ([`launch_epoch_refusal`]): the upgrade job's own rollback,
a power start, reboot-recovery, a §25 hop, KBS-state recovery. So once a VM
is meant to leave a vulnerable release, no one — least of all a miner that
blocks the new boot — can get vali to launch it on that release again.

The epoch of a launch set is its build's release epoch; an initrd that is
no registered build (a bake's own initrd, an initrd-only rebuild) is
epoch 0.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from django.db import IntegrityError, transaction

log = logging.getLogger("apps.orchestration.guest_components")

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_FAMILIES = ("initramfs-tools", "dracut")


class BuildRejected(ValueError):
    """A build document that cannot be registered (malformed, or in
    conflict with what is already registered)."""


@dataclass(frozen=True)
class BuildDocument:
    """The fields of a guest release build's `golden.measurement.json` that
    registration reads."""

    s3_bucket: str
    s3_key_prefix: str
    initrd_sha256: str
    kernel_sha256: str
    rootfs_img_sha256: str
    rootfs_verity_sha256: str
    verity_root_hash: str
    source_initrd_sha256: str
    source_bake_id: str
    family: str
    version: int
    security_epoch: int
    commit: str
    squashfs_sha256: str
    release_cpio_sha256: str
    #: The health checks the release's keepalive attests (0: none — a
    #: release without the health leg; documents written before it).
    health_mask: int
    document: dict[str, Any]


def _sha(doc: dict[str, Any], key: str, where: str = "") -> str:
    value = str(doc.get(key) or "").strip().lower()
    if not _SHA_RE.match(value):
        raise BuildRejected(f"{where}{key}: missing or not 64 lowercase hex")
    return value


def _int(doc: dict[str, Any], key: str, where: str) -> int:
    value = doc.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise BuildRejected(f"{where}{key}: missing or not a non-negative integer")
    return value


def _health_mask(release: dict[str, Any]) -> int:
    if "health_mask" not in release:
        return 0
    value = _int(release, "health_mask", "guest_release.")
    if value > 2**32 - 1:
        raise BuildRejected("guest_release.health_mask: does not fit a u32")
    return value


def parse_build(doc: Any, *, bucket: str, prefix: str) -> BuildDocument:
    """Validate a guest release build document read from `bucket`/`prefix`.
    The document must name exactly that location (the build writes it), so
    a copy of another build's document under a new prefix is refused."""
    if not isinstance(doc, dict):
        raise BuildRejected("the measurement is not a JSON object")
    if doc.get("disk_mode") != "golden_verity_overlay":
        raise BuildRejected("not a golden_verity_overlay set")
    release = doc.get("guest_release")
    provenance = doc.get("initrd_rebuild")
    if not isinstance(release, dict) or not isinstance(provenance, dict):
        raise BuildRejected("no guest_release / initrd_rebuild object: not a guest release build")
    if provenance.get("method") != "append-guest-release":
        raise BuildRejected("initrd_rebuild.method is not append-guest-release")
    prefix = prefix.strip().strip("/")
    if str(doc.get("s3_bucket") or "") != bucket or str(doc.get("s3_key_prefix") or "") != prefix:
        raise BuildRejected(
            f"the measurement names s3://{doc.get('s3_bucket')}/{doc.get('s3_key_prefix')}, "
            f"not s3://{bucket}/{prefix} where it was read"
        )
    family = str(release.get("family") or "")
    if family not in _FAMILIES or provenance.get("family") != family:
        raise BuildRejected(f"guest_release.family {family!r} is not a known initramfs family")
    commit = str(release.get("commit") or "")
    if not _COMMIT_RE.match(commit) or provenance.get("repo_commit") != commit:
        raise BuildRejected("guest_release.commit is not the 40-hex commit the build records")
    initrd = _sha(doc, "initrd_sha256")
    source_initrd = _sha(provenance, "source_initrd_sha256", "initrd_rebuild.")
    if initrd == source_initrd:
        raise BuildRejected("the build's initrd equals the base initrd it was appended to")
    return BuildDocument(
        s3_bucket=bucket,
        s3_key_prefix=prefix,
        initrd_sha256=initrd,
        kernel_sha256=_sha(doc, "kernel_sha256"),
        rootfs_img_sha256=_sha(doc, "rootfs_img_sha256"),
        rootfs_verity_sha256=_sha(doc, "rootfs_verity_sha256"),
        verity_root_hash=_sha(doc, "verity_root_hash"),
        source_initrd_sha256=source_initrd,
        source_bake_id=str(provenance.get("source_bake_id") or ""),
        family=family,
        version=_int(release, "version", "guest_release."),
        security_epoch=_int(release, "security_epoch", "guest_release."),
        commit=commit,
        squashfs_sha256=_sha(release, "squashfs_sha256", "guest_release."),
        release_cpio_sha256=_sha(release, "release_cpio_sha256", "guest_release."),
        health_mask=_health_mask(release),
        document=doc,
    )


_BUILD_FIELDS = (
    "source_bake_id",
    "family",
    "kernel_sha256",
    "rootfs_img_sha256",
    "rootfs_verity_sha256",
    "verity_root_hash",
    "base_initrd_sha256",
    "release_cpio_sha256",
    "s3_bucket",
    "s3_key_prefix",
)


def _build_fields(parsed: BuildDocument) -> dict[str, Any]:
    return {
        "source_bake_id": parsed.source_bake_id,
        "family": parsed.family,
        "kernel_sha256": parsed.kernel_sha256,
        "rootfs_img_sha256": parsed.rootfs_img_sha256,
        "rootfs_verity_sha256": parsed.rootfs_verity_sha256,
        "verity_root_hash": parsed.verity_root_hash,
        "base_initrd_sha256": parsed.source_initrd_sha256,
        "release_cpio_sha256": parsed.release_cpio_sha256,
        "s3_bucket": parsed.s3_bucket,
        "s3_key_prefix": parsed.s3_key_prefix,
    }


def _check_epoch_order(version: int, epoch: int) -> None:
    """Epochs never decrease with the version: a later release below an
    earlier one's epoch would let a "forward" upgrade lower a VM's floor."""
    from apps.orchestration.models import GuestComponentRelease

    lower = (
        GuestComponentRelease.objects.filter(version__lt=version)
        .order_by("-security_epoch")
        .values_list("security_epoch", flat=True)
        .first()
    )
    higher = (
        GuestComponentRelease.objects.filter(version__gt=version)
        .order_by("security_epoch")
        .values_list("security_epoch", flat=True)
        .first()
    )
    if (lower is not None and epoch < lower) or (higher is not None and epoch > higher):
        raise BuildRejected(
            f"release v{version} epoch {epoch} would break the epoch order "
            "(epochs never decrease with the version)"
        )


def register_build(parsed: BuildDocument) -> tuple[Any, bool]:
    """Record `parsed` (and its release, the first time a build of it is
    registered). Returns `(build, created)`.

    A release is immutable once recorded: its commit, epoch, image and —
    per initramfs family — its cpio member. A build is idempotent only when
    every immutable field matches; anything else is refused."""
    from apps.orchestration.models import GuestComponentRelease, GuestInitrdBuild

    with transaction.atomic():
        # One registration at a time: the epoch order reads every version.
        list(GuestComponentRelease.objects.select_for_update().all())
        release = GuestComponentRelease.objects.filter(version=parsed.version).first()
        if release is None:
            _check_epoch_order(parsed.version, parsed.security_epoch)
            release = GuestComponentRelease.objects.create(
                version=parsed.version,
                commit=parsed.commit,
                security_epoch=parsed.security_epoch,
                squashfs_sha256=parsed.squashfs_sha256,
                health_mask=parsed.health_mask,
                cpio_sha256={parsed.family: parsed.release_cpio_sha256},
            )
        else:
            if (
                release.commit,
                release.security_epoch,
                release.squashfs_sha256,
                release.health_mask,
            ) != (
                parsed.commit,
                parsed.security_epoch,
                parsed.squashfs_sha256,
                parsed.health_mask,
            ):
                raise BuildRejected(
                    f"release v{parsed.version} is registered with commit {release.commit[:12]} "
                    f"epoch {release.security_epoch} health_mask {release.health_mask}; this "
                    f"build says commit {parsed.commit[:12]} epoch {parsed.security_epoch} "
                    f"health_mask {parsed.health_mask}"
                )
            known = dict(release.cpio_sha256 or {})
            if known.get(parsed.family, parsed.release_cpio_sha256) != parsed.release_cpio_sha256:
                raise BuildRejected(
                    f"release v{parsed.version} has another {parsed.family} member "
                    f"({known[parsed.family][:16]}…) than this build"
                )
            if parsed.family not in known:
                known[parsed.family] = parsed.release_cpio_sha256
                release.cpio_sha256 = known
                release.save(update_fields=["cpio_sha256"])
        fields = _build_fields(parsed)
        existing = GuestInitrdBuild.objects.filter(initrd_sha256=parsed.initrd_sha256).first()
        if existing is not None:
            differs = [f for f in _BUILD_FIELDS if getattr(existing, f) != fields[f]]
            if existing.measurement != parsed.document:
                differs.append("measurement")
            if differs or existing.release_id != release.version:
                raise BuildRejected(
                    f"initrd {parsed.initrd_sha256[:16]}… is already registered with other "
                    f"{', '.join(differs) or 'release'}"
                )
            return existing, False
        try:
            with transaction.atomic():
                build = GuestInitrdBuild.objects.create(
                    release=release,
                    initrd_sha256=parsed.initrd_sha256,
                    measurement=parsed.document,
                    **fields,
                )
        except IntegrityError as exc:
            raise BuildRejected(
                f"another build of release v{release.version} for this base (kernel, "
                f"dm-verity base and base initrd {parsed.source_initrd_sha256[:16]}…), or at "
                f"{parsed.s3_key_prefix}, is already registered"
            ) from exc
    log.info(
        "guest components: registered build v%d %s (base bake %s, %s)",
        release.version,
        build.s3_key_prefix,
        build.source_bake_id,
        build.family,
    )
    return build, True


def build_for_initrd(initrd_sha256_hex: str) -> Any:
    """The registered build whose initrd this is, or None."""
    from apps.orchestration.models import GuestInitrdBuild

    if not initrd_sha256_hex:
        return None
    return (
        GuestInitrdBuild.objects.select_related("release")
        .filter(initrd_sha256=initrd_sha256_hex.strip().lower())
        .first()
    )


def base_initrd_of(initrd_sha256_hex: str) -> str:
    """The base initrd of a launch set, by its initrd: its build's base
    initrd, or the initrd itself when it is no registered build (a bake's
    own, or an initrd-only rebuild of one)."""
    initrd = (initrd_sha256_hex or "").strip().lower()
    build = build_for_initrd(initrd)
    return build.base_initrd_sha256 if build is not None else initrd


def epoch_of_initrd(initrd_sha256_hex: str) -> int:
    """The security epoch of a launch set, by its initrd: its build's
    release epoch, 0 for an initrd that is no registered build."""
    build = build_for_initrd(initrd_sha256_hex)
    return int(build.release.security_epoch) if build is not None else 0


def required_epoch(vm_id: str) -> int:
    from apps.orchestration.models import VmGuestComponents

    row = VmGuestComponents.objects.filter(vm__vm_id=vm_id).values("required_epoch").first()
    return int(row["required_epoch"]) if row else 0


_MAX_HISTORY = 50


def _set_required(row: Any, epoch: int, *, by: str, reason: str) -> None:
    from django.utils import timezone

    history = list(row.history or [])
    history.append(
        {
            "at": timezone.now().isoformat(),
            "from": row.required_epoch,
            "to": epoch,
            "by": by,
            "reason": reason,
        }
    )
    row.history = history[-_MAX_HISTORY:]
    row.required_epoch = epoch
    row.save(update_fields=["required_epoch", "history", "updated_at"])


def raise_required_epoch(vm: Any, epoch: int, *, by: str = "", reason: str = "") -> int:
    """Raise `vm`'s floor to `epoch` (never lowers it). Call inside the
    transaction that decides the upgrade. Returns the floor now in force."""
    from apps.lifecycle.models import Vm
    from apps.orchestration.models import VmGuestComponents

    # The Vm row lock first — the one the register gate decides under — so
    # a raise and a register serialize.
    Vm.objects.select_for_update().filter(pk=vm.pk).first()
    row, _ = VmGuestComponents.objects.select_for_update().get_or_create(vm=vm)
    if epoch > row.required_epoch:
        log.warning(
            "guest components: vm=%s required epoch %d → %d (%s: %s)",
            vm.vm_id,
            row.required_epoch,
            epoch,
            by,
            reason,
        )
        _set_required(row, epoch, by=by, reason=reason)
    return int(row.required_epoch)


def lower_required_epoch(vm: Any, epoch: int, *, operator: str, reason: str) -> int:
    """The audited break-glass: set `vm`'s floor DOWN to `epoch`. Refused
    while a guest upgrade holds the VM. Returns the previous floor."""
    from apps.orchestration.models import (
        TERMINAL_GUEST_UPGRADE_STATES,
        GuestUpgradeJob,
        VmGuestComponents,
    )

    if not (operator and reason):
        raise ValueError("lowering a VM's required epoch needs an operator and a reason")
    with transaction.atomic():
        from apps.lifecycle.models import Vm

        Vm.objects.select_for_update().filter(pk=vm.pk).first()
        if (
            GuestUpgradeJob.objects.filter(vm=vm)
            .exclude(state__in=TERMINAL_GUEST_UPGRADE_STATES)
            .exists()
        ):
            raise ValueError(
                f"vm {vm.vm_id!r}: a guest upgrade is in flight (pending ones too) — "
                "wait for it to end"
            )
        if epoch < 0:
            raise ValueError("an epoch is never negative")
        row, _ = VmGuestComponents.objects.select_for_update().get_or_create(vm=vm)
        before = int(row.required_epoch)
        if epoch >= before:
            raise ValueError(f"vm {vm.vm_id!r}: required epoch is {before}; {epoch} is not lower")
        log.warning(
            "guest components: vm=%s required epoch LOWERED %d → %d by %s: %s",
            vm.vm_id,
            before,
            epoch,
            operator,
            reason,
        )
        _set_required(row, epoch, by=f"lowered-by:{operator}", reason=reason)
    return before


def launch_epoch_refusal(vm_id: str, initrd_sha256_hex: str) -> str:
    """Why a launch of `vm_id` from the set whose initrd is
    `initrd_sha256_hex` must be refused (`""` = it may launch): its epoch
    is below the VM's required epoch."""
    floor = required_epoch(vm_id)
    if floor == 0:
        return ""
    epoch = epoch_of_initrd(initrd_sha256_hex)
    if epoch >= floor:
        return ""
    return (
        f"guest-epoch-below-required: vm {vm_id!r} may not launch on initrd "
        f"{(initrd_sha256_hex or '?')[:16]}… (security epoch {epoch}) — its required epoch "
        f"is {floor} (docs/design/guest-component-rollout.md, G3)"
    )
