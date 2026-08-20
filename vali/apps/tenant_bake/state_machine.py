"""TenantBake state machine — legal transitions + required fields.

Mirrors `apps.packer.state_machine` exactly. The view delegates here
so the rule set is testable without HTTP.

Legal transitions:

    Queued → Running       (baker k8s Job picks the row up)
    Running → Succeeded    (bake completes — needs all 3 SHAs + the
                            96-hex SNP launch digest)
    Running → Failed       (bake errors out — needs failure_reason)

Anything else is rejected at the view boundary. In particular:
  - `Succeeded` and `Failed` are terminal — no transition out.
  - `Queued → Succeeded` / `Queued → Failed` are rejected (the
    worker must claim the row by flipping to Running first so the
    `started_at` timestamp is set).
  - `Running → Queued` is rejected — a retry is a new row, not a
    rewind.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import TenantBakeState


class FinalizeError(Exception):
    """A finalize request was rejected for a non-CAS reason — bad
    shape, illegal source state, missing required field, etc. The
    view surfaces this as HTTP 400 with `category`.
    """

    def __init__(self, message: str, category: str) -> None:
        super().__init__(message)
        self.message = message
        self.category = category


# Stable category strings — same vocabulary as `apps.packer`.
CAT_ILLEGAL = "illegal-transition"
CAT_MISSING_FIELD = "missing-field"
CAT_BAD_FIELD = "bad-field"


@dataclass(frozen=True)
class FinalizeRequest:
    """Caller-supplied payload for
    `POST /v1/tenant-bakes/<bake_id>/finalize`.
    """

    to_state: TenantBakeState
    if_version: int
    qcow2_sha256: str | None = None
    kernel_sha256: str | None = None
    initrd_sha256: str | None = None
    # #587 Phase 1C — LUKS2-header MAC (#296) the bake→launch resolver
    # feeds into the launch spec. Optional (older bakers omit it).
    luks_header_sha256: str | None = None
    measurement_hex: str | None = None
    # golden-bake PR6 — the SHARED dm-verity base artifacts a golden bake
    # reports INSTEAD of `qcow2_sha256`. Their PRESENCE selects the golden
    # finalize contract (no qcow2 required; these three required). Empty on
    # a legacy finalize.
    rootfs_img_sha256: str | None = None
    rootfs_verity_sha256: str | None = None
    verity_root_hash: str | None = None
    failure_reason: str | None = None


_LEGAL_TRANSITIONS: frozenset[tuple[TenantBakeState, TenantBakeState]] = frozenset(
    {
        (TenantBakeState.QUEUED, TenantBakeState.RUNNING),
        (TenantBakeState.RUNNING, TenantBakeState.SUCCEEDED),
        (TenantBakeState.RUNNING, TenantBakeState.FAILED),
    }
)


def legal(from_state: TenantBakeState, to_state: TenantBakeState) -> bool:
    """Return True iff `from_state → to_state` is in the table above."""
    return (from_state, to_state) in _LEGAL_TRANSITIONS


def required_args(to_state: TenantBakeState, req: FinalizeRequest) -> None:
    """Raise `FinalizeError` if `req` is missing fields needed for
    the target state.

    - `Succeeded` (LEGACY): must carry all three artefact SHAs (qcow2 +
      kernel + initrd, 64 lowercase hex each) AND a 96-hex SNP
      launch digest.
    - `Succeeded` (GOLDEN, golden-bake PR6): a golden bake produces NO
      qcow2 — it reports `rootfs_img_sha256` + `rootfs_verity_sha256` +
      `verity_root_hash` (the shared dm-verity base) plus kernel + initrd.
      The PRESENCE of any golden field selects this contract; qcow2 is
      then forbidden (a bake is one mode or the other).
    - `Failed`: must carry `failure_reason` (non-empty).
    """
    if to_state == TenantBakeState.SUCCEEDED:
        _is_golden = any(
            (req.rootfs_img_sha256, req.rootfs_verity_sha256, req.verity_root_hash)
        )
        if _is_golden:
            _required_args_golden(req)
            return
        for field, value in (
            ("qcow2_sha256", req.qcow2_sha256),
            ("kernel_sha256", req.kernel_sha256),
            ("initrd_sha256", req.initrd_sha256),
        ):
            if not value:
                raise FinalizeError(
                    f"{field} required for Succeeded target", CAT_MISSING_FIELD
                )
            if not _is_sha256_hex(value):
                raise FinalizeError(
                    f"{field} must be 64 lowercase hex chars", CAT_BAD_FIELD
                )
        # measurement_hex is OPTIONAL on Succeeded: the SNP launch
        # digest folds OVMF + vcpus — launch-time inputs the bake
        # cannot know. The authoritative digest is computed by the
        # miner's `tenant-preflight` (and pinned by vali) AFTER the
        # bake; a baker that does know it (future UKI-style flows)
        # may still report it here. The original required-96-hex
        # contract made every real in-cluster bake fail at finalize
        # (observed live 2026-06-10, bake take-11).
        if req.measurement_hex and not _is_measurement_hex(req.measurement_hex):
            raise FinalizeError(
                "measurement_hex must be 96 lowercase hex chars",
                CAT_BAD_FIELD,
            )
    if to_state == TenantBakeState.FAILED:
        if not req.failure_reason:
            raise FinalizeError(
                "failure_reason required for Failed target", CAT_MISSING_FIELD
            )


def _required_args_golden(req: FinalizeRequest) -> None:
    """Golden-bake (PR6) Succeeded contract: the shared dm-verity base
    artifacts + kernel + initrd, all 64 lowercase hex; NO qcow2.

    A golden bake is non-confidential (unkeyed dm-verity) — it never
    produces a per-VM LUKS qcow2, so a `qcow2_sha256` on a golden finalize
    is a producer bug (mixed modes) ⇒ fail closed.
    """
    if req.qcow2_sha256:
        raise FinalizeError(
            "qcow2_sha256 must be absent on a golden (dm-verity) finalize",
            CAT_BAD_FIELD,
        )
    for field, value in (
        ("rootfs_img_sha256", req.rootfs_img_sha256),
        ("rootfs_verity_sha256", req.rootfs_verity_sha256),
        ("verity_root_hash", req.verity_root_hash),
        ("kernel_sha256", req.kernel_sha256),
        ("initrd_sha256", req.initrd_sha256),
    ):
        if not value:
            raise FinalizeError(
                f"{field} required for golden Succeeded target", CAT_MISSING_FIELD
            )
        if not _is_sha256_hex(value):
            raise FinalizeError(
                f"{field} must be 64 lowercase hex chars", CAT_BAD_FIELD
            )
    if req.measurement_hex and not _is_measurement_hex(req.measurement_hex):
        raise FinalizeError(
            "measurement_hex must be 96 lowercase hex chars", CAT_BAD_FIELD
        )


def _is_sha256_hex(s: str) -> bool:
    """64 lowercase hex chars. Same rule as `apps.packer`."""
    if len(s) != 64:
        return False
    return all(c in "0123456789abcdef" for c in s)


def _is_measurement_hex(s: str) -> bool:
    """96 lowercase hex chars — 48-byte SNP launch digest."""
    if len(s) != 96:
        return False
    return all(c in "0123456789abcdef" for c in s)
