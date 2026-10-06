"""C2 — vali's INDEPENDENT SEV-SNP launch-digest recompute.

`launch.py` auto-pins the MINER-reported `launch_digest` into the §22
allowlist. A miner can boot a BACKDOORED guest (the preflight SHA-check
only binds the download, not what is booted), report the backdoor's
digest → vali signs it into §22 → the backdoored guest attests to the
now-allowlisted measurement → the KBS releases the tenant KEK → the
backdoor exfiltrates the disk.

The fix: vali recomputes the digest a HONEST guest must produce, from the
inputs vali ITSELF put in the LaunchOrder — the pinned OVMF plus the
kernel / initrd / cmdline / vcpus / vcpu-type / guest-features — and
refuses any miner-asserted value that differs. The computation is
byte-identical to the miner-agent's (both call the same
`snp_calc_launch_digest`; see `binaries/launch-digest`), so a legitimate
launch yields the miner's value and a mismatch is a real divergence.

vali fetches the exact bytes it references (kernel/initrd from S3 by the
launch SHAs, OVMF from the pinned S3 artifact SHA-verified against
`VALI_SNP_OVMF_SHA256`) and shells out to the snp-featured
`hippius-launch-digest` binary baked in the image. The fetches go through
`s3_artifacts`: a per-pod cache keyed by the pinned sha (re-verified on
every load) and a retry of transient S3 errors.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from django.conf import settings

from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.services import s3_artifacts

_FETCH_TIMEOUT_S = 120.0
#: One budget for ALL of a recompute's fetches (OVMF + kernel + initrd,
#: retries included), so transient S3 trouble cannot hold a launch — or
#: the orchestration tick, which runs reboot-recovery launches inline —
#: much longer than a single slow fetch used to.
_FETCH_BUDGET_S = 240.0
_DIGEST_TIMEOUT_S = 60.0
_DIGEST_RE = re.compile(r"[0-9a-f]{96}")


class LaunchDigestUnavailable(Exception):
    """The recompute is not configured (fail-open pre-rollout) — distinct
    from a mismatch/computation error, which is a security signal."""


def _aws_bin() -> str:
    return str(getattr(settings, "VALI_AWS_CLI_BIN", "") or "").strip() or "aws"


def _endpoint() -> str:
    return str(getattr(settings, "VALI_S3_ENDPOINT_URL", "") or "").strip()


def is_enabled() -> bool:
    """True iff the recompute is fully configured (binary + pinned OVMF)."""
    return bool(
        str(getattr(settings, "VALI_LAUNCH_DIGEST_BIN", "") or "").strip()
        and str(getattr(settings, "VALI_SNP_OVMF_S3_URI", "") or "").strip()
        and str(getattr(settings, "VALI_SNP_OVMF_SHA256", "") or "").strip()
    )


def enforce() -> bool:
    return bool(getattr(settings, "VALI_LAUNCH_DIGEST_ENFORCE", False))


def _s3_cp(s3_uri: str, dest: Path, *, deadline: float | None = None) -> None:
    """`aws s3 cp` one object, retrying a transient S3 error (`SlowDown`,
    5xx, throttling, a timeout) until `deadline` (`time.monotonic()`) —
    see `s3_artifacts`."""
    aws = _aws_bin()
    endpoint = _endpoint()
    argv = [aws]
    if endpoint:
        argv.extend(["--endpoint-url", endpoint])
    argv.extend(["s3", "cp", s3_uri, str(dest)])

    def attempt(timeout_s: float) -> str | None:
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, no shell
                argv,
                capture_output=True,
                timeout=timeout_s,
                check=False,
                env=os.environ.copy(),
            )
        except FileNotFoundError as exc:
            raise EffectUnavailable("aws-s3-cp: binary not found") from exc
        except subprocess.TimeoutExpired:
            return f"aws-s3-cp: RequestTimeout — no answer within {timeout_s:.0f} s"
        if proc.returncode == 0:
            return None
        tail = proc.stderr.decode("utf-8", errors="replace").strip()
        return f"aws-s3-cp: exit={proc.returncode} stderr={tail!r}"

    s3_artifacts.retry_transient(
        attempt,
        what="launch-digest fetch",
        deadline=deadline if deadline is not None else time.monotonic() + _FETCH_BUDGET_S,
        attempt_timeout_s=_FETCH_TIMEOUT_S,
    )


def _fetch_verify(
    s3_uri: str, dest: Path, expected_sha256_hex: str, label: str, deadline: float
) -> None:
    """The pinned bytes at `dest`, from the per-pod sha-keyed cache or S3."""
    s3_artifacts.fetch_verified(
        s3_uri,
        dest,
        expected_sha256_hex,
        label,
        fetch=lambda uri, path: _s3_cp(uri, path, deadline=deadline),
    )


#: `MinerIdentity.snp_generation` value ⇒ (SNP vCPU model, CHIP_ID bytes).
#: Milan and Genoa both report a 64-byte CHIP_ID, so the length alone cannot
#: tell them apart: a Milan host must be registered with an explicit
#: generation, or its guests are measured (and refused) as Genoa.
SNP_GENERATION_VCPU: dict[str, tuple[str, int]] = {
    "turin": ("EpycTurin", 8),
    "genoa": ("EpycGenoa", 64),
    "milan": ("EpycMilan", 64),
}

#: Legacy inference when no generation is registered (NULL): 8-byte chip_id
#: ⇒ Turin, 64-byte ⇒ Genoa.
_CHIP_ID_BYTES_TO_VCPU: dict[int, str] = {8: "EpycTurin", 64: "EpycGenoa"}


def _vcpu_type_for_platform(
    platform_id: str, snp_generation: str | None = None
) -> str:
    """Map a miner to the SNP vCPU model its guests are measured with.

    `snp_generation` is the operator-registered `MinerIdentity.snp_generation`.
    NULL / empty ⇒ infer from the CHIP_ID length (8-byte ⇒ `EpycTurin`,
    64-byte ⇒ `EpycGenoa`). An explicit generation selects the model
    (`milan` ⇒ `EpycMilan`) but must agree with the CHIP_ID length. An
    inconsistent pair, an unknown generation, a non-hex id, an unknown
    length or an auto-provision placeholder (`onchain:<node_id>` — no chip
    registered yet) all fail closed (`EffectError`)."""
    from apps.miners.models import is_autoprovision_placeholder

    if is_autoprovision_placeholder(platform_id):
        raise EffectError(
            "platform-id-autoprovision-placeholder: the miner has no registered "
            "CHIP_ID yet (POST /v1/admin/miner/register)"
        )
    try:
        n = len(bytes.fromhex(platform_id))
    except ValueError as exc:
        raise EffectError("platform-id-not-hex") from exc
    if snp_generation:
        known = SNP_GENERATION_VCPU.get(snp_generation)
        if known is None:
            raise EffectError(
                f"snp-generation-unknown: {snp_generation!r} "
                f"(want one of {sorted(SNP_GENERATION_VCPU)})"
            )
        vcpu_type, want_bytes = known
        if n != want_bytes:
            raise EffectError(
                f"snp-generation-chip-id-mismatch: generation "
                f"{snp_generation!r} has a {want_bytes}-byte CHIP_ID, the "
                f"registered platform_id is {n} bytes"
            )
        return vcpu_type
    vcpu_type = _CHIP_ID_BYTES_TO_VCPU.get(n)
    if vcpu_type is None:
        raise EffectError(
            f"platform-id-length-unknown: {n} bytes (want 8=Turin or 64=Genoa)"
        )
    return vcpu_type


def recompute_expected_digest(
    *,
    s3_bucket: str,
    s3_key_prefix: str,
    kernel_sha256_hex: str,
    initrd_sha256_hex: str,
    cmdline: str,
    cpu_count: int,
    platform_id: str,
    snp_generation: str | None = None,
) -> str:
    """Return the 96-hex SNP launch digest a HONEST guest must produce for
    THIS launch. `snp_generation` is the host miner's registered generation
    (NULL ⇒ inferred from the CHIP_ID length). Raises
    `LaunchDigestUnavailable` if the recompute is not configured;
    `EffectError` on a fetch/SHA/computation failure."""
    if not is_enabled():
        raise LaunchDigestUnavailable("launch-digest recompute not configured")

    prefix = s3_key_prefix.rstrip("/")
    vcpu_type = _vcpu_type_for_platform(platform_id, snp_generation)
    guest_features = str(getattr(settings, "VALI_SNP_GUEST_FEATURES", "0x1"))
    ovmf_sha = str(settings.VALI_SNP_OVMF_SHA256)
    ovmf_uri = str(settings.VALI_SNP_OVMF_S3_URI)
    bin_path = str(settings.VALI_LAUNCH_DIGEST_BIN)

    with tempfile.TemporaryDirectory(prefix="c2-digest-") as td:
        tdp = Path(td)
        ovmf, kernel, initrd, cmd = (
            tdp / "ovmf.fd",
            tdp / "kernel",
            tdp / "initrd",
            tdp / "cmdline",
        )
        # Fetch + SHA-verify EXACTLY the bytes the guest boots. A miner
        # that swapped an artifact would fail its own SHA (bake-bound), so
        # the pinned SHAs are the trust anchor for the recompute inputs.
        deadline = time.monotonic() + _FETCH_BUDGET_S
        _fetch_verify(ovmf_uri, ovmf, ovmf_sha, "ovmf", deadline)
        _fetch_verify(
            f"s3://{s3_bucket}/{prefix}/tenant.vmlinuz",
            kernel,
            kernel_sha256_hex,
            "kernel",
            deadline,
        )
        _fetch_verify(
            f"s3://{s3_bucket}/{prefix}/tenant.initrd.img",
            initrd,
            initrd_sha256_hex,
            "initrd",
            deadline,
        )
        cmd.write_text(cmdline)

        argv = [
            bin_path,
            "--ovmf", str(ovmf),
            "--kernel", str(kernel),
            "--initrd", str(initrd),
            "--cmdline", str(cmd),
            "--vcpus", str(int(cpu_count)),
            "--vcpu-type", vcpu_type,
            "--guest-features", guest_features,
        ]
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, no shell
                argv,
                capture_output=True,
                timeout=_DIGEST_TIMEOUT_S,
                check=False,
                env=os.environ.copy(),
            )
        except FileNotFoundError as exc:
            raise EffectUnavailable("launch-digest: binary not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise EffectError("launch-digest: timeout") from exc
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", errors="replace").strip()
            raise EffectError(f"launch-digest: exit={proc.returncode} stderr={tail!r}")
        digest = proc.stdout.decode("utf-8", errors="replace").strip().lower()
        if not _DIGEST_RE.fullmatch(digest):
            raise EffectError(f"launch-digest: output not 96-hex: {digest!r}")
        return digest
