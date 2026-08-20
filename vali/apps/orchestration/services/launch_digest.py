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
`hippius-launch-digest` binary baked in the image.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings

from apps.orchestration.effects import EffectError, EffectUnavailable

_FETCH_TIMEOUT_S = 120.0
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


def _s3_cp(s3_uri: str, dest: Path) -> None:
    aws = _aws_bin()
    endpoint = _endpoint()
    argv = [aws]
    if endpoint:
        argv.extend(["--endpoint-url", endpoint])
    argv.extend(["s3", "cp", s3_uri, str(dest)])
    try:
        proc = subprocess.run(  # noqa: S603 — argv list, no shell
            argv,
            capture_output=True,
            timeout=_FETCH_TIMEOUT_S,
            check=False,
            env=os.environ.copy(),
        )
    except FileNotFoundError as exc:
        raise EffectUnavailable("aws-s3-cp: binary not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise EffectError("aws-s3-cp: timeout") from exc
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise EffectError(f"aws-s3-cp: exit={proc.returncode} stderr={tail!r}")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fetch_verify(s3_uri: str, dest: Path, expected_sha256_hex: str, label: str) -> None:
    _s3_cp(s3_uri, dest)
    got = _sha256_file(dest)
    if got.lower() != expected_sha256_hex.lower():
        raise EffectError(
            f"{label}-sha-mismatch: fetched {got}, pinned {expected_sha256_hex.lower()}"
        )


def _vcpu_type_for_platform(platform_id: str) -> str:
    """Map the miner CHIP_ID length to its SNP vCPU model. 8-byte chip_id
    ⇒ Turin (EpycTurin); 64-byte ⇒ Genoa (EpycGenoa) — the fleet's two
    generations. Anything else fails closed."""
    try:
        n = len(bytes.fromhex(platform_id))
    except ValueError as exc:
        raise EffectError("platform-id-not-hex") from exc
    if n == 8:
        return "EpycTurin"
    if n == 64:
        return "EpycGenoa"
    raise EffectError(
        f"platform-id-length-unknown: {n} bytes (want 8=Turin or 64=Genoa)"
    )


def recompute_expected_digest(
    *,
    s3_bucket: str,
    s3_key_prefix: str,
    kernel_sha256_hex: str,
    initrd_sha256_hex: str,
    cmdline: str,
    cpu_count: int,
    platform_id: str,
) -> str:
    """Return the 96-hex SNP launch digest a HONEST guest must produce for
    THIS launch. Raises `LaunchDigestUnavailable` if the recompute is not
    configured; `EffectError` on a fetch/SHA/computation failure."""
    if not is_enabled():
        raise LaunchDigestUnavailable("launch-digest recompute not configured")

    prefix = s3_key_prefix.rstrip("/")
    vcpu_type = _vcpu_type_for_platform(platform_id)
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
        _fetch_verify(ovmf_uri, ovmf, ovmf_sha, "ovmf")
        _fetch_verify(
            f"s3://{s3_bucket}/{prefix}/tenant.vmlinuz",
            kernel,
            kernel_sha256_hex,
            "kernel",
        )
        _fetch_verify(
            f"s3://{s3_bucket}/{prefix}/tenant.initrd.img",
            initrd,
            initrd_sha256_hex,
            "initrd",
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
