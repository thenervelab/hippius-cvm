"""Subprocess wrapper for `hippius-order-ticket-mint`.

The Rust binary lives outside vali (see `binaries/order-ticket-mint/`);
keeping the COSE_Sign1 signing in Rust means we don't import a heavy
crypto stack into the Django pod. Vali shells out with the L1 seed
file path, captures the raw bytes on `--out FILE`, and hands the bytes
to the existing kbs-admin register + Edge dispatch path.

§20 discipline:
- PRODUCTION: the L1 signing seed lives in Vault (the trusted control
  plane holds it online, mirroring the §22 allowlist-root seed). vali
  fetches the `seed` hex field, validates it (64 lower-case hex), and
  materializes it into a 0600 file inside `/dev/shm` ONLY for the
  duration of the subprocess — then unlinks it. The seed is never
  logged. TEST/dev affordance: a `VALI_L1_SIGNING_KEY_PATH` file the
  Rust binary opens directly (vali never reads its bytes).
- The tmpfs `--out` file is created in `/dev/shm` (preferred) or
  `/tmp` (fallback) and deleted on every exit path.
- Stderr classifiers from the binary are surfaced verbatim (operator
  diagnostics — the binary's §20 discipline already constrains them
  to `&'static str` tags).
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass

from django.conf import settings

from apps.orchestration.effects import EffectError, EffectUnavailable

DEFAULT_TIMEOUT_S = 30.0


@dataclass(frozen=True)
class MintArgs:
    """Inputs to one ticket mint. Mirrors the `hippius-order-ticket-mint`
    CLI surface. Strings here are passed through to argv verbatim — the
    Rust binary owns the canonical CBOR encoding + COSE signing.
    """

    kid: str
    ticket_id: str
    tenant_id: str
    user_id: str
    vm_id: str
    lease_id: str
    node_id: str
    platform_id: str
    allowed_measurement_hex: str
    userdata_vault_path: str
    userdata_vault_version: int
    luks_vault_path: str
    luks_vault_version: int
    allowed_userdata_digest_hex: str
    # #312 — `flavor` replaces v1's `resource_class: String` in the
    # OrderTicket. Canonical kebab-case identifier
    # ("small" / "medium" / "large") — the L1 mint binary's
    # `--flavor` flag parses via `Flavor::from_str`.
    flavor: str
    # §25 — the generation the ticket binds to. The KBS `check_releasable`
    # releases the KEK ONLY to a ticket whose `vm_generation` matches the
    # KBS-recorded generation, so a §25 migration MUST re-mint the dest
    # ticket at `new_gen` (the source ticket binds `source_gen` and the
    # KBS denies it after the fence). A fresh launch mints at gen 1
    # (the binary's own default), so the field defaults to 1 here too.
    vm_generation: int = 1
    lifecycle_perm: Sequence[str] = ("launch",)
    expiry_seconds: int = 86400


def _bin_path() -> str:
    path = str(
        getattr(settings, "VALI_ORDER_TICKET_MINT_BIN", "") or ""
    ).strip()
    if not path:
        raise EffectUnavailable("VALI_ORDER_TICKET_MINT_BIN is not configured")
    if not os.path.isabs(path) or not os.access(path, os.X_OK):
        raise EffectUnavailable(
            "VALI_ORDER_TICKET_MINT_BIN must be an absolute path to an "
            "executable file"
        )
    return path


def _resolve_l1_seed() -> str | None:
    """Resolve the L1 OrderTicket signing seed.

    PRODUCTION: `VALI_L1_SIGNING_KEY_VAULT_PATH` → fetch the `seed` field
    from Vault (vali holds the L1 signing seed online — the trusted
    control-plane signing authority, mirroring the §22 allowlist-root
    seed) and return it as a validated 64-hex string. The caller
    materializes it into a 0600 tmpfs file for the `--signing-key` arg
    and drops it promptly; the seed is never logged.

    TEST/dev affordance: `VALI_L1_SIGNING_KEY_PATH` → a file the Rust
    binary opens itself. Returns `None` in that case (the caller passes
    the file path straight through; vali never reads its bytes).

    Neither set ⇒ fail closed.

    §20: a returned string is secret-bearing — never log it; the caller
    materializes it 0600 and unlinks it on every exit path.
    """
    vault_path = str(
        getattr(settings, "VALI_L1_SIGNING_KEY_VAULT_PATH", "") or ""
    ).strip()
    if vault_path:
        # Local import to avoid a module-load cycle (vault_kv imports settings).
        from apps.orchestration.services.vault_kv import get_kv_field

        mount = getattr(settings, "VALI_VAULT_KV_MOUNT", "secret")
        seed_hex = get_kv_field(mount, vault_path, "seed").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", seed_hex):
            raise EffectError(
                "L1 signing Vault seed is not 64 lower-case hex chars"
            )
        return seed_hex
    seed_file = str(
        getattr(settings, "VALI_L1_SIGNING_KEY_PATH", "") or ""
    ).strip()
    if seed_file:
        if not os.path.isfile(seed_file):
            raise EffectUnavailable("VALI_L1_SIGNING_KEY_PATH does not exist")
        return None
    raise EffectUnavailable(
        "no L1 signing seed configured "
        "(set VALI_L1_SIGNING_KEY_VAULT_PATH)"
    )


def mint(args: MintArgs) -> bytes:
    """Subprocess `hippius-order-ticket-mint --out FILE` and return the
    raw COSE_Sign1 bytes.

    Fails closed: `EffectUnavailable` for misconfig / unreachable, and
    `EffectError` for any non-zero exit / write failure. The caller
    surfaces the static classifier the binary printed on stderr.
    """
    bin_path = _bin_path()
    # PRODUCTION: a 64-hex seed fetched from Vault (materialized 0600
    # below). TEST/dev: `None` ⇒ pass the configured file path through.
    seed_hex = _resolve_l1_seed()

    # tmpfs preferred; falls back to the system tempdir.
    out_dir = "/dev/shm" if os.path.isdir("/dev/shm") else None

    with tempfile.NamedTemporaryFile(
        prefix="hippius-ticket-",
        suffix=".cose",
        dir=out_dir,
        delete=False,
    ) as f:
        out_path = f.name

    # PRODUCTION: materialize the Vault seed into a 0600 file inside the
    # (tmpfs) `/dev/shm` for the `--signing-key` arg; removed on every
    # exit path (§20). TEST/dev: pass the configured file path through.
    seed_path: str
    seed_tmp_path: str | None = None
    if seed_hex is not None:
        # `mkstemp` atomically creates the file 0600 (O_EXCL) and hands
        # back an open fd — no symlink race. Mirrors the §22 allowlist
        # seed materialization (allowlist_pin); removed in the `finally`.
        seed_fd, seed_tmp_path = tempfile.mkstemp(
            prefix="hippius-l1-seed-", suffix=".hex", dir=out_dir
        )
        with os.fdopen(seed_fd, "w", encoding="utf-8") as sfh:
            sfh.write(seed_hex)
        seed_path = seed_tmp_path
    else:
        seed_path = str(getattr(settings, "VALI_L1_SIGNING_KEY_PATH", "")).strip()

    argv = [
        bin_path,
        "--signing-key",
        seed_path,
        "--kid",
        args.kid,
        "--ticket-id",
        args.ticket_id,
        "--tenant-id",
        args.tenant_id,
        "--user-id",
        args.user_id,
        "--vm-id",
        args.vm_id,
        "--lease-id",
        args.lease_id,
        "--vm-generation",
        str(args.vm_generation),
        "--node-id",
        args.node_id,
        "--platform-id",
        args.platform_id,
        "--allowed-measurement-hex",
        args.allowed_measurement_hex,
        "--userdata-vault-path",
        args.userdata_vault_path,
        "--userdata-vault-version",
        str(args.userdata_vault_version),
        "--luks-vault-path",
        args.luks_vault_path,
        "--luks-vault-version",
        str(args.luks_vault_version),
        "--allowed-userdata-digest-hex",
        args.allowed_userdata_digest_hex,
        "--flavor",
        args.flavor,
        "--expiry-seconds",
        str(args.expiry_seconds),
        "--out",
        out_path,
    ]
    for perm in args.lifecycle_perm:
        argv.extend(["--lifecycle-perm", perm])

    try:
        proc = subprocess.run(  # noqa: S603 — argv list, no shell
            argv,
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_S,
            check=False,
        )
        if proc.returncode != 0:
            stderr_tail = proc.stderr.decode("utf-8", errors="replace").strip()
            raise EffectError(
                f"order-ticket-mint: exit={proc.returncode} stderr={stderr_tail!r}"
            )
        with open(out_path, "rb") as fh:
            blob = fh.read()
        if not blob:
            raise EffectError("order-ticket-mint: empty output file")
        return blob
    except subprocess.TimeoutExpired as exc:
        raise EffectError("order-ticket-mint: timeout") from exc
    except FileNotFoundError as exc:
        raise EffectUnavailable("order-ticket-mint: binary not found") from exc
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
        # §20: drop the materialized L1 seed file (production path only).
        if seed_tmp_path is not None:
            try:
                os.unlink(seed_tmp_path)
            except OSError:
                pass
