"""`vali_create_vm` — end-to-end automation for one BYO base-OS launch.

Folds every operator step that `vali_dispatch_launch` does NOT do —
KEK generation, Vault staging of LUKS KEK + cloud-init userdata,
`allowed_userdata_digest_hex` computation, miner-side artefact fetch
+ sha verify + SNP launch_digest compute via the `tenant-preflight`
order, §22 allowlist auto-pin via kbs-admin /v1/admin/allowlist/reload,
L1 OrderTicket mint — into one CLI invocation, then chains into the
existing `kbs_admin.register_vm_active_with_vm_id` +
`order_dispatch.dispatch_order` launch path.

The ONLY thing this command does differently from the API launch is
CHOOSE THE MINER: it names one instead of running the scheduler. It is
otherwise the same path and leaves the same durable ledger — a
`lifecycle.Vm` row and an active `scheduler.Placement` (P9/#18). It used
to leave neither, which produced a real, attested, RUNNING CVM that the
control plane did not know about: §24 could never crypto-erase it (its
Vault-Transit KEK stayed live forever), and the #668 fit gate did not
count the RAM/CPU it consumed, so the miner was silently oversubscribed.

OPERATOR CLI. Production launches go through the `POST /v1/vm/launch`
API; this command is the operator/dev convenience wrapper. The §22
allowlist auto-pin signs with the PRODUCTION root seed from Vault (see
`apps.orchestration.services.allowlist_pin._resolve_seed_hex`) — no
committed dev seed. Set `VALI_ALLOW_PROD=true` to disable this CLI on a
cluster where launches must go through the API only.

Operator pre-requisites (validated, fails loud if missing):
- Artifacts (`tenant-<sha>.qcow2`, `.vmlinuz`, `.initrd.img`) uploaded
  to S3 at `s3://<bucket>/<prefix>/tenant.{qcow2,vmlinuz,initrd.img}`
  (the keys MUST match exactly — vali generates the presigned URLs
  against those paths).
- `MinerIdentity.netbird_ip` registered for `--miner-id`.
- The L1 + allowlist seeds mounted via the operator's secret-store at
  `VALI_L1_SIGNING_KEY_PATH` + `VALI_KBS_ALLOWLIST_ROOT_SEED_PATH`.
- VAULT_TOKEN + AWS_* env in the process at invocation time.
- `--measurement-hex` is OPTIONAL — when omitted, the preflight order
  computes it on the miner and pins it in the response. Operators
  should only pre-pin when iterating on the launch path without a
  matching artefact upload (e.g. for debugging).

Output: single JSON object on stdout describing the dispatch outcome
plus the vault versions, ticket id, measurement_hex source
(`preflight-auto` vs `operator-pinned`), and the staged paths.
Exit codes mirror `vali_dispatch_launch` (+ 9 = preflight failure).

Example:
    python manage.py vali_create_vm \\
        --tenant-id t-smoke --vm-id myvm-1 \\
        --user-id u-smoke --lease-id lease-smoke \\
        --miner-id miner-1 \\
        --platform-id <AMD_CHIP_ID_HEX> \\
        --userdata-file ./cloud-init.yaml \\
        --s3-bucket hippius-compute-images \\
        --s3-key-prefix tenant/myvm-1/ \\
        --luks-disk-sha256-hex <64 hex from bake measurement.json> \\
        --kernel-sha256-hex    <64 hex from bake measurement.json> \\
        --initrd-sha256-hex    <64 hex from bake measurement.json> \\
        --cmdline 'console=ttyS0,115200 ... ds=nocloud;s=/run/cloud-init/seed/ ...' \\
        --cpu-count 1 --memory-mb 2048 \\
        --auto-pin-allowlist
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.miners.models import MinerIdentity
from apps.orchestration.services import flavors, launch

# 48-byte SNP launch digest — 96 hex chars.
_MEASUREMENT_RE = re.compile(r"^[0-9a-f]{96}$")
# 32-byte CHIP_ID — 64 hex chars + 64 hex chars for FMS = 128 total.
_PLATFORM_ID_RE = re.compile(r"^[0-9a-f]{64,160}$")
# 32-byte sha256 — 64 hex chars.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class Command(BaseCommand):
    help = (
        "DEV ONLY — provision one VM end-to-end: stage Vault secrets, "
        "(optionally) pin the §22 allowlist, mint the OrderTicket, "
        "register with KBS, dispatch the launch order to the miner. "
        "Refuses to run when VALI_ALLOW_PROD=true."
    )

    def add_arguments(self, parser: Any) -> None:
        # ── Identity ─────────────────────────────────────────────────
        parser.add_argument("--tenant-id", required=True)
        parser.add_argument("--user-id", required=True)
        parser.add_argument("--vm-id", required=True)
        parser.add_argument("--lease-id", required=True)
        parser.add_argument(
            "--ticket-id",
            default="",
            help="Defaults to `tk-<vm-id>-<rand8>`",
        )
        parser.add_argument(
            "--order-id",
            default="",
            help="Defaults to `ord-<vm-id>-<rand8>`",
        )
        parser.add_argument(
            "--vm-generation",
            type=int,
            default=1,
            help="Defaults to 1 — every fresh-tenant launch is gen 1.",
        )
        parser.add_argument(
            "--decided-by",
            default="",
            help=(
                "Name of an EXISTING `ServiceClient` to credit the forced "
                "`Placement` to (the §15 audit field). Defaults to the "
                "well-known `operator-cli` principal, auto-created on "
                "first use with `is_active=False` so it can never "
                "authenticate — it exists only to own the placement row. "
                "An unknown name is refused, never created (P9/#18)."
            ),
        )

        # ── Placement ────────────────────────────────────────────────
        parser.add_argument("--miner-id", required=True)
        parser.add_argument(
            "--platform-id",
            required=True,
            help="AMD CHIP_ID / VCEK identity hex; pins this ticket to the miner's SNP HW",
        )
        # #312 — `resource_class` retired in OrderTicket v2; the
        # canonical Flavor name takes its place. Operators that need
        # an audit-only string can stash it in the userdata bytes
        # (where it does not affect ticket signing).

        # ── Cloud-init + KEK ─────────────────────────────────────────
        parser.add_argument(
            "--userdata-file",
            required=True,
            help="Path to the cloud-init NoCloud user-data plaintext YAML",
        )
        parser.add_argument(
            "--kek-file",
            default="",
            help=(
                "Path to a 32-byte raw LUKS KEK. REQUIRED for the BYO "
                "base-OS flow — the bake's luksFormat binds the rootfs "
                "keyslot to this KEK, and vali stashes the same bytes in "
                "Vault so KBS releases the matching value at boot. "
                "Mutually exclusive with --allow-random-kek (#304)."
            ),
        )
        parser.add_argument(
            "--allow-random-kek",
            action="store_true",
            help=(
                "Generate a fresh random 32-byte KEK via "
                "`secrets.token_bytes(32)` instead of reading from a "
                "file. ONLY valid for the legacy bake-as-you-go flow "
                "where vali also drives the luksFormat against the same "
                "in-memory KEK. For BYO base-OS bakes (operator-side "
                "`tenant-image-bake.sh`), this WILL produce a KEK that "
                "does not match the keyslot — cryptsetup at boot fails "
                "with `Digest 0 (pbkdf2) verify failed -1` and the "
                "guest loops in initramfs (#304)."
            ),
        )

        # ── NetBird mesh enrolment (#306) ─────────────────────────────
        parser.add_argument(
            "--enable-netbird",
            action=argparse.BooleanOptionalAction,
            default=True,
            help=(
                "Mint a one-off NetBird setup-key via the NetBird mgmt "
                "API (VALI_NETBIRD_API_BASE + VALI_NETBIRD_API_TOKEN) "
                "and substitute it for the literal "
                "`{{NETBIRD_SETUP_KEY}}` placeholder in --userdata-file "
                "before stashing in Vault. The minted key is "
                "single-use, ephemeral, expires in --netbird-key-ttl "
                "seconds, and auto-joins --netbird-group on first boot. "
                "Userdata template example: "
                "`docs/operator/userdata-templates/netbird-enabled.yaml"
                ".example`. ON BY DEFAULT — pass --no-enable-netbird to "
                "skip the NetBird API call and pass userdata through verbatim."
            ),
        )
        parser.add_argument(
            "--netbird-group",
            default="vms",
            help=(
                "NetBird auto-group the freshly-enrolled tenant peer "
                "joins on first boot. ACL rules on this group control "
                "which infra the tenant can reach (default isolation: "
                "no rules → tenant can only talk to its own peers). "
                "Default: 'hippius-tenants'. Used only with "
                "--enable-netbird."
            ),
        )
        parser.add_argument(
            "--netbird-key-ttl-seconds",
            type=int,
            default=3600,
            help=(
                "Lifetime of the minted NetBird setup-key in seconds. "
                "Short by design — the key only needs to live long "
                "enough for cloud-init's `runcmd` to feed it to "
                "`netbird up` once at first boot. Default: 3600 "
                "(1 hour). Used only with --enable-netbird."
            ),
        )
        parser.add_argument(
            "--netbird-hostname-template",
            default="hippius-tenant-{vm_id}",
            help=(
                "Python format-string the userdata's "
                "`{{NETBIRD_HOSTNAME}}` placeholder expands to. The "
                "only legal substitution token is `{vm_id}` — vali "
                "format-applies it to the launch's vm_id. Default: "
                "'hippius-tenant-{vm_id}'. Used only with "
                "--enable-netbird (#309). Stable per-vm-id FQDNs "
                "(`<template>.hippius.decentralized`) let operators "
                "ssh to a specific tenant by name without an IP "
                "lookup."
            ),
        )

        # ── Measurement (preflight auto-computes; operator may pin) ──
        parser.add_argument(
            "--measurement-hex",
            default="",
            help=(
                "48-byte (96 hex) SNP launch digest. OPTIONAL — if "
                "omitted, vali dispatches a `tenant-preflight` order "
                "first (the miner fetches via the S3 presigned URLs "
                "below, verifies SHAs, computes the digest, returns it). "
                "Pre-pin only if you've computed it out-of-band via "
                "`hippius-miner-agent launch-test --digest-only`."
            ),
        )
        parser.add_argument(
            "--auto-pin-allowlist",
            action="store_true",
            help=(
                "Sign + upload a new §22 allowlist that includes the "
                "launch_digest (with the prod root seed from Vault), then "
                "call kbs-admin /v1/admin/allowlist/reload."
            ),
        )

        # ── Artifact location (S3) ───────────────────────────────────
        parser.add_argument(
            "--s3-bucket",
            required=True,
            help=(
                "S3 bucket holding the operator's baked artifacts. "
                "Vali generates short-TTL presigned URLs for each of "
                "<bucket>/<prefix>/tenant.{qcow2,vmlinuz,initrd.img} "
                "and the miner downloads + sha-verifies them via the "
                "`tenant-preflight` order."
            ),
        )
        parser.add_argument(
            "--s3-key-prefix",
            required=True,
            help=(
                "S3 key prefix under --s3-bucket — typically "
                "`tenant/<image-name>/`. The qcow2 / vmlinuz / initrd "
                "objects MUST already exist at "
                "<prefix>/tenant.{qcow2,vmlinuz,initrd.img}."
            ),
        )
        parser.add_argument(
            "--luks-disk-sha256-hex",
            required=True,
            help="64-hex sha256 of the qcow2 bytes (from bake measurement.json).",
        )
        parser.add_argument(
            "--kernel-sha256-hex",
            required=True,
            help="64-hex sha256 of the vmlinuz bytes (from bake measurement.json).",
        )
        parser.add_argument(
            "--initrd-sha256-hex",
            required=True,
            help="64-hex sha256 of the initrd.img bytes (from bake measurement.json).",
        )
        parser.add_argument(
            "--luks-header-sha256-hex",
            required=True,
            help=(
                "64-hex sha256 of the LUKS2 header (from bake "
                "measurement.json `luks_header_sha256`). #296 — bound "
                "into the kernel cmdline as `hippius.luks_header_sha256=` "
                "so the launch_digest covers it, and the guest "
                "keyscript re-verifies before any KBS work using the "
                "detached-header pattern (Trail of Bits / "
                "CVE-2025-59054). REQUIRED — there is no safe default."
            ),
        )
        parser.add_argument(
            "--rootfs-sha256-hex",
            required=False,
            default="",
            help=(
                "64-hex sha256 of the rootfs artifact the per-tenant "
                "qcow2 was built from (Stage 1's `rootfs.tar.zst` for "
                "the split pipeline; the qcow2's plaintext root for "
                "the legacy bake). When set, bound into the kernel "
                "cmdline as `hippius.rootfs_sha256=` so the SEV-SNP "
                "launch_digest covers it — a miner can't substitute a "
                "different rootfs because the resulting launch_digest "
                "won't be in the §22 allowlist (audit follow-up "
                "Gemini #1 / Codex #1). Optional today for backward "
                "compatibility with the legacy bake; production "
                "operators should set this from the Stage 2 "
                "measurement.json's `rootfs_tar_zst_sha256`."
            ),
        )
        parser.add_argument(
            "--ovmf-path",
            default="/var/lib/hippius-miner/ovmf.fd",
        )
        parser.add_argument(
            "--rootfs-data-path",
            default="/var/lib/hippius-miner/rootfs.img",
        )
        parser.add_argument(
            "--rootfs-hash-path",
            default="/var/lib/hippius-miner/rootfs.verity",
        )

        # ── Launch knobs ─────────────────────────────────────────────
        # Two ways to size the guest:
        #   - --flavor small|medium|large : single canonical name, vali
        #     derives (vcpus, memory_mb, disk_gb) from
        #     `hippius_types::flavor::Flavor`. The flavor string ALSO
        #     becomes the ticket's `resource_class` field (see #312).
        #   - --cpu-count + --memory-mb (+ --luks-disk-size-gb) : raw
        #     scalars. Pre-flavor invocation shape; still supported for
        #     backward-compat with operator scripts that pinned these
        #     by hand.
        # Mutually exclusive — `_validate_inputs` rejects both at once.
        parser.add_argument(
            "--flavor",
            required=True,
            choices=list(flavors.FLAVOR_NAMES),
            help=(
                "Tenant VM size catalogue identifier (#312). REQUIRED "
                "as of OrderTicket v2 (#312 follow-up); the canonical "
                "flavor name is the signed-immutable carrier of "
                "(vcpus, memory_mb, disk_gb) in the ticket. Catalogue: "
                "small=1c/2GB/8GB, medium=2c/4GB/16GB, large=4c/8GB/32GB, "
                "xlarge=8c/16GB/64GB, 2xlarge=16c/32GB/128GB, "
                "4xlarge=32c/64GB/256GB."
            ),
        )
        parser.add_argument("--luks-disk-size-gb", type=int, default=10)
        parser.add_argument(
            "--cmdline",
            required=True,
            help=(
                "Kernel cmdline — MUST be the byte-exact string the "
                "operator passed to --digest-only when computing "
                "--measurement-hex. For BYO base-OS this typically "
                "includes `cryptopts=...,keyfile-size=32,keyscript=...` "
                "and `ds=nocloud;s=/run/cloud-init/seed/`."
            ),
        )

        # ── Mint knobs ───────────────────────────────────────────────
        parser.add_argument(
            "--kid",
            default="l1-order-ticket-v1",
            help="L1 signing kid embedded in the COSE protected header",
        )
        parser.add_argument(
            "--expiry-seconds",
            type=int,
            default=86400,
            help="OrderTicket validity window. Default: 24 h",
        )

    # ── handle() ─────────────────────────────────────────────────────

    def handle(self, *args: Any, **opts: Any) -> None:
        # Hard dev-mode gate — refuse even if --auto-pin-allowlist is
        # absent, because the OTHER side effects (Vault writes, ticket
        # mint with the dev L1 seed) also leak operator-tier authority.
        if bool(getattr(settings, "VALI_ALLOW_PROD", False)):
            raise CommandError(
                "vali_create_vm refuses to run with VALI_ALLOW_PROD=true. "
                "This command is the DEV-mode operator-tier wrapper; "
                "use the production §22 ceremony + tenant-secrets-stage.sh "
                "+ order-ticket-mint chain instead."
            )

        self._validate_inputs(opts)

        # Resolve --flavor early via the shared catalogue (#312) so a bad
        # name fails here with a clear message; the launch service
        # re-resolves the same name for the choreography.
        try:
            flavors.resolve_flavor(opts["flavor"])
        except flavors.UnknownFlavor as exc:
            raise CommandError(str(exc)) from exc

        # Read the cloud-init userdata plaintext + validate the NetBird
        # template BEFORE any DB / miner I/O — pure input checks fail with
        # a clean CommandError. The userdata is secret-bearing; we drop
        # our copy in the `finally` below.
        try:
            with open(opts["userdata_file"], "rb") as fh:
                userdata = fh.read()
        except OSError as exc:
            raise CommandError(
                f"cannot read --userdata-file {opts['userdata_file']!r}: {exc}"
            ) from exc
        if not userdata:
            raise CommandError("--userdata-file is empty — refusing to stage")

        # Pre-flight the NetBird template so the operator gets a clean
        # CommandError; the launch service applies the SAME rule
        # (`launch.check_netbird_userdata`) for non-CLI callers.
        nb_err = launch.check_netbird_userdata(
            userdata,
            enable=opts["enable_netbird"],
            hostname_template=opts["netbird_hostname_template"],
            vm_id=opts["vm_id"],
        )
        if nb_err is not None:
            raise CommandError(nb_err)

        # P9/#18 — resolve the audit principal the forced `Placement` is
        # attributed to alongside the other argument checks, so a bad
        # `--decided-by` fails as a clean input error with nothing staged.
        try:
            decided_by = launch.resolve_forced_launch_principal(
                opts["decided_by"]
            )
        except launch.LaunchConfigError as exc:
            raise CommandError(str(exc)) from exc

        miner_id = opts["miner_id"]
        try:
            identity = MinerIdentity.objects.get(pk=miner_id)
        except MinerIdentity.DoesNotExist as exc:
            raise CommandError(f"no MinerIdentity for {miner_id!r}") from exc
        if not identity.netbird_ip:
            raise CommandError(
                f"miner {miner_id!r} has no netbird_ip — register via PR #120 first"
            )

        kek_bytes = self._read_or_generate_kek(opts["kek_file"])

        # Build the launch intent + run the choreography for THIS miner
        # (forced — the CLI names the miner; no scheduler / Placement).
        # This is the exact sequence `handle` used to run inline, now in
        # `apps.orchestration.services.launch.launch_on_miner`.
        spec = launch.LaunchSpec(
            tenant_id=opts["tenant_id"],
            user_id=opts["user_id"],
            vm_id=opts["vm_id"],
            lease_id=opts["lease_id"],
            s3_bucket=opts["s3_bucket"],
            s3_key_prefix=opts["s3_key_prefix"],
            luks_disk_sha256_hex=opts["luks_disk_sha256_hex"],
            kernel_sha256_hex=opts["kernel_sha256_hex"],
            initrd_sha256_hex=opts["initrd_sha256_hex"],
            luks_header_sha256_hex=opts["luks_header_sha256_hex"],
            flavor=opts["flavor"],
            cmdline=opts["cmdline"],
            kek_bytes=kek_bytes,
            userdata=userdata,
            platform_id=opts["platform_id"],
            ticket_id=opts["ticket_id"],
            order_id=opts["order_id"],
            rootfs_sha256_hex=opts["rootfs_sha256_hex"],
            measurement_hex=opts["measurement_hex"],
            auto_pin_allowlist=opts["auto_pin_allowlist"],
            enable_netbird=opts["enable_netbird"],
            netbird_group=opts["netbird_group"],
            netbird_key_ttl_seconds=int(opts["netbird_key_ttl_seconds"]),
            netbird_hostname_template=opts["netbird_hostname_template"],
            ovmf_path=opts["ovmf_path"],
            rootfs_data_path=opts["rootfs_data_path"],
            rootfs_hash_path=opts["rootfs_hash_path"],
            kid=opts["kid"],
            expiry_seconds=opts["expiry_seconds"],
        )
        try:
            # P9/#18 — `launch_on_named_miner`, NOT `launch_on_miner`. The
            # operator picks the miner (that is the point of this command),
            # but the DURABLE LEDGER is not part of that choice: the VM
            # still gets its `lifecycle.Vm` row (so §24 crypto-erase, the
            # guest-liveness sweep, reboot-recovery and §25 can all see it)
            # and an active `Placement` (so the #668 fit gate counts the
            # RAM/CPU it really consumes on that miner).
            outcome = launch.launch_on_named_miner(
                spec, identity, decided_by=decided_by
            )
        except launch.ActivePlacementConflict as exc:
            self._emit(
                {"ok": False, "outcome": "placement-conflict", "error": str(exc)}
            )
            sys.exit(launch.EXIT_CONFIG_ERROR)
        except launch.LaunchConfigError as exc:
            self._emit(
                {"ok": False, "outcome": "config-error", "error": str(exc)}
            )
            sys.exit(launch.EXIT_CONFIG_ERROR)
        finally:
            # §20 — drop our secret buffers regardless of outcome.
            try:
                kek_bytes = b"\x00" * len(kek_bytes)
            except Exception:
                pass
            try:
                userdata = b"\x00" * len(userdata)
            except Exception:
                pass

        self._emit(outcome.emit)
        sys.exit(outcome.exit_code)

    # ── helpers ─────────────────────────────────────────────────────

    def _validate_inputs(self, opts: dict[str, Any]) -> None:
        # --measurement-hex is OPTIONAL — when present, must be the
        # canonical 96-hex shape; when absent, the preflight order
        # will compute + return it from the miner.
        if opts["measurement_hex"] and not _MEASUREMENT_RE.fullmatch(
            opts["measurement_hex"]
        ):
            raise CommandError(
                "--measurement-hex must be exactly 96 lower-case hex chars (48 bytes)"
            )
        if not _PLATFORM_ID_RE.fullmatch(opts["platform_id"]):
            raise CommandError(
                "--platform-id must be lower-case hex (CHIP_ID / VCEK identity)"
            )
        for flag in (
            "luks_disk_sha256_hex",
            "kernel_sha256_hex",
            "initrd_sha256_hex",
            # #296 — REQUIRED per the LUKS2 header MAC fix. Without
            # this the keyscript fails closed at boot.
            "luks_header_sha256_hex",
        ):
            if not _SHA256_RE.fullmatch(opts[flag]):
                raise CommandError(
                    f"--{flag.replace('_', '-')} must be exactly 64 lower-case hex chars"
                )
        # Audit follow-up Gemini #1 / Codex #1: optional today, so
        # gate the regex only when the operator opts in. An empty
        # string skips the cmdline append in step 4b; any non-empty
        # value must satisfy the canonical 64-hex shape.
        if opts["rootfs_sha256_hex"] and not _SHA256_RE.fullmatch(
            opts["rootfs_sha256_hex"]
        ):
            raise CommandError(
                "--rootfs-sha256-hex must be exactly 64 lower-case hex chars"
            )
        if not opts["s3_bucket"].strip():
            raise CommandError("--s3-bucket must be non-empty")
        if not opts["s3_key_prefix"].strip():
            raise CommandError("--s3-key-prefix must be non-empty")
        # #312 follow-up — OrderTicket v2 makes --flavor required and
        # drops the raw --cpu-count / --memory-mb knobs. The shared
        # `flavors` catalogue resolves it to (cpu, mem, data-disk, rootfs).
        if opts["flavor"] not in flavors.FLAVOR_NAMES:
            raise CommandError(
                f"--flavor must be one of: {', '.join(flavors.FLAVOR_NAMES)}"
            )
        if opts["expiry_seconds"] < 60:
            raise CommandError("--expiry-seconds must be >= 60")
        # `--auto-pin-allowlist` signs the §22 artifact with the prod root
        # seed from Vault (`allowlist_pin._resolve_seed_hex`) — no dev-pin
        # gate. The pinned measurement is the miner-preflight launch digest,
        # not an arbitrary value. (#587 Phase 1A.)
        # #304 — refuse silent random-KEK generation. The BYO base-OS
        # bake-as-of-2026-06-01 produces a LUKS keyslot bound to the
        # operator-side bake's --kek-file; a vali-side random KEK
        # decouples from the keyslot and the guest fails-closed at
        # `Digest 0 (pbkdf2) verify failed -1` after switch_root.
        # Legacy bake-as-you-go callers that DO want a random KEK
        # must now opt in explicitly.
        if opts["kek_file"] and opts["allow_random_kek"]:
            raise CommandError(
                "--kek-file and --allow-random-kek are mutually exclusive (#304)"
            )
        if not opts["kek_file"] and not opts["allow_random_kek"]:
            raise CommandError(
                "either --kek-file PATH (BYO base-OS bake) or "
                "--allow-random-kek (legacy bake-as-you-go) is required (#304)"
            )
        # The KEK file (if provided) must exist + be 32 bytes.
        if opts["kek_file"]:
            path = opts["kek_file"]
            if not os.path.isfile(path):
                raise CommandError(f"--kek-file {path!r} does not exist")
            size = os.path.getsize(path)
            if size != 32:
                raise CommandError(
                    f"--kek-file must be exactly 32 bytes (got {size})"
                )

    def _read_or_generate_kek(self, kek_file: str) -> bytes:
        if not kek_file:
            # _validate_inputs gates this on --allow-random-kek (#304).
            return secrets.token_bytes(32)
        with open(kek_file, "rb") as fh:
            buf = fh.read()
        # _validate_inputs already gated on size; defense-in-depth.
        if len(buf) != 32:
            raise CommandError("--kek-file is not 32 bytes")
        return buf

    def _emit(self, payload: dict[str, Any]) -> None:
        self.stdout.write(json.dumps(payload))
