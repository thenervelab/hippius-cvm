"""`vali_dispatch_launch` — smoke-test driver for the §H phase-2
order-dispatch path.

Operator workflow:

1. Vault-write the Ed25519 priv seed at
   ``secret/hippius-compute/edge-gateway/order-signing`` so the Edge
   pod's ExternalSecret materialises ``/etc/hippius-edge/order-signing/priv.hex``;
   Helm flag ``orderSigning.enabled=true`` mounts it.
2. Confirm the Edge pod logs ``order-signing-up pubkey=…`` matching the
   value committed to ``deploy/ansible/group_vars/miner_nodes.yml`` and
   re-run the miner-tasks playbook so ``edge.order_signing_pubkey`` is
   present in ``/etc/hippius-miner/config.toml`` on the box.
3. Set ``VALI_EDGE_ORDER_URL`` to the cluster-internal Edge inner-
   listener Service URL.
4. Pick a target miner_id whose ``MinerIdentity`` row carries a
   ``netbird_ip`` (PR #120 chain-provisioning).
5. Run ``python manage.py vali_dispatch_launch --miner-id …
   --vm-id …`` to fire one Launch order.

Output: a single JSON object on stdout describing the dispatch
outcome — useful for shell pipelines + the §K end-to-end runbook.
Exit code 0 on miner-accepted (2xx), 2 on miner-rejected (4xx with
classifier), 3 on Edge transport failure / misconfiguration.

The command is read-only against vali state: it does NOT mutate
``MinerIdentity``, ``Vm``, ``LeaseAssignment``, or any other model —
this is a smoke driver, not a step in the actual orchestrator
state machine.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.miners.models import MinerIdentity
from apps.orchestration import kbs_admin, order_dispatch
from apps.orchestration.effects import EffectError, EffectUnavailable

# Exit code per outcome — picked to match the orchestrator's
# fail-closed grammar elsewhere.
EXIT_MINER_ACCEPTED = 0
EXIT_MINER_REJECTED = 2
EXIT_EDGE_FAILURE = 3
# §24 lifecycle pre-registration with KBS failed. Distinct from
# `EXIT_EDGE_FAILURE` because the operator's remediation is
# different (KBS pod / network ACL vs Edge / miner). The launch
# was NOT dispatched.
EXIT_KBS_ADMIN_FAILURE = 4


class Command(BaseCommand):
    help = (
        "Smoke-test the §H phase-2 vali → Edge → miner order-dispatch "
        "chain by firing one Launch order at a known miner."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--miner-id",
            required=True,
            help="MinerIdentity.miner_id to dispatch to (must have netbird_ip)",
        )
        parser.add_argument(
            "--vm-id",
            required=True,
            help="Tenant VmId the LaunchOrder addresses",
        )
        parser.add_argument(
            "--order-id",
            required=True,
            help="Idempotency key — same id processed twice is a no-op success",
        )
        # Defaults match the §F PR-F-tenant-uki measured paths; the
        # operator can override per smoke scenario.
        parser.add_argument(
            "--ovmf-path",
            default="/var/lib/hippius-miner/ovmf.fd",
        )
        parser.add_argument(
            "--kernel-path",
            default="/var/lib/hippius-miner/vmlinuz",
        )
        parser.add_argument(
            "--initrd-path",
            default="/var/lib/hippius-miner/initrd",
        )
        parser.add_argument(
            "--cmdline",
            default="console=hvc0 quiet",
        )
        parser.add_argument(
            "--luks-disk-path",
            default="/var/lib/hippius-miner/d.img",
        )
        parser.add_argument(
            "--luks-disk-size-gb",
            type=int,
            default=10,
        )
        # Read-only dm-verity rootfs disks the miner-agent attaches at
        # /dev/vdb (data, squashfs) + /dev/vdc (hash tree). The in-guest
        # agent-initramfs verity stage pairs them with the
        # `dm-verity.root=` cmdline token to create
        # `/dev/mapper/hippius-rootfs`. Staged on the miner by the
        # `scripts/tenant-uki-stage-miner.sh` pre-flight tool.
        parser.add_argument(
            "--rootfs-data-path",
            default="/var/lib/hippius-miner/rootfs.img",
        )
        parser.add_argument(
            "--rootfs-hash-path",
            default="/var/lib/hippius-miner/rootfs.verity",
        )
        # --cpu-count and --memory-mb are measurement-affecting:
        # both feed `snp_calc_launch_digest`, so any value that does not
        # match the deployed UKI's `snp_launch_config` will produce a
        # `launch_digest` outside the §22 allowlist → the KBS denies
        # release at attestation time, the operator only sees
        # "miner-accepted, launched" and has no breadcrumb. To force a
        # conscious choice we keep them `required=True` with no default;
        # source of truth is the UKI's measurement JSON, e.g. for the
        # current §F tenant UKI:
        #   jq '.components.snp_launch_config' \
        #     test_vectors/uki/tenant-measurement.json
        # → {"vcpus": 1, "vcpu_type": "EpycV4", "guest_features": "0x1"}
        # so the matching invocation is `--cpu-count 1`. `--memory-mb`
        # is NOT folded into the launch digest today (the SNP launch
        # digest covers CPU policy + measured pages, not the VMM's
        # advertised RAM size), but the value still shapes the guest
        # boot env + the miner's resource accounting; defaulting it
        # silently to 2048 has misled smoke runs in the past, so we
        # also require it explicitly here.
        parser.add_argument(
            "--cpu-count",
            type=int,
            required=True,
            help=(
                "vCPU count for the launched guest. MUST equal the "
                "`snp_launch_config.vcpus` of the UKI the miner is "
                "staged with (see `test_vectors/uki/tenant-measurement"
                ".json` for the deployed tenant UKI); a mismatch shifts "
                "the SNP launch_digest outside the §22 allowlist and "
                "the KBS denies release silently."
            ),
        )
        parser.add_argument(
            "--memory-mb",
            type=int,
            required=True,
            help=(
                "Guest RAM size in MiB. Does not feed the SNP launch "
                "digest today, but still required so the operator "
                "picks a value consciously (the prior silent default "
                "of 2048 misled smoke runs)."
            ),
        )
        parser.add_argument(
            "--cose-ticket-path",
            required=True,
            help=(
                "Path to the raw COSE_Sign1 OrderTicket bytes (the "
                "same bytes ``apps.orders.models.OrderTicket.cose_blob`` "
                "stores). The miner-agent pushes them over AF_VSOCK to "
                "the guest after the libvirt domain reaches Running. "
                "Required: an empty / missing ticket stalls the guest "
                "§21 pipeline at the first stage. For the dev path, "
                "save the COSE blob the `order-ticket-mint` binary "
                "emitted and pass its path here."
            ),
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        miner_id = opts["miner_id"]
        try:
            identity = MinerIdentity.objects.get(pk=miner_id)
        except MinerIdentity.DoesNotExist:  # pragma: no cover
            raise CommandError(f"no MinerIdentity for {miner_id!r}") from None

        if not identity.netbird_ip:
            raise CommandError(
                f"miner {miner_id!r} has no netbird_ip recorded — "
                "register the miner via PR #120 first"
            )

        # Read the COSE_Sign1 envelope from disk. The bytes flow
        # opaquely through every downstream layer (vali → Edge sign →
        # miner-agent SignedOrder → miner-agent vsock push → guest
        # initramfs ticket::load); this command is the one place that
        # touches the filesystem.
        try:
            with open(opts["cose_ticket_path"], "rb") as fh:
                cose_ticket = fh.read()
        except OSError as exc:  # pragma: no cover — operator error path
            raise CommandError(
                f"cannot read --cose-ticket-path {opts['cose_ticket_path']!r}: {exc}"
            ) from exc

        # §24 lifecycle pre-registration: BEFORE shipping the order
        # downstream, register `VmState::Active` with the KBS using
        # the L1-signed OrderTicket as the cryptographic anchor. The
        # KBS derives `{vm_id, gen, host=platform_id, lease_id}` from
        # the verified ticket itself — vali cannot poison the
        # lifecycle even with a compromised client cert.
        #
        # Failure modes:
        #   - KbsAdminConflict (409): the target vm-state already
        #     differs from what this ticket would write. Operator
        #     must reconcile (different generation / different host /
        #     same ticket_id with different body).
        #   - EffectUnavailable: misconfig OR transient. Retry the
        #     dispatch later. The KBS caches the prior register
        #     idempotently, so a re-invocation with the same ticket
        #     succeeds.
        #   - KbsAdminTerminal: terminal 4xx other than 409. Operator
        #     must check the ticket itself (expired, bad signature,
        #     URL mismatch).
        try:
            admin_ok = kbs_admin.register_vm_active_with_vm_id(
                vm_id=opts["vm_id"],
                cose_ticket=cose_ticket,
            )
        except kbs_admin.KbsAdminConflict as exc:
            self._emit(
                {
                    "ok": False,
                    "outcome": "kbs-admin-conflict",
                    "error": str(exc),
                }
            )
            sys.exit(EXIT_KBS_ADMIN_FAILURE)
        except kbs_admin.KbsAdminTerminal as exc:
            self._emit(
                {
                    "ok": False,
                    "outcome": "kbs-admin-terminal",
                    "error": str(exc),
                }
            )
            sys.exit(EXIT_KBS_ADMIN_FAILURE)
        except EffectUnavailable as exc:
            self._emit(
                {
                    "ok": False,
                    "outcome": "kbs-admin-unavailable",
                    "error": str(exc),
                }
            )
            sys.exit(EXIT_KBS_ADMIN_FAILURE)
        except EffectError as exc:
            self._emit(
                {
                    "ok": False,
                    "outcome": "kbs-admin-error",
                    "error": str(exc),
                }
            )
            sys.exit(EXIT_KBS_ADMIN_FAILURE)
        # Light-touch log so the operator sees the pre-registration
        # outcome before the order-dispatch noise. `cached=True` is
        # the idempotent retry path — same ticket previously
        # registered, no new state-store write — and is operationally
        # equivalent to a fresh insert.
        self.stderr.write(
            f"kbs-admin: registered vm_id={admin_ok.vm_id} "
            f"gen={admin_ok.vm_generation} cached={admin_ok.cached}\n"
        )

        payload = order_dispatch.build_launch_payload(
            vm_id=opts["vm_id"],
            ovmf_path=opts["ovmf_path"],
            kernel_path=opts["kernel_path"],
            initrd_path=opts["initrd_path"],
            cmdline=opts["cmdline"],
            luks_disk_path=opts["luks_disk_path"],
            luks_disk_size_gb=opts["luks_disk_size_gb"],
            rootfs_data_path=opts["rootfs_data_path"],
            rootfs_hash_path=opts["rootfs_hash_path"],
            cpu_count=opts["cpu_count"],
            memory_mb=opts["memory_mb"],
            cose_ticket=cose_ticket,
        )
        payload_json = json.dumps(payload).encode("utf-8")

        try:
            result = order_dispatch.dispatch_order(
                miner_id=miner_id,
                netbird_ip=str(identity.netbird_ip),
                order_id=opts["order_id"],
                kind="launch",
                payload_json=payload_json,
            )
        except order_dispatch.OrderDispatchMisconfigured as exc:
            # Operator config issue — surface it loud + distinct
            # (different exit code than a wire-side failure).
            self._emit(
                {
                    "ok": False,
                    "outcome": "misconfigured",
                    "error": str(exc),
                }
            )
            sys.exit(EXIT_EDGE_FAILURE)
        except order_dispatch.OrderDispatchUnavailable as exc:
            self._emit(
                {
                    "ok": False,
                    "outcome": "edge-unreachable",
                    "error": str(exc),
                }
            )
            sys.exit(EXIT_EDGE_FAILURE)
        except order_dispatch.OrderDispatchError as exc:
            self._emit(
                {
                    "ok": False,
                    "outcome": "edge-error",
                    "error": str(exc),
                }
            )
            sys.exit(EXIT_EDGE_FAILURE)

        self._emit(
            {
                "ok": result.ok,
                "outcome": "miner-accepted" if result.ok else "miner-rejected",
                "status": result.status,
                "classifier": result.classifier,
                "miner_id": miner_id,
                "target_addr": f"{identity.netbird_ip}:{order_dispatch.DEFAULT_MINER_ORDERS_PORT}",
            }
        )
        sys.exit(EXIT_MINER_ACCEPTED if result.ok else EXIT_MINER_REJECTED)

    def _emit(self, payload: dict[str, Any]) -> None:
        # One JSON object on stdout — pipeline-friendly.
        self.stdout.write(json.dumps(payload))
