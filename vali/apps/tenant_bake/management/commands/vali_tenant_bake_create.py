"""`vali_tenant_bake_create` — operator-facing bake driver (#334 Phase 2).

Posts a per-tenant qcow2 bake request through the vali API (which
spawns a k8s Job), polls until the row reaches a terminal state, and
emits a single-line JSON envelope on stdout matching the shape
`vali_create_vm`'s pre-existing `--luks-disk-sha256-hex` /
`--kernel-sha256-hex` / `--initrd-sha256-hex` / `--measurement-hex`
flags expect.

This is the **bridge** between the legacy operator-side bake script
and the future fully-chained `vali_create_vm --in-cluster-bake`
(Phase 2.1). Today it lets the operator collapse the workstation
bake step to:

    bake=$(python manage.py vali_tenant_bake_create \\
        --vm-id myvm-1 \\
        --base-image-url \\
            https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img \\
        --base-image-sha256 0533b065... \\
        --size-gb 10 \\
        --kek-vault-path secret/.../luks-kek \\
        --s3-output-bucket hippius-compute-images \\
        --s3-output-prefix tenant/myvm-1/)

    python manage.py vali_create_vm \\
        --luks-disk-sha256-hex "$(echo "$bake" | jq -r .qcow2_sha256)" \\
        --kernel-sha256-hex    "$(echo "$bake" | jq -r .kernel_sha256)" \\
        --initrd-sha256-hex    "$(echo "$bake" | jq -r .initrd_sha256)" \\
        --measurement-hex      "$(echo "$bake" | jq -r .measurement_hex)" \\
        ... # the rest as before

Net effect: NO operator-workstation root execution of qemu-img +
losetup + cryptsetup. The bake happens inside a k8s Job, with
artefacts landing on S3 the same way the operator-side script
landed them before.

## Exit codes

    0   Bake Succeeded; JSON on stdout.
    8   Config error (CommandError).
    9   Bake failed (Failed row); failure_reason on stderr.
    10  Bake polling timed out before the row went terminal.
    11  k8s spawn failed at POST (503 from /v1/tenant-bakes).
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.tenant_bake.models import TenantBake, TenantBakeState

EXIT_OK = 0
EXIT_CONFIG = 8
EXIT_BAKE_FAILED = 9
EXIT_POLL_TIMEOUT = 10
EXIT_K8S_SPAWN_FAILED = 11

DEFAULT_POLL_INTERVAL_S = 15
DEFAULT_POLL_TIMEOUT_S = 30 * 60  # 30 min


class Command(BaseCommand):
    help = (
        "Drive a per-tenant qcow2 bake via the vali API (spawns a k8s Job), "
        "poll until terminal, emit a JSON envelope with the resulting SHAs + "
        "measurement_hex on stdout. Stand-in for the legacy operator-side "
        "tenant-image-bake.sh + aws s3 cp workflow."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--vm-id", required=True)
        parser.add_argument(
            "--base-image-url",
            required=True,
            help=(
                "HTTPS URL of the vanilla cloud image (Ubuntu / Debian). MUST "
                "be an immutable, dated upstream path — a moving segment "
                "(`latest/`, `current/`, `daily/`, a `-latest.` filename "
                "token) is refused, because it contradicts "
                "--base-image-sha256 and breaks on every point release."
            ),
        )
        parser.add_argument(
            "--base-image-sha256",
            required=True,
            help="64-hex sha256 of the base image bytes.",
        )
        parser.add_argument("--size-gb", required=True, type=int)
        parser.add_argument(
            "--kek-vault-path",
            required=True,
            help="KV-v2 path the baker reads the LUKS KEK from.",
        )
        parser.add_argument(
            "--s3-output-bucket",
            required=True,
            help="S3 bucket the baker uploads the three artefacts to.",
        )
        parser.add_argument(
            "--s3-output-prefix",
            required=True,
            help="S3 key prefix under --s3-output-bucket (typically tenant/<vm>/).",
        )
        parser.add_argument(
            "--requester-name",
            default="vali_tenant_bake_create",
            help=(
                "ServiceClient.name to record on the row's "
                "`requested_by` audit field. Defaults to the command's "
                "name so operator runs are self-tagged."
            ),
        )
        parser.add_argument(
            "--poll-interval-secs",
            type=int,
            default=DEFAULT_POLL_INTERVAL_S,
        )
        parser.add_argument(
            "--poll-timeout-secs",
            type=int,
            default=DEFAULT_POLL_TIMEOUT_S,
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        # Drive the create + poll via direct ORM calls + the same
        # `spawn_bake_job` shim the HTTP view uses — no need to round
        # trip through HTTP for an in-process management command, and
        # the resulting code path is easier to test (the test asserts
        # against the DB row state, not against the wire shape).
        #
        # Imports deferred to `handle` so module-load (e.g. for help
        # text) doesn't touch the Django app registry. This mirrors
        # `apps.orchestration` management commands.
        from apps.identity.models import PrincipalScope, ServiceClient
        from apps.tenant_bake.k8s_jobs import K8sUnavailable, spawn_bake_job
        from apps.tenant_bake.locks import bake_queue_lock
        from apps.tenant_bake.views import _mint_bake_id, _parse_create

        # Validate via the same parser the view uses so the rules
        # stay in one place.
        payload: dict[str, Any] = {
            "vm_id": opts["vm_id"],
            "base_image_url": opts["base_image_url"],
            "base_image_sha256": opts["base_image_sha256"],
            "size_gb": opts["size_gb"],
            "kek_vault_path": opts["kek_vault_path"],
            "s3_output_bucket": opts["s3_output_bucket"],
            "s3_output_prefix": opts["s3_output_prefix"],
        }
        try:
            parsed = _parse_create(payload)
        except Exception as exc:  # FinalizeError surfaces here
            raise CommandError(f"input validation: {exc}") from exc

        # Ensure the requester ServiceClient exists — same posture as
        # `apps.packer` setup; production deploys pre-seed via fixture.
        requester, _ = ServiceClient.objects.get_or_create(
            name=opts["requester_name"],
            # P2: a bake is a fleet artifact and `/finalize` is
            # operator-gated, so the auto-created requester principal is
            # seeded as an operator. (No token is minted here — see below.)
            defaults={"scope": PrincipalScope.OPERATOR.value},
        )
        # We do NOT mint a token here — the row's audit trail only
        # needs the principal name. Tokens are issued out-of-band by
        # ops (`python manage.py rotate_service_token`).

        bake_id = _mint_bake_id()
        # Ordered against the golden re-bake's check-then-insert (F6).
        with bake_queue_lock():
            row = TenantBake.objects.create(
                bake_id=bake_id,
                state=TenantBakeState.QUEUED.value,
                requested_by=requester,
                **parsed,
            )
        try:
            spawn_bake_job(row)
        except K8sUnavailable as exc:
            self.stderr.write(self.style.ERROR(f"k8s spawn failed: {exc}"))
            sys.exit(EXIT_K8S_SPAWN_FAILED)

        # Poll until terminal.
        interval = int(opts["poll_interval_secs"])
        timeout = int(opts["poll_timeout_secs"])
        deadline = time.monotonic() + timeout
        last_state = row.state
        while True:
            row.refresh_from_db()
            if row.state != last_state:
                self.stderr.write(
                    f"bake_id={bake_id} state={row.state} version={row.version}"
                )
                last_state = row.state
            if row.state == TenantBakeState.SUCCEEDED.value:
                break
            if row.state == TenantBakeState.FAILED.value:
                self.stderr.write(
                    self.style.ERROR(
                        f"bake failed: {row.failure_reason or '<no reason>'}"
                    )
                )
                sys.exit(EXIT_BAKE_FAILED)
            if time.monotonic() > deadline:
                self.stderr.write(
                    self.style.ERROR(
                        f"poll timeout after {timeout}s; row stuck in "
                        f"state={row.state}"
                    )
                )
                sys.exit(EXIT_POLL_TIMEOUT)
            time.sleep(interval)

        envelope = {
            "bake_id": bake_id,
            "vm_id": row.vm_id,
            "qcow2_sha256": row.qcow2_sha256,
            "kernel_sha256": row.kernel_sha256,
            "initrd_sha256": row.initrd_sha256,
            "measurement_hex": row.measurement_hex,
            "s3_output_bucket": row.s3_output_bucket,
            "s3_output_prefix": row.s3_output_prefix,
        }
        self.stdout.write(json.dumps(envelope))
