"""`vali_cross_gen_digest` — lab proof step 1 for cross-generation restore
and failover (docs/operator/cross-gen-failover-lab.md).

For one VM and one destination miner of ANOTHER SNP generation, it prints:

- vali's digest of the VM's recorded boot as that miner measures it
  (`cross_gen.dest_digest`, the value a cross-generation failover pins and
  puts in the destination's ticket);
- with `--preflight`, the digest the miner itself computes for the same
  inputs (a `tenant-preflight` order: the miner stages the artefacts under
  a probe id, never the VM's own, and boots nothing).

The two must be equal for every distro before `VALI_FAILOVER_CROSS_GEN_ENABLED`
is turned on. Exit status 0 when they match (or `--preflight` was not
asked), 1 on a mismatch, 2 when either side could not be computed. Reads
only; writes nothing in vali.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.lifecycle.models import Vm


class Command(BaseCommand):
    help = "Compare vali's cross-generation digest of a VM with a destination miner's own."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--vm-id", required=True)
        parser.add_argument("--dest", required=True, help="The destination miner_id.")
        parser.add_argument(
            "--preflight",
            action="store_true",
            help="Also ask the destination miner for its own digest (tenant-preflight).",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        from apps.miners.models import MinerIdentity

        from ... import cross_gen
        from ...effects import EffectError, EffectUnavailable

        vm = Vm.objects.filter(vm_id=opts["vm_id"]).first()
        if vm is None:
            raise CommandError(f"no vm {opts['vm_id']!r}")
        dest = MinerIdentity.objects.filter(miner_id=opts["dest"]).first()
        if dest is None:
            raise CommandError(f"no miner {opts['dest']!r}")
        out: dict[str, Any] = {
            "vm_id": vm.vm_id,
            "host": vm.host,
            "host_generation": _generation(vm.host),
            "dest": dest.miner_id,
            "dest_generation": _generation(dest.miner_id),
        }
        try:
            out["vali_digest"] = cross_gen.dest_digest(vm, dest.miner_id)
        except (EffectError, EffectUnavailable, ValueError) as exc:
            out["vali_error"] = str(exc)
        if opts["preflight"]:
            # What the probe leaves on the destination, for the cleanup.
            out["probe_staging_dir"] = f"/var/lib/hippius-miner/staging/{_probe_id(vm)}"
            try:
                out["miner_digest"] = _miner_digest(vm, dest)
            except (EffectError, EffectUnavailable, ValueError, TypeError) as exc:
                out["miner_error"] = str(exc)
        if "vali_error" in out or "miner_error" in out:
            out["verdict"] = "unavailable"
        elif opts["preflight"]:
            out["verdict"] = (
                "match"
                if out["vali_digest"].lower() == str(out["miner_digest"]).lower()
                else "MISMATCH"
            )
        else:
            out["verdict"] = "vali-only"
        self.stdout.write(json.dumps(out, indent=2, sort_keys=True))
        if out["verdict"] == "MISMATCH":
            raise SystemExit(1)
        if out["verdict"] == "unavailable":
            raise SystemExit(2)


def _generation(node_id: str) -> str:
    from ... import service

    try:
        return service._snp_generation(node_id)
    except service.StartError as exc:
        return f"unknown ({exc.message})"


def _probe_id(vm: Vm) -> str:
    return f"xgen-probe-{vm.vm_id}"[:64]


def _miner_digest(vm: Vm, dest: Any) -> str:
    """The destination miner's own digest of the VM's recorded boot: a
    preflight with the inputs the destination would be sent."""
    from ... import effects
    from ...services import flavors, launch, launch_record
    from ...services import preflight as preflight_svc

    record = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    if record is None:
        raise ValueError(f"vm {vm.vm_id!r} has no launch record")
    spec = launch.LaunchSpec(**record.spec_json, kek_bytes=None, userdata=b"")
    prefix, initrd_sha = launch_record.booted_artifacts(record)
    spec = dataclasses.replace(spec, s3_key_prefix=prefix, initrd_sha256_hex=initrd_sha)
    result = preflight_svc.dispatch_preflight(
        miner_id=dest.miner_id,
        netbird_ip=str(dest.netbird_ip or ""),
        order_id=preflight_svc.fresh_order_id("ord-xgen-probe"),
        # A probe id: the miner stages under it, never over the VM's own.
        vm_id=_probe_id(vm),
        ovmf_path=spec.ovmf_path,
        cmdline=effects._launch_paths(vm)["cmdline"],
        cpu_count=flavors.resolve_flavor(launch_record.booted_flavor(record)).cpu_count,
        artifacts=launch._select_preflight_artifacts(spec),
    )
    return result.launch_digest_hex
