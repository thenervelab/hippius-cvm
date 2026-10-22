"""`disk_probe` results carried in served receipts: matching, verification
and classification (design §2, §4.4; phase R1) — RECORD ONLY.

A probe result is worth nothing on its own: any guest can put a
`disk_probe` field in its own signed receipts. `route` accepts one only
when ALL of these hold, under the run's row lock:

- its `vm_id` (the receipt's, enforced by the verifier) is a
  `DiskProbeRun` VM — else `rejected_not_probe_vm` (a tenant forging a
  result);
- its `run_id` is that run's — else `rejected_unknown_run`;
- its `nonce` is that run's (constant-time) — else `rejected_wrong_nonce`;
- the receipt's node, and the node of the placement that served the
  window, are the run's — else `rejected_wrong_node`;
- that placement's owner is the run's probe owner — else
  `rejected_wrong_owner`;
- the run is still `launching` / `running` — else `repeat` when it already
  holds this very result (every receipt after the first repeats it), or
  `rejected_run_terminal` (a late result for a run that timed out), or
  `rejected_not_launched` (a run the tick has not adopted yet).

On accept, each target is graded (`classify`: `v1` for `os`, `d1` for a
dedicated slot) and stored on the run with its metrics, the QD1 histogram,
the tier it classifies as and the verdict detail. The run's verdict is its
OS target's: `verified`, or `failed` with the reason — `suspect-cache`, the
guest's target error code (`io-error`, `precondition-incomplete`, ...),
`malformed-metrics`, `profile-mismatch`, or `targets-mismatch` when the
result does not cover exactly the requested slots. A dedicated (`d1`)
target's verdict is stored here; the disk takes it once the probe VM is
gone (`dedicated_probe.settle`, R3).

Nothing here touches a pool, a dedicated disk, a cordon, placement or
rewards. The VM is torn down later by the orchestrator tick, after its
lifetime jitter (`teardown_after`). The nonce is never logged."""

from __future__ import annotations

import hmac
import logging
from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone

from apps.telemetry.verifier import DiskProbeResult, DiskProbeTarget

from .classify import classify
from .models import OS_SLOT, DiskProbeRun, ProbeRunState

log = logging.getLogger("apps.disktier.probe_results")

_ROUTABLE = (ProbeRunState.LAUNCHING, ProbeRunState.RUNNING)


def routing_on() -> bool:
    """Results are routed to their runs while either probe runs: pools
    (`VALI_DISK_PROBE_ENABLED`) or dedicated disks
    (`VALI_DEDICATED_PROBE_ENABLED`, R3)."""
    return bool(settings.VALI_DISK_PROBE_ENABLED) or bool(
        getattr(settings, "VALI_DEDICATED_PROBE_ENABLED", False)
    )


def record_unverified(probe: DiskProbeResult, *, vm_id: str, receipt_digest: str) -> None:
    """While both probes are off: note that a receipt carried a probe
    result. Nothing else."""
    log.info(
        "disk_probe result seen, not routed (both probe switches off): "
        "vm=%s run=%s targets=%d receipt=%s",
        vm_id,
        probe.run_id_hex,
        len(probe.targets),
        receipt_digest[:16],
    )


def _node(value: str) -> str:
    v = (value or "").strip().lower()
    return v[2:] if v.startswith("0x") else v


def _grade(requested: dict, got: DiskProbeTarget | None) -> dict:
    entry = {
        **requested,
        "metrics": {},
        "hist_qd1": [],
        "error": "",
        "classified_tier": "",
        "per_metric": {},
        "verdict_detail": "",
    }
    if got is None:
        entry["verdict_detail"] = "targets-mismatch"
        return entry
    entry.update(metrics=dict(got.metrics), hist_qd1=list(got.hist_qd1), error=got.error)
    if got.profile != requested.get("profile"):
        entry["verdict_detail"] = "profile-mismatch"
    elif got.error:
        # The guest could not measure the disk (`io-error`, ...).
        entry["verdict_detail"] = got.error
    else:
        try:
            verdict = classify(got.profile, got.metrics)
        except ValueError:
            entry["verdict_detail"] = "malformed-metrics"
        else:
            entry["classified_tier"] = verdict.tier.value
            entry["per_metric"] = {k: v.value for k, v in verdict.per_metric.items()}
            entry["verdict_detail"] = verdict.failure
    return entry


def route(
    probe: DiskProbeResult,
    *,
    receipt_node_id: str,
    placement_node_id: str,
    placement_owner: str,
    receipt_digest: str,
    linger_s: int,
    now: datetime | None = None,
) -> str:
    """Match `probe` to its run and, if it is the run's, record it. Returns
    the outcome (see the module docstring). Call inside a transaction."""
    now = now or timezone.now()
    run = DiskProbeRun.objects.select_for_update().filter(vm_id=probe.vm_id).first()
    if run is None:
        return "rejected_not_probe_vm"
    if probe.run_id_hex != run.run_id.hex:
        return "rejected_unknown_run"
    if not hmac.compare_digest(probe.nonce_hex.encode(), bytes(run.nonce).hex().encode()):
        return "rejected_wrong_nonce"
    run_node = _node(run.miner_node_id)
    if _node(receipt_node_id) != run_node or _node(placement_node_id) != run_node:
        return "rejected_wrong_node"
    if placement_owner != run.owner:
        return "rejected_wrong_owner"
    if run.state == ProbeRunState.SCHEDULED:
        # The intake committed but the tick has not adopted the run yet
        # (`probe.advance`); the next receipt repeats the result.
        return "rejected_not_launched"
    if run.state not in _ROUTABLE:
        return "repeat" if run.result_digest else "rejected_run_terminal"

    got = {t.slot: t for t in probe.targets}
    requested = {t["slot"]: t for t in run.targets}
    targets = [_grade(requested[slot], got.get(slot)) for slot in sorted(requested)]
    extra = sorted(set(got) - set(requested))
    os_entry = next((t for t in targets if t["slot"] == OS_SLOT), None)
    if extra:
        failure = "targets-mismatch"
    elif os_entry is None:
        # A dedicated-disk run (R3) has no OS target: its summary is the first
        # failing disk; each disk takes its own verdict (`dedicated_probe.settle`).
        failure = next((t["verdict_detail"] for t in targets if t["verdict_detail"]), "")
    else:
        failure = os_entry["verdict_detail"]
    state = ProbeRunState.FAILED if failure else ProbeRunState.VERIFIED
    run.targets = targets
    run.state = state
    run.failure_reason = failure[:128]
    run.release_version = probe.release_version
    run.result_meta = {
        "vcpus": probe.vcpus,
        "kernel": probe.kernel,
        "started_at": probe.started_at,
        "finished_at": probe.finished_at,
        # Slots the result carried that the run never asked: no disk of such
        # a result is graded (`dedicated_probe.verdict_for`).
        **({"extra_slots": extra} if extra else {}),
    }
    run.result_digest = receipt_digest
    run.result_at = now
    run.finished_at = now
    run.teardown_after = now + timedelta(seconds=max(0, linger_s))
    run.save(
        update_fields=[
            "targets",
            "state",
            "failure_reason",
            "release_version",
            "result_meta",
            "result_digest",
            "result_at",
            "finished_at",
            "teardown_after",
        ]
    )
    log.info(
        "disk-probe: run %s on node %s %s%s (os tier %s)",
        run.run_id,
        run_node[:12],
        state,
        f" ({failure})" if failure else "",
        (os_entry or {}).get("classified_tier") or "-",
    )
    return "accepted"
