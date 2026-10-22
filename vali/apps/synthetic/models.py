"""Per-miner probe state (`apps.synthetic.per_miner`).

One row per miner the per-miner probe has ever claimed: what the last
CONCLUSIVE probe found, the run of failures since the last pass, and the
claim of a probe in flight. Written only by the per-miner tier; read by
the tier itself (selection, budget), by its fleet metrics and by
`/v1/operator/nodes` (`last_probe`).
"""

from __future__ import annotations

from django.db import models


class MinerProbe(models.Model):
    """The probe ledger of one miner, keyed by its lower-case on-chain
    `node_id` (`MinerIdentity.chain_node_id`, as vali dispatched to it)."""

    miner_node_id = models.CharField(max_length=64, primary_key=True)
    # The last probe that REACHED the miner (a placement on it existed):
    # when it finished, whether every stage passed, the first stage that
    # failed ("" on a pass) and its VM.
    last_probe_at = models.DateTimeField(null=True, blank=True)
    last_ok = models.BooleanField(null=True, blank=True)
    last_stage = models.CharField(max_length=32, blank=True, default="")
    last_vm_id = models.CharField(max_length=64, blank=True, default="")
    # Internal detail of the failed stage (vali's own wording — Vault,
    # KBS, HTTP errors). Never served to an operator.
    last_detail = models.CharField(max_length=512, blank=True, default="")
    last_ok_at = models.DateTimeField(null=True, blank=True)
    # Conclusive failures since the last pass.
    fail_streak = models.PositiveIntegerField(default=0)
    # Any attempt, an inconclusive one included (the probe never reached
    # the miner): what the rotation orders by, so a miner vali cannot
    # place on is not re-picked every tick.
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    # The probe in flight ("" / null when none). A claim older than
    # `VALI_SYNTHETIC_REAP_AGE_S` is a killed run's: the light-tier reaper
    # owns its VM, and the claim no longer holds the budget.
    # Fingerprint of the miner's attested host (chip, boot_id, measurement)
    # recorded at the last attempt: a change jumps the rotation queue.
    attestor_fingerprint = models.CharField(max_length=32, blank=True, default="", db_default="")
    in_flight_vm_id = models.CharField(max_length=64, blank=True, default="")
    in_flight_since = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"MinerProbe({self.miner_node_id[:12]} ok={self.last_ok})"
