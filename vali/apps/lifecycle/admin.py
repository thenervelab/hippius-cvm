"""Django admin registrations for `apps.lifecycle` (#152).

Read-only oriented: a `Vm` row is the vali-side mirror of an
authoritative `kbs_core::lifecycle::VmState`, and mutating it from
the admin would diverge intent from the KBS gate. The transition
endpoint (`POST /v1/vm/<id>/transition`) is the canonical writer; the
admin exists to inspect.

`lifecycle_vk` (guest Ed25519 vk, 32 bytes) and `eol_nonce` (single-
use 32-byte nonce vali issues when it asks the guest to stop) are
forced read-only — both are binary, both have strict consumers
downstream (the stopped-ack verifier + the §24/§25 orchestrator), and
neither has a legitimate "edit me in the UI" reason.
"""

from __future__ import annotations

from django.contrib import admin

from .models import Vm


@admin.register(Vm)
class VmAdmin(admin.ModelAdmin):
    list_display = (
        "vm_id",
        "state",
        # The column that stops a wedged guest reading green: `state` and
        # `boot_phase` both stay healthy for a VM hung in its initramfs.
        "guest_liveness_display",
        "guest_signal_at",
        "generation",
        "host",
        "migration_dest",
        "new_generation",
        # The PHANTOM column: a row an abandoned launch left `active` with
        # no host and a LIVE per-VM KEK. Without it such a row is
        # indistinguishable in the admin from a healthy tenant.
        "launch_abandoned_at",
        "launch_abandoned_outcome",
        "version",
        "updated_at",
    )
    list_filter = ("state", "launch_abandoned_registered")

    @admin.display(description="guest liveness", ordering="guest_signal_at")
    def guest_liveness_display(self, obj: Vm) -> str:
        """`alive (42s) | wedged (3h) | unknown` — derived, never stored.

        Computed per row at render time from `guest_signal_at`; the admin
        list is small enough (and the column indexed) that this stays a
        pure in-memory classification with no extra query.
        """
        verdict = obj.guest_liveness()
        if verdict.age_s is None:
            return verdict.state
        return f"{verdict.state} ({verdict.age_s}s)"
    search_fields = ("vm_id", "lease_id", "host", "migration_dest")
    readonly_fields = (
        "id",
        # BinaryFields can't be edited from the admin form, and even
        # if Django coerced them to bytes the values are produced /
        # consumed by §7 attested release + the stopped-ack verifier —
        # mutating them from the UI is never the right ops action.
        "lifecycle_vk",
        "eol_nonce",
        # Optimistic-concurrency counter — bumped by the transition
        # view's CAS, never by hand.
        "version",
        # In-guest liveness watermark — written ONLY by the telemetry
        # ingest path (`guest_liveness.record_signal`). Hand-editing it
        # would fabricate evidence that a wedged guest is alive.
        "guest_signal_at",
        "guest_signal_kind",
        # Abandoned-launch marker — written ONLY by the launch path
        # (`launch._mark_launch_abandoned` / `_bind_vm_host`) and READ by
        # a sweep that can crypto-erase. Hand-setting `registered` would
        # hand that reap a target it never earned; hand-clearing it would
        # hide a live-KEK orphan. Both are operator actions with better
        # tools (§24 decommission / a re-launch).
        "launch_abandoned_at",
        "launch_abandoned_outcome",
        "launch_abandoned_registered",
        # Customer-held keys pin — written ONCE by `launch._ensure_vm_row`
        # and held immutable by every relaunch / re-mint path. Editing it
        # would re-mint an M1/M2 VM as another mode (or adopt a guardian).
        "key_mode",
        "guardian_endpoint",
        "guardian_pubkey",
        # Power axis — written by the power operations (`power._set_power`,
        # which stamps `power_state_at` on every transition) and the
        # abandoned-marker settler. `power_stop_ordered_at` is valid only
        # while it equals `power_state_at`; a hand edit that changes the
        # state without the stamp would forge "stopped by a completed stop
        # order", which `vali_swap_vm_initrd --revert` trusts.
        "power_state",
        "power_state_at",
        "power_stop_ordered_at",
        "power_stop_proof",
        "created_at",
        "updated_at",
    )
    ordering = ("-updated_at",)
