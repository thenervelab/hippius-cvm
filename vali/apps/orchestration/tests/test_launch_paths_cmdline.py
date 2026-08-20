"""Direct unit tests for `effects._launch_paths` cmdline resolution — the
§25 dest MUST boot the EXACT SNP-measured cmdline the source launched with.

The measured (augmented) cmdline carries `dm-verity.root=` (golden), the §23
telemetry trio, the EOL delivery tokens, etc. — none of which live in
`spec_json["cmdline"]` (the BASE cmdline). The launch persists the augmented
bytes as `result_json["emit"]["measured_cmdline"]`; `_launch_paths` must
prefer it, and FAIL CLOSED for a golden VM that predates that persistence
(carrying the base cmdline would misclassify golden→legacy on the dest AND
boot a measurement the KBS denies).
"""

from __future__ import annotations

import secrets

import pytest
from django.utils import timezone

from apps.orchestration import effects
from apps.orchestration.models import LaunchJob, LaunchJobState

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

_GOLDEN = "golden_verity_overlay"
_LEGACY = "legacy_luks"
_BASE = "ro quiet console=ttyS0 hippius.kbs_url=vsock://2:19266"
_MEASURED = _BASE + " dm-verity.root=" + "ab" * 32 + " boot=hippius-golden"


def _record(vm_id: str, *, disk_mode: str, emit: dict | None) -> LaunchJob:
    now = timezone.now()
    return LaunchJob.objects.create(
        job_id=secrets.token_hex(16),
        vm_id=vm_id,
        tenant_id="t",
        flavor="small",
        spec_json={
            "disk_mode": disk_mode,
            "vm_id": vm_id,
            "cmdline": _BASE,
            "flavor": "small",
        },
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=now,
        finished_at=now,
        result_json={"emit": emit} if emit is not None else None,
        decided_by=make_service_client(),
    )


def test_prefers_persisted_measured_cmdline_for_golden() -> None:
    vm = make_vm()
    _record(vm.vm_id, disk_mode=_GOLDEN, emit={"measured_cmdline": _MEASURED})
    paths = effects._launch_paths(vm)
    # The dest carries the MEASURED cmdline (with dm-verity.root=), NOT the base.
    assert paths["cmdline"] == _MEASURED
    assert "dm-verity.root=" in paths["cmdline"]


def test_golden_without_measured_cmdline_fails_closed() -> None:
    # A golden VM launched BEFORE the fix (no persisted measured_cmdline):
    # migrating it with the base cmdline would misclassify golden→legacy and
    # mismatch the SNP measurement — refuse rather than corrupt the dest.
    vm = make_vm()
    _record(vm.vm_id, disk_mode=_GOLDEN, emit={})
    with pytest.raises(effects.EffectError, match="no persisted measured_cmdline"):
        effects._launch_paths(vm)


def test_legacy_falls_back_to_base_cmdline() -> None:
    # Legacy VMs keep the pre-fix behaviour when no measured_cmdline is stored.
    vm = make_vm()
    _record(vm.vm_id, disk_mode=_LEGACY, emit={})
    paths = effects._launch_paths(vm)
    assert paths["cmdline"] == _BASE


def test_measured_cmdline_preferred_for_legacy_too() -> None:
    # A post-fix legacy launch also persists measured_cmdline; carry it so the
    # dest byte-matches the source measurement.
    vm = make_vm()
    measured = _BASE + " hippius.luks_header_sha256=" + "cd" * 32
    _record(vm.vm_id, disk_mode=_LEGACY, emit={"measured_cmdline": measured})
    paths = effects._launch_paths(vm)
    assert paths["cmdline"] == measured
