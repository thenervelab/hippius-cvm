"""The I/O side of gate (f): how the scheduler learns which region a miner
is in, and which region a VM asked for.

`decide_placement` is pure and only sees two dicts; these tests pin the
functions that BUILD them (`service.region_by_node`,
`service.launch_region_for_vm`, `service.placement_arguments`), because
a gate is only as fail-closed as its inputs — a map that leaked an
unverified miner in, or a lookup that lost a VM's region, would defeat
it without any placement test noticing.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation, MinerStatus
from apps.orchestration.tests.factories import make_launch_record
from apps.scheduler import service

from .factories import make_dispatchable_identity, make_snapshot, make_vm, node_id

pytestmark = pytest.mark.django_db


def _locate(
    miner: MinerIdentity, country: str, verdict: str = LocationVerdict.VERIFIED
) -> MinerLocation:
    return MinerLocation.objects.create(
        miner=miner,
        connection_ip="146.10.20.30",
        country_code=country,
        verdict=verdict,
        observed_at=timezone.now(),
    )


# ─── region_by_node ──────────────────────────────────────────────────


def test_region_by_node_is_verified_only_by_default() -> None:
    """The default is the scheduler's rule: an `unverified` or `mismatch`
    row is NOT in its country. A VPN exit whose latency contradicts its
    GeoIP must never be sold as being there."""
    _locate(make_dispatchable_identity(1), "FR")
    _locate(make_dispatchable_identity(2), "FR", LocationVerdict.UNVERIFIED)
    _locate(make_dispatchable_identity(3), "DE", LocationVerdict.MISMATCH)
    _locate(make_dispatchable_identity(4), "DE", LocationVerdict.UNKNOWN)
    assert service.region_by_node() == {node_id(1): "FR"}


def test_region_by_node_verified_only_false_admits_unverified_never_mismatch() -> None:
    """Off, `unverified` joins (a check could not be made); `mismatch` is a
    CONTRADICTION (guests egress elsewhere, sources disagree) and is never
    a location, whatever the setting."""
    _locate(make_dispatchable_identity(1), "FR")
    _locate(make_dispatchable_identity(2), "FR", LocationVerdict.UNVERIFIED)
    _locate(make_dispatchable_identity(3), "DE", LocationVerdict.MISMATCH)
    _locate(make_dispatchable_identity(4), "DE", LocationVerdict.UNKNOWN)
    assert service.region_by_node(verified_only=False) == {
        node_id(1): "FR",
        node_id(2): "FR",
    }


def test_region_by_node_ages_a_stale_row_out(settings) -> None:  # noqa: ANN001
    """A probe that stopped running must not leave `verified` standing
    forever; past `VALI_GEO_MAX_AGE_S` the miner is in no region. Same
    rule as `GET /v1/operator/regions` (shared `geo.placeable_locations`)."""
    settings.VALI_GEO_MAX_AGE_S = 3600
    _locate(make_dispatchable_identity(1), "FR")
    stale = _locate(make_dispatchable_identity(2), "FR")
    MinerLocation.objects.filter(pk=stale.pk).update(
        observed_at=timezone.now() - timedelta(hours=2)
    )
    assert service.region_by_node() == {node_id(1): "FR"}
    assert service.region_by_node(verified_only=False) == {node_id(1): "FR"}


def test_region_by_node_follows_the_setting_when_unspecified(settings) -> None:  # noqa: ANN001
    _locate(make_dispatchable_identity(1), "FR", LocationVerdict.UNVERIFIED)
    assert service.region_by_node() == {}
    settings.VALI_GEO_REQUIRE_VERIFIED = False
    assert service.region_by_node() == {node_id(1): "FR"}


def test_region_by_node_normalises_keys_and_values() -> None:
    """The gate compares with `==`: keys must be the lowercase chain id the
    snapshot carries and values the uppercase code the caller passes, or
    a correctly located miner silently fails the gate."""
    miner = make_dispatchable_identity(1)
    MinerIdentity.objects.filter(pk=miner.pk).update(chain_node_id=node_id(1).upper())
    _locate(miner, "fr")
    assert service.region_by_node() == {node_id(1): "FR"}


def test_region_by_node_skips_unbridged_and_uncountried_rows() -> None:
    """No chain id ⇒ the scheduler could never match it; no country ⇒ the
    probe found nothing. Neither may appear as being somewhere."""
    unbridged = MinerIdentity.objects.create(
        miner_id="miner-x",
        pubkey_hex="ee" * 16,
        platform_id="ff" * 16,
        chain_node_id=None,
        netbird_ip="100.64.0.77",
        last_seen_at=timezone.now(),
        status=MinerStatus.ACTIVE,
    )
    _locate(unbridged, "FR")
    _locate(make_dispatchable_identity(2), "")
    assert service.region_by_node(verified_only=False) == {}


# ─── placement_arguments ─────────────────────────────────────────────


def test_placement_arguments_adds_no_query_when_unconstrained(monkeypatch) -> None:  # noqa: ANN001
    """Every launch that asks for no region — all of them, until now — must
    not pay for the location table. The gate is inert AND free."""
    make_dispatchable_identity(1)
    _locate(MinerIdentity.objects.get(miner_id="miner-01"), "FR")
    snapshot = make_snapshot(10, [])
    monkeypatch.setattr(service, "region_by_node", lambda **kw: pytest.fail("queried"))
    args = service.placement_arguments(
        snapshot=snapshot, tenant_id="t", user_id="u", flavor="small"
    )
    assert args["region"] == ""
    assert args["region_by_node"] is None
    monkeypatch.undo()
    table = MinerLocation._meta.db_table
    with CaptureQueriesContext(connection) as ctx:
        service.placement_arguments(snapshot=snapshot, tenant_id="t", user_id="u", flavor="small")
    assert not [q for q in ctx.captured_queries if table in q["sql"]]


def test_placement_arguments_carries_the_verified_map_when_constrained() -> None:
    _locate(make_dispatchable_identity(1), "FR")
    _locate(make_dispatchable_identity(2), "DE", LocationVerdict.UNVERIFIED)
    args = service.placement_arguments(
        snapshot=make_snapshot(10, []), tenant_id="t", user_id="u", flavor="small", region="fr"
    )
    assert args["region"] == "FR"
    assert args["region_by_node"] == {node_id(1): "FR"}


# ─── launch_region_for_vm ────────────────────────────────────────────


def test_launch_region_for_vm_reads_the_newest_job() -> None:
    """A re-launch after a failure carries the current intent; an older
    job's region must not win over it."""
    vm = make_vm("vm-1")
    old = make_launch_record(vm, region="DE")
    make_launch_record(vm, region="fr")
    # `started_at` is auto_now_add; push the first job into the past.
    type(old).objects.filter(pk=old.pk).update(started_at=timezone.now() - timedelta(hours=1))
    assert service.launch_region_for_vm("vm-1") == "FR"


def test_launch_region_for_vm_is_empty_without_a_job() -> None:
    """A CLI-launched VM, or one that pre-dates the async path, asked for
    nothing — it stays unconstrained rather than un-placeable."""
    make_vm("vm-1")
    assert service.launch_region_for_vm("vm-1") == ""


def test_launch_region_for_vm_tolerates_a_pre_region_spec() -> None:
    """A `spec_json` written before the field existed has no `region` key
    at all. That is every VM on the fleet today."""
    vm = make_vm("vm-1")
    job = make_launch_record(vm)
    assert "region" not in job.spec_json
    assert service.launch_region_for_vm("vm-1") == ""


def test_launch_region_for_vm_prefers_the_launch_that_succeeded() -> None:
    """The API accepts a second launch POST for a running VM (it fails
    later with `placement-conflict`). Until it does, that queued row is
    the newest — and it must NOT strip the running VM of the region its
    real launch asked for."""
    from apps.orchestration.models import LaunchJob, LaunchJobState
    from apps.scheduler.tests.factories import make_service_client

    vm = make_vm("vm-1")
    real = make_launch_record(vm, region="FR")
    type(real).objects.filter(pk=real.pk).update(started_at=timezone.now() - timedelta(hours=1))
    LaunchJob.objects.create(
        job_id="stray",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json={"vm_id": vm.vm_id, "region": ""},
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        state=LaunchJobState.QUEUED.value,
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )
    assert service.launch_region_for_vm("vm-1") == "FR"


def test_launch_region_for_vm_falls_back_to_an_in_flight_launch() -> None:
    """A `/fail` can arrive while the FIRST launch is still running: no
    job has succeeded yet, and the running one carries the intent."""
    from apps.orchestration.models import LaunchJob, LaunchJobState
    from apps.scheduler.tests.factories import make_service_client

    vm = make_vm("vm-1")
    LaunchJob.objects.create(
        job_id="running",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json={"vm_id": vm.vm_id, "region": "de"},
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        state=LaunchJobState.RUNNING.value,
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )
    assert service.launch_region_for_vm("vm-1") == "DE"
