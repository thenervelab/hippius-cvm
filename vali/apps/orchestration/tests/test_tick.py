"""Tests for the `vali_orchestration_tick` management command."""

from __future__ import annotations

import pytest
from django.core.management import call_command

from apps.orchestration import service
from apps.orchestration.models import MigrationState

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _same_gen_miners():
    """Register the source/dest miners same-generation so §25's same-CPU-gen
    gate in `start_migration` passes (see test_migration for the rationale)."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={"pubkey_hex": "aa" * 32, "platform_id": "11" * 64},
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64},
    )


def test_tick_command_once_advances_an_in_flight_job(fx) -> None:
    vm = make_vm()
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    assert job.state == MigrationState.DRAINING.value

    call_command("vali_orchestration_tick", once=True)

    job.refresh_from_db()
    # One cycle advances the job exactly one bounded step.
    assert job.state == MigrationState.QUIESCING.value


def test_tick_command_once_with_no_jobs_is_a_noop() -> None:
    # Must not raise when there is nothing in flight.
    call_command("vali_orchestration_tick", once=True)
