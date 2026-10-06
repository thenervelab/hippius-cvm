"""Host-attestor releases are kept PER SEV-SNP GENERATION.

The attestor launch measurement covers the VMSA, which carries the vCPU
model's CPUID signature, so ONE blackbox UKI measures differently on Genoa,
Turin and Milan. The {current, previous} grace window used to be a single
fleet-wide window over every active release: on 2026-09-25 adding a Milan
release made it `current`, Turin `previous`, and evicted Genoa — a Genoa miner
went `measurement-stale` and undispatchable.

Covers: the exact incident (gate + admit path), per-generation trim, the
legacy all-untagged table behaving exactly as before, `admit_release`
generation validation, the miner-facing desired endpoint per generation,
and the migration backfill.
"""

from __future__ import annotations

import importlib
from datetime import timedelta

import pytest
from django.apps import apps as django_apps
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.miners.models import MinerIdentity
from apps.scheduler import service as scheduler_service
from apps.telemetry import release_service
from apps.telemetry.models import (
    HostAttestor,
    HostAttestorRelease,
    HostAttestorStatus,
)
from apps.telemetry.tests import test_host_attestor_release as _release_tests
from apps.telemetry.tests.test_host_attestor_release import (
    RELEASE_URL,
    FakeCosign,
    FakePin,
    _release_body,
)

pytestmark = pytest.mark.django_db

# The admin-release fixtures (cosign / pin fakes, admin principal settings),
# shared with the PR-9 release tests.
_pin_settings = _release_tests._pin_settings
admin_client = _release_tests.admin_client
fake_cosign = _release_tests.fake_cosign
fake_pin = _release_tests.fake_pin

# The live measurements of 2026-09-25 (same UKI components, per generation).
GENOA_OLD = (
    "faa6e034b8d494413596b8864187e1477d6fac57fa8a0119"
    "865e5e84c05091e12b8caac1b86bd3ea52ea49119ca426d5"
)
TURIN_OLD = (
    "feb4d0f077decebc5bc965cac7c46a6a07309c6a43aae713"
    "82c87366b880591dd58d7be6cd3a2683c7d2ea99fbfdcdc9"
)
GENOA = (
    "107e7a10a5f783b8920a7fccbdcbfc41f9511dd32211b72c"
    "8ffa4d8fdd803da6ba276b5419f000a51f44b7337f03fbd3"
)
TURIN = (
    "ce4d2921c9e767f78e70ba895e58f009bae4fe248034167e"
    "31c47cb99ab25ef3e08ac4ecc08d5f7408696a599eac550a"
)
MILAN = (
    "51d83b4cdb3bff0558d43cacc539a4ca9a23f1dc7fa21eab"
    "5492868af3520491630b9f631dc99b9bd38bfa6e5ed0048c"
)

NODE_GENOA = "a0" * 32
NODE_TURIN = "b0" * 32
NODE_MILAN = "c0" * 32
SIGNER = "ee" * 32


def _release(measurement: str, generation: str, *, age_s: int, active: bool = True) -> None:
    """An active release created `age_s` seconds ago (explicit so the
    newest-first ordering never depends on insert timing)."""
    row = HostAttestorRelease.objects.create(
        measurement=measurement, version="v", is_active=active, generation=generation
    )
    HostAttestorRelease.objects.filter(id=row.id).update(
        created_at=timezone.now() - timedelta(seconds=age_s)
    )


def _host(node_id: str, chip_id: str, measurement: str) -> None:
    now = timezone.now()
    HostAttestor.objects.create(
        chip_id=chip_id,
        node_id=node_id,
        signer_pubkey=bytes.fromhex(SIGNER),
        measurement=measurement,
        cert_expiry_at=now + timedelta(days=1),
        status=HostAttestorStatus.ATTESTED.value,
        last_seen_at=now,
    )


def _incident_hosts() -> None:
    _host(NODE_GENOA, "01" * 64, GENOA)
    _host(NODE_TURIN, "02" * 8, TURIN)
    _host(NODE_MILAN, "03" * 64, MILAN)


def _incident_releases() -> None:
    """The live table of 2026-09-25 + the Milan row that broke it."""
    _release(GENOA_OLD, "genoa", age_s=5000)
    _release(TURIN_OLD, "turin", age_s=4000)
    _release(GENOA, "genoa", age_s=3000)
    _release(TURIN, "turin", age_s=2000)
    _release(MILAN, "milan", age_s=1000)  # newest


# ─── the incident ────────────────────────────────────────────────────


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_incident_a_newer_milan_release_does_not_evict_genoa() -> None:
    """Genoa + Turin reenroll releases active, a NEWER Milan release added:
    Genoa, Turin AND Milan hosts are all covered by the dispatchability
    gate. Under the old fleet-wide window {Milan, Turin} the Genoa host was
    `measurement-stale`."""
    _incident_releases()
    _incident_hosts()

    gate = scheduler_service.attestor_gate()
    assert gate is not None
    assert gate.reason_for(NODE_GENOA) is None
    assert gate.reason_for(NODE_TURIN) is None
    assert gate.reason_for(NODE_MILAN) is None
    assert release_service.attestor_covered_node_ids() == {
        NODE_GENOA,
        NODE_TURIN,
        NODE_MILAN,
    }
    # The reward meter reads the same desired set.
    assert set(release_service.attestor_liveness_ratios()) == {
        NODE_GENOA,
        NODE_TURIN,
        NODE_MILAN,
    }


def test_incident_windows_are_per_generation() -> None:
    _incident_releases()
    by_gen = release_service.desired_by_generation()
    assert by_gen["genoa"].measurements() == (GENOA, GENOA_OLD)
    assert by_gen["turin"].measurements() == (TURIN, TURIN_OLD)
    assert by_gen["milan"].measurements() == (MILAN,)
    assert release_service._desired_measurement_set() == {
        GENOA,
        GENOA_OLD,
        TURIN,
        TURIN_OLD,
        MILAN,
    }


def test_incident_reconcile_covers_all_three_generations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.scheduler import chain

    _incident_releases()
    _incident_hosts()
    miners = tuple(
        chain.MinerView(
            node_id=n, status="active", last_transition_epoch=1, data_epoch=1, quality=1
        )
        for n in (NODE_GENOA, NODE_TURIN, NODE_MILAN)
    )
    monkeypatch.setattr(
        chain,
        "read_miner_status",
        lambda: chain.ChainSnapshot(current_epoch=1, miners=miners),
    )
    report = release_service.reconcile_coverage()
    assert (report.covered, report.stale, report.missing) == (3, 0, 0)
    assert set(report.desired_measurements) == {GENOA, GENOA_OLD, TURIN, TURIN_OLD, MILAN}


def test_incident_via_admit_path_keeps_every_generation_active(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    """The same incident through `POST /v1/admin/host-attestor/release`:
    admitting Genoa, Turin, then Milan leaves all three active (the old
    fleet-wide trim deactivated Genoa)."""
    for meas, gen in ((GENOA, "genoa"), (TURIN, "turin"), (MILAN, "milan")):
        resp = admin_client.post(
            RELEASE_URL,
            _release_body(measurement_hex=meas, generation=gen),
            format="json",
        )
        assert resp.status_code == 201, resp.data
        assert resp.data["generation"] == gen
    active = set(
        HostAttestorRelease.objects.filter(is_active=True).values_list("measurement", flat=True)
    )
    assert active == {GENOA, TURIN, MILAN}


# ─── per-generation trim ─────────────────────────────────────────────


def test_trim_is_per_generation(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    turin_rows = ["71" * 48, "72" * 48]
    genoa_rows = ["61" * 48, "62" * 48, "63" * 48]
    for m in turin_rows:
        assert (
            admin_client.post(
                RELEASE_URL, _release_body(measurement_hex=m, generation="turin"), format="json"
            ).status_code
            == 201
        )
    # A legacy untagged active row must survive tagged admissions too.
    _release("99" * 48, "", age_s=10_000)
    for m in genoa_rows:
        assert (
            admin_client.post(
                RELEASE_URL, _release_body(measurement_hex=m, generation="genoa"), format="json"
            ).status_code
            == 201
        )
    active = set(
        HostAttestorRelease.objects.filter(is_active=True).values_list("measurement", flat=True)
    )
    # Genoa kept its two newest; the oldest Genoa went; Turin + legacy untouched.
    assert active == {genoa_rows[1], genoa_rows[2], *turin_rows, "99" * 48}


# ─── legacy: an all-untagged table behaves exactly as before ─────────


def test_legacy_untagged_table_is_one_fleet_wide_window() -> None:
    _release("a1" * 48, "", age_s=300)
    _release("a2" * 48, "", age_s=200)
    _release("a3" * 48, "", age_s=100)
    # Old semantics: the two newest active rows, fleet-wide.
    assert release_service._desired_measurement_set() == {"a3" * 48, "a2" * 48}
    legacy = release_service.desired_releases(release_service.LEGACY_GENERATION)
    assert legacy.measurements() == ("a3" * 48, "a2" * 48)
    # Any node (registered or not) is served that window.
    gen, window = release_service.desired_releases_for_node(NODE_GENOA)
    assert gen == ""
    assert window.measurements() == ("a3" * 48, "a2" * 48)


def test_legacy_group_and_tagged_groups_are_both_accepted() -> None:
    """A table mid-transition (an untagged row still active next to tagged
    ones): the legacy group is one more window in the union, so a host on
    the untagged measurement stays covered, and tagged hosts are unaffected."""
    _release("a1" * 48, "", age_s=10_000)
    _incident_releases()
    _incident_hosts()
    _host("d0" * 32, "04" * 64, "a1" * 48)
    assert release_service.attestor_covered_node_ids() == {
        NODE_GENOA,
        NODE_TURIN,
        NODE_MILAN,
        "d0" * 32,
    }


def test_measurement_outside_its_generation_window_is_stale() -> None:
    """Per-generation staleness: a Genoa host on a Genoa release pushed out
    of the GENOA window is `measurement-stale`, even though other
    generations' windows hold fewer than two releases."""
    _release("61" * 48, "genoa", age_s=300, active=False)  # trimmed earlier
    _release(GENOA_OLD, "genoa", age_s=200)
    _release(GENOA, "genoa", age_s=100)
    _release(MILAN, "milan", age_s=50)
    _host(NODE_GENOA, "01" * 64, "61" * 48)
    cov = release_service.attestor_coverage_by_node()
    assert cov.reason_for(NODE_GENOA) == "measurement-stale"


# ─── admit_release generation validation ─────────────────────────────


def test_admit_requires_generation(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    body = _release_body()
    del body["generation"]
    resp = admin_client.post(RELEASE_URL, body, format="json")
    assert resp.status_code == 400
    assert "generation" in resp.data["error"]
    assert fake_pin.calls == []
    assert fake_cosign.calls == []


@pytest.mark.parametrize("bad", ["zen4", "GENOA-X", " "])
def test_admit_refuses_unknown_generation(
    bad: str, admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    resp = admin_client.post(RELEASE_URL, _release_body(generation=bad), format="json")
    assert resp.status_code == 400
    assert fake_pin.calls == []
    assert not HostAttestorRelease.objects.exists()


def test_admit_normalises_generation_case(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    resp = admin_client.post(RELEASE_URL, _release_body(generation="Milan"), format="json")
    assert resp.status_code == 201
    assert HostAttestorRelease.objects.get().generation == "milan"


def test_admit_refuses_relabelling_a_measurement(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    ok = admin_client.post(
        RELEASE_URL, _release_body(measurement_hex=GENOA, generation="genoa"), format="json"
    )
    assert ok.status_code == 201
    resp = admin_client.post(
        RELEASE_URL, _release_body(measurement_hex=GENOA, generation="milan"), format="json"
    )
    assert resp.status_code == 409
    assert resp.data["category"] == "generation-conflict"
    assert len(fake_pin.calls) == 1  # refused before cosign / pin
    assert HostAttestorRelease.objects.get(measurement=GENOA).generation == "genoa"


def test_relabel_refused_under_the_row_lock_too(
    monkeypatch: pytest.MonkeyPatch,
    admin_client: APIClient,
    fake_cosign: FakeCosign,
    fake_pin: FakePin,
) -> None:
    """The early conflict check can race a concurrent admit that tags the
    row after it ran; the re-check under `select_for_update` still refuses."""
    _release(GENOA, "genoa", age_s=100)
    real_check = release_service._refuse_generation_conflict

    def racing_check(measurement_hex: str, generation: str, *, row=None) -> None:  # noqa: ANN001
        if row is None:
            return  # the pre-check "ran before the other admit committed"
        real_check(measurement_hex, generation, row=row)

    monkeypatch.setattr(release_service, "_refuse_generation_conflict", racing_check)
    resp = admin_client.post(
        RELEASE_URL, _release_body(measurement_hex=GENOA, generation="milan"), format="json"
    )
    assert resp.status_code == 409
    assert resp.data["category"] == "generation-conflict"
    assert HostAttestorRelease.objects.get(measurement=GENOA).generation == "genoa"


def test_readmit_tags_a_legacy_row_and_reactivates_it(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    _release(MILAN, "", age_s=100, active=False)
    resp = admin_client.post(
        RELEASE_URL, _release_body(measurement_hex=MILAN, generation="milan"), format="json"
    )
    assert resp.status_code == 200
    row = HostAttestorRelease.objects.get(measurement=MILAN)
    assert (row.generation, row.is_active) == ("milan", True)


# ─── miner-facing desired endpoint: per generation ───────────────────


def _miner(miner_id: str, node_id: str, platform_id: str, generation: str = "") -> None:
    MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=miner_id[-1] * 64,
        platform_id=platform_id,
        chain_node_id=node_id,
        snp_generation=generation,
    )


def _desired(node_id: str) -> dict:
    resp = APIClient().get(reverse("host_attestor_desired", args=[node_id]))
    assert resp.status_code == 200
    return resp.data


def test_desired_endpoint_serves_the_miners_own_generation() -> None:
    _incident_releases()
    _miner("miner-a", NODE_GENOA, "01" * 64)  # 64-byte, unset ⇒ genoa
    _miner("miner-b", NODE_TURIN, "02" * 8)  # 8-byte ⇒ turin
    _miner("miner-c", NODE_MILAN, "03" * 64, "milan")  # registered milan

    genoa = _desired(NODE_GENOA)
    assert genoa["generation"] == "genoa"
    assert genoa["current"]["measurement"] == GENOA
    assert genoa["previous"]["measurement"] == GENOA_OLD

    turin = _desired(NODE_TURIN.upper())  # node id lookup is case-insensitive
    assert turin["generation"] == "turin"
    assert turin["current"]["measurement"] == TURIN
    assert turin["previous"]["measurement"] == TURIN_OLD

    milan = _desired(NODE_MILAN)
    assert milan["generation"] == "milan"
    assert milan["current"]["measurement"] == MILAN
    assert milan["current"]["generation"] == "milan"
    assert milan["previous"] is None

    # Also resolvable by miner_id.
    assert _desired("miner-c")["current"]["measurement"] == MILAN


def test_desired_endpoint_unresolved_or_unreleased_falls_back_to_legacy() -> None:
    _release("a1" * 48, "", age_s=100)
    _release(TURIN, "turin", age_s=50)
    _miner("miner-a", NODE_GENOA, "01" * 64)  # genoa — no genoa release

    unknown = _desired("dd" * 32)
    assert unknown["generation"] == ""
    assert unknown["current"]["measurement"] == "a1" * 48

    genoa = _desired(NODE_GENOA)
    assert genoa["generation"] == ""
    assert genoa["current"]["measurement"] == "a1" * 48


@pytest.mark.parametrize(
    ("platform_id", "registered", "want"),
    [
        ("01" * 64, "", "genoa"),  # 64-byte, unset ⇒ genoa (launch-digest rule)
        ("  " + "02" * 8 + " ", "", "turin"),  # whitespace-padded 8-byte ⇒ turin
        ("01" * 64, "milan", "milan"),  # registered generation wins
        ("02" * 8, "turin", "turin"),
        ("03" * 16, "", ""),  # neither 8 nor 64 bytes ⇒ unresolved
        ("amd-chipid-label", "", ""),  # not hex ⇒ unresolved
    ],
)
def test_node_generation_resolution(platform_id: str, registered: str, want: str) -> None:
    _miner("miner-a", NODE_GENOA, platform_id, registered)
    assert release_service.node_generation(NODE_GENOA) == want
    assert release_service.node_generation(NODE_GENOA.upper()) == want
    assert release_service.node_generation("miner-a") == want
    assert release_service.node_generation("dd" * 32) == ""


# ─── migration backfill ──────────────────────────────────────────────


def test_migration_backfill_tags_known_live_measurements_only() -> None:
    migration = importlib.import_module(
        "apps.telemetry.migrations.0008_hostattestorrelease_generation"
    )
    for meas in (GENOA, GENOA_OLD, TURIN, TURIN_OLD, MILAN, "ab" * 48):
        HostAttestorRelease.objects.create(measurement=meas, is_active=True)
    # A row already tagged is never overwritten.
    HostAttestorRelease.objects.filter(measurement=MILAN).update(generation="genoa")

    migration._backfill(django_apps, None)

    got = dict(HostAttestorRelease.objects.values_list("measurement", "generation"))
    assert got == {
        GENOA: "genoa",
        GENOA_OLD: "genoa",
        TURIN: "turin",
        TURIN_OLD: "turin",
        MILAN: "genoa",
        "ab" * 48: "",
    }
    # The backfill never touches activation.
    assert HostAttestorRelease.objects.filter(is_active=False).count() == 0
