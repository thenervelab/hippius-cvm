"""Light-tier check logic + the command's metric emission."""

from __future__ import annotations

import json

import pytest

from apps.synthetic import checks


def test_dynamic_capacity_over_report_cannot_inflate() -> None:
    # The real `effective_capacity` is exercised — a fabricated
    # physically-impossible free-RAM report must NOT raise the slot count
    # and MUST trip the over_claim alarm.
    r = checks.check_dynamic_capacity()
    assert r.ok, r.detail
    assert "over_claim flagged" in r.detail
    assert r.gauges["hippius_synthetic_capacity_slots"] >= 0


class _FakeMiner:
    def __init__(self, node_id: str, status: str) -> None:
        self.node_id = node_id
        self.status = status


class _FakeSnapshot:
    # `pallet_live` defaults True so the existing callers keep their
    # meaning; the epoch check reads it, and a double that silently
    # lacked the field would drift from `chain.ChainSnapshot`.
    def __init__(self, miners, current_epoch: int, pallet_live: bool = True) -> None:
        self.miners = miners
        self.current_epoch = current_epoch
        self.pallet_live = pallet_live


def test_dispatchable_flags_ghost_node(monkeypatch) -> None:
    from apps.scheduler import chain, service

    monkeypatch.setattr(
        chain, "read_miner_status", lambda: _FakeSnapshot([_FakeMiner("aa", "active")], 7)
    )
    # A dispatchable node that is NOT on-chain-active is a ghost → fail.
    monkeypatch.setattr(service, "dispatchable_node_ids", lambda: frozenset({"bb"}))
    r = checks.check_dispatchable_matches_active()
    assert not r.ok
    assert "not on-chain-active" in r.detail


def test_dispatchable_ok_subset(monkeypatch) -> None:
    from apps.scheduler import chain, service

    monkeypatch.setattr(
        chain,
        "read_miner_status",
        lambda: _FakeSnapshot([_FakeMiner("aa", "active"), _FakeMiner("cc", "quarantined")], 7),
    )
    monkeypatch.setattr(service, "dispatchable_node_ids", lambda: frozenset({"aa"}))
    r = checks.check_dispatchable_matches_active()
    assert r.ok, r.detail
    assert r.gauges["hippius_synthetic_dispatchable_count"] == 1


def test_dispatchable_chain_unreadable_fails(monkeypatch) -> None:
    from apps.scheduler import chain

    def boom():
        raise chain.ChainReadUnavailable("rpc down")

    monkeypatch.setattr(chain, "read_miner_status", boom)
    r = checks.check_dispatchable_matches_active()
    assert not r.ok
    assert "chain unreadable" in r.detail


def test_epoch_check_reads_epoch(monkeypatch) -> None:
    from apps.scheduler import chain

    monkeypatch.setattr(chain, "read_miner_status", lambda: _FakeSnapshot([], 42))
    r = checks.check_epoch_close_advancing()
    assert r.ok
    assert r.gauges["hippius_synthetic_current_epoch"] == 42
    assert r.gauges["hippius_synthetic_chain_pallet_live"] == 1.0


def test_epoch_check_fails_on_a_fossil_pallet(monkeypatch) -> None:
    """CLAIM: a frozen epoch backed by a REMOVED pallet is a FAILURE.

    Reproduces production on 2026-08-10: a runtime upgrade dropped
    `pallet-compute-scoring`, its storage prefix kept answering, and the
    epoch stuck at 5002. The old check asserted only `epoch > 0` and
    reported OK every 15 minutes for a week.
    """
    from apps.scheduler import chain

    monkeypatch.setattr(
        chain, "read_miner_status", lambda: _FakeSnapshot([], 5002, pallet_live=False)
    )
    r = checks.check_epoch_close_advancing()
    assert not r.ok, "a fossil pallet must FAIL the monitor, not pass it"
    assert "FOSSIL" in r.detail
    assert r.gauges["hippius_synthetic_chain_pallet_live"] == 0.0
    # the epoch is still reported, so an operator sees WHERE it froze
    assert r.gauges["hippius_synthetic_current_epoch"] == 5002


@pytest.mark.django_db
def test_no_stuck_jobs_clean() -> None:
    # Empty DB → no stuck jobs.
    r = checks.check_no_stuck_jobs()
    assert r.ok
    assert r.gauges["hippius_synthetic_stuck_launch_jobs"] == 0


@pytest.mark.django_db
def test_command_light_pushes_metrics(monkeypatch) -> None:
    from apps.synthetic import metrics as metrics_mod

    # Make every light check pass with a stub so the command path (metric
    # assembly + push selection) is what's under test.
    def _ok():
        return [checks.CheckResult("stub", True, "ok", {"hippius_synthetic_x": 1.0})]

    monkeypatch.setattr(checks, "run_light", _ok)
    pushed: list[dict] = []

    def fake_push(ms, *, gateway_url, job, grouping_key, replace, timeout_s):
        pushed.append({"replace": replace, "grouping_key": grouping_key, "text": ms.render()})
        return True

    monkeypatch.setattr(metrics_mod, "push", fake_push)

    from django.core.management import call_command

    call_command("vali_synthetic_monitor", "--tier", "light", "--json")
    assert len(pushed) == 1
    assert pushed[0]["replace"] is True  # success → PUT
    assert pushed[0]["grouping_key"] == {"tier": "light"}
    assert "hippius_synthetic_light_success 1" in pushed[0]["text"]
    assert "hippius_synthetic_last_success_timestamp" in pushed[0]["text"]


@pytest.mark.django_db
def test_command_light_failure_uses_post(monkeypatch) -> None:
    from apps.synthetic import metrics as metrics_mod

    monkeypatch.setattr(checks, "run_light", lambda: [checks.CheckResult("stub", False, "down")])
    pushed: list[dict] = []
    monkeypatch.setattr(
        metrics_mod,
        "push",
        lambda ms, **kw: pushed.append({"replace": kw["replace"], "text": ms.render()}) or True,
    )
    from django.core.management import call_command

    call_command("vali_synthetic_monitor", "--tier", "light")
    assert pushed[0]["replace"] is False  # failure → POST (preserves last-success ts)
    # A failing run must NOT stamp a fresh last-success timestamp.
    assert "hippius_synthetic_last_success_timestamp" not in pushed[0]["text"]
    assert "hippius_synthetic_light_success 0" in pushed[0]["text"]


@pytest.mark.django_db
def test_migrations_check_passes_when_the_schema_matches_the_code() -> None:
    """CLAIM: a fully-migrated deployment reports OK.

    The test DB is migrated by pytest-django, so the plan is empty.
    """
    r = checks.check_no_unapplied_migrations()
    assert r.ok, r.detail
    assert r.gauges["hippius_synthetic_unapplied_migrations"] == 0


@pytest.mark.django_db
def test_migrations_check_FAILS_and_names_the_pending_ones(monkeypatch) -> None:
    """CLAIM: a pending migration is a FAILURE that names what is missing.

    Reproduces 2026-08-10: `sha-7f93d33815bb` shipped the SNP liveness
    gate with `telemetry.0006_vmliveattestation` unapplied, because a new
    image does not re-run the migrations Job. Harmless only because the
    gate ships disabled; armed, every accrual would have 500'd.
    """
    from django.db.migrations.executor import MigrationExecutor

    class _M:
        app_label = "telemetry"
        name = "0006_vmliveattestation"

    monkeypatch.setattr(
        MigrationExecutor,
        "migration_plan",
        lambda self, targets, clean_start=False: [(_M(), False)],
    )
    r = checks.check_no_unapplied_migrations()
    assert not r.ok, "a pending migration must FAIL the monitor"
    assert "telemetry.0006_vmliveattestation" in r.detail
    assert r.gauges["hippius_synthetic_unapplied_migrations"] == 1


@pytest.mark.django_db
def test_migrations_check_is_registered_in_the_light_tier() -> None:
    """CLAIM: the check actually RUNS.

    A check that exists but is not in the registry is decorative — the
    same 'declared but not wired' failure this audit hit twice.
    """
    assert checks.check_no_unapplied_migrations in checks.LIGHT_CHECKS


# ── acknowledgements, as seen at the COMMAND / metric layer ──────────────
# (the parsing/policy claims live in test_ack.py)


def _ack_spec(check: str, days: int = 10) -> str:
    import datetime as dt

    until = (dt.datetime.now(tz=dt.UTC) + dt.timedelta(days=days)).date()
    return f"{check} | {until.isoformat()} | testnet runtime dropped the scoring pallet"


def _capture_push(monkeypatch) -> list[dict]:
    from apps.synthetic import metrics as metrics_mod

    pushed: list[dict] = []
    monkeypatch.setattr(
        metrics_mod,
        "push",
        lambda ms, **kw: pushed.append({"replace": kw["replace"], "text": ms.render()}) or True,
    )
    return pushed


@pytest.mark.django_db
def test_command_acked_failure_keeps_the_tier_metric_at_1(monkeypatch, settings) -> None:
    """CLAIM: an acknowledged failure does NOT zero `light_success`.

    Live shape: `epoch_close` FAILs on the fossil pallet, everything else
    is fine, and `SyntheticLightFailing` must stop firing for it — while
    the per-check gauge keeps telling the truth (0).
    """
    monkeypatch.setattr(
        checks,
        "run_light",
        lambda: [
            checks.CheckResult("vali_api", True, "up"),
            checks.CheckResult("epoch_close", False, "FOSSIL: current_epoch=5002"),
        ],
    )
    settings.VALI_SYNTHETIC_ACK = _ack_spec("epoch_close")
    pushed = _capture_push(monkeypatch)
    from django.core.management import call_command

    call_command("vali_synthetic_monitor", "--tier", "light")
    text = pushed[0]["text"]
    assert "hippius_synthetic_light_success 1" in text
    # …and the acked check STILL publishes its real verdict + the ack flag.
    assert 'hippius_synthetic_light_check_success{check="epoch_close"} 0' in text
    assert 'hippius_synthetic_light_check_acknowledged{check="epoch_close"} 1' in text
    assert 'hippius_synthetic_light_check_acknowledged{check="vali_api"} 0' in text
    # A tier that is effectively healthy must resume stamping the
    # last-success timestamp, or `SyntheticLightStale` just replaces
    # `SyntheticLightFailing` as the permanently-firing alert.
    assert "hippius_synthetic_last_success_timestamp" in text
    assert pushed[0]["replace"] is True


@pytest.mark.django_db
def test_command_unacked_failure_still_zeroes_the_tier_metric(monkeypatch, settings) -> None:
    """CLAIM: the ack covers ONLY its named check — a new, different
    failure still turns the tier red."""
    monkeypatch.setattr(
        checks,
        "run_light",
        lambda: [
            checks.CheckResult("epoch_close", False, "FOSSIL"),
            checks.CheckResult("stuck_jobs", False, "stuck launch=3"),
        ],
    )
    settings.VALI_SYNTHETIC_ACK = _ack_spec("epoch_close")
    pushed = _capture_push(monkeypatch)
    from django.core.management import call_command

    call_command("vali_synthetic_monitor", "--tier", "light")
    text = pushed[0]["text"]
    assert "hippius_synthetic_light_success 0" in text
    assert "hippius_synthetic_last_success_timestamp" not in text
    assert pushed[0]["replace"] is False


@pytest.mark.django_db
def test_command_acked_check_is_still_VISIBLE_in_the_output(monkeypatch, settings) -> None:
    """CLAIM: an acknowledged check never silently vanishes.

    It stays in the JSON payload with `ok: false`, annotated with the
    expiry and the stated reason.
    """
    monkeypatch.setattr(
        checks,
        "run_light",
        lambda: [checks.CheckResult("epoch_close", False, "FOSSIL: current_epoch=5002")],
    )
    settings.VALI_SYNTHETIC_ACK = _ack_spec("epoch_close")
    _capture_push(monkeypatch)
    from io import StringIO

    from django.core.management import call_command

    out = StringIO()
    call_command("vali_synthetic_monitor", "--tier", "light", "--json", stdout=out)
    payload = json.loads(out.getvalue())
    entry = next(c for c in payload["checks"] if c["name"] == "epoch_close")
    assert entry["ok"] is False, "the verdict itself must never be rewritten"
    assert entry["acknowledged"] is True
    assert "FOSSIL" in entry["detail"]
    assert entry["ack_reason"]
    assert payload["ack"]["applied"] == ["epoch_close"]


@pytest.mark.django_db
def test_command_emits_the_ack_expiry_and_stale_gauges(monkeypatch, settings) -> None:
    """CLAIM: the expiry/re-decision mechanism is OBSERVABLE.

    `SyntheticAckExpiring` alerts off `ack_expires_timestamp`; without the
    gauge the lapse would only be discovered when the tier reddens.
    """
    monkeypatch.setattr(
        checks, "run_light", lambda: [checks.CheckResult("epoch_close", False, "FOSSIL")]
    )
    settings.VALI_SYNTHETIC_ACK = _ack_spec("epoch_close")
    pushed = _capture_push(monkeypatch)
    from django.core.management import call_command

    call_command("vali_synthetic_monitor", "--tier", "light")
    text = pushed[0]["text"]
    assert 'hippius_synthetic_ack_expires_timestamp{check="epoch_close"}' in text
    assert 'hippius_synthetic_ack_stale{check="epoch_close"} 0' in text
    assert "hippius_synthetic_ack_invalid 0" in text


@pytest.mark.django_db
def test_command_flags_a_STALE_ack_when_the_check_recovers(monkeypatch, settings) -> None:
    """CLAIM: an acknowledged-but-RESOLVED condition is not silently acked.

    When the chain team restores the pallet, the leftover ack must announce
    itself instead of sitting pre-armed over the next failure.
    """
    monkeypatch.setattr(
        checks, "run_light", lambda: [checks.CheckResult("epoch_close", True, "epoch=42")]
    )
    settings.VALI_SYNTHETIC_ACK = _ack_spec("epoch_close")
    pushed = _capture_push(monkeypatch)
    from django.core.management import call_command

    call_command("vali_synthetic_monitor", "--tier", "light")
    text = pushed[0]["text"]
    assert 'hippius_synthetic_ack_stale{check="epoch_close"} 1' in text
    assert 'hippius_synthetic_light_check_acknowledged{check="epoch_close"} 0' in text


@pytest.mark.django_db
def test_command_counts_a_REFUSED_ack_entry(monkeypatch, settings) -> None:
    """CLAIM: a broken ack spec is alarmed, not silently ineffective."""
    monkeypatch.setattr(
        checks, "run_light", lambda: [checks.CheckResult("epoch_close", False, "FOSSIL")]
    )
    settings.VALI_SYNTHETIC_ACK = "epoch_close | 2099-01-01 | a reason that is long enough"
    pushed = _capture_push(monkeypatch)
    from django.core.management import call_command

    call_command("vali_synthetic_monitor", "--tier", "light")
    text = pushed[0]["text"]
    assert "hippius_synthetic_ack_invalid 1" in text
    assert "hippius_synthetic_light_success 0" in text, "a refused ack mutes nothing"


@pytest.mark.django_db
def test_command_default_no_ack_is_unchanged_behaviour(monkeypatch, settings) -> None:
    """CLAIM: with the empty default the tier behaves exactly as before."""
    monkeypatch.setattr(
        checks, "run_light", lambda: [checks.CheckResult("epoch_close", False, "FOSSIL")]
    )
    settings.VALI_SYNTHETIC_ACK = ""
    pushed = _capture_push(monkeypatch)
    from django.core.management import call_command

    call_command("vali_synthetic_monitor", "--tier", "light")
    assert "hippius_synthetic_light_success 0" in pushed[0]["text"]
    assert "hippius_synthetic_ack_invalid 0" in pushed[0]["text"]


# ── uptime-liveness stall: "this VM is running and earning nothing" ──────
#
# The 2026-08-13 zero-uptime incident was invisible: the miner logged ok,
# vali logged INFO, the VM stayed active and kept emitting served
# receipts. These pin the signal that makes the next occurrence loud.


def _running_vm(vm_id: str):
    from apps.lifecycle.models import Vm, VmState
    from apps.scheduler.models import VmBillingBinding

    Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=VmState.ACTIVE,
        generation=1,
        host="node-src",
        lifecycle_vk=bytes(32),
    )
    VmBillingBinding.objects.create(
        vm_id=vm_id,
        node_id_hex="aa" * 32,
        resource_class="small",
        lease_id=f"lease-{vm_id}",
    )


def _attestation(vm_id: str, verified_at_unix: int, seq: int = 1) -> None:
    from apps.telemetry.models import VmLiveAttestation

    VmLiveAttestation.objects.create(
        vm_id=vm_id,
        node_id_hex="aa" * 32,
        attestation_seq=seq,
        epoch=7,
        observed_at_unix=verified_at_unix - 1,
        verified_at_unix=verified_at_unix,
        expiry_unix=verified_at_unix + 900,
        measurement="44" * 48,
        snp_report_digest="11" * 32,
        body_digest=f"{vm_id}-{seq}".encode().hex().ljust(64, "0")[:64],
    )


@pytest.mark.django_db
def test_uptime_liveness_flags_a_vm_that_STOPPED_attesting(settings) -> None:
    """THE visibility claim. A bound, billable VM that WAS producing SNP
    live attestations and has stopped must FAIL the light tier — that is
    "running and earning nothing", and it is exactly what nothing
    detected for 3.7 h on 2026-08-13."""
    import time

    settings.VALI_UPTIME_LIVENESS_STALL_S = 1800
    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    now = int(time.time())
    _running_vm("probe-a")
    # Attested steadily until 3.7 h ago, then nothing (the incident shape).
    for i, back in enumerate(range(14_500, 13_000, -300)):
        _attestation("probe-a", now - back, seq=i + 1)

    r = checks.check_uptime_liveness()
    assert not r.ok, "a VM that stopped attesting did not fail the monitor"
    assert "probe-a" in r.detail
    assert "earning NOTHING" in r.detail
    assert r.gauges["hippius_synthetic_uptime_stalled_vms"] == 1.0
    assert r.gauges["hippius_synthetic_uptime_liveness_armed"] == 1.0


@pytest.mark.django_db
def test_uptime_liveness_passes_while_attestations_keep_landing(settings) -> None:
    import time

    settings.VALI_UPTIME_LIVENESS_STALL_S = 1800
    now = int(time.time())
    _running_vm("healthy-1")
    _attestation("healthy-1", now - 120)
    r = checks.check_uptime_liveness()
    assert r.ok, r.detail
    assert r.gauges["hippius_synthetic_uptime_stalled_vms"] == 0.0
    assert r.gauges["hippius_synthetic_uptime_attesting_vms"] == 1.0


@pytest.mark.django_db
def test_uptime_liveness_ignores_a_vm_that_has_NEVER_attested(settings) -> None:
    """A pre-keepalive image emits nothing, forever, legitimately. Flagging
    it would pin this check red for the whole rollout — and a
    permanently-firing alert is a disabled alert, which is how the real
    stall stays invisible. Absence of evidence is not a stall."""
    settings.VALI_UPTIME_LIVENESS_STALL_S = 1800
    _running_vm("pre-keepalive-tenant")
    r = checks.check_uptime_liveness()
    assert r.ok, r.detail
    assert r.gauges["hippius_synthetic_uptime_attesting_vms"] == 0.0
    assert r.gauges["hippius_synthetic_uptime_stalled_vms"] == 0.0


@pytest.mark.django_db
def test_uptime_liveness_ignores_a_decommissioned_vm(settings) -> None:
    """A destroyed VM stops attesting BY DESIGN. Paging for it would be a
    false alarm on every single decommission."""
    import time

    from apps.lifecycle.models import Vm, VmState

    settings.VALI_UPTIME_LIVENESS_STALL_S = 1800
    now = int(time.time())
    _running_vm("gone-1")
    _attestation("gone-1", now - 20_000)
    Vm.objects.filter(vm_id="gone-1").update(state=VmState.DESTROYED)
    r = checks.check_uptime_liveness()
    assert r.ok, r.detail
    assert r.gauges["hippius_synthetic_uptime_stalled_vms"] == 0.0


def test_uptime_liveness_is_registered_in_the_light_tier() -> None:
    """CLAIM: the check actually RUNS. A check that exists but is not in
    the registry is decorative."""
    assert checks.check_uptime_liveness in checks.LIGHT_CHECKS


# ── KBS running-config drift (the ConfigMap is not the config) ───────
#
# The 2026-08-13 incident in one sentence: `maxUnconfirmedReleases: 0 → 3`
# was merged and synced, the deployed ConfigMap read 3, and the running
# process still reported `gate_armed=false` because it had not been
# restarted. These tests pin the three verdicts that follow from that.


def _expect(settings, **posture) -> None:
    settings.VALI_KBS_EXPECTED_POSTURE = json.dumps(posture)


def _fake_admin(responses: dict[str, tuple[str, dict | None]]):
    """Stand in for `checks._admin_get_json` — path → (status, body)."""

    def _get(path: str, **_kw):
        return responses.get(path, ("unavailable: not stubbed", None))

    return _get


def test_kbs_config_drift_FAILS_when_the_configmap_says_3_and_the_process_says_none(
    settings, monkeypatch
) -> None:
    """THE incident, reproduced. git/ConfigMap declares the anti-rollback
    gate ARMED at 3; the running process reports the gate DISABLED
    (`configured_bound: null`). The check must FAIL and the message must
    name BOTH values — an alert that says only "drift" sends the operator
    back to the same two places they already disagree about."""
    _expect(settings, max_unconfirmed_releases=3)
    monkeypatch.setattr(
        checks,
        "_admin_get_json",
        _fake_admin(
            {
                # Pre-restart: the posture endpoint does not exist yet.
                "/v1/admin/config": ("absent", None),
                # The oracle that DOES work today, reporting the gate off.
                "/v1/admin/volume-stamp": (
                    "ok",
                    {"configured_bound": None, "gate_armed": False},
                ),
            }
        ),
    )
    r = checks.check_kbs_config_drift()
    assert not r.ok, "an inert security-gate change did not fail the monitor"
    assert "DRIFT" in r.detail
    assert "max_unconfirmed_releases" in r.detail
    assert "3" in r.detail, "the message must name the DECLARED value"
    assert "None" in r.detail, "the message must name the RUNNING value"
    assert r.gauges["hippius_synthetic_kbs_config_drift"] == 1.0
    assert r.gauges["hippius_synthetic_kbs_config_keys_compared"] == 1.0


def test_kbs_config_drift_PASSES_when_the_configmap_and_the_process_agree(
    settings, monkeypatch
) -> None:
    """The false-positive direction. This check runs every 15 minutes
    forever; a green fleet must be green, or it gets acknowledged into
    silence and the drift it exists to catch goes back to being invisible."""
    _expect(settings, max_unconfirmed_releases=3)
    monkeypatch.setattr(
        checks,
        "_admin_get_json",
        _fake_admin(
            {
                "/v1/admin/config": ("absent", None),
                "/v1/admin/volume-stamp": (
                    "ok",
                    {"configured_bound": 3, "gate_armed": True},
                ),
            }
        ),
    )
    r = checks.check_kbs_config_drift()
    assert r.ok, r.detail
    assert "AGREE" in r.detail
    assert r.gauges["hippius_synthetic_kbs_config_drift"] == 0.0
    assert r.gauges["hippius_synthetic_kbs_config_keys_compared"] == 1.0
    # The posture endpoint being absent is published, not alarmed.
    assert r.gauges["hippius_synthetic_kbs_posture_endpoint"] == 0.0


def test_kbs_config_drift_pre_restart_404_is_UNKNOWN_not_drift_and_not_agree(
    settings, monkeypatch
) -> None:
    """`GET /v1/admin/config` 404s on every KBS built before it existed,
    and restarting the KBS to fix that wipes its state/audit/evidence
    emptyDirs — so the window is long. A 404 must be a THIRD outcome:
    reporting it as DRIFT cries wolf until the next restart (and a
    wolf-crying check gets muted), reporting it as AGREE is the "all
    good" this whole item exists to stop."""
    _expect(settings, require_wrapped_kek=True)
    absent = _fake_admin(
        {
            "/v1/admin/config": ("absent", None),
            # No `configured_bound` fallback covers this key.
            "/v1/admin/volume-stamp": ("ok", {"configured_bound": 3}),
        }
    )
    monkeypatch.setattr(checks, "_admin_get_json", absent)
    r = checks.check_kbs_config_drift()

    assert "UNKNOWN" in r.detail
    assert "verified NOTHING" in r.detail
    # DISTINCT from DRIFT: no key is claimed to disagree.
    assert r.gauges["hippius_synthetic_kbs_config_drift"] == 0.0
    # DISTINCT from AGREE: nothing was compared, and the alert rules key
    # off exactly that (`keys_compared == 0` is its own, lower-severity
    # rule — it is a coverage gap, not a divergence).
    assert r.gauges["hippius_synthetic_kbs_config_keys_compared"] == 0.0
    assert r.gauges["hippius_synthetic_kbs_posture_endpoint"] == 0.0
    assert not r.ok, "'we could not look' must not read as 'all good'"

    # And the three verdicts really are three distinct values.
    assert checks.compare_posture({"a": 1}, {"a": 2}).verdict == checks.POSTURE_DRIFT
    assert checks.compare_posture({"a": 1}, {"a": 1}).verdict == checks.POSTURE_AGREE
    assert checks.compare_posture({"a": 1}, {}).verdict == checks.POSTURE_UNKNOWN
    assert len({checks.POSTURE_DRIFT, checks.POSTURE_AGREE, checks.POSTURE_UNKNOWN}) == 3


def test_kbs_config_drift_partial_coverage_is_not_a_failure(settings, monkeypatch) -> None:
    """One agreeing key + one not-yet-observable key is AGREE. This is
    exactly the deployed state between merging this PR and the next KBS
    restart, and it must be green — otherwise the check is red on day one
    and gets acknowledged away."""
    _expect(settings, max_unconfirmed_releases=3, require_wrapped_kek=True)
    monkeypatch.setattr(
        checks,
        "_admin_get_json",
        _fake_admin(
            {
                "/v1/admin/config": ("absent", None),
                "/v1/admin/volume-stamp": ("ok", {"configured_bound": 3}),
            }
        ),
    )
    r = checks.check_kbs_config_drift()
    assert r.ok, r.detail
    assert "not yet observable" in r.detail
    assert "require_wrapped_kek" in r.detail
    assert r.gauges["hippius_synthetic_kbs_config_keys_compared"] == 1.0


def test_kbs_config_drift_compares_the_full_posture_once_the_endpoint_lands(
    settings, monkeypatch
) -> None:
    """Post-restart: `GET /v1/admin/config` answers and the check
    generalises beyond the one key — a flipped `require_wrapped_kek` that
    never reached the process is caught the same way."""
    _expect(
        settings,
        max_unconfirmed_releases=3,
        require_wrapped_kek=True,
        admin_listener_mode="mtls",
    )
    monkeypatch.setattr(
        checks,
        "_admin_get_json",
        _fake_admin(
            {
                "/v1/admin/config": (
                    "ok",
                    {
                        "v": 1,
                        "max_unconfirmed_releases": 3,
                        "require_wrapped_kek": False,
                        "admin_listener_mode": "mtls",
                        # A key we do not declare must not fail us.
                        "min_tcb": 99,
                    },
                ),
                "/v1/admin/volume-stamp": ("ok", {"configured_bound": 3}),
            }
        ),
    )
    r = checks.check_kbs_config_drift()
    assert not r.ok
    assert "require_wrapped_kek" in r.detail
    assert r.gauges["hippius_synthetic_kbs_config_drift"] == 1.0
    assert r.gauges["hippius_synthetic_kbs_config_keys_compared"] == 3.0
    assert r.gauges["hippius_synthetic_kbs_posture_endpoint"] == 1.0


def test_kbs_config_drift_unreachable_admin_api_is_UNKNOWN(settings, monkeypatch) -> None:
    """A KBS we cannot reach is not a KBS we have verified. `check_kbs`
    already alarms the reachability itself; this one must not quietly
    report success."""
    _expect(settings, max_unconfirmed_releases=3)
    monkeypatch.setattr(
        checks,
        "_admin_get_json",
        _fake_admin(
            {
                "/v1/admin/config": ("unavailable: connection refused", None),
                "/v1/admin/volume-stamp": ("unavailable: connection refused", None),
            }
        ),
    )
    r = checks.check_kbs_config_drift()
    assert not r.ok
    assert "UNKNOWN" in r.detail
    assert r.gauges["hippius_synthetic_kbs_config_keys_compared"] == 0.0


def test_kbs_config_drift_undeclared_expectation_fails_loudly(settings) -> None:
    """No declaration means nothing is being checked — which must not
    look like a pass. Same reasoning as the empty-allowlist fail-closed."""
    settings.VALI_KBS_EXPECTED_POSTURE = ""
    r = checks.check_kbs_config_drift()
    assert not r.ok
    assert "VALI_KBS_EXPECTED_POSTURE" in r.detail


def test_admin_get_json_maps_404_to_absent_and_403_to_unavailable(settings) -> None:
    """The 404/other split is what makes UNKNOWN meaningful, so it is
    tested against the real classifier rather than assumed. 403 (no
    client identity on the mTLS listener) is NOT 'the endpoint is
    missing' — it is 'we were refused', which is a fault."""
    import urllib.error

    settings.VALI_SYNTHETIC_KBS_URL = "http://kbs.invalid:8001"
    settings.VALI_KBS_ADMIN_CLIENT_CERT = ""
    settings.VALI_KBS_ADMIN_CLIENT_KEY = ""
    settings.VALI_KBS_ADMIN_CACERT = ""

    def _raise(code):
        def _urlopen(*_a, **_kw):
            raise urllib.error.HTTPError("u", code, "msg", None, None)

        return _urlopen

    assert checks._admin_get_json("/v1/admin/config", _urlopen=_raise(404)) == ("absent", None)
    status, body = checks._admin_get_json("/v1/admin/config", _urlopen=_raise(403))
    assert status.startswith("unavailable") and "403" in status
    assert body is None


def test_kbs_config_drift_is_registered_in_the_light_tier() -> None:
    """CLAIM: the check actually RUNS. A check that exists but is not in
    the registry is decorative."""
    assert checks.check_kbs_config_drift in checks.LIGHT_CHECKS
