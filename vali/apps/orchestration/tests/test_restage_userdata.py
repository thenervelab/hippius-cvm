"""`vali_restage_userdata` gives an M0 VM a new cloud-init userdata at its
NEXT boot, without vali ever holding a way to read the canonical copy.

Pins, per claim:
- it stages exactly what launch intake stages (the template, at
  `…/userdata-intake`, wrapped under `ud-<vm_id>`) and points the launch
  record at that version, audited;
- the relaunch afterwards (reboot-recovery = power start) hands the NEW
  plaintext to `launch_on_miner`, which re-stages the canonical copy under
  `kek-<vm_id>` and mints the §6 digest over it — the real launch path, with
  a Vault fake that DENIES `transit/decrypt/kek-*` as production Vault does;
- an M1/M2 VM, a VM that is not active + running, an in-flight operation,
  an over-cap / malformed / NetBird-less userdata are refused before any
  write;
- `--dry-run` writes nothing, and no output carries the userdata;
- rollback (`--to-version`, `--revert-last`) re-points without new bytes
  and decrypts nothing.
"""

from __future__ import annotations

import io

import pytest
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration.effects import EffectError
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import launch, launch_record, userdata_digest, vault_kv

from .factories import make_migration_job
from .test_customer_keys_launch import (  # noqa: F401 — `harness` is a fixture
    _measured,
    _miner,
    _pinned_vm,
    _spec_json,
    _succeeded_job,
    harness,
)

pytestmark = pytest.mark.django_db

VM = "vm-restage"
ORIGINAL = b"#cloud-config\nruncmd:\n  - [ echo, original ]\n"
FIX = (
    b"#cloud-config\nbootcmd:\n  - [ cloud-init-per, once, fix-1, sh, -c, 'echo fixed' ]\n"
    b"runcmd:\n  - [ echo, original ]\n"
)
#: A substring no command output may ever carry.
SECRET_MARK = b"fixed"


class _Vault:
    """KV v2 + Transit, in memory, with production's custody split: vali may
    encrypt under `kek-*` and `ud-*` but decrypt ONLY under `ud-*`."""

    def __init__(self) -> None:
        self.kv: dict[str, list[bytes]] = {}
        self.decrypts: list[str] = []
        self.encrypts: list[str] = []

    def put_kv(self, mount: str, path: str, value: bytes, *, cas: int | None = None):
        self.kv.setdefault(path, []).append(bytes(value))
        return vault_kv.VaultWriteResult(version=len(self.kv[path]))

    def get_kv(self, mount: str, path: str, *, version: int | None = None) -> bytes:
        versions = self.kv.get(path) or []
        n = version or len(versions)
        if not 1 <= n <= len(versions):
            raise vault_kv.VaultNotFound("vault-kv-get: not-found")
        return versions[n - 1]

    def latest_version(self, mount: str, path: str) -> int:
        if path not in self.kv:
            raise EffectError("vault-kv-metadata: not-found")
        return len(self.kv[path])

    def kv_exists(self, mount: str, path: str) -> bool:
        return path in self.kv

    def transit_encrypt(self, name: str, plaintext: bytes) -> bytes:
        self.encrypts.append(name)
        return b"vault:v1:" + name.encode().hex().encode() + b"." + bytes(plaintext).hex().encode()

    def transit_decrypt(self, name: str, ciphertext: bytes) -> bytes:
        self.decrypts.append(name)
        if name.startswith("kek-"):
            raise EffectError("vault-transit-decrypt: HTTP 403 (vali is denied kek-*)")
        key_hex, _, body = ciphertext[len(b"vault:v1:") :].partition(b".")
        assert bytes.fromhex(key_hex.decode()).decode() == name, "wrong Transit key"
        return bytes.fromhex(body.decode())

    def plaintext(self, path: str, version: int) -> bytes:
        """What a holder of the key would read (the test's view, not vali's)."""
        _key, _, body = self.kv[path][version - 1][len(b"vault:v1:") :].partition(b".")
        return bytes.fromhex(body.decode())

    def install(self, monkeypatch) -> None:
        for name in (
            "put_kv",
            "get_kv",
            "latest_version",
            "kv_exists",
            "transit_encrypt",
            "transit_decrypt",
        ):
            monkeypatch.setattr(vault_kv, name, getattr(self, name))
        monkeypatch.setattr(vault_kv, "ensure_transit_key", lambda *a, **k: None)


@pytest.fixture
def vault(monkeypatch) -> _Vault:
    v = _Vault()
    v.install(monkeypatch)
    return v


def _intake() -> str:
    return f"{settings.VALI_VAULT_KV_PREFIX}/{VM}/userdata-intake"


def _m0_vm(vault: _Vault, *, enable_netbird: bool = False) -> tuple[Vm, LaunchJob]:
    """An M0 golden VM launched through intake: the template at intake v1."""
    _miner()
    vm = _pinned_vm(VM, "hippius")
    spec_json = {**_spec_json(VM, "hippius"), "enable_netbird": enable_netbird}
    job = _succeeded_job(VM, spec_json, measured_cmdline=_measured("hippius"))
    launch.stage_userdata_intake_copy("secret", _intake(), VM, ORIGINAL)
    job.userdata_vault_path = _intake()
    job.userdata_vault_version = 1
    job.save(update_fields=["userdata_vault_path", "userdata_vault_version"])
    return vm, job


def _run(tmp_path, *extra: str, userdata: bytes | None = FIX) -> str:
    out = io.StringIO()
    args = ["--vm-id", VM, "--by", "op@test", "--reason", "fix k8s worker", *extra]
    if userdata is not None:
        path = tmp_path / "userdata.yaml"
        path.write_bytes(userdata)
        args += ["--userdata-file", str(path)]
    call_command("vali_restage_userdata", *args, stdout=out)
    return out.getvalue()


def _record() -> LaunchJob:
    return launch_record.latest_record(VM)


# ── the write ────────────────────────────────────────────────────────────


def test_it_stages_the_template_as_intake_does_and_points_the_record_at_it(
    vault, tmp_path
) -> None:
    _m0_vm(vault)

    out = _run(tmp_path)

    job = _record()
    assert (job.userdata_vault_path, job.userdata_vault_version) == (_intake(), 2)
    # Wrapped under the vali-openable ud-<vm_id>, like intake; the canonical
    # copy (kek-<vm_id>) is not touched until a relaunch re-stages it.
    assert vault.kv[_intake()][1].startswith(b"vault:v1:")
    assert vault.encrypts == [vault_kv.userdata_transit_key_name(VM)] * 2
    assert vault.plaintext(_intake(), 2) == FIX
    assert f"{settings.VALI_VAULT_KV_PREFIX}/{VM}/userdata" not in vault.kv
    # Decrypts nothing.
    assert vault.decrypts == []
    (entry,) = launch_record.userdata_restages(job)
    assert entry["previous"] == {"userdata_vault_path": _intake(), "userdata_vault_version": 1}
    assert entry["new"] == {"userdata_vault_path": _intake(), "userdata_vault_version": 2}
    assert entry["operator"] == "op@test"
    assert entry["reason"] == "userdata-restage:fix k8s worker"
    assert entry["evidence"]["bytes"] == len(FIX)
    # The initrd swap's audit trail is not where this goes (it reads every
    # `superseded` entry with a `new` as a spec change of its own).
    assert "superseded" not in (job.result_json or {}).get("emit", {})
    assert SECRET_MARK.decode() not in out
    assert "rollback: --to-version 1" in out


def test_dry_run_writes_nothing_and_never_prints_the_userdata(vault, tmp_path) -> None:
    _m0_vm(vault)

    out = _run(tmp_path, "--dry-run")

    assert len(vault.kv[_intake()]) == 1
    job = _record()
    assert job.userdata_vault_version == 1
    assert launch_record.userdata_restages(job) == []
    assert "mode=dry-run" in out
    assert f"{_intake()}@2" in out and str(len(FIX)) in out
    assert SECRET_MARK.decode() not in out


# ── the relaunch reads the NEW version, end to end ────────────────────────


def test_the_next_relaunch_re_stages_and_digests_the_new_userdata(
    harness,  # noqa: F811 — the imported fixture, by name
    monkeypatch,
    tmp_path,
) -> None:
    from apps.orchestration import service

    v = _Vault()
    v.install(monkeypatch)  # over the harness's Vault stubs
    # The KEK the launch staged: a relaunch reads only its KV version.
    v.put_kv("secret", f"{settings.VALI_VAULT_KV_PREFIX}/{VM}/luks-kek", b"vault:v1:kek")
    vm, _job = _m0_vm(v)
    _run(tmp_path)

    assert service._reboot_recovery_relaunch(vm, "miner-ck") is True

    canonical = f"{settings.VALI_VAULT_KV_PREFIX}/{VM}/userdata"
    # The canonical copy the KBS releases is the NEW userdata, wrapped under
    # the KBS-only key vali cannot open.
    (ct,) = v.kv[canonical]
    assert ct.startswith(b"vault:v1:")
    assert v.plaintext(canonical, 1) == FIX
    assert vault_kv.transit_key_name(VM) in v.encrypts
    # vali opened the template under ud-<vm> only — never kek-*.
    assert v.decrypts == [vault_kv.userdata_transit_key_name(VM)]
    # The ticket binds that canonical version, and its §6 digest is over
    # the new plaintext: the KBS and the guest recompute exactly this.
    (mint,) = harness.mints
    assert (mint.userdata_vault_path, mint.userdata_vault_version) == (canonical, 1)
    assert mint.allowed_userdata_digest_hex == userdata_digest.userdata_digest_hex(
        tenant_id=mint.tenant_id,
        vm_id=VM,
        ticket_id=mint.ticket_id,
        secret_type=userdata_digest.SECRET_TYPE_USERDATA,
        path=canonical,
        version=1,
        plaintext=FIX,
    )
    # The working copy is stamped for that canonical version (the §25 pairing).
    working = f"{settings.VALI_VAULT_KV_PREFIX}/{VM}/userdata-pending"
    assert launch.open_userdata_working_copy("secret", working, VM, 1) == FIX


# ── refusals: nothing written ─────────────────────────────────────────────


def _assert_untouched(vault: _Vault) -> None:
    assert len(vault.kv.get(_intake(), [])) == 1
    assert _record().userdata_vault_version == 1
    assert launch_record.userdata_restages(_record()) == []


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_an_m1_m2_vm_is_refused(vault, tmp_path, mode) -> None:
    _miner()
    _pinned_vm(VM, mode)
    job = _succeeded_job(VM, _spec_json(VM, mode), measured_cmdline=_measured(mode))
    launch.stage_userdata_intake_copy("secret", _intake(), VM, ORIGINAL)
    LaunchJob.objects.filter(pk=job.pk).update(userdata_vault_path=_intake())

    with pytest.raises(CommandError, match=f"not-m0:{mode}"):
        _run(tmp_path)
    _assert_untouched(vault)


def test_an_m0_pin_whose_record_measured_a_guardian_is_refused(vault, tmp_path) -> None:
    """The pin alone is not enough: the measured cmdline must agree."""
    vm, job = _m0_vm(vault)
    emit = {**job.result_json["emit"], "measured_cmdline": _measured("split")}
    LaunchJob.objects.filter(pk=job.pk).update(result_json={"emit": emit})

    with pytest.raises(CommandError, match="key-mode-unprovable"):
        _run(tmp_path)
    _assert_untouched(vault)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("state", VmState.DECOMMISSIONING, "vm-not-active"),
        ("power_state", VmPowerState.STOPPED, "power-not-running"),
        ("power_state", VmPowerState.STARTING, "power-op-in-flight:starting"),
    ],
)
def test_a_vm_not_active_and_running_is_refused(vault, tmp_path, field, value, reason) -> None:
    vm, _job = _m0_vm(vault)
    Vm.objects.filter(pk=vm.pk).update(**{field: value})

    with pytest.raises(CommandError, match=reason):
        _run(tmp_path)
    _assert_untouched(vault)


def test_a_migration_in_flight_is_refused(vault, tmp_path) -> None:
    vm, _job = _m0_vm(vault)
    make_migration_job(vm)

    with pytest.raises(CommandError, match="migration-in-flight"):
        _run(tmp_path)
    _assert_untouched(vault)


def test_a_launch_job_in_flight_is_refused(vault, tmp_path) -> None:
    _vm, job = _m0_vm(vault)
    LaunchJob.objects.create(
        job_id="lj-queued", vm_id=VM, tenant_id="t-ck", flavor="small",
        spec_json=job.spec_json, userdata_vault_path=_intake(), userdata_vault_version=1,
        kek_vault_path=job.kek_vault_path, state=LaunchJobState.QUEUED.value,
        phase_started_at=job.phase_started_at, decided_by=job.decided_by,
    )

    with pytest.raises(CommandError, match="launch-job-in-flight"):
        _run(tmp_path)
    _assert_untouched(vault)


@pytest.mark.parametrize(
    ("userdata", "reason"),
    [
        (b"", "userdata-empty"),
        (b"vault:v1:abcd", "userdata-vault-prefixed"),
        (b"#cloud-config\n\xff\xfe", "userdata-not-utf8"),
    ],
)
def test_a_malformed_userdata_is_refused(vault, tmp_path, userdata, reason) -> None:
    _m0_vm(vault)

    with pytest.raises(CommandError, match=reason):
        _run(tmp_path, userdata=userdata)
    _assert_untouched(vault)


def test_a_userdata_over_the_launch_api_cap_is_refused(vault, tmp_path, settings) -> None:
    _m0_vm(vault)
    settings.DATA_UPLOAD_MAX_MEMORY_SIZE = len(FIX) - 1

    with pytest.raises(CommandError, match="userdata-too-large"):
        _run(tmp_path)
    _assert_untouched(vault)


def test_a_netbird_vm_needs_the_placeholder(vault, tmp_path) -> None:
    _m0_vm(vault, enable_netbird=True)

    with pytest.raises(CommandError, match="NETBIRD_SETUP_KEY"):
        _run(tmp_path)
    _assert_untouched(vault)

    _run(tmp_path, userdata=FIX + b"  - [ netbird, up, --setup-key={{NETBIRD_SETUP_KEY}} ]\n")
    assert _record().userdata_vault_version == 2


def test_a_relaunch_landing_between_decision_and_write_wins(
    vault, tmp_path, monkeypatch
) -> None:
    """Re-decided under the Vm row lock: a power op claimed after the first
    read refuses the write, and the staged version is left inert."""
    from apps.orchestration.management.commands import vali_restage_userdata as cmd

    vm, _job = _m0_vm(vault)
    real = cmd.verdict
    calls = {"n": 0}

    def verdict_then_start(v: Vm):
        calls["n"] += 1
        if calls["n"] == 2:
            Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STARTING)
            v.refresh_from_db()
        return real(v)

    monkeypatch.setattr(cmd, "verdict", verdict_then_start)

    with pytest.raises(CommandError, match="refused at write time: power-op-in-flight:starting"):
        _run(tmp_path)
    # Re-decided BEFORE the Vault write, which happens under the same lock:
    # nothing is staged either (a §24 that took the VM meanwhile cannot have
    # erased the path ahead of a write it would then never sweep).
    assert len(vault.kv[_intake()]) == 1
    assert _record().userdata_vault_version == 1


def test_a_version_pruned_between_check_and_write_is_refused(
    vault, tmp_path, monkeypatch
) -> None:
    """Re-checked under the lock: a launch intake (which stages before it
    locks) may have pushed the checked version out of Vault's history."""
    _m0_vm(vault)
    _run(tmp_path)
    real_get = vault.get_kv
    reads = {"n": 0}

    def pruned_on_second_read(mount, path, *, version=None):
        reads["n"] += 1
        if path == _intake() and version == 1 and reads["n"] >= 2:
            raise vault_kv.VaultNotFound("vault-kv-get: not-found")
        return real_get(mount, path, version=version)

    monkeypatch.setattr(vault_kv, "get_kv", pruned_on_second_read)

    with pytest.raises(CommandError, match="refused at write time: no-such-version"):
        _run(tmp_path, "--to-version", "1", userdata=None)
    assert _record().userdata_vault_version == 2


# ── rollback ──────────────────────────────────────────────────────────────


def test_to_version_points_back_without_writing_or_decrypting(vault, tmp_path) -> None:
    _m0_vm(vault)
    _run(tmp_path)

    out = _run(tmp_path, "--to-version", "1", userdata=None)

    job = _record()
    assert (job.userdata_vault_path, job.userdata_vault_version) == (_intake(), 1)
    assert len(vault.kv[_intake()]) == 2
    assert vault.decrypts == []
    last = launch_record.userdata_restages(job)[-1]
    assert last["reason"] == "userdata-restage-rollback:fix k8s worker"
    assert last["new"]["userdata_vault_version"] == 1
    assert "rollback: --to-version 2" in out


@pytest.mark.parametrize(
    ("version", "reason"), [("7", "no-such-version"), ("1", "already-on-version")]
)
def test_to_version_refuses_a_missing_or_current_version(vault, tmp_path, version, reason) -> None:
    _m0_vm(vault)

    with pytest.raises(CommandError, match=reason):
        _run(tmp_path, "--to-version", version, userdata=None)
    _assert_untouched(vault)


def test_revert_last_restores_a_legacy_pointer(vault, tmp_path) -> None:
    """A VM launched before the intake path existed recorded its template at
    another leaf. A restage moves it onto `userdata-intake`; `--revert-last`
    puts the exact legacy pointer back."""
    _vm, job = _m0_vm(vault)
    legacy = f"{settings.VALI_VAULT_KV_PREFIX}/{VM}/userdata-pending"
    vault.put_kv("secret", legacy, b"#cloud-config\nv1\n")
    vault.put_kv("secret", legacy, ORIGINAL)  # a pre-wrapping plaintext template
    LaunchJob.objects.filter(pk=job.pk).update(
        userdata_vault_path=legacy, userdata_vault_version=2
    )
    out = _run(tmp_path)
    assert (_record().userdata_vault_path, _record().userdata_vault_version) == (_intake(), 2)
    assert "rollback: --revert-last" in out

    _run(tmp_path, "--revert-last", userdata=None)

    assert (_record().userdata_vault_path, _record().userdata_vault_version) == (legacy, 2)


@pytest.mark.parametrize(
    ("leaf", "value", "reason"),
    [
        # Pruned from Vault's history since: nothing to read back.
        ("userdata-pending", None, "no-such-version"),
        # The canonical copy, once wrapped, is under the KBS-only kek-<vm>.
        ("userdata", b"vault:v1:canonical", "canonical-copy-not-a-template"),
    ],
)
def test_revert_last_refuses_a_legacy_pointer_a_relaunch_cannot_read(
    vault, tmp_path, leaf, value, reason
) -> None:
    _vm, job = _m0_vm(vault)
    legacy = f"{settings.VALI_VAULT_KV_PREFIX}/{VM}/{leaf}"
    if value is not None:
        vault.put_kv("secret", legacy, value)
    LaunchJob.objects.filter(pk=job.pk).update(
        userdata_vault_path=legacy, userdata_vault_version=1
    )
    if value is None:
        vault.put_kv("secret", legacy, ORIGINAL)
    _run(tmp_path)
    if value is None:
        vault.kv[legacy] = []  # pruned

    with pytest.raises(CommandError, match=reason):
        _run(tmp_path, "--revert-last", userdata=None)
    assert _record().userdata_vault_path == _intake()
    assert vault.decrypts == []


def test_revert_last_refuses_when_the_pointer_moved(vault, tmp_path) -> None:
    _m0_vm(vault)
    _run(tmp_path)
    LaunchJob.objects.filter(vm_id=VM).update(userdata_vault_version=1)

    with pytest.raises(CommandError, match="pointer-moved-since-last-restage"):
        _run(tmp_path, "--revert-last", userdata=None)


# ── --relaunch ────────────────────────────────────────────────────────────


def test_relaunch_reboots_after_the_write(vault, tmp_path, monkeypatch) -> None:
    from apps.orchestration.services import power

    _m0_vm(vault)
    seen: list[tuple[str, int]] = []

    def reboot(vm: Vm) -> Vm:
        job = _record()
        seen.append((vm.vm_id, job.userdata_vault_version))
        return vm

    monkeypatch.setattr(power, "reboot_vm", reboot)

    out = _run(tmp_path, "--relaunch")

    # The relaunch runs only once the new pointer is committed.
    assert seen == [(VM, 2)]
    assert "relaunched" in out


def test_a_refused_relaunch_keeps_the_restage_and_says_so(vault, tmp_path, monkeypatch) -> None:
    from apps.orchestration.services import power

    _m0_vm(vault)

    def refuse(vm: Vm) -> Vm:
        raise power.PowerOpRefused("relaunch-rejected", "the miner did not accept")

    monkeypatch.setattr(power, "reboot_vm", refuse)

    with pytest.raises(CommandError, match="the restage stands.*relaunch-rejected"):
        _run(tmp_path, "--relaunch")
    assert _record().userdata_vault_version == 2


def test_no_relaunch_over_a_launch_that_took_the_vm_after_the_commit(
    vault, tmp_path, monkeypatch
) -> None:
    from apps.orchestration.management.commands import vali_restage_userdata as cmd
    from apps.orchestration.services import power

    _m0_vm(vault)
    rebooted: list[str] = []
    monkeypatch.setattr(power, "reboot_vm", lambda vm: rebooted.append(vm.vm_id) or vm)
    shadows = iter(["", "launch-job-in-flight"])
    monkeypatch.setattr(cmd, "_shadowed_by", lambda *a: next(shadows))

    with pytest.raises(CommandError, match="relaunch was NOT attempted.*launch-job-in-flight"):
        _run(tmp_path, "--relaunch")
    assert rebooted == []
    assert _record().userdata_vault_version == 2


def test_dry_run_and_relaunch_are_exclusive(vault, tmp_path) -> None:
    _m0_vm(vault)

    with pytest.raises(CommandError, match="mutually exclusive"):
        _run(tmp_path, "--dry-run", "--relaunch")
    _assert_untouched(vault)
