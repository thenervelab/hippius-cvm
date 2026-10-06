"""Full-e2e VERIFY stages — crypto-erase (transit-key death + KEK-HSM
403/404 acceptance), the NetBird green path, the real-product userdata,
and the shipped timeout defaults.

These cover the 5 live-run fixes that let a full-tier run go GREEN on a
healthy system without weakening the no-leak guarantee.
"""

from __future__ import annotations

import pytest
from django.conf import settings

from apps.lifecycle.models import VmState
from apps.orchestration.services import vault_kv
from apps.orchestration.services.vault_kv import EffectError, VaultNotFound
from apps.orchestration.tests.factories import make_vm
from apps.synthetic import e2e

# ── FIX #2: crypto-erase verify ───────────────────────────────────────


@pytest.mark.django_db
def test_verify_crypto_erase_green_via_transit_death_and_kv_404(monkeypatch) -> None:
    """Strongest signal: the transit key is destroyed AND the KV 404s."""
    make_vm("synmon-erase-ok", state=VmState.DESTROYED)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: True)

    def kv_404(mount, path):
        raise VaultNotFound("vault-kv-get:secret: not-found")

    monkeypatch.setattr(vault_kv, "get_kv", kv_404)
    assert e2e._verify_crypto_erase("synmon-erase-ok", kek_was_alive=True) is True


@pytest.mark.django_db
def test_verify_crypto_erase_accepts_kv_403_read_denied(monkeypatch) -> None:
    """KEK-HSM denies vali READ on luks-kek → the KV read 403s even on a
    SUCCESSFUL erase. A 403 must be treated as gone/denied, NOT a failure
    — the transit-key-death signal is what proves the erase."""
    make_vm("synmon-erase-403", state=VmState.DESTROYED)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: True)

    def kv_403(mount, path):
        # 403 is the EXPECTED shape for `luks-kek` (vali is read-denied by
        # KEK-HSM design); the userdata paths are readable, so a 404 there
        # is an observation this token can actually make and is required.
        if path.endswith("/luks-kek"):
            raise EffectError("vault-kv-get:secret: vault returned HTTP 403")
        raise VaultNotFound("gone")

    monkeypatch.setattr(vault_kv, "get_kv", kv_403)
    # No raise ⇒ 403 accepted as not-recoverable-by-vali.
    assert e2e._verify_crypto_erase("synmon-erase-403", kek_was_alive=True) is True


@pytest.mark.django_db
def test_verify_crypto_erase_fails_when_the_userdata_key_survives(monkeypatch) -> None:
    """Two per-VM Transit keys now: `kek-<vm_id>` opens the disk KEK and
    the canonical userdata, `ud-<vm_id>` opens vali's working copy of the
    same cloud-init. A surviving `ud-*` leaves that copy decryptable from
    any Vault backup, so probing only the first would certify an erase
    that did not happen."""
    make_vm("synmon-erase-udkey", state=VmState.DESTROYED)
    monkeypatch.setattr(
        vault_kv, "transit_key_gone", lambda name: name.startswith("kek-")
    )
    monkeypatch.setattr(
        vault_kv, "get_kv", lambda m, p: (_ for _ in ()).throw(VaultNotFound("gone"))
    )
    with pytest.raises(e2e.ApiError, match="ud-synmon-erase-udkey"):
        e2e._verify_crypto_erase("synmon-erase-udkey", kek_was_alive=True)


@pytest.mark.django_db
def test_verify_crypto_erase_fails_when_transit_key_alive(monkeypatch) -> None:
    """The KEK is NOT cryptographically dead while the transit key exists
    — even if the KV blob happens to 404, the wrapped KEK stays
    unwrappable-recoverable, so the stage MUST fail."""
    make_vm("synmon-erase-alive", state=VmState.DESTROYED)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: False)
    monkeypatch.setattr(vault_kv, "get_kv", lambda m, p: (_ for _ in ()).throw(VaultNotFound("x")))
    with pytest.raises(e2e.ApiError, match="transit key"):
        e2e._verify_crypto_erase("synmon-erase-alive", kek_was_alive=True)


@pytest.mark.django_db
def test_verify_crypto_erase_fails_when_kv_still_readable(monkeypatch) -> None:
    """A clean 2xx KV read means the wrapped-KEK ciphertext is still
    present → NOT erased."""
    make_vm("synmon-erase-kv", state=VmState.DESTROYED)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: True)
    monkeypatch.setattr(vault_kv, "get_kv", lambda m, p: b"vault:v1:stillhere")
    with pytest.raises(e2e.ApiError, match="still readable"):
        e2e._verify_crypto_erase("synmon-erase-kv", kek_was_alive=True)


@pytest.mark.django_db
def test_verify_crypto_erase_fails_on_non_403_kv_error(monkeypatch) -> None:
    """A 5xx (not 403/404) is a real Vault failure, not proof of erase."""
    make_vm("synmon-erase-5xx", state=VmState.DESTROYED)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: True)

    def kv_500(mount, path):
        raise EffectError("vault-kv-get:secret: vault returned HTTP 500")

    monkeypatch.setattr(vault_kv, "get_kv", kv_500)
    with pytest.raises(e2e.ApiError, match="not 404/403"):
        e2e._verify_crypto_erase("synmon-erase-5xx", kek_was_alive=True)


@pytest.mark.django_db
def test_verify_crypto_erase_rejects_a_userdata_403(monkeypatch) -> None:
    """On `luks-kek` a 403 is expected and accepted (vali is read-denied
    there by design). On the userdata paths vali HAS read, so a 403 means
    the ACL changed — not that the secret is gone. Accepting it would let
    an ACL regression certify an erase nobody performed."""
    make_vm("synmon-erase-ud403", state=VmState.DESTROYED)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: True)

    def kv(mount, path):
        if path.endswith("/luks-kek"):
            raise VaultNotFound("gone")
        raise EffectError("vault-kv-get:secret: vault returned HTTP 403")

    monkeypatch.setattr(vault_kv, "get_kv", kv)
    with pytest.raises(e2e.ApiError, match="did not 404"):
        e2e._verify_crypto_erase("synmon-erase-ud403", kek_was_alive=True)


@pytest.mark.django_db
def test_verify_crypto_erase_fails_when_the_userdata_survived(monkeypatch) -> None:
    """The half of this check with real discriminating power: vali is
    read-DENIED on `luks-kek`, so a 403 there is accepted and proves
    nothing about deletion — but it CAN read the userdata paths (the §6
    re-mint does). A clean read means a destroyed VM's cloud-init — SSH
    keys, API tokens, the NetBird enrolment secret — outlived it, which
    is exactly what §24 used to leave behind."""
    make_vm("synmon-erase-ud", state=VmState.DESTROYED)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: True)

    def kv(mount, path):
        if path.endswith("/luks-kek"):
            raise VaultNotFound("gone")
        return b"#cloud-config\nssh_authorized_keys: [...]"

    monkeypatch.setattr(vault_kv, "get_kv", kv)
    with pytest.raises(e2e.ApiError, match="outlived it"):
        e2e._verify_crypto_erase("synmon-erase-ud", kek_was_alive=True)


@pytest.mark.django_db
def test_verify_crypto_erase_checks_both_userdata_paths(monkeypatch) -> None:
    """Both the canonical blob and the intake transport copy. The
    transport copy is the one the launch API writes and reboot-recovery
    reads, and it is the one §24 never deleted."""
    make_vm("synmon-erase-ud2", state=VmState.DESTROYED)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: True)
    read: list[str] = []

    def kv(mount, path):
        read.append(path)
        raise VaultNotFound("gone")

    monkeypatch.setattr(vault_kv, "get_kv", kv)
    assert e2e._verify_crypto_erase("synmon-erase-ud2", kek_was_alive=True) is True
    assert any(p.endswith("/userdata") for p in read), read
    assert any(p.endswith("/userdata-pending") for p in read), read


@pytest.mark.django_db
def test_verify_crypto_erase_fails_when_vm_not_destroyed(monkeypatch) -> None:
    make_vm("synmon-erase-live-vm", state=VmState.ACTIVE)
    monkeypatch.setattr(vault_kv, "transit_key_gone", lambda name: True)
    monkeypatch.setattr(vault_kv, "get_kv", lambda m, p: (_ for _ in ()).throw(VaultNotFound("x")))
    with pytest.raises(e2e.ApiError, match="expected destroyed"):
        e2e._verify_crypto_erase("synmon-erase-live-vm", kek_was_alive=True)


# ── FIX #2b: the transit_key_gone probe status mapping ────────────────


@pytest.mark.parametrize(
    "status,raw,expected",
    [
        # A missing Transit key is a 400 with a not-found body, NOT a 404.
        (400, b'{"errors":["encryption key not found"]}', True),  # key gone
        (200, b'{"data":{"ciphertext":"vault:v1:x"}}', False),  # alive
    ],
)
def test_transit_key_gone_status_mapping(monkeypatch, status, raw, expected) -> None:
    monkeypatch.setattr(vault_kv, "_round_trip", lambda *a, **k: (status, raw))
    assert vault_kv.transit_key_gone("kek-synmon-1") is expected


@pytest.mark.parametrize(
    "status,raw",
    [
        # A 404 on this route means the ROUTE is wrong (transit unmounted /
        # wrong namespace / proxy rewrite), NOT that the key is gone — the key
        # is intact, so a "crypto-erase VERIFIED" assertion must never pass on
        # it. The body also contains "not found", so the 400-normalised form
        # is covered too.
        (
            404,
            b'{"errors":["no handler for route "transit/datakey/wrapped/'
            b'kek-synmon-1". route entry not found."]}',
        ),
        (
            400,
            b'{"errors":["no handler for route "transit/datakey/wrapped/'
            b'kek-synmon-1". route entry not found."]}',
        ),
    ],
)
def test_transit_key_gone_fails_closed_on_a_wrong_route(monkeypatch, status, raw) -> None:
    monkeypatch.setattr(vault_kv, "_round_trip", lambda *a, **k: (status, raw))
    with pytest.raises(EffectError):
        vault_kv.transit_key_gone("kek-synmon-1")


def test_transit_key_gone_raises_on_403(monkeypatch) -> None:
    """A denied probe must fail loud, never be read as 'gone'."""
    monkeypatch.setattr(vault_kv, "_round_trip", lambda *a, **k: (403, b"denied"))
    with pytest.raises(EffectError):
        vault_kv.transit_key_gone("kek-synmon-1")


def test_transit_key_gone_raises_on_ambiguous_400(monkeypatch) -> None:
    """A 400 that is NOT the not-found error is ambiguous — fail closed
    rather than falsely report the key destroyed."""
    monkeypatch.setattr(
        vault_kv, "_round_trip", lambda *a, **k: (400, b'{"errors":["bad request"]}')
    )
    with pytest.raises(EffectError):
        vault_kv.transit_key_gone("kek-synmon-1")


# ── FIX #1: NetBird green path + real-product userdata ────────────────


@pytest.mark.django_db
def test_netbird_stage_green_when_ip_assigned(monkeypatch) -> None:
    monkeypatch.setattr(e2e, "_sleep", lambda *_: None)
    vm = make_vm("synmon-nb-ok", state=VmState.ACTIVE)
    vm.netbird_ip = "100.64.0.40"
    vm.save(update_fields=["netbird_ip"])
    assert e2e._await_netbird("synmon-nb-ok", deadline=e2e._now() + 30) is True


def test_default_userdata_is_real_netbird_bringup(monkeypatch, blessed_ubuntu) -> None:
    """The default userdata mirrors the REAL product template (setup-key
    FILE + management URL), not the bare `netbird up --setup-key` that
    never enrolled the golden image."""
    from apps.orchestration.services import launch

    monkeypatch.setattr(settings, "VALI_SYNTHETIC_USERDATA", "")
    body = e2e.build_launch_body("ubuntu", "synmon-ubuntu-1")
    ud = body["userdata"]
    assert "{{NETBIRD_SETUP_KEY}}" in ud
    assert "{{NETBIRD_HOSTNAME}}" in ud
    assert "--setup-key-file=" in ud
    assert "--management-url=https://vpn.hippius.network" in ud
    # It passes the SAME validation the real launch path enforces.
    assert (
        launch.check_netbird_userdata(
            ud.encode("utf-8"),
            enable=True,
            hostname_template="hippius-tenant-{vm_id}",
            vm_id="synmon-ubuntu-1",
        )
        is None
    )


# ── FIX #3 / #4: shipped timeout defaults ─────────────────────────────


def test_timeout_defaults_cover_golden_forced_reclaim() -> None:
    # Golden §24 decommission ~630s live → timeout must clear it.
    assert settings.VALI_SYNTHETIC_DECOMMISSION_TIMEOUT_S >= 720
    # Whole-run budget bumped for the golden path.
    assert settings.VALI_SYNTHETIC_E2E_BUDGET_S >= 1800
    # A rotational-disk host needs ~340 s to reach `running`.
    assert settings.VALI_SYNTHETIC_BOOT_TIMEOUT_S >= 600
    # Launch + boot + decommission caps must fit inside the whole-run budget.
    assert settings.VALI_SYNTHETIC_E2E_BUDGET_S > (
        settings.VALI_SYNTHETIC_LAUNCH_TIMEOUT_S
        + settings.VALI_SYNTHETIC_BOOT_TIMEOUT_S
        + settings.VALI_SYNTHETIC_DECOMMISSION_TIMEOUT_S
    )
    # Launch POST synchronously provisions the golden KEK → generous HTTP.
    assert settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S >= 60
    # The reaper must NEVER kill a healthy in-flight run: reap age must
    # exceed the worst-case run lifetime (budget + a fresh teardown).
    assert settings.VALI_SYNTHETIC_REAP_AGE_S > (
        settings.VALI_SYNTHETIC_E2E_BUDGET_S + settings.VALI_SYNTHETIC_DECOMMISSION_TIMEOUT_S
    )


def _run_enrol_guard(tmp_path, journal: str) -> tuple[int, str]:
    """Execute the synthetic userdata's REAL enrol command (the `sh -c`
    runcmd entry, parsed out of the YAML) with fake `journalctl` / `netbird`
    on PATH. Returns (exit code, the netbird invocations recorded)."""
    import os
    import subprocess

    import yaml

    runcmd = yaml.safe_load(e2e._DEFAULT_USERDATA)["runcmd"]
    enrol = next(c for c in runcmd if isinstance(c, list) and c[:2] == ["sh", "-c"])
    script = enrol[2].replace("{{NETBIRD_HOSTNAME}}", "hippius-tenant-synmon-x")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "netbird.calls"
    (bindir / "journalctl").write_text(f"#!/bin/sh\ncat <<'J'\n{journal}\nJ\n")
    (bindir / "netbird").write_text(f'#!/bin/sh\necho "$@" >> {calls}\n')
    for f in ("journalctl", "netbird"):
        (bindir / f).chmod(0o755)
    # /dev/console is not writable in CI; point the redirect at a file.
    script = script.replace("> /dev/console", f"> {tmp_path / 'console'}")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    proc = subprocess.run(["sh", "-c", script], env=env, check=False)
    return proc.returncode, calls.read_text() if calls.exists() else ""


def test_enrol_runs_on_a_clean_boot(tmp_path) -> None:
    _, calls = _run_enrol_guard(tmp_path, "systemd[1]: Reached target multi-user.target")
    assert "up" in calls, "a boot with no ordering cycle must enrol NetBird"
    assert "--setup-key-file=/var/lib/cloud/seed/nocloud/netbird-setup-key" in calls
    assert "--management-url=https://vpn.hippius.network" in calls
    assert "--hostname=hippius-tenant-synmon-x" in calls


def test_enrol_is_withheld_when_the_boot_has_an_ordering_cycle(tmp_path) -> None:
    journal = (
        "systemd[1]: sysinit.target: Found ordering cycle: cryptsetup.target/start "
        "after hippius-eol-sign.service/start after network-online.target/start\n"
        "systemd[1]: sysinit.target: Job cryptsetup.target/start deleted to break "
        "ordering cycle starting with sysinit.target/start"
    )
    _, calls = _run_enrol_guard(tmp_path, journal)
    assert calls == "", (
        "an ordering cycle must withhold the enrol so the netbird stage fails "
        "and the monitor alerts, even when systemd sacrificed a harmless job"
    )
    assert "ordering cycle" in (tmp_path / "console").read_text()


def test_enrol_guard_reads_only_systemd_messages() -> None:
    # A plain `journalctl -b` also holds command lines containing the phrase
    # (the guard itself if the runcmd gets logged, an operator's sudo), so the
    # probe would trip on itself. Only PID 1's messages are systemd's verdict.
    import yaml

    runcmd = yaml.safe_load(e2e._DEFAULT_USERDATA)["runcmd"]
    enrol = next(c for c in runcmd if isinstance(c, list) and c[:2] == ["sh", "-c"])
    assert "journalctl -b _PID=1 " in enrol[2]
