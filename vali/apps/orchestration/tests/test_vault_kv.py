"""KV v2 client seams — the Check-And-Set write option and the typed
not-found, both load-bearing for the §7 first-write-wins lifecycle-key
staging (`launch._stage_lifecycle_key`).
"""

from __future__ import annotations

import base64
import io
import json
import threading
import time
import urllib.error
from unittest import mock

import pytest

from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.services import vault_kv
from apps.orchestration.services.vault_kv import VaultCasConflict, VaultNotFound


def _ok_put_response(version: int = 1) -> tuple[int, bytes]:
    return 200, json.dumps({"data": {"version": version}}).encode()


def test_put_kv_omits_options_without_cas() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=_ok_put_response()) as rt:
        vault_kv.put_kv("secret", "p/x", b"v")
    body = rt.call_args.kwargs["json_body"]
    assert "options" not in body


def test_put_kv_sends_cas_option() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=_ok_put_response()) as rt:
        out = vault_kv.put_kv("secret", "p/x", b"v", cas=0)
    body = rt.call_args.kwargs["json_body"]
    assert body["options"] == {"cas": 0}
    assert body["data"]["value"] == base64.b64encode(b"v").decode()
    assert out.version == 1


def test_put_kv_cas_conflict_is_typed() -> None:
    refusal = (
        400,
        b'{"errors":["check-and-set parameter did not match the current version"]}',
    )
    with mock.patch.object(vault_kv, "_round_trip", return_value=refusal):
        with pytest.raises(VaultCasConflict):
            vault_kv.put_kv("secret", "p/x", b"v", cas=0)


def test_put_kv_other_400_is_a_plain_effect_error() -> None:
    # A non-CAS 400 (or a CAS-phrased 400 with no cas requested) must NOT
    # masquerade as a benign lost-race.
    refusal = (400, b'{"errors":["something else"]}')
    with mock.patch.object(vault_kv, "_round_trip", return_value=refusal):
        with pytest.raises(EffectError) as exc_info:
            vault_kv.put_kv("secret", "p/x", b"v", cas=0)
    assert not isinstance(exc_info.value, VaultCasConflict)


def test_get_kv_404_is_typed_not_found() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=(404, b"{}")):
        with pytest.raises(VaultNotFound):
            vault_kv.get_kv("secret", "p/x", version=1)


def test_get_kv_pins_the_requested_version() -> None:
    payload = json.dumps({"data": {"data": {"value": base64.b64encode(b"seed").decode()}}}).encode()
    with mock.patch.object(vault_kv, "_round_trip", return_value=(200, payload)) as rt:
        got = vault_kv.get_kv("secret", "p/x", version=1)
    assert got == b"seed"
    assert rt.call_args.args[1].endswith("?version=1")


# ── KEK-HSM Phase 2 — Vault Transit wrap primitives ──────────────────


def test_transit_key_name_is_per_vm() -> None:
    assert vault_kv.transit_key_name("vm-abc") == "kek-vm-abc"


def test_transit_encrypt_returns_ciphertext_bytes() -> None:
    resp = (200, json.dumps({"data": {"ciphertext": "vault:v1:abc123"}}).encode())
    with mock.patch.object(vault_kv, "_round_trip", return_value=resp) as rt:
        ct = vault_kv.transit_encrypt("kek-vm-1", b"\x11" * 32)
    assert ct == b"vault:v1:abc123"
    method, path = rt.call_args.args[0], rt.call_args.args[1]
    assert method == "POST"
    assert path == "/v1/transit/encrypt/kek-vm-1"
    # the plaintext is sent base64 in the body, never in the path
    assert rt.call_args.kwargs["json_body"]["plaintext"] == base64.b64encode(b"\x11" * 32).decode()


def test_transit_encrypt_rejects_non_vault_ciphertext() -> None:
    resp = (200, json.dumps({"data": {"ciphertext": "not-a-vault-ct"}}).encode())
    with mock.patch.object(vault_kv, "_round_trip", return_value=resp):
        with pytest.raises(EffectError):
            vault_kv.transit_encrypt("kek-vm-1", b"\x00" * 32)


def test_transit_encrypt_non_2xx_is_effect_error() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=(403, b"denied")):
        with pytest.raises(EffectError):
            vault_kv.transit_encrypt("kek-vm-1", b"\x00" * 32)


def test_ensure_transit_key_posts_to_per_vm_key_path() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=(204, b"")) as rt:
        vault_kv.ensure_transit_key("kek-vm-1")
    assert rt.call_args.args[0] == "POST"
    assert rt.call_args.args[1] == "/v1/transit/keys/kek-vm-1"


def test_transit_datakey_wrapped_returns_ciphertext_only() -> None:
    # KEK-HSM Phase 4 — the `/wrapped/` datakey endpoint returns ONLY the
    # ciphertext; vali gets no plaintext, and hits the wrapped (not plaintext)
    # path so Vault's policy can withhold the raw key.
    resp = (200, json.dumps({"data": {"ciphertext": "vault:v1:gen999"}}).encode())
    with mock.patch.object(vault_kv, "_round_trip", return_value=resp) as rt:
        ct = vault_kv.transit_datakey_wrapped("kek-vm-1")
    assert ct == b"vault:v1:gen999"
    assert rt.call_args.args[0] == "POST"
    assert rt.call_args.args[1] == "/v1/transit/datakey/wrapped/kek-vm-1"


def test_transit_datakey_wrapped_refuses_a_leaked_plaintext() -> None:
    # Defence-in-depth: if a misconfig ever surfaced a plaintext on this path,
    # vali must REFUSE rather than touch it (the whole point is never-plaintext).
    resp = (
        200,
        json.dumps({"data": {"ciphertext": "vault:v1:x", "plaintext": "QUJD"}}).encode(),
    )
    with mock.patch.object(vault_kv, "_round_trip", return_value=resp):
        with pytest.raises(EffectError):
            vault_kv.transit_datakey_wrapped("kek-vm-1")


def test_transit_datakey_wrapped_non_2xx_is_effect_error() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=(403, b"denied")):
        with pytest.raises(EffectError):
            vault_kv.transit_datakey_wrapped("kek-vm-1")


# ── §24 golden crypto-erase — Transit-key + KV destroy primitives ────


def test_transit_key_delete_sets_deletion_allowed_then_deletes() -> None:
    # The DESTROY primitive: config `deletion_allowed=true`, THEN delete.
    # After this the wrapped per-VM KEK can never be unwrapped again.
    calls: list[tuple] = []

    def _rt(method: str, path: str, *, label: str, json_body=None):
        calls.append((method, path, json_body))
        if method == "POST":
            return 204, b""  # config accepted
        return 204, b""  # delete accepted

    with mock.patch.object(vault_kv, "_round_trip", side_effect=_rt):
        vault_kv.transit_key_delete("kek-vm-1")
    assert calls[0] == (
        "POST",
        "/v1/transit/keys/kek-vm-1/config",
        {"deletion_allowed": True},
    )
    assert calls[1] == ("DELETE", "/v1/transit/keys/kek-vm-1", None)


# On the transit routes a 404 NEVER means "no such key" (that is the 400
# above) — it means the ROUTE is wrong: engine unmounted/remounted, wrong
# namespace or VAULT_ADDR, or a proxy rewrite. The key is INTACT. Verbatim
# Vault 1.18.3 body with transit unmounted — note it CONTAINS "not found".
_VAULT_404_NO_ROUTE = (
    b'{"errors":["no handler for route "transit/keys/kek-vm-1/config". route entry not found."]}'
)


def test_transit_key_delete_fails_closed_on_404_wrong_route() -> None:
    # THE false-data-death guard: a misconfigured mount must NEVER be read as
    # "already erased". If it were, every VM decommissioned during the
    # misconfiguration would be tombstoned as crypto-erased with its KEK
    # fully intact.
    with mock.patch.object(vault_kv, "_round_trip", return_value=(404, _VAULT_404_NO_ROUTE)):
        with pytest.raises(EffectError):
            vault_kv.transit_key_delete("kek-vm-1")


def test_transit_key_delete_fails_closed_on_404_delete_wrong_route() -> None:
    def _rt(method: str, path: str, *, label: str, json_body=None):
        return (204, b"") if method == "POST" else (404, _VAULT_404_NO_ROUTE)

    with mock.patch.object(vault_kv, "_round_trip", side_effect=_rt):
        with pytest.raises(EffectError):
            vault_kv.transit_key_delete("kek-vm-1")


def test_transit_key_delete_fails_closed_on_a_normalised_route_error() -> None:
    # Defence against a proxy normalising the 404 to a 400: the body says
    # "route entry not found", which CONTAINS "not found" and would otherwise
    # match the missing-key branch. It must still raise.
    with mock.patch.object(vault_kv, "_round_trip", return_value=(400, _VAULT_404_NO_ROUTE)):
        with pytest.raises(EffectError):
            vault_kv.transit_key_delete("kek-vm-1")


# Real Vault does NOT 404 a missing Transit key — it answers 400, and the
# wording DIFFERS per endpoint. These are the verbatim bodies from Vault
# 1.18.3; note the config one does NOT contain the substring "not found",
# so matching only that phrase silently fails closed on the first call.
_VAULT_400_CONFIG_MISSING = b'{"errors":["no existing key named kek-vm-1 could be found"]}'
_VAULT_400_DELETE_MISSING = (
    b'{"errors":["error deleting policy kek-vm-1: could not delete key; not found"]}'
)


def test_transit_key_delete_idempotent_on_vault_400_missing_config() -> None:
    # An already-destroyed key ⇒ the config POST 400s with the "no existing
    # key" wording ⇒ SUCCESS (the erase goal is already met), no DELETE.
    with mock.patch.object(
        vault_kv, "_round_trip", return_value=(400, _VAULT_400_CONFIG_MISSING)
    ) as rt:
        vault_kv.transit_key_delete("kek-vm-1")
    assert rt.call_count == 1


def test_transit_key_delete_idempotent_on_vault_400_missing_delete() -> None:
    def _rt(method: str, path: str, *, label: str, json_body=None):
        if method == "POST":
            return 204, b""
        return 400, _VAULT_400_DELETE_MISSING

    with mock.patch.object(vault_kv, "_round_trip", side_effect=_rt):
        vault_kv.transit_key_delete("kek-vm-1")


def test_transit_key_delete_re_run_after_a_partial_erase_succeeds() -> None:
    # THE wedge case: the Transit destroy succeeded but the KV delete failed,
    # so the caller's idempotency guard was never recorded and the next tick
    # re-enters here with the key already gone. If that 400 were treated as a
    # failure the decommission would be stuck FOREVER with the data already
    # dead. It must succeed.
    with mock.patch.object(vault_kv, "_round_trip", return_value=(400, _VAULT_400_CONFIG_MISSING)):
        vault_kv.transit_key_delete("kek-vm-1")  # must not raise


def test_transit_key_delete_fails_closed_on_an_unrelated_400() -> None:
    # A 400 that is NOT a not-found (e.g. a malformed request) must still
    # fail closed — never mistaken for "already erased".
    with mock.patch.object(
        vault_kv, "_round_trip", return_value=(400, b'{"errors":["bad request"]}')
    ):
        with pytest.raises(EffectError):
            vault_kv.transit_key_delete("kek-vm-1")


def test_transit_key_delete_fails_closed_on_permission_denied() -> None:
    # A genuine erase FAILURE (permission denied) must raise — never a silent
    # "erased". The config 403 short-circuits before any delete.
    with mock.patch.object(vault_kv, "_round_trip", return_value=(403, b"denied")):
        with pytest.raises(EffectError):
            vault_kv.transit_key_delete("kek-vm-1")


def test_transit_key_delete_fails_closed_when_delete_denied() -> None:
    def _rt(method: str, path: str, *, label: str, json_body=None):
        return (204, b"") if method == "POST" else (403, b"denied")

    with mock.patch.object(vault_kv, "_round_trip", side_effect=_rt):
        with pytest.raises(EffectError):
            vault_kv.transit_key_delete("kek-vm-1")


def test_delete_kv_all_versions_deletes_metadata() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=(204, b"")) as rt:
        vault_kv.delete_kv_all_versions("secret", "p/vm-1/luks-kek")
    assert rt.call_args.args[0] == "DELETE"
    assert rt.call_args.args[1] == "/v1/secret/metadata/p/vm-1/luks-kek"


def test_delete_kv_all_versions_is_idempotent_on_404() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=(404, b"")):
        vault_kv.delete_kv_all_versions("secret", "p/vm-1/luks-kek")  # no raise


def test_delete_kv_all_versions_fails_closed_on_5xx() -> None:
    with mock.patch.object(vault_kv, "_round_trip", return_value=(500, b"boom")):
        with pytest.raises(EffectError):
            vault_kv.delete_kv_all_versions("secret", "p/vm-1/luks-kek")


# ─── jwt auth (M-k8sauth, #94) ──────────────────────────────────────────
#
# One test per CLAIM the jwt path makes, so a future edit that breaks any
# one of them fails a test rather than degrading silently in production.


@pytest.fixture(autouse=True)
def _clear_jwt_cache():
    """The token cache is module-global; leaking it across tests would
    make ordering decide outcomes."""
    vault_kv._JWT_CACHE["token"] = ""
    vault_kv._JWT_CACHE["expires_at"] = 0.0
    yield
    vault_kv._JWT_CACHE["token"] = ""
    vault_kv._JWT_CACHE["expires_at"] = 0.0


def _login_response(token: str = "hvs.jwtminted", lease: int = 3600) -> bytes:
    return json.dumps({"auth": {"client_token": token, "lease_duration": lease}}).encode()


@pytest.fixture
def jwt_env(settings, tmp_path, monkeypatch):
    """A configured jwt role + a readable projected SA token."""
    sa = tmp_path / "token"
    sa.write_text("the.sa.jwt")
    settings.VALI_VAULT_JWT_ROLE = "vali"
    settings.VALI_VAULT_JWT_AUTH_PATH = "jwt"
    settings.VALI_VAULT_JWT_TOKEN_PATH = str(sa)
    settings.VALI_VAULT_ADDR = "https://vault.example:8200"
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    return sa


def test_jwt_login_token_is_used_instead_of_static(jwt_env, monkeypatch):
    """CLAIM: with a role configured, the token comes from the login."""
    monkeypatch.setenv("VAULT_TOKEN", "hvs.static")
    with mock.patch.object(vault_kv, "_urlopen_login", return_value=_login_response()):
        assert vault_kv._token() == "hvs.jwtminted"


def test_jwt_token_is_cached_across_calls(jwt_env):
    """CLAIM: the token is cached — N calls do not mean N logins."""
    with mock.patch.object(vault_kv, "_urlopen_login", return_value=_login_response()) as login:
        for _ in range(5):
            vault_kv._token()
    assert login.call_count == 1


def test_jwt_cache_expires_at_two_thirds_of_the_lease(jwt_env):
    """CLAIM: refresh happens at 2/3 of the lease, not at expiry — a call
    starting just before the boundary must not land after it."""
    clock = {"now": 1_000.0}
    with (
        mock.patch.object(vault_kv.time, "monotonic", lambda: clock["now"]),
        mock.patch.object(
            vault_kv, "_urlopen_login", return_value=_login_response(lease=300)
        ) as login,
    ):
        vault_kv._token()
        clock["now"] += 199.0  # just inside 2/3 of 300 == 200
        vault_kv._token()
        assert login.call_count == 1
        clock["now"] += 2.0  # now past it
        vault_kv._token()
        assert login.call_count == 2


def test_force_refresh_bypasses_the_cache(jwt_env):
    """CLAIM: force_refresh re-logs in even on a warm cache."""
    with mock.patch.object(vault_kv, "_urlopen_login", return_value=_login_response()) as login:
        vault_kv._token()
        vault_kv._token(force_refresh=True)
    assert login.call_count == 2


def test_zero_lease_does_not_relogin_on_every_call(jwt_env):
    """CLAIM: a lease Vault reports as 0 is floored, so the cache still
    HITS.

    Without the floor `expires_at` lands exactly on `now`, the cache never
    hits, and vali logs in again on every single Vault call — a hot loop
    against Vault. (The first version of this test asserted the opposite
    property and a mutation removing the floor did not kill it.)
    """
    clock = {"now": 1_000.0}
    with (
        mock.patch.object(vault_kv.time, "monotonic", lambda: clock["now"]),
        mock.patch.object(
            vault_kv, "_urlopen_login", return_value=_login_response(lease=0)
        ) as login,
    ):
        vault_kv._token()
        clock["now"] += 1.0
        vault_kv._token()
        assert login.call_count == 1, "a 0 lease must not re-login per call"
        # …and it is still bounded: past the floor it does refresh.
        clock["now"] += vault_kv._JWT_FALLBACK_LEASE_S
        vault_kv._token()
        assert login.call_count == 2


def test_403_with_a_cached_jwt_retries_once_with_a_fresh_token(jwt_env):
    """CLAIM: an expired cached token (403) is re-minted and the call
    replayed — exactly once."""
    with (
        mock.patch.object(vault_kv, "_urlopen_login", return_value=_login_response()),
        mock.patch.object(
            vault_kv, "_round_trip_once", side_effect=[(403, b"denied"), (200, b"ok")]
        ) as once,
    ):
        vault_kv._JWT_CACHE["token"] = "hvs.stale"
        vault_kv._JWT_CACHE["expires_at"] = vault_kv.time.monotonic() + 3600
        status, body = vault_kv._round_trip("GET", "/v1/x", label="l")
    assert (status, body) == (200, b"ok")
    assert once.call_count == 2
    assert once.call_args_list[1].kwargs["force_refresh"] is True


def test_persistent_403_is_returned_and_not_retried_forever(jwt_env):
    """CLAIM: a GENUINE denial (e.g. luks-kek) still 403s and costs at
    most one extra attempt — no loop."""
    with (
        mock.patch.object(vault_kv, "_urlopen_login", return_value=_login_response()),
        mock.patch.object(vault_kv, "_round_trip_once", return_value=(403, b"denied")) as once,
    ):
        vault_kv._JWT_CACHE["token"] = "hvs.live"
        vault_kv._JWT_CACHE["expires_at"] = vault_kv.time.monotonic() + 3600
        status, _ = vault_kv._round_trip("GET", "/v1/x", label="l")
    assert status == 403
    assert once.call_count == 2


def test_403_on_the_static_path_does_not_retry(settings, monkeypatch):
    """CLAIM: the retry is jwt-specific — a static-token deployment keeps
    exactly one round trip per call."""
    settings.VALI_VAULT_JWT_ROLE = ""
    monkeypatch.setenv("VAULT_TOKEN", "hvs.static")
    with mock.patch.object(vault_kv, "_round_trip_once", return_value=(403, b"denied")) as once:
        status, _ = vault_kv._round_trip("GET", "/v1/x", label="l")
    assert status == 403
    assert once.call_count == 1


def test_login_failure_falls_back_to_static_and_logs_error(jwt_env, monkeypatch):
    """CLAIM: during the transition a broken login DEGRADES to the static
    token — and says so loudly, so it cannot hide.

    Asserts on the logger call rather than via caplog: the project sets
    `propagate: False` on the `apps` logger, so caplog's root handler
    never sees the record and the assertion would fail for a reason that
    has nothing to do with this code.
    """
    monkeypatch.setenv("VAULT_TOKEN", "hvs.static")
    with (
        mock.patch.object(vault_kv, "_jwt_login", side_effect=EffectUnavailable("boom")),
        mock.patch.object(vault_kv.log, "error") as logged,
    ):
        assert vault_kv._token() == "hvs.static"
    assert logged.call_count == 1
    assert "jwt login failed" in logged.call_args.args[0]


def test_login_failure_without_a_static_token_raises(jwt_env, monkeypatch):
    """CLAIM: with nothing to fall back to it fails CLOSED, rather than
    issuing an unauthenticated request."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with mock.patch.object(vault_kv, "_jwt_login", side_effect=EffectUnavailable("boom")):
        with pytest.raises(EffectUnavailable):
            vault_kv._token()


def test_missing_sa_token_file_is_not_fatal_off_cluster(jwt_env, monkeypatch):
    """CLAIM: off-cluster (operator CLI) the projected token is absent and
    the static path still works."""
    monkeypatch.setenv("VAULT_TOKEN", "hvs.static")
    jwt_env.unlink()
    assert vault_kv._token() == "hvs.static"


# ─── P4: the failure NAMES its precondition ─────────────────────────────
#
# "vault-jwt-login: no projected SA token" ran in production for days on
# the full synthetic monitor and said nothing: not the path, not the role,
# not whether the file was absent or empty, and an audience mismatch read
# identically. One test per fact the message must carry.


def test_absent_token_names_the_path_it_looked_at(jwt_env, monkeypatch):
    """CLAIM: the error names the exact filesystem path — the first thing
    the reader needs, and the thing that identifies a missing volumeMount."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    jwt_env.unlink()
    with pytest.raises(EffectUnavailable) as caught:
        vault_kv._token()
    assert str(jwt_env) in str(caught.value)


def test_absent_token_names_the_role_and_login_mount(jwt_env, monkeypatch):
    """CLAIM: the error names the identity being presented (role + login
    mount), so a role/mount drift is diagnosable from the message alone."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    jwt_env.unlink()
    with pytest.raises(EffectUnavailable) as caught:
        vault_kv._token()
    msg = str(caught.value)
    assert "role='vali'" in msg
    assert "auth/jwt/login" in msg


def test_absent_token_names_the_missing_pod_spec_precondition(jwt_env, monkeypatch):
    """CLAIM: the error says WHAT IS MISSING — a projected
    `serviceAccountToken` volume mounted at the token path's directory.
    That is the actual repair, and naming it is the difference between a
    5-minute fix and reading the source."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    jwt_env.unlink()
    with pytest.raises(EffectUnavailable) as caught:
        vault_kv._token()
    msg = str(caught.value)
    assert "serviceAccountToken" in msg
    assert str(jwt_env.parent) in msg
    assert "bound_audiences" in msg


def test_empty_token_file_is_distinguished_from_an_absent_one(jwt_env, monkeypatch):
    """CLAIM: mounted-but-empty is a DIFFERENT fault (a broken projection,
    not a missing mount) and must not be reported as "no token"."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    jwt_env.write_text("   \n")
    with pytest.raises(EffectUnavailable) as caught:
        vault_kv._token()
    assert "EMPTY" in str(caught.value)


def test_unconfigured_token_path_is_its_own_message(jwt_env, monkeypatch, settings):
    """CLAIM: an unset `VALI_VAULT_JWT_TOKEN_PATH` names the SETTING, not a
    path — there is no path to name, and reporting `''` would be a riddle."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    settings.VALI_VAULT_JWT_TOKEN_PATH = ""
    with pytest.raises(EffectUnavailable) as caught:
        vault_kv._token()
    assert "VALI_VAULT_JWT_TOKEN_PATH is not configured" in str(caught.value)


def test_login_rejection_names_the_audience_that_was_presented(jwt_env):
    """CLAIM: an audience that does not match the role's `bound_audiences`
    is an HTTP 400 that otherwise reads like a broken deployment. The
    message carries the `aud` claim we actually sent."""
    claims = base64.urlsafe_b64encode(json.dumps({"aud": ["api"]}).encode()).decode().rstrip("=")
    jwt_env.write_text(f"hdr.{claims}.sig")
    err = urllib.error.HTTPError(
        "https://vault.example/v1/auth/jwt/login",
        400,
        "Bad Request",
        {},  # type: ignore[arg-type]
        io.BytesIO(b'{"errors":["audience claim does not match"]}'),
    )
    with mock.patch.object(vault_kv, "_urlopen_login", side_effect=err):
        with pytest.raises(EffectUnavailable) as caught:
            vault_kv._jwt_login()
    msg = str(caught.value)
    assert "aud='api'" in msg
    assert "400" in msg


def test_audience_diagnostics_leak_nothing_but_the_aud_claim(jwt_env):
    """CLAIM: §20 — the diagnostic reads EXACTLY ONE claim. A token whose
    payload also carries a secret-shaped claim must not surface it, and the
    signature/token bytes must never appear."""
    payload = {"aud": ["vault"], "sub": "system:serviceaccount:vali:vali", "secret": "s3kr3t"}
    claims = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = f"hdr.{claims}.SIGNATUREBYTES"
    jwt_env.write_text(token)
    err = urllib.error.HTTPError(
        "https://vault.example/v1/auth/jwt/login",
        403,
        "Forbidden",
        {},  # type: ignore[arg-type]
        io.BytesIO(b"{}"),
    )
    with mock.patch.object(vault_kv, "_urlopen_login", side_effect=err):
        with pytest.raises(EffectUnavailable) as caught:
            vault_kv._jwt_login()
    msg = str(caught.value)
    assert "aud='vault'" in msg
    assert "s3kr3t" not in msg
    assert "SIGNATUREBYTES" not in msg
    assert token not in msg


def test_a_non_jwt_credential_reports_unreadable_not_a_crash(jwt_env):
    """CLAIM: the diagnostic is best-effort — an opaque credential must
    degrade to `unreadable`, never raise inside the error path (which would
    replace a legible failure with a traceback)."""
    jwt_env.write_text("not-a-jwt-at-all")
    err = urllib.error.HTTPError(
        "https://vault.example/v1/auth/jwt/login",
        400,
        "Bad Request",
        {},  # type: ignore[arg-type]
        io.BytesIO(b"{}"),
    )
    with mock.patch.object(vault_kv, "_urlopen_login", side_effect=err):
        with pytest.raises(EffectUnavailable) as caught:
            vault_kv._jwt_login()
    assert "aud='unreadable'" in str(caught.value)


def test_no_role_configured_keeps_the_static_path_untouched(settings, monkeypatch):
    """CLAIM: unset role ⇒ behaviour identical to before this change."""
    settings.VALI_VAULT_JWT_ROLE = ""
    monkeypatch.setenv("VAULT_TOKEN", "hvs.static")
    assert vault_kv._token() == "hvs.static"


def test_login_error_never_echoes_the_submitted_jwt(jwt_env):
    """CLAIM: §20 — a login failure reports the status only. Some Vault
    versions echo the submitted JWT in the error body; it must not reach
    a log or an exception message."""
    err = urllib.error.HTTPError(
        "https://vault.example/v1/auth/jwt/login",
        400,
        "Bad Request",
        {},  # type: ignore[arg-type]
        io.BytesIO(b'{"errors":["invalid jwt the.sa.jwt"]}'),
    )
    with mock.patch.object(vault_kv, "_urlopen_login", side_effect=err):
        with pytest.raises(EffectUnavailable) as caught:
            vault_kv._jwt_login()
    assert "the.sa.jwt" not in str(caught.value)
    assert "400" in str(caught.value)


def test_concurrent_first_calls_mint_only_one_token(jwt_env):
    """CLAIM: the lock stops a cold cache from minting N tokens under N
    threads — every extra one would leak (never revoked, just expiring)."""

    def slow_login(*_a, **_k):
        # Widen the window a serialising lock must close.
        time.sleep(0.05)
        return _login_response()

    with mock.patch.object(vault_kv, "_urlopen_login", side_effect=slow_login) as login:
        threads = [threading.Thread(target=vault_kv._token) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

    assert login.call_count == 1
