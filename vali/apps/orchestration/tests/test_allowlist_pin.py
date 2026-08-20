"""Manifest-rewrite tests for `allowlist_pin`.

The full sign+upload+rollout path is not exercised here — that lane
runs subprocesses (kbs-allowlist-tool, aws, kubectl) that we won't
build a fake double for. We pin the in-process pieces:

- `_bump_epoch_text` finds + increments exactly one top-level
  `epoch = N` line and refuses any other shape.
- `_append_entry` produces a chunk that round-trips through stdlib
  `tomllib` (Python 3.11+) as the same shape `dev-manifest.toml`
  ships.
- `_resolve_seed_hex` reads the signing seed (Vault in prod, file in test).
"""

from __future__ import annotations

import tomllib

import pytest
from django.conf import settings

from apps.orchestration.effects import EffectUnavailable
from apps.orchestration.services import allowlist_pin

# ── epoch bump ───────────────────────────────────────────────────────


def test_bump_epoch_increments_single_line() -> None:
    src = "schema = 1\nepoch = 28\n# trailing\n"
    new, n = allowlist_pin._bump_epoch_text(src)
    assert n == 29
    assert "epoch = 29" in new
    assert "epoch = 28" not in new
    # The rest of the file is preserved verbatim — important so the
    # in-tree TOML comments survive an in-place rewrite.
    assert "schema = 1\n" in new
    assert "# trailing" in new


def test_bump_epoch_floor_overrides_increment() -> None:
    # When the static manifest lags the installed HWM, the pin loop
    # passes a floor to climb past a just-rejected epoch.
    src = "schema = 1\nepoch = 28\n"
    new, n = allowlist_pin._bump_epoch_text(src, floor=33)
    assert n == 33
    assert "epoch = 33" in new


def test_bump_epoch_floor_below_increment_is_ignored() -> None:
    # A floor at or below `current + 1` must not lower the epoch.
    src = "schema = 1\nepoch = 28\n"
    new, n = allowlist_pin._bump_epoch_text(src, floor=20)
    assert n == 29
    assert "epoch = 29" in new


def test_bump_epoch_refuses_multiple_epoch_lines() -> None:
    src = "epoch = 1\n[[entries]]\nepoch = 2\n"  # malformed manifest
    from apps.orchestration.effects import EffectError

    with pytest.raises(EffectError, match="exactly one"):
        allowlist_pin._bump_epoch_text(src)


def test_bump_epoch_refuses_missing_epoch_line() -> None:
    src = "schema = 1\n[[entries]]\nmeasurement_hex = \"00\"\n"
    from apps.orchestration.effects import EffectError

    with pytest.raises(EffectError, match="exactly one"):
        allowlist_pin._bump_epoch_text(src)


def test_bump_epoch_ignores_indented_epoch_lines() -> None:
    """`  epoch = 99` inside a sub-table is not a top-level epoch — the
    regex anchors on column 0 to avoid a false positive."""
    src = "epoch = 5\n[some]\n  epoch = 99\n"
    new, n = allowlist_pin._bump_epoch_text(src)
    assert n == 6
    assert "epoch = 6\n" in new
    assert "  epoch = 99\n" in new  # untouched


# ── append entry ─────────────────────────────────────────────────────


_BASELINE_MANIFEST = (
    "schema = 1\n"
    "epoch = 5\n"
    "\n"
    "[[entries]]\n"
    'measurement_hex = "' + "a" * 96 + '"\n'
    'accepted_l1_kids_hex = ["6c31"]\n'
    'accepted_kbs_response_kids_hex = ["6b6273"]\n'
)


def test_append_entry_round_trips_through_tomllib() -> None:
    new = allowlist_pin._append_entry(
        _BASELINE_MANIFEST,
        measurement_hex="b" * 96,
        l1_kids=("6c31",),
        kbs_kids=("6b6273",),
    )
    parsed = tomllib.loads(new)
    entries = parsed.get("entries")
    assert isinstance(entries, list)
    assert len(entries) == 2, "the new entry must be the SECOND one"
    last = entries[-1]
    assert last["measurement_hex"] == "b" * 96
    assert last["accepted_l1_kids_hex"] == ["6c31"]
    assert last["accepted_kbs_response_kids_hex"] == ["6b6273"]


def test_append_entry_default_omits_class_key() -> None:
    """A default (tenant) pin must NOT write a `class` key — byte-identical
    to legacy entries + the golden dev.cose."""
    new = allowlist_pin._append_entry(
        _BASELINE_MANIFEST,
        measurement_hex="b" * 96,
        l1_kids=("6c31",),
        kbs_kids=("6b6273",),
    )
    parsed = tomllib.loads(new)
    assert "class" not in parsed["entries"][-1]


def test_append_entry_host_attestor_writes_class() -> None:
    """A host_attestor pin must write `class = "host_attestor"` so the KBS
    namespaces the measurement apart from every tenant image."""
    new = allowlist_pin._append_entry(
        _BASELINE_MANIFEST,
        measurement_hex="d" * 96,
        l1_kids=("6c31",),
        kbs_kids=("6b6273",),
        measurement_class=allowlist_pin.ALLOWLIST_CLASS_HOST_ATTESTOR,
    )
    parsed = tomllib.loads(new)
    assert parsed["entries"][-1]["class"] == "host_attestor"


def test_append_entry_rejects_unknown_class() -> None:
    from apps.orchestration.effects import EffectError

    with pytest.raises(EffectError):
        allowlist_pin._append_entry(
            _BASELINE_MANIFEST,
            measurement_hex="e" * 96,
            l1_kids=("6c31",),
            kbs_kids=("6b6273",),
            measurement_class="root",
        )


def test_append_entry_preserves_trailing_newline_shape() -> None:
    """The committed manifest ends with one trailing newline; we must
    not introduce a double-newline or strip the final one."""
    new = allowlist_pin._append_entry(
        _BASELINE_MANIFEST,
        measurement_hex="c" * 96,
        l1_kids=("6c31",),
        kbs_kids=("6b6273",),
    )
    assert new.endswith("\n")
    assert not new.endswith("\n\n\n"), "no triple-newline at EOF"


# ── signing-seed resolution (production = Vault) ─────────────────────


def test_resolve_seed_prefers_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    # When the Vault path is set it takes precedence over any file path.
    monkeypatch.setattr(
        settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH", "hippius-compute/vali/allowlist-root"
    )
    monkeypatch.setattr(settings, "VALI_VAULT_KV_MOUNT", "secret")
    seed = "ab" * 32
    captured: dict[str, str] = {}

    def fake_get_kv_field(mount: str, path: str, field: str) -> str:
        captured.update(mount=mount, path=path, field=field)
        return seed.upper()  # resolver lower-cases + validates

    monkeypatch.setattr(
        "apps.orchestration.services.vault_kv.get_kv_field", fake_get_kv_field
    )
    assert allowlist_pin._resolve_seed_hex() == seed
    assert captured == {
        "mount": "secret",
        "path": "hippius-compute/vali/allowlist-root",
        "field": "seed",
    }


def test_resolve_seed_rejects_malformed_vault_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.orchestration.effects import EffectError

    monkeypatch.setattr(
        settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH", "hippius-compute/vali/allowlist-root"
    )
    monkeypatch.setattr(
        "apps.orchestration.services.vault_kv.get_kv_field",
        lambda *a, **k: "not-hex",
    )
    with pytest.raises(EffectError, match="64 lower-case hex"):
        allowlist_pin._resolve_seed_hex()


def test_resolve_seed_file_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    seed = "cd" * 32
    f = tmp_path / "seed.hex"
    f.write_text(seed + "\n")
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH", "")
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_PATH", str(f))
    assert allowlist_pin._resolve_seed_hex() == seed


def test_resolve_seed_fails_closed_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH", "")
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_PATH", "")
    with pytest.raises(EffectUnavailable, match="no allowlist-root signing seed"):
        allowlist_pin._resolve_seed_hex()


# ── kbs-admin reload transport ───────────────────────────────────────


def test_reload_requires_kbs_admin_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", "")
    with pytest.raises(EffectUnavailable, match="VALI_KBS_ADMIN_URL"):
        allowlist_pin._reload_kbs_allowlist(b"\xaa\xbb")


def test_reload_posts_bytes_to_admin_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Happy path — the helper sends the COSE bytes verbatim, sets
    application/cbor, and returns silently on a 2xx."""
    import urllib.request

    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", "http://kbs-admin.test")

    captured: dict[str, object] = {}

    class _FakeResp:
        status = 200

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def _fake_urlopen(req: urllib.request.Request, **kwargs: object) -> _FakeResp:
        captured["url"] = req.full_url
        captured["data"] = req.data
        captured["content_type"] = req.get_header("Content-type")
        return _FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    payload = b"\xaa\xbb\xcc"
    allowlist_pin._reload_kbs_allowlist(payload)

    assert captured["url"] == "http://kbs-admin.test/v1/admin/allowlist/reload"
    assert captured["data"] == payload
    assert captured["content_type"] == "application/cbor"


def test_reload_surfaces_http_status_on_409(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 409 (install-rejected) from kbs-admin must raise EffectError
    with the status — the operator's clear signal that the signed body
    failed signature / schema / HWM."""
    import urllib.error
    import urllib.request

    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", "http://kbs-admin.test")

    def _fake_urlopen(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.HTTPError(
            "http://kbs-admin.test/v1/admin/allowlist/reload",
            409,
            "Conflict",
            {},  # type: ignore[arg-type]
            None,
        )

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    from apps.orchestration.effects import EffectError

    with pytest.raises(EffectError, match="status=409"):
        allowlist_pin._reload_kbs_allowlist(b"\xaa")


def test_reload_classifies_transport_failure_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A URL/transport failure (connection refused, DNS, timeout) must
    raise EffectUnavailable so the orchestrator's retry policy kicks
    in — distinct from a 409 / 415 (terminal config / signing fault)."""
    import urllib.error
    import urllib.request

    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", "http://kbs-admin.test")

    def _fake_urlopen(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    with pytest.raises(EffectUnavailable, match="peer unreachable"):
        allowlist_pin._reload_kbs_allowlist(b"\xaa")


# ── `_installed_epoch_floor` — track the live HWM, not the frozen manifest ──


def test_installed_epoch_floor_none_when_no_pins() -> None:
    """With an empty ledger the floor is `None` so the pin falls back to
    the manifest's own `epoch` line + retry loop (first-ever pin)."""
    import unittest.mock as mock

    with mock.patch(
        "apps.orchestration.models.MeasurementLedger.objects"
    ) as objs:
        objs.aggregate.return_value = {"mx": None}
        assert allowlist_pin._installed_epoch_floor() is None


def test_installed_epoch_floor_is_one_past_recorded_max() -> None:
    """The floor is one past the highest epoch vali has installed — so a
    manifest frozen many pins behind the HWM still lands the first
    attempt strictly above it (regression: the +1×N retry loop can never
    climb a gap larger than `_MAX_EPOCH_RETRIES`)."""
    import unittest.mock as mock

    with mock.patch(
        "apps.orchestration.models.MeasurementLedger.objects"
    ) as objs:
        objs.aggregate.return_value = {"mx": 2600000116}
        assert allowlist_pin._installed_epoch_floor() == 2600000117


def test_installed_epoch_floor_swallows_query_failure() -> None:
    """A DB error while reading the ledger must NOT fail the pin — the
    floor is an optimisation; `None` reverts to the manifest behaviour."""
    import unittest.mock as mock

    with mock.patch(
        "apps.orchestration.models.MeasurementLedger.objects"
    ) as objs:
        objs.aggregate.side_effect = RuntimeError("db down")
        assert allowlist_pin._installed_epoch_floor() is None
