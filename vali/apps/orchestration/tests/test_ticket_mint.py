"""Seed-resolution tests for `ticket_mint`.

The full subprocess mint path is not exercised here — it shells out to
the Rust `hippius-order-ticket-mint` binary, which is not built in the
test image. We pin the in-process `_resolve_l1_seed` precedence:

- PRODUCTION: `VALI_L1_SIGNING_KEY_VAULT_PATH` → fetch the `seed` field
  from Vault and return a validated 64-hex string (lower-cased).
- TEST/dev: a `VALI_L1_SIGNING_KEY_PATH` file the Rust binary opens
  itself ⇒ the resolver returns `None` (no bytes read in Python).
- Neither set ⇒ fail closed.

Mirrors `test_allowlist_pin.py::test_resolve_seed_*`.
"""

from __future__ import annotations

import pytest
from django.conf import settings

from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.services import ticket_mint


def test_resolve_l1_seed_prefers_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    # When the Vault path is set it takes precedence over any file path.
    monkeypatch.setattr(
        settings,
        "VALI_L1_SIGNING_KEY_VAULT_PATH",
        "hippius-compute/vali/l1-order-ticket",
    )
    monkeypatch.setattr(settings, "VALI_VAULT_KV_MOUNT", "secret")
    # A file path set too — must be ignored in favor of Vault.
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_PATH", "/should/be/ignored")
    seed = "ab" * 32
    captured: dict[str, str] = {}

    def fake_get_kv_field(mount: str, path: str, field: str) -> str:
        captured.update(mount=mount, path=path, field=field)
        return seed.upper()  # resolver lower-cases + validates

    monkeypatch.setattr(
        "apps.orchestration.services.vault_kv.get_kv_field", fake_get_kv_field
    )
    assert ticket_mint._resolve_l1_seed() == seed
    assert captured == {
        "mount": "secret",
        "path": "hippius-compute/vali/l1-order-ticket",
        "field": "seed",
    }


def test_resolve_l1_seed_rejects_malformed_vault_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        settings,
        "VALI_L1_SIGNING_KEY_VAULT_PATH",
        "hippius-compute/vali/l1-order-ticket",
    )
    monkeypatch.setattr(
        "apps.orchestration.services.vault_kv.get_kv_field",
        lambda *a, **k: "not-hex",
    )
    with pytest.raises(EffectError, match="64 lower-case hex"):
        ticket_mint._resolve_l1_seed()


def test_resolve_l1_seed_file_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # No Vault path ⇒ fall back to a file the Rust binary opens itself.
    # The resolver returns None (it never reads the bytes).
    f = tmp_path / "seed.hex"
    f.write_text("cd" * 32 + "\n")
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_VAULT_PATH", "")
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_PATH", str(f))
    assert ticket_mint._resolve_l1_seed() is None


def test_resolve_l1_seed_file_fallback_missing_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_VAULT_PATH", "")
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_PATH", "/no/such/seed.hex")
    with pytest.raises(EffectUnavailable, match="does not exist"):
        ticket_mint._resolve_l1_seed()


def test_resolve_l1_seed_fails_closed_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_VAULT_PATH", "")
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_PATH", "")
    with pytest.raises(EffectUnavailable, match="no L1 signing seed"):
        ticket_mint._resolve_l1_seed()
