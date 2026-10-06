"""A fake KBS for the §22 allowlist pin tests: it keeps the installed
epoch HWM and entry set like `InstalledAllowlist::install` (full replace,
409 at or below the HWM), and the pin's signing / S3 / reload effects are
wired to it. Shared by `test_allowlist_pin_concurrency` and
`test_allowlist_supersession`.
"""

from __future__ import annotations

import subprocess
import tomllib
from typing import Any

import pytest
from django.conf import settings

from apps.orchestration.services import allowlist_pin

BASE_M = "1" * 96

_BASE_MANIFEST = (
    "schema = 1\n"
    "epoch = 5\n"
    "\n"
    "[[entries]]\n"
    f'measurement_hex = "{BASE_M}"\n'
    'accepted_l1_kids_hex = ["6c31"]\n'
    'accepted_kbs_response_kids_hex = ["6b6273"]\n'
)


class FakeKbs:
    """The installed allowlist: full replace, epoch-HWM CAS."""

    def __init__(self) -> None:
        self.epoch = 5
        self.entries: set[str] = {BASE_M}
        self.on_reload: list[Any] = []

    def reload(self, cose: bytes) -> None:
        for hook in self.on_reload:
            hook()
        manifest = tomllib.loads(cose.decode("utf-8"))
        if manifest["epoch"] <= self.epoch:
            raise allowlist_pin.AllowlistEpochConflict("409 epoch at or below the HWM")
        self.epoch = manifest["epoch"]
        self.entries = {e["measurement_hex"] for e in manifest["entries"]}


def install_fake_kbs(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> FakeKbs:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(_BASE_MANIFEST, encoding="utf-8")
    seed = tmp_path / "seed.hex"
    seed.write_text("ab" * 32, encoding="utf-8")
    tool = tmp_path / "kbs-allowlist-tool"
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)

    monkeypatch.setattr(settings, "VALI_ALLOWLIST_MANIFEST_PATH", str(manifest))
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_S3_URL", "s3://bucket/key")
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_TOOL_BIN", str(tool))
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH", "")
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_PATH", str(seed))

    def fake_sign(argv, *, label, timeout_s, env=None):  # noqa: ANN001, ANN202
        # The "COSE" is the manifest itself, so the fake KBS can read it.
        args = list(argv)
        with open(args[args.index("--manifest") + 1], "rb") as src:
            body = src.read()
        with open(args[args.index("--out") + 1], "wb") as out:
            out.write(body)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    fake = FakeKbs()
    monkeypatch.setattr(allowlist_pin, "_run", fake_sign)
    monkeypatch.setattr(allowlist_pin, "_s3_upload", lambda *a, **k: None)
    monkeypatch.setattr(allowlist_pin, "_reload_kbs_allowlist", fake.reload)
    return fake
