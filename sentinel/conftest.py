"""Shared pytest setup for the sentinel test suite.

Makes the in-tree `sentinel` package importable when pytest is invoked
from the repo root (`pytest sentinel/`) without requiring an editable
install, and provides a default `SENTINEL_ANTHROPIC_API_KEY` so the
agent's config loader doesn't error out in offline test runs. Tests
that need to assert on the missing-key path override the env var
explicitly via `monkeypatch`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

os.environ.setdefault("SENTINEL_ANTHROPIC_API_KEY", "test-key-not-for-prod")
