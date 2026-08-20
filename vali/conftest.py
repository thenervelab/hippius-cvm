"""Shared pytest fixtures + early env setup for the vali test suite.

The DB switch lives in `vali/settings_test.py` (see its docstring for
why a settings module is more reliable than env mutation). This
conftest only sets the validator-binary path so tests that exercise
the Rust shell-out can find it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key-not-for-prod")
os.environ.setdefault(
    "VALI_TICKET_VALIDATOR_BIN",
    str(REPO_ROOT / "target" / "release" / "hippius-ticket-validator"),
)


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    """DRF rate-limit counters live in the process-global LocMemCache,
    which pytest-django does NOT roll back between tests (audit
    M-ratelimit). Clear it before each test so a scoped-throttle view's
    request count can't leak across tests and cause a spurious 429."""
    from django.core.cache import cache

    cache.clear()
    yield
