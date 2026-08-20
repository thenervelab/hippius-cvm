"""Test-only Django settings.

`pytest-django` reads `DJANGO_SETTINGS_MODULE = "vali.settings_test"`
from `pyproject.toml` and eagerly evaluates the `DATABASES` dict
inside its `pytest_load_initial_conftests` hook — *before* any rootdir
`conftest.py` gets a chance to mutate the environment. The cleanest
way to keep tests on SQLite-in-memory regardless of ambient
`DATABASE_URL` is therefore a dedicated settings module.

Production / `manage.py` still use `vali.settings` (Postgres).
"""

from __future__ import annotations

import os

# `vali.settings` fail-fasts on a placeholder SECRET_KEY when
# DEBUG=False. Tests run with DEBUG enabled so the dev key is fine,
# but settings.py only reads these from the environment — set them
# BEFORE the wildcard import so the check passes deterministically.
os.environ.setdefault("DJANGO_DEBUG", "1")
os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key-not-for-prod")

from .settings import *  # noqa: E402,F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

# Production uses a DB-backed cache so the DRF throttle is global across
# gunicorn workers (RA-L1). Tests run single-process, so an in-memory cache
# is both correct for the throttle assertions AND keeps every test (incl.
# the non-`django_db` verifier tests, whose autouse `cache.clear()` would
# otherwise hit the DB) free of a database dependency.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    },
}
