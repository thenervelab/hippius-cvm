"""`settings_test` on Postgres, for the tests whose subject only exists
there — the §22 pin lock is a Postgres advisory lock, and on SQLite the
tests exercise a per-process stand-in (#1340).

`VALI_TEST_DATABASE_URL` names the server; pytest-django creates and drops
its own `test_*` database on it. CI runs the lock tests with this module
against a Postgres service container.
"""

from __future__ import annotations

import os

import dj_database_url

from .settings_test import *  # noqa: F401,F403

DATABASES = {
    "default": dj_database_url.parse(os.environ["VALI_TEST_DATABASE_URL"]),
}
