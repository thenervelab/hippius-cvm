"""`/healthz` says which image runs: its commit and the newest migration
each vali app ships — from the code, no database (it stays a liveness
probe)."""

from __future__ import annotations

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from vali import urls

pytestmark = pytest.mark.django_db


def test_healthz_reports_the_commit_and_the_shipped_migrations(settings) -> None:
    settings.VALI_GIT_SHA = "0123456789abcdef0123456789abcdef01234567"
    urls._shipped_migrations.cache_clear()
    with CaptureQueriesContext(connection) as queries:
        body = APIClient().get("/healthz").json()
    assert body["status"] == "ok"
    assert body["version"] == "0123456789abcdef0123456789abcdef01234567"
    migrations = body["migrations"]
    assert migrations["backup"].startswith("00") and migrations["orchestration"].startswith("00")
    assert "auth" not in migrations and "admin" not in migrations, "vali's own apps only"
    assert len(queries) == 0, "never the database"


def test_the_shipped_migrations_are_each_apps_leaf() -> None:
    from django.db.migrations.loader import MigrationLoader

    leaves = dict(MigrationLoader(None, ignore_no_migrations=True).graph.leaf_nodes())
    for app, name in urls._shipped_migrations().items():
        assert leaves[app] == name


def test_the_version_defaults_to_unknown(monkeypatch) -> None:
    import importlib.util

    from vali import settings as vali_settings

    monkeypatch.delenv("VALI_GIT_SHA", raising=False)
    spec = importlib.util.spec_from_file_location("_settings_copy", vali_settings.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.VALI_GIT_SHA == "unknown"
