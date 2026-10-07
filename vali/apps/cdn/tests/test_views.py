"""`GET /v1/cdn/ca.pem` and `vali_cdn_ca`."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command
from rest_framework.test import APIClient

from .. import ca
from ..models import CdnRevision
from .conftest import FakeTransit

pytestmark = pytest.mark.django_db

URL = "/v1/cdn/ca.pem"


def test_bundle_is_served_with_its_revision(
    root_client: APIClient, fake_transit: FakeTransit
) -> None:
    ca.init_ca()
    resp = root_client.get(URL)
    assert resp.status_code == 200
    assert resp["Content-Type"] == "application/x-pem-file"
    assert resp.content.decode() == ca.bundle_pem()
    assert resp["ETag"] == f'"{CdnRevision.current()}"'

    fake_transit.rotate()
    ca.init_ca()
    again = root_client.get(URL)
    assert again.content.decode().count("BEGIN CERTIFICATE") == 2
    assert again["ETag"] != resp["ETag"]


def test_bundle_404_before_init(root_client: APIClient) -> None:
    resp = root_client.get(URL)
    assert resp.status_code == 404 and resp.json()["code"] == "ca-not-initialised"


def test_bundle_404_while_disabled(
    root_client: APIClient, fake_transit: FakeTransit, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca.init_ca()
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    resp = root_client.get(URL)
    assert resp.status_code == 404 and resp.json()["code"] == "cdn-disabled"


def test_bundle_is_root_only(operator_client: APIClient, fake_transit: FakeTransit) -> None:
    ca.init_ca()
    assert operator_client.get(URL).status_code == 403
    assert APIClient().get(URL).status_code in (401, 403)


def test_command_init_export_status(fake_transit: FakeTransit, tmp_path: Path) -> None:
    out = StringIO()
    call_command("vali_cdn_ca", "init", stdout=out)
    assert "cdnca-1 created (active" in out.getvalue()

    out = StringIO()
    call_command("vali_cdn_ca", "export", stdout=out)
    assert out.getvalue() == ca.bundle_pem()

    target = tmp_path / "cdn-ca.pem"
    call_command("vali_cdn_ca", "export", "--out", str(target), stdout=StringIO())
    assert target.read_text() == ca.bundle_pem()

    out = StringIO()
    call_command("vali_cdn_ca", "status", stdout=out)
    assert out.getvalue().startswith("cdnca-1\tactive\tcdn-ca v1")


def test_command_rotation(fake_transit: FakeTransit) -> None:
    call_command("vali_cdn_ca", "init", stdout=StringIO())
    fake_transit.rotate()
    call_command("vali_cdn_ca", "init", stdout=StringIO())
    call_command("vali_cdn_ca", "activate", "cdnca-2", stdout=StringIO())
    call_command("vali_cdn_ca", "retire", "cdnca-1", stdout=StringIO())
    assert ca.active_ca().kid == "cdnca-2"


def test_command_errors_are_named(fake_transit: FakeTransit) -> None:
    with pytest.raises(CommandError, match="ca-not-initialised"):
        call_command("vali_cdn_ca", "export", stdout=StringIO())
    fake_transit.exportable = True
    with pytest.raises(CommandError, match="ca-key-unsafe"):
        call_command("vali_cdn_ca", "init", stdout=StringIO())
