"""Fixtures for the backup suite.

`fake_miner` replaces the two miner-facing effects (`dispatch_backup`,
`poll_backup_status`) with an in-memory miner that records every order and
answers polls from what the test told it; `mock_s3` is the real
`MockHippiusS3Client`, so the multipart bookkeeping is exercised as written.
"""

from __future__ import annotations

import hashlib
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import pytest
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient

from apps.identity.models import PrincipalScope, ServiceClient, ServiceToken, TokenLifetime
from apps.lifecycle.models import Vm, VmState
from apps.orchestration import effects
from apps.orchestration.models import LaunchJob
from apps.orchestration.tests.factories import make_service_client
from apps.storage import s3

ROOT = "orchestration-root"
HOST = "miner-a"


@dataclass
class FakeMiner:
    """The miner-agent's backup side, as vali sees it through the Edge.

    Point bitmaps follow the miner's scheme: every run creates
    `hippius-bk-<run_id>`; an incremental copies from its parent's point
    without consuming it; each run prunes every point but {parent, itself}.
    A reboot / QEMU restart drops them all (`bitmap_present = False`)."""

    boot_counter: int = 3
    points: set[str] = field(default_factory=set)
    #: Latest run status per vm_id (the miner keeps only the latest).
    runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    orders: list[dict[str, Any]] = field(default_factory=list)
    #: `(classifier, status)` to refuse the next dispatches with.
    reject: tuple[str, int] | None = None
    unavailable: bool = False
    poll_unavailable: bool = False
    #: vm_ids this miner has no domain for (poll → 404).
    unknown: set[str] = field(default_factory=set)
    #: The object store the miner uploads into through its presigned URLs.
    store: s3.MockHippiusS3Client | None = None
    #: Answer like today's miner-agent: the bare `RunStatus` of the latest
    #: run, 404 when there is none — no live reading.
    bare: bool = False

    @property
    def bitmap_present(self) -> bool:
        return bool(self.points)

    @bitmap_present.setter
    def bitmap_present(self, value: bool) -> None:
        if not value:
            self.points.clear()

    def dispatch(self, *, miner_id: str, order_id: str, payload: dict[str, Any]) -> None:
        if self.unavailable:
            raise effects.EffectUnavailable("backup: edge unreachable")
        if self.reject is not None:
            raise effects.BackupRejected(*self.reject)
        assert set(payload) <= {
            "vm_id",
            "run_id",
            "parent_run_id",
            "kind",
            "part_size",
            "disk_part_urls",
            "state_put_url",
        }, payload.keys()
        self.orders.append({"miner_id": miner_id, "order_id": order_id, "payload": payload})
        self.runs[payload["vm_id"]] = {
            "run_id": payload["run_id"],
            "parent_run_id": payload.get("parent_run_id"),
            "kind": payload["kind"],
            "status": "running",
            "error": None,
            "bitmap_present": None,
            "boot_counter": None,
            "virtual_size": None,
            "disk": None,
            "state": None,
        }

    def poll(self, *, vm_id: str, miner_id: str) -> dict[str, Any] | None:
        if self.poll_unavailable:
            raise effects.EffectUnavailable("edge-relay:backup: peer unreachable")
        if vm_id in self.unknown:
            return None
        if self.bare:
            return self.runs.get(vm_id)
        return {
            "vm_id": vm_id,
            "live": {"boot_counter": self.boot_counter, "point_run_ids": sorted(self.points)},
            "run": self.runs.get(vm_id),
        }

    @property
    def last(self) -> dict[str, Any]:
        return self.orders[-1]["payload"]

    def state_disk(self) -> bytes:
        return self.boot_counter.to_bytes(8, "little") + bytes(1024 * 1024 - 8)

    def finish(
        self,
        vm_id: str = "vm-1",
        *,
        disk_bytes: int | None = None,
        status: str = "done",
        reason: str = "",
        bitmap_present: bool = True,
        upload: bool = True,
        put_state: bool = True,
        **overrides: Any,
    ) -> dict[str, Any]:
        """Settle the VM's current run the way the miner would: upload the
        parts and the state disk through the order's URLs, then report.
        `overrides` tamper with the report (`part_etags`, `part_sha256_hex`,
        `disk_sha256_hex`, `state_bytes`, `state_sha256_hex`, or any
        top-level run field)."""
        run = self.runs[vm_id]
        order = next(o["payload"] for o in reversed(self.orders) if o["payload"]["vm_id"] == vm_id)
        if disk_bytes is None:
            disk_bytes = 40 * 1024**3 if order["kind"] == "full" else 100 * 1024**2
        part_size = order["part_size"]
        used = -(-disk_bytes // part_size)
        state = self.state_disk()
        if status == "failed":
            run.update(status="failed", error=reason or "miner-failed", bitmap_present=False)
            self.points.discard(run["run_id"])
            run.update(overrides)
            return run
        if self.store is not None:
            if upload:
                upload_id = _query(order["disk_part_urls"][0])["upload_id"]
                for n in range(1, min(used, len(order["disk_part_urls"])) + 1):
                    size = min(part_size, disk_bytes - (n - 1) * part_size)
                    self.store.record_part(upload_id=upload_id, part_number=n, size=size)
            if put_state:
                bucket, key = _bucket_key(order["state_put_url"])
                self.store.put_object(bucket=bucket, key=key, body=state, content_type="x")
        parts = [
            {
                "part_number": n,
                "etag": f'"etag-{n}"',
                "sha256_hex": "b" * 64,
                "size": min(part_size, disk_bytes - (n - 1) * part_size),
            }
            for n in range(1, used + 1)
        ]
        if "part_etags" in overrides:
            etags = overrides.pop("part_etags")
            parts = [{**p, "etag": e} for p, e in zip(parts, etags, strict=False)][: len(etags)]
        if "part_sha256_hex" in overrides:
            shas = overrides.pop("part_sha256_hex")
            parts = [{**p, "sha256_hex": h} for p, h in zip(parts, shas, strict=False)]
        disk = {"parts": parts, "size": disk_bytes, "sha256_hex": "a" * 64}
        if "disk_sha256_hex" in overrides:
            disk["sha256_hex"] = overrides.pop("disk_sha256_hex")
        state_piece = {
            "parts": [],
            "size": overrides.pop("state_bytes", len(state)),
            "sha256_hex": overrides.pop("state_sha256_hex", hashlib.sha256(state).hexdigest()),
        }
        # The miner keeps only {parent, this run}.
        self.points &= {run["parent_run_id"]} - {None}
        if bitmap_present:
            self.points.add(run["run_id"])
        run.update(
            status="done",
            bitmap_present=bitmap_present,
            boot_counter=self.boot_counter,
            virtual_size=40 * 1024**3,
            disk=disk,
            state=state_piece,
        )
        run.update(overrides)
        return run


def _query(url: str) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


def _bucket_key(url: str) -> tuple[str, str]:
    parts = urllib.parse.urlsplit(url)
    return parts.netloc, urllib.parse.unquote(parts.path.lstrip("/"))


@pytest.fixture(autouse=True)
def _backup_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT)
    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_BACKUP_BUCKET", "vm-backups")
    monkeypatch.setattr(settings, "VALI_BACKUP_MAX_CHAIN", 24)
    monkeypatch.setattr(settings, "VALI_BACKUP_MIN_PART_BYTES", 512 * 1024 * 1024)
    monkeypatch.setattr(settings, "VALI_BACKUP_RUN_TIMEOUT_S", 6 * 3600)
    monkeypatch.setattr(settings, "VALI_BACKUP_LOST_GRACE_S", 180)
    monkeypatch.setattr(settings, "VALI_BACKUP_PROBE_INTERVAL_S", 300)
    monkeypatch.setattr(settings, "VALI_BACKUP_RETRY_AFTER_S", 900)
    monkeypatch.setattr(settings, "VALI_PACKER_IMAGES_BUCKET", "images-public")
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_SNAPSHOT_BUCKET", "migrations")
    from apps.backup import service

    service._BUCKET_OK.clear()
    cache.clear()


@pytest.fixture
def mock_s3(monkeypatch: pytest.MonkeyPatch) -> s3.MockHippiusS3Client:
    from apps.backup import service

    client = s3.MockHippiusS3Client()
    monkeypatch.setattr(s3, "get_s3_client", lambda: client)
    monkeypatch.setattr(service, "backup_s3_client", lambda: client)
    return client


@pytest.fixture
def fake_miner(monkeypatch: pytest.MonkeyPatch, mock_s3: s3.MockHippiusS3Client) -> FakeMiner:
    miner = FakeMiner(store=mock_s3)
    monkeypatch.setattr(effects, "dispatch_backup", miner.dispatch)
    monkeypatch.setattr(effects, "poll_backup_status", miner.poll)
    return miner


def make_vm(
    vm_id: str = "vm-1",
    *,
    host: str = HOST,
    state: str = VmState.ACTIVE,
    golden: bool = True,
    flavor: str = "small",
    region: str = "",
) -> Vm:
    vm = Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=state,
        generation=1,
        host=host,
        lifecycle_vk=bytes(32),
    )
    spec: dict[str, Any] = {"vm_id": vm_id, "flavor": flavor}
    if golden:
        spec["disk_mode"] = "golden_verity_overlay"
    if region:
        spec["region"] = region
    LaunchJob.objects.create(
        job_id=secrets.token_hex(8),
        vm_id=vm_id,
        tenant_id="t",
        flavor=flavor,
        spec_json=spec,
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        state="succeeded",
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    return vm


def _bearer(name: str, scope: str, tenant_id: str = "") -> APIClient:
    sc = ServiceClient.objects.create(scope=scope, name=name, tenant_id=tenant_id)
    _row, token = ServiceToken.issue(client=sc, name="ops", lifetime=TokenLifetime.OPS.value)
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return api


@pytest.fixture
def root_client() -> APIClient:
    return _bearer(ROOT, PrincipalScope.OPERATOR.value)


@pytest.fixture
def operator_client() -> APIClient:
    return _bearer("upstream-api", PrincipalScope.OPERATOR.value)


@pytest.fixture
def tenant_client() -> APIClient:
    return _bearer("portal-a", PrincipalScope.TENANT.value, tenant_id="tenant-a")
