"""End-to-end tests for the `vali_tenant_bake_create` management
command.

The command's only non-trivial logic is the poll loop. We exercise
it by patching `spawn_bake_job` at the `apps.tenant_bake.k8s_jobs`
module level + flipping the row through a baker simulation inside
the fake — but, critically, we then RESTORE the binding before the
test exits so the view's compile-time `from .k8s_jobs import
spawn_bake_job` binding sees the original on subsequent tests.

(`apps.tenant_bake.views.spawn_bake_job` is a separate top-level
binding established at module load — `monkeypatch.setattr` against
`k8s_jobs.spawn_bake_job` doesn't reach back into `views`'s
namespace, BUT the management command does `from X import Y` at
call time inside `handle()`, which DOES pick up the monkeypatched
attribute. So this test exercises the command-side rebinding
without disturbing the view-side binding.)
"""

from __future__ import annotations

import io
import json

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from apps.tenant_bake.models import TenantBake, TenantBakeState

pytestmark = pytest.mark.django_db


GOOD_SHA = "a" * 64
GOOD_MEASUREMENT = "b" * 96


@override_settings(VALI_TENANT_BAKE_K8S_ENABLED=False)
def test_management_command_happy_path_e2e(monkeypatch: pytest.MonkeyPatch) -> None:
    """The full operator UX: command → row created → (k8s mocked) →
    poll loop observes Succeeded → stdout JSON envelope matches the
    shape `vali_create_vm` expects.

    The fake spawn synchronously flips Running → Succeeded so the
    poll loop's first `refresh_from_db` sees the terminal state.
    """

    def fake_spawn(row: TenantBake) -> None:
        TenantBake.objects.filter(bake_id=row.bake_id).update(
            state=TenantBakeState.RUNNING.value, version=2
        )
        TenantBake.objects.filter(bake_id=row.bake_id).update(
            state=TenantBakeState.SUCCEEDED.value,
            version=3,
            qcow2_sha256=GOOD_SHA,
            kernel_sha256=GOOD_SHA,
            initrd_sha256=GOOD_SHA,
            measurement_hex=GOOD_MEASUREMENT,
        )

    # The management command does `from apps.tenant_bake.k8s_jobs
    # import spawn_bake_job` inside handle(), so setattr on the
    # k8s_jobs module rebinds what the command sees.
    import apps.tenant_bake.k8s_jobs as k8s_jobs_mod

    monkeypatch.setattr(k8s_jobs_mod, "spawn_bake_job", fake_spawn)

    stdout = io.StringIO()
    stderr = io.StringIO()
    call_command(
        "vali_tenant_bake_create",
        "--vm-id",
        "myvm-e2e",
        "--base-image-url",
        "https://example.com/cloud.img",
        "--base-image-sha256",
        "f" * 64,
        "--size-gb",
        "10",
        "--kek-vault-path",
        "secret/.../luks-kek",
        "--s3-output-bucket",
        "hippius-compute-images",
        "--s3-output-prefix",
        "tenant/myvm-e2e/",
        "--poll-interval-secs",
        "0",
        "--poll-timeout-secs",
        "5",
        stdout=stdout,
        stderr=stderr,
    )

    envelope = json.loads(stdout.getvalue().strip())
    assert envelope["vm_id"] == "myvm-e2e"
    assert envelope["qcow2_sha256"] == GOOD_SHA
    assert envelope["kernel_sha256"] == GOOD_SHA
    assert envelope["initrd_sha256"] == GOOD_SHA
    assert envelope["measurement_hex"] == GOOD_MEASUREMENT
    assert envelope["s3_output_bucket"] == "hippius-compute-images"
    assert envelope["s3_output_prefix"] == "tenant/myvm-e2e/"
    assert TenantBake.objects.get(bake_id=envelope["bake_id"]).state == "succeeded"


@override_settings(VALI_TENANT_BAKE_K8S_ENABLED=False)
def test_management_command_failed_bake_exits_9(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Failed branch — baker reports failure_reason, command
    exits 9 with the reason on stderr."""

    def fake_spawn(row: TenantBake) -> None:
        TenantBake.objects.filter(bake_id=row.bake_id).update(
            state=TenantBakeState.RUNNING.value, version=2
        )
        TenantBake.objects.filter(bake_id=row.bake_id).update(
            state=TenantBakeState.FAILED.value,
            version=3,
            failure_reason="cryptsetup luksFormat returned 5",
        )

    import apps.tenant_bake.k8s_jobs as k8s_jobs_mod

    monkeypatch.setattr(k8s_jobs_mod, "spawn_bake_job", fake_spawn)

    stdout = io.StringIO()
    stderr = io.StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command(
            "vali_tenant_bake_create",
            "--vm-id",
            "myvm-fail",
            "--base-image-url",
            "https://example.com/cloud.img",
            "--base-image-sha256",
            "f" * 64,
            "--size-gb",
            "10",
            "--kek-vault-path",
            "secret/.../luks-kek",
            "--s3-output-bucket",
            "hippius-compute-images",
            "--s3-output-prefix",
            "tenant/myvm-fail/",
            "--poll-interval-secs",
            "0",
            "--poll-timeout-secs",
            "5",
            stdout=stdout,
            stderr=stderr,
        )
    assert exc.value.code == 9
    assert "cryptsetup luksFormat returned 5" in stderr.getvalue()


@override_settings(VALI_TENANT_BAKE_K8S_ENABLED=False)
def test_management_command_rejects_mutable_base_image_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Register #48 — the operator CLI is the OTHER intake path, and it
    shares `_parse_create`, so the mutable-URL refusal covers it too.

    This is what makes intake a complete chokepoint: both ways a
    `TenantBake` row can be born run through the same parser, and the
    baker only ever sees rows.
    """
    import apps.tenant_bake.k8s_jobs as k8s_jobs_mod

    spawns: list = []
    monkeypatch.setattr(
        k8s_jobs_mod, "spawn_bake_job", lambda row: spawns.append(row)
    )

    with pytest.raises(CommandError) as exc:
        call_command(
            "vali_tenant_bake_create",
            "--vm-id",
            "myvm-mutable",
            "--base-image-url",
            "https://cloud.debian.org/images/cloud/trixie/latest/"
            "debian-13-genericcloud-amd64.qcow2",
            "--base-image-sha256",
            "f" * 64,
            "--size-gb",
            "10",
            "--kek-vault-path",
            "secret/.../luks-kek",
            "--s3-output-bucket",
            "hippius-compute-images",
            "--s3-output-prefix",
            "tenant/myvm-mutable/",
            "--poll-interval-secs",
            "0",
            "--poll-timeout-secs",
            "5",
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
    assert "moving" in str(exc.value).lower(), str(exc.value)
    assert spawns == []
    assert TenantBake.objects.count() == 0
