"""P2 — object-level authorization. One test per CLAIM.

The claims, and the tests that defend each:

 C1  A tenant-A token cannot READ a tenant-B VM.
       `test_tenant_cannot_read_other_tenants_vm_state`
       `test_tenant_cannot_read_other_tenants_vm_attestation`
       `test_tenant_list_excludes_other_tenants`
       `test_tenant_list_display_filter_cannot_widen_scope`
       `test_tenant_cannot_read_other_tenants_launch_job`
       `test_tenant_cannot_read_other_tenants_migration_job`
       `test_tenant_cannot_read_other_tenants_decommission_job`
 C2  A tenant-A token cannot ACT on a tenant-B VM.
       `test_tenant_cannot_migrate_other_tenants_vm`
       `test_tenant_cannot_decommission_other_tenants_vm`
       `test_tenant_cannot_transition_other_tenants_vm`
       `test_tenant_cannot_act_on_its_OWN_vm_either`
 C3  An operator token still can (the upstream Django API keeps working).
       `test_operator_reads_any_tenants_vm`
       `test_operator_list_sees_every_tenant`
       `test_operator_can_migrate_any_tenants_vm`
 C4  A NEW endpoint that forgets the check is caught — structurally.
       `test_undeclared_endpoint_fails_the_system_check`
       `test_undeclared_endpoint_is_refused_to_a_tenant_at_runtime`
       `test_every_shipped_api_view_declares_a_scope`
 C5  A tenant token cannot promote itself to operator.
       `test_db_refuses_operator_with_a_tenant_id`
       `test_db_refuses_tenant_scope_without_a_tenant_id`
       `test_no_http_route_can_create_or_rescope_a_principal`
       `test_tenant_named_as_the_root_principal_is_still_refused`
 C6  An unclassified principal (nobody scoped it) is denied by default.
       `test_unclassified_principal_is_denied`
       `test_unclassified_principal_may_still_reach_a_public_endpoint`
 C7  The owner recorded at creation is BOUND to a tenant credential, not
     merely copied from the request body.
       `test_launch_binds_tenant_id_to_a_tenant_credential`
       `test_launch_rejects_a_mismatched_tenant_id_claim`
       `test_launch_keeps_the_body_tenant_id_for_an_operator`
"""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import override_settings
from django.urls import URLPattern, URLResolver, get_resolver, path, reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.test import APIClient
from rest_framework.views import APIView

from apps.identity import scoping
from apps.identity.checks import check_api_views_declare_object_scope, undeclared_api_views
from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.lifecycle.models import Vm, VmState
from apps.orchestration.models import (
    DecommissionJob,
    DecommissionState,
    LaunchJob,
    LaunchJobState,
    MigrationJob,
    MigrationState,
)

pytestmark = pytest.mark.django_db

ROOT_PRINCIPAL = "orchestration-root"


# ── fixtures ─────────────────────────────────────────────────────────


def _client_for(client: ServiceClient) -> APIClient:
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="t",
        lifetime=TokenLifetime.OPS.value,
    )
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return c


@pytest.fixture
def tenant_a() -> APIClient:
    return _client_for(
        ServiceClient.objects.create(
            name="portal-a", scope=PrincipalScope.TENANT.value, tenant_id="tenant-a"
        )
    )


@pytest.fixture
def tenant_b() -> APIClient:
    return _client_for(
        ServiceClient.objects.create(
            name="portal-b", scope=PrincipalScope.TENANT.value, tenant_id="tenant-b"
        )
    )


@pytest.fixture
def operator(monkeypatch: pytest.MonkeyPatch) -> APIClient:
    """The upstream Django API's principal: explicit operator, and also
    the configured orchestration root so it can drive the act paths."""
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT_PRINCIPAL)
    return _client_for(
        ServiceClient.objects.create(
            name=ROOT_PRINCIPAL, scope=PrincipalScope.OPERATOR.value
        )
    )


@pytest.fixture
def unclassified() -> APIClient:
    """A principal nobody scoped — the model default."""
    return _client_for(ServiceClient.objects.create(name="forgotten"))


@pytest.fixture(autouse=True)
def _registered_miners():
    """§25's same-CPU-gen gate resolves each host's generation from its
    registered CHIP_ID length. Register the two hosts the act-path tests
    migrate between so a REAL migration can start (the point of
    `test_operator_can_migrate_any_tenants_vm` is that authorization is
    the only thing standing in the way)."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-1", defaults={"pubkey_hex": "aa" * 32, "platform_id": "11" * 64}
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-2", defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64}
    )


def _mk_vm(vm_id: str, tenant_id: str) -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        tenant_id=tenant_id,
        lease_id=f"lease-{vm_id}",
        state=VmState.ACTIVE,
        generation=1,
        host="node-1",
        lifecycle_vk=bytes(32),
        # A launch bakes this into the measured cmdline; `start_migration`
        # refuses a VM without one (its stopped-ack could never verify).
        eol_nonce=bytes(range(32)),
    )


@pytest.fixture
def vm_a() -> Vm:
    return _mk_vm("vm-a", "tenant-a")


@pytest.fixture
def vm_b() -> Vm:
    return _mk_vm("vm-b", "tenant-b")


# ── C1: a tenant token cannot READ another tenant's objects ──────────


def test_tenant_cannot_read_other_tenants_vm_state(tenant_a, vm_b) -> None:
    resp = tenant_a.get(reverse("vm_state", args=[vm_b.vm_id]))
    # 404 not 403 — a 403 would confirm vm-b exists (see scoping.py).
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_tenant_reads_its_OWN_vm_state(tenant_a, vm_a) -> None:
    resp = tenant_a.get(reverse("vm_state", args=[vm_a.vm_id]))
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["vm_id"] == "vm-a"


def test_tenant_cannot_read_other_tenants_vm_attestation(
    tenant_a, vm_b, monkeypatch
) -> None:
    """The gate fires BEFORE the KBS is dialled — no oracle, no
    amplification through vali."""
    calls: list[str] = []

    def _boom(vm_id: str) -> dict[str, Any]:
        calls.append(vm_id)
        return {}

    monkeypatch.setattr(
        "apps.orchestration.services.kbs_evidence.fetch_evidence", _boom
    )
    resp = tenant_a.get(reverse("vm_attestation", args=[vm_b.vm_id]))
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    assert calls == []


def test_tenant_list_excludes_other_tenants(tenant_a, vm_a, vm_b) -> None:
    body = tenant_a.get(reverse("vm_list")).json()
    assert [row["vm_id"] for row in body["vms"]] == ["vm-a"]
    # `total` is computed on the SCOPED queryset — it must not leak the
    # size of the fleet either.
    assert body["total"] == 1


def test_tenant_list_display_filter_cannot_widen_scope(tenant_a, vm_a, vm_b) -> None:
    """`?tenant_id=` is a DISPLAY filter; it must only ever narrow."""
    body = tenant_a.get(reverse("vm_list"), {"tenant_id": "tenant-b"}).json()
    assert body["vms"] == []
    assert body["total"] == 0


def _mk_launch_job(vm_id: str, tenant_id: str, actor: ServiceClient) -> LaunchJob:
    return LaunchJob.objects.create(
        job_id=f"job-{vm_id}",
        vm_id=vm_id,
        tenant_id=tenant_id,
        flavor="small",
        spec_json={},
        userdata_vault_path="p",
        userdata_vault_version=1,
        kek_vault_path="k",
        state=LaunchJobState.QUEUED.value,
        phase_started_at=timezone.now(),
        decided_by=actor,
    )


def test_tenant_cannot_read_other_tenants_launch_job(tenant_a, vm_b) -> None:
    actor = ServiceClient.objects.create(
        name="actor", scope=PrincipalScope.OPERATOR.value
    )
    job = _mk_launch_job("vm-b", "tenant-b", actor)
    assert (
        tenant_a.get(reverse("vm_launch_job", args=[job.job_id])).status_code
        == status.HTTP_404_NOT_FOUND
    )


def test_tenant_reads_its_OWN_launch_job(tenant_a, vm_a) -> None:
    actor = ServiceClient.objects.create(
        name="actor", scope=PrincipalScope.OPERATOR.value
    )
    job = _mk_launch_job("vm-a", "tenant-a", actor)
    resp = tenant_a.get(reverse("vm_launch_job", args=[job.job_id]))
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["vm_id"] == "vm-a"


def test_tenant_cannot_read_other_tenants_migration_job(tenant_a, vm_b) -> None:
    actor = ServiceClient.objects.create(
        name="actor", scope=PrincipalScope.OPERATOR.value
    )
    job = MigrationJob.objects.create(
        job_id="mig-1",
        vm=vm_b,
        source_node_id="n1",
        dest_node_id="n2",
        source_gen=1,
        new_gen=2,
        state=MigrationState.DRAINING.value,
        phase_started_at=timezone.now(),
        decided_by=actor,
    )
    url = reverse("vm_migrate_job", args=[vm_b.vm_id, job.job_id])
    assert tenant_a.get(url).status_code == status.HTTP_404_NOT_FOUND


def test_tenant_cannot_read_other_tenants_decommission_job(tenant_a, vm_b) -> None:
    actor = ServiceClient.objects.create(
        name="actor", scope=PrincipalScope.OPERATOR.value
    )
    job = DecommissionJob.objects.create(
        job_id="dec-1",
        vm=vm_b,
        state=DecommissionState.DRAINING.value,
        phase_started_at=timezone.now(),
        decided_by=actor,
    )
    url = reverse("vm_decommission_job", args=[vm_b.vm_id, job.job_id])
    assert tenant_a.get(url).status_code == status.HTTP_404_NOT_FOUND


def test_tenant_cannot_see_other_tenants_price_recommendations(
    tenant_a, vm_a, vm_b
) -> None:
    from apps.scheduler.models import (
        PriceMigrationRecommendation,
        PriceRecommendationStatus,
    )

    for vm in (vm_a, vm_b):
        PriceMigrationRecommendation.objects.create(
            recommendation_id=f"rec-{vm.vm_id}",
            vm=vm,
            current_node_id="node-1",
            suggested_dest_node_id="node-2",
            new_price=500,
            ceiling=100,
            effective_block=150,
            status=PriceRecommendationStatus.PENDING.value,
        )
    body = tenant_a.get(reverse("price_recommendation_list")).json()
    assert [r["vm_id"] for r in body["recommendations"]] == ["vm-a"]


# ── C2: a tenant token cannot ACT on another tenant's VM ─────────────


def test_tenant_cannot_migrate_other_tenants_vm(tenant_a, vm_b, operator) -> None:
    resp = tenant_a.post(
        reverse("vm_migrate", args=[vm_b.vm_id]),
        {"dest_node_id": "node-2"},
        format="json",
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert not MigrationJob.objects.exists()


def test_tenant_cannot_decommission_other_tenants_vm(tenant_a, vm_b, operator) -> None:
    resp = tenant_a.post(reverse("vm_decommission", args=[vm_b.vm_id]))
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert not DecommissionJob.objects.exists()


def test_tenant_cannot_transition_other_tenants_vm(tenant_a, vm_b, operator) -> None:
    resp = tenant_a.post(
        reverse("vm_transition", args=[vm_b.vm_id]),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    vm_b.refresh_from_db()
    assert vm_b.state == VmState.ACTIVE


def test_tenant_cannot_act_on_its_OWN_vm_either(tenant_a, vm_a, operator) -> None:
    """The §24/§25 triggers are operator-only by design (they move or
    cryptographically destroy a VM). Scoping must not have opened them
    to tenants as a side effect of making the read path work."""
    assert (
        tenant_a.post(
            reverse("vm_migrate", args=[vm_a.vm_id]),
            {"dest_node_id": "node-2"},
            format="json",
        ).status_code
        == status.HTTP_403_FORBIDDEN
    )
    assert (
        tenant_a.post(reverse("vm_decommission", args=[vm_a.vm_id])).status_code
        == status.HTTP_403_FORBIDDEN
    )


# ── C3: an operator token still works ────────────────────────────────


def test_operator_reads_any_tenants_vm(operator, vm_a, vm_b) -> None:
    for vm in (vm_a, vm_b):
        resp = operator.get(reverse("vm_state", args=[vm.vm_id]))
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["vm_id"] == vm.vm_id


def test_operator_list_sees_every_tenant(operator, vm_a, vm_b) -> None:
    body = operator.get(reverse("vm_list")).json()
    assert {row["vm_id"] for row in body["vms"]} == {"vm-a", "vm-b"}


def test_operator_can_migrate_any_tenants_vm(operator, vm_b) -> None:
    resp = operator.post(
        reverse("vm_migrate", args=[vm_b.vm_id]),
        {"dest_node_id": "node-2"},
        format="json",
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert MigrationJob.objects.filter(vm=vm_b).exists()


# ── C4: a NEW endpoint that forgets the check is caught ──────────────


class _ForgotToDeclareView(APIView):
    """A brand-new endpoint whose author never thought about tenancy."""

    permission_classes = [IsAuthenticated]

    def get(self, _request):  # pragma: no cover - body is never reached
        return Response({"secret": "every tenant's data"})


_forgetful_urlpatterns = [
    path("v1/brand-new-thing", _ForgotToDeclareView.as_view(), name="brand_new"),
]


class _forgetful_urlconf:
    """Module-like object usable as `ROOT_URLCONF`."""

    urlpatterns = _forgetful_urlpatterns


@override_settings(ROOT_URLCONF=_forgetful_urlconf)
def test_undeclared_endpoint_fails_the_system_check() -> None:
    """`manage.py check` (and therefore CI + container startup) refuses
    an endpoint that did not declare its tenant posture."""
    errors = check_api_views_declare_object_scope(app_configs=None)
    assert [e.id for e in errors] == ["identity.E001"]
    assert "_ForgotToDeclareView" in errors[0].msg


@override_settings(ROOT_URLCONF=_forgetful_urlconf)
def test_undeclared_endpoint_is_refused_to_a_tenant_at_runtime(
    tenant_a, operator
) -> None:
    """Belt to the system check's braces: even if somebody skips the
    check, the middleware refuses an undeclared endpoint to a
    tenant-scoped principal. The operator is unaffected."""
    resp = tenant_a.get("/v1/brand-new-thing")
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert resp.json()["category"] == "endpoint-undeclared"
    assert operator.get("/v1/brand-new-thing").status_code == status.HTTP_200_OK


def test_declaring_a_scope_is_what_clears_the_check() -> None:
    """The check keys on the DECLARATION, not on the view's name/module —
    i.e. it is a real gate, not a hard-coded allow-list."""

    class _Declared(_ForgotToDeclareView):
        object_scope = scoping.OPERATOR_ONLY

    class _urlconf:
        urlpatterns = [path("v1/thing", _Declared.as_view(), name="thing")]

    with override_settings(ROOT_URLCONF=_urlconf):
        assert undeclared_api_views() == []


def test_a_bogus_scope_value_is_not_a_declaration() -> None:
    class _Bogus(_ForgotToDeclareView):
        object_scope = "whatever-i-felt-like"

    class _urlconf:
        urlpatterns = [path("v1/thing", _Bogus.as_view(), name="thing")]

    with override_settings(ROOT_URLCONF=_urlconf):
        errors = check_api_views_declare_object_scope(app_configs=None)
    assert len(errors) == 1
    assert "not one of" in errors[0].msg


def test_every_shipped_api_view_declares_a_scope() -> None:
    """The real URLconf is clean — this is the test that fails when
    someone adds an endpoint without declaring it."""
    assert undeclared_api_views() == []


def test_the_check_actually_covers_the_real_urlconf() -> None:
    """Guard against the check silently scanning nothing (e.g. if the
    `/v1/` prefix or the walker regressed)."""
    resolver = get_resolver()

    def _count(patterns, prefix=""):
        n = 0
        for entry in patterns:
            if isinstance(entry, URLResolver):
                n += _count(entry.url_patterns, prefix + str(entry.pattern))
            elif isinstance(entry, URLPattern) and (
                prefix + str(entry.pattern)
            ).startswith("v1/"):
                n += 1
        return n

    assert _count(resolver.url_patterns) >= 40


# ── C5: a tenant token cannot promote itself to operator ─────────────


def test_db_refuses_operator_with_a_tenant_id() -> None:
    """Promotion is not a partial UPDATE away: the DB refuses the
    `operator + tenant_id` combination outright."""
    client = ServiceClient.objects.create(
        name="portal", scope=PrincipalScope.TENANT.value, tenant_id="tenant-a"
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        ServiceClient.objects.filter(pk=client.pk).update(
            scope=PrincipalScope.OPERATOR.value
        )


def test_db_refuses_tenant_scope_without_a_tenant_id() -> None:
    """The other half of the constraint: a `tenant` principal with a
    blank tenant_id would match every legacy unowned row."""
    with pytest.raises(IntegrityError), transaction.atomic():
        ServiceClient.objects.create(name="half-set", scope=PrincipalScope.TENANT.value)


def test_no_http_route_can_create_or_rescope_a_principal() -> None:
    """The ONLY grant paths are the management command and the
    cluster-internal Django admin. Nothing under `/v1/` touches the
    identity models, so no bearer token can mint or re-scope one."""
    import importlib

    for module in ("apps.identity.urls", "apps.identity.views"):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(module)

    resolver = get_resolver()

    def _routes(patterns, prefix=""):
        for entry in patterns:
            if isinstance(entry, URLResolver):
                yield from _routes(entry.url_patterns, prefix + str(entry.pattern))
            elif isinstance(entry, URLPattern):
                yield prefix + str(entry.pattern), entry.callback

    for route, callback in _routes(resolver.url_patterns):
        if not route.startswith("v1/"):
            continue
        view_cls = getattr(callback, "cls", None)
        if view_cls is None:
            continue
        source = getattr(view_cls, "__module__", "")
        assert not source.startswith("apps.identity"), route


@pytest.mark.parametrize(
    "url_name,args",
    [
        ("miner_list", ()),
        ("scheduler_capacity", ()),
        ("tenant_bake_detail", ("bake-1",)),
        ("packer_build_detail", ("build-1",)),
    ],
)
def test_tenant_is_refused_operator_only_endpoints_that_have_no_root_gate(
    tenant_a, url_name, args
) -> None:
    """These endpoints carry only `IsAuthenticated` — before P2 any token
    reached them. The middleware's `OPERATOR_ONLY` rule is the ONLY thing
    keeping a tenant credential off the fleet surface here, so it is
    pinned independently of the root permission classes."""
    resp = tenant_a.get(reverse(url_name, args=args))
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert resp.json()["category"] == "operator-only"


def test_root_permission_class_alone_refuses_a_tenant_impostor(monkeypatch) -> None:
    """The root permission classes are pinned WITHOUT the middleware in
    the path: `IsOrchestrationRoot` must refuse a tenant-scoped client
    that carries the configured root NAME, on its own."""
    from apps.orchestration.permissions import IsOrchestrationRoot

    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT_PRINCIPAL)

    class _Req:
        pass

    req = _Req()
    req.user = ServiceClient.objects.create(
        name=ROOT_PRINCIPAL,
        scope=PrincipalScope.TENANT.value,
        tenant_id="tenant-a",
    )
    assert IsOrchestrationRoot().has_permission(req, None) is False
    # …and the genuine operator with the same name is allowed, so the
    # guard is not just "deny everything".
    req.user = ServiceClient.objects.create(
        name=f"{ROOT_PRINCIPAL}-2", scope=PrincipalScope.OPERATOR.value
    )
    monkeypatch.setattr(
        settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", f"{ROOT_PRINCIPAL}-2"
    )
    assert IsOrchestrationRoot().has_permission(req, None) is True


def test_tenant_named_as_the_root_principal_is_still_refused(
    monkeypatch, vm_b
) -> None:
    """Root permission classes match on NAME. A tenant-scoped client that
    happens to carry the configured root name must NOT inherit fleet
    authority — the operator scope is required as well."""
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT_PRINCIPAL)
    impostor = _client_for(
        ServiceClient.objects.create(
            name=ROOT_PRINCIPAL,
            scope=PrincipalScope.TENANT.value,
            tenant_id="tenant-a",
        )
    )
    resp = impostor.post(
        reverse("vm_migrate", args=[vm_b.vm_id]),
        {"dest_node_id": "node-2"},
        format="json",
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert not MigrationJob.objects.exists()


def test_model_full_clean_rejects_the_inconsistent_combination() -> None:
    """Same rule surfaced at the application layer, so the Django admin
    shows a validation error rather than a 500 from the DB."""
    bad = ServiceClient(
        name="x", scope=PrincipalScope.OPERATOR.value, tenant_id="tenant-a"
    )
    with pytest.raises(ValidationError):
        bad.full_clean()


# ── C6: an unclassified principal is denied ──────────────────────────


def test_unclassified_principal_is_denied(unclassified, vm_a) -> None:
    """The model default is NOT operator. A credential nobody scoped is
    inert on the whole non-public surface."""
    resp = unclassified.get(reverse("vm_state", args=[vm_a.vm_id]))
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert resp.json()["category"] == "principal-unclassified"
    assert unclassified.get(reverse("vm_list")).status_code == status.HTTP_403_FORBIDDEN


def test_unclassified_principal_may_still_reach_a_public_endpoint(
    unclassified,
) -> None:
    """`PUBLIC` endpoints are unauthenticated by design (guest / miner
    ingress); scoping must not break them."""
    resp = unclassified.get(reverse("epoch_weights"))
    assert resp.status_code == status.HTTP_200_OK


# ── C7: the owner is BOUND at creation, not merely copied ────────────


def _launch_intent(**over: Any) -> dict[str, Any]:
    intent = {
        "tenant_id": "tenant-a",
        "user_id": "user-1",
        "vm_id": "vm-new",
        "lease_id": "lease-1",
        "flavor": "small",
        "cmdline": "console=ttyS0",
        "s3_bucket": "b",
        "s3_key_prefix": "p",
        "luks_disk_sha256_hex": "aa" * 32,
        "kernel_sha256_hex": "bb" * 32,
        "initrd_sha256_hex": "cc" * 32,
        "luks_header_sha256_hex": "dd" * 32,
    }
    intent.update(over)
    return intent


def test_launch_binds_tenant_id_to_a_tenant_credential() -> None:
    """A tenant credential's own tenant wins over the request body — the
    field authorization is built on is not caller-chosen for it."""
    caller = ServiceClient.objects.create(
        name="portal-a", scope=PrincipalScope.TENANT.value, tenant_id="tenant-a"
    )
    intent = _launch_intent(tenant_id="")
    assert scoping.bind_tenant_id(caller, intent["tenant_id"]) == "tenant-a"


def test_launch_rejects_a_mismatched_tenant_id_claim() -> None:
    caller = ServiceClient.objects.create(
        name="portal-a", scope=PrincipalScope.TENANT.value, tenant_id="tenant-a"
    )
    with pytest.raises(ValueError):
        scoping.bind_tenant_id(caller, "tenant-b")


def test_launch_keeps_the_body_tenant_id_for_an_operator() -> None:
    """An operator legitimately launches on behalf of any tenant; the
    body value stands (a trusted caller's assertion, documented as such)."""
    caller = ServiceClient.objects.create(
        name="upstream", scope=PrincipalScope.OPERATOR.value
    )
    assert scoping.bind_tenant_id(caller, "tenant-z") == "tenant-z"


def test_start_launch_applies_the_binding(monkeypatch) -> None:
    """The binding is wired into the real intake path, not just the
    helper."""
    from apps.orchestration import launch_jobs

    caller = ServiceClient.objects.create(
        name="portal-a", scope=PrincipalScope.TENANT.value, tenant_id="tenant-a"
    )
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs.start_launch(
            intent=_launch_intent(tenant_id="tenant-b"),
            userdata=b"#cloud-config\n",
            decided_by=caller,
        )
    assert "does not match" in exc.value.message


def test_launch_stamps_the_bound_tenant_onto_the_job_row() -> None:
    """The binding has to land on the ROW the read path scopes on, not
    just on the in-memory intent."""
    from apps.orchestration import launch_jobs

    caller = ServiceClient.objects.create(
        name="portal-a", scope=PrincipalScope.TENANT.value, tenant_id="tenant-a"
    )
    captured: dict[str, Any] = {}

    class _Staged:
        version = 7

    def _put_kv(_mount, path, _data, **_kw):
        captured["path"] = path
        return _Staged()

    from unittest import mock

    with (
        mock.patch.object(launch_jobs.vault_kv, "put_kv", _put_kv),
        mock.patch.object(launch_jobs.launch, "check_netbird_userdata", return_value=None),
        override_settings(VALI_VAULT_KV_PREFIX="hippius-compute/vms"),
    ):
        job = launch_jobs.start_launch(
            # No tenant_id in the body at all — the credential supplies it.
            intent=_launch_intent(
                tenant_id="",
                kek_vault_path="hippius-compute/vms/vm-new/luks-kek",
            ),
            userdata=b"#cloud-config\n",
            decided_by=caller,
        )
    assert job.tenant_id == "tenant-a"
    assert job.spec_json["tenant_id"] == "tenant-a"


def test_launch_stamps_the_owner_onto_the_vm_row() -> None:
    """The read path scopes on `Vm.tenant_id`, so the launch must
    actually stamp it — an unstamped row is invisible to its own tenant
    (fail-closed, but broken)."""
    from apps.orchestration.services import launch

    spec = launch.LaunchSpec(
        tenant_id="tenant-a",
        user_id="user-1",
        vm_id="vm-stamped",
        lease_id="lease-1",
        flavor="small",
        cmdline="console=ttyS0",
        s3_bucket="b",
        s3_key_prefix="p",
        luks_disk_sha256_hex="aa" * 32,
        kernel_sha256_hex="bb" * 32,
        initrd_sha256_hex="cc" * 32,
        luks_header_sha256_hex="dd" * 32,
        kek_bytes=b"\x00" * 32,
        userdata=b"#cloud-config\n",
    )
    vm = launch._ensure_vm_row(spec)
    assert vm.tenant_id == "tenant-a"


# ── the grandfathering data migration ────────────────────────────────


def test_migration_grandfathers_existing_principals() -> None:
    """Pre-P2 principals were de-facto operators; the data migration
    records that explicitly so a deploy does not lose every credential.
    Without it the whole fleet's tokens would land `unclassified` =
    denied — an outage, not a security improvement."""
    import importlib

    from django.apps import apps as django_apps

    mod = importlib.import_module(
        "apps.identity.migrations.0003_serviceclient_authorization_scope"
    )
    # Simulate a row that existed before the migration ran.
    ServiceClient.objects.create(name="legacy-edge")
    ServiceClient.objects.filter(name="legacy-edge").update(
        scope=PrincipalScope.UNCLASSIFIED.value
    )
    mod.grandfather_existing_principals(django_apps, None)
    assert (
        ServiceClient.objects.get(name="legacy-edge").scope
        == PrincipalScope.OPERATOR.value
    )


# ── helper-level properties ──────────────────────────────────────────


def test_require_tenant_visible_refuses_unowned_rows_for_a_tenant() -> None:
    """A row with a blank owner (pre-P2 legacy) is not "everyone's" — a
    tenant principal is refused it, an operator is not."""

    class _Req:
        pass

    req = _Req()
    req.user = ServiceClient.objects.create(
        name="portal-a", scope=PrincipalScope.TENANT.value, tenant_id="tenant-a"
    )
    with pytest.raises(scoping.CrossTenantDenied):
        scoping.require_tenant_visible(req, "")

    req.user = ServiceClient.objects.create(
        name="upstream", scope=PrincipalScope.OPERATOR.value
    )
    scoping.require_tenant_visible(req, "")  # no raise


def test_scope_queryset_returns_nothing_for_an_unclassified_caller(vm_a) -> None:
    """Fail-closed if the helper is ever called outside the middleware
    (a management command, a future code path)."""

    class _Req:
        pass

    req = _Req()
    req.user = ServiceClient.objects.create(name="forgotten")
    assert list(scoping.scope_queryset(req, Vm.objects.all())) == []
    req.user = None
    assert list(scoping.scope_queryset(req, Vm.objects.all())) == []
