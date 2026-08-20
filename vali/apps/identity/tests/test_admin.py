"""Smoke tests for the Django admin wire-up (#152).

Scope: the admin is the ops eyeball surface for vali; these tests
freeze the contract that

  - every registered changelist page renders 200 to a logged-in
    superuser (catches a missing admin.py, a bad ModelAdmin import,
    a typo in `list_display`, etc.);
  - the admin index lists all 12 registered models so a future
    refactor can't silently un-register one;
  - the readonly-by-policy fields stay readonly (we re-assert the
    invariant directly via `get_readonly_fields`, not just via
    inspecting the rendered HTML — the form layer is the boundary
    that actually decides what's editable).

The tests pre-create a superuser via `create_superuser` (not the
`seed_admin_user` management command — that has its own dedicated
test). Auth uses Django's `Client.force_login` to avoid the
password-hashing roundtrip per test.
"""

from __future__ import annotations

import pytest
from django.contrib.admin import site as admin_site
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

pytestmark = pytest.mark.django_db


# (app_label, model_name) pairs registered with the admin (#152).
# Kept here as the single source of truth — if a future PR adds a
# new model + admin registration, append it here so the smoke test
# covers it.
_REGISTERED_MODELS: tuple[tuple[str, str], ...] = (
    ("identity", "serviceclient"),
    ("identity", "servicetoken"),
    ("lifecycle", "vm"),
    ("miners", "mineridentity"),
    ("orchestration", "migrationjob"),
    ("orchestration", "decommissionjob"),
    ("orders", "orderticketintake"),
    ("packer", "packerbuild"),
    ("scheduler", "minercapacity"),
    ("scheduler", "placement"),
    ("telemetry", "telemetrysource"),
    ("telemetry", "telemetryenvelope"),
)


@pytest.fixture
def admin_client() -> Client:
    """A test client logged in as a fresh superuser. `force_login`
    skips the password hash + middleware roundtrip — fastest path to
    an authenticated admin session.
    """
    User = get_user_model()
    user = User.objects.create_superuser(
        username="ops-test",
        email="",
        password="irrelevant-uses-force-login",  # noqa: S106
    )
    c = Client()
    c.force_login(user)
    return c


# ────────────────────────────────────────────────────────────────────
# Changelist GETs
# ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("app_label", "model_name"), _REGISTERED_MODELS)
def test_admin_changelist_renders_200(
    admin_client: Client, app_label: str, model_name: str
) -> None:
    """Every registered model's changelist must render. A 500 here
    almost always means a typo in `list_display` (a field that doesn't
    exist on the model, a `@admin.display` decorator missing on a
    custom column).
    """
    url = reverse(f"admin:{app_label}_{model_name}_changelist")
    resp = admin_client.get(url)
    assert resp.status_code == 200, (
        f"admin changelist for {app_label}.{model_name} returned "
        f"{resp.status_code} (expected 200). URL={url}"
    )


def test_admin_index_renders_200(admin_client: Client) -> None:
    """The `/admin/` landing page must render — this is the first
    page an operator sees and a 500 here means the admin is unusable.
    """
    resp = admin_client.get(reverse("admin:index"))
    assert resp.status_code == 200


def test_admin_index_lists_all_registered_models(admin_client: Client) -> None:
    """A guard against silent un-registration: every model in
    `_REGISTERED_MODELS` must appear in the admin registry. Refactors
    that accidentally drop an `@admin.register` decorator are caught
    here even when no test exercises that model's changelist directly.
    """
    registered = {
        (model._meta.app_label, model._meta.model_name)
        for model in admin_site._registry  # noqa: SLF001 — admin has no public iterator
    }
    for app_label, model_name in _REGISTERED_MODELS:
        assert (app_label, model_name) in registered, (
            f"{app_label}.{model_name} is no longer registered with the admin "
            "(check apps/<app>/admin.py)"
        )


# ────────────────────────────────────────────────────────────────────
# Readonly-by-policy invariants
# ────────────────────────────────────────────────────────────────────

# (app_label, model_name, field_name) tuples that MUST be readonly on
# the change form per the admin module docstrings. Asserting these
# directly via `get_readonly_fields` (not by parsing rendered HTML)
# keeps the check at the form layer's boundary.
_READONLY_INVARIANTS: tuple[tuple[str, str, str], ...] = (
    # Sensitive secrets — leaking the digest enables offline brute-
    # force search against a database dump.
    ("identity", "servicetoken", "token_sha256"),
    # Binary trust anchors / single-use values — owned by §7 attested
    # release + the stopped-ack verifier; never operator-editable.
    ("lifecycle", "vm", "lifecycle_vk"),
    ("lifecycle", "vm", "eol_nonce"),
    # Miner identity/trust columns — the canonical writers are the
    # register / quarantine endpoints (which mirror status onto the
    # linked TelemetrySource in the same transaction). Editing from
    # admin diverges the registry from the §9 broker trust anchor.
    ("miners", "mineridentity", "pubkey_hex"),
    ("miners", "mineridentity", "platform_id"),
    ("miners", "mineridentity", "status"),
    # §K replay-gate cursor — must only advance via row-locked CAS.
    ("miners", "mineridentity", "last_heartbeat_sequence"),
    # Append-only audit log — the byte-exact L1 envelope is the wire
    # contract; hand-edit silently breaks re-transmission to the KBS.
    ("orders", "orderticketintake", "cose_blob"),
    # `(source, source_id)` is the identity pair the broker matches
    # against; editing either rebinds an existing Ed25519 trust
    # anchor to a different source identity. Registration goes
    # through `vali_telemetry_register_source`.
    ("telemetry", "telemetrysource", "source"),
    ("telemetry", "telemetrysource", "source_id"),
    # §9 broker trust anchor — rebinding a source's verifying key
    # from the admin would silently re-trust a different signer.
    ("telemetry", "telemetrysource", "verifying_key"),
    # §20 signed body + detached sig — kept on the change form for
    # forensics but never editable.
    ("telemetry", "telemetryenvelope", "payload_cbor"),
)


@pytest.mark.parametrize(
    ("app_label", "model_name", "field_name"), _READONLY_INVARIANTS
)
def test_admin_readonly_invariant(
    admin_client: Client,
    app_label: str,
    model_name: str,
    field_name: str,
) -> None:
    """Each sensitive field must be reported readonly by the
    `ModelAdmin` for the model's change form. Asserted via
    `get_readonly_fields(request, obj=None)` — that is the exact
    method `ModelForm` consults when deciding what to render
    editable.
    """
    model_admin = _resolve_admin(app_label, model_name)
    # `get_readonly_fields` is called with `obj=None` for the add form
    # and with `obj=<instance>` for the change form. We assert against
    # the change-form path (the one operator actions touch).
    readonly = set(model_admin.get_readonly_fields(request=None, obj=None))  # type: ignore[arg-type]
    assert field_name in readonly, (
        f"{app_label}.{model_name}.{field_name} MUST be readonly per "
        f"#152 ops-eyeball discipline; got readonly_fields={sorted(readonly)}"
    )


# ────────────────────────────────────────────────────────────────────
# Access control — anon + non-superuser
# ────────────────────────────────────────────────────────────────────


def test_admin_anonymous_redirected_to_login() -> None:
    """An unauthenticated GET on the admin index must redirect to the
    login page (302). A 200 here would mean the admin is publicly
    readable — a §15 audit-trail break.
    """
    resp = Client().get(reverse("admin:index"))
    assert resp.status_code == 302
    assert "/admin/login/" in resp["Location"]


def test_admin_staff_non_superuser_sees_no_app_models() -> None:
    """A staff user with no per-model permissions must see an empty
    admin index (the contrib admin renders no app block when the
    user has 0 perms). Per #152 the only sanctioned admin caller is a
    superuser; this guards against a future regression that grants
    blanket read perms to plain staff.

    Asserted via `response.context["app_list"]` — that is the data
    structure Django's admin index template iterates to render its
    per-app blocks, so an empty list IS the "no app access" state
    (independent of any HTML-string heuristic that a Django version
    change could break).
    """
    User = get_user_model()
    User.objects.create_user(
        username="staff-test",
        password="irrelevant-uses-force-login",  # noqa: S106
        is_staff=True,
        is_superuser=False,
    )
    c = Client()
    c.force_login(User.objects.get(username="staff-test"))
    resp = c.get(reverse("admin:index"))
    assert resp.status_code == 200
    # `app_list` is the canonical context key the admin index iterates.
    # An empty list means the staff user has zero perms on every
    # registered model — which is what we want for a fresh user.
    assert resp.context["app_list"] == [], (
        f"staff non-superuser saw apps {resp.context['app_list']!r} on "
        "the admin index — #152 expects superuser-only access."
    )


# ────────────────────────────────────────────────────────────────────
# Append-only invariant — `has_add_permission` + `has_delete_permission`
# ────────────────────────────────────────────────────────────────────

# Models whose `ModelAdmin` MUST refuse both add + delete from the
# admin UI. These are the §15 audit-trail / §9 telemetry-forensics
# tables — vali's intake views are the only sanctioned writers, and
# GC management commands the only sanctioned reapers — plus the
# miner identity registry, which has its own write path
# (`POST /v1/admin/miner/register`) that also provisions the linked
# `TelemetrySource` in the same transaction; admin-side add/delete
# would orphan that link.
_APPEND_ONLY_MODELS: tuple[tuple[str, str], ...] = (
    ("orders", "orderticketintake"),
    ("telemetry", "telemetryenvelope"),
    ("miners", "mineridentity"),
)


@pytest.mark.parametrize(("app_label", "model_name"), _APPEND_ONLY_MODELS)
def test_admin_append_only_blocks_add(
    admin_client: Client, app_label: str, model_name: str
) -> None:
    """`has_add_permission` must return False on the append-only
    models. Even a superuser must NOT see the "Add" button on the
    changelist — clicking through would synthesize a row that skips
    intake validation.
    """
    ma = _resolve_admin(app_label, model_name)
    assert ma.has_add_permission(request=None) is False, (  # type: ignore[arg-type]
        f"{app_label}.{model_name} must refuse `has_add_permission` "
        "— audit-trail integrity depends on intake-view-only writes."
    )


@pytest.mark.parametrize(("app_label", "model_name"), _APPEND_ONLY_MODELS)
def test_admin_append_only_blocks_delete(
    admin_client: Client, app_label: str, model_name: str
) -> None:
    """`has_delete_permission` must return False on the append-only
    models — and as a consequence the `delete_selected` bulk action
    must NOT appear in `get_actions`. Without this gate an operator
    could bulk-delete the entire §15 ticket log or §9 telemetry
    forensics queue from the changelist.
    """
    ma = _resolve_admin(app_label, model_name)
    User = get_user_model()
    superuser = User.objects.create_superuser(
        username=f"forensics-test-{app_label}-{model_name}",
        email="",
        password="irrelevant-uses-force-login",  # noqa: S106
    )
    from django.test import RequestFactory

    req = RequestFactory().get("/")
    req.user = superuser
    assert ma.has_delete_permission(req) is False, (
        f"{app_label}.{model_name} must refuse `has_delete_permission` "
        "— audit-trail integrity depends on no-admin-delete invariant."
    )
    assert "delete_selected" not in ma.get_actions(req), (
        f"{app_label}.{model_name} must not surface the "
        "`delete_selected` bulk action — has_delete_permission=False "
        "should remove it automatically."
    )


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────


def _resolve_admin(app_label: str, model_name: str):
    """Return the registered `ModelAdmin` instance for the pair, or
    raise with a clear message if the model isn't registered.
    """
    for model, admin_instance in admin_site._registry.items():  # noqa: SLF001
        if (
            model._meta.app_label == app_label
            and model._meta.model_name == model_name
        ):
            return admin_instance
    raise AssertionError(
        f"{app_label}.{model_name} is not registered — check "
        "apps/<app>/admin.py."
    )
