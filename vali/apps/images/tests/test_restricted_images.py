"""Images restricted to one tenant (CDN plan N2): the cdn-node image is the
CDN fleet's alone — blessed only restricted to `VALI_CDN_TENANT_ID`,
launched only by it while `VALI_CDN_ENABLED` is on, by image name or by
`bake_id`, and listed to nobody else."""

from __future__ import annotations

import pytest
from django.conf import settings
from django.core.management import call_command
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.identity.models import PrincipalScope, ServiceClient, ServiceToken, TokenLifetime
from apps.images.models import GoldenImage
from apps.orchestration import launch_jobs
from apps.orchestration.launch_jobs import LaunchIntentError

pytestmark = pytest.mark.django_db

CDN = "hippius-cdn"


@pytest.fixture(autouse=True)
def _cdn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", True)
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", CDN)


NODE = "cdn-fr-7k2m"


def _node(node_id: str = NODE) -> None:
    """The CDN node the reconciler records before it launches (CDN plan V2:
    only a node's launch boots the cdn-node image)."""
    from apps.cdn.models import CdnNode

    CdnNode.objects.create(node_id=node_id, region="FR")


def _bless_cmd(image: str, bake: str, *extra: str) -> None:
    call_command("vali_bless_golden_image", image, bake, "--distro", "debian", *extra)


def _image(image: str, bake: str, restricted: str = "") -> GoldenImage:
    return GoldenImage.objects.create(
        image_name=image,
        distro="debian",
        bake_id=bake,
        blessed_at=timezone.now(),
        restricted_tenant=restricted,
    )


def _client(*, tenant: str = "") -> APIClient:
    scope = PrincipalScope.TENANT if tenant else PrincipalScope.OPERATOR
    client = ServiceClient.objects.create(
        scope=scope.value, name=f"lister-{tenant or 'op'}", tenant_id=tenant
    )
    _row, plaintext = ServiceToken.issue(client=client, name="t", lifetime=TokenLifetime.OPS.value)
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return api


# ── bless ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("extra", [(), ("--restricted-tenant", "tenant-a")])
def test_a_cdn_node_bake_is_blessed_only_for_the_cdn_tenant(
    make_golden_bake, extra: tuple[str, ...]
) -> None:
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")

    with pytest.raises(SystemExit) as exc:
        _bless_cmd("cdn-node", "gb-cdn", *extra)

    assert exc.value.code == 9
    assert not GoldenImage.objects.exists()


def test_a_cdn_node_bake_needs_the_cdn_tenant_set(
    make_golden_bake, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", "")
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")

    with pytest.raises(SystemExit):
        _bless_cmd("cdn-node", "gb-cdn", "--restricted-tenant", "")
    assert not GoldenImage.objects.exists()


def test_bless_records_the_restriction(make_golden_bake, capsys) -> None:
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    make_golden_bake(bake_id="gb-std")

    _bless_cmd("cdn-node", "gb-cdn", "--restricted-tenant", CDN)
    _bless_cmd("debian", "gb-std", "--restricted-tenant", "tenant-a")

    assert GoldenImage.objects.get(image_name="cdn-node").restricted_tenant == CDN
    assert GoldenImage.objects.get(image_name="debian").restricted_tenant == "tenant-a"
    assert '"restricted_tenant": "tenant-a"' in capsys.readouterr().out


def test_a_re_bless_keeps_the_restriction(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-std")
    make_golden_bake(bake_id="gb-std-2")
    _bless_cmd("debian", "gb-std", "--restricted-tenant", "tenant-a")

    _bless_cmd("debian", "gb-std-2")

    image = GoldenImage.objects.get(image_name="debian")
    assert (image.bake_id, image.restricted_tenant) == ("gb-std-2", "tenant-a")


def test_a_cdn_node_re_bless_keeps_its_restriction(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    make_golden_bake(bake_id="gb-cdn-2", profile="cdn-node")
    _bless_cmd("cdn-node", "gb-cdn", "--restricted-tenant", CDN)

    _bless_cmd("cdn-node", "gb-cdn-2")

    assert GoldenImage.objects.get(image_name="cdn-node").restricted_tenant == CDN
    with pytest.raises(SystemExit):
        _bless_cmd("cdn-node", "gb-cdn", "--unrestrict")


def test_unrestrict_lifts_it_loudly(make_golden_bake, capsys) -> None:
    from django.core.management.base import CommandError

    make_golden_bake(bake_id="gb-std")
    _bless_cmd("debian", "gb-std", "--restricted-tenant", "tenant-a")
    capsys.readouterr()

    _bless_cmd("debian", "gb-std", "--unrestrict")

    assert GoldenImage.objects.get(image_name="debian").restricted_tenant == ""
    assert "every tenant may now launch it" in capsys.readouterr().err
    with pytest.raises(CommandError):
        _bless_cmd("debian", "gb-std", "--unrestrict", "--restricted-tenant", "t")


def test_seed_defaults_takes_no_restriction() -> None:
    from django.core.management.base import CommandError

    with pytest.raises(CommandError):
        call_command("vali_bless_golden_image", "--seed-defaults", "--restricted-tenant", CDN)


# ── catalog ───────────────────────────────────────────────────────────


def test_the_catalog_lists_a_restricted_image_to_its_tenant_only() -> None:
    _image("debian", "gb-std")
    _image("cdn-node", "gb-cdn", restricted=CDN)
    url = reverse("image_list")

    def names(api: APIClient) -> list[str]:
        r = api.get(url)
        assert r.status_code == 200, r.content
        return [row["image_name"] for row in r.json()["images"]]

    assert names(_client()) == ["debian"]  # the operator API lists it to customers
    assert names(_client(tenant="tenant-a")) == ["debian"]
    assert names(_client(tenant=CDN)) == ["cdn-node", "debian"]


# ── launch ────────────────────────────────────────────────────────────


def _resolve(intent: dict) -> dict:
    launch_jobs._resolve_bake(intent)
    return intent


def test_a_restricted_image_launches_for_its_tenant_only(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-std")
    _image("debian", "gb-std", restricted="tenant-a")

    assert _resolve({"image": "debian", "tenant_id": "tenant-a"})["bake_id"] == "gb-std"
    for tenant in ("tenant-b", ""):
        with pytest.raises(LaunchIntentError) as exc:
            _resolve({"image": "debian", "tenant_id": tenant})
        assert exc.value.category == "image-restricted"


def test_a_restricted_bake_is_refused_by_bake_id_too(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-std")
    _image("debian", "gb-std", restricted="tenant-a")

    with pytest.raises(LaunchIntentError) as exc:
        _resolve({"bake_id": "gb-std", "tenant_id": "tenant-b"})
    assert exc.value.category == "image-restricted"
    assert _resolve({"bake_id": "gb-std", "tenant_id": "tenant-a"})["bake_id"] == "gb-std"


def test_the_cdn_node_image_launches_for_the_cdn_tenant(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    _image("cdn-node", "gb-cdn", restricted=CDN)
    _node()

    node = {"tenant_id": CDN, "vm_id": NODE}
    assert _resolve({"image": "cdn-node", **node})["bake_id"] == "gb-cdn"
    assert _resolve({"bake_id": "gb-cdn", **node})["bake_id"] == "gb-cdn"


@pytest.mark.parametrize(
    ("vm_id", "flag"), [("cdn-fr-other", True), (NODE, False)], ids=["no-node", "role-off"]
)
def test_the_cdn_tenant_alone_does_not_boot_the_cdn_node_image(
    make_golden_bake, monkeypatch: pytest.MonkeyPatch, vm_id: str, flag: bool
) -> None:
    """CDN plan V2 replaces I3's tenant check with the role: the CDN
    tenant's launch of a VM no node names — or any launch while
    VALI_CDN_LAUNCH_ROLE is off — is refused."""
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    _image("cdn-node", "gb-cdn", restricted=CDN)
    _node()
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", flag)

    with pytest.raises(LaunchIntentError) as exc:
        _resolve({"image": "cdn-node", "tenant_id": CDN, "vm_id": vm_id})
    assert exc.value.category == "image-restricted"


@pytest.mark.parametrize("by", ["image", "bake_id"])
def test_no_other_tenant_launches_the_cdn_node_image(make_golden_bake, by: str) -> None:
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    _image("cdn-node", "gb-cdn", restricted=CDN)
    key = "cdn-node" if by == "image" else "gb-cdn"

    with pytest.raises(LaunchIntentError) as exc:
        _resolve({by: key, "tenant_id": "tenant-a"})
    assert exc.value.category == "image-restricted"


def test_an_unblessed_cdn_node_bake_launches_for_the_cdn_tenant_only(make_golden_bake) -> None:
    # A cdn-node bake no image names (a re-bake awaiting its bless).
    make_golden_bake(bake_id="gb-cdn-2", profile="cdn-node")
    _node()

    assert (
        _resolve({"bake_id": "gb-cdn-2", "tenant_id": CDN, "vm_id": NODE})["bake_id"] == "gb-cdn-2"
    )
    with pytest.raises(LaunchIntentError):
        _resolve({"bake_id": "gb-cdn-2", "tenant_id": "tenant-a", "vm_id": NODE})


@pytest.mark.parametrize("by", ["image", "bake_id"])
def test_the_cdn_node_image_is_inert_while_the_flag_is_off(
    make_golden_bake, monkeypatch: pytest.MonkeyPatch, by: str
) -> None:
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    _image("cdn-node", "gb-cdn", restricted=CDN)
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    key = "cdn-node" if by == "image" else "gb-cdn"

    with pytest.raises(LaunchIntentError) as exc:
        _resolve({by: key, "tenant_id": CDN})
    assert exc.value.category == "image-restricted"


# ── by the artifacts booted ───────────────────────────────────────────


def _cdn_artifacts() -> dict:
    return {
        "verity_root_hash_hex": "c3" * 32,
        "rootfs_img_sha256_hex": "a1" * 32,
        "rootfs_verity_sha256_hex": "b2" * 32,
    }


@pytest.mark.parametrize("named", [{}, {"bake_id": "gb-std"}])
def test_a_restricted_base_is_refused_whatever_bake_the_launch_names(
    make_golden_bake, named: dict
) -> None:
    # Caller fields win over the bake's, so the artifacts decide.
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    make_golden_bake(
        bake_id="gb-std",
        rootfs_img_sha256="d4" * 32,
        rootfs_verity_sha256="e5" * 32,
        verity_root_hash="f6" * 32,
    )
    for key, value in _cdn_artifacts().items():
        intent = {"tenant_id": "tenant-a", **named, key: value}
        with pytest.raises(LaunchIntentError) as exc:
            launch_jobs._check_artifact_restriction(intent)
        assert exc.value.category == "image-restricted"


def test_the_cdn_tenant_may_boot_the_cdn_base(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    _node()

    launch_jobs._check_artifact_restriction({"tenant_id": CDN, "vm_id": NODE, **_cdn_artifacts()})


def test_an_open_base_passes_the_artifact_check(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-std")

    launch_jobs._check_artifact_restriction({"tenant_id": "tenant-a", **_cdn_artifacts()})
    launch_jobs._check_artifact_restriction({"tenant_id": "tenant-a"})


def test_start_launch_runs_the_artifact_check() -> None:
    import inspect

    source = inspect.getsource(launch_jobs.start_launch)
    assert source.index("_resolve_bake(intent)") < source.index(
        "_check_artifact_restriction(intent)"
    )


def test_one_bake_is_never_blessed_with_two_restrictions(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-std")
    _bless_cmd("debian", "gb-std", "--restricted-tenant", "tenant-a")

    with pytest.raises(SystemExit):
        _bless_cmd("debian-open", "gb-std")
    _bless_cmd("debian-a", "gb-std", "--restricted-tenant", "tenant-a")
    assert GoldenImage.objects.filter(bake_id="gb-std").count() == 2
