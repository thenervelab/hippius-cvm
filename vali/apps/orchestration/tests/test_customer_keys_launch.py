"""Customer-held keys (H6a) — the vali launch path.

Pins, per claim:
- intake gates (flag, golden-only, capable bake whose artifacts are the ones
  launched) and the M0 `spec_json` staying exactly what it was;
- M2 generates / stages / reads NO disk KEK; M1 provisions exactly today's;
- the measured tokens are appended BEFORE preflight and the C2 recompute,
  M0's cmdline is untouched, an over-long M1/M2 cmdline is refused;
- the ticket carries `key_mode` for M1/M2 only, the order `guardian_ep`;
- the mode is pinned on the `Vm` row and every relaunch / re-mint / §25 /
  restore path carries it — and refuses a different one.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.conf import settings
from django.utils import timezone

from apps.lifecycle.models import Vm
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import effects, launch_jobs, order_dispatch
from apps.orchestration.effects import EffectError
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import customer_keys as ck
from apps.orchestration.services import launch, migration_ticket, ticket_mint, vault_kv

pytestmark = pytest.mark.django_db

PK = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
EP = "100.64.3.7:7443"
#: H1b: the measured token is the lowercase hex of the endpoint.
EP_TOKEN = EP.encode().hex()
VERITY = "b3" * 32
KERNEL = "2" * 64
INITRD = "3" * 64
ROOTFS_IMG = "5" * 64
ROOTFS_VERITY = "6" * 64
BAKE_BUCKET = "hippius-compute-images"
BAKE_PREFIX = "tenant/golden-ck/"
TOKENS = (
    f"hippius.key_mode={{mode}} hippius.guardian_pk={PK} hippius.guardian_ep={EP_TOKEN}"
)


def _tokens(mode: str) -> str:
    return TOKENS.format(mode=mode)


# ── fixtures ────────────────────────────────────────────────────────────


def _bake(*, capable: bool = True, bake_id: str = "bake-ck", **overrides):
    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.tenant_bake.models import TenantBake, TenantBakeDiskMode, TenantBakeState

    sc, _ = ServiceClient.objects.get_or_create(
        scope=PrincipalScope.OPERATOR.value, name="bake-owner"
    )
    fields = dict(
        bake_id=bake_id,
        vm_id="vm-bake-ck",
        base_image_url="https://s3.example/base.qcow2",
        base_image_sha256="a" * 64,
        size_gb=10,
        kek_vault_path="",
        s3_output_bucket=BAKE_BUCKET,
        s3_output_prefix=BAKE_PREFIX,
        state=TenantBakeState.SUCCEEDED.value,
        disk_mode=TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value,
        kernel_sha256=KERNEL,
        initrd_sha256=INITRD,
        rootfs_img_sha256=ROOTFS_IMG,
        rootfs_verity_sha256=ROOTFS_VERITY,
        verity_root_hash=VERITY,
        supports_customer_keys=capable,
        requested_by=sc,
    )
    fields.update(overrides)
    return TenantBake.objects.create(**fields)


def _intent(vm_id: str = "vm-ck-1", **overrides) -> dict:
    body = {
        "tenant_id": "t-ck",
        "user_id": "u-1",
        "vm_id": vm_id,
        "lease_id": "lease-1",
        "flavor": "small",
        "cmdline": "ro",
        "bake_id": "bake-ck",
        "key_mode": "split",
        "guardian_endpoint": EP,
        "guardian_pubkey": PK,
    }
    body.update(overrides)
    return body


@pytest.fixture
def vault(monkeypatch):
    """Record every Vault touch the intake makes."""
    calls: dict[str, list] = {"put": [], "datakey": [], "ensure": []}

    def put(mount, path, value, *, cas=None):
        calls["put"].append(path)
        return vault_kv.VaultWriteResult(version=7)

    def datakey(name):
        calls["datakey"].append(name)
        return b"vault:v1:WRAPPEDKEK"

    monkeypatch.setattr(vault_kv, "put_kv", put)
    monkeypatch.setattr(vault_kv, "kv_exists", lambda m, p: p in calls["put"])
    monkeypatch.setattr(vault_kv, "transit_datakey_wrapped", datakey)
    monkeypatch.setattr(vault_kv, "ensure_transit_key", lambda n: calls["ensure"].append(n))
    monkeypatch.setattr(vault_kv, "transit_encrypt", lambda n, pt: b"vault:v1:" + pt.hex().encode())
    return calls


@pytest.fixture
def enabled(settings):
    settings.VALI_CUSTOMER_KEYS_ENABLED = True


#: A NetBird-enabled userdata whose `netbird up` vali can harden (M1/M2).
_INTAKE_USERDATA = (
    b"#cloud-config\nruncmd:\n  - [ netbird, up, --setup-key={{NETBIRD_SETUP_KEY}} ]\n"
)


def _start(intent: dict, userdata: bytes = _INTAKE_USERDATA):
    from apps.identity.models import PrincipalScope, ServiceClient

    actor, _ = ServiceClient.objects.get_or_create(
        scope=PrincipalScope.OPERATOR.value, name="root-ck"
    )
    return launch_jobs.start_launch(intent=intent, userdata=userdata, decided_by=actor)


def _luks(vm_id: str) -> str:
    return f"{settings.VALI_VAULT_KV_PREFIX}/{vm_id}/luks-kek"


# ── 1. intake gates ─────────────────────────────────────────────────────


def test_the_flag_is_off_by_default_and_refuses_customer_keys(vault) -> None:
    assert settings.VALI_CUSTOMER_KEYS_ENABLED is False
    _bake()
    for mode in ("split", "customer"):
        with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-disabled"):
            _start(_intent(key_mode=mode))
    assert vault["put"] == [] and vault["datakey"] == []


@pytest.mark.usefixtures("enabled")
def test_a_legacy_launch_cannot_take_customer_keys(vault) -> None:
    _bake(bake_id="bake-legacy", disk_mode="legacy_luks", supports_customer_keys=True,
          qcow2_sha256="1" * 64, luks_header_sha256="4" * 64,
          kek_vault_path=_luks("vm-ck-1"))
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-golden-only"):
        _start(_intent(bake_id="bake-legacy"))
    assert vault["put"] == [] and vault["datakey"] == []


@pytest.mark.usefixtures("enabled")
def test_an_incapable_bake_is_refused(vault) -> None:
    _bake(capable=False)
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-bake-not-capable"):
        _start(_intent())
    assert vault["put"] == [] and vault["datakey"] == []


@pytest.mark.usefixtures("enabled")
def test_a_launch_without_a_bake_is_refused(vault) -> None:
    body = _intent(
        bake_id=None, disk_mode="golden_verity_overlay", s3_bucket=BAKE_BUCKET,
        s3_key_prefix=BAKE_PREFIX, luks_disk_sha256_hex=ROOTFS_IMG,
        kernel_sha256_hex=KERNEL, initrd_sha256_hex=INITRD,
        rootfs_img_sha256_hex=ROOTFS_IMG, rootfs_verity_sha256_hex=ROOTFS_VERITY,
        verity_root_hash_hex=VERITY,
    )
    body.pop("bake_id")
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-bake-required"):
        _start(body)


@pytest.mark.usefixtures("enabled")
@pytest.mark.parametrize(
    "field",
    ["kernel_sha256_hex", "initrd_sha256_hex", "rootfs_img_sha256_hex",
     "rootfs_verity_sha256_hex", "verity_root_hash_hex", "s3_key_prefix", "s3_bucket"],
)
def test_an_artifact_that_is_not_the_capable_bakes_is_refused(vault, field) -> None:
    """Caller-supplied values win over the bake's in `_resolve_bake`, so a
    capable bake's NAME must not carry someone else's kernel/initrd/base."""
    _bake()
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-artifact-mismatch"):
        _start(_intent(**{field: "f" * 64}))
    assert vault["put"] == [] and vault["datakey"] == []


@pytest.mark.usefixtures("enabled")
def test_image_resolves_to_a_capable_bake() -> None:
    from apps.images.models import GoldenImage

    _bake()
    GoldenImage.objects.create(
        image_name="ubuntu", distro="ubuntu", bake_id="bake-ck", blessed_at=timezone.now()
    )
    intent = _intent(image="ubuntu")
    intent.pop("bake_id")
    launch_jobs._resolve_bake(intent)
    ck.check_new_launch(intent, ck.binding_of(intent))


@pytest.mark.usefixtures("enabled")
def test_an_image_with_a_blessed_guest_release_still_takes_customer_keys() -> None:
    """Phase 7: the build of the capable bake's initrd stands in for the
    bake's prefix + initrd; everything else stays the bake's."""
    from apps.images.models import GoldenImage
    from apps.orchestration.models import GuestComponentRelease, GuestInitrdBuild

    _bake()
    rel = GuestComponentRelease.objects.create(
        version=2, commit="c" * 40, security_epoch=1, squashfs_sha256="d" * 64
    )
    GuestInitrdBuild.objects.create(
        release=rel, source_bake_id="bake-ck", family="initramfs-tools",
        kernel_sha256=KERNEL, rootfs_img_sha256=ROOTFS_IMG,
        rootfs_verity_sha256=ROOTFS_VERITY, verity_root_hash=VERITY,
        base_initrd_sha256=INITRD, release_cpio_sha256="e" * 64,
        initrd_sha256="7d" * 32, s3_bucket=BAKE_BUCKET,
        s3_key_prefix="tenant/golden-ck-gr2/", measurement={},
    )
    GoldenImage.objects.create(
        image_name="ubuntu", distro="ubuntu", bake_id="bake-ck",
        blessed_at=timezone.now(), guest_release=2,
    )
    intent = _intent(image="ubuntu")
    intent.pop("bake_id")
    launch_jobs._resolve_bake(intent)
    assert intent["initrd_sha256_hex"] == "7d" * 32
    ck.check_new_launch(intent, ck.binding_of(intent))
    # A build that is not of this bake's initrd does not stand in.
    intent["initrd_sha256_hex"] = "8e" * 32
    with pytest.raises(ck.CustomerKeysError, match="customer-keys-artifact-mismatch"):
        ck.check_new_launch(intent, ck.binding_of(intent))


@pytest.mark.usefixtures("enabled")
def test_an_m1_intake_whose_userdata_has_no_netbird_up_is_refused(vault) -> None:
    _bake()
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-netbird-up-not-found"):
        _start(_intent(vm_id="vm-nbx"), userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n")
    assert vault["put"] == [] and vault["datakey"] == []
    # M0 with the same userdata is none of this rule's business.
    _start(
        _intent(vm_id="vm-nbx0", key_mode="hippius", guardian_endpoint=None, guardian_pubkey=None),
        userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
    )


@pytest.mark.usefixtures("enabled")
def test_bad_guardian_fields_are_refused_at_intake(vault) -> None:
    _bake()
    with pytest.raises(launch_jobs.LaunchIntentError, match="bad-guardian-pk"):
        _start(_intent(guardian_pubkey=PK.upper()))
    with pytest.raises(launch_jobs.LaunchIntentError, match="orphan"):
        _start(_intent(key_mode="hippius"))


# ── 4. KEK: M1 = today's, M2 = none ──────────────────────────────────────


@pytest.mark.usefixtures("enabled")
def test_m1_provisions_exactly_todays_wrapped_kek(vault) -> None:
    _bake()
    job = _start(_intent(vm_id="vm-m1"))
    assert vault["datakey"] == ["kek-vm-m1"]
    assert _luks("vm-m1") in vault["put"]
    assert job.kek_vault_path == _luks("vm-m1")
    assert job.spec_json["key_mode"] == "split"
    assert job.spec_json["guardian_endpoint"] == EP
    assert job.spec_json["guardian_pubkey"] == PK


@pytest.mark.usefixtures("enabled")
def test_m2_generates_and_stages_no_kek(vault) -> None:
    _bake()
    job = _start(_intent(vm_id="vm-m2", key_mode="customer"))
    # No Transit datakey (no KEK generated), nothing written at luks-kek.
    assert vault["datakey"] == []
    assert _luks("vm-m2") not in vault["put"]
    # The job names the canonical path — a name, nothing behind it.
    assert job.kek_vault_path == _luks("vm-m2")
    assert job.spec_json["key_mode"] == "customer"


@pytest.mark.usefixtures("enabled")
def test_m2_refuses_a_caller_supplied_kek(vault) -> None:
    _bake()
    with pytest.raises(launch_jobs.LaunchIntentError, match="takes no kek_vault_path"):
        _start(_intent(vm_id="vm-m2k", key_mode="customer", kek_vault_path=_luks("vm-m2k")))
    assert vault["put"] == []


@pytest.mark.usefixtures("enabled")
def test_a_repost_for_an_existing_vm_must_keep_its_mode(vault) -> None:
    _bake()
    Vm.objects.create(
        vm_id="vm-rp", lease_id="lease-1", state="active", generation=1, host="",
        lifecycle_vk=bytes(32),
    )
    with pytest.raises(launch_jobs.LaunchIntentError, match="key-mode-immutable") as exc:
        _start(_intent(vm_id="vm-rp", key_mode="customer"))
    assert exc.value.category == "conflict"
    assert vault["put"] == [] and vault["datakey"] == []


@pytest.mark.usefixtures("enabled")
def test_m2_refuses_a_vm_id_that_already_holds_a_provider_kek(vault) -> None:
    """An M1 attempt that failed after provisioning its KEK must not let a
    retry under the same vm_id become an "M2" VM with a KEK beside it."""
    _bake()
    vault["put"].append(_luks("vm-orphan"))  # the earlier attempt's KEK
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-kek-present") as exc:
        _start(_intent(vm_id="vm-orphan", key_mode="customer"))
    assert exc.value.category == "conflict"
    assert vault["datakey"] == []


def test_m0_spec_json_carries_no_customer_keys_fields(vault) -> None:
    body = _intent(vm_id="vm-m0", key_mode=None, guardian_endpoint=None, guardian_pubkey=None)
    _bake(capable=False)
    job = _start(body)
    assert not {"key_mode", "guardian_endpoint", "guardian_pubkey"} & set(job.spec_json)
    # …and an explicit `hippius` is the same M0.
    job2 = _start(_intent(vm_id="vm-m0b", key_mode="hippius", guardian_endpoint="",
                          guardian_pubkey=""))
    assert "key_mode" not in job2.spec_json


# ── 2/3/4/5. launch_on_miner ────────────────────────────────────────────


def _miner() -> MinerIdentity:
    miner, _ = MinerIdentity.objects.get_or_create(
        miner_id="miner-ck",
        defaults=dict(
            pubkey_hex="1" * 64,
            platform_id="ab" * 16,
            netbird_ip="100.64.0.9",
            chain_node_id="0" * 63 + "9",
            last_seen_at=timezone.now(),
            last_heartbeat_sequence=1,
            status=MinerStatus.ACTIVE,
        ),
    )
    return miner


def _spec(vm_id: str = "vm-ck-1", mode: str = "split", **overrides) -> launch.LaunchSpec:
    base = dict(
        tenant_id="t-ck", user_id="u-1", vm_id=vm_id, lease_id="lease-1",
        s3_bucket=BAKE_BUCKET, s3_key_prefix=BAKE_PREFIX,
        luks_disk_sha256_hex=ROOTFS_IMG, kernel_sha256_hex=KERNEL,
        initrd_sha256_hex=INITRD, luks_header_sha256_hex="",
        flavor="small", cmdline="ro", kek_bytes=None,
        userdata=b"#cloud-config\n", enable_netbird=False,
        disk_mode="golden_verity_overlay", verity_root_hash_hex=VERITY,
        rootfs_img_sha256_hex=ROOTFS_IMG, rootfs_verity_sha256_hex=ROOTFS_VERITY,
        bake_id="bake-ck",
    )
    if mode != "hippius":
        base.update(key_mode=mode, guardian_endpoint=EP, guardian_pubkey=PK)
    base.update(overrides)
    return launch.LaunchSpec(**base)


class _Harness:
    def __init__(self) -> None:
        self.preflight_cmdlines: list[str] = []
        self.recompute_cmdlines: list[str] = []
        self.mints: list[ticket_mint.MintArgs] = []
        self.intakes: list[dict] = []
        self.payloads: list[dict] = []
        self.latest_version: list[str] = []
        self.puts: list[str] = []
        self.datakeys: list[str] = []
        self.present: set[str] = set()  # KV paths `kv_exists` reports


@pytest.fixture
def harness(monkeypatch) -> _Harness:
    """Drive the REAL `launch_on_miner` with every collaborator stubbed, and
    record what the measured-cmdline / ticket / order / Vault edges saw."""
    from apps.orchestration.services import launch_digest as ld
    from apps.orchestration.services import preflight as pf

    h = _Harness()
    monkeypatch.setattr(ld, "enforce", lambda: True)
    monkeypatch.setattr(ld, "is_enabled", lambda: True)

    def recompute(**kw):
        h.recompute_cmdlines.append(kw["cmdline"])
        return "ab" * 48

    monkeypatch.setattr(ld, "recompute_expected_digest", recompute)

    def preflight(**kw):
        h.preflight_cmdlines.append(kw["cmdline"])
        vm = kw["vm_id"]
        return pf.PreflightResult(
            launch_digest_hex="ab" * 48, luks_disk_path=f"/s/{vm}/vda",
            kernel_path="/k", initrd_path="/i",
            rootfs_data_path=f"/var/lib/hippius-miner/staging/{vm}/rootfs.img",
            rootfs_hash_path=f"/var/lib/hippius-miner/staging/{vm}/rootfs.verity",
        )

    monkeypatch.setattr(pf, "dispatch_preflight", preflight)

    def latest(mount, path):
        h.latest_version.append(path)
        return 4

    def put(mount, path, value, **kw):
        h.puts.append(path)
        return vault_kv.VaultWriteResult(version=1)

    monkeypatch.setattr(vault_kv, "latest_version", latest)
    monkeypatch.setattr(vault_kv, "put_kv", put)
    monkeypatch.setattr(vault_kv, "kv_exists", lambda m, p: p in h.present)
    monkeypatch.setattr(vault_kv, "ensure_transit_key", lambda *a, **k: None)
    monkeypatch.setattr(vault_kv, "transit_encrypt", lambda *a, **k: b"vault:v1:x")
    monkeypatch.setattr(
        vault_kv, "transit_datakey_wrapped", lambda n: h.datakeys.append(n) or b"vault:v1:k"
    )
    monkeypatch.setattr(
        launch, "_stage_lifecycle_key", lambda *a, **k: (b"\x01" * 32, b"\x02" * 32)
    )
    monkeypatch.setattr(launch.telemetry_keygen, "derive_telemetry_vk", lambda *a: b"\x03" * 32)

    def mint(args):
        h.mints.append(args)
        return b"cose"

    monkeypatch.setattr(ticket_mint, "mint", mint)
    monkeypatch.setattr(
        migration_ticket, "persist_intake", lambda cose, **kw: h.intakes.append(kw)
    )
    monkeypatch.setattr(
        launch.kbs_admin,
        "register_vm_active_with_vm_id",
        lambda *a, **k: SimpleNamespace(vm_id=k.get("vm_id", ""), vm_generation=1, cached=False),
    )
    real_payload = order_dispatch.build_launch_payload

    def payload(**kw):
        p = real_payload(**kw)
        h.payloads.append(p)
        return p

    monkeypatch.setattr(order_dispatch, "build_launch_payload", payload)
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(ok=True, status=200, classifier="launched"),
    )
    monkeypatch.setattr(launch, "_record_base_image", lambda *a, **k: None)
    return h


def _fix_nonces(monkeypatch) -> None:
    """Deterministic per-launch nonces, so a cmdline can be compared as bytes."""
    monkeypatch.setattr(launch.secrets, "token_bytes", lambda n: b"\x07" * n)
    monkeypatch.setattr(launch, "_current_billing_epoch", lambda: 42)


#: The exact measured cmdline an M0 golden launch of `_spec(mode="hippius")`
#: produced BEFORE customer keys existed (captured on origin/main with the
#: same harness). M0 must stay byte-identical.
M0_GOLDEN_CMDLINE = (
    "ro dm-verity.root=" + VERITY + " boot=hippius-golden systemd.import_credentials=no "
    "hippius.disk_gb=40 "
    "hippius.lifecycle_key_path=/run/hippius/lifecycle.key hippius.node_id="
    + "0" * 63 + "9 hippius.resource_class=small hippius.family_id=742d636b "
    "hippius.validator_id=686970706975732d76616c692d7631 hippius.validator_nonce="
    + "07" * 32 + " hippius.telemetry_epoch=42 hippius.vm_id=vm-m0 hippius.lease_id=lease-1 "
    "hippius.vm_generation=1 hippius.vali_url=vsock://2:19266 "
    "hippius.kbs_url=vsock://2:19266 hippius.eol_nonce=" + "07" * 32
)


def test_m0_cmdline_ticket_and_order_are_unchanged(harness, monkeypatch) -> None:
    _fix_nonces(monkeypatch)
    out = launch.launch_on_miner(_spec(vm_id="vm-m0", mode="hippius"), _miner())
    assert out.disposition == launch.ACCEPTED, out.emit
    assert harness.preflight_cmdlines == [M0_GOLDEN_CMDLINE]
    (m,) = harness.mints
    assert m.key_mode == "hippius"
    assert harness.intakes[0]["expected_key_mode"] == "hippius"
    (p,) = harness.payloads
    assert "guardian_ep" not in p
    assert Vm.objects.get(vm_id="vm-m0").key_mode == "hippius"


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_customer_keys_tokens_are_measured_before_the_digest(harness, monkeypatch, mode) -> None:
    _fix_nonces(monkeypatch)
    out = launch.launch_on_miner(_spec(vm_id=f"vm-{mode}", mode=mode), _miner())
    assert out.disposition == launch.ACCEPTED, out.emit
    expected = M0_GOLDEN_CMDLINE.replace("vm-m0", f"vm-{mode}") + " " + _tokens(mode)
    # the miner measured it, vali recomputed the digest over it, and the
    # launch order carries it — all the SAME bytes, tokens included
    assert harness.preflight_cmdlines == [expected]
    assert harness.recompute_cmdlines == [expected]
    (p,) = harness.payloads
    assert p["cmdline"] == expected
    assert p["guardian_ep"] == EP
    (m,) = harness.mints
    assert m.key_mode == mode
    assert harness.intakes[0]["expected_key_mode"] == mode
    vm = Vm.objects.get(vm_id=f"vm-{mode}")
    assert (vm.key_mode, vm.guardian_endpoint, vm.guardian_pubkey) == (mode, EP, PK)


def test_m2_reads_no_kek_and_names_the_ref_at_the_constant_version(harness) -> None:
    launch.launch_on_miner(_spec(vm_id="vm-c2", mode="customer"), _miner())
    assert _luks("vm-c2") not in harness.latest_version
    assert _luks("vm-c2") not in harness.puts
    assert harness.datakeys == []
    (m,) = harness.mints
    assert m.luks_vault_path == _luks("vm-c2")
    assert m.luks_vault_version == ck.M2_LUKS_REF_VERSION == 1


def test_m2_launch_refuses_a_provider_kek_at_the_path(harness) -> None:
    harness.present.add(_luks("vm-c4"))
    out = launch.launch_on_miner(_spec(vm_id="vm-c4", mode="customer"), _miner())
    assert out.disposition == launch.TERMINAL
    assert "customer-keys-kek-present" in out.emit["error"]
    assert harness.mints == [] and harness.preflight_cmdlines == []


def test_m1_reads_the_staged_kek_version_as_today(harness) -> None:
    launch.launch_on_miner(_spec(vm_id="vm-s2", mode="split"), _miner())
    assert harness.latest_version == [_luks("vm-s2")]
    assert harness.mints[0].luks_vault_version == 4


def test_m2_refuses_a_plaintext_kek(harness) -> None:
    with pytest.raises(launch.LaunchConfigError, match="no Hippius disk KEK"):
        launch.launch_on_miner(
            _spec(vm_id="vm-c3", mode="customer", kek_bytes=b"\x00" * 32), _miner()
        )
    assert harness.puts == [] and not Vm.objects.filter(vm_id="vm-c3").exists()


def test_customer_keys_are_golden_only_at_launch(harness) -> None:
    with pytest.raises(launch.LaunchConfigError, match="golden-only"):
        launch.launch_on_miner(
            _spec(vm_id="vm-l", disk_mode="legacy_luks", luks_header_sha256_hex="a" * 64),
            _miner(),
        )
    assert not Vm.objects.filter(vm_id="vm-l").exists()


def _padded_base(harness, monkeypatch, total: int, vm_id: str, mode: str = "hippius") -> str:
    """A base cmdline whose measured cmdline is exactly `total` bytes when
    launched as `vm_id` in `mode` (the augmentation is measured on a
    throwaway launch of the same shape; the vm_id is in the cmdline)."""
    _fix_nonces(monkeypatch)
    probe = f"probe-{vm_id}"
    launch.launch_on_miner(_spec(vm_id=probe, mode=mode), _miner())
    grown = len(harness.preflight_cmdlines[-1]) - len("ro") - len(probe) + len(vm_id)
    return "ro " + "x" * (total - grown - 3)


def test_the_length_check_sees_the_guardian_tokens(harness, monkeypatch) -> None:
    """A base cmdline that fits for M0 but not once the three guardian tokens
    are appended is refused: the tokens go in BEFORE the 2033-byte check."""
    base = _padded_base(
        harness, monkeypatch, ck.KEY_MODE_TRUNCATION_FLOOR_MEASURED - 1, "vm-lenb"
    )
    ok = launch.launch_on_miner(_spec(vm_id="vm-lenb", mode="hippius", cmdline=base), _miner())
    assert ok.disposition == launch.ACCEPTED, ok.emit
    assert len(harness.preflight_cmdlines[-1]) == ck.KEY_MODE_TRUNCATION_FLOOR_MEASURED - 1
    mints = len(harness.mints)
    # A NEW M1/M2 vm_id is refused BEFORE its row pins the mode.
    with pytest.raises(launch.LaunchConfigError, match=r"cmdline-too-long: .*> 2033"):
        launch.launch_on_miner(_spec(vm_id="vm-lenc", cmdline=base), _miner())
    assert not Vm.objects.filter(vm_id="vm-lenc").exists()
    assert len(harness.mints) == mints


def test_the_truncation_floor_is_2022_and_2008_measured() -> None:
    """H5b's guest constant: 2047 minus `hippius.key_mode=customer`, in
    `/proc/cmdline` bytes; vali's band is that less OVMF's 14-byte prefix."""
    assert ck.KEY_MODE_TRUNCATION_FLOOR == 2022
    assert ck.KEY_MODE_TRUNCATION_FLOOR_MEASURED == 2008


def test_an_m0_cmdline_in_the_key_mode_truncation_band_is_refused(harness, monkeypatch) -> None:
    """H5b: the guest refuses to boot a /proc/cmdline of >= 2022 bytes
    (measured >= 2008) with no `hippius.key_mode` token. vali must not mint
    one (it would be an M0 VM that never boots)."""
    base = _padded_base(harness, monkeypatch, ck.KEY_MODE_TRUNCATION_FLOOR_MEASURED, "vm-band")
    mints, pre = len(harness.mints), len(harness.preflight_cmdlines)
    out = launch.launch_on_miner(_spec(vm_id="vm-band", mode="hippius", cmdline=base), _miner())
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "cmdline-too-long"
    assert "2008 bytes (>= 2008) with no hippius.key_mode token" in out.emit["error"]
    # Refused before the preflight, the mint and anything the miner sees.
    assert len(harness.mints) == mints and len(harness.preflight_cmdlines) == pre


def test_an_m0_cmdline_with_an_explicit_key_mode_token_may_use_the_band(
    harness, monkeypatch
) -> None:
    """The guest only refuses a TOKEN-LESS long cmdline; an M0 cmdline that
    names `hippius.key_mode=hippius` boots, so vali does not refuse it."""
    base = _padded_base(harness, monkeypatch, 2030 - len(" hippius.key_mode=hippius"), "vm-bt")
    out = launch.launch_on_miner(
        _spec(vm_id="vm-bt", mode="hippius",
              cmdline=base + " hippius.key_mode=hippius"),
        _miner(),
    )
    assert out.disposition == launch.ACCEPTED, out.emit
    assert len(harness.preflight_cmdlines[-1]) == 2030


def test_an_m1_cmdline_in_the_band_carries_its_token_and_is_accepted(harness, monkeypatch) -> None:
    base = _padded_base(harness, monkeypatch, ck.MAX_MEASURED_CMDLINE_LEN, "vm-b1", mode="split")
    # Pinned already, so only the exact in-flow checks apply (the pre-pin
    # one is conservative on the epoch near 2033).
    _pinned_vm("vm-b1", "split")
    out = launch.launch_on_miner(_spec(vm_id="vm-b1", cmdline=base), _miner())
    assert out.disposition == launch.ACCEPTED, out.emit
    assert len(harness.preflight_cmdlines[-1]) == ck.MAX_MEASURED_CMDLINE_LEN


def test_a_normal_m0_cmdline_is_untouched_by_the_caps(harness, monkeypatch) -> None:
    """~900 bytes, the size of a real golden M0 cmdline with a long base:
    nowhere near either cap, launched byte for byte."""
    base = _padded_base(harness, monkeypatch, 900, "vm-900")
    out = launch.launch_on_miner(_spec(vm_id="vm-900", mode="hippius", cmdline=base), _miner())
    assert out.disposition == launch.ACCEPTED, out.emit
    assert len(harness.preflight_cmdlines[-1]) == 900
    assert "hippius.key_mode" not in harness.preflight_cmdlines[-1]


@pytest.mark.parametrize(
    ("total", "explicit_token", "accepted"),
    [
        (2007, False, True),  # token-less, one below the band
        (2008, False, False),  # token-less, first byte of the band
        (2033, True, True),  # the measured cap, with an explicit M0 token
        (2034, True, False),  # one past the cap, whatever the token
    ],
)
def test_the_m0_cap_boundaries_are_exact(harness, monkeypatch, total, explicit_token, accepted):
    tail = " hippius.key_mode=hippius" if explicit_token else ""
    vm_id = f"vm-cap{total}"
    base = _padded_base(harness, monkeypatch, total - len(tail), vm_id) + tail
    out = launch.launch_on_miner(_spec(vm_id=vm_id, mode="hippius", cmdline=base), _miner())
    if accepted:
        assert out.disposition == launch.ACCEPTED, out.emit
        assert len(harness.preflight_cmdlines[-1]) == total
    else:
        assert out.disposition == launch.TERMINAL
        assert out.emit["outcome"] == "cmdline-too-long"
        assert f"{total} bytes" in out.emit["error"]


def test_an_m1_cmdline_one_past_the_measured_cap_is_refused(harness, monkeypatch) -> None:
    base = _padded_base(harness, monkeypatch, ck.MAX_MEASURED_CMDLINE_LEN, "vm-b2", mode="split")
    _pinned_vm("vm-b2", "split")
    out = launch.launch_on_miner(_spec(vm_id="vm-b2", cmdline=base + "y"), _miner())
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "cmdline-too-long"
    assert "2034 bytes (> 2033)" in out.emit["error"]


def test_the_dispatch_launch_command_refuses_a_cmdline_past_the_measured_cap() -> None:
    from apps.orchestration.management.commands import vali_dispatch_launch as cmd

    base = _measured("hippius") + " hippius.key_mode=hippius"
    at = base + " " + "x" * (ck.MAX_MEASURED_CMDLINE_LEN - len(base) - 1)
    assert len(at) == ck.MAX_MEASURED_CMDLINE_LEN
    assert cmd._customer_keys_mismatch("vm-cli-cap", at, "hippius") is None
    got = cmd._customer_keys_mismatch("vm-cli-cap", at + "y", "hippius")
    assert got is not None and "2034 bytes (> 2033)" in got


#: Another guardian than the spec's, measured the H1b way.
_OTHER_EP_TOKEN = b"10.0.0.1:1".hex()


def test_an_operator_baked_guardian_token_that_disagrees_is_refused(harness) -> None:
    # M1/M2 first launch: refused before the pin, no row.
    with pytest.raises(launch.LaunchConfigError, match="customer-keys-cmdline-refused"):
        launch.launch_on_miner(
            _spec(vm_id="vm-bk", cmdline=f"ro hippius.guardian_ep={_OTHER_EP_TOKEN}"), _miner()
        )
    assert not Vm.objects.filter(vm_id="vm-bk").exists()
    # …and for a pinned VM (no pre-pin check) the in-flow refusal holds.
    _pinned_vm("vm-bk1", "split")
    out = launch.launch_on_miner(
        _spec(vm_id="vm-bk1", cmdline=f"ro hippius.guardian_ep={_OTHER_EP_TOKEN}"), _miner()
    )
    assert out.emit["outcome"] == "customer-keys-cmdline-refused"
    out = launch.launch_on_miner(
        _spec(vm_id="vm-bk0", mode="hippius", cmdline=f"ro {_tokens('split')}"), _miner()
    )
    assert out.emit["outcome"] == "customer-keys-cmdline-refused"
    assert harness.mints == []


# ── 5. immutability ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "overrides",
    [
        {"mode": "hippius"},
        {"mode": "customer"},
        {"guardian_endpoint": "100.64.3.8:7443"},
        {"guardian_pubkey": "a" * 64},
    ],
)
def test_a_relaunch_with_another_mode_or_guardian_is_refused(harness, overrides) -> None:
    launch.launch_on_miner(_spec(vm_id="vm-pin"), _miner())
    harness.mints.clear()
    with pytest.raises(launch.LaunchConfigError, match="key-mode-immutable"):
        launch.launch_on_miner(_spec(vm_id="vm-pin", **overrides), _miner())
    assert harness.mints == []
    vm = Vm.objects.get(vm_id="vm-pin")
    assert (vm.key_mode, vm.guardian_endpoint, vm.guardian_pubkey) == ("split", EP, PK)


def test_an_existing_m0_vm_is_never_relaunched_as_customer_keys(harness) -> None:
    Vm.objects.create(
        vm_id="vm-old", lease_id="lease-1", state="active", generation=1, host="",
        lifecycle_vk=bytes(32),
    )
    with pytest.raises(launch.LaunchConfigError, match="key-mode-immutable"):
        launch.launch_on_miner(_spec(vm_id="vm-old"), _miner())


def _succeeded_job(vm_id: str, spec_json: dict, *, measured_cmdline: str | None) -> LaunchJob:
    from apps.identity.models import PrincipalScope, ServiceClient

    actor, _ = ServiceClient.objects.get_or_create(
        scope=PrincipalScope.OPERATOR.value, name="root-ck"
    )
    emit = {"measurement_hex": "ab" * 48}
    if measured_cmdline is not None:
        emit["measured_cmdline"] = measured_cmdline
    return LaunchJob.objects.create(
        job_id=uuid.uuid4().hex, vm_id=vm_id, tenant_id="t-ck", flavor="small",
        spec_json=spec_json, userdata_vault_path=f"p/{vm_id}/userdata-intake",
        userdata_vault_version=1, kek_vault_path=_luks(vm_id),
        state=LaunchJobState.SUCCEEDED.value, finished_at=timezone.now(),
        phase_started_at=timezone.now(), decided_by=actor,
        result_json={"emit": emit},
    )


def _spec_json(vm_id: str, mode: str) -> dict:
    s = _spec(vm_id=vm_id, mode=mode)
    keys = [
        "tenant_id", "user_id", "vm_id", "lease_id", "s3_bucket", "s3_key_prefix",
        "luks_disk_sha256_hex", "kernel_sha256_hex", "initrd_sha256_hex",
        "luks_header_sha256_hex", "flavor", "cmdline", "enable_netbird", "disk_mode",
        "verity_root_hash_hex", "rootfs_img_sha256_hex", "rootfs_verity_sha256_hex",
        "bake_id",
    ]
    out = {k: getattr(s, k) for k in keys}
    if mode != "hippius":
        out.update(ck.spec_fields(ck.binding_of(s)))
    return out


def _pinned_vm(vm_id: str, mode: str, host: str = "miner-ck") -> Vm:
    fields = ck.spec_fields(None if mode == "hippius" else ck.GuardianBinding(mode, PK, EP))
    return Vm.objects.create(
        vm_id=vm_id, lease_id="lease-1", tenant_id="t-ck", state="active", generation=1,
        host=host, lifecycle_vk=bytes(32), **fields,
    )


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_reboot_recovery_and_power_start_relaunch_carry_the_mode(monkeypatch, mode) -> None:
    """`_reboot_recovery_relaunch` is also what a power `start` runs."""
    from apps.orchestration import service

    _miner()
    vm = _pinned_vm(f"vm-rr-{mode}", mode)
    _succeeded_job(vm.vm_id, _spec_json(vm.vm_id, mode), measured_cmdline=None)
    monkeypatch.setattr(launch, "open_userdata_intake_copy", lambda *a: b"#cloud-config\n")
    seen: list[launch.LaunchSpec] = []

    def fake_launch(spec, miner, **kw):
        seen.append(spec)
        # the real entry check the relaunch passes through
        launch._ensure_vm_row(spec)
        return launch.LaunchOutcome(disposition=launch.TERMINAL, emit={}, exit_code=1)

    monkeypatch.setattr(launch, "launch_on_miner", fake_launch)
    service._reboot_recovery_relaunch(vm, "miner-ck")
    (spec,) = seen
    assert (spec.key_mode, spec.guardian_endpoint, spec.guardian_pubkey) == (mode, EP, PK)


def test_reboot_recovery_refuses_a_spec_that_lost_the_mode(monkeypatch) -> None:
    from apps.orchestration import service

    _miner()
    vm = _pinned_vm("vm-rr-lost", "split")
    _succeeded_job(vm.vm_id, _spec_json(vm.vm_id, "hippius"), measured_cmdline=None)
    monkeypatch.setattr(launch, "open_userdata_intake_copy", lambda *a: b"#cloud-config\n")
    refused: list[str] = []

    def fake_launch(spec, miner, **kw):
        try:
            launch._ensure_vm_row(spec)
        except launch.LaunchConfigError as exc:
            refused.append(str(exc))
            raise
        raise AssertionError("an M1 VM was relaunched as M0")

    monkeypatch.setattr(launch, "launch_on_miner", fake_launch)
    assert service._reboot_recovery_relaunch(vm, "miner-ck") is False
    assert refused and "key-mode-immutable" in refused[0]


# ── §25 / vali_kbs_recover re-mints ─────────────────────────────────────


@pytest.fixture
def remint(monkeypatch):
    seen: dict = {"mints": [], "latest": [], "intakes": []}

    def mint(args):
        seen["mints"].append(args)
        return b"cose"

    monkeypatch.setattr(ticket_mint, "mint", mint)
    monkeypatch.setattr(
        vault_kv, "latest_version", lambda m, p: seen["latest"].append(p) or 3
    )
    monkeypatch.setattr(migration_ticket, "_read_userdata_plaintext", lambda i, v: b"ud")
    monkeypatch.setattr(migration_ticket, "_node_platform_id", lambda n: "ab" * 16)
    monkeypatch.setattr(
        migration_ticket, "persist_intake", lambda cose, **kw: seen["intakes"].append(kw)
    )
    return seen


def _measured(mode: str) -> str:
    base = f"ro dm-verity.root={VERITY} boot=hippius-golden hippius.vm_id=x"
    return base if mode == "hippius" else f"{base} {_tokens(mode)}"


@pytest.mark.parametrize("mode", ["hippius", "split", "customer"])
def test_the_kbs_recover_and_migration_remint_carry_the_mode(remint, mode) -> None:
    vm = _pinned_vm(f"vm-re-{mode}", mode)
    _succeeded_job(vm.vm_id, _spec_json(vm.vm_id, mode), measured_cmdline=_measured(mode))
    migration_ticket.remint_current_ticket(vm)  # vali_kbs_recover
    migration_ticket.remint_dest_ticket(vm, dest_node_id="miner-ck", new_gen=2)  # §25
    assert [m.key_mode for m in remint["mints"]] == [mode, mode]
    assert [i["expected_key_mode"] for i in remint["intakes"]] == [mode, mode]
    if mode == "customer":
        # M2: no KEK to read; the ref names the path at the constant version.
        assert _luks(vm.vm_id) not in remint["latest"]
        assert {m.luks_vault_version for m in remint["mints"]} == {ck.M2_LUKS_REF_VERSION}
    else:
        assert _luks(vm.vm_id) in remint["latest"]


@pytest.mark.parametrize(
    ("pinned", "measured"),
    [("split", "hippius"), ("customer", "split"), ("hippius", "split"), ("split", None)],
)
def test_a_remint_never_downgrades_or_adopts_a_mode(remint, pinned, measured) -> None:
    vm = _pinned_vm(f"vm-dg-{pinned}", pinned)
    _succeeded_job(
        vm.vm_id, _spec_json(vm.vm_id, pinned),
        measured_cmdline=None if measured is None else _measured(measured),
    )
    with pytest.raises(EffectError, match="key-mode"):
        migration_ticket.remint_current_ticket(vm)
    assert remint["mints"] == []


def test_a_stored_ticket_with_another_mode_is_not_reused(remint, monkeypatch) -> None:
    from apps.orders import validator
    from apps.orders.models import OrderTicketIntake

    vm = _pinned_vm("vm-reuse", "split")
    _succeeded_job(vm.vm_id, _spec_json(vm.vm_id, "split"), measured_cmdline=_measured("split"))
    OrderTicketIntake.objects.create(
        ticket_id="tk-stale", vm_id=vm.vm_id, tenant_id="t-ck", user_id="u-1",
        lease_id="lease-1", vm_generation=2, issue_time=1, expiry=2, node_id="miner-ck",
        platform_id="ab" * 16, resource_class="small", kid_hex="6b", cose_blob=b"stale",
        received_from="system:migration-remint",
    )
    monkeypatch.setattr(validator, "validate_ticket", lambda c: SimpleNamespace(key_mode="hippius"))
    blob = migration_ticket.remint_dest_ticket(vm, dest_node_id="miner-ck", new_gen=2)
    assert blob == b"cose"  # re-minted, not the stored M0 blob
    assert [m.key_mode for m in remint["mints"]] == ["split"]
    # …while a stored ticket in the pinned mode IS reused (no re-mint)
    remint["mints"].clear()
    monkeypatch.setattr(validator, "validate_ticket", lambda c: SimpleNamespace(key_mode="split"))
    OrderTicketIntake.objects.filter(vm_id=vm.vm_id).exclude(ticket_id="tk-stale").delete()
    assert migration_ticket.remint_dest_ticket(vm, dest_node_id="miner-ck", new_gen=2) == b"stale"
    assert remint["mints"] == []


@pytest.mark.parametrize(
    ("row", "cmdline_mode", "ticket_mode", "refused"),
    [
        ("split", "split", "split", False),
        ("split", "hippius", "hippius", True),
        ("split", "split", "hippius", True),
        (None, "split", "split", True),
        (None, "hippius", "hippius", False),
        ("hippius", "hippius", "hippius", False),
    ],
)
def test_the_dispatch_launch_command_holds_the_pin(row, cmdline_mode, ticket_mode, refused) -> None:
    from apps.orchestration.management.commands import vali_dispatch_launch as cmd

    if row is not None:
        _pinned_vm("vm-cli", row)
    got = cmd._customer_keys_mismatch("vm-cli", _measured(cmdline_mode), ticket_mode)
    assert (got is not None) is refused, got


def test_a_self_minted_ticket_with_the_wrong_mode_is_not_persisted(monkeypatch) -> None:
    from apps.orders import validator

    monkeypatch.setattr(
        validator, "validate_ticket",
        lambda cose: SimpleNamespace(key_mode="hippius"),
    )
    with pytest.raises(EffectError, match="carries key_mode='hippius'"):
        migration_ticket.persist_intake(
            b"x", vm_id="v", generation=1, ticket_id="t", expected_key_mode="split"
        )


# ── §25 migrate-activate + restore orders ───────────────────────────────


@pytest.mark.parametrize("mode", ["hippius", "split"])
def test_migrate_activate_carries_the_guardian(monkeypatch, fx, mode) -> None:
    vm = _pinned_vm(f"vm-ma-{mode}", mode)
    monkeypatch.setattr(effects, "_miner_identity", lambda n: ("miner-ck", "100.64.0.9"))
    monkeypatch.setattr(migration_ticket, "remint_dest_ticket", lambda *a, **k: b"cose")
    monkeypatch.setattr(effects, "_launch_paths", lambda v: {
        "cmdline": _measured(mode), "ovmf_path": "/o", "kernel_path": "/k",
        "initrd_path": "/i", "luks_disk_path": "/d", "luks_disk_size_gb": 1,
        "rootfs_data_path": "/r", "rootfs_hash_path": "/h", "cpu_count": 1, "memory_mb": 1,
    })
    sent: list[dict] = []

    def dispatch(**kw):
        sent.append(json.loads(kw["payload_json"]))
        return order_dispatch.DispatchResult(ok=True, status=200, classifier="ok")

    monkeypatch.setattr(order_dispatch, "dispatch_order", dispatch)
    # the REAL effect (the suite's autouse `fx` fakes it by default)
    fx.real["dispatch_migrate_activate"](
        vm, dest_node_id="miner-b", new_gen=2, get_url="https://s3/x", boot_artifacts=None
    )
    (payload,) = sent
    if mode == "hippius":
        assert "guardian_ep" not in payload
    else:
        assert payload["guardian_ep"] == EP


def test_migrate_activate_refuses_a_cmdline_that_lost_the_binding(monkeypatch, fx) -> None:
    vm = _pinned_vm("vm-ma-lost", "split")
    monkeypatch.setattr(effects, "_miner_identity", lambda n: ("miner-ck", "100.64.0.9"))
    monkeypatch.setattr(migration_ticket, "remint_dest_ticket", lambda *a, **k: b"cose")
    monkeypatch.setattr(effects, "_launch_paths", lambda v: {"cmdline": _measured("hippius")})
    monkeypatch.setattr(order_dispatch, "dispatch_order", lambda **kw: pytest.fail("dispatched"))
    with pytest.raises(EffectError, match="key-mode-cmdline-mismatch"):
        fx.real["dispatch_migrate_activate"](
            vm, dest_node_id="miner-b", new_gen=2, get_url="https://s3/x", boot_artifacts=None
        )


def _activate_payload(cmdline: str, **kw) -> dict:
    return order_dispatch.build_migrate_activate_payload(
        vm_id="vm-w", get_url=kw.pop("get_url", "https://s3/x"), new_gen=2,
        ovmf_path="/var/lib/hippius-miner/ovmf.fd", kernel_path="/var/lib/hippius-miner/k",
        initrd_path="/var/lib/hippius-miner/i", cmdline=cmdline,
        luks_disk_path="/var/lib/hippius-miner/d", luks_disk_size_gb=1,
        rootfs_data_path="/var/lib/hippius-miner/r", rootfs_hash_path="/var/lib/hippius-miner/h",
        cpu_count=1, memory_mb=1024, cose_ticket=b"cose", **kw,
    )


def _launch_payload(cmdline: str) -> dict:
    return order_dispatch.build_launch_payload(
        vm_id="vm-w", ovmf_path="/var/lib/hippius-miner/ovmf.fd",
        kernel_path="/var/lib/hippius-miner/k", initrd_path="/var/lib/hippius-miner/i",
        cmdline=cmdline, luks_disk_path="/var/lib/hippius-miner/d", luks_disk_size_gb=1,
        rootfs_data_path="/var/lib/hippius-miner/r", rootfs_hash_path="/var/lib/hippius-miner/h",
        cpu_count=1, memory_mb=1024, cose_ticket=b"cose",
    )


_PRE_CUSTOMER_KEYS_LAUNCH_KEYS = {
    "vm_id", "ovmf_path", "kernel_path", "initrd_path", "cmdline", "luks_disk_path",
    "luks_disk_size_gb", "data_disk_size_gb", "rootfs_data_path", "rootfs_hash_path",
    "cpu_count", "memory_mb", "cose_ticket",
}


def test_m0_orders_have_exactly_the_pre_customer_keys_shape() -> None:
    assert set(_launch_payload(_measured("hippius"))) == _PRE_CUSTOMER_KEYS_LAUNCH_KEYS
    assert "guardian_ep" not in _activate_payload(_measured("hippius"))
    assert "guardian_ep" not in _activate_payload(
        _measured("hippius"), get_url="", staged_restore_id="r" * 32
    )


def test_a_restore_order_carries_the_guardian() -> None:
    p = _activate_payload(_measured("split"), get_url="", staged_restore_id="r" * 32)
    assert p["guardian_ep"] == EP


def test_an_order_with_a_malformed_guardian_cmdline_is_not_built() -> None:
    with pytest.raises(ValueError, match="guardian-cmdline"):
        _launch_payload(f"ro hippius.guardian_ep={EP_TOKEN}")


# ── real binaries: encode-order + mint/validate ─────────────────────────

_VALIDATOR = Path(settings.VALI_TICKET_VALIDATOR_BIN)
_needs_validator = pytest.mark.skipif(
    not _VALIDATOR.is_file(), reason=f"ticket-validator not built at {_VALIDATOR}"
)


def _encode(kind: str, payload: dict) -> bytes:
    return order_dispatch._encode_order_body(
        order_id=f"{kind}-ck",
        kind=kind,
        target_miner_id="miner-ck",
        issued_at_unix=1_790_000_000,
        payload_json=json.dumps(payload).encode("utf-8"),
    )


@_needs_validator
def test_the_real_encoder_takes_the_orders_vali_builds() -> None:
    m0 = _encode("launch", _launch_payload(_measured("hippius")))
    assert b"guardian_ep" not in m0
    m1 = _encode("launch", _launch_payload(_measured("split")))
    assert b"guardian_ep" in m1 and EP.encode() in m1
    ma = _encode("migrate-activate", _activate_payload(_measured("customer")))
    assert b"guardian_ep" in ma
    # the M0 body is exactly the pre-customer-keys body: same payload keys,
    # and deterministic canonical CBOR ⇒ same bytes
    assert _encode("launch", _launch_payload(_measured("hippius"))) == m0


_MINT = Path(str(getattr(settings, "VALI_ORDER_TICKET_MINT_BIN", "")))
_DEV_SEED = Path(__file__).resolve().parents[4] / "packer/keys/dev/l1-order-ticket.dev.ed25519"


@_needs_validator
@pytest.mark.skipif(not _MINT.is_file(), reason=f"order-ticket-mint not built at {_MINT}")
@pytest.mark.parametrize("mode", ["hippius", "split", "customer"])
def test_the_real_mint_signs_the_mode_and_m0_has_no_key(settings, mode) -> None:
    from apps.orders import validator

    settings.VALI_L1_SIGNING_KEY_VAULT_PATH = ""
    settings.VALI_L1_SIGNING_KEY_PATH = str(_DEV_SEED)
    cose = ticket_mint.mint(
        ticket_mint.MintArgs(
            kid="l1-order-ticket-v1", ticket_id=f"tk-{mode}", tenant_id="t", user_id="u",
            vm_id="vm-x", lease_id="l", node_id="miner-ck", platform_id="ab" * 16,
            allowed_measurement_hex="ab" * 48, userdata_vault_path="p/vm-x/userdata",
            userdata_vault_version=1, luks_vault_path="p/vm-x/luks-kek",
            luks_vault_version=1, allowed_userdata_digest_hex="cd" * 32, flavor="small",
            key_mode=mode,
        )
    )
    # Read back by the Rust decoder: M0 decodes with NO `key_mode` entry
    # (the validator omits the key ⇒ `hippius`); the Rust mint test pins
    # the M0 envelope bytes to the pre-customer-keys fixture.
    assert validator.validate_ticket(cose).key_mode == mode
    assert (b"key_mode" in cose) is (mode != "hippius")


def test_m0_mint_argv_is_unchanged(monkeypatch, settings) -> None:
    """The M0 argv is exactly the pre-customer-keys one — no `--key-mode`."""
    import subprocess

    settings.VALI_ORDER_TICKET_MINT_BIN = "/bin/true"
    settings.VALI_L1_SIGNING_KEY_VAULT_PATH = ""
    settings.VALI_L1_SIGNING_KEY_PATH = "/dev/null"
    monkeypatch.setattr(ticket_mint.os.path, "isfile", lambda p: True)
    argvs: list[list[str]] = []

    def run(argv, **kw):
        argvs.append(argv)
        out = argv[argv.index("--out") + 1]
        Path(out).write_bytes(b"x")
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(subprocess, "run", run)
    args = dict(
        kid="k", ticket_id="t", tenant_id="t", user_id="u", vm_id="v", lease_id="l",
        node_id="n", platform_id="p", allowed_measurement_hex="ab" * 48,
        userdata_vault_path="p/u", userdata_vault_version=1, luks_vault_path="p/l",
        luks_vault_version=1, allowed_userdata_digest_hex="cd" * 32, flavor="small",
    )
    ticket_mint.mint(ticket_mint.MintArgs(**args))
    ticket_mint.mint(ticket_mint.MintArgs(**args, key_mode="customer"))
    def _stable(argv: list[str]) -> list[str]:
        # Tmp paths and the per-ticket `--issue-time` (one second apart: one
        # ticket per VM per second) are not what this test compares.
        i = argv.index("--issue-time")
        argv = argv[:i] + argv[i + 2 :]
        return [a for a in argv if not a.startswith("/dev/shm/") and not a.startswith("/tmp/")]

    m0, m2 = (_stable(argv) for argv in argvs)
    assert "--key-mode" not in m0
    assert m2[: len(m0)] == m0 and m2[len(m0) :] == ["--key-mode", "customer"]
    with pytest.raises(EffectError, match="unknown key_mode"):
        ticket_mint.mint(ticket_mint.MintArgs(**args, key_mode="hippius2"))


# ── review follow-ups: rollout-safe columns ──────────────────────────────


@pytest.mark.parametrize(
    ("app", "migration", "field", "default"),
    [
        ("lifecycle", "0019_customer_keys", "key_mode", "hippius"),
        ("lifecycle", "0019_customer_keys", "guardian_endpoint", ""),
        ("lifecycle", "0019_customer_keys", "guardian_pubkey", ""),
        ("tenant_bake", "0005_customer_keys", "supports_customer_keys", False),
    ],
)
def test_the_new_columns_carry_a_database_default(app, migration, field, default) -> None:
    """The migrate Job runs BEFORE the Deployment rolls: old pods keep
    INSERTing rows that omit these NOT NULL columns. Only a DATABASE
    default (`db_default`) fills them; an ORM `default` is dropped after the
    ALTER. Pinned on the migration AND the model (so makemigrations never
    drifts back to an ORM-only default)."""
    from django.apps import apps as django_apps
    from django.db.migrations.loader import MigrationLoader

    mig = MigrationLoader(None, ignore_no_migrations=True).get_migration(app, migration)
    (op,) = [o for o in mig.operations if getattr(o, "name", None) == field]
    assert op.field.db_default == default and op.field.default == default
    model = django_apps.get_model(app, op.model_name)
    assert model._meta.get_field(field).db_default == default


def test_an_insert_that_omits_the_new_columns_gets_the_database_default() -> None:
    """What an old pod does mid-rollout: an INSERT naming none of the new
    columns. Raw SQL, so no ORM default can fill them."""
    from django.db import connection

    table = Vm._meta.db_table
    old_cols = [
        f.column for f in Vm._meta.concrete_fields
        if f.column not in {"key_mode", "guardian_endpoint", "guardian_pubkey"}
    ]
    probe = Vm(vm_id="vm-old-pod", lease_id="l", state="active", generation=1, host="",
               lifecycle_vk=bytes(32))
    values = [f.get_db_prep_save(f.pre_save(probe, add=True), connection)
              for f in Vm._meta.concrete_fields if f.column in old_cols]
    with connection.cursor() as cur:
        cur.execute(
            f"INSERT INTO {table} ({', '.join(old_cols)}) "
            f"VALUES ({', '.join(['%s'] * len(old_cols))})",
            values,
        )
    row = Vm.objects.get(vm_id="vm-old-pod")
    assert (row.key_mode, row.guardian_endpoint, row.guardian_pubkey) == ("hippius", "", "")


# ── review follow-ups: forbidden guardian address, pinned re-POST, admin,
#    vali_stage_tenant_kek, dispatch CLI truncation band ──────────────────

_FORBIDDEN_EP = ["127.0.0.1:7443", "10.0.0.5:7443", "192.168.1.1:7443",
                 "169.254.169.254:80", "[fd00::1]:7443", "100.100.100.100:53",
                 "localhost:7443"]


@pytest.mark.usefixtures("enabled")
@pytest.mark.parametrize("ep", _FORBIDDEN_EP)
def test_a_forbidden_guardian_address_is_refused_at_intake(vault, ep) -> None:
    """The miner relay refuses these only after the Vm pin exists, which
    would burn the vm_id: intake refuses them first and writes nothing."""
    _bake()
    with pytest.raises(launch_jobs.LaunchIntentError, match="guardian-ep-forbidden-address"):
        _start(_intent(vm_id="vm-fb", guardian_endpoint=ep))
    assert vault["put"] == [] and vault["datakey"] == []
    assert not Vm.objects.filter(vm_id="vm-fb").exists()
    assert not LaunchJob.objects.filter(vm_id="vm-fb").exists()


def test_a_forbidden_guardian_address_never_pins_a_vm_row(harness) -> None:
    """Paths that skip intake (operator CLI → `launch_vm`) are held too:
    `_ensure_vm_row` refuses before creating the row."""
    with pytest.raises(launch.LaunchConfigError, match="guardian-ep-forbidden-address"):
        launch.launch_on_miner(
            _spec(vm_id="vm-fb2", guardian_endpoint="10.1.2.3:7443"), _miner()
        )
    assert not Vm.objects.filter(vm_id="vm-fb2").exists()
    assert harness.mints == [] and harness.preflight_cmdlines == []


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_a_repost_for_a_pinned_vm_skips_the_new_launch_gates(vault, mode) -> None:
    """Flag OFF and the bake no longer capable: a re-POST for an already
    pinned M1/M2 VM is held to its pin only, never stranded by the gates."""
    assert settings.VALI_CUSTOMER_KEYS_ENABLED is False
    _bake(capable=False)
    _pinned_vm(f"vm-rp-{mode}", mode)
    job = _start(_intent(vm_id=f"vm-rp-{mode}", key_mode=mode))
    assert job.spec_json["key_mode"] == mode
    if mode == "customer":
        assert vault["datakey"] == []  # still no KEK for M2
    # …and the pin still refuses another binding on the same path.
    with pytest.raises(launch_jobs.LaunchIntentError, match="key-mode-immutable"):
        _start(_intent(vm_id=f"vm-rp-{mode}", key_mode=mode,
                       guardian_endpoint="guardian.example.com:7443"))


def test_the_new_launch_gates_still_run_for_a_vm_id_with_no_row(vault) -> None:
    _bake(capable=False)
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-disabled"):
        _start(_intent(vm_id="vm-fresh"))


def test_the_key_mode_pin_is_read_only_in_the_admin() -> None:
    from django.contrib import admin

    ro = admin.site._registry[Vm].readonly_fields
    assert {"key_mode", "guardian_endpoint", "guardian_pubkey"} <= set(ro)


@pytest.mark.parametrize(("mode", "refused"), [("customer", True), ("split", False),
                                               ("hippius", False), (None, False)])
def test_stage_tenant_kek_refuses_an_m2_vm(monkeypatch, mode, refused) -> None:
    from django.core.management import CommandError, call_command

    touched: list[str] = []
    monkeypatch.setattr(vault_kv, "ensure_transit_key", lambda n: touched.append(n))
    monkeypatch.setattr(vault_kv, "transit_datakey_wrapped", lambda n: b"vault:v1:k")
    monkeypatch.setattr(
        vault_kv, "put_kv",
        lambda m, p, v, **k: touched.append(p) or vault_kv.VaultWriteResult(version=1),
    )
    if mode is not None:
        _pinned_vm("vm-sk", mode)
    if refused:
        with pytest.raises(CommandError, match="key_mode=customer"):
            call_command("vali_stage_tenant_kek", "--vm-id", "vm-sk", "--generate")
        assert touched == []
    else:
        call_command("vali_stage_tenant_kek", "--vm-id", "vm-sk", "--generate")
        assert _luks("vm-sk") in touched


@pytest.mark.usefixtures("enabled")
@pytest.mark.parametrize(
    "overrides",
    [
        {"cmdline": "ro cc:"},
        {"cmdline": "ro x=end_cc"},
        {"vm_id": "vm-cc:x"},
        {"vm_id": "vm-end_cc"},
        {"lease_id": "lease-cc:1"},
        {"lease_id": "l-end_cc"},
    ],
)
@pytest.mark.parametrize("mode", ["split", "customer"])
def test_a_cloud_init_marker_is_refused_at_intake(vault, mode, overrides) -> None:
    _bake()
    body = _intent(**{"vm_id": "vm-cc", "key_mode": mode, **overrides})
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-cloud-init-marker"):
        _start(body)
    assert vault["put"] == [] and vault["datakey"] == []
    assert not Vm.objects.exists() and not LaunchJob.objects.exists()


def test_m0_is_not_held_to_the_cloud_init_marker_rule(vault) -> None:
    _bake(capable=False)
    job = _start(_intent(vm_id="vm-m0cc", lease_id="lease-cc:1", key_mode=None,
                         guardian_endpoint=None, guardian_pubkey=None))
    assert job.vm_id == "vm-m0cc"


@pytest.mark.usefixtures("enabled")
def test_marker_look_alikes_are_not_refused(vault) -> None:
    """Case-sensitive substrings, as cloud-init matches them."""
    _bake()
    _start(_intent(vm_id="vm-cc-ok", lease_id="CC-end-cc", cmdline="ro c:c endcc CC:x"))


@pytest.mark.usefixtures("enabled")
@pytest.mark.parametrize(
    "ep", ["guardian.example.cc:443", "acc:7443", "[2001:db8::cc:1]:443", "end-cc.example:1"]
)
def test_a_guardian_endpoint_that_spells_a_marker_is_accepted_hex_encoded(
    vault, harness, monkeypatch, ep
) -> None:
    """H1b: the endpoint is measured as hex, so no endpoint can put `cc:` /
    `end_cc` into the cmdline — such endpoints are ordinary guardians now.
    The order and the `Vm` pin carry the plain endpoint."""
    _bake()
    job = _start(_intent(vm_id="vm-cc-ep", key_mode="split", guardian_endpoint=ep))
    assert job.spec_json["guardian_endpoint"] == ep
    _fix_nonces(monkeypatch)
    out = launch.launch_on_miner(_spec(vm_id="vm-cc-ep1", guardian_endpoint=ep), _miner())
    assert out.disposition == launch.ACCEPTED, out.emit
    (cmdline,) = harness.preflight_cmdlines
    assert "cc:" not in cmdline and "end_cc" not in cmdline
    assert f" hippius.guardian_ep={ep.encode().hex()}" in cmdline
    (p,) = harness.payloads
    assert p["guardian_ep"] == ep
    assert Vm.objects.get(vm_id="vm-cc-ep1").guardian_endpoint == ep


# ── H1b: the M1/M2 lease_id charset ─────────────────────────────────────

_BAD_LEASE_IDS = ["lease 1", "lease/1", "lease=1", "lease;1", "lease:1", "lease\u00e91", "l\"1", ""]


@pytest.mark.usefixtures("enabled")
@pytest.mark.parametrize("lease_id", [x for x in _BAD_LEASE_IDS if x])
@pytest.mark.parametrize("mode", ["split", "customer"])
def test_a_bad_lease_id_is_refused_at_intake(vault, mode, lease_id) -> None:
    _bake()
    body = _intent(**{"vm_id": "vm-lease", "key_mode": mode, "lease_id": lease_id})
    with pytest.raises(launch_jobs.LaunchIntentError, match="customer-keys-bad-lease-id"):
        _start(body)
    assert vault["put"] == [] and vault["datakey"] == []
    assert not Vm.objects.exists() and not LaunchJob.objects.exists()


@pytest.mark.parametrize("lease_id", _BAD_LEASE_IDS)
def test_a_bad_lease_id_never_pins_a_vm_row(harness, lease_id) -> None:
    """Paths that skip intake are held in `_ensure_vm_row`, before the row."""
    with pytest.raises(launch.LaunchConfigError, match="customer-keys-bad-lease-id"):
        launch.launch_on_miner(_spec(vm_id="vm-lease2", lease_id=lease_id), _miner())
    assert not Vm.objects.exists()
    assert harness.mints == [] and harness.preflight_cmdlines == []


@pytest.mark.usefixtures("enabled")
def test_a_lease_id_in_the_charset_is_accepted(vault) -> None:
    _bake()
    job = _start(_intent(vm_id="vm-lease-ok", lease_id="Lease_1.a-B"))
    assert job.vm_id == "vm-lease-ok"


def test_m0_lease_ids_are_not_restricted(vault) -> None:
    """M0 stays byte-identical: its lease_id is not held to the charset."""
    _bake(capable=False)
    job = _start(_intent(vm_id="vm-m0-lease", lease_id="lease:1/x", key_mode=None,
                         guardian_endpoint=None, guardian_pubkey=None))
    assert job.vm_id == "vm-m0-lease"


@pytest.mark.parametrize(
    ("overrides", "field"),
    # (vm_id is `[a-z0-9-]` already, so it can carry neither marker.)
    [({"lease_id": "cc:x"}, "lease_id"), ({"lease_id": "l-end_cc"}, "lease_id"),
     ({"cmdline": "ro cc:"}, "cmdline"), ({"cmdline": "ro a=end_cc"}, "cmdline")],
)
def test_a_cloud_init_marker_never_pins_a_vm_row(harness, overrides, field) -> None:
    """Paths that skip intake are held in `_ensure_vm_row`, before the row."""
    spec = _spec(**{"vm_id": "vm-cc2", **overrides})
    with pytest.raises(launch.LaunchConfigError, match=f"{field} contains"):
        launch.launch_on_miner(spec, _miner())
    assert not Vm.objects.exists()
    assert harness.mints == [] and harness.preflight_cmdlines == []


def test_the_final_measured_cmdline_is_checked_for_markers(harness, monkeypatch) -> None:
    """Defence in depth: a marker introduced by augmentation itself (not by
    any input `_ensure_vm_row` saw) still never reaches the preflight."""
    real = ck.augment_cmdline
    monkeypatch.setattr(ck, "augment_cmdline", lambda c, b: real(c, b) + " x=end_cc")
    # New vm_id: refused before the pin.
    with pytest.raises(launch.LaunchConfigError, match="measured_cmdline contains 'end_cc'"):
        launch.launch_on_miner(_spec(vm_id="vm-cc3"), _miner())
    assert not Vm.objects.filter(vm_id="vm-cc3").exists()
    # Pinned vm_id: the in-flow check on the REAL cmdline refuses it.
    _pinned_vm("vm-cc4", "split")
    out = launch.launch_on_miner(_spec(vm_id="vm-cc4"), _miner())
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "customer-keys-cmdline-refused"
    assert "measured_cmdline contains 'end_cc'" in out.emit["error"]
    assert harness.mints == [] and harness.preflight_cmdlines == []


@pytest.mark.parametrize("setting", ["https://acc:7443", "vsock://2:1/end_cc"])
def test_a_config_derived_marker_never_pins_a_vm_row(harness, settings, setting) -> None:
    """A marker an `_augment_*` step appends from operator CONFIG (here the
    vali/kbs reach, `VALI_GUEST_VSOCK_URL`) is refused before the pin."""
    settings.VALI_GUEST_VSOCK_URL = setting
    with pytest.raises(launch.LaunchConfigError, match="customer-keys-cloud-init-marker"):
        launch.launch_on_miner(_spec(vm_id="vm-cfg"), _miner())
    assert not Vm.objects.filter(vm_id="vm-cfg").exists()
    assert harness.mints == [] and harness.preflight_cmdlines == []


def test_a_config_marker_does_not_refuse_m0(harness, settings) -> None:
    settings.VALI_GUEST_VSOCK_URL = "vsock://2:1/end_cc"
    out = launch.launch_on_miner(_spec(vm_id="vm-cfg0", mode="hippius"), _miner())
    assert out.disposition == launch.ACCEPTED, out.emit


#: What the pre-pin epoch upper bound (20 digits) adds over the harness's
#: fixed epoch 42.
_EPOCH_SLACK = len(str(2**64 - 1)) - len("42")


def test_the_pre_pin_length_is_an_upper_bound(harness, monkeypatch) -> None:
    """Exact stand-ins for the node id and the nonces, an UPPER BOUND for the
    epoch: the largest cmdline the pre-pin check passes is 2033 minus the
    epoch slack, and it then passes the real check; one byte more is refused
    before the pin."""
    top = ck.MAX_MEASURED_CMDLINE_LEN - _EPOCH_SLACK
    base = _padded_base(harness, monkeypatch, top, "vm-pp1", mode="split")
    out = launch.launch_on_miner(_spec(vm_id="vm-pp1", cmdline=base), _miner())
    assert out.disposition == launch.ACCEPTED, out.emit
    assert len(harness.preflight_cmdlines[-1]) == top
    with pytest.raises(launch.LaunchConfigError, match=r"cmdline-too-long: .* 2034 bytes"):
        launch.launch_on_miner(_spec(vm_id="vm-pp2", cmdline=base + "y"), _miner())
    assert not Vm.objects.filter(vm_id="vm-pp2").exists()


def test_an_epoch_that_gains_digits_after_the_pin_cannot_overflow(harness, monkeypatch) -> None:
    """Review repro: epoch 9 at pin time, 10 by the time `launch_on_miner`
    samples it. The pre-pin bound refuses the cmdline that would overflow
    only after the pin."""
    base = _padded_base(harness, monkeypatch, ck.MAX_MEASURED_CMDLINE_LEN, "vm-ep", mode="split")
    monkeypatch.setattr(launch, "_current_billing_epoch", lambda: 9)
    with pytest.raises(launch.LaunchConfigError, match="cmdline-too-long"):
        launch.launch_on_miner(_spec(vm_id="vm-ep", cmdline=base), _miner())
    assert not Vm.objects.filter(vm_id="vm-ep").exists()


@pytest.mark.parametrize("node_id", [None, "", "0" * 63, "0" * 61 + "cc:", "A" * 64, "0" * 65])
def test_customer_keys_need_a_64_hex_chain_node_id(harness, node_id) -> None:
    """The node id is measured and the pre-pin check stands in for it with
    64 hex, so an M1/M2 launch refuses any other shape before the pin."""
    miner = _miner()
    MinerIdentity.objects.filter(pk=miner.pk).update(chain_node_id=node_id)
    miner.refresh_from_db()
    with pytest.raises(launch.LaunchConfigError, match="64-hex chain_node_id"):
        launch.launch_on_miner(_spec(vm_id="vm-nid"), miner)
    assert not Vm.objects.filter(vm_id="vm-nid").exists()
    assert harness.mints == [] and harness.preflight_cmdlines == []


def test_a_named_miner_launch_checks_the_node_id_before_the_row(harness) -> None:
    """`launch_on_named_miner` (vali_create_vm) writes the Vm row and a
    Pending placement before `launch_on_miner`: the guard runs first."""
    from apps.scheduler.models import Placement

    miner = _miner()
    MinerIdentity.objects.filter(pk=miner.pk).update(chain_node_id="A" * 64)
    miner.refresh_from_db()
    with pytest.raises(launch.LaunchConfigError, match="64-hex chain_node_id"):
        launch.launch_on_named_miner(_spec(vm_id="vm-named"), miner, decided_by=None)
    assert not Vm.objects.filter(vm_id="vm-named").exists()
    assert not Placement.objects.filter(vm__vm_id="vm-named").exists()


def test_m0_is_not_held_to_the_node_id_shape(harness) -> None:
    miner = _miner()
    MinerIdentity.objects.filter(pk=miner.pk).update(chain_node_id="A" * 64)
    miner.refresh_from_db()
    out = launch.launch_on_miner(_spec(vm_id="vm-nid0", mode="hippius"), miner)
    assert out.disposition == launch.ACCEPTED, out.emit


@pytest.mark.parametrize("mode", ["hippius", "split"])
def test_the_launch_persists_the_measured_eol_nonce(harness, mode) -> None:
    """`launch_on_miner` stamps `Vm.eol_nonce` with exactly the nonce in the
    REAL measured cmdline (not a pre-pin stand-in), for every mode."""
    spec = _spec(vm_id=f"vm-eol-{mode}", mode=mode, cmdline=f"ro hippius.eol_nonce={'c4' * 32}")
    out = launch.launch_on_miner(spec, _miner())
    assert out.disposition == launch.ACCEPTED, out.emit
    assert f"hippius.eol_nonce={'c4' * 32}" in harness.preflight_cmdlines[-1]
    assert bytes(Vm.objects.get(vm_id=spec.vm_id).eol_nonce) == bytes.fromhex("c4" * 32)


def test_the_pre_pin_check_runs_only_for_a_new_row(harness, monkeypatch) -> None:
    calls: list[str] = []
    real = launch._refuse_measured_cmdline_before_pin
    monkeypatch.setattr(
        launch, "_refuse_measured_cmdline_before_pin",
        lambda spec, b: calls.append(spec.vm_id) or real(spec, b),
    )
    launch.launch_on_miner(_spec(vm_id="vm-new"), _miner())
    _pinned_vm("vm-old", "split")
    launch.launch_on_miner(_spec(vm_id="vm-old"), _miner())
    assert calls == ["vm-new"]


@pytest.mark.parametrize("marker", ["cc:", "end_cc"])
def test_a_remint_refuses_a_recorded_cmdline_with_a_marker(remint, marker) -> None:
    vm = _pinned_vm(f"vm-rc-{marker[:2]}", "split")
    _succeeded_job(
        vm.vm_id, _spec_json(vm.vm_id, "split"),
        measured_cmdline=_measured("split") + f" a={marker}",
    )
    for remint_fn in (
        lambda: migration_ticket.remint_current_ticket(vm),
        lambda: migration_ticket.remint_dest_ticket(vm, dest_node_id="miner-ck", new_gen=2),
    ):
        with pytest.raises(EffectError, match="customer-keys-cloud-init-marker"):
            remint_fn()
    assert remint["mints"] == []


def test_a_stored_ticket_is_not_reused_for_a_cmdline_with_a_marker(remint, monkeypatch) -> None:
    """The §25 idempotent shortcut returns a stored blob BEFORE the re-mint
    inputs are resolved; it is held to the same recorded-cmdline check."""
    from apps.orders import validator
    from apps.orders.models import OrderTicketIntake

    vm = _pinned_vm("vm-rcs", "split")
    _succeeded_job(
        vm.vm_id, _spec_json(vm.vm_id, "split"), measured_cmdline=_measured("split") + " a=end_cc"
    )
    OrderTicketIntake.objects.create(
        ticket_id="tk-cached", vm_id=vm.vm_id, tenant_id="t-ck", user_id="u-1",
        lease_id="lease-1", vm_generation=2, issue_time=1, expiry=2, node_id="miner-ck",
        platform_id="ab" * 16, resource_class="small", kid_hex="6b", cose_blob=b"cached",
        received_from="system:migration-remint",
    )
    monkeypatch.setattr(validator, "validate_ticket", lambda c: SimpleNamespace(key_mode="split"))
    with pytest.raises(EffectError, match="customer-keys-cloud-init-marker"):
        migration_ticket.remint_dest_ticket(vm, dest_node_id="miner-ck", new_gen=2)
    assert remint["mints"] == []


def test_the_dispatch_launch_command_refuses_a_cloud_init_marker() -> None:
    from apps.orchestration.management.commands import vali_dispatch_launch as cmd

    _pinned_vm("vm-cli-cc", "split")
    got = cmd._customer_keys_mismatch("vm-cli-cc", _measured("split") + " a=cc:", "split")
    # The grammar mirror refuses it first, exactly as the guest would (H5b).
    assert got is not None and "guardian-cmdline-cloud-init-directive" in got


def test_the_dispatch_launch_command_refuses_the_truncation_band() -> None:
    from apps.orchestration.management.commands import vali_dispatch_launch as cmd

    base = _measured("hippius")
    at = base + " " + "x" * (ck.KEY_MODE_TRUNCATION_FLOOR_MEASURED - len(base) - 1)
    assert len(at) == ck.KEY_MODE_TRUNCATION_FLOOR_MEASURED
    got = cmd._customer_keys_mismatch("vm-cli-band", at, "hippius")
    assert got is not None and "guest refuses to boot" in got
    assert cmd._customer_keys_mismatch("vm-cli-band", at[:-1], "hippius") is None


# ── M1/M2 NetBird hardening of the userdata's `netbird up` (H6b) ──────

_BINDING = ck.GuardianBinding("split", PK, EP)
_FLAGS = b"--disable-dns --disable-client-routes --disable-server-routes"
_EXAMPLE_TEMPLATE = (
    Path(settings.BASE_DIR).parent
    / "docs"
    / "operator"
    / "userdata-templates"
    / "netbird-enabled.yaml.example"
)


def test_the_documented_template_is_hardened_in_place() -> None:
    raw = _EXAMPLE_TEMPLATE.read_bytes()
    out = ck.harden_netbird_up(_BINDING, raw)
    assert (
        b"[ netbird, up, --disable-dns, --disable-client-routes, --disable-server-routes,\n"
        in out
    )
    # Nothing else moved: removing the insertion gives the template back.
    assert out.replace(
        b", --disable-dns, --disable-client-routes, --disable-server-routes", b"", 1
    ) == raw
    # The comments that merely mention `netbird up` are untouched.
    assert out.count(b"--disable-dns") == 1


@pytest.mark.parametrize(
    ("userdata", "hardened"),
    [
        (
            b"runcmd:\n  - netbird up --setup-key-file=/k --no-browser\n",
            b"runcmd:\n  - netbird up " + _FLAGS + b" --setup-key-file=/k --no-browser\n",
        ),
        (
            b"runcmd:\n  - [ sh, -c, 'if x; then /usr/bin/netbird up --no-browser; fi' ]\n",
            b"runcmd:\n  - [ sh, -c, 'if x; then /usr/bin/netbird up "
            + _FLAGS
            + b" --no-browser; fi' ]\n",
        ),
        (
            b"runcmd:\n  - - netbird\n    - up\n    - --no-browser\n",
            b"runcmd:\n  - - netbird\n    - up\n    - --disable-dns\n    - "
            b"--disable-client-routes\n    - --disable-server-routes\n    - --no-browser\n",
        ),
        (
            b"runcmd:\n  - [netbird,up]\n",
            b"runcmd:\n  - [netbird,up," + _FLAGS.replace(b" ", b",") + b"]\n",
        ),
        (
            b"runcmd:\n  - netbird up\n  - netbird up --x\n",
            b"runcmd:\n  - netbird up " + _FLAGS + b"\n  - netbird up " + _FLAGS + b" --x\n",
        ),
    ],
)
def test_every_shape_of_netbird_up_is_hardened(userdata: bytes, hardened: bytes) -> None:
    assert ck.harden_netbird_up(_BINDING, userdata) == hardened


@pytest.mark.parametrize(
    "userdata",
    [
        b"#cloud-config\n",
        b"# netbird up is run by hand\nruncmd: []\n",  # a comment only
        b"runcmd:\n  - netbird upgrade\n",
        b"runcmd:\n  - hippius-netbird up\n",
        b"runcmd:\n  - netbird login\n",
        # documented as unsupported: a QUOTED flow list
        b'runcmd:\n  - [ "netbird", "up", "--no-browser" ]\n',
    ],
)
def test_an_m1_m2_userdata_without_a_hardenable_netbird_up_is_refused(userdata: bytes) -> None:
    with pytest.raises(ck.CustomerKeysError, match="customer-keys-netbird-up-not-found"):
        ck.harden_netbird_up(_BINDING, userdata)


def test_m0_userdata_is_byte_identical() -> None:
    for raw in (_EXAMPLE_TEMPLATE.read_bytes(), b"#cloud-config\n", b"netbird up\n"):
        assert ck.harden_netbird_up(None, raw) is raw


def _netbird_launch(harness, monkeypatch, mode: str, userdata: bytes, vm_id: str):
    staged: list[bytes] = []
    monkeypatch.setattr(vault_kv, "transit_encrypt", lambda key, pt: staged.append(pt) or b"v")
    monkeypatch.setattr(
        effects,
        "mint_netbird_setup_key",
        lambda **kw: effects.MintedSetupKey(id="k1", key="SETUPKEY"),
    )
    monkeypatch.setattr(launch, "_record_netbird_key", lambda *a, **k: None)
    spec = _spec(vm_id=vm_id, mode=mode, userdata=userdata, enable_netbird=True)
    return launch.launch_on_miner(spec, _miner()), staged


_NB_USERDATA = (
    b"#cloud-config\nruncmd:\n  - [ netbird, up, --setup-key={{NETBIRD_SETUP_KEY}},"
    b" --hostname={{NETBIRD_HOSTNAME}} ]\n"
)


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_an_m1_m2_launch_stages_the_hardened_userdata(harness, monkeypatch, mode) -> None:
    out, staged = _netbird_launch(harness, monkeypatch, mode, _NB_USERDATA, f"vm-nb-{mode}")
    assert out.disposition == launch.ACCEPTED, out.emit
    want = (
        b"[ netbird, up, --disable-dns, --disable-client-routes, --disable-server-routes,"
        b" --setup-key=SETUPKEY, --hostname=hippius-tenant-vm-nb-" + mode.encode() + b" ]"
    )
    assert staged and all(want in pt for pt in staged)


def test_an_m0_launch_stages_the_userdata_unhardened(harness, monkeypatch) -> None:
    out, staged = _netbird_launch(harness, monkeypatch, "hippius", _NB_USERDATA, "vm-nb-m0")
    assert out.disposition == launch.ACCEPTED, out.emit
    want = (
        b"#cloud-config\nruncmd:\n  - [ netbird, up, --setup-key=SETUPKEY,"
        b" --hostname=hippius-tenant-vm-nb-m0 ]\n"
    )
    assert staged and all(want in pt and b"--disable" not in pt for pt in staged)


def test_an_m1_launch_whose_userdata_has_no_netbird_up_is_refused_before_the_pin(
    harness, monkeypatch
) -> None:
    ud = b"#cloud-config\nwrite_files:\n  - content: {{NETBIRD_SETUP_KEY}}\n"
    with pytest.raises(launch.LaunchConfigError, match="customer-keys-netbird-up-not-found"):
        _netbird_launch(harness, monkeypatch, "split", ud, "vm-nb-none")
    assert not Vm.objects.filter(vm_id="vm-nb-none").exists()


def test_a_pinned_data_disk_is_measured_and_ordered_whatever_the_flavor(harness) -> None:
    """A resized VM (vm resize): the flavor's vCPU/RAM, the VM's own launch
    disk — in the measured cmdline the miner sizes from AND in the order."""
    out = launch.launch_on_miner(
        _spec(vm_id="vm-pin", mode="hippius", flavor="large", data_disk_size_gb=40), _miner()
    )
    assert out.disposition == launch.ACCEPTED, out.emit
    (cmdline,) = harness.preflight_cmdlines
    assert "hippius.disk_gb=40 " in cmdline
    assert "hippius.resource_class=large " in cmdline
    (p,) = harness.payloads
    assert p["data_disk_size_gb"] == 40
    assert p["cpu_count"] == 4
