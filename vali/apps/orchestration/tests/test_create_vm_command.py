"""Argument-shape + dev-mode gate tests for `vali_create_vm`.

We do NOT exercise the dispatch wire (would need a live Edge + Vault
+ KBS + miner); the tests pin the CLI surface, the input validators,
and the prod-gate refusal so a deployment that points the dev seed at
a prod cluster cannot ship.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command

VALID_MEASUREMENT = "0" * 96
VALID_PLATFORM_ID = "0" * 128
VALID_SHA256 = "a" * 64


def _required_argv(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tenant_id": "t-test",
        "user_id": "u-test",
        "vm_id": "vm-test",
        "lease_id": "lease-test",
        "miner_id": "miner-test",
        "platform_id": VALID_PLATFORM_ID,
        "userdata_file": "/dev/null",
        # #312 follow-up — flavor is required now (cpu_count /
        # memory_mb dropped from the CLI; vali derives them from the
        # catalogue).
        "flavor": "small",
        "cmdline": "ro ds=nocloud;s=/run/cloud-init/seed/",
        "s3_bucket": "hippius-compute-images",
        "s3_key_prefix": "tenant/test-image/",
        "luks_disk_sha256_hex": VALID_SHA256,
        "kernel_sha256_hex": VALID_SHA256,
        "initrd_sha256_hex": VALID_SHA256,
        # #296 — required since the LUKS2-header MAC fix.
        "luks_header_sha256_hex": VALID_SHA256,
        # Tests don't exercise the bake / KBS chain, so allow the
        # legacy random-KEK path (#304 belt-and-suspenders for the
        # validators they DO exercise).
        "allow_random_kek": True,
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    "missing",
    [
        "tenant_id",
        "user_id",
        "vm_id",
        "lease_id",
        "miner_id",
        "platform_id",
        "userdata_file",
        "flavor",
        "cmdline",
        "s3_bucket",
        "s3_key_prefix",
        "luks_disk_sha256_hex",
        "kernel_sha256_hex",
        "initrd_sha256_hex",
        "luks_header_sha256_hex",
    ],
)
def test_required_arg_missing_errors_loudly(missing: str) -> None:
    argv = _required_argv()
    argv.pop(missing)
    with pytest.raises(CommandError) as exc:
        call_command("vali_create_vm", **argv)
    msg = str(exc.value).lower()
    assert "required" in msg
    assert "--" + missing.replace("_", "-") in str(exc.value)


def test_measurement_hex_is_optional() -> None:
    """The whole point of preflight: --measurement-hex MUST be optional
    so vali can auto-compute it on the miner."""
    from apps.orchestration.management.commands import vali_create_vm

    parser = vali_create_vm.Command().create_parser("manage.py", "vali_create_vm")
    # No --measurement-hex in the required-args set.
    actions = {a.dest: a for a in parser._actions}
    assert actions["measurement_hex"].required is False


def test_refuses_when_allow_prod_is_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", True)
    with pytest.raises(CommandError, match="VALI_ALLOW_PROD"):
        call_command("vali_create_vm", **_required_argv())


def test_rejects_short_measurement_hex(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    with pytest.raises(CommandError, match="measurement-hex"):
        call_command("vali_create_vm", **_required_argv(measurement_hex="00"))


def test_rejects_bad_platform_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    with pytest.raises(CommandError, match="platform-id"):
        call_command("vali_create_vm", **_required_argv(platform_id="zz"))


def test_rejects_bad_artifact_sha256(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    with pytest.raises(CommandError, match="luks-disk-sha256-hex"):
        call_command(
            "vali_create_vm",
            **_required_argv(luks_disk_sha256_hex="00"),
        )


def test_help_text_mentions_dev_only_and_byo_fields() -> None:
    from apps.orchestration.management.commands import vali_create_vm

    parser = vali_create_vm.Command().create_parser("manage.py", "vali_create_vm")
    text = parser.format_help()
    for needle in (
        "--tenant-id",
        "--vm-id",
        "--userdata-file",
        "--measurement-hex",
        "--auto-pin-allowlist",
        "--s3-bucket",
        "--s3-key-prefix",
        "--luks-disk-sha256-hex",
        "--kek-file",
        "--allow-random-kek",
        "--enable-netbird",
        "--netbird-group",
        "--netbird-key-ttl-seconds",
        "--netbird-hostname-template",
        "--flavor",
        "ds=nocloud",
    ):
        assert needle in text, f"help is missing {needle!r}"


def test_refuses_missing_kek_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    """#304 — `vali_create_vm` must NOT silently generate a random KEK
    when neither --kek-file nor --allow-random-kek is set, because the
    BYO-OS bake's luksFormat binds the rootfs keyslot to an operator-
    side KEK and a vali-side random KEK can never unlock it."""
    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    argv = _required_argv()
    argv.pop("allow_random_kek")
    with pytest.raises(CommandError, match="#304"):
        call_command("vali_create_vm", **argv)


def test_refuses_both_kek_file_and_random(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """#304 — the two KEK sources are mutually exclusive."""
    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    kek = tmp_path / "kek.bin"
    kek.write_bytes(b"\x00" * 32)
    with pytest.raises(CommandError, match="mutually exclusive"):
        call_command(
            "vali_create_vm",
            **_required_argv(kek_file=str(kek), allow_random_kek=True),
        )


def test_netbird_defaults_on_in_parser() -> None:
    """NetBird is ON by default for every VM (overlay reachability);
    `--no-enable-netbird` opts out. The userdata must carry the
    `{{NETBIRD_SETUP_KEY}}` placeholder unless opted out."""
    from apps.orchestration.management.commands import vali_create_vm

    parser = vali_create_vm.Command().create_parser("manage.py", "vali_create_vm")
    actions = {a.dest: a for a in parser._actions}
    assert actions["enable_netbird"].default is True
    assert actions["netbird_group"].default == "vms"
    assert actions["netbird_key_ttl_seconds"].default == 3600
    # #309 — hostname template defaults to a per-vm-id stable FQDN.
    assert actions["netbird_hostname_template"].default == "hippius-tenant-{vm_id}"


def test_netbird_enabled_requires_placeholder(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """#306 — when `--enable-netbird` is set but the userdata template
    does not carry the `{{NETBIRD_SETUP_KEY}}` placeholder, vali must
    refuse the stage rather than silently produce a tenant with no
    mesh enrolment."""
    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    ud = tmp_path / "userdata.yaml"
    ud.write_bytes(b"#cloud-config\nssh_pwauth: true\n")
    with pytest.raises(CommandError, match="NETBIRD_SETUP_KEY"):
        call_command(
            "vali_create_vm",
            **_required_argv(
                userdata_file=str(ud),
                enable_netbird=True,
            ),
        )


def test_netbird_hostname_template_rejects_unknown_placeholders(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """#309 — only `{vm_id}` is a legal substitution token in the
    hostname template. Anything else (`{tenant_id}`, `{user_id}`, ...)
    raises a CommandError so the operator sees the typo loud rather
    than getting a half-substituted FQDN at boot."""
    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    ud = tmp_path / "userdata.yaml"
    ud.write_bytes(
        b"#cloud-config\nssh_pwauth: true\n"
        b"# placeholder: {{NETBIRD_SETUP_KEY}}\n"
    )
    with pytest.raises(CommandError, match="vm_id"):
        call_command(
            "vali_create_vm",
            **_required_argv(
                userdata_file=str(ud),
                enable_netbird=True,
                netbird_hostname_template="bad-{tenant_id}",
            ),
        )


# ── #312 flavor catalogue ───────────────────────────────────────────


def test_flavor_choices_match_rust_catalogue() -> None:
    """#312 — argparse `choices` MUST list every variant the Rust
    `hippius_types::flavor::Flavor` enum carries (Small / Medium /
    Large). If a future PR adds a new flavor, this test catches the
    Python-side drift loud."""
    from apps.orchestration.management.commands import vali_create_vm

    parser = vali_create_vm.Command().create_parser("manage.py", "vali_create_vm")
    actions = {a.dest: a for a in parser._actions}
    # #312 follow-up — flavor is REQUIRED in OrderTicket v2. The
    # legacy empty-string default + raw --cpu-count/--memory-mb
    # affordance is gone; operator must pick a catalogue variant.
    assert set(actions["flavor"].choices) == {
        "small",
        "medium",
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
    }
    assert actions["flavor"].required is True


def test_flavor_python_catalogue_matches_rust_enum() -> None:
    """#312 — the shared `flavors` catalogue MUST mirror
    `hippius_types::flavor::Flavor`'s `vcpus()`/`memory_mb()`/
    `disk_gb()` numbers exactly. If a Rust-side change adds Large
    vcpus=8 but the Python table still says 4, a tenant flagged
    `large` would mint a ticket with `flavor="large"` (Rust catalogue
    says 8 vcpus) but actually launch with 4 vcpus on the miner-agent.
    That's a silent contract violation; this test catches it at CI.
    """
    from apps.orchestration.services import flavors

    # Mirror of the Rust `vcpus()`/`memory_mb()`/`disk_gb()` constants
    # from `hippius-types/src/flavor.rs`. Drift here = drift loud.
    expected = {
        "small": (1, 2048, 8),
        "medium": (2, 4096, 16),
        "large": (4, 8192, 32),
        "xlarge": (8, 16384, 64),
        "2xlarge": (16, 32768, 128),
        "4xlarge": (32, 65536, 256),
    }
    assert set(flavors.FLAVOR_NAMES) == set(expected)
    for name, (cpu, mem, disk) in expected.items():
        size = flavors.resolve_flavor(name)
        assert (size.cpu_count, size.memory_mb, size.data_disk_size_gb) == (
            cpu,
            mem,
            disk,
        ), name


def test_resolve_flavor_splits_rootfs_and_data_disk() -> None:
    """#365 — the flavor's `disk_gb` sizes the tenant DATA disk
    (`data_disk_size_gb`, attached at /dev/vde and formatted fresh in
    the guest), while the rootfs `luks_disk_size_gb` is the FIXED
    flavor-independent minimal `ROOTFS_DISK_GB`. A LUKS2+integrity
    volume can't be grown, so these two diverged in #365.
    """
    from apps.orchestration.services import flavors

    for name in flavors.FLAVOR_NAMES:
        size = flavors.resolve_flavor(name)
        # Rootfs = fixed minimal, independent of flavor.
        assert size.luks_disk_size_gb == flavors.ROOTFS_DISK_GB, name
        # Data disk diverges per flavor.
        assert size.data_disk_size_gb >= 8, name


def test_augment_cmdline_with_rootfs_sha_appends_when_absent() -> None:
    """Audit follow-up Gemini #1 / Codex #1 — the rootfs SHA token
    binds the rootfs into the SEV-SNP launch_digest. The shared
    `_augment_cmdline_with_token` helper must append when absent and be
    idempotent / no-op when already present (so the operator can
    pre-supply the token without vali silently overwriting it).
    """
    from apps.orchestration.services import launch

    sha = "f" * 64
    key = launch._ROOTFS_SHA_CMDLINE_KEY
    base = "console=ttyS0,115200 ro root=/dev/mapper/cryptroot"
    augmented = launch._augment_cmdline_with_token(base, key, sha)
    assert augmented.endswith(f"hippius.rootfs_sha256={sha}")
    # Idempotent: re-applying the SAME token is a no-op.
    assert launch._augment_cmdline_with_token(augmented, key, sha) == augmented
    # Operator-supplied token (even with a different value) wins.
    other = "0" * 64
    pre_supplied = f"{base} hippius.rootfs_sha256={other}"
    assert (
        launch._augment_cmdline_with_token(pre_supplied, key, sha) == pre_supplied
    )


def test_augment_cmdline_with_disk_gb_appends_when_absent() -> None:
    """#365 Phase 1 — the attested disk-size token. Same append /
    idempotent / operator-token-wins discipline as the other measured
    cmdline tokens; folds into the launch_digest so a grow-enabled
    image's allowlist entry binds the attested size."""
    from apps.orchestration.services import launch

    key = launch._DISK_GB_CMDLINE_KEY
    base = "console=ttyS0,115200 ro root=/dev/mapper/cryptroot"
    augmented = launch._augment_cmdline_with_token(base, key, "8")
    assert augmented.endswith("hippius.disk_gb=8")
    # Idempotent.
    assert launch._augment_cmdline_with_token(augmented, key, "8") == augmented
    # Operator-supplied token wins (no silent overwrite).
    pre_supplied = f"{base} hippius.disk_gb=16"
    assert launch._augment_cmdline_with_token(pre_supplied, key, "8") == pre_supplied


def test_augment_cmdline_strips_trailing_whitespace() -> None:
    """Same byte-stability concern as the LUKS-header helper —
    duplicated spaces in the cmdline would change the launch_digest
    bytes and break the §22 allowlist match."""
    from apps.orchestration.services import launch

    sha = "a" * 64
    augmented = launch._augment_cmdline_with_token(
        "ro root=/dev/vda ", launch._ROOTFS_SHA_CMDLINE_KEY, sha
    )
    assert augmented == f"ro root=/dev/vda hippius.rootfs_sha256={sha}"


# ── P9/#18 — the CLI must leave the same durable ledger as the API ───


@pytest.mark.django_db
def test_cli_goes_through_the_forced_launch_ledger_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """The whole of P9/#18 at the CLI seam.

    `vali_create_vm` used to call `launch.launch_on_miner` DIRECTLY, which
    writes neither a `lifecycle.Vm` row nor a `scheduler.Placement` — so
    the operator got a real, attested, RUNNING CVM that §24 could never
    crypto-erase and the #668 fit gate never counted. It must now go
    through `launch_on_named_miner`, which writes both.
    """
    from django.utils import timezone

    from apps.miners.models import MinerIdentity, MinerStatus
    from apps.orchestration.services import launch

    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    MinerIdentity.objects.create(
        miner_id="miner-test",
        pubkey_hex="0" * 64,
        platform_id="ab" * 16,
        netbird_ip="100.64.0.9",
        chain_node_id="cd" * 32,
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=1,
        status=MinerStatus.ACTIVE,
    )
    ud = tmp_path / "userdata.yaml"
    ud.write_bytes(b"#cloud-config\nssh_pwauth: true\n")

    seen: dict[str, Any] = {}

    def _fake_named(spec, miner, *, decided_by):
        seen["vm_id"] = spec.vm_id
        seen["miner_id"] = miner.miner_id
        seen["decided_by"] = decided_by.name
        return launch.LaunchOutcome(
            disposition=launch.ACCEPTED, emit={"ok": True}, exit_code=0
        )

    monkeypatch.setattr(launch, "launch_on_named_miner", _fake_named)

    # The un-ledgered entrypoint must NOT be what the CLI reaches for.
    def _forbidden(spec, miner):  # pragma: no cover — the assertion IS the point
        raise AssertionError(
            "vali_create_vm called launch_on_miner directly — that is the "
            "unbound-VM hole (P9/#18)"
        )

    monkeypatch.setattr(launch, "launch_on_miner", _forbidden)

    with pytest.raises(SystemExit) as exc:
        call_command(
            "vali_create_vm",
            **_required_argv(userdata_file=str(ud), enable_netbird=False),
        )

    assert exc.value.code == 0
    assert seen["vm_id"] == "vm-test"
    assert seen["miner_id"] == "miner-test"
    # Default audit principal — inert, cannot authenticate.
    assert seen["decided_by"] == launch.OPERATOR_CLI_PRINCIPAL


@pytest.mark.django_db
def test_cli_refuses_an_unknown_decided_by(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """A typo in `--decided-by` must fail as a clean input error BEFORE the
    miner lookup / any Vault I/O — never silently mint the principal it
    names."""
    from apps.identity.models import ServiceClient

    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", False)
    ud = tmp_path / "userdata.yaml"
    ud.write_bytes(b"#cloud-config\n")
    with pytest.raises(CommandError, match="not a registered ServiceClient"):
        call_command(
            "vali_create_vm",
            **_required_argv(
                userdata_file=str(ud),
                enable_netbird=False,
                decided_by="typo-oncall",
            ),
        )
    assert not ServiceClient.objects.filter(name="typo-oncall").exists()
