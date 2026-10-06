"""M0 untrusted-miner hardening — the MEASURED cmdline kill switch for
systemd credential import.

`launch._augment_guest_hardening` bakes `systemd.import_credentials=no`
into the measured kernel cmdline. The untrusted miner controls the libvirt
domain XML, and only OVMF + kernel + initrd + cmdline are in the SNP launch
measurement; SMBIOS type 11 OEM strings and `-fw_cfg opt/...` blobs are
fetched by the guest AFTER launch and are NOT measured. systemd imports
credentials (`io.systemd.credential:*` — root ssh keys, `tmpfiles.extra`,
`fstab.extra`) from exactly those surfaces by default, so without this
token the miner has a host->guest root channel independent of cloud-init
and of any guest agent.

These pin the pure cmdline-augment helper directly (the full
`launch_on_miner` chain talks to Vault / preflight / KBS and is exercised
live). The cmdline is disk-mode-independent, so a single helper covers
both legacy_luks and golden_verity_overlay launches.
"""

from __future__ import annotations

from apps.orchestration.services import launch


def test_token_key_and_value_are_the_documented_kill_switch() -> None:
    # systemd honours ONLY `systemd.import_credentials=no` (systemd-cmdline
    # / systemd.system-credentials). A typo silently re-opens the channel.
    assert launch._IMPORT_CREDENTIALS_CMDLINE_KEY == "systemd.import_credentials"
    assert launch._IMPORT_CREDENTIALS_VALUE == "no"


def test_max_cmdline_bytes_matches_the_kernel_and_rust_limit() -> None:
    # x86 COMMAND_LINE_SIZE is 2048 incl. NUL; SEV measures the whole string
    # while the kernel truncates, and OVMF prepends `initrd=initrd ` (14 B).
    # Must equal hippius_types::guardian::MAX_MEASURED_CMDLINE_LEN so vali
    # refuses a cmdline the guest would truncate.
    assert launch._MAX_CMDLINE_BYTES == 2033


def test_appends_import_credentials_no_when_absent() -> None:
    out = launch._augment_guest_hardening("ro quiet")
    assert out == "ro quiet systemd.import_credentials=no"
    assert (
        launch._extract_cmdline_token(out, launch._IMPORT_CREDENTIALS_CMDLINE_KEY)
        == "no"
    )


def test_is_idempotent_and_byte_stable() -> None:
    # The launch_digest covers the cmdline bytes — re-augmenting an
    # already-augmented cmdline must be a no-op (no duplicate tokens).
    once = launch._augment_guest_hardening("ro quiet")
    twice = launch._augment_guest_hardening(once)
    assert once == twice
    assert once.count("systemd.import_credentials=") == 1


def test_forces_no_over_a_base_yes() -> None:
    # A security kill switch must NOT be defeated by a base cmdline that
    # carries =yes — force the canonical =no, exactly one token.
    out = launch._augment_guest_hardening("ro systemd.import_credentials=yes quiet")
    assert (
        launch._extract_cmdline_token(out, launch._IMPORT_CREDENTIALS_CMDLINE_KEY)
        == "no"
    )
    assert "systemd.import_credentials=yes" not in out
    assert out.count("systemd.import_credentials=") == 1


def test_collapses_a_duplicated_token_to_one_no() -> None:
    pre = "ro systemd.import_credentials=no systemd.import_credentials=yes end=1"
    out = launch._augment_guest_hardening(pre)
    assert out.count("systemd.import_credentials=") == 1
    assert (
        launch._extract_cmdline_token(out, launch._IMPORT_CREDENTIALS_CMDLINE_KEY)
        == "no"
    )


def test_leaves_the_dracut_variant_and_lookalikes_untouched() -> None:
    # `rd.systemd.import_credentials=` is a DIFFERENT key (initramfs phase,
    # our measured Rust initrd), and `foo=...` merely contains the substring.
    # Neither must be stripped, and the real =no must still be appended.
    pre = "ro rd.systemd.import_credentials=no foo=systemd.import_credentials=yes"
    out = launch._augment_guest_hardening(pre)
    assert "rd.systemd.import_credentials=no" in out
    assert "foo=systemd.import_credentials=yes" in out
    assert out.rstrip().endswith("systemd.import_credentials=no")


def test_already_no_is_byte_stable_and_not_reordered() -> None:
    # A base already carrying exactly =no: forcing must be deterministic and
    # idempotent (the collapse path yields the same bytes on a second run).
    pre = "ro systemd.import_credentials=no quiet"
    once = launch._augment_guest_hardening(pre)
    assert once == launch._augment_guest_hardening(once)
    assert once.count("systemd.import_credentials=") == 1
