"""§25 source-ack DELIVERY — the launch-time cmdline inputs the guest's
`eol` signer needs to RESOLVE + DELIVER its `stopped{}` ack.

`launch.launch_on_miner` bakes `hippius.vm_id` / `hippius.lease_id` /
`hippius.vm_generation` / `hippius.vali_url` into the MEASURED cmdline so
the source guest's `agent-initramfs::main::eol_push_inputs` resolves all
its inputs (without them it logs `eol-inputs-unresolved` and never
produces an ack, stalling the §25 fence at `awaiting_source_ack`). The
`vali_url` defaults to the host vsock-proxy authority because the
confidential guest has no IP route to vali.

These pin the pure cmdline-augment helper directly (the full
`launch_on_miner` chain talks to Vault / preflight / KBS and is exercised
live, not here).
"""

from __future__ import annotations

from django.test import override_settings

from apps.orchestration.services import launch


def test_augments_all_four_eol_delivery_inputs() -> None:
    out = launch._augment_eol_delivery_inputs(
        "ro quiet", vm_id="mig-e2e-1", lease_id="lease-7"
    )
    # vm_id / lease_id / vm_generation are baked verbatim.
    assert launch._extract_cmdline_token(out, launch._VM_ID_CMDLINE_KEY) == "mig-e2e-1"
    assert launch._extract_cmdline_token(out, launch._LEASE_ID_CMDLINE_KEY) == "lease-7"
    assert (
        launch._extract_cmdline_token(out, launch._VM_GENERATION_CMDLINE_KEY)
        == str(launch._LAUNCH_GENERATION)
    )
    # vali_url defaults to the vsock proxy authority (no IP route to vali).
    assert launch._extract_cmdline_token(
        out, launch._VALI_URL_CMDLINE_KEY
    ) == launch._DEFAULT_VALI_VSOCK_URL


def test_vm_generation_matches_the_ensure_vm_row_default() -> None:
    # The guest signs at this generation; vali verifies the source ack at
    # `source_gen` (== the source VM's live generation). They MUST match,
    # so the baked generation has to equal `_ensure_vm_row`'s default.
    assert launch._LAUNCH_GENERATION == 1


def test_vali_url_defaults_to_a_vsock_authority() -> None:
    # The default reach MUST be vsock — the confidential guest cannot route
    # to vali, so the ack rides the host vsock proxy (mirrors the KBS path).
    assert launch._DEFAULT_VALI_VSOCK_URL.startswith("vsock://")


@override_settings(VALI_GUEST_VSOCK_URL="vsock://2:5555")
def test_setting_overrides_the_default_vali_url() -> None:
    out = launch._augment_eol_delivery_inputs("ro", vm_id="v", lease_id="l")
    assert (
        launch._extract_cmdline_token(out, launch._VALI_URL_CMDLINE_KEY)
        == "vsock://2:5555"
    )


def test_operator_baked_vali_url_wins() -> None:
    # An operator who pre-baked `hippius.vali_url=` (already measured) keeps
    # it — e.g. an https reach where a direct route to vali exists.
    cmdline = "ro hippius.vali_url=https://vali.internal"
    out = launch._augment_eol_delivery_inputs(cmdline, vm_id="v", lease_id="l")
    assert (
        launch._extract_cmdline_token(out, launch._VALI_URL_CMDLINE_KEY)
        == "https://vali.internal"
    )


def test_augment_is_idempotent_and_byte_stable() -> None:
    # The launch_digest covers the cmdline bytes — re-augmenting an
    # already-augmented cmdline must be a no-op (no duplicate tokens).
    once = launch._augment_eol_delivery_inputs("ro", vm_id="v", lease_id="l")
    twice = launch._augment_eol_delivery_inputs(once, vm_id="v", lease_id="l")
    assert once == twice
    # Exactly one of each token.
    assert once.count(f"{launch._VM_ID_CMDLINE_KEY}=") == 1
    assert once.count(f"{launch._VALI_URL_CMDLINE_KEY}=") == 1


# ── `hippius.kbs_url` — the boot input the guest cannot boot without ──
#
# These are regression tests for a live production failure (2026-08-18): a
# launch through the public API produced a guest with no KBS endpoint,
# because vali baked every OTHER identity/reach token and left this one to
# the caller. The guest could not fetch its KEK, so it never unlocked and
# never opened its vsock listener. The only visible symptom was
# `ticket-delivery/connect-timeout` eight minutes later, from a domain
# libvirt reported as running.


def test_kbs_url_is_baked_when_the_caller_omits_it() -> None:
    """THE regression. A caller supplying a bare cmdline — which is all the
    public API asks for — must still get a bootable guest."""
    out = launch._augment_eol_delivery_inputs(
        "console=ttyS0 root=/dev/vda", vm_id="vm-1", lease_id="lease-1"
    )
    assert launch._extract_cmdline_token(out, launch._KBS_URL_CMDLINE_KEY) == (
        launch._DEFAULT_VALI_VSOCK_URL
    )


def test_kbs_and_vali_urls_share_one_authority_by_default() -> None:
    """Both ride the same miner-agent vsock proxy, routed by path. Resolving
    them from one setting is what stops them drifting apart."""
    out = launch._augment_eol_delivery_inputs("ro", vm_id="vm-1", lease_id="l-1")
    assert launch._extract_cmdline_token(
        out, launch._KBS_URL_CMDLINE_KEY
    ) == launch._extract_cmdline_token(out, launch._VALI_URL_CMDLINE_KEY)


@override_settings(VALI_GUEST_VSOCK_URL="vsock://2:20000")
def test_setting_overrides_the_default_kbs_url() -> None:
    out = launch._augment_eol_delivery_inputs("ro", vm_id="vm-1", lease_id="l-1")
    assert (
        launch._extract_cmdline_token(out, launch._KBS_URL_CMDLINE_KEY)
        == "vsock://2:20000"
    )


def test_operator_baked_kbs_url_wins() -> None:
    """An operator-supplied token is already MEASURED — rewriting it would
    change the launch digest out from under the allowlist."""
    baked = "console=ttyS0 hippius.kbs_url=https://kbs.example/"
    out = launch._augment_eol_delivery_inputs(baked, vm_id="vm-1", lease_id="l-1")
    assert (
        launch._extract_cmdline_token(out, launch._KBS_URL_CMDLINE_KEY)
        == "https://kbs.example/"
    )
    assert out.count("hippius.kbs_url=") == 1
