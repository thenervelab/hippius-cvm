"""Argument-shape tests for the `vali_dispatch_launch` management
command.

These tests do NOT exercise the dispatch wire (that would need an Edge
in-the-loop and an attested miner); they pin the CLI surface so a
regression that re-introduces a silent `--cpu-count` / `--memory-mb`
default cannot ship. The default-2 case in particular is a known
historical footgun: `snp_calc_launch_digest` folds vcpus into the
launch digest, so any value that doesn't match the deployed UKI's
`snp_launch_config.vcpus` shifts the digest outside the §22 allowlist
and the KBS denies release at attestation time — visible to the
operator only as "miner-accepted, no release" with no breadcrumb.
"""

from __future__ import annotations

import pytest
from django.core.management import CommandError, call_command


def _required_argv() -> dict[str, object]:
    """The bare-minimum kwargs `call_command` rejects when one is missing.

    Held in one place so a future required-arg addition only touches
    one helper, not every test."""
    return {
        "miner_id": "miner-test",
        "vm_id": "vm-test",
        "order_id": "ord-test",
        "cpu_count": 1,
        "memory_mb": 2048,
        # Argparse never validates file existence — handle() does (and
        # raises CommandError "cannot read --cose-ticket-path …"). The
        # parametrized "missing X" tests below pop ONE arg, so for the
        # X != cose_ticket_path runs we never reach handle() and the
        # path string is unused. `/dev/null` is a safe pinned dummy.
        "cose_ticket_path": "/dev/null",
    }


@pytest.mark.parametrize("missing", ["cpu_count", "memory_mb", "cose_ticket_path"])
def test_missing_required_arg_errors_loudly(missing: str) -> None:
    """Omitting any of these required args must raise, not pick a
    silent default. `--cpu-count` feeds the SNP launch digest directly;
    `--memory-mb` shapes the guest boot env + resource accounting;
    `--cose-ticket-path` carries the L1 OrderTicket that the §21
    pipeline reads on its very first stage — a missing one stalls
    every guest. Each is required for a different (silent → loud)
    reason; the test pins all of them at once."""
    argv = _required_argv()
    argv.pop(missing)
    with pytest.raises(CommandError) as exc:
        call_command("vali_dispatch_launch", **argv)
    # Django's argparse adapter raises `CommandError("Error: the
    # following arguments are required: --<flag>")` — the flag name
    # surfaces, so the operator knows WHICH default disappeared.
    msg = str(exc.value)
    assert "required" in msg.lower()
    flag = "--" + missing.replace("_", "-")
    assert flag in msg, (
        f"expected the missing-arg error to name {flag!r}, got: {msg!r}"
    )


def test_help_text_pins_measurement_source_of_truth() -> None:
    """The help text must point at the UKI measurement JSON so an
    operator who hits the arg-required error knows where to look up
    the matching value (vs. guessing or reading the Makefile)."""
    from apps.orchestration.management.commands import vali_dispatch_launch

    # `Command.create_parser` builds the argparse parser the same way
    # Django would on a live `manage.py vali_dispatch_launch --help`.
    parser = vali_dispatch_launch.Command().create_parser("manage.py", "vali_dispatch_launch")
    help_blob = parser.format_help()

    for needle in (
        "--cpu-count",
        "--memory-mb",
        "--cose-ticket-path",
        "snp_launch_config",
        "measurement.json",
        "AF_VSOCK",
    ):
        assert needle in help_blob, (
            f"help text must reference {needle!r} so the operator can "
            f"trace --cpu-count back to the §F UKI measurement; got:\n"
            f"{help_blob}"
        )
