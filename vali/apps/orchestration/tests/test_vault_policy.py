"""The committed Vault policy is code — read it as such.

`deploy/terraform/policies/vali-orchestrator.hcl` is what actually
enforces the two properties this service's confidentiality story rests
on, and until now nothing read it back:

  1. vali can never decrypt a tenant disk KEK, or the canonical userdata
     the KBS releases (both wrapped under `kek-<vm_id>`). It stages them
     and hands them over; only the attested SNP KBS opens them.
  2. vali CAN decrypt its own userdata working copy (`ud-<vm_id>`),
     because the NetBird substitution at launch and the §6 digest
     re-derivation on a §25 migration / KBS-state recovery need the
     cloud-init plaintext.

A one-character edit — `transit/decrypt/ud-*` → `transit/decrypt/kek-*` —
inverts the first, and every other test in this suite stays green: the
code path is identical, only Vault's answer changes. Hence this file.

It parses the HCL structurally (path blocks + capability lists) rather
than grepping for a string, so a rule that is present but re-scoped, or
capabilities added to an existing block, still fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_POLICY = (
    Path(__file__).resolve().parents[4]
    / "deploy"
    / "terraform"
    / "policies"
    / "vali-orchestrator.hcl"
)

_BLOCK = re.compile(
    r'path\s+"(?P<path>[^"]+)"\s*\{\s*capabilities\s*=\s*\[(?P<caps>[^\]]*)\]',
    re.MULTILINE,
)


def _policy() -> dict[str, set[str]]:
    assert _POLICY.is_file(), f"policy not found at {_POLICY}"
    text = _POLICY.read_text(encoding="utf-8")
    # Strip comments so a capability named inside prose is never parsed
    # as a grant.
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return {
        m.group("path"): {c.strip().strip('"') for c in m.group("caps").split(",") if c.strip()}
        for m in _BLOCK.finditer(text)
    }


def test_vali_can_never_decrypt_a_kek_or_the_canonical_userdata() -> None:
    """THE confidentiality property. `kek-<vm_id>` wraps the tenant disk
    KEK and the canonical cloud-init the KBS releases to the attested
    guest; vali stages both and must never be able to read either back.
    A `transit/decrypt/kek-*` grant — or a wildcard that subsumes it —
    would make every launch an exfiltration opportunity."""
    policy = _policy()
    for path, caps in policy.items():
        if not path.startswith("transit/decrypt/"):
            continue
        scope = path[len("transit/decrypt/") :]
        assert scope.startswith("ud-"), (
            f"the policy grants decrypt on {path!r} ({sorted(caps)}). vali may "
            "decrypt ONLY its own userdata working copy (`ud-<vm_id>`) — a "
            "grant on `kek-*` (or a wildcard covering it) hands a vali RCE "
            "every tenant's disk key and cloud-init."
        )


def test_vali_can_decrypt_its_own_userdata_working_copy() -> None:
    """The other half: without this grant the launch worker cannot
    substitute a NetBird key and the §25 / KBS-recovery re-mint cannot
    re-derive the §6 digest, so every launch fails at staging and every
    migration fails at the mint."""
    caps = _policy().get("transit/decrypt/ud-*")
    assert caps == {"update"}, (
        "vali needs exactly `update` on `transit/decrypt/ud-*` (Vault's "
        f"capability for a decrypt call); got {caps!r}"
    )


def test_the_luks_kek_data_path_stays_read_denied() -> None:
    """KEK-HSM Phase 1: the per-VM secrets tree is stage-only by default
    and the leaves that re-grant `read` are named explicitly. `luks-kek`
    must not be one of them — that is what stops a vali RCE reading a
    tenant disk key straight out of KV, wrapped or not."""
    policy = _policy()
    assert "read" not in policy.get("secret/data/hippius-compute/kbs/tenants/*", set())
    assert not any(
        path.endswith("/luks-kek") and "read" in caps for path, caps in policy.items()
    ), "a rule re-granted read on the luks-kek data path"


@pytest.mark.parametrize(
    "leaf",
    ["userdata", "userdata-pending", "userdata-intake"],
)
def test_every_userdata_path_vali_reads_back_is_readable(leaf: str) -> None:
    """The per-VM secrets tree defaults to create/update (stage-only), and
    each leaf vali legitimately reads has to re-grant `read` explicitly. A
    missing grant is not a subtle degradation: the async launch worker
    reads the intake copy on every launch, so it would 403 and fail every
    one of them at `secret-fetch`, and the §24 monitor would see a 403
    where it requires an observed 404."""
    caps = _policy().get(f"secret/data/hippius-compute/kbs/tenants/+/{leaf}")
    assert caps is not None, f"no rule for the {leaf!r} leaf"
    assert "read" in caps, f"{leaf!r} is not readable: {sorted(caps)}"


@pytest.mark.parametrize(
    "path",
    [
        "transit/keys/ud-*",
        "transit/keys/ud-*/config",
        "transit/encrypt/ud-*",
        "transit/decrypt/ud-*",
    ],
)
def test_the_working_copy_key_is_fully_wired(path: str) -> None:
    """All four grants or the feature is broken in a different place each
    time: no `keys` create ⇒ the first launch 403s; no `encrypt` ⇒ the
    same; no `decrypt` ⇒ launches stage but migrations cannot re-mint; no
    `…/config` update + `delete` ⇒ §24 cannot destroy the key and the
    working copy stays decryptable in every Vault backup."""
    assert path in _policy(), f"missing policy grant: {path}"


def test_the_working_copy_key_can_be_destroyed_at_decommission() -> None:
    assert "delete" in _policy().get("transit/keys/ud-*", set())
    assert "update" in _policy().get("transit/keys/ud-*/config", set())
