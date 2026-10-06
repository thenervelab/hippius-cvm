"""`vali_stage_tenant_kek` — KEK-HSM Phase 4 staging behaviour.

The decisive property under test: `--generate` NEVER produces a plaintext KEK
in vali — it asks Vault Transit to generate one and returns only the wrapped
ciphertext (`transit/datakey/wrapped`). `--kek-file` still wraps an
operator-supplied plaintext (for an existing disk) and zeroizes it.
"""

from __future__ import annotations

from unittest import mock

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command

from apps.orchestration.services import vault_kv

# The command reads the VM's customer-keys pin (an M2 VM gets no KEK).
pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _vault_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_VAULT_KV_MOUNT", "secret", raising=False)
    monkeypatch.setattr(
        settings, "VALI_VAULT_KV_PREFIX", "hippius-compute/kbs/tenants", raising=False
    )


def test_generate_uses_transit_datakey_never_local_random() -> None:
    with mock.patch.object(vault_kv, "ensure_transit_key") as ensure, mock.patch.object(
        vault_kv, "transit_datakey_wrapped", return_value=b"vault:v1:gen"
    ) as datakey, mock.patch.object(
        vault_kv, "put_kv", return_value=vault_kv.VaultWriteResult(version=1)
    ) as put, mock.patch.object(
        vault_kv, "transit_encrypt"
    ) as encrypt, mock.patch("secrets.token_bytes") as token_bytes:
        call_command("vali_stage_tenant_kek", "--vm-id", "vm-gen-1", "--generate")

    ensure.assert_called_once_with("kek-vm-gen-1")
    datakey.assert_called_once_with("kek-vm-gen-1")
    # vali NEVER generates local key material and NEVER wraps a plaintext here.
    token_bytes.assert_not_called()
    encrypt.assert_not_called()
    # the wrapped ciphertext is what gets staged at the canonical luks-kek path.
    args = put.call_args.args
    assert args[1] == "hippius-compute/kbs/tenants/vm-gen-1/luks-kek"
    assert args[2] == b"vault:v1:gen"


def test_kek_file_wraps_operator_plaintext(tmp_path) -> None:
    kek_file = tmp_path / "kek.bin"
    kek_file.write_bytes(b"\x22" * 32)
    with mock.patch.object(vault_kv, "ensure_transit_key"), mock.patch.object(
        vault_kv, "transit_encrypt", return_value=b"vault:v1:wrapped"
    ) as encrypt, mock.patch.object(
        vault_kv, "put_kv", return_value=vault_kv.VaultWriteResult(version=2)
    ) as put, mock.patch.object(
        vault_kv, "transit_datakey_wrapped"
    ) as datakey:
        call_command(
            "vali_stage_tenant_kek", "--vm-id", "vm-f-1", "--kek-file", str(kek_file)
        )

    encrypt.assert_called_once_with("kek-vm-f-1", b"\x22" * 32)
    datakey.assert_not_called()
    assert put.call_args.args[2] == b"vault:v1:wrapped"


def test_kek_file_wrong_size_rejected(tmp_path) -> None:
    kek_file = tmp_path / "short.bin"
    kek_file.write_bytes(b"\x01" * 16)
    with mock.patch.object(vault_kv, "ensure_transit_key"):
        with pytest.raises(CommandError):
            call_command(
                "vali_stage_tenant_kek", "--vm-id", "vm-x", "--kek-file", str(kek_file)
            )


def test_bad_vm_id_rejected() -> None:
    with pytest.raises(CommandError):
        call_command("vali_stage_tenant_kek", "--vm-id", "BAD_ID", "--generate")
