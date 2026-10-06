"""Stage a tenant VM's LUKS KEK as Vault-Transit CIPHERTEXT (KEK-HSM Phase 2).

The operator/bake stages a tenant's disk KEK at the canonical
`{VALI_VAULT_KV_PREFIX}/{vm_id}/luks-kek` path that the KBS releases from.
Historically that value was the PLAINTEXT KEK. Phase 2 stores it WRAPPED:
this command creates the per-VM Vault Transit key `kek-<vm_id>`, encrypts
the KEK with it, and `put_kv`s the `vault:v1:…` ciphertext — so the KEK
never exists in the clear at rest. Only the attested SNP KBS can
`transit/decrypt` it (per-VM scoped by the broker) on release.

Usage:
  # wrap an EXISTING plaintext KEK (must match the disk's LUKS header):
  python manage.py vali_stage_tenant_kek --vm-id <id> --kek-file /path/to/kek.bin
  # or generate a fresh KEK entirely inside Vault Transit (KEK-HSM Phase 4 —
  # vali NEVER sees the plaintext; for a NEW disk whose bake `transit/decrypt`s
  # it to luksFormat):
  python manage.py vali_stage_tenant_kek --vm-id <id> --generate

Production-direct: no dev bypass. `--generate` uses `transit/datakey/wrapped`
so vali never holds a plaintext KEK at all; `--kek-file` holds the
operator-supplied plaintext only long enough to wrap it, then zeroizes. Only
the ciphertext is ever persisted.
"""

from __future__ import annotations

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.lifecycle.models import Vm
from apps.orchestration.services import customer_keys, vault_kv

# Same charset the canonical path + the broker BrokerScope::validate accept.
_VM_ID_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-")


class Command(BaseCommand):
    help = "Stage a tenant VM's LUKS KEK as Vault-Transit ciphertext (KEK-HSM Phase 2)."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--vm-id", required=True, help="Tenant VM id ([a-z0-9-]).")
        src = parser.add_mutually_exclusive_group(required=True)
        src.add_argument(
            "--kek-file",
            help="Path to the 32-byte raw KEK to wrap (must match the disk's LUKS header).",
        )
        src.add_argument(
            "--generate",
            action="store_true",
            help=(
                "Generate a fresh KEK inside Vault Transit (transit/datakey/wrapped) "
                "— vali never sees the plaintext; for a NEW disk whose bake "
                "transit/decrypts it to luksFormat."
            ),
        )

    def handle(self, *args, **opts) -> None:
        vm_id: str = opts["vm_id"]
        if not vm_id or not (1 <= len(vm_id) <= 64) or any(c not in _VM_ID_OK for c in vm_id):
            raise CommandError("--vm-id must be [a-z0-9-], length 1..64")

        mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
        prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", ""))
        if not prefix:
            raise CommandError("VALI_VAULT_KV_PREFIX is not configured")
        luks_path = f"{prefix}/{vm_id}/luks-kek"

        # Customer-held keys M2 (`customer`): Hippius holds NO disk KEK for
        # that VM. Staging one here would put provider key material beside
        # a disk the customer alone is meant to unlock.
        pinned = Vm.objects.filter(vm_id=vm_id).values_list("key_mode", flat=True).first()
        if pinned == customer_keys.KEY_MODE_CUSTOMER:
            raise CommandError(
                f"vm {vm_id!r} is pinned key_mode=customer: Hippius holds no disk KEK "
                "for it, refusing to stage one"
            )

        transit_key = vault_kv.transit_key_name(vm_id)
        vault_kv.ensure_transit_key(transit_key)

        if opts.get("kek_file"):
            # Operator supplies the plaintext KEK for an EXISTING disk (the
            # disk's LUKS header was formatted with exactly these bytes). vali
            # must wrap it, so it holds the operator-chosen plaintext only long
            # enough to encrypt, then zeroizes. It never GENERATES a plaintext.
            kek = bytearray(32)
            try:
                with open(opts["kek_file"], "rb") as fh:
                    raw = fh.read()
                if len(raw) != 32:
                    raise CommandError(f"--kek-file must be exactly 32 bytes (got {len(raw)})")
                kek = bytearray(raw)
                wrapped = vault_kv.transit_encrypt(transit_key, bytes(kek))
                res = vault_kv.put_kv(mount, luks_path, wrapped)
            finally:
                # §20 — zeroize the plaintext KEK buffer promptly.
                for i in range(len(kek)):
                    kek[i] = 0
        else:
            # KEK-HSM Phase 4 — `--generate`: Vault Transit generates the KEK
            # and returns ONLY the wrapped ciphertext (`transit/datakey/wrapped`)
            # — vali NEVER holds the plaintext, not even at generation. The KEK
            # material becomes recoverable ONLY via a per-VM-scoped
            # `transit/decrypt` (the attested KBS on release; the transient bake
            # `luksFormat` for a NEW disk). No `secrets.token_bytes` in vali.
            wrapped = vault_kv.transit_datakey_wrapped(transit_key)
            res = vault_kv.put_kv(mount, luks_path, wrapped)

        self.stdout.write(
            self.style.SUCCESS(
                f"staged WRAPPED KEK for {vm_id}: transit_key={vault_kv.transit_key_name(vm_id)} "
                f"path={mount}/data/{luks_path} version={res.version} "
                f"(ciphertext at rest — never plaintext)"
            )
        )
