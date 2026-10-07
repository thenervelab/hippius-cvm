"""The CDN node key (CDN plan A.6 / G.2).

    node_seed = HKDF-SHA256(ikm=lifecycle_seed, salt="", info="HIPPIUS_CDN_NODE_KEY_V1", L=32)
    node_key  = Ed25519(node_seed)

The lifecycle seed is the §7 key the KBS releases only to the VM's attested
launch, so a key derived from it belongs to that VM. vali reads the seed
(it staged it, `launch._stage_lifecycle_key`) and derives the PUBLIC key its
CDN CA certifies; the cdn-agent derives the same key in the guest
(`binaries/cdn-agent/src/identity.rs`, shared vector
`test_vectors/cdn/vectors.json`).

The proof that a seed is the VM's: its own Ed25519 public key is the VM's
recorded `Vm.lifecycle_vk`. The KBS releases the seed at version 1 forever
and `lifecycle_vk` is derived from that version at launch, so a seed that
does not match is not the one the guest holds — refused, never certified.

§20: the seed and the derived node seed are secrets. They live in local
bytes for one derivation and are never logged or stored.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

from apps.lifecycle.models import Vm

#: HKDF `info`. Changing it changes every node key.
NODE_KEY_INFO = b"HIPPIUS_CDN_NODE_KEY_V1"

#: The KV v2 version the KBS releases the lifecycle seed at, forever
#: (`kbs-core/src/release.rs` `LIFECYCLE_KEY_VERSION`).
LIFECYCLE_KEY_VERSION = 1


class NodeKeyError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _ed25519_public(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def derive_node_public_key(lifecycle_seed: bytes) -> bytes:
    """The 32-byte node public key derived from `lifecycle_seed`."""
    if len(lifecycle_seed) != 32:
        raise NodeKeyError("lifecycle-key-shape", "the lifecycle seed must be 32 bytes")
    node_seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=NODE_KEY_INFO).derive(
        lifecycle_seed
    )
    try:
        return _ed25519_public(node_seed)
    finally:
        del node_seed


def lifecycle_key_path(vm_id: str) -> str:
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", "") or "")
    if not prefix:
        raise NodeKeyError("vault-not-configured", "VALI_VAULT_KV_PREFIX is not configured")
    return f"{prefix}/{vm_id}/lifecycle-key"


def node_public_key_for(vm: Vm) -> bytes:
    """Read `vm`'s lifecycle seed at the version the KBS releases, check it
    is the seed `vm.lifecycle_vk` was derived from, and return the node
    public key derived from it.

    Raises `NodeKeyError` (`lifecycle-key-missing`, `lifecycle-key-mismatch`)
    or the Vault client's `EffectError` / `EffectUnavailable`."""
    from apps.orchestration.services import vault_kv

    recorded_vk = bytes(vm.lifecycle_vk or b"")
    if len(recorded_vk) != 32:
        raise NodeKeyError(
            "lifecycle-key-missing", f"vm {vm.vm_id} has no recorded lifecycle public key"
        )
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    try:
        seed = vault_kv.get_kv(mount, lifecycle_key_path(vm.vm_id), version=LIFECYCLE_KEY_VERSION)
    except vault_kv.VaultNotFound as exc:
        raise NodeKeyError(
            "lifecycle-key-missing", f"vm {vm.vm_id} has no staged lifecycle seed"
        ) from exc
    try:
        if len(seed) != 32 or _ed25519_public(seed) != recorded_vk:
            raise NodeKeyError(
                "lifecycle-key-mismatch",
                f"vm {vm.vm_id}: the staged lifecycle seed is not the one its lifecycle key was "
                "derived from",
            )
        return derive_node_public_key(seed)
    finally:
        del seed
