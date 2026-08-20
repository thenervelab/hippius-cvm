"""Pure-Python port of `hippius_types::digest::userdata_digest`.

The KBS recomputes this digest from the bytes it just unwrapped + the
binding fields the ticket asserts; if the L1-side preimage encoding
and the KBS-side preimage encoding diverge byte-for-byte, the §6/§19
gate fail-closes. The Rust authoritative implementation is
`hippius-types/src/digest.rs::userdata_digest`. This module is the
operator-tier mirror — it lets `vali_create_vm` mint a ticket with
the matching `allowed_userdata_digest_hex` without shelling out to
the Rust `tenant-secrets-stage.sh` helper that bakes the same
framing into a Python heredoc.

Wire shape (must NOT drift from the Rust impl):
    sha256(
        len_LE_u64("HIPPIUS_USERDATA_DIGEST_V1") ‖ b"HIPPIUS_USERDATA_DIGEST_V1"
      ‖ len_LE_u64(tenant_id) ‖ tenant_id
      ‖ len_LE_u64(vm_id) ‖ vm_id
      ‖ len_LE_u64(ticket_id) ‖ ticket_id
      ‖ len_LE_u64(secret_type) ‖ secret_type
      ‖ len_LE_u64(path) ‖ path
      ‖ version_LE_u64
      ‖ len_LE_u64(plaintext) ‖ plaintext
    )

`scripts/tenant-secrets-stage.sh::compute_userdata_digest_hex` carries
the same framing in a heredoc; the Rust unit test in
`hippius-types/src/digest.rs` and the Python tests in
`vali/apps/orchestration/tests/test_userdata_digest.py` pin the same
fixture vector so a drift fires loudly in both lanes.
"""

from __future__ import annotations

import hashlib

DOMAIN = b"HIPPIUS_USERDATA_DIGEST_V1"
SECRET_TYPE_USERDATA = "userdata"


def _put_framed(h: hashlib._Hash, s: bytes) -> None:
    h.update(len(s).to_bytes(8, "little"))
    h.update(s)


def userdata_digest(
    *,
    tenant_id: str,
    vm_id: str,
    ticket_id: str,
    secret_type: str,
    path: str,
    version: int,
    plaintext: bytes,
) -> bytes:
    """Return the 32-byte SHA-256 over the canonical preimage. The Rust
    side returns `[u8; 32]`; here we return `bytes` of length 32."""
    if version < 0:
        raise ValueError("version must be a non-negative integer")
    h = hashlib.sha256()
    _put_framed(h, DOMAIN)
    _put_framed(h, tenant_id.encode("utf-8"))
    _put_framed(h, vm_id.encode("utf-8"))
    _put_framed(h, ticket_id.encode("utf-8"))
    _put_framed(h, secret_type.encode("utf-8"))
    _put_framed(h, path.encode("utf-8"))
    h.update(version.to_bytes(8, "little"))
    _put_framed(h, plaintext)
    return h.digest()


def userdata_digest_hex(**kwargs: object) -> str:
    """Convenience: the lowercase-hex form the `order-ticket-mint` CLI
    expects for `--allowed-userdata-digest-hex`."""
    digest = userdata_digest(**kwargs)  # type: ignore[arg-type]
    return digest.hex()
