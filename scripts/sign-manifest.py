#!/usr/bin/env python3
"""`sign-manifest.py` — Ed25519 detached signature over a Stage 1
`manifest.json` (audit follow-up #2).

Stage 1 (`tenant-rootfs-build.sh`) calls this in `sign` mode to emit
`manifest.json.sig`. Stage 2 (`tenant-image-from-rootfs.sh`) calls it
in `verify` mode BEFORE trusting any SHA in the manifest, so a
compromised S3 admin who swaps both the tarball AND the manifest
cannot fool an operator running Stage 2 with a pinned public key.

The signing key shape (32-byte Ed25519 seed in a 64-hex-char ASCII
file with optional trailing newline) matches the existing dev key at
`packer/kbs-uki/keys/dev/provenance-root.dev.ed25519` so the same
seed signs both §22 allowlist artifacts AND rootfs-build manifests.

Verify mode takes a hex-encoded 32-byte verifying key (the matching
`.pub` file at the same path). The verifying key bytes are what an
operator pins out-of-band; the signing key never leaves the
offline operator workstation.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _read_seed(path: Path) -> bytes:
    raw = path.read_text(encoding="ascii").strip()
    if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
        raise SystemExit(
            f"sign-manifest: {path}: expected 64-hex-char Ed25519 seed"
        )
    return bytes.fromhex(raw)


def _read_pub_hex(value: str) -> bytes:
    value = value.strip()
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise SystemExit(
            "sign-manifest: --verify-pubkey-hex must be 64 lowercase hex chars"
        )
    return bytes.fromhex(value)


def cmd_sign(args: argparse.Namespace) -> int:
    seed = _read_seed(Path(args.signing_key))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    manifest = Path(args.manifest).read_bytes()
    sig = sk.sign(manifest)
    Path(args.out).write_bytes(sig)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    if args.verify_pubkey_hex:
        pub_bytes = _read_pub_hex(args.verify_pubkey_hex)
    elif args.verify_pubkey_file:
        pub_bytes = _read_pub_hex(
            Path(args.verify_pubkey_file).read_text(encoding="ascii")
        )
    else:
        raise SystemExit(
            "sign-manifest verify: one of --verify-pubkey-hex or "
            "--verify-pubkey-file is required"
        )
    pk = Ed25519PublicKey.from_public_bytes(pub_bytes)
    manifest = Path(args.manifest).read_bytes()
    sig = Path(args.sig).read_bytes()
    try:
        pk.verify(sig, manifest)
    except InvalidSignature:
        print(
            f"sign-manifest: VERIFY FAILED — manifest signature does not "
            f"match the pinned public key",
            file=sys.stderr,
        )
        return 4
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sign = sub.add_parser("sign", help="emit a detached Ed25519 sig")
    p_sign.add_argument("--manifest", required=True)
    p_sign.add_argument("--signing-key", required=True)
    p_sign.add_argument("--out", required=True, help="path to write the sig bytes")
    p_sign.set_defaults(func=cmd_sign)

    p_ver = sub.add_parser("verify", help="verify a detached Ed25519 sig")
    p_ver.add_argument("--manifest", required=True)
    p_ver.add_argument("--sig", required=True)
    pub_grp = p_ver.add_mutually_exclusive_group(required=True)
    pub_grp.add_argument(
        "--verify-pubkey-hex",
        help="64-hex-char Ed25519 verifying key (pinned out-of-band)",
    )
    pub_grp.add_argument(
        "--verify-pubkey-file",
        help="file containing 64-hex-char Ed25519 verifying key",
    )
    p_ver.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
