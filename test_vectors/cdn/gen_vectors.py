#!/usr/bin/env python3
"""Regenerate the cdn-agent cross-implementation vectors.

Run with PyNaCl and cryptography installed (the backend's own stack):

    python3 -I test_vectors/cdn/gen_vectors.py > test_vectors/cdn/vectors.json

Sealed boxes are randomised (ephemeral sender key), so a re-run produces
different ciphertexts that must still open to the same plaintexts. The
node-key vector is deterministic and must never change: vali derives the
node public key from the lifecycle seed with the same HKDF.
"""
import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.public import PrivateKey, SealedBox

LIFECYCLE_SEED = bytes([7] * 32)
NODE_KEY_INFO = b"HIPPIUS_CDN_NODE_KEY_V1"
FLEET_SECRET = bytes(range(32))


def node_key_vector():
    seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=NODE_KEY_INFO).derive(
        LIFECYCLE_SEED
    )
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "lifecycle_seed_hex": LIFECYCLE_SEED.hex(),
        "info": NODE_KEY_INFO.decode(),
        "node_seed_hex": seed.hex(),
        "node_public_hex": public.hex(),
    }


def sealed_box_vector():
    sk = PrivateKey(FLEET_SECRET)
    box = SealedBox(sk.public_key)
    plaintexts = [
        b"",
        b"placeholder key material, not a real key\n",
        json.dumps({"access_key_id": "AKEXAMPLE", "secret_access_key": "example"}).encode(),
        bytes(range(256)) * 4,
    ]
    return {
        "fleet_secret_hex": FLEET_SECRET.hex(),
        "fleet_public_hex": bytes(sk.public_key).hex(),
        "cases": [
            {
                "plaintext_b64": base64.b64encode(p).decode(),
                "sealed_b64": base64.b64encode(box.encrypt(p)).decode(),
            }
            for p in plaintexts
        ],
    }


print(json.dumps({"node_key": node_key_vector(), "sealed_box": sealed_box_vector()}, indent=2))
