#!/usr/bin/env python3
"""Regenerate the per-request node signature vectors (contract §C.0).

Run with `cryptography` installed (the backend's own stack):

    python3 -I test_vectors/cdn/gen_node_req_v1.py > test_vectors/cdn/node_req_v1.json

Ed25519 is deterministic, so the output is stable. cdn-agent checks every
case (binaries/cdn-agent/src/reqsign.rs); the backend's
cdn/request_signing.py must verify every signature.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DOMAIN = "HIPPIUS_CDN_NODE_REQ_V1"
LIFECYCLE_SEED = bytes([7] * 32)
NODE_KEY_INFO = b"HIPPIUS_CDN_NODE_KEY_V1"
HOST = "api.hippius.com"
NODE_ID = "cdn-fr-7k2m"
SESSION_ID = "cns_8f3a2c1d9e7b"

CASES = [
    ("feed-snapshot", "GET", "/api/cdn/node/feed/", b"", SESSION_ID),
    ("feed-delta-query", "GET", "/api/cdn/node/feed/?since=42", b"", SESSION_ID),
    ("usage-post", "POST", "/api/cdn/node/usage/",
     b'{"node":"cdn-fr-7k2m","counter_epoch":"e1","seq":7}', SESSION_ID),
    ("acme-dns01", "POST", "/api/cdn/node/acme/dns01/",
     b'{"lease_id":"l1","name":"_acme-challenge.www.example.com","value":"abc"}', SESSION_ID),
    ("percent-encoded-query", "GET", "/api/cdn/node/feed/?since=1&x=a%2Fb", b"", SESSION_ID),
    ("interim-no-session", "GET", "/api/cdn/node/feed/", b"", "-"),
]


def node_key():
    seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=NODE_KEY_INFO).derive(
        LIFECYCLE_SEED
    )
    return Ed25519PrivateKey.from_private_bytes(seed)


def message(node_id, method, host, path_and_query, timestamp, body, session_id):
    return "\n".join([DOMAIN, node_id, method.upper(), host, path_and_query, str(timestamp),
                      hashlib.sha256(body).hexdigest(), session_id]).encode()


def main():
    key = node_key()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    cases = []
    for i, (name, method, path, body, session_id) in enumerate(CASES):
        ts = 1_790_000_000 + i
        msg = message(NODE_ID, method, HOST, path, ts, body, session_id)
        cases.append({
            "name": name,
            "node_id": NODE_ID,
            "method": method,
            "host": HOST,
            "path_and_query": path,
            "timestamp": ts,
            "body_hex": body.hex(),
            "session_id": session_id,
            "message_hex": msg.hex(),
            "signature_b64": base64.b64encode(key.sign(msg)).decode(),
        })
    print(json.dumps({
        "domain": DOMAIN,
        "lifecycle_seed_hex": LIFECYCLE_SEED.hex(),
        "node_key_info": NODE_KEY_INFO.decode(),
        "node_public_hex": public.hex(),
        "cases": cases,
    }, indent=2))


if __name__ == "__main__":
    main()
