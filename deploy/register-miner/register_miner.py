#!/usr/bin/env python3
"""register-miner — permissionless on-chain miner onboarding (§23 PR-3).

Submits `pallet-compute-scoring::register_child(family, child, node_id,
node_sig)` so a miner's Ed25519 node identity is bound to an on-chain
account and becomes `Active` — the gate the Edge's permissionless
auth (PR-2) and the §23 scheduler read. No operator certificate is
involved: the trust anchor is the chain (see
`docs/design/permissionless-miner-auth.md`).

Split of duties (so a secret never leaves the box that holds it):

  1. On the MINER box (which holds the identity key, no funds):
         hippius-miner-agent sign-registration \\
             --family 0x<family_pubkey_hex> \\
             --child  0x<child_pubkey_hex> \\
             --nonce  <NodeIdNonce>
     → emits {"node_id": "...", "node_sig": "...", "nonce": N} on stdout.

  2. On the OPERATOR workstation (which holds the family key, no node
     key): feed that JSON to this script, which composes + signs +
     submits `register_child` with the family keypair.

Helper: `account-hex <ss58>` prints the 0x-hex AccountId to pass to
the agent's `--family` / `--child` (the agent takes raw 32-byte hex,
not SS58, to stay dependency-light).

Requires: substrate-interface (`pip install substrate-interface`).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

try:
    from substrateinterface import Keypair, SubstrateInterface
    from substrateinterface.utils.ss58 import ss58_decode
except ImportError:  # pragma: no cover - operator-facing guard
    sys.exit(
        "register-miner: substrate-interface is required "
        "(pip install substrate-interface)"
    )

PALLET = "ComputeScoring"
DEFAULT_SS58_FORMAT = 42


def _to_hex_account(value: str) -> str:
    """Normalise an account given as SS58 or 0x-hex to 0x-hex (32 B)."""
    v = value.strip()
    if v.startswith("0x"):
        raw = v[2:]
        if len(raw) != 64:
            raise ValueError(f"hex AccountId must be 32 bytes, got {len(raw)//2}")
        bytes.fromhex(raw)  # validate
        return "0x" + raw.lower()
    # SS58 → 0x-hex public key.
    return "0x" + ss58_decode(v)


@dataclass
class NodeAuth:
    node_id: str  # 0x-hex, 32 bytes
    node_sig: str  # 0x-hex, 64 bytes
    nonce: int

    @classmethod
    def from_agent_json(cls, blob: str) -> "NodeAuth":
        d = json.loads(blob)
        node_id = d["node_id"]
        node_sig = d["node_sig"]
        if not node_id.startswith("0x"):
            node_id = "0x" + node_id
        if not node_sig.startswith("0x"):
            node_sig = "0x" + node_sig
        if len(node_id) != 2 + 64:
            raise ValueError("node_id must be 32 bytes of hex")
        if len(node_sig) != 2 + 128:
            raise ValueError("node_sig must be 64 bytes of hex")
        return cls(node_id=node_id.lower(), node_sig=node_sig.lower(), nonce=int(d["nonce"]))


def cmd_account_hex(args: argparse.Namespace) -> int:
    """Print the 0x-hex AccountId for an SS58 address (feed to the agent)."""
    print(_to_hex_account(args.address))
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    auth = NodeAuth.from_agent_json(_read_json_arg(args.node_auth))

    substrate = SubstrateInterface(url=args.rpc, ss58_format=args.ss58_format)

    # Family keypair — the extrinsic origin. `register_child` enforces
    # `who == family`, so the submitting key IS the family account.
    family = Keypair.create_from_uri(
        _read_secret(args.family_suri), ss58_format=args.ss58_format
    )

    # Cross-check: the family the node SIGNED for must equal the
    # submitting account. A mismatch means the node_sig was produced
    # for a different family → the chain would reject it, fail loudly
    # here instead.
    signed_family_hex = _to_hex_account(args.family)
    if signed_family_hex != _to_hex_account(family.ss58_address):
        sys.exit(
            "register-miner: --family does not match --family-suri's account "
            "(the node_sig was signed for a different family)"
        )

    child_addr = args.child  # SS58 or 0x-hex; substrate-interface accepts either

    call = substrate.compose_call(
        call_module=PALLET,
        call_function="register_child",
        call_params={
            "family": family.ss58_address,
            "child": child_addr,
            "node_id": auth.node_id,
            "node_sig": auth.node_sig,
        },
    )

    if args.dry_run:
        print(json.dumps({"call": str(call.value), "nonce": auth.nonce}, indent=2))
        return 0

    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=family)
    receipt = substrate.submit_extrinsic(
        extrinsic, wait_for_inclusion=True
    )

    out = {
        "extrinsic_hash": receipt.extrinsic_hash,
        "block_hash": receipt.block_hash,
        "is_success": receipt.is_success,
        "node_id": auth.node_id,
    }
    if not receipt.is_success:
        out["error"] = str(receipt.error_message)
        print(json.dumps(out, indent=2))
        return 1
    # Surface the ChildRegistered / NodeRegistered event for confirmation.
    out["events"] = [
        {"module": e.value["module_id"], "event": e.value["event_id"]}
        for e in receipt.triggered_events
        if e.value["module_id"] == PALLET
    ]
    print(json.dumps(out, indent=2))
    return 0


def _read_json_arg(value: str) -> str:
    """A JSON blob, or `@path` / `-` to read from a file / stdin."""
    if value == "-":
        return sys.stdin.read()
    if value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8") as f:
            return f.read()
    return value


def _read_secret(value: str) -> str:
    """A mnemonic / suri inline, or `@path` to read it from a file."""
    if value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8") as f:
            return f.read().strip()
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="register-miner", description=__doc__)
    p.add_argument(
        "--ss58-format",
        type=int,
        default=DEFAULT_SS58_FORMAT,
        help=f"SS58 address format (default {DEFAULT_SS58_FORMAT}).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    ah = sub.add_parser(
        "account-hex",
        help="Print the 0x-hex AccountId for an SS58 address (for the agent).",
    )
    ah.add_argument("address", help="SS58 address to convert.")
    ah.set_defaults(func=cmd_account_hex)

    sb = sub.add_parser("submit", help="Submit register_child with the family key.")
    sb.add_argument("--rpc", required=True, help="Substrate ws/http RPC URL.")
    sb.add_argument(
        "--family",
        required=True,
        help="Family account (SS58 or 0x-hex) — must match --family-suri.",
    )
    sb.add_argument(
        "--family-suri",
        required=True,
        help="Family secret URI / mnemonic, or @path to a 0600 file.",
    )
    sb.add_argument("--child", required=True, help="Child account (SS58 or 0x-hex).")
    sb.add_argument(
        "--node-auth",
        required=True,
        help="The agent's sign-registration JSON, or @path / - for stdin.",
    )
    sb.add_argument(
        "--dry-run",
        action="store_true",
        help="Compose + print the call without submitting.",
    )
    sb.set_defaults(func=cmd_submit)
    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
