"""`node_id_to_miner_id` — the vali `miner_id` a NEW miner gets.

`miner_id` is a global namespace in vali (the `MinerIdentity` primary
key), so an operator does not choose it: it is derived from the node id,
`"m-" + the first 16 lowercase hex chars of the node id`. The node id is
the miner's Ed25519 public key, which `hippius-miner-agent init-identity`
writes to `identity.pub` as 64 hex chars (no `0x`, no newline). The
backend declares the same derived value to vali.

Anything else in `identity.pub` is refused: a truncated or foreign file
would otherwise name the miner after garbage.
"""

import re

MINER_ID_PREFIX = "m-"
MINER_ID_NODE_HEX_CHARS = 16
_NODE_ID_RE = re.compile(r"[0-9a-fA-F]{64}")


def node_id_to_miner_id(node_id: str) -> str:
    """`"m-" + node_id[:16]`, lowercased, from a 64-hex node id.

    Surrounding whitespace is ignored (the agent's own parser trims too);
    a `0x` prefix, a wrong length or a non-hex character raise.
    """
    if not isinstance(node_id, str):
        raise ValueError(f"node_id must be a string, got {type(node_id).__name__}")
    text = node_id.strip()
    if not _NODE_ID_RE.fullmatch(text):
        raise ValueError(
            "node_id must be 64 hex chars (the Ed25519 public key in "
            f"identity.pub), got {len(text)} chars: {text[:80]!r}"
        )
    return MINER_ID_PREFIX + text[:MINER_ID_NODE_HEX_CHARS].lower()


class FilterModule:
    def filters(self) -> dict:
        return {"node_id_to_miner_id": node_id_to_miner_id}
