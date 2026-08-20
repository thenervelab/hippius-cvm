"""Sentinel tool surface.

Each module here defines `@tool`-decorated callables that are read-only
queries against operational state (KBS audit chain, vali Postgres, chain
RPC, NetBird API, Vault audit, Prometheus). PR-S1 only ships the dummy
`hello_kbs` smoke tool used to validate the agent-loop wiring; real
readers land in PR-S2+ per issue #57.
"""

from sentinel.tools.anchor import publish_audit_anchor
from sentinel.tools.hello import hello_kbs, hello_kbs_impl
from sentinel.tools.kbs_audit import read_kbs_audit_tail, verify_kbs_audit_chain
from sentinel.tools.netbird import get_peer_status_tool, list_peers_tool
from sentinel.tools.thebrain_rpc import (
    read_current_epoch_tool,
    read_epoch_weights_tool,
    read_miner_status_tool,
)
from sentinel.tools.vali_postgres import (
    count_pending_tickets_tool,
    list_recent_state_transitions_tool,
    query_vm_state_tool,
)

__all__ = [
    "count_pending_tickets_tool",
    "get_peer_status_tool",
    "hello_kbs",
    "hello_kbs_impl",
    "list_peers_tool",
    "list_recent_state_transitions_tool",
    "publish_audit_anchor",
    "query_vm_state_tool",
    "read_current_epoch_tool",
    "read_epoch_weights_tool",
    "read_kbs_audit_tail",
    "read_miner_status_tool",
    "verify_kbs_audit_chain",
]
