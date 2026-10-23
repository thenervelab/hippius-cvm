"""The desired `storage-config` document: shape, static checks, canonical
form (docs/design/disk-tier-verification.md §9).

vali runs the checks the agent runs without a host
(`binaries/miner-agent/src/storage/remote.rs::validate_static`), with the
agent's refusal codes, so an operator hears about a bad document at once
instead of one push later. The host checks (mount, filesystem, budget vs
free space, live disks) stay the agent's: `POST …/storage/validate` asks
it.

The document vali stores and sends:

    {"pools": [{"id", "path", "class", "budget_gb", "os_disks", "state"}],
     "dedicated_disks": [{"id", "state", "class"?}]}

pools 1..=4 sorted by id with `default` among them; dedicated disks ≤ 24
sorted by id. `revision`, `not_after_unix` and `dry_run` are added per
push.

A dedicated disk's optional `class` (`hdd` | `ssd` | `nvme`) is the
operator's declared class, the cap of the tier it can be sold at
(`DedicatedDisk.declared_class`). It is VALI-SIDE ONLY: the agent's
`DedicatedDiskSpec` is `deny_unknown_fields`, so [`order_payload`] strips
it from every push and dry run (the agent sees, and hashes, the document
it always did). A disk without one is stored without the key, so a
document that never names a class stays byte-identical.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

#: `hippius_types::storage_report` bounds.
MAX_POOLS = 4
MAX_DEDICATED_DISKS = 24
MAX_DEDICATED_DISK_ID_LEN = 96
#: A pool's budget is a `u32` on the wire.
MAX_BUDGET_GB = 2**32 - 1
#: Longest path vali accepts (Linux `PATH_MAX`).
MAX_PATH_LEN = 4096
DEFAULT_POOL_ID = "default"

POOL_CLASSES = ("nvme", "ssd", "hdd")
DESIRED_STATES = ("active", "draining")
DEDICATED_DISK_ID_PREFIXES = ("wwn-", "ata-", "scsi-", "nvme-")

_POOL_KEYS = frozenset({"id", "path", "class", "budget_gb", "os_disks", "state"})
_DISK_KEYS = frozenset({"id", "state"})
#: Keys a dedicated disk may carry in vali's document only (never pushed).
_DISK_VALI_KEYS = frozenset({"class"})
DEDICATED_CLASSES = ("nvme", "ssd", "hdd")
_DOC_KEYS = frozenset({"pools", "dedicated_disks"})

_POOL_ID_RE = re.compile(r"[a-z0-9-]{1,32}")
_BY_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,96}")


@dataclass(frozen=True)
class DocError(Exception):
    """A refusal: the agent's code, and the pool or disk it names."""

    code: str
    message: str
    pool: str = ""
    disk: str = ""

    def body(self) -> dict[str, str]:
        out = {"error": self.message, "category": "validation", "code": self.code}
        if self.pool:
            out["pool"] = self.pool
        if self.disk:
            out["disk"] = self.disk
        return out


def is_valid_pool_id(value: str) -> bool:
    return bool(_POOL_ID_RE.fullmatch(value))


def is_valid_dedicated_disk_id(value: str) -> bool:
    """`hippius_types::storage_report::is_valid_dedicated_disk_id`: a
    `/dev/disk/by-id/` basename of 1..=96 `[A-Za-z0-9._:-]` in a stable
    family (`wwn-`, `ata-`, `scsi-`, `nvme-`) with something after the
    prefix, never a partition (`-partN`)."""
    if not _BY_ID_RE.fullmatch(value):
        return False
    if not any(len(value) > len(p) and value.startswith(p) for p in DEDICATED_DISK_ID_PREFIXES):
        return False
    _, sep, tail = value.rpartition("-part")
    return not (sep and tail.isdigit())


def is_plain_absolute(path: str) -> bool:
    """The agent's `is_plain_absolute`: absolute, in its one spelling — no
    `.`/`..` component, no doubled or trailing `/`."""
    if not path.startswith("/") or "\x00" in path or len(path) > MAX_PATH_LEN:
        return False
    if path == "/":
        return True
    return all(part not in ("", ".", "..") for part in path[1:].split("/"))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pool(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise DocError("storage-config-malformed", "each pool is an object")
    pool_id = raw.get("id")
    label = pool_id if isinstance(pool_id, str) else ""
    if set(raw) != _POOL_KEYS:
        raise DocError(
            "storage-config-malformed",
            f"a pool has exactly the keys {sorted(_POOL_KEYS)}",
            pool=label[:32],
        )
    if not isinstance(pool_id, str) or not is_valid_pool_id(pool_id):
        raise DocError("pool-id-invalid", "a pool id is [a-z0-9-]{1,32}", pool=label[:32])
    if not isinstance(raw["path"], str):
        raise DocError("pool-path-invalid", "path is a string", pool=pool_id)
    if raw["class"] not in POOL_CLASSES:
        raise DocError("pool-class-invalid", f"class is one of {POOL_CLASSES}", pool=pool_id)
    budget = raw["budget_gb"]
    if not _is_int(budget) or not 0 <= budget <= MAX_BUDGET_GB:
        raise DocError("pool-budget-invalid", "budget_gb is an integer 0..2^32-1", pool=pool_id)
    if not isinstance(raw["os_disks"], bool):
        raise DocError("storage-config-malformed", "os_disks is a boolean", pool=pool_id)
    if raw["state"] not in DESIRED_STATES:
        raise DocError("pool-state-invalid", f"state is one of {DESIRED_STATES}", pool=pool_id)
    return {k: raw[k] for k in sorted(_POOL_KEYS)}


def _disk(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise DocError("storage-config-malformed", "each dedicated disk is an object")
    disk_id = raw.get("id")
    label = disk_id if isinstance(disk_id, str) else ""
    if not _DISK_KEYS <= set(raw) <= _DISK_KEYS | _DISK_VALI_KEYS:
        raise DocError(
            "storage-config-malformed",
            f"a dedicated disk has the keys {sorted(_DISK_KEYS)} and optionally "
            f"{sorted(_DISK_VALI_KEYS)}",
            disk=label[:MAX_DEDICATED_DISK_ID_LEN],
        )
    if not isinstance(disk_id, str) or not is_valid_dedicated_disk_id(disk_id):
        raise DocError(
            "disk-id-invalid",
            "a dedicated disk id is a stable /dev/disk/by-id basename (wwn-, ata-, scsi-, "
            "nvme-), never a partition",
            disk=label[:MAX_DEDICATED_DISK_ID_LEN],
        )
    if raw["state"] not in DESIRED_STATES:
        raise DocError("disk-state-invalid", f"state is one of {DESIRED_STATES}", disk=disk_id)
    out = {"id": disk_id, "state": raw["state"]}
    if "class" in raw:
        if raw["class"] not in DEDICATED_CLASSES:
            raise DocError(
                "disk-class-invalid", f"class is one of {DEDICATED_CLASSES}", disk=disk_id
            )
        out["class"] = raw["class"]
    return out


def normalize(
    raw: Any,
    *,
    default_budget_gb: int | None = None,
    default_path: str | None = None,
    held_paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The canonical document for `raw`, or `DocError` with the agent's
    code. What vali knows of the host's local facts tightens the checks
    (each `None` = unknown, left to the agent):

    - `default_budget_gb`: the host budget the agent reports for `default`
      (its `[host] cvm_disk_gb_budget`);
    - `default_path`: `default`'s path in the last document the agent
      ACCEPTED (so its `data_disk_root`);
    - `held_paths`: `{pool_id: path}` of the accepted pools the agent
      reports holding disks: they may be neither moved nor removed
      (`pool-has-disks`; drain them instead)."""
    if not isinstance(raw, dict) or not set(raw) <= _DOC_KEYS or "pools" not in raw:
        raise DocError(
            "storage-config-malformed",
            "the document is {pools: [...], dedicated_disks: [...]}",
        )
    pools_raw = raw["pools"]
    disks_raw = raw.get("dedicated_disks", [])
    if not isinstance(pools_raw, list) or not isinstance(disks_raw, list):
        raise DocError("storage-config-malformed", "pools and dedicated_disks are lists")
    if len(pools_raw) > MAX_POOLS:
        raise DocError("too-many-pools", f"at most {MAX_POOLS} pools")
    pools = sorted((_pool(p) for p in pools_raw), key=lambda p: p["id"])
    seen_paths: set[str] = set()
    for i, pool in enumerate(pools):
        if i and pools[i - 1]["id"] == pool["id"]:
            raise DocError("pool-id-invalid", "pool ids are unique", pool=pool["id"])
        if not is_plain_absolute(pool["path"]):
            raise DocError(
                "pool-path-invalid",
                "path is absolute, without . / .. components or doubled / trailing /",
                pool=pool["id"],
            )
        if pool["path"] in seen_paths:
            raise DocError("pool-shared-fs", "two pools share a path", pool=pool["id"])
        seen_paths.add(pool["path"])
        if pool["id"] != DEFAULT_POOL_ID and pool["budget_gb"] == 0:
            raise DocError("pool-budget-invalid", "budget_gb must be > 0", pool=pool["id"])
    default = next((p for p in pools if p["id"] == DEFAULT_POOL_ID), None)
    if default is None:
        raise DocError(
            "pool-default-required", "the document must keep pool `default`", pool=DEFAULT_POOL_ID
        )
    if not default["os_disks"] or default["state"] != "active":
        raise DocError(
            "pool-conflicts-local",
            "pool `default` takes OS disks and stays active",
            pool=DEFAULT_POOL_ID,
        )
    if default_budget_gb is not None and default["budget_gb"] != default_budget_gb:
        raise DocError(
            "pool-conflicts-local",
            f"pool `default` has the host budget the miner reports ({default_budget_gb} GB)",
            pool=DEFAULT_POOL_ID,
        )
    if default_path is not None and default["path"] != default_path:
        raise DocError(
            "pool-conflicts-local",
            f"pool `default` stays at the miner's data root ({default_path})",
            pool=DEFAULT_POOL_ID,
        )
    by_id = {p["id"]: p for p in pools}
    for pool_id, path in sorted((held_paths or {}).items()):
        if pool_id not in by_id or by_id[pool_id]["path"] != path:
            raise DocError(
                "pool-has-disks",
                "the pool holds VM disks: it can be drained, not moved or removed",
                pool=pool_id,
            )

    if len(disks_raw) > MAX_DEDICATED_DISKS:
        raise DocError("too-many-disks", f"at most {MAX_DEDICATED_DISKS} dedicated disks")
    disks = sorted((_disk(d) for d in disks_raw), key=lambda d: d["id"])
    for i, disk in enumerate(disks):
        if i and disks[i - 1]["id"] == disk["id"]:
            raise DocError("disk-duplicate", "dedicated disk ids are unique", disk=disk["id"])
    return {"pools": pools, "dedicated_disks": disks}


def content_key(doc: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def agent_disks(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The document's dedicated disks as the agent takes them: `{id, state}`
    only (the vali-side `class` stripped)."""
    return [{k: d[k] for k in sorted(_DISK_KEYS)} for d in doc.get("dedicated_disks", [])]


def order_payload(
    doc: dict[str, Any], *, revision: int, not_after_unix: int, dry_run: bool
) -> bytes:
    """The `storage-config` order JSON `encode-order` reads — never a
    vali-side key ([`agent_disks`])."""
    return json.dumps(
        {
            "revision": revision,
            "not_after_unix": not_after_unix,
            "dry_run": dry_run,
            "pools": doc["pools"],
            "dedicated_disks": agent_disks(doc),
        },
        sort_keys=True,
    ).encode()
