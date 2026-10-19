"""Serials and by-id names WITHHELD from a host-inventory readout.

The §18.10 operator reads serve a node's serials and `/dev/disk/by-id/`
names to its owner (the acting family, re-checked on chain). The
miner-admin support reads (`/v1/admin/miner/<miner_id>/hardware`, …) serve
the same readouts to fleet staff who are NOT the owner, so before they go
out:

- every key naming a serial (`serial`, `board_serial`, …, any case) is
  REMOVED, wherever it sits;
- every by-id name — a device's `ids`, a dedicated disk's id in the
  cross-check or an advisory subject, one quoted inside a text — is
  replaced by an opaque handle, `withheld:<12 hex>`. A field that IS a
  by-id name (`ids`, `disk_id`, a `dedicated_disk` subject) is replaced
  whatever it looks like. The handle is an
  HMAC under the deployment secret, keyed by the node: the same disk reads
  the same within a node (support can still follow it from the disk list
  to an advisory), and neither its model nor its serial can be recovered
  or guessed back from it;
- a `serial=…` / `"serial": "…"` quoted inside a text is blanked.

Inside a text, a by-id name is recognised two ways: every name vali knows
for the node (the report's device ids and its dedicated disks), and the
by-id shape (the log filter's, `vali.log_filters`, and a wider one with the
characters udev keeps in a name) for anything else. Pool ids are exempt from
the shape test (a pool may be named `nvme-fast1`), never from the known set.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from django.conf import settings

from vali.log_filters import _BY_ID, _SERIAL

from .models import DedicatedDisk, HostInventorySection

WITHHELD_PREFIX = "withheld:"
_SERIAL_TEXT = "<withheld>"
_HMAC_LABEL = "hippius-withheld-by-id:"
#: Keys whose values are pool ids, never by-id names.
_POOL_KEYS = frozenset({"pool_id", "pool_ids"})
#: Keys whose values ARE by-id names, whatever they look like: a device's
#: `ids`, a dedicated disk's `disk_id`.
_BY_ID_KEYS = frozenset({"ids", "disk_id"})
#: Subject keys of an advisory / its history; a `dedicated_disk` subject is a
#: by-id name, a `pool` subject a pool id.
_SUBJECT_KEYS = frozenset({"ref", "subject", "subject_ref"})
#: A by-id name inside a text, wider than the log filter's: udev keeps `+ # =
#: @` and `\xNN` escapes in a name, and a name may follow an underscore. A
#: digit is required so a tool name (`nvme-cli`) passes.
_BY_ID_TEXT = re.compile(
    r"(?<![A-Za-z0-9])(?:wwn|nvme|ata|scsi|usb|virtio|mmc|ieee1394|cciss|edd|memstick|xen"
    r"|md-uuid|dm-uuid|dm-name|lvm-pv-uuid)-"
    # Bounded like the log filter's (a by-id name is at most 96 chars), so a
    # hostile string costs linear time even without the ingest's field caps.
    r"(?=[^\s,;\"'()\[\]{}<>]{0,127}\d)[^\s,;\"'()\[\]{}<>]{1,128}"
)


def _handle(node_id: str, name: str) -> str:
    key = str(settings.SECRET_KEY).encode()
    msg = f"{_HMAC_LABEL}{node_id}\0{name}".encode()
    return f"{WITHHELD_PREFIX}{hmac.new(key, msg, hashlib.sha256).hexdigest()[:12]}"


def known_by_id_names(node_id: str) -> frozenset[str]:
    """Every by-id name vali holds for `node_id`: the storage report's
    device ids and the node's dedicated disks."""
    names: set[str] = set(
        DedicatedDisk.objects.filter(miner_node_id=node_id).values_list("disk_id", flat=True)
    )
    row = HostInventorySection.objects.filter(miner_node_id=node_id, section="storage").first()
    if row is not None:
        for device in (row.body or {}).get("devices") or []:
            if isinstance(device, dict):
                names.update(i for i in device.get("ids") or [] if isinstance(i, str))
    return frozenset(n for n in names if n)


def withhold(payload: Any, *, node_id: str) -> Any:
    """`payload` (a readout: dicts, lists, scalars) with every serial key
    removed and every by-id name replaced by its handle. Pure: the input is
    not modified."""
    known = known_by_id_names(node_id)
    # Longest first, so a name that contains another is replaced whole.
    known_re = (
        re.compile("|".join(re.escape(n) for n in sorted(known, key=len, reverse=True)))
        if known
        else None
    )

    def text(value: str, *, mode: str) -> str:
        if mode == "by_id":
            return _handle(node_id, value)
        if known_re is not None:
            value = known_re.sub(lambda m: _handle(node_id, m.group(0)), value)
        if mode != "pool":
            value = _BY_ID.sub(lambda m: _handle(node_id, m.group(0)), value)
            value = _BY_ID_TEXT.sub(lambda m: _handle(node_id, m.group(0)), value)
        return _SERIAL.sub(lambda m: m.group(1) + f'"{_SERIAL_TEXT}"', value)

    def key_mode(parent: dict[str, Any], key: str) -> str:
        kind = parent.get("kind", parent.get("subject_kind"))
        if key in _BY_ID_KEYS or (kind == "dedicated_disk" and key in _SUBJECT_KEYS):
            return "by_id"
        if key in _POOL_KEYS or (kind == "pool" and key in _SUBJECT_KEYS):
            return "pool"
        return "text"

    def walk(value: Any, *, mode: str = "text") -> Any:
        if isinstance(value, dict):
            return {
                k: walk(v, mode=key_mode(value, k))
                for k, v in value.items()
                if not (isinstance(k, str) and "serial" in k.lower())
            }
        if isinstance(value, list | tuple):
            return [walk(v, mode=mode) for v in value]
        if isinstance(value, str):
            return text(value, mode=mode)
        return value

    return walk(payload)
