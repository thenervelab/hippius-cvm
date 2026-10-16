"""The probe request and the user-data that carries it to the probe VM
(design §3.2, §4.4; the guest side is `binaries/agent-disk-probe`).

The request is the guest's closed wire shape
(`binaries/agent-disk-probe/src/request.rs`, `deny_unknown_fields`):

    {"vm_id", "run_id": <32 hex>, "nonce": <64 hex>, "start_delay_s": <= 259200,
     "targets": [{"slot": "os", "profile": "v1"}, {"slot": "x0", "profile": "d1"}, ...]}

The user-data rides the KBS release to the attested guest, like any
tenant's, so the miner never sees it (nor the nonce). It holds no user and
no SSH key: the probe VM has no root path for anyone.

**How the request reaches `/run` (a gap, closed here from the user-data
side).** The guest unit `hippius-disk-probe.service` starts on
`ConditionPathExists=/run/hippius/disk-probe/request.json`, ordered only
`After=local-fs.target`, and its comment assumes the request is in `/run`
before switch_root. It is not: the initramfs only writes the released
user-data as the NoCloud seed (`/run/cloud-init/seed/`), and cloud-init's
`write_files` lays the request down later, in `cloud-init.service`, with
no ordering against the probe unit. So at boot the unit's condition may be
checked before the file exists, and a skipped unit is not retried. The
user-data therefore also starts the unit itself from `runcmd`
(`cloud-final.service`, after `write_files`): `systemctl start --no-block`
re-evaluates the condition, and is a no-op when the unit already runs
(`Type=exec`, sleeping its start delay). A guest-side fix (ordering the
unit after `cloud-init.service`, or the initramfs writing the request
before switch_root) is a guest-release change, not made here.

`render` is pure: the same run renders the same bytes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .models import OS_SLOT

#: The guest's cap on `start_delay_s` (`MAX_START_DELAY_S`).
MAX_START_DELAY_S = 72 * 3600
#: Where the guest reads the request.
REQUEST_PATH = "/run/hippius/disk-probe/request.json"
#: The guest unit the user-data starts (see the module docstring).
PROBE_UNIT = "hippius-disk-probe.service"

_VM_ID_RE = re.compile(r"[a-z0-9-]{1,64}")
_SLOT_RE = re.compile(r"os|x(?:[0-9]|1[0-9]|2[0-3])")
_PROFILE_OF_SLOT_KIND = {True: "v1", False: "d1"}


class ProbeUserdataError(ValueError):
    pass


@dataclass(frozen=True)
class RequestTarget:
    slot: str

    @property
    def profile(self) -> str:
        # `os` runs v1 (the OS disk, on a pool); `x<N>` runs d1 (a
        # dedicated disk). The guest refuses any other pairing.
        return _PROFILE_OF_SLOT_KIND[self.slot == OS_SLOT]


def request_json(
    *, vm_id: str, run_id_hex: str, nonce: bytes, start_delay_s: int, slots: tuple[str, ...]
) -> str:
    """The request file's content (compact, sorted keys)."""
    if not _VM_ID_RE.fullmatch(vm_id):
        raise ProbeUserdataError(f"vm id {vm_id!r} is not a vali vm id")
    if not re.fullmatch(r"[0-9a-f]{32}", run_id_hex):
        raise ProbeUserdataError("run_id must be 32 lower-case hex")
    if len(nonce) != 32:
        raise ProbeUserdataError("nonce must be 32 bytes")
    if not 0 <= start_delay_s <= MAX_START_DELAY_S:
        raise ProbeUserdataError(
            f"start_delay_s {start_delay_s} is outside [0, {MAX_START_DELAY_S}]"
        )
    if not slots or len(set(slots)) != len(slots) or not all(_SLOT_RE.fullmatch(s) for s in slots):
        raise ProbeUserdataError(f"targets {slots!r} are not distinct disk slots")
    targets = [
        {"slot": t.slot, "profile": t.profile} for t in (RequestTarget(s) for s in sorted(slots))
    ]
    return json.dumps(
        {
            "vm_id": vm_id,
            "run_id": run_id_hex,
            "nonce": nonce.hex(),
            "start_delay_s": start_delay_s,
            "targets": targets,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def render(request: str, *, netbird: bool) -> bytes:
    """The probe VM's cloud-config, carrying `request` (from
    `request_json`). With `netbird`, the tenant template's enrolment and
    purge lines (docs/operator/userdata-templates/netbird-enabled.yaml.example),
    unchanged: `{{NETBIRD_SETUP_KEY}}` / `{{NETBIRD_HOSTNAME}}` are
    substituted at launch."""
    json.loads(request)  # a request, never arbitrary YAML
    if "\n" in request:
        raise ProbeUserdataError("the request must be one line")
    lines = [
        "#cloud-config",
        "ssh_pwauth: false",
        "users: []",
        "write_files:",
        f"  - path: {REQUEST_PATH}",
        "    permissions: '0600'",
        "    owner: root:root",
        "    content: |",
        f"      {request}",
    ]
    if netbird:
        lines += [
            "  - path: /var/lib/cloud/seed/nocloud/netbird-setup-key",
            "    permissions: '0600'",
            "    owner: root:root",
            "    content: |",
            "      {{NETBIRD_SETUP_KEY}}",
        ]
    lines += [
        "runcmd:",
        # First, and independent of NetBird: see the module docstring.
        f"  - [ systemctl, start, --no-block, {PROBE_UNIT} ]",
    ]
    if netbird:
        lines += [
            "  - [ netbird, up,",
            "      --setup-key-file=/var/lib/cloud/seed/nocloud/netbird-setup-key,",
            "      --management-url=https://vpn.hippius.network,",
            "      --hostname={{NETBIRD_HOSTNAME}},",
            "      --no-browser ]",
            "  - [ systemd-run, --no-block, -pAfter=cloud-final.service, sh, -c, "
            '"cd /var/lib/cloud/instances && rm -f */user-data.txt* */cloud-config.txt '
            "*/obj.pkl ../seed/nocloud/netbird-setup-key /run/cloud-init/seed/user-data "
            '/run/cloud-init/combined-cloud-config.json" ]',
        ]
    return ("\n".join(lines) + "\n").encode("utf-8")
