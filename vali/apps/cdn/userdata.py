"""The user-data of a CDN node's launch (CDN plan V2).

It carries no software, only the two things the measured image cannot know:

- `/run/hippius/cdn-node.json` — the node identity the cdn-agent reads
  (`binaries/cdn-agent/src/config.rs` `RawNodeIdentity`, a closed field set:
  `node_id`, `region`, `backend_url`, nothing else);
- the NetBird enrolment, as every tenant's (`{{NETBIRD_SETUP_KEY}}` /
  `{{NETBIRD_HOSTNAME}}`, substituted at launch), then the purge of the
  setup key and of cloud-init's copies.

The tenant template's public-IP inbound unit is NOT here: the cdn-node image
bakes its own guard (80/443 only, `scripts/cdn-node/install-cdn-node.sh`)
and masks the tenant one. No user, no SSH key: the image has no sshd.

The user-data rides the KBS release to the attested guest like any tenant's;
it is also what the §6 digest binds, so it is rendered once per node and
must stay byte-stable across the node's relaunches (`render` is pure).
"""

from __future__ import annotations

import json
import re

_REGION_RE = re.compile(r"[A-Z]{2}")
_NODE_ID_RE = re.compile(r"[a-z0-9-]{1,64}")


class CdnUserdataError(Exception):
    pass


def backend_url() -> str:
    """`VALI_CDN_BACKEND_URL` — the same bare https origin the cdn-node bake
    writes into the measured agent config (the agent refuses two that
    differ)."""
    from apps.common.cdn import cdn_backend_url

    url = cdn_backend_url()
    if not url:
        raise CdnUserdataError(
            "VALI_CDN_BACKEND_URL must be a bare https origin (no path, no trailing slash)"
        )
    return url


def node_identity_json(node_id: str, region: str, url: str) -> str:
    if not _NODE_ID_RE.fullmatch(node_id):
        raise CdnUserdataError(f"node id {node_id!r} is not a vali vm id")
    if not _REGION_RE.fullmatch(region):
        raise CdnUserdataError(f"region {region!r} is not upper-case alpha-2")
    return json.dumps(
        {"node_id": node_id, "region": region, "backend_url": url},
        separators=(",", ":"),
        sort_keys=True,
    )


def render(node_id: str, region: str) -> bytes:
    """The cloud-config of node `node_id` in `region`."""
    identity = node_identity_json(node_id, region, backend_url())
    lines = [
        "#cloud-config",
        "# Hippius CDN node. Software is in the measured image; this only names",
        "# the node and enrols it in the NetBird mesh.",
        "ssh_pwauth: false",
        "users: []",
        "write_files:",
        "  - path: /run/hippius/cdn-node.json",
        "    permissions: '0644'",
        "    owner: root:root",
        "    content: |",
        f"      {identity}",
        "  - path: /var/lib/cloud/seed/nocloud/netbird-setup-key",
        "    permissions: '0600'",
        "    owner: root:root",
        "    content: |",
        "      {{NETBIRD_SETUP_KEY}}",
        "runcmd:",
        "  - [ netbird, up,",
        "      --setup-key-file=/var/lib/cloud/seed/nocloud/netbird-setup-key,",
        "      --management-url=https://vpn.hippius.network,",
        "      --hostname={{NETBIRD_HOSTNAME}},",
        "      --no-browser ]",
        # The tenant template's last line, unchanged (see
        # docs/operator/userdata-templates/netbird-enabled.yaml.example).
        "  - [ systemd-run, --no-block, -pAfter=cloud-final.service, sh, -c, "
        '"cd /var/lib/cloud/instances && rm -f */user-data.txt* */cloud-config.txt '
        "*/obj.pkl ../seed/nocloud/netbird-setup-key /run/cloud-init/seed/user-data "
        '/run/cloud-init/combined-cloud-config.json" ]',
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")
