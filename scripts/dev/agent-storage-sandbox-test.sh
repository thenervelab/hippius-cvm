#!/usr/bin/env bash
# The agent's storage checks UNDER THE AGENT UNIT'S REAL SANDBOX
# (PrivateDevices, ProtectSystem=strict, …, as the Ansible play renders it):
# a pool bind-mounted at /var/lib/hippius-miner/pools/<id> is usable, one
# elsewhere is refused, the same pool without the writable path reads
# read-only, a dedicated disk is judged from the collector's facts, and
# the sandbox really hides /dev/disk. Needs root (sudo -n) and systemd;
# skips cleanly without them.
#
#   scripts/dev/agent-storage-sandbox-test.sh <path to hippius-miner-agent>
set -euo pipefail

BIN="${1:?usage: $0 <hippius-miner-agent binary>}"
if ! command -v systemd-run >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
    echo "agent-storage-sandbox-test: SKIP (needs systemd-run and passwordless sudo)"
    # CI sets it: a runner that cannot run the test must not pass it.
    [[ "${AGENT_SANDBOX_TEST_REQUIRED:-0}" == 1 ]] && exit 1
    exit 0
fi

# It writes (and removes) files at the agent's real paths: never on a miner.
if [[ -e /etc/hippius-miner/config.toml || -e /var/lib/hippius-miner/identity.key ]]; then
    echo "agent-storage-sandbox-test: REFUSED — this host runs a miner agent" >&2
    exit 1
fi

AGENT=/usr/local/bin/hippius-miner-agent-sbxtest
WORK=/var/lib/hippius-miner-sbxtest   # not /tmp, /root: private / hidden in the sandbox
POOL=/var/lib/hippius-miner/pools/nvme0
fail=0
err() { echo "FAIL: $*" >&2; fail=1; }
ok() { echo "ok   $*"; }

cleanup() {
    sudo umount "${POOL}" 2>/dev/null || true
    sudo rm -f "${WORK}/pool.img" "${WORK}/config.toml" "${WORK}/facts.json" "${AGENT}" \
        /etc/hippius-miner/candidate.toml /root/sbxtest-candidate.toml /run/hippius-miner/disk-facts.json
    sudo rmdir /etc/hippius-miner /run/hippius-miner 2>/dev/null || true
    sudo rmdir "${WORK}/hdd0" "${WORK}" "${POOL}" 2>/dev/null || true
    sudo rmdir /var/lib/hippius-miner/pools /var/lib/hippius-miner 2>/dev/null || true
}
trap cleanup EXIT

sudo install -m 0755 "${BIN}" "${AGENT}"
sudo mkdir -p "${WORK}" "${POOL}" "${WORK}/hdd0"
# A real ext4 filesystem, larger than the 20 GiB reserve (sparse).
sudo truncate -s 30G "${WORK}/pool.img"
sudo mkfs.ext4 -q -F "${WORK}/pool.img"
sudo mount -o loop "${WORK}/pool.img" "${POOL}"

# The identity the agent must find inside the sandbox: udev's ID_FS_UUID for
# the loop device. Without it the agent falls back to `dev:` — exactly the
# original regression — so when udev knows the UUID, `uuid:` is required.
sudo udevadm settle 2>/dev/null || true
majmin="$(findmnt -no MAJ:MIN "${POOL}" | tr -d ' ')"
UDEV_UUID="$(sed -n 's/^E:ID_FS_UUID=//p' "/run/udev/data/b${majmin}" 2>/dev/null || true)"
if [[ -n "${UDEV_UUID}" ]]; then
    echo "udev has ID_FS_UUID=${UDEV_UUID} for ${majmin}: requiring a uuid: identity"
else
    echo "udev has not processed ${majmin}: accepting a dev: identity"
fi
export UDEV_UUID

sudo tee "${WORK}/config.toml" >/dev/null <<TOML
[miner]
miner_id = "sbx-test"

[edge]
endpoint = "https://edge.example.invalid:443"
client_cert = "/var/lib/hippius-miner/edge-mtls.crt"
client_key = "/var/lib/hippius-miner/edge-mtls.key"
ca_cert = "/var/lib/hippius-miner/edge-ca.crt"
order_signing_pubkey = "1111111111111111111111111111111111111111111111111111111111111111"

[identity]
key_path = "/var/lib/hippius-miner/identity.key"
pub_path = "/var/lib/hippius-miner/identity.pub"

[image]
cache_dir = "/var/lib/hippius-miner/images"
staging_dir = "/var/lib/hippius-miner/staging"
s3_endpoint = "https://s3.example.invalid"
s3_bucket = "test"

[orders]
bind_addr = "100.64.0.10:9700"

[host]
cvm_cpu_budget = 2
cvm_memory_mb_budget = 4096
cvm_disk_gb_budget = 10

[[storage.pools]]
id = "default"
path = "/var/lib/hippius-miner"
class = "nvme"
budget_gb = 10

[[storage.pools]]
id = "hdd0"
path = "${WORK}/hdd0"
class = "hdd"
budget_gb = 1

[[storage.pools]]
id = "nvme0"
path = "${POOL}"
class = "nvme"
budget_gb = 1

[[storage.dedicated_disks]]
id = "wwn-0x5000c500deadbeef"
TOML

# The collector, outside the sandbox (it reads devices).
sudo "${AGENT}" storage-collect --out "${WORK}/facts.json"

props=(-p ProtectSystem=strict -p ProtectHome=true -p PrivateTmp=true
       -p PrivateDevices=true -p NoNewPrivileges=true
       -p ProtectKernelTunables=true -p ProtectControlGroups=true)
check() {
    sudo systemd-run --quiet --wait --pipe --collect "${props[@]}" "$@" \
        "${AGENT}" storage-check --config "${WORK}/config.toml" --facts "${WORK}/facts.json"
}

# What the agent sees: its unit's ReadWritePaths.
out="$(check -p ReadWritePaths=/var/lib/hippius-miner)"
echo "${out}"
python3 - "${out}" <<'PY' || fail=1
import json, os, sys
r = json.loads(sys.argv[1])
pools = {p["id"]: p for p in r["pools"]}
bad = []
if r["storage_error"] is not None: bad.append(f"storage_error {r['storage_error']}")
if pools["nvme0"]["state"] != "active": bad.append(f"nvme0 {pools['nvme0']}")
identity = pools["nvme0"]["fs_identity"] or ""
uuid = os.environ.get("UDEV_UUID", "")
if uuid:
    if not identity.startswith(f"uuid:{uuid}"): bad.append(f"nvme0 identity {identity!r}, udev has {uuid}")
elif not identity.startswith(("uuid:", "dev:")): bad.append(f"nvme0 identity {identity!r}")
if pools["hdd0"]["error"] != "pool-outside-pools-root": bad.append(f"hdd0 {pools['hdd0']}")
if pools["default"]["state"] != "active": bad.append(f"default {pools['default']}")
disk = r["dedicated_disks"][0]
if disk["error"] != "disk-not-found": bad.append(f"disk {disk}")
if r["disk_facts_error"] is not None: bad.append(f"facts {r['disk_facts_error']}")
for b in bad: print("FAIL:", b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
[[ ${fail} -eq 0 ]] && ok "in the agent's sandbox: nvme0 active, hdd0 outside the pools root, the disk judged from facts"

# The same pool without the writable path: read-only, named as such.
out="$(check -p ReadWritePaths="${WORK}")"
if python3 - "${out}" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
pools = {p["id"]: p for p in r["pools"]}
sys.exit(0 if pools["nvme0"]["error"] == "pool-path-read-only" else 1)
PY
then
    ok "outside ReadWritePaths: pool-path-read-only"
else
    err "nvme0 not reported read-only: ${out}"
fi

# The operator doc's own commands (onboarding-a-miner.md): the candidate in
# /etc/hippius-miner, the facts at the default /run/hippius-miner path. And
# the trap the doc warns about: a config under /root reads as missing.
sudo mkdir -p /etc/hippius-miner /run/hippius-miner
sudo cp "${WORK}/config.toml" /etc/hippius-miner/candidate.toml
sudo cp "${WORK}/config.toml" /root/sbxtest-candidate.toml
sudo "${AGENT}" storage-collect --out /run/hippius-miner/disk-facts.json
if out="$(sudo systemd-run --quiet --wait --pipe --collect "${props[@]}" \
    -p ReadWritePaths=/var/lib/hippius-miner \
    "${AGENT}" storage-check --config /etc/hippius-miner/candidate.toml)" \
    && python3 -c 'import json,sys; r=json.loads(sys.argv[1]); sys.exit(r["storage_error"] is not None or r["disk_facts_error"] is not None)' "${out}"; then
    ok "the doc's storage-check command works as written"
else
    err "the doc's storage-check command failed: ${out:-}"
fi
if sudo systemd-run --quiet --wait --pipe --collect "${props[@]}" \
    "${AGENT}" storage-check --config /root/sbxtest-candidate.toml >/dev/null 2>&1; then
    err "a config under /root was readable in the sandbox (the doc says it is not)"
else
    ok "a config under /root is hidden by the sandbox"
fi

# The sandbox is real: no /dev/disk, no block device.
if sudo systemd-run --quiet --wait --pipe --collect "${props[@]}" /bin/sh -c \
    'test ! -e /dev/disk && ! ls /dev | grep -qE "^(sd|vd|nvme|loop)"'; then
    ok "the sandbox hides /dev/disk and every block device"
else
    err "the sandbox shows block devices"
fi

if [[ ${fail} -ne 0 ]]; then
    echo "agent-storage-sandbox-test: FAILED" >&2
    exit 1
fi
echo "agent-storage-sandbox-test: all passed"
