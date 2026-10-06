# hippius-miner-agent

The agent that runs on a **miner host** — an untrusted bare-metal
EPYC SEV-SNP hypervisor that rents capacity to the Hippius compute
fleet. PR-MA-1 + MA-2: the crate skeleton, the self-generated miner
identity, and the UKI image fetch + §22 verification.

## Trust model — the miner is UNTRUSTED

By design, miners are untrusted
by design. The miner-agent therefore:

- **never** authenticates to the hippius-compute Vault — no lookup, no
  token, no AppRole;
- **self-generates** its persistent Ed25519 identity locally; the
  secret half never leaves the host and is never persisted anywhere
  off-box;
- has its **public** key registered out-of-band, by the operator, with
  vali — the pubkey is *pushed by the operator*, never *pulled from the
  miner*;
- authenticates miner→Edge traffic with the NetBird WireGuard mesh
  (transport) plus signed envelopes (application layer) — never with a
  Vault credential.

## Building

On a miner host (Linux x86_64, from the repository root):

```sh
cargo build --release --locked -p hippius-miner-agent --features snp
sudo install -m 0755 target/release/hippius-miner-agent /usr/local/bin/
```

**`--features snp` is mandatory for a production binary.** The default
feature set is empty so `cargo test --workspace` stays cross-platform;
a binary built without it answers every launch order with
`cvm-launch-digest/feature-disabled`. Play 05 of
`deploy/ansible/playbooks/06-miner-bootstrap.yml` builds it this way;
see [`docs/operator/onboarding-a-miner.md`](../../docs/operator/onboarding-a-miner.md)
for the full onboarding.

## What MA-1/2 ships

| Module | Status |
|---|---|
| `identity` | **done** — Ed25519 self-gen, persist (0400), load, sign |
| `image_cache` | **done** — fetch + §22-verify via the `miner-uki-fetch` library |
| `config` | **done** — TOML parse + validate |
| `error` | **done** — `&'static str`-Display fail-closed error type |
| `edge_client` | **skeleton** — `send_envelope` returns `not-yet-wired` (MA-3) |
| `lifecycle` | **skeleton** — libvirt CVM lifecycle (MA-3 / MA-5) |

MA-1/2 makes **no** network call to hippius-compute infrastructure.
Identity self-gen and image fetch/verify work fully in isolation.

> **Spec adaptations** (the prompt's code sketches were illustrative):
> the crate is **synchronous** — `miner-uki-fetch::fetch` is itself
> sync and the only async surface (the real Edge HTTP client) is MA-3;
> `image_cache` is a thin wrapper over `miner-uki-fetch::fetch` rather
> than an async re-implementation (that function already does cached
> fetch + always-verify + atomic install); the identity uses the
> workspace `zeroize` idiom (`secrecy` is not a workspace dependency);
> `HippiusS3ImageStore` is a stub (issue #80), so `image-fetch`
> against real Hippius S3 fails closed until that backend lands.

## CLI

```
hippius-miner-agent init-identity [--key-output P] [--pub-output P] [--print-pubkey] [--force]
hippius-miner-agent image-fetch  --hash H [--cache-dir D] [--output D] [--s3-endpoint U] [--s3-bucket B]
hippius-miner-agent serve        [--config /etc/hippius-miner/config.toml]
```

`init-identity` is idempotent — a second run is a no-op; `--force`
explicitly regenerates (destructive). `serve` is a skeleton in MA-1/2:
it loads + validates the config and the identity and wires the
components; the real order-intake loop is MA-3+.

## Operator onboarding

### 1. Generate the miner identity

On the miner host, first boot:

```
hippius-miner-agent init-identity --print-pubkey
```

This writes `/var/lib/hippius-miner/identity.key` (`0400`, secret) and
`/var/lib/hippius-miner/identity.pub` (`0444`) and prints the 64-hex
public key to stdout. Capture it:

```
MINER_PUBKEY=$(hippius-miner-agent init-identity --print-pubkey)
```

The secret key never leaves the host. To rotate, re-run with `--force`
(this is destructive — the old identity is gone).

### 2. Register the public key with vali

The operator registers `{miner_id, pubkey, platform_id}` with vali —
the pubkey is **pushed by the operator**, never pulled from the miner.

> The vali admin registration endpoint (`POST /v1/miner/register`)
> does not exist yet — tracked in **issue #110**. Until it lands,
> registration is a manual operator step recorded out-of-band.

### 3. Deploy the Edge mTLS certificate

The operator delivers the miner's Edge mTLS material **out-of-band**
(SSH copy — never via Vault):

```
scp edge-mtls.crt  miner:/var/lib/hippius-miner/edge-mtls.crt
scp edge-mtls.key  miner:/var/lib/hippius-miner/edge-mtls.key   # mode 0400
scp edge-ca.crt    miner:/var/lib/hippius-miner/edge-ca.crt
```

### 4. Join the NetBird mesh

Install the NetBird agent and join the mesh with a setup key carrying
the **`miner`** tag (the miner group's id `<miner-group-id>`). A `miner`-tagged
peer can reach only the Edge gateway endpoint — never the control
plane directly.

### 5. Enable the systemd unit

Install the config (`/etc/hippius-miner/config.toml`, see
`examples/miner-agent-config.toml.example`) and a unit such as:

```ini
[Unit]
Description=Hippius miner-agent
After=network-online.target netbird.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/hippius-miner-agent serve
Restart=on-failure
User=hippius-miner
StateDirectory=hippius-miner

[Install]
WantedBy=multi-user.target
```

Then `systemctl enable --now hippius-miner-agent`.

## Storage layout — putting tenant data on dedicated disks

By default **every** per-VM disk lives under `/var/lib/hippius-miner/`
(the OS root):

| Disk | Path | Notes |
|---|---|---|
| Root qcow2 (staged) | `image.staging_dir` (`…/staging/`) | configurable since MA-1 |
| Image cache | `image.cache_dir` (`…/images/`) | configurable since MA-1 |
| **Tenant `/data`** (`/dev/vde`) | `storage.data_disk_root` + `/data/<vm>.img` | **configurable** |
| State disk (`/dev/vdd`, 1 MiB) | `storage.state_disk_root` + `/state/<vm>.raw` | configurable |

The tenant **data disk** carries by far the heaviest host I/O: at first
boot the guest does a full `cryptsetup luksFormat --integrity` wipe of
the whole disk (writes a dm-integrity HMAC tag on every block). On a big
flavor that is tens of GiB of writes. If the data disks share the OS
root — especially a RAID-1 mirror, which doubles every write — that
contends with the OS and is slow.

### Point tenant data at a dedicated mount (`[storage]`)

Add a `[storage]` section to `config.toml` (omit it to keep the
historical `/var/lib/hippius-miner` defaults):

```toml
[storage]
# The `/data` disk lands at "<data_disk_root>/data/<vm_id>.img".
# Point this at a dedicated mount to keep tenant data off the OS root.
data_disk_root = "/mnt/hippius-data"
# The tiny 1 MiB state disk; rarely worth moving.
state_disk_root = "/var/lib/hippius-miner"
```

Both must be absolute paths; the agent appends the `data/` / `state/`
subdirectory and refuses to start on a relative path. Existing running
VMs keep their disks where they were launched (the libvirt XML pins the
old path); only **new** launches use the new root.

### Example: a redundant NVMe RAID-1 for tenant data

If the host has spare NVMe (e.g. two datacenter SSDs), give tenants a
dedicated, redundant pool. RAID-1 (mirror) survives a single-disk
failure; do this once, as root, with no tenant VM running on the old
location:

```bash
# 1. mirror the two spare NVMe (adjust device names via `lsblk`)
mdadm --create /dev/md/hippius-data --level=1 --raid-devices=2 \
      /dev/nvme2n1 /dev/nvme3n1
mkfs.ext4 -L hippius-data /dev/md/hippius-data

# 2. mount it where `[storage].data_disk_root` points, persist in fstab
mkdir -p /mnt/hippius-data
echo 'LABEL=hippius-data /mnt/hippius-data ext4 defaults,noatime 0 2' >> /etc/fstab
mount /mnt/hippius-data

# 3. persist the mdadm array so it re-assembles on boot
mdadm --detail --scan | grep hippius-data >> /etc/mdadm/mdadm.conf
update-initramfs -u

# 4. CRITICAL: the systemd unit runs ProtectSystem=strict, so the whole
#    filesystem is read-only to the agent EXCEPT its ReadWritePaths
#    (default /var/lib/hippius-miner). Grant the new mount, or every
#    launch fails `data-disk/mkdir`:
mkdir -p /etc/systemd/system/hippius-miner-agent.service.d
cat > /etc/systemd/system/hippius-miner-agent.service.d/storage.conf <<'EOF'
[Service]
ReadWritePaths=/mnt/hippius-data
EOF
systemctl daemon-reload

# 5. set data_disk_root = "/mnt/hippius-data" in config.toml, then
systemctl restart hippius-miner-agent
```

The agent then creates `/mnt/hippius-data/data/<vm>.img` per tenant.
(Verified live: an 8 GiB `small`-flavor data disk landed at
`/mnt/hippius-data/data/<vm>.img`, not on the OS root.)

**Declare the capacity so the agent can defend it.** Once the pool is
mounted, set `[host].cvm_disk_gb_budget` to the pool's real free GiB
(e.g. the mirror's usable size). Two checks then keep an over-committed
host from accepting a placement it cannot honour:

1. **Budget reservation** (`check_capacity`, concurrency-safe): each
   live VM's `data_disk_size_gb` is charged against the budget. A launch
   whose sum would exceed `cvm_disk_gb_budget` is refused **before** the
   disk is created, so vali can re-place onto another miner. This catches
   the race two sparse creates would otherwise slip through.
2. **statvfs backstop** (`ensure_data_disk`, per-create): the backing
   mount's *physical* free space is checked before the sparse file is
   made. Physical free space cannot be faked, so a miner that declared a
   budget larger than its real disk still fails closed here rather than
   stalling a live guest mid-wipe with ENOSPC.

Leave `cvm_disk_gb_budget` at `0` (or omit it) to disable only the
reservation — the statvfs backstop always runs.

**Security is location-independent.** The `/data` disk is
`luksFormat`ed fresh with a **guest-held key, generated inside the
SEV-SNP boundary** (`lifecycle/data_disk.rs`); the host only ever sees
ciphertext, wherever the image file sits. Moving the disk changes
nothing about confidentiality, integrity, or the launch measurement
(disk paths are not folded into the SNP digest).

**Performance.** The data disk is rendered with `cache='writeback'`
(every other disk is `cache='none'`) so the host page cache absorbs the
first-boot wipe and flushes async — benchmarked ~2.7× faster than
O_DIRECT on a live miner. A dedicated, non-mirrored-contended NVMe mount
compounds that win.

## Follow-ups

- **§MA phase 2 (issue #109)** — MA-3 (libvirt SEV-SNP CVM launch +
  the real Edge mTLS client), MA-4 (vsock relay guest ↔ Edge), MA-5
  (lifecycle command handler), MA-6 (telemetry + heartbeats to vali),
  MA-7 (mTLS cert rotation on SIGHUP).
- **vali admin API (issue #110)** — `POST /v1/miner/register` for the
  self-generated miner pubkey.
- **Hippius S3 image backend (issue #80)** — the `HippiusS3ImageStore`
  stub `image-fetch` currently fails closed against.
