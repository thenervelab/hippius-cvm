# Onboarding a miner

How a third party brings a SEV-SNP host onto a Hippius compute fleet.

> **External operator?** See
> [`external-miner-guide.md`](./external-miner-guide.md) for the
> dashboard-driven path, step by step. This page is the full reference.

Admission is **permissionless**: there is no operator-issued client
certificate and no approval queue. The agent generates its own Ed25519
identity, presents a **self-signed** TLS client certificate whose
private key *is* that identity, and the Edge gateway admits the
connection if and only if the node id is registered and `active` on
chain. The chain is the gate.

```
  provision the host          the agent mints its own identity
  (Ansible, 8 plays)   ───▶   /var/lib/hippius-miner/identity.{key,pub}
                                          │
                              node_id = 64-hex Ed25519 public key
                                          │
                              register that node_id on chain
                              (pallet ComputeScoring::register_child)
                                          │
                              Edge re-reads the signed registry feed
                              every EDGE_REGISTRY_REFRESH_SECS (30 s)
                                          │
                                     ▼ admitted
```

Nothing in that path requires the fleet operator to hand you a secret.
What they *do* have to hand you is listed under
[What you cannot self-supply](#what-you-cannot-self-supply) — read that
section before buying hardware.

---

## 0. Before you buy the machine

The preflight play is fail-closed on all of this, so a host that misses
any of it will refuse to bootstrap rather than half-work.

| Requirement | Enforced by |
|---|---|
| **AMD EPYC with SEV-SNP** (x86_64) | `06-miner-bootstrap.yml` play 00 asserts `ansible_architecture == x86_64` and `AMD` in `ansible_processor` |
| **SEV-SNP enabled in firmware** — "SEV Control" **and** "SNP Memory (RMP Table) Coverage" | play 01 asserts `/sys/module/kvm_amd/parameters/sev_snp == Y` after reboot |
| **Ubuntu 26.04** (or 25.10, end of life) — a release whose distro libvirt >= 10.5 and QEMU >= 9.1 can boot an SNP guest. **Not 24.04** (libvirt 10.0 / QEMU 8.2): upgrade it in place first | play 00 asserts the release is in `miner_supported_ubuntu_versions` AND that the libvirt/QEMU apt resolves to meet the minimum; play 02 re-checks the installed versions |
| **No CPU offlined at runtime.** SMT may stay on. To run without it, disable it in the BIOS (AMD CBS > CPU Common Options > CCD/Core/Thread Enablement > SMT Control = Disable), never with `nosmt`, `maxcpus=`, `smt/control` or a unit that offlines CPUs: the firmware then refuses `SNP_DF_FLUSH` (error `0xe`) and the host stops launching VMs after ~99 launches since boot | play 01 removes `hippius-smt-off.service` if present and asserts no present CPU is offline once SEV-SNP is on; with `miner_heartbeat_schema_host_health: true` (off by default until the fleet's agents know the key; renders `[heartbeat] schema_host_health = true`) the v5 heartbeat reports the same count as `cpus_offline` (alert `MinerSnpCpusOffline`) |
| **Kernel ≥ 6.11** (`linux-generic-hwe-*` if the GA kernel is older) | play 00 |
| **NVMe storage** recommended, unpartitioned if you dedicate disks to tenant data (a host with only a system disk works: leave `nvme_*` empty — but a rotational disk makes first boot slow, see the Milan row below) | play 00 asserts every `nvme_data_devices` entry is a block device carrying no partition table and no signature other than `crypto_LUKS` |
| **Outbound internet** + inbound `22/tcp` and `51820/udp` | play 07 configures UFW to allow exactly those, plus everything on the mesh interface `wt0` |

Get the firmware settings confirmed **in writing by the datacentre
before you pay**. A machine with SEV-SNP fused off or firmware-disabled
is not recoverable remotely and is the single most common way this goes
wrong.

If you do have in-band access to the management controller, you can set
it yourself. On a Dell (racadm) it is `Sme`, `Snp`, `CpuMinSevAsid` and
`Rmp` under `BIOS.ProcSettings`, in three BIOS jobs because each
attribute unlocks only once its parent is applied — see "Enabling
SEV-SNP on a Dell (racadm)" in
[`deploy/ansible/README.md`](../../deploy/ansible/README.md). Other
vendors name them "SEV Control", "SNP", "SEV-ES ASID space limit" and
"SNP Memory (RMP Table) Coverage".

On a rented server whose management controller you cannot reach and
whose provider exposes no BIOS-settings API, a serial-over-LAN console
(if the provider offers one) usually reaches the firmware setup screen.
On AMI Aptio boards the settings are under Chipset → AMD CBS → CPU
Common Options: set "SEV-ES ASID Space Limit" to `100` and "SNP Memory
(RMP Table) Coverage" to `Enabled`, one reboot. A host delivered with
SEV on but SEV-ES/SNP off logs `Memory for the RMP table has not been
reserved by BIOS` in `dmesg`. Some provider images also put `iommu=pt`
on the kernel command line; play 01 removes it.

### AMD generations

| Generation | SNP report | Notes |
|---|---|---|
| **Genoa** (EPYC 9004, Zen 4) | V2, 64-byte chip_id | supported |
| **Turin** (EPYC 9005, Zen 5) | V3/V4, 8-byte HWID | supported |
| **Milan** (EPYC 7003, Zen 3) | 64-byte chip_id, like Genoa | supported. Register it with `"snp_generation": "milan"` (§6) — its chip_id length equals Genoa's, so without it vali measures the guest as Genoa and refuses the launch. Its host-attestor measurement is `miner_host_attestor.measurements.milan`. A host on a rotational disk boots golden VMs noticeably slower than an NVMe host (minutes rather than a few minutes); keep tenant data on NVMe. |

Kernel cmdline the bootstrap will set for you (play 01):
`kvm_amd.sev=1 kvm_amd.sev_es=1 kvm_amd.sev_snp=1 mem_encrypt=on`, and
it strips `iommu=pt` — SEV-SNP requires the IOMMU *not* in passthrough
mode.

---

## 1. Provision the host

Miners are **not** part of `deploy/ansible/playbooks/site.yml` — that
one targets the control-plane group. Miners have their own playbook:

```sh
cd deploy/ansible
ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml --limit <YOUR_HOST>
```

Add your host to the `miner_nodes` group in `inventory.yml` and give it
a `host_vars/<YOUR_HOST>.yml`. The eight plays, in order:

| # | Play | What it does |
|---|---|---|
| 00 | Miner preflight | Read-only fail-closed asserts (§0 above). Also asserts that no Vault address/token is defined for a miner and that k3s is absent — a miner is not a control-plane node. |
| 01 | SEV-SNP kernel cmdline | Edits `/etc/default/grub`, `update-grub`, reboots **only if the line changed**, re-asserts `sev_snp == Y`. |
| 02 | libvirt + qemu install | `libvirt-daemon-system`, `libvirt-clients`, `qemu-system-x86`, `qemu-utils`, `ovmf`, `virtinst`; enables `libvirtd`. Distro versions, deliberately unpinned. **Also stages the TENANT OVMF** (`miner_tenant_ovmf_*`) and refuses to continue unless the file on disk matches the pinned digest — see below. |
| 03 | Tenant CVM networking bridge | Enables libvirt's `default` NAT network for tenant virtio-net. |
| 04 | NetBird agent | Installs and joins the mesh with your setup key; asserts the assigned address is inside `100.64.0.0/10`. |
| 05 | miner-agent install + identity self-gen | Installs the release `hippius-miner-agent`, verified like an auto-update, unless one reporting `versions.miner_agent` is already in place (or builds it with `miner_agent_build_from_source: true`), refuses any `<…>` placeholder left in the variables, renders `/etc/hippius-miner/config.toml`, runs `init-identity`, reads the AMD CHIP_ID, prints the registration block, installs the systemd unit **without starting it**. |
| 06 | mTLS cert mount point | Creates `/var/lib/hippius-miner/mtls` (0700) and installs the Edge **server** CA so the agent can verify the Edge. In permissionless mode nothing else is placed here. |
| 07 | Host firewall | UFW default-deny inbound; allow `22/tcp`, `51820/udp`, and all traffic on `wt0`. |

> **`--features snp` is load-bearing.** The agent must be built with it
> or every launch order fail-closes with
> `cvm-launch-digest/feature-disabled`. The release binary is; if you
> build the binary yourself, do not omit it.

> **Play 05 installs the release binary itself.** Nothing to do on the
> host ([Prebuilt binary](#prebuilt-binary)). Set
> `miner_agent_build_from_source: true` in host_vars to have play 05
> clone `miner_agent_source_repo` and build on the host instead.

### Prebuilt binary

Each public release of
[`thenervelab/hippius-cvm`](https://github.com/thenervelab/hippius-cvm/releases)
attaches a `hippius-miner-agent-x86_64-linux-gnu` built from the tagged
commit with `--features snp`, with `SHA256SUMS`, `BUILD-INFO.txt`
(toolchain, commit, build host) and, from the first release cut by
`.github/workflows/miner-agent-release.yml` on, its attestation
`hippius-miner-agent-x86_64-linux-gnu.sigstore.json`. It links glibc ≥ 2.39 and
`libcrypto.so.3`, both present on Ubuntu 26.04.

When `/usr/local/bin/hippius-miner-agent` is missing, or its `--version`
does not report `versions.miner_agent` (`group_vars/miner_nodes.yml`),
play 05 installs the release with `hippius-miner-update --install`: the
auto-updater's own code, with the same choice of release and the same
checks ([4b. Auto-update](#4b-auto-update)):

- the newest complete release that has been out for
  `miner_auto_update_min_release_age_h` (24 h), never one that failed its
  health check on this host, never older than a recorded
  `/var/lib/hippius-miner/installed-release`;
- the binary matches `SHA256SUMS`, its build-provenance attestation
  verifies with cosign for the release workflow of
  `thenervelab/hippius-cvm` at that exact tag, and its `--version` names
  the tag.

It needs outbound HTTPS to `api.github.com` and `github.com`. A binary
already reporting `versions.miner_agent` is left as it is, so re-running
the play on a running miner changes nothing; a foreign one is replaced,
by that verified download only. The agent is never started, stopped or
signalled. If the release cannot be installed, the play stops with
`[MINER_AGENT_INSTALL_FAILED]` and the updater's reason
(`journalctl -t hippius-miner-update` has the whole run); the binary is
replaced only once every check has passed, and a re-run tries again.
`--check` previews the install and ends play 05 there for that host: the
rest of play 05 runs the binary. Once installed,
[auto-update](#4b-auto-update) keeps it current.

**By hand (fallback).** To install the binary yourself (to pick the
release, or when the play's install keeps failing), put it in place
before play 05; the play then leaves it alone:

```sh
TAG=<release tag>
base=https://github.com/thenervelab/hippius-cvm/releases/download/$TAG
curl -fLO "$base/hippius-miner-agent-x86_64-linux-gnu"
curl -fLO "$base/SHA256SUMS"
sha256sum -c SHA256SUMS          # must print: hippius-miner-agent-x86_64-linux-gnu: OK
sudo install -m 0755 -o root -g root hippius-miner-agent-x86_64-linux-gnu \
  /usr/local/bin/hippius-miner-agent
/usr/local/bin/hippius-miner-agent --version
```

A checksum only proves the download matches the release; check its
build-provenance attestation too, as in
[Verifying a release by hand](#verifying-a-release-by-hand).

### Variables you must supply

Per host, in `host_vars/<YOUR_HOST>.yml`:

`ansible_host`, `ansible_user`, `ansible_ssh_private_key_file`,
`cpu_model_expected`, `ram_gb_expected`, `nvme_system_devices`,
`nvme_data_devices`, `netbird_setup_key_file`.

The tenant CPU / RAM budget (`[host] cvm_*_budget`) is NOT per-host input:
the template derives it from the host's own facts, `(threads − 2) ×
cpu_ratio` vCPU and `MemTotal − 8192` MiB (group_vars `host_cvm`). To run
a box BELOW that, set `host_cvm_overrides: {cpu_budget_max: N,
memory_mb_budget_max: M}`; a value above the derivation is ignored.

Not on the list: `orders_bind_ip`, this miner's **own** mesh address,
which the agent's signed-order server binds (and only it). NetBird assigns
it at mesh join; play 04 reads it from `netbird status`, checks that the
`wt0` interface carries it, and the config uses that. A failed or partial
join stops play 04 instead of binding a placeholder. Set `orders_bind_ip`
in host_vars only to render the config in a run that skips play 04, and
only to the address `netbird status` shows; a run that renders the config
with neither refuses.

Do **not** set `miner_id` on a new host: it is derived from the node id
(see [Your `miner_id`](#your-miner_id)).

This list is the required minimum, not the whole surface — the
`host_vars/` directory documents further optional keys (data RAID,
private-network bonding) that only some hosts need.

A complete minimal `host_vars/<YOUR_HOST>.yml`, values to replace in
angle brackets (`host_vars/miner.example.yml` is the same file, commented):

```yaml
ansible_host: <PUBLIC_IP>
ansible_user: ubuntu
ansible_ssh_private_key_file: ~/.ssh/id_ed25519
cpu_model_expected: "<exact string from /proc/cpuinfo, e.g. AMD EPYC 7543 32-Core Processor>"
ram_gb_expected: <GB, assert is ">=">
# Name disks by /dev/disk/by-id (`ls -l /dev/disk/by-id | grep nvme`):
# the kernel's nvmeXn1 names move between boots.
nvme_system_devices:
  - /dev/disk/by-id/nvme-<MODEL>_<SERIAL-A>
  - /dev/disk/by-id/nvme-<MODEL>_<SERIAL-B>
nvme_data_devices: []                               # or the dedicated data NVMe(s), also by-id
netbird_setup_key_file: "netbird-<host>-setupkey"   # on the operator workstation, never committed
snp_generation: genoa                               # genoa | turin | milan
```

Then add `<YOUR_HOST>: {}` under `miner_nodes` in `inventory.yml`
(start from `inventory.example.yml`; keep your real inventory out of
version control).

Fleet-wide, in `group_vars/miner_nodes.yml` — these all point at the
fleet operator's infrastructure and must be **your fleet's** values, not
copied from an example:

| Variable | What it is |
|---|---|
| `network.edge_endpoint` | `host:443` of the Edge gateway you connect to |
| `network.netbird_management_url` | the NetBird control plane that issued your setup key |
| `network.netbird_group` | the NetBird group id miners join |
| `miner_kbs_endpoint` | the KBS the guests attest to |
| `miner_vali_lifecycle_url` | the lifecycle relay address |
| `edge_order_signing_pubkey` | 64-hex Ed25519 key; the agent `verify_strict`s **every** lifecycle order against it |
| `image.s3_endpoint` / `image.s3_bucket` | where published UKIs live |
| `miner_tenant_ovmf_url` / `_sha256` | the firmware every tenant CVM boots. **Not** the distro `ovmf` package — this exact image is folded into the SNP launch measurement, and the validator recomputes against the copy it pins. A different build measures differently, so the KBS refuses every release on your host. Fetched and digest-verified by play 02; a host without it answers every launch `tenant-preflight/ovmf-missing`. |
| `miner_kbs_ca_cert_file` / `_src` | CA the agent trusts when dialling the KBS to relay a guest's §21 release. The KBS serves a private certificate by default (internal service on the mesh, not a public ACME endpoint). Leave `_file` empty only for a publicly-trusted KBS certificate. `_src` defaults to the checkout's `miner-tasks/files/kbs-ca.crt`; without it the play downloads `miner_kbs_ca.url`. Either way it must hash to `miner_kbs_ca.sha256`. |
| `miner_edge_ca` / `miner_kbs_ca` / `miner_host_attestor.*_url` | public URL + sha256 pin of each file the play places without building it: the two CA certificates and the host-attestor kernel, initrd and OVMF (`miner-tasks/pinned-file.yml`). A file already on the host that hashes right is kept. |
| `miner_agent_source_repo` | with `miner_agent_build_from_source: true` only: the git repository play 05 clones and **builds the agent from**. A code-delivery path, not a link — whatever is here is what runs on your confidential host. The play refuses to run on an unfilled placeholder. |

Play 05 refuses any of these still set to a `<…>` placeholder
(`[PLACEHOLDER_VALUE]`, naming the config key or the variable) before it
renders the agent config: rendered as is, the agent would only refuse it
at its first start, after the play had finished green.

> **Auto-update is on by default.** The host installs each new agent
> release by itself once it is a day old and verified. See
> [Auto-update](#4b-auto-update) for how it decides, and how to turn it off.

---

## 2. The agent mints its own identity

Play 05 already ran this; you only need it by hand on a host you
provisioned some other way:

```sh
hippius-miner-agent init-identity --print-pubkey
```

It writes, atomically and refusing to overwrite an existing key:

| Path | Mode | Contents |
|---|---|---|
| `/var/lib/hippius-miner/identity.key` | `0400` | 64-hex of the 32-byte Ed25519 **seed** — the machine's whole identity |
| `/var/lib/hippius-miner/identity.pub` | `0444` | 64-hex of the 32-byte public key |

**`node_id` is that public key**, as 64 lowercase hex characters, no
`0x`, no whitespace. It is the only name the chain, the Edge and vali
know your machine by.

When the agent talks to the Edge it mints, *in memory and never on
disk*, a self-signed client certificate:

- private key = the Ed25519 identity above;
- SAN `URI:hippius-node:<node_id>`;
- EKU `clientAuth`; subject `CN=hippius-node-<first 16 hex of node_id>`.

The Edge does not check a CA chain for this certificate. It checks that
the certificate's public key **is** the node id in the SAN (a
certificate carrying more than one URI SAN is rejected outright), and
then that the node id is on chain. Possession of the key is the
credential.

### Your `miner_id`

vali also knows the miner by a `miner_id`, carried in every signed
heartbeat. It is one namespace shared by every miner, so you do not
choose it — it is derived from the node id:

```
miner_id = "m-" + <first 16 hex chars of node_id, lowercase>
```

For a node id `0123456789abcdef…` that is `m-0123456789abcdef`. The
console declares the same value to vali, and the bootstrap prints it
with the registration block. Play 05 reads `identity.pub` after
`init-identity`, computes the id and renders it into
`/etc/hippius-miner/config.toml`; it fails if `identity.pub` is missing
or is not 64 hex chars.

**Override — existing miners only.** A miner registered in vali before
this rule keeps the id it was registered under: set it in its
`host_vars/<YOUR_HOST>.yml`, where it always wins over the derivation:

```yaml
miner_id: "<THE_ID_VALI_ALREADY_HAS>"
```

Never change, or remove, the `miner_id` of a registered miner: vali
binds its identity, telemetry and placements to that id, and a miner
heart-beating under a new id is a different, unregistered miner. New
miners leave `miner_id` unset.

### Back up `identity.key`

Losing it means the chain still lists a node id your machine can no
longer prove, and re-registering a new node id costs a fresh
registration (and, past your family's free slot, a fresh deposit). Copy
it somewhere offline. Do not copy it onto a second host — two machines
presenting one identity is a fault, not a failover.

---

## 3. Register the node id on chain

Two ways. **From the console** (Dashboard → Compute miners): phase A,
before §1, picks the family and child accounts, mints your NetBird setup
key and gives you a prefilled `host_vars`; phase B, after §2, takes the
JSON block play 05 prints plus the output of `hippius-miner-agent
sign-registration`, has the FAMILY account sign one transaction in your
wallet (`add_proxy` → `register_child` → `remove_proxy`, atomic), and
declares the miner to vali for you (§6 becomes automatic). The family
key never leaves your wallet; a Polkadot Vault account attached to the
polkadot.js extension works the same way. What follows is the manual
equivalent.

Registration is a raw extrinsic.

**You need a registered, funded `family` account.** The extrinsic is
`ComputeScoring::register_child(family, child, node_id, node_sig)` and
it requires `ensure_signed(origin) == family` and
`is_registered_family(family)`. You register it yourself, as an Arion
storage miner — see below.

### What makes an account a family

On mainnet `is_registered_family(family)` is
`pallet_registration::is_owner_node_registered(family)`: the account
must own a registered node in `pallet_registration` — i.e. it is already
a storage-miner (arion) family. Any such account you control qualifies;
there is no separate "register a compute family" extrinsic. A brand-new
account cannot be a family until it registers a node there first: an
Arion storage miner, registered from the providers dashboard
(provider.hippius.com):

1. the dashboard builds the `register_node_with_coldkey` challenge for
   the storage node;
2. you run `hippius-miner-agent sign-coldkey-registration` on the
   storage host, which signs it with the Arion node key (`keypair.bin`),
   offline;
3. you paste its JSON output back into the dashboard;
4. the dashboard submits `register_node_with_coldkey`, signed by the
   owner account from your wallet.

The owner (the future family) must be your Bittensor subnet 75
**hotkey**, registered on the subnet as a **miner** UID; the chain
refuses any other account. The command and its checks are described in
[the external miner guide](external-miner-guide.md#signing-the-storage-registration-on-the-storage-host).
Hippius never registers a family on an operator's behalf. The
account must also hold at least the existential deposit, or the
extrinsic fails on funding before it fails on anything else.

Slots and deposit: `LockupEnabled` is off on mainnet today, so every
`register_child` reserves **no deposit**, whatever the slot count.
`FreeChildSlotsPerFamily` is **3**. If lockup is enabled on chain, the first three children of a
family stay free; each further one reserves the global next deposit,
which starts at the base child deposit, doubles after every paid
registration network-wide, and halves (never below the base) for every
14,400 blocks (~24 h) without one. One family
per purpose (production fleet, test bench) is a reasonable way to use
the free slots; the scheduler never looks at families, so this is
bookkeeping and dashboard scoping, not isolation.

### The proxy step, concretely

`register_child` is gated by `pallet_proxy`: the family must list the
child account as a proxy at the moment of the call, and only then.
`NonTransfer` with `delay = 0` is enough; remove it afterwards.

1. From the **family** account: `proxy.addProxy(delegate = <CHILD>,
   proxy_type = NonTransfer, delay = 0)`.
2. Submit `register_child` (step 3 below, or via
   `proxy.proxy(real = <FAMILY>, call = computeScoring.registerChild(…))`
   signed by the child — the delegate dispatches AS the family, so the
   family key need not leave cold storage).
3. From the family account: `proxy.removeProxy(<CHILD>, NonTransfer, 0)`.

`register_miner.py submit` signs as the family (`--family-suri`); it does
not add or remove the proxy — do that in Polkadot-JS Apps
(Developer → Extrinsics) or your own signer. Without step 1 the call
fails `ProxyVerificationFailed` after you have already produced the
`node_sig`; the signature is still valid, just add the proxy and resubmit
with the same nonce.

The flow deliberately splits across two boxes so the miner never holds
funds and the operator workstation never holds the node key:

```sh
# 1. On the operator workstation — get the family account as hex.
python deploy/register-miner/register_miner.py account-hex <FAMILY_SS58>

# 2. On the MINER — sign the registration message with the node key.
#    --nonce is the on-chain NodeIdNonce for this node_id (0 first time).
hippius-miner-agent sign-registration \
    --family 0x<FAMILY_HEX> --child 0x<CHILD_HEX> --nonce 0
#    → {"node_id":"…","node_sig":"…","nonce":0}

# 3. Back on the operator workstation — submit.
python deploy/register-miner/register_miner.py submit \
    --rpc <CHAIN_RPC_URL> \
    --family <FAMILY_SS58> --family-suri @<PATH_TO_FAMILY_MNEMONIC> \
    --child <CHILD_SS58> \
    --node-auth '{"node_id":"…","node_sig":"…","nonce":0}'
```

`<CHAIN_RPC_URL>` is the chain's RPC endpoint (Hippius mainnet: the public
`rpc.hippius.network`, or your own node). Requires `pip install
substrate-interface`. `--dry-run` composes the
call without submitting; use it first.

The signature is over a domain-separated message
(`HIPPIUS_COMPUTE_NODE_REG_V1` ‖ family ‖ child ‖ node_id ‖ nonce), so a
signature captured from one registration cannot be replayed into
another. The pallet enforces child/node_id uniqueness, per-family and
global caps, and a cooldown of about 12 h (7,200 blocks) after
`deregister_child` before the same child account or node id can register
again.

**Deposit.** None today: lockup is disabled on mainnet, so every
registration is free. If lockup is enabled, the first
`FreeChildSlotsPerFamily` registrations per family stay free and beyond
that the global deposit described above is reserved on the family.

On success the node's status is `Active`. Status is stored sparsely —
only non-default statuses are written — so *absent* means `Active`. The
three states are `Active`, `Quarantined`, `Decommissioned`.

### 3b. Announce your price

A miner prices its own capacity on chain. Until it does, the scheduler
treats it as price-neutral and no priced bill accrues to it, so announce
a price once the node is registered:

```
ComputeScoring::announce_price_change(node_id, new_price)
```

- **Signed by the child account** the node id is registered under
  (`NodeIdToChild[node_id] == signer`, else `NotNodeOperator`).
- **Unit:** USD per resource-unit per billing period, fixed-point ×1e6
  (USD-micros). A resource unit is the blend of vCPU, RAM and disk
  defined in `vali/apps/scheduler/scoring.py::resource_units`; the
  billing period is the validator's `VALI_BILLING_PRICE_PERIOD_S`
  (default one hour).
- **Bounds:** `new_price` must be `> 0` and inside
  `[PriceFloor, PriceCeiling]`. Read both from chain state first; while
  no ceiling is configured every announcement is refused
  `PriceBoundsNotConfigured`, and a value outside the bounds fails
  `PriceOutOfBounds`.
- **Speed limits:** a change relative to your current effective price is
  capped by the `MaxPriceChangeNumer / MaxPriceChangeDenom` ratio
  (`PriceChangeTooLarge`), and successive changes must be at least
  `MinPriceChangeIntervalBlocks` apart (`PriceChangeTooSoon`). A brand-new
  node id sets its first price freely within the bounds.
- **Notice:** the new price takes effect `PriceChangeNoticeBlocks` after
  the announcement, which gives the validator time to migrate tenant VMs
  whose price ceiling the new price would exceed. Anyone may call
  `apply_price_change(node_id)` once it is due to write it to storage;
  consumers already see it from the effective block on.

Submit it from Polkadot-JS Apps (Developer → Extrinsics) or your own
signer, as the child account — the family key is not needed.

---

## 4. Start the agent

Ansible installs the unit enabled but stopped, on purpose: you start it
once registration has landed.

```sh
sudo systemctl start hippius-miner-agent
journalctl -u hippius-miner-agent -f
```

Expect a line of the form:

```
hippius-miner-agent: serve — up (miner_id=…, identity=<64-hex>, orders=<mesh-ip>:9700). Awaiting shutdown signal.
```

The agent heartbeats to the Edge every `heartbeat.interval_secs`
(default 60) with a monotonic sequence persisted at
`/var/lib/hippius-miner/heartbeat.seq`. vali rejects a non-monotonic
sequence as replay, so do not restore that file from a backup.

---

## 4b. Auto-update

`miner_auto_update_enabled` is `true` unless you change it. The play
installs `hippius-miner-update.timer`, which every 30 minutes, plus a
random delay of up to 6 hours, checks the latest
[`thenervelab/hippius-cvm` release](https://github.com/thenervelab/hippius-cvm/releases)
and installs it when all of these hold:

- its tag is newer than the release you run (never a downgrade);
- its files have been published for at least 24 hours
  (`miner_auto_update_min_release_age_h`);
- the binary matches `SHA256SUMS`;
- its GitHub build-provenance attestation verifies with cosign for the
  release workflow of `thenervelab/hippius-cvm`, at that exact tag;
- the binary's `--version` names that tag.

It never stops or restarts the agent: a graceful stop destroys every
tenant domain on the host. It installs the new binary, then
`systemctl kill --signal=SIGKILL hippius-miner-agent`; systemd relaunches
the agent, which re-adopts the running CVMs. It refuses to do even that
unless `[host] skip_shutdown_teardown = true` is in
`/etc/hippius-miner/config.toml` (the play renders it). If the relaunched
agent has not delivered a heartbeat within 5 minutes, the updater swaps
the previous binary back the same way and never retries that tag.

```sh
journalctl -t hippius-miner-update -n 50       # what it did and why
cat /var/lib/hippius-miner/installed-release   # the release it installed
systemctl list-timers hippius-miner-update.timer
```

**Turning it off.** Right away, on the box:
`sudo touch /var/lib/hippius-miner/.no-auto-update`. Durably: set
`miner_auto_update_enabled: false` in `host_vars/<YOUR_HOST>.yml` and run
the play with `--tags miner_auto_update`; that stops and disables the
timer and leaves the agent running. Then upgrade by hand with the swap in
`deploy/ansible/playbooks/miner-tasks/AUTO_UPDATE.md`.

### Verifying a release by hand

What the updater checks, step by step. cosign is at
`/usr/local/libexec/hippius-miner/cosign` on a provisioned host, or get
it from [sigstore/cosign](https://github.com/sigstore/cosign/releases).

```sh
TAG=<release tag>
A=hippius-miner-agent-x86_64-linux-gnu
base=https://github.com/thenervelab/hippius-cvm/releases/download/$TAG
curl -fL -O "$base/$A" -O "$base/SHA256SUMS" -O "$base/$A.sigstore.json"
sha256sum -c SHA256SUMS
cosign verify-blob-attestation --bundle "$A.sigstore.json" \
  --type https://slsa.dev/provenance/v1 \
  --certificate-identity "https://github.com/thenervelab/hippius-cvm/.github/workflows/miner-agent-release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$A"                                    # must print: Verified OK
chmod +x "$A" && ./"$A" --version         # hippius-miner-agent 0.0.1 ($TAG)
```

With an authenticated `gh`, `gh attestation verify "$A" --repo
thenervelab/hippius-cvm` checks the same attestation. The workflow builds
every release twice and refuses to publish unless the bytes match; to
check the build yourself, rebuild from the tag with the command in
`BUILD-INFO.txt` and compare digests.

---

## 5. Verify you are admitted

Work down this list; each step tells you which layer failed.

1. **Identity exists.**
   `sudo cat /var/lib/hippius-miner/identity.pub` → 64 hex chars.
2. **Hardware is real.**
   `hippius-miner-agent platform-id` → the AMD CHIP_ID as hex, read
   from `/dev/sev`. Failure here means SEV-SNP is not actually live.
3. **Mesh is up.**
   `netbird status` → `Management: Connected` and an address in
   `100.64.0.0/10`.
4. **Agent is serving.**
   `curl -sf http://<MESH_IP>:9700/healthz`. The orders listener binds
   the mesh address only — it is not reachable from the public internet
   by design.
5. **On chain.** Ask the registry feed the Edge itself reads:
   `GET <VALI_URL>/v1/edge/registry` →
   `.miners[] | select(.node_id_hex=="<node_id>")` must show
   `"status":"active"`. The Edge picks that up within
   `EDGE_REGISTRY_REFRESH_SECS` (default 30) plus one handshake.
6. **Heartbeats are landing.** vali auto-provisions a miner row on the
   first verified heartbeat from an on-chain-active node — no manual
   registration call. `GET /v1/admin/miner/list` should show your node.

### If the Edge never answers at all

Check this BEFORE the table below, because it is the most likely first
failure and it produces no Edge-side log — the Edge never sees you, so it
has nothing to classify.

The Edge listens on the fleet's overlay, not on the public internet. On a
working miner the route to it leaves through the mesh interface:

```
$ ip route get <edge-ip>
<edge-ip> dev wt0 ... src 100.64.x.y      # wt0 = NetBird, src = your mesh address
```

If `netbird status` does not say `Management: Connected`, or your address is
not inside `100.64.0.0/10`, the agent cannot reach the Edge no matter how
correct the rest of your configuration is. Fix the mesh first: play 04, and
`network.netbird_management_url` / `netbird_setup_key_file` must be the
ones for the fleet you are joining — a setup key from a different NetBird
instance logs in and puts you on the wrong network.

### If the Edge refuses you

These are for when the Edge DID answer. It logs a static classifier, and
they mean different things:

| Classifier | Meaning |
|---|---|
| `registry-unhealthy` | The Edge could not read the registry feed. Not about you. It starts with an **empty** set and admits nobody until the first successful poll. |
| `not-registered` | Handshake fine, node id absent from the `active` set. Registration has not landed, or the node is quarantined/decommissioned. |
| `identity-binding` | The certificate's SAN node id does not match its own public key, or it carries more than one URI SAN. |
| `handshake` | TLS failed before any of that. |

---

## 5b. The two files nothing else creates

Both are staged by the playbooks above. They are called out separately
because a miner that skips them **registers fine, goes dispatchable, and
then fails every single launch** — the failure arrives minutes later, in a
different subsystem, naming neither file.

```sh
# On the miner, after `site.yml`:
sha256sum /var/lib/hippius-miner/ovmf.fd     # must equal miner_tenant_ovmf_sha256
grep -A3 '^\[kbs\]' /etc/hippius-miner/config.toml   # endpoint AND ca_cert
```

**The tenant OVMF** is measured into every guest's SNP launch digest. Wrong
file, wrong measurement, and the KBS declines to release any disk key on
your host. Symptom: `tenant-preflight/ovmf-missing`, or a measurement the
validator refuses.

**The KBS CA** is what lets the agent complete TLS to the KBS when it
relays a guest's release. Without it the vsock relay answers
`refused kbs-transport`, and the guest — which never receives its KEK —
sits in its initramfs burning a core while libvirt reports the domain as
`running`. Nothing in that picture says "certificate", which is why it is
worth checking directly rather than inferring from a healthy-looking VM.

## 5c. Where the disks land, and what you can oversubscribe

### Storage

Per-VM disks default to `/var/lib/hippius-miner`, and both roots are
configurable in `/etc/hippius-miner/config.toml`:

```toml
[storage]
data_disk_root  = "/srv/fast"   # → /srv/fast/data/<vm>.img  AND  /srv/fast/overlay/<vm>.img
state_disk_root = "/var/lib/hippius-miner"   # → .../state/<vm>.raw
```

`data_disk_root` is the one that matters. It holds **both** growing
artefacts — the tenant data disk (`/dev/vde`) and the golden overlay — and
the data disk takes the heaviest I/O of a VM's life: the first-boot
dm-integrity wipe writes the entire volume. A miner that leaves this on its
system disk while an NVMe sits idle is the most common self-inflicted
slowness.

A root outside `/var/lib/hippius-miner` (a dedicated mount, say) needs
only `miner_data_disk_root` / `miner_state_disk_root` in your
`host_vars`, **and it must exist before you run the play**: play 05
refuses a missing root rather than create one, because a directory
created under a mount point that is not mounted yet would put VM disks
on the system disk, hidden later by the mount. Play 05 adds the roots
to the agent unit's `ReadWritePaths`. The unit runs with
`ProtectSystem=strict`, so a root it does not list is read-only to the
agent and every launch fails with a `*-disk/mkdir` class
(`overlay-disk/mkdir` for a golden launch, `data-disk/mkdir` or
`state-disk/mkdir` otherwise). That shows only in the agent's journal
(`dispatch-failed-detail`); vali reports
`dispatch-failed-after-register`. A host with several data NVMe can,
for instance, keep them in one mdadm RAID10 mounted at
`/srv/hippius-data` and point `miner_data_disk_root` there.

`state_disk_root` holds a 1 MiB anti-rollback counter per VM. It is not
worth moving for speed — but **losing that file permanently bricks the VM**
(no counter ⇒ the KBS refuses to release the key), so choose durable over
fast.

Security is unaffected by either choice: both files are formatted inside the
SNP boundary with a key the guest holds and the host never sees. Wherever
the file sits, the miner has ciphertext.

⚠️ The **staging** root — downloaded base images (rootfs, kernel, initrd),
several GiB per distro — is a constant at `/var/lib/hippius-miner/staging`
and is NOT configurable. Size the system disk for it even after pointing the
roots above elsewhere.

### Storage pools and dedicated disks (preview)

The agent can also describe extra storage for verified disk tiers
(`docs/design/disk-tier-verification.md`). It is **inert today**: vali
places nothing on it yet, Ansible does not render these keys, and an
agent older than the one that knows them refuses a config carrying them
(the config is `deny_unknown_fields`).

```toml
[[storage.pools]]               # must include `default` at data_disk_root
id = "default"
path = "/srv/fast"              # = [storage] data_disk_root
class = "nvme"
budget_gb = 3000                # = [host] cvm_disk_gb_budget

[[storage.pools]]
id = "hdd0"
path = "/var/lib/hippius-miner/pools/hdd0"   # = /var/lib/hippius-miner/pools/<id>: an ext4/xfs/btrfs mounted (or bind-mounted) there
class = "hdd"
budget_gb = 16000
os_disks = false

[[storage.dedicated_disks]]     # a whole, blank disk (run `wipefs -a` yourself)
id = "wwn-0x5000c500a1b2c3d4"   # its /dev/disk/by-id name
```

Without `[[storage.pools]]` the agent behaves exactly as before: one pool
`default` at `data_disk_root`. Every OS disk still lands on `default`. The
other pools and the dedicated disks are only checked and reported, in the
`v7` heartbeat (`[heartbeat] emit_pools = true`, which needs vali to accept
`v7` first). The agent never formats, mounts or wipes anything. It refuses
to start if a pool that still holds VM disks disappears from the config:
set it to `state = "draining"` and empty it before removing it. Each pool
is bound to the filesystem it was first seen on (its UUID, recorded in
`<state_disk_root>/storage-pools.json`). If another filesystem shows up at
that path, even an empty one, the pool reports `pool-fs-changed` and is
not offered: remount the right one (checked on every heartbeat), or, if the
swap is deliberate, delete that pool's entry from the file and restart the
agent. A pool not mounted when the agent started reports `pool-unbound`
once it appears, until the next restart binds it. A pool whose binding was recorded by
device number (`dev:<st_dev>:<root>`, when no filesystem UUID is readable)
can stay unbound for good on LVM or md RAID if its minor number changes
across a reboot: its VMs then cannot relaunch, and vali raises
`HippiusStoragePoolOffItsFilesystem` once such a pool holding VMs has been
off its filesystem for 15 minutes. Mount the right filesystem, then delete
the pool's entry from `storage-pools.json` and restart the agent, or
restore the filesystem UUID (udev). A launch to a pool that
is draining, closed to OS disks or off its filesystem is refused with
`507 pool-unavailable:<pool>`, and vali places it elsewhere. A VM
destroyed while one of its pools is off its filesystem is noted in
`<state_disk_root>/pending-reclaim.json`, and its files there are
deleted once the pool is back.

Later, the providers dashboard will push the same document to the agent as
a signed `storage-config` order. Once applied, it is stored in
`<state_disk_root>/storage-config.json` and takes precedence over the local
`[[storage.pools]]` / `[[storage.dedicated_disks]]`, also after a restart.
The pushed document can't move `default` off `data_disk_root`, change its
budget, or give a local pool another path. If you change one of those
locally, the agent goes back to your local set and the dashboard shows the
document as not applied.

#### Where a pool lives, and checking it under the agent's sandbox

The agent runs sandboxed (`PrivateDevices=yes`, `ProtectSystem=strict`).
It sees no block device and can write only to its own paths. So every pool
other than `default` lives at `/var/lib/hippius-miner/pools/<id>`, which is
already writable to the agent. Mount the filesystem there, or bind-mount an
existing mount (here an existing `/mnt/hippius-data` as pool `nvme0`):

```sh
sudo mkdir -p /var/lib/hippius-miner/pools/nvme0
# keep it across reboots: one /etc/fstab line (added once; re-running
# this does not duplicate it)
line='/mnt/hippius-data  /var/lib/hippius-miner/pools/nvme0  none  bind,nofail,x-systemd.requires-mounts-for=/mnt/hippius-data,x-systemd.before=hippius-miner-agent.service  0 0'
grep -qF "${line}" /etc/fstab || echo "${line}" | sudo tee -a /etc/fstab
sudo systemctl daemon-reload
sudo mount /var/lib/hippius-miner/pools/nvme0     # = mount --bind /mnt/hippius-data /var/lib/hippius-miner/pools/nvme0
findmnt /var/lib/hippius-miner/pools/nvme0        # must show the bind
```

Declare the pool with `path = "/var/lib/hippius-miner/pools/nvme0"`.

With the Ansible play, declare it in the host's `host_vars` instead. The
play then creates the pool directory, writes the fstab bind and mounts it,
and renders `[[storage.pools]]` (with `default` derived from
`miner_data_disk_root` and the `[host]` budget). A hand-edited
`config.toml` is overwritten by the next play run.

```yaml
miner_storage_pools:
  - id: nvme0
    class: nvme
    budget_gb: 3200
    source: /mnt/hippius-data   # a mounted filesystem; omit if mounted at the pool path
miner_heartbeat_emit_pools: true   # v7 heartbeat: needs an agent that knows the key
```

`nofail` keeps a host booting when a pool's filesystem does not come up;
the agent then reports that pool unavailable. `x-systemd.before=` makes the
agent wait for the bind at boot (`nofail` alone would let it start first).
A pool the agent has bound once comes back as soon as it is mounted again,
without an agent restart; one mounted for the first time after the agent
started reports `pool-unbound` until the next agent start. To change a
pool's `source`, unmount the pool path first.

Once vali has pushed a storage configuration to the host, the agent keeps
it in `storage-config.json` under its state disk root (`miner_state_disk_root`), and that file — not
`config.toml` — decides the pools from then on: manage them from vali. The
play still provides the mounts.

The root is fixed: `/var/lib/hippius-miner` is the agent's layout, and the
play refuses another `miner_agent.state_dir` or a symlinked one. To put the
state dir on another disk, mount that disk at `/var/lib/hippius-miner`.

A pool declared anywhere else is refused with `pool-outside-pools-root`,
except when it is `draining`: a pool being emptied keeps reporting
`draining` wherever it sits. A path the agent cannot write to is refused
with `pool-path-read-only`.

A pool that was declared outside the root, before this rule existed, has
one way out. You can't move a pool that holds disks (`pool-has-disks`),
and any new declaration that keeps it active is refused. So:
1. Declare it `draining`. Nothing new lands on it.
2. Once it holds no disk (its VMs moved or destroyed), remove it from the
   declaration.
3. Declare it again at `/var/lib/hippius-miner/pools/<id>`.

Dedicated disks are read by a separate oneshot,
`hippius-miner-storage-collect`, which runs on a 5-minute timer, can read
devices, and has no network. It writes `/run/hippius-miner/disk-facts.json`
for the agent.

To check a declaration without touching the running agent, put the
candidate config under `/etc/hippius-miner/` and the disk facts under
`/run/hippius-miner/`. The sandbox hides `/root` and `/home`
(`ProtectHome=true`) and gives the check its own empty `/tmp`
(`PrivateTmp=true`), so a file in any of those reads as missing
(`config-read`):

```sh
sudo cp candidate.toml /etc/hippius-miner/candidate.toml
# Fresh disk facts, written by the collector (outside the sandbox) to
# /run/hippius-miner/disk-facts.json, the default `--facts` path:
sudo systemctl start hippius-miner-storage-collect.service
# The agent's view of the candidate config, under the agent's own sandbox:
sudo systemd-run --wait --pipe --collect \
  -p ProtectSystem=strict -p ProtectHome=true -p PrivateTmp=true \
  -p PrivateDevices=true -p NoNewPrivileges=true \
  -p ProtectKernelTunables=true -p ProtectControlGroups=true \
  -p ReadWritePaths=/var/lib/hippius-miner \
  /usr/local/bin/hippius-miner-agent storage-check \
  --config /etc/hippius-miner/candidate.toml
```

The JSON shows each pool's state and error, its filesystem binding, and
each dedicated disk.

Storage never stops the agent:
- a declaration that doesn't validate is ignored, the agent runs with the
  implicit `default` pool, and the reason is logged;
- a pool that fails its checks is reported `unavailable`;
- a no-longer-declared pool that may still hold disks is kept as
  `draining`.

### Disk capacity

Three things bound how much tenant disk your host takes. The tightest
one wins:

1. **`[host] cvm_disk_gb_budget`**, which the play derives: the usable
   size of the filesystem holding `miner_data_disk_root` (its blocks minus
   the root-reserved ones, 5% on ext4 by default), minus
   `host_cvm.reserve_disk_gb` (default 100 GiB), minus
   `host_cvm.reserve_disk_root_extra_gb` (default 50 GiB) when that
   filesystem is `/`. The reserve covers §25 migration downloads and
   backup/restore staging; the extra covers the OS, the image cache and
   base-image staging, which share `/` with the tenant disks. You can lower the budget
   per host with `host_cvm_overrides: {disk_gb_budget_max: N}`. You
   can't raise it above the derivation. The agent refuses any launch
   past the budget. Before a VM is registered, that's at preflight.
2. **The agent's measured gate.** Free space on that filesystem minus
   the unwritten tail of every data disk and overlay already there, so
   every existing disk is counted as if full. It runs at preflight, and
   again at disk creation under a process-wide lock, so two concurrent
   launches can't both be promised the same bytes.
3. **vali's own ledger.** For every VM it has placed on you, vali
   counts the flavor's `disk_gb` plus the rootfs. It compares that
   against the minimum of the operator-registered disk size (minus
   `VALI_DISK_RESERVE_GB`), your declared budget, your reported
   filesystem size (minus the same reserve) from the v4 heartbeat
   (`miner_heartbeat_schema_disk`), and any ceiling you have earned.
   A value you report can only lower that figure.

Any disk refusal answers **507 `insufficient-disk`**. vali treats it as a
capacity event and re-places the VM. It's never a SEV start failure,
so a full disk doesn't mark your host SEV-incapable. It does cut the
disk ceiling an *earned* host has built up.

**Why vali doesn't take your word for it.** SNP attests what the guest
runs, not the host's disks, so every disk figure a miner sends is a
self-report. The design doesn't depend on those reports being honest:

- vali's committed ledger is its own record.
- Your declared figures only ever enter a `min()`.
- The agent's gate measures the filesystem rather than trusting it.
- A refusal is charged to the host that caused it.
- vali raises an over-claim alarm when your reported free space falls
  below what it has committed to you.

A host that over-declares gains only launches it then fails, which
costs its own earnings and reputation. Tenant data safety is unaffected
either way: the guest's dm-integrity format fails closed on a disk that
can't hold it. Nothing is silently truncated.

What's still open: nothing proves a host's free space. An optional
future probe would be a vali-issued challenge. The agent would answer
it with a signed statvfs and reads of random blocks of a freshly
written file. That would turn the over-claim alarm into evidence.

### Oversubscription

| resource | oversubscribable | why |
|---|---|---|
| RAM | **no** | an SNP guest's memory is encrypted and pinned (`memfd` backing, required so KVM can map the GHCB). No ballooning, no swap, no page sharing — the hypervisor can neither move nor dedupe those pages. Not a policy choice. |
| vCPU | not today | vCPUs are threads and time-sharing would work, but admission takes `min(slots_RAM, slots_CPU)` so neither dimension is oversubscribed. A policy knob, not a wall. |
| disk | **no** | overlays and data disks are created *sparse*, but every gate counts them at full size: vali's committed ledger, the agent's `cvm_disk_gb_budget`, and the agent's measured free-space gate, which subtracts the unwritten part of every disk already on the filesystem. A tenant can always fill the disk it bought, so a full host is refused up front (507 `insufficient-disk`) rather than hitting `ENOSPC` inside a running guest. See *Disk capacity* above. |

The practical consequence: **RAM is what bounds how many VMs your host takes.**
Buying cores without RAM will not raise your slot count.

## 6. The step people miss: being *schedulable*

Passing admission and heart-beating is **not** enough to receive
tenant workloads.

vali's auto-provision path records `platform_id = "onchain:<NODE_ID_64_HEX>"`
— a per-node placeholder, not a chip id (so any number of new miners can
heartbeat before any of them is registered). The scheduler requires a **real** hex
`platform_id`, a non-null `chain_node_id`, a non-null mesh IP, local
status `ACTIVE`, and a recent heartbeat. A node with the placeholder
passes every other gate and silently never gets chosen.

Close it with one call, using the values from §5 steps 2 and 3. The
call **upgrades the auto-provisioned row in place**: when the stored
`platform_id` is still an `onchain:…` placeholder and `pubkey_hex`
matches the row's key (your node id), vali replaces the placeholder with
the real CHIP_ID and backfills the NetBird peer id / mesh IP (and
`chain_node_id` / `snp_generation` if unset). It returns `200` with the
upgraded row. `<MINER_ID>` must be the miner id the agent signs its
heartbeats with (the row vali auto-provisioned — `m-<first 16 hex of
the node id>` unless the host pins one, see
[Your `miner_id`](#your-miner_id)), and `<AMD_CHIP_ID_HEX>`
bare hex (no `0x`) — the placeholder is replaced once, so anything else
is refused `400` rather than stored. Until this call
`GET /v1/operator/nodes` shows the node with `identity.platform_id =
onchain:<node id>` and `schedulable: false`:

```sh
curl -sf -X POST "<VALI_URL>/v1/admin/miner/register" \
    -H "Authorization: Bearer <MINER_ADMIN_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
          "miner_id":     "<MINER_ID>",
          "pubkey_hex":   "<NODE_ID_64_HEX>",
          "platform_id":  "<AMD_CHIP_ID_HEX>",
          "netbird_peer_id": "<PEER_ID>",
          "netbird_ip":   "<MESH_IP>",
          "chain_node_id": "<NODE_ID_64_HEX>",
          "snp_generation": "milan"
        }' | jq
```

`snp_generation` (`milan` | `genoa` | `turin`) is required for Milan
because its chip_id is the same length as Genoa's (64 bytes): left
unset, a Milan host is measured as Genoa and every launch is refused
`launch-digest-mismatch`. Omit it (or send `genoa` / `turin`) on the
other generations.

Re-posting the same `(miner_id, pubkey_hex, platform_id)` triple is
idempotent (`200`). It is `409` (and nothing is written) when the
`pubkey_hex` differs from the row's, when the row already carries a
**real** CHIP_ID that differs from the one posted (only the placeholder
is ever replaced), or when the CHIP_ID / `chain_node_id` belongs to a
different miner. A NetBird field that already holds a different value is
left as stored (the call still returns `200`) — fix a moved mesh IP from
the Django admin. See
[`vali/apps/miners/README.md`](../../vali/apps/miners/README.md) for the
admin token and the quarantine/list endpoints.

The bootstrap prints exactly this block at the end of play 05, filled
in with the real values — keep that output. It prints the same values
once more as one JSON object, the one the console takes:

```json
{"miner_id": "<MINER_ID>", "node_id": "<NODE_ID_64_HEX>", "platform_id": "<AMD_CHIP_ID_HEX>",
 "netbird_ip": "<MESH_IP>", "snp_generation": "milan"}
```

`snp_generation` there is the generation play 00's preflight derived from
the CPU (family/model, `epyc_snp_generation` in
`deploy/ansible/playbooks/filter_plugins/host_preflight.py`), never a
host_vars value alone. When play 00 did not run in the same invocation
(`--skip-tags preflight`, `--start-at-task` past it), play 05 withholds
the JSON and prints `WARN [SNP_GENERATION_NOT_DERIVED]`: an empty
generation would read as unset, and vali would infer Genoa from a
Milan's 64-byte CHIP_ID. Run play 00 with it.

## 6b. Register the host's size (fleet operator)

This step is done by **whoever runs vali**, not by the miner operator.

Until vali knows how much hardware the host has, it admits on a flat
`capacity_slots` count and answers every feasibility query for it with
`not-now` / `host-size-unknown`. The size is an operator-registered
**trusted anchor**: it is what bounds the miner's own untrusted
heartbeat reports, so it must come from the fleet operator's own
knowledge of the hardware (the machine they provisioned or can reach
themselves, the SKU they bought), never from a figure the miner operator
sends. An inflated anchor makes vali place VMs the host cannot run. It
is set once the chain refresh has created the miner's `MinerCapacity`
row, which happens when the node appears on chain.

On a host you control, read the numbers directly:

```sh
nproc                                                   # → --cpus
awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo  # → --memory-mb (MiB)
```

then, in a vali pod:

```sh
python manage.py vali_set_miner_capacity --miner-id <MINER_ID> \
    --cpus 64 --memory-mb 256180 --dry-run
python manage.py vali_set_miner_capacity --miner-id <MINER_ID> \
    --cpus 64 --memory-mb 256180 --by <you>
```

(A 64-thread host with 256 GB of RAM reads 64 / ~256180.) `--miner-id` resolves
through the `chain_node_id` set in §6; `--node-id <NODE_ID_64_HEX>` works
too. The command prints the before/after and refuses out-of-range values
or an anchor smaller than the VMs vali has already placed there. It
warns, but still writes, when the anchor leaves no room for the host
reserve or when a fresh heartbeat's free-memory report disagrees
sharply with it. An identical re-run changes nothing. `--by` is
mandatory for a real write; the audit record (who, node, before, after)
is the last line of the output and is logged by the process you ran. With
`kubectl exec` that output only exists in your session, so keep it.
`--clear` puts the miner back on the flat fallback.

### External miners: approval

When vali runs with `VALI_MINER_APPROVAL_REQUIRED=true`, a miner first
seen on chain is **pending approval**: it heartbeats and reports as usual,
but takes no new placement (it rides the cordon gate, with the reason
`pending approval`). Miners that existed before the switch were
grandfathered approved; with the switch off (the default) a new miner is
approved on sight, which is today's behaviour.

Approving it also sets its anchor, to the smaller of what you declare and
what its fresh heartbeat reports (cpu budget, available memory, data-disk
size), so the miner's word can only lower your figure:

```sh
python manage.py vali_approve_miner --list-pending
python manage.py vali_approve_miner --miner-id <MINER_ID> \
    --cpus 64 --memory-mb 256180 --disk-gb 3500 --by <you> --reason "<why>" --dry-run
```

or, from the backend, `POST /v1/admin/miner/<MINER_ID>/approval` with the
miner-admin token and `{cpus, memory_mb, disk_gb?, trust_class?,
approved_by, reason}` (`GET` on the same path reads the state and the
heartbeat's figures). It refuses a miner whose heartbeat is stale and a
miner already approved; re-anchor an approved miner with
`vali_set_miner_capacity`. Every field lands a `MinerCapacityAudit` row
with the approver. Without `--trust operator` the miner stays `earned`, so
the anchor is one more cap on what it has proven.

**Automatic approval** (self-service onboarding): with
`VALI_MINER_AUTO_APPROVE=true` as well, the scheduler re-evaluation loop
approves a pending miner by itself (audit actor `auto:attested-soak`) once
all of these hold:

- its host-attestor is `attested` on a pinned release, beaconing, and its
  AMD-signed CHIP_ID is the `platform_id` the miner registered, and no
  other registered miner names that chip;
- it registered through `/v1/admin/miner/register` with a real CHIP_ID and
  an explicit `snp_generation`, and is not quarantined;
- its heartbeats have carried the v3 capacity, the v4 disk figures and the
  free RAM without a gap for `VALI_MINER_AUTO_APPROVE_SOAK_S` (default
  1800 s);
- it is not cordoned, and the approval above would not refuse it.

The anchor is then the heartbeat's own figure (or an anchor already on the
row, if lower), and the miner stays `earned`. `--list-pending` and the
`GET` show the first condition a pending miner still fails.

`chip-shared` is deliberate, not a bug: another registered miner already
names this host's CHIP_ID (or a prefix of it), typically the same host
re-onboarded under a new identity. A known chip coming back needs an
operator approval.

Before turning it on, check the rule against the fleet — read-only, every
miner including the approved ones:

```sh
python manage.py vali_approve_miner --auto-evaluate [--json]
```

Per miner: every condition passed or failed, `would_approve` (what the
next pass would do, switch as configured) and `would_approve_if_pending`
(the miner alone, as a new pending miner with the switch on). Approved and
revoked miners never soak, so their soak reads `null` and does not count
against them. The anchor is shown twice, term by term (declared side,
heartbeat figure, result): `anchor` keeps the row's current anchor as the
declared side, as the real pass would; `anchor_as_new` is what a new miner
on this hardware gets (the heartbeat figures, with the RAM vali's VMs hold
on it added back to the free-RAM figure — vali's placement ledger, not a
measurement: pending or power-stopped VMs make it read high — so the sum
is capped at the host's memory as known, `cap` / `cap_source`: the v3
heartbeat's CVM memory budget, else the row's anchor). `failed` also
names `anchor` /
`anchor_as_new` when that anchor would be refused.

To take an approval back — automatic or not, grandfathered included:

```sh
python manage.py vali_approve_miner --miner-id <MINER_ID> --revoke --by <you> --reason "<why>"
```

or `POST .../approval` with `{"revoke": true, "revoked_by", "reason"}`. The
miner is pending again (no new placements; its VMs stay) and is marked
revoked: the automatic approval never takes it again, only an operator
approval does. Revoking a pending miner keeps it out of the automatic
approval for good.

### Compute also requires storage

When vali runs with `VALI_COMPUTE_REQUIRES_STORAGE=true`, a compute family
must also run at least one healthy Arion storage node. Otherwise its
compute nodes take no new VM (`schedulable_reason: no-storage` in
`/v1/operator/nodes`) and earn no reward weight. The VMs already on them
keep running.

A storage node counts when it passes the Arion pallet's own filter for a
family's paid weight:

- it is an Arion child registered under the same family, and Active;
- it is not one of the family's compute children, nor registered with one
  of its compute node ids (a compute machine is not its own storage);
- the Arion validator reported its weight within the runtime's
  `StaleChildBuckets`, and has a quality record for it.

When a family loses its storage, vali first waits out
`VALI_COMPUTE_STORAGE_LAPSE_DEBOUNCE_S` (2 h), which absorbs an Arion
migration or a re-key. If there is still no storage after that, the family
has lapsed since its first read without storage, and keeps its rights until
`grace_until = lapsed_since + VALI_COMPUTE_STORAGE_GRACE_S` (72 h). A family
that never had storage is cut at once. `VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES`
(SS58, comma-separated) lists families that are never cut.

`/v1/operator/nodes` carries this per node, so the backend can warn the
operator before the cut:

```json
"storage_requirement": {
  "state": "ok | grace | lapsed | exempt | off",
  "family_storage_children": 1,
  "lapsed_since": "2026-10-20T08:00:00+00:00",
  "grace_until": "2026-10-23T08:00:00+00:00"
}
```

The field is `null` for a node vali has not read as an Active compute node.

Before turning it on, see what it would decide (read-only):

```sh
python manage.py vali_storage_requirement --evaluate [--json]
```

This prints one line per compute family: its storage count, why each Arion
child did or did not count, and its state with `lapsed_since` and
`grace_until`. Copy a family from its `family_ss58` column to exempt it.

---

## What you cannot self-supply

These come from whoever runs the fleet's control plane. If you are
standing up your own fleet, you generate them; if you are joining
someone else's, you must be given them:

| Item | Why |
|---|---|
| A **NetBird setup key** bound to the miner group, on the fleet's NetBird instance | A key from a different NetBird instance fails to log in |
| The **Edge server CA** certificate | The agent verifies the Edge's server certificate against it |
| `edge_order_signing_pubkey` | Every lifecycle order is `verify_strict`ed against it; a wrong key means every order is rejected |
| The **Edge endpoint**, **KBS endpoint** and **image object store** | Nothing resolves without them |
| A **vali miner-admin token** | Only for the §6 call above |
| The **host-attestor components** (`ovmf.fd`, `linux.bin`, `initrd.bin`) | Pinned by sha256 in `miner_host_attestor` (group_vars) and not published at a public URL; stage them into `/var/lib/hippius-miner/host-attestor/` before play 05, or it refuses to render `[host_attestor]`. Without an attested host attestor a host receives no tenant VM |
| The host-size **anchor** (§6b) | Set by the fleet operator from hardware they know, never from your report — it caps what vali will ask of your host |

Not on this list, because you sign them yourself: the family account
(your Arion storage-miner coldkey, §3) and the `pallet_proxy` delegation
from it to your child account, which `register_child` requires (§3, "The
proxy step").

Note that none of these lets the fleet operator read your tenants' data,
and none of them is a certificate authority over your identity. They are
routing and mesh membership. Your node key stays yours.

## Leaving

Do not just power off. A miner that stops heart-beating strands the VMs
it hosts. Per node, in this order:

1. On the box, with the agent running:
   `sudo hippius-miner-agent request-graceful-exit`. Vali quarantines the
   node and warm-migrates its tenants off. The bare command needs an
   agent newer than v2026.10.16.2 (PR #1645); older agents need
   `--miner-id`, `--edge-url` and
   `--ca-cert /var/lib/hippius-miner/mtls/ca.crt`.
2. Wait until the node hosts no VMs.
3. From the family: `deregister_child(child)`, then
   `claim_unbonded(child)` once the unbonding period is over (immediately
   when no deposit was reserved, the case today). The child account and
   node id can register again after a cooldown of about 12 h (7,200
   blocks).

Deregistering before the node is drained loses the warm migration: the
node drops out of vali's snapshot and its VMs are only cold re-placed.
There is no on-chain unstake step: `request_unstake` needs existing stake
and staking is off. See
[`stranded-migration-runbook.md`](./stranded-migration-runbook.md) for
what to do if a migration gets stuck part-way.

## Where vali thinks you are

You declare nothing about location. Within one probe cycle (10 min) of your
miner heartbeating, `vali_geo_probe` DETECTS it: the public IP your NetBird
peer connects from, its GeoIP/ASN, the round-trip time vali measures to
you, and the egress IP your tenant CVMs report. The result is on
`GET /v1/operator/nodes` as `location` and rolls up into
`GET /v1/operator/regions`. Only a `verified` verdict lets a
`region`-constrained launch land on you; `verdict_reasons` says what is
missing (`rtt-unavailable`, `latency-inconsistent`, `peer-stale`) or
contradictory (`guest-egress-mismatch`, `geo-source-disagree`);
`geo-rtt-arbitrated` next to `verified` is informational (the GeoIP
databases disagreed about your IP and the RTT settled it). A VPN or
tunnel in front of the host makes the RTT longer than the claimed location
permits and will keep you `unverified`. See `docs/design/miner-geolocation.md`.

## See also

- [`deploy/ansible/README.md`](../../deploy/ansible/README.md) — the bootstrap in operator terms
- [`deploy/register-miner/README.md`](../../deploy/register-miner/README.md) — full on-chain registration flow
- [`binaries/miner-agent/README.md`](../../binaries/miner-agent/README.md) — storage layout, pointing tenant data at dedicated NVMe
- [`docs/design/permissionless-miner-auth.md`](../design/permissionless-miner-auth.md) — why there is no operator CA
- [`docs/security/data-visibility.md`](../security/data-visibility.md) — what you, as the host operator, can and cannot see
