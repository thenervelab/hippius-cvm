# Onboarding a miner

How a third party brings a SEV-SNP host onto a Hippius compute fleet.

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
| **Ubuntu**, a release in `miner_supported_ubuntu_versions` | play 00 |
| **Kernel ≥ 6.11** (`linux-generic-hwe-*` if the GA kernel is older) | play 00 |
| **NVMe storage**, unpartitioned if you dedicate disks to tenant data | play 00 asserts every `nvme_data_devices` entry is a block device carrying no partition table and no signature other than `crypto_LUKS` |
| **Outbound internet** + inbound `22/tcp` and `51820/udp` | play 07 configures UFW to allow exactly those, plus everything on the mesh interface `wt0` |

Get the firmware settings confirmed **in writing by the datacentre
before you pay**. A machine with SEV-SNP fused off or firmware-disabled
is not recoverable remotely and is the single most common way this goes
wrong.

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
| 05 | miner-agent install + identity self-gen | Builds and installs `hippius-miner-agent`, renders `/etc/hippius-miner/config.toml`, runs `init-identity`, reads the AMD CHIP_ID, prints the registration block, installs the systemd unit **without starting it**. |
| 06 | mTLS cert mount point | Creates `/var/lib/hippius-miner/mtls` (0700) and installs the Edge **server** CA so the agent can verify the Edge. In permissionless mode nothing else is placed here. |
| 07 | Host firewall | UFW default-deny inbound; allow `22/tcp`, `51820/udp`, and all traffic on `wt0`. |

> **`--features snp` is load-bearing.** The agent must be built with it
> or every launch order fail-closes with
> `cvm-launch-digest/feature-disabled`. Play 05 does this; if you build
> the binary yourself, do not omit it.

> **Play 05 builds from source on the production host.** That is marked
> TEMPORARY in the playbook. If that is unacceptable in your
> environment, build the binary elsewhere and drop it at
> `/usr/local/bin/hippius-miner-agent` before running the play.

### Variables you must supply

Per host, in `host_vars/<YOUR_HOST>.yml`:

`ansible_host`, `ansible_user`, `ansible_ssh_private_key_file`,
`cpu_model_expected`, `ram_gb_expected`, `nvme_system_devices`,
`nvme_data_devices`, `host_cvm.cpu_budget`,
`host_cvm.memory_mb_budget`, `netbird_setup_key_file`,
`orders_bind_ip`.

That last one is this miner's **own** mesh address, and it is the one to
watch: the agent's signed-order server binds it and only it. Omit it and
the `group_vars` placeholder is used, the bind fails, and the miner never
receives an order — with nothing visibly wrong anywhere else. NetBird
assigns the address at mesh join, so you cannot fill it in until after
play 04.

This list is the required minimum, not the whole surface — the
`host_vars/` directory documents further optional keys (data RAID,
private-network bonding) that only some hosts need.

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
| `miner_auto_update_s3_base` | the binary auto-update channel — see the warning below |
| `edge_ca_cert_file` | path on YOUR workstation to the CA that signed the Edge's **server** certificate; defaults to `~/.config/hippius/edge-ca.crt` and is copied to the host by `mtls-cert-mount.yml` |
| `miner_tenant_ovmf_url` / `_sha256` | the firmware every tenant CVM boots. **Not** the distro `ovmf` package — this exact image is folded into the SNP launch measurement, and the validator recomputes against the copy it pins. A different build measures differently, so the KBS refuses every release on your host. Fetched and digest-verified by play 02; a host without it answers every launch `tenant-preflight/ovmf-missing`. |
| `miner_kbs_ca_cert_file` / `_src` | CA the agent trusts when dialling the KBS to relay a guest's §21 release. The KBS serves a private certificate by default (internal service on the mesh, not a public ACME endpoint). Leave empty only for a publicly-trusted KBS certificate. |
| `miner_agent_source_repo` | the git repository play 05 clones and **builds the agent from**. A code-delivery path, not a link — whatever is here is what runs on your confidential host. The play refuses to run on an unfilled placeholder. |

> **Auto-update is on by default and unsigned.** With
> `miner_auto_update_enabled: true` and `miner_auto_update_pubkey: ""`,
> the host pulls a new agent binary from `miner_auto_update_s3_base`
> and trusts it on a sha256-over-HTTPS check alone. That is a supply
> chain you are accepting. Set a pubkey, point the base at storage you
> control, or freeze the channel with
> `touch /var/lib/hippius-miner/.no-auto-update`.

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

### Back up `identity.key`

Losing it means the chain still lists a node id your machine can no
longer prove, and re-registering a new node id costs a fresh
registration (and, past your family's free slot, a fresh deposit). Copy
it somewhere offline. Do not copy it onto a second host — two machines
presenting one identity is a fault, not a failover.

---

## 3. Register the node id on chain

Registration is a raw extrinsic. There is no product UI for it today.

**You need a registered, funded `family` account.** The extrinsic is
`ComputeScoring::register_child(family, child, node_id, node_sig)` and
it requires `ensure_signed(origin) == family` and
`is_registered_family(family)`. This is the one prerequisite you cannot
generate yourself — see below.

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

Requires `pip install substrate-interface`. `--dry-run` composes the
call without submitting; use it first.

The signature is over a domain-separated message
(`HIPPIUS_COMPUTE_NODE_REG_V1` ‖ family ‖ child ‖ node_id ‖ nonce), so a
signature captured from one registration cannot be replayed into
another. The pallet enforces child/node_id uniqueness, per-family and
global caps, and cooldowns on re-registration.

**Deposit.** The first `FreeChildSlotsPerFamily` registrations per
family are free. Beyond that a global deposit is reserved that
**doubles** with each paid registration and halves back down over time.
Plan your family's slots accordingly.

On success the node's status is `Active`. Status is stored sparsely —
only non-default statuses are written — so *absent* means `Active`. The
three states are `Active`, `Quarantined`, `Decommissioned`.

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

### Oversubscription

| resource | oversubscribable | why |
|---|---|---|
| RAM | **no** | an SNP guest's memory is encrypted and pinned (`memfd` backing, required so KVM can map the GHCB). No ballooning, no swap, no page sharing — the hypervisor can neither move nor dedupe those pages. Not a policy choice. |
| vCPU | not today | vCPUs are threads and time-sharing would work, but admission takes `min(slots_RAM, slots_CPU)` so neither dimension is oversubscribed. A policy knob, not a wall. |
| disk | **already** | overlays and data disks are created *sparse*: a 256 GiB flavor consumes what it writes. A `statvfs` check runs before dispatch, so a full host is refused up front rather than hitting `ENOSPC` mid-format inside the guest. |

The practical consequence: **RAM is what bounds how many VMs your host takes.**
Buying cores without RAM will not raise your slot count.

## 6. The step people miss: being *schedulable*

Passing admission and heart-beating is **not** enough to receive
tenant workloads.

vali's auto-provision path records `platform_id = "onchain"` — a
placeholder, not a chip id. The scheduler requires a **real** hex
`platform_id`, a non-null `chain_node_id`, a non-null mesh IP, local
status `ACTIVE`, and a recent heartbeat. A node with the placeholder
passes every other gate and silently never gets chosen.

Close it with one call, using the values from §5 steps 2 and 3:

```sh
curl -sf -X POST "<VALI_URL>/v1/admin/miner/register" \
    -H "Authorization: Bearer <MINER_ADMIN_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
          "miner_id":     "<MINER_ID>",
          "pubkey_hex":   "<NODE_ID_64_HEX>",
          "platform_id":  "<AMD_CHIP_ID_HEX>",
          "netbird_peer_id": "<PEER_ID>",
          "netbird_ip":   "<MESH_IP>"
        }' | jq
```

Re-posting the same `(miner_id, pubkey_hex, platform_id)` triple is
idempotent (`200`); a collision with a different miner is `409`. See
[`vali/apps/miners/README.md`](../../vali/apps/miners/README.md) for the
admin token and the quarantine/list endpoints.

The bootstrap prints exactly this block at the end of play 05, filled
in with the real values — keep that output.

---

## What you cannot self-supply

These come from whoever runs the fleet's control plane. If you are
standing up your own fleet, you generate them; if you are joining
someone else's, you must be given them:

| Item | Why |
|---|---|
| A registered, funded **family account** on chain | `register_child` fails with `FamilyNotRegistered` without one, and the deposit must come from somewhere |
| A **`pallet_proxy` delegation** from that family to your child account | `register_child` gates on `ProxyVerifier::can_register_child`; without it the extrinsic fails `ProxyVerificationFailed` — *after* you have already produced the `node_sig`. `NonTransfer` with `delay = 0` is enough (the check does not filter on proxy type), and it can be removed once the registration is in a block, since nothing reads the gate afterwards |
| A **NetBird setup key** bound to the miner group, on the fleet's NetBird instance | A key from a different NetBird instance fails to log in |
| The **Edge server CA** certificate | The agent verifies the Edge's server certificate against it |
| `edge_order_signing_pubkey` | Every lifecycle order is `verify_strict`ed against it; a wrong key means every order is rejected |
| The **Edge endpoint**, **KBS endpoint** and **image object store** | Nothing resolves without them |
| A **vali miner-admin token** | Only for the §6 call above |

Note that none of these lets the fleet operator read your tenants' data,
and none of them is a certificate authority over your identity. They are
routing and mesh membership. Your node key stays yours.

## Leaving

Do not just power off. A miner that stops heart-beating strands the VMs
it hosts. Use the graceful-exit path so vali migrates tenants off first,
and request unstake on chain. See
[`stranded-migration-runbook.md`](./stranded-migration-runbook.md) for
what to do if a migration gets stuck part-way.

## See also

- [`deploy/ansible/README.md`](../../deploy/ansible/README.md) — the bootstrap in operator terms
- [`deploy/register-miner/README.md`](../../deploy/register-miner/README.md) — full on-chain registration flow
- [`binaries/miner-agent/README.md`](../../binaries/miner-agent/README.md) — storage layout, pointing tenant data at dedicated NVMe
- [`docs/design/permissionless-miner-auth.md`](../design/permissionless-miner-auth.md) — why there is no operator CA
- [`docs/security/data-visibility.md`](../security/data-visibility.md) — what you, as the host operator, can and cannot see
