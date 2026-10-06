# BYO base-OS bake runbook

End-to-end operator procedure to bake a Hippius-ready encrypted
qcow2 from a vanilla cloud image — **Ubuntu, Debian 12/13, CentOS
Stream 10, or Fedora 43** — suitable for launch in a SEV-SNP CVM
under the existing miner-agent / ticket-validator chain.

> **Multi-OS status (2026-06-12): all four families LIVE-VERIFIED on
> a Genoa host.** Each bakes → SNP-attested boot → in-initramfs KBS release
> → LUKS2+dm-integrity unlock → enforcing SELinux (RHEL) → encrypted
> `/data` → reboot-persisting Phase 2B counter. The Debian family
> (Ubuntu/Debian) unlocks via the `initramfs-tools` `keyscript=`; the
> RHEL family (CentOS/Fedora) via the dracut `90hippius-luks` keyfile
> module. The bake auto-detects the distro from `/etc/os-release`
> (`--distro <id>` asserts it) and dispatches apt-vs-dnf,
> initramfs-tools-vs-dracut, and ext4-vs-xfs-vs-btrfs source roots.
> A nightly `tenant-bake-e2e.yml` CI matrix re-bakes all five images
> and asserts the LUKS2+integrity header. See the per-distro catalogue
> + RHEL-family notes below.

This runbook replaces the abandoned custom-Rust-initramfs
`hippius.handoff=tenant-luks` pivot (issue #257). The architectural
shift is: **don't try to substitute for `udev` from a custom
initramfs** — instead, inject the Hippius release tooling into the
tenant distro's own initramfs (which already has udev,
cryptsetup-initramfs, systemd-cryptsetup, and the correct kernel /
.ko version pin). Pattern adapted from
[`thenervelab/hccs::hcc-image-builder`](https://github.com/thenervelab/hccs).

## TL;DR

```bash
# 1. Cross-build the two binaries the tenant initramfs needs.
docker run --rm --platform linux/amd64 \
    -v $(pwd):/src -w /src \
    hippius-tenant-uki-builder:0.0.1-tenant \
    bash -lc 'cargo build --release \
        --bin hippius-guest-release \
        --bin hippius-vsock-ticket \
        --target x86_64-unknown-linux-gnu'

# 2. Bake the qcow2. Pipe the 32-byte LUKS KEK on stdin.
cat /run/user/$(id -u)/luks-kek-${VM}.bin | sudo scripts/tenant-image-bake.sh \
    --base-image-url https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img \
    --base-image-sha256 0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe \
    --hippius-release-bin target/x86_64-unknown-linux-gnu/release/hippius-guest-release \
    --hippius-vsock-bin    target/x86_64-unknown-linux-gnu/release/hippius-vsock-ticket \
    --kbs-url              https://kbs.hippius.network \
    --output-dir           out/tenant-bake

# 3. Upload the three output files (qcow2 + kernel + initrd) to S3,
#    then call vali_create_vm — it dispatches a `tenant-preflight`
#    order so the miner-agent fetches via short-TTL presigned URLs
#    + sha-verifies. No operator-to-miner SSH required.
```

## Architecture

```
            ┌──────────────────────────────────────────────┐
            │  Operator workstation (run this runbook)     │
            │                                              │
            │   tenant-image-bake.sh                       │
            │      ├─ curl Ubuntu cloud-image (sha-gated)  │
            │      ├─ qemu-img convert qcow2 → raw         │
            │      ├─ losetup --partscan                   │
            │      ├─ mount root partition                 │
            │      ├─ chroot:                              │
            │      │     apt install                       │
            │      │       cryptsetup-initramfs            │
            │      │       initramfs-tools                 │
            │      │       linux-image-generic             │
            │      │       udhcpc isc-dhcp-client          │
            │      │     drop /etc/hippius/...keyscript    │
            │      │     drop /etc/initramfs-tools/hooks/  │
            │      │            hippius-luks               │
            │      │     install /usr/sbin/                │
            │      │            hippius-guest-release      │
            │      │            hippius-vsock-ticket       │
            │      │     update-initramfs -u -k <kver>      │
            │      ├─ unmount + losetup -d                 │
            │      ├─ cryptsetup luksFormat output raw     │
            │      ├─ dd customised root → mapper          │
            │      └─ qemu-img convert raw → qcow2         │
            │                                              │
            │   Outputs:                                   │
            │      out/tenant-bake/tenant-<sha>.qcow2      │
            │      out/tenant-bake/tenant-<sha>.vmlinuz    │
            │      out/tenant-bake/tenant-<sha>.initrd.img │
            │      out/tenant-bake/tenant-<sha>.measurement│
            └────────────────────┬─────────────────────────┘
                                 │ aws s3 cp (upload by operator)
                                 │ → vali_create_vm dispatches a
                                 │   `tenant-preflight` order; the
                                 │   miner downloads via short-TTL
                                 │   presigned URLs + sha-verifies
                                 ▼
            ┌──────────────────────────────────────────────┐
            │  Miner (libvirt + miner-agent)               │
            │                                              │
            │  SEV-SNP launch:                             │
            │    -kernel  tenant-<sha>.vmlinuz             │
            │    -initrd  tenant-<sha>.initrd.img          │
            │    -append  "ro                              │
            │              ds=nocloud;s=/run/cloud-init/seed/│
            │              hippius.kbs_url=…               │
            │              hippius.luks_device=/dev/vda"   │
            │    -drive   tenant-<sha>.qcow2               │
            │                                              │
            │  Boot path:                                  │
            │    Hippius-measured kernel boots             │
            │      → tenant distro initramfs               │
            │         (with udev + cryptsetup-initramfs)   │
            │      → systemd-cryptsetup invokes the        │
            │         keyscript=/sbin/hippius-luks-keyscript│
            │      → keyscript:                            │
            │         · static-net libvirt NAT             │
            │         · pull COSE ticket from vsock        │
            │         · hippius-guest-release CLI          │
            │             · X25519 keygen                  │
            │             · /v1/kbs/nonce                  │
            │             · /dev/sev-guest ioctl           │
            │             · /v1/kbs/release                │
            │             · verify_and_unwrap_release      │
            │             · write user-data → /run/        │
            │                 cloud-init/seed/user-data    │
            │             · write KEK to stdout            │
            │      → cryptsetup-initramfs reads KEK,       │
            │         crypt_activate_by_passphrase         │
            │         (udev creates /dev/mapper/cryptroot  │
            │         CORRECTLY — no ENOENT)               │
            │      → mount /dev/mapper/cryptroot           │
            │      → switch_root (mount --move /run)       │
            │      → cloud-init reads NoCloud seed         │
            │         from tmpfs /run/cloud-init/seed/     │
            │         (KBS-released; NEVER on disk)        │
            │         → NetBird up, SSH key, …             │
            └──────────────────────────────────────────────┘
```

## Prerequisites

| What | Why |
|---|---|
| Linux operator workstation with sudo | The bake needs `qemu-nbd / losetup / cryptsetup / chroot`. macOS dev boxes don't work — use a Linux VM. |
| `qemu-utils + cryptsetup-bin + jq + curl + sha256sum + coreutils` | The bake script's tooling check fails-fast if any are missing. |
| Pinned `tenant-uki` Docker image | Cross-builds `hippius-guest-release` + `hippius-vsock-ticket` to match the cloud image's glibc + the operator-workstation libc. Run `make -C packer/tenant-uki/uki docker-build` once. |
| 32-byte LUKS KEK already staged in Vault for the target VM | The bake uses the same `secret/hippius-compute/kbs/tenants/<vm-id>/luks-kek` path that `tenant-secrets-stage.sh` writes. Stage it first. |
| Cloud image URL + sha256 | See the per-distro catalogue below. |

## Supported base images (multi-OS series)

The bake auto-detects the distro from the image's `/etc/os-release`
(`--distro <id>` asserts it). The Debian family (Ubuntu/Debian) uses
the initramfs-tools `keyscript=` unlock; the RHEL family (CentOS
Stream/Fedora — PR6/PR7 of the series) uses the dracut
`90hippius-luks` keyfile unlock.

### The `base_image_url` MUST be immutable

`base_image_sha256` pins exact bytes. A path segment like `latest/`,
`current/` or `daily/` pins "whatever upstream published most recently".
The two are **contradictory**: the pair works right up until upstream cuts
a point release, and then the integrity check fails in a way that is
indistinguishable from a supply-chain compromise. That ambiguity is the
expensive part — it once cost this programme three cycles of treating a
routine Debian point release as a possible attack while the bytes we had
already vetted sat unchanged at the dated URL the whole time.

So vali **refuses** a bake whose `base_image_url` carries a moving path
segment, at intake, before anything is fetched (`400 bad-field`). Every
mirror below keeps each release in a dated, immutable directory — use
that. If a hash stops matching an *immutable* URL, then and only then is
it a real supply-chain event.

| Distro | Image (immutable — `latest/`/`current/` are refused at intake) | sha256 |
|---|---|---|
| Ubuntu 24.04 | `https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img` | `0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe` |
| Debian 12 | `https://gemmei.ftp.acc.umu.se/images/cloud/bookworm/<YYYYMMDD-BUILD>/debian-12-genericcloud-amd64-<YYYYMMDD-BUILD>.qcow2` | Debian publishes `SHA512SUMS` only — `sha256sum` the downloaded image and pin that |
| Debian 13 | `https://gemmei.ftp.acc.umu.se/images/cloud/trixie/20260712-2537/debian-13-genericcloud-amd64-20260712-2537.qcow2` | `2cab162ddebb1ef083cca8f8261f77c93ae70f98252aabfeb1d8a28c30b191b1` |
| CentOS Stream 10 | `https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-20260713.0.x86_64.qcow2` | `8540c746bb52575455220bbce36ab7093d893d53401a16383867470a69734e80` |
| Fedora 43 | `https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2` | `846574c8a97cd2d8dc1f231062d73107cc85cbbbda56335e264a46e3a6c8ab2f` |

Rotating any row is a normal operation: take the next dated directory, take
its checksum, bake. Note `cloud.debian.org` and `download.fedoraproject.org`
are **redirectors**, and the baker's SSRF guard forbids redirects by design
(`curl: (47) Maximum (0) redirects followed`) — point at a direct mirror
(`gemmei.ftp.acc.umu.se`, `dl.fedoraproject.org`) rather than relax the guard.

Debian notes: the genericcloud image PRE-INSTALLS a `-cloud-` kernel
that lacks `sev-guest`/`tsm`; the bake installs the FULL
`linux-image-amd64` and filters `-cloud-` out of every kernel
selection — the `verify_required_modules` gate enforces it. The launch
cmdline is identical to Ubuntu's (same keyscript model).

CentOS Stream 10 / RHEL-family notes: the root fs is **XFS** — the bake
copies it to an **ext4** output via `mkfs.ext4` + `rsync -aHAXS`
(preserves `security.selinux` labels; PR5). Unlock uses the dracut
`90hippius-luks` module (dracut has no `keyscript=`): a
`Before=cryptsetup-pre.target` pre-unit runs the SAME §21 release core
the Debian keyscript does and writes the KEK to the tmpfs keyfile
`/run/hippius/kek` that the baked `/etc/crypttab` names. The bake
installs `kernel-modules{,-extra}` (sev-guest) + `dracut{,-network}` +
`cryptsetup`, then `setfiles`-relabels the bake-written trees (falling
back to `.autorelabel` if the policy isn't present) so the data-disk
service starts under enforcing SELinux. **The launch cmdline differs
from the Debian family**: drop the initramfs-tools `cryptopts=…
keyscript=` token entirely (dracut reads the baked crypttab), and add
`rd.luks=1`:

```
--cmdline 'console=ttyS0,115200 console=tty0 earlyprintk=ttyS0 loglevel=7 \
    ro root=/dev/mapper/cryptroot rd.luks=1 \
    hippius.luks_header_sha256=<hex> hippius.kbs_url=<url> hippius.vm_id=<id> \
    ds=nocloud;s=/run/cloud-init/seed/'
```

CS10 requires an `x86-64-v3` CPU; the miner launches with QEMU
host-passthrough on EPYC Genoa so this is satisfied (documented for
operators baking on older dev boxes — the bake itself only runs static
musl binaries + container tools, so the workstation CPU level is moot).

## §20 secret discipline

- The LUKS KEK enters the bake script as **stdin only** (`--kek-source stdin`, default) or via `--kek-file PATH` (the file is read once, never copied). It NEVER lands in argv, an env var, or a temp file.
- The chroot phase customises plaintext but writes NO credentials. The customised root is `dd`'d into the LUKS-encrypted output qcow2 in step 6; the unencrypted intermediate raw is `unlink`'d on every exit path (the `cleanup` trap).
- The output qcow2 has **no plaintext credentials**. The keyscript at boot fetches the KEK from the KBS over the static-IP libvirt-NAT network; nothing is baked into the image except the CLI tooling.
- **Cloud-init user-data is KBS-released** through the same §21 envelope as the LUKS KEK (the bake script does not write any NoCloud seed onto the rootfs). The keyscript hands the unwrapped bytes to `hippius-guest-release --userdata-out /run/cloud-init/seed/user-data` BEFORE shipping the KEK; on a user-data write failure the binary fail-closes WITHOUT releasing the KEK, leaving the disk locked. `/run` is tmpfs (RAM), so user-data NEVER touches persistent storage — encrypted or otherwise. `mount --move /run` across `switch_root` carries the seed dir into the booted rootfs's namespace; the cmdline token `ds=nocloud;s=/run/cloud-init/seed/` points cloud-init's NoCloud datasource at it.

## Step-by-step

### 1. One-time: cross-build the two binaries

`hippius-guest-release` + `hippius-vsock-ticket` must match the tenant cloud image's userland (glibc ABI, ld.so path). The `tenant-uki` Docker image pins Debian Trixie 6.12 + the same glibc the noble cloud image ships, so a cross-build inside that container produces bytes that the Ubuntu initramfs can `copy_exec` cleanly:

```bash
cd <repo-root>
make -C packer/tenant-uki/uki docker-build   # one-time
docker run --rm --platform linux/amd64 \
    -e CARGO_TARGET_DIR=/build/target \
    -v $(pwd):/src -v $(pwd)/target-cross:/build/target \
    -w /src \
    hippius-tenant-uki-builder:0.0.1-tenant \
    bash -lc 'cargo build --release \
        --bin hippius-guest-release \
        --bin hippius-vsock-ticket \
        --target x86_64-unknown-linux-gnu'
```

Output: `target-cross/x86_64-unknown-linux-gnu/release/hippius-{guest-release,vsock-ticket}`.

### 2. Bake the qcow2

`tenant-image-bake.sh` is the operator-facing tool. From the repo root:

```bash
cd <repo-root>

export VAULT_ADDR=https://<YOUR_VAULT_HOST>:8200
export VAULT_TOKEN=$(cat ~/.vault-token)
export VAULT_CACERT=$PWD/vault-ca.crt

VM=tenant-pra-1   # set to your real vm_id

# Pipe the KEK from Vault straight into the bake script's stdin.
vault kv get -format=json -mount=secret \
    hippius-compute/kbs/tenants/${VM}/luks-kek \
  | jq -r '.data.data.value' \
  | base64 -d \
  | sudo --preserve-env=PATH \
      scripts/tenant-image-bake.sh \
        --base-image-url \
            https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img \
        --base-image-sha256 \
            0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe \
        --hippius-release-bin \
            target-cross/x86_64-unknown-linux-gnu/release/hippius-guest-release \
        --hippius-vsock-bin \
            target-cross/x86_64-unknown-linux-gnu/release/hippius-vsock-ticket \
        --kbs-url \
            https://kbs.hippius.network \
        --output-dir \
            out/tenant-bake/${VM}
```

Output (single-line JSON on stdout):

```json
{
  "qcow2_path": "out/tenant-bake/tenant-pra-1/tenant-53fdde898fee.qcow2",
  "qcow2_sha256": "<64 hex>",
  "qcow2_size_bytes": <N>,
  "base_image_url": "https://...",
  "base_image_sha256": "53fdde898fee...",
  "kbs_url": "https://kbs.hippius.network",
  "kernel_sha256": "<64 hex>",
  "initrd_sha256": "<64 hex>",
  "luks_version": 2,
  "luks_pbkdf": "pbkdf2"
}
```

### 3. Upload to S3 + dispatch via `vali_create_vm`

The bake produces three files. Upload them to the operator's S3 bucket
under a stable per-image prefix; vali's `tenant-preflight` order will
generate short-TTL presigned URLs for each one, the miner downloads +
sha-verifies + stages them, and vali pins the resulting SNP
launch_digest into the §22 allowlist + the OrderTicket — all in a
single management command (see `docs/operator/vali-create-vm-runbook.md`
for the full breakdown).

```bash
# 1. Upload the baked artefacts to the operator's S3 bucket. The keys
#    MUST be `tenant.{qcow2,vmlinuz,initrd.img}` under a per-image
#    prefix — that's the shape `services.preflight.dispatch_preflight`
#    consumes.
export AWS_ACCESS_KEY_ID=...       # operator-tier writer creds
export AWS_SECRET_ACCESS_KEY=...
export S3_BUCKET=hippius-compute-images
export S3_KEY_PREFIX=tenant/${VM}/

aws --endpoint-url https://s3.hippius.com s3 cp \
    out/tenant-bake/${VM}/tenant-<sha>.qcow2 \
    s3://${S3_BUCKET}/${S3_KEY_PREFIX}tenant.qcow2
aws --endpoint-url https://s3.hippius.com s3 cp \
    out/tenant-bake/${VM}/tenant-<sha>.vmlinuz \
    s3://${S3_BUCKET}/${S3_KEY_PREFIX}tenant.vmlinuz
aws --endpoint-url https://s3.hippius.com s3 cp \
    out/tenant-bake/${VM}/tenant-<sha>.initrd.img \
    s3://${S3_BUCKET}/${S3_KEY_PREFIX}tenant.initrd.img

# 2. Read the per-file sha256s back out of the bake's measurement.json.
QCOW_SHA=$(jq -r .qcow2_sha256 out/tenant-bake/${VM}/tenant-<sha>.measurement.json)
KERN_SHA=$(jq -r .kernel_sha256 out/tenant-bake/${VM}/tenant-<sha>.measurement.json)
INIT_SHA=$(jq -r .initrd_sha256 out/tenant-bake/${VM}/tenant-<sha>.measurement.json)

# 3. Dispatch — vali_create_vm does Vault stage + preflight (miner-side
#    fetch + sha verify + SNP launch_digest compute) + §22 allowlist
#    auto-pin via kbs-admin /v1/admin/allowlist/reload + ticket mint +
#    kbs-admin register + launch dispatch, all in one command.
kubectl -n vali exec deploy/vali -- python manage.py vali_create_vm \
    --tenant-id     ${TENANT} \
    --user-id       ${USER_ID} \
    --vm-id         ${VM} \
    --lease-id      ${LEASE_ID} \
    --miner-id      <MINER_ID> \
    --platform-id   <CHIP_ID hex> \
    --userdata-file /tmp/cloud-init.yaml \
    --s3-bucket     ${S3_BUCKET} \
    --s3-key-prefix ${S3_KEY_PREFIX} \
    --luks-disk-sha256-hex ${QCOW_SHA} \
    --kernel-sha256-hex    ${KERN_SHA} \
    --initrd-sha256-hex    ${INIT_SHA} \
    --cmdline 'console=ttyS0,115200 console=tty0 earlyprintk=ttyS0 loglevel=7 \
        ro root=/dev/mapper/cryptroot \
        cryptopts=target=cryptroot,source=/dev/vda,luks,keyfile-size=32,keyscript=/sbin/hippius-luks-keyscript \
        ds=nocloud;s=/run/cloud-init/seed/ \
        hippius.kbs_url=https://kbs.hippius.network hippius.luks_device=/dev/vda' \
    --flavor small \
    --auto-pin-allowlist
```

`--flavor small` resolves to `(1 vCPU, 2048 MiB RAM, 8 GiB disk)`
via the `hippius_types::flavor::Flavor` enum (#312); the canonical
flavor name also becomes the ticket's `resource_class` field. For
ad-hoc launches outside the catalogue, pass `--cpu-count` +
`--memory-mb` directly (mutually exclusive with `--flavor`).

#### Legacy path (deprecated): manual `scp` + `vali_dispatch_launch`

The historical flow scp'd artefacts to the miner manually and called
`vali_dispatch_launch` directly with an operator-pre-minted ticket. It
still works (the launch order shape hasn't changed), but it requires
the operator to run `hippius-miner-agent launch-test --digest-only` on
the miner for `--measurement-hex` AND to re-pin the §22 allowlist
manually. Prefer `vali_create_vm` unless you're debugging a specific
stage.

### 4. Observe the boot

```bash
ssh <user>@<miner> 'sudo tail -f /tmp/serial.log'
```

You should see (in order):

```
[    0.xxxxxx] Linux version 6.12.x… (the kernel from the baked qcow2)
…
Begin: Loading essential drivers ...
Begin: Running /scripts/init-premount ...
Begin: Mounting root file system ...
Begin: Running /scripts/local-top ...
hippius-luks-keyscript: bringing up network (DHCP on first ethernet)
hippius-luks-keyscript: DHCP lease acquired on eth0
hippius-luks-keyscript: KBS URL: https://kbs.hippius.network
hippius-luks-keyscript: ticket loaded from vsock (NNN bytes)
hippius-guest-release: (no fail-closed line ⇒ success)
hippius-luks-keyscript: KEK released; cryptsetup will now attempt activation
…
cryptsetup: setting up cryptroot
…
Begin: Mounting root file system ... done.
[  xx.xxxxxx] systemd[1]: Welcome to Ubuntu 24.04.x LTS!
…
Ubuntu 24.04.x LTS tenant-pra-1 ttyS0
tenant-pra-1 login:
```

The `mount-rootfs:ENOENT` we saw with the legacy custom-Rust-initramfs path is gone: the tenant distro initramfs has udev, and udev creates `/dev/mapper/cryptroot` as a proper symlink that `mount(2)` resolves cleanly.

### 5. Connect via NetBird

The intended path: cloud-init in the booted tenant reads the NoCloud seed the keyscript wrote to tmpfs `/run/cloud-init/seed/user-data` (the unwrapped KBS-released bytes per §21), installs NetBird, and joins the mesh.

For that to actually happen, the operator must (a) use a userdata template that wires NetBird and (b) pass `--enable-netbird` to `vali_create_vm` so vali mints the per-tenant setup-key and substitutes it into the template before stashing in Vault.

The shipped template lives at `docs/operator/userdata-templates/netbird-enabled.yaml.example`. It carries the literal placeholder `{{NETBIRD_SETUP_KEY}}` that vali substitutes in-memory (#306).

```bash
# 1. Copy the template + customise (ssh key, password, etc.)
cp docs/operator/userdata-templates/netbird-enabled.yaml.example \
   /tmp/tenant-userdata.yaml

# 2. Dispatch with --enable-netbird (vali mints the key automatically)
vali_create_vm \
    ...                                                                \
    --userdata-file /tmp/tenant-userdata.yaml                          \
    --enable-netbird                                                   \
    --netbird-group <group-uuid>                                       \
    --netbird-key-ttl-seconds 3600                                     \
    --netbird-hostname-template 'hippius-tenant-{vm_id}'               \
    ...

# 3. Connect — from your workstation (already on the NetBird mesh).
#    Log in as the image's DEFAULT user, not a hardcoded `ubuntu`:
#    `ubuntu` on Ubuntu, `cloud-user` on CentOS Stream / RHEL,
#    `debian` on Debian, `fedora` on Fedora (the `users: - default`
#    in the userdata template keys exactly that account).
ssh <default-user>@hippius-tenant-<vm-id>.hippius.decentralized
# or
ssh <default-user>@<tenant-100.x.y.z>

# 4. Inside the VM — confirm the seed came from KBS-released tmpfs,
#    NOT from a bake-time-injected on-disk seed:
test -s /run/cloud-init/seed/user-data && echo "tmpfs seed present"
test ! -s /var/lib/cloud/seed/nocloud/user-data && echo "no on-disk seed"
mount | grep '/run ' | head -1   # should show tmpfs
```

If `--enable-netbird` is omitted, the tenant boots without NetBird; reach it only via jumphost through the miner host (`ssh -J ubuntu@<miner> <default-user>@192.168.122.X`, where `<default-user>` is the tenant image's default account — `cloud-user` on CentOS, `ubuntu` on Ubuntu, etc.; the `ubuntu@<miner>` hop is the Ubuntu miner host).

## Troubleshooting

| Serial symptom | Cause | Fix |
|---|---|---|
| `hippius-luks-keyscript: FATAL: static-net: ip addr failed` | libvirt NAT not up, virtio_net not in initrd | Verify miner's libvirt default network is started; rebake to confirm the keyscript's `STATIC_IP` (default `192.168.122.253/24`) doesn't collide with another libvirt guest. |
| `hippius-guest-release: fail-closed: snp-device-failed:open-failed` | `/dev/sev-guest` not exposed by host kernel | Confirm SEV-SNP is enabled on the host (`dmesg \| grep sev`). The bake script doesn't gate this — it's a miner-side check. |
| `hippius-guest-release: fail-closed: kbs-failed:kbs-connect` | KBS unreachable from libvirt NAT | Same routing issue the legacy `agent-initramfs` hit (#257 session); confirm `kbs.hippius.network` resolves to a routable IP from inside libvirt NAT. |
| `hippius-guest-release: fail-closed: kbs-denial` | §22 allowlist doesn't contain this tenant's launch_digest | Re-pin the KAT to include the new kernel+initrd+cmdline measurement — see `test_vectors/uki/REGENERATE.md`. |
| `hippius-guest-release: fail-closed: userdata-out:permission-denied` | tmpfs /run not yet mounted / wrong perms when keyscript ran | Should not happen — initramfs-tools mounts /run early. If it does, an operator script is racing the keyscript. |
| `hippius-guest-release: fail-closed: binding:userdata-digest-mismatch` | Vault user-data bytes differ from the digest the ticket COSE asserts | The validator must recompute `allowed_userdata_digest_hex` from the SAME bytes it stages in Vault, then re-mint the ticket. Mismatch = stale stage or stale mint. |
| `cryptsetup: cryptsetup failed, bad password or options?` | KEK delivered ≠ KEK provisioned at bake time | Pipe the same Vault path you piped into `tenant-secrets-stage.sh`. The Vault value is the source of truth. |
| Guest boots, no SSH key / no NetBird | Cmdline missing `;s=/run/cloud-init/seed/` so cloud-init couldn't find the seed | Confirm the dispatch cmdline has `ds=nocloud;s=/run/cloud-init/seed/` and that the keyscript wrote `/run/cloud-init/seed/user-data` (visible in `cloud-init logs collect`). |

## Trust model

| Layer | Anchor |
|---|---|
| The kernel + initramfs are in the launch_digest | the §22 allowlist gates which `{OVMF + kernel + initrd + cmdline}` tuples may receive a KEK. Per-tenant rebakes shift this measurement; re-pin in lockstep. |
| The keyscript binaries are integrity-bound to the initramfs | `update-initramfs` regenerates the initramfs cpio at bake time. Any tamper post-bake shifts the initrd sha → launch_digest → KBS denies release. |
| The LUKS KEK never lives on the miner | The KEK enters the encrypted volume from KBS at every boot. The miner sees ciphertext on disk + the KEK only inside the SEV-SNP guest RAM. |
| The tenant rootfs is encrypted at rest | LUKS2 / pbkdf2 (random 256-bit KEK — KDF hardness moot) / aes-xts-plain64 + dm-integrity `hmac(sha256)`; `--integrity hmac-sha256` ensures any miner-side ciphertext bit-flip is caught with EIO at the integrity layer rather than passing attacker-controlled plaintext through to the guest. |
| **The LUKS2 header is authenticated against the launch_digest (#296)** | The bake computes `sha256(luks_header_bytes)` via `cryptsetup luksHeaderBackup` and emits it in `measurement.json`. Vali binds the digest into the kernel cmdline (`hippius.luks_header_sha256=<hex>`), so any pre-launch header swap shifts the launch_digest → §22 allowlist denies KEK release. The keyscript ALSO re-verifies post-launch using the detached-header pattern: `luksHeaderBackup` copies the header to tmpfs (guest-private memory under SEV-SNP), the COPY's SHA is verified against the cmdline value, `/etc/crypttab`'s `header=/run/hippius/luks.header` directs cryptsetup to open against the verified copy (closing the TOCTOU window). Closes the CVE-2025-59054 / CVE-2025-58356 family Trail of Bits documented for CVMs. |
| Cloud-init user-data never lives on the miner | The validator stages user-data in Vault + binds the digest into the COSE ticket; KBS HPKE-wraps and ships it in the §21 release envelope; the keyscript unwraps it to tmpfs `/run/cloud-init/seed/` inside the SEV-SNP guest. Miner sees ciphertext on the wire and nothing on disk. Bytes are protected by guest memory encryption from there on. |

## Known gaps

- ~~**AES-XTS integrity** is not yet enabled (`--integrity hmac-sha256`).~~ **Closed** — `scripts/tenant-image-bake.sh` now passes `--integrity hmac-sha256` to `cryptsetup luksFormat`. Every 512-byte sector carries a 32-byte HMAC tag the guest re-verifies on read; a miner-side bit-flip surfaces as EIO instead of attacker-controlled plaintext. Cost: ~7 % capacity + format-time wipe (~2 min/16 GiB on NVMe) + ~10 % IOPS at runtime. Verify per-tenant after a bake with `cryptsetup luksDump <out_raw> | grep -i integrity` — expect `integrity: hmac(sha256)`.
- ~~**LUKS2 header authentication**.~~ **Closed by #296** — `measurement.json` now emits `luks_header_sha256`; `vali_create_vm --luks-header-sha256-hex` binds it into the kernel cmdline (`hippius.luks_header_sha256=<hex>`, covered by `launch_digest`); the keyscript verifies via the detached-header pattern (`luksHeaderBackup` to tmpfs, SHA-compare the copy, `cryptsetup open --header /run/hippius/luks.header`). Closes CVE-2025-59054 / CVE-2025-58356 family at the keyscript layer regardless of cryptsetup version. Independent gaps still tracked: **#297** (disk anti-rollback), **#298** (cryptsetup ≥ 2.8.1 pin for defence in depth).
- **Per-tenant SEV-SNP launch_digest** is not yet machine-published. The bake step writes `tenant-<sha>.measurement.json` with kernel + initrd sha256, but the operator must manually re-pin the §22 allowlist after each bake. Closing this is part of the §263 follow-up.
- **Per-launch ticket plumbing in the miner-agent** still has rough edges. The `hippius-vsock-ticket` CLI does exist (`binaries/vsock-ticket`, wraps the same `stages::ticket_vsock` receiver the legacy agent-initramfs used), but the miner-agent's `vsock::ticket_push` path has only been wired for the managed-rootfs handoff so far — for the BYO bake smoke you can short-circuit it with `hippius.ticket_path=/some/pre-staged.cose` on the kernel cmdline.
- **Per-tenant cloud-init user-data lifecycle.** PR #264 wires KBS-released user-data delivery via `hippius-guest-release --userdata-out`; the validator still has to manually run `tenant-secrets-stage.sh --userdata-file` + recompute `allowed_userdata_digest_hex` for the ticket COSE before every dispatch. The "stage + mint together" CLI is a §263 follow-up.

## Bake operator — trust anchor (issue #284)

The HCCS-style bake (`scripts/tenant-image-bake.sh`) shifted a piece of
the TCB that the legacy custom-Rust path didn't have: **whoever runs the
bake mints the launch_digest the §22 allowlist will then accept**. If
the bake produces a malicious initramfs (one that exfiltrates the
released LUKS KEK to disk or the network the moment cryptsetup-initramfs
hands it over), the resulting boot is indistinguishable from a clean
boot to anyone outside the bake workstation — same OVMF, same kernel,
same cmdline, same launch_digest, same allowlist entry. The miner can't
tell the difference. KBS can't tell the difference. Only the bake
operator's environment can.

In other words: **the bake operator is part of the TCB. The bake
workstation is part of the TCB.** This is structurally distinct from
the rest of the trust chain (which derives from AMD's silicon root +
§22's offline ceremony key) and deserves its own discipline.

### What the bake operator must guarantee

1. **The workstation is clean.** No other tenants' data on disk. No
   software that didn't come from a trusted distro repository. Ideally
   air-gapped during the bake itself (the bake fetches the upstream
   cloud image — air-gap only after that fetch completes, then run the
   bake offline).
2. **The bake script is what's in `main`.** Run `git status` + `git log
   HEAD..origin/main` before invoking the bake — uncommitted local edits
   or out-of-tree commits CAN change the initramfs without changing
   anything visible in the runbook output.
3. **The cross-built `hippius-guest-release` + `hippius-vsock-ticket`
   binaries are reproducible.** Build them inside the pinned
   `tenant-uki` Docker image (see § "Prerequisites"), not from a host
   `cargo build`. The Docker image's pinned glibc + pinned Rust
   toolchain are what make the binary SHAs stable.
4. **The §F dev signing key (and any future bake-output signing key) is
   on this same trusted workstation** and not extractable to other
   machines.

### Two-operator cross-verification (for paying tenants)

For tenants where the launch_digest claim is the price-premium
justification, run the bake on **two independent clean workstations**
and confirm the output `tenant-<sha>.qcow2.sha256`,
`tenant-<sha>.vmlinuz.sha256`, and `tenant-<sha>.initrd.img.sha256`
match byte-for-byte before adding the measurement to the §22
allowlist. Mechanics:

```bash
# Operator A — clean workstation. Produces:
#   out/tenant-bake-A/tenant-<sha>.{qcow2,vmlinuz,initrd.img}{,.sha256}
sudo scripts/tenant-image-bake.sh \
    --base-image-url        https://... --base-image-sha256 ... \
    --hippius-release-bin   target/.../hippius-guest-release \
    --hippius-vsock-bin     target/.../hippius-vsock-ticket \
    --source-date-epoch     1730000000 \
    --output-dir            out/tenant-bake-A < kek.bin

# Operator B — different clean workstation. SAME `--source-date-epoch`.
# Produces out/tenant-bake-B/...

# Compare on a third machine that has neither's bake history.
sha256sum out/tenant-bake-A/*.sha256 out/tenant-bake-B/*.sha256
diff -ru out/tenant-bake-A/*.sha256 out/tenant-bake-B/*.sha256
# Only when ALL THREE sha256 files match between A and B → §22
# allowlist entry. Mismatch → at least one workstation is
# compromised (or non-determinism leaked through — see below).
```

A single operator can also use `scripts/verify-reproducible-bake.sh`
to bake twice on the same workstation with the same epoch + inputs.
This catches **same-workstation reproducibility regressions** (a
bake-script change that breaks determinism) before they ship; it does
NOT validate the cross-workstation case which is what the two-operator
recipe above is for.

### What reproducibility this PR delivers and what it doesn't

**Delivered** (`scripts/tenant-image-bake.sh` + this PR):

- `SOURCE_DATE_EPOCH` plumbed end-to-end. `update-initramfs` /
  `mkinitramfs` honor it from the chroot, so the initramfs cpio is
  mtime-stable.
- `LC_ALL=C LANG=C LANGUAGE=C TZ=UTC` inside the chroot — collation +
  date + locale knobs that vary between en_US / zh_CN / etc.
  workstations are pinned.
- `apt-mark hold` on the installed package set, so an inadvertent
  in-VM `apt upgrade` cannot perturb the measured kernel + initramfs.
- `scripts/verify-reproducible-bake.sh` for the same-workstation
  regression check.

**NOT yet delivered** (#284 deferred items, tracked separately):

- **Cross-workstation reproducibility is not guaranteed** because
  `apt-get install` resolves package versions at bake time against
  whatever the cloud image's apt sources point to. Two operators
  baking on different days will pull different `linux-image-virtual`
  versions (Canonical ships security updates), and the resulting
  measurement will diverge. Pinning to a snapshot repo
  (`snapshot.debian.org` for Debian; Canonical's snapshot service is
  newer and not yet stable for Ubuntu) closes this gap. Tracked: **#287**.
- **CI dual-bake gate.** A workflow that bakes twice on identical
  inputs in CI and fails the build on any SHA mismatch — converts
  reproducibility from "operator runs the verify script when they
  remember" to "main can't regress without CI catching it".
  Tracked: **#286**.

## Why this is the right architecture (vs the legacy custom Rust initramfs)

The legacy `hippius.handoff=tenant-luks` path (PRs #258–#262) attempted to perform the full LUKS unlock + mount + switch_root from a custom Rust initramfs WITHOUT `udev`. `libcryptsetup-rs`'s `crypt_activate_by_passphrase` works in that environment, but the `/dev/mapper/<name>` device node it creates (via `mknod`, not via udev's symlink-to-`/dev/dm-<N>` rule) is NOT what the kernel's `mount_bdev → blkdev_get_by_dev` accepts — `mount(2)` returns ENOENT from inside `ext4_fill_super` even though every visible major:minor matches.

This pattern (`udev` is non-trivial to substitute for) is documented in
[`thenervelab/hccs`](https://github.com/thenervelab/hccs)'s
`hcc-image-builder` which side-steps it entirely by injecting the
cryptsetup hooks into the cloud-image's distro initramfs. This runbook
adopts the same pattern adapted to the Hippius KBS release model.

See [issue #257 comment 4565408534](https://github.com/thenervelab/hippius-compute/issues/257#issuecomment-4565408534) for the full debug session and the architectural decision.
