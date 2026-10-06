# Golden guests: the non-overlay data path (`/var/lib/hippius-data`)

Issue: #1347. Code: `scripts/initramfs/hippius-golden-overlay.sh`
(`hippius_golden_bind_data`, called at the end of
`hippius_golden_mount_overlay`), shared by the initramfs-tools (Ubuntu,
Debian) and dracut (CentOS Stream 10, Fedora) golden boots.

## Why

On a golden guest `/` is an overlayfs: the shared dm-verity base as the
read-only lower, the per-VM guest-keyed LUKS2+integrity ext4 volume as the
upper. The kernel refuses an overlayfs whose upperdir is itself on an
overlay, so a container runtime that keeps its root anywhere under `/`
cannot mount its snapshots: containerd's `overlayfs` snapshotter and
Docker's `overlay2` both fail. That blocked managed Kubernetes
(hippius-backend#301) and any container-based app.

## Layout of the guest-keyed volume

```
<volume root>                     (mounted in the initramfs only)
├── .hippius-volume-stamp         anti-rollback stamp (R6)
├── .hippius-volume-timeline      stamp timeline (v2)
├── upper/                        overlayfs upperdir  -> the tenant's "/"
├── work/                         overlayfs workdir
└── data/                         plain ext4          -> /var/lib/hippius-data
```

On every boot, after the anti-rollback gate and the overlay root mount, the
initramfs:

1. creates `data/` if it is missing (mode 0755, root; on an SELinux base it
   is labelled like the lower's `/var/lib`, i.e. `var_lib_t`). Volumes
   provisioned before #1347 get it on their first boot on the new
   initramfs. An existing `data/` is never touched: the tenant's mode and
   label stay theirs;
2. creates the mount point `/var/lib/hippius-data` in the overlay root if
   it is missing (same label rule);
3. bind-mounts `data/`, and only `data/`, on it before switch-root.

If `data/` or the mount point is anything but a plain directory at its
expected place, or if `/var/lib` is missing or not a plain directory
(a symlink, even one pointing inside the tenant root), the bind is
**skipped** with a warning in the boot log, and the VM boots without
`/var/lib/hippius-data`. Following a symlink could bind the volume root
itself, or land the bind outside the tenant root. Refusing to boot would
brick a VM that can only be repaired from inside. Skipping exposes
nothing. Only in-guest root can plant such an entry (the volume is
guest-keyed): this is a robustness guard, not a confidentiality one. A
failed `mkdir` or `mount` on a healthy tree still fails the boot, like
every other step of this path.

## Guarantees

- **Same key, same integrity.** `data/` is a directory of the same
  LUKS2 + dm-integrity (hmac-sha256) volume as `upper/`. The miner sees
  ciphertext only.
- **The stamp is not exposed through the merged root or the bind.**
  Neither the merged root (its upperdir is `upper/`) nor the bind (its root
  is `data/`; `..` at a bind root walks to the parent mount, the tenant's
  `/var/lib`) reaches the volume root. The stamp defends against the host,
  not the tenant: in-guest root can always mount `/dev/mapper/hippius-upper`
  and read or edit it, as it could before this change.
- **Anti-rollback covers it.** The stamp protects the volume as a whole: a
  rolled-back volume image is refused right after the volume is mounted in
  the initramfs, before the overlay root or the data bind is assembled,
  whichever directory the stale bytes are in. A second directory adds no new
  surface.
- **Backups, restore, §25 migration.** All three copy the whole overlay
  disk image (`golden::overlay_disk_path`, the guest's `/dev/vda`) at block
  level, so `data/` follows, crash-consistent with `upper/` (one ext4, one
  journal).
- **Nothing the miner controls chooses the paths.** `data` and
  `/var/lib/hippius-data` are constants of the measured initramfs. No
  cmdline token, fw_cfg or cidata input is read to build them.
- **Not the #365 data disk.** The miner-agent never attaches the legacy
  `/dev/vde` data disk to a golden VM: its disk size goes into the overlay
  upper. But the `hippius-data-disk` unit that formats `/dev/vde` and
  mounts it at `/data` is still baked into golden images and enabled, so it
  fails on every golden boot, and a `/dev/vde` a miner attaches on its own
  would be formatted (LUKS2 + integrity, key generated in the guest and
  kept on the upper) and mounted at `/data`, with no anti-rollback. That
  predates this change and is tracked separately (#1350). Tenants and
  bootstraps on golden VMs use `/var/lib/hippius-data`, never `/data`.

## For app bootstraps

Put anything that mounts overlays, or that must not sit on an overlay,
under `/var/lib/hippius-data`, and bind your own paths onto it:

```sh
mkdir -p /var/lib/hippius-data/rancher /var/lib/rancher
mount --bind /var/lib/hippius-data/rancher /var/lib/rancher
# persist it: /etc/fstab lives on the overlay upper, which persists
echo '/var/lib/hippius-data/rancher /var/lib/rancher none bind 0 0' >> /etc/fstab
```

Same for `/var/lib/docker`, `/var/lib/containerd`, a storage manager's data
dir, and so on. Later per-pool data disks can mount at the same path, so
apps do not need to know where the bytes live.

On SELinux distros (CentOS Stream 10, Fedora) the new directory is
`var_lib_t`. Give what you put there the policy's labels for the path it
is used under with an equivalence rule, then relabel:

```sh
semanage fcontext -a -e /var/lib/rancher /var/lib/hippius-data/rancher
restorecon -R /var/lib/hippius-data/rancher
```

A plain `restorecon -R /var/lib/rancher` after the bind labels the shared
inodes too, but the next relabel of `/var/lib/hippius-data` (or an
autorelabel) puts them back to `var_lib_t` and breaks container-selinux;
the equivalence rule makes both paths agree.

## Rollout

The change is in the initramfs, so it reaches a VM with its next initrd:

- new VMs: a re-bake of the four golden distros (plus a bless) ships it;
- existing Ubuntu/Debian VMs: an initrd-only rebuild
  (`scripts/tenant-initrd-rebuild.sh`, same kernel and base, new initrd),
  then `vali_swap_vm_initrd` and a power stop/start. The first boot creates
  `data/`. The shipped patches in `scripts/initramfs/rebuild-patches/` are
  applied to the script the base carries, never to main's:
  - `m0-initramfs-guard.patch` — the M0 guard (#1305);
  - `m1-golden-data-bind.patch` — this data path;
  - `m2-golden-mask-data-disk.patch` — masks the #365 data-disk unit (#1350);
  - `m3-golden-sshd-key-only.patch` — re-asserts the sshd key-only drop-in
    `/etc/ssh/sshd_config.d/00-hippius-harden.conf`.

  A base from before the M0 guard takes all of them, which is
  the default. An M0-era base (M0 guard or stamp v2) already carries the guard:
  name `--patch m1-… --patch m2-… --patch m3-…` (the default refuses it, since M0 does
  not apply twice). Both base generations were checked to take the patches
  with no fuzz;
- existing CentOS Stream 10/Fedora VMs: `tenant-initrd-rebuild.sh` refuses
  dracut goldens, so they have no initrd-only path. See #1350 for the
  options.

Before blessing the re-baked goldens, boot one initramfs-tools golden
(Ubuntu or Debian) and one dracut golden (CentOS Stream 10 or Fedora,
enforcing) and check what CI cannot measure: the bind survives the real
switch-root (`findmnt /var/lib/hippius-data` shows ext4 with source
`/dev/mapper/hippius-upper[/data]`), `ls -Zd /var/lib/hippius-data` on the
enforcing distro, and a container runtime (`ctr`/`docker run`) with its root
bound under the path.
