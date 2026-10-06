# Guest component rollout — upgrade running VMs onto new guest components

Status: design. Phases and PRs at the end.

## Goal

Move EXISTING golden VMs (`disk_mode = golden_verity_overlay`) onto new
versions of our guest components without recreating them: same VM, same
overlay upper, same data, same KEK, same anti-rollback counter, same NetBird
and public IPs. Only the Hippius code changes. The cost to the tenant is one
reboot, inside their maintenance window.

"Guest components" means every piece of Hippius code a golden guest runs:

| | today | where it lives |
|---|---|---|
| initramfs | the §21 release (`hippius-release-core.sh`, `hippius-guest-release`, `hippius-vsock-ticket`), the golden overlay assembly + anti-rollback stamp + M0 hardening (`hippius-golden-overlay.sh`), the boot glue (`/scripts/hippius-golden`, dracut `95hippius-golden`) | the initrd, built by the base's own `mkinitramfs`/`dracut` at bake time |
| rootfs | `hippius-agent-keepalive` + `hippius-keepalive-start` + `keepalive.env`, `hippius-agent-tenant-telemetry`, `hippius-agent-initramfs` (`eol --sign-only`), their three units | the base (`/usr/sbin`, `/etc/hippius`, `/etc/systemd/system`) |

The initramfs part can already be changed for Ubuntu/Debian with the
initrd-only rebuild (`scripts/tenant-initrd-rebuild.sh`) and
`vali_swap_vm_initrd`, already used by hand once to ship a hardening fix to
the VMs that existed then. The rootfs part can only change with a new base, which an
existing VM never gets.

This design makes both parts one versioned **components release**, carried
entirely by the measured initrd, and adds the vali machinery that moves VMs
onto a release safely, one VM at a time and fleet-wide.

### Non-goals

- Changing the base (`rootfs.img` + verity) under a running VM. The base
  carries the distro and its package database; the tenant's upper carries
  their package state on top of it (and whatever unattended-upgrades patched
  there). Swapping the lower under that upper leaves the dpkg/rpm database
  describing files that are not there. A VM keeps its base for its whole
  life; distro updates for existing VMs stay the tenant's own
  unattended-upgrades.
- Kernel upgrades. The kernel's modules live in the base (see "Later").
- `legacy_luks` VMs. None are live; everything here refuses them.
- Upgrading without a reboot. Nothing can change the code a guest runs
  without a new measured boot and keep the measurement describing that code
  (see "Rejected alternatives").
- Revoking an old guest the miner keeps running (see T4).
- A tenant API in vali. The maintenance window and the notices live in
  hippius-backend, which calls vali's operator API, as the resize does.

## Threat model

Same as the rest of the golden path. The miner is untrusted. It controls
the host, QEMU and the domain XML, the disk images it stores and their I/O,
the cidata disk, SMBIOS and fw_cfg, the network between the guest and
everything else, and which artefacts it boots. The SNP launch measurement
covers OVMF + kernel + initrd + cmdline (kernel hashes), nothing else. The
KBS releases the disk KEK only to a guest whose measurement is named by a
ticket vali signed, and only while that ticket's launch is the VM's current
one (`kbs_core::lifecycle::check_current_launch`, #1375/#1376). The tenant is
root in their own VM. vali, the KBS and our build pipeline are trusted.

What this design guarantees:

- **G1. The measurement names the code.** Every Hippius byte the guest runs
  comes from its measured initrd, as one immutable image. A guest booted on
  release R runs release R's code or no Hippius rootfs code at all — never an
  older one, never a mix. The miner selects nothing: no cmdline token, path,
  fw_cfg entry, SMBIOS string, disk, write failure or network answer changes
  which code runs.
- **G2. Only the current launch can unlock and earn uptime.** Once an
  upgrade relaunch registered, the KBS refuses every earlier launch of the
  VM, for the release (KEK) and for the keepalive (live attestation).
- **G3. No launch below the VM's required epoch.** Once an upgrade to a
  release with a higher security epoch is decided for a VM, vali mints no
  ticket for that VM on any lower-epoch build again, whoever asks for the
  launch (rollout rollback, power start, reboot-recovery, §25, resize,
  restore, KBS recovery). The required epoch only moves up, except by an
  audited break-glass command.

What it does NOT guarantee: that an old guest the miner refuses to stop is
gone (T4), or that a hostile miner lets the upgrade happen at all (T3).

| # | attack | outcome |
|---|---|---|
| T1 | Miner boots the PREVIOUS initrd after an upgrade. | Every launch has its own measurement (the measured cmdline carries a fresh `validator_nonce` and EOL nonce per relaunch), and every ticket names exactly its launch's measurement. The upgrade relaunch registers with the `supersede` perm, so the new launch becomes the VM's current one at the KBS register, BEFORE the order is dispatched (`kbs-core/src/admin.rs`, `observe_launch`). From then on every earlier ticket is refused for the release (`superseded-launch`) and the keepalive (`kbs-core/src/keepalive.rs`). The old initrd cannot use the new ticket either (wrong measurement). The disk stays locked. vali's allowlist eviction (`allowlist_pin.evict_superseded_measurements`) also drops the old measurement, but that is asynchronous hygiene after the acceptance; the KBS launch binding is what closes the window. |
| T2 | Miner boots the new initrd with another base or an older upper. | The verity root hash is in the measured cmdline: another base fails `veritysetup` before any network. An older upper fails the anti-rollback stamp. Unchanged by this design. |
| T3 | Miner refuses to boot the new initrd, fails its disk I/O, or never confirms the stop. | The VM is down (its old launch is superseded) or still on the old build. Rollback is a NEW forward launch onto the previous build, allowed only when that build's epoch is at least the VM's `required_epoch`, which an epoch-raising job raised to the target BEFORE it stopped anything (G3). So an epoch-raising upgrade never rolls back and never restarts the old build: the VM is reported `upgrade_blocked` (stopped on the new build, or still running the old one if the stop never happened) for the operator (see `upgrade_blocked` under the job states). A miner can delay an upgrade and lose its uptime credit; it can make a VM come back on the previous build only when that build is as secure as the new one. |
| T4 | Miner keeps the pre-upgrade domain running (lies about the stop) or snapshots and resumes it. | That guest already has its KEK in memory and its disk open; nothing the KBS does can take that back. After the upgrade's superseding register it cannot re-unlock after a reboot, and its keepalives are refused, so it earns nothing. vali flags it (see "Detection"): a `superseded-launch` keepalive refusal after a superseding register, or ANY live attestation of a VM vali records as stopped, is a miner that did not stop the domain; it is alerted and the miner quarantined. For a VM recorded STOPPED when an epoch-raising rollout reaches it, vali does not wait for its next start: it registers a superseding ticket of the target build right away (a fence register, never dispatched), so a domain the miner kept alive loses its KBS standing at once. Two guests on one disk can corrupt the tenant's data; the miner could already do that on any relaunch (resize, power start). Before its upgrade, the old guest is legitimately the VM's current launch (an in-guest reboot re-unlocks it, as today); the exposure window of a vulnerable release is the rollout's deadline (72 h for an epoch raise). If a release fixes a flaw that leaks data to the miner from a RUNNING guest, an upgrade does not undo past exposure on an uncooperative miner: the remedy is a replacement VM with a fresh KEK, out of scope here. |
| T5 | Miner tampers with the components. | They are inside the measured initrd. At boot the initramfs copies the components image into guest RAM (SNP-encrypted) and mounts it read-only. Nothing is read back from any miner-reachable place. |
| T6 | Miner adds unmeasured inputs to steer the boot (a `cidata` disk, SMBIOS credentials, fw_cfg strings, extra NICs). | The components step reads only files of the initrd and nothing else; the existing M0 defences (`systemd.import_credentials=no`, the masks, the NoCloud pin) are part of every release. |
| T7 | Miner makes the upper refuse writes (I/O errors) so the unit links cannot be written. | The links are written fail-closed, like the M0 masks: the boot stops before `switch_root`. That is T3 (the VM does not come up), never old code running. |
| T8 | Tenant tampers with the components at run time. | Their VM. They can already stop the keepalive (their miner then goes unpaid) or forge a served receipt (uptime-billing threat model). They cannot forge an SNP report. The next boot mounts the measured image again. |
| T9 | A bad release (our bug). | Canary first, then waves; a VM is `done` only once a guest of THAT launch is attested live and stays so through the soak; a failure rolls it back (within G3) and failures above the threshold pause the rollout. |

The KBS needs no change for G1–G3. Phase 5 adds a component-health field to
what the keepalive binds into `REPORT_DATA`, for the gate.

## The components release

A components release is cut from one repo commit and has:

- `version` (integer, monotonic) and `commit`;
- `security_epoch` (integer, monotonic): raised by a release that fixes a
  security flaw OR changes something an older release cannot read back (a
  volume format). Launching a VM below its required epoch is refused
  everywhere (G3), so one floor covers both; there is no separate
  "irreversible" flag to forget in some code path;
- **the release cpio**, one per initramfs family (initramfs-tools,
  dracut), each the same bytes for every base of its family: an
  uncompressed `newc` cpio, built reproducibly (sorted, `--reproducible`,
  SDE = commit time, uid/gid 0), holding:
  - the initramfs scripts at the paths every golden initrd generation uses
    (`/lib/hippius/hippius-release-core.sh`,
    `/lib/hippius/hippius-golden-overlay.sh`, and the family's glue:
    `/scripts/hippius-golden` for initramfs-tools, `/sbin/hippius-golden-mount`
    with its units and hook for dracut), and the
    static musl `hippius-guest-release` / `hippius-vsock-ticket`;
  - `/lib/hippius/guest/components.squashfs`: the rootfs components (the
    agents, `hippius-keepalive-start`, `keepalive.env`, the unit files, a
    `manifest` naming the units to enable and the units retired by this
    release), as a squashfs carrying SELinux labels in xattrs (`bin_t`,
    `systemd_unit_file_t`, `etc_t`; ignored on Ubuntu/Debian);
  - `/lib/hippius/guest/release` (`version`, `commit`, `security_epoch`,
    sha256 of the squashfs);
  - a static busybox (Debian's `busybox-static`, from the baker image) at
    `/lib/hippius/guest/busybox`, used only by the boot step for
    `sha256sum` and the loop mount, so the step needs no `losetup`/`mount -o
    loop` from the base's initrd.

### One initrd per base: append, don't rebuild

Linux unpacks an initramfs made of several concatenated cpio archives, in
order, later files replacing earlier ones (that is how early microcode is
loaded). So the initrd a VM boots for release R is:

```
initrd(base, R) = base_initrd(base) ‖ zeros((-len(base_initrd)) mod 4) ‖ release_cpio(R)
```

where `base_initrd(base)` is the newest initrd built by the base's own
`mkinitramfs`/`dracut` for that base (the bake's, or an initrd-only rebuild
of it), never an earlier concatenation. The base's part brings the kernel
modules, busybox/udev/cryptsetup/veritysetup and the distro's boot
framework; the release part replaces every Hippius file.

The zero bytes matter: the kernel only recognises an uncompressed cpio
member that starts on a 4-byte boundary after a compressed one, and skips
zero bytes between members
(`Documentation/driver-api/early-userspace/buffer-format.rst`).

Consequences:

- no per-release chroot build, no dracut rebuild, no host noise: the base
  part is byte-identical to what the VM booted, the release part is the
  same reproducible bytes for every base of a family. Building `initrd(base, R)` is a
  download, a prefix check and an append;
- both families at once: dracut bases need nothing more than
  initramfs-tools bases;
- verifiable by anyone: `initrd(base, R)` is `base_initrd`, then fewer
  than 4 zero bytes, then `release_cpio(R)`.

Constraints the release must meet (checked by the build Job against the
real initrd of the base it builds for):

- **Leaves only, no type changes.** The kernel's unpacker is not an
  overlay: a later entry replaces an earlier one of the same type, but a
  type change is unsafe (`clean_path` cannot `rmdir` a non-empty
  directory and the replacement then silently fails; a directory entry
  `lib` would replace a usrmerge `lib -> usr/lib` symlink with a real
  directory). The release cpio therefore carries ONLY leaf entries (files
  and symlinks) and directory entries for directories that are new; it
  never has an entry for a pre-existing parent (`lib`, `usr`, `sbin`,
  `scripts`, …: the kernel follows the base's symlinks to reach them), and
  CI refuses any entry whose type differs from the same path in a live base.
  The release carries a manifest of every runtime leaf it owns, per family:
  path, type, mode, symlink target, sha256.
- **Override, never add, auto-run hooks.** initramfs-tools runs
  `/scripts/*-top` scripts through an `ORDER` file generated per initrd, so a
  release cannot add one; all release logic runs from the boot script
  (`/scripts/hippius-golden`, selected by the measured `boot=` token) or,
  under dracut, from the units and hooks the golden module already uses.
  Every Hippius file that ran automatically in ANY live base's initrd is
  either replaced by the release or replaced by a no-op. Today those are,
  for initramfs-tools, `/scripts/hippius-golden` and
  `/scripts/init-bottom/hippius-net-teardown` (in `ORDER`) plus what they
  source (`/lib/hippius/*.sh`) and call (`hippius-guest-release`,
  `hippius-vsock-ticket`); for dracut, the `cmdline` hook
  `30-parse-hippius-golden.sh`, `/sbin/hippius-golden-mount`,
  `/sbin/hippius-net-teardown`, their two units and the units' enablement
  links. Build hooks (`hippius-golden-hook`, `hippius-luks-hook`,
  `hippius-host-state-hook`, `module-setup.sh`) never run at boot.
- **Checked on the merged tree, not on file lists.** The build Job extracts
  the base's real initrd followed by the release with an extractor that
  reproduces `init/initramfs.c` (member alignment, `clean_path`, symlink
  following, same-type replacement) and refuses the build unless the result
  matches the release manifest (CI runs the same extractor against fixture
  initrds of both families); the canaries then boot it for real.
- **Tool closure.** Every command the release scripts call exists in each
  live base's merged tree, or ships in the release as a static binary.
- **Kernel modules** come from the base's initrd. The boot step needs
  `loop` and `squashfs`: `squashfs` is in every golden initrd (the base is
  one); `loop` is built in (`CONFIG_BLK_DEV_LOOP=y`) on the Ubuntu, Fedora
  and CS10 kernels, and where it is a module the boot step loads it from the
  base's `/lib/modules`, which is reachable read-only and verity-checked at
  that point (the lower is open). The build Job reads the base kernel's
  config and module list and refuses a base where neither holds.

### Boot: the initramfs mounts the release

A new step in `hippius-golden-overlay.sh`, `hippius_golden_mount_components`,
runs from `hippius_golden_run` after `hippius_golden_harden_root` (the
overlay is mounted at `${rootmnt}`, before `switch_root`; both families
reach it through `hippius_golden_run`):

1. check the squashfs against the sha in `/lib/hippius/guest/release`
   (a measured initrd cannot mismatch except by a build bug; a mismatch is
   fatal);
2. copy it to `/run/hippius/guest.squashfs` (tmpfs, guest RAM) and mount it
   read-only, `nosuid,nodev`, at `/run/hippius/guest` (a separate mount, so
   the `noexec` flag initramfs-tools puts on `/run` does not apply). `/run` is
   moved into the new root at `switch_root` by both families, with its
   submounts, and systemd keeps it;
3. in the overlay upper, make every unit of the manifest a link
   `/etc/systemd/system/<unit> -> /run/hippius/guest/units/<unit>` plus its
   `.wants` link, and mask (`/dev/null`) every retired unit, with the same
   directory-safe, verified, labelled writes as the M0 masks
   (`_hippius_golden_mask_path`). These writes are **fail-closed**: a link
   that cannot be written stops the boot (T7);
4. write `/run/hippius/guest-components` (version, commit, epoch) for the
   agents to report.

The step runs only when the initrd carries `/lib/hippius/guest/release`.
An initrd without it (every initrd built before this design, and fresh
bakes until phase 7) is a strict no-op: no links, the base's units and
agents run as today. When the marker is present, the links are always
written, whether or not the image mounted.

The upper links have the same names as the units the base ships
(`hippius-keepalive.service`, `hippius-tenant-telemetry.service`,
`hippius-eol-sign.service`), so they shadow the base's units and the base's
`/usr/sbin` agents stop running. If the image could not be mounted (only a build
bug can cause that: image and marker are both in the measured initrd) the
links dangle and NO Hippius agent runs: the tenant's VM boots, the gate
catches it, the job rolls back. Nothing falls back to the base's agents.

Why a squashfs and not files:

- one immutable image: no partial install, no per-file atomicity, no stale
  files to clean up, nothing written to the tenant's disk except the
  links;
- SELinux (Fedora/CS10): a squashfs keeps per-file `security.selinux`
  xattrs, which the policy honours (`fs_use_xattr squashfs`; the golden base
  itself is such a squashfs). A tmpfs cannot be given a label before the
  policy loads (the `context=` mount option is refused then), and files
  written into it before policy load get a transition label at load time.
  The image carries a label for EVERY entry, its root and directories
  included (an unlabelled directory on a path breaks every confined domain
  that walks it, as the upper root did before
  `hippius_golden_label_upper_root`), from a path-to-context manifest; the
  builder verifies each raw xattr after `mksquashfs`. On an SELinux base the
  unit links' labels are verified at boot and a wrong one is fatal (not the
  best-effort `_hippius_golden_relabel_from`). The canary set includes an
  enforcing Fedora and CS10 VM that runs all three units through the links,
  shuts down cleanly (eol-sign's `ExecStop`) and shows no AVC denial.
  The agents run in `unconfined_service_t` there, as the base's own agents
  did: the release changes the files' labels, not the agents' domain
  (verified on the Fedora and CS10 canaries);
- RAM, not the upper: a full or failing upper cannot stop the components
  from mounting, and nothing persists between boots but the links.

The units point at `/run/hippius/guest/bin/...` and carry
`RequiresMountsFor=/run/hippius/guest`, so `hippius-eol-sign.service`'s
`ExecStop` at shutdown still runs before the image is unmounted.

The M0 masks, the NoCloud pin and the sshd drop-in stay in
`hippius_golden_write_masks`, fail-closed as today; they are now updated by
a release like everything else.

The #1380 network profiles are NOT part of the first release. Changing how
an existing VM gets its network is the one change that can cut a tenant off,
and keepalive and telemetry (vsock) would not show it. It needs its own
release with a NetBird-reachability leg in the gate.

### Fresh bakes

New VMs boot a release from their first launch (phase 7): the bake stays
as it is, and the operator blesses a release for an image
(`vali_bless_guest_release <image> --release N`, `GoldenImage.guest_release`)
once a build of it exists for the image's blessed bake. A launch by image
then takes the bake's kernel and dm-verity base and the BUILD's prefix and
initrd (`base_initrd ‖ release_cpio(N)`). The base initrd stays published
with the bake, so the VM's later upgrades append to it like any other
VM's (releases are never chained). A build withdrawn after the bless fails
image launches closed (never a silent fallback to the bare bake, whose
agents may be older); re-blessing another bake clears the release, which
is blessed again for the new bake. A launch by image takes NO caller
artifact (disk mode, bucket, prefix, kernel, initrd, rootfs, verity): the
catalog decides them all. Customer-held-key launches accept the build of
the capable bake's own initrd in place of the bake's prefix + initrd.

Not done yet: bakes that stop installing the agents into the base (every
VM would then run only the code of its initrd).

## vali

### Builds: `GuestComponentRelease`, `GuestInitrdBuild`

`GuestComponentRelease` (immutable once registered): `version`, `commit`,
`security_epoch`, `release_cpio_sha256`, its S3 location,
`baker_digest`, `state` (`ready` / `withdrawn`).

`GuestInitrdBuild` (immutable once `ready`): `release`, the base identity
(`kernel_sha256`, `rootfs_img_sha256`, `rootfs_verity_sha256`,
`verity_root_hash`, `base_initrd_sha256`), `source_bake_id`, the result
`initrd_sha256` + `s3_bucket` + `s3_key_prefix` (a new prefix, with the base
artefacts copied or referenced as the swap needs), `state`. One build per
release and base. The base initrd is part of the base: an initrd-only
rebuild (`scripts/tenant-initrd-rebuild.sh`) shares the bake's kernel and
dm-verity base and is another base, with its own build of each release. A
VM's base initrd is its build's `base_initrd_sha256`, or its initrd when
that is no build; it only ever moves to builds of that base initrd.

`vali_guest_release_register --version N` registers a release the baker
published. `vali_initrd_build --version N [--base <bake_id> | --all-live-bases]`
spawns one build Job per base (the bake Job spawner, serial). The Job reads
the base initrd and the release cpio, checks both shas, appends, uploads to
the new prefix with a `golden.measurement.json` of the shape
`vali_swap_vm_initrd` reads, and vali finalizes the row from it. A
`withdrawn` release or build gets no new jobs; VMs already on it stay.

### Per-VM epochs

On `Vm` (or a one-to-one row):

- `required_epoch`: monotonic. Raised to the target's epoch in the
  transaction that takes the VM out of `pending` (under its row lock, with
  the CAS to `stopping`) — before anything is stopped, registered or
  launched. A pending job does not raise it: until it leaves its window,
  the VM legitimately runs (and may be relaunched on) its current set.
  A VM born on a release (its first launch boots a build, phase 7) starts
  with that release's epoch as its floor, set when its `Vm` row is
  created. A hand swap (`vali_swap_vm_initrd`) does not move it (the swap
  keeps its revert path). `vali_guest_epoch_lower
  --vm-id --to --reason --operator` is the only way down (audited, refused
  while a job runs).
- `attested_epoch`: the epoch of the build the VM was last attested live
  on (reporting).

Every place that mints a launch ticket for a golden VM — launch, power
start, reboot-recovery relaunch, §25, resize, restore, `vali_kbs_recover`
re-mints — refuses a build below `required_epoch`; a VM it refuses stays
stopped. That makes G3 hold whoever relaunches the VM, not just the
rollout.

### One operation at a time: decided under the VM row lock

`_has_active_job` is an application-level check; its own docstring says
cross-kind races are tolerated only because §24/§25 serialize through the VM
state CAS. An upgrade keeps the VM `active`, so that does not cover it, and
backup start did not re-check under a VM lock.

The serialization point is the `Vm` row lock, which every intake already
takes — power (`power._claim`), §25 and §24 intake, resize intake, launch
intake, the reboot-recovery relaunch claim — plus backup start, which now
takes it too. Under that lock each intake checks ONE shared predicate,
`_has_active_job`, which knows every kind that holds a VM: a migration or
restore, a decommission, a resize, and a guest upgrade past `pending`
(`HOLDING_GUEST_UPGRADE_STATES`). The upgrade job checks the same predicate
plus the power markers, the reboot-recovery relaunch and any launch job or
backup run in flight, under the same lock, when it leaves `pending`. Two
intakes therefore never both decide against the same state, and a new kind
of operation is added in one place.

This is the lease, derived from the rows each operation already writes
rather than kept in a table of its own: nothing to release on every terminal
path, no orphan to reclaim. The power API's generic `by_migration` bypass is
not extended: a guest upgrade's own stop and start pass its `job_id`
(`by_guest_upgrade`), and the power API refuses everyone else — and a job
id that does not hold the VM — while it holds it. `vali_swap_vm_initrd`
refuses a VM any job holds, and `vali_kbs_recover` refuses a VM whose
upgrade is between its stop and its accepted relaunch. A pending upgrade
holds nothing: a backup, a resize or a power op may run while it waits for
its window; everything is re-checked when it leaves `pending`. A power start
of a VM whose upgrade waits is handed to the job (`start_requested`).

### Ticket ordering

The launch binding orders launches by the ticket's `issue_time`, in seconds,
and the KBS ignores a superseding register whose `issue_time` is not
strictly later than the binding's (`persist.rs`, `write_launch_binding`),
while vali records `superseded_at_register` from the 200. A retry minted in
the same second as the previous launch would be recorded as superseding
when the KBS kept the old binding. vali therefore mints at most one launch
ticket per VM per wall-clock second: `last_issue_time` is stored on the VM
under the VM row lock, and a mint whose `now` is not past it waits for the next
second (a tick defers it) — never a future-dated `issue_time`, which the KBS
refuses (`kbs-core/src/ticket.rs`). (Phase 4a; it also fixes the resize.)

### `GuestUpgradeJob`

One VM, one target build. Holds the VM from leaving `pending` to
terminal state.

Refused (no job): not `active`; not golden; an operator-pinned
`measurement_hex`; `auto_pin_allowlist` off; another job holds the VM; no `ready`
build of the target release for the VM's base; already on the target; target
below the VM's floor; target older than the current build unless the job is
an explicit operator rollback.

Every external effect is preceded by an `UpgradeAttempt` row, written and
committed first: `kind` (`upgrade` / `rollback` / `recover` / `fence`),
`build`, `ticket_id` (a foreign key to the `OrderTicketIntake` row holding
the byte-exact ticket), `issue_time`, the expected launch `measurement`, `supersede`,
`register_state` (`pending` / `accepted` / `refused`), `dispatch_state`
(`pending` / `accepted` / `rejected` / `ambiguous`), `launch_job_id`. The
relaunch path (`_reboot_recovery_relaunch`) is split so that the ticket and
the measurement are minted and recorded before the register, and the
register before the dispatch. On a vali restart the job reconciles from its
newest attempt (the miner's domain state, the launch record, the KBS
register outcome, the live attestations of that measurement) before it does
anything else.

```
pending ─► stopping ─► swapping ─► launching ─► verifying ─► soaking ─► done
              │            │           │             │            │
              └────────────┴───────────┴──────┬──────┴────────────┘
                                              ▼
                              rolling_back (a forward launch of the previous build)
                                   │                     │
                              rolled_back       failed / upgrade_blocked (operator)
```

- `pending`: waits for `not_before` (the tenant's window) and for no backup
  to be running (it never interrupts a backup; it waits).
- `stopping`: `power.stop_vm(..., by_guest_upgrade=job_id)`; done when the miner
  reports the domain DOWN (`effects.poll_domain_running(vm) is False`). An
  unreachable miner: deadline ⇒ when the target does not raise the epoch,
  `rolling_back` with nothing to undo (start again on the current build if
  it went down); when it does, `upgrade_blocked` (nothing below
  `required_epoch` is started again).
- `swapping`: compare-and-set of the launch record to the target build
  (`services/initrd_swap.py`, factored out of `vali_swap_vm_initrd`, which
  keeps working). The previous build is saved on the job.
- `launching`: one attempt: mint (`supersede` until one attempt's register
  was accepted with it; a later retry does not supersede, since an earlier
  dispatched attempt may still come up), register, dispatch through
  `power.start_vm(..., by_guest_upgrade=job_id)`. `allowlist-pin-busy` retries;
  `relaunch-rejected` 3 times ⇒ `rolling_back`; `already-launched` or a
  timeout is `ambiguous` and moves to `verifying` (the attempt's own
  measurement decides, see the gate), never straight to a retry.
- `verifying`: the gate within `VALI_GUEST_UPGRADE_GUEST_TIMEOUT_S` (1200 s).
  A domain the miner reports DOWN here (a miner reboot) gets ONE `recover`
  attempt on the same build (a new attempt, a new measurement, no supersede
  needed: the ticket is newer).
- `soaking`: `VALI_GUEST_UPGRADE_SOAK_S` (900 s, three keepalive
  intervals): live attestations of the attempt's measurement keep coming.
- `done`: `attested_epoch` is set; the VM is released.
- `GuestUpgradeJob.attempts` counts the power
  dispatches claimed in the CURRENT state, before each one is sent; every
  state transition resets it to 0 (with `attempted_at`). It is not a total
  for the job: a job that went through `stopping` and `launching` shows the
  count of the state it is in. The job's history is its `UpgradeAttempt`
  rows.
- `rolling_back`: only when the previous build's epoch is at least the VM's
  `required_epoch`; otherwise `upgrade_blocked` — after `parking`: the job
  keeps holding the VM while it stops a boot of unknown health and confirms
  the domain DOWN, then releases it
  (the VM stays stopped on the target; operator: §25 and retry). Past its
  deadline it keeps holding and alerting: only an operator who looked at
  the domain releases it without the miner's DOWN (audited
  `vali_guest_upgrade --release-parked`). Rollback is
  NOT a revert of history: stop (domain DOWN), compare-and-set the record to
  the previous build, a new superseding attempt, the same gate on THAT
  attempt's measurement. `rolled_back` when it holds; `failed` (operator,
  rollout paused) when it does not.
- `upgrade_blocked` is resolved by the operator, not by the job
  (docs/operator/guest-upgrade-recovery.md). A failed target records WHY as
  a machine-readable `outcome` (`health-failed` with the missing checks,
  `health-latched`, `guest-restarted`, `resources-mismatch`, `no-sample`,
  `measurement-mismatch`, `dispatch-failed`, `stop-timeout`,
  `launch-timeout`, `c2-not-enforced`, `vm-moved`) and whose side it points
  at (`suspect`: release / miner / vali / fleet). Two operator paths, both
  through the normal launch path (G3, ENFORCE, auto-pin, KBS supersede):
  - `--recover start-on-target` (`POST .../guest-upgrade/<job>/recover`):
    an audited, ungated start of the TARGET on a stopped VM whose miner
    reports the domain DOWN — the tenant's service back, the operator
    judges the boot; recorded on the job (`recoveries`, an
    `operator_start` attempt linked to its pin);
  - a retry: an upgrade admitted on a VM whose latest job is
    `upgrade_blocked` (`retry_of`) — the same build although the record
    names it, or a newer release. It takes the VM the blocked job left
    stopped (no completed stop order since), and a retry of the same build
    keeps the blocked job's previous set, so it blocks again on failure
    instead of rolling back onto the target.
  Today's §25 cannot be the escape: it replays the source's measured boot,
  which G3 now refuses below the required epoch. Lowering the floor
  (`vali_guest_epoch_lower`, audited) is the break-glass. A §25 mode that
  boots the TARGET build at the destination ("upgrade on destination") is
  listed under "Later".

A STOPPED VM (stopped through the power API and confirmed DOWN by the
miner): the job stays `pending` (reason `vm-stopped`), which is never a
rollout success. For an epoch-raising target it first does the fence
register (T4): the swap, then a superseding register of a target-build
ticket that is not dispatched, recorded as an attempt. The tenant's next
power start is handed to the job (`start_requested`): it runs `launching`
→ `verifying` in place of a plain start, so the tenant gets no extra
reboot. Reboot-recovery does not relaunch a VM an upgrade holds.
*Not implemented yet* (tracked for phase 6c): the fence register and the
start hand-over. Until then a stopped VM's job waits in `pending`; the
tenant's next start is a plain start (on the old build), after which the
job runs as for any running VM (one extra reboot), and a rollout counts
the VM as stopped-pending, never upgraded.

A KBS restart wipes VM states and launch bindings; `vali_kbs_recover`
re-seeds them and re-registers each VM's recorded launch. For a VM whose
lease an upgrade job holds, recovery seeds the counter but does NOT
re-register the recorded (old) launch; it hands the VM to the job, which
registers a fresh attempt of its own: a new fence for a stopped VM, the
current attempt for a running one. The case "KBS wiped between the fence and
the tenant's start" is a test of phase 4.

`power.stop_vm` records STOPPED when the stop order is accepted, without
asking the miner. The job does not rely on it: `stopping` and the stopped
case above both require the miner to report the domain DOWN.

### The gate

The attempt is good when, for the attempt's own measurement `M`:

1. `M` is the measurement vali PINNED for the attempt (its
   `MeasurementLedger` row, written before the register and the dispatch,
   tagged with the attempt's id) — never the launch record, which is
   mutable, nor the miner's word. The row says whether it is vali's own
   recompute of the boot it built (`recomputed`, C2 ENFORCE, checked before
   every launch of the job); only such a row counts, so `M` is unique to
   the attempt (fresh nonces in the measured cmdline). Any attempt of the
   job for the same set may be the one that runs (a retry answered
   `already-launched` started nothing); an attempt answered as refused with
   the domain DOWN stays open until its dispatch settled;
2. a KBS-verified `VmLiveAttestation` of `M`, verified after the attempt
   started: a guest of this launch booted, was released its KEK, assembled
   the overlay, mounted the release image (the only place the keepalive now
   lives, G1) and runs its keepalive;
3. when the release's keepalive attests resources (v3, flag-gated as
   `guestResources.attest` is): the resource verdict for `M` is `ok`;
4. when the release of the build the ATTEMPT launched declares health
   checks (`health_mask != 0`; the target for an upgrade / recover
   attempt, the previous build for a rollback one): that attestation is a
   schema-v4 body naming that release and its epoch, with every declared
   check passing (see "Component health in
   `REPORT_DATA`" below). Until a release carries it, jobs run only on
   throwaway VMs, checked by hand.

Served receipts are not part of the gate: they carry no launch identity, so
an old guest could produce them.

### Component health in `REPORT_DATA` (phase 5)

Gate condition 4 needs the guest to say, inside a PSP-signed report, that
the release it booted is the one vali built and that its agents run. The
keepalive is the only agent that already talks to the KBS with a report,
so it carries the leg; the miner relays the request and the signed body
and can change neither (the KBS rebuilds `REPORT_DATA` from the request
and compares it byte for byte with the report, as for the resources).

**What the guest attests** (`hippius_types::live_attestation::GuestComponents`):

- `release_version`, `security_epoch`: read from
  `/run/hippius/guest-components`, which the measured initramfs writes
  from the release record it mounted. Redundant with the measurement (the
  initrd names the release) and kept as a cross-check of the build vali
  registered for that initrd.
- `health`, a bitmap, one bit per check, each evaluated by the keepalive on
  every tick:
  - bit 0 `MOUNTED`: the record says `mounted=yes`;
  - bit 1 `KEEPALIVE_FROM_RELEASE`: `/proc/self/exe` resolves under
    `/run/hippius/guest/bin/` (the keepalive runs from the release image,
    not from a base copy);
  - bit 2 `TELEMETRY_ACTIVE`: `hippius-tenant-telemetry.service` is
    `ActiveState=active` (`systemctl show`, read-only);
  - bit 3 `EOL_SIGN_ARMED`: `hippius-eol-sign.service` is
    `ActiveState=active` (its `ExecStop` is what signs the stopped-ack) and
    `/run/hippius/guest/bin/hippius-agent-initramfs` is an executable
    file.
  A check that cannot be evaluated is a cleared bit, never an error that
  stops the keepalive: liveness (the uptime leg) must not depend on the
  health leg. Every probe is bounded (`systemctl show` under a 5 s
  timeout, the child killed and reaped on expiry). A missing or malformed
  record reports `release_version = security_epoch = 0` with `MOUNTED`
  cleared — still a v4 report: with `--attest-components` the keepalive
  never falls back to a layout without the leg. The bit set is
  append-only; vali judges against the mask of the checks the release
  declares (`health_mask`, below), so a release can add a check without a
  schema change.
- `instance`: a random `u32` the keepalive draws when it starts. A
  restarted keepalive (a crash, an OOM kill) has another one.
- `unhealthy_ticks`: how many of THIS keepalive instance's ticks found a
  check failing (any check it knows; saturating). It is counted in the
  guest when the checks run, before any request leaves, so a tick the
  relay withholds or delays still shows in every later report: the relay
  can hide a failing sample, never the failure. The checks also run every
  30 s on a thread of their own, so a host that blocks or holds the
  keepalive's KBS round trips (the nonce request) while a check fails
  does not stop the count.

**Wire.** A new `REPORT_DATA` domain,
`HIPPIUS_LIVE_ATTESTATION_COMPONENTS_REPORT_V1`: `nonce ‖ SHA-256(canonical
CBOR map)` binding the domain, the `vm_id`, the five component values
(`components_release_version`, `components_security_epoch`,
`components_health`, `components_instance`, `components_unhealthy_ticks`,
all `u32`) and, when the keepalive also attests
resources, the four resource keys of the resources preimage. The resources
domain is not reused; within the components domain the resource keys are
either all present or all absent, and a canonical map distinguishes the
two. The request carries `components` next to `resources`; the KBS
verifies it like the resources and signs a **schema v4** body.

The body validity matrix (`LiveAttestationBody::validate`):

| schema | guest binding | resources | components |
|---|---|---|---|
| v1 | absent | absent | absent |
| v2 | required | absent | absent |
| v3 | optional | required | absent |
| v4 | optional | optional | required |

A v4 body stays under the runtime's `MaxLiveAttestationBody` (1024 bytes;
a test pins the largest the stack produces: a 64-byte `vm_id`, counters
and unix times below 2^32, every component `u32` at its max).

**Switching it on.** The keepalive sends the leg only with
`--attest-components` (`HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1` in the
release's `etc/keepalive.env`): a property of the RELEASE, in the measured
initrd, not of the miner or the cmdline. The release record declares it
(`health_mask=<decimal u32>` in `release.conf`, carried into the build's
`golden.measurement.json` and into `GuestComponentRelease.health_mask`); a
release without it is `health_mask=0` and has no gate condition 4.

**Gate.** The expectations come from the build the ATTEMPT launched (its
`initrd_sha256` → `GuestInitrdBuild` → release): the target for an
`upgrade` / `recover` attempt, the previous build for a `rollback` one (a
previous set that is a bare base, or a release with `health_mask == 0`,
has no condition 4). For such a release with `health_mask != 0`:

- verifying: the attestation that passes condition 2 must ALSO be a v4
  body with `release_version` / `security_epoch` equal to the release's and
  `health & health_mask == health_mask`;
- soaking: the soak ends only once a sample OBSERVED at or after its end
  has reached vali before the soak's deadline. A v4 body's
  `observed_at_unix` is when the KBS issued its nonce, and the keepalive
  runs its checks after it received the nonce, so a healthy request the
  relay held back across the end cannot pass for a later check (the
  relay can delay samples; arrival order means nothing). Every v4 sample of the
  job's pins verified from the gate sample (the one that passed
  verifying) to that end sample must pass the checks, carry the gate
  sample's `instance` (the same keepalive process: no restart) and its
  `unhealthy_ticks` (no tick of that process found a check failing in
  between). Because the guest counts failures before anything leaves it,
  withholding, delaying or reordering samples cannot hide one: the end
  sample carries the count. A failing sample, another instance or a
  higher count fails the soak; no end sample before the deadline fails it
  too. What the leg proves is that every tick of one keepalive process
  over the soak found the checks passing — sampled state, never
  behaviour between ticks.

Condition 3 (resources) is checked on the same rows when the pin
`attests_resources` and resource enforcement is on. A release with
`health_mask == 0` (release 1) keeps today's gate, and phase 6 refuses to
roll such a release beyond throwaway VMs.

**Release metadata path.** `health_mask` is a key of `release.conf`;
`build-guest-release.sh` writes it into the release record and
`release.json`; the initramfs record parser (which refuses unknown keys)
accepts it and ignores it at boot; `guest-initrd-build.sh` copies it into
the `guest_release` object of `golden.measurement.json`; vali's
`parse_build` / `GuestComponentRelease.health_mask` (immutable, compared
on re-registration) carry it. The keepalive's switch is
`HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1` in the release's
`etc/keepalive.env`, passed through by the `hippius-keepalive-start`
wrapper; the builder refuses a release whose `health_mask` and
`keepalive.env` disagree.

**Order.** Every consumer of the signed body must accept v4 before any
guest sends it:

0. the on-chain decoder: `pallet-compute-scoring` decodes bodies with
   `hippius_types::live_attestation` (`submit_live_attestation`). No
   submitter of live attestations runs today (vali reads them from the KBS
   path), so nothing breaks; a runtime built from a tree WITHOUT v4 must
   never be paired with a submitter while v4 bodies exist — the KBS's
   per-VM hash chain would then hold bodies the chain cannot take. The
   decoder change lands in the same PR as the type, so any runtime built
   after it accepts v4;
1. vali on every replica: `apps.telemetry.verifier`, the
   `ticket-validator` binary in its image, `vm_liveness` ingest and the
   `VmLiveAttestation` columns, the gate;
2. the KBS (`kbs-transport` request parsing, `kbs-core::keepalive`);
3. a release with `health_mask != 0` (release 2).

The miner-agent, the Edge and the KBS archive carry the `{body, sig}`
envelope opaquely and need no change. A release-2 keepalive talking to a KBS
without the leg is refused (the preimage differs): the guest runs but
earns nothing, so (2) before (3) is a hard order, enforced by the deploy
runbook, not by a fallback — a keepalive that silently dropped the leg
would make the gate unreachable rather than unsafe, and a downgrade path
is one more thing a hostile relay could steer.

**Threat model.** Unchanged in kind: the miner cannot forge or strip the
leg (it is inside the report). Root in the tenant's own VM can make the
keepalive report anything — its VM, as for the resources (T8). The leg
proves "this launch of this release booted and its agents ran", not that
they behave.

### `GuestRollout`

- **Target**: a release version. The rollout refuses to start while a VM
  in scope has no build of it for its base, and lists them; a release
  without health checks (`health_mask` 0) is canaries only.
- **Scope**: a selector (`vm_ids`, `tenant_ids`, `node_ids`, `bake_ids`,
  ANDed; an empty one is refused — it would be every VM), minus VMs
  already on the target. Its VMs are FIXED at creation (`members`): a VM
  that joins the selector later is not in the rollout, one that leaves it
  is skipped. A VM belongs to one open rollout (creations serialize on the
  open rollouts' rows).
- **Waves**: `canary` (explicit VM ids — at least one must end `done`
  before any member is touched) then cumulative percentages of the members
  (default `5, 25, 50, 100`, strictly increasing), the next ones by id; at
  most `max_concurrent` jobs (default 2) holding VMs, and one guest upgrade
  per miner at a time across every job in flight. A rollout's pending job
  leaves `pending` only with the rollout's leave (active, a free slot, a
  free miner), so a job parked on a stopped VM never starts behind a pause.
- **Advance**: when every job of a wave is terminal or `pending` on a
  stopped VM, after `wave_pause` (default 30 min). A stopped-pending VM is
  reported as such, never counted as upgraded, and keeps the rollout open
  (it is `done` only once every job is terminal).
- **Global stop**: the rollout pauses (no new job; running jobs finish, its
  pending jobs wait) on any canary outcome other than `done`, any outcome
  other than `done` / `rolled_back`, `rolled_back` above
  `max_failure_ratio` of a wave (default 10%, at least one), an admission
  refusal other than "already on the release" / "VM gone", all canaries
  skipped, or the release withdrawn.
- Pause / resume (acknowledges what stopped it; only later outcomes stop it
  again) / abort (pending jobs cancelled). Every start decision — a job
  leaving `pending` (any job: one guest upgrade per miner holds for jobs
  outside rollouts too), a rollout's tick, creation, pause, resume, abort —
  takes one global guest-upgrade lock first, then the rollout row, then the
  VM row: one lock order, no deadlock. A member that left the scope is
  skipped; a rollback counts against its own wave even after the wave
  closed. The rollout's state is its rows, so it resumes after any
  restart.
- Order in practice: a throwaway canary per family, then the operator's
  own internal VMs, then tenants. vali does not know who is internal; the
  operator names the canary and the first waves.

API (operator, root-only), mirrored by management commands:

- `POST /v1/guest-rollouts {release, canary_vm_ids, scope, waves?,
  max_concurrent?, wave_pause_s?, max_failure_ratio?, not_before?}`,
  `GET /v1/guest-rollouts/<id>`, `POST /v1/guest-rollouts/<id>/{pause,resume,abort}`;
  `vali_guest_rollout create|status|pause|resume|abort`
- `GET /v1/vm/<vm_id>/guest-components` → `{release, security_epoch,
  build_prefix, required_epoch, attested_epoch, newest_release,
  newest_security_epoch, upgrade}`
  (`release` null on a bare base; `upgrade` the job in flight, if any)
- `POST /v1/vm/<vm_id>/guest-upgrade {release, not_before?}` — the backend's
  scheduling. `not_before` absent = now; an explicit `null` is refused.
  The same `release` for a VM whose job is still `pending` moves its
  `not_before` ("upgrade now", a new window); any other job in flight is
  `409 job-in-flight`. A pending job that can no longer run (its build
  withdrawn, the VM no longer eligible) is cancelled — by that call or by
  the tick, before its window — so it never blocks a replacement.
- `GET /v1/vm/<vm_id>/guest-upgrade[/<job_id>]`, `POST
  /v1/vm/<vm_id>/guest-upgrade/<job_id>/cancel` (pending only:
  `409 not-pending` once the job holds the VM)

### Detection and metrics

`vali_guest_report` (the hourly `guest-report` CronJob, DB-only) pushes
gauges the `hippius-guest-upgrade` PrometheusRule reads:

- `hippius_guest_rollout_state{rollout,release,state}`,
  `hippius_guest_rollout_jobs{rollout,state}` → `GuestRolloutPaused`;
- `hippius_guest_upgrade_jobs{state}`,
  `hippius_guest_upgrade_outcomes_24h{state}`,
  `hippius_guest_upgrade_failures_24h{state,outcome,suspect}` →
  `GuestUpgradeFailed` (`failed` / `upgrade_blocked`, by outcome);
- `hippius_guest_vm_upgrade_stuck{vm,upgrade_job,state,outcome,suspect,power,tenant}`
  — an active VM whose latest job is `upgrade_blocked` / `failed` or parks,
  until a later job replaces it → `GuestUpgradeTenantVmDown` (critical: a
  tenant's VM not running), `GuestUpgradeVmNeedsOperator` (warning);
- `hippius_guest_upgrade_overdue_seconds{upgrade_job,vm,state}` (past its state's
  deadline: a parking job that cannot confirm DOWN, an open attempt) →
  `GuestUpgradeOverdue`;
- `hippius_guest_vm_behind_since_seconds{vm,lag}` — since when a BUILD of
  a newer release (`release`) or of a higher security epoch (`security`)
  has existed for the VM's base, judged on the release the VM booted (a
  staged swap not relaunched is still behind) → `GuestVmBehindSecurityRelease`
  (72 h), `GuestVmBehindRelease` (14 days);
- T4, two signals (critical; the operator quarantines the miner —
  automatic quarantine is not wired yet):
  - `hippius_guest_superseded_attestations_24h{vm,node}` — live
    attestations of a launch a later accepted launch superseded (the
    ingest's `superseded` verdict, which needs no stop marker: it catches
    the old guest kept running across an upgrade's relaunch) →
    `GuestSupersededGuestRunning`;
  - `hippius_guest_kbs_superseded_refusals_24h{vm,reason}` — keepalives the
    KBS refused because they came from the VM's OWN superseded guest
    (`superseded-launch` / `superseded-guest`, matched exactly; the KBS
    checks the guest against its release records first, #1405), read from
    the verified release audit log (`kbs_audit` ingest, inert until
    `kbsAuditIngest`, and off until `guestReport.kbsT4` — set it only once
    the KBS carries #1405), keepalive denials only, past the VM's last
    hand-over (a superseding register, an accepted launch, or any release
    the KBS granted — an in-guest reboot releases to a new guest) plus the
    stop margin (KBS skew + its nonce lifetime, kept equal to the KBS chart
    by CI) → `GuestKbsSupersededGuest`;
  - `hippius_guest_live_on_stopped{vm,node}` — a live attestation verified
    after a COMPLETED power stop (`Vm.stopped_by_order`) by more than the
    KBS clock skew plus a nonce lifetime → `GuestLiveOnStoppedVm`;
- `hippius_guest_report_timestamp_seconds` → `GuestReportStale` (also when
  absent). No label is named `job` or `kind`: the Pushgateway grouping
  labels would overwrite them.

Not yet: an alert on a live attestation of a measurement whose build is
below the VM's `required_epoch`. The T4 signals stay alert-only: the
operator quarantines (an automatic penalty would need node attribution
the audit does not carry).

## Maintenance windows and notices (hippius-backend)

vali enforces only `not_before`. The backend:

- stores the tenant's maintenance window (per account, overridable per VM:
  weekdays, start time, duration, UTC);
- shows a pending upgrade (`upgrade` of `GET .../guest-components`) and
  notifies the tenant: what changes, one reboot, when;
- calls `POST /v1/vm/<vm_id>/guest-upgrade` with `not_before` = the next
  window opening, or now when the tenant clicks "upgrade now";
- after the rollout's deadline (default 14 days, 72 h for an epoch raise),
  imposes it at the next window or at the deadline, with 24 h notice.

Tracked as an issue in hippius-backend with the guide, as for the resize
(#326).

## Compatibility rules (CI for every release)

- **Protocol.** The release's `hippius-guest-release` speaks what the
  deployed KBS and vali speak; the KBS keeps accepting every older guest
  still live (the §6 userdata digest is computed by three parties).
- **Every volume a live VM can have.** The release's overlay library opens
  every volume state older initrds produced (stamp history, no `data/`
  directory, earlier upper contents); CI runs it against fixture volumes of
  each live generation.
- **Every live base's initrd.** Override coverage, tool closure and module
  presence, against the real initrds (above).
- **Rollback.** The previous release can boot the volume after the new one
  did, or the release raises `security_epoch`.

## Failure cases

| case | result |
|---|---|
| Stop never confirmed (miner silent) | deadline ⇒ same-epoch target: start again on the current build if it went down, `rolled_back`; epoch raise: `upgrade_blocked` |
| Register refused / relaunch rejected 3× | `rolling_back` |
| `already-launched` or timeout on dispatch | `ambiguous`, decided by the attempt's own measurement in `verifying` |
| New guest never attests (bad release, blocked by the miner) | gate timeout ⇒ `rolling_back` if G3 allows, else `upgrade_blocked` |
| Components image fails to mount | no agent runs, no attestation ⇒ as above |
| Upper refuses the unit links | boot stops (fail-closed) ⇒ as above |
| Guest dies during the soak | as above |
| Rollback's own gate fails | `failed`, VM stopped, rollout paused, operator alerted |
| Miner reboots during `verifying` | one `recover` attempt on the same build |
| vali restarts | reconcile from the newest `UpgradeAttempt` |
| Release or build withdrawn mid-rollout | pending jobs cancelled, rollout paused, done VMs stay |
| Tenant stops the VM while `pending` | the job waits (fence register first for an epoch raise); the next power start is executed by the job |
| VM recorded stopped but still attesting | miner alert + quarantine (T4) |
| Old domain still attesting after the stop | `superseded-launch` refusals ⇒ alert + miner quarantine |

## Migration of the existing fleet

No live VM's initrd mounts a components image; their agents are the base's.
The migration is the first rollout:

1. Release 1 = current `main`: the scripts (M0, F1, R6, customer-keys inert
   in M0, …), keepalive v3, telemetry, eol with the #1322 ordering fix.
2. `vali_initrd_build --all-live-bases` (the bases of the oldest VMs
   included: their base initrd is the initrd-only rebuild they run now).
3. Roll out: a throwaway canary per family, the operator's own internal VMs, then
   tenants (rollouts need phase 5, so in practice the fleet moves to the
   first release that carries the health leg). Each VM's first boot on release 1 links the units over the
   base's and runs the agents from the image.

No base unit needs masking: the links have the same names. The base's old
binaries stay on disk, unused. The oldest VMs get the
`hippius-eol-sign.service` ordering fix (#1322) they could never get from
their base.

## Rejected alternatives

- **Swap the base.** Breaks the package database in the upper.
- **Rebuild the initrd per base with the base's own tools for every
  release** (the first version of this design, and what
  `tenant-initrd-rebuild.sh` does): needs a hermetic chroot build per base and
  release, a dracut builder with its own reproducibility work, and gains
  nothing over appending, since every Hippius file is ours anyway.
- **Install the components into the upper as files.** Per-file writes can
  fail half-way (a full disk, or I/O errors the miner injects), which leaves
  a mix of versions or falls back to the base's old agents; G1 would not
  hold.
- **A components image on a miner-supplied disk, selected by a measured
  root-hash token.** Same guarantees with no per-base build, but it needs a
  new artefact through the miner-agent, the launch spec and §25 staging; the
  append keeps everything in the one artefact the whole path already
  handles. Worth revisiting if the image grows past what the initrd should
  carry.
- **A signed-update agent (run-time download, signature checked against a
  key in the measured initrd).** No reboot, but the measurement no longer
  names the running code, a miner freezes a guest on an old version by
  blocking the download, and a floor needs its own attested protocol.
- **A per-VM UKI.** Same properties as the initrd; the golden path boots
  kernel + initrd + cmdline with kernel hashes.

## Phases

One PR each (or a short stack), with tests and a review, merged on green
CI.

1. **Design** (this document).
2. **Release cpio + boot step.** `scripts/guest/components/` (units, env,
   manifest), the squashfs builder (labels), the reproducible release cpio
   builder (with the static busybox), `hippius_golden_mount_components`
   in the overlay library and its dracut/initramfs-tools wiring. Tests: the
   boot step against temp roots (no marker = strict no-op; links, retired
   masks, fail-closed link writes, dangling links when the image is missing
   under a marker), cpio reproducibility,
   the append property, the per-base CI checks (override coverage, tool
   closure, modules) against fixture copies of the live bases' initrd file
   lists. Inert: nothing boots it until an initrd carries it.
3. **Build Job + registration.** The append Job (baker image),
   `GuestComponentRelease`, `GuestInitrdBuild`, `vali_guest_release_register`,
   `vali_initrd_build`.
4. **vali operations.** 4a: the models, build registration, the floor in
   every launch path, the interlocks (shared predicate under the VM row
   lock, job-owned power calls). 4b: `UpgradeAttempt`
   and the split relaunch (mint → register → dispatch, each recorded).
   4c: `GuestUpgradeJob`, the floor, the single-VM API, the stopped-VM
   hand-over. Flag `VALI_GUEST_UPGRADE_ENABLED` (off).
5. **Component health in `REPORT_DATA`** (keepalive + KBS + vali): gate
   condition 4. Needs a KBS roll.
6. **Rollouts.** 6a: the per-VM operator API. 6b: `GuestRollout`, waves,
   global stop, the rollout API. 6c: metrics, the PrometheusRule, the T4
   detectors, the stopped-VM fence and start hand-over.
7. **New VMs boot a release**: `vali_bless_guest_release` blesses a
   release for an image; launches by image boot its build. Later: bakes
   stop installing the agents into the base.
8. **hippius-backend issue**: windows, notices, upgrade now.

### Deploy order

1. Baker with phases 2–3. Build release 1 for ONE base, swap a THROWAWAY VM
   on it by hand (`vali_swap_vm_initrd` + power stop/start), check: the
   image mounted, the agents run from it, attested live on the new
   measurement, receipts flow, an in-guest reboot keeps it, §25 keeps it, a
   swap back to the previous build boots. Then the same on a Fedora or CS10
   throwaway (SELinux labels).
2. vali with phase 4 (flag off), then on: one job on a throwaway per family.
3. vali with phase 5, then the KBS with phase 5, then release 2 (keepalive
   with the leg): a job on a throwaway proves the health leg.
4. vali with phase 6: rollout of the operator's own internal VMs; tenants once the
   backend side is live.

## Later

- Kernel upgrades for existing VMs: ship the new kernel's modules in the
  release image, so an initrd can boot a new kernel over an old base. Own
  design (module signing, an old userspace on a newer kernel).
- Network profile migration as a release, with the NetBird gate.
- §25 "upgrade on destination": migrate a VM and boot the TARGET build at
  the destination (the escape for `upgrade_blocked` on a hostile miner).
