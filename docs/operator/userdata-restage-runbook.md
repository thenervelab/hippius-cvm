# Restaging a VM's cloud-init userdata (`vali_restage_userdata`)

How to run a one-off fix in a running tenant VM at its next boot, by giving
it a new cloud-init userdata and relaunching it. Its disks, KEK, NetBird
identity and SSH host keys are kept.

## When to use it

A guest needs a change that cloud-init can make at boot, before the
services that depend on it start. For example, a `bootcmd` that rewrites a
file before `multi-user.target`. Use it when you have no other way into the
guest, or when the change must land before the guest's own services come
up.

Do not use it for:

- **An M1/M2 VM** (`Vm.key_mode` `split` or `customer`). The command
  refuses one. The golden initramfs hands those guests the released
  userdata only on the boot that formatted their volume, and an EMPTY
  userdata on every later boot. A restage would never reach their
  cloud-init. Use the NetBird/SSH path instead.
- **A change the tenant should make.** The userdata is the tenant's. Agree
  the fix with them first.

## How it works

1. **Staging.** The command stages the new template exactly as launch
   intake does: at `{prefix}/{vm}/userdata-intake`, Transit-wrapped under
   `ud-<vm_id>`. It then points the VM's launch record
   (`LaunchJob.userdata_vault_path` / `userdata_vault_version`) at that
   version. It audits the change in `result_json.emit.userdata_restages`,
   with who, why, and the size + sha256 of the bytes. It never prints or
   stores the userdata and decrypts nothing.
2. **Relaunch.** Nothing the VM boots changes until it is relaunched. Its
   ticket binds the canonical copy the last launch staged. An in-guest
   `reboot` re-pushes that ticket, and a §25 hop re-mints from the canonical
   + working copies, not the template. Both still deliver the OLD userdata.
3. **What the relaunch does.** The relaunch (power stop + start;
   `--relaunch` does it) reads the new template. It then:
   - substitutes the NetBird placeholder;
   - re-stages the canonical copy under the KBS-only `kek-<vm_id>`, and the
     stamped working copy;
   - mints a ticket whose §6 digest is over the new plaintext.

   The KBS and the guest recompute that digest, as on every launch.
4. **What the guest does with it.** An M0 guest gets a fresh random cloud-init instance-id on EVERY boot
   (`hippius-release-core.sh` `hippius_write_seed_meta`). So the new
   userdata is applied as a NEW instance:
   - every per-instance module runs again: `users`, `ssh` (host keys are
     kept, `ssh_deletekeys: false`), `write_files`, `mounts`,
     `set_passwords`, `runcmd`, `scripts_user`;
   - `bootcmd` runs in `cloud-init.service`, before
     `network-online.target` and `multi-user.target`.

   All of this already happens on every M0 boot.

   This was proven on QEMU with cloud-init 26.1 (the Ubuntu golden's
   version). The same instance-id with a new userdata also works: NoCloud
   cannot vouch for the cached instance from `/run/cloud-init/seed/`, so
   cloud-init re-reads the seed.

## Writing the userdata

- **COMPLETE, not a patch.** It REPLACES the old userdata; nothing is
  merged. It must carry everything the original did:
  - the NetBird `{{NETBIRD_SETUP_KEY}}` placeholder when the VM enrols
    NetBird (the command refuses one without it);
  - the tenant's users and keys;
  - their `runcmd` (e.g. a cluster join script);
  - plus the fix.

  `runcmd` re-runs on every M0 boot already, so it is idempotent today. Do
  not make it less so.
- **One-shot fixes.** A `bootcmd` runs on EVERY boot for as long as this
  userdata stays staged. Make it idempotent, or run it once with:

  ```yaml
  bootcmd:
    - [ cloud-init-per, once, fix-<ticket>, sh, -c, '<command>' ]
  ```

  The `once` semaphore lives in `/var/lib/cloud/sem` on the persistent
  overlay, so it survives the per-boot instance-id. `cloud-init-per
  instance` would fire on every M0 boot.
- **Ordering.** `bootcmd` runs before `network-online.target`, so before
  units ordered after it (kubelet). It is NOT guaranteed to run before
  units ordered only after `network.target` / `local-fs.target`
  (containerd). If one of those reads the file, have the command restart
  that unit too.
- **Size.** It must fit the launch API's bound
  (`DATA_UPLOAD_MAX_MEMORY_SIZE`, 64 KiB by default).

## Procedure

Run it in a vali pod that holds the Vault credentials (the same place as
`vali_swap_vm_initrd`). Feed the userdata on stdin so the plaintext never
lands on the pod's filesystem.

1. **Dry run.** It shows the VM, its key mode, the current pointer, and the
   size, sha256 and target version of what would be staged:

   ```bash
   kubectl -n vali exec -i deploy/vali-launch-tick -- \
     python manage.py vali_restage_userdata --vm-id <vm> \
       --userdata-file /dev/stdin --by <you> --reason "<ticket>: <why>" \
       --dry-run < fix.yaml
   ```

2. **Apply and relaunch.** Drop `--dry-run` and add `--relaunch`. The
   output prints the rollback command. Without `--relaunch`, relaunch later
   with the power API (stop, then start).
3. **Verify:**
   - a new `VmLiveAttestation` of the VM's new measurement (the
     relaunch's KEK release happened);
   - the fix in the guest;
   - `cloud-init status --long` is `done`.
4. **Restage the original** once the fix is in, so the fix stops riding
   every boot. Either:
   - roll back to the version you replaced (`--to-version <N>`, printed at
     step 2); or
   - restage the original file.

   Then relaunch again, or let the next relaunch pick it up.

## Rollback

- `--to-version <N>` points the record back at version N of
  `{prefix}/{vm}/userdata-intake`. Vault KV keeps a path's last versions
  (the mount's `max_versions`, 10 by default).
- `--revert-last` restores the pointer the latest restage replaced, from
  the audit trail. Use it when that pointer was a legacy path (a VM
  launched before `userdata-intake` existed); the apply output says so.

Neither writes new bytes or decrypts anything. Both take effect at the next
relaunch.

## Refusals

Nothing is written when any of these holds:

- the VM is not `active` + powered `running`;
- a §25/restore, decommission, resize, guest upgrade, power op,
  reboot-recovery relaunch or launch job is in flight;
- the VM has no launch record;
- the VM is not provably M0: the `Vm` pin, and the record's measured
  cmdline, which must agree;
- the userdata is empty, not UTF-8, `vault:`-prefixed, over the cap, or
  lacks the NetBird placeholder;
- a rollback names a version a relaunch could not read back: pruned from
  Vault's history, an unwrapped value at the intake path, or the KBS-only
  canonical copy.

All checks run again under the Vm row lock, which is held across the Vault
write. If the record moved between the two (another restage), the version
just staged is inert: nothing points at it, and §24 erases the whole path.
The command says so. `--relaunch` checks once more before the power stop,
and leaves the VM alone if a launch or a power op took it in between.

Residual: a launch intake re-POSTed for the SAME live vm_id right after
that last check is not serialized with the stop/start. Power ops do not
refuse launch jobs (the power API has the same gap). Don't run the command
while the upper layer might re-launch the VM.
