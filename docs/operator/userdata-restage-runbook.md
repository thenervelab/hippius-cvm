# Restaging a VM's cloud-init userdata

How to run a one-off fix in a running tenant VM at its next boot, by giving
it a new cloud-init userdata and relaunching it. Its disks, KEK, NetBird
identity and SSH host keys are kept.

There are two front ends to the same operation
(`apps.orchestration.userdata_restage`):

- **the API**, `POST /v1/vm/<id>/userdata/restage`. It is root-only and off
  by default. The upper layer (hippius-backend) uses it: it rebuilds the
  complete userdata, guest secrets included, and must not hand it over
  through a person;
- **the operator CLI**, `vali_restage_userdata`, which reads a file in a
  vali pod.

## When to use it

A guest needs a change that cloud-init can make at boot, before the
services that depend on it start. For example, a `bootcmd` that rewrites a
file before `multi-user.target`. Use it when you have no other way into the
guest, or when the change must land before the guest's own services come
up.

Do not use it for:

- **An M1/M2 VM** (`Vm.key_mode` `split` or `customer`). It is refused
  (409 `userdata-restage-unsupported-key-mode`). The golden initramfs hands
  those guests the released userdata only on the boot that formatted their
  volume, and an EMPTY userdata on every later boot. A restage would never
  reach their cloud-init. Use the NetBird/SSH path instead.
- **A change the tenant should make.** The userdata is the tenant's. Agree
  the fix with them first.

## How it works

1. **Staging.** The new userdata is staged as a new version at
   `{prefix}/{vm}/userdata-intake`, Transit-wrapped under `ud-<vm_id>` like
   the launch intake's. A verbatim stamp is written inside the wrapping.
2. **Pointing.** The VM's launch record (`LaunchJob.userdata_vault_path` /
   `userdata_vault_version`) is pointed at that version. The change is
   audited in `result_json.emit.userdata_restages`: who, why, the
   `request_id`, and the size + sha256 of the bytes. Nothing prints, logs
   or stores the userdata, and nothing is decrypted.
3. **Byte for byte.** The bytes are stored and delivered exactly as given.
   **No token is required and none is substituted**: not
   `{{NETBIRD_SETUP_KEY}}`, not `{{NETBIRD_HOSTNAME}}`, not anything else.
   The relaunch mints no NetBird key for the VM: the guest is already
   enrolled, and its userdata carries whatever it needs.
4. **Nothing changes until the relaunch.** The VM's ticket binds the
   canonical copy the last launch staged. An in-guest `reboot` re-pushes
   that ticket, and a §25 hop re-mints from the canonical + working copies,
   not the template. Both still deliver the OLD userdata.
5. **The relaunch** (power stop + start) reads the new version. It then:
   - re-stages the canonical copy under the KBS-only `kek-<vm_id>`, and the
     working copy;
   - mints a ticket whose §6 digest is over these exact bytes.

   The KBS and the guest recompute that digest, as on every launch.
6. **What the guest does with it.** An M0 guest gets a fresh random
   cloud-init instance-id on EVERY boot (`hippius-release-core.sh`). So the
   new userdata is applied as a NEW instance:
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

- **COMPLETE, real values, not a template.** It REPLACES the old userdata;
  nothing is merged, and nothing is filled in. It must carry everything the
  guest's userdata did, as the guest should receive it:
  - its agent tokens and keys;
  - its NetBird line (a setup key, or an inert one for an already-enrolled
    peer);
  - its `runcmd`, e.g. a cluster join script;
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
  (`DATA_UPLOAD_MAX_MEMORY_SIZE`, 64 KiB by default). The API body carries
  it base64-encoded, so the userdata itself must stay under ~48 KiB there.

## The API

**Enable it.** Set `VALI_USERDATA_RESTAGE_ENABLED=true` and list the VMs in
`VALI_USERDATA_RESTAGE_VM_ALLOWLIST` (comma-separated vm_ids). An empty
list allows none. Otherwise the API answers 403
`userdata-restage-disabled` / `userdata-restage-not-allowed`. Turn it back
off and empty the list once the repair is done.

`/v1/vm` is published as a prefix on the public Ingress, so these routes
are reachable from outside. They are root-only (`IsOrchestrationRoot`,
`OPERATOR_ONLY`), and a test pins that on both routes.

1. **Dry run** (the default). Checks everything and writes nothing:

   ```
   POST /v1/vm/<id>/userdata/restage
   {"userdata_b64": "<base64>", "request_id": "<id>"}
   → 200 {"dry_run": true, "size", "digest_hex", "current_version",
          "would_be_version", "checks": {...}}
   ```

   `digest_hex` is the sha256 of the bytes. (The §6 digest binds a ticket
   id, so it is minted at the relaunch.)
2. **Apply.** Send the same body with `"dry_run": false`:
   - it answers `202 {"job_id", "phase": "staged", ...}`;
   - the bytes are staged and the record pointed in that request;
   - `vali_orchestration_tick` then relaunches the VM;
   - replaying a `request_id` returns its job; the same `request_id` with
     another body answers 409 `request-id-reused`.
3. **Poll** `GET /v1/vm/<id>/userdata/restage/<job_id>`:
   - `phase`: `staged` → `relaunching` → `running` | `failed`. `running`
     means the relaunch was accepted, the VM runs, and the record holds the
     new boot's measurement. Confirm the KBS release with its
     `VmLiveAttestation`;
   - `outcome`: `null` → `committed` | `failed`;
   - `error` on failure. A failed job leaves the record pointing at the new
     version, so the VM's next relaunch takes it.
4. **Roll back** with `{"rollback_to_version": N, "request_id": ..., "dry_run":
   false}`. It re-points to version N of the intake path and relaunches,
   with the same job shape. A rolled-back-to version keeps how it was
   staged: a launch template is substituted again at relaunch, a restaged
   one is delivered verbatim.
   `{"revert_last": true, ...}` instead puts back the exact pointer the
   latest restage replaced, from the audit trail. Use it when that pointer
   was a legacy path.

| Answer | When |
|---|---|
| 400 `wire` / `bad-userdata` | bad body, malformed base64, empty / non-UTF-8 / `vault:`-prefixed userdata |
| 403 | not root, `userdata-restage-disabled`, `userdata-restage-not-allowed` |
| 404 | unknown VM / job |
| 409 `userdata-restage-unsupported-key-mode` | M1/M2 |
| 409 `vm-not-restageable` | not active + running; a migration, decommission, resize, guest upgrade, power op, recovery relaunch, launch job or restage in flight; no launch record; a record that pins a measurement or does not auto-pin (a relaunch could never unlock it); a write that would prune the pointed version, or lost Vault check-and-set (retry) |
| 409 `rollback-unavailable` | the version is pruned, unwrapped, the canonical copy, or the current one |
| 409 `request-id-reused` | see above |
| 413 | over the launch limit |

## The CLI

Run it in a vali pod that holds the Vault credentials (the same place as
`vali_swap_vm_initrd`). Feed the userdata on stdin so the plaintext never
lands on the pod's filesystem. The CLI is behind the same flag and
allow-list as the API.

1. **Dry run:**

   ```bash
   kubectl -n vali exec -i deploy/vali-launch-tick -- \
     python manage.py vali_restage_userdata --vm-id <vm> \
       --userdata-file /dev/stdin --by <you> --reason "<ticket>: <why>" \
       --dry-run < fix.yaml
   ```

2. **Apply and relaunch.** Drop `--dry-run` and add `--relaunch`. This
   admits the same tracked job the API creates: it holds the VM and the tick
   stops and starts it. The output prints the job id; poll it with the
   API's `GET`. Without `--relaunch` only the record moves; the output then
   prints the rollback command.
3. **Roll back:**
   - `--to-version <N>` re-points to version N of the intake path. Vault KV
     keeps a path's last versions (the mount's `max_versions`, 10 by
     default).
   - `--revert-last` restores the pointer the latest restage replaced, from
     the audit trail. Use it when that pointer was a legacy path (a VM
     launched before `userdata-intake` existed).

## After the fix

1. **Verify:**
   - a new `VmLiveAttestation` of the VM's new measurement (the relaunch's
     KEK release happened);
   - the fix in the guest;
   - `cloud-init status --long` is `done`.
2. **Restage the original** once the fix is in, so the fix stops riding
   every boot: roll back to the version you replaced, or restage the
   original bytes.
3. **Disable** the API flag and empty the allow-list.

## Concurrency and the residual

All checks run again under the Vm row lock, and that lock is held across
the Vault write. A decommission cannot erase the path ahead of the write.
If the record moved in between, the version just staged is inert: nothing
points at it, and §24 erases the whole path. A restage also refuses to
write the version that would push the record's current one out of Vault's
history (`VALI_VAULT_KV_MAX_VERSIONS`, 10).

**API jobs hold the VM** from admission until they settle, as a resize or a
guest upgrade does. Other power ops answer `userdata-restage-in-flight`, and
§25 / §24 / resize / backup / launch intake for that vm_id are refused.
Only the job's own stop and start pass.

The tick relaunches in steps:
1. it stops the VM, once;
2. it starts it, retrying a transient refusal (`allowlist-pin-busy`, ...)
   on later ticks, so a VM it stopped is brought back;
3. it commits only once the launch record holds the relaunch's own new
   measurement.

It gives up after 10 dispatches or 30 minutes. The job's `error` then says
in which power state it left the VM.

Power operations and launch intake refuse each other for the same vm_id,
under the same Vm row lock:
- a power stop/start answers `launch-in-flight` while a launch job is
  queued, or running inside the launch-orphan bound (an orphan the janitor
  cannot settle does not disable the VM's power);
- launch intake answers `conflict` while a power `stopping`/`starting`
  marker is live, or reboot-recovery is relaunching the VM;
- §25 and restore admission refuse a launch in flight too, because their
  own stop/start bypass the power check. Failover does not refuse it: its
  host is presumed dead.

A restage — API or CLI `--relaunch` — holds the VM from admission until the
relaunch settles, so nothing can slip in between its stop and its start.
The plain power `reboot` (stop, then start) has no job: a launch admitted
in the instant between its two halves makes the start answer
`launch-in-flight`, and the VM stays stopped rather than racing the launch.
