# Stranded §25 migration — detection and recovery

**Symptom.** A tenant VM is DOWN. `Vm.state = migrating`, its `MigrationJob`
is `failed`, and `virsh list --all` shows no domain on **either** host.

**Alarm.** `orchestration tick: … stranded_migrations=N` in the
`vali-orchestration-tick` log, plus a per-tick `ERROR` from
`apps.orchestration.service` naming every affected `vm_id` and its verdict.
Any non-zero `stranded_migrations` is an outage.

---

## Why the VM is stuck

`_fail_migration` from `Quiescing` onward leaves the `Vm` fenced
`migrating`: the source guest was gracefully stopped (it signed its
`stopped{}` ack) and the destination never came up. Every automatic sweep
in vali scans a different set —

| sweep | scans |
|---|---|
| `reboot_recovery_once` | `Vm.state = active` |
| `sweep_guest_liveness` | `Vm.state = active` |
| `reclaim_migrated_sources` | `MigrationJob.state = done` |

— so a `migrating` VM behind a terminal job is in none of them.

## The one thing that decides the recovery

`effects.kbs_activate_dest` moves the KBS `VmState` to
`Migrating{old_gen, new_gen, source, dest}`. From that instant
`kbs_core::lifecycle::check_releasable` releases the tenant KEK to
`(new_gen, dest-chip)` **and to nothing else**.

There is **no route back**. The KBS admin surface has three lifecycle
writes — `register-vm`, `activate`, `seed-boot-counter` — and:

* `activate` requires the current state to be `Active` and requires
  `new_gen` to strictly increase; from `Migrating` it returns `409
  activate-conflict` (or `200 cached` for the identical request);
* `register-vm` on a state that differs from the request is a
  `409`-with-no-write.

So the recovery is decided by **one question**: did the migration ever
enter `DestActivating`? That is the sole state that calls
`kbs_activate_dest` (and the sole state that dispatches
`migrate-activate` to the destination at all).

| answer | KBS state | recovery |
|---|---|---|
| never entered it | `Active{source_gen, source}` | **source restore** — un-fence back to the source. Automatic. |
| entered it | `Migrating{new_gen, dest}` | **forward re-drive** of the SAME dest at the SAME `new_gen`. Operator. |

A "source restore" in the second row would un-fence a guest that can never
obtain its KEK (it boots and hangs in its initramfs, burning the relaunch
budget) **and** leave vali claiming `Active{source}` while the KBS says the
destination owns the VM — so a destination that later recovered would
activate at `new_gen` behind vali's back. That is why the command refuses
it, and why `--action restore-source` cannot force it.

## The evidence rule

`service.stranded_recovery_verdict` is the single decision point; the sweep
and the command share it. It PERMITS a restore only on
`MigrationJob.failed_from_state ∈ {draining, quiescing, snapshotting,
uploading, fencing, awaiting_source_ack}` — a column only `_fail_migration`
writes — **and** after these vetoes all pass:

1. `failed_from_state == dest_activating`;
2. the free-text `reason` prefix names `dest_activating` (this is what
   classifies jobs written before the column existed — the string may
   VETO, never PERMIT);
3. an `OrderTicketIntake` at `new_gen` exists (only
   `dispatch_migrate_activate` mints one, and it runs *after*
   `kbs_activate_dest`);
4. a §14 idempotency marker for either `DestActivating` effect is present,
   or the store cannot be read;
5. the KBS's own latest evidence bundle for the VM is anything other than
   the source's own grant at `source_gen` — or the KBS cannot be read.

Bundle **absence** is ambiguous (the KBS evidence sink is an `emptyDir`;
a KBS restart erases it) and is therefore neither a permit nor a veto.

Everything else — including a blank `failed_from_state`, which is every job
created before this shipped — is `blocked`, reported, and left alone.

---

## Recovery

Always start with the dry run. It computes the REAL verdict, including the
KBS read.

```bash
# survey
kubectl -n <ns> exec deploy/vali -- python manage.py vali_migration_recover --all-stranded

# one VM
kubectl -n <ns> exec deploy/vali -- python manage.py vali_migration_recover --vm-id <vm-id>
```

### `restore-source`

```bash
python manage.py vali_migration_recover --vm-id <vm-id> --commit
```

Un-fences to `active` on the source at `source_gen`, clears
`migration_dest` / `new_generation`, and settles the failed job's
`source_reclaim_state` to `skipped` (the source now holds the VM's only
copy — it must never be reclaimed). The guest is then brought back by
reboot-recovery, so confirm:

* `VALI_REBOOT_RECOVERY_ENABLED` is on;
* the source miner is on-chain-`Active` with a fresh heartbeat;
* the VM's `RebootRecovery.seen_running` is true (the #854 gate).

**Known limitation** (fail-closed, not data loss): a VM that has already
been migrated once carries `generation >= 2`, and a fresh launch bakes
`hippius.vm_generation=1` into the measured cmdline — so reboot-recovery
cannot relaunch it. The overlay is untouched; the recovery is a manual
re-launch or migration.

The tick sweep does this automatically. The command is for when
`VALI_MIGRATION_STRAND_RESTORE_ENABLED` is off, or a CAS lost.

### `redrive-dest`

**Fix the destination first.** The re-drive sends the same restore to the
same host; if it is still broken it will fail the same way.

```bash
python manage.py vali_migration_recover --vm-id <vm-id> --commit
```

This:

1. re-mints the destination `OrderTicket` at `new_gen` **fresh**
   (`reuse_existing=False`) — tickets carry a 24h expiry, and a re-drive a
   day later with the stored blob gets a `400` from the KBS;
2. opens a new `MigrationJob` at `DestActivating` carrying the failed job's
   `source_node_id` / `dest_node_id` / `source_gen` / `new_gen` /
   `snapshot_*` and its already-verified `source_ack_verified`;
3. leaves the rest to `vali_orchestration_tick`, which re-issues
   `kbs_activate_dest` (a `200 cached` at the KBS — the state is already
   what it would write), re-dispatches `migrate-activate` under a
   job-scoped `order_id`, polls, and on `done` activates the VM on the
   destination.

It refuses when:

* the failed job has no verified source-stopped ack (the §25 split-brain
  gate — a re-drive may never invent one);
* the job records no snapshot object;
* the destination reports a restore still `running` (a second concurrent
  restore of one VM) or already `done` (investigate instead of re-running);
* the VM already has an in-flight orchestration job.

An **unreachable** destination is not a refusal — that is the
post-agent-restart state a re-drive is for. It will fail loudly at the
dispatch, having mutated nothing on the VM.

### Neither is possible

If the destination is permanently gone (hardware loss) after
`kbs_activate_dest` fired, the disk is unrecoverable through the control
plane: only that chip at `new_gen` can obtain the KEK. The VM's remaining
lifecycle action is a §24 decommission (crypto-erase + reclaim). Escalate —
do not hand-edit the `Vm` row.

---

## What NOT to do

* **Do not** hand-edit `Vm.state` back to `active`. That is exactly the
  un-fence the evidence rule exists to gate; on a KBS-committed migration
  it produces a permanently wedged guest and a vali row that lies about who
  owns the VM.
* **Do not** hand-edit `MigrationJob.failed_from_state`. It is the permit
  input to the automatic restore (which is why it is read-only in the Django
  admin).
* **Do not** `register-vm` the VM back to `Active{source}` at the KBS to
  "fix" a committed migration. It is a `409`-with-no-write, and if it ever
  stopped being one it would be the split-brain primitive.
* **Do not** delete the source's `overlay/<vm>.img` / `state/<vm>.raw`. On a
  failed migration those are the tenant's only copy — which is why #936's
  reclaim gate holds at `pending` for an unproven destination.
