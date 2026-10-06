# Design: Live VM backups and failover to another miner

**Status:** Backups implemented; restore of a current-boot point (same or another miner) and operator-only manual failover implemented in vali, behind `VALI_RESTORE_ENABLED` / `VALI_FAILOVER_MANUAL_ENABLED`; restore of an earlier-boot point through a KBS-authorized rollback (§8.5) implemented in vali behind `VALI_RESTORE_ROLLBACK_ENABLED`; automatic failover is a later part · **Date:** 2026-09-28

## 1. Goal

A VM that opts in is backed up continuously while it runs. If the miner
hosting it dies, the VM is started again on another miner from its latest
backup, with its data up to the backup interval (the recovery point
objective).

Two properties are not negotiable:

- **The miner stays untrusted.** It only ever holds ciphertext and
  short-lived presigned URLs. It never holds a storage credential and never
  sees a key.
- **A restore can never roll a VM back behind the anti-rollback checks
  on its own.** A backup the KBS or the guest would refuse is not offered
  as a restore point. Going back past a reboot is possible only as an
  explicit, audited rollback that the KBS itself authorizes for one
  release (§8.5).

Backups are **crash-consistent**, like pulling the power cord: there is no
trusted agent inside a confidential VM to quiesce applications. File
systems replay their journal on the restored boot.

## 2. What a backup is

A golden VM's writable state lives in two host files:

- the **overlay** (`/dev/vda`): LUKS2 + dm-integrity ciphertext over the
  read-only dm-verity base. This is the tenant disk;
- the **state disk** (`/dev/vdd`, 1 MiB): the plaintext boot counter the
  KBS checks on every key release.

Every run leaves a **point**: an in-memory dirty bitmap named after the run
(`hippius-bk-<run_id>`). The miner creates it in the same QMP `transaction`
as the run's copy, so the bitmap and the copy start at exactly the same
instant. From then on it records every write since that run.

A **full** backup is a point-in-time copy of the whole overlay, taken while
the guest runs (QMP `blockdev-backup sync=full`).

An **incremental** backup copies only the clusters dirtied since its
**parent**, the chain's newest run that vali has committed. The miner copies
from the parent's point with `bitmap-mode=never`, so the parent is never
consumed. The copy goes into a qcow2 file with no backing file, which holds
only the dirty clusters.

A run that fails, or whose answer never reaches vali, therefore loses
nothing. The next incremental is taken from the same parent and covers
everything since. The miner keeps only the parent's point and the new run's
point, and prunes the rest.

Every run also uploads the state disk, as it was at that instant.

A **chain** is one full backup followed by its incrementals, all taken
within **one boot** of the guest. It is rebuilt by writing the full, then
committing each incremental onto it in order.

Nothing is compressed. The overlay is ciphertext and does not compress, and
an integrity-formatted overlay has no unwritten regions, so a full costs the
whole disk size in both transfer and storage. An incremental costs roughly
three times what the guest wrote, because the dm-integrity and file-system
journals are written too.

## 3. Only the current boot is restorable

Every boot moves two anti-rollback values forward:

- the KBS's stored **boot counter**. A release is refused if the counter
  the guest presents goes backwards;
- the overlay's **volume stamp**. The guest refuses an overlay older than
  its expected stamp.

Both values ride inside the backup: the counter is in the state disk and
the stamp is in the overlay. A backup taken during an earlier boot carries
values that are now behind, so the KBS or the guest refuses it. No admin
route lowers them, by design. The one exception is a one-shot rollback arm
bound to a KBS-signed checkpoint of that earlier boot (§8.5).

Hence the invariant:

> A chain is restorable **iff** its boot counter equals the VM's current
> boot counter.

It follows that:

- a reboot makes every existing chain unrestorable. vali takes a new full
  backup as soon as it sees the new boot;
- the dirty bitmap lives in QEMU's memory and dies with it, which happens
  on every reboot anyway. A chain never has to span two boots.

vali learns the current counter from the miner, which reads it from the
state disk:

- with every run report;
- from a cheap periodic probe between runs (`VALI_BACKUP_PROBE_INTERVAL_S`).

That value is host-read and unattested. It is only used to tell boots
apart, and lying about it gains the host nothing: the KBS still enforces the
real counter at restore time. vali never adopts a counter lower than one it
has already seen, which would make an old chain look current again. A run
whose poll shows the counter going backwards is failed, and a full backup
follows. vali
also folds in the live counter on every poll of a run in flight, so a
reboot during a run retires the old chain at once.

## 4. Storage

Backups go into **one bucket owned by vali's own storage account**
(`VALI_BACKUP_BUCKET`, e.g. `hippius-vm-backup`), with one prefix per VM. The tenant has no right on
it, so it can neither delete nor hide a backup. The layer above shows
restore points and bills stored bytes from vali's API (section 7), not from
the tenant's own storage.

Object keys, per run:

```
backups/<vm_id>/<chain_id>/<seq>.full.raw | <seq>.inc.qcow2   the disk piece
backups/<vm_id>/<chain_id>/<seq>.state                        the state disk (1 MiB), written by vali
backups/<vm_id>/<chain_id>/<seq>.manifest.json                written by vali
uploads/<vm_id>/<chain_id>/<seq>.state                        where the miner PUTs the state disk
```

The miner's state-disk URL points at a staging key under `uploads/`. When
the run completes, vali reads the staged copy back, checks its size and
sha256 against the report, and writes it to the final key, which no
presigned URL ever pointed at. A presigned `PUT` stays valid until it
expires, so this keeps a miner from rewriting a state disk after its run
is accepted.

Two rules catch what a crash can leave behind. vali enforces them itself: a
store may acknowledge `PutBucketLifecycle` without enforcing it, and Hippius
S3 does exactly that. The **janitor** (`apps/backup/janitor.py`) runs in the
backup tick and applies both. Listing is the one call it needs beyond
object access. If the key is not allowed to list, the janitor logs a WARNING
once per interval and backs off. Backups themselves are unaffected.

- **Stale multipart uploads.** It aborts uploads under `backups/` older than
  `VALI_BACKUP_MPU_MAX_AGE_S` (2 days) that no active run owns.
- **Stale staged state disks.** It deletes objects under `uploads/` older
  than `VALI_BACKUP_STAGING_MAX_AGE_S` (2 days) that no active run owns.

Its work is bounded. Each tick handles at most `VALI_BACKUP_JANITOR_BATCH`
items per rule. The client also enforces the page size and the markers
itself, because a store may ignore `MaxUploads` and the markers; Hippius S3
does. A single item the store refuses is skipped until the next sweep. A sweep that does not fit resumes from the store's listing
marker on the next tick, and a finished sweep restarts after
`VALI_BACKUP_JANITOR_INTERVAL_S`. The janitor never lists or touches
anything outside those two prefixes.

**The bucket itself.**

- `VALI_BACKUP_BUCKET` has no default and must name a dedicated private
  bucket. vali refuses the images bucket (it is public-read) and the
  migration-snapshot bucket.
- **Its own key.** The backup bucket is reached with its own key
  (`VALI_BACKUP_S3_ACCESS_KEY_ID`, `VALI_BACKUP_S3_SECRET_ACCESS_KEY`,
  `VALI_BACKUP_S3_ENDPOINT_URL`), never vali's default S3 credentials.
  - The key is an object-level token scoped to that one bucket: object
    reads and writes, and multipart create, upload and abort. vali makes
    no bucket-admin call with it.
  - The client uses path-style addressing and SigV4.
  - The secret is never logged.
  - The chart wires it in from a Secret (`vmBackup.credentials`, off by
    default and rendering nothing).
- Every tick first proves vali's key can reach the bucket, with a GET of a
  key that is never written, re-proven every ten minutes. `NoSuchKey` means
  the bucket is reachable; `NoSuchBucket`, `AccessDenied` or a transport
  error means it is not.
- When it cannot, the tick logs an ERROR and does no backup work, and new
  policies are refused with `503 backup-unavailable`.

The manifest records the kind, seq, parent seq, boot counter, generation,
sizes, the sha256 of each piece and of each part, and timestamps. With the
manifests alone, a chain can be rebuilt without vali's database.

The disk piece is a **multipart upload that vali drives**:

1. vali opens the upload with its own credentials
   (`CreateMultipartUpload`);
2. it presigns one `UploadPart` URL per part, plus a single `PUT` for the
   state disk;
3. it puts them in the order;
4. the miner uploads raw byte ranges and reports each part's ETag and
   sha256;
5. vali completes the upload (`CompleteMultipartUpload`) or aborts it.

The miner cannot complete, abort, overwrite or read anything.

**Checking the miner's report against the store.** vali marks a run done
only when:

- the multipart upload completes with the reported ETags;
- the object has exactly the reported size;
- for a full, that size is the whole overlay;
- the state disk matches its reported size and sha256.

A store outage while finalising gets twice the run timeout before the run
is given up: the miner is done at that point, and the backup may already be
complete. Finalisation is idempotent. If vali completed the upload and died before
recording it, the retry sees `NoSuchUpload`, finds the object already in
place at the right size, and accepts it.

**Part sizing.** One order carries at most 100 part URLs, so that it fits
the 64 KiB signed-order limit. The part size is chosen to cover the largest
piece a run of that disk can produce: the full disk, or an incremental with
every cluster dirty plus qcow2 metadata. Parts are at least
`VALI_BACKUP_MIN_PART_BYTES` (256 MiB) and at most 5 GiB, which caps a
backed-up disk at about 490 GiB. A policy for a larger disk is refused.

## 5. The wire contract

vali dispatches backups over the signed-order path every lifecycle order
uses: vali → Edge `/v1/edge/order` (kind `backup`) → the miner's
`/v1/miner/order/backup`. It polls through an unsigned Edge relay:
`GET /v1/relay/{vm_id}/backup` → the miner's
`/v1/miner/backup/{vm_id}/status`.

The miner-agent owns the types (`orders::types::BackupOrder`,
`backup::RunStatus`, `backup::restore::RestoreChain`). The Edge relays them
opaquely. `ticket-validator encode-order` builds the orders, and its tests
decode them through mirrors of the miner's types.

**`backup` order.** Fields:

- `vm_id`, `run_id`, `parent_run_id` (required for an incremental), `kind`
  (`full` | `incremental`);
- `part_size`, `disk_part_urls[]`;
- `state_put_url`.

The chain id and seq stay vali-side.

Behaviour:

- **Parent of a full.** A full names the current chain's newest committed
  run as its parent. That keeps the point alive, so the chain can still
  continue if the full fails.
- **Part layout.** Part `i` is bytes `[(i-1)·part_size, min(i·part_size,
  size))` of the piece.
- **Answers:**
  - `200` when the order is accepted;
  - `409 backup-in-flight` when another run of that VM is in flight;
  - `422` for an invalid order;
  - `503` when backups are disabled on the miner.
- **Missing parent point.** A run whose parent point is gone, because QEMU
  restarted or the guest rebooted, fails with `bitmap-missing`.

**Status.** `200 {vm_id, live: {boot_counter, point_run_ids}, run}`:

- `live` is read at poll time:
  - `boot_counter` is the state disk's committed value, or null;
  - `point_run_ids` lists the runs whose point still exists. It is `[]` when
    the domain is not running, because points die with QEMU.
- `run` is the VM's latest run since the agent started, or null. Its fields:
  - `run_id`, `parent_run_id`, `kind`, `status` (`running` | `done` |
    `failed`), `error`;
  - `bitmap_present`, meaning this run left a point that can be a parent;
  - `boot_counter`, `virtual_size`;
  - `disk` and `state`, each `{parts: [{part_number, etag, sha256_hex,
    size}], size, sha256_hex}`.

The other answers:

- `404 no-domain`: that host has no domain for the VM. For a run in flight,
  vali declares the run lost after the grace period.
- `503 status-unavailable`: libvirt or QMP is down. vali retries it and never
  reads it as an empty point list.

The miner keeps only the latest run, so vali reads a run's outcome before it
sends the VM's next order.

Failure classes vali acts on:

- `bitmap-missing`: the parent point is gone, so the next run is a full;
- `state-changed`: the guest booted mid-run, so the next run is a full;
- `run-exists`: the run id was already taken, i.e. an earlier dispatch whose
  answer was lost. vali follows that run through the status.

The between-run probe uses `live` to catch a reboot within
`VALI_BACKUP_PROBE_INTERVAL_S`. A reboot within one probe interval of a
miner dying still goes unseen, so a restore must confirm the counter against
the KBS (section 9).

**Restore.** `migrate-activate` gains an optional `backup_chain`:
`{restore_id, full, incrementals[], state}`.

- Each piece is `{url, sha256_hex, size}`, where `url` is a presigned GET of
  the completed object.
- `restore_id` is unique per attempt.
- The destination ignores `get_url` / `state_get_url`.
- It verifies every piece before applying it. On any mismatch it fails
  closed: it never boots a half-applied chain.
- Without `backup_chain`, a §25 migration is byte-for-byte unchanged.

## 6. The tick (vali `apps/backup`)

Each orchestration tick, when `VALI_BACKUP_ENABLED`:

1. **Follow in-flight runs.**
   - Re-send a pending order. The miner dedups on `backup-<run_id>`.
   - Poll a running one.
   - On `done`, check that the report is consistent with the order:
     - the kind and the echoed parent;
     - parts numbered 1..n, each exactly `part_size` except the last, adding
       up to the piece size;
     - the sha256 formats;
     - a 1 MiB state disk;
     - a boot counter;
     - for an incremental, the chain's boot counter.

     Then write the manifest and complete the upload.
   - On `failed`, a timeout (`VALI_BACKUP_RUN_TIMEOUT_S`, which is also the
     presign TTL), or a run the miner forgot (`VALI_BACKUP_LOST_GRACE_S`),
     abort the upload.
2. **Start due runs.** One run per VM at a time, enforced by a database
   constraint. Only for VMs that are `active`, powered on and placed.
   - **Full** when any of these holds:
     - the policy is new or re-enabled;
     - a new boot was seen;
     - the chain's newest point is gone (it is missing from
       `live.point_run_ids`, a run is refused `bitmap-missing`, or a done
       run reports `bitmap_present` false);
     - the chain holds `VALI_BACKUP_MAX_CHAIN` incrementals (default 24);
     - the chain's incrementals exceed half the full.
   - **Incremental** otherwise.
   - A required full (new boot, lost bitmap) starts **now**. Anything else
     waits for the interval.
   - A failure waits `VALI_BACKUP_RETRY_AFTER_S`, or the interval if that is
     shorter.
   - A lost run, a timeout or an order whose answer never came back is
     retried from the same parent: it could not consume that point.
   - A refused report or refused stored objects forces a full: the miner is
     then behaving unexpectedly.
   - Interval tiers: 24 h, 6 h, 1 h, 15 min.
3. **Prune whole chains:**
   - failed chains at once;
   - superseded chains (a newer full is done, or the policy was disabled)
     after the policy's `retention_days`;
   - every chain of a destroyed VM. Its key is gone, so its backups can
     never be decrypted.

   A chain is never pruned partially.

The **restore point** is the newest chain whose boot counter equals the
current one, and within it the full plus every `done` incremental in seq
order. Failed runs leave gaps in `seq` but no gap in the data, because
every incremental is taken from the newest committed run.

## 7. API (root only)

| Method · path | |
|---|---|
| `PUT /v1/vm/<id>/backup-policy` | `{interval_s, retention_days?, failover_mode?}`. Golden VMs only. `201` created or re-enabled, `200` updated. |
| `GET /v1/vm/<id>/backup-policy` | The enabled policy, or `404 no-backup-policy`. |
| `DELETE /v1/vm/<id>/backup-policy` | Stops new backups. Existing chains are kept for `retention_days`. |
| `GET /v1/vm/<id>/backups` | `backup_state`, `restore_point`, `stored_bytes` (billing), every unpruned chain with its runs, and `last_failure` (the newest finished run when it failed, pruned chains included). No object keys and no URLs. |

The VM wire shape gains `backup_state`, one of:

- `disabled`;
- `pending`: nothing completed yet;
- `ok`: a restore point no older than the interval plus two hours;
- `stale`: nothing restorable, typically right after a reboot, or the
  newest point is too old.

## 8. Restore

A restore puts a VM back, **in place**, to one of its backup points: same
`vm_id`, same key, same NetBird identity (so its overlay and public
addresses follow), same billing row. Only **current-boot** points are
restorable as such (§3); a point of an earlier boot needs a KBS-authorized
rollback (§8.5), and is refused (`rollback-unsupported`) while that is off.

### 8.1 Points

vali classifies every run (`GET /v1/vm/<id>/backups`, `point` on each run):

- `current-boot`: the run is DONE, every run it builds on is DONE (the
  chain's full, then each incremental naming the previous DONE run as its
  parent), the chain's counter equals the VM's current counter, and the
  chain began after the VM's last completed move (a migration or restore
  boots the guest anew even before the host-read counter catches up).
- `rollback`: the same, from an earlier boot. Restorable only when the run
  carries a KBS checkpoint of its own boot and rollbacks are enabled
  (§8.5).
- `unavailable`: an unfinished run, a failed or pruned chain, a missing
  earlier run, or a VM being destroyed.

A lying host can only make a `current-boot` classification wrong in the
fail-closed direction: the KBS refuses any counter other than
`stored + 1`, before the commit point, and the restore then reverts.

`eta_s` is the point's size over the destination's measured throughput
(its recent full backups), 100 MB/s without a sample. A restore is handed
the chain truncated at the chosen run, each piece with its multipart plan
(`part_size`, `part_sha256_hex`) so the destination fetches it in verified
parallel ranges. The presigned URLs live `max(1 h, size / 5 MB/s)`, capped
at 12 h. A chain is never pruned while a restore that uses it is in flight.

### 8.2 The job

A restore is a migration job with `kind=restore`, so it reuses the VM's
`Migrating` state, the destination activation, the reclaim gate and the
stranded-VM sweep, and it is serialised against migrations and
decommissions (one job per VM). The destination is the VM's current host
unless the operator names another one of the same SNP generation with room
for the VM.

| Phase | What happens | The original |
|---|---|---|
| `restore_staging` | The destination downloads and rebuilds the point into a staging directory (`restore` op=stage). | keeps running |
| `restore_stopping` | The domain is stopped through the power API (the reboot-watcher leaves it down); the job waits for its host to report it down. | stopped, intact |
| `dest_activating` | The VM is fenced `Migrating`; the KBS is activated at `new_gen` on the destination chip; `migrate-activate` carries `staged_restore_id`: the destination moves the live files aside (`*.pre-restore-<id>`), installs the staged ones and boots. | kept aside |
| `restore_verifying` | The job waits for the KBS evidence bundle of the restored guest's release at `new_gen` on the destination chip, then activates the VM there. | kept aside |
| `done` | Once the restored guest has also proved it runs, the `*.pre-restore-*` files are deleted (`restore` op=reclaim) and, after a move, the source copy reclaimed. A fresh full backup follows. | reclaimed |

### 8.3 Justification and the commit point

A §25 migration reaches `dest_activating` only on the source guest's
verified signed stopped-ack. A restore is typically wanted when the guest
is broken, so it cannot rely on one. Each job kind needs its own
justification, and none is accepted for another kind:

| Kind | Justification |
|---|---|
| `migrate` | the verified source stopped-ack |
| `restore` | an operator authorization (principal, request id) plus the source domain confirmed down by its host |
| `failover` | an operator authorization carrying the dead-miner evidence |

What makes the activation safe without an ack is the KBS `activate` to
`new_gen`: it fences the old instance from any future key release.

The **commit point** is the restored guest's first key release: it commits
`counter + 1`, after which the original disk is an older state.

- **Before it** (the destination could not boot the disk, or no release
  within `VALI_RESTORE_VERIFY_TIMEOUT_S`): the restore **reverts**. The KBS
  is activated at `new_gen + 1` back on the source chip (forward-only), the
  destination aborts (the original files are moved back), and the original
  is relaunched at that generation, only if it was running. The job ends
  `reverted`. A revert overwrites the restored disk, so it needs POSITIVE
  evidence that the guest did not release: the KBS's latest grant is one
  vali knows, below `new_gen`. Any sign of a release (the bundle, an
  in-guest signal, a key-released milestone) blocks it, and so does no
  evidence at all (a KBS restart erases bundles): the job then fails with
  the original kept, for an operator. The decision is taken again after the
  revert's own activate, and the source is relaunched only once the
  destination reports its abort finished.
- **After it**: the job fails and the original disk is kept
  (`VALI_RESTORE_KEEP_ORIGINAL_S`, and after it until the restored VM is
  proven on its host and alive).
- **A staging failure** fails the job with a `stage-*` reason; the VM was
  never touched. A cancel is only possible while staging or stopping; a VM
  the job stopped is started again.

A restored VM returns to its **prior power state**: a stopped VM is booted
(the release is the commit and the proof), then stopped again once it has
proved it runs, unless the tenant changed its power state in between.

### 8.4 API (root only)

| Method · path | |
|---|---|
| `POST /v1/vm/<id>/restore` | `{run_id, request_id, dest_node_id?, accept_rollback?, on_behalf_of?}` → `202` job. Idempotent on `request_id`. Refusals: `bad-request`, `on-behalf-of-required` (400); `point-not-restorable`, `rollback-unsupported`, `rollback-not-accepted`, `rollback-no-checkpoint`, `rollback-not-capable`, `job-in-flight`, `vm-not-restorable`, `no-eligible-miner`, `request-id-conflict` (409); `rollback-rate-limited` (429, with `retry_after_s`); `restore-disabled`, `restore-unavailable` (503). |
| `GET /v1/vm/<id>/restore` | The latest restore job, or `404 no-restore`. |
| `GET /v1/vm/<id>/restore/<job_id>` | One job. |
| `POST /v1/vm/<id>/restore/<job_id>/cancel` | Only in `staging` / `stopping`, else `409 not-cancellable`. |
| `POST /v1/vm/<id>/restore/<job_id>/revert` | `{on_behalf_of: {kind: superuser, id}}` → `202` job (`undo {...}`). Puts the original back after the commit point (§8.5). Idempotent. Refusals: `on-behalf-of-required` (400); `revert-superuser-only` (403); `revert-not-applicable`, `revert-cross-host-unsupported`, `revert-no-checkpoint`, `revert-not-ready`, `rollback-unsupported`, `rollback-not-capable`, `job-in-flight` (409); `rollback-rate-limited` (429); `restore-unavailable` (503). |

A job reads `{job_id, vm_id, kind, run_id, chain_id, point_taken_at, phase,
pct, reason, reverted, prior_power_state, source_node_id, dest_node_id,
eta_s, rollback, created_at, finished_at}` with `phase` one of `staging`, `stopping`,
`activating`, `verifying`, `settling`, `done`, `failed`, `reverted`.
`verifying` lasts until the restored guest has both released its key (the
job activates the VM there) and proved it runs (the reclaim gate); one
that never proves it reads `failed`, its original kept. `finished_at` is
null until the phase is final. `rollback` is null except for a rollback
restore: `{from_boot_counter, to_boot_counter, point_taken_at,
requested_by: {kind, id}, committed_at}`. Each run in `GET .../backups`
also reads `manifest_sha256` and `has_checkpoint`, and the listing reads
`rollback_capable` (bool, or null when the KBS does not answer or rollbacks
are off; read at most once a minute): while it is false, every `rollback`
point reads `restorable: false` (its class stays `rollback`).

### 8.5 Restore to an earlier boot (authorized rollback)

A guest that rebooted into a broken state has only points of an earlier
boot. Restoring one goes back past the anti-rollback checks of §3, so it is
never automatic: only the KBS can allow it, for one release, and vali asks
only on an explicit request made on behalf of a named tenant or superuser.

**The checkpoint.** When a backup run completes, vali asks the KBS (mTLS
admin listener) for a **checkpoint**: a statement, signed with the KBS's
persistent signing key, of the VM's stored boot counter and volume stamp at
that instant. vali keeps it on the run only if its counter is the run's
own (the guest did not reboot between the snapshot and the completion),
writes it into the run's `manifest.json`, and records the sha256 of the
manifest; the exact manifest bytes are kept on the run too, because the KBS
arms only against them (at most 256 KiB, naming the VM at top level and
embedding that very checkpoint — a point outside those bounds is refused at
intake, never after the VM was stopped). A run without a checkpoint is never
rollback-restorable, and neither is one whose checkpoint is unstamped
(`volume_stamp == 0`: the KBS refuses to arm it, `checkpoint-unstamped`).
The
checkpoint never costs the backup: a KBS that does not serve the route, or
cannot answer, only leaves the run without one (logged once). A checkpoint
whose signed CBOR does not say what its JSON says is rejected loudly.

**Who may ask.** `POST /v1/vm/<id>/restore` for a `rollback` point needs:

- `VALI_RESTORE_ROLLBACK_ENABLED` (else `rollback-unsupported`, as when the
  KBS does not serve the rollback routes);
- a checkpoint on the run (`rollback-no-checkpoint`);
- `on_behalf_of: {kind: tenant|superuser, id}` (`on-behalf-of-required`);
- `accept_rollback: true` (`rollback-not-accepted`);
- no rollback of the VM armed within `VALI_RESTORE_ROLLBACK_MIN_INTERVAL_S`
  (`429 rollback-rate-limited` with `retry_after_s`). The KBS enforces its
  own limit too;
- a guest the KBS reports `rollback_capable` (`GET .../rollback`, read
  afresh; KBS-owned volume stamp and guest stamp protocol v2), else
  `409 rollback-not-capable` before the VM is touched. The undo (below) is
  gated the same way. Should the KBS still refuse the arm
  `guest-not-rollback-capable`, the restore fails before its commit point
  (`rollback-not-capable`) and reverts.

A failover never rolls back, whatever the flag: its route takes neither
field, and a failover authorization that claims one fails the job's guard.

**The arm.** Right after the KBS `activate` to `new_gen` on the destination
chip, and before the destination boots anything, vali calls
`authorize-rollback` with the run's checkpoint and signature, the
manifest's sha256 and its exact bytes (`point_manifest_b64`, which must
embed that same checkpoint), `new_gen`, the destination chip, the restore id, a TTL
of one hour and `requested_by = <kind>:<id>`. The KBS verifies its own
signature, that the checkpoint is strictly behind its stored counter, and
that the VM is exactly `Migrating{new_gen, destination}`. The arm lets ONE
release, at `new_gen` from that chip, submit the checkpoint's counter + 1;
the release then sets the expected volume stamp to the checkpoint's and
commits the counter forward (the counter itself never goes down). Every
KBS refusal is a pre-commit failure: the restore reverts. Two answers are
not refusals: the admin gateway's shared limiter (`429 rate-limited`) is
retried within the phase, and a KBS running without its rollback context
(`503 rollback-unavailable`) is read as a missing route — `rollback-
unsupported` at intake, an immediate pre-commit failure in the job.

**Done.** Besides the evidence bundle and liveness gates of §8.2, a
rollback restore is done only once the KBS reports this restore's arm
consumed AND delivered (`GET .../rollback`: `last_rollback.restore_id` and
`delivered: true`). A rollback delivered during a revert blocks the revert,
as any release does (§8.3); one the KBS consumed but never delivered (or
reverted) gave the guest nothing, and does not. One consumed but neither
delivered nor reverted is still in flight: it decides nothing until the KBS
settles it.

**Every failure withdraws the arm.** A revert deletes the arm before its
own fencing `activate` (which clears arms on the KBS too); a job that ends
in any other failure has its arm deleted by the tick. Each withdrawal reads
the KBS before and after the delete, so a release that consumed the arm in
between is recorded as a commit, never as abandoned.

**A revert needs positive proof the arm was not consumed**: vali saw it
live and withdrew it, it is still live, the KBS refused it, or the KBS
reports it consumed but undelivered. A `last_clear` of
`rollback-cleared-by-boot` for THIS arm (`last_clear.restore_id`; the VM's
normal boot committed, which clears arms) hands the decision back to the
evidence bundle: a grant below `new_gen` reverts, no bundle stays
undecided. Independently of the KBS, a restore that never reached the
destination dispatch (a write-ahead mark) and for which vali never minted a
ticket at `new_gen` cannot have released anything: it reverts even when the
KBS lost its records. The absence
of a rollback record is not proof (a KBS restart or an older KBS image
loses it, and the best-effort evidence bundle may still show the
original's older grant): an arm that vanished unaccounted for blocks the
revert, and the job stops for an operator with the original kept.

At intake, vali also reads the KBS's own view: a live arm for the VM
refuses the request (`job-in-flight`), and a rollback the KBS consumed
within the interval is `rollback-rate-limited`, even if vali's own rows
do not know it. vali keeps its own
durable record of every rollback (`RollbackEvent`: point, counters,
requester, armed, committed, outcome), because the KBS's audit log does not
survive a KBS restart.

**Putting the original back after the commit point (operator).** A
restore that failed after its commit point keeps the original disk, but
the restored guest holds the VM's counter by then, so the original is
itself an older state. Right before the fence, every restore takes a KBS
checkpoint of the original and stores it on the job with the manifest
bytes that embed it. `POST /v1/vm/<id>/restore/<job_id>/revert
{on_behalf_of: {kind: superuser, id}}` (superuser only, rate-limited like
any rollback) then: fences the VM `Migrating{new_gen + 2, source}`,
`activate`s the KBS there (the restored guest can never be released a key
again), arms a rollback to the original's checkpoint (`not-a-rollback`
means the restored guest never committed: nothing to roll back), sends the
destination the existing `restore` op=abort (the restored guest down, the
retained `*.pre-restore-<id>` files renamed back; no new miner operation),
unfences the VM `Active{new_gen + 2, source}` and relaunches the original
— always, whatever its power state before, because the arm expires. The
job ends `reverted` once the KBS reports the arm consumed and delivered (or,
with no arm, a grant at `new_gen + 2`). Only a same-host restore is put
back (`revert-cross-host-unsupported` otherwise), and only while the miner
itself reports this restore's `*.pre-restore-*` files present — asked at the
request and again right before the fence, never inferred from vali's rows. The
undo stops the automatic reclaim of that original and is serialized with
the reclaim sweep on the job row. Once the original is swapped back and
relaunched it can only unlock through the undo's arm, so from then on the
deadline never ends the undo, and the tick never withdraws that arm, until
the arm is delivered (done) or gone unused (expired: failed). A failed undo
leaves the VM for an operator and is never re-driven.

**Stamp protocol v2 is one-way.** After its first v2 release every M0/M1
VM is on a non-zero timeline (a fresh one at `E = 0`, including after every
KBS restart) and is v2-only: the KBS refuses any v1 release of it (gate
5a-t), and the guest refuses v1 as well: it never retries a denied v2
release as v1 (a denial is final; every KBS refusal is the same 403, so a
miner could forge one to get a v1 adopt of an old zero-timeline disk after
a store wipe), and the golden initramfs refuses an M0/M1 release without a
timeline transition. M2 attests v1 only, as before. Consequences:

- the v1 UKI measurements are retired from the allowlist in lockstep with
  the move to the R6 bake;
- the KBS is NEVER rolled below v2 once the R6 bake is live (a pre-v2 KBS
  boots none of these VMs and ignores the timelines file, re-opening B1);
- deploy order is vali → KBS → bake;
- legacy (non-golden) guests never confirm, so they stay at `E = 0` and
  every release is a durable fresh-timeline move: the KBS rewrites and
  fsyncs its timelines file before replying. That buys them nothing (no
  in-volume stamp) and costs one whole-file durable write per release.

See `deploy/gitops/apps/kbs/README.md` ("Never roll the KBS image below
stamp protocol v2").

**Honest limit.** The submitted counter comes from a file the miner
controls, so what binds the rollback boot is the guest's check of its
in-volume stamp (inside the integrity-protected volume the host cannot
forge): the checkpoint's timeline `T_ck`, and a value in `{E_T, E_T + 1}`.
`E_T` is a disk of the checkpoint's own boot. `E_T + 1` is a disk of
exactly ONE boot after it, and the rollback release accepts that too. So a
malicious host can:

- present ANOTHER backup point of the checkpoint's boot than the one asked
  for;
- present a disk of the next boot instead. When `T_ck` is the VM's current
  timeline (always for a first rollback) and the VM is exactly one boot
  past the checkpoint, that is the VM's current, NOT-rolled-back disk: the
  host restores nothing, and vali records a rollback (the KBS reports it
  `delivered`) that did not happen. Otherwise it needs a copy of a disk of
  that next boot, which the host can always have kept.

No key leaks: the disk is the tenant's own and only this VM's attested
guest unlocks it. No disk of another timeline, of an earlier boot, or of
two or more boots later is accepted, and nothing happens without an arm
vali created. Closing this needs a per-boot timeline (a fresh timeline on
every release), which is out of scope. The fresh timeline a KBS gives an
unconfirmed VM after a store wipe narrows it in one case only: a wipe
between the checkpoint's boot and the next one moves that next boot to a
fresh timeline before any tenant byte is written, so no `(T_ck, E_T + 1)`
disk exists.

## 9. Manual failover (operator only)

When a VM's miner is dead, an operator restores the VM on another miner
from its newest current-boot point: a job of `kind=failover` that enters
`dest_activating` directly (no staging on a dead host, no stop possible),
the destination downloading the chain as it activates.

- **Dead** means all of: the miner's heartbeat and its NetBird peer both
  silent for `VALI_FAILOVER_DEAD_AFTER_S`, and the Edge unable to reach it
  (a relay probe the Edge answers 502/504). Anything vali cannot read
  counts against it. Otherwise `409 miner-not-dead`, with the evidence.
- The evidence is checked again right before the fence; a miner that came
  back in between is left alone (the job reverts, the KBS never moves).
- **Fence**: the KBS `activate` to `new_gen` on the destination chip (the
  old instance never gets a key again), and the old miner is
  **failover-quarantined**: not dispatchable (no placement, no restore or
  migration onto it) until an operator clears it
  (`manage.py vali_failover_quarantine --clear <miner>`).
- The commit point, the revert (without a relaunch on the dead miner: the
  VM is back `Active` there, and reboot-recovery relaunches it if the
  miner returns) and the post-commit retention are those of §8.3.
- **Reappearance**: once the quarantined miner heart-beats again, any domain
  it still runs for a VM that moved away is force-stopped, and its disks
  are reclaimed (the §24 `destroy`: stat before libvirt, exact paths, never
  a shared base) once the VM is proven on its new host. A failover's
  source reclaim waits for that reappearance and is never given up while
  the miner is away. A VM back on that miner is never touched.
- Only the newest current-boot point can be failed over to. A guest that
  rebooted less than one probe interval before its miner died has already
  moved the KBS counter past it: the restored guest is refused before the
  commit point, and the job does not commit.
- `POST /v1/vm/<id>/failover {run_id?, request_id, dest_node_id?}` → `202`
  job (`kind: failover`), polled like a restore. Without `dest_node_id`,
  vali picks a dispatchable miner of the same SNP generation, in the VM's
  launch region, with room for it. Behind `VALI_FAILOVER_MANUAL_ENABLED`
  (off). Tenant-triggered and automatic failover are later parts;
  `failover_mode` on the policy is stored for them.

## 10. Configuration

| Setting | Default | |
|---|---|---|
| `VALI_BACKUP_ENABLED` | `false` | Kill-switch. While off, the tick is inert and new policies are refused. |
| `VALI_BACKUP_BUCKET` | none | vali's own dedicated private bucket (e.g. `hippius-vm-backup`). Required; the images or migration-snapshot bucket is refused. |
| `VALI_BACKUP_S3_ACCESS_KEY_ID` / `VALI_BACKUP_S3_SECRET_ACCESS_KEY` / `VALI_BACKUP_S3_ENDPOINT_URL` | none | The backup bucket's own object-level key. Required. |
| `VALI_BACKUP_MAX_CHAIN` | `24` | Incrementals per chain before a rebase. Capped at 63, so a restore (at most 64 pieces) fits one 64 KiB order. |
| `VALI_BACKUP_MIN_PART_BYTES` | 256 MiB | Smallest multipart part. |
| `VALI_BACKUP_RUN_TIMEOUT_S` | 6 h | Run deadline and presign TTL (capped at 24 h). |
| `VALI_BACKUP_LOST_GRACE_S` | 180 s | How long before an order that never dispatched, or a run the miner forgot, is failed. |
| `VALI_BACKUP_PROBE_INTERVAL_S` | 300 s | Reboot probe between runs. |
| `VALI_BACKUP_RETRY_AFTER_S` | 900 s | Back-off after a failed run. |
| `VALI_BACKUP_MPU_MAX_AGE_S` | 2 d | Janitor: abort orphan multipart uploads older than this (never below twice the run timeout). |
| `VALI_BACKUP_STAGING_MAX_AGE_S` | 2 d | Janitor: delete orphan staged state disks older than this. |
| `VALI_BACKUP_JANITOR_BATCH` | 100 | Janitor: items per rule per tick. |
| `VALI_BACKUP_JANITOR_INTERVAL_S` | 1 h | Janitor: pause between two sweeps of the bucket. |
| `VALI_RESTORE_ENABLED` | `false` | Opens `POST /v1/vm/<id>/restore`. Jobs already open keep running when it is turned off. |
| `VALI_RESTORE_STREAMS` | 8 | Parallel ranged GETs per object while staging (1..16). |
| `VALI_RESTORE_DEFAULT_THROUGHPUT_BPS` | 100 MB/s | ETA for a destination with no measured full backup. |
| `VALI_RESTORE_STAGE_TIMEOUT_S` | 1 h | Floor of the staging deadline (3 × the ETA, capped at 12 h). |
| `VALI_RESTORE_STOP_TIMEOUT_S` | 600 s | How long the original's host has to report its domain down. |
| `VALI_RESTORE_VERIFY_TIMEOUT_S` | 900 s | How long the restored guest has to release its key before the restore reverts. |
| `VALI_RESTORE_REVERT_TIMEOUT_S` | 1800 s | Deadline of the revert itself. |
| `VALI_RESTORE_KEEP_ORIGINAL_S` | 24 h | How long a restore that failed after its commit point keeps the original disk. |
| `VALI_RESTORE_ROLLBACK_ENABLED` | `false` | Restores of earlier-boot points through a KBS-authorized rollback (§8.5). Turning it off also fails a rollback restore that has not armed the KBS yet. |
| `VALI_RESTORE_ROLLBACK_MIN_INTERVAL_S` | 1800 s | At most one rollback per VM this often. |
| `VALI_FAILOVER_MANUAL_ENABLED` | `false` | Opens `POST /v1/vm/<id>/failover`. |
| `VALI_FAILOVER_DEAD_AFTER_S` | 600 s | How long the heartbeat and the NetBird peer must both be silent. |

## 11. Limits

- **Golden-image VMs only.** A legacy VM's second data disk is not carried.
- **Disk size.** At most about 490 GiB.
- **Cost of a boot.** Every boot costs one full backup, the size of the
  disk. A persistent bitmap would let a chain survive a reboot, but it needs
  a qcow2 overlay.
- **Consistency.** Backups are crash-consistent, not application-consistent.
