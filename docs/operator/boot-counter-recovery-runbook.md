# Recovering a desynchronised boot counter

The per-VM boot counter is the anti-rollback gate on the §21 release: the guest
submits a value and the KBS releases the KEK only when it is **exactly
`stored + 1`**. Two copies therefore have to agree, and they are held by two
different parties:

| copy | lives on | lost by |
|---|---|---|
| KBS `stored` | `boot-counters.json` in the KBS state dir (an `emptyDir` on a Kata CVM) | a KBS pod restart |
| guest `submitted` | `/var/lib/hippius-miner/state/<vm>.raw` — one **1 MiB plaintext ext4** on the MINER host | host rebuild, disk failure, a `state/` sweep, a migration that does not carry it |

When they disagree the release fails closed **forever**: no KEK, no unlock, and
for the tenant that is indistinguishable from destruction. The counter may never
be walked **down** — that is the anti-rollback property itself — so both
recoveries below only ever move things **up**, and both are reachable only from
the mTLS admin listener.

This runbook is only about the boot counter. The `kbs_core::volume_stamp` gate —
the one that binds anti-rollback to the **encrypted volume** — is untouched by
everything here, and neither procedure can move it.

## Which failure am I looking at?

Read the refusal reason from the KBS audit sink (or the signed denial the guest
logged to its serial). It carries a stable leading classifier:

| classifier | meaning | action |
|---|---|---|
| `boot-counter-lost` | the guest submitted `1` — its "I remember no previous boot" value — against a live counter | the guest's copy is gone → **§B** |
| `boot-counter-rewind` | the guest submitted an earlier value it must once have known | a replayed state disk, or a guest bug → **investigate, do not recover** |
| `boot-counter-skip` | the guest submitted past `stored + 1` | a guest bug, or the KBS store moved under it → **investigate** |

If EVERY VM in the fleet is failing at once with `boot-counter-lost`, it is not
the miners: the KBS's own store was wiped. That is **§A**.

⚠️ The classifier is a **diagnostic, not a verdict**. The state disk is
miner-writable, so a hostile host can produce the `boot-counter-lost` shape at
will. Nothing in the release path acts on it — it tells you where to look, and a
human decides. Confirm independently (the host really was rebuilt, the file
really is absent, the miner really did report a disk failure) before §B.

## §A — the KBS forgot (`seed-boot-counter`)

Symptom: many VMs refusing at once; `GET /v1/admin/vm/<vm>/evidence` reports
`boot_counter: 0` for a VM that has demonstrably booted.

The authoritative value survives on the miner. Read it **without touching the
running VM** — copy first, loop-mount the copy read-only:

```sh
# on the miner host
cp --sparse=always /var/lib/hippius-miner/state/<vm>.raw /tmp/bc.raw
mkdir -p /tmp/bc && mount -o ro,norecovery /tmp/bc.raw /tmp/bc
cat /tmp/bc/boot-counter        # e.g. 4
umount /tmp/bc && rm -f /tmp/bc.raw
```

Then seed the KBS with it, over the admin listener:

```sh
curl --cert operator.crt --key operator.key --cacert kbs-ca.crt \
  -X POST https://<kbs-admin>:8001/v1/admin/vm/<vm>/seed-boot-counter \
  -H 'content-type: application/json' -d '{"counter": 4}'
```

Refusals, all of which write nothing:

- `409 seed-already-recovered` — the row is not wiped. Re-running a recovery
  refuses rather than overwriting; if you disagree with the stored value, that
  disagreement is the incident.
- `409 seed-not-monotonic` — a seed may only ever RAISE.
- `400 seed-above-cap` — above `MAX_SEED_COUNTER` (4096). A number the guest can
  never reach would brick the disk irreversibly, so it is refused.

## §B — the guest forgot (`arm-boot-counter-resync`)

Symptom: ONE VM refusing with `boot-counter-lost`, and you have independently
established that its host lost `state/<vm>.raw`.

Do **not** try to reconstruct the file by hand on the miner — on a permissionless
fleet you do not have shell there, and asking the host to type the number makes
the untrusted party the source of truth. Arm a one-shot resync instead:

```sh
curl --cert operator.crt --key operator.key --cacert kbs-ca.crt \
  -X POST https://<kbs-admin>:8001/v1/admin/vm/<vm>/arm-boot-counter-resync
# {"v":1,"vm_id":"<vm>","stored":4,"already_armed":false}
```

Then let the VM boot (or relaunch it). That boot is admitted, and:

- the KBS commits `stored + 1` — **never** the value the guest submitted, so a
  wrong or hostile submission cannot pull the counter anywhere;
- the committed value is echoed in the **signed** release response and the guest
  writes it to its fresh state disk, so the next boot is back in lockstep with
  no arithmetic from you;
- the arm is **consumed**. It is also cleared by any successful boot of that VM,
  so a typo'd `vm_id` disarms itself rather than lingering.

Verify: `GET /v1/admin/vm/<vm>/evidence` shows the counter advanced by exactly
one, and a repeat of the same stale submission is refused again.

Refusals:

- `409 resync-nothing-to-resync` — the KBS holds no counter for this `vm_id`, so
  there is nothing to resync (a guest with no state disk submits `1`, which that
  row already accepts). Check the `vm_id`.
- `400 vm-id-empty`.

Both the arm and its refusals are appended to the hash-chained admin audit log
under `op="arm-boot-counter-resync"`, attributed to your client cert. That
record is the **only** durable trace that a resync was authorised — the release
that consumes it is recorded as an ordinary grant — so an incident is
reconstructed by reading the two in order.

## What neither procedure can do

- **Lower a counter.** Nothing exposed here moves one down. A genuine
  `boot-counter-rewind` stays refused; there is no operator action that
  re-admits a boot the KBS has already burned.
- **Repair a lost KBS store AND a lost state disk at the same time.** §A needs
  the miner's file; §B needs the KBS's row. If both are gone for the same VM,
  the counter's history is gone with them (see below).
- **Be driven by a miner.** Both routes are registered only on the mTLS admin
  router; the guest-facing listener 404s them, and that is pinned by a test.

## Still unrecoverable

If a VM loses **both** copies — a KBS state wipe and the loss of that VM's state
disk, with no operator record of the value — there is nothing left to
re-establish the counter from. `seed-boot-counter` would accept a number, but no
one can say which number is honest, and choosing one is choosing to trust
whoever supplied it. Take the availability outcome as read and treat it as data
loss.

The durable fix for that residual case is to stop the KBS's copy being the only
authority that survives a pod restart — i.e. back `boot-counters.json` with
storage that outlives the pod (the module doc calls for a tamper-safe Tier-0
store). Until then, an operator who is about to restart the KBS should capture
the counters first.
