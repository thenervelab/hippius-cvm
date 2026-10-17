# Live storage move — a move stuck in `move-pivot-unknown`

**Symptom.** Alert `HippiusStorageMovePivotUnknown`. In vali,
`vali_storage_move status --vm-id <vm>` shows `state=failed
code=move-pivot-unknown`. The VM is down and the agent refuses to start it
(`move-pivot-unknown` on a launch, the reboot watcher holds it). The host
takes no other move (`move-busy`) until this is settled.

**Why.** The guest stopped while the agent was pivoting `vda` from the
source copy to the destination copy (`virsh blockjob --pivot`). If libvirt
completed the pivot before QEMU exited, the last writes are in the
**destination**; if not, in the **source**. The agent could not tell (the
persistent definition did not name the destination), so it kept both
copies and holds the VM. Booting the wrong copy silently loses the tenant's
last writes — never guess.

**Never** stop or restart `hippius-miner-agent` for this, never delete
either copy before the decision below, and never run anything on a host
you were not asked to touch.

---

## 1. Read the state (read-only)

On the miner (state root `/var/lib/hippius-miner` unless
`[storage] state_disk_root` says otherwise):

```bash
VM=<vm_id>
sudo cat /var/lib/hippius-miner/moves/$VM.json        # src, dst, phase, code, updated_at
sudo cat /var/lib/hippius-miner/vm-pool/$VM            # {"pool_id","root","ran"}: still the source root
sudo virsh list --all | grep "hippius-tenant-$VM"      # shut off, or absent (undefined)
sudo virsh dumpxml --inactive "hippius-tenant-$VM" 2>/dev/null \
  | grep -A4 "<target dev='vda'"                       # which file the definition boots
```

Where the pivot ended. The mirror is asynchronous: until the pivot the
guest writes the **source** and QEMU copies to the destination behind it,
so the source always holds every write; only a completed pivot moves the
writes to the destination. So the question is only "did the pivot
complete before QEMU exited", and the evidence must say so explicitly:

1. **The libvirt daemon's journal** (QMP events — only if its log filters
   keep them, which the default ones usually do not; then this is "missing") — `sudo journalctl -u virtqemud -u libvirtd --since "<updated_at - 10 min>" | grep -iE 'BLOCK_JOB_(COMPLETED|READY)|pivot'`.
   A `BLOCK_JOB_COMPLETED` for `vda` (or a successful `job-complete`/pivot)
   before the guest's shutdown ⇒ **target**.
2. **The agent's log** — `sudo journalctl -u hippius-miner-agent --since "<updated_at - 10 min>" | grep "storage-move: vm=$VM"`.
   `move-pivot-unknown-outcome` means the pivot call timed out: it decides
   nothing by itself.

**File modification times decide nothing** — the copy writes the
destination after every source write, so it looks newer either way. If no
log above says the pivot completed: **resolve on the SOURCE** only when a
log positively shows it did not (the job was still `ready` at shutdown, or
libvirt refused the pivot); otherwise escalate.

If the evidence disagrees or is missing: **stop here** and escalate. Both
copies are kept; the VM stays down, the tenant loses nothing more.

A held move whose journal phase is `prepared`/`copying` (the agent's own
records named the destination, no pivot was ever tried) is not covered
here: escalate.

## 2a. Resolve on the TARGET (the pivot completed)

**First in vali** (metadata only; it refuses when the VM has no bound
placement on this host — then stop and escalate, nothing is changed yet):

```bash
python manage.py vali_storage_move resolve --vm-id $VM --on target --by <you>
```

Then on the host, in this order — the definition first, so nothing can boot
the stale source (the journal keeps the VM held until step 5):

```bash
# (1) The persistent definition boots dst (skip if the domain is undefined:
#     the next launch renders vda from the pool record).
sudo virsh dumpxml --inactive --security-info "hippius-tenant-$VM" > /tmp/$VM.xml
#     edit /tmp/$VM.xml: <source file='<src>'/> of vda → <source file='<dst>'/>
sudo virsh define /tmp/$VM.xml
# (2) The pool record names the destination pool (root = the dst root,
#     = the journal's `dst_root`; pool_id = its `dst_pool`).
sudo sh -c "printf '%s' '{\"pool_id\":\"<dst_pool>\",\"root\":\"<dst_root>\",\"ran\":true}' \
  > /var/lib/hippius-miner/vm-pool/$VM.tmp && sync /var/lib/hippius-miner/vm-pool/$VM.tmp \
  && mv /var/lib/hippius-miner/vm-pool/$VM.tmp /var/lib/hippius-miner/vm-pool/$VM && sync /var/lib/hippius-miner/vm-pool"
# (3) Check both before going on.
sudo virsh dumpxml --inactive "hippius-tenant-$VM" | grep -A4 "<target dev='vda'"
sudo cat /var/lib/hippius-miner/vm-pool/$VM
# (3b) The agent's re-adoption snapshot names dst too (the agent's own
#      redefine rewrites it; a stale one would point a later §25 at the
#      deleted source).
sudo sh -c "jq '.luks_disk_path=\"<dst>\"' /var/lib/hippius-miner/adopt/$VM.json \
  > /var/lib/hippius-miner/adopt/$VM.json.tmp && mv /var/lib/hippius-miner/adopt/$VM.json.tmp /var/lib/hippius-miner/adopt/$VM.json"
# (4) A §25 restore marker follows the overlay it describes (as the
#     agent's own redefine does), then the stale source copy goes.
sudo test -e '<src>.restored-from' && sudo cp -p '<src>.restored-from' '<dst>.restored-from'
sudo rm -f -- '<src>' '<src>.restored-from'
# (5) Close the journal.
sudo sh -c "jq '.phase=\"done\" | .code=\"pivot-resolved-target\"' /var/lib/hippius-miner/moves/$VM.json \
  > /var/lib/hippius-miner/moves/$VM.json.tmp && mv /var/lib/hippius-miner/moves/$VM.json.tmp /var/lib/hippius-miner/moves/$VM.json"
```

(vali's placement row already names the target pool; the next backup is a
full.)

## 2b. Resolve on the SOURCE (the pivot did not complete)

The definition and the pool record already name the source; only the copy
and the journal go. vali first, then the host:

```bash
python manage.py vali_storage_move resolve --vm-id $VM --on source --by <you>
sudo virsh dumpxml --inactive "hippius-tenant-$VM" | grep -A4 "<target dev='vda'"   # must be <src>
sudo cat /var/lib/hippius-miner/vm-pool/$VM                                          # root = the src root
sudo rm -f -- '<dst>'
sudo sh -c "jq '.phase=\"aborted\" | .code=\"pivot-resolved-source\"' /var/lib/hippius-miner/moves/$VM.json \
  > /var/lib/hippius-miner/moves/$VM.json.tmp && mv /var/lib/hippius-miner/moves/$VM.json.tmp /var/lib/hippius-miner/moves/$VM.json"
```

## 3. Bring the VM back

Start it through vali (power start / reboot recovery: a **relaunch**, which
renders `vda` from the pool record and rebuilds the agent's handle) — never
a bare `virsh start`. Confirm it boots
and serves receipts before closing the incident. The alert clears with
`vali_storage_move resolve` (run first, above).

---

# Other failed moves (`HippiusStorageMoveFailed`)

`vali_storage_move status --vm-id <vm>` gives the code. A failed move can
leave the agent's journal active on its miner: while it is `redefined` the
host takes no other move (`move-busy`) and the source copy stays on disk.

| code | the VM | on the miner | to do |
|---|---|---|---|
| `verify-timeout` | on the target | journal `redefined`, source kept | check the guest is healthy, then `vali_storage_move release --vm-id <vm> --by <you>` |
| `release-refused` | on the target, or back on the source path | journal `redefined` | `last_error` has the agent's phase. If the VM's records name the source again, the agent was right: close the journal by hand (`jq '.phase="done" \| .code="move-superseded"'`, as in 2a step 5), nothing to delete. Else `release` as above |
| `agent-unanswered` | unknown | unknown | once the miner answers: `release` if the agent says `redefined`, else let the agent settle it (it aborts or redefines on its own) |
| `vm-left-host` | on another miner, or back on this one after a round trip (vali never books it then) | the old host may keep a `redefined` journal and both copies | once the old host's stale domain is destroyed (§24), its journal goes with it. If the VM's domain is already gone there and the journal remains: delete `<dst>` and `<src>` only after checking no domain, pool record or handle on that host names them, then remove `moves/<vm>.json` |
| `agent-move-not-found` | where the agent's records say | no journal | nothing on the miner; check `vm-pool/<vm>` and fix vali's placement row if it names the wrong pool |
| `operator-abandoned` | where the agent's records say | whatever the journal says | settle the journal as for the code it would have had |

Never delete a file any of `virsh dumpxml` (live or `--inactive`),
`vm-pool/<vm>` or `adopt/<vm>.json` names.
