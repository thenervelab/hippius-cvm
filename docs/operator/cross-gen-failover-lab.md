# Cross-generation failover: lab proof protocol

Cross-generation restore and failover (Genoa ↔ Turin ↔ Milan) ships OFF:
`VALI_FAILOVER_CROSS_GEN_ENABLED=false`. It is turned on only after this
protocol passes on real hardware. The design is
`apps/orchestration/cross_gen.py`:

- Before the KBS activate, vali recomputes the launch digest for the
  destination's generation and pins it in the §22 allowlist.
- The destination's ticket carries that digest.
- At the commit, the digest becomes the VM's recorded measurement.
- The source's digest stays pinned until the source is reclaimed, or until
  the VM relaunches on the destination.

**Settings for the lab window:**
- `VALI_FAILOVER_CROSS_GEN_ENABLED=true`;
- `VALI_FAILOVER_CROSS_GEN_VM_IDS=<the lab VMs, comma-separated>`. Only
  these VMs may cross, so no customer VM moves across generations and no
  customer sees the warning while the lab runs;
- `VALI_FAILOVER_CROSS_GEN_GENERATIONS` left at its default `EpycGenoa,EpycTurin`.
  vali refuses to start on a name that is no vCPU model (e.g. `genoa`).

While the lab list is set, a VM outside it keeps its own generation
everywhere: destination, failover peer, `failover_capable` pool and policy
view.

Fleet-wide pooling (`failover_capable` and gate (m) counting Genoa and
Turin as one pool) happens only once the flag is on WITHOUT a lab list, at
the final turn-on. During the window, only the listed VMs see another
generation.

**Lab hosts.** One Genoa and one Turin in the same region. For each
source host:
- it must carry ONLY lab VMs. Move every customer VM off it first (§25
  migration), then cordon it;
- it is killed by a hard power-off (the provider's IPMI / API). Never stop
  `hippius-miner-agent`: stopping the agent tears down EVERY domain on the
  host (#1107).

**Milan.** Without a second Milan-capable peer in the same region, a Milan
failover cannot be proven. Milan therefore stays out of
`VALI_FAILOVER_CROSS_GEN_GENERATIONS`; step 1 can still compare its digest.
Adding Milan later means repeating steps 2-5 with a Milan host.

**Lab VMs.** Use internal VMs only (the operator's own tenant, or a fresh
lab tenant).
- **Distros:** one per distro (ubuntu, debian, fedora, cs10), all golden.
- **One legacy (non-golden) VM**, if any still exists in the fleet.
- **One M1 (`key_mode=split`) VM.** Its guardian recomputes the digest from
  the destination's `LaunchRecipe`, so check that the guardian releases on
  the other generation.

Each lab VM:
- has `failover_mode=manual` (the operator drives every move);
- has a backup policy with a complete current-boot point;
- has NO operator-pinned `measurement_hex`.

## 0. Preconditions

1. The image carrying `cross_gen` is pinned and running. The flag is still
   off.
2. `VALI_LAUNCH_DIGEST_BIN`, `VALI_SNP_OVMF_S3_URI` and `VALI_SNP_OVMF_SHA256`
   are configured. vali refuses a cross-generation move without its own
   recompute.
3. The KBS audit ingest is green, with no `KbsAuditIngest*` alert. Step 2
   reads the KBS admin audit log.
4. Write a sentinel in each lab VM, so the restored disk can be proven to
   be the tenant's own:

   ```
   ssh <vm> 'echo "xgen-$(date -u +%s)-$RANDOM" | sudo tee /var/lib/xgen-sentinel; sync'
   ```

   Then wait for the next backup run after the write to be `complete`
   (`GET /v1/vm/<id>/backups`). Record the sentinel and the run id.

## 1. vali's digest equals the miner's

For every lab VM and each destination of another generation:

```
python manage.py vali_cross_gen_digest --vm-id <vm> --dest <miner_id> --preflight
```

- The command prints vali's digest (`vali_digest`) and the destination
  miner's own (`miner_digest`, from a `tenant-preflight` under a probe id).
  It writes nothing in vali and boots nothing.
- **Pass:** `verdict: match` (exit 0) for every lab VM, both directions,
  and Milan for the comparison.
- **Stop:** any `MISMATCH` (exit 1). The flag must not be turned on, and
  the VM, the destination and both digests go back to the team.

**Cleanup.** The probe stages the VM's artefacts on the destination (for a
golden VM, the multi-GB base image). The command prints the directory as
`probe_staging_dir`. Remove it once the comparison is done:

```
ssh <dest> sudo rm -r /var/lib/hippius-miner/staging/xgen-probe-<vm>
```

Run probes one at a time.

## 2. A failover each way, 4 distros

Set the lab-window settings above (chart values, then the pin; the keys are
new with this image). Then, for each lab VM, run Genoa → Turin, and then
Turin → Genoa back.

1. **Kill the source the way production would see it:** a hard power-off
   of the source host (it carries only lab VMs). After
   `VALI_FAILOVER_DEAD_AFTER_S` the three-way proof holds;
   `POST /v1/vm/<id>/failover` answers `miner-not-dead` before that.
2. **Fail over to the other generation:** `POST /v1/vm/<id>/failover` with
   `{"request_id": "xgen-<vm>-<n>", "dest_node_id": "<other-gen miner>"}`.
3. **Check the job,** polled with `GET /v1/vm/<id>/restore/<job_id>`:
   - `phase` reaches `done`, `outcome` `committed`.
   - In vali's DB, `MigrationJob.dest_measurement_hex` is set and differs
     from the source digest.
   - A `MeasurementLedger` row exists for it with `launch_ref` = the
     job id, and a `cross-generation failover` WARNING appears in the vali
     log.
4. **The KBS released at `new_gen`.** The KBS admin audit log has an
   `activate` of the VM to the destination chip at `new_gen`, then a
   release at `new_gen` to the destination's chip id.
5. **The sentinel.** `ssh <vm> cat /var/lib/xgen-sentinel` returns the
   value from step 0. The phase alone is not proof (see "§25 Done-gate is
   weak").
6. **The boot counter** went up by exactly 1 (KBS evidence /
   `vali_kbs_recover --dry-run` read-out).
7. **The record follows.** `launch_record.recorded_measurement(<vm>)` equals
   the job's `dest_measurement_hex`.

**Pass:** every run passes all 7 checks.

Also run one cross-generation **restore** that commits: `POST
/v1/vm/<id>/restore` with `dest_node_id` of the other generation, on a
live source. It must pass checks 3-7 too (the source stays up until the
cutover).

## 3. Reboot recovery and a KBS-recovery re-mint on the destination

On one VM per direction, after step 2:

1. **Reboot the destination host.** Reboot recovery relaunches the VM on it.
   Check that it runs, the sentinel reads back, and the boot counter went
   +1.
2. **Run a KBS-recovery re-mint for the VM:** `vali_kbs_recover` for that
   VM only, dry-run, then the real run. The re-minted ticket must carry the
   destination digest, the recorded one. The VM must keep unlocking across
   one more relaunch.

## 4. A forced revert

On one VM, run a cross-generation **restore** onto another miner
(`POST /v1/vm/<id>/restore` with `dest_node_id` of the other generation).
Make it fail after the KBS activate but before the commit.

Inject the failure in `dest_activating`, not later. `restore_verifying` is
only entered after the destination reported `done`, which is after its
release (the commit). Stopping things there gives failed-after-commit, not
a revert. The way to do it:
1. Watch the vali log for the job's `kbs_activate_dest`.
2. Right after it, block the destination host's egress to the KBS (nft
   drop), so the restored guest can never release.
3. Wait for the phase deadline.

**Pass:**
- the job reads `reverted`;
- the VM runs again on the SOURCE, at the source's own generation and
  digest (its relaunch recomputes and pins it);
- the sentinel still reads back;
- the destination's pin is superseded at the source's relaunch.

Lift the nft block afterwards.

## 5. Allowlist re-pin

1. After step 2, before the sources are reclaimed, trigger an allowlist
   re-pin: any launch, or `refresh_allowlist`. **Both** digests of a moved
   VM (the destination's and the job's `source_measurement_hex`) must still
   be in the installed allowlist. Check the KBS allowlist read-out, or
   `_query_carry_forward_classes()` in a shell. No OLDER digest of the VM
   comes back.
2. Power the source back on so it is reclaimed. The job goes to
   `source_reclaim_state=reclaimed`.
3. After the next re-pin, only the destination digest remains, and the
   source's ledger row is `evicted_at`.

## Verdict

**Pass** means all of steps 1-5 passed. The flag then goes on for good, in
a pin PR.

**A job that fails past its commit** (`failed-after-commit`). The VM stays
fenced on its source host in vali's books, but its only live copy is on the
destination, and vali records the destination's digest. Recover it onto
the destination, and escalate it to the team; there is no one-command
path. Never run `vali_kbs_recover` for it against the source host: that
re-mint would carry a digest the source chip can never measure.

On any failure:
- turn the flag back off. A job already past its KBS activate finishes; it
  does not need the flag;
- revert the moved VMs by failing them back to their own generation, or
  relaunch them on a same-generation host;
- report what failed, with the job ids and the KBS audit lines.

## Customer-facing risk (no code detects it)

**Turin → Genoa, and toward Milan.** Software built for the newer CPU may
die with SIGILL on the older one:
- `-march=native` or Zen 5-only instructions;
- AVX-512 toward Milan, which has none.

The policy shows the customer `failover_cross_generation` and, when an
older peer exists, `failover_cross_generation_warning`. The warning means
"may": the pick prefers the VM's own generation, then a newer one, then the
nearest older one.

Genoa → Turin is, as far as is known, a superset: no warning.
