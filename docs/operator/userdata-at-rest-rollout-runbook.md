# Rolling out "no plaintext cloud-init at rest"

The cloud-init user-data is now Vault-Transit-wrapped in **both** places
it is stored, and §24 destroys the keys and deletes the blobs. This
runbook is the prerequisite, the deploy order, what to verify, and how to
arm the fail-closed gate afterwards.

## What changed

THREE copies of a VM's user-data exist, and they answer to different
readers:

| Copy | Wrapped under | Who can open it | Why it exists |
|---|---|---|---|
| `{prefix}/{vm}/userdata` | `kek-<vm_id>` | the attested KBS only — vali has encrypt, never decrypt | it is what the minted ticket binds and the KBS releases to the guest |
| `{prefix}/{vm}/userdata-pending` | `ud-<vm_id>` | vali | the §6 digest re-derivation on a §25 migration / KBS-state recovery. Written by each launch attempt right after the canonical copy, and STAMPED (inside the wrapped blob) with the canonical KV version it corresponds to — the two writes are not atomic, so the stamp is what proves the pairing rather than assuming it |
| `{prefix}/{vm}/userdata-intake` | `ud-<vm_id>` | vali | the TEMPLATE the caller POSTed (NetBird placeholder still in it), read by the launch worker and by reboot-recovery, which each substitute a fresh setup key |

Before this, the second copy was **plaintext**, retained for the life of
the VM and never deleted — §24 destroyed `kek-<vm_id>` and the luks-kek
blob and left the tenant's SSH keys, API tokens and NetBird enrolment
secret sitting in KV. That is what this closes.

The §6 digest is **unchanged**: still over the plaintext, same preimage.
Three parties compute it — vali, the KBS, and the GUEST
(`hippius-guest`, in every tenant image, which re-derives it over what it
receives and refuses the release on a mismatch) — so moving it would deny
every release until the whole fleet was re-baked. That is also why vali
still needs a copy it can open: the digest binds a FRESH ticket_id on
every re-mint, so it cannot be computed once and stored.

**What this does not fix:** an RCE holding vali's own Vault credentials
can call `transit/decrypt/ud-<vm_id>` and read a tenant's cloud-init.
Removing that need means removing the ticket_id from the digest preimage,
which the guest also computes — a fleet-wide image re-bake, tracked
separately. What is fixed is the at-rest exposure (Vault storage, etcd
snapshots, backups, any token with KV read but no Transit grant) and the
§24 erase gap.

## 0. Prerequisite: apply the Vault policy FIRST

`deploy/terraform/policies/vali-orchestrator.hcl` adds the `ud-*` Transit
grants (`transit/keys/ud-*` create+update+delete, `…/config` update,
`transit/encrypt/ud-*`, `transit/decrypt/ud-*`, and
`transit/datakey/wrapped/ud-*` — the erase probe the synthetic monitor
uses to assert the key is dead after §24; without it the monitor 403s
and fails closed on a decommission that did erase). Without them **every
launch fails at staging** (loudly — `vault-transit-key: vault returned
HTTP 403`). Apply the policy, then confirm:

```
vault policy read vali-orchestrator | grep -A2 'transit/decrypt/ud-'
```

## 1. KBS first

The KBS commit ships `require_wrapped_userdata = false`
(`chart_deploy_safety.rs` keeps it that way until someone deliberately
arms it) and changes nothing about an accepted release, so it is safe on
its own. It needs a build + an image-digest pin in
`deploy/gitops/apps/kbs/values.yaml` like any other KBS change — the
commit alone does not deploy a binary. Verify against the RUNNING
process:

```
curl --cert … --key … https://<kbs-admin>/v1/admin/config | jq '{
  require_wrapped_kek, require_wrapped_userdata }'
```

If `require_wrapped_userdata` is **absent** from that JSON, the new
binary is not deployed — stop here.

## 2. vali second

Both vali workloads take the same image digest, and they are separate
Deployments, so a sync rolls them concurrently. Mixed-version pairings:

| Running | Effect |
|---|---|
| new intake + OLD worker | the old worker reads the intake copy from the path the row names, gets Transit ciphertext, and either rejects it (NetBird on — no placeholder in it) or wraps it a second time (NetBird off). The second case is caught: the new KBS refuses a value that is still `vault:`-prefixed after one unwrap. Either way the launch fails; nothing boots broken. |
| old intake + new worker | harmless — the intake copy is plaintext and the new reader passes an unwrapped value through unchanged. |

Draining the queue is not enough on its own, because the web pod keeps
accepting POSTs while the old worker is still up. **Quiesce intake for
the window**: stop accepting launches (scale `vali` web to 0, or block
`POST /v1/vm/launch` upstream), let the queue drain to zero
`queued`/`running` LaunchJob rows, roll both Deployments, then re-open.
Nothing already running is affected, and no VM boots misconfigured
either way — the failure modes above are all loud.

## 3. Verify, in this order

1. **Launch** one VM; confirm NetBird + SSH. Confirm all three userdata
   KV paths hold `vault:`-prefixed values.
2. **Migrate it (§25) or run a KBS-state recovery.** This is the path the
   previous release broke silently: the re-mint re-derives the digest,
   now from the working copy it can open.
3. **Reboot-recover it** (stop the domain on the miner; wait for the
   sweep). It reads the INTAKE copy — the template — and substitutes a
   fresh NetBird key, as it always did.
4. **Decommission it (§24)** and confirm the erase. Note the §24 step is
   keyed `crypto-erase-v2`: a job that was already in flight when this
   shipped carries an idempotency record from the narrower old step and
   would otherwise skip the expanded one.

   ```
   vault read transit/keys/kek-<vm_id>    # expect: key not found
   vault read transit/keys/ud-<vm_id>     # expect: key not found
   vault kv get secret/<prefix>/<vm_id>/userdata           # expect 404
   vault kv get secret/<prefix>/<vm_id>/userdata-pending   # expect 404
   vault kv get secret/<prefix>/<vm_id>/userdata-intake    # expect 404
   ```

   The full-tier synthetic monitor asserts the same set — both Transit
   keys destroyed, and an OBSERVED 404 on all three userdata KV paths
   (vali may read those, so a 403 there means an ACL changed, not that
   the secret is gone).

## 4. Arming `require_wrapped_userdata` (later, and deliberately)

The gate refuses any VM whose CANONICAL user-data is plaintext at rest —
every VM staged before the wrapping, and anything staged by an older
`tenant-secrets-stage.sh`. Such a VM **stops booting**.

Enumerate against the version each VM's ticket actually pins, not against
`latest` — a re-stage or a second launch leaves a wrapped v2 over a
plaintext v1 that a live ticket still points at, and the gate is applied
to the version the ticket names:

There is no query that lists the pinned version for every live VM: an
INITIAL launch ticket is deliberately not persisted as an
`OrderTicketIntake` (only re-mints are), so vali's database does not
record which userdata version each running guest's ticket names. Treat
the population, not the row:

```
# every VM that has NOT been (re)launched since this rollout is suspect
psql -c "select vm_id, max(finished_at) from orchestration_launchjob
         where state='succeeded' group by vm_id order by 2"
```

Everything launched before the rollout must be RELAUNCHED (not merely
re-staged) before arming. Re-staging writes a new KV version while the
live ticket still names the old one, so it changes nothing for the
running guest; only a fresh ticket bound to the new version does —
i.e. a relaunch through the API, or `vali_kbs_recover --commit` to
re-mint and re-register at the current generation. After that, spot-check
one VM per distro by decoding the latest canonical version:

```
vault kv get -field=value secret/<prefix>/<vm_id>/userdata | base64 -d | head -c 6   # expect: vault:
```

Arm the gate in a commit that also updates `chart_deploy_safety.rs`, with
that evidence in the message.

## Rollback

The KBS is unaffected (nothing about the release contract changed). vali
is not: the old code cannot open a wrapped intake copy, so launches and
reboot-recovery for VMs staged by the new code fail — loudly, and with
nothing lost, since the canonical copy and the KEK are untouched.

§25 is the one to be careful about. The OLD re-mint reads the canonical
path and digests whatever it finds; for a VM staged by the new code that
is Transit ciphertext, so it would mint a ticket that denies at release —
and it does so AFTER the source is quiesced, stopped and fenced, which
strands the VM. So on a rollback: quiesce launch intake AND migrations
(including the departing-miner auto-migration — drain or requarantine),
roll back, then re-open. Same quiesce as the forward roll, plus
migrations.
