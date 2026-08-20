# Cutting the KBS lifecycle admin API over to mTLS

The KBS admin listener (`kbs-server-admin.kbs.svc.cluster.local:8001`) serves
`register-vm`, `activate`, `seed-boot-counter`, `arm-boot-counter-resync`,
`reset-volume-stamp-suppression` and `allowlist/reload`. Every one of those
mutates the state that decides **which host may unlock a tenant's encrypted
disk**, and **none of them carries a per-request credential** — mTLS at the
listener is the authentication. Today it is not turned on: the pod prints

```
kbs-server: WARNING — admin.require_mtls=false and no admin TLS material: the
lifecycle admin API on 0.0.0.0:8001 is served UNAUTHENTICATED (network policy
is the only control). Issue the admin PKI and set require_mtls=true.
```

at every start, and a CiliumNetworkPolicy label match is the only thing in
front of it.

One further route, `GET /v1/admin/volume-stamp`, is a READ rather than a write
— the suppressed-confirm arming report that makes step 3 of the
`maxUnconfirmedReleases` cutover performable. It does **not** follow the "the
listener is the gate" model: it refuses with `403
admin-client-cert-required` unless the request carried a client certificate the
listener verified, so it is unusable until this runbook has been run. That is
the intended ordering — the report names every VM and flags which are one
release from being refused, and arming a fleet-wide anti-rollback gate on a
readout anyone on the pod network could have served is not a verification.

`GET /v1/admin/config` is the second READ, under the same 403 gate: it reports
the **effective security posture of the running process** — the resolved
suppressed-confirm bound, `require_wrapped_kek`, the listener mode
`AdminListenerMode::decide` actually chose, whether the evidence and
live-attestation sinks are wired, the launch-policy floor, the allowlist root
fingerprint. Posture only: no path, no URL, no key material (pinned by
`binaries/kbs-server/tests/admin_config_posture.rs`). It exists because the KBS
reads its config ONCE at start and its Deployment has no `checksum/config`
annotation, so **the rendered ConfigMap is not evidence that a setting is in
force** — ask this endpoint instead. `apps.synthetic.checks.check_kbs_config_drift`
does exactly that every ~15 min and fires `KbsRunningConfigDrift` when the
running process disagrees with the chart.

This runbook turns it on. Read **§0** before touching anything: the ordering is
a correctness requirement, not a preference.

---

## §0 — the two facts that dictate the order

**Fact 1 — on the KBS, mounting the material IS the cutover.**
`AdminListenerMode::decide` (`binaries/kbs-server/src/admin_tls.rs`) is:

| `require_mtls` | material | outcome |
|---|---|---|
| (either) | complete | **mTLS ENFORCED** |
| `true` | absent | listener **NOT BOUND** |
| `false` | absent | plaintext + warning ← today |

So there is **no "certs mounted but still plaintext" state**. The instant the
`kbs-admin-tls` Secret is mounted and the ConfigMap renders the three paths, the
listener demands client certificates. `require_mtls: true` is set *afterwards*
and changes no behaviour while material is present — its job is to remove the
plaintext fallback, so that a Secret that later fails to mount takes the
listener **down** instead of silently reverting to an unauthenticated API.

The chart enforces this: `admin.requireMtls=true` with an empty
`admin.mtls.secretName` **fails to render**.

**Fact 2 — on vali, mounting the material is inert.**
`services/kbs_admin_tls.py` picks the transport from the URL scheme:
`http://` ⇒ plaintext, `https://` ⇒ mTLS (and it refuses to dial https without
complete material rather than falling back to system roots). So vali's certs can
be staged, validated and *proven* while the KBS is still plaintext. That
asymmetry is the only place the rollout gets a rehearsal, which is why the
client side goes first.

Consequence: **steps 1–3 are reversible and non-disruptive. Step 4 is the
cutover and has a short window in which admin calls fail.** The failure is
loud and retryable (`EffectUnavailable`), never a silent unauthenticated
success — `a_plaintext_client_gets_nothing_from_an_mtls_listener` in
`binaries/kbs-server/tests/admin_mtls_client_interop.rs` is that claim.

### What the step-4 window costs

| affected | effect |
|---|---|
| running VMs | **nothing.** The release path (`:8000`) is a separate listener; an already-unlocked guest never calls the KBS again until its next boot. |
| new launches | fail at §24 `register-vm` / the §22 auto-pin, `EffectUnavailable`; the launch-tick retries. |
| §25 migrations | stall at `activate`; the orchestration tick retries. |
| tenant attestation view | `GET …/evidence` returns "unknown". |

### What the KBS restart in step 4 costs — read this before scheduling

The KBS's `state`, `audit` and `evidence` dirs are **`emptyDir`s inside a Kata
CVM**; the encryption key lives inside the CVM. A restart wipes all three
irrecoverably. Restarting is **survivable** (proven 2026-08-10, #889/#890) but
it is not free. What is lost and what must be re-established:

| lost | consequence | recovery |
|---|---|---|
| `vm-states.json` | every running VM has **no KBS record**; its next KEK release (reboot, §25 dest activation, reboot-recovery relaunch) is refused | `vali_kbs_recover` re-mints a fresh OrderTicket at the VM's current generation/host and re-registers it |
| `boot-counters.json` | the per-VM anti-rollback counter is `0` | seed it from the miner's `/var/lib/hippius-miner/state/<vm>.raw` — **one shot per VM, irreversible**; see `boot-counter-recovery-runbook.md` |
| admin audit chain | the hash-chained admin log restarts | nothing to do; the prior chain is gone |
| §280 evidence bundles | the attestation view answers "unknown" until each VM re-attests | self-heals on the next release |
| installed allowlist | — | **not** lost: the init container re-fetches the signed COSE from S3 and re-installs it at boot |

**Order matters during recovery: SEED the boot counter, THEN register.** Doing
it the other way opens a window in which a booting guest passes `check_only`
against a counter you are about to seed — a brick produced by the recovery
itself. `vali_kbs_recover` enforces this; read its module docstring.

⚠️ Therefore: do step 4 in a window where you can immediately run
`vali_kbs_recover` for every live VM, and where you already hold each VM's boot
counter read off its miner. With one tenant VM live (`realtenant-ubuntu-1`) that
is a small job — do not let it become a large one.

---

## §1 — mint the PKI (offline; nothing is applied)

One CA, two leaves. **The CA private key never enters the cluster and is never
put in Vault** — it is the key that mints admin identities, so an in-cluster
compromise must not be able to reach it. Keep it on the operator workstation /
offline media. (This is also why cert-manager is not used here: a cert-manager
`CA` Issuer keeps the CA key in a Secret in the cluster it protects. The Edge's
mTLS material is provisioned exactly this way already —
`deploy/gitops/apps/edge-gateway/templates/external-secret.yaml`.)

```sh
umask 077
mkdir -p kbs-admin-pki && cd kbs-admin-pki

# 1a. the CA (10 years; its key stays HERE)
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout ca.key -out ca.crt -subj "/CN=hippius-kbs-admin-ca"

# 1b. the LISTENER leaf — SAN must be what vali dials
cat > server.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions     = ext
[dn]
[ext]
subjectAltName = @san
extendedKeyUsage = serverAuth
[san]
DNS.1 = kbs-server-admin.kbs.svc.cluster.local
DNS.2 = kbs-server-admin.kbs.svc
DNS.3 = kbs-server-admin
EOF
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=kbs-server-admin" -config server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -extfile server.cnf -extensions ext

# 1c. vali's CLIENT leaf — the SAN URI becomes `peer_san` in the audit chain
cat > vali.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions     = ext
[dn]
[ext]
subjectAltName = URI:spiffe://hippius.network/vali
extendedKeyUsage = clientAuth
EOF
openssl req -newkey rsa:2048 -nodes -keyout vali.key -out vali.csr \
  -subj "/CN=vali" -config vali.cnf
openssl x509 -req -in vali.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out vali.crt -days 825 -extfile vali.cnf -extensions ext
```

**CHECK before going further** — all four must pass:

```sh
openssl verify -CAfile ca.crt server.crt      # server.crt: OK
openssl verify -CAfile ca.crt vali.crt        # vali.crt: OK
openssl x509 -in server.crt -noout -text | grep -A1 'Subject Alternative Name'
#   → must list kbs-server-admin.kbs.svc.cluster.local
openssl x509 -in vali.crt -noout -text | grep -A1 'Subject Alternative Name'
#   → must be exactly  URI:spiffe://hippius.network/vali
```

A client leaf with **no** identity carrier is dropped by the listener
(`peer-identity-missing`): an admin peer that cannot be named cannot be audited.

---

## §2 — stage the material in Vault (nothing is applied yet)

```sh
vault kv put secret/hippius-compute/kbs/admin-mtls \
  cert=@server.crt key=@server.key ca=@ca.crt

vault kv put secret/hippius-compute/vali/kbs-admin-mtls \
  cert=@vali.crt key=@vali.key ca=@ca.crt
```

Note both paths carry `ca` = **the same CA cert**, used for two different jobs:
the KBS pins it to verify *clients*, vali pins it to verify the *server*.

**CHECK:** `vault kv get -format=json secret/hippius-compute/vali/kbs-admin-mtls`
returns three non-empty fields. Nothing in the cluster has changed yet.

---

## §3 — stage the client half on vali (REVERSIBLE, no behaviour change)

Set in `deploy/gitops/apps/vali/values.yaml`:

```yaml
kbsAdminMtls:
  secretName: vali-kbs-admin-tls
  vaultPath: hippius-compute/vali/kbs-admin-mtls

config:
  # kbsAdminUrl stays http:// — this step must not change how vali dials
  kbsAdminClientCert: /etc/hippius/kbs-admin-tls/tls.crt
  kbsAdminClientKey:  /etc/hippius/kbs-admin-tls/tls.key
  kbsAdminCacert:     /etc/hippius/kbs-admin-tls/ca.crt
```

Apply the vali chart (this also needs the vali **image** to contain the client
that speaks mTLS — the `hippius-kbs-admin-client` with `--client-cert` /
`--client-key` / `--ca-cert`; check `hippius-kbs-admin-client register-vm
--help` inside the pod if unsure).

**CHECKS — all three, before step 4:**

1. The Secret materialised:
   ```sh
   kubectl -n vali get secret vali-kbs-admin-tls \
     -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -subject
   ```
2. Every admin-calling workload has the files. Repeat for `vali`,
   `vali-launch-tick`, `vali-orchestration-tick`:
   ```sh
   kubectl -n vali exec deploy/vali-launch-tick -- ls -l /etc/hippius/kbs-admin-tls
   ```
3. **vali says the material is staged and usable.** This is the whole point of
   the step — `services/kbs_admin_tls.py` loads and validates the certs even on
   the plaintext arm:
   ```sh
   kubectl -n vali logs deploy/vali-launch-tick | grep 'kbs-admin-tls:'
   ```
   Expect exactly:
   ```
   kbs-admin-tls: client material staged and VALID, but VALI_KBS_ADMIN_URL is
   still plaintext — the admin hop is UNAUTHENTICATED until the URL is flipped
   to https
   ```
   If it says **`NOT usable`** or **`PARTIAL`**, STOP — fix §1/§2 and repeat.
   Flipping the URL from that state is a guaranteed admin-API outage.

Launches and migrations must still be working normally at the end of §3. They
will be: nothing about how vali dials has changed.

To back out: clear the three `config.kbsAdmin*` values and `kbsAdminMtls`, apply.

---

## §4 — the cutover (KBS restart + vali URL flip, one window)

Do these two together. The admin API is down for the duration either way,
because the KBS restart alone takes it down.

**4a. KBS.** Set in `deploy/gitops/apps/kbs/values.yaml`:

```yaml
admin:
  mtls:
    secretName: kbs-admin-tls
    vaultPath: hippius-compute/kbs/admin-mtls
  # requireMtls STAYS false in this step — see 4d
```

Apply the kbs chart and roll the pod. **CHECK** the startup line changed from
`PLAINTEXT — unauthenticated` to:

```
kbs-server: admin listening on 0.0.0.0:8001 (mTLS, pinned client CA; ClusterIP-only; …)
```

If instead you see `REFUSING to serve the admin listener`, the Secret did not
mount — fix that before touching vali (the API is closed, not open).

**4b. vali.** Flip `config.kbsAdminUrl` to
`https://kbs-server-admin.kbs.svc.cluster.local:8001` and apply; the workloads
roll.

**4c. CHECK — prove the handshake, from inside vali, with a read-only probe:**

```sh
kubectl -n vali exec deploy/vali-launch-tick -- \
  /usr/local/bin/hippius-kbs-admin-client probe \
    --kbs-url https://kbs-server-admin.kbs.svc.cluster.local:8001 \
    --client-cert /etc/hippius/kbs-admin-tls/tls.crt \
    --client-key  /etc/hippius/kbs-admin-tls/tls.key \
    --ca-cert     /etc/hippius/kbs-admin-tls/ca.crt
```

`probe` does a `GET /v1/admin/vm/__mtls-probe__/evidence` — it mutates nothing.

| result | meaning |
|---|---|
| exit 0, `{"outcome":"ok","status":404,"transport":"mtls"}` | ✅ handshake completed and the KBS **accepted our client cert**. 404 is the healthy answer for a vm_id that does not exist. |
| exit 65 + a rustls message on stderr | ❌ handshake refused. Read the message: it names which side rejected which certificate. |
| exit 64 | ❌ the flags/material are inconsistent; nothing was dialled. |

Then confirm the real path end-to-end: drive one launch through
`POST /v1/vm/launch` and check that (a) it reaches `dispatched` — which means
§24 `register-vm` and the §22 auto-pin both went through the mTLS hop — and
(b) the KBS admin audit rows for it now carry
`peer_san=spiffe://hippius.network/vali` instead of `None`. That `peer_san` is
the visible proof the gate is real: before this cutover it was always `None`,
because there was no peer identity to record.

**4d. Only now**, set `admin.requireMtls: true` on the kbs chart and apply. This
does not change the running behaviour — it removes the plaintext fallback, so
that a future Secret-mount failure closes the listener instead of reopening it
unauthenticated. **CHECK** the config renders (the chart refuses the flag
without material) and the pod comes back with the same `mTLS, pinned client CA`
line.

**4e.** Run the post-restart recovery from the §0 table: seed each live VM's
boot counter from its miner, **then** `vali_kbs_recover`. Do not skip this
because "nothing looks broken" — the breakage surfaces at the VM's *next* boot.

### Rollback from step 4

Revert `admin.mtls.secretName` to `""` and `config.kbsAdminUrl` to `http://…`,
apply both charts, roll the KBS. That returns to the pre-cutover state — at the
cost of a second restart, and therefore a second round of §4e.

---

## Rotation

Both leaves are 825-day. To rotate one: mint a new leaf from the same CA, update
the Vault path, let ESO refresh (≤1 h) or force it, and roll the workload. The
pinned CA is unchanged, so old and new leaves are both acceptable during the
overlap.

Rotating the **CA** needs a bundle: put `new-ca.crt || old-ca.crt` in the `ca`
field of *both* Vault paths first (both sides then accept either), roll both
workloads, then re-issue the leaves, then drop the old CA from the bundles.

## Where the properties are proven

- `binaries/kbs-server/tests/admin_mtls_client_interop.rs` — the shipped client
  config against the real listener: a cert-less client and a wrong-CA client
  never reach a handler; the client refuses an unpinned server cert; a plaintext
  client gets nothing.
- `binaries/kbs-admin-client/src/mtls.rs` (tests) — the client decision table.
- `vali/apps/orchestration/tests/test_kbs_admin_tls.py` — vali refuses to dial
  https without material, trusts exactly one CA anchor, and carries the
  transport into all five admin callers.
- `binaries/kbs-server/tests/chart_deploy_safety.rs` — the chart cannot render
  `require_mtls=true` without material, and mounting material enforces mTLS.
- `vali/tests/test_gitops_vali_chart.py` — every admin-calling workload mounts
  the identity, and the default render is unchanged.
