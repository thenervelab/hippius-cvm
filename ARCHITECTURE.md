# Hippius DePIN compute control plane — architecture (reconciled + hardened)

Status: **design of record, no code yet**. Reconciles the original cahier des
charges (Gemini DePIN spec) with the deployed infra and every locked decision,
then hardened with the findings of an independent security review (see issue
#1 comments). The live tracking issue is in this repo.

## 1. Purpose

Run user VMs on an untrusted, decentralized fleet of AMD EPYC hypervisors
("miners") under confidential computing (AMD SEV-SNP), with absolute
least-privilege separation between Web2 orchestration, the cryptographic
control plane, the secret store (Tier-0), the edge-facing relay, and the
hostile execution edge.

## 2. Zones

> Visual overview (zones, end-to-end sequence, VM/node state machine):
> see [`DIAGRAMS.md`](DIAGRAMS.md). Diagrams are a map; this spec is the
> contract.

| Zone | Host | Role | Talks to | Path |
|---|---|---|---|---|
| **L1 — client app** | existing `hippius-backend` Django (separate cluster) | users, dashboard, NetBird multi-tenant, registry, subscriptions; **mints the signed OrderTicket** (+ NetBird enrol key via `issue_enroll_key`) | vali Django | exposed port + firewall (IP allowlist) + mTLS |
| **Edge / Miner GW** | **pair of hardened VMs (HA)**, dual-homed | stateless auth+transport relay to the hostile miner fleet | miners / vali / L1 | NetBird prod mesh (miner side, confined to these 2 VMs) ↔ **private L2 network** + mTLS (internal side) |
| **Crypto GW / vali** | dedicated validator **k8s cluster** | **vali Django** (orchestration, non-CC) + **Rust KBS core — runs in an attested SEV-SNP Confidential VM (v1, §8)** + **Packer factory** | Vault / Edge GW / L1 | Vault: public IP **firewalled** + TLS + mTLS + **KBS auth = SNP-attestation-bound, no static AppRole secret** (§8) · Edge GW: private-network+mTLS · L1: firewalled port+mTLS |
| **Tier-0 Vault** | a cloud Confidential VM (AMD SEV, Raft, KMS auto-unseal) | LUKS keys + secrets | KBS only | `https://<VAULT_HOST>:8200`, IP-whitelisted to the vali cluster egress + admin (temporary compromise — see §8) |
| **L3 — edge** | untrusted EPYC hypervisors + user VMs | KVM/libvirt, Hippius Guardian (untrusted relay), user VM (initramfs agent, cloud-init, NetBird, sshd), **validator-owned Audit VM** (per-node attested trust anchor, §23) | Edge GW | prod NetBird `miner` group |

## 3. The two Djangos (do not conflate)

- **`hippius-backend` Django (existing, client-facing)** — Layer 1. Owns users,
  dashboard, NetBird multi-tenant (`/api/network/`), registry, subscriptions.
  **Mints the signed OrderTicket** (§6) including the NetBird one-off enrol key
  via `netbird.services.enroll.issue_enroll_key` (that logic stays here). L1
  holds the **OrderTicket signing key**.
- **vali Django (NEW, greenfield, internal-only)** — in the dedicated validator
  cluster. Own codebase/DB/RBAC/deployment. Receives the OrderTicket, follows
  miner status/telemetry, issues lifecycle commands, triggers Packer, calls the
  Rust KBS. Never client-facing. **Carries the ticket opaquely; it is NOT
  trusted to parse-then-vouch** — the KBS re-validates the ticket signature.

## 4. Vali implementation split (by criticality)

- **Rust KBS core** (small, frozen, audited) — the ONLY thing touching
  plaintext secrets: OrderTicket signature verification + SEV-SNP report
  verification + Vault client + key wrap-to-guest + `zeroize`. Rust is
  non-negotiable (Python can't reliably wipe RAM; SNP verification ecosystem
  mature in Rust, weak in Python). **Runs inside an attested SEV-SNP
  Confidential VM (v1, §8); its Vault credential is SNP-attestation-bound,
  not a static AppRole secret.** Plaintext + Vault capability exist only
  inside this measured enclave.
- **vali Django** — everything iterative: OrderTicket intake, status/telemetry
  follow, lifecycle issuance, Packer trigger, the "follow everything" API.
  Submits requests to the KBS but **chooses none of the security inputs**
  (§5, §7). **Stateless / horizontally-replicated**, authoritative state in
  **Postgres** (HA, migrations, optimistic concurrency) — proven workable
  by the parallel `hccs` impl; no security state lives in vali (that is the
  KBS enclave + Vault).

## 5. Invariants (non-negotiable)

1. **KBS is policy-authoritative.** The KBS independently derives the Vault
   secret path and the release policy from the *signed OrderTicket + the
   verified attestation*, **never** from mutable vali-Django parameters. A
   compromised vali Django can submit requests but cannot choose the Vault
   path, expected measurement, tenant, or destination.
2. **Attestation is bound, not just "valid"** (§7). A bare valid SNP report is
   insufficient.
3. **OrderTicket is an immutable signed object** minted by L1 (§6); the KBS
   verifies the signature directly, not vali Django's parsed view.
4. **Edge GW is an application relay, not an IP router.**
   `net.ipv4.ip_forward=0`, no NAT/forwarding between the NetBird interface and
   the private-network interface. Only the userspace relay process crosses,
   enforcing
   authn + diode + opacity + schema validation.
5. **Diode directionality** (§9). Control flows inner → Edge GW → miner
   (signed). Telemetry flows miner → Edge GW → queue; inner **pulls** and
   treats every pulled byte as fully untrusted.
6. **Secret release is end-to-end KBS ↔ attested guest**, opaque through Edge
   GW (it never decrypts), wrapped to an ephemeral guest key.
7. **Tier-0 / control plane is off the prod NetBird mesh.** Only the Edge GW
   touches the mesh, confined to its 2 VMs.
8. **Edge GW holds no Tier-0 / user secrets.** It DOES hold authority
   (NetBird creds, internal mTLS keys) — those are sensitive, short-lived,
   revocable, scoped to relay endpoints; they are not LUKS/Vault material. If
   the Edge GW falls, the attacker gains the hostile-facing surface + an
   authenticated relay identity — not Tier-0 (§10).
9. The vali cluster is **not confidential**; the accepted risk is precisely
   stated in §8 (it is *not* equivalent to full CC isolation).

## 6. OrderTicket (signed, immutable) — Critical

The OrderTicket is the authorization root. L1 mints it; the KBS is the verifier.

- **Wire format (pinned):** **COSE_Sign1** (RFC 9052) over **deterministic
  CBOR** (RFC 8949 §4.2.1 core deterministic encoding). Signature alg
  **EdDSA (Ed25519)**. Protected header carries `alg` + **`kid`** (L1 ticket
  signing key id) for rotation. No JWS/JSON variant — one format only.
- **Fields (all signed):** schema `v`, ticket id, issue time, **expiry**,
  single-use **nonce**, tenant/user/VM ids, **`lease_id`** + monotonic
  **`vm_generation`** (bind the ticket to one VM lifecycle generation —
  §24/§25), **intended `node_id` + `platform_id`** placement constraint,
  target miner constraints, **allowed image measurement(s)**, **two
  distinct secret refs** — `userdata_vault_ref {path, version}` and
  `luks_vault_ref {path, version}` (separate KV v2 paths, each its own
  immutable version; never one shared path/version — see §19),
  **`allowed_userdata_digest`** (§20), resource class, lifecycle
  permissions. Required vs optional fields are fixed by the schema `v`;
  unknown fields ⇒ reject.
- The **NetBird enrol key rides INSIDE the encrypted user-data** (§19), never
  as a cleartext ticket field; the ticket carries only its digest binding.
- **Signed by L1's OrderTicket signing key.** vali Django and the Edge GW
  transport it **opaquely** and may not mutate it; any field they need to act
  on is read but never re-asserted to the KBS.
- The KBS **verifies the signature + expiry + single-use** before doing
  anything; it derives Vault path and release policy from ticket fields, not
  from the request envelope.
- **Key-trust model (pinned, no separate PKI).** Two trust anchors, both
  riding the existing measurement-allowlist machinery (§11) — no online PKI:
  - **Guest → KBS:** the bounded set of valid **KBS response-signing
    pubkeys (with `kid`)** is **embedded in the measured image**, so the
    guest's trust in them is itself attested.
  - **KBS → L1 ticket:** the KBS's authoritative **L1 ticket-signing
    keyring** comes **only from its offline allowlist artifact** (same
    out-of-band channel as approved measurements, §11) — never from the
    request, vali, or the guest image.
  - The **offline allowlist artifact** maps, per measurement:
    `measurement → { accepted_l1_ticket_kids, accepted_kbs_response_kids }`.
    The KBS verifies the OrderTicket against an accepted L1 `kid`, and
    **signs its response only with a live private key whose `kid` is in the
    attested measurement's `accepted_kbs_response_kids`** (so rotation can't
    produce a valid release the guest will reject).
  - **Rotation** = ship a new measured image (new embedded KBS-response
    keyring) + new allowlist entry for its measurement. **Emergency revoke**
    = drop the old measurement from the allowlist. Private-key custody
    (HSM/offline) is the only remaining operational input (§18).

## 7. KBS release contract & attestation binding — Critical

Releasing a LUKS key requires ALL of the following to verify in the Rust KBS;
any failure ⇒ deny + audit:

- **AMD chain + TCB**: VCEK/cert chain to AMD root, SNP TCB ≥ policy minimum.
- **Freshness**: a **KBS-issued nonce**, short expiry, single-use, present in
  the report's `REPORT_DATA`.
- **Guest binding**: an **ephemeral guest public key** in `REPORT_DATA`; the
  released secret is **wrapped only to that key** (RAM-to-RAM, never plaintext
  on the wire or in vali/Edge).
- **Measurement allowlist**: report measurement ∈ the OrderTicket's allowed
  image measurement(s) ∈ an **offline KBS-held allowlist** (built from the
  Packer provenance, §10). SNP faithfully attests *compromised* software too —
  the allowlist is what makes attestation meaningful.
- **Launch policy**: SNP guest policy (debug off, SMT, migration) within bounds.
- **Authorization binding**: ticket id + tenant/user/VM id + requested
  secret_ref all consistent between the verified ticket and the attestation
  context; KBS derives the Vault path from the ticket, not the request.
- **Lifecycle/generation binding (unified KBS VM state, §24).** The KBS
  serializably checks the ticket's `lease_id` + `vm_generation` +
  intended `node_id/platform_id` against the **single durable per-`vm_id`
  state model** of §24 (`Active{gen,host,lease} | Migrating{…} |
  Decommissioning | Destroyed{gen}`), **before the Vault read and again
  before the at-most-once commit**. Deny if the VM is
  `Decommissioning|Destroyed`, the generation ≠ the state's current
  active generation, or the attested node/platform ≠ the ticket's
  intended placement. This is what makes the §24 tombstone and the §25
  migration fence actually enforceable at release time.
- **Anti-replay = atomic release state machine.** No trusted "boot/session
  id" (there is no room in `REPORT_DATA` and any external id is
  attacker-controlled). Instead: the KBS-issued **nonce** and the
  **ticket** are each strictly single-use, enforced by an atomic
  transaction: `reserve(nonce, ticket_id)` → verify report → read Vault →
  wrap → sign → **durably commit-release-once BEFORE emitting any response
  byte** (at-most-once emission; never commit-after-emit). **Release-once is
  keyed strictly by `(ticket_id, nonce)`** — NOT by the Vault
  path/version/secret_ref. Consequence: the *same* `vault_path@vault_version`
  may be released again, but **only under a fresh, signed OrderTicket with a
  fresh KBS nonce** (never a replay). A crash before commit ⇒ no secret left
  the KBS; a crash after commit ⇒ that ticket/nonce spent (recover by minting
  a new ticket, §14). A replayed/proxied report or a re-used ticket/nonce
  loses the atomic reservation race ⇒ deny.
- **`REPORT_DATA` is authoritative** for the guest key (exact layout in §20).
  The `guest_ephemeral_pubkey` in the request input is **untrusted/redundant**:
  the KBS ignores it except to require **constant-time byte-equality** with the
  key committed inside the attested `REPORT_DATA`.
- **KBS→guest response authenticity is MANDATORY** (not optional): the KBS
  signs every release response; the guest verifies before decrypt/use
  (§20). HPKE confidentiality alone does not authenticate the sender.
- **The signed response carries `allowed_userdata_digest`** (§20) so the
  guest can verify user-data integrity against the **KBS signature** — the
  guest has no L1 ticket key and MUST NOT be expected to verify the ticket.
- **No standing fleet-wide read authority.** The KBS Vault policy is
  **per-VM-path scoped, no `list`**, and reads use **short-TTL,
  response-wrapped, single-use leases** — there is never a long-lived token
  that can iterate all `*/luks` paths. Combined with the §8 secret-lifecycle
  split (ephemeral user-data destroyed post-first-boot; persistent LUKS key
  protected only by scope+TTL, never re-sealed) this **bounds** — does not
  eliminate — a vali breach.

Concrete cryptographic profile (digest definition, HPKE wrap + AAD, unwrap
rules, `REPORT_DATA` layout, datasource allow/deny, no-persistence) is pinned
in **§20** — it is a spec-first prerequisite.

The **encrypted cloud-init / user-data is released under this same contract**
(same nonce, ticket, measurement, anti-replay, wrap-to-guest) — it is a
first-class Tier-0 secret, not a side channel. See §19.

Release contract input: `attestation_report + KBS_nonce + signed_OrderTicket +
requested_secret_ref + guest_ephemeral_pubkey`. Output: secret **wrapped to the
guest key**, or a signed denial. Django/Edge see only success/failure.

## 8. Threat model & accepted risk (honest framing)

**The KBS core runs inside an attested Confidential VM (AMD SEV-SNP) in
v1 — non-negotiable, NO accepted security compromise.** This is the
"blackbox" pattern (the same attested-CVM technique as the §23 Audit VM
and tenant VMs) applied to the single most critical component: *the
attester is itself attested*. The vali **orchestration** cluster (Django,
Packer-trigger, telemetry) is not confidential, but by §4/§5 it never
holds plaintext, Vault-read authority, or security inputs — the only
component with the live Vault read capability + plaintext is the
**measured KBS enclave**.

Consequently a breach of the non-confidential vali orchestration cluster
yields **no secret**: it holds only opaque tickets + deterministic
`*_vault_ref` paths (the path is not the secret) and **no Vault
credential**. The earlier "total & retroactive whole-fleet extraction"
vector (it required the KBS's Vault authority to sit on a non-CC host) is
**eliminated, not accepted**.

Mandatory mitigations — **the two secrets have different lifecycles and
MUST be treated differently** (treating them the same created earlier
self-contradictions):

- **user-data = ephemeral / one-shot.** cloud-init runs once on first boot;
  reboots never need it. L1 (its sole writer, §16) **destroys the user-data
  Vault version after the VM's first successful boot** (destroy needs no
  read — no paradox). Retro-extraction window for user-data closes at first
  boot.
- **LUKS key = persistent for the VM's lifetime.** It is required on **every**
  reboot, so it **must persist and is NEVER re-sealed/destroyed** while the
  VM lives (re-sealing is impossible — L1/vali can't read it, Packer-write /
  KBS-read only — and destroying it would brick the disk). Its protection is
  **not** obscurity but: **per-VM-path Vault policy, no `list`, short-TTL
  response-wrapped single-use KBS leases**, released only to a freshly
  **re-attested measured guest on every boot**.
- **`*_vault_ref` paths are deterministic from `vm_id`** — there is no
  secret "map" to purge (purging it would only break §14 reboot recovery
  while granting no security: the path is not the secret; the *scoped KBS
  capability + attestation* is). Knowing a path yields nothing.
- **L1 write path is separate** (§16/§19): vali Django never holds Vault
  write access nor plaintext.
- **KBS Vault credential is attestation-bound — "the attester is itself
  attested" (v1). Pinned contract (no hand-wave):**
  - There is **no static KBS AppRole secret** anywhere (disk / k8s
    Secret / env).
  - The **Vault-side authenticator** (native SNP-auth plugin **preferred**;
    else a **minimal attested broker that is itself Tier-0** — no reusable
    fleet-wide mint token, every capability-mint audited) **issues a
    single-use, short-expiry challenge nonce** and **verifies the SNP
    evidence** (KBS measurement ∈ allowlist, TCB ≥ policy, AMD chain).
  - The KBS **`REPORT_DATA` binds `{challenge_nonce, requested per-VM
    scope, KBS ephemeral auth pubkey / TLS-exporter}`** — so the granted
    capability is bound to *that* attested enclave + channel + scope and
    cannot be replayed, widened, or proxied.
  - The capability is **returned only wrapped to that attested
    channel/key**, **per-VM-scoped, no-list, short-TTL, response-wrapped**.
  - The authenticator's **root of trust for the KBS measurement (+
    monotonic high-water mark)** lives in **tamper-safe Tier-0 storage,
    analogous to §22 — never on the vali FS**.
  A breached non-CC host has no enclave ⇒ no valid SNP report ⇒ no
  capability; it cannot impersonate, replay, or proxy the KBS, nor read
  live (confidential) KBS RAM. Bootstrap is trust-on-*attestation*, never
  trust-on-first-use.
- Plus: dedicated isolated node pool · no shell/exec/debug on KBS/Packer
  nodes · seccomp/AppArmor · core-dump & memory-dump disabled.

**Residual — the host-breach fleet vector is CLOSED in v1.** With the CVM
KBS + attestation-bound Vault credential, a compromise of the
non-confidential control plane can no longer extract **any** LUKS key
(historic or in-flight): there is no usable Vault authority or plaintext
outside the attested enclave. The only irreducible is **definitional** —
an *authorized, attested, running* KBS does, by design, unwrap the
specific secret it was attested + ticket-authorized to release, inside
its measured enclave; bounded to a tiny **frozen audited core**
(no shell/exec/debug, seccomp, dumps off). That is the component's
*purpose*, **not** a security compromise.

**Distinct, still-open inherent limit (miner-side — NOT the KBS
residual).** Separately: miner hosts are **not** confidential to us and
we cannot forcibly stop code on hardware we do not own. While a tenant VM
is *live* on a hostile miner, that miner can in principle observe/retain
what the running guest exposes (a guest still running after an
EOL/migration command; the at-rest LUKS *ciphertext*). This **miner-side
live-host residual** (referenced by §23/§24/§25) is **inherent to renting
untrusted hardware**, honestly accepted, materially smaller than the old
KBS vector, and **never yields at-rest fleet key extraction**. It is
**not** closed by CVM KBS (that would need confidential *miner* hosts / a
different trust model — outside our control, not a roadmap we own). Do
not conflate it with the now-closed KBS host-breach residual above.

## 9. Diode telemetry — concrete mechanics

- **Queue lives on the Edge side** (or a dedicated broker the inner side
  *pulls* from). Inner services **never** expose an inbound endpoint to the
  hostile-facing path; they pull, with auth originating from inner → broker.
- Bounded queues, max message size, backpressure, poison-message quarantine,
  dedupe, schema **versioning + validation before enqueue and again on pull**.
- Pulled telemetry is **fully untrusted**: signed Guardian/miner envelopes
  where possible; inner consumers must be parser-hardened and must never call
  back into Edge-controlled addresses.

## 10. Edge GW compromise containment

`ip_forward=0` stops accidental routing, not application abuse. A compromised
Edge GW can flood/poison telemetry, replay, hide miner state, delay commands,
probe the private network, or exploit inner parser bugs. Mitigations:

- Edge in a **tightly firewalled private-network micro-segment**: only specific
  destination host:ports, default-deny.
- Per-peer mTLS identities (miner side and internal side), short-lived, revocable.
- Schema validation + rate limits + bounded queues before anything reaches
  inner.
- Signed telemetry envelopes from Guardian/miner identity where feasible.
- "Edge GW compromise" tabletop/drill in the runbook.

## 11. Supply chain & measured boot

SNP attests whatever software is in the image — including a compromised one.
The measurement allowlist (§7) is only as good as the build provenance.

- Packer: pinned base images **by digest**, pinned plugins, pinned package
  mirrors, signed artifacts, SBOM, SLSA-style provenance.
- **Measured** Guardian + initramfs + tenant image **+ the validator-owned
  Audit VM image** (§23, same measured-UKI machinery — distinct
  allowlisted measurement, validator-owned, no tenant data) → expected
  measurements computed at build time and pushed to the **KBS offline
  allowlist** out-of-band (not via vali Django).
- Vault role separation: **Packer = write-only AppRole** to the images
  subpath; **KBS = read-only LUKS-path policy reached ONLY through
  SNP-attestation auth (no AppRole secret-id)** — see §8. Distinct
  policies; the KBS path is attestation-bound, not credential-bound.
- **Image distribution — presigned S3; integrity from the *measured UKI*,
  NOT the transport.** Packer (vali) uploads the built qcow2 to S3; vali
  Django hands each miner a presigned GET URL. The mechanism is only sound
  because of the next bullets — "measures outside the allowlist" alone is
  **insufficient**: the SNP launch measurement covers the UKI
  (kernel+cmdline+initramfs), **not** the qcow2 rootfs.
  - **Rootfs integrity is anchored in the measured UKI.** The OS rootfs is
    **read-only with dm-verity**; its **verity root hash is embedded inside
    the signed UKI** (the same UKI folded into the SNP launch measurement —
    see "Deterministic launch measurement"). The measured initramfs
    **activates dm-verity and fails closed *before* `switch_root`** on any
    mismatch. SNP attestation thus transitively covers the **entire
    rootfs**, not just kernel+initramfs. The base qcow2 is therefore
    genuinely **non-secret and tamper-evident**: altering any rootfs byte
    fails verity → boot aborts → no secret released.
  - **Block-device layout is allowlisted.** The initramfs treats the device
    as untrusted: it mounts **only** the verity rootfs + the named per-VM
    LUKS volume and **rejects** extra partitions, qcow2 **backing-files**,
    and overlays (defeats backing-file / overlay substitution).
  - **LUKS volume = confidential per-VM writable state, encrypted at
    *sealing*, only *unlocked* post-attestation.** Packer/sealing creates
    the LUKS volume and **Packer-writes** the key to Vault; the guest
    **unlocks** (never encrypts) it after KBS release (§8 Packer-write /
    KBS-read, §19). *(Corrects the earlier "LUKS-encrypted only
    post-attestation" phrasing — encryption is at build/seal time; only the
    unlock is post-attestation.)*
  - **Build→artifact→S3 binding (closes the TOCTOU).** Image objects are
    **content-addressed by SHA-256**; the bucket uses **S3 versioning +
    Object Lock**. The out-of-band provenance pushed to the KBS offline
    allowlist is a **signed mapping** `{launch_measurement(UKI),
    verity_root_hash, artifact_sha256, s3_bucket, key, version_id}`. vali
    presigns the **exact `version_id`**; the miner verifies the SHA-256
    before boot. The security root is the verity-hash-in-UKI (a substituted
    object cannot boot); the digest/version binding is defense-in-depth +
    availability, not the primary control.
  - **Presigned URL — honest semantics (like §8).** A native S3 presigned
    GET is **not individually revocable**, so **security does NOT depend on
    URL secrecy**. Controls: short **max TTL**, single `version_id` scope,
    **no blanket S3 creds** on the untrusted miner, audit + rate-limit. A
    leaked / replayed / shared URL only yields a **public, non-secret,
    verity-anchored** artifact that cannot boot if modified. To actually
    pull a poisoned object the revocation primitive is **delete/deny that
    object-version** (and/or rotate the signing STS session) — never URL
    secrecy.
  - **Enforced non-secret base-image contract.** The Packer base image MUST
    contain **no** tenant/user data, **no** private keys/tokens, **no**
    Vault/AppRole creds, **no** static host identity (SSH host keys, NetBird
    tokens). All such identity is generated **only inside the attested guest
    after KBS release** (cloud-init, §19/§21). CI runs a **secret scan +
    SBOM/provenance attestation** and **fails the build** on any finding —
    "non-secret" is enforced, not asserted.
  - **Fetch / cache failure handling.** Bad / expired / revoked URL → vali
    reissues a fresh presigned `version_id` URL (bounded retries). The miner
    cache is **namespaced by artifact SHA-256**; a cache hit is used **only
    after checksum match**; partial downloads are discarded; repeated bad
    fetches from a node → **audit + §13 quarantine**.
- **Deterministic launch measurement (SEV-SNP specifics, mandatory).** The
  hypervisor-supplied kernel command line and initrd are folded into the
  SNP launch measurement; if the miner can vary them the measurement is not
  deterministic and the allowlist is meaningless. Therefore the guest ships
  as a **UKI (Unified Kernel Image)**: kernel + fixed cmdline + initramfs +
  embedded keyrings as one signed PE, with the **external/hypervisor cmdline
  ignored**. Pin the SNP **launch policy / IDBLOCK** (debug off, no
  migration, SMT as configured) and the **ID_KEY**; the KBS allowlist keys
  on the **UKI/launch measurement + IDBLOCK**, not a soft "image" notion.
  Note **VCEK vs VLEK** + required TCB/SVN floor (reject TCB rollback).

## 12. Rotation & revocation

Define cadence + emergency revoke for: LUKS keys (per-VM rekey story),
**non-KBS AppRole secret-ids** (L1 write-only, Packer write-only, admin —
the KBS has **no AppRole secret**; it is SNP-attestation-bound, §8, so
"rotation" there = roll the allowlisted KBS measurement, §11/§22),
mTLS certs (Edge, vali, Vault client), NetBird enrol keys,
**L1 OrderTicket signing key**, KBS signing/identity keys, the **Audit-VM
agent key + its KBS certificate** (§23 — key-ids, overlap window,
compromised-key ⇒ node `Reattesting`/quarantine, family re-signs the
`{family,node_id,audit_vm_key}` binding), and the measurement allowlist
(revoke a compromised image measurement → in-flight tickets become
unreleasable). Document tenant impact and stale-ticket invalidation.

## 13. DoS / admission control

Miners are explicitly hostile and SNP verification + Vault reads are
expensive. Required: per-miner and per-ticket quotas, admission control /
proof-of-work before expensive KBS ops, queue caps, circuit breakers, async
verification workers, Vault rate limits, and a defined degraded mode.

**Post-commit availability-burn cap (specific):** a hostile Guardian/miner
can let the KBS commit-release then drop the response, forcing the
new-ticket/reboot path (§14) to burn resources. The penalty **must target
the miner node, not the victim tenant** — punishing the tenant for a
malicious host is a trivial targeted DoS. Bound it: per-**miner-node** caps
on dropped/failed post-commit deliveries within a window, with exponential
backoff, alerting, and **removing the offending miner from scheduling**
(quarantine) pending operator review (fail-safe). The tenant's VM is
re-scheduled onto a healthy miner with a fresh ticket; tenant/VM-level
counters are advisory only, never the suspension trigger.

## 14. Failure & recovery

Specify: Edge HA split-brain, queue loss, Vault outage, KBS restart mid-
release, Packer partial failure, VM boot retry, orphaned NetBird enrol keys.
→ idempotency keys on lifecycle actions, explicit at-least-once vs exactly-once
semantics, compensating cleanup, operator runbooks.

**Secret-release recovery (consequence of §7 at-most-once + commit-before-
emit):** release-once is keyed by `(ticket_id, nonce)`, so a
lost/undelivered response after commit means *that* ticket/nonce is spent.
Recovery is **not** retry with the same ticket — it is: L1 mints a **new**
OrderTicket (new nonce). The **`luks_vault_ref` is the same** (the LUKS key
persists for the VM's lifetime, §8 — its path is deterministic from
`vm_id`, no stored map needed). The `userdata_vault_ref` only matters on
**first** boot; on a later reboot the VM is already provisioned and needs
**no user-data** (if a re-provision is ever required, L1 re-seals a fresh
user-data version). The VM reboots. Deliberate trade: confidentiality/
anti-replay over availability, bounded by the §13 per-miner cap.

> **Tracked deliverable (NOT done):** the executable operator runbook for
> this recovery (who mints, how the new ticket reaches the boot, the
> cap/escalation path) is an operational artifact still to be written — the
> architecture only pins the *semantics* here.

## 15. Audit & observability (Tier-0 grade)

Append-only, tamper-resistant decision logs from **KBS and Vault**: who
requested a key, which attestation was verified (digest, measurement), which
ticket authorized it, which Vault path was read, which guest key received it.
Correlation id flows OrderTicket → release. Alerting on abnormal release
volume, measurement mismatch, replay attempts, denied attestations.

## 16. Connectivity summary

- miners ↔ Edge GW: prod NetBird mesh (NAT traversal), NetBird identity / mTLS
- Edge GW ↔ vali & L1: **private L2 network** + per-peer mTLS, micro-segmented
- L1 (hippius-backend) ↔ vali Django: exposed port + firewall (IP allowlist) + mTLS
- **L1 ↔ Vault (direct, write-only):** L1 seals user-data itself over its
  **own** firewalled path with a **write-only AppRole** (no read, no list,
  per-VM path). It does **not** proxy the write through vali Django — vali
  never holds Vault write access nor Tier-0 plaintext (preserves §4).
- vali (KBS) ↔ Vault: the Vault host's public IP firewalled to vali-cluster egress + TLS +
  **mTLS client-cert on top of Vault auth** + Vault audit device on + firewall
  drift checks + emergency-revoke runbook (private path = roadmap). **KBS
  auth = SNP-attestation-bound (no static AppRole secret, §8)**; the
  resulting capability = **read-only, per-VM-path, no list, short-TTL
  response-wrapped**.
- secret release (LUKS key **and** encrypted cloud-init/user-data, §19):
  end-to-end KBS ↔ attested guest, wrapped, opaque through Edge

## 17. Sequenced plan (status-tracked)

> Canonical build **order**. The **granular, checkable backlog** (sub-tasks,
> open trait seams, operational inputs, current state) is the
> **Implementation-roadmap tracking issue #25** — that issue is the source
> of truth for *what's left*; #1 stays the design/decision log.

1. **Specs first (Critical) — [DONE].** OrderTicket (§6), KBS release
   contract + attestation binding (§7), encrypted user-data lifecycle
   (§19), cryptographic profile (§20), §23 v1 `f` + scoring-pallet
   schema, §24/§25 lifecycle — all pinned in this doc (§§1–26).
2. **Network — [pending, infra].** Static egress IP for the vali cluster
   → `var.gateway_ip` in `hashicorp-vault/main.tf`; edge firewall +
   private-network micro-seg; private-network enrolment for the Edge GW pair
   + vali cluster + L1.
3. **CVM-KBS substrate (v1, §8) + Vault attestation-binding — [pending,
   infra; §18 substrate choice].** Provision the SEV-SNP Confidential VM
   the KBS runs in (cloud-CC vs bare-metal SEV-SNP = §18); stand up the Vault-side
   **SNP-attestation auth** (native plugin or Tier-0 minimal attested
   broker) releasing the per-VM-scoped, no-list, short-TTL,
   response-wrapped capability **only** to the attested KBS measurement —
   **no static `kbs` AppRole secret**. `packer` stays write-only; audit
   device; mTLS.
4. **KBS core (Rust) — [scaffold DONE (PR #24); open seams pending].**
   ticket verify → SNP verify (§7) → attest-to-Vault → Vault read (LUKS +
   user-data, §19) → wrap-to-guest → zeroize; offline allowlist. Scaffold
   merged + tested; **pending: real AMD cert-chain verifier, production
   Vault SNP-auth/KV client, durable ReleaseStore, KBS transport/server,
   KBS-nonce issuance, §22 allowlist loader** (issue #25 §D).
5. **Measured guest / initramfs agent — [pending].** UKI + dm-verity
   rootfs; the §21 guest round-trip (ephemeral key, REPORT_DATA, verify
   KBS-signed response, unwrap, LUKS, switch_root) (issue #25 §E).
6. **vali Django — [pending].** OrderTicket intake, status/telemetry,
   lifecycle, Packer trigger, follow-everything API, scheduler,
   migration/decommission orchestration. No security inputs.
7. **Packer factory — [pending].** Provenance + signed artifacts +
   measured images; content-addressed S3 + signed provenance map;
   write-only Vault role; enforced non-secret base-image contract.
8. **Edge GW — [pending].** HA VM pair, dual-homed, userspace opaque
   relay (diode + opacity + schema validation), no IP forwarding,
   micro-segmented.
9. **Scoring + scheduler + Audit VM (§23) — [pending].** Deterministic
   `f`/pallet + proof-of-capacity + attested cross-check + per-node Audit
   VM + the vali trustless scheduler.
10. **Cross-cutting — [pending].** Rotation/revocation (§12), DoS (§13),
    failure/recovery (§14), audit (§15); runbooks.

## 18. Open inputs / decisions

- Static egress IP of the vali cluster → Vault firewall.
- Private-network enrolment for the Edge GW pair + vali cluster + L1.
- L1 ↔ vali firewalled+mTLS IPs.
- **Private-key custody only** (HSM/offline) for the L1 ticket-signing and
  KBS response-signing keys. The *trust/rotation model is pinned* (§6:
  keyring embedded in the measured image, rotate = new image + measurement
  allowlist, revoke = drop old measurement) — only where/how the private
  keys are physically held remains an operational decision.
- Measurement-allowlist delivery path to the KBS (out-of-band).
- §8 has **no accepted-risk sign-off** anymore — the KBS host-breach
  vector is **closed in v1** by the CVM KBS + attestation-bound Vault
  credential. The only remaining input is **operational**: which CC
  substrate the KBS CVM runs on (cloud Confidential VM vs bare-metal SEV-SNP)
  and the Vault SNP-attestation-auth mechanism (native vs thin broker).
  (The distinct miner-side live-host inherent limit, §8/§23/§24/§25,
  needs no sign-off — it is inherent to renting untrusted hardware.)
- Business sign-off on the **§23 v1 trust posture** (deliberate single-
  operator centralization; other validators powerless; decentralization =
  v2 non-goal) — same kind of conscious accepted-risk as §8.
- §23: the v1 deterministic scoring function `f` + on-chain scoring
  pallet schema are **RESOLVED — concretely specified in §23 "v1 scoring
  function `f` + pallet schema"** (`E`/`W` fixed-point, storage/
  extrinsics/events/hooks, anti-Sybil, graduated slashing). v2
  CRUSH-grade is future work, **not** a v1 blocker. (VM→node placement =
  **off-chain operator log** for v1; slashing operator-driven — no
  on-chain placement commit until v2.) Tenant billing/metering/payment is
  **not** here (owned by `hippius-backend` L1, §3/§23). The **Audit VM**
  (§23) consolidates the formerly-vague "canary VMs / validator probes";
  only its **resource-cap tuning** (tenant-safe headroom) is an open
  *operational* knob, not an architecture gap. **No architecture
  design-open items remain.**

(The earlier "HPKE Auth mode vs attested channel" question is **resolved**:
a mandatory KBS-signed response is now required regardless — §20.)

## 19. Encrypted cloud-init / user-data (Vault per-VM) — Critical

The per-VM user-data carries provisioning secrets (NetBird one-off enrol key,
SSH keys, tenant config, initial creds). A swapped/leaked cloud-init = full VM
compromise **even with perfect disk encryption** (attacker SSH keys / backdoor
injected). It is therefore a first-class Tier-0 secret, NOT a side channel.

- **Separate Vault paths (no collision):** user-data and the LUKS key live
  at **distinct per-VM KV v2 paths**, each with its **own** immutable
  version. The OrderTicket carries both (`userdata_vault_ref`,
  `luks_vault_ref`, §6). They are written by different writers at different
  times (L1 seals user-data; Packer/sealing writes LUKS) — sharing one path
  would make the single version ambiguous. Never one path/version.
- **Production & sealing (strict ordering):** L1 builds the user-data
  (incl. the NetBird enrol key), **writes it directly to its per-VM Vault
  path over L1's own write-only path** (§16 — NOT via vali Django), reads
  back the **immutable KV version**, computes `allowed_userdata_digest`
  over {path, version, plaintext, binding fields} (§20), then signs the
  OrderTicket embedding `userdata_vault_ref` + digest (all signed, §6).
- **Vault KV v2 read semantics (exact):** the KBS reads `data` at the
  **exact** signed version of each ref — never "latest". It **rejects** if a
  version is deleted/destroyed, the path is not found, the path is an alias,
  or any field is missing; full-object read only. Mismatch ⇒ deny + audit.
- **Integrity binding (both ends):** the KBS recomputes the digest from the
  Vault value at the signed `userdata_vault_ref` and constant-time compares
  to the ticket's. It then **places the verified `allowed_userdata_digest`
  into the KBS-signed response struct** (§20). The guest, after verifying
  the **KBS signature** and decrypting, **recomputes the §20 digest and
  compares it to the digest in the signed KBS response** (NOT to the ticket
  — the guest has no L1 ticket key, §6). So a forged response or a swapped
  cloud-init fails closed. vali Django / Edge GW / a miner cannot swap it.
- **Lifecycle (§8): user-data is one-shot** — L1 **destroys its Vault
  version after the VM's first successful boot** (not needed on reboot). The
  **LUKS key is NOT in scope here**: it persists for the VM's lifetime,
  never re-sealed; see §8 for its bounded residual.
- **Release:** under the **§7 contract** (same nonce, ticket, measurement,
  anti-replay). The KBS reads it from the per-VM Vault path and **wraps it to
  the attested guest ephemeral key**, RAM-to-RAM via Edge GW → Guardian. Never
  plaintext on the wire, in vali, or in Edge.
- **Injection:** the initramfs agent **verifies the KBS response signature**
  against the pinned KBS key (§20), unwraps in guest RAM (guest ephemeral
  private key never leaves guest RAM), **recomputes `allowed_userdata_digest`
  and compares it to the digest carried in the KBS-signed response** (not the
  ticket — the guest has no L1 key), then materialises a **NoCloud
  datasource on tmpfs** before `switch_root`. cloud-init consumes it; the
  seed is then **zeroized**.
  Nothing decrypted ever lands on storage readable by the hostile hypervisor.
- **Rotation/revoke:** covered by §12 (per-VM Vault path revoke invalidates an
  un-booted VM's user-data along with its LUKS key).
- **Concrete digest / wrap / datasource / no-persistence rules: §20.**

## 20. Cryptographic profile (pinned) — Critical, spec-first

Standard, auditable primitives. Same profile for the LUKS key and the
encrypted user-data (both are §7 secrets).

**Deterministic-CBOR reject profile (RFC 8949 §4.2.1 + strict).** Every
signed/digested CBOR object (OrderTicket, KBS response, context, digest
preimage) MUST be encoded canonically, and verifiers MUST **reject**:
duplicate map keys, indefinite-length items, non-minimal integer/length
encodings, unsorted map keys, floats/`simple` values where not in schema,
unexpected tags, and non-canonical COSE protected headers. Two
implementations must serialise/verify byte-identical objects or it is a bug.

**Guest ephemeral keypair.** X25519. Generated **inside the measured
initramfs** (its generation code is part of the attested image). Private key
never leaves guest RAM (mlock'd, zeroized after use). Only the 32-byte public
key leaves the guest — via `REPORT_DATA` only.

**`REPORT_DATA` layout (64 bytes, exact).**
`REPORT_DATA[0:32] = KBS_nonce` (32 random bytes, KBS-issued, single-use,
short expiry). `REPORT_DATA[32:64] = guest X25519 public key` (32 bytes). The
KBS recomputes and requires exact equality; nothing else is accepted.

**Audit-VM attestation binding (distinct — does NOT reuse the tenant
layout).** The §23 Audit-VM agent key is **Ed25519**, which does not fit
`[32:64]=X25519`. So the Audit VM uses `REPORT_DATA[0:32] = KBS_nonce`,
`REPORT_DATA[32:64] = SHA-256(audit_vm_ed25519_pubkey ‖ "HIPPIUS_AUDIT_VM_V1"
‖ node_id ‖ platform_id)`; the **full Ed25519 pubkey is delivered in the
KBS-certified Audit-VM request** and the KBS recomputes/binds it via the
Audit-VM certificate (§23). Tenant guests use the X25519 layout above;
the Audit VM uses this hash binding — never mixed.

**Secret wrapping = HPKE (RFC 9180) for confidentiality, ONE pinned suite:**
`hpke_suite_id = 0x0001` ≙ `KEM = DHKEM(X25519, HKDF-SHA256)`,
`KDF = HKDF-SHA256`, `AEAD = ChaCha20-Poly1305`. **No alternative/negotiation**
in v1 (removes downgrade ambiguity); the suite id is carried in the signed
response below and the guest rejects any other value. KBS = HPKE sender,
guest ephemeral X25519 key = recipient.

**KBS→guest response authenticity = MANDATORY (Critical).** HPKE
confidentiality does NOT authenticate the sender — in base mode any relay
that sees the guest pubkey (Guardian/Edge/miner) could forge a ciphertext to
it. Therefore the KBS **signs the whole release response** with its
**KBS response-signing key (Ed25519)** whose public key + `kid` are **pinned
into the measured initramfs image**. Signed response struct (deterministic
CBOR):
`{ v, kid, hpke_suite_id, ticket_id, vm_id, KBS_nonce, report_digest,
secret_ref, secret_type, allowed_userdata_digest, enc (HPKE encap),
ciphertext }`.
`allowed_userdata_digest` is the value the KBS verified against the ticket;
it is included **so the guest can check user-data integrity via the KBS
signature** — the guest has no L1 ticket-signing key and MUST NOT be
expected to verify the OrderTicket (it only trusts the pinned KBS key, §6).
The guest **verifies this signature against the pinned KBS key BEFORE
decrypting**; mismatch ⇒ abort boot. (HPKE Auth mode is an acceptable
*equivalent* implementation of the sender-auth requirement, but signing is
the pinned default; it is no longer "optional".)

**Context binding (HPKE `info` + AEAD `aad`).** Both set to the canonical
CBOR encoding of:
`{ v:"hippius-kbs-1", ticket_id, vm_id, tenant_id, KBS_nonce, report_digest,
secret_ref, secret_type ("luks"|"user-data"), allowed_userdata_digest }`.
A blob wrapped for one (ticket, VM, nonce, secret) **cannot** be unwrapped in
any other context — closes drop/reorder/replay/swap by a hostile
Guardian/Edge/miner. The initramfs agent MUST reconstruct the same context and
let HPKE/AEAD fail closed on mismatch.

**`allowed_userdata_digest`.** `SHA-256` over the canonical CBOR map (fixed
key order):
`{ v:"hippius-ud-1", tenant_id, vm_id, ticket_id, secret_type:"user-data",
vault_path, vault_version, userdata }` where `userdata` is the raw cloud-init
plaintext bytes. L1 computes it and puts it in the signed OrderTicket; the KBS
recomputes from the Vault-fetched value + ticket fields and compares
constant-time. Hashing both content and binding fields means neither the
cloud-init nor its context can be swapped.

**cloud-init datasource allow/deny (baked into the measured image).**
`datasource_list: [ NoCloud, None ]` only. Explicitly disabled: ConfigDrive,
OVF, SMBIOS/`seedfrom`, block-device probing, EC2/GCE/Azure network metadata,
any network datasource. The NoCloud seed is read **only** from the fixed
initramfs-populated tmpfs path, and is consumed **before** any writable
miner-backed block device is mounted.

**No-persistence / zeroization (measured-image discipline).** Seed lives only
on tmpfs, never a miner-backed device. No initramfs/cloud-init logging of seed
contents; serial console must not echo it; kdump/crashdump disabled; no
emergency/debug shell in the production initramfs; cloud-init instance cache
not written to a miner-backed disk pre-LUKS. The unwrapped buffer and the
tmpfs seed are explicitly memzeroed and the tmpfs unmounted after cloud-init
consumes it; "zeroized" must be demonstrable (no copies).

## 21. End-to-end flow (boot → attest → release → switch_root)

The single source of truth for the runtime sequence. Ties §6/§7/§19/§20
together. **Key rule: verify the attestation, THEN wrap to the key bound
*inside* the verified report — never to a key supplied loosely alongside it.**

1. **L1 (client app)** mints the **signed OrderTicket** (§6) — tenant/VM ids,
   expiry, single-use nonce, allowed image measurement(s), allowed Vault
   secret refs, `allowed_userdata_digest` (§20). It builds the cloud-init
   (incl. the NetBird one-off enrol key), and **seals it at rest in Vault**
   under the VM's per-VM path. L1 signs the ticket with its OrderTicket key.
   *(At this point the VM doesn't exist yet — there is no enclave key to
   encrypt to. Vault at-rest is layer 1.)*
2. **vali Django** receives the ticket and schedules the build/boot. The
   **Packer factory (vali side) builds the measured base image** (if not
   already cached) and **uploads the qcow2 to S3** (object store). vali
   transports the ticket **opaquely** — it cannot read/choose security
   inputs.
3. **Image distribution — presigned, no miner S3 creds.** vali Django issues
   a **short-TTL presigned S3 GET URL scoped to the exact `version_id`** of
   the content-addressed (SHA-256) image object (§11) over the control/Edge
   path. The miner holds **no blanket S3 credentials**. A presigned URL is
   **not individually revocable** — security does **not** depend on its
   secrecy (step 4); to pull a poisoned object the primitive is delete/deny
   that object-version (§11), never URL secrecy.
4. **Miner hypervisor** downloads the qcow2, **verifies the SHA-256 against
   the signed provenance mapping** (§11), and boots the **measured UKI**
   (kernel+cmdline+initramfs). **Transport integrity is irrelevant to
   security — and "measures outside the allowlist" is NOT the reason** (the
   SNP launch measurement covers the UKI, not the rootfs). The reason: the
   rootfs is **read-only dm-verity whose root hash is embedded in the
   measured UKI**; the initramfs activates verity and **fails closed before
   `switch_root`** on any mismatch, so SNP attestation transitively covers
   the **whole rootfs** (a measured-but-poisoned image is impossible). The
   initramfs mounts **only** the verity rootfs + the named LUKS volume and
   **rejects** extra partitions / qcow2 backing-files / overlays. The base
   qcow2 is genuinely **non-secret** (the per-VM LUKS volume is encrypted at
   *sealing*, only *unlocked* post-attestation, §8/§19), so a leaked/replayed
   URL exposes only a public, tamper-evident base image. Bad / expired /
   revoked URL or checksum miss → discard + vali reissues a fresh
   `version_id` URL (bounded retries; cache namespaced by SHA-256; repeated
   bad fetch → §13 quarantine).
5. **Inside the SEV-SNP guest**, the measured initramfs agent generates a
   fresh **X25519 ephemeral keypair** (§20). Private key stays in guest RAM
   (mlock'd). It obtains a fresh single-use **KBS nonce**.
6. The agent requests an **SNP attestation report** with
   `REPORT_DATA = KBS_nonce(32) ‖ guest_pubkey(32)` (§20 exact layout).
7. Report (+ ticket reference) travels guest → **Guardian** → **Edge GW**
   (NetBird mesh side) → relayed opaquely over the **private network** → **KBS** (Rust
   core). Edge GW never decrypts; it's an app relay, not an IP router (§5).
8. **KBS verifies, in order, fail-closed on any miss (§7):** AMD cert chain +
   TCB ≥ policy; nonce fresh + single-use; measurement ∈ ticket's allowed set
   ∈ offline KBS allowlist; SNP launch policy in bounds; ticket signature +
   expiry + single-use; ticket/tenant/VM/secret_ref all consistent;
   anti-replay record not seen. **The guest pubkey is taken from the verified
   `REPORT_DATA` only** — any request-supplied pubkey must byte-equal it
   (constant-time) or deny.
9. Inside one **atomic release transaction** (§7): KBS reads the per-VM
   secrets from **Vault** at the signed `vault_path@vault_version` (LUKS key
   **and** sealed cloud-init), recomputes `allowed_userdata_digest` and
   constant-time compares to the ticket, **HPKE-wraps each to the attested
   guest pubkey** (§20 context binding), **signs the response struct**
   (§20), then **durably commits the single-use release BEFORE any response
   byte leaves the KBS process** (at-most-once emission). A crash after
   commit but before delivery ⇒ the ticket/nonce are spent and the secret is
   *not* re-released; recovery = mint a new ticket (§14). Plaintext exists
   only briefly in KBS RAM, then `zeroize`.
10. Signed+wrapped response relayed back KBS → Edge GW → Guardian → guest,
    **RAM-to-RAM, opaque** (relays see only a signed ciphertext bound to a
    context + KBS signature they cannot forge).
11. **Guest verifies the KBS response signature** against the pinned KBS key
    (abort boot on mismatch), **then unwraps** with its ephemeral private
    key; HPKE/AEAD also **fails closed** on context mismatch → blocks
    forge / drop / reorder / replay / swap by a hostile Guardian/Edge/miner.
12. Guest **recomputes `allowed_userdata_digest` and checks it against the
    digest carried in the KBS-signed response** (§19/§20; the guest has **no
    L1 ticket key**, §6 — it cannot and must not compare to the ticket),
    uses the LUKS key to **unlock the per-VM confidential volume** (the
    read-only rootfs is already verity-verified, §11 — not LUKS),
    materialises the cloud-init as a **NoCloud datasource on tmpfs**
    (datasource list hard-pinned to `[NoCloud,None]`, §20), consumed
    **before** any writable miner-backed disk is mounted.
13. **`switch_root`** into the OS; cloud-init provisions (NetBird join, SSH,
    tenant config); the tmpfs seed + unwrapped buffers are **memzeroed**, the
    tmpfs unmounted. Nothing decrypted ever touches miner-readable storage.

If verification (step 8) fails, the KBS emits a **signed denial** + audit
record (§15); no secret is wrapped. vali/Edge/Django only ever see
success/failure.

### 21.5 Host→guest OrderTicket delivery — AF_VSOCK push (Phase A wire-up)

Step 5 above ("Inside the SEV-SNP guest, the measured initramfs
agent…") presupposes the agent already **has** the L1-minted COSE
OrderTicket — every downstream check (§7 KBS verify, §6 binding,
§20 release-context) is reconstructed from fields the agent reads
out of that ticket. This sub-section pins HOW the COSE bytes reach
the agent.

**Rule: per-launch tenant data may never ride a §22-measured surface.**
The kernel cmdline and any QEMU `-fw_cfg` blob both fold into the
AMD-SP `snp_launch_digest`. Per-launch ticket bytes there would
explode the §22 allowlist (one entry per launch — operationally
untenable at marketplace scale). The ticket therefore flows through
a **runtime, measurement-neutral channel**: AF_VSOCK push from the
host (miner-agent) to the guest (initramfs agent).

**Channel.** AF_VSOCK; host CID `2` (ABI-reserved); guest CID
assigned by `binaries/miner-agent/src/vsock/peer.rs::CidAllocator`
at launch and pinned in the libvirt `<vsock>` device. Port:
`hippius_types::ticket_vsock::PORT` (`0x4849` — "HI"); shared
constant so producer and consumer cannot drift. Direction: host
→ guest (opposite the existing guest→host §H relay on
`VSOCK_RELAY_PORT`).

**Wire format.** One message per connection; the host closes after
writing, the guest closes after reading.

```
   ┌──────────┬─────────────────────────────────┐
   │ u32 BE   │ raw COSE_Sign1 bytes            │
   │ length   │ (canonical CBOR, L1 signature)  │
   └──────────┴─────────────────────────────────┘
   length ≤ ticket_vsock::MAX_TICKET_BYTES (8 KiB);
   length == 0 rejected before any body alloc.
```

The endian + the size-cap-before-allocation discipline mirror the
existing relay framing (`binaries/miner-agent/src/vsock/frame.rs`)
so reviewers can recognise the pattern by sight.

**Provenance.** The COSE bytes flow byte-identical across every
layer: L1 mint → vali `OrderTicketIntake.cose_blob` → vali
`build_launch_payload(cose_ticket=…)` (base64 on the JSON wire) →
Edge re-signs the whole `OrderBody` → miner-agent decodes
`LaunchOrder.cose_ticket: ByteBuf` → after `lifecycle.launch` Ok,
`vsock::ticket_push::push_ticket(cid, PORT, &cose)` → guest reads.
Edge's re-sign is the existing `OrderBody` Ed25519 — no new
signature key, no new wire-protocol revision; only a field-set
extension of the launch payload.

**Boot race.** The miner-agent's `lifecycle.launch` returns Ok
when libvirt reports `Running`; the guest's `/init` then needs
~1–3 s for kernel boot + initramfs mount + vsock listener
prep. The push retries `connect(2)` on `ECONNREFUSED` for
`ticket_vsock::PUSH_TIMEOUT_SECS` (30 s) before failing
closed with `MinerAgentError::TicketDelivery("connect-timeout")`.
Symmetrically the guest accepts within
`ticket_vsock::ACCEPT_TIMEOUT_SECS`. Both classes are static
`&'static str` per the §20 logging discipline.

**Source-CID pinning.** The receiver
(`binaries/agent-initramfs/src/stages/ticket_vsock.rs`)
validates the accepted peer's CID equals `2` (host) — belt-and-
braces, even though the host's vsock routing already makes
cross-tenant CID spoofing infeasible.

**Failure surfaces.** A push failure surfaces to the miner-agent
HTTP intake as a dedicated `OrderRejection` class
`ticket-delivery-failed` (HTTP 500) — distinct from the
catch-all `dispatch-failed` so an operator can wire a targeted
alert. Sub-class strings (`empty` / `oversize` / `no-cid` /
`connect-timeout` / `write-failed`) hit the `dispatch-failed-detail`
log line introduced by PR #164 (`MinerAgentError::Display` is
itself the static classifier).

**Why not a measured surface (cmdline / fw_cfg).** See the lead
rule. Per-launch ticket data in either would multiply §22 allowlist
entries by the active-tenant count — a category of operational
burden that grows with tenants and cannot be sharded away.

**Why not a pre-staged file on the miner.** Decouples ticket from
dispatch (audit hole: operator could pre-stage ticket A and vali
could dispatch with ticket B with no structural detection), adds an
operator-side step that doesn't survive the Phase B/C
marketplace-driven mint flow (hippius-backend POST → vali → miner
is self-contained; there's no operator in the loop to pre-stage).

## 22. Allowlist artifact security contract (pinned) — Critical, spec-first

§6/§7/§11 make the **offline allowlist artifact** the KBS trust root
(approved measurements → `{accepted_l1_ticket_kids,
accepted_kbs_response_kids}`, + the KBS response private keys' kid set it may
sign with). Its own integrity is therefore Tier-0 and must be pinned:

- **Signed, with an offline root.** The artifact is signed by an **offline
  allowlist root key (Ed25519)** held air-gapped/HSM, entirely separate from
  the L1 ticket key and the KBS response key. The KBS has the **root public
  key compiled into its binary** (not loaded from disk/config/network) — the
  one anchor that is not itself in the artifact.
- **Deterministic format + schema.** Same deterministic-CBOR reject profile
  as §20; explicit schema `v`; unknown fields ⇒ reject.
- **Monotonic epoch + rollback protection on tamper-proof storage.** The
  artifact carries a strictly monotonic `epoch`; the KBS **refuses any
  artifact with epoch ≤ the high-water mark**. Critically, that high-water
  mark **must NOT live on the non-confidential vali node's local FS** (an
  attacker who breached the node — §8 — would just revert it and replay an
  older validly-signed artifact, re-authorizing revoked keys/measurements).
  It is stored in a **tamper-proof external store the node attacker cannot
  roll back**: a dedicated Tier-0 Vault path that the KBS can monotonically
  advance (compare-and-set / check-and-set) but not decrement. On every
  validate the KBS reads the authoritative epoch from there, not local disk.
- **Atomic install + validate-before-use.** New artifact is verified
  (root signature + schema + epoch) into a staging slot and **atomically
  swapped**; a partial/invalid artifact never becomes active. The KBS
  **re-validates at every startup and before every release** and **fails
  closed** (no releases) if no valid artifact is loaded — never falls back to
  a previous in-memory copy on validation failure.
- **Revoke propagation.** Emergency revoke = publish a new artifact (higher
  epoch) dropping the measurement/kid; revocation takes effect on the next
  validate (startup or pre-release). Revoke latency = the pre-release
  re-validate interval, which MUST be bounded (config, not "eventually").
- **No online dependency.** Delivered out-of-band (same channel as §11
  measurements); the KBS never fetches it from vali/Edge/L1/the request.

Non-blocking (build-phase / runbook, explicitly NOT architecture): the
rotation overlap/staging choreography (ship new image+keys before the
allowlist that requires them), the fail-safe suspension override/escalation
path (§13), and the executable §14 recovery runbook.

## 23. Miner inventory, attested health & trustless scheduling — Critical

The "our vSphere" plane. Core principle (like §8): **a hostile miner's
self-reported capacity/health is adversarial** (lie to attract VMs/rewards
without delivering). Schedulability is **never** derived from self-report —
only from verifiable signals. Self-report is at most an untrusted *hint*,
capped by proven capacity.

### Family model + identity/credential separation
A **miner = a "family"** running **N nodes** (hypervisors).

- **Family / owner identity = unified, ONE per operator.** A single
  `AccountId`/SS58 is the family across storage(Arion), compute and
  NetBird, for **stake / score / slashing / billing**. Same identity as
  the `NetbirdOperator` (PR4) and the arion-pallet `family` AccountId — do
  NOT create parallel *owner* identities.
- **Per-node device keys = DISTINCT per subsystem. No credential reuse.**
  Arion's `node_id` is an **ed25519 Iroh/quinn** key (storage transport);
  the compute node gets its **own, separate ed25519 keypair**; the NetBird
  peer has its **own** key. A leak of one device key must not let an
  attacker spoof the node in the other two subsystems.
- The compute scoring pallet therefore **copies pallet-arion's
  family/child *structure*** but with its **own domain separator**
  (`HIPPIUS_COMPUTE_NODE_REG_V1`, never `ARION_NODE_REG_V1`) so a
  registration signature from one pallet **cannot** be replayed into the
  other, and its **own compute `node_id`** registered under the shared
  family AccountId.
- **Graduated, not blunt, slashing.** A single compromised child key must
  NOT instantly nuke an honest 1000-node family. Escalation:
  per-node **strike → quarantine** (drain, §13) first; **family-level
  slash only on thresholds / evidence-class** (sustained, multi-node, or
  proven fraud), with a **bounded max slash**, an **appeal/dispute
  window**, an operator **key-rotation path** for a single compromised
  node, and **tenant migration** off the affected node before any slash.
  Capacity and placement remain per node.
- The family **signs the binding** {family, compute `node_id`,
  `platform_id`, `audit_vm_key_id`, NetBird peer id, control endpoint};
  the registration payload binds **chain genesis + pallet instance +
  key-type/version**, not just the domain separator (no replay across
  forks/deployments). **Split of record:** the pallet stores only the
  on-chain-relevant fields (`node_id`, `platform_id`, `audit_vm_key_id`,
  family — see schema below); the **NetBird peer id + control endpoint
  live in a signed, audited off-chain vali registry object** (consistent
  with the v1 "placement = off-chain operator log" decision), keyed by
  `node_id` and covered by the same signed binding so the two halves
  cannot be recombined.

### Trust posture — v1 = deliberate single-operator centralization
**Conscious business decision, stated honestly (not disguised as
trustless).** The review models correctly called the single-validator
model "a centralized oracle with spectators". We **accept that for
launch**, because the proposed fix (let *other* validators slash /
arbitrate) is **worse**: other validators are **equally untrusted and
self-interested** — they would score/whitewash their own miners. Handing
enforcement to untrusted parties beats no decentralization. *We run the
business; for v1 we are the trusted operator.*

- **One operator-run authoritative validator (us), trusted by fiat.** It
  computes a **deterministic `S = f(inputs)`** (CRUSH/Arion-style; v1
  simple, v2 CRUSH-grade) and pushes scores/weights on-chain.
- **Other validators = strictly read-only auditors. ZERO power** — no
  slashing, no arbitration, no fault-proof, no fallback authority
  (precisely because they cannot be trusted not to self-deal). They may
  recompute `f` over the published inputs purely for **transparency** and
  to keep a **v2 migration path** open.
- **Slashing/quarantine is performed by the authoritative validator
  (us)** — see Scheduler/graduated-slashing below. It is an operator
  action, not a multi-party game.
- **Accepted residual (v1, like §8):** the operator can in principle
  withhold/poison/censor inputs ("theatre"). Mitigated only by our own
  business incentive + **publicly logged deterministic inputs** (anyone
  can recompute and call us out reputationally) — **not** cryptographically
  enforced. **Decentralized fault-proof / multi-party arbitration is an
  explicit v2+ NON-GOAL**, deferred until there is a trusted-enough
  validator set.
- **Determinism still mandatory** (enables the transparency above + the
  v2 path): `f` uses **fixed-point only (no floats)**, **sorted/BTreeMap**
  iteration, canonical SCALE; `map_root` covers the **full canonical
  epoch input object** (proofs, attested deltas, strikes, liveness,
  transcripts); every `submit_*` vector is **bounded** with block-weight
  limits (unbounded aggregate = chain-halt vector).

### The Audit VM — per-node validator trust anchor (the "blackbox")
The **single consolidated trust anchor on the untrusted miner**. Without
it, "trusted SEV-SNP VM reports from inside" is conflated with the
*tenant's* VM — which is wrong: a tenant CVM exists for the tenant's
confidentiality, and a node with **zero tenants** would then have no
attested presence at all. So the validator runs its own.

- **What it is.** A dedicated, **validator-owned, SEV-SNP-attested**
  confidential VM, **one per registered node**, **always-on**,
  independent of any tenant VM (the trust anchor exists even at zero
  tenants). It does **not** replace per-tenant attestation: the tenant VM
  still self-witnesses its own served-delivery (Reward model); the Audit
  VM is the **node-level prover + independent cross-check / co-signer**.
- **Reuse, don't reinvent.** Built & measured by the §11 Packer factory
  as a **measured UKI** (dm-verity rootfs, root hash in the signed UKI),
  in the **§22 offline allowlist**, attested via the **exact §7/§21
  contract**. Distinct keypair per the §23 identity rule (≠ compute
  `node_id` ≠ tenant-VM keys ≠ NetBird peer).
- **Platform-bound identity (closes 1-to-N proxy/clone — Critical).**
  SEV-SNP attests the *guest measurement*, **not** "this physical host";
  `{family, node_id, audit_vm_key}` + a nonce alone does **not** stop a
  miner running **one** Audit VM and proxying it for many `node_id`s. So:
  at node enrollment `node_id` is **bound to the SNP platform identity** —
  `CHIP_ID`/VCEK (or an operator-approved privacy-preserving digest of the
  AMD platform id) **+ a TCB/SVN floor**; the pallet enforces
  **`node_id ↔ platform_id` uniqueness**; the KBS/validator check **every**
  Audit-VM attestation and report against the *registered* `platform_id`,
  not just `node_id`.
- **Attested, KBS-certified agent key (not a self-asserted key).** The
  `audit_vm_key` (**Ed25519**) is generated **inside** the attested Audit
  VM and bound to the SNP report via the **distinct Audit-VM
  `REPORT_DATA` binding of §20** (`[32:64]=SHA-256(audit_vm_pubkey ‖
  "HIPPIUS_AUDIT_VM_V1" ‖ node_id ‖ platform_id)`; full pubkey delivered
  in the certified request — it does **not** reuse the tenant X25519
  layout). After the §7 checks the KBS issues an
  **Audit-VM certificate** over `{domain, chain_genesis, pallet_instance,
  family, node_id, platform_id, audit_vm_key, measurement, launch_policy,
  tcb, nonce, expiry}`; validators accept Audit-VM signals **only** under
  a valid, unexpired cert. The family binding is thus over an *attested*
  key, not an arbitrary one.
- **Full replay/fork domain on every signature.** Every Audit-VM
  signature (heartbeat, canary result, co-sign) carries `{domain,
  chain_genesis, pallet_instance, validator_id, family_id, node_id,
  audit_vm_key_id, epoch, nonce, expiry}` — same replay-domain rigor as
  §23 registration (not just `node_id+epoch+nonce`); blocks
  cross-fork/testnet/instance/redeploy/re-registration replay.
- **Responsibilities (consolidates the inputs to `f`):** runs
  **proof-of-capacity** *inside itself*; measures health/liveness from
  inside + signs liveness heartbeats; runs **canary workloads** (this
  *is* the previously-vague "canary VMs"); **cross-checks and co-signs**
  the canonical served-delivery aggregate (below).
- **Input trust classification (host can lie — never reward
  host-claimed).** Each input is tagged **guest-derived** (signed inside
  the Audit VM), **validator-probed**, **Audit-VM-measured**, or
  **host-claimed** (libvirt/cgroups/qemu/miner API). Only the first three
  may *increase* score; **host-claimed data may only decrease score,
  trigger audit, or corroborate signed tenant receipts — never raise
  reward/eligibility** (consistent with §23 "never trust self-report").
- **Host-binary IMA/TPM measurement (validator-probed, nonce-bound).**
  The miner host agent is a **reproducibly-built binary measured via the
  host TPM/IMA** (expected hash + PCR/IMA policy pinned). The Audit VM
  cross-checks a host **TPM quote that MUST carry a fresh validator
  nonce, a short expiry, and be bound to the registered
  `node_id/platform_id`** (else quote replay/proxy weakens it). This does
  **not** make the host trusted (it still "can lie" about scheduling/NUMA
  above) — it is a *validator-probed* signal that detects a *modified*
  host agent: a cheap, implementable corroborator (shippable — `hccs`
  already does host IMA/TPM). Stale / unbound / mismatched quote ⇒
  strike/audit; it may only **corroborate or decrease** — **never** raise
  trust/reward.
- **Always-on, bounded, tenant-safe.** Continuous on every registered
  node, **resource-capped** with **tenant-safe headroom accounting** — it
  must **never** starve tenant VMs. Its overhead is **unpaid miner cost**,
  consistent with the locked *idle = 0 reward* + commitment-economics
  decision: running the Audit VM is part of the node's **availability
  commitment**, not separately rewarded.
- **Anti-suspension / anti-throttle (quantitative — "fresh but slow" =
  degraded).** Beyond missing/stale (gag-order): the validator issues
  **randomized high-frequency challenges** (no fixed cadence), enforces a
  **response deadline from validator send-time** and **per-resource-class
  canary completion deadlines**, and the Audit VM reports **`RDTSC`/TSC
  vs wall-clock drift** so hypervisor suspend / CPU-steal is detectable
  from inside. **Late-but-present evidence scores degraded → worst-case**
  on threshold/percentile breach — defeats "rob tenants 55 s, wake the
  Audit VM 5 s for a predictable heartbeat". A missing / unattested /
  stale / proxy-suspected / platform-mismatched Audit VM ⇒ node
  **WORST-case ⇒ ineligible + §13 quarantine**.
- **Canonical co-sign payload (no receipt teleportation).** The Audit VM
  co-signs a canonical **`ServedDeliveryAggregate`** digest `{domain,
  chain_genesis, pallet_instance, validator_id, family_id, node_id,
  audit_vm_key_id, epoch, challenge_nonce, interval,
  map_root(per-receipt {vm_id, lease_id, monotonic_seq} digests),
  resource-class totals, prev_aggregate_hash, expiry}`, **real-time
  within the receipt TTL**. Reward only if **every** rewarded tenant
  receipt digest is inside the co-signed digest and within its nonce
  window — a valid co-sign cannot be mixed with receipts from another
  window/node/epoch.
- **Node lifecycle state machine (activation-gated; explicit, not
  "everything = quarantine").** States `RegisteredPendingAudit →
  AuditAttested → {GraceDegraded | Draining | Quarantined | Reattesting |
  Retired}`. **First successful Audit-VM attestation is the activation
  gate**: before it — **no placement, no eligibility score, no reward, no
  tenant scheduling** (a booting honest node isn't instantly
  self-quarantined; a node can't earn before it is provably anchored).
  Transitions have explicit miss-counts / wall-clock windows; slash waits
  for **repeated or fraud-class** evidence (graduated, §23). Crash /
  restart ⇒ `Reattesting` (fresh §7/§21). Carries **no tenant data by
  construction** ⇒ §24 crypto-erase N/A; quarantine/teardown reuse
  §13/§24.
- **Honest limits (it BOUNDS gaming, it is NOT proof of host honesty).**
  Even attested + platform-bound, an SEV-SNP guest **cannot** see the
  true host CPU scheduler, NUMA locality, sustained real bandwidth, or
  whether the hypervisor lies about isolation / over-subscription — SNP
  attests the *guest*, not fair host behaviour. The Audit VM **bounds
  miner gaming within tolerances**; full elimination needs host-level CC
  the miner does not provide. This is the **inherent miner-side
  live-host limit** (§8 — distinct from, and *not* the now-closed KBS
  host-breach residual), stated honestly — **not** a guarantee.

### Verifiable inputs to `f` (all sourced from the Audit VM; no self-report)
- **Proof-of-capacity (v1 = bounded, hardened in v2)** — runs **inside
  the Audit VM**. Honest framing: **not** an unforgeable proof.
  Mitigations pinned: **continuous, unpredictable randomized re-challenge**
  (no known window — defeats rent-for-the-window); **anti-sparse/dedup/
  compression** (incompressible challenge data, random-offset reads);
  **tenant-safe headroom accounting** (cannot be satisfied by stealing a
  running tenant's allocation); **cheap, bounded verification + admission
  control / PoW** (a cartel cannot DoS the single verifier). Residual
  (accepted, v2): SEV-SNP cannot prove sustained CPU/bandwidth/NUMA —
  those rely on the cross-check + history.
- **Attested cross-check + the gag-order rule.** The **Audit VM** reports
  guest-derived signals and **co-signs the canonical
  `ServedDeliveryAggregate`** (Audit VM above). The miner can
  DROP/proxy/throttle it, therefore **`f` treats a
  missing/unreachable/unattested/platform-mismatched *or late-but-present*
  Audit-VM signal as the WORST case — ≥ the "throttled" penalty.**
  Dropping or slowing the cable is never advantageous; "node silent or
  slow" ≥ "node reports degraded".
- **Audit outcomes & liveness:** Audit-VM canaries + signed liveness +
  validator probes over the `validator↔miner` control path +
  delivered-vs-promised history — all committed as evidence (above).

### On-chain — mirror `pallet-arion` (proven pattern, do NOT reinvent)
The compute scoring pallet is a **mirror of `thenervelab/thebrain`
`pallets/arion-pallet`** (which already does exactly this for storage):
- **Per-epoch deterministic input map + `map_root`** = hash of the
  canonical SCALE encoding of the **full `EpochInput` object** (params +
  per-node records + PoC results + liveness + audit + strikes + served
  aggregates + transcripts) — **not** just the miner list. Auditors
  recompute `f` from that object and verify `map_root` — this *is* §23's
  "determinism + published inputs, no consensus". (Single canonical
  definition; used identically by the f-spec and the pallet below.)
- **Family/child registration primitives, structure copied (NOT the
  keys)**: same shape — ed25519 `node_id` + signature, payload
  `("HIPPIUS_COMPUTE_NODE_REG_V1", family, child, node_id, nonce)` with
  **its own domain separator** (never `ARION_NODE_REG_V1`) and a
  **compute-specific node keypair** distinct from the Arion Iroh/quinn key
  and the NetBird peer key; per-node_id nonce (anti-replay); **anti-Sybil
  adaptive deposit** (first child free/family, doubles per paid reg, halves
  on inactivity); **anti-yoyo** deregister→unbonding+cooldown→
  `claim_unbonded`; Config hooks deny-by-default.
- **Periodic aggregate submission** à la `submit_miner_stats(bucket,
  updates, network_totals)` for the compute signals (proof-of-capacity
  results, attested-crosscheck deltas, audit/strike counts, last_seen).
- **Two distinct on-chain quantities** (Bittensor-style weights — do NOT
  conflate): an **eligibility score** computed for **every** registered
  miner (gates *whether / where* the scheduler may place) and a **reward
  weight** driven by **attested served delivery** (drives the emission
  split). Idle proven capacity has a non-zero eligibility score but
  **zero reward weight** (see Reward model).
**Identity rule:** unify the **owner/family** (one `AccountId`/SS58 =
arion `family` = compute family = `NetbirdOperator`, PR4) for
stake/score/slash/billing — but **per-node device keys stay distinct per
subsystem** (Arion Iroh/quinn ed25519 ≠ compute node ed25519 ≠ NetBird
peer key). Unify the *owner*, never the *device credentials*.

### v1 scoring function `f` + pallet schema (concrete — closes the last design-open)
**v1 = simple & deterministic; v2 = CRUSH-grade (future, not a v1
blocker).** All arithmetic is **`u128` fixed-point (scale `1e9`), NO
floats**; all iteration over **`BTreeMap`/sorted keys**; canonical
**SCALE** encoding; the **whole** per-epoch input object (PoC results,
liveness, audit, strikes, served aggregates, params) is hashed into
**`map_root`** so any auditor recomputes `f` and verifies the root (§23
determinism; single authoritative submitter).

Two outputs per node per epoch:
- **Eligibility `E(n) ∈ [0,1e9]`** — gates scheduling/admission, **not
  paid**: `E = attested_gate · clamp( w_cap·cap_norm +
  w_live·liveness_ratio + w_audit·audit_pass_ratio − strike_penalty )`.
  `attested_gate ∈ {0,1}` is **0 unless** the node is `AuditAttested` +
  platform-bound (§23 Audit VM) — not attested ⇒ `E=0`. `cap_norm` =
  proven capacity from the **bounded proof-of-capacity** result (never
  self-report); `liveness_ratio` = fresh/in-deadline Audit-VM challenge
  fraction (late-but-present already degraded, §23); `strike_penalty`
  graduated. Idle-but-attested ⇒ `E>0, W=0`.
- **Reward weight `W(n) ≥ 0`** — drives the pot-`X` split (Reward model):
  `W = Σ_intervals resource_class_weight · delivered_fraction ·
  duration`, over **only** unique/fresh/lease-bound receipts inside a
  **co-signed `ServedDeliveryAggregate`** for a **billable third-party
  lease** (`tenant ≠ family` else the interval = 0);
  missing/late/unattested ⇒ gag-order worst-case (0). Split:
  `payout(n) = X · W(n) / Σ_m W(m)`; `W=0 ⇒ no pay`.

**Deterministic arithmetic (pinned — no ambiguity).** All ops are
**checked/saturating `u128`**, fixed scale `1e9`; multiply-then-divide via
**`mul_div_floor`** (floor rounding, single canonical order: scale-up →
sum → divide last); per-term caps on `resource_class_weight`,
`delivered_fraction ≤ 1e9`, `duration ≤ epoch_len`, and `Σ`-bounds so no
intermediate overflows; **`Σ_m W(m) = 0 ⇒ no payout this epoch, the pot
`X` carries forward** (never divide-by-zero, never burn). Identical
arithmetic on-chain and in any auditor recompute.

**Pallet schema (mirror `pallet-arion`; compute domain separator; only
the authoritative validator submits):**
- **Storage:** `Params{weights, deposits, thresholds, epoch_len}`
  (operator/governance-set); `Families: AccountId → {deposit,
  child_count}`; `Nodes: node_id → {family, platform_id,
  audit_vm_key_id, state, strikes, last_seen_epoch}`; `NodeIdNonce:
  node_id → u64`; `EpochInput: epoch →
  BoundedVec<NodeEpochRecord, MaxNodesPerEpoch>` (canonical, sorted by
  `node_id`); `EpochMapRoot: epoch → H256`; `Eligibility/Weights:
  (epoch,node_id) → u128`; `Unbonding` queue. **`NodeEpochRecord` =
  `{node_id, family, platform_id, audit_vm_key_id, poc_result{cap,
  proof_digest}, liveness{answered, deadline_misses}, audit{pass, fail},
  strikes, served_root (map_root of co-signed ServedDeliveryAggregate
  digests), last_seen_epoch, src_tags}`**; `NodeStatUpdate` = the signed
  validator-submitted delta producing it (same fields + submitter sig +
  transcript hashes). All fields fixed-width, canonically ordered, so any
  auditor recomputes `map_root`/`f` byte-identically.
- **Extrinsics:** `register_family`; `register_child(node_id,
  platform_id, sig)` — `sig` over `("HIPPIUS_COMPUTE_NODE_REG_V1",
  chain_genesis, pallet_instance, family, child, node_id, platform_id,
  NodeIdNonce)` (own separator, **never** `ARION_NODE_REG_V1`; distinct
  compute keypair; `node_id↔platform_id` **uniqueness enforced**, §23
  anti-proxy); `deregister_child`→unbonding+cooldown; `claim_unbonded`;
  `submit_audit_stats(epoch, BoundedVec<NodeStatUpdate>)` — **only the
  authoritative validator** (deny-by-default Config origin), bounded by
  block weight (unbounded = chain-halt vector); `set_params`.
- **Hooks (no chain-halt vector):** epoch close does **not** run `f`
  over the whole fleet in one `on_finalize`. A hard
  **`MaxNodesPerEpoch`** is derived from block weight, and `f` is
  computed by **paged, bounded per-block accumulation** (`on_idle`/
  multi-block finalization with a fixed per-block work budget); the
  epoch is only `EpochClosed` once the final page commits
  `Eligibility`/`Weights` + `EpochMapRoot`. No floats; every loop
  bounded.
- **Events:** `ChildRegistered`, `ChildDeregistered`, `StatsSubmitted`,
  `EpochClosed{epoch,map_root}`, `WeightsSet`, `Quarantined`, `Slashed`,
  `MigrationCommitted` (§25).
- **Anti-Sybil / anti-yoyo (copied from arion):** first child free per
  family; **global deposit doubles per paid reg up to a hard
  `MaxDeposit` cap (saturating, no overflow)**, halves once per defined
  inactivity period (exact epoch rule in `Params`); deregister →
  unbonding + cooldown, deposit reserved until `claim_unbonded`.
- **Graduated slashing (operator-driven, §23):** strike thresholds →
  per-node **quarantine** (state machine §23/§24) → **family slash**
  only on sustained / multi-node / fraud-class evidence, **bounded max**,
  **appeal window**, single-node **key-rotation** path, tenant
  **migration off** (§25) before any slash.

### Reward model — pay for served delivery, not idle capacity
Tenant-side billing / metering / pricing / payment is **owned by the
client-facing `hippius-backend` (L1) and is explicitly out of scope here**
(§3). This subsection is only the **miner-payout** side; the end-of-life
*trigger* it reacts to also originates from L1 (§24).

- **A global emission pot `X` per epoch is split pro-rata across miners by
  *attested served-VM weight*** — the share of real tenant VMs a node is
  *actually running and delivering*, witnessed from inside the tenant's
  **SEV-SNP guest**, under the **gag-order rule** (silence ≥ "degraded" ⇒
  no credit) plus delivered-vs-promised history. Never from self-report,
  never from raw/claimed capacity.
- **Empty / idle proven capacity earns ZERO.** Proof-of-capacity buys
  **scheduling eligibility only**, never reward: you are paid for
  *serving*, not for being *able* to serve. Kills capacity-farming.
- **Anti-self-dealing — only a billable, third-party lease counts.** A
  served VM contributes reward **only if** it is an **L1-signed billable
  active lease** whose payer/tenant identity **≠ the serving miner's
  `family_id`** (nor a known affiliate). The validator cross-references the
  signed OrderTicket's tenant/lease id against on-chain registered families
  *before* computing reward weight; self-/affiliate-served VMs yield
  **zero reward** (still fine for eligibility). The receipt below binds to
  the L1 **`lease_id`**. *(Pricing/settlement stays in `hippius-backend`,
  §3 — only the `lease_id` + tenant≠family binding is in scope.)* Residual:
  fully external collusion (paying a third party to pose as tenant) is
  **bounded, not eliminated** — within the §23 miner-side accepted residual.
- **`ServedDeliveryReceipt` — makes "served" unforgeable, not just
  un-hideable.** A per-VM **telemetry agent key is established inside the
  measured guest under the §7/§21 attested release** (same contract, its
  own ref). The guest signs periodic receipts over `{validator
  nonce/challenge, epoch, vm_id, lease_id, family_id, compute node_id,
  resource_class, monotonic_seq, observed_degradation, expiry}`. The
  validator **rejects stale / replayed / proxied / mismatched** receipts;
  any invalid/missing ⇒ gag-order worst-case (no credit). Reward aggregates
  **only unique, fresh, active-lease intervals**. (The gag-order alone only
  covered *silence*; the signed fresh receipt closes positive-forgery.)
  The per-node **Audit VM independently cross-checks and co-signs the
  canonical `ServedDeliveryAggregate`** (§23 Audit VM) in **real time
  within the receipt TTL**, anchored to the platform-bound attested
  blackbox; reward counts a receipt only if its digest is inside that
  co-signed aggregate and within its nonce window — so a tenant-VM receipt
  cannot be proxied, cloned, replayed, or "teleported" to another
  node/epoch.
- **Eligibility ≠ reward, deliberately.** *Every* registered miner is
  still scored for eligibility (proof-of-capacity + liveness + audit) even
  at zero reward, so the scheduler can place onto idle nodes; reward
  begins when, and scales with, attested delivery.
- **Cold-start = accepted economic tradeoff (no idle pay).** Per the
  deliberate pay-for-served rule, idle stays unpaid; rational miners might
  power down in low demand and thin the warm pool. We do **not** add an
  idle payout (that would reverse the locked decision). Mitigated *without*
  paying idle: **commitment economics** — minimum availability windows,
  opt-in capacity commitments, deregistration cooldown (reg anti-yoyo),
  missed-placement penalties; the scheduler plans on **committed eligible**
  capacity only. Honestly documented as a known v1 tradeoff of
  pay-for-served, not a bug.
- **`f` is concretely specified** in "### v1 scoring function `f` +
  pallet schema" above (`W`/`E`, deterministic arithmetic, pallet
  storage/extrinsics/hooks): `reward_weight ∝ attested_served_delivery`
  over **billable third-party leases**, `idle_capacity_reward = 0`,
  eligibility decoupled from reward, receipts unique/fresh/lease-bound.
  Only v2 CRUSH-grade refinement remains future work.

### Scheduler (in vali Django, non-Tier-0)
Consumes **proven capacity + the on-chain *eligibility score*** (NOT the
reward weight — a zero-reward node is still fully schedulable, see Reward
model), never raw self-report.
Admission control **bounded by proven capacity** (no overcommit beyond
proof); bin-packing; **anti-affinity across families** (don't concentrate
a tenant on one family/node); continuous re-evaluation; a node/family that
fails proofs/audit or degrades is **drained + §13-quarantined + slashed**.
Lives in vali Django because telemetry is untrusted-by-design and never
touches Tier-0 secrets (consistent with §4). **Authority under reorg /
stale epoch / missing submission:** the **on-chain weight/eligibility is
authoritative for *whether* a node may be scheduled**; vali only chooses
*placement among eligible* nodes. On a stale/missing epoch the scheduler
**fails closed** (treat as ineligible, don't place) rather than trusting a
stale score.

### Honest residual
Two stacked, consciously accepted v1 residuals: (1) **miner-side** —
self-report is never trusted but proofs/cross-check/score only *bound*,
not eliminate, gaming within tolerances (v2 hardens `f` + proof strength);
(2) **operator-side** — the single authoritative validator is trusted by
fiat and could itself misbehave, mitigated only by business incentive +
public deterministic logs, decentralized enforcement = v2 non-goal (Trust
posture above). Both are deliberate, not oversights.

**Decided (v1):** VM→node placement is an **off-chain operator log** (not
committed on-chain). Slashing is **operator-driven** off the periodic
deterministic score — no on-chain placement commit or fault-proof is
needed until the v2 decentralization milestone.

## 24. VM end-of-life — decommission & crypto-erase — Critical

The dual of §21. A VM dies (tenant cancel, lease expiry, non-payment,
explicit destroy). On an **untrusted miner host** a "please delete the
VM" command is not a data-destruction guarantee — the miner can ignore it
and keep the disk. The guarantee must be **cryptographic**, not
cooperative.

- **Trigger originates at L1, not us.** Cancellation / expiry / billing /
  non-payment all live in the client-facing `hippius-backend` (L1),
  **out of scope here** (§3/§23). L1 signals "VM `vm_id` is end-of-life"
  over the existing control path; **vali Django orchestrates** the
  teardown. We never decide *why*, only execute *how*.
- **Unified KBS VM lifecycle state model (single source of truth for §7,
  §24, §25 — they compose, no separate machines).** The KBS release DB
  holds **one** durable per-`vm_id` state:
  `Active{gen, host, lease_id} | Migrating{old_gen, new_gen, source,
  dest, phase, idem_key} | Decommissioning | Destroyed{gen}`. **Every**
  release (§7/§21) **serializably checks this state both before the Vault
  read and again before the at-most-once commit**, and binds the ticket's
  `lease_id`+`vm_generation`+intended `node_id/platform_id` to it (§6/§7),
  else deny. Transitions are atomic CAS:
  - Decommission (§24): `Active → Decommissioning` (before any Vault
    read/destroy) → KEK destroy → `Destroyed{gen}` (**permanent
    tombstone**).
  - Migration (§25): `Active{gen} → Migrating{…}` → on commit
    `Active{gen+1, dest}` (source fenced); abort → back to
    `Active{gen, source}` **only while `phase < new_gen_released`**
    (forward-only after that).
  Per-ticket spent-marking is **insufficient** (§14 legitimately mints
  *fresh* tickets for the same `luks_vault_ref` on reboot); the KBS
  denies *any* release whose `vm_id` is `Decommissioning|Destroyed`, or
  whose `vm_generation` ≠ the state's current `gen`, or whose intended
  `node_id/platform_id` ≠ the state's bound host — independent of
  `(ticket_id, nonce)`. **L1 stops minting tickets for a `vm_id` once it
  leaves `Active` (EOL or migration).**
- **Crypto-erase via an erasable KEK (real destruction, incl.
  backups/DR).** This is the **single deliberate exception** to §8's "LUKS
  material is NEVER destroyed while the VM lives" — at EOL the VM no longer
  lives, so destruction *is* the goal. The per-VM LUKS material is
  **envelope-encrypted under a per-VM(/epoch) KEK**; crypto-erase =
  **destroy the KEK**. A bare KV
  version-destroy is **not** a guarantee while the value can survive in
  Raft snapshots / storage backups / DR replicas / audit. Contract: KBS &
  Vault **never log secret values**; snapshots/backups are encrypted under
  **erasable keys with bounded retention** (or exclude per-VM KEK
  material); destroy must **cover replicas/DR**; restore must **not**
  resurrect a `destroyed` generation. The KEK only ever existed in Vault +
  briefly in **attested guest RAM** (zeroized, §21), never on
  miner-readable storage — so data death does **not** depend on miner
  cooperation, *and* is not silently undone by a backup restore.
- **Precise guarantee (honest — corrects an earlier overclaim).**
  Crypto-erase guarantees **no future release / reboot unlock** once the
  guest is shut down. It does **not** instantly blind a *still-running*
  hostile guest: after unlock the dm-crypt key is resident in guest RAM
  for the VM's run (the **inherent miner-side live-host limit**, §8 —
  *not* the now-closed KBS host-breach residual, and *not* fixable by the
  CVM KBS: it concerns miner hosts we do not own). So EOL adds an
  **authenticated guest EOL path**: the measured guest agent receives a
  **signed shutdown/zeroize command**, tears down dm-crypt, and powers
  off. A miner that refuses ⇒ classified as a **live-VM residual + §13
  quarantine**, *explicitly not* "completed data death" — honest, bounded
  by that inherent miner-side limit (full fix would need confidential
  *miner* hosts, outside our control).
- **Graceful teardown is best-effort (capacity, not data).** vali instructs
  the miner to stop + delete the VM, free CPU/RAM/disk; **NetBird peer +
  one-off enrol key revoked** (§12). Cooperative path — **NOT trusted** for
  data destruction (the KEK destroy + state machine settled that).
- **Capacity reclaim + on-chain.** The node's **served-set loses this VM**
  → **reward weight drops** (§23: paid for served), while the node
  **remains fully scored / eligible** (eligibility ≠ reward). Headroom
  returns to the schedulable pool. Append-only audit (trigger, time,
  KEK-destroy confirmation, §15).
- **Idempotent, retry-safe ordering.** Each EOL carries an **idempotency
  key** + durable op record with substates `ticket_frozen →
  kek_destroyed → miner_stop_requested → capacity_reclaimed → l1_acked`,
  each retry-safe. `ticket_frozen` (the CAS to `decommissioning`) and
  `kek_destroyed` are the **commit points** and must be durable **before**
  capacity is reported reclaimed or any "VM gone" ack returns to L1.
  "Already destroyed for this exact `vm_id`/generation" ⇒ **success, not
  error**. If the miner never acks the stop after KEK destroy, data death
  is already guaranteed; vali performs a **unilateral forced capacity
  reclaim after timeout + §13 quarantine** (suspected ghost load).

## 25. Miner departure & VM live/cold migration — Critical

A node may **leave gracefully** (operator announces) or be **drained
involuntarily** (quarantine/slash, §23 scheduler). Either way the tenant
VMs must move with **bounded data loss, no plaintext through the
validator, no trust in the transport**, and — critically — **no
*authorized* split-brain**: the KBS releases the per-VM key to **at most
one generation/host at a time**, so two hosts can never both *unlock*
the disk. (A hostile source that refuses to stop while still holding the
key in RAM is the inherent §8 non-CVM live-host residual, handled
honestly below — not claimed away.) Reuses existing primitives; invents
nothing.

- **Trigger & orchestration.** Graceful: the miner signals "departing"
  over the control path → vali moves the node to `Draining` (§23 state
  machine), stops new placement, enumerates the node's tenant VMs.
  Involuntary: vali initiates the same drain directly. vali
  **orchestrates only** — it never sees plaintext or relays the bytes.
- **Quiesce & crash-consistency (guest-signed proof).** vali instructs
  the **source measured guest** (via Guardian relay) to quiesce
  (fsfreeze / clean stop). The guest **itself signs a quiesce proof**
  `quiesced_at{vm_id, lease_id, vm_generation, snapshot_nonce, fs_seq}`
  from inside the attested VM (validator-nonce'd) — proving the snapshot
  is a frozen, consistent point, not host-fabricated. Bounded timeout; no
  signed quiesce ⇒ treat as **ungraceful** (snapshot-loss path below).
  Only the per-VM writable volume + metadata moves; the rootfs is
  non-secret verity (§11), rebuilt at the destination.
- **Authenticated writable volume (NOT bare dm-crypt).** The per-VM
  writable volume is **LUKS2 + dm-integrity (AEAD)** — ciphertext tamper
  is **detected on open**, not silently applied. (A hostile source could
  tamper its ciphertext *then* hash it, so `sha256(ciphertext)` alone is
  worthless; integrity must be in the volume format *and* a guest-checked
  root.) The **manifest** — signed by the source Audit VM (attested,
  platform-bound, §23) and carrying the **guest quiesce proof** — binds
  `{dm_integrity_root, sha256(ciphertext), vm_id, vm_generation,
  lease_set, snapshot_nonce, fs_seq}`. The destination, **after**
  attesting and opening the volume, verifies dm-integrity and emits a
  **destination-Audit-VM-signed restore manifest**
  `{guest_post_restore_root, source_manifest_hash, snapshot_nonce,
  vm_id, new_vm_generation, dest_node_id, dest_platform_id}` that
  **chains to the source manifest** (same `snapshot_nonce`,
  `vm_generation+1`); vali accepts the resume **only** if this restore
  manifest validates against the recorded source manifest — the
  guest-signed post-restore root is thus *bound into a signed manifest*,
  not merely checked locally. Any mismatch ⇒ fail closed (abort; source
  stays authoritative). Confidentiality from LUKS (§8/§19), integrity
  from dm-integrity + the manifest-chained guest root, transport
  untrusted (§11 framing).
- **Transport NOT through the validator.** vali issues a **presigned S3
  PUT** (source) and **GET** (destination) — short-TTL, single-object,
  `version_id`-scoped (§11 pattern, no blanket creds). Ciphertext flows
  **miner → S3 → miner directly**; vali holds only the signed manifest;
  the **Audit VM is the attested control witness** that the snapshot came
  from the quiesced authoritative source.
- **Split-brain prevention — honest about the limit.** Releases use the
  **unified §24 state model**: `Active{gen,source} →
  Migrating{old=gen,new=gen+1,source,dest,phase,idem} →
  Active{gen+1,dest}`. **Strict no-split-brain requires the source to be
  provably stopped before the destination is activated:** the source
  measured guest must return a **signed
  `stopped{vm_id,lease_id,gen,nonce}` ack** (shutdown + dm-crypt teardown
  + poweroff) — only then does the KBS CAS `Migrating → Active{gen+1,
  dest}` and release the key to the destination. **If that signed stop
  ack is not obtained within bound, this is NOT strict-clean migration:**
  it degrades to the snapshot-loss path (restore the last trusted
  snapshot at `gen+1`; source `node → §13/§24 quarantine/slash`), and a
  *still-running hostile source we cannot forcibly kill* is the
  **inherent §8 non-CVM live-host residual** — stated honestly, **not**
  claimed away. The KEK/LUKS key is **NOT destroyed** (contrast §24);
  `luks_vault_ref` is deterministic from `vm_id` (§8); only
  `vm_generation` advances.
- **Forward-only generation / rollback.** Rollback to `Active{gen,
  source}` is allowed **only while `phase < new_gen_released`**. **After
  any new-gen KBS release, recovery is forward-only** on `gen+1` (or
  operator repair) — an old generation is **never** resurrected (KBS
  denies stale `gen`, §24). Per-migration **idempotency key**; "already
  at gen N" ⇒ success; bounded retries; repeated failure ⇒ tenant stays
  on source + alert.
- **Periodic snapshot lifecycle (the backstop — specified, not just
  referenced).** Independently of migration, vali orchestrates **periodic
  crash-consistent snapshots**: the source measured guest signs the same
  `quiesced_at` + `dm_integrity_root` manifest at a **configured cadence**
  (a `Params` operational knob — the cadence **is** the tenant
  data-loss SLA bound); ciphertext pushed to **S3 via presigned PUT (not
  through vali)**; **retention** = N versions under Object Lock; restore
  = boot the measured UKI at a **fresh `vm_generation`**, verify manifest
  + dm-integrity + guest root, resume; every snapshot/restore audited
  (§15). This is the source of truth for ungraceful-departure restore.
- **Overlay reachability is NOT carried by the migration (detected, not
  yet fixed).** §25 moves the guest-keyed writable volume **intact**, so
  the guest's own NetBird identity survives the move — but the
  **management-side peer record does not**: tenant setup keys are minted
  `ephemeral`, and NetBird deletes an ephemeral peer after **~10 min
  offline**, a window a *cold* move routinely exceeds. The destination
  cannot re-enrol itself: cloud-init re-runs `netbird up` every boot, but
  with the launch-time key, which is single-use and already consumed. So
  a completed migration can leave a **running, unlocked, unreachable**
  tenant. vali therefore **arms an overlay check in the same CAS that
  activates the destination** and settles it on the orchestration tick:
  a **deleted** peer record ⇒ `Vm.netbird_status=lost` immediately (the
  verdict cannot become wrong later), a **connected** peer ⇒ `ok` (+ the
  overlay IP refreshed), a present-but-disconnected peer ⇒ waits out a
  grace window. A NetBird API failure is **never** laundered into `lost`.
  `netbird_status` is surfaced on `GET /v1/vm/<id>/state` and logged at
  ERROR. **Still open:** vali does not re-mint a setup key for the
  destination, so a `lost` VM needs operator action — a fix must deliver
  the fresh key through the **attested §21 release envelope** (userdata
  re-staged in Vault, re-digested into the dest ticket), never via the
  untrusted host, and never as a reusable key held by the guest.
- **Honest residual (accepted — inherent miner-side limit, §8; NOT the
  closed KBS residual).** Ungraceful disappearance ⇒ restore from the
  last periodic snapshot ⇒ loses **up to one snapshot interval** of
  tenant writes (bounded by the cadence SLA); a hostile source we cannot
  stop is the inherent miner-side live-host limit (miner hosts we do not
  own); zero-loss live CVM migration across untrusted hosts would need
  confidential *miner* hosts — outside our control, stated honestly,
  **not** guaranteed.

## 26. Related

- [`DIAGRAMS.md`](DIAGRAMS.md) — visual overview (zones & trust
  boundaries, end-to-end runtime sequence, unified VM/node state machine).
- `thenervelab/hippius-backend`: NetBird multi-tenant L3 (merged & deployed,
  `/api/network/`), issue #57 (rotate NetBird PAT — blast-radius rationale
  for invariant #7), #62 (NetBird public-edge exposure).
- **`thenervelab/thebrain` `pallets/arion-pallet`** — the **reference
  implementation** the §23 compute scoring pallet mirrors (per-epoch
  deterministic map + `map_root`, family/child anti-Sybil registration,
  `submit_miner_stats` aggregates). **Pin the exact upstream commit/tag**
  when implementation starts, and record **what is copied verbatim vs
  deliberately changed** (own `HIPPIUS_COMPUTE_NODE_REG_V1` domain
  separator + chain/instance/version binding; own compute node keypair;
  compute-specific evidence commitments & fault-proof not in Arion;
  full-epoch `map_root` coverage). Storage/Arion already proves the
  pattern; compute reuses the shape + the shared `family` *owner*
  identity only (per-node device keys distinct, §23).
