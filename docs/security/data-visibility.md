# Data visibility & confidential-compute trust model

What can each party in the Hippius DePIN compute control plane see, in
plaintext, at each stage of a tenant CVM's lifecycle?

This document is the **load-bearing security contract** Hippius offers
to a tenant who runs workloads on a third-party miner node. It is
deliberately exhaustive: an external auditor or new contributor should
be able to read this top-to-bottom and understand why the operator
miner — who has full root on the bare-metal host — cannot read the
tenant's data.

The contract is enforced by:

- AMD SEV-SNP memory encryption (the `kvm_amd.sev_snp=1` host kernel
  parameter — see `dmesg | grep SEV-SNP` on a Genoa / Turin host)
- LUKS2 / argon2id full-disk encryption with a KEK that never leaves
  Vault in plaintext
- HPKE (Hybrid Public Key Encryption, RFC 9180) wrapping every secret
  KBS hands the guest, keyed to an X25519 keypair generated INSIDE the
  attested guest's encrypted RAM
- The §22 signed allowlist binding (measurement → L1 signer kid)
  enforced by `kbs-core::release::run` (`kbs-core/src/release.rs`)
- The AMD VEK → ASK → ARK certificate chain enforced by
  `RealSnpVerifier` (`kbs-core/src/snp_real.rs`)

This is not aspirational — every gate listed below is in the production
code path; references are inlined.

## 1. Threat model — who's the adversary

### 1.1 In scope (the trust contract holds against these)

| Adversary | Capability assumed |
|---|---|
| **Miner operator** | Full root on the miner bare-metal host. Can run any process, read any host file, dump host RAM, snapshot the LUKS image file, intercept all host network traffic, suspend the QEMU process, attach a debugger to QEMU, replace QEMU itself. |
| **Network-on-path attacker** | Reads every TCP packet between miner ↔ NetBird mesh ↔ cc-1 cluster ↔ Vault. Replays, drops, modifies in flight. |
| **Compromised KBS pod (post-release)** | Has the static Vault token; can re-read any KV secret. Cannot retroactively decrypt past HPKE envelopes (forward secrecy by ephemeral X25519). |
| **Compromised allowlist publisher** | Pushes a malformed `dev.cose` to S3. Caught by the SHA-256 fence in the chart (`allowlist.sha256` value in `deploy/gitops/apps/kbs/values.yaml`). |
| **Cross-tenant attacker** | A second tenant on the same miner. Cannot read the first tenant's RAM (SEV-SNP separates ASIDs at the memory controller) nor disk (different LUKS KEKs in different Vault paths). |

### 1.2 Out of scope (the contract degrades or breaks here)

| Risk | Mitigation |
|---|---|
| Compromised AMD Secure Processor firmware | AMD bug bounty + firmware updates. Hippius pins minimum firmware in `dmesg \| grep "SEV-SNP API"` (≥ 1.55 today). |
| Vault Tier-0 root compromise | Vault sits behind a separate trust boundary on a Confidential VM. The operator workflow uses a scoped non-root token (`hippius-compute-tenant-stage`). |
| KBS pod compromise BETWEEN Transit-decrypt and HPKE-wrap | Microseconds-wide, inside the attested KBS CVM — the only place a plaintext KEK exists. #102's attestation-bound broker and the Vault-Transit KEK-at-rest layer both shipped; see §6 for what they do and do not remove. |
| Side channels (cache timing, RowHammer, power analysis) | Active research area. Theoretically possible, not scalable in practice on Genoa/Turin with the published firmware. |
| Operator (you) leaks the plaintext at staging time | Operator owns the source. The runbook (`docs/operator/byo-base-os-bake-runbook.md`) requires `shred -u` of in-memory KEK + user-data files after `tenant-secrets-stage.sh` returns. |
| §22 dev key not rotated to the offline ceremony key | Phase B: replace `packer/keys/dev/l1-order-ticket.dev.ed25519` with an offline-ceremony root. Tracked in `project_hippius_compute_locked_decisions.md`. |

## 2. The actors, in order they touch the data

```
┌─────────────────┐    ┌─────────────┐    ┌──────────┐    ┌──────────────┐
│ Operator (you)  │───▶│   Vault     │◀───│   KBS    │───▶│ Tenant CVM   │
│ Mac / dev VM    │    │  Tier-0     │    │   pod    │    │  (SEV-SNP)   │
└─────────────────┘    └─────────────┘    └──────────┘    └──────────────┘
                              ▲                  ▲                ▲
                              │                  │ HTTPS+HPKE      │ HTTPS
                              │                  │                 │ (terminated
                              │                  │                 │  inside guest,
                              │                  │                 │  NOT on host)
                              │                  │                 │
                              │           ┌──────┴──────┐    ┌─────┴──────┐
                              │           │ ingress-nginx│    │  Miner-1   │
                              │           │  (TLS term.) │    │  host (HOSTILE) │
                              │           └─────────────┘    └────────────┘
                              │
                              │ no path
                              │
                       ┌──────┴───────┐
                       │  Miner host  │
                       │  CANNOT reach│
                       │  Vault       │
                       └──────────────┘
```

## 3. Data classification

What we protect, ranked by sensitivity:

| Tier | Data | Where it lives | Sensitivity |
|---|---|---|---|
| **TS-1** | LUKS KEK (32 raw bytes) | Vault + brief KBS RAM + tenant CVM RAM | Disclosure ⇒ disk plaintext. Single point of compromise for the tenant volume. |
| **TS-1** | NetBird setup-key (UUID) | Vault (inside cloud-init plaintext) + brief KBS RAM + tenant CVM RAM | Disclosure ⇒ attacker can join the tenant's mesh as the same identity, see the tenant's traffic, exfiltrate. |
| **TS-1** | Tenant user-data plaintext (cloud-config YAML) | Vault + brief KBS RAM + tenant CVM RAM | Carries every first-boot secret the operator chose to include. |
| **TS-1** | X25519 private key (HPKE recipient) | Tenant CVM RAM ONLY (generated in-place, never exits) | The recipient key for all KBS releases for this VM. Disclosure ⇒ retroactive decryption of every release blob. |
| **TS-2** | OrderTicket bytes (COSE_Sign1 envelope) | Operator Mac + vali Postgres + Edge pod transient + miner-agent transient + KBS pod transient | The ticket is **opaque** — vali / Edge / miner are mandated to never parse it. Signed body carries vm_id / measurement / Vault refs (NOT the underlying KEK). Disclosure ⇒ adversary learns vm metadata but cannot replay (ticket_id single-use cell in KBS). |
| **TS-2** | SNP attestation report | `/dev/sev-guest` ioctl output in tenant CVM + transit to KBS + KBS audit log | Public attestation primitive. Carries chip_id, measurement, report_data. Public per AMD spec. |
| **TS-3** | Launch measurement, chip_id, tenant UKI SHA | All actors, on-chain eventually | Public identifiers. Used for binding, not for secrecy. |

## 4. Visibility matrix

Y = the actor sees this in plaintext at this stage.
N = the actor cannot see this in plaintext — the data is either encrypted or absent from this actor's reach.

Stages refer to the chronological flow in `docs/operator/byo-base-os-bake-runbook.md`.

|                              | Operator | Vault | ingress-nginx | KBS pod | Miner-1 host (HOSTILE) | Tenant CVM |
|------------------------------|----------|-------|---------------|---------|------------------------|------------|
| **STAGING (pre-launch)**     |          |       |               |         |                        |            |
| LUKS KEK                     | Y        | Y     | N             | N       | N                      | N (not yet booted) |
| NetBird setup-key            | Y        | Y     | N             | N       | N                      | N |
| user-data plaintext          | Y        | Y     | N             | N       | N                      | N |
| **DISPATCH (vali → miner)**  |          |       |               |         |                        |            |
| OrderTicket COSE blob        | Y        | N     | N             | N (not yet involved) | Y (transient, opaque) | N |
| **GUEST BOOT (no release yet)** |       |       |               |         |                        |            |
| X25519 keypair               | N        | N     | N             | N       | **N** (in encrypted RAM)   | Y (generated in-place) |
| SNP attestation report       | N        | N     | N             | N (not yet) | Y (transit, but it's public anyway) | Y |
| **RELEASE (KBS → guest)**    |          |       |               |         |                        |            |
| LUKS KEK on the wire         | N        | N     | N (ciphertext only — TLS terminator below) | N | N (HPKE-wrapped + TLS-encrypted) | N (still wrapped) |
| LUKS KEK in KBS RAM          | N        | N     | N             | **Y (μs window)** | N | N |
| LUKS KEK in tenant CVM RAM   | N        | N     | N             | N       | **N** (SEV-SNP encrypted DRAM) | Y |
| user-data plaintext on wire  | N        | N     | N (ciphertext) | N      | N (ciphertext)         | N |
| user-data in tenant CVM RAM  | N        | N     | N             | N       | **N** (SEV-SNP encrypted DRAM) | Y |
| **POST-RELEASE**             |          |       |               |         |                        |            |
| LUKS volume bytes on host    | N        | N     | N             | N       | Y BUT **only ciphertext** (LUKS-encrypted) | Y (decrypted via dm-crypt in encrypted RAM) |
| user-data in `/var/lib/cloud/seed/nocloud/` | N | N | N | N | N (on the LUKS volume, encrypted) | Y |
| QEMU process RAM             | N        | N     | N             | N       | **N** (SEV-SNP — dump returns ciphertext) | Y (own RAM) |
| NetBird control plane peer record | Y (operator can list via the API token at `~/.config/hippius/netbird_pat`) | N | N | N | Y (peer ID + IP only, NOT the setup-key after use) | Y |

The **Y in the Miner-1 column** for "LUKS volume bytes on host" is the key
property: the operator has the encrypted bytes — the file is right
there in their filesystem — but the bytes are ciphertext keyed to a
KEK only the attested guest holds.

## 5. Two-layer encryption on the KBS → guest hop

Every secret KBS hands the guest is wrapped twice:

1. **HPKE** (RFC 9180) — the tenant CVM generates an ephemeral X25519
   keypair inside its SEV-SNP-encrypted RAM. The pubkey leaves the
   guest as part of the SNP report's `report_data` (which AMD SP signs
   so the operator and the network cannot substitute it). KBS encrypts
   each release blob with that pubkey. ONLY the guest's private key
   (in encrypted RAM, never on the wire) can decrypt.

2. **TLS** (HTTPS to `https://kbs.hippius.network`) — the transport
   layer. cert-manager + Let's Encrypt + nginx-ingress provide the
   server cert. The guest validates the cert against its bundled CA
   trust store (the default web CA bundle in the rootfs).

Even if TLS is broken (e.g., a future quantum break, a CA compromise,
a MitM proxy with a forged cert), the HPKE layer underneath is intact:
the wrapped envelope is unreadable without the guest's X25519 private
key, which never leaves SEV-SNP RAM.

Defense in depth: a single failure does not yield the secret.

## 6. The microseconds-wide KBS window

Inside the KBS pod, on the release path (`kbs-core/src/release.rs`):

1. AMD SNP report cryptographic verification (VEK → ASK → ARK chain)
2. §22 allowlist measurement check
3. L1 ticket signature + kid acceptance check
4. Vault read of the KV path → **Transit CIPHERTEXT** (`vault:v1:…`)
5. Transit-decrypt with the per-VM key `kek-<vm_id>` → **plaintext in KBS RAM** ← THIS
6. HPKE-wrap with the guest's X25519 pubkey
7. Return the wrapped envelope to the guest

Two things changed since this section first said "the only soft spot in
Phase A, closes when #102 lands". Both shipped; the residual is smaller
and differently shaped, and it is still real.

**The KEK at rest is ciphertext.** vali stores the Transit-wrapped form,
so a vali, broker or node compromise yields ciphertext and nothing else.
The decrypt happens transiently at step 5 inside the attested KBS CVM —
the only place a plaintext KEK exists at all. The Transit key is per-VM
(`kek-<vm_id>`) and the capability token's decrypt grant is scoped to
that one key, so a compromised KBS cannot become a decryption oracle for
another tenant's ciphertext.

**A plaintext KEK at rest is refused, not merely discouraged.**
`require_wrapped_kek` rejects any non-`vault:` KEK, so a compromised
writer cannot stage a chosen plaintext key and have the KBS release it
verbatim. It is `true` in the deployed configuration.

**#102 shipped.** The KBS authenticates to an SNP-attestation-bound Vault
broker for every release, presenting a fresh `/dev/sev-guest` self-report
that binds `challenge_nonce ‖ auth_pubkey`. It is mutually exclusive with
`dev_allow_any_kbs_measurement`, which the binary refuses at startup —
the broker IS the measurement gate.

**What remains.** Between steps 5 and 6 the plaintext exists in the KBS
pod's RAM for microseconds. The pod runs under the `kata-snp` runtime
class, so that RAM is itself SEV-SNP-encrypted, and the plaintext is
`Zeroizing` — wiped on scope exit. Still in scope for a KBS-binary RCE
that dumps memory before step 6, a side-channel on the KBS pod, and an
operator with `kubectl debug` into it. That window is inherent to
wrapping a key for a guest inside a broker; closing it entirely means the
guest deriving the key without any component ever holding it.

## 7. Operator hygiene

The operator (you) is the only actor who ever sees the plaintexts on
the wire. The runbook `docs/operator/byo-base-os-bake-runbook.md` requires:

- Generate the KEK + user-data plaintexts on a tmpfs path
  (`/run/user/$(id -u)/…`), not on persistent disk
- After `tenant-secrets-stage.sh` returns the staging refs, `shred -u`
  the local plaintext files
- Never log, never commit, never paste into chat the KEK / setup-key
- The operator workstation itself is part of the TCB (trusted compute
  base) — losing root on it means losing every tenant secret you ever
  staged

The operator Vault token is the durable secret on the operator side.
The runbook's policy (`hippius-compute-tenant-stage`) scopes that
token to KV writes under
`secret/data/hippius-compute/kbs/tenants/+/{luks-kek,userdata}` only —
no read on existing secrets, no destroy. `vault token revoke` is the
off switch.

## 8. What the operator CAN observe, by design

Confidential compute hides data, not metadata. The miner operator can
legitimately observe:

- That a tenant CVM is running (`ps aux`, `virsh list`, libvirt logs)
- The QEMU process's CPU + RAM usage and timing patterns
- That the tenant joined a NetBird mesh (NetBird's control plane sees
  the peer, the miner host sees the WireGuard handshake)
- The size and timing of HTTPS request/response pairs to KBS
- The size of the LUKS image file
- The number of read/write IOPS to the LUKS image

These observations may leak side-channel information (the tenant is
training an ML model vs serving a web app), but cannot recover the
content. The §23 anti-cheating layer (Audit-VM EPIC #130, Phase D)
addresses the reverse direction: it lets the validator detect when a
miner SUSPENDS or rate-limits a tenant to fake utilization.

## 9. Cross-references — every gate in code

| Gate | File | Function |
|---|---|---|
| SEV-SNP host kernel | host kernel cmdline | `kvm_amd.sev_snp=1 mem_encrypt=on` |
| Guest `/dev/sev-guest` ioctl | `binaries/agent-initramfs/src/stages/snp_ioctl.rs` | `SevGuestProvider::report` |
| X25519 keygen in-guest | `hippius-guest/src/release.rs` | `verify_and_unwrap_release` (recipient side) |
| KBS SNP cert chain verify | `kbs-core/src/snp_real.rs` | `RealSnpVerifier::verify` |
| §22 allowlist membership | `kbs-core/src/allowlist.rs` | `accepts_l1_kid`, `accepts_kbs_kid` |
| L1 ticket signature verify | `kbs-core/src/ticket.rs` | `verify_order_ticket` |
| Ticket replay-once cell | `kbs-core/src/replay.rs` | `ReplayOnceStore::take` |
| `platform_id == chip_id` | `kbs-core/src/release.rs:176` | `hex::encode(report.chip_id) != ticket.platform_id` |
| report_data binding | `hippius-types/src/report_data.rs` | length-prefixed hash |
| Vault KV read schema lock | `binaries/kbs-server/src/vault_mvp.rs` | `StaticTokenVaultKv::read_exact` (PR #163) |
| HPKE wrap on release | `kbs-core/src/release.rs` | (HPKE recipient pubkey in `Release` body) |
| LUKS unlock in guest | `binaries/agent-initramfs/src/stages/luks_cryptsetup.rs` | `RealLuksUnlocker` |
| NoCloud seed write | `binaries/agent-initramfs/src/stages/seed.rs` | `RealSeedWriter` |
| `switch_root` to LUKS rootfs | `binaries/agent-initramfs/src/stages/switch_root.rs` | (move-mounts then chroots) |
| Operator KEK staging | `scripts/tenant-secrets-stage.sh` | (PR #163) |
| Operator-side bake (encrypted qcow2 on workstation, no miner SSH) | `scripts/tenant-image-bake.sh` | (BYO-OS, #257) |
| Public KBS exposure | `deploy/gitops/apps/kbs/templates/{ingress,networkpolicy}.yaml` | (PR #169) |

## 10. Glossary

- **AMD SP** — AMD Secure Processor. The on-die security coprocessor
  that signs SEV-SNP launch reports with a per-chip key derived from
  the chip's CHIP_ID.
- **ARK / ASK / VEK** — AMD's three-level cert chain. ARK is the AMD
  Root Key (long-lived, AMD HQ), ASK is the AMD SEV Signing Key
  (issued per CPU family, e.g. Genoa), VEK is the Versioned Endorsement
  Key (per individual chip, fetched from `kdsintf.amd.com`).
- **CHIP_ID** — 64-byte unique identifier of an AMD SEV-SNP chip,
  embedded in the launch report and used as `ticket.platform_id`.
- **HPKE** — Hybrid Public Key Encryption (RFC 9180). The asymmetric
  envelope KBS uses to encrypt release blobs to the guest's X25519
  pubkey.
- **KAT** — Known-Answer Test. A pinned measurement in
  `test_vectors/uki/tenant-measurement.json` that fails CI if the
  build drifts.
- **KEK** — Key Encryption Key. The LUKS slot passphrase (32 raw bytes
  in our scheme).
- **launch_digest / launch_measurement** — 48-byte SHA-384 the AMD SP
  computes over kernel + initrd + cmdline + ovmf + launch_config at
  CVM start. The §22 allowlist enumerates the digests that are
  permitted to release secrets.
- **§22 allowlist** — A COSE_Sign1 envelope listing (measurement →
  acceptable L1 signer kids) tuples, signed by the offline §22 root
  key (`packer/kbs-uki/keys/dev/provenance-root.dev.ed25519` in dev;
  offline ceremony key in prod).
- **UKI** — Unified Kernel Image. A PE binary that concatenates kernel
  + initrd + cmdline + (optionally) signature into a single
  measurement-stable artifact.
- **Private network / NetBird mesh** — The two private network fabrics
  in scope: a private datacentre L2 network for in-rack peers, and a
  NetBird WireGuard mesh for cross-region.

---

If you read this far and something is unclear, that's a doc bug —
please file an issue.
