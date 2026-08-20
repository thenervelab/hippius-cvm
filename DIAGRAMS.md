# Hippius Compute — visual overview

Companion to `ARCHITECTURE.md` (the authoritative spec, §§1–26). These
diagrams are a map, not the contract — on any conflict, `ARCHITECTURE.md`
wins. Rendered by GitHub (Mermaid).

---

## 1. Zones & trust boundaries

```mermaid
flowchart TD
  subgraph L1["L1 — client app (existing hippius-backend Django)"]
    L1A["users / dashboard / subscriptions<br/>mints the signed OrderTicket"]
  end

  subgraph VALI["vali cluster — Crypto GW (dedicated k8s cluster)"]
    VD["vali Django<br/>orchestration — no security inputs"]
    KBS["Rust KBS core<br/>attestation verify + release"]
    PK["Packer factory<br/>measured-UKI build"]
  end

  subgraph T0["Tier-0 — Confidential VM"]
    V["HashiCorp Vault<br/>LUKS keys + per-VM KEK + user-data"]
  end

  EG["Edge / Miner GW<br/>HA pair, dual-homed, opaque relay"]

  subgraph EDGE["L3 edge — UNTRUSTED EPYC miner"]
    G["Hippius Guardian<br/>untrusted relay"]
    TV["Tenant VM<br/>SEV-SNP attested"]
    AV["Audit VM<br/>SEV-SNP, validator-owned<br/>per-node trust anchor"]
  end

  PAL["On-chain compute scoring pallet<br/>EpochInput + map_root, E / W weights"]
  S3["S3 object store<br/>images + migration / snapshot blobs"]

  L1A -- "OrderTicket — mTLS, firewalled" --> VD
  L1A -- "seal user-data — write-only AppRole" --> V
  VD -- "orchestrate — ticket opaque" --> KBS
  KBS -- "read LUKS/KEK/user-data<br/>scoped, no-list, short-TTL" --> V
  PK -- "write-only" --> V
  PK -- "upload measured qcow2" --> S3
  VD -- "private net + mTLS" --> EG
  EG -- "NetBird mesh (miner side)" --> G
  G -- "attestation report — opaque relay" --> EG
  EG -- "opaque relay" --> KBS
  G --- TV
  G --- AV
  TV -- "presigned GET image — NOT via vali" --> S3
  AV -- "presigned PUT snapshot/migration — NOT via vali" --> S3
  AV -- "signed audit stats / co-signed receipts" --> VD
  VD -- "submit_audit_stats — single authoritative submitter" --> PAL
  PAL -- "eligibility E + reward W" --> VD
```

**Trust:** `L1`, `vali cluster`, `Tier-0 Vault` = trusted. `Edge GW` =
hardened relay (opaque, no plaintext). `L3 miner` = **untrusted**;
trust there comes only from SEV-SNP attestation of the Tenant/Audit VMs,
never from the host or Guardian. Bytes (images, migration blobs) flow
**miner ↔ S3 directly via presigned URLs — never through the validator**.

---

## 2. End-to-end runtime sequence

```mermaid
sequenceDiagram
  autonumber
  participant L1 as L1 hippius-backend
  participant VD as vali Django
  participant PK as Packer
  participant S3 as S3
  participant MN as Miner / Guardian
  participant G as Tenant guest
  participant AV as Audit VM
  participant EG as Edge GW
  participant KBS as KBS core
  participant VT as Tier-0 Vault
  participant PAL as Scoring pallet

  L1->>VT: seal user-data (write-only)
  L1->>VD: signed OrderTicket {lease_id, vm_generation, node/platform}
  PK->>S3: upload measured UKI/qcow2 (content-addressed SHA-256)
  VD->>MN: presigned S3 GET (version_id-scoped, short TTL)
  MN->>S3: download image
  MN->>G: boot measured UKI (dm-verity rootfs)
  G->>EG: SNP report (REPORT_DATA = nonce ‖ guest pubkey) via Guardian
  EG->>KBS: relay opaque
  KBS->>KBS: verify chain/TCB/measurement/nonce/ticket + unified VM state
  KBS->>VT: read LUKS key + user-data (scoped, single-use)
  KBS-->>G: signed + HPKE-wrapped secrets (commit-before-emit)
  G->>G: verify KBS sig, unlock LUKS, cloud-init, switch_root
  Note over AV,VD: proof-of-capacity + co-signed ServedDeliveryAggregate
  AV-->>VD: signed receipts / stats (gag-order: silence = worst case)
  VD->>PAL: submit_audit_stats (authoritative)
  PAL-->>VD: E (eligibility) + W (reward) — pot X split pro-rata
  Note over MN,KBS: Departure/drain → §25 migrate (gen+1, source fenced)
  Note over KBS,VT: EOL → §24 destroy per-VM KEK (Destroyed tombstone)
```

---

## 3. Unified VM lifecycle + node state

```mermaid
stateDiagram-v2
  state "KBS VM lifecycle — per vm_id, §7 / §24 / §25" as VM {
    [*] --> Active
    Active: Active gen+host+lease
    Active --> Migrating: depart / drain, §25
    Migrating --> Active: commit gen+1, source fenced
    Migrating --> Active: abort, only before new-gen release
    Active --> Decommissioning: end-of-life, §24
    Decommissioning --> Destroyed: KEK destroyed, crypto-erase
    Destroyed --> [*]
  }

  state "Node state — Audit VM, §23" as ND {
    [*] --> RegisteredPendingAudit
    RegisteredPendingAudit --> AuditAttested: first attestation, activation gate
    AuditAttested --> GraceDegraded: late / partial
    GraceDegraded --> AuditAttested: recovered
    AuditAttested --> Draining: departure / slash
    GraceDegraded --> Quarantined: threshold
    Draining --> Retired
    Quarantined --> Reattesting
    Reattesting --> AuditAttested
    Quarantined --> Retired
  }
```

**Key invariants:** the KBS releases a `vm_id`'s key to **at most one
`(gen, host)`** (no *authorized* split-brain); generation is
**forward-only** after any new-gen release; **first attestation is the
activation gate** (no placement / score / reward before it); a
missing/stale/unattested Audit VM ⇒ node treated **worst-case**.
