# Permissionless miner auth — production model

Status: **DRAFT for review** · Repo: `hippius-compute`
Supersedes the operator-CA mTLS bootstrap for the miner↔Edge link.

## The problem

Today a miner reaches the Edge over the NetBird mesh and presents an
**mTLS client cert signed by the operator CA** `hippius-compute-edge-
bootstrap-ca`; the Edge keys rate-limit/audit on the cert's SAN
(`binaries/edge-gateway/src/mtls/`). That is a **permissioned** model —
only a miner the operator has hand-issued a cert to can connect. The CA
is named *bootstrap* for a reason: it does **not** scale to a
permissionless DePIN where anyone can run a miner. Issuing a cert per
third-party miner makes the operator a gatekeeper and re-centralises the
trust the rest of the stack works hard to decentralise.

## The trust model (what actually gates a miner)

The anti-Sybil gate already exists — **on-chain**, not at the Edge:

- **`pallet-compute-scoring::register_child`** binds a miner's **ed25519
  node identity** to an on-chain account, proven by a node signature,
  and **reserves a deposit**. Our **`$`-denominated stake layer (#473)**
  raises that to skin-in-the-game proportional to what the miner hosts.
- **`MinerStatuses`** is the live `Active / Quarantined / Decommissioned`
  state; **slashing (#479)** burns the stake of a misbehaving miner.

So the question "may this miner participate?" is answered by the
**chain**: *is its node_id registered, `Active`, and stake-sufficient?*
The Edge should ask exactly that — not "did the operator sign its cert?".

## Design

The miner's **ed25519 node identity is the principal**. The Edge
authenticates by that identity, verified against the **on-chain
registry**. No operator CA.

### 1. Miner side (`miner-agent`)
- Keep the self-generated `identity.{key,pub}` (already exists).
- Generate a **self-signed** TLS client cert whose key **is** the node
  identity key (Ed25519), with the `node_id` as the SAN
  (`URI:hippius-node:<node_id_hex>`). No operator involvement; the cert
  is just a transport carrier whose possession proves the identity.
- (Config: drop the operator `client_cert/ca_cert` requirement; the
  agent mints its own on first boot, like `init-identity`.)

### 2. Edge side (`edge-gateway`)
Replace the CA-based `WebPkiClientVerifier` with an **identity
verifier** (`build_server_config`):
- Accept a **self-signed** client cert (transport encryption only).
- Extract the `node_id` from the leaf cert (its Ed25519 public key / SAN)
  and require the handshake to **prove possession** (TLS already proves
  the peer holds the cert's private key).
- **Gate on the registry**: drop the connection unless `node_id` is in
  the synced **on-chain registered + `Active` + stake-sufficient** set.
- Rate-limit/audit key stays the cryptographic identity (`node_id`) —
  same property the SAN gave today, sourced from the chain instead of a
  CA.

### 3. The registry (the Edge's source of truth)
- The Edge keeps a **cached snapshot of registered miners** from the
  chain: `NodeIdToChild` ∩ (`MinerStatuses == Active`) ∩ stake-OK,
  refreshed every N seconds (same shape as the CRL poller it replaces).
- Source: read `pallet-compute-scoring` storage over RPC (the
  `read-miner-status` decoder already does this), or a vali-served
  feed. Fail-closed if the snapshot is stale (mirrors the CRL health
  gate).

### 4. Revocation — for free
No CRL. A miner that is **slashed / quarantined / decommissioned /
stake-deficient** leaves the `Active` set on the next registry refresh →
the Edge drops it. Revocation becomes an on-chain state transition, not
a separately-distributed list.

## Migration
- Add the identity verifier behind a config flag
  (`EDGE_MINER_AUTH = ca | onchain`); ship `onchain` once the registry
  sync is validated. Keep the bootstrap CA path for the transition.
- Existing operator miners re-mint a self-signed identity cert
  and register on-chain; no more hand-issued certs.

## Implementation (proposed PRs)
1. **agent**: self-signed identity cert (mint on boot from `identity.key`).
   — ✅ **shipped (#491)**. `MinerIdentity::self_signed_client_pem` mints
   the cert with SAN `URI:hippius-node:<node_id>`; `edge.client_cert/key`
   are now optional (self-sign when absent).
2. **edge**: on-chain verifier + the registered-set registry poller
   (replacing `cert_store`'s CA verifier + `revocation` CRL), fail-closed
   on a stale snapshot. — ✅ **shipped**. Behind `EDGE_MINER_AUTH=ca|
   onchain` (default `ca`). `SelfSignedClientVerifier` accepts self-signed
   client certs; `MtlsAcceptor::accept` binds the SAN node_id to the cert
   key (anti-impersonation) then gates on the live `RegistryStore`
   (registered+`Active`), refreshed by a poller that reuses the shared
   `hippius-onchain-registry` reader (single-source with vali's
   `read-miner-status`, no storage-key drift).
3. **on-chain registration UX**: a `register-miner` flow (the agent or a
   CLI submits `register_child` + stakes) so onboarding is one command,
   permissionless, no operator step. — *pending*.
4. Deprecate the bootstrap CA once the fleet is on `onchain`. — *pending*.

### Rollout (deploy-side, not code)
- Edge: set `EDGE_MINER_AUTH=onchain` (the code default is `ca`) plus
  `EDGE_REGISTRY_FEED_URL` — vali's `GET /v1/edge/registry` feed, NOT a
  chain RPC. The Edge is egress-locked, so it polls vali and vali reads
  the chain. `EDGE_REGISTRY_REFRESH_SECS` defaults to 30;
  `EDGE_REGISTRY_FEED_PUBKEY` pins the Ed25519 key the feed is signed
  with — leave it unset only during the pre-pin window, since an unset
  pubkey means the feed is trusted unverified. NetworkPolicy must allow
  Edge→vali. A malformed `onchain` config is boot-fatal, never a silent
  fallback to `ca`.
- Miner: drop the operator `client_cert/client_key` from the agent config
  (the agent self-signs); `ca_cert` stays (it still verifies the Edge
  server cert). The Ansible `mtls.expected_files` client cert becomes
  optional for `onchain` miners.

## Why this is the right prod model
The miner is **untrusted by design** — it can only DoS, never extract
(the SNP attestation + KBS-released KEK secure tenant data regardless of
the miner). So the Edge link doesn't need operator-vouched identity; it
needs *a cryptographic identity that staked on-chain and is in good
standing*. That is exactly what the chain already tracks. Anyone can
join by staking; misbehaviour is slashed; the Edge enforces the chain's
verdict. No certs to issue, rotate, or revoke by hand.
