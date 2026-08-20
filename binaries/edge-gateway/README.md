# hippius-edge-gateway

Userspace opaque relay between the untrusted miner NetBird mesh and
the internal vRack control plane. Spec of record:
`ARCHITECTURE.md` §5 / §9 / §10 / §17.8.

## What it does

Bridges two networks Edge is *not* on the IP routing path between
(`ip_forward=0` at the kernel; vRack micro-segment default-deny). At
the application layer, every byte that crosses the diode passes
through a typestate-locked pipeline:

```
accept (mTLS, PR-H4)
   → per-source rate limit (PR-H3, keyed on PeerId)
   → canonical-CBOR + typed-schema wire gate (PR-H2)
   → bounded validate→forward queue (PR-H3)
   → forward (PR-H5 wires real egress)
   → structured static-classifier log
```

Edge **never decrypts** anything (§5.6: KBS↔guest responses are
HPKE-wrapped to the guest ephemeral key). The wire gate validates
shape, not contents.

## mTLS (PR-H4)

Edge terminates per-peer mTLS on both interfaces and uses the peer's
**cryptographic identity** — not its IP — as the rate-limit /
audit key. Survives NAT (CGNAT'd NetBird peers no longer collapse
into one rate-limit bucket) and survives the §B Q11 90-day key
rotation (the SAN identity is the rotation invariant; the key
material is not).

### Runtime configuration

| env var | role | required |
|---|---|---|
| `EDGE_GATEWAY_CONFIG` | TOML (rate limit, queue depth, idle horizon). Defaults baked in. | no |
| `EDGE_MTLS_CA_PATH`   | CA bundle for client-cert validation | **yes** |
| `EDGE_MTLS_CERT_PATH` | Edge server cert chain (leaf + intermediates) | **yes** |
| `EDGE_MTLS_KEY_PATH`  | Edge server private key (PKCS#8 / SEC1 PEM) | **yes** |
| `EDGE_MTLS_CRL_PATH`  | CRL bundle for client-cert revocation | no |

PR-K7 Ansible (still unwritten) renders these out to
`/etc/hippius-edge/mtls/{ca,cert,key,crl}.pem` and points the
systemd unit at them. The Edge binary does **not** synthesise
defaults if a required env var is unset — boot fails with class
`mtls-env-missing` rather than fall back to a baked-in cert.

### Cert rotation (90 days, §B Q11)

The CA mints per-peer certs with a **90-day lifetime**. Rotation is
**manual today** — re-mint on each peer before expiry, push the new
cert, sign a fresh CRL, and re-roll the CRL on every Edge VM. The
Ansible playbook that would automate it is PR-K7 and is **not
written**; see the roadmap below. This paragraph used to describe
that playbook in the present tense, which read as "already
automated" while the file did not exist.

Edge itself has zero rotation machinery either way: it just re-reads
the PEMs on the next handshake and re-reads the CRL on the next 60 s
poll.

### Revocation (CRL polling + live `ServerConfig` rotation)

When `EDGE_MTLS_CRL_PATH` is set, Edge spawns a background tokio
task that re-reads the CRL file every **60 seconds**. On each
successful poll, the task **rebuilds the live rustls
`ServerConfig`** (re-reading CA + cert + key from disk + embedding
the fresh CRL snapshot) and atomically swaps it into the
`MtlsRuntime`'s `ArcSwap`. The next handshake uses the new
verifier — so a freshly-revoked cert is rejected within (worst
case) 60 s + handshake of an operator's CRL push:

- **CRL valid + fresh** → live `ServerConfig` rebuilt with the new
  CRL; revoked certs rejected at handshake.
- **CRL missing / corrupt / empty** → CrlStore marked unhealthy,
  every new TCP connection dropped at the acceptor BEFORE TLS
  negotiation, live `ServerConfig` retained unchanged (stale-but-
  known-good is strictly better than no config during the
  operator's fix window — but the health gate is fail-closed
  regardless, so it doesn't matter for accepted connections).
- **`EDGE_MTLS_CRL_PATH` unset** → no CRL revocation, no rebuild.
  Acceptable only if cert lifetimes are short enough to make
  revocation latency moot (§B Q11: 90 days).

The poll cadence is **not configurable**: it matches the operator
runbook's "fresh CRL every 24 h" cadence with one minute of slack
for the Ansible push.

`MtlsAcceptor::accept` consults the health gate both BEFORE and
AFTER the handshake — closes the TOCTOU window where the poller
flips unhealthy mid-handshake (a connection that negotiated
against a stale CRL snapshot must NOT be returned).

### TLS 1.3 only — no insecure fallback

`Cargo.toml` builds `rustls` with `default-features = false,
features = ["ring", "std"]`. The `tls12` feature is OFF, so the
handshake **cannot** negotiate anything below TLS 1.3 even if a
misconfigured peer offers it. There is no runtime knob to re-enable
a downgraded protocol. A regression that turned `tls12` back on
would land in a `Cargo.toml` diff AND flip the
`rustls_tls12_feature_is_off` assertion in
`tests/mtls_integration.rs`.

### `PeerId` extraction

Post-handshake, Edge pulls the peer identity from the leaf cert in
this order:

1. `subjectAltName: URI`
2. `subjectAltName: DNS`
3. `Subject CN`

A cert with none of these is rejected (`mtls-failed/peer-id`) so
the rate limiter never collapses anonymous-cert peers into one
bucket.

### Audit classifiers (static-string vocabulary)

Every failure mode is mapped to a stable `&'static str` so the
runbook can grep for it:

| class | meaning |
|---|---|
| `mtls-env-missing` | required env var unset at boot |
| `mtls-read` | PEM file unreadable |
| `mtls-parse` | PEM block did not decode |
| `mtls-empty` | PEM file parsed but contained zero blocks |
| `mtls-build` | rustls refused to build the verifier / config |
| `mtls-failed` | handshake aborted at runtime (sub-class via inner `&'static str`: `handshake`, `crl-unhealthy`, `no-peer-cert`, `peer-id`) |
| `crl-read` | CRL file unreadable on a poll cycle |
| `crl-parse` | CRL PEM block did not decode |
| `crl-empty` | CRL file contained zero blocks |

These never embed plaintext — same `&'static str`-only `Display`
discipline as `EdgeError`.

## What's NOT in PR-H4

- HA pair (active/active or active/passive) — PR-H5.
- Signed telemetry envelopes / structured audit log — PR-H6.
- OCSP stapling — deferred. CRL is sufficient for the §B Q11
  cadence; OCSP can be added without breaking the env-var surface.
- The Ansible mint + push playbook itself — PR-K7. Not written; the
  filename it will take is deliberately not quoted here, because a
  path in a README reads as a file that exists. Until then, operators
  provision the PEMs out of band.

## Order signing (§H phase-2)

The Edge signs lifecycle `OrderBody` CBOR for miners; every
miner-agent runs `verify_strict(body, sig)` against the matching
pubkey (rendered into `/etc/hippius-miner/config.toml` by Ansible).
This section is the **operator runbook** for provisioning the keypair
end-to-end. The signing primitive in `src/order_signing.rs` is
opt-in: the subsystem stays disabled unless `EDGE_ORDER_SIGNING_KEY_PATH`
is set, which the Helm chart only sets when `orderSigning.enabled`
flips to `true`.

### Wire contract

`SignedOrder { body: bytes, sig: bytes }` canonical CBOR. `body` is
the canonical CBOR of a `MinerHeartbeat`-class `OrderBody` (defined
in `binaries/miner-agent/src/orders/types.rs`; the Edge treats it as
opaque). `sig` is a detached 64-byte Ed25519 signature over the raw
`body` bytes. The miner-agent verifies via `verify_strict` — no
timestamp, no sequence; replay protection is `order_id` idempotency
on the miner side.

### One-time keypair provisioning (offline, air-gapped box)

The keypair is generated OUT-OF-BAND, never on the cluster. The
private seed is operator-signed at commit time only by virtue of
landing in Vault Tier-0; the public key is committed to the inventory.

```bash
# 1. Generate. Ed25519 raw 32-byte seed; openssl writes a PKCS#8 DER —
#    the seed is the last 32 bytes; the pubkey is the last 32 bytes
#    of the SubjectPublicKeyInfo DER.
WORK=$(mktemp -d) && chmod 700 "$WORK"
openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null > "$WORK/priv.der"
chmod 600 "$WORK/priv.der"
tail -c 32 "$WORK/priv.der" | xxd -p -c 32 > "$WORK/priv.hex"
openssl pkey -inform DER -in "$WORK/priv.der" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$WORK/pub.hex"
echo "pubkey: $(cat "$WORK/pub.hex")"
echo "priv (sensitive): $WORK/priv.hex"

# 2. Vault-write the seed under property `priv` — 64 lowercase-hex
#    chars. This path is the one `orderSigning.vaultPath` in the Edge
#    Helm values names.
vault kv put secret/hippius-compute/edge-gateway/order-signing \
  priv=@"$WORK/priv.hex"

# 3. Wipe the local seed copy.
shred -u "$WORK/priv.hex" "$WORK/priv.der" && rmdir "$WORK"
```

### Commit the pubkey

Replace `edge_order_signing_pubkey` in `deploy/ansible/group_vars/
miner_nodes.yml` with the 64-hex pubkey from step 1 above (it is
public; safe to commit). The variable is Jinja-rendered into every
miner's `/etc/hippius-miner/config.toml` by
`deploy/ansible/playbooks/miner-tasks/templates/miner-agent-config.toml.j2`.

### Re-apply on the miners + reload

Re-run the miner-tasks playbook so each miner gets the new pubkey,
then restart `hippius-miner-agent`:

```bash
ansible-playbook -i deploy/ansible/inventory.yml \
  deploy/ansible/playbooks/06-miner-bootstrap.yml \
  --tags miner-agent
ansible miner_nodes -i deploy/ansible/inventory.yml \
  -m systemd -a "name=hippius-miner-agent state=restarted" -b
```

### Enable the Edge subsystem

Flip the Helm chart toggle. Optionally pin
`orderSigning.expectedPubkey` to the same value committed to Ansible
— the Edge then fails closed with `order-signing-pubkey-mismatch` if
the Vault seed ever drifts:

```yaml
# deploy/gitops/apps/edge-gateway/values.yaml override (or
# `--set orderSigning.enabled=true`):
orderSigning:
  enabled: true
  expectedPubkey: "075f1bf8d7a62bbb21f7faab14d8c414c2aace842b1ca99ebadf8820d2b25ca9"
```

After Argo reconciles, every Edge pod's boot log emits one line of
the form:
```
hippius-edge-gateway: lifecycle: order-signing-up pubkey=<64-hex>
```
which MUST match the value in Ansible. A mismatch means the Vault
seed and the inventory drifted — re-run the runbook from step 1.

### Smoke test (off-cluster, before any vali→Edge route lands)

Until the `POST /v1/edge/order` axum route + the Edge → miner
forwarder land in a follow-up PR, the chain is exercised by signing
an `OrderBody` off-cluster with the same priv-key and `curl`-ing the
miner directly. This proves the Vault seed + the Ansible pubkey +
the miner's `verify_strict` are end-to-end consistent.

```bash
# Materialise the priv seed (Vault read; same machine as step 1).
PRIV_HEX=$(vault kv get -field=priv \
  secret/hippius-compute/edge-gateway/order-signing)

# Build a canonical-CBOR OrderBody. The miner-agent's tests
# (`binaries/miner-agent/tests/orders_handler_test.rs::signed_wire`)
# show the exact ciborium-style encoding the agent expects; use that
# helper from a small Rust scratch program or hand-build via Python.

# Sign the body bytes with the priv-hex seed. The PKCS#8 DER is
# streamed straight to file — shell command-substitution would
# corrupt the binary at NUL bytes (the OneAsymmetricKey wrapper
# contains them), so DO NOT round-trip through a shell variable.
printf '%s' "302e020100300506032b657004220420${PRIV_HEX}" \
  | xxd -r -p > /tmp/priv.der
openssl pkeyutl -sign -inkey /tmp/priv.der -keyform DER -rawin \
  -in order_body.cbor -out order_body.sig
shred -u /tmp/priv.der

# Wrap as a `SignedOrder` CBOR { body, sig } (e.g. via `cbor-tool`).

# POST to the miner over NetBird. Miner accepts (200) iff its
# `edge.order_signing_pubkey` matches the seed we signed with.
curl -sS -X POST -H 'content-type: application/cbor' \
  --data-binary @signed_order.cbor \
  "http://${MINER_NETBIRD_IP}:9700/v1/miner/order/launch"
```

A bad sig surfaces as HTTP 401 with `bad-signature`; a missing /
mismatched pubkey on the miner side surfaces the same. A successful
launch returns 200 with one of the static classifiers (`launched`,
`idempotent-replay`, …).

### What's NOT in this PR

- The `POST /v1/edge/order` axum route + the Edge → miner HTTP
  forwarder + the vali → Edge wiring. Tracked as the follow-up; the
  load + sign primitive shipped here is the foundation.
- A managed-rotation playbook: rotation is the runbook above re-run
  end-to-end (the two sides — Vault seed + Ansible pubkey — MUST
  flip together).
