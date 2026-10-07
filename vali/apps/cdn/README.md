# `apps.cdn` — the CDN fleet in vali

Design: `docs/design/cdn.md`. Contract with the backend: `/v1/cdn/*` (§B).
KBS side: `docs/operator/cdn-fleet-keyring.md`.

Everything here is inert while `VALI_CDN_ENABLED` is off. Launching nodes
also needs `VALI_CDN_LAUNCH_ROLE`, and running the fleet needs
`VALI_CDN_RECONCILE_ENABLED`.

## Operator commands

| Command | What it does |
|---|---|
| `vali_cdn_ca init / export [--out F] / status / activate / retire` | The CDN CA. `export` prints the PEM bundle that the backend's node registration verifies node certificates against. |
| `vali_cdn_fleet list / mint / state <v> <state>` | The fleet keyring. |
| `vali_cdn_region list / create <XX>` | Regions. Set the target with `PATCH /v1/cdn/regions/<XX>`. |
| `vali_cdn_node list / drain / force-drained` | Nodes. `force-drained` stands in for the backend's dns-released ack. |

## Custody

- **CA.** The CA is the Vault Transit key `cdn-ca` (ed25519, non-exportable). vali only signs with it and reads its public half.
- **Fleet keys.** vali never holds a fleet secret:
  - Transit returns only the ciphertext.
  - vali stores it once, create-only, at `kbs/cdn-fleet/v<N>`.
  - vali records the KBS-signed public half after checking the signature under `VALI_CDN_KBS_RESPONSE_VK_HEX`.
- **`kbs_kid_hex` is informational.** The KBS signature does not cover it, and no check reads it.
- **Interrupted mint.** A mint asks the KBS before writing, and again after a refused write:
  - Vault answers a rewrite on vali's create-only path with 403.
  - A version the KBS already signs is adopted.
  - `cdn-fleet-disabled` refuses the mint.
  - A version path that holds something the KBS cannot unwrap (plaintext, garbage) stops every mint at that version with `fleet-key-not-minted`.

### Runbook: minting is stuck at `v<N>` (`fleet-key-not-minted`)

1. Confirm that vali never recorded `v<N>` (`vali_cdn_fleet list`) and that no backend feed, ticket or node ever named it. A version that was ever published must **never** be deleted: deleting its KV metadata is the one way to make `v<N>` creatable again, under a different key.
2. With an operator token, read what is there: `vault kv get -version=1 secret/hippius-compute/kbs/cdn-fleet/v<N>`. A valid entry is `{"value": base64("vault:v1:…")}` from `transit/datakey/wrapped/cdn-fleet`.
3. If it is anything else (plaintext, garbage), delete it entirely: `vault kv metadata delete secret/hippius-compute/kbs/cdn-fleet/v<N>`. KV version 1 is what the KBS reads, so a plain `kv delete` is not enough.
4. Run `vali_cdn_fleet mint` again.

## Outage breakers (`reconcile.py`)

A CDN node that fails is pulled from DNS, so a vali-side telemetry outage must not fail the whole fleet.

- **Liveness breaker.** It holds when more than half of all running VMs (≥3, tenants included) heard from within `VALI_CDN_BREAKER_CONTROL_WINDOW_S` are quiet at once.
  - It holds for at most `VALI_CDN_BREAKER_MAX_HOLD_S` (4 h). The domain-down and host-gone checks still catch the nodes that are really dead while it holds. The start is forgotten only after 2 consecutive passes without an outage, so a hovering ratio cannot restart the cap.
  - While it holds, a wedged node gets no new certificate, but it still fails if its host reports the domain down.
- **Host-unseen breaker.** It holds while more than half of the active miners heard from in that window (≥2) are unseen at once.
- **Quarantined or departing miner.** Its node fails at once, whatever the breakers say.
- **Known residual: an outage longer than the control window (24 h).** It ages every VM and miner out of both comparisons, so the breakers stop holding and nodes fail. Before that point:
  - an empty liveness control group logs at CRITICAL ("no running VM has signalled in the breaker's control window");
  - every tick of a hold logs at ERROR.
