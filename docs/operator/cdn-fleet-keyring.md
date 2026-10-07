# CDN fleet keyring (CDN K1 + K2)

Every CDN node holds the same X25519 keypair, one per version. The backend
seals zone secrets to the public half (`docs/design/cdn.md` §5.3), and nodes
unseal them in RAM. This page covers custody, setup, minting, rotation and
the KBS ceremony. The code is in `kbs-core/src/cdn_fleet.rs` and
`kbs-core/src/snp.rs` (`check_release_class`).

## Custody

- **Generation.** Vault Transit generates the key
  (`transit/datakey/wrapped/cdn-fleet bits=256`) and returns only its
  ciphertext. vali (or `scripts/cdn-fleet-mint.sh`) stores the ciphertext
  once, at `secret/hippius-compute/kbs/cdn-fleet/v<N>` = `{"value":
  base64("vault:v1:…")}` with `cas=0`, so it is KV version 1.
- **No chosen keys.** No policy grants `transit/encrypt/cdn-fleet` or
  `transit/datakey/plaintext/cdn-fleet`. Nobody can wrap a key they already
  know.
- **Unwrap.** Only the attested KBS unwraps, with a broker-minted
  capability that carries the fixed policy `kbs-cap-cdn-fleet`. The KBS
  asks for that leg in exactly two places:
  - a release whose measurement is `cdn_node`-class **and** whose
    OrderTicket carries the `cdn-node` perm;
  - the admin public-key route, which returns only public data.

  This is the one accepted exception to "no standing fleet-wide read
  authority". Each token is short-TTL with bounded `num_uses`.
- **Residuals.**
  - The broker's mint credential could create a `kbs-cap-cdn-fleet` token
    outside a release. Only broker code prevents it, exactly as for every
    per-VM KEK cap. Keep the token role's `allowed_policies` an explicit
    list (never `kbs-cap-*`), and alert on Vault audit token creates that
    carry the policy without a matching release `cdn-fleet=` row or admin
    `cdn-fleet-public` row.
  - vali signs both the allowlist and the tickets. A compromised vali can
    therefore pin an image of its own as `cdn_node` and receive the keys.
    The class and perm gate stops miners and tenants, not vali. The
    follow-up is to bind `cdn_node` to an offline-signed CDN image
    identity.
- **Release.** Each fleet key is HPKE-wrapped to the attested guest key,
  bound to the ticket, the nonce, the measurement and the fleet version
  (`secret_type = "cdn-fleet"`, `secret_version = N`). It goes out in
  `KbsResponse::cdn_fleet`. That field is absent from every other release,
  which stays byte-identical.
- **Delivered bytes.** The delivered key is the RFC 7748-clamped X25519
  secret, so it is the same in libsodium and in `crypto_box`.
- **In the guest (G1).** Only a `cdn-node` image asks for the keyring:
  its initramfs passes `--cdn-fleet-dir /run/hippius/cdn-fleet` to
  `hippius-guest-release`, which checks each key's binding (type,
  per-version path, version, clamping), writes `v<N>.key` (raw 32 bytes,
  `0400`, root) into that tmpfs directory (`0700`) before the KEK ships,
  and fails the boot closed on any error or an empty keyring. systemd's
  `LoadCredential=cdn-fleet:/run/hippius/cdn-fleet` (systemd 251 or
  newer) hands it to the agent. A tenant image never unwraps the field.

## Which versions a node gets

The ticket names them, signed by L1. A CDN node's `lifecycle_perms`
carries:

- `cdn-node`;
- one `cdn-fleet-v<N>` per version vali has `pending`, `active` or
  `retiring`.

Rules:

- `N` is canonical decimal in `1..=u32::MAX`.
- A ticket carries 1 to 4 versions.
- A duplicate or malformed perm is refused.
- A tenant ticket that names a version is refused.

The KBS keeps no keyring state, so a KBS restart loses nothing.

| class \ ticket | no `cdn-node` | `cdn-node` + ≥1 `cdn-fleet-vN` |
|---|---|---|
| `tenant` | tenant release (unchanged) | refused `cdn-perm-class-mismatch` |
| `cdn_node` | refused `cdn-class-without-perm` | release + `cdn_fleet`, or refused `cdn-fleet-disabled` while `[cdn_fleet] enabled = false` |
| `host_attestor` | unchanged, or refused with `[allowlist] enforce_release_class = true` | refused |

## Public metadata

`POST /v1/admin/cdn-fleet/public {"version": N}` is an admin mTLS route
and needs a verified client certificate. It returns:

```json
{"v":1,"version":N,"x25519_public_b64":"…","kbs_kid_hex":"…",
 "kbs_signature_b64":"…","kbs_public_key_hex":"…"}
```

- **Signature.** `kbs_signature_b64` is Ed25519 by the KBS response key
  over `"HIPPIUS_CDN_FLEET_PUB_V1" ‖ u64 big-endian(N) ‖ x25519_public`, 64
  bytes. The test vector is `test_vectors/cdn_fleet/public_key_signature.json`.
- **Verifying it.** Verifiers (vali, then the backend as
  `CDN_KBS_PUBLIC_KEY`) pin the KBS response key out of band. That is the
  key the guest UKI pins (`PINNED_KBS_RESPONSE_VK` in
  `binaries/agent-initramfs/src/trust_anchors.rs`; kid `config.kidHex` in
  the KBS chart). `kbs_public_key_hex` is only compared against that pin,
  so a verifier notices a key rotation.
- **Errors.** 404 `cdn-fleet-disabled`, 403 `admin-client-cert-required`,
  400 `cdn-fleet-bad-version`, and 502 `cdn-fleet-unwrap-failed` (never
  minted, plaintext at rest, or broker or Vault down). Every call is one
  `cdn-fleet-public` row in the admin audit chain.

## Setup, once

1. **Vault.** Create the key and write the policies. Use an operator token.
   ```bash
   vault write -f transit/keys/cdn-fleet type=aes256-gcm96 exportable=false \
     allow_plaintext_backup=false            # deletion_allowed stays false
   vault policy write kbs-cap-cdn-fleet deploy/terraform/policies/kbs-cap-cdn-fleet.hcl
   vault policy write vali-orchestrator deploy/terraform/policies/vali-orchestrator.hcl
   vault write auth/token/roles/kbs-vault-broker-cap \
     allowed_policies="kbs-cap-templated,kbs-cap-cdn-fleet" \
     allowed_entity_aliases="*" token_no_default_policy=true \
     disallowed_policies="default,root,kbs-vault-broker-mint" \
     token_explicit_max_ttl=600 renewable=false orphan=false
   ```
   `scripts/cdn-fleet-mint.sh --init-transit-key` can create the key
   instead.
2. **Broker.** Pin the broker image built from this change, then set
   `vault.cdnFleetPolicy: kbs-cap-cdn-fleet` in the broker chart. An older
   broker rejects the key at startup (`deny_unknown_fields`), so the image
   goes first.
3. **KBS.** Roll the KBS in the ceremony below. Set
   `config.cdnFleetEnabled: true` only when the first CDN node is due. A
   config change takes effect only at a restart, which means a ceremony.

## Mint a version

```bash
scripts/cdn-fleet-mint.sh --version 1 --kbs-vk-hex <pinned KBS response key>
```

The script checks that the Transit key is non-exportable, generates a
wrapped key, stores it once, and has the KBS derive, sign and return the
public half. It verifies the signature before printing the
`fleet_keys[]` entry. Once vali V1 lands, `vali_cdn_fleet_mint` runs the
same steps.

## Rotation

1. Mint `N+1`. vali records it as `pending`.
2. New CDN tickets carry `cdn-fleet-vN` and `cdn-fleet-v(N+1)`. Roll-reboot
   the nodes onto both versions, since a node gets its keys only at boot.
3. Mark `N+1` `active`, so the backend seals to it, and `N` `retiring`.
   The leader node re-seals every blob.
4. Mark `N` `retired`, so new tickets drop it.

Versions are immutable. A retired version's Vault entry can stay, because
no ticket names it any more.

**Never delete a minted version's KV metadata.** That is the one way to
make `v<N>` creatable again, under a different key. Verifiers (vali and
the backend) record each version's public key the first time they see it
and refuse a change.

## KBS ceremony for K1 + K2

Follow the "KBS roll ceremony checklist" in
`deploy/gitops/apps/kbs/README.md` and the `vali_kbs_recover` recipe. On
top of that:

- K1 and K2 hold no KBS state: the perms and the class are re-checked from
  the ticket and the allowlist on every release. There is nothing new to
  re-seed or migrate.
- The KBS image changes, so its measurement changes. Re-pin it at the broker
  (`kbsMeasurementAllowlist`) in the same window, as on every roll.
- Order matters:
  1. the broker image (with `cdnFleetPolicy` still empty);
  2. the KBS;
  3. `kbs-allowlist-tool` and vali V2, which write `cdn_node` and the perms;
  4. `cdnFleetPolicy`, `cdnFleetEnabled`, then the first mint.

  An older KBS rejects any manifest that carries `cdn_node`, which denies
  every release.
- **Rollback.** The previous KBS image is a safe rollback target while no
  manifest entry is `cdn_node`. After the first CDN pin, destroy or re-pin
  the CDN VMs first.
