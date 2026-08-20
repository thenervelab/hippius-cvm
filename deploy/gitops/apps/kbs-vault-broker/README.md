# `apps/kbs-vault-broker` — SNP-attestation-bound Vault broker (#102)

The broker replaces the KBS's static Vault token (§8). It is the
cluster's **only** holder of a privileged Vault credential; the KBS
authenticates each release with a fresh SEV-SNP self-report
(`REPORT_DATA = challenge_nonce ‖ auth_pubkey`) and receives a
**per-VM-scoped, short-TTL, bounded-use** child token instead.

Design + trust model (incl. the documented v1 bootstrap residual):
`docs/design/vault-broker-102.md`. Binary:
`binaries/kbs-vault-broker/`.

## Image

`ghcr.io/thenervelab/hippius-kbs-vault-broker`, built + cosign-signed
by `.github/workflows/broker-image.yml`, pinned by digest in
`values.yaml`. PUBLIC — the kata-qemu-snp guest pulls it itself (CoCo
guest-pull); it carries no secrets.

## Operator setup (once)

1. **Token role + broker policy + privileged token.** Vault's
   child-policy-subset rule means a non-root token can only attach a
   policy outside its own set through a token ROLE whose
   `allowed_policies_glob` covers it — hence the role-based
   `auth/token/create/kbs-vault-broker-cap` endpoint.

   ```bash
   # KEK-HSM Phase 3 (RA-KBS-M2): the broker mints the per-VM cap by
   # attaching ONE fixed TEMPLATED policy + entity_alias=<vm_id>; it NEVER
   # writes an ACL. First install the templated policy:
   vault policy write kbs-cap-templated \
     deploy/terraform/policies/kbs-cap-templated.hcl
   #   ^ the .hcl pins THIS Vault's token-auth mount accessor in its
   #     {{identity.entity.aliases.<accessor>.name}} template — re-derive
   #     via `vault auth list` if it ever changes.

   # token role — attaches the fixed templated policy + any (charset-locked)
   # entity_alias, caps TTL server-side. Keep `allowed_policies_glob=kbs-cap-*`
   # ONLY during a rollover from the old per-VM-ACL broker; DROP it once the
   # new broker is deployed + verified.
   vault write auth/token/roles/kbs-vault-broker-cap \
     allowed_policies="kbs-cap-templated" \
     allowed_entity_aliases="*" \
     token_no_default_policy=true \
     disallowed_policies="default,root,kbs-vault-broker-mint" \
     token_explicit_max_ttl=600 renewable=false orphan=false

   # broker policy — NO `sys/policies/acl` write (that grant was the
   # RA-KBS-M2 forge-everything hole). The broker only creates cap tokens.
   vault policy write kbs-vault-broker-mint - <<'HCL'
   path "auth/token/create/kbs-vault-broker-cap" { capabilities = ["create", "update"] }
   path "auth/token/renew-self"                  { capabilities = ["update"] }
   path "auth/token/lookup-self"                 { capabilities = ["read"] }
   HCL

   # privileged token (768h = system max; rotation = re-run + restage)
   vault token create -orphan -policy=kbs-vault-broker-mint \
     -no-default-policy -ttl=768h -display-name=kbs-vault-broker
   ```

   Stage the token at KV-v2 `secret/hippius-compute/kbs-vault-broker`,
   property `vault-token`. ESO materialises the
   `kbs-vault-broker-token` Secret from there.

2. **VEK** — already staged for the KBS at
   `secret/hippius-compute/kbs/vek` (property `pem`); the broker's
   ExternalSecret reads the same path. Nothing to do.

3. **KBS measurement pin** — after the KBS image/launch shape rolls,
   read the live measurement from the KBS's own SNP report and add it
   to `kbsMeasurementAllowlist` in `values.yaml`. While the list is
   empty the broker starts but **denies every redeem** (fail-closed).

## Flip order (#102 PR C final)

1. Broker Healthy + measurement pinned here.
2. KBS chart: set `vault.brokerUrl: http://kbs-vault-broker.kbs.svc:8100`,
   flip `devAllowAnyKbsMeasurement` + `devSkipTlsVerify` off.
3. Live verify: tenant launch end-to-end (release 200), then negative
   (un-pinned KBS measurement → redeem 403).
