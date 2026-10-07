# kbs-cap-cdn-fleet — the FIXED cdn-fleet leg of a KBS capability token
# (CDN K2, `kbs-core/src/cdn_fleet.rs`, `docs/design/cdn.md` §5.3).
#
# Operator-created, never broker-written, exactly like kbs-cap-templated.
# The broker attaches it (its `vault.cdn_fleet_policy`) on top of the
# templated per-VM policy when the KBS asks for a scope carrying the
# cdn-fleet leg, and alone for a fleet-only scope (the KBS admin route that
# derives and signs a fleet public key). The KBS asks for the leg ONLY
# inside a release whose measurement is `cdn_node`-class AND whose
# OrderTicket carries the `cdn-node` perm — the one accepted exception to
# "no standing fleet-wide read authority". Each token is short-TTL with
# bounded num_uses.
#
# Residual, the same one every per-VM KEK cap already has: the broker's
# own mint credential (`kbs-vault-broker-mint`) can create a token with
# this policy outside a release; only broker code restricts it to the
# KBS's requests. Keep the token role's `allowed_policies` an explicit
# list (never the `kbs-cap-*` glob) and watch the Vault audit log for
# token creates carrying `kbs-cap-cdn-fleet` that do not match a release
# (`cdn-fleet=` rows) or an admin `cdn-fleet-public` row.
#
# The token role must allow it:
#   vault write auth/token/roles/kbs-vault-broker-cap \
#     allowed_policies="kbs-cap-templated,kbs-cap-cdn-fleet" ...
#
# The fleet keys are Transit ciphertexts (`transit/datakey/wrapped/
# cdn-fleet`, one immutable KV entry per version). NO policy anywhere
# grants `transit/encrypt/cdn-fleet` or `transit/datakey/plaintext/
# cdn-fleet`: nobody can wrap a key they chose, and nobody but the
# attested KBS ever sees a plaintext fleet key.

# Every fleet key version (read; versions are write-once, KV version 1).
path "secret/data/hippius-compute/kbs/cdn-fleet/v*" {
  capabilities = ["read"]
}
# Unwrap them, inside the attested KBS only.
path "transit/decrypt/cdn-fleet" {
  capabilities = ["update"]
}
