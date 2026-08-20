# Vault policy: sentinel-anchor-signing  (ARCHITECTURE.md §15; locked Q6/Q7)
#
# hippius-sentinel signs audit hash-chain head anchors with the
# `sentinel` transit key before they are snapshotted to the
# `hippius-compute-audit-anchors` bucket. `update` only — no `read`,
# no `list`, no `delete`.

path "transit/sign/sentinel" {
  capabilities = ["update"]
}
