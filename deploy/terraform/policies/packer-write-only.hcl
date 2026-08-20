# Vault policy: packer-write-only  (ARCHITECTURE.md §11; locked Q6/Q7)
#
# The Packer factory writes per-image build secrets into its own KV-v2
# subtree and never reads them back. The `+` glob matches exactly ONE
# path segment (a single image id) — tighter than `*`: it cannot reach
# a nested path and cannot escape `secret/data/packer/`. `create` +
# `update` only — no `read`, no `list`, no `delete`.

path "secret/data/packer/+" {
  capabilities = ["create", "update"]
}
