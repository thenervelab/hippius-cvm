# Vault policy: l1-ticket-signing  (ARCHITECTURE.md §6; locked Q6/Q7)
#
# L1 (hippius-backend) signs OrderTickets with the `l1-ticket` transit
# key. Tracking placeholder: the consumer lives in the separate
# hippius-backend repo, but the policy is locked HERE so the Tier-0
# Vault surface stays single-sourced + reviewable in one place.
# `update` only — no `read`, no `list`, no `delete`.

path "transit/sign/l1-ticket" {
  capabilities = ["update"]
}
