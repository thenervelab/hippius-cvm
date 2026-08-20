# Vault policy: kbs-response-signing  (ARCHITECTURE.md §7/§20; locked Q6/Q7)
#
# The KBS encrypts + signs release responses with the `kbs-response`
# transit key. Write-only by responsibility: the only capability is
# `update` — the transit encrypt/sign write operation. No `read`, no
# `list`, no `delete`, and no path beyond these two. Vault is
# default-deny, so every path not named here is denied.

path "transit/encrypt/kbs-response" {
  capabilities = ["update"]
}

path "transit/sign/kbs-response" {
  capabilities = ["update"]
}
