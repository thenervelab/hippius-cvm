"""Operator-tier services that vali_create_vm orchestrates.

These modules concentrate every credential-touching dev-mode automation
(Vault writes, §22 allowlist signing + S3 upload, L1 ticket mint, KBS
deploy patch) the `vali_create_vm` management command stitches together.
None of these helpers are reachable from the runtime HTTP surface —
they are CLI-only and gated by `VALI_ALLOW_PROD` so an accidental prod
config refuses to load them.
"""
