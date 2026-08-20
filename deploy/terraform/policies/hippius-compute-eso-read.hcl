# hippius-compute-eso-read — scoped to EXACTLY the leaves ESO syncs (RA-N1).
#
# Was `secret/data/hippius-compute/*` (read-all), which re-exposed via a
# SECOND token the H2 trust-anchor seeds (vali/allowlist-root,
# vali/l1-order-ticket), every tenant KEK (kbs/tenants/*), s3/operator, and
# eso/vault-token. ESO only ever syncs the 13 leaves below, so grant read on
# exactly those (data + metadata). renew-self / lookup-self come from the
# token's `default` policy. Any new ExternalSecret leaf must be added here.

path "secret/data/hippius-compute/edge-gateway/mtls" { capabilities = ["read"] }
path "secret/data/hippius-compute/edge-gateway/order-signing" { capabilities = ["read"] }
path "secret/data/hippius-compute/edge-gateway/vali-ingest-token" { capabilities = ["read"] }
path "secret/data/hippius-compute/ghcr" { capabilities = ["read"] }
path "secret/data/hippius-compute/kbs" { capabilities = ["read"] }
path "secret/data/hippius-compute/kbs-vault-broker" { capabilities = ["read"] }
# RA-KBS-M1 — the broker's TLS server cert+key (broker-tls) and the KBS's
# pin of it (broker-ca) both read `cert`/`key` from this leaf.
path "secret/data/hippius-compute/kbs-vault-broker/tls" { capabilities = ["read"] }
path "secret/data/hippius-compute/kbs/vek" { capabilities = ["read"] }
path "secret/data/hippius-compute/observability/alertmanager" { capabilities = ["read"] }
path "secret/data/hippius-compute/observability/grafana" { capabilities = ["read"] }
path "secret/data/hippius-compute/vali" { capabilities = ["read"] }
path "secret/data/hippius-compute/vali/netbird" { capabilities = ["read"] }
path "secret/data/hippius-compute/vali/s3" { capabilities = ["read"] }
# Synthetic-monitor full-tier orchestration-root ServiceToken — ESO syncs
# it into the `vali-synthetic-monitor` Secret (external-secret-synthetic).
path "secret/data/hippius-compute/vali/synthetic-monitor" { capabilities = ["read"] }

path "secret/metadata/hippius-compute/edge-gateway/mtls" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/edge-gateway/order-signing" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/edge-gateway/vali-ingest-token" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/ghcr" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/kbs" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/kbs-vault-broker" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/kbs-vault-broker/tls" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/kbs/vek" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/observability/alertmanager" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/observability/grafana" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/vali" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/vali/netbird" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/vali/s3" { capabilities = ["read"] }
path "secret/metadata/hippius-compute/vali/synthetic-monitor" { capabilities = ["read"] }
