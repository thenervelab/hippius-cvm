# `addons/kube-prometheus-stack` — Prometheus + Alertmanager + Grafana

PR-K14, §K (issue [#54][issue-54]) — implements slice 1 of the Phase 1
plan in tracking issue [#128][issue-128]. Installs the upstream
[`kube-prometheus-stack`][chart] community Helm chart and adds this
cluster's local overlays: a `ClusterSecretStore`-backed Grafana admin
password and Alertmanager config (Slack webhook), a NetBird-only
Grafana Ingress, the panoramic "stack overview" dashboard, and the
first set of Hippius-specific `PrometheusRule`s.

A wrapper Helm chart, same convention as the PR-K3 / PR-K11 addons
(see [`../README.md`](../README.md)).

[issue-54]: https://github.com/thenervelab/hippius-compute/issues/54
[issue-128]: https://github.com/thenervelab/hippius-compute/issues/128
[chart]: https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack

## What is deployed

| Resource | Purpose |
| --- | --- |
| Prometheus + Operator | metric ingest + service discovery (CRD-driven) |
| Alertmanager | route alerts → Slack (operators channel + deadmans channel) |
| Grafana | dashboards UI, fronted by NetBird-only Ingress at `grafana.hippius.network` |
| `kube-state-metrics`, `node-exporter`, `kubelet` ServiceMonitors | cluster-wide pod / node / volume metrics — the chart wires these out of the box |
| `ServiceMonitor` for ingress-nginx | scrape the controller's built-in exporter (enabled in the sibling addon's values.yaml in this PR) |
| `PrometheusRule/hippius-critical` | the first tier of Hippius-specific alerts (ingress 5xx spike, watchdog heartbeat) |
| `ConfigMap/hippius-dashboard-stack-overview` | the "morning-coffee" panoramic dashboard, sidecar-imported |
| `ExternalSecret/grafana-admin` | Grafana admin pw from Vault |
| `ExternalSecret/alertmanager-config` | full Alertmanager config (Slack webhook URL) from Vault |
| `Ingress/grafana` | `grafana.hippius.network` — NetBird CGNAT only, cert-manager TLS |

## What is NOT in this PR (deferred follow-ups, all tracked under #128)

| Follow-up | Scope |
| --- | --- |
| **PR-K14a** | Wire `EDGE_PEER_ENDPOINT` (StatefulSet conversion + headless Service per pod) OR add an unconditional metrics-only listener to the edge-gateway binary; then a `ServiceMonitor` and the `EdgeHaPeerDown` alert + an Edge panel row on the stack-overview dashboard. *Today the binary gates `/metrics` on `EDGE_PEER_ENDPOINT` being set (`binaries/edge-gateway/src/ha/mod.rs:34-36`), and the chart runs single-instance — so no metrics endpoint to scrape yet.* |
| **PR-K14b** | KBS `/metrics` endpoint (hand-rolled Prometheus text fmt, same pattern as the edge-gateway exporter) + ServiceMonitor + `kbs-health` dashboard + KBS release / denial / audit-depth alerts |
| **PR-K14c** | vali `/metrics` via [`django-prometheus`][dp] middleware + ServiceMonitor + `vali-state` dashboard |
| **PR-K14d** | postgres-exporter sidecar on the vali Postgres pod + Postgres dashboard |
| **PR-K14e** | miner-agent `/metrics` endpoint over NetBird + bare-metal scrape config (Prometheus reaches miner hosts via the NetBird IP from the `MinerIdentity` table — needs a static-config scrape job because miner-agent targets are NOT k8s Services) + `miner-fleet` dashboard |
| **PR-K14f** | sentinel `/metrics` + ServiceMonitor + sentinel dashboard |
| **PR-K14g** | Allowlist-epoch + audit-chain alerts (depend on KBS metrics — land after PR-K14b) |

[dp]: https://github.com/korfuri/django-prometheus

## Operator setup — Vault secrets

The chart requires two operator-provisioned Vault secrets. After this
addon syncs (the `ExternalSecret`s will sit in `SecretSyncedError`
until both exist), write the following at the `secret/` KV v2 engine
that the `hippius-vault` `ClusterSecretStore` is bound to:

```bash
# Grafana admin user + password (the chart's hard-coded keys are
# admin-user / admin-password — values.yaml maps them by those names).
vault kv put secret/hippius-compute/observability/grafana \
  admin-user=admin \
  admin-password=<long-random-string>

# Full alertmanager.yaml — including the Slack webhook URL — under
# property `alertmanager.yaml`. The full schema is documented in
# templates/external-secret-alertmanager.yaml. Minimal version below.
cat <<'EOF' > /tmp/alertmanager.yaml
route:
  receiver: slack-operators
  group_by: [alertname, severity]
  repeat_interval: 4h
  routes:
    - matchers: ['alertname="HippiusObservabilityWatchdog"']
      receiver: slack-deadmans
      repeat_interval: 1m
receivers:
  - name: slack-operators
    slack_configs:
      - api_url: https://hooks.slack.com/services/T.../B.../...
        channel: '#hippius-alerts'
        send_resolved: true
  - name: slack-deadmans
    slack_configs:
      - api_url: https://hooks.slack.com/services/T.../B.../...
        channel: '#hippius-deadmans'
        send_resolved: false
EOF

vault kv put secret/hippius-compute/observability/alertmanager \
  alertmanager.yaml=@/tmp/alertmanager.yaml

rm /tmp/alertmanager.yaml
```

The ESO `refreshInterval` is 1 h on both — operators can force an
immediate re-sync after a Vault edit:

```bash
kubectl -n observability annotate externalsecret grafana-admin       force-sync=$(date +%s) --overwrite
kubectl -n observability annotate externalsecret alertmanager-config force-sync=$(date +%s) --overwrite
```

## Post-merge smoke

After Argo CD reconciles (the `observability` namespace appears + all
pods Running):

```bash
# Targets up
kubectl -n observability port-forward svc/kube-prometheus-stack-prometheus 9090 &
curl -s 'http://localhost:9090/api/v1/query?query=up' | jq '.data.result[] | {job: .metric.job, instance: .metric.instance, up: .value[1]}'

# Watchdog firing (silence = problem)
curl -s 'http://localhost:9090/api/v1/query?query=ALERTS{alertname="HippiusObservabilityWatchdog"}' | jq '.data.result'

# Grafana over NetBird
open https://grafana.hippius.network  # log in with the Vault-provisioned admin pw
```

A synthetic ingress-5xx alert can be triggered by `kubectl scale`-ing a
backend Deployment to zero replicas under load — the
`IngressNginxHigh5xxRate` rule should reach Slack within ~5 min and
clear after the scale-back.

## Bumping the chart

```bash
helm repo update prometheus-community
# pick the new version
helm search repo prometheus-community/kube-prometheus-stack | head -3
# update Chart.yaml `version:` to the new pin, then
helm dependency update deploy/gitops/addons/kube-prometheus-stack/
git add deploy/gitops/addons/kube-prometheus-stack/Chart.{yaml,lock}
```

Bump the wrapper chart's own `version` in `Chart.yaml` alongside the
dependency bump.
