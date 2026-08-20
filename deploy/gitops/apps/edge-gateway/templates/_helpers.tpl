{{/*
Fleet labels carried by every resource in this chart (locked #1 +
apps/README conventions). `part-of` / `managed-by` are mandatory
fleet-wide.
*/}}
{{- define "edge-gateway.labels" -}}
app.kubernetes.io/name: hippius-edge-gateway
app.kubernetes.io/part-of: hippius-compute
app.kubernetes.io/managed-by: argocd
app.kubernetes.io/component: edge-gateway
{{- end -}}

{{/*
Selector labels — the STABLE subset used by the Deployment selector,
the Service selector, the PDB selector, and the CiliumNetworkPolicy
endpoint selector. Never add a churning label (version, digest) here.
*/}}
{{- define "edge-gateway.selectorLabels" -}}
app.kubernetes.io/name: hippius-edge-gateway
{{- end -}}
