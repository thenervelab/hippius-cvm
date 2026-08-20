{{/*
Fleet labels carried by every resource in this chart (locked #1 +
apps/README conventions). `part-of` / `managed-by` are mandatory
fleet-wide.
*/}}
{{- define "kbs.labels" -}}
app.kubernetes.io/name: kbs-server
app.kubernetes.io/part-of: hippius-compute
app.kubernetes.io/managed-by: argocd
app.kubernetes.io/component: key-broker
{{- end -}}

{{/*
Selector labels — the STABLE subset used by the Deployment selector,
the Service selector, the PDB selector, and the CiliumNetworkPolicy
endpoint selector. Never add a churning label (version, digest) here.
*/}}
{{- define "kbs.selectorLabels" -}}
app.kubernetes.io/name: kbs-server
{{- end -}}
