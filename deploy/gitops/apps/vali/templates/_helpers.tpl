{{/*
Fleet labels carried by every resource in this chart (locked #1 +
apps/README conventions). `part-of` / `managed-by` are mandatory.
*/}}
{{- define "vali.labels" -}}
app.kubernetes.io/part-of: hippius-compute
app.kubernetes.io/managed-by: argocd
{{- end -}}

{{/*
Broad `name: vali` selector — matches BOTH the vali Deployment pods and
the django-migrations Job pod. Used only where both must be selected
together: the vali CiliumNetworkPolicy endpoint selector (both need the
same Postgres + DNS egress) and the Postgres CNP "ingress from vali"
rule (both connect to Postgres). Never add a churning label.
*/}}
{{- define "vali.valiSelector" -}}
app.kubernetes.io/name: vali
{{- end -}}

{{/*
Precise selector for the vali Deployment's web pods ONLY — `name: vali`
plus `component: orchestration`, which the migration Job pod
(`component: migrations`) does NOT carry. Used by the Deployment
selector, the Service selector, and the PDB selector: a Service must
not route to the short-lived migrate pod, and a PDB whose selector
catches a Job pod fails with `CalculateExpectedPodCountFailed` (a Job
has no `scale` subresource) and reports the app Degraded.
*/}}
{{- define "vali.valiWebSelector" -}}
app.kubernetes.io/name: vali
app.kubernetes.io/component: orchestration
{{- end -}}

{{/*
Stable selector label for the Postgres workload.
*/}}
{{- define "vali.postgresSelector" -}}
app.kubernetes.io/name: postgres
{{- end -}}

{{/*
Vault `jwt`-auth wiring (M-k8sauth, #94).

Every vali workload that talks to Vault includes these three snippets.
They are a named template rather than copy-paste because the audience,
the mount path and the role must agree across 7 workloads AND with the
Vault-side role's `bound_audiences` — a drift in any one of them is an
auth failure that only shows up at runtime.

`vali.vaultAuthEnv` — points the client at the login mount + role.
`vali.vaultTokenVolume` / `vali.vaultTokenVolumeMount` — the PROJECTED
ServiceAccount token, audience `vault`. Deliberately not the default
API-audience token: Vault pins `bound_audiences=["vault"]`, so this
credential cannot be replayed against the Kubernetes API (and the API
token is rejected by Vault — verified live, HTTP 400).

THE THREE ARE ONE UNIT. `vaultAuthEnv` without `vaultTokenVolumeMount`
is the worst shape available: the process is TOLD to authenticate with a
projected token that is not there, so it fails closed at the first Vault
call — and, in a workload whose Vault use is at the END of a long job
(the full synthetic monitor's crypto-erase verify), only after the rest
of the work is already done. That exact asymmetry ran in production from
2026-08-09: both synthetic-monitor CronJobs carried the env AND the
`vault-sa-token` volume, but the container had no volumeMount, so
`/var/run/secrets/vault/token` did not exist. `test_vault_auth_chart.py`
now asserts every rendered container that carries
`VALI_VAULT_JWT_TOKEN_PATH` also mounts a projected token AT that path.
*/}}
{{- define "vali.vaultAuthEnv" -}}
{{- if .Values.vaultAuth.jwt.enabled }}
- name: VALI_VAULT_JWT_ROLE
  value: {{ .Values.vaultAuth.jwt.role | quote }}
- name: VALI_VAULT_JWT_AUTH_PATH
  value: {{ .Values.vaultAuth.jwt.authPath | quote }}
- name: VALI_VAULT_JWT_TOKEN_PATH
  value: {{ printf "%s/token" .Values.vaultAuth.jwt.mountPath | quote }}
{{- end }}
{{- end -}}

{{- define "vali.vaultTokenVolume" -}}
{{- if .Values.vaultAuth.jwt.enabled }}
- name: vault-sa-token
  projected:
    sources:
      - serviceAccountToken:
          path: token
          audience: {{ .Values.vaultAuth.jwt.audience | quote }}
          expirationSeconds: {{ .Values.vaultAuth.jwt.expirationSeconds }}
{{- end }}
{{- end -}}

{{- define "vali.vaultTokenVolumeMount" -}}
{{- if .Values.vaultAuth.jwt.enabled }}
- name: vault-sa-token
  mountPath: {{ .Values.vaultAuth.jwt.mountPath | quote }}
  readOnly: true
{{- end }}
{{- end -}}

{{/*
KBS admin mTLS — vali's CLIENT identity on the lifecycle admin hop.

The KBS admin API's only authentication is mTLS at the listener; these
two snippets put vali's leaf + key + the pinned server CA on disk at
`kbsAdminMtls.mountPath`, which is what `VALI_KBS_ADMIN_CLIENT_CERT` /
`_CLIENT_KEY` / `_CACERT` in the ConfigMap point at.

A named template rather than copy-paste because FIVE workloads reach the
admin API (web, launch-tick, orchestration-tick, and both synthetic
CronJobs) and the mount path must agree with the ConfigMap in all of
them. A workload that carries the env but not the volume fails closed at
its first admin call — `kbs_admin_tls` refuses to dial when the files
are absent — which is the safe direction but is a runtime-only failure,
exactly the asymmetry that bit the Vault token mount.

Gated on `secretName` so the chart renders unchanged until the operator
has provisioned the PKI. NOTE the asymmetry with the KBS side: mounting
material on VALI enables nothing by itself (vali stays plaintext until
its URL is flipped to https), which is precisely what makes the cutover
orderable.
*/}}
{{- define "vali.kbsAdminTlsVolume" -}}
{{- if .Values.kbsAdminMtls.secretName }}
- name: kbs-admin-tls
  secret:
    secretName: {{ .Values.kbsAdminMtls.secretName | quote }}
    defaultMode: 0400
{{- end }}
{{- end -}}

{{- define "vali.kbsAdminTlsVolumeMount" -}}
{{- if .Values.kbsAdminMtls.secretName }}
- name: kbs-admin-tls
  mountPath: {{ .Values.kbsAdminMtls.mountPath | quote }}
  readOnly: true
{{- end }}
{{- end -}}

{{/*
`vali.vaultStaticTokenEnv` — the PRE-migration static `VAULT_TOKEN`,
rendered ONLY while jwt auth is OFF (#94 Phase 5).

The `vali-vault` Secret no longer HAS a `token` key: the static
`vali-orchestrator` token was revoked once every workload moved to
`auth/jwt/login`. A `secretKeyRef` to an absent key is not a soft
failure — the kubelet refuses to start the container
(`CreateContainerConfigError: couldn't find key token in Secret
vali/vali-vault`), so a chart that keeps the reference unconditionally
cannot be applied AT ALL. That is why the live objects were hand-patched
instead of synced, and hand-patching is how the CronJobs lost their
volumeMount.

Gating on `not jwt.enabled` keeps the documented rollback intact
(`vaultAuth.jwt.enabled: false` ⇒ the static token comes back, and the
operator re-stages the key) while making the jwt-on chart — the one that
matches production — applyable. This is NOT a re-introduction of a
static token on the live path: with `jwt.enabled: true` it renders
NOTHING.
*/}}
{{- define "vali.vaultStaticTokenEnv" -}}
{{- if not .Values.vaultAuth.jwt.enabled }}
- name: VAULT_TOKEN
  valueFrom:
    secretKeyRef:
      name: vali-vault
      key: token
{{- end }}
{{- end -}}

{{/*
Live VM backups (`apps.backup`). Renders NOTHING unless
`vmBackup.credentials.enabled` — so the chart change is inert for every
image until someone opts in. The backup bucket has its OWN object-level
key (Secret `vmBackup.credentials.secretName`, default `vali-backup-s3`:
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / ENDPOINT_URL / BUCKET), never
the shared `vali-s3` images key. Every ref is `optional` so a pod still
starts when the Secret is absent; vali then refuses backup work loudly
(`backup-unavailable`). `vmBackup.enabled` additionally turns the backup
tick on (VALI_BACKUP_ENABLED); `vmBackup.restoreEnabled` opens
`POST /v1/vm/<id>/restore` (VALI_RESTORE_ENABLED), and
`vmBackup.failoverManualEnabled` `POST /v1/vm/<id>/failover`
(VALI_FAILOVER_MANUAL_ENABLED), and `vmBackup.restoreRollbackEnabled` restores
of points of an earlier boot (VALI_RESTORE_ROLLBACK_ENABLED).
*/}}
{{- define "vali.backupEnv" -}}
{{- if .Values.vmBackup.credentials.enabled }}
{{- $secret := .Values.vmBackup.credentials.secretName }}
- name: VALI_BACKUP_S3_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: AWS_ACCESS_KEY_ID
      optional: true
- name: VALI_BACKUP_S3_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: AWS_SECRET_ACCESS_KEY
      optional: true
- name: VALI_BACKUP_S3_ENDPOINT_URL
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: ENDPOINT_URL
      optional: true
- name: VALI_BACKUP_BUCKET
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: BUCKET
      optional: true
{{- if .Values.vmBackup.enabled }}
- name: VALI_BACKUP_ENABLED
  value: "true"
{{- end }}
{{- if .Values.vmBackup.restoreEnabled }}
- name: VALI_RESTORE_ENABLED
  value: "true"
{{- end }}
{{- if .Values.vmBackup.failoverManualEnabled }}
- name: VALI_FAILOVER_MANUAL_ENABLED
  value: "true"
{{- end }}
{{- if .Values.vmBackup.restoreRollbackEnabled }}
- name: VALI_RESTORE_ROLLBACK_ENABLED
  value: "true"
{{- end }}
{{- end }}
{{- end }}
