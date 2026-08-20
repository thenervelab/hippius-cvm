#!/usr/bin/env bash
# addons-digest-pin-test.sh — every image the addon charts RENDER must be
# pinned by `@sha256:`.
#
# Why render and not grep: #927 was opened against the one tag-only reference
# WRITTEN in this repo (`kata/values.yaml`'s kubectlImage). Rendering found 24
# references, 14 of them mutable tags — because only three addons override any
# image at all and the rest inherit upstream subchart defaults that never
# appear in git. The worst was `quay.io/kata-containers/kata-deploy:3.31.0`
# with `imagePullPolicy: Always`: kata-deploy INSTALLS the Kata shim, QEMU,
# OVMF and the guest kernel onto the confidential node, so a registry-side
# re-tag needs no cluster access at all. It was invisible to grep precisely
# because we never overrode it.
#
# So the invariant is about what is RENDERED, and the check has to render.
#
# Requires network (the addon charts pull their upstream dependency from an
# HTTP or OCI repo per Chart.lock). On a box without network this SKIPS with a
# clear message rather than passing vacuously — a green tick that proved
# nothing is worse than a skip that says so.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDONS="${HERE}/../../deploy/gitops/addons"

if ! command -v helm >/dev/null 2>&1; then
    if [[ -n "${CI:-}" ]]; then
        echo "addons-digest-pin: helm is not installed and CI is set — FAIL (the check cannot be vacuous in CI)"
        exit 1
    fi
    echo "addons-digest-pin: helm not installed — SKIP (local)"
    exit 0
fi

# The wrapper charts pull their upstream dependency from these repos. Without
# them `helm dependency build` fails per-addon, which on the first CI run meant
# 22 of 26 references went unchecked while the job printed ALL OK.
for spec in \
    "jetstack https://charts.jetstack.io" \
    "external-secrets https://charts.external-secrets.io" \
    "cilium https://helm.cilium.io" \
    "ingress-nginx https://kubernetes.github.io/ingress-nginx" \
    "metallb https://metallb.github.io/metallb" \
    "prometheus-community https://prometheus-community.github.io/helm-charts"
do
    helm repo add ${spec} >/dev/null 2>&1 || true
done
helm repo update >/dev/null 2>&1 || true
[[ -d "${ADDONS}" ]] || { echo "addons-digest-pin: ${ADDONS} not found"; exit 1; }

# Images we deliberately do not pin, with the reason. Anything not listed here
# MUST carry a digest. Keep this list short and justified — it is the only way
# a mutable tag can survive this check.
is_allowed_unpinned() {
    case "$1" in
        # `prometheusOperator.thanosImage` renders only as inert text inside a
        # CLI flag on the operator; nothing pulls it. Recorded in #927.
        *thanos*) return 0 ;;
        *) return 1 ;;
    esac
}

FAILED=0
TOTAL=0
PINNED=0

for dir in "${ADDONS}"/*/; do
    name="$(basename "${dir}")"
    [[ -f "${dir}/Chart.yaml" ]] || continue

    if ! helm dependency build "${dir}" >/dev/null 2>&1; then
        if [[ -n "${CI:-}" ]]; then
            echo "  FAIL     ${name}: dependency build failed — in CI this is a FAILURE, not a skip"
            echo "           (a check that silently verifies 4 of 26 references and prints ALL OK"
            echo "            is worse than no check; that is exactly what this job did on its"
            echo "            first run before the repos were added below)"
            FAILED=1
        else
            echo "addons-digest-pin: ${name}: dependency build failed (no network?) — SKIP (local)"
        fi
        continue
    fi

    rendered="$(helm template "${name}" "${dir}" 2>/dev/null || true)"
    if [[ -z "${rendered}" ]]; then
        echo "addons-digest-pin: ${name}: render produced nothing — FAIL"
        FAILED=1
        continue
    fi

    # `image:` values in any rendered PodSpec-ish position.
    while IFS= read -r ref; do
        ref="${ref%\"}"; ref="${ref#\"}"
        [[ -z "${ref}" ]] && continue
        TOTAL=$((TOTAL + 1))
        if [[ "${ref}" == *"@sha256:"* ]]; then
            PINNED=$((PINNED + 1))
        elif is_allowed_unpinned "${ref}"; then
            echo "  ALLOWED  ${name}: ${ref} (documented exception)"
        else
            echo "  FAIL     ${name}: ${ref} — rendered without @sha256:, so a registry-side re-tag changes what runs"
            FAILED=1
        fi
    done < <(printf '%s\n' "${rendered}" | grep -oE '^[[:space:]]*image:[[:space:]]*.*$' | sed -E 's/^[[:space:]]*image:[[:space:]]*//' | tr -d "'" | sort -u)
done

echo "addons-digest-pin: ${PINNED}/${TOTAL} rendered image references are digest-pinned"

# Vacuity floor. The first CI run of this check rendered 4 references, found
# them all pinned, and printed ALL OK — while 22 went unexamined. A count is
# therefore part of the assertion, not just decoration.
MIN_REFS=20
if [[ -n "${CI:-}" && "${TOTAL}" -lt "${MIN_REFS}" ]]; then
    echo "addons-digest-pin: only ${TOTAL} references rendered (expected >= ${MIN_REFS}) — FAIL, the check is not seeing the tree"
    FAILED=1
fi
[[ "${FAILED}" == "0" ]] && echo "addons-digest-pin: ALL OK" || echo "addons-digest-pin: FAILURES"
exit "${FAILED}"
