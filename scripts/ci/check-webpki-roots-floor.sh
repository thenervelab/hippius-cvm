#!/usr/bin/env bash
# Fail the build if a webpki-roots 1.x in Cargo.lock is below 1.0.10.
#
# .cargo/audit.toml ignores RUSTSEC-2026-0381 because the only flagged copy,
# webpki-roots 0.26.11 (pulled by ureq 2.x), is a shim that re-exports the
# webpki-roots 1.x root set. That ignore is only sound while every 1.x copy
# is >= 1.0.10, the release that dropped the distrusted emSign root. This
# check holds that premise independently of the advisory database, and
# fails if a 0.26 copy stops being the 1.x shim (any 0.26 other than
# 0.26.11, the last release). Remove it with the ignore (#1721).
#
# Usage: scripts/ci/check-webpki-roots-floor.sh   (from the repo root)
set -euo pipefail

lock="${1:-Cargo.lock}"
floor="1.0.10"

versions="$(awk '
    $0 == "name = \"webpki-roots\"" { getline; gsub(/^version = "|"$/, ""); print }
' "$lock")"

if [[ -z "$versions" ]]; then
    echo "check-webpki-roots-floor: no webpki-roots in ${lock}; drop this check and the RUSTSEC-2026-0381 ignore."
    exit 0
fi

status=0
while read -r v; do
    case "$v" in
        1.*)
            lowest="$(printf '%s\n%s\n' "$floor" "$v" | sort -V | head -n1)"
            if [[ "$lowest" != "$floor" ]]; then
                echo "::error::webpki-roots ${v} in ${lock} is below ${floor} (RUSTSEC-2026-0381); the audit.toml ignore would no longer be sound"
                status=1
            fi
            ;;
        0.26.11) ;;
        *)
            echo "::error::unexpected webpki-roots ${v} in ${lock}; the RUSTSEC-2026-0381 ignore only covers the 0.26.11 shim"
            status=1
            ;;
    esac
done <<<"$versions"

if [[ "$status" -eq 0 ]]; then
    echo "check-webpki-roots-floor: ok ($(echo "$versions" | tr '\n' ' '))"
fi
exit "$status"
