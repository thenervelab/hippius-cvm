#!/usr/bin/env bash
# Fetch the pinned GeoIP database (geoip.env) for the cdn-node image.
#
#   fetch-geoip.sh <out-dir>
#
# Writes <out-dir>/dbip-country-lite.mmdb and <out-dir>/VERSION
# (dbip-country-lite-YYYY-MM). Run by the tenant-baker image build; the
# cdn-node installer stages both into the image.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: fetch-geoip.sh <out-dir>}"
die() { echo "fetch-geoip: $*" >&2; exit 2; }

# shellcheck source=geoip.env
. "${here}/geoip.env"
month="${DBIP_COUNTRY_LITE_MONTH:-}"
mirror="${DBIP_COUNTRY_LITE_MIRROR_URL:-}"
url="${DBIP_COUNTRY_LITE_URL:-}"
sum="${DBIP_COUNTRY_LITE_SHA256:-}"
[[ "${month}" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] || die "bad DBIP_COUNTRY_LITE_MONTH '${month}'"
[[ "${mirror}" == "https://s3.hippius.com/hippius-compute-images/geoip/dbip-country-lite-${month}.mmdb.gz" ]] \
    || die "DBIP_COUNTRY_LITE_MIRROR_URL must be the ${month} file of the mirror (got '${mirror}')"
[[ "${url}" == "https://download.db-ip.com/free/dbip-country-lite-${month}.mmdb.gz" ]] \
    || die "DBIP_COUNTRY_LITE_URL must be the ${month} file of download.db-ip.com (got '${url}')"
[[ "${sum}" =~ ^[0-9a-f]{64}$ ]] || die "bad DBIP_COUNTRY_LITE_SHA256"

tmp="$(mktemp -d)"
trap 'rm -f "${tmp}/db.gz"; rmdir "${tmp}"' EXIT
# The mirror first, then DB-IP; each copy must match the one pinned sha256.
got=""
for src in "${mirror}" "${url}"; do
    rm -f "${tmp}/db.gz"
    if ! curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 5 -o "${tmp}/db.gz" "${src}"; then
        echo "fetch-geoip: cannot download ${src}" >&2
        continue
    fi
    if ! echo "${sum}  ${tmp}/db.gz" | sha256sum -c --quiet - >/dev/null 2>&1; then
        echo "fetch-geoip: ${src}: sha256 does not match geoip.env, not used" >&2
        continue
    fi
    got="${src}"
    break
done
[[ -n "${got}" ]] \
    || die "no copy of dbip-country-lite-${month} matches geoip.env (mirror missing? DB-IP serves only the current and the previous month)"
mkdir -p "${out}"
gunzip -c "${tmp}/db.gz" > "${out}/dbip-country-lite.mmdb.new"
mv "${out}/dbip-country-lite.mmdb.new" "${out}/dbip-country-lite.mmdb"
printf 'dbip-country-lite-%s\n' "${month}" > "${out}/VERSION"
echo "fetch-geoip: dbip-country-lite-${month} ($(sha256sum "${out}/dbip-country-lite.mmdb" | cut -c1-12)) from ${got}"
