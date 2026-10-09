#!/usr/bin/env bash
# Run the cdn-node data-plane tests against an OpenResty tree.
#
#   OPENRESTY_PREFIX=/opt/openresty packer/cdn-node/openresty/tests/run.sh
#
# 1. render.sh refuses unsafe values and unset placeholders;
# 2. Lua unit tests (resty CLI);
# 3. integration tests: real nginx, mock agent, mock S3 origin.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
prefix="${OPENRESTY_PREFIX:-/opt/openresty}"
export OPENRESTY_PREFIX="$prefix"
export LD_LIBRARY_PATH="${prefix}/luajit/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

echo "== render.sh guards"
tmp="$(mktemp -d)"
trap 'find "$tmp" -mindepth 1 -delete; rmdir "$tmp"' EXIT
valid=(PREFIX=/opt/openresty PID=/run/cdn/nginx.pid TEMP_DIR=/run/cdn/tmp LUA_DIR=/opt/hippius-cdn/lua
       DOCS_DICT_SIZE=512m METER_SOCKET=/run/cdn-agent/meter.sock CACHE_DIR=/var/lib/hippius-data/cache
       S3_REGION=us-east-1 RESOLVER=127.0.0.53 CACHE_CONF=/run/cdn/cache.conf
       ORIGIN_CONF=/opt/hippius-cdn/origin.conf RATE_PER_IP=200r/s CTL_SOCKET=/run/cdn/ctl.sock
       CTL_MAX_BODY=256m LISTEN_HTTP=80 LISTEN_HTTPS=443 PLACEHOLDER_CERT=/run/cdn/placeholder.pem
       PLACEHOLDER_KEY=/run/cdn/placeholder.key BURST_PER_IP=400 CONN_PER_IP=256
       CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt GEOIP_DB=/opt/hippius-cdn/geoip/dbip-country-lite.mmdb ORIGIN_SOCKET=/run/cdn/origin.sock)
"$root/render.sh" conf "$root/nginx.conf.in" "$tmp/x.conf" "${valid[@]}"
if "$root/render.sh" conf "$root/nginx.conf.in" "$tmp/x.conf" PREFIX=/opt/openresty 2>/dev/null; then
  echo "render.sh accepted a config with unset placeholders" >&2; exit 1
fi
# Each unsafe value is the only thing wrong with an otherwise valid call
# (later NAME=VALUE pairs are ignored once the first substitution ran, so
# the unsafe one goes first).
for v in 'PID=/run/x;' 'LISTEN_HTTPS=443 ssl proxy_protocol' 'PID=/run/x#' 'PID=@PREFIX@' 'PID=a&b' 'PID=a{'; do
  if "$root/render.sh" conf "$root/nginx.conf.in" "$tmp/x.conf" "$v" "${valid[@]}" 2>/dev/null; then
    echo "render.sh accepted an unsafe value: $v" >&2; exit 1
  fi
done
if "$root/render.sh" cache "$tmp/c.conf" "/cache dir" 10m 2>/dev/null; then
  echo "render.sh accepted a cache dir with a space" >&2; exit 1
fi
"$root/render.sh" cache-auto "$tmp/auto.conf" "$tmp" 75 16m
grep -qE '^proxy_cache_path [^ ]+/objects levels=1:2 keys_zone=hippius_cache:16m max_size=[1-9][0-9]*k inactive=30d use_temp_path=off;$' "$tmp/auto.conf" \
  || { echo "render.sh cache-auto wrote: $(cat "$tmp/auto.conf")" >&2; exit 1; }
for bad in 5 95 x; do
  if "$root/render.sh" cache-auto "$tmp/auto.conf" "$tmp" "$bad" 2>/dev/null; then
    echo "render.sh cache-auto accepted percent $bad" >&2; exit 1
  fi
done
echo "ok"

echo "== GeoIP test databases"
python3 -I "$here/geoip/make_test_mmdb.py" "$tmp/geoip"
export HIPPIUS_TEST_GEOIP_DIR="$tmp/geoip"
echo "ok"

echo "== Lua unit tests"
"${prefix}/bin/resty" --nginx "${prefix}/nginx/sbin/nginx" \
  -I "${prefix}/lualib" -I "$root/lua" "$here/unit/run.lua"

if [ -n "${HIPPIUS_REAL_GEOIP_DB:-}" ]; then
  echo "== GeoIP against the real database"
  "${prefix}/bin/resty" --nginx "${prefix}/nginx/sbin/nginx" \
    -I "${prefix}/lualib" -I "$root/lua" "$here/geoip/real_db_check.lua"
fi

echo "== integration tests"
OPENRESTY_PREFIX="$prefix" python3 -I "$here/integration/test_dataplane.py"
