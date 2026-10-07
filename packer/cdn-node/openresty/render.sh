#!/usr/bin/env bash
# Render the cdn-node OpenResty files.
#
#   render.sh conf <nginx.conf.in> <out> NAME=VALUE...
#       Substitute every @NAME@; fails if one is left unset. The image bake
#       (I3) renders the production values once; the tests render their own.
#   render.sh cache <out> <cache_dir> <max_size> [keys_zone_size]
#       Write the proxy_cache_path include. At node start, OpenResty's
#       ExecStartPre passes `hippius-cdn-agent cache-size` as max_size.
#   render.sh cache-auto <out> <cache_dir> <percent> [keys_zone_size]
#       The same include, max_size = <percent> (10-90) of the volume that
#       holds <cache_dir> (statvfs). The cdn-node OpenResty unit's
#       ExecStartPre (spec §5.2: 75 %, the rest is headroom).
#   render.sh placeholder <cert.pem> <key.pem>
#       nginx refuses a TLS listener without a certificate, even when
#       ssl_certificate_by_lua always replaces it. Generate a throwaway
#       self-signed pair on tmpfs at each start (never baked, never
#       presented: the Lua handler swaps it or refuses the handshake).
set -euo pipefail

die() { echo "render: $*" >&2; exit 2; }

case "${1:-}" in
  conf)
    [ $# -ge 3 ] || die "usage: render.sh conf <in> <out> NAME=VALUE..."
    in="$2"; out="$3"; shift 3
    text="$(cat "$in")"
    for kv in "$@"; do
      name="${kv%%=*}"; value="${kv#*=}"
      [[ "$name" =~ ^[A-Z0-9_]+$ ]] || die "bad name: $name"
      # Values land inside nginx directives: one token of path, address,
      # size or rate characters only. No space (an extra parameter), no
      # ";" "{" "#" (a new directive, block or comment), no "@" (a value
      # re-scanned as a placeholder), no "&" (bash replacement syntax).
      [[ "$value" =~ ^[A-Za-z0-9._/:-]+$ ]] || die "unsafe value for $name"
      text="${text//@${name}@/"${value}"}"
    done
    if left="$(grep -o '@[A-Z0-9_]*@' <<<"$text" | sort -u | tr '\n' ' ')" && [ -n "$left" ]; then
      die "unset placeholders: $left"
    fi
    printf '%s\n' "$text" > "$out"
    ;;
  cache)
    [ $# -ge 4 ] || die "usage: render.sh cache <out> <cache_dir> <max_size> [keys_zone_size]"
    out="$2"; dir="$3"; size="$4"; keys="${5:-1024m}"
    [[ "$size" =~ ^[0-9]+[kmg]?$ ]] || die "bad max_size: $size"
    [[ "$keys" =~ ^[0-9]+[kmg]?$ ]] || die "bad keys_zone size: $keys"
    [[ "$dir" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "bad cache dir: $dir"
    printf 'proxy_cache_path %s levels=1:2 keys_zone=hippius_cache:%s max_size=%s inactive=30d use_temp_path=off;\n' \
      "$dir" "$keys" "$size" > "$out"
    ;;
  cache-auto)
    [ $# -ge 4 ] || die "usage: render.sh cache-auto <out> <cache_dir> <percent> [keys_zone_size]"
    out="$2"; dir="$3"; pct="$4"; keys="${5:-1024m}"
    [[ "$pct" =~ ^[0-9]+$ ]] && (( pct >= 10 && pct <= 90 )) || die "bad percent: $pct"
    [[ "$dir" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "bad cache dir: $dir"
    read -r blocks bsize < <(stat -f -c '%b %S' "$dir") || die "statvfs failed: $dir"
    size_k=$(( blocks * bsize / 1024 * pct / 100 ))
    (( size_k > 0 )) || die "cache volume too small: $dir"
    exec "$0" cache "$out" "$dir" "${size_k}k" "$keys"
    ;;
  placeholder)
    [ $# -eq 3 ] || die "usage: render.sh placeholder <cert.pem> <key.pem>"
    umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -days 3650 -subj "/CN=placeholder.invalid" -keyout "$3" -out "$2" 2>/dev/null
    ;;
  *)
    die "usage: render.sh conf|cache|cache-auto|placeholder ..."
    ;;
esac
