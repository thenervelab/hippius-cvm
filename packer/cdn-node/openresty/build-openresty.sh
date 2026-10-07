#!/usr/bin/env bash
# Build the cdn-node OpenResty tree reproducibly (CDN plan I2).
#
#   build-openresty.sh <output.tar.gz> [download-cache-dir]
#
# - Sources: versions.env (versioned URLs, SHA-256 checked before use).
#   A download cache directory may already hold the tarballs (CI cache,
#   offline builds); a cached tarball is re-hashed before it is used.
# - OpenSSL, PCRE2 and zlib are compiled in statically, so the tree needs
#   nothing from the guest but glibc. It installs under /opt/openresty.
# - Reproducible: the build runs in a FIXED directory (BUILD_ROOT, default
#   /tmp/hippius-openresty-build, emptied first) because configure
#   arguments and compiler flags end up in the binary; SOURCE_DATE_EPOCH
#   pins every embedded date and every tar entry; tar ordering, owners and
#   gzip headers are normalised. Same sources + same toolchain image =
#   same bytes.
# - Brotli is not built (see versions.env).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: build-openresty.sh <output.tar.gz> [download-cache-dir]}"
cache="${2:-}"
# shellcheck source=versions.env
source "${here}/versions.env"
export SOURCE_DATE_EPOCH

root="${BUILD_ROOT:-/tmp/hippius-openresty-build}"
case "$root" in
  /tmp/?*|/build) ;;
  *) echo "build-openresty: BUILD_ROOT must be /build or under /tmp (it is emptied)" >&2; exit 2 ;;
esac
if [ -d "$root" ]; then
  find "$root" -mindepth 1 -delete
fi
mkdir -p "$root/src" "$root/stage"

fetch() { # name url sha256
  local name="$1" url="$2" sum="$3" base file
  base="$(basename "$url")"
  file="$root/src/$base"
  if [ -n "$cache" ] && [ -f "$cache/$base" ]; then
    cp "$cache/$base" "$file"
  else
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 -o "$file" "$url"
  fi
  if ! echo "${sum}  ${file}" | sha256sum -c --status -; then
    echo "build-openresty: ${name} sha256 mismatch for ${url}" >&2
    exit 1
  fi
  if [ -n "$cache" ] && [ ! -f "$cache/$base" ]; then
    mkdir -p "$cache"
    cp "$file" "$cache/$base"
  fi
  tar -xzf "$file" -C "$root/src"
}

fetch openresty "$OPENRESTY_URL" "$OPENRESTY_SHA256"
fetch openssl "$OPENSSL_URL" "$OPENSSL_SHA256"
fetch pcre2 "$PCRE2_URL" "$PCRE2_SHA256"
fetch zlib "$ZLIB_URL" "$ZLIB_SHA256"

src="$root/src"
map="-ffile-prefix-map=${root}=/build"
jobs="$(nproc)"
cd "$src/openresty-${OPENRESTY_VERSION}"
./configure \
  --prefix=/opt/openresty \
  --with-cc-opt="-O2 -g0 ${map} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC" \
  --with-ld-opt="-Wl,-z,relro -Wl,-z,now -Wl,--build-id=none" \
  --with-luajit-xcflags="${map}" \
  --with-openssl="$src/openssl-${OPENSSL_VERSION}" \
  --with-openssl-opt="no-shared no-tests no-docs ${map}" \
  --with-pcre="$src/pcre2-${PCRE2_VERSION}" \
  --with-pcre-jit \
  --with-zlib="$src/zlib-${ZLIB_VERSION}" \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_slice_module \
  --without-http_redis2_module \
  --without-http_memc_module \
  --without-http_rds_json_module \
  --without-http_rds_csv_module \
  --without-lua_redis_parser \
  --without-lua_rds_parser \
  --without-mail_pop3_module \
  --without-mail_imap_module \
  --without-mail_smtp_module \
  -j"$jobs"
make -j"$jobs"
make install DESTDIR="$root/stage"

# Keep only what a node runs: no perl docs, no perl-based tools. The
# `resty` CLI stays for the CI tests but is not needed at runtime.
tree="$root/stage/opt/openresty"
for f in pod bin/restydoc bin/restydoc-index bin/opm bin/nginx-xml2pod bin/md2pod.pl; do
  if [ -e "$tree/$f" ]; then
    find "$tree/$f" -depth -delete
  fi
done
strip --strip-unneeded "$tree/nginx/sbin/nginx"
find "$root/stage" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

mkdir -p "$(dirname "$out")"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -C "$root/stage" -cf - opt | gzip -n -9 > "$out"
sha256sum "$out" | awk '{print $1}' > "${out}.sha256"
echo "build-openresty: $(cat "${out}.sha256")  ${out}"
