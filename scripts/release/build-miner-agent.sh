#!/usr/bin/env bash
# Builds the released hippius-miner-agent binary for <tag> into <out dir>:
#
#   hippius-miner-agent-x86_64-linux-gnu   the binary, release tag compiled in
#   SHA256SUMS                             sha256 of the binary
#   BUILD-INFO.txt                         how to rebuild it byte for byte
#
# Run from the repository root of a clean checkout of the tag. The
# release workflow (.github/workflows/miner-agent-release.yml) runs it
# twice, in two different checkout directories, and refuses to publish
# unless both produce the same bytes.
#
#   scripts/release/build-miner-agent.sh v2026.10.08 dist
set -euo pipefail

TAG="${1:?usage: build-miner-agent.sh <vYYYY.MM.DD[.N]> <out dir>}"
OUT="${2:?usage: build-miner-agent.sh <vYYYY.MM.DD[.N]> <out dir>}"
ASSET="hippius-miner-agent-x86_64-linux-gnu"

# The miner-side updater accepts exactly this shape and orders it as
# (YYYY, MM, DD, N); publishing anything else would strand the fleet.
[[ "$TAG" =~ ^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[1-9][0-9]{0,2})?$ ]] \
    || { echo "error: tag '$TAG' is not vYYYY.MM.DD[.N]" >&2; exit 1; }

CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$CARGO_HOME=/cargo"
export HIPPIUS_RELEASE_TAG="$TAG"
cargo build --release --locked -p hippius-miner-agent --features snp --bin hippius-miner-agent

mkdir -p "$OUT"
cp target/release/hippius-miner-agent "$OUT/$ASSET"
BIN="$OUT/$ASSET"

# Smoke: the tag is compiled in, and the snp feature is on (without it
# `serve` fails `snp-feature-disabled` before it ever reads the config).
crate_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' binaries/miner-agent/Cargo.toml | head -n1)"
version="$("$BIN" --version)"
[ "$version" = "hippius-miner-agent $crate_version ($TAG)" ] \
    || { echo "error: --version printed '$version', expected the tag $TAG" >&2; exit 1; }
set +e
serve_err="$("$BIN" serve --config /nonexistent/config.toml 2>&1)"
serve_rc=$?
set -e
if [ "$serve_rc" = 0 ] || ! grep -q 'config-read' <<<"$serve_err" || grep -q 'snp-feature-disabled' <<<"$serve_err"; then
    echo "error: serve smoke failed (rc=$serve_rc): $serve_err" >&2
    exit 1
fi

(cd "$OUT" && sha256sum "$ASSET" >SHA256SUMS)
sha="$(cut -d' ' -f1 "$OUT/SHA256SUMS")"

cat >"$OUT/BUILD-INFO.txt" <<EOF
hippius-miner-agent — build information

Release tag:      $TAG
Source:           ${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-thenervelab/hippius-cvm}
Commit:           $(git rev-parse HEAD)
Workflow run:     ${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-thenervelab/hippius-cvm}/actions/runs/${GITHUB_RUN_ID:-local}
Crate version:    $version
Features:         snp
Profile:          release (Cargo.lock honoured: --locked)

Toolchain:        $(rustc --version)
                  $(cargo --version)
                  (pinned by rust-toolchain.toml)
Build host:       $(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release), $(uname -m)
                  $(ldd --version | head -n1)
                  OpenSSL dev headers: libssl-dev $(dpkg-query -W -f='${Version}' libssl-dev 2>/dev/null || echo unknown)
                  Linker: $(ld --version | head -n1)

Build command (from the repository root, clean checkout of the commit above):
  CARGO_INCREMENTAL=0 HIPPIUS_RELEASE_TAG=$TAG \\
  RUSTFLAGS="--remap-path-prefix=\$PWD=/build --remap-path-prefix=\${CARGO_HOME:-\$HOME/.cargo}=/cargo" \\
  cargo build --release --locked -p hippius-miner-agent --features snp --bin hippius-miner-agent
Output:           target/release/hippius-miner-agent

The workflow built this twice, in two checkout directories, and got the
same bytes. A byte-identical rebuild elsewhere also needs the same
toolchain and the same distro packages (linker, OpenSSL headers).

Binary:           $ASSET
SHA-256:          $sha
Size:             $(stat -c %s "$BIN") bytes

Provenance: $ASSET.sigstore.json is the GitHub build-provenance
attestation of this binary. Verify it with:
  cosign verify-blob-attestation --bundle $ASSET.sigstore.json \\
    --type https://slsa.dev/provenance/v1 \\
    --certificate-identity https://github.com/thenervelab/hippius-cvm/.github/workflows/miner-agent-release.yml@refs/tags/$TAG \\
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
    $ASSET
EOF

echo "built $ASSET $TAG sha256=$sha"
