#!/usr/bin/env bash
# Fail the build if a QUIC stack is COMPILED into any workspace crate.
#
# quinn stays in Cargo.lock through reqwest's weak feature `quinn?/ring`
# without ever being built (rust-lang/cargo#10801), so the lockfile proves
# nothing: this reads the resolved build graph instead — normal
# dependencies, every target, every feature (a superset of what any binary
# is built with). A QUIC endpoint is a UDP attack surface reachable before
# any TLS identity is checked (RUSTSEC-2026-0338..0342 were all
# peer-triggerable); one entering the build must be a reviewed decision.
# hickory-* is listed on purpose: its DNS-over-QUIC sits behind a feature,
# and adding the resolver at all deserves that same look.
#
# Usage: scripts/ci/check-no-quic-stack.sh   (from the repo root)
set -euo pipefail

forbidden='^(h3|h3-[a-z0-9-]+|quinn|quinn-[a-z0-9-]+|iroh|iroh-[a-z0-9-]+|hickory-[a-z0-9-]+|[a-z0-9-]*quic(he)?(-[a-z0-9-]+)?|msquic|tquic)$'

tree="$(cargo tree --locked --workspace --all-features -e normal --target all --prefix none --format '{p}')"
# grep exits 1 on no match (the good case), 2 on an error (fatal).
found="$(printf '%s\n' "$tree" | awk '{print $1}' | { grep -E "$forbidden" || [[ $? -eq 1 ]]; } | sort -u)"

if [[ -n "$found" ]]; then
    echo "::error::a QUIC stack entered the build; review its attack surface: $(echo "$found" | tr '\n' ' ')"
    echo "Pulled in by:"
    while read -r crate; do
        cargo tree --locked --workspace --all-features -e normal --target all -i "$crate" --depth 4 || true
    done <<<"$found"
    exit 1
fi
echo "no QUIC stack in the build"
