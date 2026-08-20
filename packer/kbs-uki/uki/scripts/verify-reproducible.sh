#!/usr/bin/env bash
# `verify-reproducible.sh` — runs `make uki` twice + diffs.
#
# Convenience wrapper around `make uki-reproducible-check` for
# operators who prefer a script entry point.

set -euo pipefail

cd "$(dirname "$0")/.."
exec make uki-reproducible-check
