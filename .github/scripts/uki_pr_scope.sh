#!/usr/bin/env bash
# Decide whether a pull request can move a measured UKI's launch digest.
#
# usage: uki_pr_scope.sh <base-sha> <sde-dir> <packages> <extra-paths>
#
#   <base-sha>     the PR base commit; the PR's changes are `git diff <base-sha> HEAD`
#   <sde-dir>      the directory the UKI Makefile derives SOURCE_DATE_EPOCH from
#   <packages>     space-separated cargo packages the UKI Dockerfile builds;
#                  `pkg+feat` builds `pkg` with `--features feat`
#   <extra-paths>  space-separated repo paths that also feed the build
#                  (lockfiles, the workflow itself, the KAT, ...)
#
# Writes `in_scope=true|false` and `sde_touched=true|false` to stdout, in
# `$GITHUB_OUTPUT` form.
#
# The workspace crates the measured binaries link are derived from
# `cargo tree`, not listed by hand: the KAT went stale for months because
# a change to `kbs-core` moves the agent-initramfs bytes, and no hand-kept
# list would have stayed in step with the dependency graph.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <base-sha> <sde-dir> <packages> <extra-paths>" >&2
  exit 2
fi
base_sha="$1"
sde_dir="${2%/}"
packages="$3"
extra_paths="$4"

root="$(git rev-parse --show-toplevel)"

inputs=("$sde_dir")
for p in $extra_paths; do
  inputs+=("${p%/}")
done
for spec in $packages; do
  pkg="${spec%%+*}"
  features=()
  if [ "$spec" != "$pkg" ]; then
    features=(--features "${spec#*+}")
  fi
  # Captured before parsing so a failing `cargo tree` aborts the script
  # instead of silently yielding an empty dependency set.
  tree="$(cargo tree -p "$pkg" "${features[@]}" -e normal,build --prefix none)"
  # Workspace members and path dependencies print their absolute source
  # directory in parentheses; registry crates do not.
  local_dirs="$(grep -o '(/[^)]*)' <<< "$tree" | tr -d '()' | sort -u)"
  if [ -z "$local_dirs" ]; then
    echo "::error::cargo tree -p ${pkg} listed no local crates — refusing to guess the scope." >&2
    exit 1
  fi
  while IFS= read -r dir; do
    case "$dir" in
      "$root"/*) inputs+=("${dir#"$root"/}") ;;
    esac
  done <<< "$local_dirs"
done

changed="$(git diff --name-only "$base_sha" HEAD)"

in_scope=false
sde_touched=false
while IFS= read -r f; do
  [ -n "$f" ] || continue
  for dir in "${inputs[@]}"; do
    if [ "$f" = "$dir" ] || [[ "$f" == "$dir"/* ]]; then
      echo "measurement input changed: $f (under $dir)" >&2
      in_scope=true
      break
    fi
  done
  if [[ "$f" == "$sde_dir"/* ]]; then
    sde_touched=true
  fi
done <<< "$changed"

echo "in_scope=${in_scope}"
echo "sde_touched=${sde_touched}"
