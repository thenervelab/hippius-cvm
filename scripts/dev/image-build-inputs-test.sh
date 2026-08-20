#!/usr/bin/env bash
# image-build-inputs-test.sh — every workspace crate an image's Dockerfile
# actually compiles into that image must be covered by that image workflow's
# `paths:` filter.
#
# Why this exists: `.github/workflows/kbs-image.yml` hand-listed its build
# inputs as binaries/kbs-server + kbs-core + hippius-types + Cargo.{toml,lock}.
# `kbs-transport/` was never on that list — and `kbs-transport/src/
# admin_handler.rs` is where the ENTIRE KBS admin router is registered
# (/v1/admin/volume-stamp, reset-volume-stamp-suppression,
# arm-boot-counter-resync, allowlist/reload, …). A change confined to that
# crate therefore produced a green CI run, a merged PR, and NO NEW IMAGE. The
# fix simply never shipped, and nothing anywhere said so. Same for
# `vendor/sev`, the `[patch.crates-io]` in-tree copy every SNP-linking image
# builds: the file operators edit to add a new EPYC generation
# (vendor/sev/src/measurement/vcpu_types.rs) rebuilt NOTHING.
#
# The shape is this repo's most repeated defect — #908 all over again: a thing
# is declared in one place and not wired in the other, and every test that
# exercises the declared half passes. Appending the missing crate to the list
# fixes today and rots tomorrow, because the list is hand-maintained and the
# dependency graph is not. So the pin has to be the RELATIONSHIP — the
# Dockerfile compiles package P ⇒ every in-tree crate P transitively depends
# on is in that workflow's `paths:` — and the left-hand side has to be DERIVED
# (`cargo metadata`), never transcribed.
#
# Nothing here is hand-maintained: the workflows are globbed, each one's
# Dockerfile is read out of its own `docker/build-push-action` step, the
# packages are read out of that Dockerfile's `cargo build` lines, and the
# closure comes from `cargo metadata`. Add a crate to a dependency graph and
# this check knows about it on the next run.
#
# Requires cargo + jq. On a box without them this SKIPS with a clear message
# locally and FAILS in CI — a green tick that proved nothing is worse than a
# skip that says so.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
WORKFLOWS="${ROOT}/.github/workflows"

for tool in cargo jq; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        if [[ -n "${CI:-}" ]]; then
            echo "image-build-inputs: ${tool} is not installed and CI is set — FAIL (the check cannot be vacuous in CI)"
            exit 1
        fi
        echo "image-build-inputs: ${tool} not installed — SKIP (local)"
        exit 0
    fi
done
[[ -d "${WORKFLOWS}" ]] || { echo "image-build-inputs: ${WORKFLOWS} not found"; exit 1; }

FAILED=0
ok()  { echo "image-build-inputs: OK — $1"; }
bad() { echo "image-build-inputs: FAIL — $1"; FAILED=1; }

# ── the dependency graph, derived once ──────────────────────────────
#
# `--all-features` deliberately: features gate optional path deps
# (miner-agent's `snp`, agent-initramfs's `cryptsetup`), and the several
# Dockerfiles that pass `--features` would each resolve a different subgraph.
# A path filter may over-cover (a needless rebuild) but must never under-cover,
# so the closure is taken over the union.
#
# `--locked` deliberately omitted: enabling features forces a re-resolve, and
# the vendored `thebrain` dep `pallet-staking-reward-fn` has a Cargo.toml the
# current strict cargo rejects mid-resolve — fatal under `--locked`, harmless
# without it (see the same rationale in ci.yml's `packer-f3` job).
META="$(mktemp)"
CLOSURE_JQ="$(mktemp)"
trap 'rm -f "${META}" "${CLOSURE_JQ}"' EXIT

if ! (cd "${ROOT}" && cargo metadata --format-version 1 --all-features >"${META}" 2>/dev/null); then
    echo "image-build-inputs: cargo metadata failed — FAIL (cannot derive the build-input set)"
    exit 1
fi

cat >"${CLOSURE_JQ}" <<'JQ'
. as $m
| ($m.resolve.nodes | INDEX(.id)) as $nodes
| ($m.packages | INDEX(.id)) as $pkgs
| $m.workspace_root as $wsroot
| ($names | split(",")) as $rootnames
# "Local" = a package whose manifest lives inside this repo. That is the set a
# `paths:` filter can possibly react to, and it is WIDER than the workspace
# members: `[patch.crates-io] sev = { path = "vendor/sev" }` is in-tree too.
| def islocal($id): ($id | startswith("path+file://" + $wsroot));
  def closure($frontier; $seen):
    if ($frontier | length) == 0 then $seen
    else
      ( [ $frontier[]
          | ($nodes[.].deps // [])[]
          # Normal + build deps only. A dev-dependency is compiled for
          # `cargo test`, never into the released binary, so it is not an
          # image build input.
          | select(any(.dep_kinds[]?; .kind == null or .kind == "build"))
          | .pkg
          | select(islocal(.))
        ] | unique | map(select(. as $x | $seen | index($x) | not)) ) as $next
      | closure($next; (($seen + $next) | unique))
    end;
  ( [ $m.packages[] | select(.name | IN($rootnames[])) | .id ] ) as $rootids
  | if ($rootids | length) != ($rootnames | length)
    then error("unknown package name in: " + $names)
    else . end
  | closure($rootids; $rootids)
  | map($pkgs[.] | (.manifest_path | sub("^" + $wsroot + "/"; "") | sub("/Cargo.toml$"; "")))
  | unique
  | .[]
JQ

# bin-target name -> owning package name, for the Dockerfiles that say
# `--bin X` rather than `-p X`.
BIN_MAP="$(jq -r '
    .workspace_root as $r
    | .packages[]
    | select(.id | startswith("path+file://" + $r))
    | . as $p
    | .targets[] | select(.kind | index("bin"))
    | .name + " " + $p.name
' "${META}")"

PKG_NAMES="$(jq -r '
    .workspace_root as $r
    | .packages[] | select(.id | startswith("path+file://" + $r)) | .name
' "${META}")"

# ── workflow parsing ────────────────────────────────────────────────

# The `paths:` list of one trigger block (`push` / `pull_request`) inside the
# top-level `on:` mapping.
workflow_paths() {
    local wf="$1" block="$2"
    awk -v blk="${block}" '
        /^on:/            { inon = 1; next }
        /^[A-Za-z]/       { inon = 0; inblk = 0; inp = 0 }
        inon && $0 ~ "^  " blk ":[[:space:]]*$" { inblk = 1; next }
        inon && /^  [A-Za-z_]+:/ { inblk = 0; inp = 0 }
        inblk && /^    paths:[[:space:]]*$/ { inp = 1; next }
        inblk && /^    [A-Za-z_]+:/ { inp = 0 }
        inp && /^      - / {
            line = $0
            sub(/^      - /, "", line)
            gsub(/"/, "", line)
            print line
        }
    ' "${wf}"
}

# The Dockerfile a workflow builds (from its docker/build-push-action `file:`).
workflow_dockerfile() {
    grep -oE '^[[:space:]]*file:[[:space:]]*[^[:space:]]+' "$1" 2>/dev/null \
        | head -n1 | awk '{print $2}' || true
}

# Its build CONTEXT — the directory a Dockerfile's COPY sources are relative
# to. Repo root (`.`) for most, `deploy/epoch-closer` for the epoch closer.
workflow_context() {
    grep -oE '^[[:space:]]*context:[[:space:]]*[^[:space:]]+' "$1" 2>/dev/null \
        | head -n1 | awk '{print $2}' || true
}

# Packages a Dockerfile compiles. Comments are stripped first — the
# tenant-baker Dockerfile documents `cargo build --release --bin
# hippius-agent-initramfs` in prose, and a check that believed prose would
# pass or fail for the wrong reason.
dockerfile_packages() {
    local df="$1"
    sed -e 's/[[:space:]]*#.*$//' "${df}" \
        | sed -e ':a' -e '/\\$/{N;s/\\\n[[:space:]]*/ /;ba' -e '}' \
        | grep -E 'cargo[[:space:]]+(build|install)' \
        | grep -oE '(-p|--package|--bin)[[:space:]]+[A-Za-z0-9_-]+' \
        | awk '{print $2}' \
        | sort -u || true
}

# Host paths a Dockerfile COPYs out of the BUILD CONTEXT. `--from=<stage>`
# copies come from an earlier stage, not the repo; `COPY . <dst>` is the
# whole-context copy every builder stage does, for which the cargo closure is
# the precise answer. What is left is the assets the runtime image carries
# verbatim — the bake script, the initramfs/dracut modules, the §23 keepalive
# shim — and they are build inputs exactly like the crates.
dockerfile_context_copies() {
    local df="$1"
    sed -e 's/[[:space:]]*#.*$//' "${df}" \
        | sed -e ':a' -e '/\\$/{N;s/\\\n[[:space:]]*/ /;ba' -e '}' \
        | grep -E '^COPY[[:space:]]' \
        | grep -v -- '--from=' \
        | awk '{ for (i = 2; i < NF; i++) if ($i !~ /^--/ && $i != ".") print $i }' \
        | sed 's|/$||' \
        | sort -u || true
}

# Does any entry of the workflow's `paths:` list cover everything under DIR?
# `kbs-core/**` covers `kbs-core`; `binaries/**` would cover
# `binaries/kbs-server`; `scripts/tenant-image-bake.sh` covers neither.
covers_dir() {
    local dir="$1"; shift
    local entry base
    for entry in "$@"; do
        base="${entry%/\*\*}"
        base="${base%/\*}"
        base="${base%/}"
        [[ "${base}" == "${dir}" || "${dir}" == "${base}/"* ]] && return 0
    done
    return 1
}

covers_file() {
    local file="$1"; shift
    local entry base
    for entry in "$@"; do
        base="${entry%/\*\*}"
        base="${base%/\*}"
        base="${base%/}"
        [[ "${base}" == "${file}" || "${file}" == "${base}/"* ]] && return 0
    done
    return 1
}

# ── the check ───────────────────────────────────────────────────────

CHECKED_WORKFLOWS=0
TOTAL_COVERINGS=0

for wf in "${WORKFLOWS}"/*.yml; do
    wfname="$(basename "${wf}")"
    dockerfile="$(workflow_dockerfile "${wf}")"
    [[ -n "${dockerfile}" ]] || continue
    if [[ ! -f "${ROOT}/${dockerfile}" ]]; then
        bad "${wfname}: builds '${dockerfile}', which does not exist"
        continue
    fi

    context="$(workflow_context "${wf}")"
    context="${context%/}"
    [[ "${context}" == "." || -z "${context}" ]] && context=""

    # The in-tree crate closure — empty for the image workflows that build no
    # Rust at all (epoch-closer, runner). Those still get the COPY / Dockerfile
    # / workflow-file / dead-entry assertions below; only the cargo half is
    # skipped.
    crates=()
    names=""
    mapfile -t pkgs < <(dockerfile_packages "${ROOT}/${dockerfile}")
    if (( ${#pkgs[@]} > 0 )); then
        # Resolve every `-p` / `--bin` name to a package name.
        resolved=()
        unresolved=0
        for name in "${pkgs[@]}"; do
            if grep -qxF "${name}" <<<"${PKG_NAMES}"; then
                resolved+=("${name}")
                continue
            fi
            owner="$(awk -v b="${name}" '$1 == b { print $2; exit }' <<<"${BIN_MAP}")"
            if [[ -n "${owner}" ]]; then
                resolved+=("${owner}")
            else
                bad "${wfname}: ${dockerfile} builds '${name}', which is neither a workspace package nor a bin target"
                unresolved=1
            fi
        done
        (( unresolved )) && continue

        names="$(printf '%s\n' "${resolved[@]}" | sort -u | paste -sd, -)"
        if ! closure="$(jq -r --arg names "${names}" -f "${CLOSURE_JQ}" "${META}")"; then
            bad "${wfname}: could not derive the dependency closure of ${names}"
            continue
        fi
        mapfile -t crates <<<"${closure}"

        # Per-workflow vacuity floor. Every image that builds Rust here builds
        # at least its own crate plus a shared one (hippius-types / kbs-core /
        # vendor/sev); a closure of one means the derivation broke, not that
        # the graph is small.
        if (( ${#crates[@]} < 2 )); then
            bad "${wfname}: derived only ${#crates[@]} in-tree crate(s) for ${names} — the derivation is not seeing the graph"
            continue
        fi
    fi

    mapfile -t push_paths < <(workflow_paths "${wf}" push)
    mapfile -t pr_paths   < <(workflow_paths "${wf}" pull_request)
    if (( ${#push_paths[@]} == 0 )); then
        bad "${wfname}: no push \`paths:\` filter parsed — either the workflow shape changed or it rebuilds on every push"
        continue
    fi
    if [[ "$(printf '%s\n' "${push_paths[@]}" | sort)" != "$(printf '%s\n' "${pr_paths[@]}" | sort)" ]]; then
        bad "${wfname}: the push and pull_request \`paths:\` lists differ — a PR would be validated against a different input set than main builds from"
    fi

    CHECKED_WORKFLOWS=$((CHECKED_WORKFLOWS + 1))
    TOTAL_COVERINGS=$((TOTAL_COVERINGS + ${#crates[@]}))
    if (( ${#crates[@]} > 0 )); then
        echo "image-build-inputs: ${wfname} → ${dockerfile} → ${names} → ${#crates[@]} in-tree crates"
    else
        echo "image-build-inputs: ${wfname} → ${dockerfile} → no cargo build (assets only)"
    fi

    for crate in "${crates[@]}"; do
        if covers_dir "${crate}" "${push_paths[@]}"; then
            ok "${wfname}: ${crate}/ is covered"
        else
            bad "${wfname}: ${crate}/ is a transitive build input of ${names} but NO \`paths:\` entry covers it — a change confined to that crate merges green and ships NO new image, silently"
        fi
    done

    while IFS= read -r asset; do
        [[ -n "${asset}" ]] || continue
        [[ -n "${context}" ]] && asset="${context}/${asset}"
        TOTAL_COVERINGS=$((TOTAL_COVERINGS + 1))
        if covers_file "${asset}" "${push_paths[@]}"; then
            ok "${wfname}: COPYed asset ${asset} is covered"
        else
            bad "${wfname}: ${dockerfile} COPYs '${asset}' out of the build context but NO \`paths:\` entry covers it — editing that asset merges green and the image keeps shipping the OLD copy"
        fi
    done < <(dockerfile_context_copies "${ROOT}/${dockerfile}")

    # The workspace manifests are build inputs of anything that compiles Rust:
    # a lockfile bump changes every binary in the image.
    if (( ${#crates[@]} > 0 )); then
        for lit in Cargo.toml Cargo.lock; do
            if printf '%s\n' "${push_paths[@]}" | grep -qxF "${lit}"; then
                ok "${wfname}: ${lit} is covered"
            else
                bad "${wfname}: ${lit} is not in \`paths:\` — a dependency bump would not rebuild the image"
            fi
        done
    fi
    if covers_file "${dockerfile}" "${push_paths[@]}"; then
        ok "${wfname}: ${dockerfile} is covered"
    else
        bad "${wfname}: its own Dockerfile ${dockerfile} is not covered by \`paths:\`"
    fi
    if covers_file ".github/workflows/${wfname}" "${push_paths[@]}"; then
        ok "${wfname}: the workflow file itself is covered"
    else
        bad "${wfname}: the workflow file itself is not in \`paths:\` — editing the build would not run it"
    fi

    # A `paths:` entry aimed at a path that does not exist is how this rots in
    # the other direction: kbs-image.yml carried `kbs-server/**` long after the
    # crate moved to `binaries/kbs-server`, which reads like coverage and is
    # not.
    for entry in "${push_paths[@]}"; do
        base="${entry%/\*\*}"
        base="${base%/\*}"
        base="${base%/}"
        [[ -e "${ROOT}/${base}" ]] || bad "${wfname}: \`paths:\` entry '${entry}' matches nothing in the tree — a dead filter that looks like coverage"
    done
done

echo "image-build-inputs: ${CHECKED_WORKFLOWS} image workflows checked, ${TOTAL_COVERINGS} build-input coverings asserted"

# Vacuity floor. Every guard above is a per-crate assertion, so a parser that
# silently returns nothing would print ALL OK while examining zero crates —
# exactly the failure `addons-digest-pin-test.sh` shipped on its first run. The
# counts are therefore part of the assertion.
MIN_WORKFLOWS=8
MIN_COVERINGS=25
if (( CHECKED_WORKFLOWS < MIN_WORKFLOWS )); then
    bad "only ${CHECKED_WORKFLOWS} image workflows examined (expected >= ${MIN_WORKFLOWS}) — the discovery step is not seeing the tree"
fi
if (( TOTAL_COVERINGS < MIN_COVERINGS )); then
    bad "only ${TOTAL_COVERINGS} build-input coverings asserted (expected >= ${MIN_COVERINGS}) — the derivation is not seeing the graph"
fi

[[ "${FAILED}" == "0" ]] && echo "image-build-inputs: ALL OK" || echo "image-build-inputs: FAILURES"
exit "${FAILED}"
