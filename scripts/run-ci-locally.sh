#!/usr/bin/env bash
# run-ci-locally.sh — run the checks CI runs, before you push.
#
# The README has promised this script since PR #176 and it was never
# written, so anyone who followed the README's own instructions hit a
# missing file on their first contribution. This is that script.
#
# WHAT IT COVERS: the offline checks of the `rust`, `vali` and `sentinel`
# jobs in `.github/workflows/ci.yml`.
#
# The toolchain commands below are written out, because they are inline in
# the workflow and there is nothing to derive them from. The repository's
# `bash scripts/**.sh` checks are NOT written out — they are READ OUT OF
# `ci.yml` and run, whatever they happen to be today.
#
# That distinction is the whole point, and it was paid for. This script
# used to say "the command list below is copied from those jobs; if you
# change one there, change it here" — an invariant with no enforcement, of
# exactly the kind #963 removed one layer up the supply chain. It had
# already rotted, and by more than it looked: SEVENTEEN offline, REQUIRED
# repository checks were missing. Reading `ci.yml` by eye found seven of
# them; the other ten sit inside multi-line `run: |` blocks and were only
# found by deriving the list — which is its own argument for deriving it.
# Among the missing was `docs-links-test.sh`, added to that job by the
# same person who left it out of here.
#
# Proven rather than assumed —
# one broken link in `README.md` gave a full green from this script
# (10/10 ok, exit 0) and a red from CI. A contributor who ran this,
# believed it and pushed would be red for something it could have caught
# in three seconds.
#
# So the list is derived. A check added to `ci.yml` runs here the day it
# lands, with nobody remembering to mirror it.
#
# WHAT IT DOES NOT COVER, and will say so as it goes:
#   - anything needing the network, docker or a registry: the addons
#     digest-pin render, image builds, and cosign SIGNATURE verification
#     (`verify-gitops-signatures.yml` — note that the provenance
#     DECLARATION half is offline and does run here);
#   - the `packer-f3` and `audit` jobs, which need docker and a
#     network-fetched advisory database;
#   - the wasm32 no_std builds, unless you have the target installed;
#   - the workflow's inline `shellcheck` / `bash -n` / `node --check`
#     linting and the §22 allowlist KAT. These are inline `run:` blocks,
#     so the derivation below cannot see them; they are cheap and they do
#     fail CI, so run them by hand if you touched a shell script.
#
# So a green run here is "CI will probably pass", not "CI passed". It is
# the cheap filter, not the gate.
set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FAILED=0
run() {
    local label="$1"; shift
    printf '\n\033[1m── %s\033[0m\n' "${label}"
    if "$@"; then
        printf '   \033[32mok\033[0m  %s\n' "${label}"
    else
        printf '   \033[31mFAILED\033[0m  %s\n' "${label}"
        FAILED=1
    fi
}
skip() { printf '\n   \033[33mskip\033[0m  %s — %s\n' "$1" "$2"; }

# ── the repository's own checks, read out of ci.yml ──────────────────
# Seconds each, so they go first: there is no reason to find a broken
# documentation link after a twelve-minute `cargo test`.
#
# Scope, stated because it is a real limit: this sees `bash scripts/….sh`
# invocations in the offline jobs. A check added as an inline `run: |`
# block is invisible to it and stays uncovered — see the header.
WF=".github/workflows/ci.yml"
if [[ -r "${WF}" ]]; then
    mapfile -t ci_checks < <(awk '
        /^  [a-z0-9_-]+:[[:space:]]*$/ { job = $1; sub(/:$/, "", job) }
        job ~ /^(rust|vali|sentinel)$/ &&
            match($0, /bash scripts\/[A-Za-z0-9_\/.-]+\.sh/) {
                print substr($0, RSTART + 5, RLENGTH - 5)
            }
    ' "${WF}" | sort -u)

    # Vacuity floor. An extractor that stopped matching would run zero
    # checks and print the same cheerful summary as a clean tree — the
    # failure this repository keeps rediscovering in its own guards, and
    # the one that let this script ship blind in the first place.
    if (( ${#ci_checks[@]} < 5 )); then
        printf '\n   \033[31mFAILED\033[0m  reading the checks out of %s — found %d, expected at least 5.\n' \
            "${WF}" "${#ci_checks[@]}"
        echo "            The extractor is not seeing the workflow, which is NOT the same"
        echo "            as the workflow having no checks. Fix this before trusting a green run."
        FAILED=1
    else
        for c in "${ci_checks[@]}"; do
            if [[ -r "${c}" ]]; then
                run "${c}" bash "${c}"
            else
                skip "${c}" "named in ${WF} but not present in this tree"
            fi
        done
    fi
else
    skip "the repository's own checks" "${WF} not readable"
fi

# ── rust ────────────────────────────────────────────────────────────
if command -v cargo >/dev/null 2>&1; then
    run "cargo fmt --check"  cargo fmt --all -- --check
    run "cargo clippy"       cargo clippy --workspace --all-targets -- -D warnings
    run "cargo build"        cargo build --workspace --locked
    run "cargo test"         cargo test --workspace --locked

    # The two no_std crates must still build for the runtime's target.
    # Skipped rather than failed when the target is absent: a first-time
    # contributor should not have to install a cross target to find out
    # their patch does not compile.
    if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
        run "wasm32 hippius-types" \
            cargo build -p hippius-types --no-default-features --target wasm32-unknown-unknown
        run "wasm32 pallet-compute-scoring" \
            cargo build -p pallet-compute-scoring --no-default-features --target wasm32-unknown-unknown
    else
        skip "wasm32 no_std builds" "target not installed (rustup target add wasm32-unknown-unknown)"
    fi
else
    skip "the whole rust job" "cargo not on PATH"
fi

# ── vali ────────────────────────────────────────────────────────────
# Uses the venv if there is one, so a contributor who followed
# `vali/README` does not need it on PATH.
vali_py=""
for c in vali/.venv/bin ""; do
    if [[ -n "$c" && -x "$c/pytest" ]]; then vali_py="$c/"; break; fi
    if [[ -z "$c" ]] && command -v pytest >/dev/null 2>&1; then vali_py=""; break; fi
done
if [[ -n "${vali_py}" ]] || command -v pytest >/dev/null 2>&1; then
    run "vali ruff"   bash -c "cd vali && ${vali_py:+../}${vali_py}ruff check ."
    run "vali pytest" bash -c "cd vali && ${vali_py:+../}${vali_py}pytest -q"
else
    skip "the vali job" "no pytest (python -m venv vali/.venv && pip install -e 'vali[dev]')"
fi

# ── sentinel ────────────────────────────────────────────────────────
if [[ -x sentinel/.venv/bin/pytest ]]; then
    run "sentinel ruff"   bash -c "cd sentinel && .venv/bin/ruff check sentinel tests conftest.py"
    run "sentinel pytest" bash -c "cd sentinel && .venv/bin/pytest -v"
else
    skip "the sentinel job" "sentinel/.venv not built"
fi

printf '\n'
if (( FAILED )); then
    echo "run-ci-locally: SOMETHING FAILED — see above. CI would fail too."
else
    echo "run-ci-locally: everything that ran, passed. Skipped checks are listed above;"
    echo "                CI runs those too, so a green run here is a filter, not a verdict."
fi
exit "${FAILED}"
