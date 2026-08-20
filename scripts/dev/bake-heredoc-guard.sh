#!/usr/bin/env bash
# Heredoc-safety guard for `scripts/tenant-image-bake.sh`.
#
# An UNQUOTED heredoc (`<<WORD`, not `<<'WORD'`) is expanded by the
# outer shell: every backtick — INCLUDING inside comments — is a
# command substitution, and `$(…)` likewise. That is how the 2026-07-04
# baker (66ef008b) silently lost the hippius initramfs hook: a `word`
# in a comment EXECUTED mid-bake and mangled the chroot script, so
# every guest hung at cryptroot with no hippius files in the initrd
# (and the same class of bug is the best explanation for the earlier
# #673 baker hang).
#
# Rule enforced here: the BODY of any unquoted heredoc in the bake
# script must contain NO UNESCAPED backtick and NO unescaped `$(`
# (`\`` and `\$(` are inert and stay allowed). Deliberate outer
# `${VAR}` expansion stays allowed (that is the one legitimate reason
# to leave a heredoc unquoted). Prefer a quoted heredoc + env(1) for
# anything script-sized — see the chroot-install blocks.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-${HERE}/../tenant-image-bake.sh}"
[[ -r "${TARGET}" ]] || { echo "bake-heredoc-guard: target not found: ${TARGET}" >&2; exit 1; }

fail=0
while IFS=$'\t' read -r start_line delim; do
    # Body = lines after the opener up to the terminator line.
    body="$(awk -v s="${start_line}" -v d="${delim}" '
        NR > s && $0 == d {exit}
        NR > s {print}
    ' "${TARGET}")"
    if grep -qP '(?<!\\)`|(?<!\\)\$\(' <<<"${body}"; then
        echo "bake-heredoc-guard: FAIL: unquoted heredoc <<${delim} at line ${start_line} contains an unescaped backtick or \$( —" >&2
        echo "  the outer shell WILL command-substitute it (even inside comments)." >&2
        echo "  Quote the delimiter (<<'${delim}') and pass outer values via env(1)," >&2
        echo "  escape it (\\\` / \\\$(), or drop it from the body. Offending line(s):" >&2
        grep -nP '(?<!\\)`|(?<!\\)\$\(' <<<"${body}" | head -5 | sed 's/^/    /' >&2
        fail=1
    fi
done < <(grep -nE '<<-?[A-Z_][A-Z_0-9]*$' "${TARGET}" \
    | sed -E 's/^([0-9]+):.*<<-?([A-Z_][A-Z_0-9]*)$/\1\t\2/')

if [[ ${fail} -eq 0 ]]; then
    echo "bake-heredoc-guard: OK (no command substitution reachable from unquoted heredoc bodies)"
else
    exit 1
fi
