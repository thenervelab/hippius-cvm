#!/usr/bin/env bash
# A fake `aws` CLI over a local directory, for tests: FAKE_S3_ROOT/<bucket>/<key>.
# Implements exactly what the guest initrd build uses:
#   aws s3 cp [--only-show-errors] <src> <dst>        (local <-> s3://)
#   aws s3api list-objects-v2 --bucket B --prefix P --max-keys N --query KeyCount --output text
#   aws s3api put-object --bucket B --key K --body F [--if-none-match '*']
# Knobs: FAKE_S3_CORRUPT=<key suffix> corrupts that object on download;
# FAKE_S3_LIST_EMPTY=1 makes every listing report 0 keys (a lost race).
set -euo pipefail
root="${FAKE_S3_ROOT:?}"
path_of() { local u="${1#s3://}"; printf '%s/%s' "${root}" "${u}"; }
case "${1:-} ${2:-}" in
    "s3 cp")
        shift 2
        [[ "${1:-}" == --only-show-errors ]] && shift
        src="$1" dst="$2"
        if [[ "${src}" == s3://* ]]; then
            [[ -f "$(path_of "${src}")" ]] || { echo "fake-aws: no such key ${src}" >&2; exit 1; }
            cp "$(path_of "${src}")" "${dst}"
            if [[ -n "${FAKE_S3_CORRUPT:-}" && "${src}" == *"${FAKE_S3_CORRUPT}" ]]; then
                printf 'x' >> "${dst}"
            fi
        else
            mkdir -p "$(dirname "$(path_of "${dst}")")"
            cp "${src}" "$(path_of "${dst}")"
        fi
        ;;
    "s3api list-objects-v2")
        shift 2
        bucket="" prefix=""
        while [[ $# -gt 0 ]]; do
            case "$1" in --bucket) bucket="$2"; shift 2 ;; --prefix) prefix="$2"; shift 2 ;; *) shift ;; esac
        done
        if [[ "${FAKE_S3_LIST_EMPTY:-0}" == 1 ]]; then echo 0; exit 0; fi
        n=0
        if [[ -d "${root}/${bucket}" ]]; then
            n="$(cd "${root}/${bucket}" && find . -type f | sed 's|^\./||' | grep -c "^${prefix}" || true)"
        fi
        [[ "${n}" -gt 0 ]] && echo 1 || echo 0
        ;;
    "s3api put-object")
        shift 2
        bucket="" key="" body="" inm=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --bucket) bucket="$2"; shift 2 ;; --key) key="$2"; shift 2 ;;
                --body) body="$2"; shift 2 ;; --if-none-match) inm="$2"; shift 2 ;; *) shift ;;
            esac
        done
        dst="${root}/${bucket}/${key}"
        if [[ "${inm}" == '*' && -e "${dst}" ]]; then
            echo "fake-aws: PreconditionFailed ${key}" >&2; exit 254
        fi
        mkdir -p "$(dirname "${dst}")"
        cp "${body}" "${dst}"
        ;;
    *) echo "fake-aws: unsupported: $*" >&2; exit 2 ;;
esac
