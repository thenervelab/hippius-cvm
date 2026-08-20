#!/usr/bin/env bash
# publishability-test.sh — nothing in the tracked tree may disclose our
# infrastructure. A pre-publication gate, not a credential scanner.
#
# WHY THIS IS NOT gitleaks: gitleaks looks for things shaped like
# credentials (tokens, keys, high-entropy strings) and it is GREEN on this
# repo today. It has no opinion about "this hostname is our datacentre" or
# "this IPv4 is a machine we own". Those are not credentials; they are a
# map of our estate, and publishing them is the risk this gate exists for.
#
# WHY THE DENYLIST LIVES OUTSIDE THE REPO — read this before "simplifying"
# it back inline. A checker that greps for `203.0.113.7` must CONTAIN
# `203.0.113.7`. Inline the patterns and the gate becomes the leak: publish
# the tool and you publish the estate it was written to hide. So the
# patterns come from a file that is never committed, and this script — which
# IS publishable — carries none of them.
#
# Usage:
#   PUBLISH_DENYLIST=/path/to/list scripts/dev/publishability-test.sh
# Format, one rule per line, TAB-separated, `#` comments ignored:
#   <class-name>\t<extended-regex>
# See .publish-denylist.example for the shape.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
LIST="${PUBLISH_DENYLIST:-${ROOT}/.publish-denylist}"
SELF_REL="scripts/dev/publishability-test.sh"

if [[ ! -r "${LIST}" ]]; then
    # NEVER a skip. An absent denylist means we verified nothing, and a
    # gate that passes when it checked nothing is the exact defect this
    # repo keeps finding. Fail, and say what is missing.
    echo "publishability: denylist not readable at '${LIST}'"
    echo "  this gate cannot run without it, and it will NOT pass vacuously."
    echo "  copy .publish-denylist.example, fill in the real values, keep it UNCOMMITTED."
    exit 1
fi

mapfile -t RULES < <(grep -vE '^[[:space:]]*(#|$)' "${LIST}")
CLASSES="${#RULES[@]}"

# The denylist lives outside the repo — a local file here, a CI secret
# there — so the two copies can drift and nothing would say so. A COUNT
# does not catch that. This gate shipped with a floor of 4 while the real
# list carried 10, and a list truncated to 5 printed ALL CLEAN against a
# tree that contained a chip id. Half the coverage gone, green tick: the
# exact defect this gate exists to prevent, built into the gate itself.
#
# So the expected CLASSES are named here, in the script, where they get
# reviewed. Class names are categories, not the estate — "host-ips"
# discloses nothing, which is precisely why they can live in a publishable
# file while the patterns cannot. Adding or retiring a class means editing
# this line, and that is the point: a visible act, not a silent one.
EXPECTED_CLASSES="provider host-ips control-plane-ip secret-store-ip internal-domain host-names overlay-net cluster-net node-ids chip-ids chain-accounts org-emails"

# The example is the ONLY artifact that survives publication — the real
# denylist never does. Whoever rebuilds this gate later, us or someone
# adopting it, starts from that file. It has drifted three times in a
# week, once per class added: at the last check it documented 11 of 12,
# named one class `secret-store` where the code says `secret-store-ip`,
# and omitted `cluster-net` and `node-ids` entirely.
#
# So the example must illustrate every class the code expects. Missing
# documentation for a class is a defect in the class, not a nicety.
EXAMPLE="${ROOT}/.publish-denylist.example"
if [[ -r "${EXAMPLE}" ]]; then
    undocumented=""
    for want in ${EXPECTED_CLASSES}; do
        grep -qE "^#[[:space:]]*${want}"$'\t' "${EXAMPLE}" || undocumented+="${want} "
    done
    if [[ -n "${undocumented}" ]]; then
        echo "publishability: .publish-denylist.example documents no line for: ${undocumented}"
        echo "  That file is the only thing left to rebuild this gate from once the"
        echo "  real denylist is gone. Add an illustrative line per class."
        exit 1
    fi
else
    echo "publishability: .publish-denylist.example is missing — the only artifact"
    echo "  that survives publication. Restore it."
    exit 1
fi

loaded_names=""
for rule in "${RULES[@]}"; do
    loaded_names+="${rule%%$'\t'*} "
done
missing=""
for want in ${EXPECTED_CLASSES}; do
    case " ${loaded_names}" in
        *" ${want} "*) ;;
        *) missing+="${want} " ;;
    esac
done
if [[ -n "${missing}" ]]; then
    echo "publishability: the denylist is missing expected class(es): ${missing}"
    echo "  ${CLASSES} rule(s) loaded; expected: ${EXPECTED_CLASSES}"
    echo "  A short denylist does not scan less loudly — it scans less SILENTLY."
    echo "  Either the list/secret has drifted, or a class was retired on purpose"
    echo "  and EXPECTED_CLASSES in this script must be updated to say so."
    exit 1
fi

FILES="$(cd "${ROOT}" && git ls-files | wc -l)"
if (( FILES < 100 )); then
    echo "publishability: git ls-files returned ${FILES} paths — not scanning a real tree"
    exit 1
fi

FAILED=0
ALLOWED_TOTAL=0
# A hit is not always a disclosure. A credential-scanner ruleset has to
# name the vendors it detects — the same way it names AWS and GCP — and a
# detection rule is not a map of our estate. This comment deliberately
# does NOT write those vendor names itself: this script is published, so
# anything it says is published too, and it should be clean on its own
# merits rather than by leaning on the self-exclusion below.
#
# So there is an exception marker, deliberately awkward to use: it lives
# in the offending FILE (a reviewer sees it in the diff, not buried in a
# config), it names ONE class, and it must carry a reason. A file with
#     publishability-allow: provider — detection rule, not our estate
# is exempt for `provider` and for nothing else.
#
# And the mechanism is capped. If it ever excuses more than a handful of
# files it has stopped being an exception and become the bypass, so the
# gate fails on the mechanism itself rather than on any one file.
MAX_ALLOWED=5
echo "publishability: ${CLASSES} class(es) against ${FILES} tracked files"
for rule in "${RULES[@]}"; do
    name="${rule%%$'\t'*}"
    pat="${rule#*$'\t'}"
    [[ "${name}" == "${pat}" ]] && { echo "  MALFORMED rule (need a TAB): ${rule}"; FAILED=1; continue; }

    # Exclude the denylist (never committed) and this script. The
    # denylist legitimately contains every pattern; this script contains
    # none of them, and the exclusion exists only so that a rule cannot
    # match the code that applies it.
    #
    # Keep that narrow. The exclusion previously carried a justification
    # — "neither is published with them" — that was true of the denylist
    # and false of this script, which IS published. An exclusion whose
    # stated reason has quietly stopped applying is how a gate starts
    # covering things nobody decided to cover, so anything written here
    # must be clean without it.
    # `-i`, and it is load-bearing rather than tidy. A hex identifier is
    # written in whichever case the tool that printed it chose: the DER
    # decode path below uppercases, `hippius-miner-agent platform-id`
    # prints lowercase, and the validator stores lowercase. A chip-id rule
    # written in uppercase — as it must be for the DER path — was blind to
    # every lowercase occurrence in a config, a log or a doc, which is the
    # form it would actually take in the tree.
    mapfile -t hit_files < <(cd "${ROOT}" && git grep -lIiE "${pat}" -- . \
             ":(exclude)${SELF_REL}" ":(exclude).publish-denylist*" 2>/dev/null)

    # `git grep -I` skips binary files, and base64 hides everything else.
    # A certificate is the case that matters here: an AMD VCEK carries the
    # 64-byte CHIP_ID of a physical machine in an X.509 extension, so the
    # identifier of a host we own can sit in the tree in plain sight while
    # every text search over it comes back clean. Renaming the file — which
    # is what an earlier pass did — changes nothing about its contents.
    #
    # So certificate-ish files are additionally scanned as DECODED HEX.
    # Rules meant for this are written as hex; a rule that is not hex simply
    # will not match a hex dump, which costs nothing.
    #
    # And the file list is NOT driven by extension. The scope this gate was
    # written against names `vault-ca-configmap.yaml` — CA material lives in
    # Helm values and ConfigMaps at least as often as in a `.pem`, and a
    # `.yaml` full of base64 is exactly as opaque to a text search as a
    # binary. Selecting by extension would have inspected the file that was
    # already obvious and skipped the ones that are not.
    #
    # So: any tracked file that CONTAINS a PEM block gets its blocks pulled
    # out and decoded, whatever it is called.
    while IFS= read -r cert; do
        [[ -z "${cert}" ]] && continue
        # `openssl x509` for a bare cert file; otherwise pull every PEM
        # block out of whatever the file is and decode each one.
        der_hex="$(openssl x509 -in "${ROOT}/${cert}" -outform DER 2>/dev/null \
                    | xxd -p 2>/dev/null | tr -d '\n' | tr 'a-f' 'A-F')"
        if [[ -z "${der_hex}" ]]; then
            der_hex="$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "${ROOT}/${cert}" 2>/dev/null \
                        | sed -E 's/^[^A-Za-z0-9+/=]*//; /BEGIN|END/d' \
                        | tr -d '\n' \
                        | base64 -d 2>/dev/null | xxd -p 2>/dev/null | tr -d '\n' | tr 'a-f' 'A-F')"
        fi
        [[ -z "${der_hex}" ]] && continue
        if printf '%s' "${der_hex}" | grep -qiE "${pat}"; then
            hit_files+=("${cert}")
        fi
    done < <(cd "${ROOT}" && { git ls-files '*.pem' '*.crt' '*.cer' '*.der';
                               git grep -lI "BEGIN CERTIFICATE" -- . ":(exclude)${SELF_REL}"; } 2>/dev/null | sort -u)

    leaks=()
    for f in "${hit_files[@]}"; do
        [[ -z "${f}" ]] && continue
        # The marker must name THIS class and be followed by a reason.
        if grep -qE "publishability-allow:[[:space:]]*${name}[[:space:]]*[-—:][[:space:]]*[^[:space:]]" "${ROOT}/${f}" 2>/dev/null; then
            reason="$(grep -oE "publishability-allow:[[:space:]]*${name}[[:space:]]*[-—:][[:space:]]*.*" "${ROOT}/${f}" | head -1 | sed -E "s/.*[-—:][[:space:]]*//")"
            echo "  ALLOW ${name}: ${f} — ${reason}"
            ALLOWED_TOTAL=$((ALLOWED_TOTAL + 1))
        else
            leaks+=("${f}")
        fi
    done

    if (( ${#leaks[@]} > 0 )); then
        echo "  LEAK  ${name}: ${#leaks[@]} file(s)"
        printf '          %s\n' "${leaks[@]}" | head -12
        FAILED=1
    else
        echo "  clean ${name}"
    fi
done

if (( ALLOWED_TOTAL > MAX_ALLOWED )); then
    echo "publishability: ${ALLOWED_TOTAL} allow-markers (max ${MAX_ALLOWED}) — the exception is being used as a bypass"
    FAILED=1
fi

if (( FAILED )); then
    echo "publishability: NOT PUBLISHABLE"
else
    echo "publishability: ALL CLEAN — tree discloses none of the denylisted classes"
fi
exit "${FAILED}"
