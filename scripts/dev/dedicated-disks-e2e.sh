#!/usr/bin/env bash
#
# REAL end-to-end for the dedicated-disk opener
# (`hippius-guest-release --open-dedicated-disks`,
# docs/design/disk-tier-verification.md §4.2): real cryptsetup, real
# device-mapper, sparse 1000 GiB loop devices exposed under the virtio
# serial names the guest looks for (`virtio-hippius-<slot>` links in a
# by-id directory). Needs root: run by the `golden-integrity` workflow on a
# GitHub-hosted runner, never on a miner.
#
# Checks what the unit tests (fake host) can only argue:
#   1. first boot: each slot is LUKS2 aes-xts-plain64 512-bit, NO
#      integrity, carries the UUID the record names, opens as
#      /dev/mapper/hippius-<slot>, and the header accepts exactly the
#      documented HKDF key (recomputed here independently);
#   2. what is written through the mapping is not on the raw device;
#   3. reboot: reopened, not reformatted (a sentinel survives);
#   4. slots swapped by the host ⇒ both `mismatch`, nothing opened;
#   5. a blank disk under a recorded slot ⇒ `mismatch`, left blank;
#   6. an absent slot ⇒ `missing`, the others still open;
#   7. a disk smaller than its anchor, or carrying a signature ⇒
#      `mismatch`, never formatted;
#   8. a host-forged header with the recorded UUID but another key ⇒
#      `mismatch` (open refused); one that accepts OUR key but declares
#      another cipher, or a reencryption in flight ⇒ `mismatch` before any
#      activation; the real disks still open afterwards;
#   9. a malformed anchor ⇒ every slot device `mismatch`, nothing opened.
#
# Usage: sudo BIN=/path/to/hippius-guest-release bash dedicated-disks-e2e.sh
set -euo pipefail

: "${BIN:?set BIN to the hippius-guest-release binary}"
[ "$(id -u)" -eq 0 ] || { echo "dedicated-disks-e2e: needs root" >&2; exit 1; }

fail=0
ok()  { echo "dedicated-disks-e2e: OK — $*"; }
err() { echo "dedicated-disks-e2e: FAIL — $*" >&2; fail=1; }

WORK="$(mktemp -d)"
RUNDIR="$(mktemp -d -p /run hippius-dd-e2e.XXXXXX)"
STATE="${RUNDIR}/slots"
BYID="${WORK}/by-id"
VOL="${WORK}/vol"
mkdir -p "${BYID}" "${VOL}"
LOOPS=()
cleanup() {
    for m in hippius-x0 hippius-x1 hippius-x2 hippius-x3 hippius-x4 hippius-e2e-forge; do
        cryptsetup close "$m" 2>/dev/null || true
    done
    for l in "${LOOPS[@]}"; do losetup -d "$l" 2>/dev/null || true; done
    rm -rf "${WORK}" "${RUNDIR}"
}
trap cleanup EXIT

# Sets NEWLOOP (not echoed: a command substitution would run it in a
# subshell and the cleanup would never see the loop).
new_loop() { # name size
    truncate -s "$2" "${WORK}/$1.img"
    NEWLOOP="$(losetup -f --show "${WORK}/$1.img")"
    LOOPS+=("${NEWLOOP}")
}
link() { ln -sfn "$2" "${BYID}/virtio-hippius-$1"; }
unlink_slot() { rm -f "${BYID}/virtio-hippius-$1"; }

head -c 32 /dev/urandom > "${WORK}/kek"
VM=vm-e2e-0001
CMDLINE="${WORK}/cmdline"
anchor() { printf 'ro quiet hippius.vm_id=%s hippius.dedicated=%s\n' "${VM}" "$1" > "${CMDLINE}"; }
close_all() { for m in hippius-x0 hippius-x1 hippius-x2 hippius-x3 hippius-x4; do cryptsetup close "$m" 2>/dev/null || true; done; }
open_run() {
    rm -f "${STATE}"
    "${BIN}" --open-dedicated-disks "${WORK}/kek" --dedicated-volume-root "${VOL}" \
        --dedicated-state-out "${STATE}" --dedicated-cmdline "${CMDLINE}" --dedicated-by-id "${BYID}" \
        2>"${WORK}/run.err" || err "opener exited non-zero: $(tail -3 "${WORK}/run.err")"
    cat "${WORK}/run.err" >> "${WORK}/all.err"
}
slot_line() { grep -E "^$1 " "${STATE}" || true; }
expect() { # slot "state ... reason"
    local got
    got="$(slot_line "$1" | awk '{print $2" "$5}')"
    [[ "${got}" == "$2" ]] && ok "$1: $2${3:+ — $3}" || err "$1: want '$2', got '${got}' ($(tail -2 "${WORK}/run.err"))"
}
record_uuid() { awk -v s="$1" '$1==s {print $3}' "${VOL}/.hippius-dedicated-disks"; }
# The documented key, recomputed independently of the binary.
hkdf_key() { # slot -> 64 raw bytes on stdout
    python3 -I - "${WORK}/kek" "${VM}$1" <<'PY'
import hashlib, hmac, sys
ikm = open(sys.argv[1], "rb").read()
prk = hmac.new(b"hippius-dedicated-disk-v1", ikm, hashlib.sha256).digest()
t, okm, i = b"", b"", 1
while len(okm) < 64:
    t = hmac.new(prk, t + sys.argv[2].encode() + bytes([i]), hashlib.sha256).digest()
    okm += t
    i += 1
sys.stdout.buffer.write(okm[:64])
PY
}

new_loop d0 1000G; L0="${NEWLOOP}"
new_loop d1 1000G; L1="${NEWLOOP}"
link x0 "${L0}"
link x1 "${L1}"
anchor x0:1000,x1:1000

# ── 1. first boot ───────────────────────────────────────────────────
open_run
expect x0 "attached -"
expect x1 "attached -"
[[ -b /dev/mapper/hippius-x0 && -b /dev/mapper/hippius-x1 ]] && ok "mappers exist" || err "mappers missing"
if compgen -G "${RUNDIR}/.header-*" >/dev/null; then err "header copies left in tmpfs"; else ok "no header copy left behind"; fi
st="$(cryptsetup status hippius-x0)"
grep -q 'cipher:  aes-xts-plain64' <<<"${st}" && grep -qE 'keysize: 512 \[?bits\]?' <<<"${st}" \
    && ! grep -q integrity <<<"${st}" && ok "x0 active: aes-xts-plain64, 512-bit, no integrity" || err "x0 status: ${st}"
json="$(cryptsetup luksDump --dump-json-metadata "${L0}")"
python3 -I -c 'import json,sys; d=json.load(sys.stdin); s=d["segments"]; assert list(s)==["0"], s; s=s["0"]; assert s["encryption"]=="aes-xts-plain64" and "integrity" not in s and s["offset"]=="16777216" and s["sector_size"]==4096, s' <<<"${json}" \
    && ok "x0 header: one aes-xts-plain64 segment at 16 MiB, 4096-byte sectors, no integrity" || err "x0 header: ${json}"
[[ "$(cryptsetup luksUUID "${L0}")" == "$(record_uuid x0)" && -n "$(record_uuid x0)" ]] \
    && ok "x0 header UUID == recorded UUID" || err "x0 uuid: header $(cryptsetup luksUUID "${L0}") record $(record_uuid x0)"
head -1 "${VOL}/.hippius-dedicated-disks" | grep -qx 'hippius-dedicated-disks v1' \
    && grep -qE '^x0 ready [0-9a-f-]{36} 1000$' "${VOL}/.hippius-dedicated-disks" \
    && ok "record: x0 ready <uuid> 1000" || err "record: $(cat "${VOL}/.hippius-dedicated-disks")"
[[ "$(stat -c %a "${VOL}/.hippius-dedicated-disks")" == 600 ]] && ok "record mode 0600" || err "record mode"
[[ "$(cryptsetup luksDump "${L0}" | sed -n 's/^Label:[[:space:]]*//p')" == hippius-x0 ]] && ok "x0 LUKS label hippius-x0" || err "x0 label"
# The documented HKDF key is both the keyslot passphrase and the volume key.
hkdf_key x0 > "${WORK}/k0"
if cryptsetup luksDump --dump-volume-key --batch-mode --key-file "${WORK}/k0" --keyfile-size 64 \
        --volume-key-file "${WORK}/vk0" "${L0}" >/dev/null 2>&1 \
    && cmp -s "${WORK}/k0" "${WORK}/vk0"; then
    ok "volume key == keyslot passphrase == HKDF(KEK, salt, vm_id‖x0)"
else
    err "the header does not hold the documented HKDF key"
fi
hkdf_key x1 > "${WORK}/k1"
cmp -s "${WORK}/k0" "${WORK}/k1" && err "x0 and x1 share a key" || ok "per-slot keys differ"

# ── 2. ciphertext on the raw device ─────────────────────────────────
head -c 4096 /dev/urandom > "${WORK}/sentinel"
dd if="${WORK}/sentinel" of=/dev/mapper/hippius-x0 bs=4096 count=1 oflag=direct status=none
off="$(python3 -I -c 'import json,sys; print(json.load(sys.stdin)["segments"]["0"]["offset"])' <<<"${json}")"
dd if="${L0}" bs=4096 skip=$((off / 4096)) count=1 iflag=direct status=none | cmp -s - "${WORK}/sentinel" \
    && err "plaintext on the raw device" || ok "the raw device holds ciphertext only"

# ── 3. reboot ───────────────────────────────────────────────────────
close_all
u0="$(record_uuid x0)"
open_run
expect x0 "attached -" "reopened"
expect x1 "attached -"
dd if=/dev/mapper/hippius-x0 bs=4096 count=1 iflag=direct status=none | cmp -s - "${WORK}/sentinel" \
    && ok "sentinel survives the reboot (not reformatted)" || err "sentinel lost"
[[ "$(record_uuid x0)" == "${u0}" && "$(cryptsetup luksUUID "${L0}")" == "${u0}" ]] && ok "same UUID" || err "UUID changed"

# ── 4. swapped by the host ──────────────────────────────────────────
close_all
link x0 "${L1}"; link x1 "${L0}"
open_run
expect x0 "mismatch uuid-mismatch"
expect x1 "mismatch uuid-mismatch"
[[ ! -e /dev/mapper/hippius-x0 && ! -e /dev/mapper/hippius-x1 ]] && ok "nothing opened" || err "a swapped slot was opened"
link x0 "${L0}"; link x1 "${L1}"

# ── 5. blank disk under a recorded slot ─────────────────────────────
new_loop blank 1000G; LB="${NEWLOOP}"
link x1 "${LB}"
open_run
expect x0 "attached -"
expect x1 "mismatch no-header"
cryptsetup isLuks "${LB}" && err "the blank replacement was formatted" || ok "the blank replacement left untouched"
close_all

# ── 6. absent slot ──────────────────────────────────────────────────
unlink_slot x1
open_run
expect x0 "attached -"
expect x1 "missing absent"
link x1 "${L1}"
close_all

# ── 7. too small / signature ────────────────────────────────────────
new_loop small 999G; LS="${NEWLOOP}"
new_loop sig 1000G; LG="${NEWLOOP}"
printf '\x53\xef' | dd of="${LG}" bs=1 seek=1080 conv=notrunc status=none
link x2 "${LS}"; link x3 "${LG}"
anchor x0:1000,x1:1000,x2:1000,x3:1000
open_run
expect x0 "attached -"
expect x1 "attached -"
expect x2 "mismatch too-small"
expect x3 "mismatch not-blank"
if cryptsetup isLuks "${LS}" || cryptsetup isLuks "${LG}"; then err "a refused disk was formatted"; else ok "refused disks untouched"; fi
grep -qE '^x[23] ' "${VOL}/.hippius-dedicated-disks" && err "a refused slot was recorded" || ok "refused slots never recorded"
close_all

# ── 8. forged headers ───────────────────────────────────────────────
# (a) the recorded UUID (plaintext in the header) on a header keyed by
# someone else.
new_loop forge 1000G; LF="${NEWLOOP}"
head -c 64 /dev/urandom > "${WORK}/other"
cryptsetup luksFormat --batch-mode --type luks2 --uuid "$(record_uuid x1)" --offset 32768 --sector-size 4096 \
    --key-file "${WORK}/other" --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${LF}" >/dev/null
link x1 "${LF}"
anchor x0:1000,x1:1000
open_run
expect x1 "mismatch open-failed" "a copied UUID without our key does not open"
[[ ! -e /dev/mapper/hippius-x1 ]] && ok "forged x1 not mapped" || err "forged x1 mapped"
link x1 "${L1}"
close_all
# (b) a header that accepts OUR key but declares another cipher: refused
# on the metadata check, before any activation.
new_loop null 1000G; LN="${NEWLOOP}"
if cryptsetup luksFormat --batch-mode --type luks2 --uuid "$(record_uuid x0)" --cipher serpent-xts-plain64 \
        --key-size 512 --volume-key-file "${WORK}/k0" --key-file "${WORK}/k0" --keyfile-size 64 \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${LN}" >/dev/null 2>&1; then
    link x0 "${LN}"
    open_run
    expect x0 "mismatch bad-header" "another cipher behind our own key is refused"
    [[ ! -e /dev/mapper/hippius-x0 ]] && ok "x0 not mapped" || err "x0 mapped"
    link x0 "${L0}"
else
    err "could not build the serpent-cipher forgery"
fi
close_all
# (c) our own key and UUID, but a reencryption "in progress" (a forger
# would make the old segment linear / cipher_null): refused.
new_loop reenc 1000G; LR="${NEWLOOP}"
if cryptsetup luksFormat --batch-mode --type luks2 --uuid "$(record_uuid x0)" --cipher aes-xts-plain64 \
        --offset 32768 --sector-size 4096 --key-size 512 --volume-key-file "${WORK}/k0" --key-file "${WORK}/k0" --keyfile-size 64 \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${LR}" >/dev/null 2>&1 \
    && cryptsetup reencrypt --init-only --batch-mode --key-file "${WORK}/k0" --keyfile-size 64 \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${LR}" >/dev/null 2>&1; then
    link x0 "${LR}"
    open_run
    expect x0 "mismatch bad-header" "a header with a reencryption in flight is refused"
    [[ ! -e /dev/mapper/hippius-x0 ]] && ok "x0 not mapped" || err "x0 mapped"
    link x0 "${L0}"
else
    err "could not build the reencryption forgery"
fi
close_all
# The real disks still open after all that.
open_run
expect x0 "attached -"
expect x1 "attached -"
dd if=/dev/mapper/hippius-x0 bs=4096 count=1 iflag=direct status=none | cmp -s - "${WORK}/sentinel" \
    && ok "x0 data intact after the forgeries" || err "x0 data lost"
close_all

# ── 9. malformed anchor ─────────────────────────────────────────────
anchor x0:1000,x0:1000
open_run
expect x0 "mismatch anchor-slot-repeated"
expect x1 "mismatch anchor-slot-repeated"
[[ ! -e /dev/mapper/hippius-x0 ]] && ok "malformed anchor: nothing opened" || err "malformed anchor opened x0"

# ── no anchor: nothing at all ───────────────────────────────────────
printf 'ro quiet hippius.vm_id=%s\n' "${VM}" > "${CMDLINE}"
open_run
[[ ! -e "${STATE}" ]] && ok "no anchor: no state file, nothing touched" || err "no anchor wrote $(cat "${STATE}")"

# Key bytes never in the diagnostics.
k0hex="$(od -An -tx1 "${WORK}/k0" | tr -d ' \n')"
if grep -qi "${k0hex:0:16}" "${WORK}/all.err"; then err "key bytes in the log"; else ok "no key bytes in any run's log"; fi

[[ "${fail}" -eq 0 ]] || { echo "dedicated-disks-e2e: FAILED" >&2; exit 1; }
echo "dedicated-disks-e2e: OK (all checks passed)"
