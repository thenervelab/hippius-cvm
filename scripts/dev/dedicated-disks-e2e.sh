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
#   9. a malformed anchor ⇒ every slot device `mismatch`, nothing opened;
#  10. an integrity slot (`:i`, guest release 8) on a small loop device:
#      formatted aes-xts-plain64 + hmac(sha256) under the documented 96-byte
#      key, opened as hippius-<slot>-init with no journal and its two ends
#      primed (the middle still reads EIO), recorded `formatting`; the
#      booted OS's `--dedicated-init-wipe` killed mid-way ⇒ the next boot
#      starts again from scratch; run to the end ⇒ every tag initialised
#      (a full read succeeds), recorded `ready`, journaled, renamed
#      hippius-<slot>; a reboot reopens it (same UUID, data intact, no
#      re-format); one tampered ciphertext block reads as an I/O error, its
#      neighbours do not; the anchor/record mode must agree; an unknown
#      suffix refuses every slot.
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
    for m in hippius-x0 hippius-x1 hippius-x2 hippius-x3 hippius-x4 hippius-x4-init hippius-e2e-forge; do
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
close_all() { for m in hippius-x0 hippius-x1 hippius-x2 hippius-x3 hippius-x4 hippius-x4-init; do cryptsetup close "$m" 2>/dev/null || true; done; }
EXTRA=()
open_run() {
    rm -f "${STATE}"
    "${BIN}" --open-dedicated-disks "${WORK}/kek" --dedicated-volume-root "${VOL}" \
        --dedicated-state-out "${STATE}" --dedicated-cmdline "${CMDLINE}" --dedicated-by-id "${BYID}" \
        ${EXTRA[@]+"${EXTRA[@]}"} 2>"${WORK}/run.err" || err "opener exited non-zero: $(tail -3 "${WORK}/run.err")"
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
hkdf_key() { # slot [L salt] -> L raw bytes on stdout (64, the plain salt)
    python3 -I - "${WORK}/kek" "${VM}$1" "${2:-64}" "${3:-hippius-dedicated-disk-v1}" <<'PY'
import hashlib, hmac, sys
ikm = open(sys.argv[1], "rb").read()
n = int(sys.argv[3])
prk = hmac.new(sys.argv[4].encode(), ikm, hashlib.sha256).digest()
t, okm, i = b"", b"", 1
while len(okm) < n:
    t = hmac.new(prk, t + sys.argv[2].encode() + bytes([i]), hashlib.sha256).digest()
    okm += t
    i += 1
sys.stdout.buffer.write(okm[:n])
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

# ── 10. integrity slots (guest release 8) ───────────────────────────
# A small loop device (the size floor is the test seam, never passed at
# boot), so the full wipe takes seconds.
EXTRA=(--dedicated-test-min-gib 1)
close_all
new_loop i0 1100M; LI="${NEWLOOP}"
link x4 "${LI}"
anchor x0:1000,x1:1000,x4:1:i
open_run
expect x0 "attached -" "a plain slot next to an integrity one"
expect x4 "initializing init-0"
[[ -b /dev/mapper/hippius-x4-init && ! -e /dev/mapper/hippius-x4 ]] \
    && ok "x4 opened as hippius-x4-init only (not the tenant's name before the wipe)" || err "x4 mappings: $(ls /dev/mapper)"
grep -qx x4 "${RUNDIR}/init" && ok "x4 in the init list" || err "init list: $(cat "${RUNDIR}/init" 2>&1)"
grep -qE '^x4 formatting [0-9a-f-]{36} 1 integrity$' "${VOL}/.hippius-dedicated-disks" \
    && ok "record: x4 formatting <uuid> 1 integrity (never ready before the wipe)" || err "record: $(cat "${VOL}/.hippius-dedicated-disks")"
ijson="$(cryptsetup luksDump --dump-json-metadata "${LI}")"
echo "dedicated-disks-e2e: x4 luksDump JSON: ${ijson}" | tr -d '\n'; echo
python3 -I -c 'import json,sys; d=json.load(sys.stdin); s=d["segments"]["0"]; assert s["encryption"]=="aes-xts-plain64" and s["integrity"]["type"]=="hmac(sha256)" and s["offset"]=="16777216" and s["sector_size"]==4096, s' <<<"${ijson}" \
    && ok "x4 header: aes-xts-plain64 + hmac(sha256), 16 MiB, 4096-byte sectors" || err "x4 header: ${ijson}"
cryptsetup luksDump "${LI}" | grep -qE 'Key:[[:space:]]+768 bits' && ok "x4 keyslot: 768-bit volume key (512 xts + 256 hmac)" \
    || err "x4 key size: $(cryptsetup luksDump "${LI}" | grep -i key)"
hkdf_key x4 96 hippius-dedicated-disk-aead-v1 > "${WORK}/k4"
if cryptsetup luksDump --dump-volume-key --batch-mode --key-file "${WORK}/k4" --keyfile-size 96 \
        --volume-key-file "${WORK}/vk4" "${LI}" >/dev/null 2>&1 \
    && cmp -s "${WORK}/k4" "${WORK}/vk4"; then
    ok "x4 volume key == keyslot passphrase == HKDF(KEK, aead salt, vm_id‖x4), 96 bytes"
else
    err "the x4 header does not hold the documented 96-byte HKDF key"
fi
ist="$(cryptsetup status hippius-x4-init)"
echo "dedicated-disks-e2e: x4-init status: ${ist}" | tr '\n' '|'; echo
[[ "$(dmsetup table hippius-x4-init_dif | awk '{print $7}')" == D ]] \
    && ok "x4-init: dm-integrity without journal for the wipe" || err "x4-init _dif: $(dmsetup table hippius-x4-init_dif)"
isz="$(blockdev --getsize64 /dev/mapper/hippius-x4-init)"
# The ends were written before udev could probe; the middle was not.
dd if=/dev/mapper/hippius-x4-init of=/dev/null bs=1M count=8 iflag=direct status=none \
    && dd if=/dev/mapper/hippius-x4-init of=/dev/null bs=4096 skip=$(( isz / 4096 - 2048 )) count=2048 iflag=direct status=none \
    && ok "x4-init: both 8 MiB ends read back (primed)" || err "x4-init: an end does not read"
# One 4 KiB sector just before the tail's primed 8 MiB is still unwritten.
if dd if=/dev/mapper/hippius-x4-init of=/dev/null bs=4096 skip=$(( isz / 4096 - 2049 )) count=1 iflag=direct status=none 2>/dev/null; then
    err "x4-init: the sector before the primed tail reads (primed more than 8 MiB?)"
else
    ok "x4-init: priming covers exactly the last 8 MiB"
fi
if dd if=/dev/mapper/hippius-x4-init of=/dev/null bs=4096 skip=$(( isz / 8192 )) count=1 iflag=direct status=none 2>/dev/null; then
    err "x4-init: an unwritten middle sector reads (no integrity?)"
else
    ok "x4-init: an unwritten middle sector is an I/O error before the wipe (tags not yet initialised)"
fi
grep -qE '^x4 initializing 1 loop[0-9]+ init-0$' "${STATE}" \
    && ok "state file: x4 initializing on its device, init-0" || err "state: $(cat "${STATE}")"

# The booted OS's wipe, interrupted: killed part-way (or the VM going down
# before it ends: the mapping is gone, the record still says formatting),
# so the next boot starts again from scratch.
init_run() {
    "${BIN}" --dedicated-init-wipe --dedicated-init-state "${STATE}" --dedicated-init-volume-root "${VOL}" \
        "${EXTRA[@]}" 2>"${WORK}/init.err"
}
"${BIN}" --dedicated-init-wipe --dedicated-init-state "${STATE}" --dedicated-init-volume-root "${VOL}" \
    "${EXTRA[@]}" 2>"${WORK}/init-killed.err" &
wpid=$!
sleep 0.2
kill -9 "${wpid}" 2>/dev/null || true
wait "${wpid}" 2>/dev/null || true
if grep -qE '^x4 ready ' "${VOL}/.hippius-dedicated-disks"; then
    # The whole wipe beat the kill on this runner: roll the record back to
    # what a power loss before the end leaves behind.
    echo "dedicated-disks-e2e: (the wipe finished before the kill; simulating the interruption)"
    sed -i 's/^x4 ready /x4 formatting /' "${VOL}/.hippius-dedicated-disks"
fi
grep -qE '^x4 formatting ' "${VOL}/.hippius-dedicated-disks" \
    && ok "an interrupted wipe leaves the record formatting" || err "record after kill: $(cat "${VOL}/.hippius-dedicated-disks")"
u4="$(awk '$1=="x4" {print $3}' "${VOL}/.hippius-dedicated-disks")"
close_all
open_run
expect x4 "initializing init-0" "an interrupted wipe starts again from scratch on the next boot"
[[ "$(cryptsetup luksUUID "${LI}")" == "${u4}" ]] && ok "same UUID on the re-format" || err "x4 uuid changed"
t0="$(date +%s.%N)"
init_run || err "the wipe exited non-zero: $(tail -3 "${WORK}/init.err")"
t1="$(date +%s.%N)"
cat "${WORK}/init.err" >> "${WORK}/all.err"
python3 -I -c "import sys; s=float(sys.argv[2])-float(sys.argv[1]); print(f'dedicated-disks-e2e: x4 wipe {int(sys.argv[3])>>20} MiB in {s:.2f} s = {int(sys.argv[3])/s/1e6:.0f} MB/s (no-journal dm-integrity on a loop device)')" "${t0}" "${t1}" "${isz}"
expect x4 "attached -" "after the wipe"
[[ -b /dev/mapper/hippius-x4 && ! -e /dev/mapper/hippius-x4-init && -b /dev/mapper/hippius-x4_dif ]] \
    && ok "renamed hippius-x4 (+ hippius-x4_dif)" || err "x4 names: $(ls /dev/mapper)"
[[ "$(dmsetup table hippius-x4_dif | awk '{print $7}')" == J ]] \
    && ok "x4: switched to the integrity journal" || err "x4 _dif: $(dmsetup table hippius-x4_dif)"
grep -qE "^x4 ready ${u4} 1 integrity$" "${VOL}/.hippius-dedicated-disks" \
    && ok "record: x4 ready (after the wipe only)" || err "record: $(cat "${VOL}/.hippius-dedicated-disks")"
dd if=/dev/mapper/hippius-x4 of=/dev/null bs=4M iflag=direct status=none \
    && ok "x4: the whole device reads back (every tag initialised)" || err "x4: a full read failed after the wipe"
# Throughput, plain vs integrity (journaled), O_DIRECT 4 MiB, 256 MiB each
# way: loop devices on a CI runner, so only the ratio means anything.
rate() { # label dd-args...
    local label="$1" t0 t1
    shift
    t0="$(date +%s.%N)"
    dd "$@" bs=4M count=64 status=none || err "${label}: dd failed"
    t1="$(date +%s.%N)"
    python3 -I -c "import sys; print(f'dedicated-disks-e2e: {sys.argv[1]}: {256/(float(sys.argv[3])-float(sys.argv[2])):.0f} MiB/s')" "${label}" "${t0}" "${t1}"
}
rate "plain write" if=/dev/zero of=/dev/mapper/hippius-x0 seek=128 oflag=direct
rate "integrity write" if=/dev/zero of=/dev/mapper/hippius-x4 seek=64 oflag=direct
rate "plain read" if=/dev/mapper/hippius-x0 of=/dev/null skip=128 iflag=direct
rate "integrity read" if=/dev/mapper/hippius-x4 of=/dev/null skip=64 iflag=direct
# Data through the mapping, a reboot: same UUID, journaled, no re-format.
B=$(( isz / 4096 / 2 ))
head -c 4096 /dev/urandom > "${WORK}/s4"
dd if="${WORK}/s4" of=/dev/mapper/hippius-x4 bs=4096 seek="${B}" count=1 oflag=direct,sync status=none
close_all
cp --sparse=never "${LI}" "${WORK}/x4-before.img" 2>/dev/null || dd if="${LI}" of="${WORK}/x4-before.img" bs=4M status=none
open_run
expect x4 "attached -" "reopened after a reboot"
[[ "$(cryptsetup luksUUID "${LI}")" == "${u4}" ]] && ok "x4: same UUID after the reboot" || err "x4 uuid changed"
[[ ! -e "${RUNDIR}/init" ]] && ok "a finished wipe is never redone (no init list)" || err "init list after the wipe: $(cat "${RUNDIR}/init")"
[[ "$(dmsetup table hippius-x4_dif | awk '{print $7}')" == J ]] && ok "x4 reopened journaled" || err "x4 reopen mode"
dd if=/dev/mapper/hippius-x4 bs=4096 skip="${B}" count=1 iflag=direct status=none | cmp -s - "${WORK}/s4" \
    && ok "x4: data survives the reboot" || err "x4: data lost"
echo "dedicated-disks-e2e: x4 status: $(cryptsetup status hippius-x4 | tr '\n' '|')"
# Tamper ONE ciphertext block on the raw device: find where block B landed
# (the 4 KiB raw block, past the journal, whose bytes changed wholesale
# between the two images), flip a byte, reopen: that block reads EIO,
# its neighbours read fine.
# Rewrite B with new bytes so the before/after diff names its location.
head -c 4096 /dev/urandom > "${WORK}/s4b"
dd if="${WORK}/s4b" of=/dev/mapper/hippius-x4 bs=4096 seek="${B}" count=1 oflag=direct,sync status=none
close_all
raw="$(python3 -I - "${WORK}/x4-before.img" "${LI}" <<'PY'
import sys
a, b = open(sys.argv[1], "rb"), open(sys.argv[2], "rb")
best, off = None, 0
while True:
    x, y = a.read(1 << 20), b.read(1 << 20)
    if not x or not y:
        break
    for i in range(0, min(len(x), len(y)), 4096):
        bx, by = x[i:i + 4096], y[i:i + 4096]
        if bx != by and sum(p != q for p, q in zip(bx, by)) > 3500:
            best = off + i
    off += len(x)
print(best if best is not None else "")
PY
)"
if [[ -n "${raw}" ]]; then
    printf '\xff' | dd of="${LI}" bs=1 seek=$(( raw + 100 )) conv=notrunc status=none
    printf '\x00' | dd of="${LI}" bs=1 seek=$(( raw + 101 )) conv=notrunc status=none
    open_run
    expect x4 "attached -" "the header is intact"
    if dd if=/dev/mapper/hippius-x4 of=/dev/null bs=4096 skip="${B}" count=1 iflag=direct status=none 2>/dev/null; then
        err "x4: a tampered ciphertext block read back without an error"
    else
        ok "x4: the tampered ciphertext block (raw offset ${raw}) reads as an I/O error"
    fi
    dd if=/dev/mapper/hippius-x4 of=/dev/null bs=4096 skip=$(( B - 1 )) count=1 iflag=direct status=none \
        && dd if=/dev/mapper/hippius-x4 of=/dev/null bs=4096 skip=$(( B + 1 )) count=1 iflag=direct status=none \
        && ok "x4: its neighbours still read" || err "x4: a neighbour of the tampered block fails"
else
    err "could not locate block ${B} on the raw device"
fi
close_all
# The anchor and the record must agree: x4 as a plain slot is refused.
anchor x0:1000,x1:1000,x4:1
open_run
expect x4 "mismatch mode-mismatch" "an integrity slot is never opened as a plain one"
close_all
# An unknown suffix refuses every slot.
anchor x0:1000,x4:1:z
open_run
expect x0 "mismatch anchor-mode"
expect x4 "mismatch anchor-mode"
close_all
rm -f "${WORK}/x4-before.img"
EXTRA=()

# Key bytes never in the diagnostics.
k0hex="$(od -An -tx1 "${WORK}/k0" | tr -d ' \n')"
k4hex="$(od -An -tx1 "${WORK}/k4" | tr -d ' \n')"
if grep -qiE "${k0hex:0:16}|${k4hex:0:16}|${k4hex:128:16}" "${WORK}/all.err"; then err "key bytes in the log"; else ok "no key bytes in any run's log"; fi

[[ "${fail}" -eq 0 ]] || { echo "dedicated-disks-e2e: FAILED" >&2; exit 1; }
echo "dedicated-disks-e2e: OK (all checks passed)"
