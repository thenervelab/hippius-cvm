#!/usr/bin/env bash
# Unit test for scripts/guest/hippius-disks (no root): it lists the slots
# from the opener's state file and PRINTS commands, never runs them.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${HERE}/../guest/hippius-disks"
fail=0
ok()  { echo "hippius-disks-test: OK — $*"; }
err() { echo "hippius-disks-test: FAIL — $*" >&2; fail=1; }

W="$(mktemp -d)"
trap 'rm -rf "${W}"' EXIT
mkdir -p "${W}/sys/dm-0" "${W}/sys/dm-1" "${W}/mapper" "${W}/bin"
# 22300 GiB and 22301 GiB in 512-byte sectors.
echo $((22300 * 2097152)) > "${W}/sys/dm-0/size"
echo $((22301 * 2097152)) > "${W}/sys/dm-1/size"
ln -s "${W}/sys/dm-0" "${W}/mapper/hippius-x0"
ln -s "${W}/sys/dm-1" "${W}/mapper/hippius-x1"
# Any of these on PATH would mean the tool ran one.
for t in mdadm zpool mkfs.xfs mkfs.ext4 wipefs cryptsetup; do
    printf '#!/bin/sh\necho RAN %s >> %s/ran\n' "$t" "${W}" > "${W}/bin/$t"
    chmod +x "${W}/bin/$t"
done
run() {
    PATH="${W}/bin:${PATH}" HIPPIUS_DISKS_STATE="$1" HIPPIUS_DISKS_SYS_BLOCK="${W}/sys" \
        HIPPIUS_DISKS_MAPPER_DIR="${W}/mapper" sh "${TOOL}"
}

out="$(run "${W}/none")"
[[ "${out}" == *"no dedicated disks"* ]] && ok "no state file: says so, exit 0" || err "no state: ${out}"

cat > "${W}/slots" <<'EOF'
# hippius-dedicated-disks state v1
x0 attached 22300 vdb -
x1 attached 22300 vdc -
x2 missing 22300 - absent
x3 mismatch 22300 vde uuid-mismatch
junk line here now
EOF
out="$(run "${W}/slots")"
grep -qE '^x0 +attached +22300 +/dev/mapper/hippius-x0' <<<"${out}" && ok "x0 listed with its mapper" || err "x0: ${out}"
grep -qE '^x1 +attached +22301 ' <<<"${out}" && ok "size from the live mapping" || err "x1 size: ${out}"
grep -qE '^x2 +missing .*absent' <<<"${out}" && ok "missing slot shown" || err "x2: ${out}"
grep -qE '^x3 +mismatch .*uuid-mismatch, device vde' <<<"${out}" && ok "mismatch slot shown with reason" || err "x3: ${out}"
grep -q 'junk' <<<"${out}" && err "junk line printed" || ok "junk lines skipped"
grep -q 'zpool create -o ashift=12 -O compression=lz4 tank mirror /dev/mapper/hippius-x0 /dev/mapper/hippius-x1' <<<"${out}" \
    && ok "ZFS mirror example over the attached disks only" || err "zfs example: ${out}"
grep -q 'mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/mapper/hippius-x0 /dev/mapper/hippius-x1' <<<"${out}" \
    && ok "mdadm RAID1 example" || err "mdadm example: ${out}"
[[ ! -e "${W}/ran" ]] && ok "nothing was run" || err "the tool RAN: $(cat "${W}/ran")"

printf 'x0 attached 1000 vdb -\nx1 attached 1000 vdc -\nx4 attached 1000 vdd -\nx5 attached 1000 vdf -\n' > "${W}/four"
out="$(run "${W}/four")"
grep -q 'raidz2' <<<"${out}" && grep -q -- '--level=6 --raid-devices=4' <<<"${out}" \
    && ok "four disks: raidz2 / RAID6 examples" || err "four: ${out}"

printf 'x0 attached 1000 vdb -\n' > "${W}/one"
out="$(run "${W}/one")"
grep -q 'mkfs.xfs -L data /dev/mapper/hippius-x0' <<<"${out}" && ! grep -q mdadm <<<"${out}" \
    && ok "one disk: filesystem / single-disk pool examples, no RAID" || err "one: ${out}"

printf 'x0 missing 1000 - absent\n' > "${W}/none-open"
out="$(run "${W}/none-open")"
[[ "${out}" == *"No dedicated disk is open."* ]] && ok "nothing open: no commands" || err "none open: ${out}"
[[ ! -e "${W}/ran" ]] && ok "still nothing run" || err "the tool RAN: $(cat "${W}/ran")"

# Integrity slots (guest release 8): one still initialising, one open with
# its dm-integrity layer, one that kept its init name this boot.
mkdir -p "${W}/sys/dm-2" "${W}/sys/dm-3" "${W}/sys/dm-4"
echo $((3500 * 2097152)) > "${W}/sys/dm-2/size"
echo $((3500 * 2097152)) > "${W}/sys/dm-4/size"
ln -s "${W}/sys/dm-2" "${W}/mapper/hippius-x6"
ln -s "${W}/sys/dm-3" "${W}/mapper/hippius-x6_dif"
ln -s "${W}/sys/dm-4" "${W}/mapper/hippius-x8-init"
cat > "${W}/integrity" <<'EOF'
# hippius-dedicated-disks state v1
x6 attached 3500 vdb -
x7 initializing 3500 vdc init-42
x8 attached 3500 vdd init-name
EOF
out="$(run "${W}/integrity")"
grep -qE '^x6 +attached +3500 +/dev/mapper/hippius-x6 +integrity \(AEAD\)' <<<"${out}" \
    && ok "an integrity slot is marked" || err "x6: ${out}"
grep -qE '^x7 +initializing .*42% done' <<<"${out}" && ok "initialising slot shows its progress" || err "x7: ${out}"
grep -qE '^x8 +attached +3500 +/dev/mapper/hippius-x8-init +named hippius-x8-init until the next boot' <<<"${out}" \
    && ok "a slot that kept its init name is listed under it" || err "x8: ${out}"
grep -q 'zpool create -o ashift=12 -O compression=lz4 tank mirror /dev/mapper/hippius-x6 /dev/mapper/hippius-x8-init' <<<"${out}" \
    && ok "examples over the usable disks only (never the initialising one)" || err "examples: ${out}"
grep -q 'The ones marked "integrity"' <<<"${out}" && ok "mixed integrity text" || err "integrity text: ${out}"
printf 'x6 attached 3500 vdb -\n' > "${W}/one-integrity"
out="$(run "${W}/one-integrity")"
grep -q 'a sector altered on the host reads as an I/O error' <<<"${out}" && ! grep -q 'NO integrity' <<<"${out}" \
    && ok "all-integrity text" || err "all-integrity: ${out}"
printf 'x7 initializing 3500 vdc init-0\n' > "${W}/only-init"
out="$(run "${W}/only-init")"
[[ "${out}" == *"No dedicated disk is open."* && "${out}" == *"written once in full"* ]] \
    && ok "only initialising: explained, no commands" || err "only init: ${out}"

if PATH="${W}/bin:${PATH}" sh "${TOOL}" --bogus >/dev/null 2>&1; then err "unknown flag accepted"; else ok "unknown flag refused"; fi

[[ "${fail}" -eq 0 ]] || { echo "hippius-disks-test: FAILED" >&2; exit 1; }
echo "hippius-disks-test: OK (all checks passed)"
