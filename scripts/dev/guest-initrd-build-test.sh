#!/usr/bin/env bash
# scripts/guest/guest-initrd-build.sh on fixtures (local dirs, no S3):
# the appended initrd per family, the output measurement (the shape
# vali_swap_vm_initrd reads + the guest_release object), reproducibility,
# --build-release, and every refusal. Root-free.
#
#   GUEST_RELEASE_TEST_STATIC_BUSYBOX=<static busybox> \
#       bash scripts/dev/guest-initrd-build-test.sh
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${HERE}/../.." && pwd)"
TOOL="${REPO}/scripts/guest/guest-initrd-build.sh"
BUILD="${REPO}/scripts/guest/build-guest-release.sh"
STATIC_BB="${GUEST_RELEASE_TEST_STATIC_BUSYBOX:?set GUEST_RELEASE_TEST_STATIC_BUSYBOX to a static busybox}"
for t in jq python3 cpio gzip mksquashfs unsquashfs rdsquashfs sha256sum; do
    command -v "${t}" >/dev/null 2>&1 || { echo "guest-initrd-build-test: ${t} not installed" >&2; exit 1; }
done

fail=0
ok()  { echo "guest-initrd-build-test: OK — $*"; }
err() { echo "guest-initrd-build-test: FAIL — $*" >&2; fail=1; }

T="$(mktemp -d)"
trap 'chmod -R u+w "${T}" 2>/dev/null; rm -r "${T}"' EXIT
# shellcheck source=scripts/dev/guest-initrd-fixtures.sh
. "${HERE}/guest-initrd-fixtures.sh"
sha() { sha256sum "$1" | cut -d' ' -f1; }
COMMIT="$(printf 'c%.0s' $(seq 40))"

# The release, from stub binaries.
mkdir -p "${T}/bins"
for b in hippius-agent-keepalive hippius-agent-tenant-telemetry hippius-agent-initramfs \
         hippius-guest-release hippius-vsock-ticket; do
    printf '#!/bin/sh\necho %s --attest-components\n' "${b}" > "${T}/bins/${b}"; chmod 0755 "${T}/bins/${b}"
done
"${BUILD}" --bin-dir "${T}/bins" --busybox "${STATIC_BB}" --commit "${COMMIT}" \
    --source-date-epoch 1700000000 --out "${T}/release" 2>/dev/null \
    || { echo "guest-initrd-build-test: cannot build the release" >&2; exit 1; }

# A golden base set of one family: kernel, base initrd, rootfs, verity and
# the measurement a bake writes.
KVER="6.8.0-90-generic"
mkset() {
    # mkset <dir> <family> [jq filter applied to the measurement] [loop: builtin|module|none]
    local dir="$1" family="$2" filter="${3:-.}" loop="${4:-builtin}"
    mkdir -p "${dir}"
    mktree "${dir}.tree" "${family}"
    mkbase "${dir}.tree" "${dir}/tenant.initrd.img"
    mkvmlinuz "${dir}/tenant.vmlinuz" "${KVER}"
    mkrootfs "${dir}/rootfs.img" "${KVER}" "${loop}"
    head -c 512 /dev/zero | tr '\0' 'v' > "${dir}/rootfs.verity"
    jq -n --arg k "$(sha "${dir}/tenant.vmlinuz")" --arg i "$(sha "${dir}/tenant.initrd.img")" \
        --arg r "$(sha "${dir}/rootfs.img")" --arg v "$(sha "${dir}/rootfs.verity")" \
        '{disk_mode: "golden_verity_overlay", kernel_sha256: $k, initrd_sha256: $i,
          rootfs_img_sha256: $r, rootfs_verity_sha256: $v,
          verity_root_hash: "'"$(printf 'e%.0s' $(seq 64))"'", distro: "x"}' \
        | jq "${filter}" > "${dir}/golden.measurement.json"
}
run() {
    # run <out> <source dir> [extra args...]
    local out="$1" src="$2"; shift 2
    "${TOOL}" --source-dir "${src}" --source-bake-id bake-1 --release-dir "${T}/release" \
        --output-dir "${out}" "$@" > "${T}/run.out" 2> "${T}/run.err"
}

for family in initramfs-tools dracut; do
    S="${T}/set-${family}"
    mkset "${S}" "${family}"
    O="${T}/out-${family}"
    run "${O}" "${S}" || { err "${family}: build failed: $(tail -3 "${T}/run.err")"; continue; }
    M="${O}/golden.measurement.json"
    base_len="$(stat -c %s "${S}/tenant.initrd.img")"
    pad=$(( (4 - base_len % 4) % 4 ))
    cmp -s <({ cat "${S}/tenant.initrd.img"; head -c "${pad}" /dev/zero; cat "${T}/release/release-${family}.cpio"; }) \
        "${O}/tenant.initrd.img" || err "${family}: the initrd is not base ‖ pad ‖ release member"
    [[ "$(jq -r .initrd_sha256 "${M}")" == "$(sha "${O}/tenant.initrd.img")" ]] || err "${family}: initrd_sha256"
    for k in kernel_sha256 rootfs_img_sha256 rootfs_verity_sha256 verity_root_hash disk_mode; do
        [[ "$(jq -r ".${k}" "${M}")" == "$(jq -r ".${k}" "${S}/golden.measurement.json")" ]] \
            || err "${family}: ${k} changed"
    done
    for a in tenant.vmlinuz rootfs.img rootfs.verity; do
        cmp -s "${S}/${a}" "${O}/${a}" || err "${family}: ${a} is not the base's"
    done
    # The keys vali_swap_vm_initrd reads.
    [[ "$(jq -r .initrd_rebuild.source_initrd_sha256 "${M}")" == "$(sha "${S}/tenant.initrd.img")" ]] \
        || err "${family}: initrd_rebuild.source_initrd_sha256"
    [[ "$(jq -r .initrd_rebuild.source_bake_id "${M}")" == bake-1 ]] || err "${family}: source_bake_id"
    [[ "$(jq -r .initrd_rebuild.method "${M}")" == append-guest-release ]] || err "${family}: method"
    [[ "$(jq -r .guest_release.family "${M}")" == "${family}" ]] || err "${family}: guest_release.family"
    [[ "$(jq -r .guest_release.version "${M}")" == "$(jq -r .version "${T}/release/release.json")" ]] \
        || err "${family}: guest_release.version"
    [[ "$(jq -r .guest_release.release_cpio_sha256 "${M}")" == "$(sha "${T}/release/release-${family}.cpio")" ]] \
        || err "${family}: guest_release.release_cpio_sha256"
    [[ "$(jq -r .guest_release.health_mask "${M}")" == "$(jq -r .health_mask "${T}/release/release.json")" ]] \
        || err "${family}: guest_release.health_mask"
    grep -q "^GUEST INITRD OK initrd_sha256=$(sha "${O}/tenant.initrd.img") .*family=${family}" "${T}/run.out" \
        || err "${family}: summary line: $(cat "${T}/run.out")"
    # Reproducible: a second run gives the same bytes.
    run "${T}/again-${family}" "${S}" || err "${family}: second run failed"
    for a in tenant.initrd.img golden.measurement.json; do
        cmp -s "${O}/${a}" "${T}/again-${family}/${a}" || err "${family}: ${a} not reproducible"
    done
done
ok "both families: base ‖ pad ‖ member, base artifacts untouched, measurement shape, reproducible"

# --build-release: the same release, built in place.
S="${T}/set-initramfs-tools"
"${TOOL}" --source-dir "${S}" --source-bake-id bake-1 --build-release --commit "${COMMIT}" \
    --source-date-epoch 1700000000 --bin-dir "${T}/bins" --busybox "${STATIC_BB}" \
    --output-dir "${T}/out-built" > /dev/null 2> "${T}/run.err" \
    || err "--build-release failed: $(tail -3 "${T}/run.err")"
cmp -s "${T}/out-built/tenant.initrd.img" "${T}/out-initramfs-tools/tenant.initrd.img" \
    || err "--build-release gave another initrd than the prebuilt release"
ok "--build-release builds the same release in place"

# Refusals.
refuse() {
    # refuse <what> <pattern> <source dir> [extra args]
    local what="$1" pat="$2" src="$3"; shift 3
    local out="${T}/refused-${RANDOM}"
    set +e; run "${out}" "${src}" "$@"; local rc=$?; set -e
    if [[ ${rc} -eq 0 ]]; then
        err "accepted: ${what}"
    elif ! grep -q -- "${pat}" "${T}/run.err"; then
        err "refused ${what} for another reason: $(tail -3 "${T}/run.err")"
    fi
    [[ ! -e "${out}/tenant.initrd.img" ]] || err "${what}: an initrd was left behind"
}
mkset "${T}/bad-sha" initramfs-tools; printf x >> "${T}/bad-sha/rootfs.img"
refuse "an artifact that does not match its measurement" "does not match the source measurement" "${T}/bad-sha"
refuse "a wrong --expect-initrd-sha256" "does not match the pinned" "${T}/set-initramfs-tools" \
    --expect-initrd-sha256 "$(printf 'a%.0s' $(seq 64))"
mkset "${T}/chained" initramfs-tools '.guest_release = {version: 1}'
refuse "a source that is already a release build" "never chained" "${T}/chained"
mkset "${T}/legacy" initramfs-tools '.disk_mode = "legacy_luks"'
refuse "a non-golden source" "not a golden_verity_overlay" "${T}/legacy"
refuse "a --family that is not the base's" "but the base initrd is" "${T}/set-dracut" --family initramfs-tools
mkset "${T}/no-hippius" initramfs-tools
rm -r "${T}/no-hippius.tree/usr/lib/hippius"
mkbase "${T}/no-hippius.tree" "${T}/no-hippius/tenant.initrd.img"
jq --arg i "$(sha "${T}/no-hippius/tenant.initrd.img")" '.initrd_sha256 = $i' \
    "${T}/no-hippius/golden.measurement.json" > "${T}/m.json" && mv "${T}/m.json" "${T}/no-hippius/golden.measurement.json"
refuse "a base the release does not merge over" "does not merge cleanly" "${T}/no-hippius"
cp -r "${T}/release" "${T}/release-tampered"
printf x >> "${T}/release-tampered/release-initramfs-tools.cpio"
set +e
"${TOOL}" --source-dir "${T}/set-initramfs-tools" --source-bake-id bake-1 --release-dir "${T}/release-tampered" \
    --output-dir "${T}/refused-tampered" >/dev/null 2>"${T}/run.err"
rc=$?
set -e
[[ ${rc} -ne 0 ]] && grep -q "does not match release.json" "${T}/run.err" \
    || err "accepted a release member that does not match release.json: $(tail -2 "${T}/run.err")"
mkset "${T}/no-loop" initramfs-tools . none
refuse "a base kernel without the loop driver" "no loop driver" "${T}/no-loop"
mkset "${T}/loop-module" initramfs-tools . module
run "${T}/out-loop-module" "${T}/loop-module" || err "a base with loop as a module was refused: $(tail -2 "${T}/run.err")"
# ... but only with the module really in the base, and a modprobe in the initrd.
mkset "${T}/loop-dep-only" initramfs-tools . module
python3 - "${T}/loop-dep-only" "${KVER}" <<'PYDEP'
import os, subprocess, sys, tempfile
d, kver = sys.argv[1], sys.argv[2]
t = tempfile.mkdtemp()
subprocess.run(["unsquashfs", "-no-xattrs", "-q", "-d", t + "/r", d + "/rootfs.img"], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.remove(f"{t}/r/usr/lib/modules/{kver}/kernel/drivers/block/loop.ko.zst")
os.remove(d + "/rootfs.img")
subprocess.run(["mksquashfs", t + "/r", d + "/rootfs.img", "-noappend", "-all-root", "-quiet"],
               check=True, stdout=subprocess.DEVNULL)
PYDEP
jq --arg r "$(sha "${T}/loop-dep-only/rootfs.img")" '.rootfs_img_sha256 = $r' "${T}/loop-dep-only/golden.measurement.json" \
    > "${T}/m.json" && mv "${T}/m.json" "${T}/loop-dep-only/golden.measurement.json"
refuse "a loop module listed in modules.dep but absent" "no loop driver" "${T}/loop-dep-only"
mkset "${T}/loop-no-modprobe" initramfs-tools . module
rm "${T}/loop-no-modprobe.tree/usr/sbin/modprobe"
mkbase "${T}/loop-no-modprobe.tree" "${T}/loop-no-modprobe/tenant.initrd.img"
jq --arg i "$(sha "${T}/loop-no-modprobe/tenant.initrd.img")" '.initrd_sha256 = $i' "${T}/loop-no-modprobe/golden.measurement.json" \
    > "${T}/m.json" && mv "${T}/m.json" "${T}/loop-no-modprobe/golden.measurement.json"
refuse "a loop module with no modprobe in the initrd" "does not merge cleanly" "${T}/loop-no-modprobe"
grep -q "command modprobe" "${T}/run.err" || err "the no-modprobe refusal does not name modprobe: $(tail -3 "${T}/run.err")"
# Chained by CONTENT: a release build fed back as a source, its provenance
# stripped from the measurement.
mkdir -p "${T}/stripped"
cp "${T}/out-initramfs-tools"/{tenant.vmlinuz,tenant.initrd.img,rootfs.img,rootfs.verity} "${T}/stripped/"
jq 'del(.guest_release, .initrd_rebuild)' "${T}/out-initramfs-tools/golden.measurement.json" \
    > "${T}/stripped/golden.measurement.json"
refuse "a release build with its provenance stripped" "already carries a guest release" "${T}/stripped"
mkdir -p "${T}/full"; : > "${T}/full/x"
set +e; run "${T}/full" "${T}/set-initramfs-tools"; rc=$?; set -e
[[ ${rc} -eq 2 ]] || err "accepted a non-empty --output-dir (rc=${rc})"
ok "refuses: a sha mismatch, a wrong pin, a chained release (by provenance and by content), a non-golden source, a wrong family, a base that does not merge, no loop driver (incl. a loop module listed but absent, or no modprobe to load it), a tampered release, a non-empty output dir; accepts loop as a module"

# ── S3 publication (a fake aws over a local dir) ────────────────────
mkdir -p "${T}/fakebin" "${T}/s3"
ln -s "${HERE}/fake-aws.sh" "${T}/fakebin/aws"
export FAKE_S3_ROOT="${T}/s3"
mkdir -p "${T}/s3/b1/tenant/base"
cp "${T}/set-initramfs-tools"/* "${T}/s3/b1/tenant/base/"
s3run() {
    # s3run <output prefix> [env...]: build from s3://b1/tenant/base/
    local outp="$1"; shift
    env PATH="${T}/fakebin:${PATH}" "$@" "${TOOL}" --source-prefix s3://b1/tenant/base/ --source-bake-id bake-1 \
        --release-dir "${T}/release" --output-dir "${T}/s3out-${RANDOM}" --output-prefix "${outp}" \
        > "${T}/run.out" 2> "${T}/run.err"
}
s3run s3://b1/tenant/out1/ || err "S3 publication failed: $(tail -3 "${T}/run.err")"
for a in tenant.vmlinuz tenant.initrd.img rootfs.img rootfs.verity golden.measurement.json .claim; do
    [[ -f "${T}/s3/b1/tenant/out1/${a}" ]] || err "S3: ${a} not published"
done
[[ "$(jq -r .s3_bucket "${T}/s3/b1/tenant/out1/golden.measurement.json")" == b1 ]] || err "S3: measurement s3_bucket"
[[ "$(jq -r .s3_key_prefix "${T}/s3/b1/tenant/out1/golden.measurement.json")" == tenant/out1 ]] || err "S3: measurement s3_key_prefix"
cmp -s "${T}/s3/b1/tenant/out1/tenant.initrd.img" "${T}/out-initramfs-tools/tenant.initrd.img" \
    || err "S3: the published initrd is not the local build's"
s3refuse() {
    # s3refuse <what> <pattern> <output prefix> [env...]
    local what="$1" pat="$2" outp="$3"; shift 3
    set +e; s3run "${outp}" "$@"; local rc=$?; set -e
    if [[ ${rc} -eq 0 ]]; then
        err "S3 accepted: ${what}"
    elif ! grep -q -- "${pat}" "${T}/run.err"; then
        err "S3 refused ${what} for another reason: $(tail -2 "${T}/run.err")"
    fi
}
s3refuse "a non-empty output prefix" "is not empty" s3://b1/tenant/out1/
s3refuse "a prefix another build claimed (lost race)" "could not claim" s3://b1/tenant/out1/ FAKE_S3_LIST_EMPTY=1
s3refuse "an initrd whose read-back differs" "read-back sha differs" s3://b1/tenant/out2/ FAKE_S3_CORRUPT=out2/tenant.initrd.img
[[ ! -e "${T}/s3/b1/tenant/out2/golden.measurement.json" ]] || err "S3: a measurement was published after a failed read-back"
s3refuse "an output bucket other than the base's" "cannot change a VM's bucket" s3://b2/tenant/out3/
ok "S3: claim, payloads read back, measurement last (with the output's bucket/prefix); refuses a used prefix, a lost claim, a bad read-back (no measurement), another bucket"

if [[ ${fail} -ne 0 ]]; then
    echo "guest-initrd-build-test: FAILED" >&2
    exit 1
fi
echo "guest-initrd-build-test: all passed"
