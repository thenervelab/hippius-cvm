#!/usr/bin/env bash
# Fixture test for scripts/tenant-initrd-rebuild.sh — root-free, no S3,
# no real bake.
#
# The chroot mkinitramfs itself needs root + a real distro tree, so it is
# replaced through the script's HCC_TEST_INITRD_BUILDER seam by a fixture
# builder that emits a deterministic newc initrd. Everything AROUND the
# build runs for real: fetching (through an `aws` shim backed by a temp
# dir), the source sha checks against measurement.json + --expect pins,
# the bzImage kernel-version read, the initrd cpio/decompression parser,
# the squashfs base preflight (unsquashfs -lls / -cat on a real squashfs),
# the SOURCE_DATE_EPOCH derivation, the output checks (kernel version,
# new scripts landed, reused bytes untouched), the measurement shape and
# the new-prefix-only upload.
#
# Pinned:
#   - the DEFAULT inputs are the base's own scripts (checked against the
#     source initrd) + ALL the shipped strict patches, in name order; each
#     shipped patch is exactly main's change (reverse-applies, newest
#     first, to the repo's hippius-golden-overlay.sh, leaving none of its
#     code); a base that already carries the M0 guard takes the later
#     patches by explicit --patch, and the default path refuses it;
#   - the rebuilt initrd may differ from the source one only in the
#     changed inputs' files + the known host noise (changed, not added);
#   - every refusal exits 3 with its message (sha mismatch per artifact,
#     --expect pin, non-golden source, kernel mismatches, rhel base,
#     non-hippius base, stale scripts in the output, output prefix nested
#     in / non-empty);
#   - the output measurement is the source one with ONLY initrd_sha256
#     changed + the initrd_rebuild provenance object;
#   - two runs over the same inputs give the same initrd + measurement
#     sha, and the SDE is the source squashfs mkfs time;
#   - the source prefix is byte-unchanged after an upload.
#
# Needs: bash, python3, jq, sha256sum, GNU patch, mksquashfs + unsquashfs (>= 4.6).
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOOL="${HERE}/../tenant-initrd-rebuild.sh"
REAL_SCRIPTS="${HERE}/../initramfs"
SHIPPED_PATCH="${REAL_SCRIPTS}/rebuild-patches/m0-initramfs-guard.patch"
# Every shipped patch, in the order the default path applies them (name).
SHIPPED_PATCHES=("${REAL_SCRIPTS}"/rebuild-patches/*.patch)
[[ "${SHIPPED_PATCHES[0]}" == "${SHIPPED_PATCH}" ]] \
    || { echo "tenant-initrd-rebuild-test: the M0 patch must sort first in rebuild-patches/" >&2; exit 1; }
[[ -x "${TOOL}" ]] || { echo "tenant-initrd-rebuild-test: ${TOOL} missing or not executable" >&2; exit 1; }
for t in python3 jq mksquashfs unsquashfs sha256sum patch; do
    command -v "${t}" >/dev/null 2>&1 || { echo "tenant-initrd-rebuild-test: ${t} not installed" >&2; exit 1; }
done

T="$(mktemp -d)"
trap 'rm -rf -- "${T}"' EXIT

fail=0
ok()  { echo "tenant-initrd-rebuild-test: OK — $*"; }
err() { echo "tenant-initrd-rebuild-test: FAIL — $*" >&2; fail=1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

KVER="6.12.99+deb13-amd64"   # '+' on purpose: a regex-built lookup once missed it
REPO_COMMIT="0123456789abcdef0123456789abcdef01234567"

# ── fixture helpers (python) ────────────────────────────────────────
FX="${T}/fx.py"
cat > "${FX}" <<'PY_EOF'
import gzip, json, os, struct, sys

def newc(entries):
    """entries: list of (name, mode, data_bytes). Returns one newc archive."""
    out = bytearray()
    def emit(name, mode, data, ino):
        nb = name.encode() + b"\0"
        hdr = "070701" + "".join("%08x" % v for v in (
            ino, mode, 0, 0, 1, 86400, len(data), 0, 0, 0, 0, len(nb), 0))
        out.extend(hdr.encode()); out.extend(nb)
        while len(out) % 4: out.append(0)
        out.extend(data)
        while len(out) % 4: out.append(0)
    for i, (n, m, d) in enumerate(entries, 1):
        emit(n, m, d, i)
    emit("TRAILER!!!", 0, b"", 0)
    return bytes(out)

def initrd(path, kver, files, vermagic=None):
    """Early uncompressed cpio + gzip'd main cpio, like a real initramfs.
    files: {rel: (mode, bytes)}; one fake module whose modinfo vermagic
    is <vermagic or kver>."""
    early = newc([("kernel", 0o40755, b""), ("kernel/x86", 0o40755, b"")])
    ko = b"\x7fELF....vermagic=%s SMP preempt mod_unload\0license=GPL\0" % (vermagic or kver).encode()
    main = [("usr", 0o40755, b""), ("lib", 0o120777, b"usr/lib"),
            ("usr/lib/modules/%s" % kver, 0o40755, b""),
            ("usr/lib/modules/%s/modules.dep" % kver, 0o100644, b""),
            ("usr/lib/modules/%s/kernel/fake.ko" % kver, 0o100644, ko)]
    for name, (mode, data) in sorted(files.items()):
        main.append((name, mode, data))
    blob = early + b"\0" * 8 + gzip.compress(newc(main), mtime=0)
    open(path, "wb").write(blob)

def vmlinuz(path, kver):
    d = bytearray(0x1000)
    d[0x202:0x206] = b"HdrS"
    s = ("%s (fixture@build) #1 SMP" % kver).encode() + b"\0"
    off = 0x400
    struct.pack_into("<H", d, 0x20E, off)
    d[off + 0x200: off + 0x200 + len(s)] = s
    open(path, "wb").write(bytes(d))

cmd = sys.argv[1]
if cmd == "vmlinuz":
    vmlinuz(sys.argv[2], sys.argv[3])
elif cmd == "initrd":  # path kver [rel=mode:file ...]; FX_VERMAGIC overrides the module's
    files = {}
    for kv in sys.argv[4:]:
        rel, spec = kv.split("=", 1)
        mode, src = spec.split(":", 1)
        files[rel] = (int(mode, 8), open(src, "rb").read())
    initrd(sys.argv[2], sys.argv[3], files, os.environ.get("FX_VERMAGIC") or None)
PY_EOF
fx() { python3 "${FX}" "$@"; }

# The fixture builder the tool calls instead of the chroot:
#   <rootfs.img> <kver> <sde> <scripts-dir> <out>
# FX_BUILD_KVER / FX_BUILD_STALE_OVERLAY / FX_BUILD_OVERLAY_MODE /
# FX_BUILD_NO_ORDER / FX_VERMAGIC inject the output-side faults.
BUILDER="${T}/builder.sh"
cat > "${BUILDER}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
kver="\${FX_BUILD_KVER:-\$2}"
sd="\$4"
overlay="\${sd}/hippius-golden-overlay.sh"
[[ -z "\${FX_BUILD_STALE_OVERLAY:-}" ]] || overlay="\${FX_BUILD_STALE_OVERLAY}"
fxtmp="\$(mktemp -d)"
trap 'rm -r -- "\${fxtmp}"' EXIT
order="\${fxtmp}/ORDER.fixture"
confmod="\${fxtmp}/modules.fixture"
printf '%s' "\${FX_BUILD_CONF_MODULES:-}" > "\${confmod}"
extra=()
[[ -z "\${FX_BUILD_EXTRA:-}" ]] || extra+=("\${FX_BUILD_EXTRA}=100644:\${confmod}")
if [[ -z "\${FX_BUILD_NO_ORDER:-}" ]]; then
    printf '/scripts/init-bottom/hippius-net-teardown "\$@"\n[ -e /conf/param.conf ] && . /conf/param.conf\n' > "\${order}"
else
    printf '/scripts/init-bottom/udev "\$@"\n' > "\${order}"
fi
python3 "${FX}" initrd "\$5" "\${kver}" \\
    "usr/lib/hippius/hippius-golden-overlay.sh=\${FX_BUILD_OVERLAY_MODE:-100644}:\${overlay}" \\
    "usr/lib/hippius/hippius-release-core.sh=100644:\${sd}/hippius-release-core.sh" \\
    "scripts/hippius-golden=100755:\${sd}/hippius-golden-boot" \\
    "scripts/init-bottom/hippius-net-teardown=100755:\${sd}/hippius-net-teardown" \\
    "scripts/init-bottom/ORDER=100644:\${order}" \\
    "usr/sbin/hippius-luks-keyscript=100755:\${sd}/hippius-luks-keyscript" \\
    "conf/modules=100644:\${confmod}" \${extra[@]+"\${extra[@]}"}
EOF
chmod 0755 "${BUILDER}"

# The scripts an OLD golden base carries: the repo's own, minus the
# shipped patch. Also the lockstep check: the shipped patch must be EXACTLY
# main's guard. It must reverse-apply to the repo overlay with no fuzz (a
# stale patch, or a later edit of any guard line on main, fails that), and
# the result must carry no trace of the guard (a partial patch leaves some).
OLD_SCRIPTS="${T}/old-scripts"
mkdir -p "${OLD_SCRIPTS}"
find "${REAL_SCRIPTS}" -maxdepth 1 -type f -exec cp {} "${OLD_SCRIPTS}/" \;
# Remnant patterns per shipped patch. `_hippius_golden_relabel_from`
# counts by its DEFINITION only: the M0 guard ships it, the data bind calls it.
# Likewise the data path's two constants: later code that only a fresh bake
# ships (the cdn-node ephemeral root) uses them.
remnant_re() {
    case "$(basename "$1")" in
        m0-initramfs-guard.patch) echo 'hippius_golden_harden_root|hippius_golden_has_no_credential_import|hippius_golden_write_masks|_hippius_golden_mask_path|_hippius_golden_relabel_from\(\)|M0 UNTRUSTED-MINER|99-zz-hippius-harden' ;;
        m1-golden-data-bind.patch) echo 'hippius_golden_bind_data|HIPPIUS_GOLDEN_DATA_(NAME|MOUNT)=|/var/lib/hippius-data' ;;
        m2-golden-mask-data-disk.patch) echo 'hippius-data-disk' ;;
        m3-golden-sshd-key-only.patch) echo '00-hippius-harden|HIPPIUS_SSHD_HARDEN|sshd key-only|_hippius_golden_selinux_ctx' ;;
        m4-golden-guest-components.patch) echo 'hippius_golden_mount_components|_hippius_golden_components_|HIPPIUS_GUEST_|hippius_golden_parse_release' ;;
        *) echo "__no_remnant_pattern_for_$(basename "$1")__" ;;
    esac
}
# Reverse-apply newest first: each patch must come off with no fuzz, and
# once ALL are off none of their code may be left. The overlay with the
# later patches off but M0 still in = what an M0-era base (bakes m0b, b2)
# carries.
OLD_M0_SCRIPTS="${T}/old-m0-scripts"
for (( i = ${#SHIPPED_PATCHES[@]} - 1; i >= 0; i-- )); do
    pf="${SHIPPED_PATCHES[i]}"
    if [[ ${i} -eq 0 ]]; then
        mkdir -p "${OLD_M0_SCRIPTS}"; cp "${OLD_SCRIPTS}"/* "${OLD_M0_SCRIPTS}/"
    fi
    patch --fuzz=0 --reverse --batch --no-backup-if-mismatch -r - "${OLD_SCRIPTS}/hippius-golden-overlay.sh" < "${pf}" >/dev/null 2>&1 \
        || err "shipped patch $(basename "${pf}") does not reverse-apply to scripts/initramfs/hippius-golden-overlay.sh (after the later ones) — stale vs main; regenerate it"
done
for pf in "${SHIPPED_PATCHES[@]}"; do
    remnants="$(grep -nE "$(remnant_re "${pf}")" "${OLD_SCRIPTS}/hippius-golden-overlay.sh" || true)"
    if [[ -z "${remnants}" ]]; then
        ok "shipped $(basename "${pf}") = main's whole change (reverse-applies, nothing left behind)"
    else
        err "shipped $(basename "${pf}") is PARTIAL — the repo overlay minus the patches still carries its code: ${remnants}"
    fi
done
PATCHED_OVERLAY="${T}/patched-overlay"
cp "${OLD_SCRIPTS}/hippius-golden-overlay.sh" "${PATCHED_OVERLAY}"
for pf in "${SHIPPED_PATCHES[@]}"; do
    patch --fuzz=0 --batch --no-backup-if-mismatch -r - "${PATCHED_OVERLAY}" < "${pf}" >/dev/null
done
cmp -s "${PATCHED_OVERLAY}" "${REAL_SCRIPTS}/hippius-golden-overlay.sh" \
    && ok "the old overlay + every shipped patch, in order = the repo overlay" \
    || err "the old overlay + the shipped patches differ from the repo overlay"

# The --scripts-dir override's scripts: the old ones with a marker
# appended to the overlay, so old ≠ new is observable.
NEW_SCRIPTS="${T}/new-scripts"
mkdir -p "${NEW_SCRIPTS}"
cp "${OLD_SCRIPTS}"/* "${NEW_SCRIPTS}/"
echo "# fixture: new guard" >> "${NEW_SCRIPTS}/hippius-golden-overlay.sh"

# make_bake <dir> [os_id] [modules_kver] [initrd_kver] [sde] [omit_dest]
make_bake() {
    local d="$1" os_id="${2:-debian}" mod_kver="${3:-${KVER}}" initrd_kver="${4:-${KVER}}" sde="${5:-86400}" omit="${6:-}"
    local tree="${d}.tree"
    mkdir -p "${d}" "${tree}/usr/lib/modules/${mod_kver}" "${tree}/usr/sbin" "${tree}/etc/hippius" \
        "${tree}/usr/lib/hippius" "${tree}/etc/initramfs-tools/hooks" "${tree}/etc/initramfs-tools/scripts/init-bottom"
    ln -s usr/lib "${tree}/lib"
    ln -s usr/sbin "${tree}/sbin"
    printf 'ID=%s\nID_LIKE=%s\n' "${os_id}" "$([[ "${os_id}" == centos ]] && echo "rhel fedora" || echo debian)" > "${tree}/usr/lib/os-release"
    ln -s ../usr/lib/os-release "${tree}/etc/os-release"
    : > "${tree}/usr/sbin/mkinitramfs"
    local pf
    for pf in hippius-release-core.sh:etc/hippius/hippius-release-core.sh \
              hippius-release-core.sh:usr/lib/hippius/hippius-release-core.sh \
              hippius-golden-overlay.sh:etc/hippius/hippius-golden-overlay.sh \
              hippius-golden-overlay.sh:usr/lib/hippius/hippius-golden-overlay.sh \
              hippius-golden-boot:etc/hippius/hippius-golden-boot \
              hippius-golden-hook:etc/initramfs-tools/hooks/hippius-golden \
              hippius-luks-keyscript:etc/hippius/hippius-luks-keyscript \
              hippius-luks-keyscript:usr/sbin/hippius-luks-keyscript \
              hippius-net-teardown:etc/initramfs-tools/scripts/init-bottom/hippius-net-teardown \
              hippius-luks-hook:etc/initramfs-tools/hooks/hippius-luks; do
        [[ "${pf#*:}" == "${omit}" ]] && continue
        cp "${FX_SCRIPTS:-${OLD_SCRIPTS}}/${pf%%:*}" "${tree}/${pf#*:}"
    done
    # FX_BASE_TWEAK=<path>: that one base copy drifts from its twin.
    [[ -z "${FX_BASE_TWEAK:-}" ]] || echo "# drift" >> "${tree}/${FX_BASE_TWEAK}"
    SOURCE_DATE_EPOCH="${sde}" mksquashfs "${tree}" "${d}/rootfs.img" -noappend -all-root -quiet -no-progress >/dev/null
    head -c 8192 /dev/zero | tr '\0' 'v' > "${d}/rootfs.verity"
    fx vmlinuz "${d}/tenant.vmlinuz" "${KVER}"
    # The source initrd = the fixture builder over the base's scripts,
    # with the build host's efivarfs leaked into conf/modules.
    # FX_SRC_OVERLAY: the initrd carries another overlay than the base.
    FX_BUILD_KVER="${initrd_kver}" FX_BUILD_CONF_MODULES=efivarfs FX_BUILD_STALE_OVERLAY="${FX_SRC_OVERLAY:-}" \
        "${BUILDER}" "${d}/rootfs.img" "${initrd_kver}" "${sde}" "${FX_SCRIPTS:-${OLD_SCRIPTS}}" "${d}/tenant.initrd.img"
    jq -n \
        --arg ri "$(sha "${d}/rootfs.img")" --argjson ris "$(stat -c %s "${d}/rootfs.img")" \
        --arg rv "$(sha "${d}/rootfs.verity")" --argjson rvs "$(stat -c %s "${d}/rootfs.verity")" \
        --arg k "$(sha "${d}/tenant.vmlinuz")" --arg i "$(sha "${d}/tenant.initrd.img")" \
        '{disk_mode:"golden_verity_overlay", rootfs_img_path:"/work/out/golden-x.rootfs.img",
          rootfs_img_sha256:$ri, rootfs_img_size_bytes:$ris,
          rootfs_verity_path:"/work/out/golden-x.rootfs.verity",
          rootfs_verity_sha256:$rv, rootfs_verity_size_bytes:$rvs,
          verity_root_hash:("ab" * 32), verity_salt:("00" * 32),
          verity_uuid:"00000000-0000-0000-0000-000000000000", verity_hash_alg:"sha256",
          verity_data_block_size:4096, verity_hash_block_size:4096,
          base_image_url:"https://example.invalid/base.img", base_image_sha256:("cd" * 32),
          kbs_url:"vsock://2:19266", kernel_sha256:$k, initrd_sha256:$i}' > "${d}/golden.measurement.json"
}

# run <name> [tool args...] — runs the tool with the fixture builder; sets RC + OUT.
run() {
    local name="$1"; shift
    set +e
    OUT="$(HCC_TEST_INITRD_BUILDER="${BUILDER}" "${TOOL}" --source-bake-id fixture-bake \
        --repo-commit "${REPO_COMMIT}" --work-dir "${T}/work-${name}" "$@" 2>&1)"
    RC=$?
    set -e
}

expect_refusal() {  # <case> <message fragment> -- run args...
    local name="$1" frag="$2"; shift 3
    run "${name}" "$@"
    if [[ ${RC} -eq 3 && "${OUT}" == *"${frag}"* ]]; then
        ok "refuses: ${name}"
    else
        err "${name}: expected exit 3 with '${frag}', got rc=${RC}: ${OUT}"
    fi
}

# ── happy path + measurement shape ──────────────────────────────────
GOOD="${T}/good"
make_bake "${GOOD}"
run good1 --source-dir "${GOOD}" --output-dir "${T}/out1"
if [[ ${RC} -ne 0 ]]; then
    err "default (base + patch) path failed rc=${RC}: ${OUT}"
else
    ok "default path: the base's own scripts + the shipped patch"
    M="${T}/out1/golden.measurement.json"
    jq -e --arg ov "$(sha "${PATCHED_OVERLAY}")" --arg ps "$(sha "${SHIPPED_PATCH}")" \
          --arg rc "$(sha "${OLD_SCRIPTS}/hippius-release-core.sh")" \
          --argjson np "${#SHIPPED_PATCHES[@]}" \
        '.initrd_rebuild.inputs_from == "base"
         and .initrd_rebuild.patches_sha256["m0-initramfs-guard.patch"] == $ps
         and (.initrd_rebuild.patches_sha256 | length) == $np
         and .initrd_rebuild.inputs_sha256["hippius-golden-overlay.sh"] == $ov
         and .initrd_rebuild.inputs_sha256["hippius-release-core.sh"] == $rc
         and ([.initrd_rebuild.initrd_changes[] | "\(.kind) \(.path)"] | sort)
             == ["host-noise conf/modules", "input usr/lib/hippius/hippius-golden-overlay.sh"]' "${M}" >/dev/null \
        && ok "only the patched overlay + the host noise changed; release-core stays the base's" \
        || err "default-path provenance wrong: $(jq -c .initrd_rebuild "${M}")"
fi
run good1b --source-dir "${GOOD}" --output-dir "${T}/out1b"
[[ ${RC} -eq 0 && "$(sha "${T}/out1/tenant.initrd.img")" == "$(sha "${T}/out1b/tenant.initrd.img")" ]] \
    && ok "default path: two runs → identical initrd" || err "default path runs diverge (rc=${RC})"

# ── an M0-era base (bakes m0b, b2): the later patches, by name ──────
# It already carries the guard, so the default path (every patch, M0
# first) must refuse it; naming the later patches brings it to main's
# overlay.
M0B="${T}/m0-era"
FX_SCRIPTS="${OLD_M0_SCRIPTS}" make_bake "${M0B}"
expect_refusal "m0-era-base-default-patches" "does not apply cleanly" -- --source-dir "${M0B}" --output-dir "${T}/o-m0d"
later=()
for pf in "${SHIPPED_PATCHES[@]:1}"; do later+=(--patch "${pf}"); done
if [[ ${#later[@]} -eq 0 ]]; then
    ok "no patch after M0 shipped — nothing to check on an M0-era base"
else
    run m0-era --source-dir "${M0B}" --output-dir "${T}/o-m0e" "${later[@]}"
    if [[ ${RC} -eq 0 ]] && jq -e --arg ov "$(sha "${REAL_SCRIPTS}/hippius-golden-overlay.sh")" \
            '.initrd_rebuild.inputs_sha256["hippius-golden-overlay.sh"] == $ov
             and (.initrd_rebuild.patches_sha256 | has("m0-initramfs-guard.patch") | not)' \
            "${T}/o-m0e/golden.measurement.json" >/dev/null; then
        ok "an M0-era base + the later patches by name = the repo overlay (no M0 re-applied)"
    else
        err "M0-era base + later patches: rc=${RC}: ${OUT}"
    fi
fi

# ── the --scripts-dir override ──────────────────────────────────────
run sd1 --source-dir "${GOOD}" --output-dir "${T}/out-sd1" --scripts-dir "${NEW_SCRIPTS}"
if [[ ${RC} -ne 0 ]]; then
    err "happy path failed rc=${RC}: ${OUT}"
else
    ok "happy path builds"
    for a in tenant.vmlinuz rootfs.img rootfs.verity; do
        [[ "$(sha "${T}/out-sd1/${a}")" == "$(sha "${GOOD}/${a}")" ]] && ok "${a} reused byte-for-byte" || err "${a} differs from the source"
    done
    new_sha="$(sha "${T}/out-sd1/tenant.initrd.img")"
    [[ "${new_sha}" != "$(sha "${GOOD}/tenant.initrd.img")" ]] && ok "initrd changed" || err "initrd did not change"
    M="${T}/out-sd1/golden.measurement.json"
    [[ "$(jq -r .initrd_sha256 "${M}")" == "${new_sha}" ]] && ok "measurement initrd_sha256 = new initrd" || err "measurement initrd_sha256 wrong"
    if [[ "$(jq -S 'del(.initrd_sha256, .initrd_rebuild)' "${M}")" == "$(jq -S 'del(.initrd_sha256)' "${GOOD}/golden.measurement.json")" ]]; then
        ok "every other measurement field is the source's"
    else
        err "measurement fields other than initrd_sha256 changed"
    fi
    jq -e --arg c "${REPO_COMMIT}" --arg si "$(sha "${GOOD}/tenant.initrd.img")" --arg k "${KVER}" \
        --arg ov "$(sha "${NEW_SCRIPTS}/hippius-golden-overlay.sh")" \
        '.initrd_rebuild.source_bake_id == "fixture-bake"
         and .initrd_rebuild.source_initrd_sha256 == $si
         and .initrd_rebuild.repo_commit == $c
         and .initrd_rebuild.kernel_version == $k
         and .initrd_rebuild.source_date_epoch == 86400
         and .initrd_rebuild.inputs_from == "scripts-dir"
         and .initrd_rebuild.patches_sha256 == {}
         and .initrd_rebuild.inputs_sha256["hippius-golden-overlay.sh"] == $ov' "${M}" >/dev/null \
        && ok "initrd_rebuild provenance recorded (bake id, source initrd, commit, kernel, SDE, inputs)" \
        || err "initrd_rebuild provenance incomplete: $(jq -c .initrd_rebuild "${M}")"
    [[ "${OUT}" == *'changed input "usr/lib/hippius/hippius-golden-overlay.sh"'* ]] \
        && ok "per-file diff vs the source initrd is logged" || err "no per-file diff in the log: ${OUT}"
fi

# ── reproducibility: same inputs → same bytes; SDE from the squashfs ─
run good2 --source-dir "${GOOD}" --output-dir "${T}/out2" --scripts-dir "${NEW_SCRIPTS}"
if [[ ${RC} -eq 0 && "$(sha "${T}/out-sd1/tenant.initrd.img")" == "$(sha "${T}/out2/tenant.initrd.img")" \
      && "$(sha "${T}/out-sd1/golden.measurement.json")" == "$(sha "${T}/out2/golden.measurement.json")" ]]; then
    ok "two runs → identical initrd + measurement"
else
    err "two runs diverge (rc=${RC})"
fi
SDEB="${T}/sde"
make_bake "${SDEB}" debian "${KVER}" "${KVER}" 1234567
run sde --source-dir "${SDEB}" --output-dir "${T}/out-sde"
[[ ${RC} -eq 0 && "$(jq .initrd_rebuild.source_date_epoch "${T}/out-sde/golden.measurement.json")" == 1234567 ]] \
    && ok "SOURCE_DATE_EPOCH = the source squashfs mkfs time" || err "SDE not derived from the squashfs (rc=${RC}): ${OUT}"

# ── refusals: the source ────────────────────────────────────────────
for a in rootfs.img rootfs.verity tenant.vmlinuz tenant.initrd.img; do
    B="${T}/tamper-${a}"
    make_bake "${B}"
    printf 'X' | dd of="${B}/${a}" bs=1 seek=3000 conv=notrunc status=none
    expect_refusal "tampered-${a}" "does not match the source measurement" -- --source-dir "${B}" --output-dir "${T}/o-${a}"
done
expect_refusal "expect-pin" "does not match the pinned --expect value" -- --source-dir "${GOOD}" --output-dir "${T}/o-pin" \
    --expect-initrd-sha256 "$(printf '%064d' 0)"
B="${T}/legacy"; make_bake "${B}"
jq '.disk_mode = "legacy_luks"' "${B}/golden.measurement.json" > "${B}/m" && mv "${B}/m" "${B}/golden.measurement.json"
expect_refusal "legacy-source" "not golden_verity_overlay" -- --source-dir "${B}" --output-dir "${T}/o-legacy"
B="${T}/initrd-kver"; make_bake "${B}" debian "${KVER}" "6.1.0-99-amd64"
expect_refusal "source-initrd-kernel" "inconsistent source bake" -- --source-dir "${B}" --output-dir "${T}/o-ik"
B="${T}/base-kver"; make_bake "${B}" debian "6.1.0-99-amd64"
expect_refusal "base-modules" "its modules do not match the source kernel" -- --source-dir "${B}" --output-dir "${T}/o-bk"
B="${T}/rhel"; make_bake "${B}" centos
expect_refusal "rhel-base" "dracut goldens are not supported" -- --source-dir "${B}" --output-dir "${T}/o-rhel"
B="${T}/nohook"; make_bake "${B}" debian "${KVER}" "${KVER}" 86400 etc/initramfs-tools/hooks/hippius-golden
expect_refusal "non-hippius-base" "not a hippius golden base" -- --source-dir "${B}" --output-dir "${T}/o-nh"

# ── refusals: the inputs (default path) ─────────────────────────────
echo "# not what the base carries" > "${T}/other-overlay"
B="${T}/src-mismatch"; FX_SRC_OVERLAY="${T}/other-overlay" make_bake "${B}"
expect_refusal "base-scripts-not-the-source-initrd" "not what the source initrd was built from" -- \
    --source-dir "${B}" --output-dir "${T}/o-srcm"
B="${T}/twin-drift"; FX_BASE_TWEAK=etc/hippius/hippius-golden-overlay.sh make_bake "${B}"
expect_refusal "base-twin-copies-differ" "differs from its other copy" -- --source-dir "${B}" --output-dir "${T}/o-twin"
expect_refusal "patch-already-applied" "does not apply cleanly" -- --source-dir "${GOOD}" --output-dir "${T}/o-twice" \
    --patch "${SHIPPED_PATCH}" --patch "${SHIPPED_PATCH}"
sed 's/^ hippius_golden_run() {$/ hippius_golden_run_renamed() {/' "${SHIPPED_PATCH}" > "${T}/fuzzy.patch"
expect_refusal "patch-context-mismatch" "does not apply cleanly" -- --source-dir "${GOOD}" --output-dir "${T}/o-fuzz" \
    --patch "${T}/fuzzy.patch"
sed 's|hippius-golden-overlay.sh|hippius-guest-release|g' "${SHIPPED_PATCH}" > "${T}/foreign.patch"
run foreign-patch --source-dir "${GOOD}" --output-dir "${T}/o-foreign" --patch "${T}/foreign.patch"
[[ ${RC} -eq 2 && "${OUT}" == *"which is not a hippius initramfs input"* ]] \
    && ok "refuses: a patch on a non-input file" || err "foreign patch: rc=${RC}: ${OUT}"

# ── refusals: the output ────────────────────────────────────────────
FX_BUILD_EXTRA=etc/unexpected expect_refusal "output-unexpected-file" 'beyond the changed inputs: added "etc/unexpected"' -- \
    --source-dir "${GOOD}" --output-dir "${T}/o-extra"
FX_BUILD_EXTRA=etc/unexpected run extra-allowed --source-dir "${GOOD}" --output-dir "${T}/o-extra-ok" \
    --allow-initrd-change etc/unexpected
[[ ${RC} -eq 0 ]] && ok "--allow-initrd-change accepts that path on purpose" || err "allow-initrd-change: rc=${RC}: ${OUT}"
FX_BUILD_EXTRA=.random-seed expect_refusal "output-noise-path-appears" 'beyond the changed inputs: added ".random-seed"' -- \
    --source-dir "${GOOD}" --output-dir "${T}/o-seed"
FX_BUILD_EXTRA=usr/conf/modules expect_refusal "output-no-usr-alias-outside-lib" 'added "usr/conf/modules"' -- \
    --source-dir "${GOOD}" --output-dir "${T}/o-usrconf"
FX_BUILD_EXTRA="usr/lib/hippius/hippius-golden-overlay.sh x" expect_refusal "output-path-with-a-space" \
    'added "usr/lib/hippius/hippius-golden-overlay.sh x"' -- --source-dir "${GOOD}" --output-dir "${T}/o-space"
FX_BUILD_CONF_MODULES=efivarfs run noise-kept --source-dir "${GOOD}" --output-dir "${T}/o-noise-kept"
[[ ${RC} -eq 0 && "$(jq -c '[.initrd_rebuild.initrd_changes[].path]' "${T}/o-noise-kept/golden.measurement.json")" \
    == '["usr/lib/hippius/hippius-golden-overlay.sh"]' ]] \
    && ok "without the host leak, the patched overlay is the ONLY change" || err "noise-kept: rc=${RC}: ${OUT}"
FX_BUILD_KVER="6.8.0-1-generic" expect_refusal "output-kernel" "rebuilt initrd carries modules for" -- \
    --source-dir "${GOOD}" --output-dir "${T}/o-okv"
echo "stale" > "${T}/stale-overlay"
FX_BUILD_STALE_OVERLAY="${T}/stale-overlay" expect_refusal "output-stale-scripts" "the new inputs did not land" -- \
    --source-dir "${GOOD}" --output-dir "${T}/o-stale"
FX_BUILD_OVERLAY_MODE=100755 expect_refusal "output-wrong-mode" "the new inputs did not land" -- \
    --source-dir "${GOOD}" --output-dir "${T}/o-mode"
FX_BUILD_NO_ORDER=1 expect_refusal "output-teardown-not-in-ORDER" "does not run /scripts/init-bottom/hippius-net-teardown" -- \
    --source-dir "${GOOD}" --output-dir "${T}/o-order"
FX_VERMAGIC="6.8.0-1-generic" expect_refusal "output-module-vermagic" "are not all built for" -- \
    --source-dir "${GOOD}" --output-dir "${T}/o-vermagic"
expect_refusal "future-sde" "is in the future" -- --source-dir "${GOOD}" --output-dir "${T}/o-future" \
    --source-date-epoch 99999999999
run octal-sde --source-dir "${GOOD}" --output-dir "${T}/o-octal" --source-date-epoch 02000000000
[[ ${RC} -eq 2 ]] && ok "refuses: a leading-zero SDE (bash would read it as octal)" || err "octal SDE: rc=${RC}: ${OUT}"
mkdir -p "${T}/used-work" && touch "${T}/used-work/leftover"
set +e
OUT="$(HCC_TEST_INITRD_BUILDER="${BUILDER}" "${TOOL}" --source-bake-id fixture-bake --scripts-dir "${NEW_SCRIPTS}" \
    --repo-commit "${REPO_COMMIT}" --work-dir "${T}/used-work" --source-dir "${GOOD}" --output-dir "${T}/o-used" 2>&1)"; RC=$?
set -e
[[ ${RC} -eq 2 && "${OUT}" == *"is not empty — use a fresh one"* ]] && ok "refuses: a reused work dir" || err "reused work dir: rc=${RC}: ${OUT}"
[[ ! -e "${T}/o-okv/tenant.initrd.img" && ! -e "${T}/o-stale/golden.measurement.json" ]] \
    && ok "a refused build emits nothing" || err "a refused build left output behind"

# ── S3: read the source, write only a NEW empty prefix ──────────────
S3="${T}/s3"
SHIM="${T}/bin"
mkdir -p "${SHIM}" "${S3}/bucket/tenant/golden-x"
cp "${GOOD}"/* "${S3}/bucket/tenant/golden-x/"
cat > "${SHIM}/aws" <<EOF
#!/usr/bin/env bash
# s3://bucket/key ⇔ ${S3}/bucket/key
set -euo pipefail
p() { local u="\$1"; [[ "\$u" == s3://* ]] && echo "${S3}/\${u#s3://}" || echo "\$u"; }
case "\$1 \$2" in
  "s3 cp") shift 2; [[ "\$1" == --only-show-errors ]] && shift
           src="\$(p "\$1")"; dst="\$(p "\$2")"; [[ -f "\$src" ]] || exit 1
           mkdir -p "\$(dirname "\$dst")"; cp "\$src" "\$dst" ;;
  "s3api list-objects-v2") [[ -z "\${FX_AWS_LIST_FAIL:-}" ]] || exit 254
           d="${S3}/\$4/\$6"; if [[ -d "\$d" ]]; then ls -A "\$d" | wc -l | tr -d ' '; else echo 0; fi ;;
  "s3api head-object") stat -c %s "${S3}/\$4/\$6" ;;
  *) echo "aws shim: unsupported \$*" >&2; exit 2 ;;
esac
EOF
chmod 0755 "${SHIM}/aws"
before="$(cd "${S3}/bucket/tenant/golden-x" && sha256sum ./* | sha256sum)"
PATH="${SHIM}:${PATH}" run s3-up --source-prefix s3://bucket/tenant/golden-x --output-dir "${T}/o-s3" \
    --output-prefix s3://bucket/tenant/golden-x-initrd1/
if [[ ${RC} -eq 0 ]]; then
    ok "upload to a new prefix"
    for a in tenant.vmlinuz rootfs.img rootfs.verity tenant.initrd.img golden.measurement.json; do
        cmp -s "${T}/o-s3/${a}" "${S3}/bucket/tenant/golden-x-initrd1/${a}" || err "uploaded ${a} differs"
    done
    jq -e '.initrd_rebuild.source_location == "s3://bucket/tenant/golden-x/"' \
        "${S3}/bucket/tenant/golden-x-initrd1/golden.measurement.json" >/dev/null \
        && ok "source prefix recorded" || err "source prefix not recorded"
else
    err "upload failed rc=${RC}: ${OUT}"
fi
after="$(cd "${S3}/bucket/tenant/golden-x" && sha256sum ./* | sha256sum)"
[[ "${before}" == "${after}" && "$(ls "${S3}/bucket/tenant/golden-x" | wc -l)" -eq 5 ]] \
    && ok "source prefix untouched" || err "source prefix was modified"
PATH="${SHIM}:${PATH}" expect_refusal "output-prefix-not-empty" "is not empty — never overwrite" -- \
    --source-prefix s3://bucket/tenant/golden-x --output-dir "${T}/o-s3b" --output-prefix s3://bucket/tenant/golden-x-initrd1
FX_AWS_LIST_FAIL=1 PATH="${SHIM}:${PATH}" expect_refusal "output-prefix-list-error" "whose emptiness is unknown" -- \
    --source-prefix s3://bucket/tenant/golden-x --output-dir "${T}/o-s3e" --output-prefix s3://bucket/tenant/golden-x-initrd9
PATH="${SHIM}:${PATH}" expect_refusal "output-prefix-inside-source" "is inside the source prefix" -- \
    --source-prefix s3://bucket/tenant/golden-x --output-dir "${T}/o-s3c" --output-prefix s3://bucket/tenant/golden-x/v2
PATH="${SHIM}:${PATH}" expect_refusal "output-prefix-contains-source" "contains the source prefix" -- \
    --source-prefix s3://bucket/tenant/golden-x --output-dir "${T}/o-s3d" --output-prefix s3://bucket/tenant

if [[ ${fail} -ne 0 ]]; then
    echo "tenant-initrd-rebuild-test: FAILED" >&2
    exit 1
fi
echo "tenant-initrd-rebuild-test: all checks passed"
