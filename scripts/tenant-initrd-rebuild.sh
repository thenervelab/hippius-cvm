#!/usr/bin/env bash
# `tenant-initrd-rebuild.sh` — rebuild ONLY the initramfs of an EXISTING
# golden (golden_verity_overlay) bake, against the hippius initramfs
# scripts of a given repo checkout.
#
# Why this exists: a full re-bake installs whatever kernel the distro
# ships today, whose modules the old dm-verity base does not carry, and
# swapping the base under a running tenant's overlay upper drifts their
# OS. To move running tenants onto a new initramfs guard (e.g. the M0
# guard in scripts/initramfs/hippius-golden-overlay.sh) the kernel and the
# base must stay byte-identical and ONLY tenant.initrd.img may change.
#
# What it does:
#   1. fetch the source bake (tenant.vmlinuz, tenant.initrd.img,
#      rootfs.img, rootfs.verity, golden.measurement.json) from an S3
#      prefix or a local dir, and REFUSE unless every artifact's sha256
#      matches the source measurement.json (and the optional --expect-*
#      pins, e.g. the vali TenantBake row);
#   2. read the kernel version out of the source vmlinuz (bzImage header)
#      and REFUSE unless the source initrd and the base's /lib/modules
#      carry exactly that kernel;
#   3. pick the hippius initramfs inputs. DEFAULT = the MINIMAL delta:
#      the copies the base itself carries (what the source initrd was
#      built from — REFUSE unless they are byte-equal to the ones inside
#      the source initrd), plus the shipped strict patches in
#      initramfs/rebuild-patches/ (m0: the #1305 M0 guard, m1: the #1347
#      data path, m2: the #1350 data-disk mask, m3: the sshd key-only
#      drop-in, m4: the guest components release step, a no-op until a
#      release is appended; an M0-era base takes m1..m4 by explicit
#      --patch) applied
#      in name order with no fuzz and no
#      rejects. The new scripts therefore only ever run
#      against the base's own hippius-guest-release & co. --scripts-dir
#      (whole scripts from a checkout) is an explicit override;
#   4. unsquashfs the base (the exact tree the original bake ran
#      update-initramfs in), overwrite the inputs that changed (same
#      destinations + modes as tenant-image-bake.sh), and run the base's
#      own mkinitramfs for that kernel inside a HERMETIC chroot: no host
#      /proc, /sys or /dev (the
#      bake's bind mounts leaked the build host's md arrays and EFI state
#      into the initrd), a synthetic /dev whose random/urandom read zeros
#      (the overlayroot hook bakes 4 KiB of /dev/random into
#      /.random-seed — public in a published initrd anyway, and the only
#      nondeterministic byte source), a fixed env (LC_ALL=C, TZ=UTC) and
#      SOURCE_DATE_EPOCH = the squashfs superblock mkfs time of the source
#      rootfs.img (the SDE the original bake used). mkinitramfs then clamps
#      every mtime, sorts the cpio (LC_ALL=C) with `cpio --reproducible`,
#      and compresses single-threaded — byte-reproducible;
#   5. REFUSE unless the new initrd carries exactly the source kernel's
#      modules, the hippius scripts it carries are byte-equal to the
#      inputs, and it differs from the source initrd ONLY in the files of
#      the inputs that changed plus the known build-host leaks the
#      hermetic build drops (INITRD_HOST_NOISE); the per-file diff is
#      logged. Re-check the reused artifacts' shas;
#   6. write the output set (reused kernel/rootfs/verity + new initrd +
#      golden.measurement.json of the same shape, new initrd_sha256, plus
#      an `initrd_rebuild` provenance object) to --output-dir and, with
#      --output-prefix, upload it to a NEW, EMPTY S3 prefix. The source
#      prefix is never written.
#
# Supported: apt / initramfs-tools goldens (Ubuntu, Debian). RHEL-family
# (dracut: CentOS Stream, Fedora) goldens are REFUSED for now — their
# initrd is dracut's, needs the 95hippius-golden module + an offline
# SELinux relabel of the staged files, and gets its own builder.
#
# Exit codes: 0 ok, 2 usage/tooling, 3 refused (a verification failed),
# 4 build failure.
#
# ── Operator note: one-off k8s Job (control-plane cluster, namespace vali)
# Run it in the tenant-baker image built from the commit whose
# rebuild-patches you want (the image ships this script at
# /usr/local/bin/ and the patches at /usr/local/bin/initramfs/), with
# the same S3 creds + endpoint the bake Jobs get:
#
#   apiVersion: batch/v1
#   kind: Job
#   metadata: {name: initrd-rebuild-<bake>, namespace: vali}
#   spec:
#     backoffLimit: 0
#     ttlSecondsAfterFinished: 86400
#     template:
#       spec:
#         restartPolicy: Never
#         imagePullSecrets: [{name: ghcr-pull-secret}]
#         containers:
#         - name: rebuild
#           image: ghcr.io/thenervelab/hippius-tenant-baker@sha256:<digest built from COMMIT>
#           command: ["/usr/local/bin/tenant-initrd-rebuild.sh"]
#           args: ["--source-prefix", "s3://hippius-compute-images/tenant/golden-<distro>-<bake>/",
#                  "--source-bake-id", "<SOURCE_BAKE_ID>",
#                  "--expect-initrd-sha256", "<TenantBake.initrd_sha256>",
#                  "--repo-commit", "<COMMIT>",
#                  "--output-dir", "/work/out",
#                  "--output-prefix", "s3://hippius-compute-images/tenant/golden-<distro>-<bake>-initrd-<short>/"]
#           env:
#           - {name: AWS_ACCESS_KEY_ID, valueFrom: {secretKeyRef: {name: vali-s3, key: access-key}}}
#           - {name: AWS_SECRET_ACCESS_KEY, valueFrom: {secretKeyRef: {name: vali-s3, key: secret-key}}}
#           - {name: AWS_ENDPOINT_URL, value: "https://s3.hippius.com"}
#           - {name: AWS_DEFAULT_REGION, value: "us-east-1"}
#           volumeMounts: [{name: work, mountPath: /work}]
#         volumes: [{name: work, emptyDir: {sizeLimit: 8Gi}}]
#
# It runs as root (unsquashfs keeps owners/xattrs; chroot + mknod) but
# needs no `privileged`, no loop devices and no network beyond S3. Read
# the new sha from the log (`REBUILD OK initrd_sha256=...`) or from the
# uploaded golden.measurement.json. Re-running the Job with the same
# source + image must print the same sha (the reproducibility check).
# Registering the new prefix as a bake in vali (TenantBake row + the
# measurement pin for the new initrd) is a separate step.
#
# Local run (workstation with docker, same image):
#   docker run --rm -v "$PWD/out:/work/out" -e AWS_... --entrypoint \
#     /usr/local/bin/tenant-initrd-rebuild.sh <image> --source-prefix ... \
#     --source-bake-id ... --repo-commit ... --output-dir /work/out
#
# CI: scripts/dev/tenant-initrd-rebuild-test.sh (fixtures, root-free).

set -euo pipefail

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/${PROG}"

log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() { printf '%s: FATAL: %s\n' "${PROG}" "$*" >&2; exit 3; }
usage_die() { printf '%s: %s\n' "${PROG}" "$*" >&2; exit 2; }
build_die() { printf '%s: BUILD FAILED: %s\n' "${PROG}" "$*" >&2; exit 4; }

usage() {
    cat <<EOF
Usage: ${PROG} (--source-prefix s3://B/P/ | --source-dir DIR) --source-bake-id ID
               --output-dir DIR [--output-prefix s3://B/P2/] [options]

  --source-prefix URI       S3 prefix of the source golden bake (read only)
  --source-dir DIR          local dir holding the same five files instead
  --source-bake-id ID       vali TenantBake.bake_id of the source (recorded)
  --output-dir DIR          where the output set is written (must not exist
                            or be empty)
  --output-prefix URI       upload the output set here; must be a NEW, EMPTY
                            prefix, disjoint from the source prefix
  --patch FILE              strict patch (no fuzz) on the base's own inputs;
                            repeatable (default, without --scripts-dir: every
                            ${SCRIPT_DIR}/initramfs/rebuild-patches/*.patch)
  --scripts-dir DIR         OVERRIDE: take WHOLE hippius inputs from DIR
                            instead of the base (+ only explicit --patch). The
                            scripts then run against the base's OLD binaries.
  --allow-initrd-change P   also accept a change of initrd path P (relative);
                            repeatable (needed when a hook input changes)
  --repo-commit SHA         commit the patches/scripts come from (default: git
                            HEAD of their dir if it is a clean checkout)
  --source-date-epoch N     override the SDE (default: the source
                            rootfs.img squashfs mkfs time)
  --expect-kernel-sha256 H  \\
  --expect-initrd-sha256 H   | pin the source artifacts in addition to
  --expect-rootfs-img-sha256 H | its measurement.json (e.g. to the vali
  --expect-rootfs-verity-sha256 H / TenantBake row)
  --work-dir DIR            scratch (default: mktemp under \$TMPDIR)
  --verify-source-only      stop after the source checks (no root needed)
EOF
}

# ── Args ────────────────────────────────────────────────────────────
source_prefix=""
source_dir=""
source_bake_id=""
output_dir=""
output_prefix=""
scripts_dir=""
patches=()
allow_changes=()
repo_commit=""
sde_override=""
expect_kernel=""
expect_initrd=""
expect_rootfs_img=""
expect_rootfs_verity=""
work_dir=""
verify_source_only=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-prefix) source_prefix="${2:?}"; shift 2 ;;
        --source-dir) source_dir="${2:?}"; shift 2 ;;
        --source-bake-id) source_bake_id="${2:?}"; shift 2 ;;
        --output-dir) output_dir="${2:?}"; shift 2 ;;
        --output-prefix) output_prefix="${2:?}"; shift 2 ;;
        --scripts-dir) scripts_dir="${2:?}"; shift 2 ;;
        --patch) patches+=("${2:?}"); shift 2 ;;
        --allow-initrd-change) allow_changes+=("${2:?}"); shift 2 ;;
        --repo-commit) repo_commit="${2:?}"; shift 2 ;;
        --source-date-epoch) sde_override="${2:?}"; shift 2 ;;
        --expect-kernel-sha256) expect_kernel="${2:?}"; shift 2 ;;
        --expect-initrd-sha256) expect_initrd="${2:?}"; shift 2 ;;
        --expect-rootfs-img-sha256) expect_rootfs_img="${2:?}"; shift 2 ;;
        --expect-rootfs-verity-sha256) expect_rootfs_verity="${2:?}"; shift 2 ;;
        --work-dir) work_dir="${2:?}"; shift 2 ;;
        --verify-source-only) verify_source_only=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; usage_die "unknown argument: $1" ;;
    esac
done

[[ -n "${source_prefix}" || -n "${source_dir}" ]] || usage_die "one of --source-prefix / --source-dir is required"
[[ -z "${source_prefix}" || -z "${source_dir}" ]] || usage_die "--source-prefix and --source-dir are mutually exclusive"
[[ -n "${source_bake_id}" ]] || usage_die "--source-bake-id is required (recorded in the output measurement)"
if [[ "${verify_source_only}" -eq 0 ]]; then
    [[ -n "${output_dir}" ]] || usage_die "--output-dir is required"
fi
for h in "${expect_kernel}" "${expect_initrd}" "${expect_rootfs_img}" "${expect_rootfs_verity}"; do
    [[ -z "${h}" || "${h}" =~ ^[0-9a-f]{64}$ ]] || usage_die "--expect-*-sha256 must be 64 lowercase hex: ${h}"
done
# Plain decimal, no leading zero (bash arithmetic would read 0NNN as octal).
[[ -z "${sde_override}" || "${sde_override}" =~ ^(0|[1-9][0-9]{0,10})$ ]] || usage_die "--source-date-epoch must be a plain decimal epoch"

norm_prefix() {
    local p="$1"
    [[ "${p}" =~ ^s3://[^/]+/.+ ]] || usage_die "not an s3://bucket/prefix URI: ${p}"
    printf '%s/\n' "${p%/}"
}
[[ -z "${source_prefix}" ]] || source_prefix="$(norm_prefix "${source_prefix}")"
[[ -z "${output_prefix}" ]] || output_prefix="$(norm_prefix "${output_prefix}")"
if [[ -n "${output_prefix}" ]]; then
    [[ -n "${source_prefix}" ]] || usage_die "--output-prefix needs --source-prefix (the source location is recorded)"
    # Disjoint, never nested: writing under (or above) the source would
    # touch the prefix running tenants boot from.
    case "${output_prefix}" in "${source_prefix}"*) die "--output-prefix ${output_prefix} is inside the source prefix ${source_prefix}" ;; esac
    case "${source_prefix}" in "${output_prefix}"*) die "--output-prefix ${output_prefix} contains the source prefix ${source_prefix}" ;; esac
fi

for tool in sha256sum jq python3 unsquashfs; do
    command -v "${tool}" >/dev/null 2>&1 || usage_die "${tool} not on PATH"
done
if [[ -n "${source_prefix}${output_prefix}" ]]; then
    command -v aws >/dev/null 2>&1 || usage_die "aws not on PATH (needed for S3)"
fi

# The hippius initramfs inputs a debian-family golden bake stages, with
# the exact destinations + modes tenant-image-bake.sh installs them at
# (keep in lockstep with its stage 4 + golden block). Every destination
# must already exist in the base: this tool REPLACES inputs, it never
# grows a non-golden or foreign image into one.
#   <file under scripts-dir>|<destination in the guest root>|<mode>
DEBIAN_INPUTS=(
    "hippius-release-core.sh|/etc/hippius/hippius-release-core.sh|0644"
    "hippius-release-core.sh|/lib/hippius/hippius-release-core.sh|0644"
    "hippius-golden-overlay.sh|/etc/hippius/hippius-golden-overlay.sh|0644"
    "hippius-golden-overlay.sh|/lib/hippius/hippius-golden-overlay.sh|0644"
    "hippius-golden-boot|/etc/hippius/hippius-golden-boot|0644"
    "hippius-golden-hook|/etc/initramfs-tools/hooks/hippius-golden|0755"
    "hippius-luks-keyscript|/etc/hippius/hippius-luks-keyscript|0644"
    "hippius-luks-keyscript|/sbin/hippius-luks-keyscript|0755"
    "hippius-net-teardown|/etc/initramfs-tools/scripts/init-bottom/hippius-net-teardown|0755"
    "hippius-luks-hook|/etc/initramfs-tools/hooks/hippius-luks|0755"
)
# What the new initrd must carry, byte-equal to --scripts-dir, as a
# regular file with exactly this mode (what the hooks install):
#   <file under scripts-dir>|<path in the initrd, relative, /usr-merge aware>|<mode>
INITRD_MUST_CARRY=(
    "hippius-golden-overlay.sh|lib/hippius/hippius-golden-overlay.sh|100644"
    "hippius-release-core.sh|lib/hippius/hippius-release-core.sh|100644"
    "hippius-golden-boot|scripts/hippius-golden|100755"
    "hippius-net-teardown|scripts/init-bottom/hippius-net-teardown|100755"
    "hippius-luks-keyscript|sbin/hippius-luks-keyscript|100755"
)
# ... and /scripts/init-bottom/ORDER must RUN the teardown: a script that
# is shipped but not listed there never executes (#289, 2026-07-04).
ORDER_MUST_RUN="/scripts/init-bottom/hippius-net-teardown"

# Initrd paths the ORIGINAL bake picked up from its build host (bind-
# mounted /proc, /sys, /dev) and the hermetic build no longer does, with
# the ONE status each may show: the host's md arrays in mdadm.conf, its
# efivarfs in conf/modules, a random /.random-seed (changed), and
# mkconf's leftover when it finds no arrays (added; nothing reads it).
# Every other difference must be an input's own file.
INITRD_HOST_NOISE=(etc/mdadm/mdadm.conf=changed conf/modules=changed .random-seed=changed etc/mdadm/mdadm.conf.tmp=added)

input_names() { local e; for e in "${DEBIAN_INPUTS[@]}"; do printf '%s\n' "${e%%|*}"; done | sort -u; }

if [[ -n "${scripts_dir}" ]]; then
    inputs_from="scripts-dir"
    for f in $(input_names); do
        [[ -r "${scripts_dir}/${f}" ]] || usage_die "--scripts-dir ${scripts_dir} has no ${f}"
    done
else
    inputs_from="base"
    if [[ ${#patches[@]} -eq 0 ]]; then
        shopt -s nullglob
        patches=("${SCRIPT_DIR}"/initramfs/rebuild-patches/*.patch)
        shopt -u nullglob
        [[ ${#patches[@]} -gt 0 ]] \
            || usage_die "no --patch given and no ${SCRIPT_DIR}/initramfs/rebuild-patches/*.patch — nothing to change"
    fi
fi
# Every patch edits exactly ONE input, named by its basename.
patch_targets=()
for pf in "${patches[@]}"; do
    [[ -r "${pf}" ]] || usage_die "--patch ${pf} is not readable"
    mapfile -t tgts < <(sed -n 's|^+++ \([^[:space:]]*\).*$|\1|p' "${pf}" | sort -u)
    [[ ${#tgts[@]} -eq 1 ]] || usage_die "patch ${pf} must edit exactly one file (edits ${#tgts[@]})"
    tgt="$(basename "${tgts[0]}")"
    input_names | grep -qFx "${tgt}" || usage_die "patch ${pf} edits ${tgt}, which is not a hippius initramfs input"
    patch_targets+=("${tgt}")
done
[[ ${#patches[@]} -eq 0 ]] || command -v patch >/dev/null 2>&1 || usage_die "patch not on PATH"

if [[ -z "${repo_commit}" ]]; then
    if [[ -n "${scripts_dir}" ]]; then commit_dir="${scripts_dir}"; else commit_dir="$(dirname "${patches[0]}")"; fi
    git -C "${commit_dir}" rev-parse HEAD >/dev/null 2>&1 \
        || usage_die "--repo-commit is required (${commit_dir} is not a git checkout)"
    dirty="$(git -C "${commit_dir}" status --porcelain -- .)" \
        || usage_die "git status failed in ${commit_dir} — pass --repo-commit explicitly"
    [[ -z "${dirty}" ]] \
        || usage_die "${commit_dir} has uncommitted changes — commit them or pass --repo-commit explicitly"
    repo_commit="$(git -C "${commit_dir}" rev-parse HEAD)"
fi

# ── Workspace ───────────────────────────────────────────────────────
if [[ -z "${work_dir}" ]]; then
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/initrd-rebuild.XXXXXX")"
else
    # Fresh only: a reused work dir would carry a previous run's input
    # snapshot and source copies into this run.
    [[ ! -e "${work_dir}" || -z "$(ls -A "${work_dir}" 2>/dev/null)" ]] \
        || usage_die "--work-dir ${work_dir} is not empty — use a fresh one"
    mkdir -p "${work_dir}"
fi
SRC="${work_dir}/src"
mkdir -p "${SRC}"

INPUTS="${work_dir}/inputs"
BASE_INPUTS="${work_dir}/base-inputs"
mkdir -p "${INPUTS}" "${BASE_INPUTS}"

# Hippius S3 needs path-style addressing, which has no env knob; use a
# private config (the baker entrypoint does `aws configure set` for the
# same reason) unless the operator brought their own.
if [[ -z "${AWS_CONFIG_FILE:-}" ]]; then
    printf '[default]\ns3 =\n    addressing_style = path\n' > "${work_dir}/aws-config"
    export AWS_CONFIG_FILE="${work_dir}/aws-config"
fi

# ── Python helper: bzImage version, squashfs mkfs time, initrd manifest ─
INSPECT="${work_dir}/inspect.py"
cat > "${INSPECT}" <<'PY_EOF'
import gzip, hashlib, json, lzma, bz2, re, struct, subprocess, sys

def vmlinuz_kver(path):
    d = open(path, "rb").read(0x10000)
    if len(d) < 0x210 or d[0x202:0x206] != b"HdrS":
        sys.exit("not a bzImage (no HdrS setup header): %s" % path)
    off = struct.unpack("<H", d[0x20E:0x210])[0]
    if off == 0:
        sys.exit("bzImage carries no kernel_version string: %s" % path)
    full = open(path, "rb").read()
    s = full[off + 0x200: off + 0x200 + 256].split(b"\0", 1)[0].decode("ascii", "replace")
    kver = s.split(" ", 1)[0]
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+_~-]*", kver):
        sys.exit("unparseable kernel version %r in %s" % (s, path))
    return kver

def squashfs_mkfs_time(path):
    d = open(path, "rb").read(12)
    if d[:4] != b"hsqs":
        sys.exit("not a squashfs image: %s" % path)
    return struct.unpack("<I", d[8:12])[0]

def decompress(blob):
    if blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob)
    if blob[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(blob)
    if blob[:3] == b"BZh":
        return bz2.decompress(blob)
    tool = None
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        tool = ["zstd", "-dcq"]
    elif blob[:4] in (b"\x02\x21\x4c\x18", b"\x04\x22\x4d\x18"):
        tool = ["lz4", "-dcq"]
    if tool is None:
        sys.exit("initrd: unknown compression magic %s" % blob[:6].hex())
    return subprocess.run(tool, input=blob, stdout=subprocess.PIPE, check=True).stdout

MODULE_RE = re.compile(r"\.ko(\.(zst|xz|gz))?$")

def module_vermagic(name, body):
    if name.endswith(".zst"):
        body = subprocess.run(["zstd", "-dcq"], input=body, stdout=subprocess.PIPE, check=True).stdout
    elif name.endswith(".xz"):
        body = lzma.decompress(body)
    elif name.endswith(".gz"):
        body = gzip.decompress(body)
    i = body.find(b"vermagic=")
    if i < 0:
        return ""
    return body[i + 9: body.find(b"\0", i)].decode("ascii", "replace")

def parse_cpio(data, pos, out, want_vermagic=False, keep=()):
    """Parse one newc archive starting at pos; return the offset after its trailer."""
    while True:
        if data[pos:pos + 6] not in (b"070701", b"070702"):
            sys.exit("initrd: bad cpio magic at %d" % pos)
        h = data[pos:pos + 110]
        field = lambda i: int(h[6 + 8 * i: 14 + 8 * i], 16)
        mode, uid, gid, filesize, namesize = field(1), field(2), field(3), field(6), field(11)
        name_start = pos + 110
        name = data[name_start:name_start + namesize - 1].decode("utf-8", "surrogateescape")
        dpos = (name_start + namesize + 3) & ~3
        body = data[dpos:dpos + filesize]
        pos = (dpos + filesize + 3) & ~3
        if name == "TRAILER!!!":
            return pos
        name = name[2:] if name.startswith("./") else name
        if name in ("", "."):
            continue
        kind = mode & 0o170000
        ent = {"mode": "%o" % mode, "owner": "%d:%d" % (uid, gid)}
        if kind == 0o100000:
            ent["sha256"] = hashlib.sha256(body).hexdigest()
            if want_vermagic and MODULE_RE.search(name):
                ent["vermagic"] = module_vermagic(name, body)
            if name in keep:
                ent["body"] = body
        elif kind == 0o120000:
            ent["link"] = body.decode("utf-8", "surrogateescape")
        out[name] = ent  # a later entry for the same path wins, as in the kernel

def manifest(path, want_vermagic=False, keep=()):
    data = open(path, "rb").read()
    out, pos = {}, 0
    while pos < len(data):
        while pos < len(data) and data[pos] == 0:
            pos += 1
        if pos >= len(data):
            break
        if data[pos:pos + 6] in (b"070701", b"070702"):
            pos = parse_cpio(data, pos, out, want_vermagic, keep)
            continue
        inner, ipos = decompress(data[pos:]), 0
        while ipos < len(inner):
            while ipos < len(inner) and inner[ipos] == 0:
                ipos += 1
            if ipos >= len(inner):
                break
            ipos = parse_cpio(inner, ipos, out, want_vermagic, keep)
        break
    return out

def kvers(man):
    vs = set()
    for name in man:
        m = re.match(r"(?:usr/)?lib/modules/([^/]+)(?:/|$)", name)
        if m:
            vs.add(m.group(1))
    return sorted(vs)

def aliases(rel):
    """rel + its /usr-merge twin. Only lib/, bin/, sbin/ are merged into
    usr/; scripts/, conf/, etc/ never are."""
    if rel.split("/", 1)[0] in ("lib", "bin", "sbin"):
        return (rel, "usr/" + rel)
    return (rel,)

def lookup(man, rel):
    for cand in aliases(rel):
        if cand in man:
            return man[cand]
    return None

cmd = sys.argv[1]
if cmd == "vmlinuz-kver":
    print(vmlinuz_kver(sys.argv[2]))
elif cmd == "squashfs-mkfs-time":
    print(squashfs_mkfs_time(sys.argv[2]))
elif cmd == "initrd-kvers":
    print(" ".join(kvers(manifest(sys.argv[2]))))
elif cmd == "initrd-entry":  # <initrd> <rel path> → "<mode> <owner> <sha256>" or "absent"
    ent = lookup(manifest(sys.argv[2]), sys.argv[3])
    print("%s %s %s" % (ent["mode"], ent["owner"], ent.get("sha256", "-")) if ent else "absent")
elif cmd == "initrd-cat":  # <initrd> <rel path> → the file's bytes
    rel = sys.argv[3]
    ent = lookup(manifest(sys.argv[2], keep=aliases(rel)), rel)
    if not ent or "body" not in ent:
        sys.exit("%s: not a regular file in the initrd" % rel)
    sys.stdout.buffer.write(ent["body"])
elif cmd == "initrd-vermagic":  # <initrd> <kver> → every module built for <kver>
    kver, n, bad = sys.argv[3], 0, []
    for name, ent in sorted(manifest(sys.argv[2], want_vermagic=True).items()):
        if "vermagic" in ent:
            n += 1
            if ent["vermagic"].split(" ", 1)[0] != kver:
                bad.append("%s (vermagic %r)" % (name, ent["vermagic"]))
    if n == 0:
        sys.exit("no kernel modules in the initrd")
    if bad:
        sys.exit("%d of %d modules are not built for %s: %s" % (len(bad), n, kver, "; ".join(bad[:5])))
    print(n)
elif cmd == "initrd-gate":  # <old> <new> <allowed rel...> -- <noise rel=status,...>...
    # JSON list of every differing path, each classified: "input" (an
    # allowed rel or its usr-merge twin, any status), "host-noise" (a
    # noise rel with a listed status) or "UNEXPECTED". Exact path
    # matches only; paths are never re-split on whitespace.
    a, b = manifest(sys.argv[2]), manifest(sys.argv[3])
    rest = sys.argv[4:]
    sep = rest.index("--")
    allowed = {c for rel in rest[:sep] for c in aliases(rel)}
    noise = {}
    for spec in rest[sep + 1:]:
        rel, sts = spec.split("=", 1)
        for c in aliases(rel):
            noise[c] = set(sts.split(","))
    desc = lambda e: "-" if e is None else "%s:%s:%s" % (
        e["mode"], e["owner"], e.get("sha256", e.get("link", "-"))[:16])
    out = []
    for n in sorted(set(a) | set(b)):
        st = "removed" if n not in b else "added" if n not in a else "changed" if a[n] != b[n] else None
        if not st:
            continue
        kind = "input" if n in allowed else "host-noise" if st in noise.get(n, ()) else "UNEXPECTED"
        out.append({"status": st, "path": n, "kind": kind, "old": desc(a.get(n)), "new": desc(b.get(n))})
    print(json.dumps(out))
else:
    sys.exit("unknown inspect command %s" % cmd)
PY_EOF
inspect() { python3 "${INSPECT}" "$@"; }

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

# ── 1. Fetch the source bake ────────────────────────────────────────
ARTIFACTS=(tenant.vmlinuz tenant.initrd.img rootfs.img rootfs.verity golden.measurement.json)
if [[ -n "${source_prefix}" ]]; then
    log "fetching source bake ${source_prefix} (read-only)"
    for a in "${ARTIFACTS[@]}"; do
        # Retried: a GET of the ~700 MB rootfs.img has been seen to drop
        # mid-transfer. A short/corrupt file cannot slip through — the sha
        # check below is against measurement.json.
        fetched=0
        for attempt in 1 2 3; do
            if aws s3 cp --only-show-errors "${source_prefix}${a}" "${SRC}/${a}"; then
                fetched=1; break
            fi
            log "fetch ${a} failed (attempt ${attempt}/3)"
            sleep $((attempt * 5))
        done
        [[ ${fetched} -eq 1 ]] || die "could not fetch ${source_prefix}${a}"
    done
    source_location="${source_prefix}"
else
    for a in "${ARTIFACTS[@]}"; do
        [[ -f "${source_dir}/${a}" ]] || die "source dir ${source_dir} has no ${a}"
        # A private copy, never a hard link: nothing here may share an
        # inode with the source bake.
        cp "${source_dir}/${a}" "${SRC}/${a}"
    done
    source_location="$(cd "${source_dir}" && pwd)"
fi
M_SRC="${SRC}/golden.measurement.json"
jq -e 'type == "object"' "${M_SRC}" >/dev/null 2>&1 || die "source golden.measurement.json is not a JSON object"

# ── 2. Verify the source: every sha vs its measurement.json ─────────
mode="$(jq -r '.disk_mode // empty' "${M_SRC}")"
[[ "${mode}" == "golden_verity_overlay" ]] \
    || die "source disk_mode is '${mode:-<none>}', not golden_verity_overlay — only golden bakes can be initrd-rebuilt"
if jq -e 'has("initrd_rebuild")' "${M_SRC}" >/dev/null; then
    log "note: the source is itself an initrd rebuild (of $(jq -r '.initrd_rebuild.source_bake_id' "${M_SRC}"))"
fi

# check_artifact <file> <measurement key> <size key or ""> <expect pin or "">
check_artifact() {
    local file="$1" key="$2" size_key="$3" pin="$4" want got
    want="$(jq -r --arg k "${key}" '.[$k] // empty' "${M_SRC}")"
    [[ "${want}" =~ ^[0-9a-f]{64}$ ]] || die "source measurement.json has no 64-hex ${key}"
    got="$(sha_of "${SRC}/${file}")"
    [[ "${got}" == "${want}" ]] \
        || die "${file}: sha256 ${got} does not match the source measurement ${key}=${want} — refusing to build on bytes the bake did not produce"
    if [[ -n "${pin}" && "${got}" != "${pin}" ]]; then
        die "${file}: sha256 ${got} does not match the pinned --expect value ${pin}"
    fi
    if [[ -n "${size_key}" ]]; then
        local want_size got_size
        want_size="$(jq -r --arg k "${size_key}" '.[$k] // empty' "${M_SRC}")"
        got_size="$(stat -c '%s' "${SRC}/${file}")"
        [[ -z "${want_size}" || "${want_size}" == "${got_size}" ]] \
            || die "${file}: size ${got_size} does not match the source measurement ${size_key}=${want_size}"
    fi
    printf '%s' "${got}"
}
kernel_sha="$(check_artifact tenant.vmlinuz kernel_sha256 "" "${expect_kernel}")"
src_initrd_sha="$(check_artifact tenant.initrd.img initrd_sha256 "" "${expect_initrd}")"
rootfs_img_sha="$(check_artifact rootfs.img rootfs_img_sha256 rootfs_img_size_bytes "${expect_rootfs_img}")"
rootfs_verity_sha="$(check_artifact rootfs.verity rootfs_verity_sha256 rootfs_verity_size_bytes "${expect_rootfs_verity}")"
src_measurement_sha="$(sha_of "${M_SRC}")"
log "source artifacts match their measurement: kernel=${kernel_sha} initrd=${src_initrd_sha} rootfs.img=${rootfs_img_sha} rootfs.verity=${rootfs_verity_sha}"

# ── 3. Kernel version: vmlinuz ⇔ source initrd ⇔ base modules ───────
kver="$(inspect vmlinuz-kver "${SRC}/tenant.vmlinuz")" || die "cannot read the kernel version from tenant.vmlinuz"
src_kvers="$(inspect initrd-kvers "${SRC}/tenant.initrd.img")" || die "cannot parse the source initrd"
[[ "${src_kvers}" == "${kver}" ]] \
    || die "source initrd carries modules for '${src_kvers:-<none>}', the source kernel is ${kver} — inconsistent source bake"

# Base tree preflight without extracting (root-free): the kernel's
# modules must be in the base, and so must every input we replace.
LISTING="${work_dir}/rootfs.lls"
# One absolute path per line (`-lls` prints "<perms> <owner> ... squashfs-root/<path>[ -> <target>]").
unsquashfs -lls "${SRC}/rootfs.img" 2>/dev/null \
    | sed -n 's|^.* squashfs-root\(/.*\)$|\1|p' | sed 's| -> .*$||' > "${LISTING}" \
    || die "unsquashfs cannot list rootfs.img"
base_has() {  # <absolute path> — also resolves the /usr-merge (lib→usr/lib, sbin→usr/sbin)
    local p="$1" alt="$1"
    case "${p}" in /lib/*|/sbin/*|/bin/*) alt="/usr${p}" ;; esac
    grep -qFx -e "${p}" -e "${alt}" "${LISTING}"
}
base_has "/lib/modules/${kver}" \
    || die "the base rootfs has no /lib/modules/${kver} — its modules do not match the source kernel"
os_release="$(unsquashfs -cat "${SRC}/rootfs.img" usr/lib/os-release 2>/dev/null \
    || unsquashfs -cat "${SRC}/rootfs.img" etc/os-release 2>/dev/null || true)"
os_id="$(printf '%s\n' "${os_release}" | sed -n 's/^ID=//p' | tr -d '"' | head -1)"
os_like="$(printf '%s\n' "${os_release}" | sed -n 's/^ID_LIKE=//p' | tr -d '"' | head -1)"
case " ${os_id} ${os_like} " in
    *" debian "*|*" ubuntu "*) family=debian ;;
    *" rhel "*|*" fedora "*|*" centos "*) die "base is ${os_id} (rhel family): dracut goldens are not supported by this tool yet — only apt/initramfs-tools goldens (Ubuntu, Debian)" ;;
    *) die "cannot identify the base distro (ID='${os_id}' ID_LIKE='${os_like}')" ;;
esac
for entry in "${DEBIAN_INPUTS[@]}"; do
    dest="$(cut -d'|' -f2 <<< "${entry}")"
    base_has "${dest}" || die "the base has no ${dest} — not a hippius golden base (this tool only replaces existing inputs)"
done
base_has "/usr/sbin/mkinitramfs" || die "the base has no /usr/sbin/mkinitramfs"

if [[ -n "${sde_override}" ]]; then
    sde="${sde_override}"
else
    sde="$(inspect squashfs-mkfs-time "${SRC}/rootfs.img")" || die "cannot read the squashfs mkfs time"
fi
# mkinitramfs only clamps mtimes NEWER than the SDE: a future SDE leaves
# every file it writes at its wall-clock mtime, i.e. a different cpio per run.
[[ "${sde}" =~ ^(0|[1-9][0-9]{0,10})$ ]] || die "SOURCE_DATE_EPOCH '${sde}' is not a plain decimal epoch"
(( 10#${sde} <= $(date +%s) )) || die "SOURCE_DATE_EPOCH ${sde} is in the future — the build would not be reproducible"
log "kernel ${kver} (source initrd + base modules agree); distro ${os_id} (${family}); SOURCE_DATE_EPOCH=${sde}"

# ── 3b. The inputs: the base's own copies (+ strict patches) ────────
base_cat() {  # <absolute path in the base> <out>
    local p="${1#/}"
    unsquashfs -cat "${SRC}/rootfs.img" "${p}" > "$2" 2>/dev/null \
        || unsquashfs -cat "${SRC}/rootfs.img" "usr/${p}" > "$2" 2>/dev/null
}
# What the base carries, one copy per input; every destination of the
# same input must hold the same bytes (the bake installs one file twice).
for entry in "${DEBIAN_INPUTS[@]}"; do
    IFS='|' read -r f dest m <<< "${entry}"
    base_cat "${dest}" "${work_dir}/base.cat" || die "cannot read ${dest} from the base"
    if [[ -e "${BASE_INPUTS}/${f}" ]]; then
        cmp -s "${work_dir}/base.cat" "${BASE_INPUTS}/${f}" \
            || die "the base's ${dest} differs from its other copy of ${f} — inconsistent base"
    else
        mv "${work_dir}/base.cat" "${BASE_INPUTS}/${f}"
    fi
done
rm -f "${work_dir}/base.cat"
if [[ "${inputs_from}" == base ]]; then
    # The base's copies must be what the source initrd was built from.
    for entry in "${INITRD_MUST_CARRY[@]}"; do
        IFS='|' read -r f rel mode <<< "${entry}"
        got="$(inspect initrd-entry "${SRC}/tenant.initrd.img" "${rel}")" || die "cannot parse the source initrd"
        [[ "${got}" == "${mode} 0:0 $(sha_of "${BASE_INPUTS}/${f}")" ]] \
            || die "source initrd /${rel} (${got}) is not the base's ${f} — the base scripts are not what the source initrd was built from"
    done
    log "base hippius scripts = the ones inside the source initrd"
    cp -f "${BASE_INPUTS}"/* "${INPUTS}/"
else
    # One snapshot: staging, the audit and the provenance all read it.
    for f in $(input_names); do
        cp -f "${scripts_dir}/${f}" "${INPUTS}/${f}" || usage_die "cannot snapshot ${scripts_dir}/${f}"
    done
    log "OVERRIDE: whole inputs from ${scripts_dir} — they will run against the base's own binaries"
fi
for i in "${!patches[@]}"; do
    pf="${patches[$i]}"; tgt="${patch_targets[$i]}"
    before="$(sha_of "${INPUTS}/${tgt}")"
    # Strict: no fuzz, not already applied, rejects are a failure (offsets
    # are fine — a base predates the lines around the change).
    patch --fuzz=0 --forward --batch --no-backup-if-mismatch --reject-file=- \
        "${INPUTS}/${tgt}" < "${pf}" > "${work_dir}/patch.log" 2>&1 \
        || die "patch $(basename "${pf}") does not apply cleanly to the ${inputs_from}'s ${tgt}: $(tr '\n' ' ' < "${work_dir}/patch.log")"
    [[ "$(sha_of "${INPUTS}/${tgt}")" != "${before}" ]] || die "patch $(basename "${pf}") changed nothing in ${tgt}"
    log "patched ${tgt} with $(basename "${pf}"): ${before} → $(sha_of "${INPUTS}/${tgt}")"
done
changed_inputs=()
for f in $(input_names); do
    cmp -s "${INPUTS}/${f}" "${BASE_INPUTS}/${f}" || changed_inputs+=("${f}")
done
[[ ${#changed_inputs[@]} -gt 0 ]] || die "no input differs from the base — nothing to rebuild"
log "inputs changed vs the base: ${changed_inputs[*]}"

if [[ "${verify_source_only}" -eq 1 ]]; then
    log "VERIFY-SOURCE OK (no build requested)"
    exit 0
fi

# ── 4. Build the initrd in the base tree ────────────────────────────
if [[ -e "${output_dir}" ]] && [[ -n "$(ls -A "${output_dir}" 2>/dev/null)" ]]; then
    usage_die "--output-dir ${output_dir} is not empty"
fi
mkdir -p "${output_dir}"
NEW_INITRD="${work_dir}/tenant.initrd.img"

build_debian() {
    [[ ${EUID} -eq 0 ]] || usage_die "the build needs root (unsquashfs owners/xattrs, mknod, chroot) — run it in the baker image"
    local root="${work_dir}/root" entry f dest m
    [[ ! -e "${root}" ]] || build_die "${root} already exists (reuse of a work dir?)"
    log "unsquashfs base → ${root}"
    unsquashfs -q -no-progress -d "${root}" "${SRC}/rootfs.img" >/dev/null || build_die "unsquashfs failed"

    for entry in "${DEBIAN_INPUTS[@]}"; do
        IFS='|' read -r f dest m <<< "${entry}"
        # Unchanged inputs stay the base's file, mode and all.
        cmp -s "${INPUTS}/${f}" "${root}${dest}" && continue
        log "input ${dest}: $(sha_of "${root}${dest}") → $(sha_of "${INPUTS}/${f}")"
        install -m "${m}" -o 0 -g 0 "${INPUTS}/${f}" "${root}${dest}"
    done

    # Hermetic chroot: nothing from the build host. A synthetic /dev, a
    # static /proc stand-in, no /sys: the bake's bind mounts let the mdadm hook copy
    # the build host's arrays and its EFI state into the initrd. random /
    # urandom are the zero device: the overlayroot hook's /.random-seed is
    # then 4 KiB of zeros instead of bytes that differ per build (and were
    # public in every published initrd anyway).
    mv "${root}/dev" "${root}/dev.base"
    mkdir -m 0755 "${root}/dev"
    mknod -m 0666 "${root}/dev/null" c 1 3
    mknod -m 0666 "${root}/dev/zero" c 1 5
    mknod -m 0666 "${root}/dev/full" c 1 7
    mknod -m 0666 "${root}/dev/random" c 1 5
    mknod -m 0666 "${root}/dev/urandom" c 1 5
    # A static /proc stand-in, not procfs. mounts: mkinitramfs links
    # /etc/mtab → /proc/mounts and then DELETES every symlink that dangles
    # in the build root, so without it the initrd loses /etc/mtab. mdstat +
    # partitions: the mdadm hook's mkconf then finds "MD loaded, no arrays"
    # instead of the build host's arrays (or failing and leaving a .tmp).
    mv "${root}/proc" "${root}/proc.base"
    mkdir -m 0555 "${root}/proc"
    : > "${root}/proc/mounts"
    printf 'Personalities : \nunused devices: <none>\n' > "${root}/proc/mdstat"
    printf 'major minor  #blocks  name\n\n' > "${root}/proc/partitions"
    mkdir -p "${root}/tmp" "${root}/var/tmp"
    chmod 1777 "${root}/tmp" "${root}/var/tmp"

    log "chroot mkinitramfs ${kver} (SOURCE_DATE_EPOCH=${sde}, hermetic)"
    chroot "${root}" /usr/bin/env -i \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        SOURCE_DATE_EPOCH="${sde}" \
        LC_ALL=C LANG=C LANGUAGE=C TZ=UTC HOME=/root TMPDIR=/var/tmp \
        mkinitramfs -o /tmp/hippius-rebuilt.initrd.img "${kver}" \
        || build_die "mkinitramfs failed in the base chroot"
    cp "${root}/tmp/hippius-rebuilt.initrd.img" "${NEW_INITRD}"
    # The extracted base is ~3x rootfs.img; free it before the output copies.
    rm -rf -- "${root}"
}

if [[ -n "${HCC_TEST_INITRD_BUILDER:-}" ]]; then
    # Test seam (scripts/dev/tenant-initrd-rebuild-test.sh): replace the
    # root-only chroot build with a fixture builder so every check around
    # it runs in CI. Never set in the baker image.
    log "TEST: building with ${HCC_TEST_INITRD_BUILDER}"
    "${HCC_TEST_INITRD_BUILDER}" "${SRC}/rootfs.img" "${kver}" "${sde}" "${INPUTS}" "${NEW_INITRD}" \
        || build_die "test builder failed"
else
    build_debian
fi
[[ -s "${NEW_INITRD}" ]] || build_die "no initrd produced"

# ── 5. Verify the output ────────────────────────────────────────────
new_kvers="$(inspect initrd-kvers "${NEW_INITRD}")" || die "cannot parse the rebuilt initrd"
[[ "${new_kvers}" == "${kver}" ]] \
    || die "rebuilt initrd carries modules for '${new_kvers:-<none>}', the source kernel is ${kver} — refusing"
nmods="$(inspect initrd-vermagic "${NEW_INITRD}" "${kver}")" \
    || die "rebuilt initrd modules are not all built for ${kver} — refusing"
for entry in "${INITRD_MUST_CARRY[@]}"; do
    IFS='|' read -r f rel mode <<< "${entry}"
    want="${mode} 0:0 $(sha_of "${INPUTS}/${f}")"
    got="$(inspect initrd-entry "${NEW_INITRD}" "${rel}")" || die "cannot parse the rebuilt initrd"
    [[ "${got}" == "${want}" ]] \
        || die "rebuilt initrd /${rel} is '${got}', expected '${want}' (${f} from --scripts-dir) — the new inputs did not land"
done
order="$(inspect initrd-cat "${NEW_INITRD}" scripts/init-bottom/ORDER)" \
    || die "rebuilt initrd has no /scripts/init-bottom/ORDER"
grep -q "^${ORDER_MUST_RUN} " <<< "${order}" \
    || die "rebuilt initrd /scripts/init-bottom/ORDER does not run ${ORDER_MUST_RUN}"
log "output initrd: kernel ${kver}, ${nmods} modules all vermagic ${kver}, hippius inputs landed, ORDER runs the net teardown"

new_initrd_sha="$(sha_of "${NEW_INITRD}")"

# The new initrd may differ from the source one ONLY in the initrd files
# of the changed inputs, the known host leaks (changed, never added or
# removed), and explicit --allow-initrd-change paths.
allowed=("${allow_changes[@]}")
for entry in "${INITRD_MUST_CARRY[@]}"; do
    IFS='|' read -r f rel mode <<< "${entry}"
    printf '%s\n' "${changed_inputs[@]}" | grep -qFx "${f}" && allowed+=("${rel}")
done
gate="$(inspect initrd-gate "${SRC}/tenant.initrd.img" "${NEW_INITRD}" "${allowed[@]}" -- "${INITRD_HOST_NOISE[@]}")" \
    || die "cannot diff the rebuilt initrd against the source"
log "per-file diff, source initrd → rebuilt initrd (<status> <kind> <path> <mode:owner:sha> → <...>):"
jq -r '.[] | "    \(.status) \(.kind) \(.path | @json) \(.old) → \(.new)"' <<< "${gate}" >&2
mapfile -t unexpected < <(jq -r '.[] | select(.kind == "UNEXPECTED") | "\(.status) \(.path | @json)"' <<< "${gate}")
changes_json="$(jq -c 'map({status, path, kind})' <<< "${gate}")"
for noise in etc/mdadm/mdadm.conf conf/modules; do
    jq -e --arg p "${noise}" 'any(.[]; .path == $p and .status == "changed")' <<< "${gate}" >/dev/null || continue
    log "  ${noise}:"
    diff -u <(inspect initrd-cat "${SRC}/tenant.initrd.img" "${noise}") <(inspect initrd-cat "${NEW_INITRD}" "${noise}") \
        | tail -n +3 | grep '^[-+]' | sed 's/^/        /' >&2 || true
done
[[ ${#unexpected[@]} -eq 0 ]] \
    || die "rebuilt initrd differs from the source initrd beyond the changed inputs: ${unexpected[*]} — refusing (--allow-initrd-change to accept a path on purpose)"

# ── 6. Emit the output set ──────────────────────────────────────────
inputs_json="$(
    for entry in "${DEBIAN_INPUTS[@]}"; do
        f="${entry%%|*}"
        printf '%s %s\n' "${f}" "$(sha_of "${INPUTS}/${f}")" || exit 1
    done | sort -u | jq -Rn '[inputs | split(" ") | {(.[0]): .[1]}] | add'
)" || die "cannot hash the input snapshot"
patches_json="$(
    for pf in "${patches[@]}"; do printf '%s %s\n' "$(basename "${pf}")" "$(sha_of "${pf}")"; done \
        | jq -Rn '[inputs | split(" ") | {(.[0]): .[1]}] | add // {}'
)" || die "cannot hash the patches"
for a in tenant.vmlinuz rootfs.img rootfs.verity; do
    cp "${SRC}/${a}" "${output_dir}/${a}"
done
cp "${NEW_INITRD}" "${output_dir}/tenant.initrd.img"
jq \
    --arg initrd_sha "${new_initrd_sha}" \
    --arg bake_id "${source_bake_id}" \
    --arg src "${source_location}" \
    --arg src_initrd "${src_initrd_sha}" \
    --arg src_meas "${src_measurement_sha}" \
    --arg commit "${repo_commit}" \
    --argjson sde "${sde}" \
    --arg kver "${kver}" \
    --arg family "${family}" \
    --arg tool_sha "$(sha_of "${SCRIPT_PATH}")" \
    --argjson inputs "${inputs_json}" \
    --arg inputs_from "${inputs_from}" \
    --argjson patches "${patches_json}" \
    --argjson changes "${changes_json}" \
    '.initrd_sha256 = $initrd_sha
     | .initrd_rebuild = {
         source_bake_id: $bake_id,
         source_location: $src,
         source_initrd_sha256: $src_initrd,
         source_measurement_sha256: $src_meas,
         repo_commit: $commit,
         source_date_epoch: $sde,
         kernel_version: $kver,
         family: $family,
         inputs_from: $inputs_from,
         inputs_sha256: $inputs,
         patches_sha256: $patches,
         initrd_changes: $changes,
         tool: "scripts/tenant-initrd-rebuild.sh",
         tool_sha256: $tool_sha
       }' "${M_SRC}" > "${output_dir}/golden.measurement.json"

# Final gate on the EMITTED bytes (the ones that get uploaded): reused
# artifacts = the source measurement, initrd = the one audited above.
[[ "$(sha_of "${output_dir}/tenant.vmlinuz")" == "${kernel_sha}" ]] || die "output tenant.vmlinuz is not the source kernel"
[[ "$(sha_of "${output_dir}/rootfs.img")" == "${rootfs_img_sha}" ]] || die "output rootfs.img is not the source rootfs.img"
[[ "$(sha_of "${output_dir}/rootfs.verity")" == "${rootfs_verity_sha}" ]] || die "output rootfs.verity is not the source rootfs.verity"
[[ "$(sha_of "${output_dir}/tenant.initrd.img")" == "${new_initrd_sha}" ]] || die "output tenant.initrd.img is not the audited initrd"

log "output set in ${output_dir}:"
(cd "${output_dir}" && sha256sum tenant.vmlinuz tenant.initrd.img rootfs.img rootfs.verity golden.measurement.json) | sed 's/^/    /' >&2

# ── 7. Upload to a NEW prefix ───────────────────────────────────────
if [[ -n "${output_prefix}" ]]; then
    bucket_key="${output_prefix#s3://}"
    bucket="${bucket_key%%/*}"
    key_prefix="${bucket_key#*/}"
    # Fail CLOSED: a list error is a refusal, never "empty". (Single
    # writer assumed — no conditional PUT; do not run two rebuilds at the
    # same output prefix.)
    nkeys="$(aws s3api list-objects-v2 --bucket "${bucket}" --prefix "${key_prefix}" --max-keys 1 \
        --query 'KeyCount' --output text)" \
        || die "cannot list ${output_prefix} — refusing to write to a prefix whose emptiness is unknown"
    [[ "${nkeys}" == "0" ]] || die "--output-prefix ${output_prefix} is not empty — never overwrite a prefix"
    # Uploads the local, verified bytes (no server-side copy): what lands
    # is exactly what was checked above. Measurement last, so a partial
    # upload never looks complete.
    for a in tenant.vmlinuz rootfs.img rootfs.verity tenant.initrd.img golden.measurement.json; do
        log "upload ${output_prefix}${a}"
        aws s3 cp --only-show-errors "${output_dir}/${a}" "${output_prefix}${a}" || die "upload of ${a} failed"
    done
    # Read back: every object's size, and the sha of everything but the
    # ~GB rootfs.img (its size + the uploaded local sha stand for it).
    readback="${work_dir}/readback"
    mkdir -p "${readback}"
    for a in tenant.vmlinuz rootfs.img rootfs.verity tenant.initrd.img golden.measurement.json; do
        remote_size="$(aws s3api head-object --bucket "${bucket}" --key "${key_prefix}${a}" --query ContentLength --output text)" \
            || die "head-object ${output_prefix}${a} failed after upload"
        [[ "${remote_size}" == "$(stat -c '%s' "${output_dir}/${a}")" ]] \
            || die "${output_prefix}${a}: remote size ${remote_size} != local"
        [[ "${a}" == rootfs.img ]] && continue
        aws s3 cp --only-show-errors "${output_prefix}${a}" "${readback}/${a}" || die "read-back of ${a} failed"
        [[ "$(sha_of "${readback}/${a}")" == "$(sha_of "${output_dir}/${a}")" ]] \
            || die "${output_prefix}${a}: read-back sha differs from the uploaded file"
    done
    log "uploaded to ${output_prefix} (read-back verified)"
fi

echo "REBUILD OK inputs_from=${inputs_from} initrd_sha256=${new_initrd_sha} source_initrd_sha256=${src_initrd_sha} kernel=${kver} source_bake_id=${source_bake_id} repo_commit=${repo_commit}"
