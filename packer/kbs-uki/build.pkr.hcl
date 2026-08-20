# `packer/kbs-uki/build.pkr.hcl` — qemu source + build pipeline.
#
# PR-F1 scope: skeleton that `packer validate` accepts. Provisioning
# is a single placeholder shell step; PR-F2 replaces it with the
# real preseed-driven install + UKI assembly.
#
# Spec: `ARCHITECTURE.md` §11. The eventual goals are:
#   - read-only dm-verity rootfs (PR-F3),
#   - signed UKI with embedded verity root hash + pinned cmdline
#     (PR-F2),
#   - content-addressed S3 upload + signed provenance map (PR-F4),
#   - allowlist push via the Q12 OOB path (build pipeline →
#     S3 Object Lock → signed by §22 root → KBS pull).

source "qemu" "kbs-uki" {
  # ── Pinned base ─────────────────────────────────────────────────
  # Debian Bookworm netinst, pinned by URL + SHA-256 digest. Packer
  # fetches the ISO, verifies the digest before booting, and refuses
  # any mismatch. The placeholder digest in `variables.pkr.hcl` is
  # deliberately wrong so a `packer build` without an operator-
  # supplied override is fail-closed — see the README.
  iso_url      = var.debian_iso_url
  iso_checksum = var.debian_iso_sha256

  # ── Output ──────────────────────────────────────────────────────
  output_directory = "${var.output_directory}/${var.image_version}"
  vm_name          = "kbs-uki-${var.image_version}.qcow2"
  format           = "qcow2"
  disk_compression = true

  # ── VM shape ────────────────────────────────────────────────────
  cpus      = var.vm_cpus
  memory    = var.vm_memory_mb
  disk_size = var.vm_disk_size

  headless       = true
  accelerator    = var.qemu_accelerator
  net_device     = "virtio-net"
  disk_interface = "virtio"

  # ── SSH (PR-F2 will wire the real preseed) ─────────────────────
  # PR-F1 supplies a username only so HCL validation succeeds; the
  # build will not run end-to-end until PR-F2 adds the preseed and
  # a real SSH key/password material via a *.pkrvars.hcl that is
  # NEVER committed (gitignored — see `.gitignore`).
  ssh_username           = var.ssh_username
  ssh_timeout            = "30m"
  ssh_handshake_attempts = 100

  # ── Boot — PR-F2 will replace this stub ────────────────────────
  # Packer needs a non-empty boot_command to drive the bookworm
  # installer. PR-F1 emits a no-op `<wait>` so HCL parsing succeeds;
  # `packer build` would time out on `ssh_wait_timeout` because
  # nothing actually installs an SSH-reachable system. That is the
  # PR-F1 contract — `validate` passes, `build` is for PR-F2+.
  boot_wait    = "5s"
  boot_command = ["<wait>"]

  # ── Reproducibility hooks (recorded, used by PR-F3+) ───────────
  # PR-F3 pins SMBIOS / firmware so the SNP launch measurement is
  # byte-identical between builds. PR-F1 keeps the qemuargs list
  # empty so the qemu defaults are explicit (not implicit overrides
  # of future PR-F3 additions).
  qemuargs = []
}

build {
  name    = "kbs-uki"
  sources = ["source.qemu.kbs-uki"]

  # ── PR-F1 stub provisioner ─────────────────────────────────────
  # The shell-local provisioner emits a single marker line so the
  # build block is non-empty (Packer requires at least one). PR-F2
  # replaces this with the real provisioning chain (apt install,
  # systemd-boot/UKI assembly, dm-verity image creation, etc.).
  provisioner "shell-local" {
    inline = [
      "echo 'kbs-uki PR-F1 skeleton: real provisioning lands in PR-F2'",
    ]
  }

  # ── PR-F4 post-processor placeholder (intentionally absent) ───
  # PR-F4 will add a `post-processor "manifest"` that emits the
  # provenance map fields the rest of the pipeline consumes —
  # currently the shape is:
  #
  #   {launch_measurement, verity_root_hash, artifact_sha256,
  #    bucket, key, version_id, packer_cli_version,
  #    qemu_plugin_version, qemu_accelerator}
  #
  # Per the Q12 LOCKED flow (#1 c4496539510), Packer itself does
  # NOT sign anything: it uploads the unsigned manifest + artifact
  # to S3 with Object Lock. The offline §22 root then pulls,
  # verifies, signs, and re-uploads the signed manifest. The KBS
  # pulls only the SIGNED object from S3. The signing step lives
  # OUTSIDE this Packer template (on the air-gapped machine) by
  # design — Packer must not have the §22 key in its execution
  # context.
}
