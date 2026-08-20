# `packer/tenant-uki/variables.pkr.hcl` — build inputs.
#
# Every input that affects the resulting image bytes is a typed
# variable so two operators can reproduce the same artifact by
# loading the same `*.pkrvars.hcl` file. The companion
# `tenant-uki.auto.pkrvars.hcl.example` documents the expected shape.

variable "debian_iso_url" {
  type        = string
  description = <<-EOT
    Debian Bookworm (12.x) netinst ISO URL. Bookworm is the only
    distribution PR-F1 targets — see `README.md` for why. The exact
    point release is pinned via `debian_iso_release`, and the bytes
    are pinned via `debian_iso_sha256`.
  EOT

  # Default is a parameterized URL so an air-gapped mirror can be
  # swapped in via a single `-var` override at build time (§11
  # "pinned package mirrors").
  default = "https://cdimage.debian.org/debian-cd/12.8.0/amd64/iso-cd/debian-12.8.0-amd64-netinst.iso"
}

variable "debian_iso_release" {
  type        = string
  description = <<-EOT
    Debian point release this build targets. Recorded in the
    README + commit message; baked into the image_version stamp
    and (PR-F4) the signed provenance map.

    MUST match the version segment of `debian_iso_url` — a
    `-var` override could otherwise silently record one release
    while fetching another (a provenance footgun for PR-F4).
    Packer's variable-validation block can only inspect the
    variable in isolation (no cross-variable refs), so this
    consistency check is enforced by:

    - PR-F4: the provenance-emit step asserts the
      `debian_iso_release`-vs-`debian_iso_url` match before
      anything is written to the manifest.
    - Operator discipline: only override BOTH together in
      `tenant-uki.auto.pkrvars.hcl`.
  EOT

  default = "12.8.0"
}

variable "debian_iso_sha256" {
  type        = string
  description = <<-EOT
    SHA-256 of `debian_iso_url`. MUST be cross-checked against
    `SHA256SUMS` from the same `debian-cd/<release>/amd64/iso-cd/`
    directory AND the detached `SHA256SUMS.sign` signature
    (Debian release keys, validated against an out-of-band-trusted
    keyring) before this skeleton is promoted to a real build.

    The placeholder value below is a 32-zero-byte digest — Packer
    will REFUSE to fetch the ISO with this value (no real artifact
    will match), so a `packer build` without an operator-supplied
    override is fail-closed at fetch time. `packer validate`
    doesn't fetch, so the PR-F1 skeleton's validate contract still
    passes.

    PR-F2 swaps this default for the verified-and-recorded SHA-256
    of the targeted point release. A `validation { }` block that
    rejected the placeholder eagerly would break `packer validate`,
    so we rely on the SHA mismatch at fetch instead — same
    fail-closed posture, just one step later.
  EOT

  default = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

variable "image_version" {
  type        = string
  description = "Image version stamp baked into the artifact name. PR-F4 wires this into the signed provenance map alongside launch_measurement + verity_root_hash + artifact_sha256."
  default     = "0.0.1-pr-f1-skeleton"
}

variable "output_directory" {
  type        = string
  description = "Where Packer writes the qcow2 output. Build runs in a k8s Job whose volume is mounted here (PR-F4)."
  default     = "output/tenant-uki"
}

variable "qemu_accelerator" {
  type        = string
  description = <<-EOT
    qemu accelerator. `tcg` is the deterministic CPU-emulation
    path and is the ONLY option supported for production /
    measured builds; `kvm` (Linux) and `hvf` (macOS) are
    faster but expose host CPU behaviour that may perturb the
    install-time bytes until PR-F6's reproducibility gate has
    proven otherwise. The accelerator value is included in the
    PR-F4 provenance map so any divergence is auditable.

    Treat anything other than `tcg` as **dev-only** until
    PR-F6 lands.
  EOT

  default = "tcg"

  validation {
    condition     = contains(["tcg", "kvm", "hvf"], var.qemu_accelerator)
    error_message = "The qemu_accelerator variable must be one of tcg, kvm, or hvf."
  }
}

variable "vm_cpus" {
  type    = number
  default = 2
}

variable "vm_memory_mb" {
  type        = number
  description = "Guest RAM in MiB. 2 GiB is enough for the bookworm netinst path; the real UKI build (PR-F2) may need more."
  default     = 2048
}

variable "vm_disk_size" {
  type        = string
  description = "qcow2 disk size. The UKI itself is small (~50 MiB), but PR-F2's package install needs working space."
  default     = "8G"
}

variable "ssh_username" {
  type        = string
  description = "Provisioner SSH user. PR-F1 has no real provisioning — value matters only when PR-F2 wires the preseed.cfg."
  default     = "packer"
}
