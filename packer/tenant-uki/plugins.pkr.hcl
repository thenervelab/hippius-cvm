# `packer/tenant-uki/plugins.pkr.hcl` — pinned Packer + plugin versions.
#
# Spec of record: `ARCHITECTURE.md` §11 (Supply chain & measured boot)
# — "Packer: pinned base images by digest, pinned plugins, pinned
# package mirrors, signed artifacts, SBOM, SLSA-style provenance".
#
# Pins use exact-version operators (`= X.Y.Z`), NOT pessimistic
# (`~> X.Y`) — two builders on different days MUST resolve to the
# byte-identical plugin binary. Updates are a deliberate PR that
# bumps the constant and re-checks the launch measurement; never
# transitive.

packer {
  # Packer CLI version — pinned EXACT. Even with the qemu plugin
  # pinned, the CLI still controls HCL evaluation, builder/
  # provisioner orchestration, post-processor behaviour, plugin
  # install semantics, and `manifest` defaults. For measured-boot
  # reproducibility ("two builders on different days resolve to the
  # byte-identical toolchain"), the CLI MUST be pinned just as
  # exactly as the plugin. Upgrade procedure mirrors the qemu-plugin
  # one — bump-and-re-attest in a deliberate PR; never transitive.
  required_version = "= 1.15.3"

  required_plugins {
    # https://github.com/hashicorp/packer-plugin-qemu — exact pin.
    # When upgrading, the PR MUST:
    #  1. record the previous and new versions in the commit message,
    #  2. re-run a clean build and diff the launch measurement,
    #  3. update the §22 offline allowlist with the new measurement
    #     before the new image can boot in prod (Q12 OOB flow).
    qemu = {
      version = "= 1.1.2"
      source  = "github.com/hashicorp/qemu"
    }
  }
}
