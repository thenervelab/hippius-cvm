# Terraform state backend.
#
# publishability-allow: provider — the remote-state instructions below name
# GCS because that is the service being configured; a deployer cannot act on
# "use an object store". It says "your own project", not ours.
#
# MVP: the **local** backend. `terraform.tfstate` lands in this
# directory and is git-ignored by `deploy/.gitignore` (`*.tfstate`,
# `*.tfstate.*`). State embeds resolved values — including secrets — in
# plaintext, so it MUST never be committed.
#
# Migration to remote state (recommended once the team is >1 operator):
# create a GCS bucket `hippius-tfstate` (versioned, uniform access,
# CMEK-encrypted) in your own GCP project, then replace the
# `backend "local"` block below with the commented `backend "gcs"` one
# and run `terraform init -migrate-state`. GCS encrypts state at rest
# and supports state locking — both absent from the local backend.
#
#   backend "gcs" {
#     bucket = "hippius-tfstate"
#     prefix = "hippius-compute/deploy"
#   }

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
