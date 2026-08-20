# Security policy

This project's entire claim is that a machine's operator, holding root on the
bare metal, cannot read the tenant data running on it. A vulnerability report
against that claim is the most valuable thing anyone can send us.

## Reporting a vulnerability

**Do not open a public issue.** Email `infos@hippius.com`.

Include what you have — a description, the affected component, and any way to
reproduce. A report that is only a hypothesis is still worth sending; we would
rather read ten that turn out to be wrong than miss the one that does not.

You should get an acknowledgement within three working days. If you do not,
assume the mail was lost rather than ignored, and try again.

## What is in scope

The things that would break the confidentiality claim, roughly in order of
how badly we want to know:

- **Key release without a valid attestation.** Any path that gets a tenant's
  disk key out of the KBS for a guest whose SEV-SNP report is absent, forged,
  replayed, or whose measurement is not on the signed allowlist.
- **Plaintext reachable by the host.** Anywhere the miner's operator can read
  a tenant key or tenant data — a key that touches host memory in the clear,
  a disk image mounted outside the guest, a debug path that dumps state.
- **Allowlist forgery or rollback.** Minting an entry without the §22 root, or
  making a KBS accept an older allowlist than the one it has seen.
- **Lifecycle abuse.** Crypto-erase that does not erase, decommission that
  leaves a usable key, migration that unlocks a disk on a host the ticket did
  not name, or a boot-counter rollback that revives a retired VM.
- **Miner impersonation.** Presenting as a registered miner without holding
  that node's identity key, or getting placed without being `active` on chain.

`docs/security/data-visibility.md` states exactly what each party is supposed
to see in plaintext at each stage. **A demonstration that the document is
wrong is a valid report**, and one of the more useful kinds.

## What is not in scope

- Anything requiring a tenant's own credentials — a tenant can already read
  their own data; that is the point.
- Denial of service against a miner's own hardware. A miner can always switch
  their machine off; the design assumes it, and the migration path exists
  because of it.
- The committed development keys under `packer/kbs-uki/keys/dev/`. They are
  deliberately public and no production trust anchor is derived from them —
  the deployed KBS holds a different allowlist root. That directory's README
  explains why they are committed.
- Findings from a scanner with no reachable path behind them. We run
  `gitleaks` over the whole tree on every change; a report that repeats what
  it already prints is not a finding.

## Disclosure

Tell us before you tell everyone, and we will not sit on it. We will agree a
date with you rather than impose one. If we go quiet, publish — a silent
maintainer is not a reason for a real hole to stay open.
