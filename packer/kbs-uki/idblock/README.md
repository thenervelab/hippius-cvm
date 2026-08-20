# `packer/kbs-uki/idblock/` — SEV-SNP ID block (PR-F3 placeholder)

## What an ID block is

An AMD SEV-SNP **ID block** is a launch-time structure the guest owner
uses to bind a launch policy and the *expected* launch measurement to
the VM. It is signed by an **author key**; the hypervisor passes it to
`SNP_LAUNCH_FINISH`, and the guest can later prove — in its attestation
report — that it booted under an owner-authorised policy.

The ID block is **not** an input to the launch *measurement* itself
(`snp_calc_launch_digest` does not consume it — see
`binaries/uki-measure/`). It is the owner's *signature over* that
measurement. So PR-F3 scaffolds it here but does not yet sign it.

## What PR-F3 ships

| File | Status |
|---|---|
| `idblock.bin` | **Placeholder** — 96 zero bytes (SEV-SNP ID block size). |
| `id-auth.bin` | **Placeholder** — 4096 zero bytes (ID auth info size). |
| `DO-NOT-TRUST-IN-PROD` | Loud marker — the third belt (read it). |

The placeholders let the rest of the §F pipeline (provenance map in
PR-F4, the launch-config plumbing) take shape without blocking on the
author-key custody decision.

## The three-belt defence (post-PR-F3)

PR-F3 lifts `measurement_kind` to the real `snp_launch_digest_v1`, so
the discriminator alone no longer marks a build pre-production. The
belts are now:

1. **`measurement_kind`** — the §22 ceremony signer refuses any kind
   that is not `snp_launch_digest_v1`.
2. **`DO-NOT-TRUST-IN-PROD`** — present here ⇒ the ID block is an
   all-zero placeholder; the launch is dev-only. A production turn-up
   replaces the blocks AND deletes the marker, in one visible diff.
3. **PR-F4 provenance** — the signed provenance map records the
   IDBLOCK digest; an all-zero block is auditable out-of-band.

## Producing a real ID block (future PR)

The real ID block must be signed by an author key. That key's custody
— generation, ceremony, rotation — is **deliberately out of PR-F3's
scope**: per issue #1 (§B/custody Q&A) it is either PR-K7
(mTLS-CA-adjacent) or a dedicated future PR. `idblock.bin` /
`id-auth.bin` stay zero-filled until that lands.

## NOT a secret

The placeholder blocks are all-zero — no key material. The real ID
block is also non-secret (it is published with the image); only the
*author key* that signs it is sensitive, and that key never lives in
this repository.
