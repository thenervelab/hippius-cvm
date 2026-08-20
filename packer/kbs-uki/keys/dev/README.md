# `keys/dev/` — DEV ONLY signing keys

**⚠️ DEV PLACEHOLDERS. NEVER USE IN PRODUCTION. ⚠️**

This directory ships two committed **dev placeholder** keypairs:

1. an RSA-2048 self-signed X.509 keypair the PR-F2 UKI build flow
   sbsigns the UKI PE binary with;
2. an Ed25519 §22 allowlist **provenance root** keypair the PR-F4
   `hippius-image-provenance` tool signs the image provenance map
   with.

| File | Contents | Status |
|---|---|---|
| `db.key` | RSA-2048 private key, PEM, unencrypted | **PUBLIC** — committed to git. |
| `db.crt` | Self-signed cert, `CN=hippius-uki-dev-placeholder`, validity 100 years. | **PUBLIC** — committed to git. |
| `provenance-root.dev.ed25519` | Ed25519 §22 provenance-root private seed, 64 hex chars. | **PUBLIC** — committed to git. |
| `provenance-root.dev.ed25519.pub` | Ed25519 §22 provenance-root public key, 64 hex chars. | **PUBLIC** — committed to git. |

## Why commit a private key?

The launch measurement emitted by
[`binaries/uki-measure`](../../../../binaries/uki-measure/) MUST be
byte-identical between a developer machine (macOS Apple Silicon via
Docker) and CI (Linux/amd64). If `make uki` generated a fresh key
on first run, every machine would produce a different signed UKI →
a different measurement → reproducibility broken. The §22 allowlist
signer (which Vali / KBS will pull from) depends on this invariant.

Committing a deterministic dev keypair is the smallest infrastructure
that makes "two runs back-to-back = bytes identiques" work across
machines.

## Three-belt defense against prod use

A DEV key in a public repo is dangerous IF a placeholder image ever
escapes into the production allowlist trust path. Three independent
gates must ALL fail before a dev-signed UKI becomes a prod trust
anchor. PR-F3 lifted `measurement_kind` to the real
`snp_launch_digest_v1`, so the belts that flag a *dev SNP build* are
now the cert CN and the IDBLOCK marker:

1. **Dev cert CN**: `CN=hippius-uki-dev-placeholder` and this
   directory's `dev/` segment make a dev-signed UKI visually obvious
   in any `openssl x509 -in db.crt -text` audit. Prod overrides the
   key via `SBSIGN_KEY`/`SBSIGN_CRT` (see below).
2. **IDBLOCK `DO-NOT-TRUST-IN-PROD` marker**: while
   `../../idblock/DO-NOT-TRUST-IN-PROD` exists beside an all-zero
   `idblock.bin`, the SEV-SNP launch policy is unauthenticated —
   the build is dev-only. A production turn-up replaces the ID block
   AND deletes the marker in one visible diff.
3. **`measurement_kind` + §22 signer**: the §22 ceremony signer MUST
   refuse to sign any allowlist entry where `measurement_kind !=
   "snp_launch_digest_v1"` — that catches a default (`uki_sha384`)
   build outright — and the operator verifies provenance before
   signing, never a silent acceptance.

## Secret-scan allowlist (PR-F6)

`.github/workflows/secret-scan.yml` runs `gitleaks` on every PR. This
directory is one of the narrowly-allowlisted paths in
[`.gitleaks.toml`](../../../../.gitleaks.toml) (the others being the
config file itself and `vendor/sev/`, whose source carries PEM header
*string constants*, not keys) — the committed dev keys (the PEM
`db.key`, the raw Ed25519 seed) would otherwise fail every PR. This
directory's exception is scoped to **exactly** `packer/kbs-uki/keys/dev/`:
every other path — including the rest of `packer/kbs-uki/keys/` — stays
scanned, so a real key committed anywhere else still fails the build.
Excluding the dev keys is safe because their defence is the three belts
above, not secrecy.

## Production override

The Makefile reads `SBSIGN_KEY` + `SBSIGN_CRT` env vars; both
default to the files here. Production hosts override:

```bash
make uki SBSIGN_KEY=/run/secrets/uki-signing.key \
         SBSIGN_CRT=/run/secrets/uki-signing.crt
```

Prod keys typically live in Vault transit OR on an offline ceremony
machine that signs only after the §22 allowlist signer has approved
the measurement. They MUST NOT end up in this directory or anywhere
else under `packer/kbs-uki/keys/` — the root `.gitignore` blocks
`*.key` outside this allowlist.

## How this dev key was generated

For reproducibility, the exact `openssl` invocation:

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout db.key -out db.crt \
  -days 36500 -nodes \
  -subj "/CN=hippius-uki-dev-placeholder"
```

Regenerating is **never** correct — it would break reproducibility
across dev + CI. If the cert ever needs to rotate (e.g. an upstream
sbsign change rejects the format), the rotation is a deliberate
multi-machine sync via a separate PR.

## The §22 provenance root key (`provenance-root.dev.ed25519`)

PR-F4's `hippius-image-provenance` tool signs the image provenance
map (ARCHITECTURE.md §11/§22) with an **Ed25519 allowlist root key**.
§22 mandates that key be held offline/air-gapped; this directory
ships a **dev placeholder** so the whole build → measure → sign →
publish flow is exercisable on a laptop and in CI.

- `provenance-root.dev.ed25519` — the 32-byte Ed25519 seed, encoded
  as 64 lowercase-hex characters. The seed is the ASCII bytes of
  `HIPPIUS-DEV-PROVENANCE-ROOT-KEY!` (a deliberately recognisable,
  obviously-dev value — verify with
  `printf '%s' 'HIPPIUS-DEV-PROVENANCE-ROOT-KEY!' | xxd -p`).
- `provenance-root.dev.ed25519.pub` — the matching 32-byte public
  key. This is what a verifier (the §22 ceremony signer, the PR-F5
  miner fetch tool) pins as the root anchor. The
  `committed_dev_pubkey_matches_the_seed` test asserts the two files
  agree.

**Production swap.** Nothing in `hippius-image-provenance` is
hard-coded to these files — `sign --signing-key` and
`verify --root-pubkey` take paths. Production signs on the offline
§22 ceremony machine with the real air-gapped root seed and never
commits it. The wire signature format is identical, so swapping the
key file is the only change.

**Why a dev key is safe here.** A dev provenance signature is not a
production trust anchor because the §22 ceremony signer compiles in
the *real* root public key and rejects a provenance map signed by
any other key — exactly as it rejects a `measurement_kind` that is
not `snp_launch_digest_v1`. A dev-signed provenance map simply does
not verify against the production root.

This key MUST NOT be regenerated — the PR-F4 known-answer test
(`test_vectors/provenance/`) pins a signature produced by this exact
seed. See `test_vectors/provenance/REGENERATE.md`.
