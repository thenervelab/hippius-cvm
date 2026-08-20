#!/usr/bin/env bash
# docs-links-test.sh — every relative link in the docs must resolve.
#
# A newcomer meets the documentation before the code, so a link that goes
# nowhere is a defect of the same kind as a function that does not compile
# — it just fails on a person instead of a compiler.
#
# This check has already paid twice, which is why it is a file rather than
# a snippet someone pastes:
#
#   - it found `scripts/run-ci-locally.sh`, promised twice in the README
#     since PR #176 and never written, so every contributor who followed
#     the README's own instructions hit a missing file;
#   - it stopped a link being added from a doc on `main` to a file that
#     exists only on `release/opensource`. That direction matters in a way
#     nothing else covers: the deploy scrub CREATES files
#     (`host_vars/README.md`, `miner.example.yml`, `inventory.example.yml`)
#     which live on the publishable branch alone. A link to them resolves
#     in the published tree and dangles in the internal one, and running
#     this on both branches is the only thing that catches either case.
#
# It checks TWO things, because documentation points at files in two
# different ways and only one of them looked like a link:
#
#   1. relative markdown links — `[text](../path)`
#   2. bare repo-relative paths written in prose or a code fence —
#      "run `scripts/foo.sh`", "see `binaries/bar/src/baz.rs`"
#
# The second pass exists because the first could not have caught the very
# defect that motivated this file. `run-ci-locally.sh` was named in the
# README as a COMMAND, not a link, and stayed missing for months. Measured
# when the pass was added: 58 markdown links against 235 bare paths, so
# four fifths of what the docs point at was unchecked — and eight of those
# paths did not exist, including a `deploy/runbooks/` directory that had
# been deleted wholesale and a crate dropped in #472 whose regeneration
# instructions were still committed.
#
# Scope: RELATIVE links and repo-relative paths. External URLs are not
# checked; that needs the network and would fail for reasons that are not
# ours.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
cd "${ROOT}"

python3 - <<'PY'
import re, pathlib, subprocess, sys

files = subprocess.run(["git", "ls-files", "*.md"],
                       capture_output=True, text=True).stdout.split()
if not files:
    print("docs-links: git ls-files returned no markdown — not scanning a real tree")
    sys.exit(1)

# `[text](target)` where target is relative: either explicitly ./ or ../,
# or a bare path ending in an extension we ship. A bare word with no
# extension is usually an anchor or an external shorthand, not a path.
LINK = re.compile(
    r'\[[^\]]*\]\('
    r'(\.{1,2}/[^)#\s]+|[A-Za-z0-9_][^):#\s]*\.(?:md|sh|py|rs|toml|yaml|yml|json))'
    r'(?:#[^)]*)?\)'
)

broken, total = [], 0
for f in files:
    p = pathlib.Path(f)
    for m in LINK.finditer(p.read_text(errors="ignore")):
        target = m.group(1)
        total += 1
        if not (p.parent / target).resolve().exists():
            broken.append((f, target))

print(f"docs-links: {total} relative link(s) across {len(files)} markdown file(s)")

# Vacuity floor. A regex that stopped matching would report zero broken
# links over zero links and read identically to a clean tree — the failure
# this repository keeps rediscovering in its own guards.
MIN = 40
if total < MIN:
    print(f"docs-links: only {total} links matched (expected >= {MIN}) — "
          "the extractor is not seeing the docs, which is not the same as them being clean")
    sys.exit(1)

for f, t in broken:
    print(f"  BROKEN  {f} -> {t}")

# ── pass 2: bare repo-relative paths ────────────────────────────────
#
# A path is resolved against the repo root AND against the directory of
# the document naming it, because both conventions are in use here and
# both are legitimate. Only a path that resolves NEITHER way is a defect.
# Getting this wrong in the probe that found these bugs produced two
# rounds of false positives — first by resolving root-only, then by an
# extension-anchored regex that truncated `x.yaml.example` to `x.yaml`.
# Hence the greedy tail below: capture the WHOLE token, then test it.
PATH_RE = re.compile(
    r'(?:^|[\s`\'"(])('
    r'(?:scripts|deploy|binaries|vali|sentinel|packer|docs|test_vectors'
    r'|clients|kbs-core|hippius-guest|hippius-types)'
    r'/[A-Za-z0-9_./-]*[A-Za-z0-9_-]\.[A-Za-z0-9_.-]+)'
)

# Paths a document legitimately names while they do not exist. Each needs
# a reason, and the reasons are all one of three kinds: a BUILD OUTPUT, a
# file the docs tell you to CREATE, or a deliverable that is explicitly
# still PLANNED. Anything else is a defect, not an entry here.
#
# This list is the part that rots. It is printed on every run so that its
# growth is visible in CI output rather than discovered later.
ALLOWED = {
    "packer/kbs-uki/uki/output/measurement.json":
        "build output — produced by the UKI build, never committed",
    "packer/kbs-uki/uki/output/blackbox-measurement.json":
        "build output — same, for the blackbox attestor UKI",
    "packer/ovmf/output-run-a/OVMF.fd":
        "build output — produced by the OVMF reproducibility run",
    "deploy/ansible/inventory.yml":
        "gitignored by design — the docs tell you to create it from the example",
    "sentinel/tests/fixtures/audit_known_good/audit.lock":
        "transient — the README's own line is the `rm` that deletes it",
    "test_vectors/uki/blackbox-measurement.json":
        "planned — pinned on the first CI build, per its REGENERATE doc",
    "test_vectors/uki/tenant-debian-measurement.json":
        "planned — phase 2 deliverable, per the packer README that names it",
}

bad_paths, seen_paths, allowed_hits = [], 0, set()
for f in files:
    p = pathlib.Path(f)
    for m in PATH_RE.finditer(p.read_text(errors="ignore")):
        target = m.group(1).rstrip('.,;:)')
        seen_paths += 1
        if pathlib.Path(target).exists() or (p.parent / target).exists():
            continue
        if target in ALLOWED:
            allowed_hits.add(target)
            continue
        bad_paths.append((f, target))

print(f"docs-links: {seen_paths} bare repo-relative path(s) named in the docs")
for t in sorted(allowed_hits):
    print(f"  allowed {t} — {ALLOWED[t]}")

# Same vacuity floor as above, for the same reason: an extractor that
# stopped matching would report zero missing paths over zero paths.
MIN_PATHS = 150
if seen_paths < MIN_PATHS:
    print(f"docs-links: only {seen_paths} paths matched (expected >= {MIN_PATHS}) — "
          "the extractor is not seeing the docs")
    sys.exit(1)

for f, t in bad_paths:
    print(f"  MISSING {f} -> {t}")

if broken or bad_paths:
    print(f"docs-links: {len(broken)} broken link(s), {len(bad_paths)} missing path(s)")
    sys.exit(1)
print("docs-links: all relative links resolve, and every path the docs name exists")
PY
