# Cutting the public repository

This repository is internal. What gets published is a **new repository with
a single squashed commit** taken from the `release/opensource` branch.

Publishing is a deliberate human act. Nothing automates it, and nothing
prevents it either — `release/opensource` is not a protected branch, so the
checks below run on every push and **inform** the decision rather than block
it. That is the point of this document: the verification is a step you take,
not one you inherit.

## Why a new repository and not this one

`git log -S` over this repository's history returns, today:

| pattern | commits |
|---|---|
| the Vault address | 43 |
| a miner's public IP | 6 |
| our internal domain | 15 |

Scrubbing the working tree does nothing about those. Rewriting history in
place would break every clone, every open PR, every pinned CI ref and every
commit sha this project's runbooks cite. A squashed orphan commit starts at
zero and leaves the internal repository untouched.

**The squash is what guarantees the history, not a search.** `git log -S`
searches the text of diffs, so it cannot see an identifier that lives as
base64 inside DER — a chip id in a certificate returns zero matches in a
repository that certainly contains one. Verify structurally, below.

## Why `release/opensource` and not `main`

`main` is what production deploys from and is deliberately NOT publishable:
the ArgoCD values carry the real Vault address, the real cluster CIDRs and
the real hostnames, because five applications selfHeal from it. Gating `main`
on the publishability check would force a choice between scrubbing what
production needs and a permanently red pipeline.

`release/opensource` is cut from `main` and carries the scrub. The two are
not meant to converge. A CI guard asserts they differ **only** in
configuration and documentation, so the published tree is byte-identical to
the tested one everywhere that matters:

```sh
bash scripts/dev/release-diverges-only-in-config.sh
```

## Before you publish

Bring the branch up to date and read what the checks print — a green tick is
not evidence until you have read it:

```sh
git checkout release/opensource
git merge origin/main && git push
```

Then wait for the `publishability` workflow and confirm it says `ALL CLEAN`.
It will not, until the outstanding decisions are closed; that is deliberate,
and the failing check IS the outstanding decision rather than a note in a
file somewhere.

## Cutting it

```sh
git clone --branch release/opensource <this-repo> /tmp/public && cd /tmp/public
git checkout --orphan public
git commit -m "Initial public release"
git branch -D release/opensource     # ← the whole point; see below
git remote remove origin
git reflog expire --expire=now --all && git gc --prune=now --aggressive
```

**Do not skip the `git branch -D`.** `git clone` brings the source branch
with it, and `--orphan` ADDS a branch rather than replacing one. Leave it and
the new repository holds two: your single squashed commit, and the original
967 with every contaminated commit intact. `git gc` will not collect what a
ref still points at.

This is not hypothetical. The first version of this runbook omitted that
line. Run verbatim it produced:

```
git rev-list --all --count  ->  968     (this document claimed 1)
git for-each-ref | wc -l    ->  2       (claimed 1)
```

Anyone who had followed it and pushed would have published the history this
entire procedure exists to leave behind — and the two checks below are what
caught it, which is why they are counts and not a glance.

## Verifying it, before you add a remote

Structural, not textual — this is the part that actually proves the history
is empty:

```sh
git rev-list --all --count      # must be 1
git for-each-ref | wc -l        # must be 1
git reflog | wc -l              # must be 0
git fsck --unreachable          # must print nothing
```

And the tree itself, with the denylist that is deliberately **not** in this
repository (see `.publish-denylist.example`):

```sh
PUBLISH_DENYLIST=/path/to/list bash scripts/dev/publishability-test.sh
```

`ALL CLEAN` across every class, or do not publish.

## What publishing does not undo

An accidental commit cannot be un-pushed. GitHub keeps `refs/pull/N/head`
after a pull request is closed and its branch deleted, so "close the PR and
delete the branch" is not a remediation — it was tried here and the objects
remained fetchable. Prevention is the only remediation, which is why
operational captures are ignored at the root (`/*.log`) rather than merely
discouraged.

## Choosing a name

**Do not name it `hippius-compute`.** The cosign trust anchors in
`.github/workflows/verify-gitops-signatures.yml` and
`.github/scripts/verify_image_provenance.py` match first-party images by
repository NAME, and every currently pinned image was signed under that name.
Giving it to a repository we do not control transfers the first-party trust
anchor to that repository. Any other name costs nothing.


## Refreshing it at each release

The cut above happens once. After that the public repository is a *published
snapshot* of a release, and this internal repository stays where the work
happens. Each release republishes; nothing is ever developed on the public
side.

`thenervelab/hippius-cvm` was cut on 2026-08-19 from `main` at `5ca6e16`.

### The recipe, in the order that works

```sh
# 1. Start from the SCRUBBED branch and bring main INTO it.
git worktree add --detach /tmp/pub origin/release/opensource
cd /tmp/pub
git merge -X ours origin/main          # `ours` = keep the scrub

# 2. Gate it. The denylist is never committed — see the script header.
PUBLISH_DENYLIST=/path/to/.publish-denylist scripts/dev/publishability-test.sh

# 3. Squash to ONE commit with no ancestry, and verify the depth.
git checkout --orphan publish && git add -A && git commit
git log --oneline | wc -l              # must print 1

# 4. Push over SSH (see below), then confirm on the remote.
git remote add public git@github.com:thenervelab/hippius-cvm.git
git push public publish
```

### Four things that cost a cycle each

**Merge main INTO the scrubbed branch, never the reverse.** The scrub is not
a set of file deletions — it EDITS content across dozens of files (cluster
addressing, internal domains, an operator email). Taking `main` and
re-applying only the file removals leaves 20 files disclosing, which the gate
catches and a hurried person does not. `-X ours` keeps every scrub edit and
still takes main's new files.

**`release/opensource` alone is not enough either.** It drifts behind `main`
the moment anything merges. Published as-is on 2026-08-19 it would have
shipped a tree whose API path could not boot a guest — the `hippius.kbs_url`
fix was 23 commits newer. Always merge, always re-gate.

**Push over SSH, not HTTPS.** An OAuth token without the `workflow` scope is
refused the moment the push contains `.github/workflows/*`:

    refusing to allow an OAuth App to create or update workflow ... without `workflow` scope

The repository ends up created and EMPTY, which looks like success until you
list its contents. SSH is not OAuth-scoped and pushes fine. (The alternative
— `gh auth refresh -h github.com -s workflow` — also works, but changing the
transport is the smaller change.)

**Re-run the gate on the merged tree, not on the branch you trust.** The one
file that leaked on 2026-08-19 was written the previous morning, in this
repository, by someone who had no idea a public snapshot would carry it. That
is the normal case: the gate exists because prose accumulates addresses.

### Keeping the internal repository publishable-adjacent

Every leak the gate has caught so far arrived in a *comment* — an explanation
that named a real address because the author was explaining a real system.
Nothing forbids that here, and it should not: this repository is private and
the concrete value is often the clearest way to say it. But a file that will
be published reads better when the reasoning survives without the literal,
and fixing it here is one line, while finding it during a release is an
interrupted release.
