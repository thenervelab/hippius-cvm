#!/usr/bin/env python3
"""
Post-merge tracking sync.

Given one or more merged PR numbers, marks the corresponding PR-XN line
done in the chunk tracking issue (#38-#57) and prints a suggested
annotation for the global roadmap (#25).

Usage:
    scripts/post-merge-tracking.py PR_NUMBER [PR_NUMBER ...]
    scripts/post-merge-tracking.py --dry-run PR_NUMBER

The script is idempotent: running it twice on the same PR doesn't
produce new diffs (lines already marked done are detected and skipped).

Discipline note: this only handles the structured chunk-issue breakdown.
The global roadmap #25 has free-form prose around each item — we print
a suggested annotation string but DON'T edit #25 automatically, because
auto-generated rich annotations always end up worse than manual ones.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

# Section letter → tracking issue number. Sections without their own
# tracking issue (J cross-cutting, N shared engineering) only appear
# in #25 and are skipped silently.
SECTION_TO_ISSUE: dict[str, int] = {
    "E": 42,
    "F": 41,
    "G": 38,
    "H": 39,
    "I": 40,
    "K": 54,
    "S": 57,
}

# Title formats accepted:
#   feat(§I PR-I3): ...
#   feat(§E PR-E1.2): ...
#   feat(§S PR-S2): ...
#   fix(§I PR-I4): ...    (review-fix follow-ups)
TITLE_RE = re.compile(
    r"^(?:feat|fix|refactor|docs)"
    r"\(§([A-Z])\s+(PR-[A-Z]\d+(?:\.\d+)?)\)"
)


@dataclass
class ParsedPR:
    number: int
    title: str
    state: str
    section: Optional[str]
    pr_id: Optional[str]


def run_gh(args: list[str], **kw) -> str:
    """Run `gh` with capture. Raises CalledProcessError on non-zero."""
    res = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=True, **kw
    )
    return res.stdout


def fetch_pr(number: int) -> ParsedPR:
    out = run_gh(
        ["pr", "view", str(number), "--json", "title,number,state"]
    )
    data = json.loads(out)
    title = data["title"]
    m = TITLE_RE.match(title)
    section = m.group(1) if m else None
    pr_id = m.group(2) if m else None
    return ParsedPR(
        number=data["number"],
        title=title,
        state=data["state"],
        section=section,
        pr_id=pr_id,
    )


def fetch_issue_body(number: int) -> str:
    return run_gh(["issue", "view", str(number), "--json", "body", "--jq", ".body"])


def update_issue_body(number: int, body: str) -> tuple[bool, str]:
    res = subprocess.run(
        ["gh", "issue", "edit", str(number), "--body-file", "-"],
        input=body,
        text=True,
        capture_output=True,
    )
    return res.returncode == 0, (res.stdout + res.stderr).strip()


def mark_pr_done(body: str, pr_id: str, pr_number: int) -> tuple[str, bool, str]:
    """
    Try to mark `pr_id` as done in `body`.

    Returns (new_body, changed, message). The patterns below cover the
    formatting variants seen across our tracking issues. Each pattern
    matches an UNCHECKED line referencing the PR id, and replaces it
    with a checked variant + a `(PR #N merged)` annotation.

    If the PR is ALREADY marked done, `changed` is False but no error
    is returned — the function is idempotent by design.
    """
    # Idempotency: detect the PR-id already marked done with EITHER format
    # variant we know of:
    #   1. our own writer: `... (PR #N merged) ...`
    #   2. parallel sessions: `**PR-XN (#N)** ...` (id and number bolted together)
    if re.search(
        rf"(?:- \[x\]|- ✅)[^\n]*\b{re.escape(pr_id)}\b[^\n]*(?:PR #|\(#){pr_number}\b",
        body,
    ):
        return body, False, "already marked with this PR ref (idempotent skip)"

    # Variants seen in the tracking issues. Order matters — most specific first.
    transforms = [
        # `- [ ] **PR-X1** — description`  →  `- [x] **PR-X1** (PR #N merged) — description`
        (
            rf"^- \[ \] \*\*{re.escape(pr_id)}\*\* — ",
            rf"- [x] **{pr_id}** (PR #{pr_number} merged) — ",
        ),
        # `- [ ] PR-X1: description`  →  `- [x] PR-X1 (PR #N merged): description`
        (
            rf"^- \[ \] {re.escape(pr_id)}: ",
            rf"- [x] {pr_id} (PR #{pr_number} merged): ",
        ),
        # `- PR-X1: description` (plain bullet, no checkbox)  →
        # `- ✅ **PR-X1** (PR #N merged) — description` (promoted to
        # bold + completion marker for visual consistency with the
        # other variants).
        (
            rf"^- {re.escape(pr_id)}: ",
            rf"- ✅ **{pr_id}** (PR #{pr_number} merged) — ",
        ),
        # `- 🆕 **PR-X1** — description`  →  `- ✅ **PR-X1** (PR #N merged) — description`
        (
            rf"^- 🆕 \*\*{re.escape(pr_id)}\*\* — ",
            rf"- ✅ **{pr_id}** (PR #{pr_number} merged) — ",
        ),
        # `- 🔴 **PR-X1** — description`  →  `- ✅ **PR-X1** (PR #N merged) — description`
        (
            rf"^- 🔴 \*\*{re.escape(pr_id)}\*\* — ",
            rf"- ✅ **{pr_id}** (PR #{pr_number} merged) — ",
        ),
        # `- 🔄 **PR-X1** (en cours...) — description`  →  `- ✅ **PR-X1** (PR #N merged) — description`
        (
            rf"^- 🔄 \*\*{re.escape(pr_id)}\*\*[^—]*— ",
            rf"- ✅ **{pr_id}** (PR #{pr_number} merged) — ",
        ),
        # Bare `- [ ] PR-X1 description`  →  `- [x] PR-X1 (PR #N merged) description`
        (
            rf"^- \[ \] {re.escape(pr_id)}(\b)",
            rf"- [x] {pr_id} (PR #{pr_number} merged)\1",
        ),
    ]

    for pat, repl in transforms:
        new_body, n = re.subn(pat, repl, body, count=1, flags=re.MULTILINE)
        if n > 0:
            return new_body, True, "marked done"

    # Found the PR id but couldn't match an "unchecked" pattern.
    if re.search(rf"\b{re.escape(pr_id)}\b", body):
        return body, False, (
            f"{pr_id} referenced but no matching unchecked pattern — "
            "either already done with a different annotation style, "
            "or the breakdown uses a format not yet covered"
        )

    return body, False, f"{pr_id} not found in issue body"


def suggest_roadmap_annotation(pr: ParsedPR) -> str:
    """Build a copy-pasteable suggestion for #25."""
    return (
        f"  → Suggestion for #25 § section §{pr.section}: append "
        f"`(PR #{pr.number} — {pr.pr_id})` after the relevant unchecked "
        f"item, and flip `[ ]` to `[~]` (partial) or `[x]` (done) "
        f"depending on whether the chunk is closed."
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync GitHub chunk tracking issues post-merge."
    )
    parser.add_argument("pr_numbers", nargs="+", type=int)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned changes but don't push them to GitHub",
    )
    args = parser.parse_args()

    any_failure = False

    for pr_num in args.pr_numbers:
        print(f"\n=== PR #{pr_num} ===")

        try:
            pr = fetch_pr(pr_num)
        except subprocess.CalledProcessError as e:
            print(f"  ERROR fetching PR: {e.stderr.strip()}")
            any_failure = True
            continue

        print(f"  title:   {pr.title}")
        print(f"  state:   {pr.state}")

        if pr.state != "MERGED":
            print(f"  SKIP: not merged yet (state={pr.state})")
            continue

        if not pr.section or not pr.pr_id:
            print(
                "  SKIP: could not parse section/PR-id from title — "
                "expected `feat(§X PR-XN): ...` format"
            )
            continue

        print(f"  section: §{pr.section}")
        print(f"  pr_id:   {pr.pr_id}")

        chunk_issue = SECTION_TO_ISSUE.get(pr.section)
        if not chunk_issue:
            print(
                f"  NOTE: §{pr.section} has no dedicated chunk issue "
                "(cross-cutting or shared) — only #25 needs annotation"
            )
            print(suggest_roadmap_annotation(pr))
            continue

        try:
            body = fetch_issue_body(chunk_issue)
        except subprocess.CalledProcessError as e:
            print(f"  ERROR fetching #{chunk_issue}: {e.stderr.strip()}")
            any_failure = True
            continue

        new_body, changed, msg = mark_pr_done(body, pr.pr_id, pr.number)

        if not changed:
            print(f"  #{chunk_issue}: {msg}")
            print(suggest_roadmap_annotation(pr))
            continue

        if args.dry_run:
            print(f"  #{chunk_issue}: DRY RUN — would mark done ({msg})")
            print(suggest_roadmap_annotation(pr))
            continue

        ok, out = update_issue_body(chunk_issue, new_body)
        if ok:
            print(f"  #{chunk_issue}: ✓ {msg}")
        else:
            print(f"  #{chunk_issue}: ✗ FAILED — {out}")
            any_failure = True

        print(suggest_roadmap_annotation(pr))

    print("\nDone.")
    return 1 if any_failure else 0


if __name__ == "__main__":
    sys.exit(main())
