"""Miner-agent releases, as the miners' updater sees them.

`vali_agent_release_watch` (a CronJob, `VALI_AGENT_RELEASE_WATCH`) reads
`GET https://api.github.com/repos/<VALI_AGENT_RELEASE_REPO>/releases?per_page=20`
and replaces `AgentRelease` with the COMPLETE releases in it, by exactly
the rule of `hippius-miner-update` (deploy/ansible/playbooks/miner-tasks/
files/hippius-miner-update.sh, its selection step):

- not a draft, not a prerelease;
- a `vYYYY.MM.DD` / `vYYYY.MM.DD.N` tag (N = 1..999, no leading zero),
  ordered as the integers (YYYY, MM, DD, N), N = 0 when absent;
- the binary, `SHA256SUMS` and the `.sigstore.json` attestation attached;
- a readable `published_at`, and a tag dated at most one day after its UTC
  publication day (a mistyped far-future tag is passed over);
- ready when the last of the three files landed (newest asset
  `updated_at`, never before `published_at`).

The operator rows then show the newest complete release
(`latest_agent_release`, with the instant it becomes eligible: ready +
`VALI_AGENT_RELEASE_SOAK_H`, the updater's `MIN_RELEASE_AGE_H` default)
and whether the node's agent is behind the newest release eligible NOW
(`update_pending`). A host's own failed marker or canary soak is not
known here: the node reports those itself (`auto_update`).

Display only: nothing that places, pays or gates reads this.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import transaction

from apps.miners.models import AgentRelease
from apps.orchestration.effects import EffectError, EffectUnavailable

log = logging.getLogger(__name__)

ASSET = "hippius-miner-agent-x86_64-linux-gnu"
#: Every file the updater needs before it considers a release.
REQUIRED_ASSETS: tuple[str, ...] = (ASSET, "SHA256SUMS", f"{ASSET}.sigstore.json")
#: The updater's `TAG_RE`.
TAG_RE = re.compile(r"^v([0-9]{4})\.([0-9]{2})\.([0-9]{2})(\.([1-9][0-9]{0,2}))?$")
#: What the updater asks for, and so what this mirrors.
PER_PAGE = 20
#: A response past this is refused (20 releases are a few hundred KB).
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

ReleaseKey = tuple[int, int, int, int]


def release_key(tag: str | None) -> ReleaseKey | None:
    """`(YYYY, MM, DD, N)` of a release tag, `None` for anything else
    (`dev`, `v2026.10.08.0`, garbage)."""
    m = TAG_RE.fullmatch(tag or "")
    if m is None:
        return None
    return int(m[1]), int(m[2]), int(m[3]), int(m[5] or 0)


@dataclass(frozen=True)
class CompleteRelease:
    tag: str
    key: ReleaseKey
    published_at: datetime
    ready_at: datetime


def _ts(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("not a timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("naive timestamp")
    return parsed


def complete_releases(payload: Any) -> list[CompleteRelease]:
    """The complete releases of a release-list response (or of one release
    object), newest tag first. Anything malformed is passed over, as the
    updater does; only a payload that is not JSON at all is an error (the
    caller's)."""
    items = payload if isinstance(payload, list) else [payload]
    out: dict[str, CompleteRelease] = {}
    for rel in items:
        if not isinstance(rel, dict):
            continue
        tag = rel.get("tag_name")
        m = TAG_RE.fullmatch(tag) if isinstance(tag, str) else None
        if rel.get("draft") or rel.get("prerelease") or m is None:
            continue
        raw_assets = rel.get("assets")
        assets = {
            a.get("name"): a
            for a in (raw_assets if isinstance(raw_assets, list) else [])
            if isinstance(a, dict)
        }
        if not all(name in assets for name in REQUIRED_ASSETS):
            continue
        try:
            published = _ts(rel.get("published_at"))
            tag_day = datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=UTC)
            ready = max(
                [published]
                + [
                    _ts(assets[name].get("updated_at") or rel.get("published_at"))
                    for name in REQUIRED_ASSETS
                ]
            )
        except (TypeError, ValueError):
            continue
        if tag_day > published + timedelta(days=1):
            continue
        out[tag] = CompleteRelease(
            tag=tag,
            key=(int(m[1]), int(m[2]), int(m[3]), int(m[5] or 0)),
            published_at=published,
            ready_at=ready,
        )
    return sorted(out.values(), key=lambda r: r.key, reverse=True)


def releases_url() -> str:
    repo = str(settings.VALI_AGENT_RELEASE_REPO or "").strip()
    if not _REPO_RE.match(repo):
        raise EffectError(f"VALI_AGENT_RELEASE_REPO {repo!r} is not <owner>/<repo>")
    return f"https://api.github.com/repos/{repo}/releases?per_page={PER_PAGE}"


def fetch_releases() -> Any:
    """One GET of the release list, parsed. `EffectUnavailable` on a
    transport failure, `EffectError` on a non-2xx, an oversized or a
    non-JSON answer."""
    request = urllib.request.Request(
        releases_url(),
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hippius-vali-agent-release-watch",
        },
        method="GET",
    )
    timeout = float(settings.VALI_AGENT_RELEASE_HTTP_TIMEOUT_S)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310
            status, body = resp.status, resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status, body = exc.code, b""
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise EffectUnavailable(f"github releases: unreachable ({exc})") from exc
    if not 200 <= status < 300:
        raise EffectError(f"github releases: HTTP {status}")
    if len(body) > MAX_RESPONSE_BYTES:
        raise EffectError("github releases: response too large")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError("github releases: non-JSON response") from exc
    if not isinstance(payload, list):
        raise EffectError("github releases: not a release list")
    return payload


@dataclass(frozen=True)
class SyncResult:
    stored: tuple[str, ...]
    removed: tuple[str, ...]


def store(releases: list[CompleteRelease], *, now: datetime) -> SyncResult:
    """Replace `AgentRelease` with `releases`, in one transaction."""
    tags = [r.tag for r in releases]
    with transaction.atomic():
        removed = tuple(
            sorted(AgentRelease.objects.exclude(tag__in=tags).values_list("tag", flat=True))
        )
        AgentRelease.objects.exclude(tag__in=tags).delete()
        for r in releases:
            AgentRelease.objects.update_or_create(
                tag=r.tag,
                defaults={"published_at": r.published_at, "ready_at": r.ready_at, "seen_at": now},
            )
    return SyncResult(stored=tuple(tags), removed=removed)


def watch_once(*, now: datetime) -> SyncResult:
    """Fetch, select, store. Raises what `fetch_releases` raises, leaving the
    table as it was. A list with no complete release at all leaves it too
    (logged): a glitched answer must not blank every row, and the miners'
    updater installs nothing from such a list either."""
    releases = complete_releases(fetch_releases())
    if not releases:
        log.warning("agent release watch: no complete release in the list; releases unchanged")
        return SyncResult(stored=(), removed=())
    return store(releases, now=now)


# ─── reads (the operator rows) ───────────────────────────────────────


def soak() -> timedelta:
    return timedelta(hours=int(settings.VALI_AGENT_RELEASE_SOAK_H))


@dataclass(frozen=True)
class ReleaseView:
    """What every operator row of one request is judged against."""

    #: `latest_agent_release`, or `None` when no release is known.
    latest: dict[str, Any] | None
    #: The newest release eligible at the request's instant.
    eligible_key: ReleaseKey | None
    #: Whether any release is known at all (the watch ran).
    known: bool

    def update_pending(self, agent_version: str | None) -> bool | None:
        """The node's agent is older than the newest eligible release.
        `None` when it cannot be told: no release known, or the agent's
        tag is not a release (none reported, a `dev` build). `False` when
        releases are known but none is eligible yet."""
        if not self.known:
            return None
        running = release_key(agent_version)
        if running is None:
            return None
        return self.eligible_key is not None and running < self.eligible_key


def release_view(*, now: datetime) -> ReleaseView:
    """ONE query for the whole request."""
    rows = [(key, r) for r in AgentRelease.objects.all() if (key := release_key(r.tag)) is not None]
    if not rows:
        return ReleaseView(latest=None, eligible_key=None, known=False)
    wait = soak()
    _, newest = max(rows, key=lambda kr: kr[0])
    eligible = [key for key, r in rows if r.ready_at + wait <= now]
    return ReleaseView(
        latest={
            "tag": newest.tag,
            "published_at": newest.published_at.isoformat(),
            "eligible_at": (newest.ready_at + wait).isoformat(),
        },
        eligible_key=max(eligible) if eligible else None,
        known=True,
    )
