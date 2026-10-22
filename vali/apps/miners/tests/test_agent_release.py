"""`apps.miners.agent_release` + `vali_agent_release_watch`: the complete
releases, selected by the miners' updater rule, stored, read back."""

from __future__ import annotations

import io
import json
import urllib.error
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from apps.miners import agent_release
from apps.miners.agent_release import complete_releases, release_key
from apps.miners.models import AgentRelease

ASSET = agent_release.ASSET
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def _iso(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def release(
    tag: str,
    *,
    published: str | None = None,
    updated: str | None = None,
    assets: tuple[str, ...] = (ASSET, "SHA256SUMS", f"{ASSET}.sigstore.json", "BUILD-INFO.txt"),
    **extra: Any,
) -> dict[str, Any]:
    published = published or _iso(48)
    return {
        "tag_name": tag,
        "published_at": published,
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": name,
                "updated_at": updated or published,
                "browser_download_url": f"https://github.test/{tag}/{name}",
            }
            for name in assets
        ],
        **extra,
    }


# ─── the selection rule (the updater's) ──────────────────────────────


def test_tags_order_as_the_updater_does() -> None:
    assert release_key("v2026.10.08") < release_key("v2026.10.08.1")  # type: ignore[operator]
    assert release_key("v2026.10.08.2") < release_key("v2026.10.08.10")  # type: ignore[operator]
    assert release_key("v2026.10.08.999") < release_key("v2026.10.09")  # type: ignore[operator]
    for bad in (
        "dev",
        "",
        None,
        "v2026.10.8",
        "v2026.10.08.0",
        "v2026.10.08.01",
        "2026.10.08",
        "v2026.10.08\n",
    ):
        assert release_key(bad) is None, bad


def test_only_complete_published_releases_count() -> None:
    # Every tag is dated before its publication (NOW - 48 h = 2026-10-20),
    # so only the rule under test can pass a release over.
    payload = [
        release("v2026.10.15"),
        release("v2026.10.16", draft=True),
        release("v2026.10.17", prerelease=True),
        release("v2026.10.18", assets=(ASSET, "SHA256SUMS")),  # no attestation
        release("v2026.10.19", assets=("SHA256SUMS", f"{ASSET}.sigstore.json")),  # no binary
        release("v2026.10.19.1", assets=(ASSET, f"{ASSET}.sigstore.json")),  # no SHA256SUMS
        release("dev-build"),
        release("v2026.10.14.0"),
        release("v2026.10.14\n"),  # the updater's fullmatch refuses a trailing newline
        release("v2026.13.01"),  # impossible date: passed over, not fatal
        release("v2026.10.13", published="garbage"),
        "not an object",
        {"tag_name": "v2026.10.12", "assets": "nope", "published_at": _iso(48)},
    ]
    assert [r.tag for r in complete_releases(payload)] == ["v2026.10.15"]
    # The control: the same releases, made complete and published, all count.
    fixed = [release(t) for t in ("v2026.10.16", "v2026.10.17", "v2026.10.18", "v2026.10.19")]
    assert len(complete_releases(fixed)) == 4


def test_a_tag_dated_after_its_publication_day_is_passed_over() -> None:
    # Published 2026-10-20 UTC: one day of slack (2026-10-21) is fine,
    # 2026-10-22 is a mistyped future tag.
    payload = [
        release("v2026.10.21", published="2026-10-20T23:00:00Z"),
        release("v2026.10.22", published="2026-10-20T23:00:00Z"),
    ]
    assert [r.tag for r in complete_releases(payload)] == ["v2026.10.21"]


def test_ready_is_the_last_required_asset_never_before_publication() -> None:
    rel = release("v2026.10.21", published=_iso(30))
    rel["assets"][1]["updated_at"] = _iso(10)  # SHA256SUMS re-uploaded later
    rel["assets"][3]["updated_at"] = _iso(1)  # BUILD-INFO is not required
    (only,) = complete_releases([rel])
    assert only.ready_at == NOW - timedelta(hours=10)
    early = release("v2026.10.20", published=_iso(30), updated=_iso(40))
    (only,) = complete_releases([early])
    assert only.ready_at == only.published_at


def test_releases_come_newest_tag_first() -> None:
    payload = [release("v2026.10.08.1"), release("v2026.10.09"), release("v2026.10.08")]
    assert [r.tag for r in complete_releases(payload)] == [
        "v2026.10.09",
        "v2026.10.08.1",
        "v2026.10.08",
    ]


# ─── storing ─────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_store_replaces_the_table() -> None:
    AgentRelease.objects.create(tag="v2026.10.01", published_at=NOW, ready_at=NOW, seen_at=NOW)
    first = complete_releases([release("v2026.10.20"), release("v2026.10.21")])
    result = agent_release.store(first, now=NOW)
    assert result.stored == ("v2026.10.21", "v2026.10.20")
    assert result.removed == ("v2026.10.01",)
    # v2026.10.21 pulled from GitHub: it drops out.
    later = NOW + timedelta(hours=1)
    result = agent_release.store(complete_releases([release("v2026.10.20")]), now=later)
    assert result.removed == ("v2026.10.21",)
    assert list(AgentRelease.objects.values_list("tag", "seen_at")) == [("v2026.10.20", later)]


# ─── fetching (urlopen mocked; the suite forbids the network) ────────


class _Resp:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.status = status
        self._body = io.BytesIO(body)

    def read(self, n: int = -1) -> bytes:
        return self._body.read(n)

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.fixture
def github(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"body": b"[]", "status": 200, "error": None, "requests": []}

    def urlopen(request: Any, timeout: float) -> _Resp:
        state["requests"].append((request.full_url, dict(request.header_items()), timeout))
        if state["error"] is not None:
            raise state["error"]
        return _Resp(state["body"], state["status"])

    monkeypatch.setattr(agent_release.urllib.request, "urlopen", urlopen)
    return state


@pytest.mark.django_db
@override_settings(VALI_AGENT_RELEASE_WATCH=True)
def test_the_command_stores_what_github_lists(github: dict[str, Any]) -> None:
    github["body"] = json.dumps(
        [release("v2026.10.21"), release("v2026.10.22", draft=True)]
    ).encode()
    out = io.StringIO()
    call_command("vali_agent_release_watch", stdout=out)
    assert "stored=v2026.10.21 removed=-" in out.getvalue()
    assert list(AgentRelease.objects.values_list("tag", flat=True)) == ["v2026.10.21"]
    ((url, headers, _timeout),) = github["requests"]
    assert url == "https://api.github.com/repos/thenervelab/hippius-cvm/releases?per_page=20"
    assert headers["Accept"] == "application/vnd.github+json"


@pytest.mark.django_db
def test_the_command_is_off_by_default(github: dict[str, Any]) -> None:
    out = io.StringIO()
    call_command("vali_agent_release_watch", stdout=out)
    assert "off" in out.getvalue()
    assert github["requests"] == []


@pytest.mark.django_db
@override_settings(VALI_AGENT_RELEASE_WATCH=True)
@pytest.mark.parametrize(
    "setup",
    [
        {"status": 403},
        {"body": b"<html>rate limited</html>"},
        {"body": b'{"message": "Not Found"}'},
        {"error": urllib.error.URLError("dns")},
        {"body": b"[" + b" " * (agent_release.MAX_RESPONSE_BYTES + 1) + b"]"},
    ],
)
def test_a_github_failure_fails_the_run_and_keeps_the_table(
    github: dict[str, Any], setup: dict[str, Any]
) -> None:
    AgentRelease.objects.create(tag="v2026.10.20", published_at=NOW, ready_at=NOW, seen_at=NOW)
    github.update(setup)
    with pytest.raises(CommandError, match="releases unchanged"):
        call_command("vali_agent_release_watch", stdout=io.StringIO())
    assert list(AgentRelease.objects.values_list("tag", flat=True)) == ["v2026.10.20"]


@pytest.mark.django_db
@override_settings(VALI_AGENT_RELEASE_WATCH=True, VALI_AGENT_RELEASE_REPO="evil/../x?y")
def test_a_malformed_repository_is_refused_before_any_request(github: dict[str, Any]) -> None:
    with pytest.raises(CommandError):
        call_command("vali_agent_release_watch", stdout=io.StringIO())
    assert github["requests"] == []


@pytest.mark.django_db
@override_settings(VALI_AGENT_RELEASE_WATCH=True)
def test_a_list_without_any_complete_release_keeps_the_table(github: dict[str, Any]) -> None:
    AgentRelease.objects.create(tag="v2026.10.20", published_at=NOW, ready_at=NOW, seen_at=NOW)
    github["body"] = json.dumps([release("v2026.10.21", draft=True)]).encode()
    out = io.StringIO()
    call_command("vali_agent_release_watch", stdout=out)
    assert "stored=- removed=-" in out.getvalue()
    assert list(AgentRelease.objects.values_list("tag", flat=True)) == ["v2026.10.20"]


# ─── reading ─────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_the_view_without_releases_knows_nothing() -> None:
    view = agent_release.release_view(now=NOW)
    assert view.latest is None
    assert view.update_pending("v2026.10.01") is None
