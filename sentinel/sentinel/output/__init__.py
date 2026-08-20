"""Output channels for sentinel findings (PR-S5).

PR-S4 patrols the control plane and emits `Finding` records into an
in-memory ring. PR-S5 is where those findings *leave* the process:

  * `GitHubIssueChannel`  — structured incident issues, ALERT+.
  * `SlackWebhookChannel` — acute pages, CRITICAL only.
  * `DailySummaryChannel` — a daily Markdown report committed to a
    dedicated `sentinel-reports/main` git branch.

`FindingRouter` is the single fan-out point: it applies the severity
routing policy and a rate limiter. `build_router_from_env` wires
whichever channels the environment configures.

Public surface kept deliberately small so the §S security review can
audit every write path the sentinel has — see issue #57's strict
write-allowlist (GitHub Issues, Slack, S3 anchors; nothing else).
"""

from sentinel.output.channels import (
    ChannelResult,
    DispatchStatus,
    OutputChannel,
    iso_utc,
    severity_at_least,
    signature,
    utc_day,
)
from sentinel.output.daily_summary import (
    DailySummaryChannel,
    DailySummaryConfig,
    render_daily_summary,
)
from sentinel.output.github_issue import GitHubIssueChannel, GitHubIssueConfig
from sentinel.output.redact import redact_finding, redact_mapping, redact_text
from sentinel.output.router import (
    FindingRouter,
    RoutingResult,
    TokenBucket,
    build_rate_limiter_from_env,
    build_router_from_env,
)
from sentinel.output.slack_webhook import SlackWebhookChannel, SlackWebhookConfig

__all__ = [
    "ChannelResult",
    "DailySummaryChannel",
    "DailySummaryConfig",
    "DispatchStatus",
    "FindingRouter",
    "GitHubIssueChannel",
    "GitHubIssueConfig",
    "OutputChannel",
    "RoutingResult",
    "SlackWebhookChannel",
    "SlackWebhookConfig",
    "TokenBucket",
    "build_rate_limiter_from_env",
    "build_router_from_env",
    "iso_utc",
    "redact_finding",
    "redact_mapping",
    "redact_text",
    "render_daily_summary",
    "severity_at_least",
    "signature",
    "utc_day",
]
