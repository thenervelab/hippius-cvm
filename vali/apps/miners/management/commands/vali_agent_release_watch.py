"""`vali_agent_release_watch` — store the complete miner-agent releases.

One run: GET the last releases of `VALI_AGENT_RELEASE_REPO`, keep the
complete ones (the miners' updater rule, `apps.miners.agent_release`) and
replace `AgentRelease` with them. Run by the `agent-release-watch` CronJob.

Off (`VALI_AGENT_RELEASE_WATCH` false): exits 0 without a request. A
GitHub failure exits 1 and leaves the table as it was (the rows keep
showing the last release read).
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.miners import agent_release
from apps.orchestration.effects import EffectError, EffectUnavailable


class Command(BaseCommand):
    help = "Store the complete miner-agent releases (VALI_AGENT_RELEASE_WATCH)."

    def handle(self, *args: Any, **opts: Any) -> None:
        if not settings.VALI_AGENT_RELEASE_WATCH:
            self.stdout.write("agent release watch: off (VALI_AGENT_RELEASE_WATCH)")
            return
        try:
            result = agent_release.watch_once(now=timezone.now())
        except (EffectError, EffectUnavailable) as exc:
            raise CommandError(f"agent release watch: {exc}; releases unchanged") from exc
        self.stdout.write(
            "agent release watch: stored="
            + (",".join(result.stored) or "-")
            + " removed="
            + (",".join(result.removed) or "-")
        )
