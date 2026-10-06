from __future__ import annotations

from django.apps import AppConfig


class SchedulerConfig(AppConfig):
    name = "apps.scheduler"
    label = "scheduler"
    verbose_name = "vali §23 trustless scheduler"

    def ready(self) -> None:
        # Validate every capacity knob at START. The getters raise
        # `ImproperlyConfigured` on a malformed value, and admission reads
        # them on every placement — a typo must crash-loop the pod here,
        # not fail each launch later.
        from . import capacity_config

        capacity_config.validate_all()
