from __future__ import annotations

from django.apps import AppConfig


class LifecycleConfig(AppConfig):
    name = "apps.lifecycle"
    label = "lifecycle"
    verbose_name = "vali VM lifecycle state machine"
