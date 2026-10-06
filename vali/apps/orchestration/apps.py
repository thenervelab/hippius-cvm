from __future__ import annotations

from django.apps import AppConfig


class OrchestrationConfig(AppConfig):
    name = "apps.orchestration"
    label = "orchestration"
    verbose_name = "vali §24/§25 migration + decommission orchestrators"

    def ready(self) -> None:
        # Validate the sales cap at START: a typo in
        # `VALI_SCHEDULER_MAX_FLAVOR` must crash-loop the pod, not surface
        # later as a 500 on every launch and feasibility call.
        from .services.flavors import max_offered_flavor

        max_offered_flavor()
