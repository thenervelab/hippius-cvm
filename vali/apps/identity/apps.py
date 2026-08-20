from __future__ import annotations

from django.apps import AppConfig


class IdentityConfig(AppConfig):
    name = "apps.identity"
    label = "identity"
    verbose_name = "vali identity (mTLS + service tokens)"

    def ready(self) -> None:
        # Registers `identity.E001` — every /v1/ view must declare its
        # `object_scope`. Import for the side effect only (P2).
        from . import checks  # noqa: F401
