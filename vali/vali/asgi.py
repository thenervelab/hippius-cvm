"""ASGI entrypoint for the vali service.

Production runs under an ASGI server (uvicorn / hypercorn). The
intake view itself is synchronous because it shell-outs to a Rust
binary, but other surfaces (telemetry pull in PR-G6, etc.) will be
async.
"""

from __future__ import annotations

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vali.settings")

application = get_asgi_application()
