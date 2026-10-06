from __future__ import annotations

from django.apps import AppConfig


class NetworkConfig(AppConfig):
    """Public IPv4 addresses for tenant VMs, served from ingress edges:
    the edges, their address pool, which VM holds which address, and the
    NetBird exit routing that carries the VM's traffic to its edge. The
    edge's firewall rules are NOT here — they belong to the layer above.
    See `docs/design/public-ip.md`."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.network"
    label = "network"
    verbose_name = "vali public IPs and ingress edges"
