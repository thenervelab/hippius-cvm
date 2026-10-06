"""Rewrite the legacy shared auto-provision placeholder to the per-node form.

`MinerIdentity.platform_id` is unique, so the shared literal `"onchain"`
let only ONE unregistered permissionless miner exist at a time. The
placeholder is now `onchain:<node_id_hex>`
(`apps.miners.models.autoprovision_platform_id`); this rewrites any row
still carrying the bare literal, keyed on its `chain_node_id` (what the
auto-provision path writes) or, failing that, its `pubkey_hex` (the same
node key there). Both are unique, so the rewritten value is too.

The literals are frozen here on purpose — a migration must not follow a
later change of the model constants.
"""

from __future__ import annotations

from typing import Any

from django.db import migrations

_LEGACY_PLACEHOLDER = "onchain"
_PER_NODE_PREFIX = "onchain:"


def _forwards(apps: Any, schema_editor: Any) -> None:
    MinerIdentity = apps.get_model("miners", "MinerIdentity")
    for miner in MinerIdentity.objects.filter(platform_id=_LEGACY_PLACEHOLDER):
        node = (miner.chain_node_id or miner.pubkey_hex).lower()
        miner.platform_id = f"{_PER_NODE_PREFIX}{node}"
        miner.save(update_fields=["platform_id"])


class Migration(migrations.Migration):

    dependencies = [
        ("miners", "0005_mineridentity_snp_generation"),
    ]

    operations = [
        # Reverse is a no-op: collapsing several per-node placeholders back
        # onto one shared literal would violate the unique index.
        migrations.RunPython(_forwards, migrations.RunPython.noop),
    ]
