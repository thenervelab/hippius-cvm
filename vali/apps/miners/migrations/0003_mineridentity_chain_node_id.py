from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("miners", "0002_mineridentity_last_heartbeat_sequence"),
    ]

    operations = [
        migrations.AddField(
            model_name="mineridentity",
            name="chain_node_id",
            field=models.CharField(
                blank=True,
                help_text=(
                    "The miner's on-chain compute node_id — 64 lowercase "
                    "hex (the 32-byte ed25519 key registered in "
                    "pallet-compute-scoring). This is the key the §23 "
                    "scheduler ranks placements by "
                    "(`scheduler.MinerCapacity.miner_node_id`), and the "
                    "bridge the launch pipeline joins on to recover THIS "
                    "identity (miner_id, netbird_ip, platform_id) from a "
                    "scheduler-chosen placement. DISTINCT from `pubkey_hex` "
                    "— that is the off-chain telemetry-signing key; this is "
                    "the on-chain compute-registration key. NULL until the "
                    "operator backfills it at register; unique when set, so "
                    "two miners can never claim the same on-chain node."
                ),
                max_length=64,
                null=True,
                unique=True,
            ),
        ),
    ]
