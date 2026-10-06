import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("miners", "0003_mineridentity_chain_node_id"),
    ]

    operations = [
        migrations.CreateModel(
            name="MinerLocation",
            fields=[
                (
                    "miner",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="location",
                        serialize=False,
                        to="miners.mineridentity",
                    ),
                ),
                ("connection_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("country_code", models.CharField(blank=True, db_index=True, default="", max_length=2)),
                ("city", models.CharField(blank=True, default="", max_length=64)),
                ("latitude", models.FloatField(blank=True, null=True)),
                ("longitude", models.FloatField(blank=True, null=True)),
                ("asn", models.PositiveBigIntegerField(blank=True, null=True)),
                ("as_prefix", models.CharField(blank=True, default="", max_length=64)),
                ("as_holder", models.CharField(blank=True, default="", max_length=128)),
                ("rtt_ms", models.FloatField(blank=True, null=True)),
                ("rtt_vantage", models.CharField(blank=True, default="", max_length=64)),
                ("guest_egress_ips", models.JSONField(blank=True, default=list)),
                (
                    "verdict",
                    models.CharField(
                        choices=[
                            ("verified", "Verified"),
                            ("unverified", "Unverified"),
                            ("mismatch", "Mismatch"),
                            ("unknown", "Unknown"),
                        ],
                        db_index=True,
                        default="unknown",
                        max_length=16,
                    ),
                ),
                ("verdict_reasons", models.JSONField(blank=True, default=list)),
                ("netbird_last_seen_at", models.DateTimeField(blank=True, null=True)),
                ("geo_refreshed_at", models.DateTimeField(blank=True, null=True)),
                ("observed_at", models.DateTimeField()),
                ("evidence_json", models.JSONField(blank=True, default=dict)),
            ],
            options={"ordering": ["miner_id"]},
        ),
    ]
