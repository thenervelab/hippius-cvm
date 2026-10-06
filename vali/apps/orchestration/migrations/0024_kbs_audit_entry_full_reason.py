from django.db import migrations, models


class Migration(migrations.Migration):
    """`KbsAuditEntry.reason`: the FULL reason (was cut to 128 chars, which
    dropped a rollback row's `timeline_to=…` / ticket detail).

    NOT safely reversible once rows with a reason longer than 128 chars
    exist: reversing alters the column back to varchar(128), which fails
    on PostgreSQL (value too long) for any such row. Truncate or delete
    those rows by hand first if this must ever be rolled back."""

    dependencies = [
        ("orchestration", "0023_kbs_audit_entry"),
    ]

    operations = [
        migrations.AlterField(
            model_name="kbsauditentry",
            name="reason",
            field=models.TextField(blank=True, default=""),
        ),
    ]
