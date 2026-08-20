import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0003_receiptwatermark_usageaccrual'),
    ]

    operations = [
        migrations.CreateModel(
            name='VmBillingBinding',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('vm_id', models.CharField(max_length=128, unique=True)),
                ('node_id_hex', models.CharField(max_length=64)),
                ('resource_class', models.CharField(max_length=128)),
                ('lease_id', models.CharField(blank=True, default='', max_length=256)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
