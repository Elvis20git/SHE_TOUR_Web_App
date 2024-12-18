# Generated by Django 5.1.2 on 2024-11-28 08:56

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SHE', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='observationattachment',
            options={},
        ),
        migrations.AlterField(
            model_name='observationattachment',
            name='file',
            field=models.FileField(upload_to='observation_attachments/%Y/%m/'),
        ),
        migrations.AlterField(
            model_name='observationattachment',
            name='observation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attachments', to='SHE.sheobservation'),
        ),
    ]
