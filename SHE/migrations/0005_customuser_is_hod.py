# Generated by Django 5.1.2 on 2024-12-12 08:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SHE', '0004_profile'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='is_HOD',
            field=models.BooleanField(default=False),
        ),
    ]