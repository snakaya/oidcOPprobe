# -*- coding: utf-8 -*-
# Generated by Django 1.11.14 on 2018-08-30 07:34
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rp', '0008_auto_20180815_2041'),
    ]

    operations = [
        migrations.AddField(
            model_name='opsettings',
            name='supportPkce',
            field=models.BooleanField(default=False),
        ),
    ]
