# -*- coding: utf-8 -*-
# Generated by Django 1.11.14 on 2018-07-25 16:28
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rp', '0002_opsettings_responsetype'),
    ]

    operations = [
        migrations.CreateModel(
            name='OPConfigratuins',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('opId', models.CharField(db_index=True, max_length=200)),
                ('configrations', models.TextField(blank=True)),
                ('createDate', models.DateTimeField(auto_now_add=True)),
                ('updateDate', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'opconfigrations',
            },
        ),
        migrations.RemoveField(
            model_name='opsettings',
            name='configrations',
        ),
    ]
