# -*- coding: utf-8 -*-
# Generated by Django 1.11.14 on 2018-07-22 00:06
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='OPSettings',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('opId', models.CharField(db_index=True, max_length=200)),
                ('displayName', models.CharField(db_index=True, max_length=200)),
                ('issuer', models.CharField(db_index=True, max_length=200)),
                ('clientId', models.CharField(blank=True, max_length=200)),
                ('clientSecret', models.CharField(blank=True, max_length=200)),
                ('redirect_url', models.CharField(blank=True, max_length=200)),
                ('authorizationEndpoint', models.CharField(blank=True, max_length=200)),
                ('tokenizationEndpoint', models.CharField(blank=True, max_length=200)),
                ('userinfoEndpoint', models.CharField(blank=True, max_length=200)),
                ('introspectionEndpoint', models.CharField(blank=True, max_length=200)),
                ('scope', models.TextField(blank=True)),
                ('options', models.CharField(blank=True, max_length=200)),
                ('configrations', models.TextField(blank=True)),
                ('createDate', models.DateTimeField(auto_now_add=True)),
                ('updateDate', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'opsettings',
            },
        ),
        migrations.CreateModel(
            name='OPTokens',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('opId', models.CharField(db_index=True, max_length=200)),
                ('subject', models.CharField(db_index=True, max_length=200)),
                ('accessToken', models.TextField(blank=True)),
                ('refreshToken', models.TextField(blank=True)),
                ('expireDate', models.DateTimeField(blank=True)),
                ('idToken', models.TextField(blank=True)),
                ('createDate', models.DateTimeField(auto_now_add=True)),
                ('updateDate', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'optokens',
            },
        ),
    ]
