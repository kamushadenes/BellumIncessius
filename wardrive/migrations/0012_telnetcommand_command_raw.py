# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-06-30 20:45
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wardrive', '0011_telnetcommand'),
    ]

    operations = [
        migrations.AddField(
            model_name='telnetcommand',
            name='command_raw',
            field=models.TextField(default=''),
            preserve_default=False,
        ),
    ]
