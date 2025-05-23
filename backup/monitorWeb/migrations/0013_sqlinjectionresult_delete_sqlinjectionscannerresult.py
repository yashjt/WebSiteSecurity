# Generated by Django 4.1 on 2023-10-01 12:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitorWeb', '0012_sqlinjectionscannerresult'),
    ]

    operations = [
        migrations.CreateModel(
            name='SQLInjectionResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField()),
                ('is_vulnerable', models.BooleanField(default=False)),
                ('scan_date', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.DeleteModel(
            name='SQLInjectionScannerResult',
        ),
    ]
