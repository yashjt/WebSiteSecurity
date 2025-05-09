# Generated by Django 4.2.5 on 2023-09-11 14:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitorWeb', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScannedWebsite',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField(unique=True)),
                ('scan_result', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='ShortenedURL',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('long_url', models.URLField(unique=True)),
                ('short_code', models.CharField(max_length=10, unique=True)),
            ],
        ),
    ]
