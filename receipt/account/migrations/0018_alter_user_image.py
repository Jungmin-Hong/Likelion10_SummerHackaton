# Generated by Django 4.0.6 on 2022-08-17 17:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0017_alter_user_image'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='image',
            field=models.ImageField(blank=True, default='static/img/blank.jpg', null=True, upload_to=''),
        ),
    ]
