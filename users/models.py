from django.db import models
from django.contrib.auth.models import User
from datetime import datetime, timedelta
import secrets
from django.utils import timezone
from django.core.exceptions import ValidationError


class VerifyEmail(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        if self.pk:
            return timezone.now() > self.created_at + timedelta(minutes=5)

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.code = secrets.randbelow(900000) + 100000

        super().save(*args, **kwargs)


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    twofa_enabled = models.BooleanField(default=False)
    profile_pic_id = models.CharField(max_length=255, null=True, blank=True)


class PermissionVerify(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        if self.pk:
            return timezone.now() > self.created_at + timedelta(minutes=5)

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.code = secrets.randbelow(900000) + 100000

        super().save(*args, **kwargs)
