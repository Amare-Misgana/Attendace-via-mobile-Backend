from django.db import models
from django.contrib.auth.models import User


class AttendanceSession(models.Model):
    title = models.CharField(max_length=50)
    description = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    is_closed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.title} - {self.is_closed}"


class Attendance(models.Model):
    STATUS_CHOICE = (
        ("absent", "Absent"),
        ("present", "Present"),
        ("late", "Late"),
        ("secial_case", "Special Case"),
    )
    session = models.ForeignKey(AttendanceSession, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    attended_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICE)
    reason = models.CharField(max_length=200, blank=True, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "session"],
                name="unique_user_per_session",
            )
        ]

    def __str__(self):
        return f"{self.user.username} - {self.status}"
