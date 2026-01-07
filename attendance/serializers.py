from .models import Attendance, AttendanceSession
from rest_framework import serializers
from users.serializers import UserSerializer


class AttendanceSessionSerializer(serializers.ModelSerializer):

    class Meta:
        model = AttendanceSession
        fields = "__all__"
        read_only_fields = ["created_at"]


class AttendanceSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    session = AttendanceSessionSerializer(read_only=True)

    class Meta:
        model = Attendance
        fields = [
            "id",
            "attended_at",
            "status",
            "reason",
            "session",
            "user",
        ]
