from django.contrib import admin
from .models import Attendance, AttendanceSession

admin.site.register([Attendance, AttendanceSession])
