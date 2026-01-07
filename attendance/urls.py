from django.urls import path
from .views import (
    AttendanceSessionView,
    AttendanceDetailView,
    SessionDetailView,
    AttendanceStatsView,
)

urlpatterns = [
    path("stats/", AttendanceStatsView.as_view()),
    path("sessions/get/", AttendanceSessionView.as_view()),
    path("session/detail/<int:session_id>/", SessionDetailView.as_view()),
    path("recored/<int:session_id>/", AttendanceDetailView.as_view()),
]
