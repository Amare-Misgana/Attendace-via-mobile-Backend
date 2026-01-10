from django.urls import path
from .views import (
    AttendanceViaCodeView,
    AttendanceSessionView,
    AttendanceView,
    EndAttendanceSession,
    DeleteSessionViaCodeView,
    DeleteSessionView,
    DeleteUsersView,
    ClosedSessionAttendanceView,
    EditAttendanceRecordView,
    GetUserAttendanceHistory,
)

urlpatterns = [
    path("", AttendanceView.as_view()),
    path("test/", ClosedSessionAttendanceView.as_view()),
    path("user/delete/", DeleteUsersView.as_view()),
    path("session/delete/<int:session_id>/", DeleteSessionView.as_view()),
    path("session/", AttendanceSessionView.as_view()),
    path("session/<int:session_id>/", AttendanceSessionView.as_view()),
    path("session/delete/<int:session_id>/", AttendanceSessionView.as_view()),
    path("attendance/recored/code/", AttendanceViaCodeView.as_view()),
    path("attendance/recored/", AttendanceView.as_view()),
    path("attendance/recored/stats/", GetUserAttendanceHistory.as_view()),
    path(
        "attendance/recored/edit/<int:attendance_id>/",
        EditAttendanceRecordView.as_view(),
    ),
    path("session/end/<int:session_id>/", EndAttendanceSession.as_view()),
    path("session/delete/code/<int:session_id>/", DeleteSessionViaCodeView.as_view()),
]
