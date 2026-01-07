from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth.models import User
from rest_framework_simplejwt.authentication import JWTAuthentication
from users.serializers import UserSerializer
from .serializers import AttendanceSessionSerializer, AttendanceSerializer
from .models import Attendance, AttendanceSession


class AttendanceSessionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sessions = AttendanceSession.objects.all()
        serialized_sessions = AttendanceSessionSerializer(sessions, many=True)

        return Response(
            {"sessions": serialized_sessions.data}, status=status.HTTP_200_OK
        )


class AttendanceDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        user = request.user
        try:
            session = AttendanceSession.objects.get(id=session_id)
            attendance = Attendance.objects.get(user=user, session=session)

        except AttendanceSession.DoesNotExist:
            return Response(
                {"error": f"Session with '{session_id}' doesn't exist."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Attendance.DoesNotExist:
            return Response(
                {"error": "There is no recored yet."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = AttendanceSerializer(attendance)
        return Response({"attendance": serializer.data}, status=status.HTTP_200_OK)


class SessionDetailView(APIView):
    def get(self, request, session_id):
        try:
            session = AttendanceSession.objects.get(id=session_id)
            serializer = AttendanceSessionSerializer(session)
            return Response({"session": serializer.data}, status=status.HTTP_200_OK)
        except AttendanceSession.DoesNotExist:
            return Response(
                {"errors": [{"session": "Session doesn't exist."}]},
                status=status.HTTP_404_NOT_FOUND,
            )


class AttendanceStatsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        data = {
            "total_sessions": AttendanceSession.objects.all().count(),
            "total_closed_sessions": AttendanceSession.objects.filter(
                is_closed=True
            ).count(),
            "total_open_sessions": AttendanceSession.objects.filter(
                is_closed=False
            ).count(),
            "total_present": Attendance.objects.filter(
                session__is_closed=True, status="present"
            ).count(),
            "total_late": Attendance.objects.filter(
                session__is_closed=True, status="late"
            ).count(),
            "total_absent": Attendance.objects.filter(
                session__is_closed=True, status="absent"
            ).count(),
            "total_special_case": Attendance.objects.filter(
                session__is_closed=True, status="special_case"
            ).count(),
        }
        return Response({"data": data}, status=status.HTTP_200_OK)
