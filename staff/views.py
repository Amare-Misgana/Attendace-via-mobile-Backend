from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth.models import User
from rest_framework_simplejwt.authentication import JWTAuthentication
from attendance.models import Attendance, AttendanceSession
from attendance.serializers import AttendanceSerializer, AttendanceSessionSerializer
from django.core import signing
from django.db import transaction
from users.models import PermissionVerify
from django.core.mail import send_mail
from django.conf import settings

EMAIL = settings.EMAIL


class AttendanceSessionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        serializer = AttendanceSessionSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"attendance_session": serializer.data}, status=status.HTTP_200_OK
            )

        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    def patch(self, request, session_id):
        try:
            session = AttendanceSession.objects.get(id=session_id)
        except AttendanceSession.DoesNotExist:
            return Response(
                {"error": "Session id is required."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = AttendanceSessionSerializer(
            session, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response({"session": serializer.data}, status=status.HTTP_200_OK)
        return Response(
            {"errors", serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )


class DeleteSessionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def delete(self, request, session_id):
        password = request.data.get("password") or None
        if not password:
            return Response(
                {"error": "To delete a session, password is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        allowed_to_delete = request.user.check_password(password)

        if not allowed_to_delete:
            return Response(
                {"error": "Invalid password."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            session = AttendanceSession.objects.get(id=session_id)
            session.delete()
            return Response(
                {"message": "Session deleted successfully."}, status=status.HTTP_200_OK
            )
        except AttendanceSession.DoesNotExist:
            return Response(
                {"errors": [{"session": "Session doesn't exist."}]},
                status=status.HTTP_404_NOT_FOUND,
            )


class DeleteSessionViaCodeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        user = request.user
        if not user.email:
            return Response(
                {"error": "User doesn't have email."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        old_permission_verify = PermissionVerify.objects.filter(user=user).first()
        if old_permission_verify:
            old_permission_verify.delete()

        try:
            permission_verify = PermissionVerify.objects.create(user=user)
            send_mail(
                subject="Verify your email",
                message=f"Your permission code is {permission_verify.code}, not that after performing the action, it can't be undone!",
                from_email=EMAIL,
                recipient_list=[user.email],
            )
        except Exception as e:

            return Response(
                {"message": f"Unable to send the code{str(e)}."},
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )

        return Response(
            {"message": "verification code sent successfully."},
            status=status.HTTP_200_OK,
        )

    def delete(self, request, session_id):
        code = (request.data.get("code") or "").strip()
        user = request.user

        if not AttendanceSession.objects.filter(id=session_id).exists():
            return Response(
                {"error": "Session doesn't exist."}, status=status.HTTP_404_NOT_FOUND
            )

        permission_verify = PermissionVerify.objects.filter(user=user).first()
        if not permission_verify:
            return Response(
                {"error": "Permission code not sent yet."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if permission_verify.is_expired():
            return Response(
                {"error": "Permission code is expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not permission_verify.code == code:
            return Response(
                {"error": "Invalid permission code."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        with transaction.atomic():

            try:
                permission_verify.delete()
                session = AttendanceSession.objects.get(id=session_id)
                session.delete()
                return Response(
                    {"message": "Session deleted successfully."},
                    status=status.HTTP_200_OK,
                )
            except AttendanceSession.DoesNotExist:
                return Response(
                    {"error": {"session": "Session doesn't exist."}},
                    status=status.HTTP_404_NOT_FOUND,
                )


class AttendanceView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        attendance_status = (request.data.get("status") or "").strip()
        user_id = request.data.get("user_id") or None
        session_id = request.data.get("session_id") or None

        errors = {}
        if attendance_status.lower() not in [
            "present",
            "late",
            "absent",
            "special_case",
        ]:
            errors["status"] = "Invalid status"
        if not user_id:
            errors["user_id"] = "User id is required"
        if not session_id:
            errors["session_id"] = "Session id is required"

        reason = (request.data.get("reason") or "").strip()
        if attendance_status == "special_case":
            if not reason:
                errors["reason"] = (
                    "If it is set to 'speical case' reason is required.  "
                )

        if errors:
            return Response({"errors": errors}, status=status.HTTP_404_NOT_FOUND)

        try:
            user = User.objects.get(id=user_id)
            session = AttendanceSession.objects.get(id=session_id)
            if session.is_closed:
                return Response(
                    {"error": "Session ended."}, status=status.HTTP_406_NOT_ACCEPTABLE
                )
            attendance_exists = Attendance.objects.filter(
                user=user, session=session
            ).exists()

            if attendance_exists:
                return Response(
                    {"error": "Attendance record already set for this user."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            attendance = Attendance.objects.create(
                user=user, session=session, status=attendance_status
            )
            if reason:
                attendance.reason = reason
                attendance.save()

            return Response(
                {"message": "Attendance set successfully."}, status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            return Response(
                {"error": f"User with '{user_id}' doesn't exists."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except AttendanceSession.DoesNotExist:
            return Response(
                {"error": f"Session with '{session_id}' doesn't exists."},
                status=status.HTTP_404_NOT_FOUND,
            )

    def patch(self, request):
        attendance_status = (request.data.get("status") or "").strip()
        user_id = (request.data.get("user_id") or "").strip()
        session_id = (request.data.get("session_id") or "").strip()

        errors = {}
        if attendance_status.lower() not in [
            "present",
            "late",
            "absent",
            "special_case",
        ]:
            errors["status"] = "Invalid status"
        if not user_id:
            errors["user_id"] = "User id is required"
        if not session_id:
            errors["session_id"] = "Session id is required"

        if attendance_status == "special_case":
            reason = (request.data.get("reason") or "").strip()
            if not reason:
                errors["special_case"] = "Special Case is required"

        if errors:
            return Response({"errors": errors}, status=status.HTTP_404_NOT_FOUND)

        try:
            user = User.objects.get(id=user_id)
            session = AttendanceSession.objects.get(id=session_id)
            attendance_exists = Attendance.objects.filter(
                user=user, session=session
            ).exists()

            if not attendance_exists:
                return Response(
                    {"error": "Attendance record doesn't exist for this user."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            attendance = Attendance.objects.get(user=user, session=session)
            attendance.status = attendance_status
            if reason:
                attendance.reason = reason
            attendance.save()

            return Response(
                {"message": "Attendance updated successfully."},
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response(
                {"error": f"User with '{user_id}' doesn't exists."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except AttendanceSession.DoesNotExist:
            return Response(
                {"error": f"Session with '{session_id}' doesn't exists."},
                status=status.HTTP_404_NOT_FOUND,
            )

    def delete(self, request):
        user_id = (request.data.get("user_id") or "").strip()
        session_id = (request.data.get("session_id") or "").strip()

        errors = {}

        if not user_id:
            errors["user_id"] = "User id is required"
        if not session_id:
            errors["session_id"] = "Session id is required"

        if errors:
            return Response({"errors": errors}, status=status.HTTP_404_NOT_FOUND)

        try:
            user = User.objects.get(id=user_id)
            session = AttendanceSession.objects.get(id=session_id)
            attendance_exists = Attendance.objects.filter(
                user=user, session=session
            ).exists()

            if not attendance_exists:
                return Response(
                    {"error": "Attendance record doesn't exist for this user."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            attendance = Attendance.objects.get(user=user, session=session)

            attendance.delete()

            return Response(
                {"message": "Attendance deleted successfully."},
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response(
                {"error": f"User with '{user_id}' doesn't exists."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except AttendanceSession.DoesNotExist:
            return Response(
                {"error": f"Session with '{session_id}' doesn't exists."},
                status=status.HTTP_404_NOT_FOUND,
            )


class AttendanceViaCodeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        code = (request.data.get("code") or "").strip()
        attendance_status = (request.data.get("status") or "").strip()
        session_id = request.data.get("session_id") or None

        errors = {}
        if attendance_status.lower() not in [
            "present",
            "late",
            "absent",
        ]:
            errors["status"] = "Invalid status"

        if not code:
            errors["code"] = "Code is required"

        if not session_id:
            errors["session_id"] = "Session id is required"

        if code:
            try:
                user_data = signing.loads(code)
                user = User.objects.get(id=user_data["id"])
            except signing.BadSignature:
                errors["code"] = "Invalid code"
            except User.DoesNotExist:
                errors["code"] = "User doesn't exist"

        if errors:
            return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

        session = AttendanceSession.objects.get(id=session_id)
        if session.is_closed:
            return Response(
                {"error": "Session ended."}, status=status.HTTP_406_NOT_ACCEPTABLE
            )
        attendance_exists = Attendance.objects.filter(
            user=user, session=session
        ).exists()

        if attendance_exists:
            return Response(
                {"error": "Attendance record already set for this user."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        Attendance.objects.create(user=user, session=session, status=attendance_status)
        return Response(
            {"message": "Attendance set successfully."}, status=status.HTTP_200_OK
        )


class EndAttendanceSession(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request, session_id):
        attendance_status = (request.data.get("status") or "").strip()

        if not session_id:
            return Response(
                {"error": "Session id is mandatory."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        session_id = int(session_id)

        try:
            session = AttendanceSession.objects.get(id=session_id)
        except AttendanceSession.DoesNotExist:
            return Response(
                {"error": f"Session with '{session_id}' doesn't exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

        bulk_status = attendance_status or "absent"

        try:
            with transaction.atomic():
                session.is_closed = True
                session.save()
                users = User.objects.filter(is_staff=False)
                attendance_data = []
                errors = {}

                errors = {
                    "message": "These users already have attendance recorded.",
                    "users": [],
                }
                for user in users:
                    if not Attendance.objects.filter(
                        user=user, session=session
                    ).exists():
                        attendance_data.append(
                            Attendance(user=user, status=bulk_status, session=session)
                        )
                    else:
                        errors["users"].append(user.username)

                Attendance.objects.bulk_create(attendance_data)
                response = {
                    "message": "Attendance ended successfully.",
                }
                if errors["users"]:
                    response["error"] = errors
                return Response(
                    response,
                    status=status.HTTP_200_OK,
                )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class DeleteUsersView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def delete(self, request, user_id):
        code = (request.data.get("code") or "").strip()
        user = request.user

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": f"User with '{user_id}' doesn't exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        permission_verify = PermissionVerify.objects.filter(user=user).first()
        if not permission_verify:
            return Response(
                {"error": "Permission code not sent yet."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if permission_verify.is_expired():
            return Response(
                {"error": "Permission code is expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not permission_verify.code == code:
            return Response(
                {"error": "Invalid permission code."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        with transaction.atomic():

            try:
                permission_verify.delete()
                username = user.username
                user.delete()
                return Response(
                    {"message": f"'{username}' deleted successfully."},
                    status=status.HTTP_200_OK,
                )
            except Exception as e:
                return Response(
                    {"error": str(e)},
                    status=status.HTTP_404_NOT_FOUND,
                )


class ClosedSessionAttendanceView(APIView):
    def get(self, request):
        attendances = Attendance.objects.filter(session__is_closed=True).select_related(
            "user", "session"
        )

        serializer = AttendanceSerializer(attendances, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class EditAttendanceRecordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def patch(self, request, attendance_id):
        user_id = request.data.get("user_id") or None
        attendance_status = (request.data.get("status") or "").strip()
        reason = (request.data.get("reason") or "").strip()

        if not attendance_status:
            return Response(
                {"error": "Status is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        if attendance_status not in ["present", "absent", "late", "special_case"]:
            return Response(
                {"error": "Inavlid status."}, status=status.HTTP_400_BAD_REQUEST
            )

        if attendance_status == "special_case":
            if not reason:
                return Response(
                    {"error": "Reason is required."}, status=status.HTTP_400_BAD_REQUEST
                )

        try:
            user = User.objects.get(id=user_id)
            attendance = Attendance.objects.get(id=attendance_id, user=user)
        except User.DoesNotExist:
            return Response(
                {"error": "User doesn't exist."}, status=status.HTTP_404_NOT_FOUND
            )
        except Attendance.DoesNotExist:
            return Response(
                {"error": "Attendance record doesn't exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        attendance.status = attendance_status
        attendance.reason = reason
        attendance.save()
        return Response(
            {"message": "Attendace updated successfully."}, status=status.HTTP_200_OK
        )


class GetUserAttendanceHistory(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User doesn't exist."}, status=status.HTTP_404_NOT_FOUND
            )

        records = Attendance.objects.filter(user=user)
        serializer = AttendanceSerializer(records, many=True)
        return Response({"records": serializer.data}, status=status.HTTP_200_OK)
