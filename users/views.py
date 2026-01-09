from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth.models import User
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserSerializer, ProfileSerializer
from django.core import signing
from .models import VerifyEmail, Profile, PermissionVerify
from django.contrib.auth import authenticate
from django.db import transaction
from django.conf import settings
from utils.mail import send_email
from datetime import datetime

IS_TWOFA_MANDATORY = settings.IS_TWOFA_MANDATORY


EMAIL = settings.EMAIL


class GetUserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.filter(is_staff=False)
        return Response(
            {"users": UserSerializer(users, many=True).data}, status=status.HTTP_200_OK
        )


class UserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        serializer = UserSerializer(user)
        return Response({"user": serializer.data}, status=status.HTTP_200_OK)

    def patch(self, request):
        user = request.user
        serializer = UserSerializer(user, request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"user": serializer.data}, status=status.HTTP_200_OK)

        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    def delete(self, request):
        code = (request.data.get("code") or "").strip()
        user = request.user

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
                user = request.user
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


class UserDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": f"User with '{user_id}' id doesn't exist."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = UserSerializer(user)
        return Response({"user": serializer.data}, status=status.HTTP_200_OK)


class UserCodeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        code = (request.data.get("code") or "").strip()
        try:
            user_data = signing.loads(code)
        except signing.BadSignature:
            return Response(
                {"message": "Bad signing."}, status=status.HTTP_400_BAD_REQUEST
            )
        return Response(user_data)


class LoginView(APIView):
    def post(self, request):
        username = (request.data.get("username") or "").strip()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid username or password"},
                status=status.HTTP_404_NOT_FOUND,
            )

        profile, created = Profile.objects.get_or_create(user=user)

        if IS_TWOFA_MANDATORY or profile.twofa_enabled:

            return Response(
                {
                    "error": "Two step verification is mandatory.",
                    "verify": True,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        password = (request.data.get("password") or "").strip()

        user = authenticate(username=username, password=password)

        if user:
            refresh = RefreshToken.for_user(user)
            return Response(
                {"access": str(refresh.access_token), "refresh": str(refresh)},
                status=status.HTTP_200_OK,
            )

        return Response(
            {"error": "Invalid username or password"}, status=status.HTTP_404_NOT_FOUND
        )


class SendVerificationCodeView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        print("send verification has been touched!!")

        if request.user.is_authenticated:
            return Response(
                {"message": "Already authenticated."},
                status=status.HTTP_200_OK,
            )

        username = (request.data.get("username") or "").strip()
        if not username:
            return Response(
                {"error": "Username is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.filter(username=username).first()

        if not user:
            return Response(
                {"error": "Invalid Username."}, status=status.HTTP_400_BAD_REQUEST
            )

        if not user.email:
            return Response(
                {"error": "User doesn't have email."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            old_email_verify = VerifyEmail.objects.filter(user=user).first()
            if old_email_verify:
                old_email_verify.delete()
        except Exception as e:
            return Response(
                {"error": "Unable to delete old verification code."},
                status=status.HTTP_510_NOT_EXTENDED,
            )

        try:
            email_verif = VerifyEmail.objects.create(user=user)
            current_year = datetime.now().year
            html_content = f"""<!doctype html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="margin:0; padding:0; background-color:#f5f6f8;">
<div style="font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;padding:20px;min-height:100vh;display:flex;align-items:center;justify-content:center;box-sizing:border-box;">
    <div style="max-width:100%;width:100%;padding:0 15px;box-sizing:border-box;">
        <div style="max-width:660px;margin:0 auto;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.1);">
            
            <div style="background:linear-gradient(135deg,#FD8A6B 0%,#FA5C5C 100%);padding:32px;position:relative;">
                <div style="display:flex;align-items:center;">
                    <div style="width:56px;height:56px;border-radius:14px;background:rgba(255,255,255,0.2);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:24px;border:1px solid rgba(255,255,255,0.3);">M</div>
                    <div style="margin-left:16px;">
                        <div style="font-size:26px;font-weight:800;color:#fff;letter-spacing:-0.5px;">MeetMark</div>
                        <div style="font-size:14px;color:rgba(255,255,255,0.9);margin-top:2px;font-weight:500;">Secure Verification</div>
                    </div>
                </div>
            </div>

            <div style="padding:40px 32px;background:#ffffff;">
                <div style="text-align:center;margin-bottom:32px;">
<h1 style="font-size:24px;color:#111;margin:0 0 12px;font-weight:700;line-height:1.3;">Hi {username}</h1>
                    <h2 style="font-size:24px;color:#111;margin:0 0 12px;font-weight:500;line-height:1.3;">Confirm Your Email</h2>
                    <p style="font-size:15px;color:#555;margin:0;line-height:1.6;">Use the code below to verify your email address and finish setting up your account.</p>
                </div>

                <div style="text-align:center;margin:32px 0;">
                    <div style="display:inline-block;background:#f8f9fa;border-radius:16px;padding:24px 40px;border:1px dashed #FD8A6B;box-shadow:0 4px 12px rgba(253, 138, 107, 0.1);">
                        <div style="font-family:'Courier New', Courier, monospace;font-size:32px;font-weight:600;letter-spacing:0.2em;color:#FA5C5C;user-select:all;">
                            {email_verif.code}
                        </div>
                    </div>
                    <div style="margin-top:12px;font-size:12px;color:#999;font-weight:500;">Tip: Long-press or double-tap to copy</div>
                </div>

                <div style="background:#f0f4ff;border-radius:12px;padding:16px;margin-bottom:16px;border-left:4px solid #667eea;display:flex;align-items:center;">
                    <div style="margin-right:12px;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#667eea" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                    </div>
                    <div>
                        <div style="font-size:14px;color:#111;font-weight:600;">Expires in 5 minutes</div>
                    </div>
                </div>

                <div style="background:#fff5f5;border-radius:12px;padding:16px;border:1px solid rgba(250, 92, 92, 0.2);display:flex;align-items:flex-start;">
                    <div style="margin-right:12px;margin-top:2px;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FA5C5C" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                    </div>
                    <div>
                        <div style="font-size:14px;color:#c53030;font-weight:700;margin-bottom:4px;">Security Notice</div>
                        <div style="font-size:13px;color:#666;line-height:1.5;">Never share this code. MeetMark employees will never ask for your verification code.</div>
                    </div>
                </div>
            </div>

            <div style="background:#f8f9fa;padding:24px;border-top:1px solid #eee;text-align:center;">
                <div style="font-size:12px;color:#999;">© {current_year} MeetMark Inc. All rights reserved.</div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
            """

            send_email(
                to_email=user.email,
                subject="MeetMark — Your verification code",
                html_content=html_content,
                sender_name="MeetMark",
            )

        except Exception as e:

            return Response(
                {"message": f"Unable to send the code. Try later."},
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )

        return Response(
            {"message": "verification code sent successfully."},
            status=status.HTTP_200_OK,
        )


class VerifyCodeView(APIView):
    def post(self, request):
        username = (request.data.get("username") or "").strip()
        code = (request.data.get("code") or "").strip()

        if not code or not username:
            return Response(
                {"error": "Code and Username are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.filter(username=username).first()

        if not user:
            return Response(
                {"error": "Invalid username."}, status=status.HTTP_400_BAD_REQUEST
            )

        email_verify = VerifyEmail.objects.filter(user=user).first()

        if not email_verify:
            return Response(
                {"error": "Verificaiton code has not been sent yet."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if str(email_verify.code) != str(code):
            return Response(
                {"error": "Invalid verification code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if email_verify.is_expired():
            email_verify.delete()
            return Response(
                {"error": "Code expired."}, status=status.HTTP_400_BAD_REQUEST
            )

        profile, created = Profile.objects.get_or_create(user=user)

        try:
            with transaction.atomic():
                user.is_active = True
                if IS_TWOFA_MANDATORY:
                    profile.twofa_enabled = True
                email_verify.delete()
                user.save()
            refresh = RefreshToken.for_user(user)

            return Response(
                {"access": str(refresh.access_token), "refresh": str(refresh)},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"error": f"Something went wrong.{str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class EditProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        user = request.user
        profile, created = Profile.objects.get_or_create(user=user)
        serializer = ProfileSerializer(
            instance=profile,
            data=request.data,
            partial=True,
            context={"request": request},
        )

        if serializer.is_valid():
            serializer.save()
            return Response({"profile": serializer.data}, status=status.HTTP_200_OK)

        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )


class SendPermissionCodeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

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
                message=f"Your permission code is {permission_verify.code}, note that after performing the action, it can't be undone!",
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


class RegisterView(APIView):
    def post(self, request):
        user_serializer = UserSerializer(data=request.data)

        user_valid = user_serializer.is_valid()

        if user_valid:

            user_serializer.save()
            return Response({"user": user_serializer.data}, status=status.HTTP_200_OK)

        return Response(
            {
                "errors": user_serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Logout successfully."},
                status=status.HTTP_205_RESET_CONTENT,
            )
        except Exception:
            return Response(
                {"message": "Unable to logout."}, status=status.HTTP_400_BAD_REQUEST
            )
