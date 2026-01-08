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
from django.core.mail import send_mail


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
            send_mail(
                subject="Verify your email",
                message=f"Your verification code is {email_verif.code}",
                from_email=EMAIL,
                recipient_list=[user.email],
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
        profile = request.user.profile
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
