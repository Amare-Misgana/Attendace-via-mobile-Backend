from rest_framework import serializers
from django.contrib.auth.models import User
from django.core import signing
from .models import Profile
from rest_framework.validators import UniqueValidator
import time
import environ
import cloudinary
import cloudinary.uploader
import cloudinary.utils
from pathlib import Path
from django.conf import settings

env = environ.Env()

IS_TWOFA_MANDATORY = settings.IS_TWOFA_MANDATORY

BASE_DIR = Path(__file__).resolve().parent
environ.Env.read_env(str(BASE_DIR / ".env"))

cloudinary.config(
    cloud_name=env("CLOUD_NAME"),
    api_key=env("API_KEY"),
    api_secret=env("API_SECRET"),
    secure=True,
)


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    code = serializers.SerializerMethodField()
    profile = serializers.SerializerMethodField()
    username = serializers.CharField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(), message="This username is already taken."
            )
        ],
    )
    email = serializers.EmailField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(), message="This email is already taken."
            )
        ],
    )
    is_active = serializers.BooleanField(required=False)

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "username",
            "email",
            "password",
            "last_login",
            "is_active",
            "date_joined",
            "code",
            "profile",
        ]
        read_only_fields = ["date_joined", "code", "last_login"]

    def get_profile(self, obj):
        from .serializers import ProfileSerializer

        try:
            profile = obj.profile
            return ProfileSerializer(profile, context=self.context).data
        except Profile.DoesNotExist:
            user = obj
            profile = Profile.objects.create(user=user)
            return ProfileSerializer(profile, context=self.context).data

    def get_code(self, obj):
        user_data = {
            "id": obj.id,
            "username": obj.username,
        }
        if obj.id and obj.username:

            return signing.dumps(user_data)
        return None

    def create(self, validated_data):
        password = validated_data.pop("password")

        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)

        if not self.context["request"].user.is_staff:
            validated_data.pop("is_active", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class ProfileSerializer(serializers.ModelSerializer):
    profile_pic_url = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = [
            "id",
            "twofa_enabled",
            "profile_pic_id",
            "profile_pic_url",
        ]

    def create(self, validated_data):
        profile_pic_file = self.context["request"].FILES.get("profile_pic")
        if profile_pic_file:
            validated_data["profile_pic_id"] = self.upload_private_file(
                profile_pic_file
            )
        profile = Profile(**validated_data)
        profile.save()
        return profile

    def update(self, instance, validated_data):
        profile_pic_file = self.context["request"].FILES.get("profile_pic")
        if profile_pic_file:
            validated_data["profile_pic_id"] = self.upload_private_file(
                profile_pic_file
            )

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

    def validate_twofa_enabled(self, value):
        request = self.context.get("request")

        if not request or not request.user.is_authenticated:
            return value

        if IS_TWOFA_MANDATORY and value is False:
            raise serializers.ValidationError(
                "You can't disable two-factor authentication."
            )
        print(IS_TWOFA_MANDATORY)

        return value

    def get_profile_pic_url(self, obj):
        if obj.profile_pic_id:
            try:
                return self.get_signed_url(obj.profile_pic_id)
            except Exception as e:
                print(f"Cloudinary error: {e}")
                return None
        return None

    # --- helper methods ---
    def upload_private_file(self, file):
        result = cloudinary.uploader.upload(
            file, folder="users/profiles", resource_type="image", type="authenticated"
        )
        return result["public_id"]

    def get_signed_url(self, public_id, expires_in=30):
        url, _ = cloudinary.utils.cloudinary_url(
            public_id,
            resource_type="image",
            type="authenticated",
            sign_url=True,
            secure=True,
            expires_at=int(time.time()) + expires_in,
        )
        return url
