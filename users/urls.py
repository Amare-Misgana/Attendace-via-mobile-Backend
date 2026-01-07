from django.urls import path
from .views import (
    UserView,
    UserDetailView,
    LoginView,
    SendVerificationCodeView,
    VerifyCodeView,
    EditProfileView,
    GetUserView,
    SendPermissionCodeView,
    RegisterView,
    LogoutView,
)

urlpatterns = [
    path("", UserView.as_view()),
    path("get/", GetUserView.as_view()),
    path("profile/edit/", EditProfileView.as_view()),
    path("get/<int:user_id>/", UserDetailView.as_view()),
    path("login/", LoginView.as_view()),
    path("register/", RegisterView.as_view()),
    path("logout/", LogoutView.as_view()),
    path("verify/", VerifyCodeView.as_view()),
    path("send-code/", SendVerificationCodeView.as_view()),
    path("permission/", SendPermissionCodeView.as_view()),
]
