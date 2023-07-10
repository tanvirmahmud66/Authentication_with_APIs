from django.urls import path
from . import views


urlpatterns = [
    path('user/registration/', views.UserRegistrationView.as_view(), name='user-registration'), #user Registration
    path('user/login/', views.UserLoginView.as_view(), name='user-login'), #user login
    path('user/profile/', views.UserProfileView.as_view(), name='user-profile'), #user profile
    path('user/change-password/', views.ChangePassword.as_view(), name='change-pass'), #change password
    path('user/send-reset-password-email/', views.SendPasswordResetEmail.as_view(), name='reset-pass-email'), #reset-pass-email
    path('user/reset-password/<uid>/<token>/', views.UserResetPassword.as_view(), name='user-reset-pass'),
]