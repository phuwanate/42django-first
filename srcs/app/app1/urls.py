from django.urls import path

from . import views

urlpatterns = [
    path("users/<int:user_id>/profile/", views.UserProfile, name="userProfile"),
    path("users/<int:user_id>/delete/", views.delete_user, name="deleteProfile"),
    path("auth/register", views.Register, name="register"),
    path("auth/login", views.UserLogin, name="userLogin"),
    path("auth/logout", views.UserLogout, name="userLogout"),
    path("get_csrf_token_and_session_id/", views.get_csrf_token_and_session_id, name="csrft_session")
]