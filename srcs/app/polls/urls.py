from django.urls import path

from . import views

app_name = "polls"

urlpatterns = [
    path("", views.home_view, name="index"),
]