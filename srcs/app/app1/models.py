from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Users(models.Model):
    user_auth_id = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    username = models.CharField(max_length=200)
    avatar = models.CharField(max_length=200, default='/jpg/default.jpg')
    rank = models.IntegerField(default=0)
    win = models.IntegerField(default=0)
    lose = models.IntegerField(default=0)
    status = models.CharField(max_length=200, default="offline")
    def __str__(self):
        return self.user.username
