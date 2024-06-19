import json
from .models import Users
from django.http import HttpResponse, JsonResponse
from django.core import serializers
from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.shortcuts import redirect
from django.middleware.csrf import get_token
from django.contrib.auth.decorators import login_required

def delete_user(request, user_id):
    try:
        user = Users.objects.get(pk=user_id)
        user.delete()
        return JsonResponse({'message': 'User deleted successfully'})
    except Users.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

def UserProfile(request, user_id):
    try:
        if request.user.is_authenticated:
            user_obj = Users.objects.get(pk=user_id)
            user_json = serializers.serialize('json', [user_obj])
            user_data = json.loads(user_json)[0] #From json to dictionary
            user_data['fields']['id'] = user_data['pk'] #Add pk to dictionary

            return JsonResponse(user_data['fields'], safe=False) #select only fields key from meta-data
        else:
            return JsonResponse({'message': 'User is not logged in'}, status=401)
    except Users.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

def Register(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return JsonResponse({'error': 'Both username and password are required'}, status=400)

            if User.objects.filter(username=username).exists():
                return JsonResponse({'error': 'Username already exists'}, status=400)

            user = User.objects.create_user(username=username, password=password)
            return JsonResponse({'message': 'User created successfully'}, status=201)
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
        
def UserLogin(request):
    if request.method == 'POST':
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return JsonResponse({'message': 'Login success'}, status=200)
            else:
                return JsonResponse({'error': 'Invalid username or password'}, status=401)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def UserLogout(request):
    if request.method == 'POST':
        if request.user.is_authenticated:
            logout(request)
            return JsonResponse({'message': 'Logout success'}, status=200)
        else:
            return JsonResponse({'message': 'User is not logged in'}, status=401)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def get_csrf_token_and_session_id(request):
    csrf_token = get_token(request)
    session_id = request.session.session_key
    return JsonResponse({'csrf_token': csrf_token, 'sessionid': session_id})