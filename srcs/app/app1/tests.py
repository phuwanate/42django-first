from django.test import TestCase
import json
from .models import Users
from .views import UserProfile
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout

#Test view
from django.test import Client

# Create your tests here.
import datetime

def create_user():
    return Users.objects.create(
        username="pream",
        avatar="/usr/pream.jpg",
        rank=1,
        win=3,
        lose=2,
        status="online",
        user_auth_id= None
    )

class UserProfileTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.profile_url ='/api/users/' 

    def test_exist_user_profile(self):
        """
        If user does exist json should be return.
        """
        #Prepare
        profile_stub = create_user()
        payload = {
	        "id": 1,
	        "username": "pream",
	        "avatar": "/usr/pream.jpg",
	        "rank": 1,
	        "win": 3,
	        "lose": 2,
	        "status": "online",
            "user_auth_id": None
        }
        # true_stub = json.dumps(true_stub, indent=4)
        #Action
        response = self.client.get(f'{self.profile_url}{profile_stub.id}/profile/')
        # print(response.context)
        #Assert
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), payload)
        # print(response.json())
    
    def test_not_exist_user_profile(self):
        """
        If user does not exist should be return 404 staus and User not found JSON.
        """
        #Prepare
        profile_stub = create_user()
        payload = {
	        'error': 'User not found'
        }
        # true_stub = json.dumps(true_stub, indent=4)
        #Action
        response = self.client.get(f'{self.profile_url}{profile_stub.id + 1}/profile/')
        # print(response.context)
        #Assert
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), payload)

class RegisterTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url ='/api/auth/register'

    def test_register_success(self):
        """
            If user registered success should return status 201
        """
        #Prepare
        payload = {
	        "username" : "user1234",
	        "password" : "password1234"
        }
        #Action
        response = self.client.post(
            self.register_url, 
            json.dumps(payload, indent=4),
            content_type='application/json')
        #Assert
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()['message'], 'User created successfully')
    
    def test_register_duplicated_user(self):
        """
            If user already exist should return status 400
            {'error': 'Username already exists'}
        """

        User.objects.create_user(username="user1234", password="password1234")
        payload = {
	        "username" : "user1234",
	        "password" : "password1234"
        }

        response = self.client.post(
            self.register_url, 
            json.dumps(payload),
            content_type='application/json')

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Username already exists')
    
    def test_register_missing_field(self):
        """
            If JSON is missing field  should return status 400
            {'error': 'Username already exists'}
        """
        payload = {"password" : "password1234"}

        response = self.client.post(
            self.register_url, 
            json.dumps(payload, indent=4),
            content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Both username and password are required')

    def test_register_invalid_json(self):
        """
            If JSON is invalid format should return status 400
        """
        invalid_payload = '{ "username" : "user1234", "password" : "password1234"'

        response = self.client.post(
            self.register_url, 
            invalid_payload,
            content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Invalid JSON format')

class LoginTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.login_url ='/api/auth/login'

    def test_login_success(self):
        """
            If login success should return 200
        """
        User.objects.create_user(username="user1234", password="password1234")
        payload = {
            "username": "user1234",
            "password": "password1234"
        }
        response = self.client.post(
            self.login_url, 
            json.dumps(payload),
            content_type='application/json')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['message'], 'Login success')
    
    def test_login_fail(self):
        """
            If login failed should return 401
        """
        User.objects.create_user(username="user1234", password="password1234")
        invalid_payload = {
            "username": "user1234",
            "password": "password12345"
        }
        response = self.client.post(
            self.login_url, 
            json.dumps(invalid_payload),
            content_type='application/json')

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['error'], 'Invalid username or password')

class LogoutTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.logout_url ='/api/auth/logout'
        self.login_url = '/api/auth/login'

        # Create a user
        self.user = User.objects.create_user(username="user1234", password="password1234")
        
        # Login the user to create a session
        self.payload = {
            "username": "user1234",
            "password": "password1234"
        }
        response = self.client.post(
            self.login_url, 
            json.dumps(self.payload),
            content_type='application/json')

    
    def test_logout_success(self):
        """
            If logout success should return 200
        """
        response = self.client.post(self.logout_url, content_type='application/json')
    
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['message'], 'Logout success')