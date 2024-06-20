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
        username="user1234",
        avatar="/usr/default.jpg",
        rank=0,
        win=0,
        lose=0,
        status="offline",
        user_auth_id= None
    )

class UserProfileTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.profile_url ='/api/users/'
        self.user = User.objects.create_user(username="user1234", password="password1234")
        payload = {
            "username": "user1234", 
            "password": "password1234"
        }
        response = self.client.post(
            "/api/auth/login", 
            json.dumps(payload),
            content_type='application/json')

    def test_exist_user_profile(self):
        """
        If user does exist json should be return.
        """
        #Prepare
        payload = {
	        "id": 1,
	        "username": "user1234",
	        "avatar": "/jpg/default.jpg",
	        "rank": 0,
	        "win": 0,
	        "lose": 0,
	        "status": "offline",
            "user_auth_id": 1
        }

        # true_stub = json.dumps(true_stub, indent=4)
        #Action
        response = self.client.get(f'{self.profile_url}{self.user.id}/profile/')
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
        payload = {
	        'error': 'User not found'
        }
        # true_stub = json.dumps(true_stub, indent=4)
        #Action
        response = self.client.get(f'{self.profile_url}{self.user.id + 1}/profile/')
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

class getCSRFandSession(TestCase):
    def setUp(self):
        self.client = Client()
        self.token_url ='/api/get_csrf_token_and_session_id/'
        self.login_url = '/api/auth/login'
        self.logout_url ='/api/auth/logout'

        # Create a user
        self.user = User.objects.create_user(username="user1234", password="password1234")
        
        # Login the user to create a session
        self.payload = {
            "username": "user1234",
            "password": "password1234"
        }

    def test_get_csrf_session_before_login(self):
        """
            If has token and session id should return 200
            session id should be none
            crsf token should not be none
        """
        response = self.client.get(self.token_url)
        csrf = response.json()['csrf_token']
        session_id = response.json()['sessionid']
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(session_id, None)
        self.assertNotEqual(csrf, None)

    def test_get_csrf_session_after_login(self):
        """
            If has token and session id should return 200
            session id should not be none
            crsf token should not be none
        """
        self.client.login(username=self.payload['username'], password=self.payload['password'])
        response = self.client.get(self.token_url)
        csrf = response.json()['csrf_token']
        session_id = response.json()['sessionid']
        
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(session_id, None)
        self.assertNotEqual(csrf, None)
    
    def test_get_csrf_session_after_logout(self):
        """
            If has token and session id should return 200
            session id should be none
            crsf token should not be none
        """
        self.client.login(username=self.payload['username'], password=self.payload['password'])
        self.client.post(self.logout_url, content_type='application/json')
        response = self.client.get(self.token_url)
        csrf = response.json()['csrf_token']
        session_id = response.json()['sessionid']
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(session_id, None)
        self.assertNotEqual(csrf, None)