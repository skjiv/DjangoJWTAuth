from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from rest_framework.views import status
from .models import Songs
from .serializers import SongsSerializer
import json

class BaseViewTest(APITestCase):
    client = APIClient()

    @staticmethod
    def create_song(title="", artist=""):
        if title != "" and artist !="":
            Songs.objects.create(title=title, artist=artist)

    def login_client(self, username="", password=""):
        # Get a token from drf
        response = self.client.post(
            reverse('create-token'),
            data = json.dumps({
                'username': username,
                'password': password
            }),
            content_type = 'application/json'
        )
        self.token = response.data['token']
        self.client.credentials(
            HTTP_AUTHORIZATION = 'Bearer ' + self.token
        )
        self.client.login(username=username, password=password)
        return self.token

    def login_a_user(self, username="", password=""):
        url = reverse(
            "auth-login",
            kwargs={
                "version": "v1"
            }
        )
        return self.client.post(
            url,
            data = json.dumps({
                "username": username,
                "password": password
            }),
            content_type="application/json"
        )

    def setUp(self):
        # Create an admin user
        self.user = User.objects.create_superuser(
            username="test_user",
            email="test@mail.com",
            password="testing",
            first_name="test",
            last_name="user",
        )
        # add test data
        self.create_song("like glue", "sean paul")
        self.create_song("simle song", "knoshen")
        self.create_song("love is wicked", "brick and lace")
        self.create_song("jam rock", "damien marley")

class GetAllSongsTest(BaseViewTest):

    def test_get_all_songs(self):
        """
        This test ensures that all songs added in the setUp method
        are returned when a GET request is made to the songs/ endpoint
        """

        # first login and obtain a valid token
        self.login_client('test_user', 'testing')
        # hit the API endpoint
        response = self.client.get(
                reverse("songs-all", kwargs={"version": "v1"})
        )

        expected = Songs.objects.all()
        serialized = SongsSerializer(expected, many=True)
        self.assertEqual(response.data, serialized.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

class AuthLoginUserTest(BaseViewTest):
    """
    Tests for auth/login/ endpoint
    """

    def test_login_user_with_valid_credentials(self):
        # test login with valid credentials
        response = self.login_a_user("test_user", "testing")
        # assert token key exists
        self.assertIn("token", response.data)
        # status code should be 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # test login with invalid credentials
        response = self.login_a_user("anonymous", "pass")
        # status code should be 401 UNAUTHORIZED
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

