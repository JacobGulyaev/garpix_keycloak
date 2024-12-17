import requests
from unittest.mock import MagicMock, patch

import jwt
from django.conf import settings
from django.test.testcases import TestCase
from django.http.request import HttpRequest
from django.contrib.auth.models import Group
from django.utils.http import urlencode

from user.models import User
from garpix_keycloak.models.group import KeycloakGroup
from garpix_keycloak.services import KeycloakService


ORIGINAL_KEYCLOAK_SETTINGS = settings.KEYCLOAK


class KeycloakServiceTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls._update_settings()

        cls.keycloak_service = KeycloakService()
        cls.full_url = "test_server/auth/realms/test_realm/protocol/openid-connect/token"

    @classmethod
    def tearDownClass(cls):
        settings.KEYCLOAK = ORIGINAL_KEYCLOAK_SETTINGS

    def test_get_token(self) -> None:
        response = requests.Response()
        response.status_code = 400
        requests.post = MagicMock(return_value=response)
        data = {"username": "test_user", "password": "test_password"}
        self.assertIsNone(self.keycloak_service.get_token(data))
        requests.post.assert_called_once_with(
            self.full_url,
            data={
                "username": "test_user",
                "password": "test_password",
                "grant_type": "password",
                "client_id": "test_client_id",
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

        response = type(
            "Response",
            (requests.Response,),
            {"json": lambda: {"access_token": "test_token"}},
        )
        response.status_code = 200
        requests.post = MagicMock(return_value=response)
        self.assertEqual(self.keycloak_service.get_token(data), "test_token")
        requests.post.assert_called_once_with(
            self.full_url,
            data={
                "username": "test_user",
                "password": "test_password",
                "grant_type": "password",
                "client_id": "test_client_id",
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    def test_get_token_by_code(self) -> None:
        response = requests.Response()
        response.status_code = 400
        HttpRequest.build_absolute_uri = MagicMock(return_value="test_uri")
        requests.post = MagicMock(return_value=response)
        self.assertIsNone(
            self.keycloak_service.get_token_by_code("test_code", HttpRequest(), "test_uri")
        )
        HttpRequest.build_absolute_uri.assert_called_once_with("test_uri")
        requests.post.assert_called_once_with(
            self.full_url,
            data={
                "code": "test_code",
                "grant_type": "authorization_code",
                "client_id": "test_client_id",
                "client_secret": "test_secret_key",
                "redirect_uri": "test_uri",
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

        response = type(
            "Response",
            (requests.Request,),
            {"json": lambda: {"access_token": "test_token"}},
        )
        response.status_code = 200
        requests.post = MagicMock(return_value=response)
        HttpRequest.build_absolute_uri.reset_mock()
        self.assertEqual(
            self.keycloak_service.get_token_by_code("test_code", HttpRequest(), "test_uri"),
            {"access_token": "test_token"},
        )
        HttpRequest.build_absolute_uri.assert_called_once_with("test_uri")
        requests.post.assert_called_once_with(
            self.full_url,
            data={
                "code": "test_code",
                "grant_type": "authorization_code",
                "client_id": "test_client_id",
                "client_secret": "test_secret_key",
                "redirect_uri": "test_uri",
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    def test_get_user(self) -> None:
        self._delete_all_users()
        keycloak_data = {
            "sub": 1,
            "given_name": "test_first_name",
            "family_name": "test_last_name",
            "preferred_username": "test_username",
            "email": "test_email",
            "realm_access": {
                "roles": ["test_role1", "test_role2"],
            },
        }
        request = HttpRequest()
        group = Group.objects.create(name="test_group1")
        KeycloakGroup.objects.create(name="test_role1", group=group)
        with patch("django.contrib.auth.get_user_model") as get_user_model:
            get_user_model.return_value = User
            user = self.keycloak_service.get_user(keycloak_data, request)
            self._user_check(user)
    
    def test_get_user_from_request(self) -> None:
        token = jwt.encode(
            {
                "sub": 1,
                "given_name": "test_first_name",
                "family_name": "test_last_name",
                "preferred_username": "test_username",
                "email": "test_email",
                "realm_access": {
                    "roles": ["test_role1", "test_role2"],
                },
            },
            "",
        )
        response = type(
            "Response",
            (requests.Response,),
            {"json": lambda: {"access_token": token}},
        )
        response.status_code = 200
        requests.post = MagicMock(return_value=response)
        group = Group.objects.create(name="test_group1")
        KeycloakGroup.objects.create(name="test_role1", group=group)
        with patch("django.contrib.auth.get_user_model") as get_user_model:
            get_user_model.return_value = User
            user = self.keycloak_service.get_user_from_request(HttpRequest(), "code", "url")
            self._user_check(user)

    def test_user_data_by_token(self) -> None:
        token = jwt.encode({"username": "test_user"}, "")
        self.assertEqual(
            self.keycloak_service.get_user_data_by_token(token),
            {"username": "test_user"},
        )

    def test_get_keycloak_url(self) -> None:
        class Request(HttpRequest):
            session = {}

        HttpRequest.build_absolute_uri = MagicMock(return_value="test_uri")
        request = Request()
        with patch("garpix_keycloak.services.get_random_string") as get_random_string:
            get_random_string.return_value = "test"
            query_params = {
                'client_id': "test_client_id",
                'redirect_uri': "test_uri",
                'state': "test",
                'response_type': 'code',
                'scope': 'openid profile',
                'nonce': "test",
            }
            self.assertEqual(
                self.keycloak_service.get_keycloak_url(request, "test_uri"),
                f"test_server/auth/realms/test_realm/protocol/openid-connect/auth?{urlencode(query_params)}",
            )
            self.assertEqual(request.session["keycloak_state"], "test")
            self.assertEqual(request.session["keycloak_nonce"], "test")

    def test_get_user_info_by_token(self) -> None:
        response = type(
            "Response",
            (requests.Response,),
            {"json": lambda: {"test": "test"}},
        )
        requests.get = MagicMock(return_value=response)
        self.assertEqual(
            self.keycloak_service.get_user_info_by_token("test_token"),
            {"test": "test"},
        )
        requests.get.assert_called_once_with(
            "test_server/auth/realms/test_realm/protocol/openid-connect/userinfo",
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "authorization": "Bearer " + "test_token",
            }
        )
    
    def _user_check(self, user: User) -> None:
        self.assertEqual(user.first_name, "test_first_name")
        self.assertEqual(user.last_name, "test_last_name")
        self.assertEqual(user.username, "test_username")
        self.assertEqual(user.email, "test_email")
        self.assertEqual(list(user.groups.values_list("name"))[0], ("test_group1",))
        self.assertEqual(
            list(user.keycloak_groups.values_list("name")),
            [("test_role1",), ("test_role2",)],
        )

    @staticmethod
    def _update_settings() -> None:
        settings.KEYCLOAK["SERVER_URL"] = "test_server"
        settings.KEYCLOAK["REALM"] = "test_realm"
        settings.KEYCLOAK["CLIENT_ID"] = "test_client_id"
        settings.KEYCLOAK["CLIENT_SECRET_KEY"] = "test_secret_key"

        KeycloakService.server_url = "test_server"
        KeycloakService.realm = "test_realm"
        KeycloakService.client_id = "test_client_id"
        KeycloakService.client_secret_key = "test_secret_key"
    
    def _delete_all_users(self) -> None:
        User.objects.all().delete()
