from unittest.mock import patch

import jwt
from django.test import TestCase
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.http.request import HttpRequest

from user.models import User
from garpix_keycloak.rest import (
    get_user_by_kk_token,
    get_token_from_request,
    KeycloakAuthentication,
)


class GetUserByKkTokenTest(TestCase):
    def setUp(self):
        self._delete_all_users()
        settings.GARPIX_ACCESS_TOKEN_TTL_SECONDS = 3

    def test_get_user_by_kk_token_expired(self) -> None:
        token = jwt.encode({"expires_in": 2}, "")
        self.assertIsInstance(get_user_by_kk_token(token), AnonymousUser)

    def test_get_user_by_kk_token(self) -> None:
        payload = {
            "sub": 1,
            "given_name": "test_first_name",
            "family_name": "test_last_name",
            "preferred_username": "test_username",
            "email": "test_email",
            "realm_access": {
                "roles": ["test_role1", "test_role2"],
            },
            "expires_in": 3
        }
        token = jwt.encode(payload, "")
        with patch("django.contrib.auth.get_user_model") as get_user_model:
            get_user_model.return_value = User
            user = get_user_by_kk_token(token)
            self.assertEqual(user.first_name, "test_first_name")
            self.assertEqual(user.last_name, "test_last_name")
            self.assertEqual(user.username, "test_username")
            self.assertEqual(user.email, "test_email")

    def _delete_all_users(self) -> None:
            User.objects.all().delete()


class GetTokenFromRequestTest(TestCase):
    def test_get_token_from_request(self) -> None:
        request = HttpRequest()
        request.META["HTTP_X_AUTHORIZATION"] = "Bearer test_token"
        self.assertEqual(get_token_from_request(request), "test_token")

    def test_get_token_from_request_none(self) -> None:
        self.assertIsNone(get_token_from_request(HttpRequest()))


class KeycloakAuthenticatonTest(TestCase):
    def setUp(self):
        self._delete_all_users()
        self.auth = KeycloakAuthentication()

    def test_authenticate_token_not_exists(self) -> None:
        self.assertIsNone(self.auth.authenticate(HttpRequest()))
    
    def test_authenticate(self) -> None:
        request = HttpRequest()
        keycloak_data = {
            "sub": 1,
            "given_name": "test_first_name",
            "family_name": "test_last_name",
            "preferred_username": "test_username",
            "email": "test_email",
            "realm_access": {
                "roles": ["test_role1", "test_role2"],
            },
            "expires_in": 3,
        }
        token = jwt.encode(keycloak_data, "")
        request.META["HTTP_X_AUTHORIZATION"] = "Bearer " + token
        user = self.auth.authenticate(request)[0]
        self.assertEqual(user.keycloak_id, 1)
        self.assertEqual(user.username, "test_username")
        self.assertEqual(
            list(user.keycloak_groups.values_list("name")),
            [("test_role1",), ("test_role2",)],
        )
    
    def _delete_all_users(self) -> None:
        User.objects.all().delete()
