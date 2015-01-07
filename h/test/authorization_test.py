# -*- coding: utf-8 -*-
from collections import namedtuple
import unittest

from mock import patch
from jwt import DecodeError
from pyramid.testing import DummyRequest

from h.authorization import RequestValidator, now, posix_seconds
from h.security import WEB_SCOPES

FakeClient = namedtuple('FakeClient', ['client_id', 'client_secret'])


class TestRequestValidator(unittest.TestCase):

    def setUp(self):
        self.client = FakeClient('someclient', 'somesecret')
        self.request = DummyRequest(
            access_token=None,
            client=None,
            client_id=None,
            client_secret=None,
            state=None,
            extra_credentials=None,
            user=None,
            scopes=['world'],
            get_client=lambda _cid: self.client,
        )
        self.request.registry.web_client = self.client
        self.validator = RequestValidator()

        self.decode_patcher = patch('jwt.decode')
        self.decode = self.decode_patcher.start()

    def test_authenticate_client_ok(self):
        self.request.client_id = 'someclient'
        self.request.client_secret = 'somesecret'
        res = self.validator.authenticate_client(self.request)
        assert res is True

    def test_authenticate_client_not_ok(self):
        res = self.validator.authenticate_client(self.request)
        assert res is False

        self.request.client_id = 'someclient'
        self.request.client_secret = 'sauce'
        res = self.validator.authenticate_client(self.request)
        assert res is False

    def test_authenticate_client_web_ok(self):
        with patch('h.authorization.check_csrf_token') as csrf:
            csrf.return_value = True
            res = self.validator.authenticate_client(self.request)
            assert res is True

    def test_authenticate_client_web_not_ok(self):
        res = self.validator.authenticate_client(self.request)
        assert res is False

    def test_validate_bearer_token_expired(self):
        self.decode.return_value = {
            'aud': self.request.host_url,
            'sub': 'citizen',
            'exp': posix_seconds(now()) - 300,
            'iss': self.client.client_id,
        }
        res = self.validator.validate_bearer_token('', [], self.request)
        assert res is False

    def test_validate_bearer_token_future(self):
        self.decode.return_value = {
            'aud': self.request.host_url,
            'sub': 'citizen',
            'exp': posix_seconds(now()) + 3600,
            'nbf': posix_seconds(now()) + 1800,
            'iss': self.client.client_id,
        }
        res = self.validator.validate_bearer_token('', [], self.request)
        assert res is False

    def test_validate_bearer_token_no_subject(self):
        self.decode.return_value = {
            'aud': self.request.host_url,
            'exp': posix_seconds(now()) + 3600,
            'iss': self.client.client_id,
        }
        res = self.validator.validate_bearer_token('', [], self.request)
        assert res is False

    def test_validate_bearer_token_bad_issuer(self):
        self.decode.return_value = {
            'aud': self.request.host_url,
            'sub': 'citizen',
            'exp': posix_seconds(now()) + 3600,
            'iss': 'bogus',
        }
        res = self.validator.validate_bearer_token('', [], self.request)
        assert res is False

    def test_validate_bearer_token_invalid(self):
        self.decode.side_effect = DecodeError
        res = self.validator.validate_bearer_token('', [], self.request)
        assert res is False

    def test_validate_bearer_token_valid(self):
        self.decode.return_value = {
            'aud': self.request.host_url,
            'sub': 'citizen',
            'exp': posix_seconds(now()) + 30,
            'iss': self.client.client_id,
        }
        res = self.validator.validate_bearer_token('', [], self.request)
        assert res is True
        assert self.request.client is self.client
        assert self.request.scopes == WEB_SCOPES
        assert self.request.user == 'citizen'

    def test_validate_annotator_token_valid(self):
        self.decode.return_value = {
            'consumerKey': self.client.client_id,
            'userId': 'citizen',
            'ttl': 30,
            'issuedAt': now().isoformat(),
        }
        res = self.validator.validate_bearer_token('', [], self.request)
        assert res is True
        assert self.request.client is self.client
        assert self.request.scopes == WEB_SCOPES
        assert self.request.user == 'citizen'

    def test_validate_scopes_ok(self):
        client = FakeClient('other', 'secret')
        res = self.validator.validate_scopes(
            client.client_id,
            [],
            client,
            self.request
        )
        assert res is True

    def test_validate_scopes_not_ok(self):
        client = FakeClient('other', 'secret')
        res = self.validator.validate_scopes(
            client.client_id,
            ['bogus'],
            client,
            self.request
        )
        assert res is False

    def test_validate_scopes_web_ok(self):
        res = self.validator.validate_scopes(
            self.client.client_id,
            WEB_SCOPES,
            self.client,
            self.request
        )
        assert res is True

    def test_validate_scopes_web_not_ok(self):
        res = self.validator.validate_scopes(
            self.client.client_id,
            WEB_SCOPES + ['bogus'],
            self.client,
            self.request
        )
        assert res is False
