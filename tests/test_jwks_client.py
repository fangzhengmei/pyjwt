import contextlib
import copy
import http.client
import io
import json
import ssl
import threading
import time
from collections.abc import Iterator
from typing import Any
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from urllib.error import HTTPError, URLError
from email.message import Message

import pytest

import jwt
from jwt import PyJWKClient
from jwt.jwks_client import _NoRedirectHandler
from jwt.api_jwk import PyJWK, PyJWKSet
from jwt.exceptions import (
    DecodeError,
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWKSetError,
)
from jwt.jwk_set_cache import JWKSetCache

from .utils import crypto_required

RESPONSE_DATA_WITH_MATCHING_KID = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "0wtlJRY9-ru61LmOgieeI7_rD1oIna9QpBMAOWw8wTuoIhFQFwcIi7MFB7IEfelCPj08vkfLsuFtR8cG07EE4uvJ78bAqRjMsCvprWp4e2p7hqPnWcpRpDEyHjzirEJle1LPpjLLVaSWgkbrVaOD0lkWkP1T1TkrOset_Obh8BwtO-Ww-UfrEwxTyz1646AGkbT2nL8PX0trXrmira8GnrCkFUgTUS61GoTdb9bCJ19PLX9Gnxw7J0BtR0GubopXq8KlI0ThVql6ZtVGN2dvmrCPAVAZleM5TVB61m0VSXvGWaF6_GeOhbFoyWcyUmFvzWhBm8Q38vWgsSI7oHTkEw",
            "e": "AQAB",
            "kid": "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw",
            "x5t": "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw",
            "x5c": [
                "MIIDBzCCAe+gAwIBAgIJNtD9Ozi6j2jJMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFmRldi04N2V2eDlydS5hdXRoMC5jb20wHhcNMTkwNjIwMTU0NDU4WhcNMzMwMjI2MTU0NDU4WjAhMR8wHQYDVQQDExZkZXYtODdldng5cnUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wtlJRY9+ru61LmOgieeI7/rD1oIna9QpBMAOWw8wTuoIhFQFwcIi7MFB7IEfelCPj08vkfLsuFtR8cG07EE4uvJ78bAqRjMsCvprWp4e2p7hqPnWcpRpDEyHjzirEJle1LPpjLLVaSWgkbrVaOD0lkWkP1T1TkrOset/Obh8BwtO+Ww+UfrEwxTyz1646AGkbT2nL8PX0trXrmira8GnrCkFUgTUS61GoTdb9bCJ19PLX9Gnxw7J0BtR0GubopXq8KlI0ThVql6ZtVGN2dvmrCPAVAZleM5TVB61m0VSXvGWaF6/GeOhbFoyWcyUmFvzWhBm8Q38vWgsSI7oHTkEwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQlGXpmYaXFB7Q3eG69Uhjd4cFp/jAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAIzQOF/h4T5WWAdjhcIwdNS7hS2Deq+UxxkRv+uavj6O9mHLuRG1q5onvSFShjECXaYT6OGibn7Ufw/JSm3+86ZouMYjBEqGh4OvWRkwARy1YTWUVDGpT2HAwtIq3lfYvhe8P4VfZByp1N4lfn6X2NcJflG+Q+mfXNmRFyyft3Oq51PCZyyAkU7bTun9FmMOyBtmJvQjZ8RXgBLvu9nUcZB8yTVoeUEg4cLczQlli/OkiFXhWgrhVr8uF0/9klslMFXtm78iYSgR8/oC+k1pSNd1+ESSt7n6+JiAQ2Co+ZNKta7LTDGAjGjNDymyoCrZpeuYQwwnHYEHu/0khjAxhXo="
            ],
        }
    ]
}

RESPONSE_DATA_NO_MATCHING_KID = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "39SJ39VgrQ0qMNK74CaueUBlyYsUyuA7yWlHYZ-jAj6tlFKugEVUTBUVbhGF44uOr99iL_cwmr-srqQDEi-jFHdkS6WFkYyZ03oyyx5dtBMtzrXPieFipSGfQ5EGUGloaKDjL-Ry9tiLnysH2VVWZ5WDDN-DGHxuCOWWjiBNcTmGfnj5_NvRHNUh2iTLuiJpHbGcPzWc5-lc4r-_ehw9EFfp2XsxE9xvtbMZ4SouJCiv9xnrnhe2bdpWuu34hXZCrQwE8DjRY3UR8LjyMxHHPLzX2LWNMHjfN3nAZMteS-Ok11VYDFI-4qCCVGo_WesBCAeqCjPLRyZoV27x1YGsUQ",
            "e": "AQAB",
            "kid": "MLYHNMMhwCNXw9roHIILFsK4nLs=",
        }
    ]
}


@contextlib.contextmanager
def mocked_success_response(data: object) -> Iterator[mock.Mock]:
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock()
        response.read.side_effect = [json.dumps(data)]
        urlopen_mock.return_value = response
        yield urlopen_mock


@contextlib.contextmanager
def mocked_failed_response() -> Iterator[mock.Mock]:
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        urlopen_mock.side_effect = URLError("Fail to process the request.")
        yield urlopen_mock


@contextlib.contextmanager
def mocked_first_call_wrong_kid_second_call_correct_kid(
    response_data_one: object, response_data_two: object
) -> Iterator[mock.Mock]:
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock()
        response.read.side_effect = [
            json.dumps(response_data_one),
            json.dumps(response_data_two),
        ]
        urlopen_mock.return_value = response
        yield urlopen_mock


@contextlib.contextmanager
def mocked_timeout() -> Iterator[mock.Mock]:
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        urlopen_mock.side_effect = TimeoutError("timed out")
        yield urlopen_mock


@contextlib.contextmanager
def mocked_incomplete_read_response() -> Iterator[mock.Mock]:
    # The connection drops partway through the body, which surfaces as
    # http.client.IncompleteRead when json.load() reads the response.
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        # A truthy __exit__ return value tells the `with` statement to
        # suppress whatever exception was raised in its body, which would
        # hide the IncompleteRead below before fetch_data() ever sees it.
        response.__exit__ = mock.Mock(return_value=False)
        response.read.side_effect = http.client.IncompleteRead(partial=b"", expected=1)
        urlopen_mock.return_value = response
        yield urlopen_mock


@contextlib.contextmanager
def mocked_http_error_response() -> Iterator[tuple[mock.Mock, HTTPError]]:
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        http_error = HTTPError(
            url="https://example.com",
            code=401,
            msg="Unauthorized",
            hdrs=Message(),
            fp=io.BytesIO(b""),
        )
        urlopen_mock.side_effect = http_error
        yield urlopen_mock, http_error


@crypto_required
class TestPyJWKClient:
    def test_fetch_data_rejects_redirect_without_contacting_destination(self) -> None:
        destination_requests = 0

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                nonlocal destination_requests
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", f"{base_url}/destination")
                    self.end_headers()
                else:
                    destination_requests += 1
                    self.send_response(200)
                    self.end_headers()

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        base_url = f"http://127.0.0.1:{server.server_port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = PyJWKClient(
                f"{base_url}/start", headers={"Authorization": "secret"}
            )
            with pytest.raises(PyJWKClientConnectionError):
                client.fetch_data()
            assert destination_requests == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_redirect_handler_does_not_follow_redirects(self) -> None:
        handler = _NoRedirectHandler()

        assert (
            handler.redirect_request(
                mock.Mock(), mock.Mock(), 302, "Found", {}, "https://other.test"
            )
            is None
        )

    def test_fetch_data_forwards_headers_to_correct_url(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as mock_request:
            custom_headers = {"User-agent": "my-custom-agent"}
            jwks_client = PyJWKClient(url, headers=custom_headers)
            jwk_set = jwks_client.get_jwk_set()
            request_params = mock_request.call_args[0][0]
            assert request_params.full_url == url
            assert request_params.headers == custom_headers

        assert len(jwk_set.keys) == 1

    def test_get_jwk_set(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client = PyJWKClient(url)
            jwk_set = jwks_client.get_jwk_set()

        assert len(jwk_set.keys) == 1

    def test_get_signing_keys(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client = PyJWKClient(url)
            signing_keys = jwks_client.get_signing_keys()

        assert len(signing_keys) == 1
        assert isinstance(signing_keys[0], PyJWK)

    def test_get_signing_keys_if_no_use_provided(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        mocked_key = RESPONSE_DATA_WITH_MATCHING_KID["keys"][0].copy()
        del mocked_key["use"]
        response = {"keys": [mocked_key]}

        with mocked_success_response(response):
            jwks_client = PyJWKClient(url)
            signing_keys = jwks_client.get_signing_keys()

        assert len(signing_keys) == 1
        assert isinstance(signing_keys[0], PyJWK)

    def test_get_signing_keys_raises_if_none_found(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        mocked_key = RESPONSE_DATA_WITH_MATCHING_KID["keys"][0].copy()
        mocked_key["use"] = "enc"
        response = {"keys": [mocked_key]}
        with mocked_success_response(response):
            jwks_client = PyJWKClient(url)

            with pytest.raises(PyJWKClientError) as exc:
                jwks_client.get_signing_keys()

        assert "The JWKS endpoint did not contain any signing keys" in str(exc.value)

    def test_get_signing_key(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client = PyJWKClient(url)
            signing_key = jwks_client.get_signing_key(kid)

        assert isinstance(signing_key, PyJWK)
        assert signing_key.key_type == "RSA"
        assert signing_key.key_id == kid
        assert signing_key.public_key_use == "sig"

    def test_get_signing_key_caches_result(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        jwks_client = PyJWKClient(url, cache_keys=True)

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_signing_key(kid)

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_signing_key(kid)

        assert repeated_call.call_count == 0

    def test_get_signing_key_does_not_cache_opt_out(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        jwks_client = PyJWKClient(url, cache_jwk_set=False)

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_signing_key(kid)

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_signing_key(kid)

        assert repeated_call.call_count == 1

    def test_get_signing_key_from_jwt(self) -> None:
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client = PyJWKClient(url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="https://expenses-api",
            options={"verify_exp": False},
        )

        assert data == {
            "iss": "https://dev-87evx9ru.auth0.com/",
            "sub": "aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC@clients",
            "aud": "https://expenses-api",
            "iat": 1572006954,
            "exp": 1572006964,
            "azp": "aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC",
            "gty": "client-credentials",
        }

    def test_get_signing_key_from_jwt_rejects_payload_recursion_error(self) -> None:
        token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.e30."

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as open_mock:
            jwks_client = PyJWKClient("https://example.test/.well-known/jwks.json")
            with mock.patch(
                "jwt.api_jwt.json.loads",
                side_effect=[
                    {"alg": "RS256", "kid": "test-key"},
                    RecursionError(),
                ],
            ):
                with pytest.raises(DecodeError, match="Invalid payload") as exc:
                    jwks_client.get_signing_key_from_jwt(token)

        assert isinstance(exc.value.__cause__, RecursionError)
        assert open_mock.call_count == 0

    def test_get_jwk_set_caches_result(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        assert jwks_client.jwk_set_cache is not None

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_jwk_set()

        assert repeated_call.call_count == 0

    def test_get_jwk_set_returns_pyjwkset_cached_by_the_client(self) -> None:
        # Regression for #914: whatever the client itself stores in the JWK
        # Set cache must be readable back out of it on the next call.
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            first = jwks_client.get_jwk_set()

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            second = jwks_client.get_jwk_set()

        assert repeated_call.call_count == 0
        assert isinstance(second, PyJWKSet)
        assert [key.key_id for key in second.keys] == [key.key_id for key in first.keys]

    def test_get_jwk_set_accepts_externally_cached_pyjwkset(self) -> None:
        # Regression for #914: `JWKSetCache.put()` documents `PyJWKSet` as the
        # cached value, so callers may pre-populate the cache with one to skip
        # the network round-trip. Reading it back used to raise
        # PyJWKClientError("The JWKS endpoint did not return a JSON object").
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        jwks_client = PyJWKClient(url)
        assert jwks_client.jwk_set_cache is not None
        jwks_client.jwk_set_cache.put(
            PyJWKSet.from_dict(RESPONSE_DATA_WITH_MATCHING_KID)
        )

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as call:
            jwk_set = jwks_client.get_jwk_set()

        assert call.call_count == 0
        assert isinstance(jwk_set, PyJWKSet)
        assert jwk_set[kid].key_id == kid

    def test_client_caches_the_parsed_jwk_set(self) -> None:
        # The cache stores the parsed `PyJWKSet`, not the raw payload, so
        # every cache hit is served without re-parsing each key.
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        assert jwks_client.jwk_set_cache is not None
        assert isinstance(jwks_client.jwk_set_cache.get(), PyJWKSet)

    def test_get_jwk_set_reuses_the_cached_instance(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            first = jwks_client.get_jwk_set()

        assert jwks_client.jwk_set_cache is not None
        assert jwks_client.jwk_set_cache.get() is first

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            second = jwks_client.get_jwk_set()

        assert second is first
        assert repeated_call.call_count == 0

    def test_fetch_data_override_result_is_cached(self) -> None:
        # A subclass may filter or transform `fetch_data()`'s result. That
        # final value has to be what later cache hits serve, otherwise a key
        # the subclass removed reappears on the second call.
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        dropped = "SECOND-KEY-KID"

        two_keys = copy.deepcopy(RESPONSE_DATA_WITH_MATCHING_KID)
        second_key = copy.deepcopy(two_keys["keys"][0])
        second_key["kid"] = dropped
        two_keys["keys"].append(second_key)

        class FilteringClient(PyJWKClient):
            def fetch_data(self) -> Any:
                data = super().fetch_data()
                return {"keys": [k for k in data["keys"] if k["kid"] != dropped]}

        jwks_client = FilteringClient(url)
        with mocked_success_response(two_keys):
            first = [key.key_id for key in jwks_client.get_jwk_set().keys]

        # No second mock: a cache hit must not reach the network.
        second = [key.key_id for key in jwks_client.get_jwk_set().keys]

        assert dropped not in first
        assert second == first

    def test_cache_put_rejects_a_value_that_is_not_a_jwk_set(self) -> None:
        cache = JWKSetCache(300)

        with pytest.raises(PyJWKSetError, match="Invalid JWK Set value"):
            cache.put("not a jwk set")  # type: ignore[arg-type]

    def test_cache_put_none_clears_the_cache(self) -> None:
        cache = JWKSetCache(300)
        cache.put(RESPONSE_DATA_WITH_MATCHING_KID)
        assert cache.get() is not None

        cache.put(None)

        assert cache.get() is None

    def test_get_jwk_set_raises_when_endpoint_does_not_return_an_object(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with mocked_success_response([{"kty": "RSA"}]):
            with pytest.raises(PyJWKClientError, match="did not return a JSON object"):
                jwks_client.get_jwk_set()

    def test_get_jwt_set_cache_expired_result(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url, lifespan=1)
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        time.sleep(2)

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_jwk_set()

        assert repeated_call.call_count == 1

    def test_get_jwt_set_cache_disabled(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url, cache_jwk_set=False)
        assert jwks_client.jwk_set_cache is None

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        assert jwks_client.jwk_set_cache is None

        time.sleep(2)

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_jwk_set()

        assert repeated_call.call_count == 1

    def test_get_jwt_set_failed_refresh_preserves_cached_jwks(self) -> None:
        # Regression: a transient fetch failure used to clear the cache via
        # the previous `finally: put(jwk_set=None)` pattern, turning one bad
        # request from the JWKS endpoint into application-wide auth failure.
        # The cache must survive.
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        assert jwks_client.jwk_set_cache is not None
        assert jwks_client.jwk_set_cache.get() is not None

        with pytest.raises(PyJWKClientError):
            with mocked_failed_response():
                jwks_client.get_jwk_set(refresh=True)

        cached = jwks_client.jwk_set_cache.get()
        assert cached is not None
        # Subsequent reads still serve from cache without another fetch.
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as call:
            jwks_client.get_jwk_set()
        assert call.call_count == 0

    @pytest.mark.parametrize("stale_ttl", [float("nan"), float("inf"), -1.0])
    def test_client_rejects_invalid_stale_ttl(self, stale_ttl: float) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with pytest.raises(PyJWKClientError, match="Stale TTL"):
            PyJWKClient(url, stale_ttl=stale_ttl)

    def test_cache_get_stale_none_without_stale_window(self) -> None:
        # With the default stale_ttl of 0, an expired set must not be
        # served as stale, preserving the pre-opt-in behavior.
        cache = JWKSetCache(lifespan=1, stale_ttl=0)
        cache.put(RESPONSE_DATA_WITH_MATCHING_KID)
        assert cache.jwk_set_with_timestamp is not None

        cache.jwk_set_with_timestamp.timestamp = time.monotonic() - 2
        assert cache.get() is None
        assert cache.get_stale() is None

    def test_cache_get_stale_serves_within_window_and_cuts_off_after(self) -> None:
        cache = JWKSetCache(lifespan=10, stale_ttl=20)
        cache.put(RESPONSE_DATA_WITH_MATCHING_KID)
        assert cache.jwk_set_with_timestamp is not None

        # Fresh: both get() and get_stale() serve the set.
        cache.jwk_set_with_timestamp.timestamp = time.monotonic() - 5
        assert cache.get() is not None
        assert cache.get_stale() is not None
        # Stale but inside the hard cutoff (10 + 20 = 30).
        cache.jwk_set_with_timestamp.timestamp = time.monotonic() - 15
        assert cache.get() is None
        assert cache.get_stale() is not None
        # Past the hard cutoff: trust is revoked.
        cache.jwk_set_with_timestamp.timestamp = time.monotonic() - 31
        assert cache.get() is None
        assert cache.get_stale() is None

    def test_cache_rejects_invalid_stale_ttl(self) -> None:
        with pytest.raises(PyJWKClientError, match="Stale TTL"):
            JWKSetCache(lifespan=10, stale_ttl=-1)

    def _client_with_aged_cache(
        self,
        lifespan: float,
        stale_ttl: float,
        age: float,
        cooldown_duration: float = 0,
    ) -> PyJWKClient:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(
            url,
            lifespan=lifespan,
            stale_ttl=stale_ttl,
            cooldown_duration=cooldown_duration,
        )
        assert jwks_client.jwk_set_cache is not None

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        # Age the cached set by moving its stored timestamp back, rather
        # than mocking the clock, so the age is independent of which module
        # reads time.monotonic().
        assert jwks_client.jwk_set_cache.jwk_set_with_timestamp is not None
        jwks_client.jwk_set_cache.jwk_set_with_timestamp.timestamp = (
            time.monotonic() - age
        )
        assert jwks_client.jwk_set_cache.get() is None
        return jwks_client

    def test_failed_refresh_serves_stale_set_within_trust_window(self) -> None:
        # Endpoint down after the cache expired: old keys remain trusted
        # until the hard cutoff, so in-flight tokens keep verifying.
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"
        jwks_client = self._client_with_aged_cache(lifespan=10, stale_ttl=20, age=15)

        with mocked_failed_response() as call:
            jwk_set = jwks_client.get_jwk_set()

        assert call.call_count == 1
        assert jwk_set[kid].key_id == kid

        # The failed fetch must not have replaced the cached set.
        assert jwks_client.jwk_set_cache is not None
        assert jwks_client.jwk_set_cache.get_stale() is not None

    def test_failed_refresh_raises_after_stale_window_cutoff(self) -> None:
        # Past lifespan + stale_ttl the old key set is no longer trusted,
        # even while the endpoint keeps failing: revoked keys have a hard
        # trust boundary.
        jwks_client = self._client_with_aged_cache(lifespan=10, stale_ttl=20, age=31)

        with pytest.raises(PyJWKClientConnectionError):
            with mocked_failed_response() as call:
                jwks_client.get_jwk_set()

        assert call.call_count == 1

    def test_invalid_response_does_not_replace_usable_set(self) -> None:
        # A 200 response whose body is not a JSON object is an invalid
        # response. It must neither overwrite the cache nor reject tokens
        # while the stale set is still inside its trust window.
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"
        jwks_client = self._client_with_aged_cache(lifespan=10, stale_ttl=20, age=15)

        with mocked_success_response(["not", "an", "object"]) as call:
            jwk_set = jwks_client.get_jwk_set()

        assert call.call_count == 1
        assert jwk_set[kid].key_id == kid

    def test_stale_fallback_does_not_serve_when_disabled(self) -> None:
        # Default stale_ttl of 0: once expired, a failed refresh propagates
        # instead of extending trust in the old set.
        jwks_client = self._client_with_aged_cache(lifespan=10, stale_ttl=0, age=11)

        with pytest.raises(PyJWKClientConnectionError):
            with mocked_failed_response() as call:
                jwks_client.get_jwk_set()

        assert call.call_count == 1

    def test_recovered_endpoint_replaces_stale_set(self) -> None:
        # Once the endpoint answers again, the fresh response replaces the
        # stale set and normal fresh-cache behavior resumes.
        new_kid = "ROTATED-KEY"
        rotated = copy.deepcopy(RESPONSE_DATA_WITH_MATCHING_KID)
        rotated["keys"][0]["kid"] = new_kid
        jwks_client = self._client_with_aged_cache(lifespan=10, stale_ttl=20, age=15)

        with mocked_success_response(rotated) as call:
            jwk_set = jwks_client.get_jwk_set()

        assert call.call_count == 1
        assert [key.key_id for key in jwk_set.keys] == [new_kid]
        # The new set is cached and served without another request.
        with mocked_success_response(rotated) as repeated:
            again = jwks_client.get_jwk_set()
        assert repeated.call_count == 0
        assert [key.key_id for key in again.keys] == [new_kid]

    def test_outage_makes_one_request_per_cooldown_then_cuts_off(self) -> None:
        # During an outage, repeated lookups against an expired cache must
        # not hammer the endpoint: while the cooldown is in force the stale
        # set is served with no request at all; once the cooldown elapses a
        # single retry is allowed. After the stale window's hard cutoff the
        # connection error propagates instead.
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"
        jwks_client = self._client_with_aged_cache(
            lifespan=10, stale_ttl=20, age=15, cooldown_duration=30
        )
        # Let the first expired read attempt a refresh immediately.
        jwks_client._last_refresh_attempt = None

        with mocked_failed_response() as failing:
            jwk_set = jwks_client.get_jwk_set()
            assert jwk_set[kid].key_id == kid
            # Further reads inside the cooldown make no further requests.
            for _ in range(3):
                jwk_set = jwks_client.get_jwk_set()
                assert jwk_set[kid].key_id == kid
        assert failing.call_count == 1

        # After the cooldown elapses, exactly one retry is permitted.
        jwks_client._last_refresh_attempt = time.monotonic() - 31
        with mocked_failed_response() as retried:
            jwk_set = jwks_client.get_jwk_set()
        assert retried.call_count == 1
        assert jwk_set[kid].key_id == kid

        # Past the hard cutoff (10 + 20 = 30): trust is revoked.
        assert jwks_client.jwk_set_cache is not None
        assert jwks_client.jwk_set_cache.jwk_set_with_timestamp is not None
        jwks_client.jwk_set_cache.jwk_set_with_timestamp.timestamp = (
            time.monotonic() - 31
        )
        jwks_client._last_refresh_attempt = time.monotonic() - 31
        with pytest.raises(PyJWKClientConnectionError):
            with mocked_failed_response() as cut_off:
                jwks_client.get_jwk_set()
        assert cut_off.call_count == 1

    def test_failed_forced_refresh_restarts_cooldown(self) -> None:
        # An unknown kid forces a refresh; when that refresh fails, the
        # attempt itself starts the cooldown so repeated unknown-kid
        # lookups do not produce another request until it elapses.
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "unknown-kid"
        jwks_client = PyJWKClient(url, lifespan=10, stale_ttl=20, cooldown_duration=30)

        with mocked_success_response(RESPONSE_DATA_NO_MATCHING_KID):
            with pytest.raises(PyJWKClientError, match="matches"):
                jwks_client.get_signing_key(kid)
        # No refresh was needed on the first fetch; reset the cooldown so
        # the next unknown-kid lookup is allowed to force one.
        jwks_client._last_refresh_attempt = None

        with mocked_failed_response() as failing:
            with pytest.raises(PyJWKClientError, match="matches"):
                jwks_client.get_signing_key(kid)
            assert failing.call_count == 1
            # Cooldown is now in force: no more requests for unknown kids.
            for _ in range(3):
                with pytest.raises(PyJWKClientError, match="matches"):
                    jwks_client.get_signing_key(kid)
            assert failing.call_count == 1

        # Once the cooldown elapses, one more attempt is allowed.
        jwks_client._last_refresh_attempt = time.monotonic() - 31
        with mocked_failed_response() as retried:
            with pytest.raises(PyJWKClientError, match="matches"):
                jwks_client.get_signing_key(kid)
        assert retried.call_count == 1

    def test_unknown_kid_served_from_stale_set_during_outage(self) -> None:
        # A token signed with a key the cached set already knows must still
        # verify during an outage after expiry, within the trust window.
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"
        jwks_client = self._client_with_aged_cache(lifespan=10, stale_ttl=20, age=15)

        with mocked_failed_response() as call:
            signing_key = jwks_client.get_signing_key(kid)

        assert call.call_count == 1
        assert signing_key.key_id == kid

    def test_concurrent_expired_refresh_runs_once_and_serves_stale(self) -> None:
        # When several threads hit an expired cache while the endpoint is
        # down, exactly one fetch is made and every caller receives the
        # stale set within its trust window: the lock serializes the
        # refresh and the cooldown blocks the waiters.
        jwks_client = self._client_with_aged_cache(
            lifespan=10, stale_ttl=20, age=15, cooldown_duration=30
        )
        assert jwks_client.jwk_set_cache is not None
        jwks_client._last_refresh_attempt = None
        refresh_started = threading.Event()
        release_refresh = threading.Event()

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            opener = build_opener_mock.return_value

            def failing_open(*args: object, **kwargs: object) -> mock.Mock:
                refresh_started.set()
                release_refresh.wait(timeout=5)
                raise URLError("Fail to process the request.")

            opener.open.side_effect = failing_open
            results: list[PyJWKSet] = []
            errors: list[Exception] = []

            def lookup() -> None:
                try:
                    results.append(jwks_client.get_jwk_set())
                except Exception as error:  # noqa: BLE001 - recorded for assert
                    errors.append(error)

            threads = [threading.Thread(target=lookup) for _ in range(4)]
            for thread in threads:
                thread.start()
            assert refresh_started.wait(timeout=5)
            release_refresh.set()
            for thread in threads:
                thread.join(timeout=5)
                assert not thread.is_alive()

        assert opener.open.call_count == 1
        assert errors == []
        assert len(results) == 4
        assert all(isinstance(result, PyJWKSet) for result in results)

    def test_failed_request_should_raise_connection_error(self) -> None:
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with pytest.raises(PyJWKClientConnectionError):
            with mocked_failed_response():
                jwks_client.get_signing_key_from_jwt(token)

    def test_incomplete_read_should_raise_connection_error(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with pytest.raises(PyJWKClientConnectionError):
            with mocked_incomplete_read_response():
                jwks_client.get_jwk_set()

    def test_get_jwt_set_refresh_cache(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, cooldown_duration=0)

        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        # The first call will return response with no matching kid,
        # the function should make another call to try to refresh the cache.
        with mocked_first_call_wrong_kid_second_call_correct_kid(
            RESPONSE_DATA_NO_MATCHING_KID, RESPONSE_DATA_WITH_MATCHING_KID
        ) as call_data:
            jwks_client.get_signing_key(kid)

        assert call_data.call_count == 2

    def test_get_jwt_set_no_matching_kid_after_second_attempt(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(url)

        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        with pytest.raises(PyJWKClientError):
            with mocked_first_call_wrong_kid_second_call_correct_kid(
                RESPONSE_DATA_NO_MATCHING_KID, RESPONSE_DATA_NO_MATCHING_KID
            ):
                jwks_client.get_signing_key(kid)

    def test_unknown_kid_refresh_is_cooled_down(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "unknown-kid"
        jwks_client = PyJWKClient(url, cooldown_duration=30)

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            opener = mock.Mock()
            build_opener_mock.return_value = opener
            response = mock.Mock()
            response.__enter__ = mock.Mock(return_value=response)
            response.__exit__ = mock.Mock()
            response.read.return_value = json.dumps(RESPONSE_DATA_NO_MATCHING_KID)
            opener.open.return_value = response

            for _ in range(2):
                with pytest.raises(PyJWKClientError, match="matches"):
                    jwks_client.get_signing_key(kid)

        assert opener.open.call_count == 1

    def test_unknown_kid_refresh_runs_again_after_cooldown(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "unknown-kid"
        jwks_client = PyJWKClient(url, cooldown_duration=0.01)

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            opener = mock.Mock()
            build_opener_mock.return_value = opener
            response = mock.Mock()
            response.__enter__ = mock.Mock(return_value=response)
            response.__exit__ = mock.Mock()
            response.read.return_value = json.dumps(RESPONSE_DATA_NO_MATCHING_KID)
            opener.open.return_value = response

            clock = [0.0]
            with mock.patch(
                "jwt.jwks_client.time.monotonic", side_effect=lambda: clock[0]
            ):
                with pytest.raises(PyJWKClientError, match="matches"):
                    jwks_client.get_signing_key(kid)
                clock[0] = 0.02
                with pytest.raises(PyJWKClientError, match="matches"):
                    jwks_client.get_signing_key(kid)

        assert opener.open.call_count == 2

    def test_unknown_kid_refresh_serializes_concurrent_misses(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "unknown-kid"
        jwks_client = PyJWKClient(url, cooldown_duration=30)
        refresh_started = threading.Event()
        second_done = threading.Event()
        release_refresh = threading.Event()

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            opener = mock.Mock()
            build_opener_mock.return_value = opener
            response = mock.Mock()
            response.__enter__ = mock.Mock(return_value=response)
            response.__exit__ = mock.Mock()
            response.read.return_value = json.dumps(RESPONSE_DATA_NO_MATCHING_KID)

            opener.open.return_value = response
            jwks_client.get_jwk_set()
            jwks_client._last_successful_fetch = 0
            # The cooldown is measured from the last fetch *attempt*; put
            # it outside the cooldown window so the unknown kid can force a
            # refresh under the mocked clock.
            jwks_client._last_refresh_attempt = 0

            def open_response(*args: object, **kwargs: object) -> mock.Mock:
                if opener.open.call_count == 1:
                    refresh_started.set()
                    release_refresh.wait(timeout=5)
                return response

            opener.open.reset_mock()
            opener.open.side_effect = open_response
            errors: list[Exception] = []

            def lookup() -> None:
                try:
                    jwks_client.get_signing_key(kid)
                except PyJWKClientError as error:
                    errors.append(error)

            first = threading.Thread(target=lookup)

            def second_lookup() -> None:
                lookup()
                second_done.set()

            second = threading.Thread(target=second_lookup)
            with mock.patch("jwt.jwks_client.time.monotonic", return_value=31):
                first.start()
                assert refresh_started.wait(timeout=5)
                second.start()
                assert not second_done.wait(timeout=0.1)
                release_refresh.set()
                first.join(timeout=5)
                second.join(timeout=5)

        assert len(errors) == 2
        assert not first.is_alive()
        assert not second.is_alive()
        assert opener.open.call_count == 1

    def test_unknown_kid_refresh_ignores_cooldown_when_cache_disabled(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "unknown-kid"
        jwks_client = PyJWKClient(url, cache_jwk_set=False, cooldown_duration=30)

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            opener = mock.Mock()
            build_opener_mock.return_value = opener
            response = mock.Mock()
            response.__enter__ = mock.Mock(return_value=response)
            response.__exit__ = mock.Mock()
            response.read.side_effect = [
                json.dumps(RESPONSE_DATA_NO_MATCHING_KID),
                json.dumps(RESPONSE_DATA_NO_MATCHING_KID),
                json.dumps(RESPONSE_DATA_NO_MATCHING_KID),
                json.dumps(RESPONSE_DATA_NO_MATCHING_KID),
            ]
            opener.open.return_value = response

            for _ in range(2):
                with pytest.raises(PyJWKClientError, match="matches"):
                    jwks_client.get_signing_key(kid)

        assert opener.open.call_count == 4

    @pytest.mark.parametrize(
        "cooldown_duration", [float("nan"), float("inf"), float("-inf")]
    )
    def test_unknown_kid_refresh_rejects_non_finite_cooldown(
        self, cooldown_duration: float
    ) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with pytest.raises(PyJWKClientError, match="Cooldown duration"):
            PyJWKClient(url, cooldown_duration=cooldown_duration)

    def test_get_jwt_set_invalid_lifespan(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with pytest.raises(PyJWKClientError):
            jwks_client = PyJWKClient(url, lifespan=-1)
            assert jwks_client is None

    @pytest.mark.parametrize(
        "uri",
        [
            "file:///etc/passwd",
            "ftp://example.org/keys.json",
            'data:application/json,{"keys":[]}',
            "/etc/passwd",  # urlparse gives scheme="" — also rejected
            "ldap://internal.test/jwks",
        ],
    )
    def test_pyjwkclient_rejects_non_http_schemes(self, uri: str) -> None:
        # urllib's default OpenerDirector handles file://, ftp://, and data:
        # URIs. PyJWKClient must reject these so callers can't be tricked
        # into reading attacker-controlled local files or other unintended
        # schemes via a manipulated URI.
        with pytest.raises(PyJWKClientError, match="Invalid JWKS URI scheme"):
            PyJWKClient(uri)

    @pytest.mark.parametrize(
        "uri",
        [
            "http://localhost/jwks.json",
            "https://example.test/jwks.json",
            "HTTPS://Example.Test/jwks.json",  # case-insensitive
        ],
    )
    def test_pyjwkclient_accepts_http_https_schemes(self, uri: str) -> None:
        # Construction succeeds; no fetch is made until get_jwk_set().
        PyJWKClient(uri)

    def test_get_jwt_set_timeout(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, timeout=5)

        with pytest.raises(PyJWKClientError) as exc:
            with mocked_timeout():
                jwks_client.get_jwk_set()

        assert 'Fail to fetch data from the url, err: "timed out"' in str(exc.value)

    def test_get_jwt_set_sslcontext_default(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        ssl_ctx = ssl.create_default_context()
        jwks_client = PyJWKClient(url, ssl_context=ssl_ctx)

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            opener = mock.Mock()
            build_opener_mock.return_value = opener
            response = mock.Mock()
            response.__enter__ = mock.Mock(return_value=response)
            response.__exit__ = mock.Mock()
            response.read.return_value = json.dumps(RESPONSE_DATA_WITH_MATCHING_KID)
            opener.open.return_value = response
            jwk_set = jwks_client.get_jwk_set()
            handlers = build_opener_mock.call_args.args
            assert any(
                getattr(handler, "_context", None) is ssl_ctx for handler in handlers
            )

        assert jwk_set is not None

    def test_get_jwt_set_sslcontext_no_ca(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(
            url, ssl_context=ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        )

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            build_opener_mock.return_value.open.side_effect = URLError(
                ssl.SSLCertVerificationError("certificate verify failed")
            )
            with pytest.raises(PyJWKClientError):
                jwks_client.get_jwk_set()

    def test_http_error_is_closed_on_connection_failure(self) -> None:
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(url)

        with mocked_http_error_response() as (_, http_error):
            with pytest.raises(PyJWKClientConnectionError):
                jwks_client.get_jwk_set()

            assert http_error.closed
