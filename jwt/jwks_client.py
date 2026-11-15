from __future__ import annotations

import http.client
import json
import math
import threading
import time
import urllib.request
from functools import lru_cache
from ssl import SSLContext
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError, PyJWTError
from .jwk_set_cache import JWKSetCache


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class PyJWKClient:
    def __init__(
        self,
        uri: str,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        cache_jwk_set: bool = True,
        lifespan: float = 300,
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
        ssl_context: SSLContext | None = None,
        cooldown_duration: float = 30,
        stale_ttl: float = 0,
    ):
        """A client for retrieving signing keys from a JWKS endpoint.

        ``PyJWKClient`` uses a two-tier caching system to avoid unnecessary
        network requests:

        **Tier 1 — JWK Set cache** (enabled by default):
        Caches the entire JSON Web Key Set response from the endpoint.
        Controlled by:

        - ``cache_jwk_set``: Set to ``True`` (the default) to enable this
          cache. When enabled, the JWK Set is fetched from the network only
          when the cache is empty or expired.
        - ``lifespan``: Time in seconds during which the cached JWK Set is
          considered fresh. Defaults to ``300`` (5 minutes). Must be greater
          than 0.
        - ``stale_ttl``: Bounds how long an expired (stale) JWK Set may keep
          being trusted after its ``lifespan`` has elapsed. When a refresh
          fails because the endpoint is unreachable or returns an invalid
          response, the stale set is still served until ``lifespan +
          stale_ttl`` seconds have passed since it was cached. Once that hard
          cutoff passes, the stale set is discarded and tokens can no longer
          be verified against it, so a revoked key can never be trusted
          indefinitely. A failed refresh never overwrites a usable set.
          Defaults to ``0``, which disables stale fallback: an expired set
          plus a failed refresh results in an error, matching the behavior of
          clients that do not opt in.

        Unknown key IDs can trigger one forced refresh after the cooldown
        period configured by ``cooldown_duration``. Every fetch attempt
        (successful or not) starts this cooldown, including the initial fetch
        and cache-expiry fetches. A newly rotated key may therefore wait for
        the cooldown period before it is fetched; set ``cooldown_duration``
        to ``0`` to disable this behavior. The cooldown is bypassed when
        ``cache_jwk_set`` is ``False``.

        **Tier 2 — Signing key cache** (disabled by default):
        Caches individual signing keys (looked up by ``kid``) using an LRU
        cache with **no time-based expiration**. Keys are evicted only when
        the cache reaches its maximum size. Controlled by:

        - ``cache_keys``: Set to ``True`` to enable this cache.
          Defaults to ``False``.
        - ``max_cached_keys``: Maximum number of signing keys to keep in
          the LRU cache. Defaults to ``16``.

        :param uri: The URL of the JWKS endpoint.
        :type uri: str
        :param cache_keys: Enable the per-key LRU cache (Tier 2).
        :type cache_keys: bool
        :param max_cached_keys: Max entries in the signing key LRU cache.
        :type max_cached_keys: int
        :param cache_jwk_set: Enable the JWK Set response cache (Tier 1).
        :type cache_jwk_set: bool
        :param lifespan: TTL in seconds for the JWK Set cache.
        :type lifespan: float
        :param headers: Optional HTTP headers to include in requests.
        :type headers: dict or None
        :param timeout: HTTP request timeout in seconds.
        :type timeout: float
        :param ssl_context: Optional SSL context for the request.
        :type ssl_context: ssl.SSLContext or None
        :param cooldown_duration: Minimum time in seconds between forced
            refreshes after an unknown key ID. Defaults to ``30``.
        :type cooldown_duration: float
        :param stale_ttl: Maximum extra time in seconds that an expired JWK
            Set remains trusted when a refresh fails. Defaults to ``0``
            (fail immediately instead of serving stale keys).
        :type stale_ttl: float
        """
        if headers is None:
            headers = {}
        # urllib's default OpenerDirector also handles file://, ftp://, and
        # data: URIs. Reject anything that isn't http(s) eagerly so a caller
        # passing an attacker-influenced URL (e.g. taken from a `jku` token
        # header) can't read local files or reach other unintended schemes.
        scheme = urlparse(uri).scheme.lower()
        if scheme not in ("http", "https"):
            raise PyJWKClientError(
                f"Invalid JWKS URI scheme {scheme!r}: only 'http' and 'https' "
                f"are supported."
            )
        self.uri = uri
        self.jwk_set_cache: JWKSetCache | None = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        if cooldown_duration < 0:
            raise PyJWKClientError(
                "Cooldown duration must be greater than or equal to 0, "
                f'the input is "{cooldown_duration}"'
            )
        if not math.isfinite(cooldown_duration):
            raise PyJWKClientError(
                f'Cooldown duration must be finite, the input is "{cooldown_duration}"'
            )
        if stale_ttl < 0:
            raise PyJWKClientError(
                "Stale TTL must be greater than or equal to 0, "
                f'the input is "{stale_ttl}"'
            )
        if not math.isfinite(stale_ttl):
            raise PyJWKClientError(
                f'Stale TTL must be finite, the input is "{stale_ttl}"'
            )
        self.cooldown_duration = cooldown_duration
        self.stale_ttl = stale_ttl
        self._last_successful_fetch: float | None = None
        # Timestamp of the most recent fetch attempt, including failed
        # ones, so a failing endpoint cannot bypass the refresh cooldown.
        self._last_refresh_attempt: float | None = None
        self._client_lock = threading.RLock()

        if cache_jwk_set:
            # Init jwt set cache with default or given lifespan.
            # Default lifespan is 300 seconds (5 minutes).
            if lifespan <= 0:
                raise PyJWKClientError(
                    f'Lifespan must be greater than 0, the input is "{lifespan}"'
                )
            self.jwk_set_cache = JWKSetCache(lifespan, stale_ttl=stale_ttl)
        else:
            self.jwk_set_cache = None

        if cache_keys:
            # Cache signing keys
            get_signing_key = lru_cache(maxsize=max_cached_keys)(self.get_signing_key)
            # Ignore mypy (https://github.com/python/mypy/issues/2427)
            self.get_signing_key = get_signing_key  # type: ignore[method-assign]

    def fetch_data(self) -> Any:
        """Fetch the JWK Set from the JWKS endpoint.

        Makes an HTTP request to the configured ``uri`` and returns the
        parsed JSON response. If the JWK Set cache is enabled, the
        response is stored in the cache.

        :returns: The parsed JWK Set as a dictionary.
        :raises PyJWKClientConnectionError: If the HTTP request fails.
        :raises PyJWKClientError: If the endpoint does not return a JSON
            object.
        :raises PyJWKSetError: If the JWK Set cache is enabled and the
            response contains no usable keys.
        """
        try:
            r = urllib.request.Request(url=self.uri, headers=self.headers)
            handlers: list[Any] = [_NoRedirectHandler()]
            if self.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(r, timeout=self.timeout) as response:
                jwk_set = json.load(response)
        except (URLError, TimeoutError, http.client.HTTPException) as e:
            if isinstance(e, HTTPError):
                e.close()
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{e}"'
            ) from e

        # Validate the payload before it reaches the cache, so an endpoint
        # returning something that isn't a JSON object is reported as such
        # rather than as a malformed JWK Set.
        jwk_set = self._as_jwk_set_payload(jwk_set)

        # Only update the cache on a successful fetch. Writing in a
        # `finally` block with `jwk_set=None` on error clears any
        # previously-cached JWKS, turning a transient outage into a cache
        # wipe that breaks legitimate auth.
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        self._last_successful_fetch = time.monotonic()
        return jwk_set

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        """Return the JWK Set, using the cache when available.

        When the cache is enabled and a refresh fails (network error or an
        invalid response from the endpoint), a previously cached set that is
        still inside its stale window (``lifespan + stale_ttl``) is served
        instead of propagating the failure. Once that window elapses the
        stale set is no longer returned and the underlying error is raised.
        A failed refresh never replaces the cached set, so one bad response
        cannot discard a still-usable one. While a refresh cooldown is
        active, an expired-but-still-trustable set is served without any
        request at all.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the fresh cache.
        :type refresh: bool
        :returns: The JWK Set.
        :rtype: PyJWKSet
        :raises PyJWKClientError: If the endpoint does not return a JSON
            object and no cached set is available within the stale window.
        :raises PyJWKClientConnectionError: If the endpoint is unreachable
            and no cached set is available within the stale window.
        """
        # Serialize refreshes across threads: without this, concurrent
        # lookups against an expired/missing cache would each issue their
        # own request, and a forced refresh could run while another one is
        # in flight.
        with self._client_lock:
            data = None
            fetched = False
            if self.jwk_set_cache is not None and not refresh:
                data = self.jwk_set_cache.get()

            if data is None:
                # While a refresh cooldown is in force and a still-trustable
                # stale set exists, serve it instead of issuing another
                # request. This bounds the endpoint to at most one fetch per
                # cooldown window during an outage or a rotation that has not
                # propagated yet. A forced refresh bypasses this, and with
                # stale_ttl=0 there is no stale set to fall back on.
                if not refresh and self._is_cooling_down():
                    stale = (
                        self.jwk_set_cache.get_stale()
                        if self.jwk_set_cache is not None
                        else None
                    )
                    if stale is not None:
                        return stale
                try:
                    data = self.fetch_data()
                    fetched = True
                except PyJWTError:
                    # Do not let a single failed/invalid response wipe out a
                    # still-trustable set. Serve the stale cache while the
                    # hard cutoff (lifespan + stale_ttl) has not passed;
                    # beyond it, revoke trust by re-raising.
                    if self.jwk_set_cache is None:
                        raise
                    stale = self.jwk_set_cache.get_stale()
                    if stale is None:
                        raise
                    return stale
                finally:
                    self._last_refresh_attempt = time.monotonic()

            # A cache hit is already parsed, so serve it as-is. Only a fresh
            # fetch reaches the check below, which still matters because
            # `fetch_data()` may be overridden by a subclass.
            if isinstance(data, PyJWKSet):
                jwk_set = data
            else:
                jwk_set = PyJWKSet.from_dict(self._as_jwk_set_payload(data))

            # `fetch_data()` caches the payload it received from the endpoint,
            # but a subclass may filter or transform it before returning. Cache
            # the value actually being returned, so later cache hits serve the
            # same key set as this call rather than the pre-transform one.
            if fetched and self.jwk_set_cache is not None:
                self.jwk_set_cache.put(jwk_set)

            return jwk_set

    @staticmethod
    def _as_jwk_set_payload(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")

        return data

    def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:
        """Return all signing keys from the JWK Set.

        Filters the JWK Set to keys whose ``use`` is ``"sig"`` (or
        unspecified) and that have a ``kid``.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache.
        :type refresh: bool
        :returns: A list of signing keys.
        :rtype: list[PyJWK]
        :raises PyJWKClientError: If no signing keys are found.
        """
        jwk_set = self.get_jwk_set(refresh)
        return self._get_signing_keys_from_jwk_set(jwk_set)

    @staticmethod
    def _get_signing_keys_from_jwk_set(jwk_set: PyJWKSet) -> list[PyJWK]:
        signing_keys = [
            jwk_set_key
            for jwk_set_key in jwk_set.keys
            if jwk_set_key.public_key_use in ["sig", None] and jwk_set_key.key_id
        ]

        if not signing_keys:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

        return signing_keys

    def get_signing_key(self, kid: str) -> PyJWK:
        """Return the signing key matching the given ``kid``.

        If no match is found in the current JWK Set, the set is refreshed
        from the endpoint and the lookup is retried once when the refresh
        cooldown permits it. When the refresh fails but a stale set is
        available within its trust window, the retry runs against that set.

        :param kid: The key ID to look up.
        :type kid: str
        :returns: The matching signing key.
        :rtype: PyJWK
        :raises PyJWKClientError: If no matching key is found after
            refreshing.
        """
        with self._client_lock:
            signing_keys = self.get_signing_keys()
            signing_key = self.match_kid(signing_keys, kid)

            if not signing_key and not self._is_cooling_down():
                # A failed refresh is served from the stale set (or raises)
                # inside get_jwk_set(); either way the cooldown was restarted
                # by the attempt, so failures cannot trigger request storms.
                signing_keys = self.get_signing_keys(refresh=True)
                signing_key = self.match_kid(signing_keys, kid)

            if not signing_key:
                raise PyJWKClientError(
                    f'Unable to find a signing key that matches: "{kid}"'
                )

            return signing_key

    def _is_cooling_down(self) -> bool:
        """Whether a forced refresh is currently blocked by the cooldown.

        The cooldown is measured from the most recent fetch *attempt*, so a
        failing endpoint restarts it just like a successful one and repeated
        unknown-``kid`` lookups during an outage make at most one request per
        cooldown window. It only applies while the JWK Set cache is enabled.
        """
        if self.jwk_set_cache is None or self._last_refresh_attempt is None:
            return False
        return time.monotonic() - self._last_refresh_attempt < self.cooldown_duration

    def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Return the signing key for a JWT by reading its ``kid`` header.

        Extracts the ``kid`` from the token's unverified header and
        delegates to :meth:`get_signing_key`.

        :param token: The encoded JWT.
        :type token: str or bytes
        :returns: The matching signing key.
        :rtype: PyJWK
        """
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return self.get_signing_key(header.get("kid"))

    @staticmethod
    def match_kid(signing_keys: list[PyJWK], kid: str) -> PyJWK | None:
        """Find a key in *signing_keys* that matches *kid*.

        :param signing_keys: The list of keys to search.
        :type signing_keys: list[PyJWK]
        :param kid: The key ID to match.
        :type kid: str
        :returns: The matching key, or ``None`` if not found.
        :rtype: PyJWK or None
        """
        signing_key = None

        for key in signing_keys:
            if key.key_id == kid:
                signing_key = key
                break

        return signing_key
