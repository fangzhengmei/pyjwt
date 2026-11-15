import math
import time
from typing import Any, Optional, Union

from .api_jwk import PyJWKSet, PyJWTSetWithTimestamp
from .exceptions import PyJWKClientError, PyJWKSetError


class JWKSetCache:
    def __init__(self, lifespan: float, stale_ttl: float = 0) -> None:
        """Cache a JWK Set with a fresh window and a bounded stale window.

        A cached set is *fresh* for ``lifespan`` seconds and may then be
        served as *stale* for at most ``stale_ttl`` additional seconds while
        a refresh is attempted. The sum of the two is a hard cutoff: once it
        has passed, neither :meth:`get` nor :meth:`get_stale` returns the
        set, so a key removed from the endpoint can only keep being trusted
        for a bounded time.

        :param lifespan: Time in seconds during which the cached set is
            considered fresh.
        :param stale_ttl: Time in seconds after expiry during which the cached
            set may still be served when a refresh fails. Defaults to ``0``,
            which disables stale fallback entirely.
        """
        if stale_ttl < 0:
            raise PyJWKClientError(
                "Stale TTL must be greater than or equal to 0, "
                f'the input is "{stale_ttl}"'
            )
        if not math.isfinite(stale_ttl):
            raise PyJWKClientError(
                f'Stale TTL must be finite, the input is "{stale_ttl}"'
            )
        self.jwk_set_with_timestamp: Optional[PyJWTSetWithTimestamp] = None
        self.lifespan = lifespan
        self.stale_ttl = stale_ttl

    def put(self, jwk_set: Optional[Union[PyJWKSet, dict[str, Any]]]) -> None:
        """Cache *jwk_set*, or clear the cache when it is ``None``.

        Accepts either an already-parsed ``PyJWKSet`` or the raw JWKS
        payload it is parsed from, and always stores it parsed so that
        reads never have to parse the keys again.

        :raises PyJWKSetError: If *jwk_set* is neither a ``PyJWKSet`` nor a
            JWKS payload containing usable keys.
        """
        if jwk_set is None:
            # clear cache
            self.jwk_set_with_timestamp = None
            return

        if not isinstance(jwk_set, PyJWKSet):
            if not isinstance(jwk_set, dict):
                raise PyJWKSetError("Invalid JWK Set value")
            jwk_set = PyJWKSet.from_dict(jwk_set)

        self.jwk_set_with_timestamp = PyJWTSetWithTimestamp(jwk_set)

    def get(self) -> Optional[PyJWKSet]:
        if self.jwk_set_with_timestamp is None or self.is_expired():
            return None

        return self.jwk_set_with_timestamp.get_jwk_set()

    def get_stale(self) -> Optional[PyJWKSet]:
        """Return the cached set while it is still inside the stale window.

        Unlike :meth:`get`, an expired set is returned as long as the hard
        cutoff (``lifespan + stale_ttl`` from when it was cached) has not
        passed. Returns ``None`` when nothing is cached, the stale window is
        disabled, or the cutoff has passed.
        """
        if (
            self.jwk_set_with_timestamp is None
            or self.stale_ttl <= 0
            or self.is_stale_window_elapsed()
        ):
            return None

        return self.jwk_set_with_timestamp.get_jwk_set()

    def is_expired(self) -> bool:
        return (
            self.jwk_set_with_timestamp is not None
            and self.lifespan > -1
            and time.monotonic()
            > self.jwk_set_with_timestamp.get_timestamp() + self.lifespan
        )

    def is_stale_window_elapsed(self) -> bool:
        """Whether the cached set has outlived ``lifespan + stale_ttl``."""
        return (
            self.jwk_set_with_timestamp is not None
            and time.monotonic()
            > self.jwk_set_with_timestamp.get_timestamp()
            + self.lifespan
            + self.stale_ttl
        )
