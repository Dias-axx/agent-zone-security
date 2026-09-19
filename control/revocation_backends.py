"""Optional shared RevocationStore backends. Import-guarded so the rest of the
repository runs, and all PoCs and tests pass, with no Redis server and no
`redis` package installed. Never a hard dependency — mirrors
agents/adapters/llm.py's stance on optional infrastructure.
"""

from __future__ import annotations

import importlib.util
from typing import Any

# Availability is checked without importing redis's typed symbols, so this
# module's own type-checking doesn't depend on whether the optional `redis`
# package happens to be installed in a given environment — client is typed as
# Any below regardless, since RedisRevocationStore only calls two duck-typed
# methods (setex, exists) on whatever client it's given.
HAS_REDIS = importlib.util.find_spec("redis") is not None


def is_available() -> bool:
    return HAS_REDIS


class RedisRevocationStore:
    """Shares revocation state across every process pointed at the same Redis
    instance — the actual fix for the single-process revocation gap: a token
    revoked by one response-controller invocation is immediately revoked for
    every other process verifying tokens against the same store.

    Fails closed on a Redis outage: is_revoked() re-raises rather than
    returning False, because "the revocation store is unreachable" and "this
    token is not revoked" are not the same fact, and treating them as
    equivalent would let a revoked-but-unverifiable token keep working during
    an outage — the opposite of what revocation is for. Callers that need a
    fallback (e.g. falling back to a local cache) must implement that
    explicitly; this class will not paper over it silently.

    Revocation entries carry a TTL slightly longer than
    control.token_issuer.MAX_TTL_SECONDS so Redis never accumulates entries
    for tokens that would have expired anyway.
    """

    _KEY_PREFIX = "agent-zone-control:revoked:"
    _TTL_SECONDS = 3600 + 60  # MAX_TTL_SECONDS + margin, avoided importing token_issuer to prevent a cycle

    def __init__(self, client: Any) -> None:
        if not HAS_REDIS:
            raise RuntimeError("redis package is not installed; RedisRevocationStore is optional")
        self._client = client

    def revoke(self, token_id: str) -> None:
        self._client.setex(self._KEY_PREFIX + token_id, self._TTL_SECONDS, "1")

    def is_revoked(self, token_id: str) -> bool:
        return bool(self._client.exists(self._KEY_PREFIX + token_id))
