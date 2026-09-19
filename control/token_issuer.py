"""Short-lived capability tokens bound to (agent_id, role, session_id, scope).

Tokens are signed with HMAC-SHA256. The signing secret and the revocation set
are both pluggable (see `secret` and `revocation_store` on TokenIssuer):

- By default, TokenIssuer generates a fresh random secret per instance and
  keeps revocations in an in-memory set — the original v1 behaviour, correct
  for a single process (tests, PoCs, a single-replica deployment).
- For multiple processes/replicas to verify each other's tokens and see each
  other's revocations, both need to be shared: pass the same `secret` bytes
  to every TokenIssuer instance (loaded from a shared secret store — this
  module does not fetch one for you, deliberately: secret distribution is a
  deployment concern, not something to bake in here) and a shared
  `RevocationStore` (see control.revocation_backends.RedisRevocationStore for
  an optional, import-guarded option).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Protocol

MAX_TTL_SECONDS = 3600


class TokenError(ValueError):
    """Raised for a malformed or out-of-policy token request."""


@dataclass(frozen=True)
class CapabilityToken:
    token_id: str
    agent_id: str
    role: str
    session_id: str
    scope: frozenset[str]
    issued_at: float
    expires_at: float
    delegated_by: str | None
    signature: str


class RevocationStore(Protocol):
    """Tracks revoked token ids. Implementations must fail closed: if a
    revocation store cannot be reached to answer is_revoked(), that is not
    the same as "not revoked" and callers should treat it as revoked (see
    control.revocation_backends.RedisRevocationStore's docstring)."""

    def revoke(self, token_id: str) -> None: ...
    def is_revoked(self, token_id: str) -> bool: ...


class InMemoryRevocationStore:
    """The v1 behaviour: a plain set, scoped to this process. Correct for a
    single-process deployment; a second process (a second replica, a second
    CLI invocation) never sees revocations made here."""

    def __init__(self) -> None:
        self._revoked: set[str] = set()

    def revoke(self, token_id: str) -> None:
        self._revoked.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self._revoked


class TokenIssuer:
    def __init__(
        self,
        *,
        secret: bytes | None = None,
        revocation_store: RevocationStore | None = None,
    ) -> None:
        self._secret = secret if secret is not None else secrets.token_bytes(32)
        self._revocation_store: RevocationStore = revocation_store or InMemoryRevocationStore()

    def _payload(
        self,
        token_id: str,
        agent_id: str,
        role: str,
        session_id: str,
        scope: frozenset[str],
        expires_at: float,
        delegated_by: str | None,
    ) -> bytes:
        parts = [
            token_id,
            agent_id,
            role,
            session_id,
            ",".join(sorted(scope)),
            repr(expires_at),
            delegated_by or "",
        ]
        return "|".join(parts).encode("utf-8")

    def issue(
        self,
        *,
        agent_id: str,
        role: str,
        session_id: str,
        scope: set[str],
        ttl_seconds: int,
        delegated_by: str | None = None,
    ) -> CapabilityToken:
        if ttl_seconds <= 0:
            raise TokenError("ttl_seconds must be positive")
        if ttl_seconds > MAX_TTL_SECONDS:
            raise TokenError(f"ttl_seconds {ttl_seconds} exceeds hard ceiling {MAX_TTL_SECONDS}")

        token_id = str(uuid.uuid4())
        issued_at = time.time()
        expires_at = issued_at + ttl_seconds
        frozen_scope = frozenset(scope)
        payload = self._payload(token_id, agent_id, role, session_id, frozen_scope, expires_at, delegated_by)
        signature = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

        return CapabilityToken(
            token_id=token_id,
            agent_id=agent_id,
            role=role,
            session_id=session_id,
            scope=frozen_scope,
            issued_at=issued_at,
            expires_at=expires_at,
            delegated_by=delegated_by,
            signature=signature,
        )

    def verify(self, token: CapabilityToken) -> bool:
        if self._revocation_store.is_revoked(token.token_id):
            return False
        if time.time() > token.expires_at:
            return False
        payload = self._payload(
            token.token_id,
            token.agent_id,
            token.role,
            token.session_id,
            token.scope,
            token.expires_at,
            token.delegated_by,
        )
        expected = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, token.signature)

    def revoke(self, token_id: str) -> None:
        self._revocation_store.revoke(token_id)
