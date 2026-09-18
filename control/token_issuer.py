"""Short-lived capability tokens bound to (agent_id, role, session_id, scope).

Tokens are signed with HMAC-SHA256 using a secret generated at runtime (per
TokenIssuer instance) — no bespoke crypto scheme, no persisted key material.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass

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


class TokenIssuer:
    def __init__(self) -> None:
        self._secret = secrets.token_bytes(32)
        self._revoked: set[str] = set()

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
        if token.token_id in self._revoked:
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
        self._revoked.add(token_id)
