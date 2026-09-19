"""Tests for TokenIssuer's pluggable secret and RevocationStore, and the
optional Redis-backed store. No real Redis is required: RedisRevocationStore
is exercised against a fake client implementing the two methods it calls
(setex, exists) — the same shape redis-py's client provides.
"""

from __future__ import annotations

import pytest

from control.revocation_backends import RedisRevocationStore
from control.token_issuer import InMemoryRevocationStore, TokenIssuer


class FakeRevocationStore:
    def __init__(self) -> None:
        self.revoked: set[str] = set()

    def revoke(self, token_id: str) -> None:
        self.revoked.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self.revoked


def test_default_revocation_store_is_in_memory() -> None:
    issuer = TokenIssuer()
    token = issuer.issue(agent_id="a1", role="r", session_id="s1", scope=set(), ttl_seconds=60)
    issuer.revoke(token.token_id)
    assert not issuer.verify(token)


def test_custom_revocation_store_is_used() -> None:
    store = FakeRevocationStore()
    issuer = TokenIssuer(revocation_store=store)
    token = issuer.issue(agent_id="a1", role="r", session_id="s1", scope=set(), ttl_seconds=60)
    issuer.revoke(token.token_id)
    assert token.token_id in store.revoked
    assert not issuer.verify(token)


def test_shared_secret_lets_a_second_issuer_verify_the_first_issuers_token() -> None:
    secret = b"x" * 32
    shared_store = FakeRevocationStore()
    issuer_a = TokenIssuer(secret=secret, revocation_store=shared_store)
    issuer_b = TokenIssuer(secret=secret, revocation_store=shared_store)

    token = issuer_a.issue(agent_id="a1", role="r", session_id="s1", scope={"log.read"}, ttl_seconds=60)
    assert issuer_b.verify(token)

    issuer_b.revoke(token.token_id)
    assert not issuer_a.verify(token)


def test_default_random_secrets_mean_separate_issuers_cannot_verify_each_other() -> None:
    issuer_a = TokenIssuer()
    issuer_b = TokenIssuer()
    token = issuer_a.issue(agent_id="a1", role="r", session_id="s1", scope=set(), ttl_seconds=60)
    assert not issuer_b.verify(token)


class FakeRedisClient:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def setex(self, key: str, ttl: int, value: str) -> None:
        assert ttl > 0
        self.store[key] = value

    def exists(self, key: str) -> int:
        return 1 if key in self.store else 0


def test_redis_revocation_store_revoke_and_check() -> None:
    client = FakeRedisClient()
    store = RedisRevocationStore(client)
    assert not store.is_revoked("tok-1")
    store.revoke("tok-1")
    assert store.is_revoked("tok-1")
    assert not store.is_revoked("tok-2")


def test_redis_revocation_store_used_via_token_issuer() -> None:
    client = FakeRedisClient()
    store = RedisRevocationStore(client)
    issuer = TokenIssuer(revocation_store=store)
    token = issuer.issue(agent_id="a1", role="r", session_id="s1", scope=set(), ttl_seconds=60)
    assert issuer.verify(token)
    issuer.revoke(token.token_id)
    assert not issuer.verify(token)


def test_in_memory_revocation_store_is_importable_directly() -> None:
    store = InMemoryRevocationStore()
    assert not store.is_revoked("x")
    store.revoke("x")
    assert store.is_revoked("x")


def test_redis_store_construction_raises_if_flagged_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import control.revocation_backends as backends

    monkeypatch.setattr(backends, "HAS_REDIS", False)
    with pytest.raises(RuntimeError):
        backends.RedisRevocationStore(FakeRedisClient())
