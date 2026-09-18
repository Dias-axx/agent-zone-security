from __future__ import annotations

import dataclasses

import pytest

from control.token_issuer import MAX_TTL_SECONDS, TokenError, TokenIssuer


def test_issue_and_verify_roundtrip() -> None:
    issuer = TokenIssuer()
    token = issuer.issue(
        agent_id="a1", role="read-only-agent", session_id="s1", scope={"log.read"}, ttl_seconds=60
    )
    assert issuer.verify(token)


def test_ttl_above_ceiling_rejected() -> None:
    issuer = TokenIssuer()
    with pytest.raises(TokenError):
        issuer.issue(agent_id="a1", role="r", session_id="s1", scope=set(), ttl_seconds=MAX_TTL_SECONDS + 1)


def test_ttl_zero_rejected() -> None:
    issuer = TokenIssuer()
    with pytest.raises(TokenError):
        issuer.issue(agent_id="a1", role="r", session_id="s1", scope=set(), ttl_seconds=0)


def test_revoked_token_denied_immediately() -> None:
    issuer = TokenIssuer()
    token = issuer.issue(agent_id="a1", role="r", session_id="s1", scope=set(), ttl_seconds=60)
    assert issuer.verify(token)
    issuer.revoke(token.token_id)
    assert not issuer.verify(token)


def test_tampered_token_denied() -> None:
    issuer = TokenIssuer()
    token = issuer.issue(agent_id="a1", role="r", session_id="s1", scope={"log.read"}, ttl_seconds=60)
    tampered = dataclasses.replace(token, agent_id="a2")
    assert not issuer.verify(tampered)


def test_delegated_by_carried_on_token() -> None:
    issuer = TokenIssuer()
    token = issuer.issue(
        agent_id="a1", role="deploy-agent", session_id="s1", scope={"deploy.plan"}, ttl_seconds=60,
        delegated_by="alice@example.internal",
    )
    assert token.delegated_by == "alice@example.internal"
    assert issuer.verify(token)
