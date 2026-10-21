from __future__ import annotations

from talos_a2a.capability import CapabilityToken
from talos_a2a.identity import TalosDid


def test_capability_token_lifecycle():
    issuer = TalosDid.generate("authority")
    audience = TalosDid.generate("worker")

    token = CapabilityToken.issue(
        issuer=issuer,
        audience_did=audience.did,
        allowed_tools=["qdrant_search", "deepseek_reasoning"],
        ttl_seconds=3600,
        max_invocations=50,
    )

    assert token.verify(issuer) is True
    assert token.allows_tool("qdrant_search") is True
    assert token.allows_tool("deepseek_reasoning") is True
    assert token.allows_tool("delete_database") is False

    # Test compact serialization
    compact = token.to_compact()
    restored = CapabilityToken.from_compact(compact)
    assert restored.verify(issuer) is True
    assert restored.issuer_did == issuer.did
    assert restored.audience_did == audience.did
