from __future__ import annotations

from talos_a2a.identity import TalosDid, build_authenticated_agent_card


def test_talos_did_generation_and_signing():
    did = TalosDid.generate(name="scout")
    assert did.did.startswith("did:talos:agent:scout:")

    doc = did.to_did_document()
    assert doc["id"] == did.did
    assert len(doc["verificationMethod"]) == 1

    payload = b"A2A Task Execution Authorization"
    sig = did.sign(payload)
    assert did.verify(payload, sig) is True
    assert did.verify(b"Tampered payload", sig) is False


def test_authenticated_agent_card():
    did = TalosDid.generate(name="scout")
    card = build_authenticated_agent_card(
        did=did,
        name="Talos Scout",
        description="Autonomous scout agent",
        skills=[{"id": "s1", "name": "Scout", "description": "Vector search"}],
    )
    assert card["did"] == did.did
    assert card["name"] == "Talos Scout"
    assert "proof" in card
    assert card["proof"]["verificationMethod"] == f"{did.did}#key-1"
