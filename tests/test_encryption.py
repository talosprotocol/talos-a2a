from __future__ import annotations

import pytest
from talos_a2a.encryption import E2EESession


def test_e2ee_session_envelope_encryption():
    session = E2EESession.create()
    sender_did = "did:talos:agent:sender"
    recipient_did = "did:talos:agent:receiver"

    original_payload = {
        "task": "Extract founders",
        "parameters": {"limit": 10},
    }

    envelope = session.encrypt_payload(
        payload=original_payload,
        sender_did=sender_did,
        recipient_did=recipient_did,
    )

    assert envelope.sender_did == sender_did
    assert envelope.recipient_did == recipient_did
    assert envelope.session_id == session.session_id
    assert envelope.ciphertext_b64 != ""

    decrypted = session.decrypt_payload(envelope)
    assert decrypted == original_payload


def test_tampered_envelope_fails():
    session = E2EESession.create()
    envelope = session.encrypt_payload(
        {"secret": 123},
        "did:sender",
        "did:receiver",
    )
    # Tamper with recipient
    envelope.recipient_did = "did:attacker"
    with pytest.raises(Exception):
        session.decrypt_payload(envelope)
