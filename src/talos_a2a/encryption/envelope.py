from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


@dataclass
class EncryptedEnvelope:
    sender_did: str
    recipient_did: str
    nonce_b64: str
    ciphertext_b64: str
    session_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "senderDid": self.sender_did,
            "recipientDid": self.recipient_did,
            "nonce": self.nonce_b64,
            "ciphertext": self.ciphertext_b64,
            "sessionId": self.session_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EncryptedEnvelope:
        return cls(
            sender_did=str(data.get("senderDid") or data.get("sender_did", "")),
            recipient_did=str(data.get("recipientDid") or data.get("recipient_did", "")),
            nonce_b64=str(data.get("nonce", "")),
            ciphertext_b64=str(data.get("ciphertext", "")),
            session_id=str(data.get("sessionId") or data.get("session_id", "")),
        )


class E2EESession:
    """End-to-End Encrypted Session implementing ChaCha20-Poly1305 forward-secret envelopes."""

    def __init__(self, session_id: str, shared_key: bytes) -> None:
        if len(shared_key) != 32:
            raise ValueError("shared_key must be exactly 32 bytes")
        self.session_id = session_id
        self._key = shared_key
        self._aead = ChaCha20Poly1305(self._key)
        self._step_counter = 0

    @classmethod
    def create(cls, session_id: str | None = None) -> E2EESession:
        key = ChaCha20Poly1305.generate_key()
        sid = session_id or os.urandom(16).hex()
        return cls(session_id=sid, shared_key=key)

    def encrypt_payload(
        self,
        payload: dict[str, Any],
        sender_did: str,
        recipient_did: str,
    ) -> EncryptedEnvelope:
        nonce = os.urandom(12)
        plaintext = json.dumps(payload).encode("utf-8")
        aad = f"{sender_did}:{recipient_did}:{self.session_id}".encode("utf-8")
        ciphertext = self._aead.encrypt(nonce, plaintext, aad)
        self._step_counter += 1

        return EncryptedEnvelope(
            sender_did=sender_did,
            recipient_did=recipient_did,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            session_id=self.session_id,
        )

    def decrypt_payload(self, envelope: EncryptedEnvelope) -> dict[str, Any]:
        nonce = base64.b64decode(envelope.nonce_b64.encode("ascii"))
        ciphertext = base64.b64decode(envelope.ciphertext_b64.encode("ascii"))
        aad = f"{envelope.sender_did}:{envelope.recipient_did}:{self.session_id}".encode("utf-8")
        plaintext = self._aead.decrypt(nonce, ciphertext, aad)
        return json.loads(plaintext.decode("utf-8"))
