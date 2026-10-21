from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass
class TalosDid:
    did: str
    signing_public_key: ed25519.Ed25519PublicKey
    signing_private_key: ed25519.Ed25519PrivateKey | None = None

    @classmethod
    def generate(cls, name: str = "agent") -> TalosDid:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        raw_pub = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        fingerprint = hashlib.sha256(raw_pub).hexdigest()[:32]
        did_str = f"did:talos:agent:{name}:{fingerprint}"
        return cls(
            did=did_str,
            signing_public_key=public_key,
            signing_private_key=private_key,
        )

    def sign(self, data: bytes) -> str:
        if not self.signing_private_key:
            raise RuntimeError("Private key unavailable for signing")
        sig = self.signing_private_key.sign(data)
        return base64.b64encode(sig).decode("ascii")

    def verify(self, data: bytes, signature_b64: str) -> bool:
        sig = base64.b64decode(signature_b64.encode("ascii"))
        try:
            self.signing_public_key.verify(sig, data)
            return True
        except Exception:
            return False

    def export_public_bytes(self) -> bytes:
        return self.signing_public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

    def to_did_document(self) -> dict[str, Any]:
        pub_b64 = base64.b64encode(self.export_public_bytes()).decode("ascii")
        return {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": self.did,
            "verificationMethod": [
                {
                    "id": f"{self.did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": self.did,
                    "publicKeyMultibase": f"z{pub_b64}",
                }
            ],
            "authentication": [f"{self.did}#key-1"],
            "assertionMethod": [f"{self.did}#key-1"],
        }
