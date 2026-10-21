from __future__ import annotations

import base64
import json
from typing import Any

from .did import TalosDid


def build_authenticated_agent_card(
    did: TalosDid,
    name: str,
    description: str,
    skills: list[dict[str, Any]],
    supported_task_modes: list[str] | None = None,
    protocols: list[dict[str, Any]] | None = None,
    extensions: list[str] | None = None,
    endpoints: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generates a cryptographically signed A2A Agent Card."""
    card_body: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://talosprotocol.com/schemas/agent-card/v1.json",
        ],
        "name": name,
        "description": description,
        "did": did.did,
        "version": "1.0.0",
        "protocol": "a2a-v1",
        "supportedTaskModes": supported_task_modes or ["immediate", "streaming", "wait", "get"],
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "extendedAgentCard": True,
            "extensions": extensions or [
                "talos.security.v1",
                "talos.capability.v1",
                "talos.audit.v1",
            ],
        },
        "protocols": protocols or [
            {"protocol": "a2a-v1", "role": "server"},
            {"protocol": "jsonrpc-2.0", "role": "bidirectional"},
        ],
        "skills": skills,
    }

    if endpoints:
        card_body["endpoints"] = endpoints

    serialized = json.dumps(card_body, sort_keys=True).encode("utf-8")
    sig = did.sign(serialized)

    return {
        **card_body,
        "proof": {
            "type": "Ed25519Signature2020",
            "verificationMethod": f"{did.did}#key-1",
            "created": "2026-10-21T00:00:00Z",
            "signature": sig,
        },
    }


def verify_agent_card(
    card: dict[str, Any],
    verifier: TalosDid | bytes | None = None,
) -> bool:
    """Verifies the cryptographic Ed25519 signature on an authenticated Agent Card."""
    if not isinstance(card, dict) or "proof" not in card:
        return False

    proof = card["proof"]
    sig = proof.get("signature")
    if not sig:
        return False

    # Extract body without proof
    body = {k: v for k, v in card.items() if k != "proof"}
    serialized = json.dumps(body, sort_keys=True).encode("utf-8")

    if isinstance(verifier, TalosDid):
        return verifier.verify(serialized, sig)
    elif isinstance(verifier, bytes):
        did_obj = TalosDid.from_public_bytes(verifier, did_str=card.get("did"))
        return did_obj.verify(serialized, sig)

    return False
