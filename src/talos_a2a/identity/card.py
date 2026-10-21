from __future__ import annotations

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
) -> dict[str, Any]:
    """Generates a cryptographically signed A2A Agent Card."""
    card_body = {
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
        },
        "protocols": protocols or [
            {"protocol": "a2a-v1", "role": "server"},
            {"protocol": "jsonrpc-2.0", "role": "bidirectional"},
        ],
        "skills": skills,
    }

    serialized = json.dumps(card_body, sort_keys=True).encode("utf-8")
    sig = did.sign(serialized)

    return {
        **card_body,
        "proof": {
            "type": "Ed25519Signature2020",
            "verificationMethod": f"{did.did}#key-1",
            "signature": sig,
        },
    }
