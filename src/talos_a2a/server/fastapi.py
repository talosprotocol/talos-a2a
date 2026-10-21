from __future__ import annotations

from typing import Any

from ..identity.card import build_authenticated_agent_card
from ..identity.did import TalosDid


def mount_agent_card(
    app: Any,
    did: TalosDid,
    name: str,
    description: str,
    skills: list[dict[str, Any]],
    supported_task_modes: list[str] | None = None,
    protocols: list[dict[str, Any]] | None = None,
    extensions: list[str] | None = None,
    endpoints: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Mounts authenticated Agent Card and W3C DID document endpoints on a FastAPI/Starlette app.

    Exposes:
      - GET /.well-known/agent.json
      - GET /.well-known/agent-card.json
      - GET /.well-known/did.json
      - GET /extendedAgentCard
    """
    card = build_authenticated_agent_card(
        did=did,
        name=name,
        description=description,
        skills=skills,
        supported_task_modes=supported_task_modes,
        protocols=protocols,
        extensions=extensions,
        endpoints=endpoints,
    )
    did_doc = did.to_did_document()

    # Define route handler
    async def get_agent_card() -> dict[str, Any]:
        return card

    async def get_did_doc() -> dict[str, Any]:
        return did_doc

    if hasattr(app, "add_api_route"):
        # FastAPI
        app.add_api_route("/.well-known/agent.json", get_agent_card, methods=["GET"], tags=["A2A Discovery"])
        app.add_api_route("/.well-known/agent-card.json", get_agent_card, methods=["GET"], tags=["A2A Discovery"])
        app.add_api_route("/.well-known/did.json", get_did_doc, methods=["GET"], tags=["A2A Discovery"])
        app.add_api_route("/extendedAgentCard", get_agent_card, methods=["GET"], tags=["A2A Discovery"])
    elif hasattr(app, "add_route"):
        # Starlette
        app.add_route("/.well-known/agent.json", get_agent_card, methods=["GET"])
        app.add_route("/.well-known/agent-card.json", get_agent_card, methods=["GET"])
        app.add_route("/.well-known/did.json", get_did_doc, methods=["GET"])
        app.add_route("/extendedAgentCard", get_agent_card, methods=["GET"])

    return card
