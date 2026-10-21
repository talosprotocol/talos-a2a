from typing import Any

from talos_a2a import (
    TalosDid,
    build_authenticated_agent_card,
    mount_agent_card,
    verify_agent_card,
)


def test_authenticated_agent_card_verification() -> None:
    # 1. Generate DID
    did = TalosDid.generate(name="scout")

    # 2. Build signed card
    card = build_authenticated_agent_card(
        did=did,
        name="Visa Scout",
        description="Edge slot monitor",
        skills=[{"id": "scout:slots", "name": "Slot Scout"}],
        extensions=["talos.security.v1", "talos.audit.v1"],
        endpoints={"rpc": "http://localhost:8000/rpc"},
    )

    # 3. Verify with correct DID
    assert verify_agent_card(card, verifier=did) is True

    # 4. Verify with public bytes
    pub_bytes = did.export_public_bytes()
    assert verify_agent_card(card, verifier=pub_bytes) is True

    # 5. Tampered card must fail verification
    tampered_card = dict(card)
    tampered_card["description"] = "Tampered description"
    assert verify_agent_card(tampered_card, verifier=did) is False

    # 6. Different DID must fail verification
    other_did = TalosDid.generate(name="other")
    assert verify_agent_card(card, verifier=other_did) is False


def test_mount_agent_card_mock_app() -> None:
    did = TalosDid.generate(name="fastapi-agent")

    class MockApp:
        def __init__(self) -> None:
            self.routes: dict[str, Any] = {}

        def add_api_route(self, path: str, endpoint: Any, methods: list[str], **kwargs: Any) -> None:
            self.routes[path] = endpoint

    app = MockApp()
    card = mount_agent_card(
        app=app,
        did=did,
        name="FastAPI Agent",
        description="Mounted on FastAPI",
        skills=[{"id": "test_skill", "name": "Test"}],
    )

    assert "/.well-known/agent.json" in app.routes
    assert "/.well-known/did.json" in app.routes
    assert "/extendedAgentCard" in app.routes
    assert card["name"] == "FastAPI Agent"
