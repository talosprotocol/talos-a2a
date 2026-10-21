from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from talos_a2a.capability import CapabilityToken
from talos_a2a.identity import TalosDid
from talos_a2a.middleware import TalosA2AMiddleware


@pytest.mark.asyncio
async def test_middleware_audit_logging_and_attestation():
    agent_did = TalosDid.generate("scout-agent")
    middleware = TalosA2AMiddleware(agent_did)

    async def mock_handler(task, emit_status, is_cancelled):
        await emit_status("Step A")
        art = MagicMock()
        art.to_dict.return_value = {"id": "art-1", "name": "Output artifact"}
        return "Task finished", [art]

    wrapped = middleware.wrap_handler(mock_handler)

    task_mock = MagicMock()
    task_mock.id = "task-xyz"
    task_mock.context_id = "ctx-abc"
    task_mock.metadata = {}

    emit_mock = pytest.importorskip("unittest.mock").AsyncMock()
    cancel_mock = MagicMock(return_value=False)

    out_text, artifacts = await wrapped(task_mock, emit_mock, cancel_mock)

    assert out_text == "Task finished"
    assert len(artifacts) == 1
    assert "merkleReceipt" in task_mock.metadata
    assert task_mock.metadata["attestedByDid"] == agent_did.did
    assert task_mock.metadata["merkleReceipt"]["leafCount"] >= 3


@pytest.mark.asyncio
async def test_middleware_capability_enforcement():
    issuer = TalosDid.generate("authority")
    worker = TalosDid.generate("worker")
    middleware = TalosA2AMiddleware(worker)

    token = CapabilityToken.issue(
        issuer=issuer,
        audience_did=worker.did,
        allowed_tools=["allowed_tool_only"],
    )

    async def tool_handler(task, emit_status, is_cancelled):
        return "Executed", []

    # Requires 'forbidden_tool'
    restricted_wrapped = middleware.wrap_handler(tool_handler, required_tool="forbidden_tool")

    task_mock = MagicMock()
    task_mock.id = "task-restricted"
    task_mock.context_id = "ctx-1"
    task_mock.metadata = {"capabilityToken": token.to_compact()}

    with pytest.raises(PermissionError, match="Capability token does not allow tool: forbidden_tool"):
        await restricted_wrapped(task_mock, MagicMock(), MagicMock())
