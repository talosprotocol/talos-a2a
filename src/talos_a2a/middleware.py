from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from .audit.merkle import MerkleAuditTree
from .capability.token import CapabilityToken
from .identity.did import TalosDid

LOGGER = logging.getLogger(__name__)


class TalosA2AMiddleware:
    def __init__(self, agent_did: TalosDid) -> None:
        self.agent_did = agent_did
        self._audit_trees: dict[str, MerkleAuditTree] = {}

    def get_audit_tree(self, task_id: str) -> MerkleAuditTree:
        if task_id not in self._audit_trees:
            self._audit_trees[task_id] = MerkleAuditTree()
        return self._audit_trees[task_id]

    def wrap_handler(
        self,
        handler: Callable[[Any, Callable[[str, dict[str, Any] | None], Awaitable[None]], Callable[[], bool]], Awaitable[tuple[str, list[Any]]]],
        required_tool: str | None = None,
    ) -> Callable[[Any, Callable[[str, dict[str, Any] | None], Awaitable[None]], Callable[[], bool]], Awaitable[tuple[str, list[Any]]]]:
        """Wraps an A2A task handler with Talos capability enforcement and Merkle audit logging."""

        async def wrapped(
            task: Any,
            emit_status: Callable[[str, dict[str, Any] | None], Awaitable[None]],
            is_cancelled: Callable[[], bool],
        ) -> tuple[str, list[Any]]:
            audit = self.get_audit_tree(task.id)

            # 1. Capability Verification (if token provided in metadata)
            cap_compact = (task.metadata or {}).get("capabilityToken")
            if cap_compact:
                try:
                    token = CapabilityToken.from_compact(cap_compact)
                    if required_tool and not token.allows_tool(required_tool):
                        raise PermissionError(f"Capability token does not allow tool: {required_tool}")
                    audit.append_event("capability_verified", {"iss": token.issuer_did, "aud": token.audience_did})
                except Exception as exc:
                    LOGGER.warning("Capability token rejected for task %s: %s", task.id, exc)
                    raise

            audit.append_event("task_started", {"taskId": task.id, "contextId": task.context_id})

            async def audited_emit_status(step_msg: str, details: dict[str, Any] | None = None) -> None:
                audit.append_event("status_update", {"message": step_msg, "details": details})
                await emit_status(step_msg, details)

            output_text, artifacts = await handler(task, audited_emit_status, is_cancelled)

            for art in artifacts:
                art_dict = art.to_dict() if hasattr(art, "to_dict") else {}
                audit.append_event("artifact_emitted", art_dict)

            receipt = audit.generate_receipt()
            task.metadata["merkleReceipt"] = receipt.to_dict()
            task.metadata["attestedByDid"] = self.agent_did.did

            return output_text, artifacts

        return wrapped
