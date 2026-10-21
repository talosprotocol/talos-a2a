#!/usr/bin/env python3
"""
Example 05: Secure A2A Task Middleware with Auditing & Capability Enforcement.

Demonstrates integrating `TalosA2AMiddleware` into an A2A task execution pipeline:
- Intercepting incoming tasks
- Enforcing signed capability delegation tokens
- Automatically recording every execution step into a Merkle audit tree
- Cryptographically attesting results with the agent's DID and attaching receipts to metadata
"""

import asyncio
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

# Add src to sys.path so example runs out-of-the-box
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from talos_a2a.capability import CapabilityToken
from talos_a2a.identity import TalosDid
from talos_a2a.middleware import TalosA2AMiddleware


@dataclass
class MockArtifact:
    name: str
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "data": self.data}


@dataclass
class MockTask:
    id: str
    context_id: str
    metadata: dict[str, Any] = field(default_factory=dict)


async def main() -> None:
    # 1. Initialize Authority (issuer) and Worker (executor)
    authority = TalosDid.generate(name="compliance-authority")
    worker = TalosDid.generate(name="database-migrator")

    # 2. Attach security middleware to worker
    middleware = TalosA2AMiddleware(agent_did=worker)

    # 3. Define the actual task business logic
    async def database_migration_handler(task, emit_status, is_cancelled):
        await emit_status("Validating schema compatibility")
        await emit_status("Migrating customer partitions to sharded cluster")

        artifact = MockArtifact(
            name="migration_summary",
            data={"rows_migrated": 42000, "integrity_checksum": "9f83ac..."}
        )
        return "Migration completed successfully.", [artifact]

    # 4. Wrap handler requiring 'sharded_migration' capability
    secured_handler = middleware.wrap_handler(
        database_migration_handler,
        required_tool="sharded_migration"
    )

    # Test Case A: Execution WITHOUT capability token -> Access Denied
    print("[*] Case A: Disagreeing invocation with unauthorized token...")
    unauthorized_token = CapabilityToken.issue(
        issuer=authority,
        audience_did=worker.did,
        allowed_tools=["read_only_schema_view"]  # Does not include 'sharded_migration'
    )

    task_unauthorized = MockTask(
        id="task-tx-001",
        context_id="ctx-db-1",
        metadata={"capabilityToken": unauthorized_token.to_compact()}
    )

    try:
        await secured_handler(task_unauthorized, emit_status=lambda m, d: asyncio.sleep(0), is_cancelled=lambda: False)
        print("[-] SECURITY FAILURE: Unauthorized tool was allowed!")
    except PermissionError as exc:
        print(f"[+] Security Verified: Execution blocked ({exc})")

    # Test Case B: Execution WITH valid capability token
    print("\n[*] Case B: Invocation with valid capability token...")
    authorized_token = CapabilityToken.issue(
        issuer=authority,
        audience_did=worker.did,
        allowed_tools=["sharded_migration", "read_only_schema_view"]
    )

    task_authorized = MockTask(
        id="task-tx-002",
        context_id="ctx-db-1",
        metadata={"capabilityToken": authorized_token.to_compact()}
    )

    async def log_status(msg, details):
        print(f"    -> [STATUS]: {msg}")

    result_text, artifacts = await secured_handler(
        task_authorized,
        emit_status=log_status,
        is_cancelled=lambda: False
    )

    print(f"\n[+] Task Completed: {result_text}")
    print(f"    Artifacts Emitted: {artifacts[0].name}")

    # Inspect cryptographic attestations attached by TalosA2AMiddleware
    receipt = task_authorized.metadata["merkleReceipt"]
    attested_did = task_authorized.metadata["attestedByDid"]
    print(f"\n[*] Cryptographic Attestation Metadata:")
    print(f"    Attested By DID: {attested_did}")
    print(f"    Merkle Root:     {receipt['rootHash']}")
    print(f"    Leaves Audited:  {receipt['leafCount']}")


if __name__ == "__main__":
    asyncio.run(main())
