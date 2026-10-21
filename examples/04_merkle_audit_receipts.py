#!/usr/bin/env python3
"""
Example 04: Merkle Audit Trees & Cryptographic Receipts.

Demonstrates recording append-only agent events (task creation, status transitions,
tool outputs, emitted artifacts) into an RFC-compliant Merkle Tree, computing
tamper-evident SHA-256 root hashes, and generating verifiable audit receipts.
"""

import json
import sys
from pathlib import Path

# Add src to sys.path so example runs out-of-the-box
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from talos_a2a.audit import MerkleAuditTree, MerkleReceipt


def main() -> None:
    print("[*] Initializing Merkle Audit Tree...")
    tree = MerkleAuditTree()

    # 1. Record task initialization
    h1 = tree.append_event("task_created", {
        "taskId": "task-audit-901",
        "contextId": "ctx-financial-settlement",
        "sender": "did:talos:agent:treasury:1111"
    })
    print(f"[+] Appended event 'task_created' -> Leaf Hash: {h1[:24]}...")

    # 2. Record intermediate working states & tool executions
    h2 = tree.append_event("tool_invoked", {
        "tool": "verify_bank_wire",
        "reference_id": "WIRE-88921-X",
        "amount": 100000.00
    })
    print(f"[+] Appended event 'tool_invoked'  -> Leaf Hash: {h2[:24]}...")

    h3 = tree.append_event("artifact_emitted", {
        "name": "wire_confirmation_pdf",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    })
    print(f"[+] Appended event 'artifact_emitted' -> Leaf Hash: {h3[:24]}...")

    # 3. Record task completion
    h4 = tree.append_event("task_completed", {
        "state": "COMPLETED",
        "completion_timestamp": 1792550999
    })
    print(f"[+] Appended event 'task_completed' -> Leaf Hash: {h4[:24]}...")

    # 4. Generate Merkle Audit Receipt
    receipt = tree.generate_receipt()
    print("\n[*] Cryptographic Merkle Receipt Generated:")
    print(f"    Total Leaves: {receipt.leaf_count}")
    print(f"    Merkle Root:  {receipt.root_hash}")
    print("\nReceipt JSON Payload:")
    print(json.dumps(receipt.to_dict(), indent=2))

    # 5. Verify determinism: Independent validator recalculates root
    print("\n[*] Independent Auditor verifying batch...")
    auditor_tree = MerkleAuditTree()
    auditor_tree.append_event("task_created", {
        "taskId": "task-audit-901",
        "contextId": "ctx-financial-settlement",
        "sender": "did:talos:agent:treasury:1111"
    })
    auditor_tree.append_event("tool_invoked", {
        "tool": "verify_bank_wire",
        "reference_id": "WIRE-88921-X",
        "amount": 100000.00
    })
    auditor_tree.append_event("artifact_emitted", {
        "name": "wire_confirmation_pdf",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    })
    auditor_tree.append_event("task_completed", {
        "state": "COMPLETED",
        "completion_timestamp": 1792550999
    })

    verified_root = auditor_tree.get_root_hash()
    print(f"[+] Auditor Root Hash: {verified_root}")
    print(f"[+] Match Success:     {verified_root == receipt.root_hash}")


if __name__ == "__main__":
    main()
