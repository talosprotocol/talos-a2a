from __future__ import annotations

from talos_a2a.audit import MerkleAuditTree


def test_merkle_audit_tree():
    tree = MerkleAuditTree()

    tree.append_event("task_created", {"taskId": "t-100"})
    tree.append_event("status_working", {"step": "vector search"})
    tree.append_event("artifact_emitted", {"art": "matches"})
    tree.append_event("task_completed", {"output": "Done"})

    receipt = tree.generate_receipt()
    assert receipt.leaf_count == 4
    assert len(receipt.leaf_hashes) == 4
    assert receipt.root_hash != ""

    # Tree root must be deterministic
    tree2 = MerkleAuditTree()
    tree2.append_event("task_created", {"taskId": "t-100"})
    tree2.append_event("status_working", {"step": "vector search"})
    tree2.append_event("artifact_emitted", {"art": "matches"})
    tree2.append_event("task_completed", {"output": "Done"})

    assert tree2.get_root_hash() == receipt.root_hash
