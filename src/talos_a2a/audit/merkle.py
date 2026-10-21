from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


def hash_leaf(data: bytes) -> bytes:
    # 0x00 prefix for leaf hash to prevent second-preimage attacks
    return hashlib.sha256(b"\x00" + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    # 0x01 prefix for internal node hash
    return hashlib.sha256(b"\x01" + left + right).digest()


@dataclass
class MerkleReceipt:
    root_hash: str
    leaf_count: int
    leaf_hashes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rootHash": self.root_hash,
            "leafCount": self.leaf_count,
            "leafHashes": self.leaf_hashes,
        }


class MerkleAuditTree:
    """Incremental Merkle audit tree recording task state transitions and artifacts."""

    def __init__(self) -> None:
        self.leaves: list[bytes] = []

    def append_event(self, event_type: str, payload: dict[str, Any]) -> str:
        serialized = json.dumps({"type": event_type, "data": payload}, sort_keys=True).encode("utf-8")
        h = hash_leaf(serialized)
        self.leaves.append(h)
        return h.hex()

    def get_root_hash(self) -> str:
        if not self.leaves:
            return hashlib.sha256(b"empty").hexdigest()
        current_layer = list(self.leaves)
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                if i + 1 < len(current_layer):
                    right = current_layer[i + 1]
                else:
                    right = left
                next_layer.append(hash_node(left, right))
            current_layer = next_layer
        return current_layer[0].hex()

    def generate_receipt(self) -> MerkleReceipt:
        root = self.get_root_hash()
        return MerkleReceipt(
            root_hash=root,
            leaf_count=len(self.leaves),
            leaf_hashes=[l.hex() for l in self.leaves],
        )
