#!/usr/bin/env python3
"""
Example 01: Decentralized Identity (DID) & Authenticated W3C Agent Cards.

Demonstrates generating an Ed25519-backed Talos DID, signing/verifying payloads,
and generating a cryptographically attested W3C Agent Card for agent discovery.
"""

import json
import sys
from pathlib import Path

# Add src to sys.path so example runs out-of-the-box
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from talos_a2a.identity import TalosDid, build_authenticated_agent_card


def main() -> None:
    # 1. Generate an Ed25519 identity for an autonomous auditing agent
    auditor = TalosDid.generate(name="auditor")
    print(f"[+] Generated Agent DID: {auditor.did}")

    # 2. Export W3C DID Document
    did_doc = auditor.to_did_document()
    print("\n[*] W3C DID Document:")
    print(json.dumps(did_doc, indent=2))

    # 3. Sign and verify an arbitrary payload
    payload = b"Authorize transfer of 500 ComputeCredits to node-alpha"
    signature = auditor.sign(payload)
    print(f"\n[+] Digital Signature (b64): {signature[:32]}... (len={len(signature)} chars)")

    valid = auditor.verify(payload, signature)
    print(f"[+] Signature verification on original payload: {valid}")

    tampered_valid = auditor.verify(payload + b"!", signature)
    print(f"[-] Signature verification on tampered payload: {tampered_valid}")

    # 4. Generate a signed, authenticated Agent Card (for A2A discovery)
    agent_card = build_authenticated_agent_card(
        did=auditor,
        name="Talos Auditor Node",
        description="Autonomous security auditor verifying Merkle trees and cryptographic receipts.",
        skills=[
            {"id": "merkle_verify", "name": "Merkle Verifier", "description": "Validates SHA-256 audit roots"},
            {"id": "anomaly_scan", "name": "Anomaly Scanner", "description": "Scans A2A task traces for integrity breaches"}
        ]
    )

    print("\n[*] Attested W3C Agent Card:")
    print(json.dumps(agent_card, indent=2))


if __name__ == "__main__":
    main()
