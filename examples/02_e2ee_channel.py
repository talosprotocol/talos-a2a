#!/usr/bin/env python3
"""
Example 02: End-to-End Encrypted (E2EE) Channel using ChaCha20-Poly1305.

Demonstrates creating a forward-secret encrypted session between two agents,
encrypting structured A2A task envelopes, verifying tamper resistance with
Authenticated Additional Data (AAD), and decrypting payloads.
"""

import json
import sys
from pathlib import Path

# Add src to sys.path so example runs out-of-the-box
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from talos_a2a.encryption import E2EESession, EncryptedEnvelope
from talos_a2a.identity import TalosDid


def main() -> None:
    # 1. Initialize two agent identities
    alice = TalosDid.generate(name="alice-planner")
    bob = TalosDid.generate(name="bob-executor")

    print(f"[+] Alice DID: {alice.did}")
    print(f"[+] Bob DID:   {bob.did}")

    # 2. Negotiate an E2EE session with ephemeral 256-bit symmetric key
    session = E2EESession.create()
    print(f"\n[*] Established E2EE Session ID: {session.session_id}")

    # 3. Prepare confidential task payload
    confidential_task = {
        "action": "execute_private_liquidity_swap",
        "parameters": {
            "token_in": "USDC",
            "token_out": "ETH",
            "amount_in": 250000.0,
            "slippage_tolerance_bps": 15,
            "private_rpc": "https://secure-mev-protect.internal/v1"
        },
        "deadline_block": 21894020
    }

    # 4. Encrypt payload with ChaCha20-Poly1305 AEAD bound to sender/recipient DIDs
    envelope = session.encrypt_payload(
        payload=confidential_task,
        sender_did=alice.did,
        recipient_did=bob.did
    )

    print("\n[*] Encrypted Transmission Envelope:")
    print(json.dumps(envelope.to_dict(), indent=2))

    # 5. Bob receives and decrypts the envelope
    decrypted_task = session.decrypt_payload(envelope)
    print("\n[+] Successfully decrypted by recipient:")
    print(f"    Action: {decrypted_task['action']}")
    print(f"    Amount: {decrypted_task['parameters']['amount_in']} {decrypted_task['parameters']['token_in']}")

    # 6. Verify tamper-resistance: Attempt MITM attack modifying recipient DID
    print("\n[*] Simulating MITM tampering attack (modifying recipient DID)...")
    tampered_envelope = EncryptedEnvelope.from_dict(envelope.to_dict())
    tampered_envelope.recipient_did = "did:talos:agent:mallory-attacker:9999"

    try:
        session.decrypt_payload(tampered_envelope)
        print("[-] SECURITY FAILURE: Tampered envelope decrypted!")
    except Exception as exc:
        print(f"[+] Security Verified: Tampered envelope rejected by AEAD MAC check ({type(exc).__name__})")


if __name__ == "__main__":
    main()
