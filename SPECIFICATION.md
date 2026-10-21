# Talos Protocol Trust & Security Layer Specification

**Document Version:** 1.0.0  
**Status:** Implemented  
**Repository:** `talosprotocol/talos-a2a`

---

## 1. Executive Overview

`talos-a2a` provides zero-trust identity, end-to-end encryption (E2EE), capability-based delegation, and tamper-evident audit receipts for the Talos A2A Engine. It ensures that multi-agent interactions across disparate infrastructure are strictly authenticated, confidential, bounded by authorization tokens, and verifiable after execution.

---

## 2. Core Security Primitives

```
+---------------------------------------------------------------------------------+
|                               TALOS-A2A MIDDLEWARE                              |
|                                                                                 |
|   +-------------------+   +--------------------+   +------------------------+   |
|   |   Identity (DID)  |   |    E2EE Channel    |   | Capability Delegation  |   |
|   |  - did:talos:...  |   |  - Forward Secrecy |   | - Scoped actions       |   |
|   |  - Ed25519 Keys   |   |  - ChaCha20-Poly   |   | - Expiration & Quotas  |   |
|   +---------+---------+   +---------+----------+   +-----------+------------+   |
|             |                       |                          |                |
|             +-----------------------+--------------------------+                |
|                                     |                                           |
|                           +---------v----------+                                |
|                           |  Merkle Tree Audit |                                |
|                           |  - SHA-256 Hashes  |                                |
|                           |  - Cryptographic   |                                |
|                           |    Receipts        |                                |
|                           +--------------------+                                |
+---------------------------------------------------------------------------------+
```

---

## 3. Cryptographic Identity (W3C DID)

- **DID Scheme:** `did:talos:<base58_public_key>`
- **Key Pairs:** Ed25519 for digital signatures, authenticating agent-to-agent challenge handshakes and token issuance.
- **Agent Cards:** Exported W3C-compliant DID documents specifying public keys, authentication assertion methods, and supported A2A service endpoints.

---

## 4. End-to-End Encryption (E2EE)

- **Channel Protocol:** Asymmetric key agreement paired with ChaCha20-Poly1305 AEAD authenticated encryption.
- **Envelope Structure:**
  ```json
  {
    "sender_did": "did:talos:8xK...",
    "recipient_did": "did:talos:9yM...",
    "nonce": "<base64_12_bytes>",
    "ciphertext": "<base64_payload>",
    "signature": "<base64_ed25519_signature>"
  }
  ```
- **Forward Secrecy:** Session keys are ephemeral and ratcheted per task transmission to prevent compromise of historical conversations.

---

## 5. Capability-Based Delegation

Rather than giving agents broad permissions, `talos-a2a` introduces cryptographically signed **Capability Tokens**:
- **Fields:**
  - `issuer`: Master/Supervising agent DID.
  - `subject`: Delegated worker agent DID.
  - `allowed_tools`: Whitelist of approved tool/method names (e.g. `["visa_query", "web_search"]`).
  - `max_invocations`: Maximum permitted calls before token exhaustion.
  - `expires_at`: Unix timestamp ceiling.
  - `signature`: Ed25519 signature over the token canonical bytes.

---

## 6. Merkle Audit Receipts

Every dispatched request, task mutation, tool call, and response is hashed into an append-only **Merkle Audit Tree**:
- **Algorithm:** SHA-256 binary tree.
- **Receipts:** Generating a `MerkleReceipt` provides a logarithmic-sized proof of inclusion verifying that an agent action occurred within a given transaction batch without disclosing neighboring task data.
