# talosprotocol/talos-a2a

Cryptographic security, identity, and verifiable trust layer for **Agent-to-Agent (A2A) v1** interactions.

## Features

- **Agent DIDs (`did:talos:agent:...`)**: Cryptographically verifiable agent identifiers derived from Ed25519 signing keys.
- **Double Ratchet E2EE**: End-to-end encrypted messaging channels ensuring forward secrecy and break-in recovery across untrusted brokers.
- **Attenuated Capability Tokens**: UCAN-style capability delegation restricting agent invocation scopes, tool permissions, spending limits, and expiration.
- **Merkle Execution Receipts**: Append-only BLAKE3 Merkle audit tree linking task states, reasoning traces, and emitted artifacts into verifiable cryptographic receipts.
- **A2A Runner Middleware**: Pluggable security middleware wrapping `talosprotocol-a2a` runners with zero-trust verification.
