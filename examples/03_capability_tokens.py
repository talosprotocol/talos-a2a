#!/usr/bin/env python3
"""
Example 03: Capability Delegation Tokens.

Demonstrates issuing cryptographically signed capability tokens that restrict
a worker agent's tool access (whitelist), maximum invocations quota, and TTL.
Also demonstrates compact URL-safe serialization and authorization verification.
"""

import sys
from pathlib import Path

# Add src to sys.path so example runs out-of-the-box
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from talos_a2a.capability import CapabilityToken
from talos_a2a.identity import TalosDid


def main() -> None:
    # 1. Establish identities for Supervisor (issuer) and Delegated Worker (audience)
    supervisor = TalosDid.generate(name="supervisor")
    worker = TalosDid.generate(name="scraper-worker")

    print(f"[+] Supervisor DID: {supervisor.did}")
    print(f"[+] Worker DID:     {worker.did}")

    # 2. Issue a scoped Capability Token
    # Whitelist specific tools: 'web_scrape' and 'parse_html' (no database writes or shell access)
    allowed_tools = ["web_scrape", "parse_html"]
    token = CapabilityToken.issue(
        issuer=supervisor,
        audience_did=worker.did,
        allowed_tools=allowed_tools,
        ttl_seconds=1800,       # 30-minute validity
        max_invocations=25,     # Quota: 25 executions max
        metadata={"project": "q3_market_research", "cost_center": "ops_410"}
    )

    print("\n[*] Capability Token Issued:")
    print(f"    Issuer:          {token.issuer_did}")
    print(f"    Audience:        {token.audience_did}")
    print(f"    Allowed Tools:   {token.allowed_tools}")
    print(f"    Max Invocations: {token.max_invocations}")
    print(f"    Expires At:      {token.expires_at}")
    print(f"    Signature:       {token.signature_b64[:32]}...")

    # 3. Cryptographic Verification
    is_valid = token.verify(supervisor)
    print(f"\n[+] Token Cryptographic Verification against Supervisor: {is_valid}")

    # 4. Verify tool authorization checks
    test_tools = ["web_scrape", "parse_html", "drop_tables", "run_bash_command"]
    print("\n[*] Tool Permission Checks:")
    for tool in test_tools:
        permitted = token.allows_tool(tool)
        status_sym = "[ALLOWED]" if permitted else "[DENIED]"
        print(f"    {status_sym:9} -> {tool}")

    # 5. Compact Serialization (for HTTP Headers / JSON-RPC metadata)
    compact_token = token.to_compact()
    print(f"\n[*] Compact Token (URL-safe base64, len={len(compact_token)}):")
    print(f"    {compact_token[:48]}...{compact_token[-16:]}")

    # 6. Deserialization & Re-verification on remote worker node
    restored_token = CapabilityToken.from_compact(compact_token)
    print(f"\n[+] Deserialized Token on Worker Node:")
    print(f"    Matches Original: {restored_token.issuer_did == token.issuer_did}")
    print(f"    Valid Signature:  {restored_token.verify(supervisor)}")


if __name__ == "__main__":
    main()
