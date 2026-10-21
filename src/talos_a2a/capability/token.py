from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..identity.did import TalosDid


@dataclass
class CapabilityToken:
    issuer_did: str
    audience_did: str
    allowed_tools: list[str]
    max_invocations: int
    expires_at: int
    signature_b64: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def issue(
        cls,
        issuer: TalosDid,
        audience_did: str,
        allowed_tools: list[str],
        ttl_seconds: int = 3600,
        max_invocations: int = 100,
        metadata: dict[str, Any] | None = None,
    ) -> CapabilityToken:
        now = int(time.time())
        expires = now + ttl_seconds
        payload = {
            "iss": issuer.did,
            "aud": audience_did,
            "tools": sorted(allowed_tools),
            "max": max_invocations,
            "exp": expires,
            "meta": metadata or {},
        }
        serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = issuer.sign(serialized)
        return cls(
            issuer_did=issuer.did,
            audience_did=audience_did,
            allowed_tools=allowed_tools,
            max_invocations=max_invocations,
            expires_at=expires,
            signature_b64=sig,
            metadata=metadata or {},
        )

    def verify(self, issuer: TalosDid) -> bool:
        if issuer.did != self.issuer_did:
            return False
        if time.time() > self.expires_at:
            return False

        payload = {
            "iss": self.issuer_did,
            "aud": self.audience_did,
            "tools": sorted(self.allowed_tools),
            "max": self.max_invocations,
            "exp": self.expires_at,
            "meta": self.metadata,
        }
        serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
        return issuer.verify(serialized, self.signature_b64)

    def allows_tool(self, tool_name: str) -> bool:
        if "*" in self.allowed_tools:
            return True
        return tool_name in self.allowed_tools

    def to_compact(self) -> str:
        d = {
            "iss": self.issuer_did,
            "aud": self.audience_did,
            "tools": self.allowed_tools,
            "max": self.max_invocations,
            "exp": self.expires_at,
            "sig": self.signature_b64,
            "meta": self.metadata,
        }
        return base64.urlsafe_b64encode(json.dumps(d).encode("utf-8")).decode("ascii")

    @classmethod
    def from_compact(cls, compact_str: str) -> CapabilityToken:
        raw = base64.urlsafe_b64decode(compact_str.encode("ascii")).decode("utf-8")
        d = json.loads(raw)
        return cls(
            issuer_did=d["iss"],
            audience_did=d["aud"],
            allowed_tools=d["tools"],
            max_invocations=d["max"],
            expires_at=d["exp"],
            signature_b64=d["sig"],
            metadata=d.get("meta", {}),
        )
