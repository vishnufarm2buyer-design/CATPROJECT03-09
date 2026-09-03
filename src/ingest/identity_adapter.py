"""
src/ingest/identity_adapter.py
------------------------------
Adapter for identity tool events (Azure AD / Okta / similar).

HOW THIS WORKS:
  1. Inherits BaseAdapter.load() — gets file reading + validation for free.
  2. Declares source_name = "identity" and the required fields for this source.
  3. The normalizer (src/normalize/normalizer.py) later maps these raw fields
     to the CommonEvent schema.

WHAT IT READS:
  Raw identity events look like:
    {
      "userId":     "alice@corp.com",
      "timestamp":  "2024-11-15T08:01:00Z",
      "eventType":  "LOGIN_FAILED",
      "riskLevel":  "medium",
      "sourceIp":   "185.220.101.45",
      "deviceId":   null,           ← OPTIONAL (may be null for pure identity events)
      "sessionId":  null            ← OPTIONAL
    }

REQUIRED FIELDS (events missing these are rejected at ingestion):
  userId, timestamp, eventType, riskLevel

OPTIONAL FIELDS (passed through even if absent/null):
  deviceId, sessionId, sourceIp, location, userAgent
"""

from __future__ import annotations

from src.ingest.base_adapter import BaseAdapter


class IdentityAdapter(BaseAdapter):
    """Adapter for identity-tool (Azure AD / Okta) event files."""

    @property
    def source_name(self) -> str:
        return "identity"

    @property
    def _required_fields(self) -> list[str]:
        # These four fields MUST be present. If any are missing, the event
        # is rejected at load() time and logged as a warning.
        return ["userId", "timestamp", "eventType", "riskLevel"]
