"""
src/normalize/schema.py
-----------------------
Defines CommonEvent — the single normalized schema that ALL source events
are mapped into after ingestion.

WHY A COMMON SCHEMA?
  Each security tool has its own field names and formats:
    - Identity tool uses "userId", "eventType", "riskLevel"
    - Endpoint tool uses "hostName", "eventCategory", "alertSeverity"
  If the correlation engine had to handle each tool's format separately,
  adding a new source would require rewriting the correlation logic too.

  By mapping everything to CommonEvent first, the correlation engine only
  needs to understand ONE format. Adding a new source just means writing
  one new adapter + normalizer — the rest of the pipeline is unchanged.

OPTIONAL FIELDS:
  identity_id and asset_id are marked Optional because not every event has both:
    - A network flow event has no user (identity_id = None)
    - A cloud API call may have no device (asset_id = None)
  Setting to None (instead of omitting) makes missing data explicit and
  prevents KeyError bugs in downstream code.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime


# ── Allowed values for the 'source' field ────────────────────────────────────
VALID_SOURCES = {"identity", "endpoint", "email", "network", "cloud"}

# ── Allowed values for the 'severity' field ──────────────────────────────────
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# ── Allowed values for event_type (normalized, source-agnostic) ──────────────
VALID_EVENT_TYPES = {
    # Identity events
    "LOGIN_SUCCESS", "LOGIN_FAILED", "MFA_BYPASS", "PASSWORD_RESET",
    # Endpoint events
    "PROCESS_EXEC", "FILE_WRITE", "NETWORK_CONN",
    # Email events (Phase 2)
    "EMAIL_CLICK", "EMAIL_ATTACHMENT",
    # Network events (Phase 2)
    "DNS_QUERY", "NET_FLOW",
    # Cloud events (Phase 2)
    "CLOUD_API_CALL", "CLOUD_ROLE_ASSUME",
    # Catch-all for unrecognized events (not rejected, just flagged)
    "UNKNOWN",
}


@dataclasses.dataclass
class CommonEvent:
    """
    The normalized representation of any security event from any source.

    After normalization, the correlation engine only sees CommonEvent objects —
    it never looks at raw source-specific dictionaries.

    Fields marked OPTIONAL may be None. The engine handles None gracefully:
    events with identity_id=None are indexed by asset only, and vice versa.
    """

    # ── Required fields ───────────────────────────────────────────────────────
    event_id: str         # UUID assigned at normalization time (not from source)
    timestamp: datetime   # UTC datetime. All sources normalized to UTC.
    source: str           # Which tool: "identity" | "endpoint" | "email" | "network" | "cloud"
    event_type: str       # Normalized category (see VALID_EVENT_TYPES above)
    severity: str         # "low" | "medium" | "high" | "critical"
    raw_payload: dict     # The ORIGINAL unmodified event dict. Always preserved.
                          # If normalization has a bug, raw_payload lets us re-process
                          # without re-ingesting from the source tool.

    # ── Optional fields ───────────────────────────────────────────────────────
    identity_id: str | None = None
    # Who did this? Matches Identity.identity_id. None for events with no user context
    # (e.g., raw network flows, system processes).

    asset_id: str | None = None
    # What device? Matches Asset.asset_id. None for events with no device context
    # (e.g., cloud API calls from a browser session with no source host).

    session_id: str | None = None
    # Links events that occurred within the same authenticated session.
    # OPTIONAL — most tools don't export session IDs. When present, used as a
    # high-confidence join key instead of the time-window heuristic.

    @staticmethod
    def new_id() -> str:
        """Generate a fresh UUID for event_id."""
        return str(uuid.uuid4())

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict (for audit logging and output)."""
        d = dataclasses.asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d
