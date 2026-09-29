"""
src/normalize/normalizer.py
---------------------------
Maps raw source-specific event dicts → CommonEvent objects.

WHY THIS IS THE MOST IMPORTANT MODULE:
  This is where the "common language" is established. After normalization,
  the entire rest of the pipeline — entity resolution, correlation, audit —
  speaks only CommonEvent. No other module ever looks at raw tool-specific dicts.

HOW FIELD MAPPING WORKS:
  Each source has different field names for the same concepts:
    - Identity tool: "userId"     → CommonEvent.identity_id
    - Endpoint tool: "loggedOnUser" → CommonEvent.identity_id
    - Identity tool: "riskLevel"  → CommonEvent.severity  (mapped via severity map)
    - Endpoint tool: "alertSeverity" → CommonEvent.severity (mapped via severity map)

  Source-specific mapping is isolated in _IDENTITY_MAP and _ENDPOINT_MAP.
  Adding a Phase 2 source means adding one new map here — nothing else changes.

TIMESTAMP HANDLING:
  All timestamps are parsed to timezone-aware UTC datetime objects.
  This ensures that events from tools in different timezones can be compared.

MALFORMED EVENTS:
  If normalization fails (e.g., unparseable timestamp), the event is rejected
  and a NormalizationError is logged. The caller (main.py) logs this to the
  audit trail and continues.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.normalize.schema import (
    VALID_EVENT_TYPES,
    VALID_SEVERITIES,
    VALID_SOURCES,
    CommonEvent,
)

logger = logging.getLogger(__name__)


# ── Severity mapping tables ───────────────────────────────────────────────────
# Each source tool uses its own severity labels. Map them to our four-level scale.

_IDENTITY_SEVERITY_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    # Some tools use numeric or alternative labels:
    "info": "low",
    "warning": "medium",
    "error": "high",
}

_ENDPOINT_SEVERITY_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "informational": "low",
    "moderate": "medium",
}

# ── Event-type mapping tables ─────────────────────────────────────────────────
# Map source-specific event category strings to our normalized event_type values.

_IDENTITY_EVENT_TYPE_MAP = {
    "LOGIN_SUCCESS": "LOGIN_SUCCESS",
    "LOGIN_FAILED": "LOGIN_FAILED",
    "MFA_BYPASS": "MFA_BYPASS",
    "PASSWORD_RESET": "PASSWORD_RESET",
    "SIGN_IN_SUCCESS": "LOGIN_SUCCESS",   # Azure AD variant
    "SIGN_IN_FAILURE": "LOGIN_FAILED",    # Azure AD variant
    "INTERACTIVE_USER_SIGN_IN": "LOGIN_SUCCESS",
}

_ENDPOINT_EVENT_TYPE_MAP = {
    "PROCESS_EXEC": "PROCESS_EXEC",
    "FILE_WRITE": "FILE_WRITE",
    "NETWORK_CONN": "NETWORK_CONN",
    "ProcessCreate": "PROCESS_EXEC",      # Sysmon variant
    "FileCreate": "FILE_WRITE",           # Sysmon variant
    "NetworkConnect": "NETWORK_CONN",     # Sysmon variant
}


_EMAIL_SEVERITY_MAP = {
    "low": "low", "medium": "medium", "high": "high", "critical": "critical",
    "info": "low", "warning": "medium",
}

_EMAIL_EVENT_TYPE_MAP = {
    "EMAIL_DELIVERED": "EMAIL_DELIVERED",
    "EMAIL_CLICK": "EMAIL_CLICK",
    "PHISHING_CLICK": "EMAIL_CLICK",  # Normalize phishing click to EMAIL_CLICK
    "EMAIL_ATTACHMENT": "EMAIL_ATTACHMENT",
    "LINK_CLICK": "EMAIL_CLICK",
}

class NormalizationError(Exception):
    """Raised when an event cannot be normalized."""


def _parse_timestamp(ts_str: str) -> datetime:
    """
    Parse an ISO-8601 timestamp string to a UTC-aware datetime.

    Handles the common case where 'Z' suffix means UTC.
    Raises ValueError if the string cannot be parsed.
    """
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts_str)
    # Ensure timezone-aware (assume UTC if naive)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize(raw: dict, source: str) -> CommonEvent:
    """
    Normalize a raw event dict from the given source into a CommonEvent.

    Args:
        raw:    Raw event dict (as loaded by an adapter).
        source: Source label — must be in VALID_SOURCES.

    Returns:
        CommonEvent

    Raises:
        NormalizationError: if the event cannot be normalized (bad timestamp,
                            unknown source, etc.).
    """
    if source not in VALID_SOURCES:
        raise NormalizationError(f"Unknown source: {source!r}")

    try:
        if source == "identity":
            return _normalize_identity(raw)
        elif source == "endpoint":
            return _normalize_endpoint(raw)
        elif source == "email":
            return _normalize_email(raw)
        else:
            # Phase 2 sources: network, cloud
            raise NormalizationError(
                f"Normalizer for source {source!r} not yet implemented (Phase 2)"
            )
    except (KeyError, ValueError, TypeError) as exc:
        raise NormalizationError(f"Failed to normalize {source} event: {exc}") from exc


def _normalize_identity(raw: dict) -> CommonEvent:
    """
    Map an identity-tool raw event to CommonEvent.

    Field mapping:
      userId        → identity_id
      timestamp     → timestamp  (parsed to UTC)
      eventType     → event_type (via lookup table)
      riskLevel     → severity   (via lookup table)
      deviceId      → asset_id   (OPTIONAL, may be None)
      sessionId     → session_id (OPTIONAL, may be None)
    """
    try:
        timestamp = _parse_timestamp(raw["timestamp"])
    except (ValueError, KeyError) as exc:
        raise NormalizationError(f"Invalid timestamp: {exc}") from exc

    raw_event_type = raw.get("eventType", "UNKNOWN")
    event_type = _IDENTITY_EVENT_TYPE_MAP.get(raw_event_type, "UNKNOWN")
    if event_type not in VALID_EVENT_TYPES:
        logger.warning("Unknown identity event type %r — mapping to UNKNOWN", raw_event_type)
        event_type = "UNKNOWN"

    raw_severity = str(raw.get("riskLevel", "low")).lower()
    severity = _IDENTITY_SEVERITY_MAP.get(raw_severity, "low")
    if severity not in VALID_SEVERITIES:
        severity = "low"

    return CommonEvent(
        event_id=CommonEvent.new_id(),
        timestamp=timestamp,
        source="identity",
        event_type=event_type,
        severity=severity,
        raw_payload=dict(raw),
        identity_id=raw.get("userId") or None,
        asset_id=raw.get("deviceId") or None,      # OPTIONAL
        session_id=raw.get("sessionId") or None,   # OPTIONAL
    )


def _normalize_endpoint(raw: dict) -> CommonEvent:
    """
    Map an endpoint-tool raw event to CommonEvent.

    Field mapping:
      hostName        → asset_id   (hostname used as stable asset identifier)
      timestamp       → timestamp  (parsed to UTC)
      eventCategory   → event_type (via lookup table)
      alertSeverity   → severity   (via lookup table)
      loggedOnUser    → identity_id (OPTIONAL — None for system processes)
    """
    try:
        timestamp = _parse_timestamp(raw["timestamp"])
    except (ValueError, KeyError) as exc:
        raise NormalizationError(f"Invalid timestamp: {exc}") from exc

    raw_event_type = raw.get("eventCategory", "UNKNOWN")
    event_type = _ENDPOINT_EVENT_TYPE_MAP.get(raw_event_type, "UNKNOWN")
    if event_type not in VALID_EVENT_TYPES:
        logger.warning("Unknown endpoint event type %r — mapping to UNKNOWN", raw_event_type)
        event_type = "UNKNOWN"

    raw_severity = str(raw.get("alertSeverity", "low")).lower()
    severity = _ENDPOINT_SEVERITY_MAP.get(raw_severity, "low")
    if severity not in VALID_SEVERITIES:
        severity = "low"

    return CommonEvent(
        event_id=CommonEvent.new_id(),
        timestamp=timestamp,
        source="endpoint",
        event_type=event_type,
        severity=severity,
        raw_payload=dict(raw),
        identity_id=raw.get("loggedOnUser") or None,  # OPTIONAL
        asset_id=raw.get("hostName") or None,
        session_id=None,   # Endpoint tool doesn't export session IDs in Phase 1
    )


def _normalize_email(raw: dict) -> CommonEvent:
    """
    Map an email-tool raw event to CommonEvent.

    Field mapping:
      recipient     → identity_id
      timestamp     → timestamp  (parsed to UTC)
      eventType     → event_type (via lookup table)
      severity      → severity   (via lookup table)
    """
    try:
        timestamp = _parse_timestamp(raw["timestamp"])
    except (ValueError, KeyError) as exc:
        raise NormalizationError(f"Invalid timestamp: {exc}") from exc

    raw_event_type = raw.get("eventType", "UNKNOWN")
    event_type = _EMAIL_EVENT_TYPE_MAP.get(raw_event_type, "UNKNOWN")
    if event_type not in VALID_EVENT_TYPES:
        logger.warning("Unknown email event type %r — mapping to UNKNOWN", raw_event_type)
        event_type = "UNKNOWN"

    raw_severity = str(raw.get("severity", "low")).lower()
    severity = _EMAIL_SEVERITY_MAP.get(raw_severity, "low")
    if severity not in VALID_SEVERITIES:
        severity = "low"

    return CommonEvent(
        event_id=CommonEvent.new_id(),
        timestamp=timestamp,
        source="email",
        event_type=event_type,
        severity=severity,
        raw_payload=dict(raw),
        identity_id=raw.get("recipient") or None,
        asset_id=None,
        session_id=None,
    )
