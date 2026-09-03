"""
tests/test_malformed_event.py
-----------------------------
Edge Case 3: Malformed or incomplete events from a source.

WHAT WE'RE TESTING:
  Security tools sometimes emit malformed events:
  - A field name changed in a tool update (schema drift)
  - A network interruption mid-transmission truncated the JSON
  - A new event type was introduced that the adapter doesn't know about
  - A required field has an unexpected type (e.g., timestamp is an integer)

  The engine must:
  1. Reject the malformed event gracefully (not crash)
  2. Continue processing the remaining valid events
  3. Log the rejection (for debugging — this is the "audit trail" test too)

  This implements Risk R4 (schema drift) mitigation from the risk register.

SCENARIOS TESTED:
  1. Event missing a required field (e.g., no "userId" in identity event)
  2. Event with an unparseable timestamp (wrong format)
  3. Event that is not a dict (null, string, integer)
  4. Event with a valid schema but unknown event_type → mapped to UNKNOWN, NOT rejected
  5. Mix of valid and malformed events → valid ones still processed correctly
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingest.identity_adapter import IdentityAdapter
from src.ingest.endpoint_adapter import EndpointAdapter
from src.normalize.normalizer import NormalizationError, normalize
from src.normalize.schema import CommonEvent


# ── Test 1: Adapter rejects event missing required field ─────────────────────

def test_adapter_rejects_event_missing_required_field(tmp_path):
    """
    An identity event missing the required 'userId' field must be rejected
    at the adapter (load) stage and NOT passed to normalization.
    """
    import json

    # Write a JSON file with one valid and one malformed event
    events = [
        {
            "userId": "valid_user@corp.com",
            "timestamp": "2024-11-15T08:00:00Z",
            "eventType": "LOGIN_SUCCESS",
            "riskLevel": "low",
        },
        {
            # Missing 'userId' — required field
            "timestamp": "2024-11-15T08:01:00Z",
            "eventType": "LOGIN_FAILED",
            "riskLevel": "high",
        },
    ]
    test_file = tmp_path / "test_identity.json"
    test_file.write_text(json.dumps(events))

    adapter = IdentityAdapter()
    result = adapter.load(test_file)

    # Only the valid event should be returned
    assert len(result) == 1, f"Expected 1 valid event, got {len(result)}"
    assert result[0]["userId"] == "valid_user@corp.com"


# ── Test 2: Normalizer raises on unparseable timestamp ───────────────────────

def test_normalizer_raises_on_bad_timestamp():
    """
    An event with a malformed timestamp must raise NormalizationError,
    NOT silently produce a CommonEvent with a wrong timestamp.
    """
    malformed_event = {
        "userId": "alice@corp.com",
        "timestamp": "NOT-A-DATE",  # ← unparseable
        "eventType": "LOGIN_FAILED",
        "riskLevel": "high",
    }
    with pytest.raises(NormalizationError, match="Invalid timestamp"):
        normalize(malformed_event, "identity")


# ── Test 3: Adapter skips non-dict items ─────────────────────────────────────

def test_adapter_skips_non_dict_items(tmp_path):
    """
    A JSON array containing non-dict items (null, string, number) must have
    those items silently skipped. The adapter must not crash.
    """
    import json

    events = [
        {"userId": "u@corp.com", "timestamp": "2024-01-01T00:00:00Z",
         "eventType": "LOGIN_SUCCESS", "riskLevel": "low"},
        None,         # ← null
        "bad string", # ← string instead of object
        42,           # ← integer
        {"userId": "u2@corp.com", "timestamp": "2024-01-01T00:01:00Z",
         "eventType": "LOGIN_FAILED", "riskLevel": "low"},
    ]
    test_file = tmp_path / "mixed.json"
    test_file.write_text(json.dumps(events))

    adapter = IdentityAdapter()
    result = adapter.load(test_file)

    # Only the two dict events should be returned (null/string/int skipped)
    assert len(result) == 2, f"Expected 2 valid dicts, got {len(result)}"


# ── Test 4: Unknown event_type maps to UNKNOWN, not rejected ─────────────────

def test_unknown_event_type_mapped_to_unknown_not_rejected():
    """
    An event with an unrecognized eventType must NOT be rejected.
    Instead, event_type is set to "UNKNOWN" and the event is normalized.

    This is important because security tools frequently add new event types.
    We don't want to silently drop events we haven't categorized yet.
    """
    event = {
        "userId": "alice@corp.com",
        "timestamp": "2024-11-15T08:00:00Z",
        "eventType": "COMPLETELY_NEW_EVENT_TYPE_FROM_TOOL_UPDATE",
        "riskLevel": "medium",
    }
    result = normalize(event, "identity")

    assert isinstance(result, CommonEvent)
    assert result.event_type == "UNKNOWN", (
        f"Expected event_type='UNKNOWN' for unrecognized type, got {result.event_type!r}"
    )
    assert result.identity_id == "alice@corp.com"
    # raw_payload must be preserved
    assert result.raw_payload["eventType"] == "COMPLETELY_NEW_EVENT_TYPE_FROM_TOOL_UPDATE"


# ── Test 5: Mix of valid and malformed — valid ones still processed ───────────

def test_valid_events_processed_despite_malformed_mixed_in():
    """
    When a mix of valid and malformed events is fed through normalization
    in a loop (as main.py does), valid events must still produce CommonEvent
    objects, and malformed ones must only raise NormalizationError without
    affecting the others.
    """
    mixed_raw = [
        # Valid
        {"userId": "alice@corp.com", "timestamp": "2024-11-15T08:00:00Z",
         "eventType": "LOGIN_FAILED", "riskLevel": "high"},
        # Malformed: bad timestamp
        {"userId": "bob@corp.com", "timestamp": "GARBAGE",
         "eventType": "LOGIN_FAILED", "riskLevel": "high"},
        # Valid
        {"userId": "carol@corp.com", "timestamp": "2024-11-15T08:02:00Z",
         "eventType": "LOGIN_SUCCESS", "riskLevel": "low"},
    ]

    results: list[CommonEvent] = []
    errors: list[str] = []

    for raw in mixed_raw:
        try:
            results.append(normalize(raw, "identity"))
        except NormalizationError as exc:
            errors.append(str(exc))

    assert len(results) == 2, f"Expected 2 valid events, got {len(results)}"
    assert len(errors) == 1, f"Expected 1 normalization error, got {len(errors)}"
    assert "timestamp" in errors[0].lower() or "Invalid" in errors[0]

    # Verify the two valid events are correct
    identity_ids = {e.identity_id for e in results}
    assert "alice@corp.com" in identity_ids
    assert "carol@corp.com" in identity_ids
    assert "bob@corp.com" not in identity_ids  # Malformed one must not appear
