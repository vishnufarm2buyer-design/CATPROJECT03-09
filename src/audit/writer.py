"""
src/audit/writer.py
-------------------
Append-only JSONL audit trail writer.

WHY AN AUDIT TRAIL?
  Every decision the correlation engine makes — ingesting an event, resolving
  an entity link, firing a rule, creating a chain — is logged here. This serves
  three purposes:
  1. COMPLIANCE: Provides evidence of what the system detected and when.
  2. DEBUGGING: If a chain alert fires on a false positive, you can replay the
     exact sequence of decisions that led to it.
  3. EXPLAINABILITY: SOC analysts can ask "why did the engine link these events?"
     and get a clear answer from the audit trail.

WHY JSONL (JSON Lines)?
  - Append-only: each record is a single line. Adding a new record never
    modifies existing records (unlike a database update).
  - Human-readable: you can grep the file to find all decisions about a
    specific identity_id or chain_id.
  - No database dependency: just a file. Works without any infrastructure.
  - Example grep: grep "alice@corp.com" audit_trail.jsonl

RECORD SCHEMA:
  {
    "ts":         "2024-11-15T08:05:30+00:00",  ← When the decision was made
    "event_type": "RULE_FIRED",                  ← What type of decision
    "actor":      "engine",                      ← Who made the decision
    "detail":     { ... }                        ← Source-specific detail dict
  }

EVENT TYPES:
  INGESTION_SUCCESS   — N events loaded from a source file
  INGESTION_ERROR     — A source file was missing or a malformed event was rejected
  ENTITY_RESOLVED     — identity ↔ asset link established
  RULE_FIRED          — a correlation rule matched
  CHAIN_CREATED       — a CorrelationChain was assembled and is being alerted
  BASELINE_RESULT     — the naive baseline produced N raw matches
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class AuditWriter:
    """
    Writes audit records to an append-only JSONL file.

    Every record written is a single line of JSON. Records are NEVER modified
    or deleted — the file only grows. This is the "append-only" invariant.

    Usage:
        writer = AuditWriter("audit_trail.jsonl")
        writer.log("RULE_FIRED", {"rule": "BRUTE_FORCE_ENDPOINT", "chain_id": "..."})
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        # Create the file and any parent directories if they don't exist
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
        logger.info("[AuditWriter] Audit trail at: %s", self._path.resolve())

    def log(
        self,
        event_type: str,
        detail: dict,
        actor: str = "engine",
    ) -> None:
        """
        Append one audit record to the JSONL file.

        Args:
            event_type: One of the audit event types (e.g., "RULE_FIRED").
            detail:     Arbitrary dict with event-specific context.
            actor:      Who/what triggered this record. Default: "engine".
        """
        record = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "event_type": event_type,
            "actor": actor,
            "detail": detail,
        }
        line = json.dumps(record, default=str)  # default=str handles datetime objects
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def log_ingestion_success(self, source: str, count: int, path: str) -> None:
        self.log("INGESTION_SUCCESS", {"source": source, "event_count": count, "file": path})

    def log_ingestion_error(self, source: str, error: str, path: str) -> None:
        self.log("INGESTION_ERROR", {"source": source, "error": error, "file": path})

    def log_normalization_error(self, source: str, raw_event: dict, error: str) -> None:
        self.log("NORMALIZATION_ERROR", {
            "source": source,
            "error": error,
            "raw_event_preview": str(raw_event)[:200],  # Truncate to avoid huge records
        })

    def log_entity_resolved(self, identity_id: str, asset_ids: list[str]) -> None:
        self.log("ENTITY_RESOLVED", {
            "identity_id": identity_id,
            "linked_asset_ids": list(asset_ids),
        })

    def log_rule_fired(
        self,
        rule_name: str,
        identity_id: str,
        asset_ids: list[str],
        event_ids: list[str],
        confidence: float,
    ) -> None:
        self.log("RULE_FIRED", {
            "rule": rule_name,
            "identity_id": identity_id,
            "asset_ids": asset_ids,
            "contributing_event_ids": event_ids,
            "confidence": confidence,
        })

    def log_chain_created(self, chain_id: str, rule_name: str, event_count: int) -> None:
        self.log("CHAIN_CREATED", {
            "chain_id": chain_id,
            "rule": rule_name,
            "event_count": event_count,
        })

    def log_baseline_result(self, match_count: int, method: str) -> None:
        self.log("BASELINE_RESULT", {"matches": match_count, "method": method})

    def log_source_missing(self, source: str, expected_path: str) -> None:
        self.log("SOURCE_MISSING", {
            "source": source,
            "expected_path": expected_path,
            "action": "treating as offline — continuing with available sources",
        })
