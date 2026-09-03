"""
src/correlate/chain.py
----------------------
CorrelationChain dataclass — the output object of the correlation engine.

A CorrelationChain represents a detected multi-stage attack sequence:
  - One or more related events across sources, ordered by time
  - The rule that triggered the chain
  - The identities and assets involved
  - A confidence score
  - When the engine detected it

This object is what gets sent to the SOC alerting system (stdout in Phase 1,
webhook to SIEM in Phase 2) and is written to the audit trail.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime, timezone

from src.normalize.schema import CommonEvent


@dataclasses.dataclass
class CorrelationChain:
    """
    A detected attack chain — a sequence of correlated events across sources.

    Fields:
        chain_id:       UUID for this chain instance (unique per detection)
        rule_name:      Which rule fired (e.g., "BRUTE_FORCE_ENDPOINT")
        confidence:     0.0–1.0. Higher = more corroborating signals.
        events:         The CommonEvent objects in this chain, sorted by time.
        identity_ids:   All identities implicated in this chain.
        asset_ids:      All assets implicated in this chain.
        detected_at:    UTC datetime when the engine detected this chain.
        time_span_mins: Duration from the first to last event in the chain.
        description:    Human-readable summary of what happened.
    """

    chain_id: str
    rule_name: str
    confidence: float
    events: list[CommonEvent]
    identity_ids: list[str]
    asset_ids: list[str]
    detected_at: datetime
    time_span_mins: float
    description: str

    @staticmethod
    def create(
        rule_name: str,
        events: list[CommonEvent],
        confidence: float,
        description: str,
    ) -> "CorrelationChain":
        """
        Factory method: build a CorrelationChain from a list of events.
        Automatically computes chain_id, identity_ids, asset_ids, time_span_mins.
        """
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        first_ts = sorted_events[0].timestamp
        last_ts = sorted_events[-1].timestamp
        span = (last_ts - first_ts).total_seconds() / 60.0

        identity_ids = sorted({e.identity_id for e in events if e.identity_id})
        asset_ids = sorted({e.asset_id for e in events if e.asset_id})

        return CorrelationChain(
            chain_id=str(uuid.uuid4()),
            rule_name=rule_name,
            confidence=confidence,
            events=sorted_events,
            identity_ids=identity_ids,
            asset_ids=asset_ids,
            detected_at=datetime.now(tz=timezone.utc),
            time_span_mins=round(span, 2),
            description=description,
        )

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict for output/audit logging."""
        return {
            "chain_id": self.chain_id,
            "rule_name": self.rule_name,
            "confidence": self.confidence,
            "identity_ids": self.identity_ids,
            "asset_ids": self.asset_ids,
            "detected_at": self.detected_at.isoformat(),
            "time_span_mins": self.time_span_mins,
            "event_count": len(self.events),
            "description": self.description,
            "events": [e.to_dict() for e in self.events],
        }

    def summary(self) -> str:
        """Short human-readable summary for console output."""
        return (
            f"[CHAIN ALERT] rule={self.rule_name} "
            f"confidence={self.confidence:.0%} "
            f"identities={self.identity_ids} "
            f"assets={self.asset_ids} "
            f"events={len(self.events)} "
            f"span={self.time_span_mins:.1f}min"
        )
