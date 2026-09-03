"""
src/correlate/baseline.py
-------------------------
The naive baseline — "isolated-tool review" simulated in code.

WHY WE NEED A BASELINE:
  This is the comparison point for Phase 2's measured experiment.
  The baseline represents the WORST CASE: what happens if you try to
  correlate events using the simplest possible logic — no chain reasoning,
  just "same user + same time window."

  By implementing the baseline in code, Phase 2 can run BOTH approaches on
  the same data and measure:
    - How many false correlations does the baseline produce?
    - How long does it take to find real chains?
    - How does the rule-based engine compare?

WHAT THE NAIVE BASELINE DOES:
  Groups events by identity_id, then within each identity group, pairs up
  any two events that fall within a ±WINDOW_MINUTES window of each other.
  Returns all such pairs as "correlated" — regardless of whether they
  represent a real attack chain or just coincidental timing.

  This mimics what a human analyst does when they see the same username
  in two separate tool alerts and assume they must be related.

PROBLEMS WITH THE NAIVE APPROACH (intentional — this is what we improve on):
  1. HIGH FALSE POSITIVE RATE: A user's routine login + routine Chrome launch
     will be flagged as a correlation just because they happened close in time.
  2. NO CHAIN LOGIC: The baseline can't distinguish "login → powershell → C2"
     from "login → email → meeting invite" — both look the same to it.
  3. NO CROSS-SOURCE REASONING: The baseline joins on identity_id only. It
     has no concept of asset linking (identity ↔ endpoint).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta

from src.normalize.schema import CommonEvent

logger = logging.getLogger(__name__)

# Default time window for the naive baseline correlation
BASELINE_WINDOW_MINUTES: int = 10


def naive_join(
    events: list[CommonEvent],
    window_minutes: int = BASELINE_WINDOW_MINUTES,
) -> list[dict]:
    """
    Naive baseline correlation: pair events that share an identity_id
    and fall within window_minutes of each other.

    This is the "isolated-tool review" baseline:
    - Groups events by identity_id
    - Within each group, finds all pairs (e1, e2) where
      |e1.timestamp - e2.timestamp| ≤ window_minutes
    - Returns each pair as a "correlation" — no chain logic, no rule reasoning

    Args:
        events:         All normalized CommonEvent objects.
        window_minutes: Time window in minutes (default: 10).

    Returns:
        List of dicts, each representing one naive correlation pair:
        {
          "identity_id": "alice@corp.com",
          "event_1_id":  "...",
          "event_2_id":  "...",
          "event_1_type": "LOGIN_FAILED",
          "event_2_type": "PROCESS_EXEC",
          "delta_minutes": 4.5,
          "method": "naive_same_identity_time_window"
        }
    """
    window = timedelta(minutes=window_minutes)

    # Group events by identity_id (skip events with no identity)
    by_identity: dict[str, list[CommonEvent]] = defaultdict(list)
    for event in events:
        if event.identity_id:
            by_identity[event.identity_id].append(event)

    # Sort each group by timestamp
    for identity_id in by_identity:
        by_identity[identity_id].sort(key=lambda e: e.timestamp)

    results: list[dict] = []

    for identity_id, identity_events in by_identity.items():
        n = len(identity_events)
        for i in range(n):
            for j in range(i + 1, n):
                e1 = identity_events[i]
                e2 = identity_events[j]

                delta = e2.timestamp - e1.timestamp
                if delta <= window:
                    results.append({
                        "identity_id": identity_id,
                        "event_1_id": e1.event_id,
                        "event_2_id": e2.event_id,
                        "event_1_type": e1.event_type,
                        "event_2_type": e2.event_type,
                        "event_1_source": e1.source,
                        "event_2_source": e2.source,
                        "delta_minutes": round(delta.total_seconds() / 60, 2),
                        "method": "naive_same_identity_time_window",
                    })
                else:
                    # Events are sorted, so once delta > window for e2,
                    # all subsequent e_j will also exceed the window for e_i.
                    break

    logger.info(
        "[Baseline] Naive join produced %d raw correlations "
        "(window=%dm, identities=%d)",
        len(results),
        window_minutes,
        len(by_identity),
    )
    return results
