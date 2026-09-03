"""
main.py
-------
End-to-end runner for the Attack-Chain Correlation Engine (Phase 1).

WHAT THIS SCRIPT DOES (in order):
  1. INGEST  — load raw events from identity + endpoint JSON files
  2. NORMALIZE — map each raw event to CommonEvent schema
  3. ENTITY RESOLVE — build identity ↔ asset map
  4. BASELINE — run naive join (for comparison; prints result count)
  5. CORRELATE — run rule engine, collect CorrelationChains
  6. OUTPUT — print chain summaries to stdout
  7. AUDIT — every decision along the way is written to audit_trail.jsonl

RUN:
    python main.py

OUTPUT:
    Console: chain alerts + summary statistics
    File:    audit_trail.jsonl (append-only, created in project root)
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# ── Add project root to path so imports work from any working directory ───────
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.audit.writer import AuditWriter
from src.correlate.baseline import naive_join
from src.correlate.rules import RuleEngine
from src.entity.resolver import EntityResolver
from src.ingest.endpoint_adapter import EndpointAdapter
from src.ingest.identity_adapter import IdentityAdapter
from src.normalize.normalizer import NormalizationError, normalize

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")

# ── File paths ────────────────────────────────────────────────────────────────
DATA_DIR = PROJECT_ROOT / "data"
IDENTITY_FILE = DATA_DIR / "identity_events.json"
ENDPOINT_FILE = DATA_DIR / "endpoint_events.json"
AUDIT_FILE = PROJECT_ROOT / "audit_trail.jsonl"


def main() -> None:
    print("=" * 70)
    print("  Attack-Chain Correlation Engine — Phase 1")
    print("=" * 70)

    # ── Step 0: Initialize audit trail ────────────────────────────────────────
    audit = AuditWriter(AUDIT_FILE)
    logger.info("Audit trail: %s", AUDIT_FILE)

    # ── Step 1: Ingest ────────────────────────────────────────────────────────
    print("\n[1/5] INGESTING events...")

    id_adapter = IdentityAdapter()
    ep_adapter = EndpointAdapter()

    raw_identity = id_adapter.load(IDENTITY_FILE)
    raw_endpoint = ep_adapter.load(ENDPOINT_FILE)

    # Log ingestion to audit trail
    if raw_identity:
        audit.log_ingestion_success("identity", len(raw_identity), str(IDENTITY_FILE))
    else:
        audit.log_source_missing("identity", str(IDENTITY_FILE))

    if raw_endpoint:
        audit.log_ingestion_success("endpoint", len(raw_endpoint), str(ENDPOINT_FILE))
    else:
        audit.log_source_missing("endpoint", str(ENDPOINT_FILE))

    print(f"    Identity events loaded:  {len(raw_identity)}")
    print(f"    Endpoint events loaded:  {len(raw_endpoint)}")

    # ── Step 2: Normalize ─────────────────────────────────────────────────────
    print("\n[2/5] NORMALIZING events to CommonEvent schema...")

    all_events = []
    norm_errors = 0

    for raw in raw_identity:
        try:
            all_events.append(normalize(raw, "identity"))
        except NormalizationError as exc:
            audit.log_normalization_error("identity", raw, str(exc))
            norm_errors += 1

    for raw in raw_endpoint:
        try:
            all_events.append(normalize(raw, "endpoint"))
        except NormalizationError as exc:
            audit.log_normalization_error("endpoint", raw, str(exc))
            norm_errors += 1

    print(f"    Normalized: {len(all_events)} events ({norm_errors} errors)")

    # ── Step 3: Entity Resolution ─────────────────────────────────────────────
    print("\n[3/5] RESOLVING entity links (identity <-> asset)...")

    resolver = EntityResolver()
    resolver.ingest(all_events)

    # Log entity links to audit trail
    # (log one entry per identity that has linked assets)
    _logged_identities: set[str] = set()
    for event in all_events:
        if event.identity_id and event.identity_id not in _logged_identities:
            assets = resolver.assets_for_identity(event.identity_id)
            if assets:
                audit.log_entity_resolved(event.identity_id, list(assets))
                _logged_identities.add(event.identity_id)

    print(f"    Entity links built. Example:")
    for identity_id in list(_logged_identities)[:3]:
        assets = resolver.assets_for_identity(identity_id)
        print(f"      {identity_id} -> {sorted(assets)}")

    # ── Step 4: Baseline (naive join — comparison point) ─────────────────────
    print("\n[4/5] RUNNING baseline (naive same-identity time-window join)...")

    baseline_matches = naive_join(all_events, window_minutes=10)
    audit.log_baseline_result(len(baseline_matches), "naive_same_identity_time_window")

    print(f"    Baseline produced {len(baseline_matches)} raw correlations")
    print(f"    (This includes false positives — see docs/schema.md for explanation)")

    import time
    start_time = time.perf_counter()
    # ── Step 5: Rule-based correlation ────────────────────────────────────────
    print("\n[5/5] RUNNING rule-based correlation engine...")

    engine = RuleEngine()
    chains = engine.run(all_events, resolver)
    end_time = time.perf_counter()
    processing_time_ms = (end_time - start_time) * 1000

    for chain in chains:
        audit.log_rule_fired(
            rule_name=chain.rule_name,
            identity_id=", ".join(chain.identity_ids),
            asset_ids=chain.asset_ids,
            event_ids=[e.event_id for e in chain.events],
            confidence=chain.confidence,
        )
        audit.log_chain_created(chain.chain_id, chain.rule_name, len(chain.events))

    # ── Output ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  RESULTS")
    print("=" * 70)
    print(f"\n  Total events processed:    {len(all_events)}")
    print(f"  Baseline correlations:     {len(baseline_matches)} (naive join)")
    print(f"  Rule-based chains:         {len(chains)}")
    print(f"  Time-to-correlate:         {processing_time_ms:.2f} ms")
    if len(chains) > 1:
         print(f"  (Note: Deduplication of overlapping chains will be added in Phase 2)")
    print()

    if not chains:
        print("  No chains detected.")
    else:
        for i, chain in enumerate(chains, 1):
            print(f"\n  ── Chain #{i} ──────────────────────────────────────────")
            print(f"  Rule:        {chain.rule_name}")
            print(f"  Confidence:  {chain.confidence:.0%}")
            print(f"  Identities:  {chain.identity_ids}")
            print(f"  Assets:      {chain.asset_ids}")
            print(f"  Events:      {len(chain.events)} events over {chain.time_span_mins:.1f} min")
            print(f"  Description: {chain.description}")
            print(f"\n  Event timeline:")
            for event in chain.events:
                print(
                    f"    {event.timestamp.strftime('%H:%M:%S')} "
                    f"[{event.source:8s}] "
                    f"{event.event_type:20s} "
                    f"id={event.identity_id or '-':25s} "
                    f"asset={event.asset_id or '-'}"
                )

    print(f"\n  Audit trail written to: {AUDIT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
