"""
tests/test_missing_source.py
----------------------------
Edge Case 1: Missing source file.

WHAT WE'RE TESTING:
  If the endpoint source file doesn't exist (e.g., the endpoint tool is offline,
  the file wasn't exported, or a network share is unavailable), the engine must:
  1. Not crash with a FileNotFoundError or any exception
  2. Continue processing with only the identity events
  3. Return 0 endpoint events (empty list from the adapter)

WHY THIS MATTERS:
  The "degrade gracefully when a source is missing or delayed" constraint is
  a hard requirement from the stakeholder assumptions. If the engine crashes when
  one source is offline, it becomes useless precisely when it's needed most
  (e.g., during an incident where some tools may be overwhelmed or offline).

EXPECTED BEHAVIOR:
  - IdentityAdapter.load(identity_file) → returns events normally
  - EndpointAdapter.load(nonexistent_file) → returns [] without raising
  - normalize() runs on identity events successfully
  - RuleEngine.run() runs without error even with no endpoint events
  - No CorrelationChain is detected (can't fire endpoint rules without endpoint data)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.correlate.rules import RuleEngine
from src.entity.resolver import EntityResolver
from src.ingest.endpoint_adapter import EndpointAdapter
from src.ingest.identity_adapter import IdentityAdapter
from src.normalize.normalizer import normalize

DATA_DIR = Path(__file__).parent.parent / "data"
NONEXISTENT_FILE = Path(__file__).parent / "nonexistent_endpoint_file.json"


def test_missing_endpoint_source_does_not_crash():
    """
    EndpointAdapter.load() on a nonexistent file must return [] and not raise.
    This is the core graceful-degradation test.
    """
    adapter = EndpointAdapter()
    result = adapter.load(NONEXISTENT_FILE)

    assert isinstance(result, list), "Expected a list, not an exception"
    assert len(result) == 0, f"Expected 0 events from missing file, got {len(result)}"


def test_missing_endpoint_engine_still_runs():
    """
    With identity events but NO endpoint events:
    - Normalization should succeed on identity events
    - EntityResolver.ingest() should run without error
    - RuleEngine.run() should run without error
    - No chains should be detected (no endpoint events to link to)
    """
    # Load only identity events
    id_adapter = IdentityAdapter()
    raw_identity = id_adapter.load(DATA_DIR / "identity_events.json")
    assert len(raw_identity) > 0, "Identity data must exist for this test"

    # Load nonexistent endpoint file → empty list
    ep_adapter = EndpointAdapter()
    raw_endpoint = ep_adapter.load(NONEXISTENT_FILE)
    assert raw_endpoint == []

    # Normalize identity events only
    all_events = []
    for raw in raw_identity:
        all_events.append(normalize(raw, "identity"))
    # No endpoint events to normalize

    # Entity resolution must not crash
    resolver = EntityResolver()
    resolver.ingest(all_events)

    # Rule engine must not crash, and should produce no chains
    # (because rules require endpoint events to be linked)
    engine = RuleEngine()
    chains = engine.run(all_events, resolver)

    # Assertion: no chains because no endpoint data
    assert isinstance(chains, list), "Expected a list of chains"
    assert len(chains) == 0, (
        f"Expected 0 chains with no endpoint data, got {len(chains)}. "
        "This indicates a rule is firing without endpoint events, which is wrong."
    )


def test_missing_identity_source_does_not_crash():
    """
    Symmetric test: missing IDENTITY file.
    Engine should run on endpoint-only data without crashing.
    """
    id_adapter = IdentityAdapter()
    raw_identity = id_adapter.load(NONEXISTENT_FILE)
    assert raw_identity == []

    ep_adapter = EndpointAdapter()
    raw_endpoint = ep_adapter.load(DATA_DIR / "endpoint_events.json")
    assert len(raw_endpoint) > 0

    all_events = []
    for raw in raw_endpoint:
        all_events.append(normalize(raw, "endpoint"))

    resolver = EntityResolver()
    resolver.ingest(all_events)

    engine = RuleEngine()
    chains = engine.run(all_events, resolver)

    # No identity events → no failed logins → BRUTE_FORCE rule can't fire
    assert isinstance(chains, list)
    assert len(chains) == 0
