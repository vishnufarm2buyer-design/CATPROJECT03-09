"""
tests/test_cross_domain_rule.py
-------------------------------
Tests for Rule 3: PHISHING_TO_CLOUD_COMPROMISE.

WHAT WE'RE TESTING:
  The cross-domain rule detects a multi-stage attack chain that spans
  all 5 source domains: email -> identity -> network -> endpoint -> cloud.
  This is the proof that the architecture generalizes beyond 2 sources.

TEST SCENARIOS:
  1. Full 5-source chain fires with high confidence (all corroboration signals)
  2. Partial chain (phishing + login + cloud, no endpoint/network) still fires
  3. Phishing click with no subsequent login -> 0 chains
  4. Events outside the time window -> 0 chains
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.correlate.rules import RuleEngine
from src.entity.resolver import EntityResolver
from src.normalize.schema import CommonEvent

BASE = datetime(2024, 11, 15, 7, 0, 0, tzinfo=timezone.utc)


def _evt(
    source: str,
    event_type: str,
    minutes: float,
    identity_id: str | None = None,
    asset_id: str | None = None,
    severity: str = "medium",
    session_id: str | None = None,
    **extra_payload,
) -> CommonEvent:
    """Create a test CommonEvent at a specific time offset from BASE."""
    payload = dict(extra_payload)
    return CommonEvent(
        event_id=CommonEvent.new_id(),
        timestamp=BASE + timedelta(minutes=minutes),
        source=source,
        event_type=event_type,
        severity=severity,
        raw_payload=payload,
        identity_id=identity_id,
        asset_id=asset_id,
        session_id=session_id,
    )


def _build_full_5_source_chain() -> list[CommonEvent]:
    """
    Build a complete 5-source attack chain for alice@corp.com:
      T=0:  Email - phishing click
      T=5:  Identity - login success (credential captured)
      T=6:  Network - DNS query to C2 (corroboration)
      T=7:  Endpoint - suspicious process (corroboration)
      T=10: Cloud - role assume (privilege escalation)
      T=12: Cloud - API call (data access)
    """
    return [
        _evt("email", "EMAIL_CLICK", 0, identity_id="alice@corp.com",
             severity="high", url="https://evil-domain.com/harvest"),
        _evt("identity", "LOGIN_SUCCESS", 5, identity_id="alice@corp.com",
             asset_id="WKSTN-042", severity="high", session_id="sess-test-001",
             sourceIp="185.220.101.45"),
        _evt("network", "DNS_QUERY", 6, asset_id="WKSTN-042",
             severity="high", dnsQuery="c2.evil-domain.com"),
        _evt("endpoint", "PROCESS_EXEC", 7, identity_id="alice@corp.com",
             asset_id="WKSTN-042", severity="critical",
             processName="powershell.exe",
             commandLine="powershell -nop -enc JABjAGwAaQBlAG4AdAA="),
        _evt("cloud", "CLOUD_ROLE_ASSUME", 10, identity_id="alice@corp.com",
             severity="high"),
        _evt("cloud", "CLOUD_API_CALL", 12, identity_id="alice@corp.com",
             severity="critical"),
    ]


def test_full_5_source_chain_fires():
    """
    The full 5-source chain should fire PHISHING_TO_CLOUD_COMPROMISE
    with confidence >= 0.55 (the base value).
    """
    events = _build_full_5_source_chain()
    resolver = EntityResolver()
    resolver.ingest(events)

    engine = RuleEngine()
    chains = engine.run(events, resolver)

    # Filter to only the phishing-to-cloud rule
    phish_chains = [c for c in chains if c.rule_name == "PHISHING_TO_CLOUD_COMPROMISE"]
    assert len(phish_chains) >= 1, (
        f"Expected at least 1 PHISHING_TO_CLOUD_COMPROMISE chain, "
        f"got {len(phish_chains)}. All chains: {[c.rule_name for c in chains]}"
    )

    chain = phish_chains[0]
    assert chain.confidence >= 0.55, (
        f"Confidence should be at least 0.55 (base), got {chain.confidence}"
    )
    assert "alice@corp.com" in chain.identity_ids
    # Should have events from multiple sources
    sources = {e.source for e in chain.events}
    assert len(sources) >= 3, (
        f"Cross-domain chain should span at least 3 sources, got {sources}"
    )


def test_partial_chain_phish_login_cloud_only():
    """
    Phishing click + login + cloud abuse (no endpoint, no network)
    should STILL fire the rule — but potentially with lower confidence.
    """
    events = [
        _evt("email", "EMAIL_CLICK", 0, identity_id="bob@corp.com",
             severity="high"),
        _evt("identity", "LOGIN_SUCCESS", 10, identity_id="bob@corp.com",
             asset_id="WKSTN-017", session_id="sess-bob-001"),
        _evt("cloud", "CLOUD_ROLE_ASSUME", 20, identity_id="bob@corp.com",
             severity="high"),
    ]
    resolver = EntityResolver()
    resolver.ingest(events)

    engine = RuleEngine()
    chains = engine.run(events, resolver)

    phish_chains = [c for c in chains if c.rule_name == "PHISHING_TO_CLOUD_COMPROMISE"]
    assert len(phish_chains) >= 1, (
        "Partial chain (email + identity + cloud) should still fire"
    )


def test_phish_click_no_login_no_chain():
    """
    A phishing click with no subsequent login within the window
    should NOT produce a chain. Phishing alone is not a chain — we need
    credential capture evidence.
    """
    events = [
        _evt("email", "EMAIL_CLICK", 0, identity_id="carol@corp.com",
             severity="high"),
        # No login event for carol — the credential was not captured
    ]
    resolver = EntityResolver()
    resolver.ingest(events)

    engine = RuleEngine()
    chains = engine.run(events, resolver)

    phish_chains = [c for c in chains if c.rule_name == "PHISHING_TO_CLOUD_COMPROMISE"]
    assert len(phish_chains) == 0, (
        "Phishing click alone (no login) should not fire the cross-domain rule"
    )


def test_events_outside_time_window_no_chain():
    """
    If the login happens 60 minutes after the phishing click (outside the
    default 30-min window), the rule should NOT fire.
    """
    events = [
        _evt("email", "EMAIL_CLICK", 0, identity_id="dave@corp.com",
             severity="high"),
        _evt("identity", "LOGIN_SUCCESS", 60, identity_id="dave@corp.com",
             asset_id="WKSTN-099", session_id="sess-dave-001"),
        _evt("cloud", "CLOUD_ROLE_ASSUME", 70, identity_id="dave@corp.com",
             severity="high"),
    ]
    resolver = EntityResolver()
    resolver.ingest(events)

    engine = RuleEngine()
    chains = engine.run(events, resolver)

    phish_chains = [c for c in chains if c.rule_name == "PHISHING_TO_CLOUD_COMPROMISE"]
    assert len(phish_chains) == 0, (
        "Login at T+60 is outside the 30-min phish-to-login window — "
        "rule should not fire"
    )
