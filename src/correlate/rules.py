"""
src/correlate/rules.py
----------------------
Rule-based correlation engine.

HOW THE RULE ENGINE WORKS:
  Each "rule" is a method on the RuleEngine class that:
    1. Accepts the full list of normalized events and the entity resolver
    2. Looks for a specific multi-stage attack pattern
    3. Returns a list of CorrelationChain objects (one per detected instance)

  The engine runs ALL rules and collects all chains. Rules are independent —
  they don't interfere with each other.

WHY RULE-BASED (NOT ML)?
  Phase 1 uses rule-based correlation because:
  - Rules are explainable: "this chain fired because conditions X, Y, Z were met"
  - Rules don't need training data
  - Rules are tunable by the security lead without code changes (thresholds
    will move to a config file in Phase 2)
  - ML correlation is Phase 2 — it needs baseline data first (which Phase 1 establishes)

IMPLEMENTED RULES:

  Rule 1 — BRUTE_FORCE_ENDPOINT:
    "N failed logins for identity X within T minutes, followed by any suspicious
     endpoint process event on an asset linked to X, within T minutes of the last
     failed login."
    This detects: attacker brute-forces a password → gains access → runs malware.

  Rule 2 — MFA_BYPASS_COMPROMISE:
    "A LOGIN_SUCCESS event immediately followed (within T minutes) by an MFA_BYPASS
     event for the same identity, AND at least one suspicious endpoint event on a
     linked asset."
    This detects: attacker bypasses MFA after obtaining credentials → executes payload.

SUSPICIOUS PROCESS NAMES (heuristic — will move to config in Phase 2):
  powershell.exe with -enc (encoded command) or -nop (no profile, common in malware)
  mimikatz.exe, cmd.exe with 'net user' (credential dumping / reconnaissance)
  Any process not in a standard system path writing to AppData or Temp

ADDING NEW RULES (Phase 2):
  Add a new method named _rule_<name> that follows the same signature:
      def _rule_<name>(self, events, resolver) -> list[CorrelationChain]
  The run() method auto-discovers all _rule_ methods via introspection.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta

from src.correlate.chain import CorrelationChain
from src.entity.resolver import EntityResolver
from src.normalize.schema import CommonEvent

logger = logging.getLogger(__name__)

# ── Tunable thresholds (will move to config file in Phase 2) ─────────────────
BRUTE_FORCE_MIN_FAILURES: int = 3          # Minimum failed logins to qualify
BRUTE_FORCE_WINDOW_MINUTES: int = 10       # Window for failed logins
ENDPOINT_FOLLOW_WINDOW_MINUTES: int = 15   # Window after last failure for endpoint event
MFA_BYPASS_WINDOW_MINUTES: int = 5         # Window for MFA bypass after login success

# ── Suspicious process heuristics ────────────────────────────────────────────
_SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "meterpreter", "cobalt", "svchost32.exe",
}

_SUSPICIOUS_ARGS = {
    "-enc", "-encodedcommand", "-nop", "sekurlsa", "net user /domain",
    "whoami", "ipconfig /all", "net localgroup", "persistence",
}


def _is_suspicious_endpoint_event(event: CommonEvent) -> bool:
    """
    Heuristic: is this endpoint event suspicious enough to be part of a chain?
    Checks process name and command-line arguments against known-bad patterns.
    """
    if event.source != "endpoint":
        return False
    if event.severity in {"high", "critical"}:
        return True  # High/critical severity always qualifies

    raw = event.raw_payload
    process = str(raw.get("processName", "")).lower()
    cmdline = str(raw.get("commandLine", "")).lower()

    if any(sus in process for sus in _SUSPICIOUS_PROCESSES):
        return True
    if any(sus in cmdline for sus in _SUSPICIOUS_ARGS):
        return True

    return False


class RuleEngine:
    """
    Evaluates all correlation rules against a normalized event stream.

    Usage:
        engine = RuleEngine()
        chains = engine.run(events, resolver)
    """

    def run(
        self,
        events: list[CommonEvent],
        resolver: EntityResolver,
    ) -> list[CorrelationChain]:
        """
        Run all rules and return all detected chains.

        Auto-discovers rule methods via naming convention: any method starting
        with '_rule_' is treated as a rule and called automatically.
        """
        chains: list[CorrelationChain] = []

        # Discover all rule methods dynamically
        rule_methods = [
            getattr(self, name)
            for name in dir(self)
            if name.startswith("_rule_")
        ]

        for rule_fn in rule_methods:
            rule_name = rule_fn.__name__.replace("_rule_", "").upper()
            logger.info("[RuleEngine] Evaluating rule: %s", rule_name)
            try:
                new_chains = rule_fn(events, resolver)
                if new_chains:
                    logger.info(
                        "[RuleEngine] Rule %s fired: %d chain(s)", rule_name, len(new_chains)
                    )
                chains.extend(new_chains)
            except Exception as exc:
                logger.error("[RuleEngine] Rule %s raised exception: %s", rule_name, exc)

        logger.info("[RuleEngine] Total chains detected: %d", len(chains))
        return chains

    # ── Rule 1: Brute Force → Endpoint Compromise ─────────────────────────────

    def _rule_brute_force_endpoint(
        self,
        events: list[CommonEvent],
        resolver: EntityResolver,
    ) -> list[CorrelationChain]:
        """
        BRUTE_FORCE_ENDPOINT rule:

        Pattern: N failed logins for identity X within BRUTE_FORCE_WINDOW_MINUTES,
                 followed by a suspicious endpoint event on an asset linked to X
                 within ENDPOINT_FOLLOW_WINDOW_MINUTES of the last failure.

        Why this matters: Classic credential-stuffing / password spray attack.
        The attacker tries many passwords, succeeds, then immediately runs
        a payload on the compromised machine.

        Confidence scoring:
          - Base: 0.60
          - +0.10 per failure beyond the minimum threshold (up to +0.20)
          - +0.10 if the suspicious event is critical severity
          - +0.05 if there are multiple suspicious endpoint events
        """
        chains: list[CorrelationChain] = []
        brute_window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        follow_window = timedelta(minutes=ENDPOINT_FOLLOW_WINDOW_MINUTES)

        # Index: identity_id → list of LOGIN_FAILED events, sorted by time
        failures_by_identity: dict[str, list[CommonEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == "LOGIN_FAILED" and event.identity_id:
                failures_by_identity[event.identity_id].append(event)

        for identity_id, failures in failures_by_identity.items():
            failures.sort(key=lambda e: e.timestamp)

            # Sliding window: find windows of ≥ BRUTE_FORCE_MIN_FAILURES failures
            n = len(failures)
            i = 0
            while i < n:
                window_failures = [failures[i]]
                j = i + 1
                while j < n:
                    if failures[j].timestamp - failures[i].timestamp <= brute_window:
                        window_failures.append(failures[j])
                        j += 1
                    else:
                        break

                if len(window_failures) >= BRUTE_FORCE_MIN_FAILURES:
                    last_failure_time = window_failures[-1].timestamp

                    # Look for suspicious endpoint events on linked assets
                    linked_assets = resolver.assets_for_identity(identity_id)
                    if not linked_assets:
                        i += 1
                        continue

                    suspicious_endpoint_events: list[CommonEvent] = [
                        e for e in events
                        if (
                            e.asset_id in linked_assets
                            and _is_suspicious_endpoint_event(e)
                            and timedelta(0)
                            <= e.timestamp - last_failure_time
                            <= follow_window
                        )
                    ]

                    if suspicious_endpoint_events:
                        # Build confidence score
                        confidence = 0.60
                        extra_failures = len(window_failures) - BRUTE_FORCE_MIN_FAILURES
                        confidence += min(extra_failures * 0.10, 0.20)
                        if any(e.severity == "critical" for e in suspicious_endpoint_events):
                            confidence += 0.10
                        if len(suspicious_endpoint_events) > 1:
                            confidence += 0.05
                        confidence = min(confidence, 1.0)

                        chain_events = window_failures + suspicious_endpoint_events
                        chain = CorrelationChain.create(
                            rule_name="BRUTE_FORCE_ENDPOINT",
                            events=chain_events,
                            confidence=confidence,
                            description=(
                                f"{len(window_failures)} failed logins for {identity_id} "
                                f"within {BRUTE_FORCE_WINDOW_MINUTES}min, followed by "
                                f"{len(suspicious_endpoint_events)} suspicious endpoint "
                                f"event(s) on {list(linked_assets)}"
                            ),
                        )
                        chains.append(chain)

                # Move the window forward
                i += max(1, len(window_failures))

        return chains

    # ── Rule 2: MFA Bypass → Endpoint Compromise ─────────────────────────────

    def _rule_mfa_bypass_compromise(
        self,
        events: list[CommonEvent],
        resolver: EntityResolver,
    ) -> list[CorrelationChain]:
        """
        MFA_BYPASS_COMPROMISE rule:

        Pattern: LOGIN_SUCCESS immediately followed by MFA_BYPASS for the same
                 identity within MFA_BYPASS_WINDOW_MINUTES, AND at least one
                 suspicious endpoint event on a linked asset.

        Why this matters: MFA bypass (e.g., via SIM-swap, session hijack, or
        adversary-in-the-middle) after credential compromise is a strong signal
        that a real attacker (not the legitimate user) has taken over the account.

        Confidence: starts at 0.75 (MFA bypass is a high-signal event by itself)
        """
        chains: list[CorrelationChain] = []
        bypass_window = timedelta(minutes=MFA_BYPASS_WINDOW_MINUTES)
        follow_window = timedelta(minutes=ENDPOINT_FOLLOW_WINDOW_MINUTES)

        # Index by identity
        successes: dict[str, list[CommonEvent]] = defaultdict(list)
        bypasses: dict[str, list[CommonEvent]] = defaultdict(list)

        for event in events:
            if not event.identity_id:
                continue
            if event.event_type == "LOGIN_SUCCESS":
                successes[event.identity_id].append(event)
            elif event.event_type == "MFA_BYPASS":
                bypasses[event.identity_id].append(event)

        for identity_id, bypass_events in bypasses.items():
            login_events = successes.get(identity_id, [])
            if not login_events:
                continue

            for bypass_event in bypass_events:
                # Find a LOGIN_SUCCESS within bypass_window BEFORE this MFA_BYPASS
                preceding_logins = [
                    e for e in login_events
                    if timedelta(0) <= bypass_event.timestamp - e.timestamp <= bypass_window
                ]
                if not preceding_logins:
                    continue

                # Check for suspicious endpoint events after the bypass
                linked_assets = resolver.assets_for_identity(identity_id)
                suspicious_endpoint_events = [
                    e for e in events
                    if (
                        e.asset_id in linked_assets
                        and _is_suspicious_endpoint_event(e)
                        and timedelta(0)
                        <= e.timestamp - bypass_event.timestamp
                        <= follow_window
                    )
                ]

                if suspicious_endpoint_events:
                    confidence = 0.75
                    if any(e.severity == "critical" for e in suspicious_endpoint_events):
                        confidence += 0.10
                    confidence = min(confidence, 1.0)

                    chain_events = preceding_logins + [bypass_event] + suspicious_endpoint_events
                    chain = CorrelationChain.create(
                        rule_name="MFA_BYPASS_COMPROMISE",
                        events=chain_events,
                        confidence=confidence,
                        description=(
                            f"MFA bypassed for {identity_id} after successful login, "
                            f"followed by {len(suspicious_endpoint_events)} suspicious "
                            f"endpoint event(s) on {list(linked_assets)}"
                        ),
                    )
                    chains.append(chain)

        return chains
