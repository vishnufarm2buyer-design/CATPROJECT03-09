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

CONFIGURATION:
  All thresholds, confidence weights, and heuristic lists are loaded from
  src/correlate/config.yaml. A security lead can edit that file without
  touching code. If config.yaml is missing, hardcoded defaults apply.

IMPLEMENTED RULES:

  Rule 1 — BRUTE_FORCE_ENDPOINT:
    "N failed logins for identity X within T minutes, followed by any suspicious
     endpoint process event on an asset linked to X, within T minutes of the last
     failed login."

  Rule 2 — MFA_BYPASS_COMPROMISE:
    "A LOGIN_SUCCESS event immediately followed (within T minutes) by an MFA_BYPASS
     event for the same identity, AND at least one suspicious endpoint event on a
     linked asset."

  Rule 3 — PHISHING_TO_CLOUD_COMPROMISE:
    "A phishing click (email) followed by credential capture/login (identity),
     then cloud API abuse (cloud) — optionally corroborated by endpoint/network
     events. Spans all 5 source domains."

ADDING NEW RULES:
  Add a new method named _rule_<name> that follows the same signature:
      def _rule_<name>(self, events, resolver) -> list[CorrelationChain]
  The run() method auto-discovers all _rule_ methods via introspection.
  Add the rule's thresholds to config.yaml.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from src.correlate.chain import CorrelationChain
from src.entity.resolver import EntityResolver
from src.normalize.schema import CommonEvent

logger = logging.getLogger(__name__)

# ── Configuration loading ────────────────────────────────────────────────────

_CONFIG_PATH = Path(__file__).parent / "config.yaml"

# Hardcoded defaults (used if config.yaml is missing or a key is absent)
_DEFAULTS = {
    "rules": {
        "brute_force_endpoint": {
            "min_failures": 3,
            "failure_window_minutes": 10,
            "endpoint_follow_window_minutes": 15,
            "base_confidence": 0.60,
            "extra_failure_bonus": 0.10,
            "max_extra_failure_bonus": 0.20,
            "critical_severity_bonus": 0.10,
            "multiple_events_bonus": 0.05,
        },
        "mfa_bypass_compromise": {
            "bypass_window_minutes": 5,
            "endpoint_follow_window_minutes": 15,
            "base_confidence": 0.75,
            "critical_severity_bonus": 0.10,
        },
        "phishing_to_cloud_compromise": {
            "phish_to_login_window_minutes": 30,
            "login_to_cloud_window_minutes": 60,
            "base_confidence": 0.55,
            "ip_match_bonus": 0.15,
            "dns_suspicious_bonus": 0.10,
            "role_assume_bonus": 0.10,
            "endpoint_corroboration_bonus": 0.10,
        },
    },
    "entity_resolution": {
        "max_session_hours": 8.0,
    },
    "suspicious_processes": [
        "mimikatz.exe", "meterpreter", "cobalt", "svchost32.exe",
    ],
    "suspicious_args": [
        "-enc", "-encodedcommand", "-nop", "sekurlsa", "net user /domain",
        "whoami", "ipconfig /all", "net localgroup", "persistence",
    ],
    "baseline": {
        "window_minutes": 10,
    },
}


def _deep_merge(defaults: dict, overrides: dict) -> dict:
    """Recursively merge overrides into defaults."""
    result = dict(defaults)
    for key, val in overrides.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load_config(config_path: Path | None = None) -> dict:
    """
    Load configuration from YAML, falling back to defaults if missing.

    Args:
        config_path: Path to config.yaml. Defaults to the one next to this file.

    Returns:
        Merged config dict (defaults + any overrides from YAML).
    """
    path = config_path or _CONFIG_PATH
    if path.exists():
        try:
            with path.open("r", encoding="utf-8") as fh:
                file_config = yaml.safe_load(fh) or {}
            logger.info("[Config] Loaded configuration from %s", path)
            return _deep_merge(_DEFAULTS, file_config)
        except Exception as exc:
            logger.warning(
                "[Config] Failed to load %s: %s — using defaults", path, exc
            )
    else:
        logger.info("[Config] No config file at %s — using defaults", path)
    return dict(_DEFAULTS)


# Load config at module level (once on import)
CONFIG = load_config()


# ── Suspicious process heuristics ────────────────────────────────────────────

def _get_suspicious_processes() -> set[str]:
    return set(CONFIG.get("suspicious_processes", _DEFAULTS["suspicious_processes"]))


def _get_suspicious_args() -> set[str]:
    return set(CONFIG.get("suspicious_args", _DEFAULTS["suspicious_args"]))


def _is_suspicious_endpoint_event(event: CommonEvent) -> bool:
    """
    Heuristic: is this endpoint event suspicious enough to be part of a chain?
    Checks process name and command-line arguments against known-bad patterns
    loaded from config.yaml.
    """
    if event.source != "endpoint":
        return False
    if event.severity in {"high", "critical"}:
        return True  # High/critical severity always qualifies

    raw = event.raw_payload
    process = str(raw.get("processName", "")).lower()
    cmdline = str(raw.get("commandLine", "")).lower()

    if any(sus in process for sus in _get_suspicious_processes()):
        return True
    if any(sus in cmdline for sus in _get_suspicious_args()):
        return True

    return False


class RuleEngine:
    """
    Evaluates all correlation rules against a normalized event stream.
    Configuration is loaded from config.yaml.

    Usage:
        engine = RuleEngine()
        chains = engine.run(events, resolver)
    """

    def __init__(self, config: dict | None = None) -> None:
        self.cfg = config or CONFIG

    def _get_rule_cfg(self, rule_name: str) -> dict:
        """Get config dict for a specific rule, with defaults."""
        return self.cfg.get("rules", {}).get(rule_name, {})

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

        Pattern: N failed logins for identity X within failure_window_minutes,
                 followed by a suspicious endpoint event on an asset linked to X
                 within endpoint_follow_window_minutes of the last failure.

        Why this matters: Classic credential-stuffing / password spray attack.
        The attacker tries many passwords, succeeds, then immediately runs
        a payload on the compromised machine.

        All thresholds and confidence weights are loaded from config.yaml.
        """
        cfg = self._get_rule_cfg("brute_force_endpoint")
        min_failures = cfg.get("min_failures", 3)
        brute_window = timedelta(minutes=cfg.get("failure_window_minutes", 10))
        follow_window = timedelta(minutes=cfg.get("endpoint_follow_window_minutes", 15))
        base_confidence = cfg.get("base_confidence", 0.60)
        extra_bonus = cfg.get("extra_failure_bonus", 0.10)
        max_extra_bonus = cfg.get("max_extra_failure_bonus", 0.20)
        crit_bonus = cfg.get("critical_severity_bonus", 0.10)
        multi_bonus = cfg.get("multiple_events_bonus", 0.05)
        max_session_hours = self.cfg.get("entity_resolution", {}).get("max_session_hours", 8.0)

        chains: list[CorrelationChain] = []

        # Index: identity_id → list of LOGIN_FAILED events, sorted by time
        failures_by_identity: dict[str, list[CommonEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == "LOGIN_FAILED" and event.identity_id:
                failures_by_identity[event.identity_id].append(event)

        for identity_id, failures in failures_by_identity.items():
            failures.sort(key=lambda e: e.timestamp)

            # Sliding window: find windows of ≥ min_failures failures
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

                if len(window_failures) >= min_failures:
                    last_failure_time = window_failures[-1].timestamp

                    # Session-bounded: get assets active at the time of the last failure
                    linked_assets = resolver.assets_for_identity_at(
                        identity_id, last_failure_time, max_session_hours
                    )
                    # Fall back to static mapping if no session-bounded results
                    if not linked_assets:
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
                        confidence = base_confidence
                        extra_failures = len(window_failures) - min_failures
                        confidence += min(extra_failures * extra_bonus, max_extra_bonus)
                        if any(e.severity == "critical" for e in suspicious_endpoint_events):
                            confidence += crit_bonus
                        if len(suspicious_endpoint_events) > 1:
                            confidence += multi_bonus
                        confidence = min(confidence, 1.0)

                        chain_events = window_failures + suspicious_endpoint_events
                        chain = CorrelationChain.create(
                            rule_name="BRUTE_FORCE_ENDPOINT",
                            events=chain_events,
                            confidence=confidence,
                            description=(
                                f"{len(window_failures)} failed logins for {identity_id} "
                                f"within {int(brute_window.total_seconds()//60)}min, followed by "
                                f"{len(suspicious_endpoint_events)} suspicious endpoint "
                                f"event(s) on {sorted(linked_assets)}"
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
                 identity within bypass_window_minutes, AND at least one
                 suspicious endpoint event on a linked asset.

        All thresholds loaded from config.yaml.
        """
        cfg = self._get_rule_cfg("mfa_bypass_compromise")
        bypass_window = timedelta(minutes=cfg.get("bypass_window_minutes", 5))
        follow_window = timedelta(minutes=cfg.get("endpoint_follow_window_minutes", 15))
        base_confidence = cfg.get("base_confidence", 0.75)
        crit_bonus = cfg.get("critical_severity_bonus", 0.10)
        max_session_hours = self.cfg.get("entity_resolution", {}).get("max_session_hours", 8.0)

        chains: list[CorrelationChain] = []

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

                # Session-bounded asset lookup
                linked_assets = resolver.assets_for_identity_at(
                    identity_id, bypass_event.timestamp, max_session_hours
                )
                if not linked_assets:
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
                    confidence = base_confidence
                    if any(e.severity == "critical" for e in suspicious_endpoint_events):
                        confidence += crit_bonus
                    confidence = min(confidence, 1.0)

                    chain_events = preceding_logins + [bypass_event] + suspicious_endpoint_events
                    chain = CorrelationChain.create(
                        rule_name="MFA_BYPASS_COMPROMISE",
                        events=chain_events,
                        confidence=confidence,
                        description=(
                            f"MFA bypassed for {identity_id} after successful login, "
                            f"followed by {len(suspicious_endpoint_events)} suspicious "
                            f"endpoint event(s) on {sorted(linked_assets)}"
                        ),
                    )
                    chains.append(chain)

        return chains

    # ── Rule 3: Phishing → Credential Capture → Cloud Abuse ──────────────────

    def _rule_phishing_to_cloud_compromise(
        self,
        events: list[CommonEvent],
        resolver: EntityResolver,
    ) -> list[CorrelationChain]:
        """
        PHISHING_TO_CLOUD_COMPROMISE rule — the cross-domain proof.

        Pattern (spans all 5 source domains):
          1. EMAIL_CLICK (phishing) for identity X
          2. Within 30 min: LOGIN_SUCCESS for X (credential captured via phish)
          3. Within 60 min of login: CLOUD_ROLE_ASSUME or CLOUD_API_CALL
             with severity >= medium from X
          4. Optionally: corroborating endpoint/network events on linked assets

        Why this rule matters: It proves the architecture generalizes beyond
        2 sources. A single chain can touch email → identity → network →
        endpoint → cloud. If any source is missing, the rule still fires
        with lower confidence on the remaining signals.

        Confidence scoring (from config.yaml):
          - Base: 0.55 (phishing click alone is lower-signal)
          - +0.15 if login IP matches the phishing source
          - +0.10 if DNS query to suspicious domain from linked asset
          - +0.10 if CLOUD_ROLE_ASSUME detected (privilege escalation)
          - +0.10 if suspicious endpoint event on linked asset
          - Cap at 1.0
        """
        cfg = self._get_rule_cfg("phishing_to_cloud_compromise")
        phish_to_login = timedelta(minutes=cfg.get("phish_to_login_window_minutes", 30))
        login_to_cloud = timedelta(minutes=cfg.get("login_to_cloud_window_minutes", 60))
        base_confidence = cfg.get("base_confidence", 0.55)
        ip_match_bonus = cfg.get("ip_match_bonus", 0.15)
        dns_bonus = cfg.get("dns_suspicious_bonus", 0.10)
        role_assume_bonus = cfg.get("role_assume_bonus", 0.10)
        endpoint_bonus = cfg.get("endpoint_corroboration_bonus", 0.10)
        max_session_hours = self.cfg.get("entity_resolution", {}).get("max_session_hours", 8.0)

        chains: list[CorrelationChain] = []

        # Index email clicks by identity
        phish_clicks: dict[str, list[CommonEvent]] = defaultdict(list)
        logins: dict[str, list[CommonEvent]] = defaultdict(list)
        cloud_events_by_identity: dict[str, list[CommonEvent]] = defaultdict(list)

        for event in events:
            if not event.identity_id:
                continue
            if event.event_type == "EMAIL_CLICK" and event.source == "email":
                phish_clicks[event.identity_id].append(event)
            elif event.event_type == "LOGIN_SUCCESS" and event.source == "identity":
                logins[event.identity_id].append(event)
            elif event.source == "cloud" and event.event_type in {
                "CLOUD_API_CALL", "CLOUD_ROLE_ASSUME"
            }:
                cloud_events_by_identity[event.identity_id].append(event)

        for identity_id, clicks in phish_clicks.items():
            identity_logins = logins.get(identity_id, [])
            identity_cloud = cloud_events_by_identity.get(identity_id, [])

            for click in clicks:
                # Step 1: Find LOGIN_SUCCESS within phish_to_login window after click
                matching_logins = [
                    e for e in identity_logins
                    if timedelta(0) <= e.timestamp - click.timestamp <= phish_to_login
                ]
                if not matching_logins:
                    continue

                first_login = min(matching_logins, key=lambda e: e.timestamp)

                # Step 2: Find cloud events within login_to_cloud window after login
                matching_cloud = [
                    e for e in identity_cloud
                    if (
                        timedelta(0) <= e.timestamp - first_login.timestamp <= login_to_cloud
                        and e.severity in {"medium", "high", "critical"}
                    )
                ]
                if not matching_cloud:
                    continue

                # ── Build chain and compute confidence ────────────────────────
                confidence = base_confidence

                # Bonus: login IP matches phishing source
                click_url_domain = str(click.raw_payload.get("url", "")).lower()
                login_ip = str(first_login.raw_payload.get("sourceIp", ""))
                # Check if login came from same suspicious IP/domain
                if login_ip and (
                    login_ip in click_url_domain
                    or any(
                        login_ip == str(e.raw_payload.get("sourceIp", ""))
                        for e in matching_cloud
                    )
                ):
                    confidence += ip_match_bonus

                # Bonus: DNS query to suspicious domain from linked asset
                linked_assets = resolver.assets_for_identity_at(
                    identity_id, first_login.timestamp, max_session_hours
                )
                if not linked_assets:
                    linked_assets = resolver.assets_for_identity(identity_id)

                dns_corroboration: list[CommonEvent] = []
                if linked_assets:
                    dns_corroboration = [
                        e for e in events
                        if (
                            e.source == "network"
                            and e.event_type == "DNS_QUERY"
                            and e.asset_id in linked_assets
                            and e.severity in {"high", "critical"}
                            and timedelta(0)
                            <= e.timestamp - click.timestamp
                            <= phish_to_login + login_to_cloud
                        )
                    ]
                    if dns_corroboration:
                        confidence += dns_bonus

                # Bonus: CLOUD_ROLE_ASSUME (privilege escalation)
                if any(e.event_type == "CLOUD_ROLE_ASSUME" for e in matching_cloud):
                    confidence += role_assume_bonus

                # Bonus: suspicious endpoint event on linked asset
                endpoint_corroboration: list[CommonEvent] = []
                if linked_assets:
                    endpoint_corroboration = [
                        e for e in events
                        if (
                            e.asset_id in linked_assets
                            and _is_suspicious_endpoint_event(e)
                            and timedelta(0)
                            <= e.timestamp - click.timestamp
                            <= phish_to_login + login_to_cloud
                        )
                    ]
                    if endpoint_corroboration:
                        confidence += endpoint_bonus

                confidence = min(confidence, 1.0)

                # Assemble all chain events
                chain_events = (
                    [click]
                    + matching_logins
                    + dns_corroboration
                    + endpoint_corroboration
                    + matching_cloud
                )

                sources_involved = sorted({e.source for e in chain_events})
                chain = CorrelationChain.create(
                    rule_name="PHISHING_TO_CLOUD_COMPROMISE",
                    events=chain_events,
                    confidence=confidence,
                    description=(
                        f"Phishing click by {identity_id} led to credential compromise "
                        f"and cloud abuse ({len(matching_cloud)} cloud event(s)). "
                        f"Sources: {sources_involved}"
                    ),
                )
                chains.append(chain)

        return chains
