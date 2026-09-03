"""
src/ingest/base_adapter.py
--------------------------
Abstract base class for all source adapters.

WHY AN ABSTRACT BASE CLASS?
  All five source adapters (identity, endpoint, email, network, cloud) do the
  same thing at a high level:
    1. Read raw events from a file (Phase 1) or API (Phase 2)
    2. Validate that events have the minimum required fields
    3. Return a list of raw dicts, skipping malformed ones

  By defining this contract in a base class, we guarantee that:
  - Every adapter can be swapped in/out without changing the calling code
  - Adding a new source (Phase 2) follows the same pattern as Phase 1 sources
  - The missing-source failure mode is handled ONCE here, not in each adapter

GRACEFUL DEGRADATION:
  If a file is missing (source offline), load() returns [] and logs a warning.
  The calling code never crashes — it just has fewer events to work with.
  This implements the "degrade gracefully when a source is missing" constraint.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)


class BaseAdapter(ABC):
    """
    Abstract adapter. Subclass this for each data source.

    Subclasses must implement:
        source_name  (property)  — the normalized source label, e.g. "identity"
        _required_fields         — list of field names that MUST be present
        _validate(raw)           — return True if the event passes validation
    """

    @property
    @abstractmethod
    def source_name(self) -> str:
        """The normalized source label used in CommonEvent.source."""
        ...

    @property
    @abstractmethod
    def _required_fields(self) -> list[str]:
        """
        Field names that MUST exist in a raw event for it to be accepted.
        Events missing any of these fields are rejected and logged.
        """
        ...

    def load(self, path: str | Path) -> list[dict]:
        """
        Load raw events from a JSON file at the given path.

        Returns:
            List of raw event dicts. Empty list if:
              - The file doesn't exist (missing source — logged as WARNING)
              - The file contains invalid JSON (logged as ERROR)

        Malformed individual events are skipped but the rest are still returned.
        This way a single bad event doesn't abort the entire ingestion run.
        """
        path = Path(path)

        # ── Missing source: degrade gracefully ────────────────────────────────
        if not path.exists():
            logger.warning(
                "[%s] Source file not found: %s — treating as offline source (0 events)",
                self.source_name,
                path,
            )
            return []

        # ── Parse JSON ────────────────────────────────────────────────────────
        try:
            raw_text = path.read_text(encoding="utf-8")
            events = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            logger.error(
                "[%s] Invalid JSON in %s: %s — source skipped entirely",
                self.source_name,
                path,
                exc,
            )
            return []

        if not isinstance(events, list):
            logger.error(
                "[%s] Expected a JSON array in %s, got %s — source skipped",
                self.source_name,
                path,
                type(events).__name__,
            )
            return []

        # ── Validate individual events ────────────────────────────────────────
        accepted: list[dict] = []
        rejected_count = 0

        for i, event in enumerate(events):
            if not isinstance(event, dict):
                logger.warning(
                    "[%s] Event #%d is not a dict (got %s) — skipped",
                    self.source_name,
                    i,
                    type(event).__name__,
                )
                rejected_count += 1
                continue

            missing = [f for f in self._required_fields if f not in event]
            if missing:
                logger.warning(
                    "[%s] Event #%d missing required fields %s — skipped. Event: %s",
                    self.source_name,
                    i,
                    missing,
                    event,
                )
                rejected_count += 1
                continue

            accepted.append(event)

        logger.info(
            "[%s] Loaded %d events from %s (%d rejected)",
            self.source_name,
            len(accepted),
            path.name,
            rejected_count,
        )
        return accepted
