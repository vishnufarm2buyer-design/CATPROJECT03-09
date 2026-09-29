"""
src/ingest/email_adapter.py
---------------------------
Adapter for email tool events.

HOW THIS WORKS:
  1. Inherits BaseAdapter.load() — gets file reading + validation for free.
  2. Declares source_name = "email" and the required fields for this source.
  3. The normalizer (src/normalize/normalizer.py) later maps these raw fields
     to the CommonEvent schema.
"""

from __future__ import annotations

from src.ingest.base_adapter import BaseAdapter


class EmailAdapter(BaseAdapter):
    """Adapter for email tool event files."""

    @property
    def source_name(self) -> str:
        return "email"

    @property
    def _required_fields(self) -> list[str]:
        return ["messageId", "timestamp", "eventType", "recipient"]
