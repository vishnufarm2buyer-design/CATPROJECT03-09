"""
src/ingest/cloud_adapter.py
---------------------------
Adapter for cloud events.
"""

from __future__ import annotations

from src.ingest.base_adapter import BaseAdapter


class CloudAdapter(BaseAdapter):
    """Adapter for cloud tool event files."""

    @property
    def source_name(self) -> str:
        return "cloud"

    @property
    def _required_fields(self) -> list[str]:
        return ["eventId", "timestamp", "eventType", "principal"]
