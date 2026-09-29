"""
src/ingest/network_adapter.py
-----------------------------
Adapter for network events.
"""

from __future__ import annotations

from src.ingest.base_adapter import BaseAdapter


class NetworkAdapter(BaseAdapter):
    """Adapter for network tool event files."""

    @property
    def source_name(self) -> str:
        return "network"

    @property
    def _required_fields(self) -> list[str]:
        return ["flowId", "timestamp", "eventType", "sourceIp"]
