"""
src/ingest/endpoint_adapter.py
------------------------------
Adapter for endpoint tool events (CrowdStrike / Microsoft Defender / similar).

HOW THIS WORKS:
  Same pattern as IdentityAdapter — inherits BaseAdapter.load() and declares
  the fields specific to endpoint tool exports.

WHAT IT READS:
  Raw endpoint events look like:
    {
      "hostName":      "WKSTN-042",
      "timestamp":     "2024-11-15T08:05:30Z",
      "eventCategory": "PROCESS_EXEC",
      "alertSeverity": "high",
      "processName":   "powershell.exe",
      "commandLine":   "powershell -nop -enc ...",
      "loggedOnUser":  "alice@corp.com",   ← OPTIONAL (null for system processes)
      "pid":           4821
    }

REQUIRED FIELDS:
  hostName, timestamp, eventCategory, alertSeverity

OPTIONAL FIELDS:
  loggedOnUser (null for system-initiated processes — e.g., scheduled tasks),
  processName, commandLine, parentProcess, pid, filePath,
  destinationIp, destinationPort
"""

from __future__ import annotations

from src.ingest.base_adapter import BaseAdapter


class EndpointAdapter(BaseAdapter):
    """Adapter for endpoint-tool (CrowdStrike / Defender) event files."""

    @property
    def source_name(self) -> str:
        return "endpoint"

    @property
    def _required_fields(self) -> list[str]:
        return ["hostName", "timestamp", "eventCategory", "alertSeverity"]
