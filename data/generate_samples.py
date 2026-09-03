"""
generate_samples.py
-------------------
Regenerates synthetic sample data for identity and endpoint sources.
Run this to recreate data/identity_events.json and data/endpoint_events.json
from scratch — ensures the repo is fully reproducible.

Usage:
    python data/generate_samples.py
"""

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Reproducibility ──────────────────────────────────────────────────────────
random.seed(42)

BASE_DATE = datetime(2024, 11, 15, 7, 0, 0, tzinfo=timezone.utc)
OUT_DIR = Path(__file__).parent


def ts(offset_minutes: float) -> str:
    """Return an ISO-8601 UTC timestamp offset from BASE_DATE."""
    return (BASE_DATE + timedelta(minutes=offset_minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


# ── Identity Events ───────────────────────────────────────────────────────────
# Scenario A: alice@corp.com — brute-force then MFA bypass (the main chain)
# Scenario B: bob@corp.com   — normal login + password reset
# Scenario C: carol@corp.com — one failed + one successful login (normal)
# Scenario D: dave@corp.com  — failed logins only (no compromise)
# Scenario E: eve@corp.com   — privileged login + credential dump

identity_events = [
    # -- alice: 5 failed logins then success + MFA bypass (t=61..67 min) --
    {"userId": "alice@corp.com", "timestamp": ts(61.0), "eventType": "LOGIN_FAILED",
     "riskLevel": "medium", "sourceIp": "185.220.101.45", "deviceId": None,
     "sessionId": None, "location": "RU", "userAgent": "python-requests/2.28"},
    {"userId": "alice@corp.com", "timestamp": ts(61.5), "eventType": "LOGIN_FAILED",
     "riskLevel": "medium", "sourceIp": "185.220.101.45", "deviceId": None,
     "sessionId": None, "location": "RU", "userAgent": "python-requests/2.28"},
    {"userId": "alice@corp.com", "timestamp": ts(62.0), "eventType": "LOGIN_FAILED",
     "riskLevel": "medium", "sourceIp": "185.220.101.45", "deviceId": None,
     "sessionId": None, "location": "RU", "userAgent": "python-requests/2.28"},
    {"userId": "alice@corp.com", "timestamp": ts(62.5), "eventType": "LOGIN_FAILED",
     "riskLevel": "high", "sourceIp": "185.220.101.45", "deviceId": None,
     "sessionId": None, "location": "RU", "userAgent": "python-requests/2.28"},
    {"userId": "alice@corp.com", "timestamp": ts(63.17), "eventType": "LOGIN_FAILED",
     "riskLevel": "high", "sourceIp": "185.220.101.45", "deviceId": None,
     "sessionId": None, "location": "RU", "userAgent": "python-requests/2.28"},
    {"userId": "alice@corp.com", "timestamp": ts(64.0), "eventType": "LOGIN_SUCCESS",
     "riskLevel": "high", "sourceIp": "185.220.101.45", "deviceId": "WKSTN-042",
     "sessionId": "sess-alice-001", "location": "RU", "userAgent": "python-requests/2.28"},
    {"userId": "alice@corp.com", "timestamp": ts(64.75), "eventType": "MFA_BYPASS",
     "riskLevel": "critical", "sourceIp": "185.220.101.45", "deviceId": "WKSTN-042",
     "sessionId": "sess-alice-001", "location": "RU", "userAgent": "python-requests/2.28"},
    # -- bob: normal session (t=120..150 min) --
    {"userId": "bob@corp.com", "timestamp": ts(120.0), "eventType": "LOGIN_SUCCESS",
     "riskLevel": "low", "sourceIp": "10.0.1.5", "deviceId": "WKSTN-017",
     "sessionId": "sess-bob-001", "location": "US", "userAgent": "Mozilla/5.0"},
    {"userId": "bob@corp.com", "timestamp": ts(150.0), "eventType": "PASSWORD_RESET",
     "riskLevel": "low", "sourceIp": "10.0.1.5", "deviceId": "WKSTN-017",
     "sessionId": "sess-bob-001", "location": "US", "userAgent": "Mozilla/5.0"},
    # -- carol: one failed then success (t=180..181 min) --
    {"userId": "carol@corp.com", "timestamp": ts(180.0), "eventType": "LOGIN_FAILED",
     "riskLevel": "low", "sourceIp": "10.0.2.33", "deviceId": None,
     "sessionId": None, "location": "US", "userAgent": "Mozilla/5.0"},
    {"userId": "carol@corp.com", "timestamp": ts(181.0), "eventType": "LOGIN_SUCCESS",
     "riskLevel": "low", "sourceIp": "10.0.2.33", "deviceId": "WKSTN-099",
     "sessionId": "sess-carol-001", "location": "US", "userAgent": "Mozilla/5.0"},
    # -- dave: 3 failed logins (no success) (t=240 min) --
    {"userId": "dave@corp.com", "timestamp": ts(240.0), "eventType": "LOGIN_FAILED",
     "riskLevel": "medium", "sourceIp": "203.0.113.77", "deviceId": None,
     "sessionId": None, "location": "CN", "userAgent": "curl/7.68"},
    {"userId": "dave@corp.com", "timestamp": ts(240.33), "eventType": "LOGIN_FAILED",
     "riskLevel": "medium", "sourceIp": "203.0.113.77", "deviceId": None,
     "sessionId": None, "location": "CN", "userAgent": "curl/7.68"},
    {"userId": "dave@corp.com", "timestamp": ts(240.67), "eventType": "LOGIN_FAILED",
     "riskLevel": "medium", "sourceIp": "203.0.113.77", "deviceId": None,
     "sessionId": None, "location": "CN", "userAgent": "curl/7.68"},
    # -- eve: privileged login on DC (t=0 min) --
    {"userId": "eve@corp.com", "timestamp": ts(0.0), "eventType": "LOGIN_SUCCESS",
     "riskLevel": "low", "sourceIp": "10.0.3.12", "deviceId": "SRV-DC-01",
     "sessionId": "sess-eve-001", "location": "US", "userAgent": "Mozilla/5.0"},
]

# ── Endpoint Events ───────────────────────────────────────────────────────────
endpoint_events = [
    # -- WKSTN-042 (alice's machine): suspicious powershell → C2 → dropper --
    {"hostName": "WKSTN-042", "timestamp": ts(65.5), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "high", "processName": "powershell.exe",
     "commandLine": "powershell -nop -enc JABjAGwAaQBlAG4AdAA=",
     "parentProcess": "winlogon.exe", "loggedOnUser": "alice@corp.com", "pid": 4821,
     "filePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    {"hostName": "WKSTN-042", "timestamp": ts(66.0), "eventCategory": "NETWORK_CONN",
     "alertSeverity": "high", "processName": "powershell.exe", "commandLine": None,
     "parentProcess": None, "loggedOnUser": "alice@corp.com", "pid": 4821,
     "destinationIp": "185.220.101.45", "destinationPort": 4444},
    {"hostName": "WKSTN-042", "timestamp": ts(67.0), "eventCategory": "FILE_WRITE",
     "alertSeverity": "medium", "processName": "powershell.exe", "commandLine": None,
     "parentProcess": None, "loggedOnUser": "alice@corp.com", "pid": 4821,
     "filePath": "C:\\Users\\alice\\AppData\\Roaming\\svchost32.exe"},
    {"hostName": "WKSTN-042", "timestamp": ts(68.0), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "critical", "processName": "svchost32.exe",
     "commandLine": "svchost32.exe -persist", "parentProcess": "powershell.exe",
     "loggedOnUser": "alice@corp.com", "pid": 4902,
     "filePath": "C:\\Users\\alice\\AppData\\Roaming\\svchost32.exe"},
    # -- WKSTN-017 (bob's machine): normal activity --
    {"hostName": "WKSTN-017", "timestamp": ts(125.0), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "low", "processName": "chrome.exe",
     "commandLine": "chrome.exe --profile-directory=Default",
     "parentProcess": "explorer.exe", "loggedOnUser": "bob@corp.com", "pid": 3210,
     "filePath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
    {"hostName": "WKSTN-017", "timestamp": ts(130.0), "eventCategory": "FILE_WRITE",
     "alertSeverity": "low", "processName": "chrome.exe", "commandLine": None,
     "parentProcess": None, "loggedOnUser": "bob@corp.com", "pid": 3210,
     "filePath": "C:\\Users\\bob\\Downloads\\report.pdf"},
    # -- WKSTN-099 (carol's machine): normal --
    {"hostName": "WKSTN-099", "timestamp": ts(183.0), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "low", "processName": "outlook.exe", "commandLine": "OUTLOOK.EXE",
     "parentProcess": "explorer.exe", "loggedOnUser": "carol@corp.com", "pid": 5500,
     "filePath": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},
    # -- SRV-DC-01 (eve's machine): credential dump --
    {"hostName": "SRV-DC-01", "timestamp": ts(10.0), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "medium", "processName": "cmd.exe",
     "commandLine": "cmd.exe /c net user /domain", "parentProcess": "powershell.exe",
     "loggedOnUser": "eve@corp.com", "pid": 1102,
     "filePath": "C:\\Windows\\System32\\cmd.exe"},
    {"hostName": "SRV-DC-01", "timestamp": ts(12.0), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "high", "processName": "mimikatz.exe",
     "commandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
     "parentProcess": "cmd.exe", "loggedOnUser": "eve@corp.com", "pid": 1150,
     "filePath": "C:\\Temp\\mimikatz.exe"},
    {"hostName": "SRV-DC-01", "timestamp": ts(15.0), "eventCategory": "NETWORK_CONN",
     "alertSeverity": "high", "processName": "mimikatz.exe", "commandLine": None,
     "parentProcess": None, "loggedOnUser": "eve@corp.com", "pid": 1150,
     "destinationIp": "10.0.99.5", "destinationPort": 445},
    # -- C2 beacon from WKSTN-042 (continuation of alice chain, ~80 min) --
    {"hostName": "WKSTN-042", "timestamp": ts(80.0), "eventCategory": "NETWORK_CONN",
     "alertSeverity": "high", "processName": "svchost32.exe", "commandLine": None,
     "parentProcess": None, "loggedOnUser": "alice@corp.com", "pid": 4902,
     "destinationIp": "185.220.101.45", "destinationPort": 443},
    {"hostName": "WKSTN-042", "timestamp": ts(90.0), "eventCategory": "FILE_WRITE",
     "alertSeverity": "critical", "processName": "svchost32.exe", "commandLine": None,
     "parentProcess": None, "loggedOnUser": "alice@corp.com", "pid": 4902,
     "filePath": "C:\\Windows\\System32\\drivers\\etc\\hosts"},
    # -- System process with no user (loggedOnUser null) --
    {"hostName": "WKSTN-LEGACY-03", "timestamp": ts(60.0), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "low", "processName": "antivirus.exe",
     "commandLine": "antivirus.exe --scan --quick", "parentProcess": "services.exe",
     "loggedOnUser": None, "pid": 800,
     "filePath": "C:\\Program Files\\Antivirus\\antivirus.exe"},
    # -- Scheduled backup (should NOT trigger correlation) --
    {"hostName": "WKSTN-111", "timestamp": ts(780.0), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "low", "processName": "python.exe",
     "commandLine": "python scheduled_backup.py", "parentProcess": "taskeng.exe",
     "loggedOnUser": None, "pid": 6600, "filePath": "C:\\Python39\\python.exe"},
    # -- Benign alice activity late in day (should NOT chain with morning events) --
    {"hostName": "WKSTN-042", "timestamp": ts(705.0), "eventCategory": "PROCESS_EXEC",
     "alertSeverity": "low", "processName": "notepad.exe",
     "commandLine": "notepad.exe C:\\Users\\alice\\notes.txt",
     "parentProcess": "explorer.exe", "loggedOnUser": "alice@corp.com", "pid": 7700,
     "filePath": "C:\\Windows\\notepad.exe"},
]

# ── Write files ───────────────────────────────────────────────────────────────
(OUT_DIR / "identity_events.json").write_text(
    json.dumps(identity_events, indent=2), encoding="utf-8"
)
(OUT_DIR / "endpoint_events.json").write_text(
    json.dumps(endpoint_events, indent=2), encoding="utf-8"
)
print(f"Generated {len(identity_events)} identity events → data/identity_events.json")
print(f"Generated {len(endpoint_events)} endpoint events → data/endpoint_events.json")
