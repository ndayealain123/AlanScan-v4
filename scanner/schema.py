"""
AlanScan structured-output versioning (events, JSONL rows, findings, metrics).
"""

SCHEMA_VERSION = "1.0"
EVENT_VERSION = "1.0"

# Legacy envelope key kept for readers; prefer schema_version / event_version.
ENVELOPE_SCHEMA_ID = "alanscan/1.0"
