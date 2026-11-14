"""Append-only SQLite audit trail for SafeMail security events.

The log intentionally stores identifiers and decision metadata only; never
store email bodies, passwords, session cookies, or signing secrets here.
"""

import json
import sqlite3
import time
from pathlib import Path


ALLOWED_EVENTS = {
    "APPROVAL_ISSUED",
    "APPROVAL_EXPIRED",
    "APPROVAL_CONSUMED",
    "POLICY_BLOCKED",
    "EMAIL_SEND_SUCCEEDED",
    "EMAIL_SEND_FAILED",
}


def record_event(event_type, *, db_path="safemail/approvals.db", details=None):
    """Persist one security event. Raises on failure so callers can fail closed."""
    if event_type not in ALLOWED_EVENTS:
        raise ValueError("Unsupported audit event type.")

    safe_details = details or {}
    if not isinstance(safe_details, dict):
        raise ValueError("Audit details must be a dictionary.")

    # Keep the audit schema deliberately small and avoid storing message content.
    payload = json.dumps(safe_details, sort_keys=True, separators=(",", ":"))
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path), timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                details_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO audit_events (event_type, occurred_at, details_json) "
            "VALUES (?, ?, ?)",
            (event_type, time.time(), payload),
        )
        conn.commit()
    finally:
        conn.close()
