
import sqlite3
import uuid
import hmac
from pathlib import Path
from datetime import datetime, timezone


DB_PATH = Path(__file__).resolve().parent / "approvals.db"


def _utc_now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def initialize_database():
    """Create the database and migrate older database schemas."""

    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS approval_requests (
                request_id TEXT PRIMARY KEY,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (status IN (
                        'PENDING', 'APPROVED',
                        'REJECTED', 'EXPIRED'
                    )),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_at TEXT,
                authorization_token_hash TEXT,
                authorization_expires_at TEXT,
                authorization_consumed_at TEXT
            )
        """)

        existing = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(approval_requests)"
            ).fetchall()
        }

        migrations = {
            "authorization_token_hash":
                "ALTER TABLE approval_requests ADD COLUMN authorization_token_hash TEXT",

            "authorization_expires_at":
                "ALTER TABLE approval_requests ADD COLUMN authorization_expires_at TEXT",

            "authorization_consumed_at":
                "ALTER TABLE approval_requests ADD COLUMN authorization_consumed_at TEXT",
        }

        for column, statement in migrations.items():
            if column not in existing:
                conn.execute(statement)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_approval_status_created
            ON approval_requests(status, created_at)
        """)

        conn.commit()


# =========================================================
# CREATE APPROVAL REQUEST
# =========================================================

def create_request(recipient, subject, body, ttl_seconds=300):

    if not all(
        isinstance(value, str) and value.strip()
        for value in (recipient, subject, body)
    ):
        raise ValueError(
            "Recipient, subject and body are required."
        )

    if (
        not isinstance(ttl_seconds, int)
        or isinstance(ttl_seconds, bool)
        or ttl_seconds <= 0
        or ttl_seconds > 86400
    ):
        raise ValueError(
            "TTL must be between 1 and 86400 seconds."
        )

    now = _utc_now()
    request_id = str(uuid.uuid4())

    expires_at = datetime.fromtimestamp(
        now.timestamp() + ttl_seconds,
        timezone.utc
    )

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO approval_requests (
                request_id,
                recipient,
                subject,
                body,
                status,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, 'PENDING', ?, ?)
        """, (
            request_id,
            recipient.strip(),
            subject.strip(),
            body,
            _iso(now),
            _iso(expires_at)
        ))

        conn.commit()

    return request_id


# =========================================================
# GET REQUEST
# =========================================================

def get_request(request_id):

    if not isinstance(request_id, str) or not request_id.strip():
        return None

    with get_connection() as conn:
        row = conn.execute("""
            SELECT *
            FROM approval_requests
            WHERE request_id = ?
        """, (request_id,)).fetchone()

    return dict(row) if row else None


# =========================================================
# ADMIN APPROVE / REJECT
# =========================================================

def decide_request(request_id, decision):

    if decision not in {"APPROVED", "REJECTED"}:
        raise ValueError("Invalid decision.")

    now = _utc_now()
    now_text = _iso(now)

    with get_connection() as conn:

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("""
            SELECT status, expires_at
            FROM approval_requests
            WHERE request_id = ?
        """, (request_id,)).fetchone()

        if row is None:
            conn.rollback()
            return False, "Request not found."

        if row["status"] != "PENDING":
            conn.rollback()
            return False, "Request already processed."

        expiry = datetime.fromisoformat(row["expires_at"])

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        if now >= expiry:

            conn.execute("""
                UPDATE approval_requests
                SET status = 'EXPIRED',
                    decided_at = ?
                WHERE request_id = ?
                  AND status = 'PENDING'
            """, (now_text, request_id))

            conn.commit()

            return False, "Request has expired."

        cursor = conn.execute("""
            UPDATE approval_requests
            SET status = ?,
                decided_at = ?
            WHERE request_id = ?
              AND status = 'PENDING'
        """, (decision, now_text, request_id))

        if cursor.rowcount != 1:
            conn.rollback()
            return False, "Request was already processed."

        conn.commit()

    return True, f"Request {decision.lower()} successfully."


# =========================================================
# STORE SIGNED AUTHORIZATION HASH
# =========================================================

def store_authorization(
    request_id,
    token_hash,
    ttl_seconds=300
):
    """
    Store only the SHA-256 hash of the signed token.

    Call this from the trusted approval service after
    an authenticated administrator approves the request.

    Never store the raw authorization token.
    """

    if not isinstance(token_hash, str) or len(token_hash) != 64:
        raise ValueError("A SHA-256 hex digest is required.")

    try:
        int(token_hash, 16)
    except ValueError:
        raise ValueError("Invalid authorization token hash.")

    if (
        not isinstance(ttl_seconds, int)
        or isinstance(ttl_seconds, bool)
        or ttl_seconds <= 0
        or ttl_seconds > 3600
    ):
        raise ValueError(
            "Authorization TTL must be 1 to 3600 seconds."
        )

    now = _utc_now()

    auth_expiry = datetime.fromtimestamp(
        now.timestamp() + ttl_seconds,
        timezone.utc
    )

    with get_connection() as conn:

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("""
            SELECT status, expires_at,
                   authorization_token_hash
            FROM approval_requests
            WHERE request_id = ?
        """, (request_id,)).fetchone()

        if row is None:
            conn.rollback()
            return False, "Request not found."

        request_expiry = datetime.fromisoformat(
            row["expires_at"]
        )

        if request_expiry.tzinfo is None:
            request_expiry = request_expiry.replace(
                tzinfo=timezone.utc
            )

        if row["status"] != "APPROVED":
            conn.rollback()
            return False, (
                "Only approved requests can receive authorization."
            )

        if now >= request_expiry:
            conn.rollback()
            return False, "Approval request has expired."

        if row["authorization_token_hash"] is not None:
            conn.rollback()
            return False, "Authorization has already been issued."

        conn.execute("""
            UPDATE approval_requests
            SET authorization_token_hash = ?,
                authorization_expires_at = ?
            WHERE request_id = ?
              AND status = 'APPROVED'
              AND authorization_token_hash IS NULL
        """, (
            token_hash.lower(),
            _iso(auth_expiry),
            request_id
        ))

        conn.commit()

    return True, "Authorization hash stored."


# =========================================================
# ONE-TIME AUTHORIZATION CONSUMPTION
# =========================================================

def consume_authorization(request_id, token_hash):
    """
    Atomically consume an authorization exactly once.

    The gateway MUST verify the cryptographic signature
    and exact email claims before calling this function.
    """

    if not isinstance(token_hash, str) or len(token_hash) != 64:
        return False, "Invalid authorization."

    try:
        int(token_hash, 16)
    except ValueError:
        return False, "Invalid authorization."

    now = _utc_now()
    now_text = _iso(now)

    with get_connection() as conn:

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("""
            SELECT status,
                   authorization_token_hash,
                   authorization_expires_at,
                   authorization_consumed_at
            FROM approval_requests
            WHERE request_id = ?
        """, (request_id,)).fetchone()

        if row is None:
            conn.rollback()
            return False, "Request not found."

        if row["status"] != "APPROVED":
            conn.rollback()
            return False, "Request is not approved."

        stored_hash = row["authorization_token_hash"]

        if not stored_hash:
            conn.rollback()
            return False, "No authorization was issued."

        if not hmac.compare_digest(
            stored_hash,
            token_hash.lower()
        ):
            conn.rollback()
            return False, "Authorization does not match."

        if row["authorization_consumed_at"] is not None:
            conn.rollback()
            return False, "Authorization already consumed."

        if not row["authorization_expires_at"]:
            conn.rollback()
            return False, "Authorization expiry is missing."

        expiry = datetime.fromisoformat(
            row["authorization_expires_at"]
        )

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        if now >= expiry:
            conn.rollback()
            return False, "Authorization has expired."

        cursor = conn.execute("""
            UPDATE approval_requests
            SET authorization_consumed_at = ?
            WHERE request_id = ?
              AND status = 'APPROVED'
              AND authorization_token_hash = ?
              AND authorization_consumed_at IS NULL
        """, (
            now_text,
            request_id,
            stored_hash
        ))

        if cursor.rowcount != 1:
            conn.rollback()
            return False, "Authorization already consumed."

        conn.commit()

    return True, "Authorization consumed."


# =========================================================
# LIST PENDING REQUESTS
# =========================================================

def list_pending_requests():

    now_text = _iso(_utc_now())

    with get_connection() as conn:
        rows = conn.execute("""
            SELECT request_id,
                   recipient,
                   subject,
                   body,
                   created_at,
                   expires_at
            FROM approval_requests
            WHERE status = 'PENDING'
              AND expires_at > ?
            ORDER BY created_at DESC
        """, (now_text,)).fetchall()

    return [dict(row) for row in rows]
