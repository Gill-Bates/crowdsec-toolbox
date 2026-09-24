#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/database.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import os
import sqlite3
import threading
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from app.logger import (
    TAGS,
    print_config_info,
    print_database_error,
    print_debug,
    print_log,
)

DB_PATH = Path(
    os.getenv(
        "ABUSE_DB_PATH",
        str(Path(__file__).resolve().parent.parent / "data" / "abuse_alerts.db"),
    )
)

NEGATIVE_CACHE = ""
SQLITE_PARAM_LIMIT = 900
NEGATIVE_CACHE_TTL_DAYS = 7

# Statuses that mean "do not re-process this report". 'unknown_send_state' is
# a terminal state for rows where SMTP outcome is uncertain (crashed mid-send).
# We never retry these to guarantee at-most-once delivery for abuse reports.
HANDLED_STATUSES = ("sent", "pending", "unknown_send_state")

_thread_local = threading.local()
_db_initialized = False
_init_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    """
    Get or create database connection for current thread with lazy initialization.

    Returns:
        Thread-safe SQLite connection
    """
    global _db_initialized

    if not hasattr(_thread_local, "conn"):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Create connection with thread safety
        _thread_local.conn = sqlite3.connect(
            DB_PATH,
            check_same_thread=False,
            timeout=30.0,
        )
        _thread_local.conn.row_factory = sqlite3.Row

        # Enable performance optimizations
        _thread_local.conn.execute("PRAGMA journal_mode=WAL")
        _thread_local.conn.execute("PRAGMA synchronous=NORMAL")
        _thread_local.conn.execute("PRAGMA foreign_keys=ON")
        _thread_local.conn.execute("PRAGMA busy_timeout=5000")

        # Initialize database schema if needed
        if not _db_initialized:
            with _init_lock:
                if not _db_initialized:
                    _initialize_database_schema(_thread_local.conn)
                    _db_initialized = True

    return _thread_local.conn


def _initialize_database_schema(conn: sqlite3.Connection) -> None:
    """
    Initialize database tables and indexes.

    Args:
        conn: Database connection
    """
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='abuse_alerts'"
        )
        schema_exists = cursor.fetchone()[0] > 0

        # Create main alerts table.
        # Status drives idempotency:
        #   'pending'            - claimed for sending; never re-sent automatically
        #   'sent'               - mail delivered; never sent again
        #   'failed'             - send failed (no mail went out); eligible for retry
        #   'unknown_send_state' - stale 'pending' moved here by the reaper; terminal
        # Idempotency unit is one report per (alert, IP): a single alert can
        # bundle several bans (different IPs), so AlertId alone is not unique —
        # the (AlertId, IPAddress) pair is.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS abuse_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                AlertId INTEGER NOT NULL,
                Recipient TEXT NOT NULL,
                IPAddress TEXT NOT NULL,
                Scenario TEXT NOT NULL,
                Sent INTEGER NOT NULL DEFAULT 1
                    CHECK (Sent IN (0, 1)),
                Status TEXT NOT NULL DEFAULT 'sent'
                    CHECK (Status IN ('pending', 'sent', 'failed', 'unknown_send_state')),
                ErrorMessage TEXT,
                CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(AlertId, IPAddress)
            )
        """)

        # Create abuse contacts cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS abuse_contacts_cache (
                ip_prefix TEXT PRIMARY KEY,
                abuse_contact TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Control data about the exporter itself (last run start/end/exit
        # code, active metrics backend). Key/value, one row per key.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS run_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Durable spool for metrics points the backend has not accepted yet.
        #
        # This is control data, not a second copy of the report: the line holds
        # only what was already sent to the backend, and a row exists only while
        # that write is outstanding. Without it a failed write lost the points
        # for good, because with a backend enabled the report details are stored
        # nowhere else (see abuse_alerts above, whose detail columns stay empty
        # in that mode).
        #
        # Replaying the spool is exactly idempotent — the timestamp is part of
        # the line and of the backend's dedup key set — so a point may be sent
        # again without tracking which one of a batch failed.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metrics_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                line TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for better performance
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_id ON abuse_alerts(AlertId)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_ip_address ON abuse_alerts(IPAddress)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_created_at ON abuse_alerts(CreatedAt)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_sent_status ON abuse_alerts(Sent)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_status ON abuse_alerts(Status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cache_prefix ON abuse_contacts_cache(ip_prefix)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cache_updated ON abuse_contacts_cache(updated_at)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_outbox_created ON metrics_outbox(created_at)"
        )

        # Create trigger for automatic UpdatedAt
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS update_abuse_alerts_timestamp
            AFTER UPDATE ON abuse_alerts
            BEGIN
                UPDATE abuse_alerts SET UpdatedAt = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
        """)

        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS update_cache_timestamp
            AFTER UPDATE ON abuse_contacts_cache
            BEGIN
                UPDATE abuse_contacts_cache SET updated_at = CURRENT_TIMESTAMP WHERE ip_prefix = NEW.ip_prefix;
            END
        """)

        conn.commit()
        if schema_exists:
            print_debug(f"Database ready at {DB_PATH}")
        else:
            print_config_info(f"Database schema created at {DB_PATH}")

    except Exception as e:
        print_database_error(0, f"Failed to initialize database schema: {e}")
        conn.rollback()
        raise


@contextmanager
def db_transaction():
    """
    Context manager for database write transactions with automatic rollback on error.
    Use db_read() for read-only operations to avoid unnecessary commits.

    Yields:
        Database connection for transaction operations
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        print_database_error(0, f"Transaction failed, rolled back: {e}")
        raise


@contextmanager
def db_read():
    """
    Context manager for read-only database operations.
    Does not commit, avoiding unnecessary WAL writes.

    Yields:
        Database connection for read operations
    """
    yield get_connection()


def init_db() -> None:
    """
    Initialize the database (public interface).

    Schema creation itself is lazy (triggered by get_connection()), but this
    call is still load-bearing: main() calls it as an early startup gate and
    treats any exception as a hard failure (exit code 1), before the run
    state is set and before any report is claimed or sent.
    """
    # Connection will be initialized on first access
    get_connection()
    print_config_info("Database initialization completed")


def _chunks(values: list[Any], size: int = SQLITE_PARAM_LIMIT):
    """Yield successive chunks from values."""
    for index in range(0, len(values), size):
        yield values[index : index + size]


def batch_check_processed_alerts(
    alert_keys: list[tuple[int, str]]
) -> set[tuple[int, str]]:
    """
    Batch check which (alert, IP) reports must NOT be (re)processed in this run.

    A report is considered done when its Status is in HANDLED_STATUSES: 'sent'
    (already reported), 'pending' (claimed/in-flight or left over from a crash
    mid-send) or 'unknown_send_state' (reaped stale claim) — never auto-resent,
    to guarantee at-most-once delivery. Rows with Status 'failed' are
    intentionally excluded so genuine send failures can be retried.

    Args:
        alert_keys: List of (alert_id, ip) pairs to check

    Returns:
        Set of (alert_id, ip) pairs that should be skipped
    """
    if not alert_keys:
        return set()

    # Each pair binds two params; HANDLED_STATUSES adds fixed extra params per
    # query. Subtract those first so the total never exceeds SQLITE_PARAM_LIMIT.
    pair_chunk_size = (SQLITE_PARAM_LIMIT - len(HANDLED_STATUSES)) // 2

    processed: set[tuple[int, str]] = set()
    with db_read() as conn:
        cursor = conn.cursor()
        status_placeholders = ",".join("?" for _ in HANDLED_STATUSES)
        for chunk in _chunks(alert_keys, pair_chunk_size):
            placeholders = ",".join("(?,?)" for _ in chunk)
            params: list[Any] = [value for pair in chunk for value in pair]
            query = f"""
                SELECT AlertId, IPAddress FROM abuse_alerts
                WHERE (AlertId, IPAddress) IN ({placeholders})
                  AND Status IN ({status_placeholders})
            """
            cursor.execute(query, [*params, *HANDLED_STATUSES])
            processed.update((row[0], row[1]) for row in cursor.fetchall())

    print_debug(
        f"Batch check: {len(processed)} of {len(alert_keys)} reports already handled"
    )
    return processed


def claim_alert_for_send(alert_id: int, ip: str, scenario: str) -> bool:
    """
    Atomically claim an alert for sending.

    A single conditional UPSERT either inserts a fresh 'pending' row or promotes
    a previously 'failed' row back to 'pending'. Rows already in 'sent' or
    'pending' state are left untouched. The claim succeeds (returns True) only
    when this call is the one that created or transitioned the row, so two
    concurrent runs can never both send the same report.

    Note: a send interrupted after SMTP accepted the mail but before
    finalize_alert() runs leaves the row 'pending'. reap_stale_pending() moves
    such a row to the terminal 'unknown_send_state', which is never claimed
    again, so no duplicate report can be produced.

    Args:
        alert_id: CrowdSec alert identifier
        ip: Source IP address
        scenario: CrowdSec scenario name

    Returns:
        True if the caller owns the claim and may send; False when the report
        is already 'sent' or 'pending' and must be skipped.

    Raises:
        sqlite3.Error / Exception: The claim could not be recorded (DB locked,
            disk full, ...). Propagated on purpose: a persistence failure must
            stay distinguishable from a legitimate "already handled" skip, or
            the run reports success while no report went out.
    """
    try:
        with db_transaction() as conn:
            # RETURNING reports whether this statement inserted or updated a row.
            # It is unaffected by the UpdatedAt trigger (which would otherwise
            # inflate total_changes), so it reliably signals claim ownership.
            cursor = conn.execute(
                """
                INSERT INTO abuse_alerts
                    (AlertId, Recipient, IPAddress, Scenario, Sent, Status)
                VALUES (?, '', ?, ?, 0, 'pending')
                ON CONFLICT(AlertId, IPAddress) DO UPDATE SET
                    Status = 'pending',
                    Scenario = excluded.Scenario,
                    UpdatedAt = CURRENT_TIMESTAMP
                WHERE abuse_alerts.Status = 'failed'
                RETURNING AlertId
                """,
                (alert_id, ip, scenario),
            )
            return cursor.fetchone() is not None
    except Exception as e:
        print_database_error(alert_id, f"Failed to claim alert for send: {e}")
        # Fail closed (no send without a recorded claim) *and* fail loud: the
        # caller must count this as a database error, not as an idempotent skip.
        raise


def finalize_alert(
    alert_id: int,
    recipient: str,
    ip: str,
    scenario: str,
    sent: bool,
    error_msg: str | None = None,
) -> None:
    """
    Record the outcome of a claimed send (transition out of 'pending').

    Args:
        alert_id: CrowdSec alert identifier
        recipient: Abuse contact email
        ip: Source IP address
        scenario: CrowdSec scenario name
        sent: Whether the email was delivered successfully
        error_msg: Error message if sending failed
    """
    status = "sent" if sent else "failed"
    try:
        with db_transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE abuse_alerts SET
                    Recipient = ?,
                    Scenario = ?,
                    Sent = ?,
                    Status = ?,
                    ErrorMessage = ?,
                    UpdatedAt = CURRENT_TIMESTAMP
                WHERE AlertId = ? AND IPAddress = ? AND Status = 'pending'
                """,
                (recipient, scenario, int(sent), status, error_msg, alert_id, ip),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(
                    f"Expected to finalize one pending row for alert={alert_id}, ip={ip}; "
                    f"updated {cursor.rowcount} (row missing, already finalized, or not pending)"
                )
    except Exception as e:
        print_database_error(alert_id, f"Failed to finalize alert: {e}")
        raise


def reap_stale_pending(max_age_minutes: int) -> int:
    """Mark stale 'pending' rows as having an unknown SMTP outcome.

    A row stays 'pending' when a send was claimed but never finalized — the
    process crashed or was killed mid-send, or finalize_alert() itself failed
    (DB locked, disk full). SMTP may or may not have accepted the mail, so the
    row is moved to the terminal 'unknown_send_state' instead of being requeued:
    at-most-once delivery is preferred over a possible duplicate abuse report.
    These rows are never retried automatically and stay visible in the DB for
    manual inspection. Runs are serial, so any row still pending past
    max_age_minutes belongs to an interrupted earlier run.

    Args:
        max_age_minutes: Mark pending rows older than this. 0 = disabled.

    Returns:
        Number of rows marked 'unknown_send_state'.
    """
    if max_age_minutes <= 0:
        return 0

    try:
        with db_transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE abuse_alerts
                SET Status = 'unknown_send_state',
                    Sent = 0,
                    ErrorMessage = 'SMTP outcome unknown: claimed but never finalized (interrupted run)',
                    UpdatedAt = CURRENT_TIMESTAMP
                WHERE Status = 'pending'
                  AND UpdatedAt < datetime('now', ?)
                """,
                (f"-{max_age_minutes} minutes",),
            )
            marked = cursor.rowcount

        if marked > 0:
            print_config_info(
                f"Reaper: {marked} stale pending report(s) older than {max_age_minutes}min "
                f"marked unknown_send_state (SMTP outcome uncertain, not retried)"
            )
        return marked

    except Exception as e:
        print_database_error(0, f"Failed to reap stale pending rows: {e}")
        return 0


def get_cached_abuse_contact(ip_prefix: str) -> tuple[bool, str | None]:
    """
    Get cached abuse contact for an IP prefix.

    Args:
        ip_prefix: IP network prefix (e.g., "192.0.2.0/24")

    Returns:
        Tuple of (cache_hit, abuse_contact). abuse_contact is None for negative cache entries.
    """
    try:
        with db_read() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT abuse_contact FROM abuse_contacts_cache WHERE ip_prefix = ?",
                (ip_prefix,),
            )
            result = cursor.fetchone()
            if result is None:
                return False, None
            return True, result[0] if result[0] != NEGATIVE_CACHE else None

    except Exception as e:
        print_database_error(
            0, f"Failed to get cached abuse contact for {ip_prefix}: {e}"
        )
        return False, None


def set_cached_abuse_contact(ip_prefix: str, abuse_contact: str | None) -> None:
    """
    Cache abuse contact for an IP prefix.

    Args:
        ip_prefix: IP network prefix
        abuse_contact: Abuse contact email or None for negative caching
    """
    try:
        with db_transaction() as conn:
            cursor = conn.cursor()
            contact_to_cache = abuse_contact or NEGATIVE_CACHE

            cursor.execute(
                """
                INSERT INTO abuse_contacts_cache
                (ip_prefix, abuse_contact)
                VALUES (?, ?)
                ON CONFLICT(ip_prefix) DO UPDATE SET
                    abuse_contact = excluded.abuse_contact,
                    updated_at = CURRENT_TIMESTAMP
            """,
                (ip_prefix, contact_to_cache),
            )

    except Exception as e:
        print_database_error(0, f"Failed to cache abuse contact for {ip_prefix}: {e}")


def set_run_state(values: dict[str, str]) -> None:
    """Upsert control values (e.g. last_run_started_at) in run_state. Non-fatal."""
    try:
        with db_transaction() as conn:
            conn.executemany(
                """
                INSERT INTO run_state (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                list(values.items()),
            )
    except sqlite3.Error as e:
        print_database_error(0, f"Failed to record run state: {e}")


def spool_metric_points(lines: list[str]) -> bool:
    """Append metrics points to the outbox before any backend write is attempted.

    Returns False when the points could not be persisted, which is the only case
    where a subsequent write failure still loses them.
    """
    if not lines:
        return True
    try:
        with db_transaction() as conn:
            conn.executemany(
                "INSERT INTO metrics_outbox (line) VALUES (?)",
                [(line,) for line in lines],
            )
        return True
    except sqlite3.Error as e:
        print_database_error(0, f"Failed to spool {len(lines)} metrics point(s): {e}")
        return False


def load_metric_points(limit: int) -> list[tuple[int, str]]:
    """Return up to *limit* spooled points as (id, line), oldest first."""
    if limit <= 0:
        return []
    try:
        with db_read() as conn:
            rows = conn.execute(
                "SELECT id, line FROM metrics_outbox ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
            return [(row[0], row[1]) for row in rows]
    except sqlite3.Error as e:
        print_database_error(0, f"Failed to read the metrics outbox: {e}")
        return []


def delete_metric_points(ids: list[int]) -> int:
    """Remove acknowledged points from the outbox. Returns the rows deleted."""
    if not ids:
        return 0
    deleted = 0
    try:
        with db_transaction() as conn:
            for chunk in _chunks(ids):
                placeholders = ",".join("?" for _ in chunk)
                cursor = conn.execute(
                    f"DELETE FROM metrics_outbox WHERE id IN ({placeholders})",
                    chunk,
                )
                deleted += cursor.rowcount or 0
    except sqlite3.Error as e:
        # The points are already in the backend; a failure here only means they
        # will be sent once more on the next run, which dedup collapses.
        print_database_error(0, f"Failed to clear {len(ids)} outbox row(s): {e}")
    return deleted


def count_metric_points() -> int:
    """Return the number of points currently waiting in the outbox."""
    try:
        with db_read() as conn:
            return conn.execute("SELECT COUNT(*) FROM metrics_outbox").fetchone()[0]
    except sqlite3.Error as e:
        print_database_error(0, f"Failed to count the metrics outbox: {e}")
        return 0


def prune_metric_outbox(max_rows: int, max_age_days: int) -> int:
    """Drop the oldest spooled points beyond the configured bounds.

    A prolonged backend outage must not grow the database without limit. Oldest
    rows go first: they are the least useful, and discarding them is exactly the
    outcome this code had before the outbox existed. Either bound is disabled
    with 0.
    """
    dropped = 0
    try:
        with db_transaction() as conn:
            if max_age_days > 0:
                cursor = conn.execute(
                    "DELETE FROM metrics_outbox "
                    "WHERE created_at < datetime('now', ?)",
                    (f"-{max_age_days} days",),
                )
                dropped += cursor.rowcount or 0
            if max_rows > 0:
                # Keep the newest max_rows rows; id is monotonic, so the cut-off
                # is the id of the newest row to drop.
                cursor = conn.execute(
                    "DELETE FROM metrics_outbox WHERE id NOT IN ("
                    "  SELECT id FROM metrics_outbox ORDER BY id DESC LIMIT ?"
                    ")",
                    (max_rows,),
                )
                dropped += cursor.rowcount or 0
    except sqlite3.Error as e:
        print_database_error(0, f"Failed to prune the metrics outbox: {e}")
        return dropped
    if dropped:
        print_log(
            "WARNING",
            TAGS["WARNING"],
            f"Dropped {dropped} metrics point(s) from the outbox "
            f"(limits: {max_rows} rows, {max_age_days} days) — the backend was "
            f"unreachable for too long",
        )
    return dropped


def get_run_state() -> dict[str, str]:
    """Return all run_state entries; empty on error."""
    try:
        with db_read() as conn:
            rows = conn.execute("SELECT key, value FROM run_state").fetchall()
            return {row[0]: row[1] for row in rows}
    except sqlite3.Error as e:
        print_database_error(0, f"Failed to read run state: {e}")
        return {}


def get_alert_stats() -> dict[str, Any]:
    """
    Get statistics about processed alerts.

    Returns:
        Dictionary with alert statistics
    """
    try:
        with db_read() as conn:
            cursor = conn.cursor()
            stats = {}

            cursor.execute("SELECT COUNT(*) FROM abuse_alerts")
            stats["total"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM abuse_alerts WHERE Sent = 1")
            stats["successful"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM abuse_alerts WHERE Sent = 0")
            stats["failed"] = cursor.fetchone()[0]

            return stats

    except Exception as e:
        print_database_error(0, f"Failed to get alert statistics: {e}")
        return {}


def cleanup_old_records(days_to_keep: int) -> tuple[int, int]:
    """Delete records older than days_to_keep and reclaim disk space.

    abuse_alerts rows are removed by CreatedAt; abuse_contacts_cache entries
    by updated_at (using 2× the retention period so contacts are re-resolved
    less often than alerts are retired). After any deletion the WAL is
    truncated with a checkpoint, which must run outside the transaction.

    Args:
        days_to_keep: Delete records older than this many days. 0 = skip.

    Returns:
        Tuple of (alerts_deleted, cache_entries_deleted)
    """
    if days_to_keep <= 0:
        return 0, 0

    alerts_deleted = 0
    cache_deleted = 0

    try:
        with db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM abuse_alerts WHERE CreatedAt < datetime('now', ?)",
                (f"-{days_to_keep} days",),
            )
            alerts_deleted = cursor.rowcount
            cursor.execute(
                """
                DELETE FROM abuse_contacts_cache
                WHERE (
                    abuse_contact != ?
                    AND updated_at < datetime('now', ?)
                ) OR (
                    abuse_contact = ?
                    AND updated_at < datetime('now', ?)
                )
                """,
                (
                    NEGATIVE_CACHE,
                    f"-{days_to_keep * 2} days",
                    NEGATIVE_CACHE,
                    f"-{NEGATIVE_CACHE_TTL_DAYS} days",
                ),
            )
            cache_deleted = cursor.rowcount

        cleanup_msg = (
            f"DB cleanup: {alerts_deleted} alert(s), {cache_deleted} cache "
            f"entry/entries removed"
        )
        if alerts_deleted > 0 or cache_deleted > 0:
            # Use WAL checkpoint instead of VACUUM: checkpointing is non-blocking
            # and sufficient to reclaim WAL space. VACUUM requires exclusive access
            # and can stall concurrent startups.
            with suppress(Exception):
                get_connection().execute("PRAGMA wal_checkpoint(TRUNCATE)")
            print_config_info(cleanup_msg)
        else:
            print_debug(cleanup_msg)
        return alerts_deleted, cache_deleted

    except Exception as e:
        print_database_error(0, f"Failed to cleanup old records: {e}")
        return 0, 0


def run_db_maintenance() -> None:
    """Run lightweight per-startup maintenance tasks.

    - PRAGMA optimize: lets SQLite selectively run ANALYZE when query-planner
      statistics are stale. Designed to be called before long-lived connections
      are closed; here it runs early so the planner is calibrated for this run.
    - PRAGMA wal_checkpoint(PASSIVE): incorporates any unmerged WAL pages into
      the main DB file without blocking readers. Python exits after each run so
      the WAL is always checkpointed eventually, but calling it explicitly keeps
      the WAL file small across rapid-restart scenarios.
    """
    try:
        conn = get_connection()
        conn.execute("PRAGMA optimize")
        result = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        if result and result[1] > 0:
            print_debug(
                f"DB maintenance: WAL checkpoint ({result[1]} pages written, "
                f"{result[2]} checkpointed)"
            )
    except Exception as e:
        print_database_error(0, f"DB maintenance failed (non-fatal): {e}")


def close_connection() -> None:
    """Close the database connection for current thread."""
    if hasattr(_thread_local, "conn"):
        try:
            _thread_local.conn.close()
        except Exception as e:
            print_database_error(0, f"Error closing connection: {e}")
        finally:
            delattr(_thread_local, "conn")
        print_debug("Database connection closed")

