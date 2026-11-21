#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/tests/test_hardening.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import base64
import contextlib
import email
import io
import json
import logging
import os
import re
import shutil
import signal
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

try:
    import jsonschema
except ImportError:  # dev dependency; the conformance test is skipped without it
    jsonschema = None

import dns.resolver
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["SMTP_PASSWORD"] = ""

from app import (
    abuse,
    abusix,
    config,
    crowdsec,
    database,
    dns_utils,
    geoip,
    heartbeat,
    logger,
    reportbody,
)
from app import main as crowdsec_main

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ENTRYPOINT = _REPO_ROOT / "docker" / "entrypoint.sh"
_DOCKERFILE = _REPO_ROOT / "docker" / "Dockerfile"
_STUB_ID = "#!/bin/sh\necho 1000\n"  # non-root uid: skips the chown/gosu branch


class AbuseHardeningTest(unittest.TestCase):
    def test_smtp_setup_failure_is_logged_once(self):
        server = MagicMock()
        server.starttls.side_effect = smtplib.SMTPException("TLS failed")
        with (
            patch.object(abuse.smtplib, "SMTP", return_value=server),
            patch.object(abuse, "SMTP_USERNAME", ""),
            patch.object(abuse, "SMTP_PASSWORD", ""),
            patch.object(abuse, "print_mail_error") as mail_error,
        ):
            result = abuse.send_abuse_mail("a@example.com", "subject", "body", max_retries=1)

        self.assertFalse(result[0])
        mail_error.assert_called_once()

    def test_from_header_survives_special_characters_in_sender_name(self):
        from email import message_from_string, policy

        for name in ("Müller IT", "Doe, John (IT)", "Müller, IT (Security) " + "x" * 60):
            with patch.object(abuse, "SENDER_NAME", name), patch.object(abuse, "SMTP_SENDER", "abuse@example.org"):
                msg = abuse._create_mime_message(["a@example.com"], "s", "body", None)
            raw = msg.as_string()
            parsed = message_from_string(raw, policy=policy.default)
            addresses = parsed["From"].addresses
            self.assertEqual(len(addresses), 1, name)
            self.assertEqual(addresses[0].addr_spec, "abuse@example.org", name)
            self.assertEqual(addresses[0].display_name, name, name)
            self.assertTrue(all(len(line) <= 78 for line in raw.split("\n\n", 1)[0].splitlines()), name)

    def _send_with_sendmail(self, **sendmail_kwargs):
        server = MagicMock()
        server.sendmail.configure_mock(**sendmail_kwargs)
        with (
            patch("gillbates_smtp_client.transport.smtp_connection") as conn,
            patch.object(abuse, "print_mail_error"),
            patch("time.sleep"),
        ):
            conn.return_value.__enter__.return_value = server
            result = abuse.send_abuse_mail("a@example.com", "s", "b", max_retries=3, retry_delay=0)
        return result, server

    def test_connection_drop_during_transfer_is_never_retried(self):
        failures = (smtplib.SMTPServerDisconnected("gone"), TimeoutError("timed out"), ConnectionResetError("reset"))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                (ok, err), server = self._send_with_sendmail(side_effect=failure)
                self.assertFalse(ok)
                self.assertIsInstance(err, abuse.UncertainSendError)
                self.assertEqual(server.sendmail.call_count, 1)

    def test_explicit_server_rejection_is_not_marked_uncertain(self):
        (ok, err), _server = self._send_with_sendmail(side_effect=smtplib.SMTPDataError(554, b"no"))
        self.assertFalse(ok)
        self.assertNotIsInstance(err, abuse.UncertainSendError)

    def test_partially_refused_primary_recipients_count_as_delivered(self):
        refused = {"b@example.com": (550, b"no")}
        with patch("gillbates_smtp_client.transport.smtp_connection") as conn:
            server = MagicMock()
            server.sendmail.return_value = refused
            conn.return_value.__enter__.return_value = server
            msg = abuse._create_mime_message(["a@example.com", "b@example.com"], "s", "b")
            abuse._send_smtp_message(msg, ["a@example.com", "b@example.com"], ["a@example.com", "b@example.com"])
            server.sendmail.return_value = {"a@example.com": (550, b"no"), "b@example.com": (550, b"no")}
            with self.assertRaises(smtplib.SMTPRecipientsRefused):
                abuse._send_smtp_message(msg, ["a@example.com", "b@example.com"], ["a@example.com", "b@example.com"])

    def test_xarf_attachment_failure_is_logged_once(self):
        with (
            patch.object(abuse, "MIMEBase", side_effect=ValueError("bad attachment")),
            patch.object(abuse, "print_mail_error") as mail_error,
        ):
            result = abuse.send_abuse_mail("a@example.com", "subject", "body", xarf_attachment="{}", max_retries=1)

        self.assertFalse(result[0])
        mail_error.assert_called_once()

    def test_create_mime_message_does_not_serialize_bcc_header(self):
        msg = abuse._create_mime_message(
            recipients=["one@example.com", "two@example.com"],
            subject="Hello\r\nInjected: no",
            body="Body",
        )

        self.assertEqual(msg["To"], "one@example.com")
        self.assertEqual(msg["Subject"], "Hello Injected: no")
        self.assertIsNone(msg["Bcc"])

    def test_report_mail_follows_xarf_email_transport_layout(self):
        # XARF e-mail transport: multipart/report with text, feedback headers, base64 JSON.
        xarf = json.dumps({"xarf_version": "4.2.0", "note": "Übung"})
        text = "Zeile mit Umlaut: ü\n" + "word " * 60
        msg = email.message_from_string(abuse._create_mime_message(["a@example.com"], "s", text, xarf).as_string())

        self.assertEqual(msg.get_content_type(), "multipart/report")
        self.assertEqual(msg.get_param("report-type"), "feedback-report")
        parts = msg.get_payload()
        self.assertEqual(
            [p.get_content_type() for p in parts],
            ["text/plain", "message/feedback-report", "application/json"],
        )
        self.assertIn("ü", parts[0].get_payload(decode=True).decode("utf-8"))
        # The parser exposes message/* parts as a nested message holding the headers.
        self.assertEqual(parts[1].get_payload(0)["Feedback-Type"], "xarf")
        self.assertEqual(parts[2].get_filename(), "xarf.json")
        self.assertEqual(parts[2]["Content-Transfer-Encoding"], "base64")
        self.assertEqual(json.loads(parts[2].get_payload(decode=True)), json.loads(xarf))
        self.assertTrue(msg["Message-ID"] and msg["Date"])
        longest = max(len(line) for line in msg.as_string().splitlines())
        self.assertLessEqual(longest, 78)

    def test_mail_without_xarf_report_is_plain_text(self):
        msg = abuse._create_mime_message(["a@example.com"], "s", "body")
        self.assertEqual(msg.get_content_type(), "text/plain")

    def test_normalize_recipients_validates_list_entries(self):
        recipients = abuse._normalize_recipients(
            ["valid@example.com", "bad\r\nbcc:evil@example.com", "two@example.net"]
        )

        self.assertEqual(recipients, ["valid@example.com", "two@example.net"])


class AbusixHardeningTest(unittest.TestCase):
    def test_build_resolver_uses_container_system_dns(self):
        fake_resolver = dns.resolver.Resolver(configure=False)
        fake_resolver.nameservers = ["10.30.0.2"]

        with (
            patch.object(abusix.dns.resolver, "Resolver", return_value=fake_resolver),
            patch.object(
                abusix,
                "get_effective_nameservers",
                return_value=["10.30.0.2"],
            ),
        ):
            resolver = abusix._build_resolver()

        self.assertEqual(list(resolver.nameservers), ["10.30.0.2"])

    def test_negative_cache_hit_skips_dns_lookup(self):
        with (
            patch.object(abusix, "get_ip_prefix", return_value="203.0.113.0"),
            patch.object(abusix, "get_cached_abuse_contact", return_value=(True, None)),
            patch.object(abusix, "query_abuse_contact_dns") as mock_query,
        ):
            result = abusix.extract_abuse_contact("203.0.113.4")

        self.assertIsNone(result)
        mock_query.assert_not_called()

    def test_operational_dns_errors_propagate_and_are_not_cached(self):
        with (
            patch.object(abusix, "get_ip_prefix", return_value="203.0.113.0"),
            patch.object(abusix, "get_cached_abuse_contact", return_value=(False, None)),
            patch.object(
                abusix,
                "query_abuse_contact_dns",
                side_effect=abusix.AbuseContactDnsError("timeout"),
            ),
            patch.object(abusix, "set_cached_abuse_contact") as mock_set_cache,
            self.assertRaises(abusix.AbuseContactDnsError),
        ):
            abusix.extract_abuse_contact("203.0.113.4")

        mock_set_cache.assert_not_called()


class DatabaseHardeningTest(unittest.TestCase):
    def test_get_alert_stats_counts_only_failed_status_as_failed(self):
        with self._fresh_db():
            statuses = (
                (1, 1, "sent"),
                (2, 0, "failed"),
                (3, 0, "pending"),
                (4, 0, "unknown_send_state"),
            )
            with database.db_transaction() as conn:
                conn.executemany(
                    "INSERT INTO abuse_alerts (AlertId, Recipient, IPAddress, Scenario, Sent, Status) "
                    "VALUES (?, 'a@example.com', ?, 'test', ?, ?)",
                    [(alert_id, f"203.0.113.{alert_id}", sent, status) for alert_id, sent, status in statuses],
                )

            self.assertEqual(database.get_alert_stats(), {"total": 4, "successful": 1, "failed": 1})

    def test_database_connection_uses_five_second_busy_timeout(self):
        with self._fresh_db():
            conn = database.get_connection()
            self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone()[0], 5_000)

    def test_schema_migration_drops_duplicate_indexes(self):
        with self._fresh_db():
            with database.db_read() as conn:
                fresh_alert_indexes = {row[1] for row in conn.execute("PRAGMA index_list('abuse_alerts')")}
                fresh_cache_indexes = {row[1] for row in conn.execute("PRAGMA index_list('abuse_contacts_cache')")}
            self.assertNotIn("idx_alert_id", fresh_alert_indexes)
            self.assertNotIn("idx_cache_prefix", fresh_cache_indexes)

            with database.db_transaction() as conn:
                conn.execute("CREATE INDEX idx_alert_id ON abuse_alerts(AlertId)")
                conn.execute("CREATE INDEX idx_cache_prefix ON abuse_contacts_cache(ip_prefix)")
                conn.execute("PRAGMA user_version = 0")
            database.close_connection()
            with patch.object(database, "_db_initialized", False):
                database.init_db()

            with database.db_read() as conn:
                alert_indexes = {row[1] for row in conn.execute("PRAGMA index_list('abuse_alerts')")}
                cache_indexes = {row[1] for row in conn.execute("PRAGMA index_list('abuse_contacts_cache')")}
                schema_version = conn.execute("PRAGMA user_version").fetchone()[0]

            self.assertNotIn("idx_alert_id", alert_indexes)
            self.assertNotIn("idx_cache_prefix", cache_indexes)
            self.assertEqual(schema_version, database._SCHEMA_VERSION)

    def test_batch_check_processed_alerts_chunks_large_queries(self):
        class FakeCursor:
            def __init__(self):
                self.calls = []

            def execute(self, query, params):
                self.calls.append((query, list(params)))

            def fetchall(self):
                return []

        class FakeConn:
            def __init__(self):
                self.cursor_obj = FakeCursor()

            def cursor(self):
                return self.cursor_obj

        fake_conn = FakeConn()

        # 950 (alert_id, ip) pairs. Each pair binds 2 params and every query adds
        # the status params, so a chunk holds (900 - 3) // 2 = 448 pairs: 448 + 448 + 54.
        keys = [(i, f"1.2.3.{i % 256}") for i in range(950)]
        with patch.object(database, "db_read") as mock_db_read:
            mock_db_read.return_value.__enter__.return_value = fake_conn
            database.batch_check_processed_alerts(keys)

        calls = fake_conn.cursor_obj.calls
        # Large inputs must be split across queries, none binding more than
        # SQLITE_PARAM_LIMIT params, and every key must appear exactly once.
        # Params layout: [pair_id, pair_ip, ..., *HANDLED_STATUSES]; the trailing
        # status entries are filters, not pair data.
        # Tombstone lookups bind pair params only and are checked separately.
        n_status = len(database.HANDLED_STATUSES)
        tombstone_calls = [params for query, params in calls if "abuse_alert_tombstones" in query]
        calls = [(query, params) for query, params in calls if "abuse_alert_tombstones" not in query]
        self.assertGreater(len(calls), 1)
        self.assertEqual(len(tombstone_calls), len(calls))
        queried_keys = []
        for _query, params in calls:
            self.assertLessEqual(len(params), database.SQLITE_PARAM_LIMIT)
            pair_params = params[:-n_status]
            self.assertEqual(len(pair_params) % 2, 0)
            self.assertEqual(params[-n_status:], list(database.HANDLED_STATUSES))
            queried_keys.extend((pair_params[i], pair_params[i + 1]) for i in range(0, len(pair_params), 2))
        self.assertCountEqual(queried_keys, keys)

    def test_expired_negative_cache_entry_is_a_miss_without_cleanup(self):
        with self._fresh_db():
            database.set_cached_abuse_contact("203.0.113.0", None)
            self.assertEqual(database.get_cached_abuse_contact("203.0.113.0"), (True, None))
            with database.db_transaction() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO abuse_contacts_cache (ip_prefix, abuse_contact, updated_at) "
                    "VALUES (?, ?, datetime('now', '-30 days'))",
                    ("203.0.113.0", database.NEGATIVE_CACHE),
                )
            self.assertEqual(database.get_cached_abuse_contact("203.0.113.0"), (False, None))

    def test_finalize_alert_records_unknown_outcome_as_terminal_state(self):
        with self._fresh_db():
            self.assertTrue(database.claim_alert_for_send(1, "203.0.113.1", "s"))
            database.finalize_alert(1, "a@example.com", "203.0.113.1", "s", False, "x", outcome_unknown=True)
            self.assertFalse(database.claim_alert_for_send(1, "203.0.113.1", "s"))
            self.assertIn((1, "203.0.113.1"), database.batch_check_processed_alerts([(1, "203.0.113.1")]))

    # Retention cleanup keeps the at-most-once proof.

    _OLD_SCHEMA = """
        CREATE TABLE abuse_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            AlertId INTEGER NOT NULL,
            Recipient TEXT NOT NULL,
            IPAddress TEXT NOT NULL,
            Scenario TEXT NOT NULL,
            Sent INTEGER NOT NULL DEFAULT 1 CHECK (Sent IN (0, 1)),
            Status TEXT NOT NULL DEFAULT 'sent'
                CHECK (Status IN ('pending', 'sent', 'failed', 'unknown_send_state')),
            ErrorMessage TEXT,
            CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(AlertId, IPAddress)
        );
    """

    @contextlib.contextmanager
    def _fresh_db(self, old_schema_rows=None):
        """Temp database; with old_schema_rows it starts on the pre-tombstone schema."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.db"
            if old_schema_rows is not None:
                with contextlib.closing(sqlite3.connect(path)) as raw:
                    raw.executescript(self._OLD_SCHEMA)
                    raw.executemany(
                        "INSERT INTO abuse_alerts (AlertId, Recipient, IPAddress, Scenario, Sent, Status, CreatedAt)"
                        " VALUES (?, 'r@example.com', ?, 's', 0, ?, datetime('now', ?))",
                        old_schema_rows,
                    )
                    raw.commit()
            database.close_connection()
            with patch.object(database, "DB_PATH", path), patch.object(database, "_db_initialized", False):
                database.init_db()
                try:
                    yield path
                finally:
                    database.close_connection()

    @staticmethod
    def _age_all(days):
        with database.db_transaction() as conn:
            conn.execute("UPDATE abuse_alerts SET CreatedAt = datetime('now', ?)", (f"-{days} days",))

    def test_cleanup_keeps_sent_and_unknown_pairs_unclaimable(self):
        # Property: retention may delete the row, never the at-most-once proof.
        with self._fresh_db():
            for alert_id, outcome_unknown, sent in ((1, False, True), (2, True, False)):
                self.assertTrue(database.claim_alert_for_send(alert_id, "203.0.113.1", "s"))
                database.finalize_alert(alert_id, "a@example.com", "203.0.113.1", "s", sent, "x", outcome_unknown)
            self._age_all(400)
            self.assertEqual(database.cleanup_old_records(365)[0], 2)
            with database.db_read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM abuse_alerts").fetchone()[0], 0)
            keys = [(1, "203.0.113.1"), (2, "203.0.113.1")]
            self.assertEqual(database.batch_check_processed_alerts(keys), set(keys))
            for alert_id, _ip in keys:
                self.assertFalse(database.claim_alert_for_send(alert_id, "203.0.113.1", "s"))
            # Same alert, other IP is a different pair and stays claimable.
            self.assertTrue(database.claim_alert_for_send(1, "203.0.113.2", "s"))

    def test_cleanup_leaves_pending_and_failed_follows_retry_semantics(self):
        with self._fresh_db():
            self.assertTrue(database.claim_alert_for_send(1, "203.0.113.1", "s"))  # stays pending
            self.assertTrue(database.claim_alert_for_send(2, "203.0.113.1", "s"))
            database.finalize_alert(2, "a@example.com", "203.0.113.1", "s", False, "smtp down")
            self._age_all(400)
            database.cleanup_old_records(365)
            # pending: untouched, still handled; the reaper then turns it terminal.
            self.assertEqual(database.batch_check_processed_alerts([(1, "203.0.113.1")]), {(1, "203.0.113.1")})
            self.assertFalse(database.claim_alert_for_send(1, "203.0.113.1", "s"))
            self.assertEqual(database.reap_stale_pending(1), 0)  # fresh UpdatedAt
            with database.db_transaction() as conn:
                # The update trigger would reset UpdatedAt, so bypass it for the backdating.
                conn.execute("DROP TRIGGER update_abuse_alerts_timestamp")
                conn.execute("UPDATE abuse_alerts SET UpdatedAt = datetime('now', '-1 day')")
            self.assertEqual(database.reap_stale_pending(1), 1)
            database.cleanup_old_records(365)
            self.assertFalse(database.claim_alert_for_send(1, "203.0.113.1", "s"))
            # failed: deleted, not protected; a fresh claim equals the retry.
            self.assertEqual(database.batch_check_processed_alerts([(2, "203.0.113.1")]), set())
            self.assertTrue(database.claim_alert_for_send(2, "203.0.113.1", "s"))

    def test_cleanup_disabled_with_zero_retention_changes_nothing(self):
        with self._fresh_db():
            self.assertTrue(database.claim_alert_for_send(1, "203.0.113.1", "s"))
            database.finalize_alert(1, "a@example.com", "203.0.113.1", "s", True)
            self._age_all(4000)
            self.assertEqual(database.cleanup_old_records(0), (0, 0))
            with database.db_read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM abuse_alerts").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM abuse_alert_tombstones").fetchone()[0], 0)

    def test_old_schema_migrates_additively_and_loses_no_proof(self):
        rows = [
            (1, "198.51.100.1", "sent", "-900 days"),
            (2, "198.51.100.1", "unknown_send_state", "-900 days"),
            (3, "198.51.100.1", "pending", "-900 days"),
            (4, "198.51.100.1", "failed", "-900 days"),
            (5, "198.51.100.1", "sent", "-1 days"),
        ]
        with self._fresh_db(old_schema_rows=rows):
            with database.db_read() as conn:
                # abuse_alerts keeps its original table (no rebuild) and its rows.
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM abuse_alerts").fetchone()[0], 5)
                self.assertIn(
                    "UNIQUE(AlertId, IPAddress)",
                    conn.execute("SELECT sql FROM sqlite_master WHERE name='abuse_alerts'").fetchone()[0],
                )
            database.init_db()
            database.cleanup_old_records(365)
            database.cleanup_old_records(365)  # idempotent
            keys = [(i, "198.51.100.1") for i in range(1, 6)]
            self.assertEqual(database.batch_check_processed_alerts(keys), {k for k in keys if k[0] != 4})
            for alert_id, ip in keys:
                self.assertEqual(database.claim_alert_for_send(alert_id, ip, "s"), alert_id == 4)

    def test_interrupted_cleanup_rolls_back_tombstones_and_deletes_together(self):
        with self._fresh_db():
            self.assertTrue(database.claim_alert_for_send(1, "203.0.113.1", "s"))
            database.finalize_alert(1, "a@example.com", "203.0.113.1", "s", True)
            self._age_all(400)
            real_conn = database.get_connection()

            class FailingOnDelete:
                def __init__(self, conn):
                    self._conn = conn

                def cursor(self):
                    outer = self._conn.cursor()

                    class Cur:
                        def execute(self, sql, *args):
                            if sql.lstrip().startswith("DELETE FROM abuse_alerts"):
                                raise RuntimeError("boom between tombstone insert and delete")
                            return outer.execute(sql, *args)

                    return Cur()

                def __getattr__(self, name):
                    return getattr(self._conn, name)

            with patch.object(database, "get_connection", return_value=FailingOnDelete(real_conn)):
                self.assertEqual(database.cleanup_old_records(365), (0, 0))
            with database.db_read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM abuse_alerts").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM abuse_alert_tombstones").fetchone()[0], 0)
            self.assertFalse(database.claim_alert_for_send(1, "203.0.113.1", "s"))

    def _claim_from_threads(self, alert_id, ip, workers=4):
        """Race ``workers`` threads, each on its own connection, for one claim; return their results."""
        results = []

        def worker():
            try:
                results.append(database.claim_alert_for_send(alert_id, ip, "s"))
            finally:
                database.close_connection()

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive(), "claim worker did not finish")
        return results

    def test_concurrent_claims_after_cleanup_never_win(self):
        with self._fresh_db():
            self.assertTrue(database.claim_alert_for_send(1, "203.0.113.1", "s"))
            database.finalize_alert(1, "a@example.com", "203.0.113.1", "s", True)
            self._age_all(400)
            database.cleanup_old_records(365)
            self.assertEqual(self._claim_from_threads(1, "203.0.113.1"), [False] * 4)
            # A fresh, never-handled pair still has exactly one winner.
            self.assertEqual(sorted(self._claim_from_threads(9, "203.0.113.9")), [False, False, False, True])

    def test_cleanup_with_outbox_and_cache_and_prune_contract(self):
        with self._fresh_db():
            with database.db_transaction() as conn:
                conn.execute(
                    "INSERT INTO abuse_contacts_cache (ip_prefix, abuse_contact, updated_at) "
                    "VALUES ('203.0.113.0', 'abuse@example.com', datetime('now', '-900 days'))"
                )
            self.assertTrue(database.spool_metric_points(["a", "b", "c"]))
            self.assertEqual(database.cleanup_old_records(365), (0, 1))
            self.assertEqual(database.prune_metric_outbox(1, 0), 2)
            self.assertEqual(database.count_metric_points(), 1)

    def test_get_cached_abuse_contact_distinguishes_negative_cache(self):
        class FakeCursor:
            def __init__(self, row):
                self.row = row

            def execute(self, _query, _params):
                return None

            def fetchone(self):
                return self.row

        class FakeConn:
            def __init__(self, row):
                self.row = row

            def cursor(self):
                return FakeCursor(self.row)

        with patch.object(database, "db_read") as mock_db_read:
            mock_db_read.return_value.__enter__.return_value = FakeConn((database.NEGATIVE_CACHE, 0))
            cache_hit, cached_contact = database.get_cached_abuse_contact("203.0.113.0")

        self.assertTrue(cache_hit)
        self.assertIsNone(cached_contact)


class CrowdsecHardeningTest(unittest.TestCase):
    def test_lapi_base_url_appends_v1_once(self):
        with patch.object(crowdsec, "CROWDSEC_LAPI_URL", "http://lapi:8080"):
            self.assertEqual(crowdsec._get_lapi_base_url(), "http://lapi:8080/v1")

        with patch.object(crowdsec, "CROWDSEC_LAPI_URL", "http://lapi:8080/v1"):
            self.assertEqual(crowdsec._get_lapi_base_url(), "http://lapi:8080/v1")

    def test_lapi_credentials_fall_back_to_local_credentials_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_path = Path(tmpdir) / "local_api_credentials.yaml"
            credentials_path.write_text(
                "url: http://lapi.internal:8080\nlogin: watcher\npassword: secret\n",
                encoding="utf-8",
            )

            with (
                patch.object(crowdsec, "CROWDSEC_LAPI_URL", ""),
                patch.object(crowdsec, "CROWDSEC_LAPI_MACHINE_ID", ""),
                patch.object(crowdsec, "CROWDSEC_LAPI_PASSWORD", ""),
                patch.object(
                    crowdsec,
                    "CROWDSEC_LAPI_CREDENTIALS_PATH",
                    str(credentials_path),
                ),
            ):
                resolved = crowdsec._resolve_lapi_credentials()

        self.assertEqual(
            resolved,
            {
                "url": "http://lapi.internal:8080",
                "machine_id": "watcher",
                "password": "secret",
            },
        )

    def test_get_lapi_token_missing_password_includes_credentials_hint(self):
        with (
            patch.object(crowdsec, "CROWDSEC_LAPI_MACHINE_ID", "watcher"),
            patch.object(crowdsec, "CROWDSEC_LAPI_PASSWORD", ""),
            patch.object(crowdsec, "CROWDSEC_LAPI_CREDENTIALS_PATH", "/no/such/file"),
            self.assertRaises(crowdsec.CrowdSecFetchError) as ctx,
        ):
            crowdsec._get_lapi_token(object())

        self.assertIn("missing or incomplete", str(ctx.exception))
        self.assertIsNotNone(ctx.exception.hint)
        self.assertIn("docker exec -it <your crowdsec container name>", ctx.exception.hint)
        self.assertIn("/etc/crowdsec/local_api_credentials.yaml", ctx.exception.hint)

    def test_get_lapi_token_http_403_includes_credentials_hint(self):
        request = httpx.Request("POST", "http://lapi:8080/v1/watchers/login")
        response = httpx.Response(403, request=request)

        class FakeClient:
            def request(self, *_args, **_kwargs):
                return response

        with (
            patch.object(crowdsec, "CROWDSEC_LAPI_MACHINE_ID", "watcher"),
            patch.object(crowdsec, "CROWDSEC_LAPI_PASSWORD", "wrong-secret"),
            self.assertRaises(crowdsec.CrowdSecFetchError) as ctx,
        ):
            crowdsec._get_lapi_token(FakeClient())

        self.assertIn("HTTP 403", str(ctx.exception))
        self.assertIsNotNone(ctx.exception.hint)
        self.assertIn("CROWDSEC_LAPI_PASSWORD", ctx.exception.hint)

    def test_extract_context_from_alert_merges_meta_and_extra(self):
        alert = {
            "events": [
                {
                    "meta": [{"key": "source_ip", "value": "8.8.8.8"}],
                    "extra": {"service": "sshd"},
                }
            ]
        }

        context = crowdsec._extract_context_from_alert(alert)

        self.assertEqual(
            context,
            {
                "source_ip": "8.8.8.8",
                "service": "sshd",
            },
        )

    def test_get_crowdsec_decisions_derives_decision_from_active_alert(self):
        alerts = [
            {
                "id": 123,
                "scenario": "crowdsecurity/ssh-bf",
                "message": "ssh brute force",
                "events_count": 7,
                "created_at": "2026-06-19T10:00:00Z",
                "start_at": "2026-06-19T09:50:00Z",
                "stop_at": "2026-06-19T10:00:00Z",
                "source": {"ip": "8.8.8.8", "scope": "Ip"},
                "events": [{"meta": [{"key": "http_path", "value": "/login"}], "extra": {}}],
                "decisions": [
                    {
                        "type": "ban",
                        "scope": "Ip",
                        "value": "8.8.8.8",
                        "duration": "4h",
                    }
                ],
            }
        ]

        with patch.object(crowdsec, "get_crowdsec_alerts", return_value=alerts):
            decisions = crowdsec.get_crowdsec_decisions()

        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(decision["alert_id"], 123)
        self.assertEqual(decision["alert_ids"], [123])
        self.assertEqual(decision["scenario"], "crowdsecurity/ssh-bf")
        self.assertEqual(decision["value"], "8.8.8.8")
        self.assertEqual(decision["source"]["ip"], "8.8.8.8")
        self.assertEqual(decision["context"]["http_path"], "/login")

    def test_get_crowdsec_decisions_emits_one_report_per_ip(self):
        # A single alert bundling several bans must yield one reportable
        # decision per IP, each carrying only its own ban.
        alerts = [
            {
                "id": 500,
                "scenario": "http:scan",
                "source": {"scope": "Ip", "value": ""},
                "decisions": [
                    {"id": 1, "type": "ban", "scope": "Ip", "value": "1.1.1.1", "duration": "4h", "origin": "crowdsec"},
                    {"id": 2, "type": "ban", "scope": "Ip", "value": "2.2.2.2", "duration": "4h", "origin": "crowdsec"},
                ],
            }
        ]

        with patch.object(crowdsec, "get_crowdsec_alerts", return_value=alerts):
            decisions = crowdsec.get_crowdsec_decisions()

        self.assertEqual(len(decisions), 2)
        by_ip = {d["source"]["ip"]: d for d in decisions}
        self.assertEqual(set(by_ip), {"1.1.1.1", "2.2.2.2"})
        # Both reports keep the originating alert id; the DB keys them per IP.
        self.assertEqual(by_ip["1.1.1.1"]["alert_id"], 500)
        self.assertEqual(by_ip["2.2.2.2"]["alert_id"], 500)
        # Each report's body list is scoped to its own IP.
        self.assertEqual(len(by_ip["1.1.1.1"]["decisions"]), 1)
        self.assertEqual(by_ip["2.2.2.2"]["decisions"][0]["value"], "2.2.2.2")

    def test_get_crowdsec_decisions_skips_capi_bans(self):
        # Community-blocklist bans (origin CAPI) are not our own observations
        # and must never become reports.
        alerts = [
            {
                "id": 600,
                "scenario": "http:scan",
                "source": {"scope": "Ip", "value": ""},
                "decisions": [
                    {"id": 10, "type": "ban", "scope": "Ip", "value": "3.3.3.3", "duration": "4h", "origin": "CAPI"},
                    {
                        "id": 11,
                        "type": "ban",
                        "scope": "Ip",
                        "value": "4.4.4.4",
                        "duration": "4h",
                        "origin": "crowdsec",
                    },
                ],
            }
        ]

        with patch.object(crowdsec, "get_crowdsec_alerts", return_value=alerts):
            decisions = crowdsec.get_crowdsec_decisions()

        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["source"]["ip"], "4.4.4.4")

    def test_get_crowdsec_decisions_recovers_ip_from_event_meta_when_source_is_unusable(self):
        # A local observation whose ban value is empty but whose source IP is
        # recoverable from event metadata.
        alerts = [
            {
                "id": 321,
                "scenario": "ssh:bruteforce",
                "message": "local decision with event source ip",
                "events_count": 5,
                "source": {"scope": "Ip", "value": ""},
                "events": [
                    {
                        "meta": [
                            {"key": "source_ip", "value": "202.191.58.34"},
                            {"key": "service", "value": "ssh"},
                        ]
                    }
                ],
                "decisions": [
                    {
                        "type": "ban",
                        "scope": "Ip",
                        "value": "",
                        "duration": "4h",
                        "origin": "crowdsec",
                    }
                ],
            }
        ]

        with patch.object(crowdsec, "get_crowdsec_alerts", return_value=alerts):
            decisions = crowdsec.get_crowdsec_decisions()

        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(decision["source"]["ip"], "202.191.58.34")
        self.assertEqual(decision["source"]["value"], "202.191.58.34")
        self.assertEqual(decision["context"]["source_ip"], "202.191.58.34")


class CrowdsecMalformedAlertTest(unittest.TestCase):
    def test_null_decisions_and_events_do_not_abort_the_run(self):
        good = {"id": 2, "scenario": "s", "source": {"ip": "203.0.113.2"}, "decisions": [{"value": "203.0.113.2"}]}
        alerts = [
            {"id": 1, "decisions": None, "events": None},
            {**good, "events": [None, "x", {"meta": [{"key": "k", "value": "v"}]}]},
        ]
        with patch.object(crowdsec, "get_crowdsec_alerts", return_value=alerts):
            decisions = crowdsec.get_crowdsec_decisions()
        self.assertEqual([d["alert_id"] for d in decisions], [2])


class CrowdsecAlertFetchLimitTest(unittest.TestCase):
    def _run(self, sizes, no_warning=True):
        """Run the fetch with one mocked LAPI page per entry of `sizes`."""
        pages = [[{"id": i} for i in range(n)] for n in sizes]
        responses = []
        for page in pages:
            response = MagicMock()
            response.json.return_value = page
            responses.append(response)
        with (
            patch.object(crowdsec, "_build_lapi_client", return_value=MagicMock()),
            patch.object(crowdsec, "_get_lapi_token", return_value="t"),
            patch.object(crowdsec, "CROWDSEC_FETCH_ALERT_DETAILS", False),
            patch.object(crowdsec, "DEFAULT_ALERT_FETCH_LIMIT", 3),
            patch.object(crowdsec, "MAX_ALERT_FETCH_LIMIT", 30),
            patch.object(crowdsec, "_request_with_retry", side_effect=responses) as request,
            self.assertNoLogs(crowdsec.logger, level="WARNING") if no_warning else contextlib.nullcontext(),
        ):
            alerts = crowdsec._fetch_lapi_alerts()
        return alerts, [call.kwargs["params"]["limit"] for call in request.call_args_list]

    def test_unsaturated_response_is_a_single_request(self):
        alerts, limits = self._run([2])
        self.assertEqual((len(alerts), limits), (2, ["3"]))

    def test_saturated_response_raises_limit_until_complete(self):
        alerts, limits = self._run([3, 29])
        self.assertEqual((len(alerts), limits), (29, ["3", "30"]))

    def test_hard_cap_stops_escalation_and_warns(self):
        with self.assertLogs(crowdsec.logger, level="WARNING") as logs:
            alerts, limits = self._run([3, 30], no_warning=False)
        self.assertEqual((len(alerts), limits), (30, ["3", "30"]))
        self.assertTrue(any("maximum fetch limit" in line for line in logs.output))


class DnsUtilsHardeningTest(unittest.TestCase):
    def test_get_effective_nameservers_uses_system_resolver_only(self):
        with patch.object(dns_utils, "_system_nameservers", return_value=["10.30.0.2"]):
            nameservers = dns_utils.get_effective_nameservers()

        self.assertEqual(nameservers, ["10.30.0.2"])

    def test_get_effective_nameservers_returns_empty_without_system_dns(self):
        with patch.object(dns_utils, "_system_nameservers", return_value=[]):
            nameservers = dns_utils.get_effective_nameservers()

        self.assertEqual(nameservers, [])

    def test_resolve_hostname_uses_selected_nameservers(self):
        fake_answer = MagicMock()
        fake_answer.__str__.return_value = "93.184.216.34"
        fake_resolver = MagicMock()
        fake_resolver.resolve.return_value = [fake_answer]

        with patch.object(dns_utils.dns.resolver, "Resolver", return_value=fake_resolver):
            resolved = dns_utils.resolve_hostname("example.com", ["1.1.1.1"])

        self.assertEqual(resolved, ["93.184.216.34", "93.184.216.34"])
        self.assertEqual(fake_resolver.nameservers, ["1.1.1.1"])


def _import_config_with_env(name: str, value: str) -> subprocess.CompletedProcess:
    """Import app.config in a fresh interpreter with ``name=value`` and no settings file."""
    env = {**os.environ, name: value, "SETTINGS_PATH": os.devnull}
    return subprocess.run(
        [sys.executable, "-c", "from app import config"],
        check=False,
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class ConfigWhitelistTest(unittest.TestCase):
    def _import_config(self, value: str) -> subprocess.CompletedProcess:
        return _import_config_with_env("WHITELISTED_ASN", value)

    def test_invalid_whitelist_entry_stops_startup(self):
        result = self._import_config("AS8881, AS12foo34")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AS12foo34", result.stderr)

    def test_valid_whitelist_is_accepted(self):
        self.assertEqual(self._import_config("AS8881, 51167,").returncode, 0)


class ConfigSmtpSenderTest(unittest.TestCase):
    def _import_config(self, value: str) -> subprocess.CompletedProcess:
        return _import_config_with_env("SMTP_SENDER", value)

    def test_non_address_sender_stops_startup(self):
        for value in ("", "Abuse <abuse@example.net>", "abuse", "abuse@localhost"):
            with self.subTest(value=value):
                result = self._import_config(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("SMTP_SENDER", result.stderr)

    def test_plain_address_is_accepted(self):
        self.assertEqual(self._import_config("abuse@example.net").returncode, 0)


class ConfigEnvLoaderTest(unittest.TestCase):
    """Covers the stdlib KEY=VALUE loader."""

    def _load(self, content: str, *keys: str, preset: dict[str, str] | None = None, override: bool = True):
        """Load ``content`` with ``keys`` unset (except ``preset``) and return their resulting values."""
        tmp_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = tmp_dir / "settings.env"
        path.write_text(content, encoding="utf-8")
        with patch.dict(os.environ, preset or {}, clear=False):
            for key in keys:
                if key not in (preset or {}):
                    os.environ.pop(key, None)
            config.load_settings_env(path, override=override)
            return {key: os.environ.get(key) for key in keys}

    def test_skips_blank_lines_and_comments(self):
        values = self._load("\n# full-line comment\nFOO=bar\n   \n# another comment\nBAZ=qux\n", "FOO", "BAZ")
        self.assertEqual(values, {"FOO": "bar", "BAZ": "qux"})

    def test_export_prefix_is_stripped(self):
        self.assertEqual(self._load("export FOO=bar\n", "FOO"), {"FOO": "bar"})

    def test_matching_quotes_are_stripped(self):
        values = self._load('DOUBLE="hello"\nSINGLE=\'world\'\nMIXED="unterminated\n', "DOUBLE", "SINGLE", "MIXED")
        # Mismatched/unterminated quoting is left as-is (no stripping).
        self.assertEqual(values, {"DOUBLE": "hello", "SINGLE": "world", "MIXED": '"unterminated'})

    def test_quoted_password_preserves_surrounding_whitespace(self):
        values = self._load('SMTP_PASSWORD="  s3cr3t  "\n', "SMTP_PASSWORD")
        self.assertEqual(values, {"SMTP_PASSWORD": "  s3cr3t  "})

    def test_unquoted_value_is_stripped(self):
        self.assertEqual(self._load("FOO=  spaced value  \n", "FOO"), {"FOO": "spaced value"})

    def test_unquoted_value_strips_inline_comment(self):
        self.assertEqual(self._load("FOO=bar # note\n", "FOO"), {"FOO": "bar"})

    def test_unquoted_value_without_leading_space_keeps_hash(self):
        self.assertEqual(self._load("FOO=a#b\n", "FOO"), {"FOO": "a#b"})

    def test_quoted_value_with_hash_is_kept_verbatim(self):
        values = self._load('SMTP_PASSWORD="s3cr3t # not a comment"\n', "SMTP_PASSWORD")
        self.assertEqual(values, {"SMTP_PASSWORD": "s3cr3t # not a comment"})

    def test_override_false_keeps_existing_environment_variable(self):
        values = self._load("FOO=from_file\n", "FOO", preset={"FOO": "from_env"}, override=False)
        self.assertEqual(values, {"FOO": "from_env"})

    def test_override_true_replaces_existing_environment_variable(self):
        values = self._load("FOO=from_file\n", "FOO", preset={"FOO": "from_env"}, override=True)
        self.assertEqual(values, {"FOO": "from_file"})

    def test_missing_file_is_not_an_error(self):
        tmp_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        config.load_settings_env(tmp_dir / "does-not-exist.env", override=True)

    def test_unreadable_settings_path_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir, self.assertRaises(IsADirectoryError):
            config.load_settings_env(Path(tmp_dir), override=True)


class _TtyStream(io.StringIO):
    """StringIO that claims to be a TTY so colour codes are emitted."""

    def isatty(self) -> bool:
        return True


class LoggerHardeningTest(unittest.TestCase):
    def setUp(self):
        # The print_* helpers honour the root level; capture every level in these tests.
        root = logging.getLogger()
        previous = root.level
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.setLevel, previous)

    def test_print_log_sanitizes_newlines(self):
        stream = io.StringIO()
        with (
            patch.object(sys, "stdout", stream),
            patch.object(sys, "stderr", stream),
        ):
            logger.print_log("INFO", "INFO", "line1\nline2")

        self.assertIn("line1\\nline2", stream.getvalue())

    def test_print_log_escapes_terminal_control_characters(self):
        stream = io.StringIO()
        message = "before\x1b[31mred\x1b[0m\x07\x7f\x85\t\u2028after"
        with (
            patch.object(sys, "stdout", stream),
            patch.object(sys, "stderr", stream),
        ):
            logger.print_log("INFO", "INFO", message)

        output = stream.getvalue()
        self.assertIn(r"\x1b[31mred\x1b[0m\x07\x7f\x85\t\u2028", output)
        self.assertFalse(any(char in output for char in "\x1b\x07\x7f\x85\t\u2028"))

    def _capture(self, call):
        """Run ``call`` and return (stdout_text, stderr_text) with colours on."""
        out, err = _TtyStream(), _TtyStream()
        with patch.object(sys, "stdout", out), patch.object(sys, "stderr", err):
            call()
        return out.getvalue(), err.getvalue()

    def test_print_helpers_emit_expected_tag_colour_and_stream(self):
        # Pins the rendered tag, ANSI colour and target stream of every print_* helper.
        cases = [
            (lambda: logger.print_processing(1, 2, "203.0.113.5", "scan"), "PROCESS", "PROCESSING", False),
            (lambda: logger.print_dns_query("203.0.113.5", "IPv4"), "DNS", "DNS_QUERY", False),
            (lambda: logger.print_abuse_contact_found("203.0.113.5", "a@example.com"), "INFO", "INFO", False),
            (lambda: logger.print_mail_sent("a@example.com", 7, 1.5), "MAIL", "MAIL_SENT", False),
            (lambda: logger.print_mail_error("a@example.com", "boom", 7), "MAIL", "ERROR", True),
            (lambda: logger.print_no_contact_found("203.0.113.5", 7), "WARNING", "WARNING", True),
            (lambda: logger.print_dns_error("203.0.113.5", "timeout", 7), "ERROR", "ERROR", True),
            (lambda: logger.print_database_error(7, "locked"), "ERROR", "ERROR", True),
            (lambda: logger.print_internal_ip_skipped("10.0.0.1", 7), "INFO", "INFO", False),
            (lambda: logger.print_config_info("hello"), "INFO", "INFO", False),
            (lambda: logger.print_summary_header("HEAD"), "INFO", "INFO", False),
            (lambda: logger.print_stat_item("Label", "3"), "INFO", "INFO", False),
        ]

        for call, tag, colour_key, to_stderr in cases:
            with self.subTest(tag=tag, colour=colour_key):
                out, err = self._capture(call)
                text = err if to_stderr else out
                self.assertEqual("" if to_stderr else err, "")
                self.assertTrue(text.startswith(logger.COLORS[colour_key]), text)
                self.assertTrue(text.rstrip("\n").endswith(logger.COLORS["RESET"]))
                self.assertIn(f"| {tag:<8} | crowdsec_abuse | ", text)

    def test_print_debug_respects_log_level(self):
        root = logging.getLogger()
        previous = root.level
        try:
            root.setLevel(logging.INFO)
            out, _ = self._capture(lambda: logger.print_debug("quiet"))
            self.assertEqual(out, "")

            root.setLevel(logging.DEBUG)
            out, _ = self._capture(lambda: logger.print_debug("loud"))
            self.assertIn("| DEBUG    | crowdsec_abuse | loud", out)
        finally:
            root.setLevel(previous)

    def test_split_recipients_uses_abuse_validation(self):
        # logger.split_recipients must delegate to app.abuse, which enforces a
        # real TLD. A naive '@'-only check would wrongly accept these.
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                logger.split_recipients("ok@example.com, user@localhost, bare@"),
                ["ok@example.com"],
            )
            self.assertEqual(logger.split_recipients(""), [])

    def test_print_mail_error_counts_refused_recipients_once(self):
        # Reaches the dict-parsing branch: contains braces and "Invalid RCPT TO"
        # but not the literal "Invalid RCPT TO address" handled one branch above.
        out, err = self._capture(
            lambda: logger.print_mail_error(
                "a@example.com,bogus",
                "SMTP error: {'b@example.com': (550, 'Invalid RCPT TO')}",
                7,
            )
        )
        self.assertIn("1 invalid recipient(s)", err)
        self.assertIn("Alert 7", err)
        # The recipient list is split exactly once. A second split would repeat
        # the "Filtered out ..." notice that split_recipients emits as a side
        # effect, printing it twice for a single error.
        self.assertEqual(out.count("Filtered out"), 1)

    def test_print_mail_error_maps_plain_rcpt_rejection(self):
        _, err = self._capture(lambda: logger.print_mail_error("a@example.com", "Invalid RCPT TO address", None))
        self.assertIn("Invalid recipient address", err)
        self.assertNotIn("Alert", err)

    def test_format_recipients_display_truncates(self):
        self.assertEqual(logger.format_recipients_display([]), "no recipients")
        self.assertEqual(logger.format_recipients_display(["a@example.com"]), "a@example.com")
        self.assertEqual(
            logger.format_recipients_display(["a@example.com", "b@example.com"]),
            "a@example.com +1 more",
        )
        self.assertEqual(
            logger.format_recipients_display(["a" * 50 + "@example.com"], 20),
            "a" * 17 + "...",
        )


class ReviewFindingsTest(unittest.TestCase):
    """Fixes from past code reviews, kept as explicit regressions."""

    def test_normalize_asn_rejects_mixed_garbage(self):
        self.assertEqual(config.normalize_asn("AS8881"), "8881")
        self.assertEqual(config.normalize_asn("as8881"), "8881")
        self.assertEqual(config.normalize_asn(" 8881 "), "8881")
        self.assertEqual(config.normalize_asn(8881), "8881")
        # Digit scraping would whitelist AS1234 here.
        self.assertEqual(config.normalize_asn("AS12foo34"), "")
        self.assertEqual(config.normalize_asn("8881, 9999"), "")
        self.assertEqual(config.normalize_asn(""), "")
        self.assertEqual(config.normalize_asn(None), "")

    def test_normalize_ip_rejects_ranges_but_keeps_single_hosts(self):
        self.assertEqual(crowdsec._normalize_ip("203.0.113.5"), "203.0.113.5")
        self.assertEqual(crowdsec._normalize_ip("203.0.113.5/32"), "203.0.113.5")
        self.assertEqual(crowdsec._normalize_ip("2001:db8::1/128"), "2001:db8::1")
        # A range must not collapse to its network address.
        self.assertIsNone(crowdsec._normalize_ip("203.0.113.0/24"))
        self.assertIsNone(crowdsec._normalize_ip("2001:db8::/48"))
        self.assertIsNone(crowdsec._normalize_ip("not-an-ip"))

    def test_get_alert_ip_does_not_collapse_a_range_decision(self):
        self.assertEqual(
            crowdsec_main.get_alert_ip({"value": "203.0.113.0/24", "scope": "Range"}),
            "unknown",
        )
        self.assertEqual(
            crowdsec_main.get_alert_ip({"value": "203.0.113.5/32", "scope": "Ip"}),
            "203.0.113.5",
        )
        self.assertEqual(
            crowdsec_main.get_alert_ip({"value": "203.0.113.5", "scope": "Ip"}),
            "203.0.113.5",
        )

    def test_lapi_credentials_file_url_is_used_when_env_is_unset(self):
        with patch.object(
            crowdsec,
            "_read_lapi_credentials_file",
            return_value={"url": "http://lapi.internal:8080", "login": "m", "password": "p"},
        ):
            with patch.object(crowdsec, "CROWDSEC_LAPI_URL", ""):
                resolved = crowdsec._resolve_lapi_credentials()
            self.assertEqual(resolved["url"], "http://lapi.internal:8080")

            with patch.object(crowdsec, "CROWDSEC_LAPI_URL", "http://env:9000"):
                resolved = crowdsec._resolve_lapi_credentials()
            self.assertEqual(resolved["url"], "http://env:9000")

    def test_lapi_rejects_non_object_auth_payload(self):
        response = MagicMock()
        response.json.return_value = ["unexpected"]
        client = MagicMock()
        with (
            patch.object(crowdsec, "_request_with_retry", return_value=response),
            patch.object(
                crowdsec,
                "_resolve_lapi_credentials",
                return_value={"url": "http://x", "machine_id": "m", "password": "p"},
            ),
            self.assertRaises(crowdsec.CrowdSecFetchError),
        ):
            crowdsec._get_lapi_token(client)

    def test_request_with_retry_retries_transient_then_succeeds(self):
        ok = MagicMock()
        ok.raise_for_status.return_value = None
        client = MagicMock()
        client.request.side_effect = [httpx.ConnectError("boom"), ok]

        with patch.object(crowdsec.time, "sleep") as sleep:
            result = crowdsec._request_with_retry(client, "GET", "/alerts")

        self.assertIs(result, ok)
        self.assertEqual(client.request.call_count, 2)
        sleep.assert_called_once()

    def test_request_with_retry_does_not_retry_client_errors(self):
        failing = MagicMock()
        failing.raise_for_status.side_effect = httpx.HTTPStatusError(
            "unauthorized", request=MagicMock(), response=MagicMock(status_code=401)
        )
        client = MagicMock()
        client.request.return_value = failing

        with (
            patch.object(crowdsec.time, "sleep") as sleep,
            self.assertRaises(httpx.HTTPStatusError),
        ):
            crowdsec._request_with_retry(client, "GET", "/alerts")

        self.assertEqual(client.request.call_count, 1)
        sleep.assert_not_called()

    def test_smtp_connection_rejects_half_configured_credentials(self):
        with (
            patch.object(abuse, "SMTP_USERNAME", "user"),
            patch.object(abuse, "SMTP_PASSWORD", ""),
            self.assertRaises(RuntimeError) as ctx,
            abuse.smtp_connection(),
        ):
            pass
        self.assertIn("both be set", str(ctx.exception))

    def test_smtp_connection_does_not_relabel_send_errors(self):
        server = MagicMock()
        server.sock = MagicMock(spec=ssl.SSLSocket)
        server.sock.getpeercert.return_value = b"der-cert"
        with (
            patch.object(abuse.smtplib, "SMTP", return_value=server),
            patch.object(abuse, "SMTP_USERNAME", ""),
            patch.object(abuse, "SMTP_PASSWORD", ""),
            patch.object(abuse, "print_mail_error") as mail_error,
            contextlib.suppress(smtplib.SMTPRecipientsRefused),
            abuse.smtp_connection(),
        ):
            raise smtplib.SMTPRecipientsRefused({"a@example.com": (550, b"no")})

        mail_error.assert_not_called()

    def test_query_abuse_contact_dns_rejects_unusable_txt_record(self):
        rdata = MagicMock()
        rdata.strings = [b"not-an-address@"]
        with (
            patch.object(abusix._resolver, "resolve", return_value=[rdata]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertIsNone(abusix.query_abuse_contact_dns("203.0.113.5"))

        rdata.strings = [b"abuse@example.com"]
        with (
            patch.object(abusix._resolver, "resolve", return_value=[rdata]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(abusix.query_abuse_contact_dns("203.0.113.5"), "abuse@example.com")

    def test_extract_report_ip_does_not_collapse_a_range(self):
        # The address named in the outgoing report must never be a range's
        # network address, which usually belongs to an uninvolved party.
        self.assertEqual(
            reportbody._extract_report_ip({"decisions": [{"value": "203.0.113.0/24", "scope": "Range"}]}),
            "unknown",
        )
        self.assertEqual(
            reportbody._extract_report_ip({"decisions": [{"value": "203.0.113.5/32", "scope": "Ip"}]}),
            "203.0.113.5",
        )
        self.assertEqual(reportbody._extract_report_ip({"source": {"ip": "203.0.113.7"}}), "203.0.113.7")

    def test_claim_failure_is_a_database_error_not_already_handled(self):
        with (
            patch.object(crowdsec_main, "extract_abuse_contact", return_value="a@example.com"),
            patch.object(
                crowdsec_main,
                "claim_alert_for_send",
                side_effect=OSError("disk full"),
            ),
            patch.object(crowdsec_main, "send_abuse_report") as send,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = crowdsec_main.process_single_alert({"alert_id": 5, "source": {"ip": "203.0.113.5"}}, 1, 1, "host")

        # Must not be swallowed as an idempotent skip, and must not send.
        self.assertTrue(result.db_error)
        self.assertEqual(result.error_type, "database_error")
        self.assertFalse(result.success)
        send.assert_not_called()

    def test_get_alert_confidence_rejects_non_finite_values(self):
        self.assertEqual(crowdsec_main.get_alert_confidence({"confidence": 0.5}), 0.5)
        self.assertEqual(crowdsec_main.get_alert_confidence({"confidence": "nan"}), 1.0)
        self.assertEqual(crowdsec_main.get_alert_confidence({"confidence": "inf"}), 1.0)
        self.assertEqual(crowdsec_main.get_alert_confidence({"score": "-inf"}), 1.0)
        self.assertEqual(crowdsec_main.get_alert_confidence({}), 1.0)

    def test_app_log_formatter_keeps_exception_traceback(self):
        formatter = logger.LOG.formatter()
        try:
            raise ValueError("boom")
        except ValueError:
            record = logging.LogRecord("t", logging.ERROR, __file__, 1, "failed", None, sys.exc_info())
        rendered = formatter.format(record)

        self.assertIn("failed", rendered)
        self.assertIn("ValueError", rendered)
        self.assertIn("boom", rendered)
        # Single-line invariant of the log format must survive.
        self.assertNotIn("\n", rendered)

    def test_redaction_covers_secrets_inside_uris_and_query_strings(self):
        self.assertEqual(
            reportbody._redact_context_value("target_uri", "/reset?token=abcd&id=7"),
            "/reset?token=%5BREDACTED%5D&id=7",
        )
        self.assertEqual(
            reportbody._redact_context_value("http_args", "api_key=xyz&page=2"),
            "api_key=%5BREDACTED%5D&page=2",
        )
        # A URI without sensitive parameters stays byte-identical.
        self.assertEqual(
            reportbody._redact_context_value("path", "/login?next=/home"),
            "/login?next=/home",
        )
        # Key-based redaction still wins outright.
        self.assertEqual(
            reportbody._redact_context_value("authorization", "Bearer x"),
            "[REDACTED]",
        )

    def test_decisions_for_drops_malformed_entries(self):
        self.assertEqual(
            reportbody._decisions_for({"decisions": [{"value": "1.2.3.4"}, "junk", None]}),
            [{"value": "1.2.3.4"}],
        )
        # An all-malformed list falls back to the alert itself when it looks
        # like a derived decision, rather than crashing the report build.
        self.assertEqual(
            reportbody._decisions_for({"decisions": ["junk"], "value": "1.2.3.4"}),
            [{"decisions": ["junk"], "value": "1.2.3.4"}],
        )

    def test_geoip_adapter_binds_app_settings_and_delegates(self):
        cfg = geoip._geo.config
        self.assertEqual(cfg.directory, config.GEOIP_DIR)
        self.assertEqual(cfg.user_agent, "crowdsec-abuse-reporter/1.0")
        with (
            patch.object(geoip._geo, "ensure", return_value={"city": True, "asn": True}) as ensure,
            patch.object(geoip._geo, "lookup", return_value={"asn": 1}) as lookup,
            patch.object(geoip._geo, "lookup_asn_providers", return_value={"1": "X"}) as providers,
        ):
            self.assertEqual(geoip.ensure_geoip_databases(force=True), {"city": True, "asn": True})
            self.assertEqual(geoip.lookup("8.8.8.8"), {"asn": 1})
            self.assertEqual(geoip.lookup_asn_providers({"1"}), {"1": "X"})
        ensure.assert_called_once_with(force=True)
        lookup.assert_called_once_with("8.8.8.8")
        providers.assert_called_once_with({"1"})

    def test_entrypoint_hardcodes_data_dir(self):
        content = _ENTRYPOINT.read_text(encoding="utf-8")
        self.assertIn('DATA_DIR="/data"', content)
        self.assertNotIn("${DATA_DIR:-/data}", content)

    def test_dockerfile_keeps_app_root_owned(self):
        content = _DOCKERFILE.read_text(encoding="utf-8")
        self.assertNotIn("chown -R app:app /app", content)
        self.assertIn("chown -R app:app /data", content)

    def test_dockerfile_healthcheck_rejects_future_timestamps(self):
        content = _DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn('test "$age" -ge 0', content)
        self.assertIn('test "$api_age" -ge 0', content)

    def test_dockerfile_runs_tini_and_healthcheck_mirrors_metrics_enable_condition(self):
        dockerfile = _DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn('ENTRYPOINT ["/usr/bin/tini", "--", "./entrypoint.sh"]', dockerfile)
        self.assertNotIn("init: true", (_REPO_ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8"))
        # The metrics heartbeat is only required where the entrypoint starts the loop.
        self.assertIn(
            '[ -n "${METRICS_BACKEND:-}" ] && [ "${METRICS_BACKEND}" != "none" ]',
            _ENTRYPOINT.read_text(encoding="utf-8"),
        )
        self.assertIn('test -n "${METRICS_BACKEND:-}" && test "${METRICS_BACKEND}" != none', dockerfile)


_XARF_SCHEMA_DIR = Path(__file__).resolve().parent / "fixtures" / "xarf-v4.2.0" / "schemas" / "v4"


def _xarf_schema_errors(report: dict) -> list[str]:
    """Validate a report against the vendored XARF v4.2.0 master schema.

    Mirrors scripts/validate-schemas.py of xarf-spec v4.2.0: relative $refs are
    inlined, then Draft 2020-12 is applied with format checking.
    """

    def inline(node, base: Path):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith(("http", "#")):
                target = (base / ref).resolve()
                return inline(json.loads(target.read_text(encoding="utf-8")), target.parent)
            return {key: inline(value, base) for key, value in node.items()}
        if isinstance(node, list):
            return [inline(item, base) for item in node]
        return node

    master = _XARF_SCHEMA_DIR / "xarf-v4-master.json"
    schema = inline(json.loads(master.read_text(encoding="utf-8")), master.parent)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [f"{'/'.join(map(str, e.absolute_path)) or 'root'}: {e.message}" for e in validator.iter_errors(report)]


class ReportBodyHardeningTest(unittest.TestCase):
    def test_sensitive_header_lines_are_redacted_in_every_container_shape(self):
        secret = "example-secret-token"  # noqa: S105
        alert = {
            "id": 7,
            "scenario": "s",
            "start_at": "2026-06-23T19:25:48Z",
            "source": {"ip": "203.0.113.9"},
            "decisions": [{"type": "ban", "scope": "Ip", "value": "203.0.113.9"}],
            "meta": [
                {
                    "key": "headers",
                    "value": json.dumps([f"Authorization: Bearer {secret}", f"Cookie: session={secret}"]),
                },
                {"key": "raw_headers", "value": f"Host: example.org\nX-Api-Key: {secret}\nAccept: */*"},
                {"key": "hdr_dict", "value": json.dumps({"Proxy-Authorization": f"Basic {secret}"})},
            ],
        }
        body = reportbody.build_mail_body(alert, hostname="h")
        xarf = reportbody.build_xarf_report(alert, hostname="h")
        self.assertNotIn(secret, body)
        self.assertNotIn(secret, xarf)
        # The CrowdSec data travels base64-encoded, so check the decoded evidence too.
        evidence = base64.b64decode(json.loads(xarf)["evidence"][0]["payload"]).decode("utf-8")
        self.assertNotIn(secret, evidence)
        self.assertIn("Host: example.org", body)

    def test_build_mail_body_footer_describes_crowdsec_as_metric_source(self):
        body = reportbody.build_mail_body(
            {
                "id": 61,
                "scenario": "local/uiw-scan-one_port",
                "created_at": "2026-06-23T19:26:20Z",
                "start_at": "2026-06-23T19:25:48Z",
                "stop_at": "2026-06-23T19:26:19Z",
                "source": {"ip": "45.79.207.252"},
                "decisions": [{"type": "ban", "scope": "Ip", "value": "45.79.207.252"}],
            },
            hostname="sensor.example.net",
        )

        self.assertIn(
            "This report was generated automatically by our abuse reporting system "
            "based on CrowdSec metrics (https://www.crowdsec.net/).",
            " ".join(body.split()),  # the footer is wrapped to the mail line width
        )
        self.assertNotIn("generated automatically by CrowdSec", body)

    @patch.object(reportbody.uuid, "uuid4", return_value="fixed-report-id")
    @patch.object(
        reportbody,
        "_xarf_contact",
        return_value={"org": "Example", "contact": "abuse@example.net", "domain": "example.net"},
    )
    def test_build_xarf_report_remarks_describe_crowdsec_as_metric_source(
        self,
        _mock_reporter,
        _mock_uuid,
    ):
        payload = json.loads(
            reportbody.build_xarf_report(
                {
                    "id": 61,
                    "scenario": "local/uiw-scan-one_port",
                    "created_at": "2026-06-23T19:26:20Z",
                    "start_at": "2026-06-23T19:25:48Z",
                    "stop_at": "2026-06-23T19:26:19Z",
                    "source": {"ip": "45.79.207.252"},
                    "decisions": [{"type": "ban", "scope": "Ip", "value": "45.79.207.252"}],
                },
                hostname="sensor.example.net",
            )
        )

        self.assertIn("based on CrowdSec metrics", payload["remarks"])
        self.assertIn("XARF v4", payload["remarks"])
        self.assertNotIn("generated automatically by CrowdSec", payload["remarks"])

    @unittest.skipIf(jsonschema is None, "jsonschema (dev dependency) not installed")
    def test_xarf_reports_conform_to_v420_schemas(self):
        # Every generated report must validate; scenarios cover each type mapping.
        contact = {"org": "Example", "contact": "abuse@example.net", "domain": "example.net"}
        cases = {
            "crowdsecurity/ssh-bf": {},
            "crowdsecurity/ssh-bf with port": {"meta": [{"key": "source_port", "value": "40222"}]},
            "crowdsecurity/http-probing": {},
            "crowdsecurity/http-sqli-probing-detection": {},
            "crowdsecurity/http-sqli-probing with port": {"meta": [{"key": "source_port", "value": "40222"}]},
            "crowdsecurity/http-path-traversal-probing": {},
            "crowdsecurity/http-wordpress-scan": {},
            "crowdsecurity/http-wordpress_bf_xmlrpc with port": {"meta": [{"key": "source_port", "value": "40222"}]},
            "crowdsecurity/iptables-scan-multi_ports": {},
            "crowdsecurity/http-cve-2021-41773": {},
            "local/uiw-scan-one_port": {},
            "crowdsecurity/unknown-thing": {},
            "crowdsecurity/ddos-flood": {},
            "crowdsecurity/spam-wave": {},
        }
        types = {}
        for scenario, extra in cases.items():
            alert = {
                "id": 5,
                "scenario": scenario.split(" ")[0],
                "created_at": "2026-06-23T19:26:20Z",
                "start_at": "2026-06-23T19:25:48Z",
                "stop_at": "2026-06-23T19:26:19Z",
                "events_count": 7,
                "source": {"ip": "198.51.100.7", "cn": "DE"},
                "decisions": [{"type": "ban", "scope": "Ip", "value": "198.51.100.7"}],
                **extra,
            }
            with patch.object(reportbody, "_xarf_contact", return_value=contact):
                report = json.loads(reportbody.build_xarf_report(alert, hostname="h"))
            self.assertEqual(_xarf_schema_errors(report), [], scenario)
            types[scenario] = (report["category"], report["type"])
        # Without a stated source port a login attack must not be filed as login_attack.
        self.assertEqual(types["crowdsecurity/ssh-bf"], ("reputation", "threat_intelligence"))
        self.assertEqual(types["crowdsecurity/ssh-bf with port"], ("connection", "login_attack"))
        self.assertEqual(types["crowdsecurity/unknown-thing"], ("reputation", "threat_intelligence"))

    def test_scenario_names_map_to_expected_xarf_types(self):
        # (scenario, source_port) -> (category, type, key fields); matching is by name token.
        tm = ("reputation", "threat_intelligence")
        vs = ("connection", "vulnerability_scan")
        cases = [
            ("crowdsecurity/ssh-bf", None, (*tm, {"threat_type": "brute_force", "service": "ssh"})),
            ("crowdsecurity/ssh-slow-bf", 4000, ("connection", "login_attack", {"service": "ssh"})),
            ("crowdsecurity/http-probing", None, (*vs, {"scan_type": "mixed", "targeted_services": ["http"]})),
            ("crowdsecurity/http-crawl-non_statics", None, (*vs, {"scan_type": "mixed"})),
            ("crowdsecurity/http-bad-user-agent", None, (*tm, {"threat_type": "other", "service": "http"})),
            ("crowdsecurity/http-sqli-probing", None, ("connection", "sql_injection", {"protocol": "tcp"})),
            ("crowdsecurity/http-xss-probing", None, (*vs, {"scan_type": "web_vuln_scan"})),
            ("crowdsecurity/http-path-traversal-probing", None, (*vs, {"scan_type": "web_vuln_scan"})),
            ("crowdsecurity/http-wordpress-scan", None, (*vs, {"targeted_services": ["http"]})),
            ("crowdsecurity/http-wordpress_wpconfig", None, (*tm, {"service": "http"})),
            ("crowdsecurity/http-wordpress_user-enum", None, (*tm, {"service": "http"})),
            ("crowdsecurity/http-wordpress_bf_xmlrpc", 5000, ("connection", "login_attack", {"service": "http"})),
            (
                "crowdsecurity/http-cve-2021-41773",
                None,
                (*vs, {"scan_type": "web_vuln_scan", "vulnerabilities_probed": ["CVE-2021-41773"]}),
            ),
            ("crowdsecurity/http-backdoors-attempts", None, (*tm, {"threat_type": "malware", "service": "http"})),
            ("crowdsecurity/http-sensitive-files", None, (*tm, {"threat_type": "other"})),
            ("crowdsecurity/iptables-scan-multi_ports", None, (*vs, {"scan_type": "port_scan"})),
            ("crowdsecurity/mysql-bf", None, (*tm, {"threat_type": "brute_force"})),
            ("crowdsecurity/postfix-spam", None, (*tm, {"threat_type": "spam"})),
            ("crowdsecurity/smb-bf", 4000, (*tm, {"threat_type": "brute_force"})),
            ("crowdsecurity/rdp-bf", 4000, ("connection", "login_attack", {"service": "rdp"})),
            ("custom/http-resource-limit", None, (*tm, {"threat_type": "other", "service": "http"})),
            ("custom/http-resource-flood", None, (*tm, {"threat_type": "ddos", "service": "http"})),
            ("local/something-else", None, (*tm, {"threat_type": "other"})),
        ]
        for scenario, port, (category, xarf_type, fields) in cases:
            got_cat, got_type, got_fields = reportbody._xarf_classification(scenario, port)
            self.assertEqual((got_cat, got_type), (category, xarf_type), scenario)
            for key, value in fields.items():
                self.assertEqual(got_fields.get(key), value, f"{scenario}: {key}")
        # No wrong service from substrings ("rdp" in "wordpress").
        for scenario, _port, _exp in cases:
            if "wordpress" in scenario:
                _, _, got = reportbody._xarf_classification(scenario, 5000)
                self.assertNotIn("rdp", json.dumps(got), scenario)

    def test_context_redacts_folded_header_continuation_lines(self):
        text = "Authorization: Bearer abc\n   folded-secret\nUser-Agent: curl\nCookie: a=b;\n\tc=d"
        redacted = reportbody._redact_header_lines(text)
        self.assertNotIn("abc", redacted)
        self.assertNotIn("folded-secret", redacted)
        self.assertNotIn("c=d", redacted)
        self.assertIn("User-Agent: curl", redacted)

    def test_xarf_report_requires_an_incident_time_and_never_invents_one(self):
        base = {"id": 1, "scenario": "crowdsecurity/http-probing", "source": {"ip": "198.51.100.7"}}
        for alert in (base, {**base, "start_at": "garbage", "created_at": ""}):
            with self.assertRaises(ValueError):
                reportbody.build_xarf_report(alert, hostname="h")
        report = json.loads(reportbody.build_xarf_report({**base, "created_at": "2026-06-23T19:26:20Z"}, hostname="h"))
        self.assertEqual(report["timestamp"], "2026-06-23T19:26:20+00:00")

    def test_xarf_report_never_accuses_an_unknown_source(self):
        # source_identifier names the offender; a placeholder must fail the build, not be sent.
        base = {"id": 1, "scenario": "crowdsecurity/http-probing", "start_at": "2026-06-23T19:25:48Z"}
        for source in ({}, {"ip": "not-an-ip"}, {"range": "203.0.113.0/24", "scope": "Range"}):
            with self.subTest(source=source), self.assertRaises(ValueError):
                reportbody.build_xarf_report({**base, "source": source}, hostname="h")

    def test_xarf_report_uses_the_ip_the_caller_already_derived(self):
        # main derives the IP also from context/meta; the report must accuse that IP, still validated.
        alert = {"id": 1, "scenario": "crowdsecurity/http-probing", "start_at": "2026-06-23T19:25:48Z", "source": {}}
        report = json.loads(reportbody.build_xarf_report(alert, hostname="h", ip="203.0.113.5"))
        self.assertEqual(report["source_identifier"], "203.0.113.5")
        with self.assertRaises(ValueError):
            reportbody.build_xarf_report(alert, hostname="h", ip="not-an-ip")

    def test_xarf_report_rejects_oversized_evidence_instead_of_truncating(self):
        alert = {
            "id": 1,
            "scenario": "crowdsecurity/http-probing",
            "start_at": "2026-06-23T19:25:48Z",
            "source": {"ip": "198.51.100.7"},
        }
        with (
            patch.object(reportbody, "XARF_MAX_EVIDENCE_BYTES", 200),
            self.assertRaisesRegex(ValueError, "X-ARF limit"),
        ):
            reportbody.build_xarf_report(alert, hostname="h")

    def test_xarf_contact_carries_domain_of_sender_address(self):
        self.assertEqual(
            reportbody._xarf_contact("abuse@example.net", ""),
            {"org": "example.net", "contact": "abuse@example.net", "domain": "example.net"},
        )

    def test_mail_body_lines_are_wrapped_but_keep_non_ascii(self):
        alert = {
            "id": 9,
            "scenario": "crowdsecurity/http-probing",
            "source": {"ip": "198.51.100.7"},
            "decisions": [{"type": "ban", "scope": "Ip", "value": "198.51.100.7"}],
            "message": "Ünïcode " + "lange Nachricht " * 30,
            "meta": [
                {"key": "user_agent", "value": "Mozilla/5.0 " * 40},
                {"key": "target_uri", "value": json.dumps(["/" + "a" * 300])},
                {"key": "a_very_long_context_key_name_beyond_any_column", "value": "x " * 80},
            ],
        }
        body = reportbody.build_mail_body(alert, hostname="h")
        self.assertLessEqual(max(len(line) for line in body.splitlines()), 78)
        self.assertIn("Ünïcode", body)

    def test_context_redacts_sensitive_headers_and_limits_large_values(self):
        large_value = "x" * (reportbody.MAX_FIELD_LENGTH + 50)
        combined = reportbody.extract_context_for_json(
            {
                "headers": {
                    "Authorization": "secret-token",
                    "User-Agent": large_value,
                }
            },
            {},
        )

        self.assertEqual(combined["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(
            combined["headers"]["User-Agent"],
            large_value[: reportbody.MAX_FIELD_LENGTH],
        )

    def test_extract_context_details_aligns_longer_labels(self):
        # source_ip and SourceRange are suppressed (redundant with INCIDENT/NETWORK).
        # Only non-suppressed keys must align at the same column.
        alert = {
            "meta": [
                {"key": "service", "value": "svc"},
                {"key": "source_ip", "value": "198.51.100.7"},
                {"key": "SourceRange", "value": "138.124.112.0/21"},
                {"key": "datasource_path", "value": "/var/log/ufw.log"},
                {"key": "datasource_type", "value": "file"},
            ]
        }

        context = reportbody.extract_context_details({}, alert)
        lines = {line.strip().split(":", 1)[0]: line for line in context.splitlines() if ":" in line}

        self.assertNotIn("Source IP", lines)
        self.assertNotIn("SourceRange", lines)

        value_columns = {
            "Service": lines["Service"].index("svc"),
            "datasource_path": lines["datasource_path"].index("/var/log/ufw.log"),
            "datasource_type": lines["datasource_type"].index("file"),
        }

        self.assertEqual(len(set(value_columns.values())), 1)


class HeartbeatHardeningTest(unittest.TestCase):
    """Tests for app/heartbeat.py failure paths."""

    @patch.object(heartbeat, "setup_logging")
    @patch.object(heartbeat, "print_debug")
    @patch.object(heartbeat, "check_lapi_health", return_value=True)
    def test_run_heartbeat_fails_when_heartbeat_file_cannot_be_updated(
        self,
        _check_lapi_health,
        _print_config_info,
        _setup_logging,
    ):
        # LAPI is reachable but the file touch raises — run_heartbeat must
        # return False so the entrypoint logs WARNING and the Docker HEALTHCHECK
        # sees a stale file rather than a contradictory "OK" signal.
        mock_file = MagicMock()
        mock_file.touch.side_effect = OSError("read-only filesystem")
        with patch.object(heartbeat, "_HEARTBEAT_FILE", mock_file):
            self.assertFalse(heartbeat.run_heartbeat())


class _EntrypointSandbox:
    """Mixin for TestCases that run a sandboxed copy of docker/entrypoint.sh with stub executables."""

    def _sandbox_entrypoint(self, root: Path, stubs: dict[str, str]) -> tuple[Path, Path, Path, Path]:
        """Write the copy below ``root``; return (script, data_dir, runtime_dir, stub_bin)."""
        data_dir, runtime_dir, stub_bin = root / "data", root / "runtime", root / "bin"
        for directory in (data_dir, runtime_dir, stub_bin):
            directory.mkdir()
        script_text = _ENTRYPOINT.read_text(encoding="utf-8")
        # A silent no-op replace would run the script against the real /data and /tmp.
        for variable, real_dir, sandbox_dir in (("DATA_DIR", "/data", data_dir), ("RUNTIME_DIR", "/tmp", runtime_dir)):
            self.assertIn(f'{variable}="{real_dir}"', script_text)
            script_text = script_text.replace(f'{variable}="{real_dir}"', f'{variable}="{sandbox_dir}"', 1)
        script = root / "entrypoint.sh"
        script.write_text(script_text, encoding="utf-8")
        for name, contents in stubs.items():
            stub = stub_bin / name
            stub.write_text(contents, encoding="utf-8")
            stub.chmod(0o755)
        return script, data_dir, runtime_dir, stub_bin

    @staticmethod
    def _spawn_entrypoint(script: Path, env: dict[str, str]) -> subprocess.Popen:
        """Start the script in its own session so the whole process group can be killed."""
        return subprocess.Popen(
            ["bash", str(script)],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )


class EntrypointHardeningTest(_EntrypointSandbox, unittest.TestCase):
    """Smoke-tests for shell-level entrypoint.sh configuration validation.

    The _api_heartbeat_loop background process inherits the bash shell's stdout/
    stderr FDs, so subprocess.communicate() would block indefinitely waiting for
    EOF even after the main bash process exits. We run each test in its own
    session (start_new_session=True) and kill the whole process group on timeout
    so the pipes are released and communicate() can return.
    """

    def _run_entrypoint(self, env_overrides: dict, timeout: int = 3, extra_stubs=None, prepare=None):
        with tempfile.TemporaryDirectory(prefix="entrypoint-hardening-") as temp_dir:
            stubs = {
                "id": _STUB_ID,
                "python": "#!/bin/sh\nprintf 'STUB_PYTHON:%s\\n' \"$*\"\nexit 0\n",
                # Stop after one run instead of waiting on the production intervals.
                "sleep": "#!/bin/sh\nexit 77\n",
                **(extra_stubs or {}),
            }
            script, data_dir, _runtime_dir, stub_bin = self._sandbox_entrypoint(Path(temp_dir), stubs)
            if prepare:
                prepare(data_dir)

            env = {
                **os.environ,
                "PATH": f"{stub_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "SMTP_SERVER": "smtp.example.net",
                "RUN_ONCE": "false",
                "ABUSE_DB_PATH": str(data_dir / "abuse_alerts.db"),
                "GEOIP_DIR": str(Path(temp_dir) / "geoip"),
                "STUB_MARK": str(Path(temp_dir) / "dropped"),
                **env_overrides,
            }
            proc = self._spawn_entrypoint(script, env)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                stdout, stderr = proc.communicate()
            return subprocess.CompletedProcess(proc.args, proc.returncode, stdout=stdout, stderr=stderr)

    def test_entrypoint_derives_jitter_from_the_interval(self):
        cases = {"3600": 300, "60": 6, "9": 0, "08": 0}
        for interval, expected in cases.items():
            with self.subTest(interval=interval):
                result = self._run_entrypoint({"RUN_INTERVAL": interval})
                match = re.search(r"max jitter (\d+)s .*start offset (\d+)s", result.stdout)
                self.assertIsNotNone(match, result.stdout)
                self.assertEqual(int(match.group(1)), expected)
                self.assertLessEqual(int(match.group(2)), expected)

    def test_entrypoint_caps_hourly_jitter(self):
        result = self._run_entrypoint({"RUN_EVERY_HOUR": "6"})
        self.assertIn("max jitter 300s", result.stdout)

    def test_entrypoint_rejects_oversized_numbers_and_accepts_the_maximum(self):
        # An oversized value would overflow bash arithmetic; the bound is checked as a string.
        seconds = 31536000
        bounds = {
            "RUN_EVERY_HOUR": 8760,
            "RUN_INTERVAL": seconds,
            "API_HEARTBEAT_INTERVAL": seconds,
            "METRICS_INTERVAL": seconds,
            "METRICS_HEARTBEAT_MAX_AGE_SECONDS": seconds,
        }
        for name, maximum in bounds.items():
            base = {"METRICS_BACKEND": "influxdb2"} if name.startswith("METRICS_") else {}
            for value in ("9" * 20, str(maximum + 1)):
                with self.subTest(name=name, value=value):
                    result = self._run_entrypoint({**base, name: value})
                    self.assertEqual(result.returncode, 1)
                    self.assertTrue(
                        result.stderr.strip().endswith(f"| ERROR    | entrypoint | {name} must be at most {maximum}.")
                    )
                    self.assertNotIn("STUB_PYTHON:", result.stdout)
            with self.subTest(name=name, value="maximum"):
                result = self._run_entrypoint({**base, name: str(maximum)})
                self.assertNotIn("must be at most", result.stderr)
                self.assertIn("STUB_PYTHON:", result.stdout)

    def test_entrypoint_leading_zero_run_every_hour_is_decimal(self):
        result = self._run_entrypoint({"RUN_EVERY_HOUR": "08"})
        self.assertNotIn("RUN_EVERY_HOUR", result.stderr)
        self.assertIn("running every 08 hour(s) (28800s)", result.stdout)

    def test_restricted_subdirectory_warning_names_the_paths_and_start_continues(self):
        # Root phase simulated: stub id reports 0 until the stub gosu has dropped privileges.
        stubs = {
            "id": '#!/bin/sh\nif [ -e "$STUB_MARK" ]; then echo 1000; else echo 0; fi\n',
            "gosu": '#!/bin/sh\ntouch "$STUB_MARK"\nshift\nexec bash "$@"\n',
            "chown": (
                "#!/bin/sh\n"
                'case "$3" in */data) '
                "for n in 1 2 3 4 5 6 7; do "
                "echo \"chown: cannot read directory '/data/restricted$n': Permission denied\" >&2; done; "
                "exit 1;; esac\nexit 0\n"
            ),
        }
        result = self._run_entrypoint({}, extra_stubs=stubs)
        self.assertIn("| WARNING  | entrypoint | chown -R on", result.stderr)
        self.assertIn("/data/restricted1, /data/restricted2", result.stderr)
        self.assertIn("/data/restricted5 (+2 more)", result.stderr)
        self.assertNotIn("/data/restricted6", result.stderr)
        self.assertIn("STUB_PYTHON:", result.stdout)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses file permissions")
    def test_unwritable_data_dir_fails_fast_with_a_clear_error(self):
        result = self._run_entrypoint({}, prepare=lambda d: d.chmod(0o500))
        self.assertEqual(result.returncode, 1)
        self.assertIn("| ERROR    | entrypoint | ", result.stderr)
        self.assertIn("is not writable by uid", result.stderr)
        self.assertNotIn("STUB_PYTHON:", result.stdout)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses file permissions")
    def test_unwritable_database_file_fails_fast(self):
        def readonly_db(data_dir):
            db = data_dir / "abuse_alerts.db"
            db.write_text("")
            db.chmod(0o400)

        result = self._run_entrypoint({}, prepare=readonly_db)
        self.assertEqual(result.returncode, 1)
        self.assertIn("database file", result.stderr)

    def test_entrypoint_does_not_duplicate_successful_heartbeat_logs(self):
        content = _ENTRYPOINT.read_text(encoding="utf-8")

        self.assertNotIn('echo "[heartbeat] LAPI OK"', content)


_STUB_PYTHON = """#!/bin/sh
# Stand-in for `python`: records its pid, then behaves as scripted by $STUB_DIR.
kind=main
case "$1" in -m) kind=heartbeat ;; esac
[ -n "${METRICS_ONLY:-}" ] && kind=metrics
echo "$$" >> "$STUB_DIR/pids.$kind"
if [ -e "$STUB_DIR/fail.$kind" ]; then exit 1; fi
if [ -e "$STUB_DIR/slow.$kind" ]; then exec sleep 30; fi
if [ "$kind" = main ]; then
    if [ -e "$STUB_DIR/main.rc" ]; then exit "$(cat "$STUB_DIR/main.rc")"; fi
    exec sleep 30
fi
exit 0
"""


def _bash_at_least_5_1() -> bool:
    # Evaluated at import: a missing or hung bash must skip the class, not break collection.
    try:
        probe = subprocess.run(
            ["bash", "-c", "echo $((BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1]))"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except OSError, subprocess.TimeoutExpired:
        return False
    return probe.returncode == 0 and int(probe.stdout.strip() or 0) >= 501


@unittest.skipUnless(
    sys.platform.startswith("linux") and _bash_at_least_5_1(),
    "entrypoint supervision needs Linux /proc and bash >= 5.1",
)
class EntrypointSupervisionTest(_EntrypointSandbox, unittest.TestCase):
    """Runs entrypoint.sh with a stub python, a stub id (non-root uid) and private state dirs."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.stub = root / "stub"
        self.stub.mkdir()
        self.script, self.data, self.run_dir, self.bin = self._sandbox_entrypoint(
            root, {"python": _STUB_PYTHON, "id": _STUB_ID}
        )
        self.procs = []
        self.addCleanup(self._reap)

    def _reap(self):
        for proc in self.procs:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            for stream in (proc.stdout, proc.stderr):
                stream.close()

    def _start(self, **env):
        full = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "STUB_DIR": str(self.stub),
            "SMTP_SERVER": "smtp.example.net",
            "RUN_ONCE": "false",
            "RUN_INTERVAL": "30",
            "API_HEARTBEAT_INTERVAL": "1",
            "METRICS_BACKEND": "none",
            **env,
        }
        proc = self._spawn_entrypoint(self.script, full)
        self.procs.append(proc)
        return proc

    def _wait_for(self, predicate, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    @staticmethod
    def _alive(pid):
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
        except FileNotFoundError, ProcessLookupError:
            return False
        return state != "Z"

    def _helper_pid(self, name):
        path = self.run_dir / name
        self.assertTrue(self._wait_for(path.exists), f"{name} was not written")
        return int(path.read_text().split()[0])

    def _finish(self, proc, timeout=10):
        try:
            _out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.fail("entrypoint did not exit in time")
        return proc.returncode, err

    def test_run_once_success_exits_zero_and_marks_heartbeat(self):
        (self.stub / "main.rc").write_text("0")
        rc, _err = self._finish(self._start(RUN_ONCE="true"))
        self.assertEqual(rc, 0)
        self.assertTrue((self.data / "heartbeat").exists())

    def test_run_once_failure_propagates_exit_code(self):
        (self.stub / "main.rc").write_text("3")
        rc, _err = self._finish(self._start(RUN_ONCE="true"))
        self.assertEqual(rc, 3)
        self.assertFalse((self.data / "heartbeat").exists())

    def _health_limits(self, **env):
        proc = self._start(**env)
        path = self.run_dir / "health_limits"
        self.assertTrue(self._wait_for(path.exists), "health_limits was not written")
        limits = [int(value) for value in path.read_text().split()]
        return proc, limits

    def test_health_limits_follow_intervals_and_explicit_values_win(self):
        # 12 h interval: main limit = interval + jitter cap (300) + 7200 reserve.
        proc, limits = self._health_limits(RUN_EVERY_HOUR="12", API_HEARTBEAT_INTERVAL="0900")
        self.assertEqual(limits, [12 * 3600 + 300 + 7200, 900 + 400, 0])
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        (self.run_dir / "health_limits").unlink()
        _proc, limits = self._health_limits(
            RUN_INTERVAL="08",
            METRICS_BACKEND="influxdb2",
            METRICS_INTERVAL="08",
            HEALTHCHECK_MAX_AGE_SECONDS="0100",
            API_HEARTBEAT_MAX_AGE_SECONDS="50",
        )
        self.assertEqual(limits, [100, 50, 8 * 10 + 300])

    def test_healthcheck_runs_under_posix_sh_with_leading_zero_values(self):
        dockerfile = _DOCKERFILE.read_text(encoding="utf-8")
        match = re.search(r"HEALTHCHECK .*?CMD sh -ec '(.*?)'\n", dockerfile, re.DOTALL)
        self.assertIsNotNone(match)
        script = match.group(1).replace("\\\n", "\n")
        script = re.sub(r"/(data|tmp)/", lambda m: f"{self.data if m[1] == 'data' else self.run_dir}/", script)
        shell = shutil.which("dash") or "sh"
        # RUN_EVERY_HOUR=12 outlives the old fixed 8 h limit; leading zeros must stay decimal.
        _proc, _limits = self._health_limits(RUN_EVERY_HOUR="12", API_HEARTBEAT_INTERVAL="0300", METRICS_BACKEND="none")
        self._helper_pid("api_heartbeat.pid")
        for name in ("heartbeat", "api_heartbeat"):
            (self.data / name).touch()
        os.utime(self.data / "heartbeat", (time.time() - 9 * 3600,) * 2)
        env = {**os.environ, "METRICS_BACKEND": "none", "METRICS_INTERVAL": "08"}
        run = subprocess.run([shell, "-ec", script], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        # A heartbeat older than the derived limit (12 h + 300 s + 2 h) is unhealthy.
        os.utime(self.data / "heartbeat", (time.time() - 15 * 3600,) * 2)
        run = subprocess.run([shell, "-ec", script], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 1, run.stderr)

    def test_pid_files_hold_pid_and_start_time_of_the_helper(self):
        proc = self._start()
        pid = self._helper_pid("api_heartbeat.pid")
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        recorded = (self.run_dir / "api_heartbeat.pid").read_text().split()
        self.assertEqual(recorded, [str(pid), stat[19]])
        self.assertFalse((self.run_dir / "metrics.pid").exists())
        proc.terminate()
        self._finish(proc)

    def _assert_helper_death_stops_container(self, helper_file, **env):
        proc = self._start(**env)
        helper = self._helper_pid(helper_file)
        # Wait until the main run is in flight so its stop can be observed.
        self.assertTrue(self._wait_for((self.stub / "pids.main").exists))
        main_pid = int((self.stub / "pids.main").read_text().split()[0])
        os.kill(helper, signal.SIGKILL)
        rc, err = self._finish(proc)
        self.assertEqual(rc, 1)
        self.assertIn("exited unexpectedly", err)
        self.assertFalse(self._alive(main_pid), "main run survived the container stop")

    def test_dead_api_heartbeat_loop_stops_container_with_exit_1(self):
        self._assert_helper_death_stops_container("api_heartbeat.pid")

    def test_dead_metrics_loop_stops_container_with_exit_1(self):
        self._assert_helper_death_stops_container("metrics.pid", METRICS_BACKEND="influxdb2", METRICS_INTERVAL="1")

    def test_helper_death_interrupts_the_inter_run_sleep(self):
        (self.stub / "main.rc").write_text("0")
        proc = self._start()
        helper = self._helper_pid("api_heartbeat.pid")
        self.assertTrue(self._wait_for((self.data / "heartbeat").exists))
        os.kill(helper, signal.SIGKILL)
        rc, _err = self._finish(proc, timeout=5)
        self.assertEqual(rc, 1)

    def test_failing_helper_commands_do_not_end_the_container(self):
        (self.stub / "fail.heartbeat").write_text("")
        (self.stub / "fail.metrics").write_text("")
        proc = self._start(METRICS_BACKEND="influxdb2", METRICS_INTERVAL="1")
        self.assertTrue(
            self._wait_for(
                lambda: (
                    len((self.stub / "pids.heartbeat").read_text().split()) >= 3
                    if (self.stub / "pids.heartbeat").exists()
                    else False
                )
            )
        )
        self.assertIsNone(proc.poll())
        self.assertFalse((self.run_dir / "metrics_heartbeat").exists())
        proc.terminate()
        rc, _err = self._finish(proc)
        self.assertEqual(rc, 0)

    def test_successful_metrics_snapshot_touches_its_heartbeat(self):
        proc = self._start(METRICS_BACKEND="influxdb2", METRICS_INTERVAL="1")
        self.assertTrue(self._wait_for((self.run_dir / "metrics_heartbeat").exists))
        proc.terminate()
        self._finish(proc)

    def test_stop_signal_terminates_running_jobs_and_exits_zero(self):
        proc = self._start(METRICS_BACKEND="influxdb2", METRICS_INTERVAL="1")
        self.assertTrue(self._wait_for((self.stub / "pids.main").exists))
        self.assertTrue(self._wait_for((self.stub / "pids.metrics").exists))
        pids = [int(x) for f in ("main", "metrics") for x in (self.stub / f"pids.{f}").read_text().split()]
        proc.terminate()
        rc, _err = self._finish(proc, timeout=5)
        self.assertEqual(rc, 0)
        self.assertEqual([p for p in pids if self._alive(p)], [])

    def test_stop_signal_also_reaches_children_of_helper_loops(self):
        # A helper loop is a subshell; its running python/sleep child must get
        # the stop signal too instead of being orphaned until SIGKILL.
        (self.stub / "slow.heartbeat").write_text("")
        (self.stub / "slow.metrics").write_text("")
        proc = self._start(METRICS_BACKEND="influxdb2", METRICS_INTERVAL="1")
        for kind in ("heartbeat", "metrics"):
            self.assertTrue(self._wait_for((self.stub / f"pids.{kind}").exists))
        pids = [int(x) for k in ("heartbeat", "metrics") for x in (self.stub / f"pids.{k}").read_text().split()]
        proc.terminate()
        rc, _err = self._finish(proc, timeout=5)
        self.assertEqual(rc, 0)
        self.assertEqual([p for p in pids if self._alive(p)], [])

    def test_optional_metrics_max_age_is_validated(self):
        rc, err = self._finish(self._start(METRICS_BACKEND="influxdb2", METRICS_HEARTBEAT_MAX_AGE_SECONDS="soon"))
        self.assertEqual(rc, 1)
        self.assertIn("METRICS_HEARTBEAT_MAX_AGE_SECONDS", err)


if __name__ == "__main__":
    unittest.main()
