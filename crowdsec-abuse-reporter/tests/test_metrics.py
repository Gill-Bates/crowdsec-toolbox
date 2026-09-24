#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/tests/test_metrics.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["SMTP_PASSWORD"] = ""

from app import config, database, metrics
from app import main as crowdsec_main


class _TempDbMixin:
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        database.close_connection()
        self._patches = [
            patch.object(database, "DB_PATH", Path(self._tmp.name) / "t.db"),
            patch.object(database, "_db_initialized", False),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        database.close_connection()
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()


class LineProtocolTest(unittest.TestCase):
    def test_host_tag_is_escaped(self):
        line = metrics.format_report_line(
            "crowdsec-abuse",
            host="node,one",
            alert_id=1,
            ip="198.51.100.1",
            scenario="ssh",
            status="sent",
            recipient="abuse@example.com",
            error=None,
            country="DE",
            as_number="1",
            as_name="Example",
            processing_time=0.1,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        )
        self.assertIn(",host=node\\,one ", line)

    def test_host_tag_in_report_point_is_separate_from_email_identity(self):
        result = crowdsec_main.ProcessResult(
            success=True,
            alert_id=1,
            ip="198.51.100.1",
            scenario="ssh",
            recipient="abuse@example.com",
        )
        with patch.object(crowdsec_main, "get_source_host", return_value="node-one"):
            line = crowdsec_main.build_report_point(
                {"id": 1, "source": {"ip": "198.51.100.1"}},
                result,
                "reporter.example.net",
                datetime(2026, 1, 1, tzinfo=UTC),
            )
        self.assertTrue(line.startswith("reporter.example.net,"))
        self.assertIn(",host=node-one ", line)

    def test_source_host_reads_mounted_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "hostname"
            path.write_text("node-one\n", encoding="utf-8")
            with patch.object(metrics, "HOST_HOSTNAME_PATH", path):
                self.assertEqual(metrics.get_source_host(), "node-one")

    def test_escapes_tags_and_fields(self):
        line = metrics.format_report_line(
            "crowdsec-abuse",
            alert_id=7,
            ip="2001:db8::1",
            scenario="crowdsecurity/ssh bf",
            status="failed",
            recipient='a"b@example.com',
            error="550 no\nsuch user",
            country="DE",
            as_number="8881",
            as_name="1&1 Versatel, GmbH",
            processing_time=1.5,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        )
        self.assertEqual(
            line,
            "crowdsec-abuse,ip_address=2001:db8::1,scenario=crowdsecurity/ssh\\ bf,"
            "status=failed,country=DE,as_number=8881,"
            "as_name=1&1\\ Versatel\\,\\ GmbH "
            'alert_id=7i,abuse_email="a\\"b@example.com",processing_time=1.5,'
            'error_message="550 no such user" 1767225600000000000',
        )

    def test_empty_tags_are_omitted(self):
        line = metrics.format_report_line(
            "m", alert_id=1, ip="198.51.100.1", scenario="", status="sent",
            recipient="x@example.com", error=None, country="", as_number="",
            as_name="", processing_time=0.0,
        )
        self.assertTrue(line.startswith("m,ip_address=198.51.100.1,status=sent "))

    def test_error_message_field_is_always_present(self):
        """`error_message` must be written on every point, even empty.

        ILP creates a column lazily on its first point. A conditional field
        would leave the column missing from the table until the first failed
        report, and a dashboard query selecting it as a plain column fails
        with QuestDB's "Invalid column" until then.
        """
        line = metrics.format_report_line(
            "m", alert_id=1, ip="198.51.100.1", scenario="", status="sent",
            recipient="x@example.com", error=None, country="", as_number="",
            as_name="", processing_time=0.0,
        )
        self.assertIn('error_message=""', line)


class BackendWriteTest(unittest.TestCase):
    def _response(self, status: int) -> httpx.Response:
        return httpx.Response(status, text="err")

    def test_questdb_uses_bearer_token_and_write_endpoint(self):
        with (
            patch.object(metrics, "METRICS_BACKEND", "questdb"),
            patch.object(metrics, "QUESTDB_TOKEN", "tok"),
            patch.object(metrics, "_post", return_value=self._response(204)) as post,
        ):
            self.assertTrue(metrics.write_points(["a", "b"]))
        url = post.call_args.args[0]
        self.assertTrue(url.endswith("/write"))
        self.assertEqual(post.call_args.kwargs["payload"], "a\nb")
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer tok")

    def test_influxdb_requires_204(self):
        with (
            patch.object(metrics, "METRICS_BACKEND", "influxdb2"),
            patch.object(metrics, "print_database_error"),
            patch.object(metrics, "_post", return_value=self._response(400)),
        ):
            self.assertFalse(metrics.write_points(["a"]))

    def test_connection_error_returns_false(self):
        with (
            patch.object(metrics, "METRICS_BACKEND", "influxdb2"),
            patch.object(metrics, "print_database_error"),
            patch.object(metrics, "_post", side_effect=httpx.ConnectError("down")),
        ):
            self.assertFalse(metrics.write_points(["a"]))

    def test_disabled_backend_sends_nothing(self):
        with (
            patch.object(metrics, "METRICS_BACKEND", "none"),
            patch.object(metrics, "_post") as post,
        ):
            self.assertTrue(metrics.write_points(["a"]))
        post.assert_not_called()


class QuestDbTtlTest(unittest.TestCase):
    def test_parse_ttl(self):
        self.assertEqual(config.parse_questdb_ttl("365d"), "365 DAYS")
        self.assertEqual(config.parse_questdb_ttl("6M"), "6 MONTHS")
        self.assertEqual(config.parse_questdb_ttl("48h"), "48 HOURS")
        self.assertIsNone(config.parse_questdb_ttl("0"))
        self.assertIsNone(config.parse_questdb_ttl(""))
        with self.assertRaises(ValueError):
            config.parse_questdb_ttl("365")

    def test_ttl_applied_after_questdb_write(self):
        client = MagicMock()
        client.__enter__.return_value.get.return_value = httpx.Response(200, text="{}")
        with (
            patch.object(metrics, "METRICS_BACKEND", "questdb"),
            patch.object(metrics, "QUESTDB_TTL", "365 DAYS"),
            patch.object(metrics, "_post", return_value=httpx.Response(204)),
            patch.object(metrics.httpx, "Client", return_value=client),
            patch.object(metrics, "print_config_info"),
        ):
            self.assertTrue(metrics.write_points(["a"]))
        # Two DDL statements follow a successful write: TTL first, then dedup.
        queries = [
            c.kwargs["params"]["query"]
            for c in client.__enter__.return_value.get.call_args_list
        ]
        for call in client.__enter__.return_value.get.call_args_list:
            self.assertTrue(call.args[0].endswith("/exec"))
        self.assertIn(
            f'ALTER TABLE "{metrics.QUESTDB_TABLE}" SET TTL 365 DAYS', queries
        )

    def test_ttl_failure_does_not_fail_write(self):
        client = MagicMock()
        client.__enter__.return_value.get.side_effect = httpx.ConnectError("down")
        with (
            patch.object(metrics, "METRICS_BACKEND", "questdb"),
            patch.object(metrics, "QUESTDB_TTL", "365 DAYS"),
            patch.object(metrics, "_post", return_value=httpx.Response(204)),
            patch.object(metrics.httpx, "Client", return_value=client),
            patch.object(metrics, "print_config_info"),
            patch.object(metrics, "print_log"),
        ):
            self.assertTrue(metrics.write_points(["a"]))


class SqliteControlDataOnlyTest(_TempDbMixin, unittest.TestCase):
    """In metrics mode SQLite must hold control data only, yet keep at-most-once."""

    def _process(self, *, metrics_enabled: bool, send_ok: bool = True):
        alert = {"id": 5, "source": {"ip": "8.8.8.8"}, "scenario": "ssh-bf"}
        with (
            patch.object(crowdsec_main, "METRICS_ENABLED", metrics_enabled),
            patch.object(crowdsec_main, "extract_abuse_contact", return_value="abuse@example.com"),
            patch.object(
                crowdsec_main,
                "send_abuse_report",
                return_value=(send_ok, None if send_ok else "boom"),
            ),
            patch.object(crowdsec_main, "print_processing"),
            patch.object(crowdsec_main, "print_mail_sent"),
            patch.object(crowdsec_main, "print_mail_error"),
            patch.object(crowdsec_main, "print_config_info"),
        ):
            return crowdsec_main.process_single_alert(alert, 1, 1, "host")

    def _row(self):
        conn = sqlite3.connect(database.DB_PATH)
        try:
            return conn.execute(
                "SELECT Recipient, Scenario, Status, ErrorMessage FROM abuse_alerts"
            ).fetchone()
        finally:
            conn.close()

    def test_default_mode_keeps_full_audit_row(self):
        result = self._process(metrics_enabled=False)
        self.assertTrue(result.finalized)
        self.assertEqual(self._row(), ("abuse@example.com", "ssh-bf", "sent", None))

    def test_metrics_mode_stores_no_report_details(self):
        result = self._process(metrics_enabled=True, send_ok=False)
        self.assertTrue(result.finalized)
        self.assertEqual(result.recipient, "abuse@example.com")
        self.assertEqual(self._row(), ("", "", "failed", None))

    def test_metrics_mode_still_blocks_second_send(self):
        self.assertTrue(self._process(metrics_enabled=True).success)
        second = self._process(metrics_enabled=True)
        self.assertEqual(second.error_type, "already_handled")
        self.assertFalse(second.finalized)

    def test_run_state_roundtrip(self):
        database.set_run_state({"last_run_started_at": "x", "last_run_exit_code": "0"})
        database.set_run_state({"last_run_exit_code": "1"})
        self.assertEqual(
            database.get_run_state(),
            {"last_run_started_at": "x", "last_run_exit_code": "1"},
        )


class MainMetricsFlowTest(unittest.TestCase):
    def _run_main(self, write_ok: bool, outbox_count: int = 0):
        alert = {"id": 1, "source": {"ip": "8.8.8.8"}, "scenario": "one"}
        result = crowdsec_main.ProcessResult(
            success=True, alert_id=1, ip="8.8.8.8", scenario="one",
            recipient="abuse@example.com", finalized=True,
        )
        fake_geoip = MagicMock(ensure_geoip_databases=lambda: {"city": True, "asn": True})
        quiet = [
            "print_banner", "print_summary_header", "print_detailed_summary",
            "print_config_info", "print_database_error", "print_whitelisted_asn_table",
            "print_alert_overview_table", "init_db", "cleanup_old_records",
            "reap_stale_pending", "run_db_maintenance",
        ]
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"app.geoip": fake_geoip}))
            for name in quiet:
                stack.enter_context(patch.object(crowdsec_main, name))
            values = {
                "METRICS_ENABLED": True,
                "METRICS_BACKEND": "questdb",
                "get_alert_stats": MagicMock(return_value={}),
                "get_node_ip": MagicMock(return_value="127.0.0.1"),
                "get_crowdsec_decisions": MagicMock(return_value=[alert]),
                "batch_check_processed_alerts": MagicMock(return_value=set()),
                "deduplicate_and_filter_alerts": MagicMock(
                    return_value=([alert], 0, 0, 0, 0)
                ),
                "process_single_alert": MagicMock(return_value=result),
                "flush_points": MagicMock(return_value=write_ok),
                # The saturation check reads the outbox; keep it away from the
                # real database and below the escalation threshold by default.
                "count_metric_points": MagicMock(return_value=outbox_count),
                "set_run_state": MagicMock(),
            }
            for name, value in values.items():
                stack.enter_context(patch.object(crowdsec_main, name, value))
            stack.enter_context(patch.object(metrics, "METRICS_BACKEND", "questdb"))
            gih = stack.enter_context(patch.object(crowdsec_main, "GracefulInterruptHandler"))
            gih.return_value.__enter__.return_value.interrupted = False
            code = crowdsec_main.main()
        wp, run_state = values["flush_points"], values["set_run_state"]
        return code, wp, run_state

    def test_points_written_and_run_state_recorded(self):
        code, wp, run_state = self._run_main(write_ok=True)
        self.assertEqual(code, 0)
        lines = wp.call_args.args[0]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("crowdsec-abuse,ip_address=8.8.8.8,"))
        final = run_state.call_args_list[-1].args[0]
        self.assertEqual(final["last_run_exit_code"], "0")

    def test_deferred_backend_write_does_not_fail_the_run(self):
        # Points are spooled to SQLite before the write is attempted, so an
        # unreachable backend costs a retry on the next run, not the data.
        # Failing the run here would withhold the heartbeat - and eventually flip
        # the container unhealthy - for a condition that loses nothing.
        code, _wp, run_state = self._run_main(write_ok=False)
        self.assertEqual(code, 0)
        self.assertEqual(run_state.call_args_list[-1].args[0]["last_run_exit_code"], "0")
    def test_saturated_outbox_fails_the_run(self):
        # Once the spool nears its bound the next prune starts discarding points
        # for real, which is the failure that has to become visible.
        with patch.object(crowdsec_main, "METRICS_OUTBOX_MAX_ROWS", 100):
            code, _wp, run_state = self._run_main(write_ok=False, outbox_count=95)
        self.assertEqual(code, 1)
        self.assertEqual(run_state.call_args_list[-1].args[0]["last_run_exit_code"], "1")


class MetricsOutboxTest(_TempDbMixin, unittest.TestCase):
    """The durable spool that keeps a failed backend write from losing points.
    Replay is deliberately not selective: a point carries its own timestamp and
    every dedup key, so the whole spool may be re-sent rather than tracking which
    point of a batch the backend rejected.
    """
    def test_spool_load_delete_roundtrip(self):
        self.assertTrue(database.spool_metric_points(["a 1", "b 2"]))
        self.assertEqual(database.count_metric_points(), 2)
        pending = database.load_metric_points(10)
        self.assertEqual([line for _, line in pending], ["a 1", "b 2"])
        database.delete_metric_points([row_id for row_id, _ in pending])
        self.assertEqual(database.count_metric_points(), 0)
    def test_points_survive_a_failed_write(self):
        with (
            patch.object(metrics, "METRICS_ENABLED", True),
            patch.object(metrics, "write_points", return_value=False),
        ):
            self.assertFalse(metrics.flush_points(["x 1"]))
        # Still spooled, so the next run retries them.
        self.assertEqual(database.count_metric_points(), 1)
    def test_successful_write_clears_the_spool(self):
        with (
            patch.object(metrics, "METRICS_ENABLED", True),
            patch.object(metrics, "write_points", return_value=True) as wp,
        ):
            self.assertTrue(metrics.flush_points(["x 1"]))
        self.assertEqual(database.count_metric_points(), 0)
        self.assertEqual(wp.call_args.args[0], ["x 1"])
    def test_flush_resends_points_left_by_an_earlier_run(self):
        database.spool_metric_points(["old 1"])
        with (
            patch.object(metrics, "METRICS_ENABLED", True),
            patch.object(metrics, "write_points", return_value=True) as wp,
        ):
            self.assertTrue(metrics.flush_points(["new 2"]))
        # One batch, oldest first: the leftover is not stranded behind new points.
        self.assertEqual(wp.call_args.args[0], ["old 1", "new 2"])
        self.assertEqual(database.count_metric_points(), 0)
    def test_prune_drops_oldest_beyond_max_rows(self):
        database.spool_metric_points([f"p {n}" for n in range(5)])
        database.prune_metric_outbox(max_rows=2, max_age_days=0)
        remaining = [line for _, line in database.load_metric_points(10)]
        self.assertEqual(remaining, ["p 3", "p 4"])
    def test_prune_drops_rows_beyond_max_age(self):
        database.spool_metric_points(["stale 1"])
        with database.db_transaction() as conn:
            conn.execute(
                "UPDATE metrics_outbox SET created_at = datetime('now', '-40 days')"
            )
        database.prune_metric_outbox(max_rows=0, max_age_days=30)
        self.assertEqual(database.count_metric_points(), 0)
    def test_disabled_backend_never_spools(self):
        with patch.object(metrics, "METRICS_ENABLED", False):
            self.assertTrue(metrics.flush_points(["x 1"]))
        self.assertEqual(database.count_metric_points(), 0)
class QuestDbDedupTest(unittest.TestCase):
    """Storage-level idempotency of report points.

    Deduplication must never be mistaken for the at-most-once send protocol:
    it makes a repeated *write* a no-op, while `claim_alert_for_send()` decides
    whether a mail may be sent at all.
    """

    def test_dedup_declared_after_questdb_write(self):
        client = MagicMock()
        client.__enter__.return_value.get.return_value = httpx.Response(200, text="{}")
        with (
            patch.object(metrics, "METRICS_BACKEND", "questdb"),
            patch.object(metrics, "QUESTDB_TTL", None),
            patch.object(metrics, "_post", return_value=httpx.Response(204)),
            patch.object(metrics.httpx, "Client", return_value=client),
            patch.object(metrics, "print_config_info"),
        ):
            self.assertTrue(metrics.write_points(["a"]))
        queries = [
            c.kwargs["params"]["query"]
            for c in client.__enter__.return_value.get.call_args_list
        ]
        self.assertIn(
            f'ALTER TABLE "{metrics.QUESTDB_TABLE}" DEDUP ENABLE UPSERT KEYS('
            '"timestamp", "host", "ip_address", "scenario", "status", '
            '"country", "as_number", "as_name")',
            queries,
        )

    def test_dedup_failure_does_not_fail_write(self):
        client = MagicMock()
        client.__enter__.return_value.get.side_effect = httpx.ConnectError("down")
        with (
            patch.object(metrics, "METRICS_BACKEND", "questdb"),
            patch.object(metrics, "QUESTDB_TTL", None),
            patch.object(metrics, "_post", return_value=httpx.Response(204)),
            patch.object(metrics.httpx, "Client", return_value=client),
            patch.object(metrics, "print_config_info"),
            patch.object(metrics, "print_log"),
        ):
            # The rows are already stored when the DDL runs, so a failure here
            # must not turn a successful write into a failed run.
            self.assertTrue(metrics.write_points(["a"]))

    def test_dedup_keys_are_tag_columns_only(self):
        """QuestDB upsert keys must be tags; a field key would be rejected."""
        line = metrics.format_report_line(
            "m",
            host="h",
            alert_id=7,
            ip="8.8.8.8",
            scenario="scn",
            status="sent",
            recipient="abuse@example.com",
            error=None,
            country="US",
            as_number="15169",
            as_name="GOOGLE",
            processing_time=1.5,
        )
        head, fields, _ts = line.split(" ")
        tag_names = {part.split("=")[0] for part in head.split(",")[1:]}
        field_names = {part.split("=")[0] for part in fields.split(",")}
        for key in metrics.DEDUP_KEYS:
            if key == "timestamp":  # the designated timestamp, not a tag
                continue
            self.assertIn(key, tag_names, f"{key} is not a tag")
            self.assertNotIn(key, field_names)

    def test_no_dedup_declaration_without_keys(self):
        with patch.object(metrics.httpx, "Client") as client:
            self.assertTrue(metrics.ensure_questdb_dedup("t", ()))
        client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
