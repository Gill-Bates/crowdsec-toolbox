#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/tests/test_metrics.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import os
import re
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


_RealClient = httpx.Client


class _FakeQuestDb:
    """Stub of QuestDB's /write and /exec endpoints behind an httpx MockTransport.

    The SQL behaviour rests on QuestDB's documentation, not on a live server.
    `alter_applies=False` models an ALTER that answers 200 but changes nothing
    visible (lagging or foreign metadata); `exec_fail(query)` returns an HTTP
    status to inject for that statement, or None.
    """

    def __init__(
        self,
        *,
        exists=False,
        dedup=True,
        wal=True,
        keys=None,
        show_create="CREATE TABLE t (...) WAL DEDUP UPSERT KEYS(timestamp, host)",
        ttl_status=200,
        alter_applies=True,
        build_info="Build Information: QuestDB 10.0.0, JDK 25, Commit Hash abc",
    ):
        self.exists, self.dedup, self.wal = exists, dedup, wal
        self.keys = list(keys if keys is not None else metrics.DEDUP_KEYS)
        self.show_create, self.ttl_status, self.alter_applies = show_create, ttl_status, alter_applies
        self.exec_fail = None
        self.views: list[list] = []
        self.state_rows: list[list] = []
        self.on_write = None  # called after each /write, to model the async refresh
        self.build_info = build_info
        self.events: list[tuple[str, str]] = []

    @property
    def queries(self):
        return [value for kind, value in self.events if kind == "exec"]

    @property
    def writes(self):
        return [value for kind, value in self.events if kind == "write"]

    def count(self, prefix):
        # The shared downsampling state table has its own CREATE TABLE; it is not the report table.
        return sum(1 for query in self.queries if query.startswith(prefix) and "_crowdsec_downsampling" not in query)

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/write":
            self.events.append(("write", request.content.decode()))
            if self.on_write:
                self.on_write()
            return httpx.Response(204)
        query = request.url.params["query"]
        self.events.append(("exec", query))
        if self.exec_fail and (status := self.exec_fail(query)):
            return httpx.Response(status, text="injected")
        rows: list = []
        if query == "SELECT build()":
            rows = [] if self.build_info is None else [[self.build_info]]
        elif query.startswith("SELECT dedup, walEnabled FROM tables()"):
            rows = [[self.dedup, self.wal]] if self.exists else []
        elif query.startswith("SELECT dedup FROM tables()"):
            rows = [[self.dedup]] if self.exists else []
        elif query.startswith("CREATE TABLE"):
            if not self.exists:
                self.exists, self.dedup, self.wal = True, True, True
        elif "DEDUP ENABLE UPSERT KEYS" in query:
            if self.alter_applies:
                self.dedup, self.keys = True, re.findall(r'"([^"]+)"', query.split("KEYS", 1)[1])
        elif "materialized_views()" in query:
            rows = self.views
        elif "LATEST ON timestamp PARTITION BY table_name" in query:
            rows = self.state_rows
        elif "table_columns(" in query:
            rows = [[key] for key in self.keys]
        elif query.startswith("SHOW CREATE TABLE"):
            rows = [[self.show_create]]
        elif "SET TTL" in query:
            return httpx.Response(self.ttl_status, text="ttl")
        return httpx.Response(200, json={"dataset": rows})


class _QuestDbStubMixin:
    """Route every QuestDB request of `metrics` to a `_FakeQuestDb`; one gate per test."""

    def start_questdb(self, fake: _FakeQuestDb, *, ttl="365 DAYS") -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(metrics, "METRICS_BACKEND", "questdb"))
        stack.enter_context(patch.object(metrics, "QUESTDB_TTL", ttl))
        stack.enter_context(patch.dict(metrics._GATE_RESULTS, clear=True))
        stack.enter_context(patch.dict(metrics._VERSION_RESULT, clear=True))
        stack.enter_context(patch.object(metrics.time, "sleep"))
        stack.enter_context(patch.object(metrics, "print_config_info"))
        self.log = MagicMock()
        for level in ("info", "warning", "error"):
            stack.enter_context(
                patch.object(metrics, f"print_{level}", side_effect=lambda msg, lv=level: self.log(lv.upper(), msg))
            )
        stack.enter_context(
            patch.object(
                metrics.httpx,
                "Client",
                side_effect=lambda **kw: _RealClient(transport=httpx.MockTransport(fake.handler), **kw),
            )
        )
        self.fake = fake


def _minimal_sent_line() -> str:
    """Report point of a successful send with every optional tag empty."""
    return metrics.format_report_line(
        "m",
        alert_id=1,
        ip="198.51.100.1",
        scenario="",
        status="sent",
        recipient="x@example.com",
        error=None,
        country="",
        as_number="",
        as_name="",
        processing_time=0.0,
    )


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
        line = _minimal_sent_line()
        self.assertTrue(line.startswith("m,ip_address=198.51.100.1,status=sent "))

    def test_error_message_field_is_always_present(self):
        """`error_message` must be written on every point, even empty.

        ILP creates a column lazily on its first point. A conditional field
        would leave the column missing from the table until the first failed
        report, and a dashboard query selecting it as a plain column fails
        with QuestDB's "Invalid column" until then.
        """
        line = _minimal_sent_line()
        self.assertIn('error_message=""', line)


class BackendWriteTest(unittest.TestCase):
    def _response(self, status: int) -> httpx.Response:
        return httpx.Response(status, text="err")

    def test_questdb_uses_bearer_token_and_write_endpoint(self):
        with (
            patch.object(metrics, "METRICS_BACKEND", "questdb"),
            patch.object(metrics, "QUESTDB_TOKEN", "tok"),
            patch.object(metrics, "ensure_questdb_version", return_value=True),
            patch.object(metrics, "ensure_questdb_table", return_value=True),
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


class QuestDbTtlTest(_QuestDbStubMixin, unittest.TestCase):
    def test_parse_ttl(self):
        self.assertEqual(config.parse_questdb_ttl("365d"), "365 DAYS")
        self.assertEqual(config.parse_questdb_ttl("6M"), "6 MONTHS")
        self.assertEqual(config.parse_questdb_ttl("48h"), "48 HOURS")
        self.assertIsNone(config.parse_questdb_ttl("0"))
        self.assertIsNone(config.parse_questdb_ttl(""))
        with self.assertRaises(ValueError):
            config.parse_questdb_ttl("365")

    def test_ttl_applied_after_questdb_write(self):
        self.start_questdb(_FakeQuestDb())
        self.assertEqual(metrics.write_points(["a"]), metrics.WriteStatus.OK)
        ttl_index = next(i for i, (_, v) in enumerate(self.fake.events) if "SET TTL" in v)
        write_index = next(i for i, (k, _) in enumerate(self.fake.events) if k == "write")
        self.assertGreater(ttl_index, write_index)
        self.assertIn(f'ALTER TABLE "{metrics.QUESTDB_TABLE}" SET TTL 365 DAYS', self.fake.queries)

    def test_ttl_failure_is_written_but_not_a_plain_failure(self):
        # Written and unconfigured are two outcomes: the batch is stored (truthy,
        # so the outbox rows go), yet the status is not OK so the run exits 1.
        self.start_questdb(_FakeQuestDb(ttl_status=500))
        status = metrics.write_points(["a"])
        self.assertEqual(status, metrics.WriteStatus.WRITTEN_TTL_FAILED)
        self.assertTrue(status)
        self.assertEqual(len(self.fake.writes), 1)


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
            return conn.execute("SELECT Recipient, Scenario, Status, ErrorMessage FROM abuse_alerts").fetchone()
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
    def _run_main(self, write_ok: bool, outbox_count: int = 0, flush_error=None, decisions=None):
        alert = {"id": 1, "source": {"ip": "8.8.8.8"}, "scenario": "one"}
        result = crowdsec_main.ProcessResult(
            success=True,
            alert_id=1,
            ip="8.8.8.8",
            scenario="one",
            recipient="abuse@example.com",
            finalized=True,
        )
        fake_geoip = MagicMock(ensure_geoip_databases=lambda: {"city": True, "asn": True})
        quiet = [
            "print_banner",
            "print_summary_header",
            "print_detailed_summary",
            "print_config_info",
            "print_database_error",
            "print_whitelisted_asn_table",
            "print_alert_overview_table",
            "init_db",
            "cleanup_old_records",
            "reap_stale_pending",
            "run_db_maintenance",
        ]
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"app.geoip": fake_geoip}))
            for name in quiet:
                stack.enter_context(patch.object(crowdsec_main, name))
            values = {
                "METRICS_ENABLED": True,
                "METRICS_BACKEND": "questdb",
                "ensure_questdb_version": MagicMock(return_value=True),
                "get_alert_stats": MagicMock(return_value={}),
                "get_node_ip": MagicMock(return_value="127.0.0.1"),
                "get_crowdsec_decisions": MagicMock(return_value=[alert] if decisions is None else decisions),
                "batch_check_processed_alerts": MagicMock(return_value=set()),
                "deduplicate_and_filter_alerts": MagicMock(return_value=([alert], 0, 0, 0, 0)),
                "process_single_alert": MagicMock(return_value=result),
                "flush_points": MagicMock(return_value=write_ok, side_effect=flush_error),
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
        flush, run_state = values["flush_points"], values["set_run_state"]
        return code, flush, run_state

    def test_points_written_and_run_state_recorded(self):
        code, flush, run_state = self._run_main(write_ok=True)
        self.assertEqual(code, 0)
        lines = flush.call_args.args[0]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("crowdsec-abuse,ip_address=8.8.8.8,"))
        final = run_state.call_args_list[-1].args[0]
        self.assertEqual(final["last_run_exit_code"], "0")

    def test_deferred_backend_write_does_not_fail_the_run(self):
        # Points are spooled to SQLite before the write is attempted, so an
        # unreachable backend costs a retry on the next run, not the data.
        # Failing the run here would withhold the heartbeat - and eventually flip
        # the container unhealthy - for a condition that loses nothing.
        code, _flush, run_state = self._run_main(write_ok=False)
        self.assertEqual(code, 0)
        self.assertEqual(run_state.call_args_list[-1].args[0]["last_run_exit_code"], "0")

    def test_points_lost_when_spool_and_backend_both_fail_fails_the_run(self):
        code, _flush, run_state = self._run_main(write_ok=False, flush_error=metrics.MetricsLostError("lost"))
        self.assertEqual(code, 1)
        self.assertEqual(run_state.call_args_list[-1].args[0]["last_run_exit_code"], "1")

    def test_saturated_outbox_fails_a_run_without_decisions(self):
        with patch.object(crowdsec_main, "METRICS_OUTBOX_MAX_ROWS", 100):
            code, _flush, _rs = self._run_main(write_ok=True, outbox_count=95, decisions=[])
        self.assertEqual(code, 1)

    def test_unsaturated_outbox_keeps_a_run_without_decisions_healthy(self):
        with patch.object(crowdsec_main, "METRICS_OUTBOX_MAX_ROWS", 100):
            code, _flush, _rs = self._run_main(write_ok=True, outbox_count=5, decisions=[])
        self.assertEqual(code, 0)

    def test_saturated_outbox_fails_the_run(self):
        # Once the spool nears its bound the next prune starts discarding points
        # for real, which is the failure that has to become visible.
        with patch.object(crowdsec_main, "METRICS_OUTBOX_MAX_ROWS", 100):
            code, _flush, run_state = self._run_main(write_ok=False, outbox_count=95)
        self.assertEqual(code, 1)
        self.assertEqual(run_state.call_args_list[-1].args[0]["last_run_exit_code"], "1")

    def test_pruned_points_fail_the_run(self):
        # Undelivered rows dropped by the outbox bounds are lost data.
        code, _flush, _rs = self._run_main(write_ok=True, flush_error=metrics.MetricsPrunedError("2 dropped"))
        self.assertEqual(code, 1)

    def test_failed_dedup_gate_fails_the_run_at_once(self):
        # The outbox is below saturation, yet a gate failure must not exit 0.
        code, _flush, run_state = self._run_main(write_ok=True, flush_error=metrics.MetricsGateError("no dedup"))
        self.assertEqual(code, 1)
        self.assertEqual(run_state.call_args_list[-1].args[0]["last_run_exit_code"], "1")

    def test_failed_dedup_gate_at_startup_flush_is_counted_too(self):
        error = metrics.MetricsGateError("no dedup")
        code, flush, _rs = self._run_main(write_ok=True, outbox_count=3, flush_error=error)
        self.assertEqual(code, 1)
        self.assertEqual(flush.call_count, 2)

    def test_startup_flush_error_fails_run_without_new_alerts(self):
        code, _flush, run_state = self._run_main(
            write_ok=True, outbox_count=3, flush_error=metrics.MetricsGateError("no dedup"), decisions=[]
        )
        self.assertEqual(code, 1)
        self.assertEqual(run_state.call_args_list[-1].args[0]["last_run_exit_code"], "1")

    def test_failed_ttl_fails_the_run(self):
        code, _flush, _rs = self._run_main(write_ok=True, flush_error=metrics.MetricsTtlError("no ttl"))
        self.assertEqual(code, 1)


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

    def test_flush_raises_when_spool_and_write_both_fail(self):
        with (
            patch.object(metrics, "METRICS_ENABLED", True),
            patch.object(metrics, "spool_metric_points", return_value=False),
            patch.object(metrics, "prune_metric_outbox", return_value=0),
            patch.object(metrics, "write_points", return_value=False),
            self.assertRaises(metrics.MetricsLostError),
        ):
            metrics.flush_points(["a 1"])

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
            conn.execute("UPDATE metrics_outbox SET created_at = datetime('now', '-40 days')")
        database.prune_metric_outbox(max_rows=0, max_age_days=30)
        self.assertEqual(database.count_metric_points(), 0)

    def _flush_with_old_rows(self, count, *, max_rows, max_age_days, write_ok=True):
        database.spool_metric_points([f"p {n}" for n in range(count)])
        with database.db_transaction() as conn:
            conn.execute("UPDATE metrics_outbox SET created_at = datetime('now', '-40 days') WHERE id <= 2")
        with (
            patch.object(metrics, "METRICS_ENABLED", True),
            patch.object(metrics, "METRICS_OUTBOX_MAX_ROWS", max_rows),
            patch.object(metrics, "METRICS_OUTBOX_MAX_AGE_DAYS", max_age_days),
            patch.object(metrics, "write_points", return_value=write_ok) as wp,
        ):
            return wp, metrics.flush_points(["new 1"])

    def test_nothing_pruned_raises_nothing(self):
        _wp, ok = self._flush_with_old_rows(3, max_rows=100, max_age_days=0)
        self.assertTrue(ok)

    def test_age_pruned_rows_raise_but_remaining_rows_are_sent(self):
        with self.assertRaises(metrics.MetricsPrunedError) as ctx:
            self._flush_with_old_rows(4, max_rows=0, max_age_days=30)
        self.assertIn("2 undelivered", str(ctx.exception))
        # The remaining rows were flushed and acknowledged despite the loss.
        self.assertEqual(database.count_metric_points(), 0)

    def test_row_bound_pruned_rows_raise(self):
        with self.assertRaises(metrics.MetricsPrunedError):
            self._flush_with_old_rows(5, max_rows=3, max_age_days=0)

    def test_prune_loss_and_failed_write_stay_spooled_and_raise(self):
        with self.assertRaises(metrics.MetricsPrunedError):
            self._flush_with_old_rows(4, max_rows=0, max_age_days=30, write_ok=False)
        self.assertEqual(database.count_metric_points(), 3)

    def test_prune_and_spool_loss_are_one_error(self):
        with (
            patch.object(metrics, "METRICS_ENABLED", True),
            patch.object(metrics, "spool_metric_points", return_value=False),
            patch.object(metrics, "prune_metric_outbox", return_value=4),
            patch.object(metrics, "write_points", return_value=False),
            self.assertRaises(metrics.MetricsLostError) as ctx,
        ):
            metrics.flush_points(["a 1"])
        self.assertNotIsInstance(ctx.exception, metrics.MetricsPrunedError)
        self.assertIn("4 undelivered", str(ctx.exception))

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

    def test_no_dedup_declaration_without_keys(self):
        with patch.object(metrics.httpx, "Client") as client:
            self.assertTrue(metrics.ensure_questdb_table("t", ()))
        client.assert_not_called()

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


class QuestDbDownsamplingTest(_QuestDbStubMixin, unittest.TestCase):
    TABLE = metrics.QUESTDB_TABLE
    VIEW = f"{metrics.QUESTDB_TABLE}_rollup_1h_v1"

    def _write(self, fake, *, ttl="365 DAYS", profile="medium"):
        self.start_questdb(fake, ttl=ttl)
        patcher = patch.object(metrics, "QUESTDB_DOWNSAMPLING", profile)
        patcher.start()
        self.addCleanup(patcher.stop)
        days = {"365 DAYS": 365, None: None}[ttl]
        days_patch = patch.object(metrics, "QUESTDB_TTL_DAYS", days)
        days_patch.start()
        self.addCleanup(days_patch.stop)
        return metrics.write_points(["a"])

    @staticmethod
    def _state(fake):
        return [q for q in fake.queries if q.startswith('INSERT INTO "_crowdsec_downsampling"')]

    def test_rollup_dimensions_stay_within_the_dedup_keys(self):
        self.assertLessEqual(set(metrics.ROLLUP.dimensions), set(metrics.DEDUP_KEYS))

    def test_current_view_shortens_raw_ttl_and_publishes_after_it(self):
        fake = _FakeQuestDb()
        fake.views = [[self.VIEW, self.TABLE, "valid", 4, 4]]
        self.assertEqual(self._write(fake), metrics.WriteStatus.OK)
        raw = f'ALTER TABLE "{self.TABLE}" SET TTL 30 DAYS'
        (state,) = self._state(fake)
        self.assertIn(f'ALTER MATERIALIZED VIEW "{self.VIEW}" SET TTL 365 DAYS', fake.queries)
        self.assertLess(fake.queries.index(raw), fake.queries.index(state))
        self.assertIn("true, 30,", state)

    def test_refreshing_view_keeps_full_raw_ttl_without_failing(self):
        fake = _FakeQuestDb()
        fake.views = [[self.VIEW, self.TABLE, "refreshing", 1, 4]]
        self.assertEqual(self._write(fake), metrics.WriteStatus.OK)
        self.assertIn(f'ALTER TABLE "{self.TABLE}" SET TTL 365 DAYS', fake.queries)
        (state,) = self._state(fake)
        self.assertIn("'disabled'", state)

    def _warnings(self):
        return [call.args[1] for call in self.log.call_args_list if call.args[0] == "WARNING"]

    def _raw_ttl(self, fake):
        return [q for q in fake.queries if q.startswith(f'ALTER TABLE "{self.TABLE}" SET TTL')]

    def test_refresh_lagging_only_this_runs_own_write_still_shortens_the_raw_ttl(self):
        fake = _FakeQuestDb()
        fake.views = [[self.VIEW, self.TABLE, "valid", 4, 4]]
        fake.on_write = lambda: fake.views.__setitem__(0, [self.VIEW, self.TABLE, "refreshing", 4, 5])
        self.assertEqual(self._write(fake), metrics.WriteStatus.OK)
        self.assertEqual(self._warnings(), [])
        self.assertEqual(self._raw_ttl(fake), [f'ALTER TABLE "{self.TABLE}" SET TTL 30 DAYS'])

    def test_view_behind_the_state_before_the_write_keeps_the_raw_ttl(self):
        fake = _FakeQuestDb()
        fake.views = [[self.VIEW, self.TABLE, "refreshing", 1, 4]]
        self.assertEqual(self._write(fake), metrics.WriteStatus.OK)
        self.assertEqual(self._raw_ttl(fake), [f'ALTER TABLE "{self.TABLE}" SET TTL 365 DAYS'])

    def test_persistent_lag_escalates_to_a_warning(self):
        fake = _FakeQuestDb()
        fake.views = [[self.VIEW, self.TABLE, "refreshing", 1, 4]]
        patcher = patch.object(metrics, "_PENDING_RUNS", {})
        patcher.start()
        self.addCleanup(patcher.stop)
        for _ in range(metrics._PENDING_WARN_AFTER - 1):
            self._write(fake)
        self._write(fake)
        self.assertIn("consecutive runs", "\n".join(self._warnings()))

    def test_null_symbols_in_the_state_row_do_not_trigger_a_new_insert(self):
        fake = _FakeQuestDb()
        fake.views = [[self.VIEW, self.TABLE, "refreshing", 1, 4]]
        fake.state_rows = [["disabled", 1, False, 365, None, None, "365 DAYS"]]
        self.assertEqual(self._write(fake), metrics.WriteStatus.OK)
        self.assertEqual(self._state(fake), [])

    def test_failed_raw_ttl_publishes_nothing_and_keeps_the_data(self):
        fake = _FakeQuestDb()
        fake.views = [[self.VIEW, self.TABLE, "valid", 4, 4]]
        fake.exec_fail = lambda q: 400 if q.startswith("ALTER TABLE") and "SET TTL" in q else None
        self.assertEqual(self._write(fake), metrics.WriteStatus.WRITTEN_TTL_FAILED)
        self.assertEqual(self._state(fake), [])

    def test_disabled_total_ttl_lifts_the_view_ttl(self):
        fake = _FakeQuestDb()
        fake.views = [[self.VIEW, self.TABLE, "valid", 4, 4]]
        self.assertEqual(self._write(fake, ttl=None), metrics.WriteStatus.OK)
        self.assertIn(f'ALTER MATERIALIZED VIEW "{self.VIEW}" SET TTL 0 HOURS', fake.queries)

    def test_profile_off_creates_no_view(self):
        fake = _FakeQuestDb()
        self.assertEqual(self._write(fake, profile=""), metrics.WriteStatus.OK)
        self.assertEqual(fake.count("CREATE MATERIALIZED VIEW"), 0)
        self.assertIn(f'ALTER TABLE "{self.TABLE}" SET TTL 365 DAYS', fake.queries)


class QuestDbGateTest(_QuestDbStubMixin, unittest.TestCase):
    """Dedup is a hard precondition: nothing is written to QuestDB before it is verified."""

    def test_gate_runs_before_the_first_write(self):
        self.start_questdb(_FakeQuestDb())
        self.assertEqual(metrics.write_points(["a"]), metrics.WriteStatus.OK)
        first_write = next(i for i, (kind, _) in enumerate(self.fake.events) if kind == "write")
        before = [value for _, value in self.fake.events[:first_write]]
        create = next(q for q in before if q.startswith("CREATE TABLE"))
        self.assertTrue(any("DEDUP ENABLE UPSERT KEYS" in q for q in before))
        self.assertTrue(any("table_columns(" in q for q in before))
        self.assertIn('"timestamp" TIMESTAMP, "host" SYMBOL, "ip_address" SYMBOL', create)
        self.assertIn('"as_name" SYMBOL) TIMESTAMP("timestamp") PARTITION BY DAY WAL DEDUP UPSERT KEYS(', create)

    def test_gate_runs_once_per_process(self):
        self.start_questdb(_FakeQuestDb())
        metrics.write_points(["a"])
        metrics.write_points(["b"])
        self.assertEqual(self.fake.count("CREATE TABLE"), 1)
        self.assertEqual(len(self.fake.writes), 2)

    def test_failed_gate_is_cached_and_never_writes(self):
        self.start_questdb(_FakeQuestDb(dedup=False, exists=True, alter_applies=False))
        for _ in range(2):
            with self.assertRaises(metrics.MetricsGateError):
                metrics.write_points(["a"])
        self.assertEqual(self.fake.writes, [])
        self.assertEqual(self.fake.count("CREATE TABLE"), 1)

    def test_other_key_set_blocks_the_write(self):
        self.start_questdb(_FakeQuestDb(exists=True, keys=["timestamp", "ip_address"], alter_applies=False))
        with self.assertRaises(metrics.MetricsGateError):
            metrics.write_points(["a"])
        self.assertEqual(self.fake.writes, [])

    def test_missing_dedup_blocks_the_write(self):
        self.start_questdb(_FakeQuestDb(exists=True, dedup=False, alter_applies=False))
        with self.assertRaises(metrics.MetricsGateError):
            metrics.write_points(["a"])
        self.assertEqual(self.fake.writes, [])

    def test_non_wal_table_and_skip_mode_block_the_write(self):
        for fake in (_FakeQuestDb(exists=True, wal=False), _FakeQuestDb(show_create="... DEDUP SKIP ...")):
            with self.subTest(exists=fake.exists, wal=fake.wal):
                self.start_questdb(fake)
                with self.assertRaises(metrics.MetricsGateError):
                    metrics.write_points(["a"])
                self.assertEqual(fake.writes, [])

    def test_transient_5xx_is_retried(self):
        fake = _FakeQuestDb()
        failures = iter([503, 500])
        fake.exec_fail = lambda q: next(failures, None) if q.startswith("CREATE TABLE") else None
        self.start_questdb(fake)
        self.assertEqual(metrics.write_points(["a"]), metrics.WriteStatus.OK)
        self.assertEqual(fake.count("CREATE TABLE"), 3)

    def test_4xx_is_final_and_not_retried(self):
        fake = _FakeQuestDb()
        fake.exec_fail = lambda q: 400 if q.startswith("CREATE TABLE") else None
        self.start_questdb(fake)
        with self.assertRaises(metrics.MetricsGateError):
            metrics.write_points(["a"])
        self.assertEqual(fake.count("CREATE TABLE"), 1)
        self.assertEqual(fake.writes, [])

    def test_enabling_dedup_on_an_existing_table_warns_with_runbook(self):
        self.start_questdb(_FakeQuestDb(exists=True, dedup=False))
        self.assertEqual(metrics.write_points(["a"]), metrics.WriteStatus.OK)
        warnings = [c.args[1] for c in self.log.call_args_list if c.args[0] == "WARNING"]
        self.assertTrue(any("metrics-backends.md" in w and "NOT deduplicated" in w for w in warnings))

    def test_influxdb_needs_no_gate(self):
        with (
            patch.object(metrics, "METRICS_BACKEND", "influxdb2"),
            patch.object(metrics, "ensure_questdb_table") as gate,
            patch.object(metrics, "_post", return_value=httpx.Response(204)),
            patch.object(metrics, "print_config_info"),
        ):
            self.assertTrue(metrics.write_points(["a"]))
        gate.assert_not_called()


class QuestDbFlushGateTest(_QuestDbStubMixin, _TempDbMixin, unittest.TestCase):
    """The outbox is the only durable copy: a failed gate must never delete from it."""

    def setUp(self):
        _TempDbMixin.setUp(self)
        patcher = patch.object(metrics, "METRICS_ENABLED", True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_successful_gate_writes_and_clears_the_outbox(self):
        self.start_questdb(_FakeQuestDb())
        database.spool_metric_points(["old 1"])
        self.assertTrue(metrics.flush_points(["new 2"]))
        self.assertEqual(self.fake.writes, ["old 1\nnew 2"])
        self.assertEqual(database.count_metric_points(), 0)

    def test_failed_gate_keeps_every_row_and_writes_nothing(self):
        self.start_questdb(_FakeQuestDb(exists=True, dedup=False, alter_applies=False))
        database.spool_metric_points(["old 1"])
        with self.assertRaises(metrics.MetricsGateError) as ctx:
            metrics.flush_points(["new 2"])
        self.assertNotIsInstance(ctx.exception, metrics.MetricsLostError)
        self.assertEqual(self.fake.writes, [])
        self.assertEqual(database.count_metric_points(), 2)

    def test_gate_failure_and_pruning_are_one_gate_error(self):
        self.start_questdb(_FakeQuestDb(exists=True, dedup=False, alter_applies=False))
        database.spool_metric_points(["a", "b", "c"])
        with (
            patch.object(metrics, "METRICS_OUTBOX_MAX_ROWS", 2),
            self.assertRaises(metrics.MetricsGateError) as ctx,
        ):
            metrics.flush_points()
        self.assertIn("were also dropped", str(ctx.exception))

    def test_gate_failure_without_a_spool_is_a_loss(self):
        self.start_questdb(_FakeQuestDb(exists=True, dedup=False, alter_applies=False))
        with (
            patch.object(metrics, "spool_metric_points", return_value=False),
            self.assertRaises(metrics.MetricsLostError),
        ):
            metrics.flush_points(["x 1"])

    def test_ttl_failure_raises_after_delivery_without_resend(self):
        self.start_questdb(_FakeQuestDb(ttl_status=500))
        database.spool_metric_points(["old 1"])
        with self.assertRaises(metrics.MetricsTtlError):
            metrics.flush_points(["new 2"])
        self.assertEqual(len(self.fake.writes), 1)
        self.assertEqual(database.count_metric_points(), 0)
        # The next flush has nothing left to send, so no DDL failure causes a resend.
        self.assertTrue(metrics.flush_points())
        self.assertEqual(len(self.fake.writes), 1)


class QuestDbSnapshotGateTest(_QuestDbStubMixin, unittest.TestCase):
    """METRICS_ONLY snapshots call write_points directly and must pass the same gate."""

    def _snapshot(self):
        with (
            patch.object(crowdsec_main, "METRICS_ENABLED", True),
            patch.object(
                crowdsec_main, "get_crowdsec_decisions", return_value=[{"id": 1, "source": {"ip": "8.8.8.8"}}]
            ),
            patch.object(crowdsec_main, "print_database_error") as err,
        ):
            return crowdsec_main._run_metrics_snapshot("h"), err

    def test_snapshot_passes_the_gate_before_writing(self):
        self.start_questdb(_FakeQuestDb())
        code, _err = self._snapshot()
        self.assertEqual(code, 0)
        events = self.fake.events
        first_write = next(i for i, (kind, _) in enumerate(events) if kind == "write")
        self.assertEqual(self.fake.count("CREATE TABLE"), 1)
        self.assertTrue(any(v.startswith("CREATE TABLE") for _, v in events[:first_write]))

    def test_snapshot_exits_1_without_writing_when_the_gate_fails(self):
        self.start_questdb(_FakeQuestDb(exists=True, dedup=False, alter_applies=False))
        code, err = self._snapshot()
        self.assertEqual(code, 1)
        self.assertEqual(self.fake.writes, [])
        err.assert_called()
        message = err.call_args.args[1]
        self.assertIn("point(s) were not written", message)
        self.assertNotIn("outbox", message)

    def test_snapshot_exits_1_after_a_failed_ttl(self):
        self.start_questdb(_FakeQuestDb(ttl_status=500))
        code, _err = self._snapshot()
        self.assertEqual(code, 1)
        self.assertEqual(len(self.fake.writes), 1)


class QuestDbVersionGateTest(_QuestDbStubMixin, _TempDbMixin, unittest.TestCase):
    """Only QuestDB 10.x is supported; anything else writes nothing and keeps the outbox."""

    def setUp(self):
        _TempDbMixin.setUp(self)
        patcher = patch.object(metrics, "METRICS_ENABLED", True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_version_10_is_accepted_and_cached(self):
        self.start_questdb(_FakeQuestDb(build_info="QuestDB 10.2.1"))
        self.assertTrue(metrics.ensure_questdb_version())
        self.assertTrue(metrics.ensure_questdb_version())
        self.assertEqual(self.fake.count("SELECT build()"), 1)

    def test_other_or_unreadable_versions_are_rejected(self):
        for info, found in (
            ("Build Information: QuestDB 9.3.4, JDK 21", "9.3.4"),
            ("Build Information: QuestDB 11.0.0, JDK 25", "11.0.0"),
            ("garbage", "unknown"),
            (None, "unknown"),
        ):
            with self.subTest(info=info):
                self.start_questdb(_FakeQuestDb(build_info=info))
                self.assertFalse(metrics.ensure_questdb_version())
                message = self.log.call_args_list[-1].args[1]
                expected = (
                    "QuestDB version could not be determined"
                    if found == "unknown"
                    else "Unsupported QuestDB version at"
                )
                self.assertIn(expected, message)
                if found != "unknown":
                    self.assertIn(f"found {found}, ", message)
                self.assertIn("required 10.x; nothing was written", message)

    def test_unreachable_server_is_rejected_after_retries(self):
        fake = _FakeQuestDb()
        fake.exec_fail = lambda query: 503 if query == "SELECT build()" else None
        self.start_questdb(fake)
        self.assertFalse(metrics.ensure_questdb_version())
        self.assertEqual(fake.count("SELECT build()"), len(metrics._RETRY_BACKOFF_SECONDS) + 1)

    def test_flush_keeps_the_outbox_and_writes_nothing_on_a_wrong_version(self):
        self.start_questdb(_FakeQuestDb(build_info="QuestDB 9.0.0"))
        database.spool_metric_points(["old 1"])
        with self.assertRaises(metrics.MetricsGateError):
            metrics.flush_points(["new 2"])
        self.assertEqual(self.fake.writes, [])
        self.assertEqual(self.fake.count("CREATE TABLE"), 0)
        self.assertEqual(database.count_metric_points(), 2)

    def test_metrics_only_snapshot_refuses_a_wrong_version(self):
        self.start_questdb(_FakeQuestDb(build_info="QuestDB 11.0.0"))
        with (
            patch.object(crowdsec_main, "METRICS_ENABLED", True),
            patch.object(
                crowdsec_main, "get_crowdsec_decisions", return_value=[{"id": 1, "source": {"ip": "8.8.8.8"}}]
            ),
            patch.object(crowdsec_main, "print_database_error"),
        ):
            self.assertEqual(crowdsec_main._run_metrics_snapshot("h"), 1)
        self.assertEqual(self.fake.writes, [])

    def test_run_exits_1_before_init_db_on_a_wrong_version(self):
        self.start_questdb(_FakeQuestDb(build_info="QuestDB 9.0.0"))
        with (
            patch.object(crowdsec_main, "METRICS_BACKEND", "questdb"),
            patch.object(crowdsec_main, "print_banner"),
            patch.object(crowdsec_main, "setup_logging"),
            patch.object(crowdsec_main, "init_db", side_effect=AssertionError("init_db must not run")),
        ):
            self.assertEqual(crowdsec_main._run("2026-01-01T00:00:00Z"), 1)
        self.assertEqual(self.fake.writes, [])

    def test_check_is_skipped_for_influxdb_and_none(self):
        for backend in ("influxdb2", "none"):
            with self.subTest(backend=backend):
                fake = _FakeQuestDb()
                self.start_questdb(fake)
                with (
                    patch.object(metrics, "METRICS_BACKEND", backend),
                    patch.object(metrics, "send_to_influxdb", return_value=True),
                ):
                    metrics.write_points(["x 1"])
                self.assertEqual(fake.queries, [])


if __name__ == "__main__":
    unittest.main()
