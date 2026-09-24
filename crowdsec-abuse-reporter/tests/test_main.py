#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/tests/test_main.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import os
import sys
import types
import unittest
from contextlib import ExitStack, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["SMTP_PASSWORD"] = ""

from app import main as crowdsec_main

# main() records run state in SQLite after init_db(); tests patch init_db, so
# keep run_state writes away from the real data/abuse_alerts.db.
_run_state_patch = patch.object(crowdsec_main, "set_run_state")


def setUpModule():
    _run_state_patch.start()


def tearDownModule():
    _run_state_patch.stop()


class DummyInterruptHandler:
    def __init__(self):
        self.interrupted = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class MainHelpersTest(unittest.TestCase):
    def test_get_alert_id_rejects_missing_invalid_and_non_positive_values(self):
        self.assertIsNone(crowdsec_main.get_alert_id({}))
        self.assertIsNone(crowdsec_main.get_alert_id({"id": "nope"}))
        self.assertIsNone(crowdsec_main.get_alert_id({"id": 0}))
        self.assertIsNone(crowdsec_main.get_alert_id({"id": -5}))
        self.assertEqual(crowdsec_main.get_alert_id({"id": "7"}), 7)

    def test_get_alert_ip_falls_back_to_value_context_and_meta(self):
        self.assertEqual(
            crowdsec_main.get_alert_ip(
                {"source": {"scope": "Ip", "value": "202.191.58.34"}}
            ),
            "202.191.58.34",
        )
        self.assertEqual(
            crowdsec_main.get_alert_ip({"context": {"source_ip": "198.51.100.7"}}),
            "198.51.100.7",
        )
        self.assertEqual(
            crowdsec_main.get_alert_ip(
                {"events": [{"meta": [{"key": "source_ip", "value": "203.0.113.9"}]}]}
            ),
            "203.0.113.9",
        )

    @patch.object(crowdsec_main, "print_config_info")
    def test_deduplicate_skips_alerts_with_invalid_ids(self, _print_config_info):
        decisions = [
            {"id": "bad", "source": {"ip": "8.8.8.8"}, "scenario": "one"},
            {"id": 42, "source": {"ip": "9.9.9.9"}, "scenario": "two"},
        ]

        alerts, invalid_ips, invalid_ids, skipped, whitelisted = (
            crowdsec_main.deduplicate_and_filter_alerts(decisions, set())
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], 42)
        self.assertEqual(invalid_ips, 0)
        self.assertEqual(invalid_ids, 1)
        self.assertEqual(skipped, 0)
        self.assertEqual(whitelisted, 0)

    @patch.object(crowdsec_main, "print_internal_ip_skipped")
    def test_is_valid_public_ip_rejects_cgnat_space(self, _print_internal_ip_skipped):
        self.assertFalse(crowdsec_main.is_valid_public_ip("100.64.0.1", 11))
        self.assertTrue(crowdsec_main.is_valid_public_ip("8.8.8.8", 12))

    def test_build_whitelisted_asn_rows_uses_alert_provider_names(self):
        decisions = [
            {"source": {"as_number": "8881", "as_name": "1&1 Versatel"}},
            {"source": {"as_number": "3209", "as_name": "Vodafone"}},
        ]

        with (
            patch.object(
                crowdsec_main, "WHITELISTED_ASN", frozenset({"8881", "51167", "3209"})
            ),
            patch.dict(
                sys.modules,
                {
                    "app.geoip": types.SimpleNamespace(
                        lookup_asn_providers=lambda _asns: {
                            "8881": "1&1 Versatel GmbH",
                            "3209": "Vodafone GmbH",
                        }
                    )
                },
            ),
        ):
            rows = crowdsec_main.build_whitelisted_asn_rows(decisions)

        self.assertEqual(
            rows,
            [
                ("AS3209", "Vodafone GmbH"),
                ("AS8881", "1&1 Versatel GmbH"),
                ("AS51167", "unknown"),
            ],
        )

    def test_build_whitelisted_asn_rows_uses_local_asn_db_names(self):
        with (
            patch.object(
                crowdsec_main, "WHITELISTED_ASN", frozenset({"8881", "51167", "3209"})
            ),
            patch.dict(
                sys.modules,
                {
                    "app.geoip": types.SimpleNamespace(
                        lookup_asn_providers=lambda _asns: {
                            "8881": "1&1 Versatel GmbH",
                            "51167": "Contabo GmbH",
                            "3209": "Vodafone GmbH",
                        }
                    )
                },
            ),
        ):
            rows = crowdsec_main.build_whitelisted_asn_rows()

        self.assertEqual(
            rows,
            [
                ("AS3209", "Vodafone GmbH"),
                ("AS8881", "1&1 Versatel GmbH"),
                ("AS51167", "Contabo GmbH"),
            ],
        )

    def test_build_whitelisted_asn_rows_reports_provider_lookup_failure(self):
        def fail_lookup(_asns):
            raise RuntimeError("ASN database unavailable")

        with (
            patch.object(crowdsec_main, "WHITELISTED_ASN", frozenset({"8881"})),
            patch.dict(
                sys.modules,
                {"app.geoip": types.SimpleNamespace(lookup_asn_providers=fail_lookup)},
            ),
            patch.object(crowdsec_main, "print_debug") as debug,
        ):
            rows = crowdsec_main.build_whitelisted_asn_rows()

        self.assertEqual(rows, [("AS8881", "unknown")])
        debug.assert_called_once_with(
            "ASN provider lookup failed: ASN database unavailable"
        )

    def test_build_whitelisted_asn_rows_reports_alert_lookup_failure(self):
        def fail_lookup(_ip):
            raise RuntimeError("GeoIP reader unavailable")

        with (
            patch.object(crowdsec_main, "WHITELISTED_ASN", frozenset({"8881"})),
            patch.dict(
                sys.modules,
                {
                    "app.geoip": types.SimpleNamespace(
                        lookup_asn_providers=lambda _asns: {}, lookup=fail_lookup
                    )
                },
            ),
            patch.object(crowdsec_main, "print_debug") as debug,
        ):
            rows = crowdsec_main.build_whitelisted_asn_rows(
                [{"source": {"ip": "203.0.113.1", "as_number": "8881"}}]
            )

        self.assertEqual(rows, [("AS8881", "unknown")])
        debug.assert_called_once_with(
            "GeoIP lookup failed for 203.0.113.1: GeoIP reader unavailable"
        )

    def test_build_alert_overview_rows_ranks_countries_and_patterns(self):
        decisions = [
            {"scenario": "ssh-bf", "source": {"cn": "DE"}},
            {"scenario": "ssh-bf", "source": {"cn": "DE"}},
            {"scenario": "http-scan", "source": {"cn": "US"}},
            {"scenario": "redis-bf", "source": {"country": "FR"}},
            {"scenario": "", "source": {}},
        ]

        rows = crowdsec_main.build_alert_overview_rows(decisions, limit=3)

        self.assertEqual(
            rows,
            [
                (1, "DE", 2, "ssh-bf", 2),
                (2, "US", 1, "http-scan", 1),
                (3, "FR", 1, "redis-bf", 1),
            ],
        )

    @patch.object(crowdsec_main, "print_summary_header")
    @patch.object(crowdsec_main, "print_config_info")
    def test_print_alert_overview_table_formats_compact_ranking(
        self,
        mock_print_config_info,
        mock_print_summary_header,
    ):
        crowdsec_main.print_alert_overview_table(
            [
                {"scenario": "very-long-attack-pattern-name-that-needs-truncation", "source": {"cn": "Germany"}},
                {"scenario": "ssh-bf", "source": {"cn": "Germany"}},
                {"scenario": "ssh-bf", "source": {"cn": "US"}},
            ],
            limit=2,
        )

        mock_print_summary_header.assert_called_once_with("CURRENT ACTIVE REPORTABLE SIGNALS")
        printed = [call.args[0] for call in mock_print_config_info.call_args_list]
        self.assertIn("Country", printed[0])
        self.assertIn("Attack pattern", printed[0])
        self.assertIn("Germany", printed[2])
        self.assertIn("ssh-bf", printed[2])
        self.assertIn("very-long-attack-pattern-name-tha...", printed[3])

    def test_print_whitelisted_asn_table_prints_local_provider_names(self):
        with (
            patch.object(
                crowdsec_main, "WHITELISTED_ASN", frozenset({"8881", "51167", "3209"})
            ),
            patch.object(
                crowdsec_main,
                "build_whitelisted_asn_rows",
                return_value=[
                    ("AS3209", "Vodafone GmbH"),
                    ("AS8881", "1&1 Versatel GmbH"),
                    ("AS51167", "Contabo GmbH"),
                ],
            ),
            patch.object(crowdsec_main, "print_config_info") as mock_print,
        ):
            crowdsec_main.print_whitelisted_asn_table()

        printed = [call.args[0] for call in mock_print.call_args_list]
        self.assertIn("Configured whitelisted ASNs:", printed)
        self.assertIn("  AS8881   1&1 Versatel GmbH", printed)
        self.assertIn("  AS51167  Contabo GmbH", printed)
        self.assertIn("  AS3209   Vodafone GmbH", printed)
        self.assertLess(
            printed.index("  AS8881   1&1 Versatel GmbH"),
            printed.index("  AS51167  Contabo GmbH"),
        )
        self.assertLess(
            printed.index("  AS51167  Contabo GmbH"),
            printed.index("  AS3209   Vodafone GmbH"),
        )

    @patch.object(crowdsec_main, "send_abuse_mail", return_value=(True, None))
    @patch.object(crowdsec_main, "build_xarf_report", return_value="xarf")
    @patch.object(crowdsec_main, "build_mail_body", return_value="body")
    def test_send_abuse_report_sanitizes_subject_headers(
        self,
        _build_mail_body,
        _build_xarf_report,
        mock_send_abuse_mail,
    ):
        alert = {
            "id": 99,
            "source": {"ip": "1.2.3.4\r\nBcc: hidden@example.com"},
            "scenario": "ssh\r\nX-Injected: header",
        }

        crowdsec_main.send_abuse_report(
            alert,
            recipient="abuse@example.com",
            hostname="sensor.example.net",
        )

        subject = mock_send_abuse_mail.call_args.kwargs["subject"]
        # Invariant: subject must be a single line with no CR/LF characters.
        # We do not assert the exact string because that would lock in the
        # current (weak) sanitization strategy and block future improvements.
        self.assertNotIn("\n", subject)
        self.assertNotIn("\r", subject)
        self.assertEqual(subject.splitlines(), [subject])
        self.assertTrue(subject.startswith("Abuse Report - "))

    def test_sleep_between_mails_only_waits_between_successful_sends(self):
        handler = DummyInterruptHandler()
        with (
            patch.object(crowdsec_main, "SLEEP_BETWEEN_MAILS", 3),
            patch.object(crowdsec_main, "print_config_info"),
            patch.object(crowdsec_main, "interruptible_sleep") as mock_sleep,
        ):
            crowdsec_main.sleep_between_mails(True, True, handler)
            crowdsec_main.sleep_between_mails(False, True, handler)
            crowdsec_main.sleep_between_mails(True, False, handler)

        # Sleep only between successful sends that have a successor, and via the
        # interruptible variant so a stop signal aborts the rate-limit pause.
        mock_sleep.assert_called_once_with(3, handler)

    def test_handled_alerts_excludes_database_errors(self):
        stats = crowdsec_main.ProcessingStats(
            mails_sent=1,
            no_contact=2,
            dns_errors=3,
            send_errors=4,
            database_errors=5,
        )

        self.assertEqual(stats.handled_alerts(), 10)

    def test_print_detailed_summary_uses_compact_sectioned_layout(self):
        stats = crowdsec_main.ProcessingStats(
            mails_sent=1,
            no_contact=0,
            whitelisted_asns=1,
            total_processing_time=0.86,
            start_time=0.0,
        )

        with patch.object(crowdsec_main.time, "monotonic", return_value=32.04):
            buffer = StringIO()
            with redirect_stdout(buffer):
                crowdsec_main.print_detailed_summary(
                    stats,
                    total_alerts=3,
                    unique_alerts=1,
                    mails_sent_details=[
                        (
                            61,
                            "45.79.207.252",
                            "local/uiw-scan-one_port",
                            "abuse@akamai.com, abuse@linode.com",
                        )
                    ],
                )

        output = buffer.getvalue()
        self.assertIn("RUN SUMMARY", output)
        self.assertIn("Overview", output)
        self.assertIn("Eligible after filtering   : 1", output)
        self.assertIn("Results", output)
        self.assertIn("Performance", output)
        self.assertIn("Total processing time  : 32.04s", output)
        self.assertIn("Sent emails (1)", output)
        self.assertIn("1. Alert #61 | 45.79.207.252 | local/uiw-scan-one_port", output)
        self.assertIn("Recipients: abuse@akamai.com, abuse@linode.com", output)

    def test_print_detailed_summary_truncates_sent_email_list(self):
        stats = crowdsec_main.ProcessingStats(
            mails_sent=6,
            total_processing_time=6.0,
            start_time=0.0,
        )
        mails = [
            (index, f"198.51.100.{index}", f"scenario-{index}", "abuse@example.com")
            for index in range(1, 7)
        ]

        with patch.object(crowdsec_main.time, "monotonic", return_value=12.0):
            buffer = StringIO()
            with redirect_stdout(buffer):
                crowdsec_main.print_detailed_summary(
                    stats,
                    total_alerts=6,
                    unique_alerts=6,
                    mails_sent_details=mails,
                )

        output = buffer.getvalue()
        self.assertIn("Sent emails (6)", output)
        self.assertIn("5. Alert #5 | 198.51.100.5 | scenario-5", output)
        self.assertNotIn("6. Alert #6 | 198.51.100.6 | scenario-6", output)
        self.assertIn("... 1 more entry not shown", output)

    def test_main_counts_database_persistence_failures(self):
        alerts = [
            {"id": 1, "source": {"ip": "8.8.8.8"}, "scenario": "one"},
            {"id": 2, "source": {"ip": "9.9.9.9"}, "scenario": "two"},
        ]
        result = crowdsec_main.ProcessResult(
            success=True,
            alert_id=1,
            ip="8.8.8.8",
            scenario="one",
            recipient="abuse@example.com",
            processing_time=0.1,
            db_error=True,
        )

        with (
            patch.object(
                crowdsec_main, "GracefulInterruptHandler", DummyInterruptHandler
            ),
            patch.object(crowdsec_main, "print_banner"),
            patch.object(crowdsec_main, "print_summary_header"),
            patch.object(crowdsec_main, "print_stat_item"),
            patch.object(crowdsec_main, "print_detailed_summary") as mock_summary,
            patch.object(crowdsec_main, "print_config_info"),
            patch.object(crowdsec_main, "init_db"),
            patch.object(crowdsec_main, "get_node_ip", return_value="127.0.0.1"),
            patch.object(crowdsec_main, "get_crowdsec_decisions", return_value=alerts),
            patch.object(
                crowdsec_main, "batch_check_processed_alerts", return_value=set()
            ),
            patch.object(
                crowdsec_main,
                "deduplicate_and_filter_alerts",
                return_value=([alerts[0]], 0, 0, 0, 0),
            ),
            patch.object(
                crowdsec_main, "process_single_alert", return_value=result
            ) as mock_process_single_alert,
        ):
            crowdsec_main.main()

        self.assertEqual(mock_process_single_alert.call_count, 1)
        stats = mock_summary.call_args.args[0]
        self.assertEqual(stats.database_errors, 1)

    def test_main_exits_cleanly_with_hint_on_lapi_credentials_error(self):
        fake_geoip = types.SimpleNamespace(
            ensure_geoip_databases=lambda: {"city": True, "asn": True}
        )
        fetch_error = crowdsec_main.CrowdSecFetchError(
            "LAPI authentication failed with HTTP 403 (Forbidden).",
            hint=(
                "Use `docker exec -it <your crowdsec container name> "
                "cat /etc/crowdsec/local_api_credentials.yaml` to inspect the "
                "generated credentials."
            ),
        )

        with (
            patch.dict(sys.modules, {"app.geoip": fake_geoip}),
            patch.object(crowdsec_main, "print_banner"),
            patch.object(crowdsec_main, "print_summary_header"),
            patch.object(crowdsec_main, "print_config_info") as mock_print_config_info,
            patch.object(
                crowdsec_main, "GracefulInterruptHandler", DummyInterruptHandler
            ),
            patch.object(crowdsec_main, "init_db"),
            patch.object(crowdsec_main, "get_node_ip", return_value="127.0.0.1"),
            patch.object(
                crowdsec_main,
                "get_active_nameservers",
                return_value=["1.1.1.1", "9.9.9.9"],
            ),
            patch.object(
                crowdsec_main,
                "get_crowdsec_decisions",
                side_effect=fetch_error,
            ),
        ):
            exit_code = crowdsec_main.main()

        self.assertEqual(exit_code, 1)
        printed_messages = [call.args[0] for call in mock_print_config_info.call_args_list]
        self.assertIn(
            "ERROR: Could not fetch CrowdSec decisions: "
            "LAPI authentication failed with HTTP 403 (Forbidden).",
            printed_messages,
        )
        self.assertIn(
            "HINT: Use `docker exec -it <your crowdsec container name> "
            "cat /etc/crowdsec/local_api_credentials.yaml` to inspect the "
            "generated credentials.",
            printed_messages,
        )

    def test_main_prints_whitelisted_asn_table_before_fetch(self):
        fake_geoip = types.SimpleNamespace(
            ensure_geoip_databases=lambda: {"city": True, "asn": True}
        )

        with (
            patch.dict(sys.modules, {"app.geoip": fake_geoip}),
            patch.object(crowdsec_main, "print_banner"),
            patch.object(crowdsec_main, "print_summary_header"),
            patch.object(crowdsec_main, "print_stat_item"),
            patch.object(crowdsec_main, "print_detailed_summary"),
            patch.object(crowdsec_main, "print_config_info") as mock_print_config_info,
            patch.object(
                crowdsec_main, "GracefulInterruptHandler", DummyInterruptHandler
            ),
            patch.object(crowdsec_main, "init_db"),
            patch.object(crowdsec_main, "get_node_ip", return_value="127.0.0.1"),
            patch.object(
                crowdsec_main,
                "get_active_nameservers",
                return_value=["127.0.0.11"],
            ),
            patch.object(
                crowdsec_main,
                "get_crowdsec_decisions",
                side_effect=crowdsec_main.CrowdSecFetchError("boom"),
            ),
            patch.object(
                crowdsec_main, "batch_check_processed_alerts", return_value=set()
            ),
            patch.object(
                crowdsec_main, "WHITELISTED_ASN", frozenset({"8881", "51167"})
            ),
            patch.object(
                crowdsec_main,
                "build_whitelisted_asn_rows",
                return_value=[
                    ("AS8881", "1&1 Versatel GmbH"),
                    ("AS51167", "Contabo GmbH"),
                ],
            ),
        ):
            exit_code = crowdsec_main.main()

        self.assertEqual(exit_code, 1)
        printed_messages = [call.args[0] for call in mock_print_config_info.call_args_list]
        self.assertIn("Configured whitelisted ASNs:", printed_messages)
        self.assertTrue(any(msg.strip().startswith("ASN") and "Provider" in msg for msg in printed_messages))
        self.assertIn("  AS8881   1&1 Versatel GmbH", printed_messages)
        self.assertIn("  AS51167  Contabo GmbH", printed_messages)


if __name__ == "__main__":
    unittest.main()


class WhitelistAsnTableOrderTest(unittest.TestCase):
    """The whitelist table must be printed after the GeoIP databases are ready.

    Provider names are resolved from the local ASN MMDB. Printing the table with
    the rest of the startup configuration listed every entry as "unknown"
    whenever that database was not on disk yet — a cold start without an image
    baseline, or a run whose first action is to download it. The lookup itself
    was never broken, only its position in the sequence.
    """

    def test_table_is_printed_after_geoip_is_ensured(self):
        calls: list[str] = []
        fake_geoip = types.SimpleNamespace(
            ensure_geoip_databases=lambda: (
                calls.append("geoip"),
                {"city": True, "asn": True},
            )[1],
            GeoIPUnavailableError=crowdsec_main.GeoIPUnavailableError,
        )

        quiet = [
            "print_banner", "print_summary_header", "print_config_info",
            "print_database_error", "get_alert_stats",
        ]
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"app.geoip": fake_geoip}))
            for name in quiet:
                stack.enter_context(patch.object(crowdsec_main, name))
            stack.enter_context(patch.object(
                crowdsec_main, "print_whitelisted_asn_table",
                side_effect=lambda *a, **k: calls.append("table"),
            ))
            stack.enter_context(patch.object(
                crowdsec_main, "get_node_ip", return_value="203.0.113.1"
            ))
            # Stops the run right after the two calls under test, so the rest of
            # the pipeline needs no mocking.
            stack.enter_context(patch.object(
                crowdsec_main, "init_db", side_effect=RuntimeError("stop here")
            ))
            stack.enter_context(patch.object(
                crowdsec_main, "GracefulInterruptHandler", DummyInterruptHandler
            ))
            stack.enter_context(redirect_stdout(StringIO()))
            code = crowdsec_main.main()

        self.assertEqual(code, 1)
        self.assertEqual(calls, ["geoip", "table"])
