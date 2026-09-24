#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/tests/test_hardening.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import inspect
import io
import json
import logging
import os
import signal
import smtplib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import dns.resolver
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["SMTP_PASSWORD"] = ""

import contextlib

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


class AbuseHardeningTest(unittest.TestCase):
    def test_smtp_setup_failure_is_logged_once(self):
        server = MagicMock()
        server.starttls.side_effect = smtplib.SMTPException("TLS failed")
        with (
            patch.object(abuse.smtplib, "SMTP", return_value=server),
            patch.object(abuse, "SMTP_USE_TLS", True),
            patch.object(abuse, "SMTP_USERNAME", ""),
            patch.object(abuse, "SMTP_PASSWORD", ""),
            patch.object(abuse, "print_mail_error") as mail_error,
        ):
            result = abuse.send_abuse_mail("a@example.com", "subject", "body", max_retries=1)

        self.assertFalse(result[0])
        mail_error.assert_called_once()

    def test_xarf_attachment_failure_is_logged_once(self):
        with (
            patch.object(abuse, "MIMEApplication", side_effect=ValueError("bad attachment")),
            patch.object(abuse, "print_mail_error") as mail_error,
        ):
            result = abuse.send_abuse_mail(
                "a@example.com", "subject", "body", xarf_attachment="{}", max_retries=1
            )

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

        # 950 (alert_id, ip) pairs. Each pair binds 2 params, so chunks hold
        # 450 pairs (900 params): 450 + 450 + 50 pairs over three calls.
        keys = [(i, f"1.2.3.{i % 256}") for i in range(950)]
        with patch.object(database, "db_read") as mock_db_read:
            mock_db_read.return_value.__enter__.return_value = fake_conn
            database.batch_check_processed_alerts(keys)

        calls = fake_conn.cursor_obj.calls
        # Invariant: large inputs must be split across multiple queries, and no
        # single query may bind more than SQLITE_PARAM_LIMIT params. We also
        # verify completeness: every key appears exactly once across all calls.
        # Params layout: [pair_id, pair_ip, ..., *HANDLED_STATUSES] — the last
        # len(HANDLED_STATUSES) entries are status filters, not pair data.
        n_status = len(database.HANDLED_STATUSES)
        self.assertGreater(len(calls), 1)
        queried_keys = []
        for _query, params in calls:
            self.assertLessEqual(len(params), database.SQLITE_PARAM_LIMIT)
            pair_params = params[:-n_status]
            self.assertEqual(len(pair_params) % 2, 0)
            # Verify the trailing entries are exactly the expected status values
            self.assertEqual(params[-n_status:], list(database.HANDLED_STATUSES))
            queried_keys.extend(
                (pair_params[i], pair_params[i + 1])
                for i in range(0, len(pair_params), 2)
            )
        self.assertCountEqual(queried_keys, keys)

    def test_get_cached_abuse_contact_distinguishes_negative_cache(self):
        class FakeCursor:
            def __init__(self, row):
                self.row = row

            def execute(self, query, params):
                return None

            def fetchone(self):
                return self.row

        class FakeConn:
            def __init__(self, row):
                self.row = row

            def cursor(self):
                return FakeCursor(self.row)

        with patch.object(database, "db_read") as mock_db_read:
            mock_db_read.return_value.__enter__.return_value = FakeConn(
                (database.NEGATIVE_CACHE,)
            )
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
                "events": [
                    {"meta": [{"key": "http_path", "value": "/login"}], "extra": {}}
                ],
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
                    {"id": 1, "type": "ban", "scope": "Ip", "value": "1.1.1.1",
                     "duration": "4h", "origin": "crowdsec"},
                    {"id": 2, "type": "ban", "scope": "Ip", "value": "2.2.2.2",
                     "duration": "4h", "origin": "crowdsec"},
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
                    {"id": 10, "type": "ban", "scope": "Ip", "value": "3.3.3.3",
                     "duration": "4h", "origin": "CAPI"},
                    {"id": 11, "type": "ban", "scope": "Ip", "value": "4.4.4.4",
                     "duration": "4h", "origin": "crowdsec"},
                ],
            }
        ]

        with patch.object(crowdsec, "get_crowdsec_alerts", return_value=alerts):
            decisions = crowdsec.get_crowdsec_decisions()

        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["source"]["ip"], "4.4.4.4")

    def test_get_crowdsec_decisions_recovers_ip_from_event_meta_when_source_is_unusable(self):
        # Models a local crowdsec observation where the ban value is empty but
        # the source IP is recoverable from event metadata. Using a clearly local
        # origin avoids confusion with community-blocklist (CAPI) logic, which is
        # tested separately in test_get_crowdsec_decisions_skips_capi_bans.
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


class DnsUtilsHardeningTest(unittest.TestCase):
    def test_invalid_geoip_stamp_is_reported_before_refresh(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            (Path(tmp_dir) / geoip._STAMP_FILE).write_text("invalid", encoding="utf-8")
            with (
                patch.object(geoip, "_geoip_dir", return_value=Path(tmp_dir)),
                patch.object(geoip, "_verify", return_value=True),
                patch.object(geoip, "_download", return_value=False),
                self.assertLogs(geoip._log, level="DEBUG") as logs,
            ):
                result = geoip.ensure_geoip_databases()

        self.assertEqual(result, {"city": True, "asn": True})
        self.assertTrue(any("check stamp could not be read" in line for line in logs.output))

    def test_get_effective_nameservers_uses_system_resolver_only(self):
        with patch.object(
            dns_utils, "_system_nameservers", return_value=["10.30.0.2"]
        ):
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

    def test_geoip_download_uses_selected_nameservers_for_http_request(self):
        class FakeResponse:
            url = geoip.CITY_URL

            def __init__(self):
                self.headers = {"Content-Type": "application/octet-stream"}

            def read(self, _size):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False

        with (
            tempfile.TemporaryDirectory() as tmpdir, patch.object(
                geoip,
                "_geoip_dir",
                return_value=Path(tmpdir),
            ),
            patch.object(
                geoip,
                "get_effective_nameservers",
                return_value=["10.30.0.2"],
            ),
            patch.object(
                geoip,
                "_open_resolved_url",
                return_value=FakeResponse(),
            ) as mock_open_resolved_url,
            patch.object(geoip, "_verify", return_value=True),
        ):
            updated = geoip._download(geoip._SPECS["city"], force=True)

        self.assertTrue(updated)
        mock_open_resolved_url.assert_called_once()
        self.assertEqual(
            mock_open_resolved_url.call_args.kwargs["nameservers"],
            ["10.30.0.2"],
        )

    def test_lookup_asn_providers_reads_local_mmdb_records(self):
        class FakeReader:
            def __iter__(self):
                yield "1.0.0.0/24", {
                    "autonomous_system_number": 8881,
                    "autonomous_system_organization": "1&1 Versatel GmbH",
                }
                yield "2.0.0.0/24", {
                    "autonomous_system_number": 3209,
                    "autonomous_system_organization": "Vodafone GmbH",
                }
                yield "3.0.0.0/24", {
                    "autonomous_system_number": 51167,
                    "autonomous_system_organization": "Contabo GmbH",
                }

            def close(self):
                return None

        geoip._cached_asn_providers.cache_clear()
        with (
            patch.object(geoip, "_HAS_MAXMINDDB", True),
            patch.object(geoip, "_geoip_dir", return_value=Path("/tmp")),
            patch.object(geoip.maxminddb, "open_database", return_value=FakeReader()),
            patch.object(Path, "exists", return_value=True),
        ):
            providers = geoip.lookup_asn_providers(frozenset({"8881", "51167"}))

        self.assertEqual(
            providers,
            {"8881": "1&1 Versatel GmbH", "51167": "Contabo GmbH"},
        )


class ConfigEnvLoaderTest(unittest.TestCase):
    """Covers the stdlib KEY=VALUE loader that replaced python-dotenv."""

    def _write_env(self, content: str) -> Path:
        tmp_dir = Path(tempfile.mkdtemp())
        path = tmp_dir / "settings.env"
        path.write_text(content, encoding="utf-8")
        return path

    def test_skips_blank_lines_and_comments(self):
        path = self._write_env(
            "\n# full-line comment\nFOO=bar\n   \n# another comment\nBAZ=qux\n"
        )
        env: dict[str, str] = {}
        with patch.dict(os.environ, {}, clear=False):
            for key in ("FOO", "BAZ"):
                os.environ.pop(key, None)
            config.load_settings_env(path, override=True)
            env = {"FOO": os.environ.get("FOO"), "BAZ": os.environ.get("BAZ")}

        self.assertEqual(env, {"FOO": "bar", "BAZ": "qux"})

    def test_export_prefix_is_stripped(self):
        path = self._write_env("export FOO=bar\n")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FOO", None)
            config.load_settings_env(path, override=True)
            self.assertEqual(os.environ["FOO"], "bar")

    def test_matching_quotes_are_stripped(self):
        path = self._write_env('DOUBLE="hello"\nSINGLE=\'world\'\nMIXED="unterminated\n')
        with patch.dict(os.environ, {}, clear=False):
            for key in ("DOUBLE", "SINGLE", "MIXED"):
                os.environ.pop(key, None)
            config.load_settings_env(path, override=True)
            self.assertEqual(os.environ["DOUBLE"], "hello")
            self.assertEqual(os.environ["SINGLE"], "world")
            # Mismatched/unterminated quoting is left as-is (no stripping).
            self.assertEqual(os.environ["MIXED"], '"unterminated')

    def test_quoted_password_preserves_surrounding_whitespace(self):
        path = self._write_env('SMTP_PASSWORD="  s3cr3t  "\n')
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SMTP_PASSWORD", None)
            config.load_settings_env(path, override=True)
            self.assertEqual(os.environ["SMTP_PASSWORD"], "  s3cr3t  ")

    def test_unquoted_value_is_stripped(self):
        path = self._write_env("FOO=  spaced value  \n")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FOO", None)
            config.load_settings_env(path, override=True)
            self.assertEqual(os.environ["FOO"], "spaced value")

    def test_unquoted_value_strips_inline_comment(self):
        path = self._write_env("FOO=bar # note\n")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FOO", None)
            config.load_settings_env(path, override=True)
            self.assertEqual(os.environ["FOO"], "bar")

    def test_unquoted_value_without_leading_space_keeps_hash(self):
        path = self._write_env("FOO=a#b\n")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FOO", None)
            config.load_settings_env(path, override=True)
            self.assertEqual(os.environ["FOO"], "a#b")

    def test_quoted_value_with_hash_is_kept_verbatim(self):
        path = self._write_env('SMTP_PASSWORD="s3cr3t # not a comment"\n')
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SMTP_PASSWORD", None)
            config.load_settings_env(path, override=True)
            self.assertEqual(os.environ["SMTP_PASSWORD"], "s3cr3t # not a comment")

    def test_override_false_keeps_existing_environment_variable(self):
        path = self._write_env("FOO=from_file\n")
        with patch.dict(os.environ, {"FOO": "from_env"}, clear=False):
            config.load_settings_env(path, override=False)
            self.assertEqual(os.environ["FOO"], "from_env")

    def test_override_true_replaces_existing_environment_variable(self):
        path = self._write_env("FOO=from_file\n")
        with patch.dict(os.environ, {"FOO": "from_env"}, clear=False):
            config.load_settings_env(path, override=True)
            self.assertEqual(os.environ["FOO"], "from_file")

    def test_missing_file_is_not_an_error(self):
        missing = Path(tempfile.mkdtemp()) / "does-not-exist.env"
        # Must not raise.
        config.load_settings_env(missing, override=True)

    def test_unreadable_settings_path_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir, self.assertRaises(IsADirectoryError):
            config.load_settings_env(Path(tmp_dir), override=True)


class _TtyStream(io.StringIO):
    """StringIO that claims to be a TTY so colour codes are emitted."""

    def isatty(self) -> bool:
        return True


class LoggerHardeningTest(unittest.TestCase):
    def test_print_log_sanitizes_newlines(self):
        stream = io.StringIO()
        with (
            patch.object(sys, "stdout", stream),
            patch.object(sys, "stderr", stream),
        ):
            logger.print_log("INFO", "[INFO]", "line1\nline2")

        self.assertIn("line1\\nline2", stream.getvalue())

    def _capture(self, call):
        """Run ``call`` and return (stdout_text, stderr_text) with colours on."""
        out, err = _TtyStream(), _TtyStream()
        with patch.object(sys, "stdout", out), patch.object(sys, "stderr", err):
            call()
        return out.getvalue(), err.getvalue()

    def test_print_helpers_emit_expected_tag_colour_and_stream(self):
        # Pins the rendered tag, ANSI colour and target stream of every print_*
        # helper, so the formatting stays identical when call sites stop passing
        # a colour that print_log already derives from the level.
        cases = [
            (lambda: logger.print_processing(1, 2, "203.0.113.5", "scan"),
             "[PROCESS]", "PROCESSING", False),
            (lambda: logger.print_dns_query("203.0.113.5", "IPv4"),
             "[DNS]", "DNS_QUERY", False),
            (lambda: logger.print_abuse_contact_found("203.0.113.5", "a@example.com"),
             "[INFO]", "INFO", False),
            (lambda: logger.print_mail_sent("a@example.com", 7, 1.5),
             "[MAIL]", "MAIL_SENT", False),
            (lambda: logger.print_mail_error("a@example.com", "boom", 7),
             "[MAIL]", "ERROR", True),
            (lambda: logger.print_no_contact_found("203.0.113.5", 7),
             "[WARNING]", "WARNING", False),
            (lambda: logger.print_dns_error("203.0.113.5", "timeout", 7),
             "[ERROR]", "ERROR", True),
            (lambda: logger.print_database_error(7, "locked"),
             "[ERROR]", "ERROR", True),
            (lambda: logger.print_internal_ip_skipped("10.0.0.1", 7),
             "[INFO]", "INFO", False),
            (lambda: logger.print_config_info("hello"),
             "[INFO]", "INFO", False),
            (lambda: logger.print_summary_header("HEAD"),
             "[INFO]", "INFO", False),
            (lambda: logger.print_stat_item("Label", "3"),
             "[INFO]", "INFO", False),
        ]

        for call, tag, colour_key, to_stderr in cases:
            with self.subTest(tag=tag, colour=colour_key):
                out, err = self._capture(call)
                text = err if to_stderr else out
                self.assertEqual("" if to_stderr else err, "")
                self.assertTrue(text.startswith(logger.COLORS[colour_key]), text)
                self.assertTrue(text.rstrip("\n").endswith(logger.COLORS["RESET"]))
                self.assertIn(tag, text)

    def test_print_debug_respects_log_level(self):
        root = logging.getLogger()
        previous = root.level
        try:
            root.setLevel(logging.INFO)
            out, _ = self._capture(lambda: logger.print_debug("quiet"))
            self.assertEqual(out, "")

            root.setLevel(logging.DEBUG)
            out, _ = self._capture(lambda: logger.print_debug("loud"))
            self.assertIn("[DEBUG]", out)
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
        _, err = self._capture(
            lambda: logger.print_mail_error(
                "a@example.com", "Invalid RCPT TO address", None
            )
        )
        self.assertIn("Invalid recipient address", err)
        self.assertNotIn("Alert", err)

    def test_format_recipients_display_truncates(self):
        self.assertEqual(logger.format_recipients_display([]), "no recipients")
        self.assertEqual(
            logger.format_recipients_display(["a@example.com"]), "a@example.com"
        )
        self.assertEqual(
            logger.format_recipients_display(["a@example.com", "b@example.com"]),
            "a@example.com +1 more",
        )
        self.assertEqual(
            logger.format_recipients_display(["a" * 50 + "@example.com"], 20),
            "a" * 17 + "...",
        )


class ReviewFindingsTest(unittest.TestCase):
    """Regressions for the findings fixed in the security review pass."""

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
        with (
            patch.object(abuse.smtplib, "SMTP", return_value=server),
            patch.object(abuse, "SMTP_USE_TLS", False),
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
            self.assertEqual(
                abusix.query_abuse_contact_dns("203.0.113.5"), "abuse@example.com"
            )

    def test_extract_report_ip_does_not_collapse_a_range(self):
        # The address named in the outgoing report must never be a range's
        # network address, which usually belongs to an uninvolved party.
        self.assertEqual(
            reportbody._extract_report_ip(
                {"decisions": [{"value": "203.0.113.0/24", "scope": "Range"}]}
            ),
            "unknown",
        )
        self.assertEqual(
            reportbody._extract_report_ip(
                {"decisions": [{"value": "203.0.113.5/32", "scope": "Ip"}]}
            ),
            "203.0.113.5",
        )
        self.assertEqual(
            reportbody._extract_report_ip({"source": {"ip": "203.0.113.7"}}), "203.0.113.7"
        )

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
            result = crowdsec_main.process_single_alert(
                {"alert_id": 5, "source": {"ip": "203.0.113.5"}}, 1, 1, "host"
            )

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
        formatter = logger._AppLogFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            record = logging.LogRecord(
                "t", logging.ERROR, __file__, 1, "failed", None, sys.exc_info()
            )
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

    def test_geoip_download_retries_transient_then_gives_up(self):
        with (
            patch.object(
                geoip,
                "_download_once",
                side_effect=geoip._TransientDownloadError("dns"),
            ) as once,
            patch.object(geoip.time, "sleep") as sleep,
        ):
            self.assertFalse(geoip._download(geoip._SPECS["asn"]))

        self.assertEqual(once.call_count, geoip._DOWNLOAD_MAX_ATTEMPTS)
        self.assertEqual(sleep.call_count, geoip._DOWNLOAD_MAX_ATTEMPTS - 1)

    def test_geoip_download_does_not_retry_deterministic_failures(self):
        with (
            patch.object(geoip, "_download_once", return_value=False) as once,
            patch.object(geoip.time, "sleep") as sleep,
        ):
            self.assertFalse(geoip._download(geoip._SPECS["asn"]))

        self.assertEqual(once.call_count, 1)
        sleep.assert_not_called()

    def test_geoip_download_has_no_early_return_for_existing_db(self):
        # The If-Modified-Since request must stay reachable, otherwise the DB
        # freezes at its first downloaded version forever.
        source = inspect.getsource(geoip._download_once)
        self.assertNotIn("and _verify(target, spec):\n        return False", source)
        self.assertIn("If-Modified-Since", source)

    def test_entrypoint_hardcodes_data_dir(self):
        content = _ENTRYPOINT.read_text(encoding="utf-8")
        self.assertIn('DATA_DIR="/data"', content)
        self.assertNotIn("${DATA_DIR:-/data}", content)

    def test_dockerfile_keeps_app_root_owned(self):
        content = (_REPO_ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn("chown -R app:app /app", content)
        self.assertIn("chown -R app:app /data", content)

    def test_dockerfile_healthcheck_rejects_future_timestamps(self):
        content = (_REPO_ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('test "$age" -ge 0', content)
        self.assertIn('test "$api_age" -ge 0', content)


class ReportBodyHardeningTest(unittest.TestCase):
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
            body,
        )
        self.assertNotIn("generated automatically by CrowdSec", body)

    @patch.object(reportbody.uuid, "uuid4", return_value="fixed-report-id")
    @patch.object(reportbody, "_xarf_reporter", return_value={"org": "Example", "contact": "abuse@example.net"})
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
        lines = {
            line.strip().split(":", 1)[0]: line
            for line in context.splitlines()
            if ":" in line
        }

        # source_ip and SourceRange must be absent (suppressed)
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
    @patch.object(heartbeat, "print_config_info")
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
        mock_file.parent.mkdir = MagicMock()
        mock_file.touch.side_effect = OSError("read-only filesystem")
        with patch.object(heartbeat, "_HEARTBEAT_FILE", mock_file):
            self.assertFalse(heartbeat.run_heartbeat())


class EntrypointHardeningTest(unittest.TestCase):
    """Smoke-tests for shell-level entrypoint.sh configuration validation.

    The _api_heartbeat_loop background process inherits the bash shell's stdout/
    stderr FDs, so subprocess.communicate() would block indefinitely waiting for
    EOF even after the main bash process exits. We run each test in its own
    session (start_new_session=True) and kill the whole process group on timeout
    so the pipes are released and communicate() can return.
    """

    def _run_entrypoint(self, env_overrides: dict, timeout: int = 3):
        env = {
            **os.environ,
            "SMTP_SERVER": "smtp.example.net",
            "RUN_ONCE": "false",
            **env_overrides,
        }
        proc = subprocess.Popen(
            ["bash", str(_ENTRYPOINT)],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        return subprocess.CompletedProcess(
            proc.args, proc.returncode, stdout=stdout, stderr=stderr
        )

    def test_entrypoint_rejects_non_integer_run_jitter(self):
        # RUN_JITTER is validated in the main shell before Python is invoked.
        # The bash main process exits quickly (rc=1). The background heartbeat
        # loop keeps the pipe open until we kill the process group on timeout,
        # after which proc.communicate() returns with the correct exit code.
        result = self._run_entrypoint({"RUN_JITTER": "invalid"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RUN_JITTER", result.stderr)

    def test_entrypoint_accepts_zero_run_jitter(self):
        # RUN_JITTER=0 disables jitter and must not produce a validation error.
        # The script enters the periodic loop and runs until we kill it on timeout.
        result = self._run_entrypoint({"RUN_JITTER": "0"})
        self.assertNotIn("RUN_JITTER", result.stderr)

    def test_entrypoint_does_not_duplicate_successful_heartbeat_logs(self):
        content = _ENTRYPOINT.read_text(encoding="utf-8")

        self.assertNotIn('echo "[heartbeat] LAPI OK"', content)

if __name__ == "__main__":
    unittest.main()
