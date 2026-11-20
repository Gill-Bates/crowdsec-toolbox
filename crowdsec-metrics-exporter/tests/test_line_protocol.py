#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/tests/test_line_protocol.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# InfluxDB line protocol escaping, the dedup-key-is-a-tag invariant, record-id and coordinate robustness,
# and the transport warnings of the InfluxDB path.
import re

import pytest
import requests

import main
from app import events, influxdb
from app.influxdb import (
    escape_influxdb_string_field,
    escape_influxdb_value,
    format_influxdb_line_protocol,
)

ALERT = {
    "ip_address": "203.0.113.7",
    "as_name": "Example Net, Inc",
    "as_number": 64500,
    "country": "DE",
    "scenario": "crowdsecurity/ssh bf",
    "start_at": "2026-01-02T03:04:05Z",
    "message": 'say "hi"\\',
}
GOOD = {"id": 1, "start_at": "2026-01-02T03:04:05Z"}


def _tag_keys(line: str) -> set[str]:
    """Tag keys of a line: the section between the first comma and the first unescaped space."""
    head = re.split(r"(?<!\\) ", line, maxsplit=1)[0]
    return {pair.split("=", 1)[0] for pair in re.split(r"(?<!\\),", head)[1:]}


def test_tag_values_escape_comma_equals_and_space():
    assert escape_influxdb_value("a,b=c d") == "a\\,b\\=c\\ d"
    assert escape_influxdb_value("") == ""


def test_string_field_escapes_backslash_before_quote():
    assert escape_influxdb_string_field('a"b\\') == '"a\\"b\\\\"'
    assert escape_influxdb_string_field("") == '""'


def test_alert_line_has_escaped_tags_and_utc_nanosecond_timestamp():
    line = format_influxdb_line_protocol(ALERT, "host name", host="h1")
    assert line.startswith("host\\ name,")
    assert "as_name=Example\\ Net\\,\\ Inc" in line
    assert line.endswith(" 1767323045000000000")


@pytest.mark.parametrize("events_count", ["abc", True, 1.5, None])
def test_non_integer_events_count_is_dropped_not_written_raw(events_count):
    # A raw non-integer field value would make the whole ILP batch invalid; the point keeps its other fields.
    line = format_influxdb_line_protocol({**ALERT, "events_count": events_count}, "h")
    assert "events_count=" not in line
    assert "message=" in line
    assert " events_count=7," in format_influxdb_line_protocol({**ALERT, "events_count": 7}, "h")


@pytest.mark.parametrize("start_at", [None, "", "not a date"])
def test_alert_without_parseable_start_is_skipped(start_at):
    assert format_influxdb_line_protocol({**ALERT, "start_at": start_at}, "h") is None


@pytest.fixture
def run_main(monkeypatch, isolated_main, sent_payloads):
    """Return a runner that executes main() over the given decisions and yields (exit code, payloads)."""

    def run(decisions):
        monkeypatch.setattr(isolated_main, "get_crowdsec_decisions", lambda: decisions)
        return isolated_main.main(), sent_payloads

    return run


def test_main_exports_valid_alerts_but_exits_1_when_one_has_no_timestamp(run_main):
    bad = {"id": 2, "start_at": None}
    code, sent = run_main([GOOD, bad])
    assert code == 1
    assert len(sent) == 1
    assert sent[0].count("\n") == 0
    assert sent[0].endswith(" 1767323045000000000")


def test_main_with_only_untimestamped_alerts_sends_nothing_and_exits_1(run_main):
    code, sent = run_main([{"id": 2, "start_at": ""}])
    assert code == 1
    assert sent == []


def test_main_skips_non_text_scenario_and_marks_run_incomplete(run_main):
    good = {**GOOD, "scenario": "crowdsecurity/ssh"}
    malformed = {**GOOD, "id": 2, "scenario": 42}
    code, sent = run_main([good, malformed])
    assert code == 1
    assert len(sent) == 1
    assert "scenario=ssh" in sent[0]


def test_empty_tags_are_dropped_and_as_name_falls_back():
    tags = _tag_keys(format_influxdb_line_protocol({"start_at": "2026-01-02T03:04:05Z"}, "h"))
    assert "as_name" in tags
    assert "ip_address" not in tags


def test_alert_dedup_keys_are_tags_not_fields():
    # QuestDB rejects UPSERT KEYS that are field columns.
    tags = _tag_keys(format_influxdb_line_protocol(ALERT, "h", host="h1")) | {"timestamp"}
    assert set(main.ALERT_DEDUP_KEYS) <= tags


def test_event_dedup_keys_are_tags_not_fields():
    line = events.format_event_line_protocol(
        "m", host="h1", alert_id=7, event_seq=0, scenario="s", ip="203.0.113.7", meta={}, timestamp_ns=1
    )
    assert "host" in events.DEDUP_KEYS
    assert set(events.DEDUP_KEYS) <= _tag_keys(line) | {"timestamp"}


def test_control_characters_are_replaced_in_tags_and_string_fields():
    assert escape_influxdb_value("a\r\nb\x00c") == "a\\ \\ b\\ c"
    assert escape_influxdb_string_field("x\ny\rz") == '"x y z"'
    # Tab is valid in both and stays untouched.
    assert escape_influxdb_value("a\tb") == "a\tb"


def test_crowdsec_metadata_with_line_breaks_yields_single_lines():
    alert = {**ALERT, "as_name": "Evil\nNet", "scenario": "s\r\nx", "message": "GET /a\nb\r"}
    line = format_influxdb_line_protocol(alert, "h", host="h\n1")
    assert "\n" not in line and "\r" not in line

    meta = {"http_path": "/a\r\nb", "http_verb": "GET\n", "target_fqdn": "a\nb.example"}
    line = events.format_event_line_protocol(
        "m", host="h", alert_id=1, event_seq=0, scenario="s\n", ip="1.2.3.4", meta=meta, timestamp_ns=1
    )
    assert "\n" not in line and "\r" not in line
    assert 'http_path="/a  b"' in line


def test_naive_start_at_is_read_as_utc():
    line = format_influxdb_line_protocol({**ALERT, "start_at": "2026-01-02T03:04:05"}, "h")
    assert line.endswith(" 1767323045000000000")


def test_event_timestamp_prefers_meta_then_alert_start():
    assert events._event_timestamp_ns({"timestamp": "2026-01-02T03:04:05Z"}, "") == 1767323045000000000
    assert events._event_timestamp_ns({}, "2026-01-02T03:04:05Z") == 1767323045000000000


def test_event_without_any_timestamp_is_skipped_and_counted():
    alerts = [
        {"id": 1, "start_at": "2026-01-02T03:04:05Z", "events": [{"meta": []}]},
        {
            "id": 2,
            "start_at": "",
            "events": [{"meta": []}, {"meta": [{"key": "timestamp", "value": "2026-01-02T03:04:05Z"}]}],
        },
    ]
    lines, skipped = events.build_event_lines(alerts, "m", host="h")
    assert skipped == 1
    assert len(lines) == 2
    assert all(line.endswith(" 1767323045000000000") for line in lines)


def test_malformed_event_and_non_text_scenario_are_skipped_and_counted():
    alerts = [
        {"id": 1, "start_at": "2026-01-02T03:04:05Z", "scenario": "bad", "events": [{"meta": []}, "bad"]},
        {"id": 2, "start_at": "2026-01-02T03:04:05Z", "scenario": 42, "events": [{"meta": []}]},
    ]
    lines, skipped = events.build_event_lines(alerts, "m", host="h")
    assert len(lines) == 1
    assert skipped == 2


def test_non_list_event_details_are_skipped_and_counted():
    lines, skipped = events.build_event_lines(
        [{"id": 1, "start_at": "2026-01-02T03:04:05Z", "events": 3}], "m", host="h"
    )
    assert lines == []
    assert skipped == 1


def test_main_exits_1_but_exports_valid_events_when_one_has_no_timestamp(monkeypatch, sent_payloads):
    alerts = [
        {"id": 1, "start_at": "2026-01-02T03:04:05Z", "events": [{"meta": []}]},
        {"id": 2, "start_at": "", "events": [{"meta": []}]},
    ]
    monkeypatch.setattr(main, "get_crowdsec_alerts", lambda _since: alerts)
    assert main.export_events("host") is False
    assert len(sent_payloads) == 1
    assert sent_payloads[0].count("\n") == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        *[("latitude", v) for v in (None, "abc", "nan", float("inf"), 91)],
        *[("longitude", v) for v in (None, "abc", "nan", float("inf"), 181)],
    ],
)
def test_invalid_coordinate_is_left_out_of_the_line(field, value):
    line = format_influxdb_line_protocol({**ALERT, "latitude": 48.1, "longitude": 11.5, field: value}, "h")
    assert f"{field}=" not in line
    other = "longitude" if field == "latitude" else "latitude"
    assert f"{other}=" in line


@pytest.mark.parametrize("source", [None, ["203.0.113.7"], "203.0.113.7"])
def test_non_dict_source_does_not_crash_main_and_valid_data_is_exported(run_main, source):
    code, sent = run_main([{**GOOD, "source": source}, {**GOOD, "id": 2}])
    assert code == 0
    assert sent[0].count("\n") == 1


def test_non_dict_decision_is_skipped_and_the_run_exits_1(run_main):
    code, sent = run_main([GOOD, "oops", 7, None])
    assert code == 1
    assert len(sent) == 1
    assert sent[0].count("\n") == 0


@pytest.mark.parametrize(
    "bad_id",
    [{}, {"id": None}, {"id": "abc"}, {"id": 1.5}, {"id": True}, {"id": -3}, {"id": ""}],
    ids=["missing", "none", "text", "float", "bool", "negative", "empty"],
)
def test_alert_with_missing_or_invalid_id_is_skipped_without_substitute_id(run_main, bad_id):
    code, sent = run_main([{"start_at": "2026-01-02T03:04:05Z", **bad_id}, GOOD, {**GOOD, "id": "7"}])
    assert code == 1
    assert len(sent) == 1
    lines = sent[0].split("\n")
    assert len(lines) == 2
    assert not any("alert_id=0i" in line for line in lines)


@pytest.mark.parametrize("bad_id", [None, "abc", 1.5, True], ids=["missing", "text", "float", "bool"])
def test_event_alert_with_missing_or_invalid_id_is_skipped_and_counted(bad_id):
    alerts = [
        {"id": bad_id, "start_at": "2026-01-02T03:04:05Z", "events": [{"meta": []}]},
        {"id": 5, "start_at": "2026-01-02T03:04:05Z", "events": [{"meta": []}]},
    ]
    lines, skipped = events.build_event_lines(alerts, "m", host="h")
    assert skipped == 1
    assert len(lines) == 1
    assert "alert_id=5" in lines[0]


def test_missing_event_alert_id_makes_the_event_export_fail(monkeypatch, sent_payloads):
    alerts = [{"start_at": "2026-01-02T03:04:05Z", "events": [{"meta": []}]}, {**GOOD, "events": [{"meta": []}]}]
    monkeypatch.setattr(main, "get_crowdsec_alerts", lambda _since: alerts)
    assert main.export_events("host") is False
    assert len(sent_payloads) == 1


def test_missing_as_number_is_not_written_as_the_tag_none():
    line = format_influxdb_line_protocol({**ALERT, "as_number": None}, "h")
    assert "None" not in line
    assert "as_number=0" in line


@pytest.mark.parametrize(
    ("use_https", "validate", "warns"),
    [(False, True, True), (True, False, True), (True, True, False)],
    ids=["plain-http", "no-cert-validation", "verified-https"],
)
def test_insecure_transport_only_warns(monkeypatch, use_https, validate, warns):
    messages = []
    monkeypatch.setattr(main, "INFLUXDB_USE_HTTPS", use_https)
    monkeypatch.setattr(main, "INFLUXDB_VALIDATE_CERTIFICATE", validate)
    monkeypatch.setattr(main, "print_warning", messages.append)
    main.warn_insecure_transport()
    assert bool(messages) is warns


def _influx_main(monkeypatch, *, use_https, validate):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("main must not prompt or contact a third party")

    monkeypatch.setattr("builtins.input", forbidden)
    monkeypatch.setattr(requests.Session, "request", forbidden)
    monkeypatch.setattr(main, "METRICS_BACKEND", "influxdb2")
    monkeypatch.setattr(main, "INFLUXDB_USE_HTTPS", use_https)
    monkeypatch.setattr(main, "INFLUXDB_VALIDATE_CERTIFICATE", validate)


def _influx_run(monkeypatch):
    monkeypatch.setattr(main, "get_crowdsec_decisions", lambda: [GOOD])
    return main.main()


@pytest.mark.usefixtures("isolated_main")
@pytest.mark.parametrize(("use_https", "validate"), [(False, True), (True, False)])
def test_main_on_influxdb_neither_prompts_nor_contacts_a_third_party(monkeypatch, use_https, validate):
    sent = []
    _influx_main(monkeypatch, use_https=use_https, validate=validate)
    monkeypatch.setattr(main, "send_to_influxdb", lambda payload: sent.append(payload) or True)
    assert _influx_run(monkeypatch) == 0
    assert len(sent) == 1


@pytest.mark.usefixtures("isolated_main")
def test_tls_handshake_failure_on_the_write_still_exits_1(monkeypatch):
    class Session:
        def post(self, *_args, **_kwargs):
            raise requests.exceptions.SSLError("handshake rejected")

        def close(self):
            pass

    _influx_main(monkeypatch, use_https=True, validate=True)
    monkeypatch.setattr(influxdb, "create_secure_session", Session)
    assert _influx_run(monkeypatch) == 1
