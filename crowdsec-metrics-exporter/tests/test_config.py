#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/tests/test_config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# Pure parsing and validation helpers of app.config; no network, no settings.env.
import pytest

from app import config


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("KEY=value", ("KEY", "value")),
        ("export KEY=value", ("KEY", "value")),
        ('KEY="quoted value"', ("KEY", "quoted value")),
        ("KEY='single'", ("KEY", "single")),
        ("KEY=value # inline comment", ("KEY", "value")),
        ("KEY=pass#word", ("KEY", "pass#word")),
        ("KEY=a=b", ("KEY", "a=b")),
    ],
)
def test_parse_env_line_accepts_dotenv_forms(line, expected):
    assert config._parse_env_line(line) == expected


@pytest.mark.parametrize("line", ["", "   ", "# comment", "no equals sign", "1BAD=x", "=value", "BAD KEY=x"])
def test_parse_env_line_ignores_non_assignments(line):
    assert config._parse_env_line(line) is None


def test_load_settings_env_override_controls_precedence(tmp_path, monkeypatch):
    env_file = tmp_path / "settings.env"
    env_file.write_text("EXPORTER_TEST_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("EXPORTER_TEST_KEY", "ambient")

    config.load_settings_env(env_file, override=False)
    assert config.os.environ["EXPORTER_TEST_KEY"] == "ambient"

    config.load_settings_env(env_file, override=True)
    assert config.os.environ["EXPORTER_TEST_KEY"] == "from-file"


def test_load_settings_env_missing_file_is_not_an_error(tmp_path):
    config.load_settings_env(tmp_path / "absent.env", override=True)


@pytest.mark.parametrize("raw", ["true", " TRUE ", "True"])
def test_env_bool_accepts_true_values(monkeypatch, raw):
    monkeypatch.setenv("EXPORTER_TEST_BOOL", raw)
    assert config._env_bool("EXPORTER_TEST_BOOL", False) is True


@pytest.mark.parametrize("raw", ["false", " FALSE ", "False"])
def test_env_bool_accepts_false_values(monkeypatch, raw):
    monkeypatch.setenv("EXPORTER_TEST_BOOL", raw)
    assert config._env_bool("EXPORTER_TEST_BOOL", True) is False


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_env_bool_uses_default_when_unset_or_empty(monkeypatch, raw):
    if raw is None:
        monkeypatch.delenv("EXPORTER_TEST_BOOL", raising=False)
    else:
        monkeypatch.setenv("EXPORTER_TEST_BOOL", raw)
    assert config._env_bool("EXPORTER_TEST_BOOL", True) is True


@pytest.mark.parametrize("raw", ["treu", "yes", "0"])
def test_env_bool_rejects_ambiguous_values(monkeypatch, raw):
    monkeypatch.setenv("EXPORTER_TEST_BOOL", raw)
    with pytest.raises(SystemExit, match="Config Error: EXPORTER_TEST_BOOL"):
        config._env_bool("EXPORTER_TEST_BOOL", True)


def test_questdb_event_table_must_differ_from_alert_table():
    with pytest.raises(SystemExit, match="EVENTS_TABLE must differ from QUESTDB_TABLE"):
        config._validate_questdb_event_table("questdb", True, "crowdsec", "crowdsec")


@pytest.mark.parametrize(
    ("backend", "enabled", "alert_table", "event_table"),
    [("questdb", False, "same", "same"), ("influxdb2", True, "same", "same"), ("questdb", True, "alerts", "events")],
)
def test_questdb_event_table_validation_allows_non_colliding_modes(backend, enabled, alert_table, event_table):
    config._validate_questdb_event_table(backend, enabled, alert_table, event_table)


@pytest.mark.parametrize(
    ("raw", "clause", "days"),
    [
        ("365d", "365 DAYS", 365),
        ("48h", "48 HOURS", 2),
        ("12w", "12 WEEKS", 84),
        ("6M", "6 MONTHS", 180),
        ("1y", "1 YEARS", 365),
    ],
)
def test_questdb_ttl_clause_and_days_agree(raw, clause, days):
    assert config.parse_questdb_ttl(raw) == clause
    assert config.questdb_ttl_days(raw) == days


@pytest.mark.parametrize("raw", ["", "0", "0d"])
def test_questdb_ttl_disabled_forms(raw):
    assert config.parse_questdb_ttl(raw) is None
    assert config.questdb_ttl_days(raw) is None


@pytest.mark.parametrize("raw", ["abc", "10", "10x", "-5d", "1.5d"])
def test_questdb_ttl_rejects_malformed_values(raw):
    with pytest.raises(ValueError, match="QUESTDB_TTL"):
        config.parse_questdb_ttl(raw)


def test_require_bare_host_accepts_hosts_and_ipv6_literals():
    assert config._require_bare_host("QUESTDB_URL", " db.example.org/ ") == "db.example.org"
    assert config._require_bare_host("QUESTDB_URL", "[::1]") == "[::1]"


@pytest.mark.parametrize("raw", ["https://db.example.org", "db.example.org/path", "db.example.org:9000"])
def test_require_bare_host_rejects_scheme_path_and_port(raw):
    with pytest.raises(SystemExit):
        config._require_bare_host("QUESTDB_URL", raw)


@pytest.mark.parametrize(("cast", "raw", "expected"), [(int, "45", 45), (float, "2.5", 2.5), (float, " 7 ", 7.0)])
def test_positive_timeout_accepts_finite_positive_values(monkeypatch, cast, raw, expected):
    monkeypatch.setenv("EXPORTER_TEST_TIMEOUT", raw)
    assert config._positive_timeout("EXPORTER_TEST_TIMEOUT", cast, 30) == expected


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_positive_timeout_unset_or_empty_uses_default(monkeypatch, raw):
    if raw is None:
        monkeypatch.delenv("EXPORTER_TEST_TIMEOUT", raising=False)
    else:
        monkeypatch.setenv("EXPORTER_TEST_TIMEOUT", raw)
    assert config._positive_timeout("EXPORTER_TEST_TIMEOUT", float, 30.0) == 30.0


@pytest.mark.parametrize(("cast", "raw"), [(int, "abc"), (int, "1.5"), (float, "abc"), (float, "1,5")])
def test_positive_timeout_unparsable_aborts_with_exit_1(monkeypatch, cast, raw):
    monkeypatch.setenv("EXPORTER_TEST_TIMEOUT", raw)
    with pytest.raises(SystemExit, match="Config Error: EXPORTER_TEST_TIMEOUT") as excinfo:
        config._positive_timeout("EXPORTER_TEST_TIMEOUT", cast, 30)
    # A string argument makes the interpreter exit with status 1.
    assert isinstance(excinfo.value.code, str)


@pytest.mark.parametrize(
    ("cast", "raw"),
    [(int, "0"), (int, "-5"), (float, "0"), (float, "-1.5"), (float, "nan"), (float, "inf"), (float, "-inf")],
)
def test_positive_timeout_rejects_unusable_values(monkeypatch, cast, raw):
    monkeypatch.setenv("EXPORTER_TEST_TIMEOUT", raw)
    with pytest.raises(SystemExit, match="EXPORTER_TEST_TIMEOUT"):
        config._positive_timeout("EXPORTER_TEST_TIMEOUT", cast, 30)
