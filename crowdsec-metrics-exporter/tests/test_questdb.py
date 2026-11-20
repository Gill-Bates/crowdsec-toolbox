#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/tests/test_questdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# QuestDB dedup gate, TTL handling and exit codes, against an in-memory fake of the /exec and /write endpoints.
import re

import httpx
import pytest

import main
from app import questdb

ALERT_TABLE = "crowdsec"
EVENT_TABLE = "crowdsec_events"
DECISION = {"id": 1, "source": {"ip": "203.0.113.7"}, "start_at": "2026-01-02T03:04:05Z", "scenario": "x/ssh"}
EVENT_ALERT = {"id": 1, "start_at": "2026-01-02T03:04:05Z", "events": [{"meta": []}]}


def _quoted(sql: str) -> list[str]:
    return re.findall(r'"([^"]+)"', sql)


class FakeQuestDB:
    """Just enough of QuestDB's /exec metadata and /write to exercise the gate."""

    def __init__(self):
        self.tables: dict[str, dict] = {}
        self.log: list[str] = []  # every SQL statement and "WRITE", in order
        self.writes: list[str] = []
        self.write_status = 204
        self.fail: dict[str, list[int]] = {}  # SQL needle -> statuses served in order (200 = pass)
        self.ignore_alter: set[str] = set()  # tables owned by someone else: ALTER has no effect
        self.alter_lag = 0  # tables() reports dedup=false for this many reads after an ALTER
        self.views: list[list] = []
        self.state_rows: list[list] = []  # rows served for the downsampling state lookup
        self.on_write = None  # called after each /write, to model the async refresh
        self.empty_show_create = False
        self.sleeps: list[float] = []  # recorded instead of sleeping
        self.logs: list[str] = []  # captured print_* output as "level: message"
        self.build_info: object = "Build Information: QuestDB 10.0.0, JDK 25, Commit Hash abc"

    def add_table(self, name, *, dedup=True, wal=True, keys=(), mode="UPSERT"):
        self.tables[name] = {"dedup": dedup, "wal": wal, "keys": list(keys), "mode": mode, "lag": 0}

    def count(self, needle: str) -> int:
        return sum(needle in sql for sql in self.log)

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/write":
            self.log.append("WRITE")
            self.writes.append(request.content.decode())
            if self.on_write:
                self.on_write()
            return httpx.Response(self.write_status)
        sql = request.url.params["query"]
        self.log.append(sql)
        for needle, statuses in self.fail.items():
            if needle in sql and statuses:
                status = statuses.pop(0)
                if status != 200:
                    return httpx.Response(status, text="injected failure")
        return httpx.Response(200, json={"dataset": self._rows(sql)})

    def _rows(self, sql: str) -> list:
        names = _quoted(sql)
        if sql.startswith("CREATE TABLE IF NOT EXISTS") and "UPSERT KEYS" in sql:
            self.tables.setdefault(
                names[0],
                {"dedup": True, "wal": True, "keys": names[1 + len(names[1:]) // 2 :], "mode": "UPSERT", "lag": 0},
            )
        elif sql.startswith("ALTER TABLE") and "DEDUP ENABLE" in sql:
            table = self.tables[names[0]]
            if names[0] not in self.ignore_alter:
                table.update(dedup=True, keys=names[1:], mode="UPSERT", lag=self.alter_lag)
        elif sql == "SELECT build()":
            return [] if self.build_info is None else [[self.build_info]]
        elif "FROM tables()" in sql:
            table = self.tables.get(re.search(r"table_name = '([^']+)'", sql).group(1))
            if table is None:
                return []
            dedup = table["dedup"] and table["lag"] <= 0
            table["lag"] -= 1
            return [[dedup, table["wal"]]] if "walEnabled" in sql else [[table["dedup"]]]
        elif "upsertKey" in sql:
            return [[key] for key in self.tables[re.search(r"table_columns\('([^']+)'\)", sql).group(1)]["keys"]]
        elif "FROM table_columns" in sql:
            return [[key] for key in ("timestamp", "host", "country", "scenario", "events_count")]
        elif sql.startswith("SHOW CREATE TABLE"):
            if self.empty_show_create:
                return []
            table = self.tables[names[0]]
            return [[f"CREATE TABLE ... DEDUP {table['mode']} KEYS({','.join(table['keys'])})"]]
        elif "materialized_views()" in sql:
            return self.views
        elif "LATEST ON timestamp PARTITION BY table_name" in sql:
            return self.state_rows
        return []


@pytest.fixture
def db(monkeypatch, isolated_main):
    fake = FakeQuestDB()
    real_client = httpx.Client
    monkeypatch.setattr(
        questdb.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(fake.handler), **kw)
    )
    monkeypatch.setattr(questdb.time, "sleep", fake.sleeps.append)
    monkeypatch.setattr(questdb, "_GATE_RESULTS", {})
    monkeypatch.setattr(questdb, "_VERSION_RESULT", {})
    monkeypatch.setattr(isolated_main, "METRICS_BACKEND", "questdb")
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "")
    # The logger writes to its own stream, so capture the calls instead.
    for module in (questdb, main):
        for level in ("info", "warning", "error"):
            name = f"print_{level}"
            monkeypatch.setattr(module, name, lambda message, _level=level: fake.logs.append(f"{_level}: {message}"))
    return fake


def _run_main(monkeypatch, *, events=None):
    monkeypatch.setattr(main, "get_crowdsec_decisions", lambda: [DECISION])
    monkeypatch.setattr(main, "EVENTS_ENABLED", events is not None)
    monkeypatch.setattr(main, "get_crowdsec_alerts", lambda _since: events)
    return main.main()


def _send_alerts(table=ALERT_TABLE, keys=main.ALERT_DEDUP_KEYS):
    return main._send("payload", table, keys, main.ALERT_ROLLUP)


def test_gate_creates_enables_and_verifies_dedup_before_the_first_write(db):
    assert _send_alerts() is main.SendStatus.OK
    assert db.writes == ["payload"]
    first_write = db.log.index("WRITE")
    before = db.log[:first_write]
    assert any(sql.startswith("CREATE TABLE IF NOT EXISTS") and "WAL DEDUP UPSERT KEYS" in sql for sql in before)
    assert any("DEDUP ENABLE UPSERT KEYS" in sql for sql in before)
    assert any("upsertKey = true" in sql for sql in before)
    assert db.tables[ALERT_TABLE]["keys"] == list(main.ALERT_DEDUP_KEYS)


@pytest.mark.parametrize(
    "owned_keys",
    [list(main.ALERT_DEDUP_KEYS[:-1]), ["timestamp", "something_else"], [*main.ALERT_DEDUP_KEYS, "extra"]],
    ids=["missing-key", "other-key-set", "extra-key"],
)
def test_foreign_key_set_blocks_the_write_and_exits_1(db, monkeypatch, owned_keys):
    db.add_table(ALERT_TABLE, keys=owned_keys)
    db.ignore_alter.add(ALERT_TABLE)
    assert _run_main(monkeypatch) == 1
    assert db.writes == []
    assert db.count("upsertKey = true") == questdb._VERIFY_POLLS


@pytest.mark.parametrize("flag", [{"mode": "SKIP"}, {"wal": False}], ids=["skip-mode", "not-wal"])
def test_wrong_dedup_mode_or_non_wal_table_blocks_the_write(db, flag):
    db.add_table(ALERT_TABLE, keys=main.ALERT_DEDUP_KEYS, **flag)
    db.ignore_alter.add(ALERT_TABLE)
    assert _send_alerts() is main.SendStatus.NOT_WRITTEN
    assert db.writes == []


@pytest.mark.parametrize("response", ["empty", "unreadable"])
def test_unverifiable_dedup_mode_blocks_the_write(db, response):
    if response == "empty":
        db.empty_show_create = True
    else:
        db.fail[f'SHOW CREATE TABLE "{ALERT_TABLE}"'] = [400]
    assert _send_alerts() is main.SendStatus.NOT_WRITTEN
    assert db.writes == []


@pytest.mark.parametrize("step", ["CREATE TABLE IF NOT EXISTS", "DEDUP ENABLE"])
def test_failing_ddl_blocks_the_write_and_a_4xx_is_not_retried(db, monkeypatch, step):
    needle = f'{step} "{ALERT_TABLE}"' if step.startswith("CREATE") else step
    db.fail[needle] = [400] * 10
    assert _run_main(monkeypatch) == 1
    assert db.writes == []
    assert db.count(needle) == 1


@pytest.mark.parametrize("status", [503, 429])
def test_transient_statuses_are_retried_with_bounded_backoff(db, status):
    create = f'CREATE TABLE IF NOT EXISTS "{ALERT_TABLE}"'
    db.fail[create] = [status, status, 200]
    assert _send_alerts() is main.SendStatus.OK
    assert db.count(create) == 3
    assert db.sleeps[:2] == list(questdb._RETRY_BACKOFF_SECONDS[:2])


def test_persistent_5xx_stops_after_the_retry_budget(db):
    db.fail["DEDUP ENABLE"] = [503] * 20
    assert _send_alerts() is main.SendStatus.NOT_WRITTEN
    assert db.count("DEDUP ENABLE") == len(questdb._RETRY_BACKOFF_SECONDS) + 1
    assert db.writes == []


def test_alter_that_becomes_visible_late_is_polled(db):
    db.alter_lag = 2
    db.add_table(ALERT_TABLE, dedup=False, keys=())
    assert _send_alerts() is main.SendStatus.OK
    assert db.sleeps.count(questdb._VERIFY_INTERVAL_SECONDS) == 2


def test_failed_ttl_keeps_the_data_exits_1_and_does_not_resend(db, monkeypatch):
    db.fail["SET TTL"] = [400] * 10
    assert _run_main(monkeypatch) == 1
    assert db.count("WRITE") == 1
    text = "\n".join(db.logs)
    assert "were written" in text and "retention/downsampling setup failed" in text
    assert "Failed to send" not in text


def test_failed_write_is_reported_as_not_stored(db, monkeypatch):
    db.write_status = 500
    assert _run_main(monkeypatch) == 1
    assert "nothing was stored" in "\n".join(db.logs)


def test_unready_rollup_keeps_the_full_raw_ttl_and_a_current_one_shortens_it(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    view = "crowdsec_rollup_1h_v1"
    db.views = [[view, ALERT_TABLE, "valid", 5, 9]]
    assert _send_alerts() is main.SendStatus.OK
    raw_ttl = [sql for sql in db.log if sql.startswith(f'ALTER TABLE "{ALERT_TABLE}" SET TTL')]
    assert raw_ttl == [f'ALTER TABLE "{ALERT_TABLE}" SET TTL 365 DAYS']

    db.log.clear()
    questdb._GATE_RESULTS.clear()
    db.views = [[view, ALERT_TABLE, "valid", 9, 9]]
    assert _send_alerts() is main.SendStatus.OK
    assert f'ALTER TABLE "{ALERT_TABLE}" SET TTL 30 DAYS' in db.log


def test_failed_rollup_ddl_keeps_full_raw_ttl_and_exits_1(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.fail["CREATE MATERIALIZED VIEW"] = [400]
    assert _run_main(monkeypatch) == 1
    assert len(db.writes) == 1
    assert f'ALTER TABLE "{ALERT_TABLE}" SET TTL 365 DAYS' in db.log


def test_failed_rollup_ttl_keeps_full_raw_ttl_and_exits_1(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.views = [["crowdsec_rollup_1h_v1", ALERT_TABLE, "valid", 9, 9]]
    db.fail["ALTER MATERIALIZED VIEW"] = [400]
    assert _run_main(monkeypatch) == 1
    assert len(db.writes) == 1
    assert f'ALTER TABLE "{ALERT_TABLE}" SET TTL 365 DAYS' in db.log


def _state_inserts(db):
    return [sql for sql in db.log if sql.startswith('INSERT INTO "_crowdsec_downsampling"')]


def test_state_is_published_only_after_the_raw_ttl_is_in_force(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.views = [["crowdsec_rollup_1h_v1", ALERT_TABLE, "valid", 9, 9]]
    db.fail[f'ALTER TABLE "{ALERT_TABLE}" SET TTL'] = [400]
    assert _send_alerts() is main.SendStatus.WRITTEN_UNCONFIGURED
    assert _state_inserts(db) == []

    questdb._GATE_RESULTS.clear()
    assert _send_alerts() is main.SendStatus.OK
    (insert,) = _state_inserts(db)
    assert "true, 30," in insert
    ttl_index = db.log.index(f'ALTER TABLE "{ALERT_TABLE}" SET TTL 30 DAYS')
    assert ttl_index < db.log.index(insert)


def test_a_refreshing_rollup_publishes_the_full_raw_window_not_an_active_profile(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.views = [["crowdsec_rollup_1h_v1", ALERT_TABLE, "valid", 5, 9]]
    assert _send_alerts() is main.SendStatus.OK
    (insert,) = _state_inserts(db)
    assert "'disabled'" in insert and "false, 365," in insert


def test_disabled_total_ttl_removes_an_existing_rollup_view_ttl(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    monkeypatch.setattr(questdb, "QUESTDB_TTL", None)
    monkeypatch.setattr(questdb, "QUESTDB_TTL_DAYS", None)
    db.views = [["crowdsec_rollup_1h_v1", ALERT_TABLE, "valid", 9, 9]]
    assert _send_alerts() is main.SendStatus.OK
    assert 'ALTER MATERIALIZED VIEW "crowdsec_rollup_1h_v1" SET TTL 0 HOURS' in db.log
    assert f'ALTER TABLE "{ALERT_TABLE}" SET TTL 30 DAYS' in db.log


def test_gate_runs_once_per_table_and_process(db):
    assert _send_alerts() is main.SendStatus.OK
    assert _send_alerts() is main.SendStatus.OK
    assert db.count(f'CREATE TABLE IF NOT EXISTS "{ALERT_TABLE}" (') == 1
    assert main._send("p", EVENT_TABLE, main.EVENT_DEDUP_KEYS) is main.SendStatus.OK
    assert db.count(f'CREATE TABLE IF NOT EXISTS "{EVENT_TABLE}"') == 1
    assert len(db.writes) == 3


def test_gate_rejects_a_cached_table_with_different_dedup_keys(db):
    assert _send_alerts() is main.SendStatus.OK
    assert main._send("event-payload", ALERT_TABLE, main.EVENT_DEDUP_KEYS) is main.SendStatus.NOT_WRITTEN
    assert db.writes == ["payload"]


def test_failing_alert_table_does_not_block_the_events_pass(db, monkeypatch):
    db.add_table(ALERT_TABLE, keys=["timestamp", "other"])
    db.ignore_alter.add(ALERT_TABLE)
    assert _run_main(monkeypatch, events=[EVENT_ALERT]) == 1
    assert len(db.writes) == 1
    assert "alert_id=1" in db.writes[0]
    assert db.tables[EVENT_TABLE]["keys"] == list(main.EVENT_DEDUP_KEYS)


def test_failing_events_gate_still_exports_the_alerts(db, monkeypatch):
    db.add_table(EVENT_TABLE, keys=["timestamp"])
    db.ignore_alter.add(EVENT_TABLE)
    assert _run_main(monkeypatch, events=[EVENT_ALERT]) == 1
    assert len(db.writes) == 1
    assert db.tables[ALERT_TABLE]["keys"] == list(main.ALERT_DEDUP_KEYS)


def test_enabling_dedup_on_an_existing_table_warns_about_stored_duplicates(db):
    db.add_table(ALERT_TABLE, dedup=False)
    assert _send_alerts() is main.SendStatus.OK
    assert any("metrics-backends.md" in line for line in db.logs)

    db.logs.clear()
    assert main._send("p", EVENT_TABLE, main.EVENT_DEDUP_KEYS) is main.SendStatus.OK
    assert not any("metrics-backends.md" in line for line in db.logs)


def test_influxdb_backend_never_touches_the_gate(db, monkeypatch):
    monkeypatch.setattr(main, "METRICS_BACKEND", "influxdb2")
    monkeypatch.setattr(main, "send_to_influxdb", lambda _payload: True)
    assert _send_alerts() is main.SendStatus.OK
    assert db.log == []


@pytest.mark.parametrize("info", ["Build Information: QuestDB 10.0.0, JDK 25", "QuestDB 10.2.1", "QuestDB 10.1"])
def test_questdb_10_is_accepted_and_main_exports(db, monkeypatch, info):
    db.build_info = info
    assert _run_main(monkeypatch) == 0
    assert db.log[0] == "SELECT build()"
    assert db.writes


@pytest.mark.parametrize(
    ("info", "found"),
    [
        ("Build Information: QuestDB 9.3.4, JDK 21", "9.3.4"),
        ("Build Information: QuestDB 11.0.0, JDK 25", "11.0.0"),
        ("garbage", "unknown"),
        (None, "unknown"),
    ],
)
def test_other_versions_exit_1_before_any_fetch_or_write(db, monkeypatch, info, found):
    db.build_info = info
    monkeypatch.setattr(main, "get_crowdsec_decisions", lambda: pytest.fail("LAPI must not be fetched"))
    assert main.main() == 1
    assert db.log == ["SELECT build()"]
    assert db.writes == []
    assert any(f"found {found}, required 10.x; nothing was written" in line for line in db.logs if "error" in line)


def test_unreachable_server_is_rejected_after_the_retry_budget(db, monkeypatch):
    db.fail["build()"] = [503] * 10
    monkeypatch.setattr(main, "get_crowdsec_decisions", lambda: pytest.fail("LAPI must not be fetched"))
    assert main.main() == 1
    assert db.count("build()") == len(questdb._RETRY_BACKOFF_SECONDS) + 1
    assert db.writes == []


def test_transient_version_error_is_retried(db, monkeypatch):
    db.fail["build()"] = [503, 200]
    assert _run_main(monkeypatch) == 0


def test_client_error_on_version_query_is_final(db):
    db.fail["build()"] = [401]
    assert questdb.ensure_questdb_version() is False
    assert db.count("build()") == 1


def test_influxdb_backend_skips_the_version_check(db, monkeypatch):
    monkeypatch.setattr(main, "METRICS_BACKEND", "influxdb2")
    monkeypatch.setattr(main, "send_to_influxdb", lambda _payload: True)
    assert _run_main(monkeypatch) == 0
    assert db.log == []


VIEW = "crowdsec_rollup_1h_v1"


def _raw_ttl(db):
    return [sql for sql in db.log if sql.startswith(f'ALTER TABLE "{ALERT_TABLE}" SET TTL')]


def test_a_refresh_that_lags_only_this_runs_own_write_still_shortens_the_raw_ttl(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.views = [[VIEW, ALERT_TABLE, "valid", 9, 9]]
    # The write commits txn 10; the async refresh has not started when the check runs.
    db.on_write = lambda: db.views.__setitem__(0, [VIEW, ALERT_TABLE, "refreshing", 9, 10])
    assert _send_alerts() is main.SendStatus.OK
    assert _raw_ttl(db) == [f'ALTER TABLE "{ALERT_TABLE}" SET TTL 30 DAYS']
    assert not any(line.startswith("warning:") for line in db.logs)


def test_a_view_behind_the_state_before_the_write_keeps_the_raw_ttl_and_only_informs(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.views = [[VIEW, ALERT_TABLE, "refreshing", 5, 9]]
    db.on_write = lambda: db.views.__setitem__(0, [VIEW, ALERT_TABLE, "refreshing", 5, 10])
    assert _send_alerts() is main.SendStatus.OK
    assert _raw_ttl(db) == [f'ALTER TABLE "{ALERT_TABLE}" SET TTL 365 DAYS']
    assert any(line.startswith("info:") and "still refreshing" in line for line in db.logs)
    assert not any(line.startswith("warning:") for line in db.logs)


def test_a_view_created_in_this_run_is_pending_at_info_level(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.on_write = lambda: setattr(db, "views", [[VIEW, ALERT_TABLE, "refreshing", 0, 1]])
    assert _send_alerts() is main.SendStatus.OK
    assert _raw_ttl(db) == [f'ALTER TABLE "{ALERT_TABLE}" SET TTL 365 DAYS']
    assert not any(line.startswith("warning:") for line in db.logs)


def test_an_invalid_view_still_warns_and_fails_the_run(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.views = [[VIEW, ALERT_TABLE, "invalid", 9, 9]]
    assert _send_alerts() is main.SendStatus.WRITTEN_UNCONFIGURED
    assert _raw_ttl(db) == [f'ALTER TABLE "{ALERT_TABLE}" SET TTL 365 DAYS']
    assert any(line.startswith("warning:") and "invalid" in line for line in db.logs)


def test_a_lag_that_persists_over_several_runs_escalates_to_a_warning(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    monkeypatch.setattr(questdb, "_PENDING_RUNS", {})
    db.views = [[VIEW, ALERT_TABLE, "refreshing", 5, 9]]
    for _ in range(questdb._PENDING_WARN_AFTER):
        db.logs.clear()
        assert _send_alerts() is main.SendStatus.OK
    assert any(line.startswith("warning:") and "consecutive runs" in line for line in db.logs)


def test_the_state_row_is_not_reinserted_when_quest_db_returns_null_for_empty_symbols(db, monkeypatch):
    monkeypatch.setattr(questdb, "QUESTDB_DOWNSAMPLING", "medium")
    db.views = [[VIEW, ALERT_TABLE, "valid", 5, 9]]  # unready: published as disabled with empty strings
    db.state_rows = [["disabled", 1, False, 0, None, None, None]]
    monkeypatch.setattr(questdb, "QUESTDB_TTL", None)
    monkeypatch.setattr(questdb, "QUESTDB_TTL_DAYS", None)
    assert _send_alerts() is main.SendStatus.OK
    assert _state_inserts(db) == []
