#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/tests/test_crowdsec.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# LAPI fetch completeness (limit escalation, ceiling) and incomplete event details, over mocked HTTP.
import io
from unittest import mock

import httpx
import pytest

import main
from app import banner, crowdsec, version_check
from app.version import GIT_SHA, VERSION

BASE = "http://lapi.test/v1"


def _client(handler) -> httpx.Client:
    return httpx.Client(base_url=BASE, transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(crowdsec.time, "sleep", lambda _seconds: None)


def _patch_lapi(monkeypatch, handler, limit=2, ceiling=100):
    monkeypatch.setattr(crowdsec, "_build_lapi_client", lambda: _client(handler))
    monkeypatch.setattr(crowdsec, "_get_lapi_token", lambda _client: "tok")
    monkeypatch.setattr(crowdsec, "CROWDSEC_ALERT_LIMIT", limit)
    monkeypatch.setattr(crowdsec, "MAX_ALERT_FETCH_LIMIT", ceiling)


def test_full_response_escalates_limit_until_shorter_than_limit(monkeypatch):
    limits = []

    def handler(request):
        limit = int(request.url.params["limit"])
        limits.append(limit)
        return httpx.Response(200, json=[{"id": i} for i in range(min(limit, 25))])

    _patch_lapi(monkeypatch, handler, limit=2, ceiling=1000)
    assert len(crowdsec.get_crowdsec_decisions()) == 25
    assert limits == [2, 20, 200]


def test_transient_retry_emits_one_formatted_warning(monkeypatch, capsys):
    attempts = 0

    def handler(_request):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503, text="temporary")
        return httpx.Response(200, json=[])

    _patch_lapi(monkeypatch, handler, limit=2, ceiling=20)
    assert crowdsec.get_crowdsec_decisions() == []
    warnings = [line for line in capsys.readouterr().err.splitlines() if "LAPI request GET /alerts failed" in line]
    assert len(warnings) == 1
    assert " | WARNING  | crowdsec_metrics | " in warnings[0]
    assert "503 Service Unavailable" in warnings[0]


def _saturated_handler(limits):
    def handler(request):
        if not request.url.path.endswith("/alerts"):
            return httpx.Response(200, json={"id": 1, "events": [{"meta": []}]})
        limit = int(request.url.params["limit"])
        limits.append(limit)
        return httpx.Response(200, json=[{"id": i, "events": [{}]} for i in range(limit)])

    return handler


def test_saturated_ceiling_raises_incomplete_with_fetched_alerts(monkeypatch, capsys):
    limits = []
    _patch_lapi(monkeypatch, _saturated_handler(limits), limit=2, ceiling=20)
    with pytest.raises(crowdsec.CrowdSecIncompleteFetchError) as excinfo:
        crowdsec.get_crowdsec_decisions()
    assert len(excinfo.value.alerts) == 20
    assert limits == [2, 20]
    warnings = [line for line in capsys.readouterr().err.splitlines() if "maximum fetch limit" in line]
    assert len(warnings) == 1
    assert " | WARNING  | crowdsec_metrics | " in warnings[0]


def test_saturated_ceiling_event_fetch_still_returns_alerts_in_error(monkeypatch):
    _patch_lapi(monkeypatch, _saturated_handler([]), limit=2, ceiling=20)
    with pytest.raises(crowdsec.CrowdSecIncompleteFetchError) as excinfo:
        crowdsec.get_crowdsec_alerts("30m")
    assert len(excinfo.value.alerts) == 20


@pytest.fixture
def main_env(monkeypatch, isolated_main, sent_payloads):
    """Return a configurator that sets what the LAPI fetch yields; sent payloads land in the returned list."""

    def configure(*, decisions=None, error=None, events=False):
        def fake_decisions():
            if error is not None:
                raise error
            return decisions

        monkeypatch.setattr(isolated_main, "METRICS_BACKEND", "questdb")
        monkeypatch.setattr(isolated_main, "ensure_questdb_version", lambda: True)
        monkeypatch.setattr(isolated_main, "get_crowdsec_decisions", fake_decisions)
        monkeypatch.setattr(isolated_main, "EVENTS_ENABLED", events)
        return sent_payloads

    return configure


_DECISION = {"id": 1, "source": {"ip": "203.0.113.7"}, "start_at": "2026-01-02T03:04:05Z"}


def test_main_exports_partial_alerts_but_exits_1_at_ceiling(main_env):
    error = crowdsec.CrowdSecIncompleteFetchError("ceiling", [_DECISION])
    sent = main_env(error=error)
    assert main.main() == 1
    assert len(sent) == 1


def test_main_complete_run_exits_0(main_env):
    sent = main_env(decisions=[_DECISION])
    assert main.main() == 0
    assert len(sent) == 1


def test_main_banner_centers_metadata_and_separates_logs(main_env, capsys):
    main_env(decisions=[])
    assert main.main() == 0

    lines = capsys.readouterr().out.splitlines()
    title_index = next(i for i, line in enumerate(lines) if "crowdsec-metrics-exporter" in line)
    banner_block = lines[: title_index + 3]
    canvas_width = max(map(len, banner_block))
    assert len(lines[title_index]) == canvas_width
    assert all(len(line) == canvas_width for line in lines[:title_index])
    assert lines[title_index] == ">>> crowdsec-metrics-exporter | Metrics Export Tool for CrowdSec <<<".center(
        canvas_width
    )
    assert lines[title_index + 1] == f"v{VERSION} ({GIT_SHA[:7]}) | by Gill-Bates".center(canvas_width)
    assert lines[title_index + 2] == "Independent project; not affiliated with CrowdSec".center(canvas_width)
    assert lines[title_index + 3] == ""
    assert " | INFO     | crowdsec_metrics | Starting CrowdSec" in lines[title_index + 4]


def test_banner_uses_colors_only_for_tty_and_prints_build_metadata(monkeypatch):
    class Stream(io.StringIO):
        def __init__(self, tty):
            super().__init__()
            self.tty = tty

        def isatty(self):
            return self.tty

    tty = Stream(True)
    monkeypatch.setattr("sys.stdout", tty)
    banner.print_banner("1.2.3", "abcdef012345")
    colored = tty.getvalue()
    assert "\033[96m\033[1m" in colored
    assert "\033[97m" in colored
    assert "\033[90m" in colored
    assert ">>> crowdsec-metrics-exporter | Metrics Export Tool for CrowdSec <<<" in colored
    assert "v1.2.3 (abcdef0) | by Gill-Bates" in colored

    plain = Stream(False)
    monkeypatch.setattr("sys.stdout", plain)
    banner.print_banner("1.2.3", "abcdef012345")
    output = plain.getvalue()
    assert "\033[" not in output
    assert ">>> crowdsec-metrics-exporter | Metrics Export Tool for CrowdSec <<<" in output
    assert "v1.2.3 (abcdef0) | by Gill-Bates" in output


def test_banner_prints_release_notice_after_the_banner(monkeypatch, capsys):
    monkeypatch.setattr(version_check, "fetch_latest_version", lambda: "v1.10.0")
    banner.print_banner("1.9.0", "abcdef012345")
    out = capsys.readouterr().out
    assert out.endswith(f"A new version is available: v1.10.0 (running: v1.9.0) - {version_check.RELEASES_URL}\n\n")
    assert "Independent project" in out.split("A new version")[0]
    monkeypatch.setattr(version_check, "fetch_latest_version", lambda: "v1.9.0")
    banner.print_banner("1.9.0", "abcdef012345")
    assert capsys.readouterr().out.endswith("Your version is up to date.\n\n")


def test_release_lookup_is_silent_when_unavailable_or_dev(monkeypatch, capsys):
    banner.print_banner("1.9.0", "abcdef012345")
    assert capsys.readouterr().out.rstrip(" \n").endswith("not affiliated with CrowdSec")
    monkeypatch.setattr(version_check, "fetch_latest_version", lambda: pytest.fail("dev build must not fetch"))
    banner.print_banner("dev", "dev")
    assert capsys.readouterr().out.rstrip(" \n").endswith("not affiliated with CrowdSec")


def test_fetch_latest_version_survives_errors_and_bounds_the_wait(monkeypatch):
    seen = {}

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"tag_name": "v2.0.0"}

    monkeypatch.undo()
    monkeypatch.setattr(version_check.httpx, "get", lambda url, **kw: seen.update(kw, url=url) or Resp())
    assert version_check.fetch_latest_version() == "v2.0.0"
    assert seen["timeout"] <= 5
    assert seen["url"].endswith("/repos/Gill-Bates/crowdsec-toolbox/releases/latest")
    for error in (httpx.ConnectError("offline"), ValueError("bad json")):
        monkeypatch.setattr(version_check.httpx, "get", mock.Mock(side_effect=error))
        assert version_check.fetch_latest_version() is None


def test_event_ceiling_exports_partial_events_and_main_exits_1(monkeypatch, main_env):
    sent = main_env(decisions=[_DECISION], events=True)
    partial = [{"id": 1, "start_at": "2026-01-02T03:04:05Z", "events": [{"meta": []}]}]

    def fake_fetch(_since):
        raise crowdsec.CrowdSecIncompleteFetchError("ceiling", partial)

    monkeypatch.setattr(main, "get_crowdsec_alerts", fake_fetch)
    assert main.main() == 1
    assert len(sent) == 2


def _detail_handler(failing_ids):
    def handler(request):
        if request.url.path.endswith("/alerts"):
            return httpx.Response(200, json=[{"id": 1}, {"id": 2}])
        alert_id = int(request.url.path.rsplit("/", 1)[1])
        if alert_id in failing_ids:
            return httpx.Response(404)
        return httpx.Response(200, json={"id": alert_id, "events": [{"meta": []}]})

    return handler


def test_failed_event_detail_raises_incomplete_with_all_alerts(monkeypatch, capsys):
    _patch_lapi(monkeypatch, _detail_handler({2}), limit=100)
    with pytest.raises(crowdsec.CrowdSecIncompleteFetchError) as excinfo:
        crowdsec.get_crowdsec_alerts("30m")
    assert [alert["id"] for alert in excinfo.value.alerts] == [1, 2]
    assert excinfo.value.alerts[0]["events"]
    assert "events" not in excinfo.value.alerts[1]
    warnings = [line for line in capsys.readouterr().err.splitlines() if "Failed to fetch detail for alert 2" in line]
    assert len(warnings) == 1
    assert " | WARNING  | crowdsec_metrics | " in warnings[0]


def test_complete_event_details_return_normally(monkeypatch):
    _patch_lapi(monkeypatch, _detail_handler(set()), limit=100)
    alerts = crowdsec.get_crowdsec_alerts("30m")
    assert [alert["id"] for alert in alerts] == [1, 2]
    assert all(alert["events"] for alert in alerts)


@pytest.mark.parametrize(
    "detail",
    [
        {"id": 1, "events_count": 2},
        {"id": 1, "events_count": 2, "events": []},
        {"id": 1, "events_count": 2, "events": [{}, "malformed"]},
    ],
    ids=["missing-events", "empty-event-list", "malformed-event"],
)
def test_successful_but_incomplete_event_detail_fails_the_fetch(monkeypatch, detail):
    summary = {"id": 1, "events_count": 2}

    def handler(request):
        if request.url.path.endswith("/alerts"):
            return httpx.Response(200, json=[summary])
        return httpx.Response(200, json=detail)

    _patch_lapi(monkeypatch, handler, limit=100)
    with pytest.raises(crowdsec.CrowdSecIncompleteFetchError) as excinfo:
        crowdsec.get_crowdsec_alerts("30m")
    assert excinfo.value.alerts == [summary]
    assert "Event detail missing" in str(excinfo.value)


def test_capped_event_list_is_complete(monkeypatch):
    # CrowdSec stores fewer events than events_count (scenario cache_size).
    detail = {"id": 1, "events_count": 50, "events": [{"meta": []}] * 6}

    def handler(request):
        if request.url.path.endswith("/alerts"):
            return httpx.Response(200, json=[{"id": 1, "events_count": 50}])
        return httpx.Response(200, json=detail)

    _patch_lapi(monkeypatch, handler, limit=100)
    assert crowdsec.get_crowdsec_alerts("30m") == [detail]


def test_incomplete_events_are_still_written_but_run_fails(monkeypatch, sent_payloads):
    partial = [{"id": 1, "events": []}]

    def fake_fetch(_since):
        raise crowdsec.CrowdSecIncompleteFetchError("missing", partial)

    monkeypatch.setattr(main, "get_crowdsec_alerts", fake_fetch)
    monkeypatch.setattr(main, "build_event_lines", lambda *_a, **_k: (["line"], 0))
    assert main.export_events("host") is False
    assert sent_payloads == ["line"]
