#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/tests/test_entrypoint.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# docker/entrypoint.sh scheduling variables and run_once exit handling, run through bash with a stub python.
import contextlib
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

import pytest

_ENTRYPOINT = Path(__file__).resolve().parents[1] / "docker" / "entrypoint.sh"
_DOCKERFILE = _ENTRYPOINT.parent / "Dockerfile"
_STATE_DIR = (Path(os.sep) / "tmp" / "state").as_posix()
_HEALTH_LIMITS_FILE = (Path(os.sep) / "tmp" / "health_limits").as_posix()
_STATE_LINE = f"readonly STATE_DIR={_STATE_DIR}"
_HEALTH_LIMITS_LINE = f"readonly HEALTH_LIMITS_FILE={_HEALTH_LIMITS_FILE}"
_TIMEOUT_SECONDS = 20


@pytest.fixture
def sandbox(tmp_path):
    """Copy of the entrypoint with a private state dir and a stub `python` on PATH."""
    text = _ENTRYPOINT.read_text(encoding="utf-8")
    assert _STATE_LINE in text
    assert _HEALTH_LIMITS_LINE in text
    state = tmp_path / "state"
    script = tmp_path / "entrypoint.sh"
    text = text.replace(_STATE_LINE, f'readonly STATE_DIR="{state}"')
    text = text.replace(_HEALTH_LIMITS_LINE, f'readonly HEALTH_LIMITS_FILE="{state / "health_limits"}"')
    script.write_text(text, encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "python"
    stub.write_text(
        '#!/bin/sh\n[ -n "${STUB_RUN_SECONDS:-}" ] && "$REAL_SLEEP" "$STUB_RUN_SECONDS"\nexit "${STUB_RC:-0}"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    # Without STUB_FAST_SLEEP the real sleep runs; with it every sleep returns at once.
    sleep_stub = bin_dir / "sleep"
    sleep_stub.write_text(
        '#!/bin/sh\n[ -n "${STUB_FAST_SLEEP:-}" ] && exit 0\nexec "$REAL_SLEEP" "$@"\n', encoding="utf-8"
    )
    sleep_stub.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "REAL_SLEEP": shutil.which("sleep")}
    for key in (
        "RUN_ONCE",
        "RUN_EVERY_HOUR",
        "RUN_INTERVAL",
        "EVENTS_ENABLED",
        "EVENTS_SINCE",
        "HEALTHCHECK_MAX_AGE_SECONDS",
    ):
        env.pop(key, None)
    return script, state, env


def _run(sandbox, **overrides):
    script, _state, env = sandbox
    return subprocess.run(
        ["bash", str(script)],
        env={**env, **overrides},
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )


def _periodic_output(sandbox, stop_marker, **overrides):
    """Start the periodic loop, collect stdout up to a marker line, then stop the loop.

    A watchdog kills the process group on timeout, so a silent script cannot hang the suite.
    """
    script, _state, env = sandbox
    proc = subprocess.Popen(
        ["bash", str(script)],
        env={**env, **overrides},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    def kill_group():
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)

    watchdog = threading.Timer(_TIMEOUT_SECONDS, kill_group)
    watchdog.start()
    lines = []
    try:
        for line in proc.stdout:
            lines.append(line.rstrip("\n"))
            if stop_marker in line:
                break
    finally:
        watchdog.cancel()
        kill_group()
        proc.wait()
        stderr = proc.stderr.read()
        proc.stdout.close()
        proc.stderr.close()
    return lines, stderr


def _docker_healthcheck(sandbox, **overrides):
    _script, state, env = sandbox
    dockerfile = _DOCKERFILE.read_text(encoding="utf-8")
    match = re.search(r"HEALTHCHECK .*?CMD sh -ec '(.*?)'\n", dockerfile, re.DOTALL)
    assert match
    command = match.group(1).replace("\\\n", "\n")
    command = command.replace(_STATE_DIR, str(state))
    command = command.replace(_HEALTH_LIMITS_FILE, str(state / "health_limits"))
    shell = shutil.which("dash") or "sh"
    return subprocess.run(
        [shell, "-ec", command],
        env={**env, **overrides},
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )


@pytest.mark.parametrize("value", ["08", "008", "8"])
def test_run_every_hour_leading_zeros_are_decimal(sandbox, value):
    lines, stderr = _periodic_output(sandbox, "Periodic mode", RUN_EVERY_HOUR=value)
    assert "value too great" not in stderr
    assert lines[-1].endswith("(28800s)")


_PREFIX = r"[\d-]+ [\d:]+ UTC \| INFO     \| entrypoint \| "
_SCHEDULING = _PREFIX + r"Scheduling: max jitter (\d+)s \(interval/10, capped at 300s\), start offset (\d+)s"


@pytest.mark.parametrize(
    ("interval", "max_jitter"),
    [("3600", 300), ("3000", 300), ("60", 6), ("10", 1), ("9", 0), ("1", 0), ("08", 0)],
)
def test_jitter_is_derived_from_the_interval(sandbox, interval, max_jitter):
    lines, stderr = _periodic_output(sandbox, "Scheduling:", RUN_INTERVAL=interval, STUB_FAST_SLEEP="1")
    assert stderr == ""
    match = re.fullmatch(_SCHEDULING, lines[-1])
    assert match
    assert int(match.group(1)) == max_jitter
    assert 0 <= int(match.group(2)) <= max_jitter


def test_every_hour_interval_caps_jitter_and_health_window(sandbox):
    lines, _stderr = _periodic_output(sandbox, "Scheduling:", RUN_EVERY_HOUR="6", STUB_FAST_SLEEP="1")
    assert re.fullmatch(_SCHEDULING, lines[-1]).group(1) == "300"
    assert (sandbox[1] / "health_limits").read_text().strip() == "22200"

    heartbeat = sandbox[1] / "heartbeat"
    heartbeat.touch()
    timestamp = time.time()
    os.utime(heartbeat, (timestamp - 22000, timestamp - 22000))
    assert _docker_healthcheck(sandbox, RUN_EVERY_HOUR="6").returncode == 0
    os.utime(heartbeat, (timestamp - 22400, timestamp - 22400))
    assert _docker_healthcheck(sandbox, RUN_EVERY_HOUR="6").returncode == 1

    result = _run(sandbox, RUN_EVERY_HOUR="1", HEALTHCHECK_MAX_AGE_SECONDS="900")
    assert result.returncode == 1
    assert "HEALTHCHECK_MAX_AGE_SECONDS must be at least 4200s" in result.stderr
    assert not (sandbox[1] / "health_limits").exists()


def test_next_run_stays_within_slot_and_jitter(sandbox):
    lines, stderr = _periodic_output(sandbox, "Run complete", RUN_INTERVAL="3600", STUB_FAST_SLEEP="1")
    assert stderr == ""
    match = re.fullmatch(_PREFIX + r"Run complete — jitter (\d+)s, sleeping (\d+)s, next run at .+ UTC", lines[-1])
    assert match
    jitter, wait = int(match.group(1)), int(match.group(2))
    assert 0 <= jitter <= 300
    # The grid slot is one interval after the start; the run itself took about no time.
    assert 3600 + jitter - 5 <= wait <= 3600 + jitter


def test_overrunning_run_skips_missed_slots(sandbox):
    # A 3 s run against a 1 s grid misses two slots; the loop must not catch up.
    lines, stderr = _periodic_output(sandbox, "Run complete", RUN_INTERVAL="1", STUB_RUN_SECONDS="3")
    assert re.search(r"run overran the 1s interval; skipping [1-9]\d* missed slot\(s\)", stderr)
    assert re.search(r"sleeping [01]s", lines[-1])


@pytest.mark.parametrize(
    ("since", "warns"),
    [("30m", True), ("2h", True), ("30s", True), ("7h", False), ("1d", False), ("bad", False)],
)
def test_events_since_shorter_than_interval_plus_jitter_warns(sandbox, since, warns):
    # 6 h interval: jitter 300 s, so EVENTS_SINCE must exceed 21900 s (about 6.1 h).
    _lines, stderr = _periodic_output(
        sandbox, "Scheduling:", RUN_EVERY_HOUR="6", EVENTS_ENABLED="true", EVENTS_SINCE=since, STUB_FAST_SLEEP="1"
    )
    assert ("EVENTS_SINCE=" in stderr) is warns


def test_events_since_is_not_checked_when_events_are_disabled(sandbox):
    _lines, stderr = _periodic_output(
        sandbox, "Scheduling:", RUN_EVERY_HOUR="6", EVENTS_ENABLED="false", EVENTS_SINCE="1m", STUB_FAST_SLEEP="1"
    )
    assert stderr == ""


def test_run_interval_leading_zero_is_unaffected(sandbox):
    lines, stderr = _periodic_output(sandbox, "Scheduling:", RUN_INTERVAL="08")
    assert stderr == ""
    assert any(line.endswith("running every 08s") for line in lines)
    assert (sandbox[1] / "health_limits").read_text().strip() == "900"


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"RUN_EVERY_HOUR": "0"}, "RUN_EVERY_HOUR must be greater than 0."),
        ({"RUN_EVERY_HOUR": "00"}, "RUN_EVERY_HOUR must be greater than 0."),
        ({"RUN_EVERY_HOUR": "abc"}, "RUN_EVERY_HOUR must be a positive integer."),
        ({"RUN_INTERVAL": "0"}, "RUN_INTERVAL must be greater than 0."),
        ({"RUN_INTERVAL": "abc"}, "RUN_INTERVAL must be a positive integer number of seconds."),
    ],
)
def test_invalid_scheduling_values_are_rejected(sandbox, env, message):
    result = _run(sandbox, **env)
    assert result.returncode == 1
    assert result.stderr.strip().endswith(f"| ERROR    | entrypoint | {message}")
    assert result.stdout == ""


_BOUNDS = {"RUN_EVERY_HOUR": 8760, "RUN_INTERVAL": 31536000}


@pytest.mark.parametrize("name", list(_BOUNDS))
@pytest.mark.parametrize("offset", ["20digits", 1])
def test_oversized_scheduling_values_are_rejected(sandbox, name, offset):
    value = "9" * 20 if offset == "20digits" else str(_BOUNDS[name] + offset)
    result = _run(sandbox, **{name: value})
    assert result.returncode == 1
    assert result.stderr.strip().endswith(f"| ERROR    | entrypoint | {name} must be at most {_BOUNDS[name]}.")
    assert result.stdout == ""
    assert not (sandbox[1] / "heartbeat").exists()


@pytest.mark.parametrize("name", list(_BOUNDS))
def test_maximum_scheduling_values_are_accepted(sandbox, name):
    lines, stderr = _periodic_output(sandbox, "Scheduling:", **{name: str(_BOUNDS[name])})
    assert stderr == ""
    assert any("Periodic mode" in line for line in lines)
    assert (sandbox[1] / "health_limits").read_text().strip() == "31536600"


def test_run_once_success_touches_heartbeat(sandbox):
    result = _run(sandbox, RUN_ONCE="true")
    assert result.returncode == 0
    assert (sandbox[1] / "heartbeat").is_file()
    assert not (sandbox[1] / "health_limits").exists()
    assert _docker_healthcheck(sandbox, RUN_ONCE="true").returncode == 0


@pytest.mark.parametrize("rc", [1, 7])
def test_run_once_propagates_exit_code_without_heartbeat(sandbox, rc):
    result = _run(sandbox, RUN_ONCE="true", STUB_RC=str(rc))
    assert result.returncode == rc
    assert f"rc={rc}" in result.stderr
    assert not (sandbox[1] / "heartbeat").exists()
