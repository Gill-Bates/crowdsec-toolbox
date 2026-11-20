#!/usr/bin/env python3
#
# crowdsec-metrics-exporter/tests/conftest.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# app.config reads the environment at import time and exits on invalid values,
# so drop every exporter setting before the first import and test against defaults.
import os

import pytest

_PREFIXES = ("LOG_LEVEL", "METRICS_BACKEND", "CROWDSEC_", "INFLUXDB_", "QUESTDB_", "EVENTS_", "HOSTNAME_OVERRIDE")

for _key in [key for key in os.environ if key.startswith(_PREFIXES)]:
    del os.environ[_key]


@pytest.fixture
def isolated_main(monkeypatch):
    """Return `main` with its process wiring stubbed; the test supplies the data sources."""
    import main

    monkeypatch.setattr(main, "register_handlers", lambda: None)
    monkeypatch.setattr(main, "get_hostname", lambda: "host")
    monkeypatch.setattr(main, "EVENTS_ENABLED", False)
    return main


@pytest.fixture
def sent_payloads(monkeypatch):
    """Collect every payload handed to `main._send`; each send reports OK."""
    import main

    sent = []
    monkeypatch.setattr(main, "_send", lambda payload, *_a: sent.append(payload) or main.SendStatus.OK)
    return sent


@pytest.fixture(autouse=True)
def no_release_lookup(monkeypatch):
    """Keep the startup banner offline; tests of the lookup itself patch it again."""
    from app import version_check

    monkeypatch.setattr(version_check, "fetch_latest_version", lambda: None)
