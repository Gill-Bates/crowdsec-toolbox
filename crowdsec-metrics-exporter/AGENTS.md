<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-09-23 -->

# crowdsec-metrics-exporter (formerly crowdsec-influx)

## Purpose
Exports CrowdSec decisions as time series to InfluxDB 2.x or QuestDB
(selectable via `METRICS_BACKEND`). It reads the decision list from a local
CrowdSec instance through its **Local API over HTTP**, authenticating as a
registered machine (`POST /v1/watchers/login`, then `GET /v1/alerts`), and
writes the full current list on every run. It needs no Docker socket. It keeps **no local state**: both
backends deduplicate, so a repeated row is discarded instead of appended.

This is the **less maintained tool** in this toolbox and deviates from the
conventions of its sibling `crowdsec-abuse-reporter`; read the warnings below before
changing anything here.

## Key Files
| File | Description |
|------|-------------|
| `main.py` | Entry point and whole orchestration: verify TLS, fetch, map, send, declare TTL/dedup, log a one-line result |
| `setup.conf` | **Two lines only** — creates a venv and activates it. No `pip install`, no cron line |
| `settings.env` | Runtime configuration — gitignored, never commit; `INFLUXDB_TOKEN` is stored in plaintext |
| `docker/settings.env.example` | The only tracked configuration template; a direct host run copies it to `settings.env` in the project root |
| `README.md` | Operator documentation (setup, configuration, known limitations) |

Dependencies are the `default` group in this tool's own `pyproject.toml`; `setup.conf` creates the venv and installs them.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `app/` | All application logic, including `influxdb.py` and `questdb.py` write backends (see `app/AGENTS.md`) |
| `docker/` | Container build for this tool, modeled on `../crowdsec-abuse-reporter/docker/`; both are LAPI-over-HTTP consumers and neither needs the Docker socket (see `docker/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- All third-party imports must be declared in the `metrics-exporter` group
  of this tool's own `pyproject.toml`. There is no root manifest - every
  component in the repository owns its own (see `../AGENTS.md`).
- **`app/influxdb.py` is on `requests`, `app/questdb.py` is on `httpx`.**
  Its sibling `crowdsec-abuse-reporter` uses `httpx` throughout; this tool is mixed on
  purpose. `app/influxdb.py` builds a hardened `TLS12Adapter` on top of a
  `urllib3` SSL context. Do not "modernize" it to httpx as a side effect of
  another change — that would drop the custom cipher/TLS-version handling.
  `httpx` is declared in the `metrics-exporter` group solely for
  `questdb.py`.
- **`app/questdb.py`** sends the same InfluxDB Line Protocol payload
  (built by `app/influxdb.py`'s `format_influxdb_line_protocol()`) to
  QuestDB's ILP-over-HTTP `/write` endpoint, over an `httpx.Client` call —
  no TLS hardening, since QuestDB's endpoint has no equivalent cipher/version
  requirement. Do not point it at `TLS12Adapter`; that adapter is
  `requests`/`urllib3`-specific and targets the InfluxDB endpoint only.
- `main.py` selects the backend via `METRICS_BACKEND` (`influxdb2` default,
  or `questdb`; any other value aborts at config import) and only runs `verify_secure_connection()` (the
  `howsmyssl.com` TLS check) for `influxdb2`.
- **Importing `app.config` has side effects.** It calls its own stdlib
  `load_settings_env(..., override=True)` at import time. It reads `settings.env` into module-level
  constants, including `INFLUXDB_TOKEN` in plaintext.
- `setup.conf` deviates from its siblings: the venv lives at
  `/opt/jobs/crowdsec_influx` and is activated via `bin/activate`, not
  `.venv/bin/activate`, and no cron entry is documented. The deployment
  schedule for this project is not captured in the repo.
- Comments, docstrings, and console messages are in English; console output
  also uses emoji.

### Releasing
Releases run from a repo-wide `vX.Y.Z` tag (see `../AGENTS.md`), which also
requires this tool's `pyproject.toml` version to match. The image is published
as `crowdsec-toolbox:metrics-exporter-<version>` plus the moving
`crowdsec-toolbox:metrics-exporter-latest` tag.

### Testing Requirements
```bash
ruff check .                 # from the repository root
```
No test suite exists and none should be added without an explicit request. A
real run needs a reachable CrowdSec instance and the configured metrics
backend, so there is no meaningful local smoke test.

### Common Patterns
- Idempotent full export: every run sends the complete current data set and
  the backend deduplicates. For QuestDB, `ensure_questdb_dedup()` re-declares
  `DEDUP ENABLE UPSERT KEYS` after each successful write (ILP creates tables
  append-only); for InfluxDB 2.x, series + timestamp already overwrite. The
  key sets live in `main.ALERT_DEDUP_KEYS` and `app.events.DEDUP_KEYS` — a
  column used as a key must be a **tag**, not a field.
- Failure paths print via `logger.print_error()` and return early;
  `main()` returns the exit code (`0` success or nothing new, `1` TLS check,
  LAPI fetch or backend write failed) and `__main__` passes it to
  `sys.exit()`.
- Console output is plain log lines in the WireBuddy layout
  (`%Y-%m-%d %H:%M:%S | LEVEL | crowdsec_metrics | message`, see
  `app/logger.py`); no tables are printed.

### Known Deviation
`app.crowdsec.get_abuse_contact()` is a **stub** that returns the constant
`"abuse@example.com"` for every IP. Its value is written into every InfluxDB
point as `abuse_email`, so that field carries no real information. Do not build
anything on it; the real abuse-contact resolution lives in `crowdsec-abuse-reporter`.

## Dependencies

### Internal
- `app/AGENTS.md` — per-module rules for the application code
- `../crowdsec-abuse-reporter/` — the other CrowdSec consumer; unrelated code, different
  data path (its own LAPI client and credentials)

### External
- A CrowdSec instance whose Local API is reachable over HTTP, plus watcher
  container — this project shells out to `docker`
- InfluxDB 2.x write endpoint, or a QuestDB instance with ILP-over-HTTP
  enabled
- `requests` + `urllib3` — `metrics-exporter` group
- `httpx` — declared in the `metrics-exporter` group, used only by
  `app/questdb.py`
- `settings.env` loading (`config.py`) and coloured console output (`logger.py`) use
  only the stdlib — no `python-dotenv` or `colorama` dependency

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
