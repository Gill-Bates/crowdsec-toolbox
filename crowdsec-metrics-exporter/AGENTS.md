<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-11-19 -->

# crowdsec-metrics-exporter (formerly crowdsec-influx)

## Purpose
Exports CrowdSec decisions as time series to InfluxDB 2.x or QuestDB
(selectable via `METRICS_BACKEND`). It reads the decision list from a local
CrowdSec instance through its **Local API over HTTP**, authenticating as a
registered machine (`POST /v1/watchers/login`, then `GET /v1/alerts`), and
writes the full current list on every run. It needs no Docker socket. It keeps
**no local state**: both backends deduplicate, so a repeated row is discarded
instead of appended.

This is the **less maintained tool** in this toolbox and deviates from the
conventions of its sibling `crowdsec-abuse-reporter`; read the warnings below before
changing anything here.

## Key Files
| File | Description |
|------|-------------|
| `main.py` | Entry point and whole orchestration: warn on insecure transport, fetch, map, verify dedup, send, declare TTL/downsampling, log a one-line result |
| `settings.env` | Runtime configuration — gitignored, never commit; `INFLUXDB_TOKEN` is stored in plaintext |
| `docker/settings.env.example` | The only tracked configuration template; a direct host run copies it to `settings.env` in the project root |
| `README.md` | Landing page: highlights, quick start, links to the full documentation (configuration and known limitations live in `docs/metrics-exporter/`) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `app/` | All application logic, including `influxdb.py` and `questdb.py` write backends (see `app/AGENTS.md`) |
| `docker/` | Container build for this tool, modeled on `../crowdsec-abuse-reporter/docker/` (see `docker/AGENTS.md`) |
| `tests/` | Offline pytest suite (see `tests/AGENTS.md`) |
| `grafana/` | QuestDB dashboards for alerts (`dashboard_questdb.json`) and per-event export (`dashboard_questdb_events.json`); the InfluxDB dashboard is still a `.todo` placeholder |

## For AI Agents

### Working In This Directory
- All third-party imports must be declared in the `default` group
  of this tool's own `pyproject.toml`. There is no root manifest - every
  component in the repository owns its own (see `../AGENTS.md`).
- **`app/influxdb.py` is on `requests`, `app/questdb.py` is on `httpx`.**
  Its sibling `crowdsec-abuse-reporter` uses `httpx` throughout; this tool is mixed on
  purpose. `app/influxdb.py` builds a hardened `TLS12Adapter` on top of a
  `urllib3` SSL context. Do not "modernize" it to httpx as a side effect of
  another change — that would drop the custom cipher/TLS-version handling.
- **`app/questdb.py`** sends the same InfluxDB Line Protocol payload
  (built by `app/influxdb.py`'s `format_influxdb_line_protocol()`) to
  QuestDB's ILP-over-HTTP `/write` endpoint, over an `httpx.Client` call —
  no TLS hardening, since QuestDB's endpoint has no equivalent cipher/version
  requirement. Do not point it at `TLS12Adapter`; that adapter is
  `requests`/`urllib3`-specific and targets the InfluxDB endpoint only.
- `main.py` selects the backend via `METRICS_BACKEND` (`influxdb2` default,
  or `questdb`; any other value aborts at config import) and calls `warn_insecure_transport()` for
  `influxdb2`: plain HTTP or `INFLUXDB_VALIDATE_CERTIFICATE=false` only warns,
  there is no third-party TLS check and no prompt.
- **Importing `app.config` has side effects.** It calls its own stdlib
  `load_settings_env(..., override=True)` at import time. It reads `settings.env` into module-level
  constants, including `INFLUXDB_TOKEN` in plaintext.
- The production venv (root `setup.conf`) deviates from its sibling: it lives at
  `/opt/jobs/crowdsec_influx` and is activated via `bin/activate`, not
  `.venv/bin/activate`. `setup.conf` holds no cron entry; the schedule shown in
  `docs/getting-started/installation.md` is an example, not the recorded
  production schedule.
- Comments, docstrings, and console messages are in English.

### Releasing
Releases run from a repo-wide `vX.Y.Z` tag (see `../AGENTS.md`), which also
requires this tool's `pyproject.toml` version to match. The image is published
as `crowdsec-toolbox:metrics-exporter-<version>` plus the moving
`crowdsec-toolbox:metrics-exporter-latest` tag.

### Testing Requirements
```bash
ruff check . && ruff format --check .   # from the repository root
cd crowdsec-metrics-exporter && python -m pytest
```
The offline suite in `tests/` covers config parsing and validation,
strict transport booleans, QuestDB table-name collisions, line-protocol
escaping, the dedup-key-is-a-tag invariant, record-id and coordinate
robustness, LAPI and event-detail completeness, QuestDB dedup and retention
gates against a fake `/exec` and `/write`, and the scheduling and exit-code
handling of `docker/entrypoint.sh`. `tests/conftest.py`
clears the exporter's environment variables before `app.config` is first
imported, because that module reads them at import time. A real run needs a
reachable CrowdSec instance and the configured metrics backend, so there is no
local smoke test; do not add tests that need the network.

### Common Patterns
- Idempotent full export: every run sends the complete current data set and
  the backend deduplicates. For QuestDB, `ensure_questdb_table()` is a gate that
  runs before the first write of each table per process: it creates the table
  with `DEDUP UPSERT KEYS`, re-declares them and verifies flags, key set and
  mode, and nothing is written when that fails (ILP creates tables
  append-only); for InfluxDB 2.x, series + timestamp already overwrite. The
  key sets live in `main.ALERT_DEDUP_KEYS` and `app.events.DEDUP_KEYS` — a
  column used as a key must be a **tag**, not a field.
- Optional QuestDB downsampling (`QUESTDB_DOWNSAMPLING=low|medium|high`) keeps
  the alert table's raw window short and the long-term history in a
  materialized rollup view. The rollup definitions sit next to the dedup keys
  (`main.ALERT_ROLLUP`, `app.events.ROLLUP`); the events table has none on
  purpose (see `app/AGENTS.md`). `apply_questdb_retention()` verifies the rollup, sets
  the raw TTL and only then publishes the state. The abuse reporter has identical copies
  (`test_shared_code.py`).
- QuestDB 10.x is the only supported release line; there is no fallback for
  older servers. `main()` calls `ensure_questdb_version()` (`SELECT build()` over
  `/exec`, major must be `10`) before the LAPI fetch and returns `1` with one
  ERROR line when it fails or cannot be read; nothing is written. It is skipped
  for `influxdb2`. The entrypoint loop keeps retrying every interval.
- Failure paths print via `logger.print_error()` and return early;
  `main()` returns the exit code (`0` success or nothing new, `1` QuestDB not 10.x, LAPI
  fetch, backend write, dedup gate or configured TTL failed, or the data is incomplete:
  fetch ceiling reached, alert/event without a usable timestamp or a valid id; valid records are still exported) and `__main__` passes it to
  `sys.exit()`.
- Console output is plain single-line log entries in the layout shared with the
  abuse reporter (`%Y-%m-%d %H:%M:%S UTC | LEVEL    | crowdsec_metrics | message`,
  see `app/logger.py` and `docs/reference/log-format.md`). The two no-data messages
  use `💤`; there are no summary tables. WARNING and above go to stderr.

### Known Deviation
`app.crowdsec.get_abuse_contact()` is a **stub** that returns the constant
`"abuse@example.com"` for every IP. Its value is written into every point
(InfluxDB and QuestDB) as `abuse_email`, so that field carries no real information. Do not build
anything on it; the real abuse-contact resolution lives in `crowdsec-abuse-reporter`.

## Dependencies

### Internal
- `app/AGENTS.md` — per-module rules for the application code
- `../crowdsec-abuse-reporter/` — the other CrowdSec consumer; unrelated code, different
  data path (its own LAPI client and credentials)

### External
- A CrowdSec instance whose Local API is reachable over HTTP, plus watcher
  credentials (no Docker CLI or socket is used)
- InfluxDB 2.x write endpoint, or a QuestDB 10.x instance with ILP-over-HTTP
  enabled
- `requests` + `urllib3` — `default` group
- `httpx` — declared in the `default` group, used only by
  `app/questdb.py`
- `gillbates-logging` — logging core, git URL pinned by tag in `[project].dependencies` (private repository)
- `settings.env` loading (`config.py`) uses only the stdlib; coloured console output (`logger.py`) comes from the external `gillbates-logging` package — no `python-dotenv` or `colorama` dependency

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
