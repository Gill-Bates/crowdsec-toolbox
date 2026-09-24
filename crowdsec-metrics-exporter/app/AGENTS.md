<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-09-23 -->

# app

## Purpose
The application package. `main.py` drives it: `config` loads
`settings.env` → `influxdb.verify_tls_configuration()` gates the run (only
for `METRICS_BACKEND=influxdb2`) → `crowdsec` fetches the alerts behind the
active decisions from the LAPI → `influxdb.format_influxdb_line_protocol()` formats line
protocol, shared by both backends → `main._send()` hands it to
`influxdb.send_to_influxdb()` or `questdb.send_to_questdb()`, selected by
`config.METRICS_BACKEND`, and for QuestDB re-declares TTL and dedup
afterwards. With `EVENTS_ENABLED`, a second pass fetches `GET /v1/alerts?since`
and `events.build_event_lines()` writes one point per event to
`EVENTS_TABLE`. `logger`, `kbinterrupt`, `version` and the banner are support
modules.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Empty package marker; contains only a comment, no re-exports. The `banner` string lives in `main.py` |
| `config.py` | Reads `settings.env` via a small stdlib parser and exposes module-level constants |
| `crowdsec.py` | `httpx` LAPI client: credentials resolution, `/watchers/login` token, bounded retry, `CrowdSecFetchError`, hostname, abuse-contact **stub**; `/alerts?has_active_decision` for the alert export and `/alerts?since` plus a per-alert `/alerts/{id}` fallback for the event export |
| `events.py` | Per-event export: flattens each alert's `events[].meta` list and builds line protocol for `EVENTS_TABLE`; reuses the escaping helpers from `influxdb.py` |
| `influxdb.py` | `TLS12Adapter`, hardened `requests` session, line-protocol escaping/formatting (shared with QuestDB) and send |
| `questdb.py` | `httpx.Client` POST of the same line protocol to QuestDB's ILP-over-HTTP `/write` endpoint; bearer token or basic auth, no TLS hardening |
| `logger.py` | Coloured console helpers (`print_info`/`success`/`warning`/`error`), gated by `config.LOG_LEVEL` |
| `version.py` | Reads `APP_VERSION` / `GIT_SHA` (build args) for the startup banner |
| `kbinterrupt.py` | SIGINT/SIGTERM handlers for a clean shutdown |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
- **`config.py` runs work at import time**: `load_settings_env(override=True)`,
  a small stdlib KEY=VALUE parser. Importing this module from a test or a
  helper script therefore reads and overrides process environment variables
  from `settings.env`; there is no lazy-loading entry point.
- `INFLUXDB_TOKEN` and every other setting are read directly from
  `settings.env` as plaintext. `settings.env` is gitignored; never commit it
  or copy its values elsewhere.
- `SENSITIVE_KEYS`-style filtering does not exist here: this project sends no
  mail, so there is no `SMTP_PASSWORD` handling to speak of.
- `influxdb.py` is `requests`-based on purpose (see `../AGENTS.md`). The TLS
  hardening — minimum version, cipher list, adapter — is the reason; do not
  swap the client library casually.
- `questdb.py` is `httpx`-based (a short-lived `httpx.Client` per write) and
  deliberately does not reuse `TLS12Adapter`/`create_secure_session()` from
  `influxdb.py`; that hardening is `requests`/`urllib3`-specific and targets
  the InfluxDB endpoint. `questdb.py` reuses only
  `format_influxdb_line_protocol()` / `escape_influxdb_value()` /
  `escape_influxdb_string_field()` from `influxdb.py`, since ILP is the same
  wire format for both backends. `httpx` is declared in the
  `metrics-exporter` group specifically for this module.
- QuestDB table/column creation is **not** handled here; QuestDB's
  ILP-over-HTTP `/write` auto-creates the table (`QUESTDB_TABLE`) and columns
  from the first write. There is no TTL or schema management, unlike
  fritzfluxdb's QuestDB writer.
- **No local state.** There is no persisted cursor and no local database
  file; the exporter re-sends everything each run and the backend
  deduplicates (series + timestamp overwrite for InfluxDB, `DEDUP ENABLE
  UPSERT KEYS` for QuestDB). Any new column that is meant to distinguish
  rows must therefore be a **tag** (part of the series identity and usable
  in QuestDB `UPSERT KEYS`), never a field.
- The event export is additive and gated by `EVENTS_ENABLED` (default off). A
  failure there must not roll back the alert export, but it still makes
  `main()` return `1` so the container health check sees the failed run.
- `events.py` keeps `http_path` as a string **field**, not a tag: scan paths
  are unbounded and QuestDB `SYMBOL` columns handle high cardinality badly.
  Row identity is carried by the `alert_id` + `event_seq` tags instead, so
  repeated paths are not collapsed. Empty tag values are dropped, since line
  protocol cannot express them.
- QuestDB retention and deduplication are declared from `questdb.py`
  (`ensure_questdb_ttl()`, `ensure_questdb_dedup()`) after each successful
  write, via the `/exec` SQL endpoint. Both are idempotent and only warn on
  failure, because the rows are already stored at that point.

### Testing Requirements
No test suite exists for this project and none should be added without an
explicit request. `ruff check .` from the repository root is the only automated
gate; a real run needs CrowdSec and the configured metrics backend reachable.

### Common Patterns
- Helpers report external failures to their callers.
  `get_crowdsec_decisions()` and `get_crowdsec_alerts()` distinguish failure
  (`None`) from an empty list (`[]`, a successful run).
- Subprocess calls go through `_run_command()`, which sets `timeout=30` and
  handles `TimeoutExpired`, `CalledProcessError` and `FileNotFoundError`
  separately.
- Alert dicts from the LAPI are read defensively with nested
  `.get("source", {}).get(...)` chains; the upstream shape is not guaranteed.
- Values are escaped with `escape_influxdb_value()` /
  `escape_influxdb_string_field()` before they enter line protocol.

## Dependencies

### Internal
- `../main.py` — the only caller; owns the whole control flow
- `../settings.env` — read by `config.py`

### External
- `requests` + `urllib3` (`influxdb.py`), `httpx` (`questdb.py`) — declared in the
  `default` group of `../pyproject.toml`; stdlib
  `socket` / `re`. `config.py` and `logger.py` use only the
  stdlib (no `python-dotenv` or `colorama`).
- A reachable CrowdSec Local API and valid watcher credentials

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
