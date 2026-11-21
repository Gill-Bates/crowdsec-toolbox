<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-11-18 -->

# app

## Purpose
The application package. `main.py` drives it: `config` loads
`settings.env` → `main.warn_insecure_transport()` warns about an unencrypted
or unverified InfluxDB connection → `crowdsec` fetches alerts from the LAPI →
`influxdb.format_influxdb_line_protocol()` formats the shared payload →
`main._send()` writes it to the selected backend. InfluxDB verifies TLS during
the write. For QuestDB, `ensure_questdb_version()` first requires a 10.x server, then
`ensure_questdb_table()` verifies UPSERT deduplication before the first write; TTL and optional downsampling are configured after the
write. With `EVENTS_ENABLED`, a second pass fetches `GET /v1/alerts?since`,
checks event-detail completeness and `events.build_event_lines()` writes one
point per event to `EVENTS_TABLE`. `logger`, `kbinterrupt`, `version` and the
banner are support modules.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Empty package marker; contains only a comment, no re-exports |
| `banner.py` | `print_banner()`, the startup banner (shared copy, see below) |
| `config.py` | Reads `settings.env` via a small stdlib parser and exposes module-level constants |
| `crowdsec.py` | `httpx` LAPI client: credentials resolution, `/watchers/login` token, bounded retry, `CrowdSecFetchError`, hostname, abuse-contact **stub**; `/alerts?has_active_decision` for the alert export and `/alerts?since` plus a per-alert `/alerts/{id}` fallback for the event export |
| `events.py` | Per-event export: flattens each alert's `events[].meta` list and builds line protocol for `EVENTS_TABLE`; reuses the escaping helpers from `influxdb.py` |
| `influxdb.py` | `TLS12Adapter`, hardened `requests` session, line-protocol escaping/formatting (shared with QuestDB) and send |
| `questdb.py` | `httpx.Client` POST of the same line protocol to QuestDB's ILP-over-HTTP `/write` endpoint; bearer token or basic auth, no TLS hardening |
| `logger.py` | Binds the external `gillbates-logging` package to the `crowdsec_metrics` source: console helpers (`print_info`/`success`/`warning`/`error`), root logging configured on import from `config.LOG_LEVEL` |
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
  wire format for both backends.
- `ensure_questdb_table()` creates each QuestDB table with its dedup keys before
  the first write. ILP-over-HTTP `/write` auto-creates additional columns.
- **No local state.** There is no persisted cursor and no local database
  file; the exporter re-sends everything each run and the backend
  deduplicates (series + timestamp overwrite for InfluxDB, `DEDUP ENABLE
  UPSERT KEYS` for QuestDB). Any new column that is meant to distinguish
  rows must therefore be a **tag** (part of the series identity and usable
  in QuestDB `UPSERT KEYS`), never a field.
- The event export is additive and gated by `EVENTS_ENABLED` (default off). A
  failure there must not roll back the alert export, but it still makes
  `main()` return `1` so the container health check sees the failed run.
- Event rows use `timestamp`, `host`, `alert_id` and `event_seq` as QuestDB
  upsert keys. `host` prevents same-timestamp event IDs from separate CrowdSec
  instances from replacing each other in a shared events table.
- `events.py` keeps `http_path` as a string **field**, not a tag: scan paths
  are unbounded and QuestDB `SYMBOL` columns handle high cardinality badly.
  Row identity also includes `host`, so repeated paths are not collapsed and
  same-ID events from different instances stay separate. Empty tag values are
  dropped, since line protocol cannot express them.
- QuestDB retention, deduplication and downsampling are declared from
  `questdb.py` (`ensure_questdb_table()`, `ensure_questdb_ttl()`,
  `ensure_questdb_downsampling()`, `apply_questdb_retention()`: rollup, raw TTL, then state) via the `/exec` SQL endpoint. The table gate
  runs before the first write and a failure blocks it (cached per table and key
  set per process; only transport errors, 5xx and 429 are retried). TTL and
  downsampling run after the write, which is already stored. Failed retention
  or rollup setup makes `main()` exit `1` without resending. A rollup that is
  still refreshing keeps the full raw TTL and does not fail the run.
- `ensure_questdb_downsampling()` returns a `DownsamplingResult` containing the
  raw table TTL and setup status. `apply_questdb_retention()` applies that raw TTL; a failed
  view TTL or rollup verification returns the full `QUESTDB_TTL`, so the raw
  window is not shortened until the rollup view is valid and caught up.
- A `RollupSpec`'s `dimensions` must stay a subset of that table's dedup keys:
  QuestDB rejects a materialized view whose non-aggregate columns are not. That
  is why the events table has `ROLLUP = None` — its keys are `timestamp`,
  `host`, `alert_id` and `event_seq`.

### Testing Requirements
Offline tests live in `../tests/`; do not add tests that need the network.
`ruff check .`, `ruff format --check .` and the offline suite in `../tests/` are the only automated
gate; a real run needs CrowdSec and the configured metrics backend reachable.

### Common Patterns
- Helpers report external failures to their callers.
  `get_crowdsec_decisions()` and `get_crowdsec_alerts()` raise
  `CrowdSecFetchError` on failure; an empty list is a successful run.
  `get_crowdsec_alerts()` raises `CrowdSecIncompleteFetchError` (carrying the
  alerts retrieved so far) when the fetch ceiling is hit with a full response or
  event details are missing; callers export that data, then return `1`.
  `format_influxdb_line_protocol()` returns `None` and `build_event_lines()`
  counts a skipped event when no timestamp is usable; the current time is never
  substituted, and `main()` rates the run `1`.
- LAPI calls go through `_request_with_retry()` in `crowdsec.py` (bounded retry
  on transport errors); no subprocess or Docker CLI is involved.
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
  `socket` / `re`. `config.py` uses only the
  stdlib; `logger.py` needs only the external `gillbates-logging` package (stdlib-only itself) (no `python-dotenv` or `colorama`).
- A reachable CrowdSec Local API and valid watcher credentials

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->

- **Log layout.** `logger.py` renders `<UTC time> | LEVEL | <source> | message` on a single line (see `docs/reference/log-format.md`); WARNING and above go to stderr, colour only on a TTY with `NO_COLOR` unset. The two no-data messages use `💤`; do not add multi-line output or summary tables.

### Code shared with the abuse reporter
`banner.py` (`print_banner`), `version.py` and the LAPI login block of `crowdsec.py` are deliberate copies of the sibling tool's code, never imports. The QuestDB client (`/exec` retries, dedup gate, version check, TTL, rollup retention) is no longer copied: it comes from the external `gillbates-questdb-client` package and `app/questdb.py` / `app/metrics.py` only bind it to the tool's settings and log helpers. Change one copy only together with the other: `.github/scripts/test_shared_code.py` compares them by AST and fails on drift.
