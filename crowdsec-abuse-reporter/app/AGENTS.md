<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-11-19 -->

# app

## Purpose
The complete application package. A run flows in one direction:
`main` orchestrates → `crowdsec` fetches decisions → `geoip` + `abusix` enrich
and resolve the abuse contact → `reportbody` renders the mail body and X-ARF
JSON → `abuse` delivers it over SMTP → `database` records the outcome.
With metrics enabled, `metrics` exports the finalized report outcome.
`config`, `logger`, `banner` and `version` are cross-cutting support modules.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package marker only |
| `main.py` | Orchestrator: fetch, filter, subnet-dedup, claim, send, finalize, summary, exit code |
| `crowdsec.py` | LAPI auth/fetch with bounded retry, decision derivation, context extraction, node-IP detection |
| `abusix.py` | Abuse-contact lookup via the Abusix DNS contact DB, backed by the SQLite contact cache |
| `abuse.py` | SMTP connection management, MIME assembly (multipart/report with feedback-report and `xarf.json` parts per the XARF e-mail transport guide), recipient validation, send retry |
| `reportbody.py` | Human-readable mail body (wrapped to 76 columns) and X-ARF v4.2.0 JSON (category/type mapping, evidence items), incl. secret redaction of context |
| `database.py` | SQLite schema, the claim/finalize idempotency protocol, permanent `abuse_alert_tombstones`, contact cache, reaper, retention, metrics outbox |
| `metrics.py` | Optional InfluxDB or QuestDB export of report outcomes; gates every QuestDB write on a 10.x version check (`ensure_questdb_version()`) and verified dedup (`ensure_questdb_table()`, `DEDUP_KEYS`) and applies retention after it (`apply_questdb_retention()`, optional `QUESTDB_DOWNSAMPLING` rollup `ROLLUP`, implemented by the external `gillbates-questdb-client` package); `flush_points()` is the durable path via the SQLite outbox |
| `geoip.py` | GeoLite2 City/ASN download (pinned hosts, atomic write, verify), readers, LRU lookups |
| `dns_utils.py` | Resolver selection and bounded hostname resolution shared by geoip/abusix |
| `config.py` | Loads `settings.env`, validates and coerces every env var, fails clean at startup |
| `logger.py` | Binds the external `gillbates-logging` package to the `crowdsec_abuse` source: tagged console output (`print_*`) plus `setup_logging()` for stdlib `logger.*` records |
| `heartbeat.py` | `python -m app.heartbeat` — LAPI liveness probe that refreshes `/data/api_heartbeat` |
| `banner.py` | ASCII startup banner, followed by the release notice from `version_check.py` |
| `version_check.py` | Startup lookup of the latest GitHub release of `Gill-Bates/crowdsec-toolbox` (httpx, 3 s timeout, every failure silent); shared copy |
| `version.py` | Reads `APP_VERSION` (build arg), falls back to the version in this tool's `pyproject.toml`, then `dev` |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
- `config.py` is import-time: it loads `settings.env` and calls `_fail_clean()`
  (SystemExit 1) on invalid configuration. Importing any module that pulls in
  `config` therefore needs a valid environment — tests patch module attributes
  rather than re-importing.
- Two logging styles coexist on purpose. `print_*` helpers in `logger.py` are
  user-facing console output; `logging.getLogger(__name__)` is used inside
  `crowdsec.py`, `geoip.py` and `reportbody.py` for API/debug traces.
  `setup_logging()` routes both through the same tagged format.
- `logger.split_recipients` imports from `app.abuse` lazily — `abuse` imports
  `logger`, so a module-level import would be circular. Keep it lazy.
- `database.py` holds one connection per thread in `threading.local()` with
  lazy schema init. Do not introduce a module-level shared connection and do not
  hold long write transactions.
- `geoip.py` downloads only from the hosts in `_ALLOWED_HOSTS`, validating
  scheme and host before **every** request including each redirect hop. That is
  an SSRF/egress guard — do not relax it to a post-hoc check of the final URL.
- `metrics.DEDUP_KEYS` makes repeated *writes* idempotent in QuestDB (InfluxDB
  does it inherently). It is **not** a substitute for the claim protocol in
  `database.py`: storage dedup cannot gate an outbound mail, since that
  decision precedes the write and needs an atomic compare-and-set. Every key
  except the designated `timestamp` must be a tag column of
  `format_report_line()`; QuestDB rejects a field key used for deduplication.
- That idempotency is also what the `metrics_outbox` table relies on.
  `metrics.flush_points()` attempts to spool points before network access and
  deletes spooled rows only after the backend acknowledges their batch. If the
  spool write fails, it tries one direct write; if that fails too, the points
  are lost. Pending rows are read in bounded batches, and a failed batch is
  retried as a whole because its timestamp is part of the line and dedup keys.
  Do not add per-point success tracking or bypass a successful spool.
- A deferred batch is a **warning**, not a failed run: nothing is lost, and
  failing would withhold the heartbeat and eventually flip the container
  unhealthy for a recoverable condition. Only a spool at ≥90% of
  `METRICS_OUTBOX_MAX_ROWS` sets `stats.metrics_errors` (exit 1), because the
  remaining capacity is small and a new batch may exceed the bound. Reaching
  that threshold does not itself mean points were lost. Points actually dropped
  by pruning are lost: `flush_points()` raises `MetricsPrunedError` (a
  `MetricsLostError`) after flushing the rest, and `main` counts one metrics error.
- QuestDB 10.x is the only supported release line, with no fallback for older
  servers. `ensure_questdb_version()` (copied from the exporter, never imported)
  reads `SELECT build()` and caches the verdict per process. `main._run()` calls
  it right after the banner when `METRICS_BACKEND=questdb`, so a mismatch, an
  unreachable server or an unparsable answer exits `1` before mail, SQLite or the
  outbox is touched; `write_points()` repeats it and raises `MetricsGateError`
  before writing. `flush_points()` keeps pending rows in its outbox. It never runs
  for `influxdb2` or `none`.
- QuestDB dedup is a hard precondition: `write_points()` runs
  `ensure_questdb_table()` (copied from the exporter, never imported) before the
  first write of the table per process and raises `MetricsGateError` without
  writing when it fails. `flush_points()` then keeps every outbox row and the run
  exits `1` at once through `stats.metrics_errors`; this is deliberately not an
  outage (warning, exit `0`) and not a `MetricsLostError`, since nothing is lost.
  `write_points()` returns a `WriteStatus`: `WRITTEN_TTL_FAILED` is truthy (rows
  are delivered and deleted, never resent) and surfaces as `MetricsTtlError` /
  exit `1`. Keep "data written" and "database configured" apart. The gate's SQL
  facts rest on QuestDB's documentation and the test fake, not a live server.
- `METRICS_ONLY` snapshots stay on the bare `write_points()` path on purpose
  (no spool: they run every `METRICS_INTERVAL` seconds and the next snapshot
  supersedes them), but they pass the same gate; a gate or TTL failure exits `1`.
- Untrusted input reaches mail headers and report bodies. `_validate_email()`
  and `sanitize_header_value()` in `main.py`, and `_is_sensitive_key()` /
  `_redact_context_value()` in `reportbody.py`, are security controls, not
  cosmetics.

### Testing Requirements
```bash
cd crowdsec-abuse-reporter && python -m pytest
```
`test_hardening.py` covers most app modules. `metrics.py` is covered in
`test_metrics.py`, `main.py` mainly in `test_main.py`, and `banner.py` in
`test_banner.py` (which also covers `version_check.py`); `version.py` has no dedicated test. `config.py` is covered by
`ConfigEnvLoaderTest` and `normalize_asn`, and `geoip.py` by
`DnsUtilsHardeningTest` and `ReviewFindingsTest`. A behavioural change to the claim/finalize protocol,
the reaper, GeoIP download flow, or report rendering needs a matching test
there.

### Common Patterns
- Extraction helpers cover known alternate shapes from CrowdSec: missing or
  non-dict source/context values fall back, and malformed decision-list items
  are skipped. Keep fallback claims tied to shapes the code handles.
- Returning `"unknown"` is the documented "cannot determine" sentinel.
- `_limit_value()` bounds only the strings, lists and dictionaries passed to it
  (`MAX_FIELD_LENGTH`, `MAX_LIST_ITEMS`, `MAX_DICT_ITEMS`). Apply it explicitly
  to untrusted free-form values before rendering them.
- LRU caches in `geoip.py` are invalidated by passing the `_cache_gen` counter
  as a cache-key argument; the counter is bumped when a DB file is replaced.

## Dependencies

### Internal
- `../tests/` — the hardening suite imports every module in this package
- `../docker/entrypoint.sh` — invokes `run.py` and `python -m app.heartbeat`
- `../run.py` — thin shim over `app.main:main`

### External
- `httpx` (`crowdsec.py`), `dns.resolver` (`abusix.py`, `dns_utils.py`),
  `geoip2` / `maxminddb` (`geoip.py`),
  stdlib `sqlite3` / `smtplib` / `email` / `fcntl`. `config.py` loads
  `settings.env` with its own stdlib parser (no third-party dependency).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->

- **Log layout.** `logger.py` renders `<UTC time> | LEVEL | <source> | message` on a single line (see `docs/reference/log-format.md`); WARNING and above go to stderr, colour only on a TTY with `NO_COLOR` unset. Do not add emoji or multi-line output.

### Code shared with the exporter
`banner.py` (`print_banner`), `version.py`, `version_check.py` and the LAPI login block of `crowdsec.py` are deliberate copies of the sibling tool's code, never imports. The QuestDB client (`/exec` retries, dedup gate, version check, TTL, rollup retention) is no longer copied: it comes from the external `gillbates-questdb-client` package and `app/questdb.py` / `app/metrics.py` only bind it to the tool's settings and log helpers. Change one copy only together with the other: `.github/scripts/test_shared_code.py` compares them by AST and fails on drift.
