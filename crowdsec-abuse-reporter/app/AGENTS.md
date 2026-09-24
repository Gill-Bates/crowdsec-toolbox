<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-09-23 -->

# app

## Purpose
The complete application package. A run flows in one direction:
`main` orchestrates → `crowdsec` fetches decisions → `geoip` + `abusix` enrich
and resolve the abuse contact → `reportbody` renders the mail body and X-ARF
attachment → `abuse` delivers it over SMTP → `database` records the outcome.
With metrics enabled, `metrics` exports the finalized report outcome.
`config`, `logger`, `banner` and `version` are cross-cutting support modules.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package marker only |
| `main.py` | Orchestrator: fetch, filter, subnet-dedup, claim, send, finalize, summary, exit code |
| `crowdsec.py` | LAPI auth/fetch with bounded retry, decision derivation, context extraction, node-IP detection |
| `abusix.py` | Abuse-contact lookup via the Abusix DNS contact DB, backed by the SQLite contact cache |
| `abuse.py` | SMTP connection management, MIME/X-ARF assembly, recipient validation, send retry |
| `reportbody.py` | Human-readable mail body and X-ARF v4 JSON, incl. secret redaction of context |
| `database.py` | SQLite schema, the claim/finalize idempotency protocol, contact cache, reaper, retention, metrics outbox |
| `metrics.py` | Optional InfluxDB or QuestDB export of report outcomes; declares QuestDB TTL and dedup (`DEDUP_KEYS`) after each write; `flush_points()` is the durable path via the SQLite outbox |
| `geoip.py` | GeoLite2 City/ASN download (pinned hosts, atomic write, verify), readers, LRU lookups |
| `dns_utils.py` | Resolver selection and bounded hostname resolution shared by geoip/abusix |
| `config.py` | Loads `settings.env`, validates and coerces every env var, fails clean at startup |
| `logger.py` | Tagged timestamped console output plus `setup_logging()` for stdlib `logger.*` records |
| `heartbeat.py` | `python -m app.heartbeat` — LAPI liveness probe that refreshes `/data/api_heartbeat` |
| `banner.py` | ASCII startup banner |
| `version.py` | Reads `APP_VERSION` (build arg), defaults to `1.0.0` |

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
  must be a tag column of `format_report_line()`; a field key would be
  rejected by QuestDB.
- That idempotency is also what the `metrics_outbox` table relies on.
  `metrics.flush_points()` spools points **before** any network call and deletes
  them only after the backend acknowledged the batch, so a failed write defers
  rather than loses them. Replay is deliberately not selective — the timestamp
  is baked into the line and into `DEDUP_KEYS`, so the whole spool is re-sent
  instead of tracking which point of a batch failed. Do not add per-point
  success tracking, and do not make the write path bypass the spool.
- A deferred batch is a **warning**, not a failed run: nothing is lost, and
  failing would withhold the heartbeat and eventually flip the container
  unhealthy for a recoverable condition. Only a spool at ≥90% of
  `METRICS_OUTBOX_MAX_ROWS` sets `stats.metrics_errors` (exit 1), because the
  next prune would then discard points for real.
- `METRICS_ONLY` snapshots stay on the bare `write_points()` path on purpose.
  They run every `METRICS_INTERVAL` seconds and would dominate the spool during
  an outage, and the next snapshot supersedes them anyway.
- Untrusted input reaches mail headers and report bodies. `_validate_email()`
  and `sanitize_header_value()` in `main.py`, and `_is_sensitive_key()` /
  `_redact_context_value()` in `reportbody.py`, are security controls, not
  cosmetics.

### Testing Requirements
```bash
cd crowdsec-abuse-reporter && python -m pytest
```
Every module here except `banner.py` and `version.py` is exercised by
`../tests/test_hardening.py`, but not all of it via a dedicated class:
`config.py` is covered only through `normalize_asn`, `geoip.py` through
`DnsUtilsHardeningTest` and `ReviewFindingsTest`, and `main.py` mainly through
`../tests/test_main.py`. A behavioural change to the claim/finalize protocol,
the reaper, GeoIP download flow, or report rendering needs a matching test
there.

### Common Patterns
- Extraction helpers are layered and tolerant: `get_alert_ip()`,
  `_extract_report_ip()`, `_dict_or_empty()`, `_alert_source()` all accept
  malformed upstream shapes and fall back rather than raise, because CrowdSec's
  payload shape varies by producer and API surface.
- Returning `"unknown"` is the documented "cannot determine" sentinel.
- `_limit_value()` bounds every value rendered into a report
  (`MAX_FIELD_LENGTH`, `MAX_LIST_ITEMS`, `MAX_DICT_ITEMS`).
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
