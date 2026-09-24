<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-09-23 -->

# tests

## Purpose
`unittest`-based suite executed with pytest. Its focus is regression hardening:
most cases pin down a specific safety, security or idempotency property that
was reasoned about once and must not silently regress — not broad functional
coverage.

## Key Files
| File | Description |
|------|-------------|
| `test_hardening.py` | 73 tests, the main suite; one class per app module it covers directly, plus `ReviewFindingsTest` and entrypoint/Dockerfile checks |
| `test_main.py` | 20 tests for `app.main` helpers: IP/ID/confidence extraction, dedup, stats, plus `WhitelistAsnTableOrderTest` (startup call order) |
| `test_metrics.py` | 22 tests for `app.metrics` and its `main.py` integration: line protocol, backend writes, QuestDB TTL and dedup, and the control-data-only property of SQLite in metrics mode |
| `test_banner.py` | Smoke test that the banner renders |

### Classes in `test_metrics.py`
| Class | Covers |
|-------|--------|
| `LineProtocolTest` | Tag/field escaping and point shape of `format_report_line()` |
| `BackendWriteTest` | InfluxDB/QuestDB write paths, auth precedence, disabled backend |
| `QuestDbTtlTest` | `QUESTDB_TTL` parsing and the `SET TTL` statement after a write |
| `QuestDbDedupTest` | `DEDUP ENABLE UPSERT KEYS` after a write, warn-only failure, and the invariant that every dedup key is a **tag** column — a field key would be rejected by QuestDB |
| `SqliteControlDataOnlyTest` | With a backend enabled, SQLite stores control data only |
| `MainMetricsFlowTest` | `main()` writes points and records `run_state`; a failed write fails the run |

### Classes in `test_hardening.py`
| Class | Covers |
|-------|--------|
| `AbuseHardeningTest` | SMTP connection handling, recipient validation |
| `AbusixHardeningTest` | Abuse-contact DNS lookups and caching |
| `DatabaseHardeningTest` | SQLite param chunking, negative contact-cache distinction |
| `CrowdsecHardeningTest` | LAPI auth, retry/status handling, payload parsing |
| `DnsUtilsHardeningTest` | Resolver selection and timeout bounds |
| `LoggerHardeningTest` | Tagging, TTY colour handling, control-character sanitising |
| `ReviewFindingsTest` | Fixes from past code reviews, kept as explicit regressions — the largest class (22 tests); also the only coverage of `config.normalize_asn`, the `main.py` extraction helpers, the GeoIP download flow, the claim failure path, and the entrypoint/Dockerfile text assertions |
| `ReportBodyHardeningTest` | Body/X-ARF rendering, redaction, malformed input |
| `HeartbeatHardeningTest` | LAPI probe and heartbeat-file update semantics |
| `EntrypointHardeningTest` | Asserts against `docker/entrypoint.sh` — partly executes it |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
- Tests insert the project root on `sys.path` (`Path(__file__).resolve().parents[1]`)
  and import `from app import ...`. Run pytest from the project directory.
- Prefer `unittest.mock.patch.object` on already-imported module attributes.
  Re-importing `app.config` re-reads `settings.env` and can `SystemExit`.
- `EntrypointHardeningTest` is the only class that shells out. Some of it greps
  `docker/entrypoint.sh` as text; `test_entrypoint_rejects_non_integer_run_jitter`
  actually executes it and **fails on hosts without `gosu`**. That failure is
  environmental and expected outside the container.
- New findings from a code review belong in `ReviewFindingsTest` with a comment
  naming the property being protected, matching the existing style.

### Testing Requirements
```bash
cd crowdsec-abuse-reporter && python -m pytest          # full suite
python -m pytest tests/test_hardening.py -k Database -q   # one area
```
The current host baseline is 123 passed, 1 failed (the `gosu` case above). Any
other failure is a real regression. The suite currently collects 124 tests in
total across the four files listed above.

Known gap: `reap_stale_pending()` and `cleanup_old_records()` have no test at
all, and the claim/finalize protocol is covered only indirectly by
`ReviewFindingsTest.test_claim_failure_is_a_database_error_not_already_handled`.
Treat changes to those paths as unguarded.

### Common Patterns
- Multi-context `with (...)` blocks combining several `patch.object` calls and
  the assertion context.
- Temporary SQLite databases via `tempfile` with `database.DB_PATH` patched.
- `_TtyStream(io.StringIO)` fakes a TTY to exercise the colour branch in
  `logger.print_log`.

## Dependencies

### Internal
- `../app/` — every module is imported by `test_hardening.py`
- `../docker/entrypoint.sh` — asserted against by `EntrypointHardeningTest`

### External
- `pytest` (runner), stdlib `unittest` / `unittest.mock`
- `httpx` and `dns.resolver` for constructing fake responses and errors

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
