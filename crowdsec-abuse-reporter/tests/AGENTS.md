<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-11-19 -->

# tests

## Purpose
`unittest`-based suite executed with pytest. Its focus is regression hardening:
most cases pin down a specific safety, security or idempotency property that
was reasoned about once and must not silently regress — not broad functional
coverage.

## Key Files
| File | Description |
|------|-------------|
| `test_hardening.py` | 129 tests, the main suite; one class per app module it covers directly, plus `ReviewFindingsTest` and entrypoint/Dockerfile checks |
| `test_main.py` | 25 tests for `app.main` helpers: IP/ID/confidence extraction, dedup, stats, plus `WhitelistAsnTableOrderTest` (startup call order) |
| `test_metrics.py` | 78 tests for `app.metrics` and its `main.py` integration: line protocol, backend writes, the QuestDB version and dedup gates and TTL against a fake `/exec`, the metrics outbox, and the control-data-only property of SQLite in metrics mode |
| `test_banner.py` | 5 tests: the version/metadata line is centred within the visual width of the banner; the release notice after the banner, its silent cases, fetch errors and version precedence (offline, `fetch_latest_version` patched) |

### Classes in `test_metrics.py`
| Class | Covers |
|-------|--------|
| `LineProtocolTest` | Tag/field escaping and point shape of `format_report_line()` |
| `BackendWriteTest` | InfluxDB/QuestDB write paths, auth precedence, disabled backend |
| `QuestDbTtlTest` | `QUESTDB_TTL` parsing, the `SET TTL` statement after a write, and a failed TTL as written-but-unconfigured |
| `QuestDbDownsamplingTest` | Opt-in rollup: view TTL, raw TTL before the published state, refreshing view keeps full retention, failed TTL publishes nothing, `QUESTDB_TTL=0` lifts the view TTL |
| `QuestDbDedupTest` | The invariant that every dedup key is a **tag** column — a field key would be rejected by QuestDB |
| `QuestDbGateTest` | The gate before the first write: once per process, missing/other keys, non-WAL and SKIP mode block the write, 5xx retried, 4xx final, runbook warning |
| `QuestDbFlushGateTest` | A failed gate keeps all outbox rows (distinct from an outage), a TTL failure exits without resend |
| `QuestDbSnapshotGateTest` | `METRICS_ONLY` snapshots pass the gate and exit `1` on gate or TTL failure |
| `QuestDbVersionGateTest` | Only QuestDB 10.x is accepted: other or unreadable versions write nothing, keep the outbox, and exit `1` before `init_db` |
| `SqliteControlDataOnlyTest` | With a backend enabled, SQLite stores control data only |
| `MainMetricsFlowTest` | `main()` writes points and records `run_state`; a lost, pruned, gate or TTL failure fails the run, a deferred write does not |
| `MetricsOutboxTest` | The SQLite `metrics_outbox` spool: spool before write, delete after acknowledgement, bounds and saturation |

### Classes in `test_hardening.py`
| Class | Covers |
|-------|--------|
| `AbuseHardeningTest` | SMTP connection handling, recipient validation, the XARF e-mail MIME layout (multipart/report) |
| `AbusixHardeningTest` | Abuse-contact DNS lookups and caching |
| `DatabaseHardeningTest` | SQLite param chunking, negative contact-cache distinction, retention cleanup with permanent tombstones (old-schema migration, interrupted cleanup, concurrent claims, `failed`/`pending` handling, `DB_RETENTION_DAYS=0`), `prune_metric_outbox` count |
| `CrowdsecHardeningTest` | LAPI auth, retry/status handling, payload parsing |
| `CrowdsecMalformedAlertTest` | `null` decisions and non-dict events skip the record instead of aborting the run |
| `CrowdsecAlertFetchLimitTest` | Alert-limit escalation up to the ceiling and the warning when it is saturated |
| `ConfigWhitelistTest` | An invalid `WHITELISTED_ASN` entry stops startup (subprocess import) |
| `ConfigSmtpSenderTest` | A non-address `SMTP_SENDER` (empty, `Name <addr>`, no domain) stops startup (subprocess import) |
| `DnsUtilsHardeningTest` | Resolver selection, plus GeoIP tests: stamp validation, download via the selected nameservers, local ASN provider lookup |
| `ConfigEnvLoaderTest` | The stdlib `settings.env` parser of `app.config` (quoting, comments, `override`) |
| `LoggerHardeningTest` | Tagging, TTY colour handling, control-character sanitising |
| `ReviewFindingsTest` | Fixes from past code reviews, kept as explicit regressions — the largest class (23 tests); also the only coverage of `config.normalize_asn`, the claim failure path, and the entrypoint/Dockerfile text assertions |
| `ReportBodyHardeningTest` | Body/X-ARF rendering, redaction, malformed input, line wrapping, and conformance of generated reports to the vendored XARF v4.2.0 schemas (`tests/fixtures/xarf-v4.2.0/`, needs the `jsonschema` dev dependency) |
| `HeartbeatHardeningTest` | LAPI probe and heartbeat-file update semantics |
| `EntrypointHardeningTest` | Asserts against `docker/entrypoint.sh` — partly executes it |
| `EntrypointSupervisionTest` | Executes `entrypoint.sh` with a stub `python`, a stub `id` (skips the root/`gosu` branch) and private data/runtime dirs: normal loop, `RUN_ONCE` exit codes, a killed helper loop ends the container with exit 1, failing helper commands do not, stop signal reaches job and helper children and exits 0, PID-file content. Needs Linux `/proc` and bash >= 5.1, else skipped |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `fixtures/xarf-v4.2.0/` | Unmodified X-ARF v4.2.0 JSON schemas (core, master, `types/`) from `xarf/xarf-spec`; `SOURCE.txt` names the tag. Read by `ReportBodyHardeningTest`; update them only together with a deliberate X-ARF version change. Excluded from the image by `**/tests/` |

## For AI Agents

### Working In This Directory
- Tests insert the project root on `sys.path` (`Path(__file__).resolve().parents[1]`)
  and import `from app import ...`. Run pytest from the project directory.
- Prefer `unittest.mock.patch.object` on already-imported module attributes.
  Re-importing `app.config` re-reads `settings.env` and can `SystemExit`.
- `EntrypointHardeningTest` and `EntrypointSupervisionTest` are the only classes that shell out. Some of it greps
  `docker/entrypoint.sh` as text; the jitter validation tests execute a temporary
  copy with isolated data/runtime paths and stub `id`, `python` and `sleep`, so
  they do not require the image's `gosu` binary or `app` user.
- New findings from a code review belong in `ReviewFindingsTest` with a comment
  naming the property being protected, matching the existing style.

### Testing Requirements
```bash
cd crowdsec-abuse-reporter && python -m pytest          # full suite
python -m pytest tests/test_hardening.py -k Database -q   # one area
```
The suite currently collects 233 tests in total across the four files listed
above.

Known gap: `reap_stale_pending()` is covered only inside the retention tests,
and the claim/finalize protocol mainly by
`ReviewFindingsTest.test_claim_failure_is_a_database_error_not_already_handled`
plus the `DatabaseHardeningTest` retention tests. Treat changes to the reaper as
thinly guarded.

### Common Patterns
- Multi-context `with (...)` blocks combining several `patch.object` calls and
  the assertion context.
- `_FakeQuestDb` + `_QuestDbStubMixin` in `test_metrics.py` route QuestDB `/write` and `/exec` through an `httpx.MockTransport`
  and clear the per-process gate cache; use them for any test that reaches `write_points()` with `questdb`.
- Temporary SQLite databases via `tempfile` with `database.DB_PATH` patched.
- `_TtyStream(io.StringIO)` fakes a TTY to exercise the colour branch in
  `logger.print_log`.

## Dependencies

### Internal
- `../app/` — every module is imported by `test_hardening.py`
- `../docker/entrypoint.sh` — asserted against by `EntrypointHardeningTest`

### External
- `pytest` (runner), stdlib `unittest` / `unittest.mock`
- `jsonschema` (`dev` group) for the X-ARF schema-conformance test
- `httpx` and `dns.resolver` for constructing fake responses and errors

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
