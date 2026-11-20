# Testing

```bash
ruff check .                                    # from the repository root
ruff format --check .                           # formatting is enforced too
cd crowdsec-abuse-reporter && python -m pytest
cd crowdsec-metrics-exporter && python -m pytest
```

!!! note "The exporter suite is small on purpose"
    `crowdsec-metrics-exporter/tests/` holds 204 offline tests: config parsing and
    validation, line-protocol escaping, the rule that dedup keys are tags, LAPI
    fetch completeness and the QuestDB dedup gate against an in-memory fake. A
    real run needs a reachable CrowdSec instance and a live backend, so there is
    no local smoke test and no test may use the network. The rest of this page
    describes the abuse reporter's suite.

## What the suite is for

The tests are `unittest`-style classes executed with pytest — there are no pytest
fixtures. Their focus is **regression hardening**: most cases pin down a specific
safety, security or idempotency property that was reasoned about once and must not
silently regress. They are not broad functional coverage.

| File | Tests | Covers |
|---|---|---|
| `test_hardening.py` | 108 | The main suite; one class per app module, plus `ReviewFindingsTest` and the entrypoint/Dockerfile checks |
| `test_main.py` | 24 | `app.main` helpers: IP/ID/confidence extraction, dedup, stats |
| `test_metrics.py` | 67 | `app.metrics` and its `main.py` integration: line protocol, backend writes, the QuestDB dedup gate and TTL, the outbox, SQLite control-data-only property |
| `test_banner.py` | 1 | Smoke test that the banner renders |

The suite collects **200 tests** across those four files.

### Notable classes

| Class | Protects |
|---|---|
| `ReviewFindingsTest` | Fixes from past code reviews, kept as explicit regressions — the largest class at 23 tests, and the only coverage of `config.normalize_asn`, the `main.py` extraction helpers, the GeoIP download flow and the claim failure path |
| `QuestDbDedupTest` | That every dedup key is a **tag** column; a field key would be rejected by QuestDB |
| `QuestDbGateTest`, `QuestDbFlushGateTest`, `QuestDbSnapshotGateTest` | That nothing is written to QuestDB before dedup is verified, that a failed gate keeps the whole outbox, and that snapshots pass the same gate (against a fake `/exec`, not a live server) |
| `SqliteControlDataOnlyTest` | That with a backend enabled, SQLite stores control data only |
| `EntrypointHardeningTest` | Asserts against `docker/entrypoint.sh`, partly by executing it |

## Running subsets

```bash
cd crowdsec-abuse-reporter
python -m pytest tests/test_hardening.py -k Database -q
```

Tests insert the project root on `sys.path` and import `from app import ...`, so
run pytest from the project directory.

## Entrypoint validation tests

`EntrypointHardeningTest` executes a temporary copy of `docker/entrypoint.sh` with
temporary data and runtime paths. Stub `id`, `python` and `sleep` commands keep the
validation checks independent of Docker's `gosu` binary and `app` user. CI runs the
full abuse-reporter pytest suite, including the jitter tests.

## Writing tests

- Prefer `unittest.mock.patch.object` on already-imported module attributes.

    !!! danger "Do not re-import `app.config`"
        Re-importing it re-reads `settings.env` and can `SystemExit`.

- Use temporary SQLite databases via `tempfile` with `database.DB_PATH` patched.
- New findings from a code review belong in `ReviewFindingsTest`, with a comment
  naming the property being protected.
- Changing a validation message in `entrypoint.sh` breaks the tests that grep for
  it. That coupling is intentional.

## Known coverage gaps

!!! warning "Treat these paths as unguarded"
    - `reap_stale_pending()` is exercised only through the cleanup tests.
    - The claim/finalize protocol is covered mainly by
      `ReviewFindingsTest.test_claim_failure_is_a_database_error_not_already_handled`
      and the retention tests in `DatabaseHardeningTest`, which also cover
      `cleanup_old_records()` and the tombstone migration.

    Both sit on the at-most-once contract described in
    [Delivery Guarantees](../abuse-reporter/delivery.md).
