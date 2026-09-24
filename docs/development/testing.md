# Testing

```bash
ruff check .                                    # from the repository root
cd crowdsec-abuse-reporter && python -m pytest  # the only test suite
```

!!! note "Only one tool has tests"
    `crowdsec-metrics-exporter` has no test suite and none should be added without
    an explicit request. A real run needs a reachable CrowdSec instance and a live
    backend, so there is no meaningful local smoke test.

## What the suite is for

The tests are `unittest`-style classes executed with pytest — there are no pytest
fixtures. Their focus is **regression hardening**: most cases pin down a specific
safety, security or idempotency property that was reasoned about once and must not
silently regress. They are not broad functional coverage.

| File | Tests | Covers |
|---|---|---|
| `test_hardening.py` | 73 | The main suite; one class per app module, plus `ReviewFindingsTest` and the entrypoint/Dockerfile checks |
| `test_main.py` | 20 | `app.main` helpers: IP/ID/confidence extraction, dedup, stats |
| `test_metrics.py` | 31 | `app.metrics` and its `main.py` integration: line protocol, backend writes, QuestDB TTL and dedup, SQLite control-data-only property |
| `test_banner.py` | 1 | Smoke test that the banner renders |

The suite collects **125 tests** across those four files.

### Notable classes

| Class | Protects |
|---|---|
| `ReviewFindingsTest` | Fixes from past code reviews, kept as explicit regressions — the largest class at 22 tests, and the only coverage of `config.normalize_asn`, the `main.py` extraction helpers, the GeoIP download flow and the claim failure path |
| `QuestDbDedupTest` | That every dedup key is a **tag** column; a field key would be rejected by QuestDB |
| `SqliteControlDataOnlyTest` | That with a backend enabled, SQLite stores control data only |
| `EntrypointHardeningTest` | Asserts against `docker/entrypoint.sh`, partly by executing it |

## Running subsets

```bash
cd crowdsec-abuse-reporter
python -m pytest tests/test_hardening.py -k Database -q
```

Tests insert the project root on `sys.path` and import `from app import ...`, so
run pytest from the project directory.

## The known environmental failure

!!! warning "Baseline is 124 passed, 1 failed"
    `test_entrypoint_rejects_non_integer_run_jitter` **fails on any host without
    `gosu`**, because it actually executes the container entrypoint. Installing
    `gosu` alone does not fix it either — the entrypoint then fails one step later
    on the missing `app` user, which only the image creates.

    This is environmental, not a code defect. **Any other failure is a real
    regression.**

CI deselects exactly this one test so the gate stays meaningful rather than
permanently red. The rest of `EntrypointHardeningTest` still runs, since most of it
greps the entrypoint as text rather than executing it.

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
    - `reap_stale_pending()` and `cleanup_old_records()` have **no test at all**.
    - The claim/finalize protocol is covered only indirectly, by
      `ReviewFindingsTest.test_claim_failure_is_a_database_error_not_already_handled`.

    Both sit on the at-most-once contract described in
    [Delivery Guarantees](../abuse-reporter/delivery.md).
