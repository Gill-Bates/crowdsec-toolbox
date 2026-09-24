<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-09-23 -->

# crowdsec-abuse-reporter

## Purpose
Unattended collector/reporter that turns CrowdSec bans into abuse reports. It
fetches decisions from the CrowdSec Local API (LAPI), enriches each source IP
with GeoIP data, resolves the responsible abuse contact via the Abusix DNS
contact database, and emails an X-ARF v4 report to that contact. Every report
is recorded in SQLite so a ban is reported **at most once**.

It can optionally export report outcomes to InfluxDB or QuestDB while SQLite
retains the at-most-once control data and spools not-yet-acknowledged metrics
points in `metrics_outbox`, so an unreachable backend defers points instead of
losing them. It uses the `app/` package layout with
a top-level `run.py` shim.

## Key Files
| File | Description |
|------|-------------|
| `run.py` | Entry-point shim: `raise SystemExit(main())` from `app.main` |
| `setup.conf` | Single source of truth for venv install, buildx build, and deploy |
| `settings.env` | Active runtime configuration with real credentials — gitignored, never commit |
| `settings-*.env` | Optional site-specific profiles — gitignored, never commit |
| `BUILD_INFO` | Version/SHA/date written by the buildx command in `setup.conf` |
| `README.md` | Operator documentation in English (Docker usage, data ownership) |
| `data/abuse_alerts.db` | Default SQLite store for direct host runs |
| `.gitignore` | Excludes `/data/` and legacy root-level `abuse_alerts.db` files (the repo-root `.gitignore` also covers `*.db*`, `settings*.env`, `BUILD_INFO`) |

Runtime deps (dnspython, geoip2, httpx, pinned) are the `abuse`
`default` group in this tool's own `pyproject.toml`; there is no
`requirements.txt` and no root manifest.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `app/` | Application package — all Python logic (see `app/AGENTS.md`) |
| `tests/` | unittest suite run via pytest (see `tests/AGENTS.md`) |
| `docker/` | Image, compose, entrypoint, env template (see `docker/AGENTS.md`) |
| `data/` | Gitignored runtime state: GeoLite2 MMDBs, heartbeat files, DB |

## For AI Agents

### Working In This Directory
- Python 3.13+ only. Modern idioms: `pathlib`, `|` unions, `StrEnum`,
  `typing.Self`, timezone-aware datetimes. No `typing.Optional`, no `os.path`,
  no pre-3.13 compatibility shims.
- Scope changes to this project. Do not refactor across the toolbox and do not
  extract shared packages — `logger.py`, `config.py` and friends are duplicated
  across projects on purpose so each stays independently deployable.
- Comments and docstrings in English; user-facing strings are frequently German
  and must keep their wording and non-ASCII characters.
- `docker/settings.env.example` is the single tracked template and must list
  every supported variable; there is no project-root copy any more.
- Never hardcode or log secrets (SMTP password, LAPI password).
- `settings.env` / `settings-*.env` hold real SMTP and LAPI credentials. They
  are gitignored and dockerignored; never commit them or copy their values
  elsewhere. They were tracked in the former monorepo, so credentials from
  that era must be treated as exposed until rotated.

### Delivery Semantics (do not break)
The at-most-once contract is the central invariant of this project:
- A report is claimed (`claim_alert_for_send`) immediately before sending and
  finalized (`finalize_alert`) after. Only the claim owner may send.
- Rows left `pending` by a crash are moved to the terminal
  `unknown_send_state` by the reaper and are **never** retried, because SMTP may
  already have accepted the mail.
- The idempotency key is the `(AlertId, IPAddress)` pair, not `AlertId` alone —
  one alert can bundle bans for several IPs.
- A CrowdSec `Range` decision must never be collapsed to its network address
  and reported as the offender.

### Releasing
Releases run from a repo-wide `vX.Y.Z` tag (see `../AGENTS.md`), which also
requires this tool's `pyproject.toml` version to match. The image is published
as `crowdsec-toolbox:abuse-reporter-<version>` plus the moving
`crowdsec-toolbox:abuse-reporter-latest` tag.

### Testing Requirements
```bash
ruff check .                              # from the repository root
cd crowdsec-abuse-reporter && python -m pytest
```
There is no typechecker in this repository — do not add mypy or pyright and do
not claim a typecheck ran. Ruff is the single linter; no config is committed
here; this tool's own `pyproject.toml` carries the `[tool.ruff.lint]` section that
ignores `BLE001`, since the broad `except Exception` handlers here are
deliberate (see Common Patterns). Do not narrow that ignore or add new
findings.

Known environment-dependent failure:
`tests/test_hardening.py::EntrypointHardeningTest::test_entrypoint_rejects_non_integer_run_jitter`
fails on hosts without `gosu` because it executes the container entrypoint
directly. That is environmental, not a code defect.

### Common Patterns
- Broad `except Exception` at collector and outer-loop boundaries is deliberate
  so one bad alert cannot kill the run. Do not narrow those handlers.
- Every outbound HTTP, DNS and SMTP call carries an explicit timeout.
- Exit codes: `0` normal (per-report DNS/send failures still exit 0), `1` hard
  failure (config, GeoIP cold start, DB init, LAPI fetch, database errors),
  `130` interrupted. The entrypoint only refreshes `/data/heartbeat` on exit 0.

### Database Location
Direct host runs store the database at `data/abuse_alerts.db` by default. The
Docker entrypoint overrides this via `ABUSE_DB_PATH=/data/abuse_alerts.db`, so
the container's database is persisted under its mounted data directory. Keep
the database history when migrating to avoid sending reports twice.

## Dependencies

### Internal
- `app/AGENTS.md`, `tests/AGENTS.md`, `docker/AGENTS.md` — per-directory rules
- `../crowdsec-metrics-exporter/` — sibling tool; shares no code or runtime

### External
- `httpx` — CrowdSec LAPI and public-IP detection
- `dnspython` — Abusix abuse-contact lookups and resolver control
- `geoip2` / `maxminddb` — GeoLite2 City and ASN enrichment
- stdlib `sqlite3`, `smtplib`, `email` — storage and report delivery; `settings.env` is
  loaded by a small stdlib parser in `config.py` (no third-party dependency)

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
