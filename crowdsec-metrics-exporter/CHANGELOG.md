## [1.0.4] - 2026-xx-xx
- `New` The start banner is followed by a release check: it compares the running version with the latest GitHub release of crowdsec-toolbox and prints either a new-version notice with a link or "Your version is up to date.". The lookup times out after 3 seconds and stays silent when offline, rate-limited or on a `dev` build; it never blocks or fails the start.
- `Changed` The release check moved into the `gillbates-logging` package (`app/version_check.py` removed). The notice now also reports "Your version (vX) is newer than the latest release.", its link has the form `https://github.com/Gill-Bates/crowdsec-toolbox/releases/latest`, and colour follows `NO_COLOR` (non-empty), `FORCE_COLOR`, `TERM=dumb` and a TTY like the log lines.
- `Changed` The QuestDB client (`/exec` retries, dedup gate, version check, TTL, rollup retention) moved into the external `gillbates-questdb-client` package (`Gill-Bates/python-libraries`, pinned by tag in `[project].dependencies`); QuestDB behaviour and log output are unchanged. Local dev installs it with `pip install -e <checkout>/packages/questdb-client`.
- `Changed` The logging core moved into the external `gillbates-logging` package (`Gill-Bates/python-libraries`, pinned by tag in the `default` group); log output is unchanged. Local dev installs it with `pip install -e <checkout>/packages/logging`.

<details markdown="1">
<summary>Previous versions...</summary>

## [1.0.3] - 2026-11-20

- `Changed` **Breaking:** Invalid `INFLUXDB_PORT`, `QUESTDB_PORT`, `CROWDSEC_ALERT_LIMIT` or `EVENTS_ENABLED` values now abort startup with a `Config Error` instead of silently falling back to the default. `INFLUXDB_URL` must be a bare host name, like `QUESTDB_URL`.
- `Changed` **Breaking:** `CROWDSEC_LAPI_VERIFY_TLS` is now `CROWDSEC_LAPI_VALIDATE_CERTIFICATE`, matching the abuse reporter; the old name is no longer read. The `INFLUXDB_URL` default is `localhost` instead of a private host.
- `Changed` Log lines now come from the same logger as the abuse reporter: the layout is unchanged, but all control characters (not only line breaks) are escaped, `NO_COLOR` also disables the banner colour, and `httpx`/`urllib3` stay quiet below WARNING.
- `Changed` Quieter INFO log: QuestDB version/dedup checks and `Writing data to QuestDB` move to DEBUG. LAPI requests log their duration and size at DEBUG, and `Retrieved N alerts` shows the elapsed time.
- `Fix` QuestDB rollup readiness is judged against the base-table state before this run's write, so the asynchronous refresh no longer keeps the raw TTL at full length with a warning on every run; NULL symbols in the state table no longer re-insert a state row each run.
- `Fix` QuestDB downsampling publishes `_crowdsec_downsampling` only after the raw TTL is in force and reports a refreshing or failed rollup as `disabled`; `QUESTDB_TTL=0` now removes an existing TTL from the raw table and the rollup view.
- `Fix` `EVENTS_ENABLED` ignores case and surrounding whitespace, and the entrypoint's `EVENTS_SINCE` warning applies the same rule.
- `Fix` The event export validates alert IDs before fetching missing event details, like the alert export.
- `Fix` A non-integer `events_count` in a LAPI alert no longer invalidates the whole write batch; the field is left out for that point and the rest is exported.
- `Security` Error responses from InfluxDB and QuestDB are cut to 300 characters in the log.

## [1.0.2] - 2026-11-19

- `New` QuestDB `low`/`medium`/`high` downsampling keeps 90/30/7 days of raw alerts, then rolls up older data at 1h/1h/6h; effective retention is recorded in `_crowdsec_downsampling`.
- `New` A QuestDB event dashboard adds “Top Endpoints” and “Top Target FQDNs” panels for per-event exports.
- `Changed` **Breaking:** QuestDB 10.x is required. Other or unreadable versions fail before DDL or writes; data from older servers is not migrated.
- `Changed` **Breaking:** `RUN_JITTER` is no longer supported; the entrypoint schedules runs on a fixed interval with automatic jitter capped at 300 seconds.
- `Changed` Incomplete `EVENTS_SINCE` windows now warn when shorter than the interval plus jitter. Logs use single-line UTC formatting, and insecure InfluxDB transport warns without prompting.
- `Fix` QuestDB verifies WAL and the exact UPSERT keys before writing; failed retention or rollup setup keeps the full raw window, and delivered points are never resent.
- `Fix` Alert and event exports now run independently, and full alert responses retry with tenfold limits. Naive timestamps are treated as UTC; malformed IDs, scenarios, events, or timestamps are skipped while valid records still export and incomplete runs exit nonzero.
- `Fix` Invalid TLS booleans, timeouts, and colliding event/alert table names now fail configuration. Dashboard table selectors exclude rollups and internal tables.
- `Security` The exporter container now starts as uid `10001` with all capabilities dropped.
- `Security` InfluxDB writes no longer send a TLS self-test request to a third-party service; the exporter contacts only configured endpoints.

## [1.0.1] - 2026-09-25

- ``New`` Grafana dashboard: added chart overviews ("Alerts by Host", "Scenarios by Host", "Top 15 Networks / ASN") above the existing detail tables for a quicker at-a-glance read.
- ``Fix`` Guarded against a potential invalid Line Protocol payload if a data point were ever written without tags (not currently reachable, since every point always has at least one tag).

## [1.0.0] - 2026-09-24
- Project initialization
</details>
