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

<details markdown="1">
<summary>Previous versions...</summary>

## [1.0.1] - 2026-09-25

- ``New`` Grafana dashboard: added chart overviews ("Alerts by Host", "Scenarios by Host", "Top 15 Networks / ASN") above the existing detail tables for a quicker at-a-glance read.
- ``Fix`` Guarded against a potential invalid Line Protocol payload if a data point were ever written without tags (not currently reachable, since every point always has at least one tag).

## [1.0.0] - 2026-09-24
- Project initialization
</summary>
