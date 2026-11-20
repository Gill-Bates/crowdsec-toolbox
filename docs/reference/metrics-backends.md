# Metrics Backends

Both tools can write to InfluxDB 2.x or QuestDB, using the same variables and the
same line-protocol payload. For the exporter this is its purpose; for the abuse
reporter it is optional and off by default.

| | crowdsec-abuse-reporter | crowdsec-metrics-exporter |
|---|---|---|
| `METRICS_BACKEND` default | `none` | `influxdb2` |
| Default table | `crowdsec-abuse` | `crowdsec` |
| What a point represents | one sent or failed report | one alert (or one event) |

Any other value aborts at startup; `none` exists only in the abuse reporter.

## Transport

Both backends receive the same InfluxDB Line Protocol payload over HTTP(S).
QuestDB accepts it on its own `/write` ILP endpoint and auto-creates the target
table and columns on first write.

!!! note "Two HTTP clients, on purpose"
    In the exporter, `app/influxdb.py` uses `requests` with a hardened
    `TLS12Adapter` built on a `urllib3` SSL context, while `app/questdb.py` uses
    `httpx`. QuestDB's endpoint has no equivalent cipher or TLS-version
    requirement, and the adapter is `requests`-specific. Do not unify them —
    that would drop the InfluxDB TLS hardening.

## Point schema

=== "Abuse reporter"

    Each sent or failed report becomes one point.

    | Kind | Columns |
    |---|---|
    | Tags | `ip_address`, `scenario`, `status`, `country`, `as_number`, `as_name`, `host` |
    | Fields | `alert_id`, `abuse_email`, `processing_time`, `error_message` |

    With `METRICS_ONLY=true` the current decisions are exported as points with
    `status=observed` and no mail is sent.

=== "Metrics exporter"

    Each alert becomes one point, tagged with the host identity, source IP,
    scenario and the AS/country enrichment. With `EVENTS_ENABLED=true` a second
    pass writes one point per event into a separate table — see
    [Per-Event Export](../metrics-exporter/events.md).

    !!! warning "`abuse_email` is a placeholder"
        The exporter's `get_abuse_contact()` is a stub returning a constant
        address for every IP. The field carries no real information.

## Deduplication

Both tools rely on the backend for idempotency instead of a local watermark,
which is why the exporter needs no database and no persistent volume.

### InfluxDB 2.x

Inherent and requires no configuration: a point repeating an existing series
(measurement + tag set) at the same timestamp overwrites it rather than adding a
row.

!!! note "Records without a timestamp"
    The exporter takes the timestamp from the alert's `start_at` (events: the
    event's own timestamp, then `start_at`). A record with neither is skipped
    and the run exits `1`: the export time would differ on every run and defeat
    deduplication.

### QuestDB

**Only QuestDB 10.x is supported.** There is no compatibility path for 9.x or
older releases and no migration: data an older server stored is out of scope,
and a server upgrade is the operator's task. With `METRICS_BACKEND=questdb`,
both tools read `SELECT build()` over `/exec` before any DDL or write and
accept only a `10.x` major version. A different major version, an
unreachable server or an answer that does not contain a version stops the run
with exit code `1` and writes nothing:

```text
2026-11-19 12:24:36 UTC | ERROR    | crowdsec_metrics | Unsupported QuestDB version at http://localhost:9000: found 9.3.4, required 10.x; nothing was written
```

The reporter performs the same check before any mail is sent, in `METRICS_ONLY`
snapshots and before every outbox flush. Its SQLite outbox is never discarded
for this reason: the points stay until the server is a 10.x release. The check
does not apply to `influxdb2` or `none`. In the container loop the next run
repeats the check, so upgrading the server is enough to recover.

Deduplication must be declared, because ILP auto-creates tables as **append-only**. The
exporter therefore does not write first and repair afterwards: before the first
write of each table it runs `CREATE TABLE IF NOT EXISTS ... WAL DEDUP UPSERT
KEYS(...)` with only the key columns (ILP adds the others),
`ALTER TABLE ... DEDUP ENABLE UPSERT KEYS(...)`, and reads the result back from
`tables()`, `table_columns()` and `SHOW CREATE TABLE`. The table must be a WAL
table with dedup on and exactly the expected key set in UPSERT mode. If that
cannot be verified, for example because another tool owns the table with other
keys, nothing is written and the run exits `1`. Transport errors, 5xx and 429 are
retried a few times with backoff; a 4xx is final.

The abuse reporter applies the same gate to its table, once per process before
the first write; the `METRICS_ONLY` snapshot loop passes it as well. If it fails,
nothing is written and the reporter keeps **every** row in its SQLite outbox,
which is the only durable copy. The run exits `1` at once, not only at outbox
saturation. This is a configuration failure and is reported separately from an
unreachable backend, which stays a deferred batch with exit `0`. The next run
repeats the gate and sends the outbox when it passes.

Two outcomes are kept apart in the log and in the result: *data written* and
*database correctly configured*. After a successful write, a `QUESTDB_TTL` or rollup that
cannot be set up exits `1` as well, but the data stays stored and is not sent again.
The reporter behaves the same: rows already
acknowledged leave the outbox and are not resent for a failed TTL. A failed
downsampling rollup logs an error and
keeps the full raw TTL, which loses no data and does not change the exit code.

| Table | Upsert keys |
|---|---|
| Exporter alerts (`QUESTDB_TABLE`) | `timestamp`, `host`, `ip_address`, `as_name`, `as_number`, `country`, `scenario` |
| Exporter events (`EVENTS_TABLE`) | `timestamp`, `host`, `alert_id`, `event_seq` |
| Abuse reports (`QUESTDB_TABLE`) | `timestamp`, `host`, `ip_address`, `scenario`, `status`, `country`, `as_number`, `as_name` |

!!! danger "An upsert key must be a tag column"
    QuestDB upsert keys have to be columns of the row identity. `alert_id` is a
    *field* in the alert and report tables, so it cannot be a key there — a field
    key is rejected outright.

#### The alert table's key is not exact

Because `alert_id` is unavailable as a key, two distinct alerts that agree on
host, IP, scenario, AS and country *and* carry the same timestamp collapse into
one row.

In practice, alerts agreeing on all of those are the same alert. The case that
looks similar — one IP triggering several scenarios in the same second — differs
in `scenario` and is preserved.

The events table has no such compromise: `event_seq` makes its key exact.

#### Removing duplicates stored before dedup was enabled

Enabling dedup does not remove rows that are already stored; only new inserts
are deduplicated. When the exporter or the abuse reporter enables dedup on an
existing table it logs a warning pointing here. Neither cleans up by itself. To
remove the duplicates by hand (for the reporter, use its table and keys from the
table above):

1. Stop the tool that writes the table.
2. Create a new table with the same columns and `DEDUP UPSERT KEYS(...)` from the
   table above, and copy the rows with `INSERT INTO new SELECT * FROM old`; the
   upsert keys collapse the duplicates.
3. Rename the old table out of the way and the new one to the original name.
4. Bump `QUESTDB_DOWNSAMPLING_SCHEMA_VERSION` in the tool's `app/config.py`
   when downsampling is on: a rollup view stays bound to the old base table, so the swapped table
   needs a new view.
5. Start the tool and check that the gate reports dedup as verified.

## Retention

`QUESTDB_TTL` is applied after each successful write with
`ALTER TABLE ... SET TTL`; `0` removes an existing TTL with `SET TTL 0 HOURS`
([TTL: removing](https://questdb.com/docs/concepts/ttl/)).

| Value | Meaning |
|---|---|
| `365d` | Default |
| `12w`, `6M`, `1y`, `48h` | Other accepted units |
| `0` | Retention disabled; an existing TTL on the table and on the rollup view is removed |

A failure logs a warning; both tools also exit `1` (the data stays
stored and is not sent again). InfluxDB retention is configured on the bucket, not
by these tools.

!!! warning "Set TTL before enabling the event export"
    The events table grows far faster than the alert table. See
    [Per-Event Export](../metrics-exporter/events.md#cost).

### Downsampling (QuestDB)

`QUESTDB_DOWNSAMPLING` is opt-in in both tools and takes the same profiles. It
keeps the raw rows for a short window and the long-term history in a
materialized rollup view. The view carries `QUESTDB_TTL`, the raw table the
profile's shorter window. Without a profile both tools keep the raw table at
`QUESTDB_TTL` and create no view. A view's TTL is independent of its base
table's TTL ([TTL: materialized views](https://questdb.com/docs/concepts/ttl/)).

| Profile | Raw window | Rollup interval |
|---|---|---|
| unset | `QUESTDB_TTL` | no rollup |
| `low` | 90 days | 1h |
| `medium` | 30 days | 1h |
| `high` | 7 days | 6h |

Exporter alert table: the rollup keeps `host`, `country` and `scenario` and
aggregates `count()` as `decisions_count` plus `sum`/`max` of `events_count`.
Dropping `ip_address`, `as_name` and `as_number` is what shrinks the history;
the per-IP coordinates are meaningless once IPs are collapsed and are not
carried over.

Abuse reporter report table: the rollup keeps `host`, `country`, `scenario` and
`status` and aggregates `count()` as `reports_count` plus `avg`/`max` of
`processing_time`. `abuse_email` and `error_message` are strings and `alert_id`
is an identity, so none of them has a meaningful aggregate and they are not
carried over. `METRICS_ONLY` snapshot points (`status=observed`) land in the
same table and are counted under that status. The dimensions are a subset of
the table's dedup keys, as QuestDB requires for a view over a deduplicated
table ([Materialized views](https://questdb.com/docs/concepts/materialized-views/)). The view is named
`<table>_rollup_<interval>_v<schema version>`, so a later definition change
creates a new view instead of altering an existing one.

Order in both tools after a successful write: create the view if missing,
set the view's TTL, check `materialized_views()`, set the raw TTL, then publish
the effective state. The raw TTL is only shortened once the view is `valid` and
`refresh_base_table_txn` has reached `base_table_txn`. A view that is still
refreshing keeps the full raw retention and does not fail the run; an `invalid`
view, failed DDL or an unreadable status keeps it too but exits `1`. QuestDB
documents `REFRESH MATERIALIZED VIEW ... FULL` as the recovery for an invalid
view; it deletes the view's data and is never run automatically.

!!! warning "Switching a profile off does not restore raw history"
    Clearing `QUESTDB_DOWNSAMPLING` puts `QUESTDB_TTL` back on the raw table at
    the next successful write, but rows the shorter window already dropped are
    gone — only the rollup view still covers that period, and it is kept.

The events table is deliberately excluded. QuestDB requires a materialized
view's non-aggregate columns to be a subset of the base table's `DEDUP` keys,
and those keys are the per-event identity (`host`, `alert_id`, `event_seq`),
which a rollup cannot group by usefully. The events table therefore keeps full
resolution for the whole `QUESTDB_TTL` window.

### The effective retention is queryable

Both tools write the configured TTL and the effective profile into the shared
`_crowdsec_downsampling` table (one row per `table_name`) after each run, so a
dashboard does not have to read `settings.env`. The row is written only after
the raw TTL is in force, and `enabled` is true only for a valid, caught-up
rollup; a refreshing or failed rollup is published as `disabled` with the full
raw window:

| Column | Meaning |
|---|---|
| `table_name` | The table this row describes |
| `profile` | Active profile, or `disabled` |
| `schema_version` | Rollup definition version |
| `enabled` | Whether a rollup is in effect |
| `raw_days` | Days of full-resolution history |
| `rollup_interval`, `rollup_view` | Sample interval and view name, empty when disabled |
| `total_ttl` | The configured `QUESTDB_TTL`, e.g. `365 DAYS` |

`raw_days` counts whole days. A value of `0` can mean that TTL is disabled or
that the configured TTL is shorter than one day; check `total_ttl` to tell them
apart.

```sql
SELECT * FROM _crowdsec_downsampling
LATEST ON timestamp PARTITION BY table_name;
```

A row is only appended when the state actually changed.

## Write behaviour and failure

All points of a run are written in **one request at the end of the run**, even
after an interrupt.

| Tool | A failed write means |
|---|---|
| Abuse reporter | Backend unreachable: points stay in the SQLite outbox and are re-sent on the next run; the run still exits `0`. QuestDB dedup not verifiable or QuestDB not 10.x: nothing is written, the outbox is kept, the run exits `1`. |
| Metrics exporter | Run exits `1`. The next run re-sends the same data. |

## Durability: the outbox

The abuse reporter is the case that needs protecting: by the time a point is
written the mail has already gone out, and with a backend enabled the report
details are stored nowhere else.

A report point is therefore appended to a SQLite `metrics_outbox` table **before**
any network call and removed only once the backend acknowledged it. The flush runs
at the start of a run (draining what an earlier run could not deliver) and at the
end (this run's points, oldest first, in one batch).

!!! note "Replay is safe because it is exactly idempotent"
    The timestamp is baked into the line by `format_report_line()` and is part of
    the dedup key set, so re-sending a point the backend already holds collapses onto the same
    row. There is no need to determine *which* point of a failed batch was
    rejected — the spool is simply replayed in full.

`METRICS_WRITE_RETRIES` adds retries within a run for transport-level failures (a
resolver hiccup, a reset connection), so a blip never reaches the spool. An HTTP
status is never retried: a 4xx means the payload or credentials are wrong, and
repeating it cannot help.

### Bounds

A prolonged outage must not grow the database without limit, so the spool is
bounded by `METRICS_OUTBOX_MAX_ROWS` and `METRICS_OUTBOX_MAX_AGE_DAYS`. Oldest
points are dropped first — they are the least useful, and discarding them is
exactly the outcome that existed before the outbox.

!!! warning "Saturation is the failure worth surfacing"
    A single unreachable-backend run loses nothing, so it stays exit `0` and the
    container stays healthy. Once the spool reaches 90% of the row bound the run
    exits `1`, because the next prune starts discarding points for real. This
    also applies when the run has nothing to send. If both the spool and the
    backend write fail, points are lost and the run exits `1`. The same holds
    when the bounds drop points the backend never acknowledged (also with
    `METRICS_OUTBOX_MAX_ROWS=0` plus an age limit): that run exits `1` and
    logs the number of dropped points. The remaining points are still sent.

### The snapshot loop is not spooled

`METRICS_ONLY` snapshots are deliberately excluded. They run every
`METRICS_INTERVAL` seconds and write one point per active decision, so spooling
them during an outage would dominate the database — and the next snapshot
supersedes them anyway. They still pass the QuestDB dedup gate before writing.
A failed snapshot, including a failed gate or TTL, exits `1`, which the
entrypoint's metrics loop logs without touching the heartbeat.

!!! danger "Deduplication is not a delivery guarantee"
    For the abuse reporter, backend deduplication makes storage idempotent but
    cannot decide whether a mail may be sent. That decision needs the SQLite
    claim protocol — see [Delivery Guarantees](../abuse-reporter/delivery.md).
    The outbox holds points, never pending mails.

## Variable reference

The variables are identical for both tools (`QUESTDB_DOWNSAMPLING` is described under Retention):

| Variable | Applies to |
|---|---|
| `METRICS_BACKEND`, `REQUEST_TIMEOUT` | both backends |
| `INFLUXDB_URL`, `INFLUXDB_PORT`, `INFLUXDB_USE_HTTPS`, `INFLUXDB_VALIDATE_CERTIFICATE`, `INFLUXDB_ORGANIZATION`, `INFLUXDB_BUCKET`, `INFLUXDB_TOKEN` | `influxdb2` |
| `QUESTDB_URL`, `QUESTDB_PORT`, `QUESTDB_USE_HTTPS`, `QUESTDB_VALIDATE_CERTIFICATE`, `QUESTDB_TABLE`, `QUESTDB_TTL`, `QUESTDB_DOWNSAMPLING`, `QUESTDB_TOKEN`, `QUESTDB_USERNAME`, `QUESTDB_PASSWORD` | `questdb` |

Full descriptions: [exporter](../metrics-exporter/configuration.md) ·
[abuse reporter](../abuse-reporter/configuration.md#metrics-backend).
