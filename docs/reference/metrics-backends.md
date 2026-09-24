# Metrics Backends

Both tools can write to InfluxDB 2.x or QuestDB, using the same variables and the
same line-protocol payload. For the exporter this is its purpose; for the abuse
reporter it is optional and off by default.

| | crowdsec-abuse-reporter | crowdsec-metrics-exporter |
|---|---|---|
| `METRICS_BACKEND` default | `none` | `influxdb2` |
| Default table | `crowdsec-abuse` | `crowdsec` |
| What a point represents | one sent or failed report | one alert (or one event) |

Any value other than the three supported ones aborts at startup.

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

### QuestDB

Must be declared, because ILP auto-creates tables as **append-only**. After every
successful write the tool issues `ALTER TABLE ... DEDUP ENABLE UPSERT KEYS(...)`,
which is idempotent. This needs **QuestDB 7.3+** and a WAL table (ILP tables are
WAL). A failure only logs a warning — the rows are stored either way, but
duplicates would then accumulate.

| Table | Upsert keys |
|---|---|
| Exporter alerts (`QUESTDB_TABLE`) | `timestamp`, `host`, `ip_address`, `as_name`, `as_number`, `country`, `scenario` |
| Exporter events (`EVENTS_TABLE`) | `timestamp`, `alert_id`, `event_seq` |
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

## Retention

`QUESTDB_TTL` is applied after each successful write with
`ALTER TABLE ... SET TTL` (QuestDB 8.3+).

| Value | Meaning |
|---|---|
| `365d` | Default |
| `12w`, `6M`, `1y`, `48h` | Other accepted units |
| `0` | Retention disabled |

A failure only logs a warning. InfluxDB retention is configured on the bucket, not
by these tools.

!!! warning "Set TTL before enabling the event export"
    The events table grows far faster than the alert table. See
    [Per-Event Export](../metrics-exporter/events.md#cost).

## Write behaviour and failure

All points of a run are written in **one request at the end of the run**, even
after an interrupt.

| Tool | A failed write means |
|---|---|
| Abuse reporter | Points stay in the SQLite outbox and are re-sent on the next run. The run still exits `0`. |
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
    This is what makes the whole approach work without bookkeeping. The timestamp
    is baked into the line by `format_report_line()` and is part of the dedup key
    set, so re-sending a point the backend already holds collapses onto the same
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
    exits `1`, because the next prune starts discarding points for real.

### The snapshot loop is not spooled

`METRICS_ONLY` snapshots are deliberately excluded. They run every
`METRICS_INTERVAL` seconds and write one point per active decision, so spooling
them during an outage would dominate the database — and the next snapshot
supersedes them anyway. A failed snapshot exits `1`, which the entrypoint's
metrics loop logs without touching the heartbeat.

!!! danger "Deduplication is not a delivery guarantee"
    For the abuse reporter, backend deduplication makes storage idempotent but
    cannot decide whether a mail may be sent. That decision needs the SQLite
    claim protocol — see [Delivery Guarantees](../abuse-reporter/delivery.md).
    The outbox holds points, never pending mails.

## Variable reference

The variables are identical for both tools:

| Variable | Applies to |
|---|---|
| `METRICS_BACKEND`, `REQUEST_TIMEOUT` | both backends |
| `INFLUXDB_URL`, `INFLUXDB_PORT`, `INFLUXDB_USE_HTTPS`, `INFLUXDB_VALIDATE_CERTIFICATE`, `INFLUXDB_ORGANIZATION`, `INFLUXDB_BUCKET`, `INFLUXDB_TOKEN` | `influxdb2` |
| `QUESTDB_URL`, `QUESTDB_PORT`, `QUESTDB_USE_HTTPS`, `QUESTDB_VALIDATE_CERTIFICATE`, `QUESTDB_TABLE`, `QUESTDB_TTL`, `QUESTDB_TOKEN`, `QUESTDB_USERNAME`, `QUESTDB_PASSWORD` | `questdb` |

Full descriptions: [exporter](../metrics-exporter/configuration.md) ·
[abuse reporter](../abuse-reporter/configuration.md#metrics-backend).
