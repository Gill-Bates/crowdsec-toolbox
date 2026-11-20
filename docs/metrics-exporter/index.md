# crowdsec-metrics-exporter

Exports CrowdSec ban decisions as time series to InfluxDB 2.x or QuestDB.

## What it does

It reads the alerts behind the currently active decisions from the CrowdSec Local
API over HTTP, authenticating as a registered machine
(`POST /v1/watchers/login`, then `GET /v1/alerts`), and writes the full current
list to the configured backend on every run.

The backend is selected with `METRICS_BACKEND` (`influxdb2` by default, or
`questdb`). Both receive the same InfluxDB Line Protocol payload over HTTP(S);
QuestDB accepts it on its own `/write` endpoint and auto-creates the target table
and columns on first write.

## No local state

The exporter keeps no database, no watermark and no persistent volume. Both
backends deduplicate, so re-sending data that is already stored is a no-op.

That is what makes a failed run need no special handling: the next run sends the
same data again and the result is identical. See
[Metrics Backends](../reference/metrics-backends.md#deduplication).

## Requirements

- A CrowdSec instance whose Local API is reachable over HTTP, plus watcher
  credentials
- An InfluxDB 2.x write endpoint, or a **QuestDB 10.x** instance with
  ILP-over-HTTP enabled (default port `9000`); other QuestDB versions are
  rejected at startup with exit `1`
- Python 3.14+ with the `default` dependency group of `crowdsec-metrics-exporter/pyproject.toml` installed

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, including a run that found nothing new to export |
| `1` | The LAPI fetch or a backend write failed (including a rejected TLS handshake); for QuestDB, the server is not a 10.x release (nothing is written), the deduplication gate could not be verified (nothing is written) or a configured `QUESTDB_TTL` could not be set (the data is kept and not sent again); or the data is incomplete: event details could not be fetched, the alert fetch hit its ceiling, an alert or event has no usable timestamp, or an alert or decision has a missing or invalid `id` and was skipped. Valid records are still exported, but the heartbeat is not refreshed. An invalid timeout setting also exits `1` with a `Config Error` before any fetch |

`main()` returns the code and `__main__` passes it to `sys.exit()`, so cron and
the container health check can both detect a failed run.

## Two export passes

| Pass | Enabled by | Granularity | Table |
|---|---|---|---|
| Alerts | always | one point per alert | `QUESTDB_TABLE` / the InfluxDB measurement |
| Events | `EVENTS_ENABLED=true` | one point per *event* | `EVENTS_TABLE` |

The alert pass carries aggregate information only. The per-event pass adds
request-level detail — HTTP verb, path, status, target FQDN — at a much higher
volume. See [Per-Event Export](events.md).

The passes are independent: if the alert table fails, the events pass still runs,
and the run exits `1` when either failed.

## Known limitations

!!! warning "`get_abuse_contact()` is a stub"
    It returns the constant placeholder `abuse@example.com` for every IP, and
    that value is written into every InfluxDB point as `abuse_email`. The field
    carries no real information — do not build anything on it. Real
    abuse-contact resolution lives in the
    [abuse reporter](../abuse-reporter/index.md).

- The test suite is offline: config parsing, line-protocol escaping,
  LAPI fetch completeness and the QuestDB deduplication gate against an
  in-memory fake. A real run still needs a reachable CrowdSec instance and a
  live backend, so there is no local smoke test and no test may use the network.
- With `METRICS_BACKEND=influxdb2`, plain HTTP and
  `INFLUXDB_VALIDATE_CERTIFICATE=false` only log a warning on every run. There
  is no separate TLS self-test and no prompt: the write itself performs the
  handshake and exits `1` when it is rejected.
- The QuestDB backend creates the table with its dedup keys and verifies
  deduplication *before* the first write of each table (see
  [Metrics Backends](../reference/metrics-backends.md#questdb)). TTL and the
  optional downsampling rollup view are declared *afterwards*. A failed TTL
  exits `1`; the data stays stored and is not sent again. A failed rollup only
  logs an error and leaves the full raw TTL in place.

## This is the less maintained tool

!!! note "Deliberate deviations from its sibling"
    The exporter does not follow all of the abuse reporter's conventions, and
    some differences are load-bearing:

    - `app/influxdb.py` uses `requests` with a hardened `TLS12Adapter` built on a
      `urllib3` SSL context. `app/questdb.py` uses `httpx`. This mix is
      intentional — "modernising" InfluxDB to httpx would drop the custom
      cipher and TLS-version handling.
    - Importing `app.config` has side effects: it loads `settings.env` at import
      time with `override=True`, so for this tool the file beats an existing
      environment variable.
    - The production venv in the root `setup.conf` lives at
      `/opt/jobs/crowdsec_influx` and is activated via `bin/activate`, not
      `.venv/bin/activate`; `setup.conf` documents no cron entry.

## Documentation

- [Configuration](configuration.md) — every supported variable
- [Per-Event Export](events.md) — the second pass and its cost
- [Metrics Backends](../reference/metrics-backends.md) — deduplication, retention, point schema
- [Grafana Dashboards](../reference/dashboards.md)

!!! important
    crowdsec-metrics-exporter is an independent community project. It is not
    affiliated with, endorsed by, or sponsored by CrowdSec.
