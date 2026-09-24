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
- An InfluxDB 2.x write endpoint, or a QuestDB instance with ILP-over-HTTP
  enabled (default port `9000`)
- Python 3.13+ with the `metrics-exporter` dependency group installed

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, including a run that found nothing new to export |
| `1` | The TLS check, the LAPI fetch or a backend write failed |

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

## Known limitations

!!! warning "`get_abuse_contact()` is a stub"
    It returns the constant placeholder `abuse@example.com` for every IP, and
    that value is written into every InfluxDB point as `abuse_email`. The field
    carries no real information — do not build anything on it. Real
    abuse-contact resolution lives in the
    [abuse reporter](../abuse-reporter/index.md).

- **No test suite exists** for this tool, and none should be added without an
  explicit request. A real run needs a reachable CrowdSec instance and a live
  backend, so there is no meaningful local smoke test.
- With `METRICS_BACKEND=influxdb2` and `INFLUXDB_USE_HTTPS=true`, each run checks
  TLS against `www.howsmyssl.com`. If that check fails the script asks
  interactively whether to continue; without a terminal (cron) it aborts the run.
  The check does not run for `questdb`.
- The QuestDB backend relies on ILP-over-HTTP to auto-create the table and
  columns on first write. TTL and deduplication are declared *afterwards*; a
  failure there only logs a warning, since the data itself is already stored.

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
    - `setup.conf` creates the venv at `/opt/jobs/crowdsec_influx` and activates
      it via `bin/activate`, not `.venv/bin/activate`, and documents no cron
      entry.

## Documentation

- [Configuration](configuration.md) — every supported variable
- [Per-Event Export](events.md) — the second pass and its cost
- [Metrics Backends](../reference/metrics-backends.md) — deduplication, retention, point schema
- [Grafana Dashboards](../reference/dashboards.md)

!!! important
    crowdsec-metrics-exporter is an independent community project. It is not
    affiliated with, endorsed by, or sponsored by CrowdSec.
