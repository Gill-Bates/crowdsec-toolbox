# Metrics Exporter Configuration

Configuration is read from `settings.env` when present. Environment variables are
also supported.

!!! warning "Precedence: the file wins"
    `app.config` loads `settings.env` at import time with `override=True`, so
    values in the file override an existing environment variable. This is the
    opposite of the [abuse reporter](../abuse-reporter/configuration.md).

## CrowdSec LAPI

| Variable | Default | Description |
|---|---|---|
| `CROWDSEC_LAPI_URL` | falls back to the credentials file, then `http://127.0.0.1:8080` | LAPI base URL |
| `CROWDSEC_LAPI_MACHINE_ID` | — | Watcher machine ID (`login` in CrowdSec's credentials file) |
| `CROWDSEC_LAPI_PASSWORD` | — | Watcher password; plaintext, and rejected if it contains CR, LF or NUL |
| `CROWDSEC_LAPI_CREDENTIALS_PATH` | `/etc/crowdsec/local_api_credentials.yaml` | Fallback credentials file for direct host runs |
| `CROWDSEC_LAPI_VERIFY_TLS` | `true` | Verify the LAPI TLS certificate |
| `CROWDSEC_LAPI_TIMEOUT` | `30` | Request timeout in seconds, minimum `1` |
| `CROWDSEC_ALERT_LIMIT` | `10000` | Maximum alerts requested per LAPI call |

## General

| Variable | Default | Description |
|---|---|---|
| `METRICS_BACKEND` | `influxdb2` | `influxdb2` or `questdb`; any other value aborts at startup |
| `HOSTNAME_OVERRIDE` | system hostname | Overrides the source host name. InfluxDB uses it as the measurement, QuestDB as the `host` tag. |
| `REQUEST_TIMEOUT` | `30` | Write timeout in seconds, both backends |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`; any other value aborts at startup |

Under Docker the host name is read from the host's `/etc/hostname`, mounted
read-only at `/run/host/hostname`. `HOSTNAME_OVERRIDE` takes precedence.

## InfluxDB 2.x

Used when `METRICS_BACKEND=influxdb2`.

| Variable | Description |
|---|---|
| `INFLUXDB_URL` | InfluxDB host |
| `INFLUXDB_PORT` | InfluxDB port |
| `INFLUXDB_USE_HTTPS` | Use HTTPS for the connection |
| `INFLUXDB_VALIDATE_CERTIFICATE` | Validate the TLS certificate |
| `INFLUXDB_ORGANIZATION` | InfluxDB organization |
| `INFLUXDB_BUCKET` | Bucket to write points to |
| `INFLUXDB_TOKEN` | API token — required, stored in plaintext |

!!! warning "The external TLS check"
    With `INFLUXDB_USE_HTTPS=true`, each run verifies TLS against
    `www.howsmyssl.com`. On failure the script asks interactively whether to
    continue; without a terminal, such as under cron, it aborts the run. This
    check does not run for QuestDB.

## QuestDB

Used when `METRICS_BACKEND=questdb`.

| Variable | Default | Description |
|---|---|---|
| `QUESTDB_URL` | — | Bare host name only |
| `QUESTDB_PORT` | `9000` | HTTP port |
| `QUESTDB_USE_HTTPS` | `false` | Use HTTPS for the connection |
| `QUESTDB_VALIDATE_CERTIFICATE` | `true` | Validate the TLS certificate |
| `QUESTDB_TABLE` | `crowdsec` | Table written to |
| `QUESTDB_TTL` | `365d` | Retention applied after each write; `0` disables |
| `QUESTDB_TOKEN` | — | Bearer token; takes precedence over username/password |
| `QUESTDB_USERNAME` / `QUESTDB_PASSWORD` | — | HTTP basic auth, used only when `QUESTDB_TOKEN` is unset |

!!! danger "`QUESTDB_URL` must be a bare host name"
    No `https://`, no port, no path. The scheme comes from `QUESTDB_USE_HTTPS`
    and the port from `QUESTDB_PORT`. A value carrying a scheme, port or path
    aborts at startup.

`QUESTDB_TTL` accepts values such as `365d`, `12w`, `6M`, `1y` or `48h`, and is
applied with `ALTER TABLE ... SET TTL` after every successful write (QuestDB
8.3+). A failure only logs a warning.

## Per-event export

| Variable | Default | Description |
|---|---|---|
| `EVENTS_ENABLED` | `false` | Enable the second, per-event pass |
| `EVENTS_TABLE` | `<QUESTDB_TABLE>_events` | Table/measurement for event points |
| `EVENTS_SINCE` | `30m` | Window for the LAPI `since` parameter, e.g. `2h`, `1d` |

See [Per-Event Export](events.md) before enabling this — the write amplification
and table growth are substantial.

## Container scheduling

Read by `docker/entrypoint.sh`, not by the application, so they appear only in
`docker/settings.env.example`. A direct host run has no entrypoint and ignores
them.

| Variable | Default | Description |
|---|---|---|
| `RUN_ONCE` | `false` | Perform one export and exit |
| `RUN_EVERY_HOUR` | — | Interval in hours; takes precedence over `RUN_INTERVAL` |
| `RUN_INTERVAL` | `60` | Interval in seconds |
| `RUN_JITTER` | `0` | Random delay after each run, in seconds |
| `HEALTHCHECK_MAX_AGE_SECONDS` | `900` | Heartbeat staleness limit |

## Secrets

!!! danger
    `CROWDSEC_LAPI_PASSWORD`, `INFLUXDB_TOKEN` and the QuestDB credentials are
    read as plaintext from `settings.env`. The file is gitignored and must never
    be committed.
