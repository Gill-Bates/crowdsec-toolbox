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
| `CROWDSEC_LAPI_VALIDATE_CERTIFICATE` | `true` | Verify the LAPI TLS certificate |
| `CROWDSEC_LAPI_TIMEOUT` | `30` | Request timeout in seconds, a finite number; values below `1` are raised to `1`. Unset or empty uses the default; a set but unparsable value, zero, a negative value, `nan` or `inf` aborts the run with a `Config Error` (exit `1`) |
| `CROWDSEC_ALERT_LIMIT` | `10000` | Starting limit per LAPI call, an integer of at least `1`; any other set value aborts with a `Config Error`. A response that fills the limit is requested again with a tenfold limit, up to `max(100000, CROWDSEC_ALERT_LIMIT)`; if the response at that ceiling is still full, completeness cannot be proven: a warning is logged, the alerts retrieved so far are exported, and the run exits `1` |

## General

| Variable | Default | Description |
|---|---|---|
| `METRICS_BACKEND` | `influxdb2` | `influxdb2` or `questdb`; any other value aborts at startup |
| `HOSTNAME_OVERRIDE` | system hostname | Overrides the source host name. InfluxDB uses it as the measurement, QuestDB as the `host` tag. |
| `REQUEST_TIMEOUT` | `30` | Write timeout in seconds, both backends; an integer greater than `0`. Unset or empty uses the default; a set but unparsable value, zero or a negative value aborts the run with a `Config Error` (exit `1`) |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`; any other value aborts at startup |

Under Docker the host name is read from the host's `/etc/hostname`, mounted
read-only at `/run/host/hostname`. `HOSTNAME_OVERRIDE` takes precedence.

An invalid integer or `true`/`false` value aborts startup with a `Config Error`
line (exit `1`) instead of falling back to the default.

## InfluxDB 2.x

Used when `METRICS_BACKEND=influxdb2`.

| Variable | Default | Description |
|---|---|---|
| `INFLUXDB_URL` | `localhost` | InfluxDB host, bare host name only; a scheme, port or path aborts with a `Config Error`. Always set it |
| `INFLUXDB_PORT` | `443` | InfluxDB port, an integer from 1 to 65535 |
| `INFLUXDB_USE_HTTPS` | `true` | Use HTTPS for the connection |
| `INFLUXDB_VALIDATE_CERTIFICATE` | `true` | Validate the TLS certificate |
| `INFLUXDB_ORGANIZATION` | `myOrg` | InfluxDB organization |
| `INFLUXDB_BUCKET` | `crowdsec` | Bucket to write points to |
| `INFLUXDB_TOKEN` | — | API token — required, stored in plaintext |

!!! warning "Insecure transport only warns"
    `INFLUXDB_USE_HTTPS=false` and `INFLUXDB_VALIDATE_CERTIFICATE=false` log a
    warning on every run and do not stop it. The exporter contacts no third
    party and never prompts; a TLS handshake the server rejects fails the write
    and exits `1`.

## QuestDB

Used when `METRICS_BACKEND=questdb`. Only **QuestDB 10.x** is supported: the
exporter checks `SELECT build()` before any write and exits `1` for any other
version or when the version cannot be read. Data from older servers is not
migrated.

| Variable | Default | Description |
|---|---|---|
| `QUESTDB_URL` | `localhost` | Bare host name only |
| `QUESTDB_PORT` | `9000` | HTTP port, an integer from 1 to 65535 |
| `QUESTDB_USE_HTTPS` | `false` | Use HTTPS for the connection |
| `QUESTDB_VALIDATE_CERTIFICATE` | `true` | Validate the TLS certificate |
| `QUESTDB_TABLE` | `crowdsec` | Table written to |
| `QUESTDB_TTL` | `365d` | Retention applied after each write; `0` disables. If it cannot be set, the run exits `1` (data kept, not sent again) |
| `QUESTDB_DOWNSAMPLING` | — | Downsampling profile for the alert table: empty (off), `low`, `medium` or `high`; any other value aborts at startup |
| `QUESTDB_TOKEN` | — | Bearer token; takes precedence over username/password |
| `QUESTDB_USERNAME` / `QUESTDB_PASSWORD` | — | HTTP basic auth, used only when `QUESTDB_TOKEN` is unset |

!!! warning "`QUESTDB_URL` must be a bare host name"
    No `https://`, no port, no path. The scheme comes from `QUESTDB_USE_HTTPS`
    and the port from `QUESTDB_PORT`. A value carrying a scheme, port or path
    aborts at startup.

`QUESTDB_TTL` accepts values such as `365d`, `12w`, `6M`, `1y` or `48h`, and is
applied with `ALTER TABLE ... SET TTL` after every successful write.

`QUESTDB_DOWNSAMPLING` trades per-IP detail for a smaller long-term history. See
[Retention and downsampling](../reference/metrics-backends.md#retention) for what
each profile keeps and what it drops.

## Per-event export

| Variable | Default | Description |
|---|---|---|
| `EVENTS_ENABLED` | `false` | Enable the second, per-event pass; only `true` or `false` (case-insensitive, surrounding whitespace ignored), anything else aborts with a `Config Error`. The container entrypoint applies the same trim and case-insensitive match for its `EVENTS_SINCE` warning |
| `EVENTS_TABLE` | `<QUESTDB_TABLE>_events` | Table/measurement for event points |
| `EVENTS_SINCE` | `30m` | Window for the LAPI `since` parameter, e.g. `2h`, `1d` |

See [Per-Event Export](events.md) before enabling this — the write amplification
and table growth are substantial.

## Container scheduling

Read by `docker/entrypoint.sh` and the image's health check, not by the
application. A direct host run has no entrypoint and ignores them.
`RUN_ONCE` and `RUN_INTERVAL` are set in `docker/settings.env.example`;
`RUN_EVERY_HOUR` and `HEALTHCHECK_MAX_AGE_SECONDS` appear there only as comments.

| Variable | Default | Description |
|---|---|---|
| `RUN_ONCE` | `false` | Perform one export and exit |
| `RUN_EVERY_HOUR` | — | Interval in hours (1 to 8760); takes precedence over `RUN_INTERVAL` |
| `RUN_INTERVAL` | `60` | Interval in seconds (1 to 31536000) |
| `HEALTHCHECK_MAX_AGE_SECONDS` | `max(900, RUN_INTERVAL + max jitter + 300)` | Heartbeat staleness limit; a value below that minimum for the schedule stops the entrypoint |

Jitter is automatic: up to `min(RUN_INTERVAL / 10, 300)` seconds per run plus a
random start offset of the same size. With
`EVENTS_ENABLED=true`, keep `EVENTS_SINCE` longer than the interval plus that
jitter; the entrypoint warns otherwise.

## Secrets

!!! danger
    `CROWDSEC_LAPI_PASSWORD`, `INFLUXDB_TOKEN` and the QuestDB credentials are
    read as plaintext from `settings.env`. The file is gitignored and must never
    be committed.
