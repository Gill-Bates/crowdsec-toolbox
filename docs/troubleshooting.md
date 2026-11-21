# Troubleshooting

Symptom-driven fixes for both tools. For what "healthy" means, see
[Health Checks](reference/health.md).

## Container start

### "no settings available"

```
2026-11-19 12:13:50 UTC | ERROR    | entrypoint | no settings available.
```

The abuse reporter's entrypoint checks `SMTP_SERVER` and refuses to start without
it. Provide `./settings.env` via Compose's `env_file`, or set the required
variables directly.

### "RUN_INTERVAL must be a positive integer"

The entrypoint validates `RUN_INTERVAL`, `RUN_EVERY_HOUR`,
`METRICS_INTERVAL` and `API_HEARTBEAT_INTERVAL` as integers before any arithmetic
and exits non-zero on bad input. Check for a stray unit suffix — `6h` is not
valid, `6` is. Values above the documented maximum (8760 hours, 31536000 seconds)
are rejected with `must be at most N`.

### Permission errors on the data directory

```
2026-11-19 12:13:50 UTC | WARNING  | entrypoint | chown -R on /data had permission errors (subdirectory with restricted access: /data/old, /data/backup); continuing, the database and heartbeat files are verified after the privilege drop
```

A warning, not a failure. The container drops all capabilities except `CHOWN`,
`SETUID` and `SETGID`, so root in the container cannot enter a subdirectory of
`/data` that belongs to another user and is closed to others (for example a
`0700` directory left by an older image or created on the host). `chown -R`
skips it and names it, up to five paths. The abuse reporter does not use that
subdirectory: its files (`abuse_alerts.db`, its WAL/SHM files, `heartbeat`,
`api_heartbeat`) live directly in `/data`, which stays writable for uid `10001`.

Find the culprit on the host (adjust the bind-mount path):

```sh
find /opt/docker/crowdsec-abuse-reporter/data ! -user 10001 -printf '%u:%g %m %p\n'
```

Then either move the directory out, delete it if it is a stray, or give it to the
app user with `chown -R 10001:10001 <path>`. Leaving it is harmless.

If the data directory itself or the database file is not writable for the app
user, the entrypoint stops with `ERROR | entrypoint | ... is not writable by uid`
and exit code 1. Fix it with `chown -R 10001:10001 <data dir>` on the host.

### The container keeps restarting and the log names a loop

```
2026-11-19 12:13:50 UTC | ERROR    | entrypoint | LAPI heartbeat loop (pid 23) exited unexpectedly (rc=137) — stopping container
```

The abuse reporter treats the LAPI heartbeat loop and, with a metrics backend, the
`metrics` loop as required. When one of these processes dies (for example killed
by the OOM killer), the entrypoint stops all jobs and exits `1`, and
`restart: unless-stopped` starts the container again. Check the host for memory
pressure or a manual `kill`. An unreachable LAPI, SMTP server or metrics backend
does not cause this; it only logs a warning or turns the container `unhealthy`.

### The container exits immediately

Check whether `RUN_ONCE=true` is set. That is one run and exit, by design.

## CrowdSec LAPI

### Connection refused

!!! warning "`127.0.0.1` inside a container is the container"
    `CROWDSEC_LAPI_URL=http://127.0.0.1:8080` points at the container itself. Use
    the CrowdSec container's name on a shared Docker network, or the host's
    address.

### 401 or 403 from the LAPI

The machine ID and password must match a registered watcher. Re-read them from the
host:

```bash
docker exec -it crowdsec cat /etc/crowdsec/local_api_credentials.yaml
```

`login` is the machine ID. For the exporter, note that a password containing CR,
LF or NUL is rejected outright.

### TLS verification fails

`CROWDSEC_LAPI_VALIDATE_CERTIFICATE` controls verification. The abuse reporter's template
ships `true`. The example LAPI URL uses HTTP and is intended for a trusted private
network; use HTTPS and keep verification enabled when traffic crosses a network
you do not fully trust. The exporter also defaults to `true`.

## DNS and abuse contacts

### Every contact lookup fails

DNS uses the container's system resolver **only** — under Docker usually the
embedded resolver `127.0.0.11`. There is no environment variable to point at a
different resolver and no public fallback. If the embedded resolver cannot reach
the Abusix zone, fix the container's DNS configuration at the Docker level.

Timeouts are `ABUSIX_TIMEOUT` (per query, default `3`) and
`ABUSIX_DNS_LIFETIME` (total, default `5`).

!!! note "A failed lookup does not fail the run"
    Per-report DNS failures still exit `0`. Check the logs or the metrics backend
    rather than the health check.

## Mail delivery

### No mail is sent, but the run succeeds

Work through these in order:

1. `METRICS_ONLY=true` exports points and sends **no mail** by design. The
   container's metrics loop sets it.
2. The ban may already have been reported. The `(AlertId, IPAddress)` pair is
   reported at most once — see [Delivery Guarantees](abuse-reporter/delivery.md).
3. The source ASN may be in `WHITELISTED_ASN`.
4. The contact lookup may have failed for that IP.

### Reports stuck in `pending`, then `unknown_send_state`

Expected after a crash. A `pending` row left by a crash is reaped after
`PENDING_REAP_MINUTES` into the terminal state `unknown_send_state` and is
**never** retried.

!!! danger "This is not a bug to fix"
    The crash may have happened after SMTP accepted the mail. Retrying would send
    a second accusation for the same ban.

### `unknown_send_state` without a crash

A report also ends in `unknown_send_state` when the SMTP connection is lost after
the transfer began: the server may already have accepted the mail,
so the report is recorded as such and **never** re-sent.
If all primary recipients are refused, the report stays `failed` and is retried in
the next run.

### SMTP authentication fails

Authentication requires TLS, which is always on (`SMTP_USE_TLS=false` is rejected at
startup). Set both `SMTP_USERNAME` and `SMTP_PASSWORD`.

### Mails arrive from the wrong identity

Set `HOSTNAME_OVERRIDE`: automatic detection can fall back to a private
container address. See
[Reporting identity](abuse-reporter/configuration.md#reporting-identity).

## Metrics backends

### Points could not be written to the backend

For the **abuse reporter** nothing is lost: the points were spooled to SQLite
before the write was attempted and are re-sent on the next run. The log says so
explicitly, and the run still exits `0`:

```
1 metrics point(s) stay in the outbox and will be retried on the next run (nothing lost)
```

For the **exporter** the run exits `1` and the next run re-sends the same data,
since it re-reads the full decision list every time.

### The abuse reporter exits 1 with a metrics error

Check the log for the cause. If it says `QuestDB dedup ... could not be verified`,
nothing was written and the outbox keeps every point: fix the table (WAL table,
the abuse-report upsert keys; see
[Metrics Backends](reference/metrics-backends.md#questdb)) and the next run sends
the outbox. A `QuestDB TTL ... could not be applied` means the points were
delivered and are not resent.

Otherwise the spool has reached 90% of `METRICS_OUTBOX_MAX_ROWS`, so the next prune would
start discarding points. Fix the backend connectivity; the spool drains by itself
once the backend answers. Raising the bound only buys time.

Inspect the backlog directly:

```bash
sqlite3 docker/data/abuse_alerts.db \
  "SELECT COUNT(*), MIN(created_at), MAX(created_at) FROM metrics_outbox;"
```

### The InfluxDB exporter warns about its connection

Plain HTTP (`INFLUXDB_USE_HTTPS=false`) and `INFLUXDB_VALIDATE_CERTIFICATE=false`
only log a warning; the run continues. The exporter has no TLS self-test and no
prompt, so it behaves the same under cron. A server that rejects the TLS handshake
fails the write and the run exits `1`.

### Unsupported QuestDB version

```text
2026-11-19 12:24:36 UTC | ERROR    | crowdsec_metrics | Unsupported QuestDB version at http://localhost:9000: found 9.3.4, required 10.x; nothing was written
```

Both tools support **QuestDB 10.x only** and check the server with
`SELECT build()` before the first DDL or write. The run exits `1` and nothing is
written. Upgrade the server to 10.x; the next run passes. The reporter keeps every point in its SQLite outbox meanwhile.
Nothing is migrated: data stored by an older server stays with that server. The
check is skipped for `METRICS_BACKEND=influxdb2` and `none`.

### QuestDB version could not be determined

```text
2026-11-20 17:45:00 UTC | ERROR    | crowdsec_metrics | QuestDB version could not be determined at http://metrics.example.com:443 (check host, port, HTTPS setting and credentials); required 10.x; nothing was written
```

The server did not answer `SELECT build()` with a usable version: it is
unreachable, rejected the credentials (HTTP 401/403), answered with an error or
is not a QuestDB `/exec` endpoint. This is a connection problem, not a version
problem. A WARNING `QuestDB version not readable: …` just before names the
cause. A common one is `QUESTDB_USE_HTTPS=false` against a TLS port such as
443; set it to `true`. Nothing is written and the run exits `1` as for an
unsupported version.

### QuestDB startup abort

`QUESTDB_URL` must be a **bare host name** — no scheme, no port, no path. The
scheme comes from `QUESTDB_USE_HTTPS` and the port from `QUESTDB_PORT`.

An unrecognised `METRICS_BACKEND` aborts startup in both tools, an unrecognised
`LOG_LEVEL` in the exporter only.

### Duplicate rows accumulate in QuestDB

The exporter and the abuse reporter verify deduplication before the first write
of each table and write nothing when they cannot (`QuestDB dedup ... could not be verified`, exit
`1`). Duplicates therefore come from rows stored *before* dedup was enabled:
enabling it does not remove them. The exporter logs a warning when it enables
dedup on an existing table. See the
[cleanup runbook](reference/metrics-backends.md#removing-duplicates-stored-before-dedup-was-enabled).
Requirement: a WAL table on QuestDB 10.x. Data stored by an older server is not migrated.

### Two alerts collapsed into one row

Expected for the alert table, whose upsert key cannot be exact: `alert_id` is a
field, not a tag. Two alerts agreeing on host, IP, scenario, AS, country and
timestamp collapse. See
[Metrics Backends](reference/metrics-backends.md#the-alert-tables-key-is-not-exact).

## Grafana

### The dashboard is rejected on import

!!! warning "Grafana 13 is required"
    The dashboards use the v2 schema (`dashboard.grafana.app/v2`), which Grafana
    validates against its CUE definition on import. An older release rejects them
    outright.

### "Top Endpoints" / "Top Target FQDNs" report an unknown table

The events table does not exist until `EVENTS_ENABLED=true` has written once. If
you set a custom `EVENTS_TABLE` that does not follow the
`<QUESTDB_TABLE>_events` pattern, adjust those two queries.

### A host disappears when selected

Points written before the `host` tag was added do not carry it and do not appear
under a host filter.

### Country flags render as boxes

Rendering requires an emoji-capable browser or system font. Unknown values and the
non-country codes `AP`/`ZZ` display as 🌐 by design.

### The map is blank or stays dark in light mode

The basemap is Esri's Dark Gray Canvas, so the browser must reach
`services.arcgisonline.com`. It staying dark in Grafana's light theme is a known
tradeoff — see [Grafana Dashboards](reference/dashboards.md#the-map-basemap).

## GeoIP

### The whitelist table shows `unknown` providers

Provider names come from the local GeoLite2 ASN database; a single `unknown`
means the ASN is not in it, see
[Never-report list](abuse-reporter/configuration.md#never-report-list).

If *every* entry reads `unknown`, the ASN database is not being read at all —
check that the GeoIP step reported `GeoIP databases ready (City + ASN)` and that
`GEOIP_DIR` points where the entrypoint seeded the baseline.

### Enrichment is empty on a fresh container

The entrypoint seeds the databases from the image baseline at
`/opt/geoip-baseline`. If it warns that no baseline exists, the first run depends
on the update check reaching the mirror.

A GeoIP **cold start** with no usable database is a hard failure and exits `1`.

### The databases never get newer

!!! note "Rebuild the image to move the baseline forward"
    The runtime copy lives on tmpfs and is discarded on container stop, so every
    start begins from the image baseline and re-checks the mirror. See
    [GeoIP Databases](abuse-reporter/geoip.md).

### Leftover `data/geolite2` after upgrading

Direct host runs used that layout. After moving to a container deployment the
directory is leftover and can be deleted.

## Development

### `pip install --group` is not recognised

pip 25.1 or newer is required for PEP 735 groups. Upgrade pip inside the venv.

### `zensical build --strict` fails

Usually a broken internal link, or a new page missing from the `nav` in
`zensical.toml`. Run the clean strict build from the repository root:

```bash
zensical build --config-file zensical.toml --strict --clean
```
