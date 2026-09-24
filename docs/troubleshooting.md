# Troubleshooting

Symptom-driven fixes for both tools. For what "healthy" means, see
[Health Checks](reference/health.md).

## Container start

### "no settings available"

```
[entrypoint] ERROR: no settings available.
```

The abuse reporter's entrypoint checks `SMTP_SERVER` and refuses to start without
it. Provide `./settings.env` via Compose's `env_file`, or set the required
variables directly.

### "RUN_JITTER must be a non-negative integer"

The entrypoint validates `RUN_INTERVAL`, `RUN_EVERY_HOUR`, `RUN_JITTER`,
`METRICS_INTERVAL` and `API_HEARTBEAT_INTERVAL` as integers before any arithmetic
and exits non-zero on bad input. Check for a stray unit suffix — `6h` is not
valid, `6` is.

### Permission errors on the data directory

```
[entrypoint] WARNING: chown -R on /data had permission errors
```

A warning, not a failure. The entrypoint chowns the top-level data directory
unconditionally and descends best-effort, because a subdirectory with restrictive
host permissions is not readable even by root under `-R`. If the application then
cannot write, fix the host ownership of `docker/data/` to uid/gid `10001`.

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

`CROWDSEC_LAPI_VERIFY_TLS` controls verification. The abuse reporter's template
ships `false` for a plain-HTTP LAPI on a trusted network; the exporter defaults to
`true`.

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

### SMTP authentication fails

Authentication requires TLS. Set both `SMTP_USERNAME` and `SMTP_PASSWORD`, and
leave `SMTP_USE_TLS=true`.

### Mails arrive from the wrong identity

!!! warning "Set `HOSTNAME_OVERRIDE` in a container"
    Left empty, autodetection falls back to the private container IP unless
    `PUBLIC_IP_DETECTION` resolves a WAN address. `HOSTNAME_OVERRIDE` is the
    supported way to keep the reported identity stable.

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

The spool has reached 90% of `METRICS_OUTBOX_MAX_ROWS`, so the next prune would
start discarding points. Fix the backend connectivity; the spool drains by itself
once the backend answers. Raising the bound only buys time.

Inspect the backlog directly:

```bash
sqlite3 docker/data/abuse_alerts.db \
  "SELECT COUNT(*), MIN(created_at), MAX(created_at) FROM metrics_outbox;"
```

### The exporter hangs or aborts under cron

!!! warning "The external TLS check needs a terminal"
    With `METRICS_BACKEND=influxdb2` and `INFLUXDB_USE_HTTPS=true`, each run checks
    TLS against `www.howsmyssl.com`. On failure it asks interactively whether to
    continue; without a terminal it aborts the run. The check does not run for
    `questdb`.

### QuestDB startup abort

`QUESTDB_URL` must be a **bare host name** — no scheme, no port, no path. The
scheme comes from `QUESTDB_USE_HTTPS` and the port from `QUESTDB_PORT`.

`METRICS_BACKEND` and `LOG_LEVEL` also abort at startup on an unrecognised value.

### Duplicate rows accumulate in QuestDB

Deduplication is declared after each write with
`ALTER TABLE ... DEDUP ENABLE UPSERT KEYS(...)`, and a failure there only logs a
**warning** — the rows are stored either way. Check the logs for that warning and
confirm QuestDB 7.3+ with a WAL table.

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

Provider names come from the local GeoLite2 ASN database. The table is printed
after the GeoIP step, so the database is present by then and `unknown` means the
ASN genuinely is not in it.

If *every* entry reads `unknown`, the ASN database is not being read at all —
check that the GeoIP step reported `✓ GeoIP databases ready (City + ASN)` and that
`GEOIP_DIR` points where the entrypoint seeded the baseline.

!!! note "This used to be an ordering bug"
    Earlier versions printed the table with the rest of the startup
    configuration, before the databases were ensured, so a cold start listed every
    entry as `unknown`. Guarded by
    `WhitelistAsnTableOrderTest` in `tests/test_main.py`.

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

### One pytest test always fails locally

`test_entrypoint_rejects_non_integer_run_jitter` fails on any host without `gosu`
and the `app` user. The baseline is 124 passed, 1 failed; any *other* failure is a
real regression. See [Testing](development/testing.md).

### `mkdocs build --strict` fails

Usually a broken internal link, or a new page missing from the `nav` in
`docs/mkdocs.yml`.
