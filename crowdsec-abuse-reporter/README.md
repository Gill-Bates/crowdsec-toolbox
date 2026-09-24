# crowdsec-abuse-reporter

Turns CrowdSec bans into abuse reports. It fetches decisions from the CrowdSec
Local API (LAPI), enriches each source IP with GeoIP data when the databases are
available, resolves the abuse contact via the Abusix DNS contact database, and
emails an X-ARF v4 report. Every `(AlertId, IPAddress)` pair is recorded in
SQLite, so the same ban is reported at most once for each source IP.

Because the tool talks to the LAPI directly, the container needs no access to
`/var/run/docker.sock`.

## Docker Artifacts

The `docker/` directory contains:

- `Dockerfile`: builds the runtime image
- `docker-compose.yml`: runs the service from this directory
- `entrypoint.sh`: periodic or one-shot execution inside the container
- `settings.env.example`: the only tracked template, for `docker/settings.env` (next to `docker-compose.yml`)

## Usage

```bash
cd /opt/python/crowdsec_abuse_reporter/docker   # deployment path, see setup.conf
cp settings.env.example settings.env
# edit settings.env
docker compose pull && docker compose up -d
```

`docker-compose.yml` uses the prebuilt image from the registry. The image is
built and pushed with `docker buildx build` from the repository root (see
`setup.conf`); dependencies come from the `default` group in this tool's own
`pyproject.toml`.

The build reads the application version from this tool's own `pyproject.toml` and embeds it
with the current Git commit hash. Both values appear in the startup banner and
the image's OCI metadata.

The Compose service sends abuse mail every six hours by default (`RUN_EVERY_HOUR=6`). When metrics are enabled, snapshots are written every minute (`METRICS_INTERVAL=60`) without sending mail. Both intervals are overridable with `RUN_INTERVAL`, `RUN_EVERY_HOUR` or `METRICS_INTERVAL`.
with up to five minutes of random jitter after each run. Set `RUN_ONCE=true` or
override the scheduling variables in the Compose file for a different mode.

The application runs as the non-root user `app` (uid/gid `10001`). `./data`
must be owned by this user, otherwise writing the database, heartbeat files
and GeoIP databases fails with a permission error. No manual `chown` is
needed: the container starts as root, `entrypoint.sh` fixes the ownership of
`./data` once and then switches permanently to `app` via `gosu` before any
application code runs, even if Docker creates `./data` as root on first start.
For this, `cap_add: [CHOWN, SETUID, SETGID]` in `docker-compose.yml` restores
exactly the three capabilities that `cap_drop: [ALL]` would otherwise remove.

## Persistent Data

The compose stack reads `./settings.env` and writes all other mutable data to
`./data/`, both relative to `docker/` (i.e. `docker/settings.env` and
`docker/data/`):

- `abuse_alerts.db` (also the default location for direct host runs)
- `heartbeat`
- `api_heartbeat`

### GeoLite2 databases

The image ships the GeoLite2 City and ASN databases as a build-time baseline in
`/opt/geoip-baseline`. At container start the entrypoint copies them into
`GEOIP_DIR` (`/tmp/geoip`, a tmpfs), so enrichment works from the first run
without waiting for a download and the databases never occupy a persistent
volume. `app/geoip.py` then checks the mirror — conditionally, via
`If-Modified-Since` derived from the MMDB build epoch — and overwrites the
tmpfs copy when a newer release exists.

Consequences worth knowing:

- The tmpfs copy is discarded on container stop, so every start begins from the
  image baseline and re-checks the mirror. Rebuild the image to move the
  baseline forward.
- The databases live in RAM: roughly 78 MB (City ~66 MB, ASN ~12 MB), which is
  why Compose gives `/tmp/geoip` a 256 MB tmpfs — an update writes a temporary
  file before replacing the target, so the peak exceeds the resident size.
- Direct host runs keep the previous layout under `data/geolite2`. After
  upgrading a container deployment, the old `./data/geolite2` directory is
  leftover and can be deleted.

## Configuration

Copy `settings.env.example` and set the CrowdSec LAPI URL, machine ID and
password, plus the SMTP server and sender address. If SMTP authentication is
used, set both `SMTP_USERNAME` and `SMTP_PASSWORD`; authentication requires
TLS. `CROWDSEC_LAPI_CREDENTIALS_PATH` is an optional fallback for direct host
runs when the LAPI credentials are not supplied as environment variables.

`SETTINGS_PATH` points at an env file other than the default
`<project root>/settings.env`, e.g. one of the site-specific `settings-*.env`
profiles. Unlike `crowdsec-metrics-exporter`, the file is loaded with
`override=False`, so an existing environment variable wins over the file.

### Metrics backend (optional)

`METRICS_BACKEND` selects an optional time-series output, using the same
variables as `crowdsec-metrics-exporter`: `none` (default), `influxdb2`
(`INFLUXDB_*`, token required) or `questdb` (`QUESTDB_*`). Each sent or failed
report becomes one line-protocol point with the tags `ip_address`,
`scenario`, `status`, `country`, `as_number`, `as_name` (and `host`) and the
fields `alert_id`, `abuse_email`, `processing_time` and `error_message`.

`METRICS_ONLY=true` exports the current CrowdSec decisions as points with
`status=observed` and sends **no mail**. The container entrypoint uses it for
the separate `METRICS_INTERVAL` loop, so snapshots can be written every minute
while reports still go out on the `RUN_EVERY_HOUR` schedule. Each snapshot run
writes one point per active decision, so the point count grows with the ban
duration divided by `METRICS_INTERVAL`.

With a backend enabled, SQLite holds **control data only**, so no report data
is stored twice:

| SQLite data | `none` | `influxdb2` / `questdb` |
|-------------|--------|-------------------------|
| `abuse_alerts` claim row: `AlertId`, `IPAddress`, `Status`, timestamps | yes | yes — required for at-most-once delivery |
| `abuse_alerts.Recipient`, `Scenario`, `ErrorMessage` | yes | empty |
| `abuse_contacts_cache` | yes | yes |
| `run_state` (last run start/end, exit code, backend) | yes | yes |

With `questdb`, `QUESTDB_TTL` (default `365d`; `12w`, `6M`, `1y`, `48h`, `0` = off)
is applied after each write via `ALTER TABLE ... SET TTL` (QuestDB 8.3+). A
failure only logs a warning.

Both backends also deduplicate the report points, so re-writing a batch updates
rows instead of appending copies. For InfluxDB 2.x that is inherent: a point
repeating an existing series and timestamp overwrites it. For QuestDB it is
declared after each write with
`ALTER TABLE ... DEDUP ENABLE UPSERT KEYS("timestamp", "host", "ip_address", "scenario", "status", "country", "as_number", "as_name")`
(QuestDB 7.3+, idempotent, failure only warns). Those are exactly the tag
columns of a point — `alert_id` is a field and cannot be an upsert key.

**This does not replace the SQLite claim protocol.** Deduplication makes
*storage* idempotent. It cannot decide whether a mail may be sent: that
decision happens before the write and needs the atomic compare-and-set in
`claim_alert_for_send()`. The claim row stays mandatory in every mode.

All points of a run are written in one request at the end of the run, even
after an interrupt. Points are spooled to the SQLite table `metrics_outbox`
**before** the write is attempted and removed only once the backend
acknowledged them, so an unreachable backend defers them to the next run
instead of losing them — the mails have already gone out at that point, so
they are never resent either way. The flush also runs at the start of a run, so
a backend that came back is drained even when there is nothing new to report.

Replaying the spool is safe because it is exactly idempotent: the timestamp is
part of the point and of the dedup key set, so a point the backend already holds
collapses onto the same row. There is therefore no need to determine which point
of a failed batch was rejected — the spool is replayed in full.

`METRICS_WRITE_RETRIES` (default `2`, spaced by `METRICS_RETRY_BACKOFF * 2ⁿ`
seconds) resolves a transport blip inside the run; an HTTP status is never
retried. `METRICS_OUTBOX_MAX_ROWS` (default `50000`) and
`METRICS_OUTBOX_MAX_AGE_DAYS` (default `30`) bound the spool, dropping oldest
first. A deferred batch is a warning and the run still exits `0`; once the spool
reaches 90% of the row bound the run exits `1`, because the next prune would
start discarding points.

The `METRICS_ONLY` snapshot loop is deliberately not spooled: it writes one point
per active decision every `METRICS_INTERVAL` seconds and would dominate the
database during an outage, and the next snapshot supersedes it anyway.

The tracked Compose file uses a plain bridge network. The container needs to
reach the CrowdSec LAPI, your SMTP server and the Abusix DNS zone from there;
attach it to an existing Docker network, and pin an address, if your setup
requires it. `HOSTNAME_OVERRIDE` is the supported way to keep the reported
node identity stable regardless of the container's address.

The container reports healthy only while both the main-run heartbeat and the
LAPI heartbeat are fresh.

## Grafana

`grafana/` holds this tool's dashboards, using the v2 dashboard schema
(`dashboard.grafana.app/v2`) and targeting Grafana 13:

- `dashboard_questdb.json` — QuestDB SQL via the
  [QuestDB data source plugin](https://grafana.com/grafana/plugins/questdb-questdb-datasource/).
  Variables: `datasource`, `host`, plus a hidden `table` (`QUESTDB_TABLE`,
  default `crowdsec-abuse`) — that one is deployment configuration, not a
  filter. `host` is multi-select with an **All** option, matched NULL-safely so
  points predating the `host` tag group under `(unknown)`. Panels: a compact KPI
  header (sent, failed, success rate, total reports), a full-width unstacked
  daily chart, then top recipients as plain horizontal bars beside a donut of
  the top origin countries, and a paginated table of the latest 100 reports.
  Country codes render as flag emoji (AP/ZZ and unknown as 🌐), the same logic
  the metrics dashboard uses. Colour is semantic only: green for delivered, red
  for failed, neutral palettes for plain distributions.
- `dashboard_influxdb2.json` — placeholder, not yet built.

## Notes

- The CrowdSec connection requires `CROWDSEC_LAPI_URL`, `CROWDSEC_LAPI_MACHINE_ID`
  and `CROWDSEC_LAPI_PASSWORD`. Outside Docker, the tool can instead read the
  default file `/etc/crowdsec/local_api_credentials.yaml`.
- All secrets, including `SMTP_PASSWORD`, are read as plaintext from
  `settings.env` (or the Docker `env_file`).
- Docker reads `./settings.env` via `env_file`; the file is not bind-mounted
  into the container.
- Compose mounts the Docker host's `/etc/hostname` read-only at
  `/run/host/hostname` for the `host` tag in InfluxDB and QuestDB metrics. The
  E-mail reporting identity remains controlled by `HOSTNAME_OVERRIDE` or
  public-IP detection.
- DNS uses only the system resolver inside the container. Under Docker this is
  usually the embedded resolver `127.0.0.11`; there is no extra environment
  variable and no public resolver fallback.
- The build deliberately copies only runtime files and no local secrets into
  the image.
- The compose stack uses `read_only`, `cap_drop: [ALL]`, `no-new-privileges`
  and a `tmpfs` for `/tmp` as defense in depth.
- The build must run from the repository root with
  `-f crowdsec-abuse-reporter/docker/Dockerfile` (see `setup.conf`); running
  `docker build .` directly in `docker/` is intentionally unsupported.

## Disclaimer

crowdsec-abuse-reporter is an independent community project. It is not affiliated with,
endorsed by, or sponsored by CrowdSec.
