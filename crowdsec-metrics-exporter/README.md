# crowdsec-metrics-exporter

Exports CrowdSec ban decisions as time series to InfluxDB 2.x or QuestDB.

It reads the alerts behind the currently active decisions from the CrowdSec
Local API (LAPI) over HTTP, authenticating as a registered machine, and writes
them to the configured backend on every run. It needs **no** access to the
Docker socket. The exporter keeps no local state: both backends deduplicate rows, so
re-sending data that is already stored is a no-op (see
[Deduplication](#deduplication)).

The write backend is selected via `METRICS_BACKEND` (`influxdb2`, the
default, or `questdb`). Both backends receive the same InfluxDB Line
Protocol payload over HTTP(S); QuestDB accepts it on its own `/write` endpoint
and auto-creates the target table and columns on first write.

## Requirements

- A CrowdSec instance whose Local API is reachable over HTTP, plus watcher
  credentials (machine ID and password)
- An InfluxDB 2.x write endpoint, or a QuestDB instance with ILP-over-HTTP
  enabled (default port `9000`)
- Python 3.13+ with this tool's `default` dependency group installed
  (`requests`, `urllib3`, `httpx`) — `setup.conf` does that, see below

## Setup

```bash
cd crowdsec-metrics-exporter
source setup.conf    # venv at /opt/jobs/crowdsec_influx + deps (needs pip >= 25.1)
cp docker/settings.env.example settings.env   # the only tracked template
# edit settings.env with your CrowdSec and InfluxDB/QuestDB connection details
# (RUN_* entries apply to the container entrypoint only and are ignored here)
python main.py
```

`setup.conf` creates and activates the virtual environment and installs the
`default` group from this tool's own `pyproject.toml`. There is no root
manifest — every component in this repository owns its own. It must be
`source`d: running it with `bash` would activate the venv in a subshell only.

## Configuration

Configuration is read from `settings.env` when present. Environment variables
are also supported, and values in `settings.env` override them:

| Variable | Description |
|----------|-------------|
| `CROWDSEC_LAPI_URL` | LAPI base URL, e.g. `http://127.0.0.1:8080`. Falls back to the credentials file, then `http://127.0.0.1:8080` |
| `CROWDSEC_LAPI_MACHINE_ID` | Watcher machine ID (`login` in CrowdSec's credentials file) |
| `CROWDSEC_LAPI_PASSWORD` | Watcher password — plaintext in `settings.env`; rejected if it contains CR/LF/NUL |
| `CROWDSEC_LAPI_CREDENTIALS_PATH` | Fallback credentials file for direct host runs (default `/etc/crowdsec/local_api_credentials.yaml`) |
| `CROWDSEC_LAPI_VERIFY_TLS` | Verify the LAPI TLS certificate (default `true`) |
| `CROWDSEC_LAPI_TIMEOUT` | LAPI request timeout in seconds (default `30`, minimum `1`) |
| `CROWDSEC_ALERT_LIMIT` | Maximum alerts requested per LAPI call (default `10000`) |
| `HOSTNAME_OVERRIDE` | Overrides the source host name. Docker reads `/etc/hostname` from the host; direct runs use the system hostname. InfluxDB uses it as the measurement, QuestDB as the `host` tag. |
| `REQUEST_TIMEOUT` | Write timeout in seconds, both backends (default `30`) |
| `METRICS_BACKEND` | `influxdb2` (default) or `questdb`; any other value aborts at startup |
| `LOG_LEVEL` | `DEBUG`, `INFO` (default), `WARNING` or `ERROR`; any other value aborts at startup |
| `INFLUXDB_URL` | InfluxDB host |
| `INFLUXDB_PORT` | InfluxDB port |
| `INFLUXDB_USE_HTTPS` | Use HTTPS for the InfluxDB connection |
| `INFLUXDB_VALIDATE_CERTIFICATE` | Validate the InfluxDB TLS certificate |
| `INFLUXDB_ORGANIZATION` | InfluxDB organization |
| `INFLUXDB_BUCKET` | InfluxDB bucket to write points to |
| `INFLUXDB_TOKEN` | InfluxDB API token — stored in plaintext in `settings.env` |
| `QUESTDB_URL` | QuestDB host (used when `METRICS_BACKEND=questdb`). Bare host name only — no `https://`, no port, no path; the scheme comes from `QUESTDB_USE_HTTPS` and the port from `QUESTDB_PORT`. A value with a scheme, port or path aborts at startup. |
| `QUESTDB_PORT` | QuestDB HTTP port (default `9000`) |
| `QUESTDB_USE_HTTPS` | Use HTTPS for the QuestDB connection |
| `QUESTDB_VALIDATE_CERTIFICATE` | Validate the QuestDB TLS certificate |
| `QUESTDB_TABLE` | QuestDB table name written to (default `crowdsec`) |
| `QUESTDB_TTL` | Retention set on the table after each write via `ALTER TABLE ... SET TTL` (QuestDB 8.3+): `365d` (default), `12w`, `6M`, `1y`, `48h`; `0` disables. A failure only logs a warning. |
| `QUESTDB_TOKEN` | QuestDB bearer token, if configured; takes precedence over username/password |
| `QUESTDB_USERNAME` / `QUESTDB_PASSWORD` | QuestDB HTTP basic auth, used only if `QUESTDB_TOKEN` is unset |
| `EVENTS_ENABLED` | Enable the per-event export (default `false`), see below |
| `EVENTS_TABLE` | Table/measurement for event points (default `<QUESTDB_TABLE>_events`) |
| `EVENTS_SINCE` | Window for the LAPI `since` parameter, e.g. `30m` (default), `2h`, `1d` |

### Per-event export

The default export writes one point per alert, which carries only aggregate
information. With `EVENTS_ENABLED=true`, a second pass reads
`GET /v1/alerts?since=<EVENTS_SINCE>` and writes one point per *event* into
`EVENTS_TABLE`. Whether that response already embeds `events[]` depends on the
CrowdSec version, so alerts that arrive without them are enriched individually
via `GET /v1/alerts/{id}`. The event `meta` blocks are what carry
the request details:

| Column | Source meta key | Kind |
|--------|-----------------|------|
| `host`, `ip_address`, `scenario` | host identity, `source_ip`, alert scenario | tag |
| `alert_id` | alert `id` | tag |
| `event_seq` | event's index inside its alert | tag |
| `http_verb`, `http_status`, `target_fqdn`, `target_technology`, `target_user`, `service` | same-named meta keys | tag |
| `http_path` | `http_path` | string field |

`http_path` is a field rather than a tag because scan paths are effectively
unbounded and QuestDB `SYMBOL` columns are a poor fit for high cardinality.
ASN and geo data are not duplicated per event — join on `alert_id` against the
alert table instead.

Every run re-sends the whole `EVENTS_SINCE` window; the backend discards what
it already has. Keep the window well above the export interval so nothing
falls between two runs, but be aware that window ÷ interval is the write
amplification: with a 60 s interval and a 30 m window each event is sent
about 30 times before it ages out.

Two caveats. The written volume grows with the number of events per alert — a
single HTTP scan easily produces hundreds — so the events table grows much
faster than the alert table; set `QUESTDB_TTL` accordingly. And `target_user`
only appears for scenarios that parse authentication logs (e.g.
`crowdsecurity/sshd`); with HTTP-only scenarios the column stays empty.
Requested paths are stored verbatim, so a credential or token that a scanner
happens to put in a URL is stored with it.

## Running

Run `python main.py` on a schedule (e.g. cron). Each run fetches the current
decision list and writes all of it to the configured backend. A failed send
needs no special handling: the next run sends the same data again, and
deduplication keeps the result identical.

### Deduplication

The exporter is idempotent by relying on the backend instead of a local
watermark, which is why it needs no database and no persistent volume.

For **InfluxDB 2.x** this is inherent: a point that repeats an existing
series (measurement + tag set) at the same timestamp overwrites it rather
than adding a row. No configuration is required.

For **QuestDB** it must be declared, because ILP auto-creates tables as
append-only. After every successful write the exporter issues
`ALTER TABLE ... DEDUP ENABLE UPSERT KEYS(...)`, which is idempotent. This
needs **QuestDB 7.3+** and a WAL table (ILP tables are WAL). Failure only
logs a warning — the rows are stored either way, but duplicates would then
accumulate. The key sets are:

| Table | Keys | Identity |
|-------|------|----------|
| alerts (`QUESTDB_TABLE`) | `timestamp`, `host`, `ip_address`, `as_name`, `as_number`, `country`, `scenario` | the tag columns, i.e. the same identity InfluxDB derives from its series |
| events (`EVENTS_TABLE`) | `timestamp`, `alert_id`, `event_seq` | exact: `event_seq` is the event's index inside its alert, which the LAPI returns in a stable order |

The alert table has no exact key available — `alert_id` is a field, not a
tag, and QuestDB upsert keys must be columns of the row identity. Two
distinct alerts for the same host, IP, scenario, AS and country carrying the
same timestamp would therefore collapse into one row. In practice alerts
that agree on all of those are the same alert; the case that looks similar —
one IP triggering several scenarios in the same second — differs in
`scenario` and is preserved.

## Docker

A container build lives in `docker/` (`Dockerfile`, `docker-compose.yml`,
`entrypoint.sh`, `settings.env.example`); see `docker/AGENTS.md` for the full
rationale. Summary:

- `main.py` is one-shot; `entrypoint.sh` turns it into a periodic job
  (`RUN_INTERVAL`/`RUN_EVERY_HOUR`, `RUN_ONCE`, `RUN_JITTER`, all set in
  `settings.env` rather than in the Compose file), the same
  scheduling model as `crowdsec-abuse-reporter`, adapted from its entrypoint.
- The container mounts **no Docker socket**. Earlier versions ran
  `docker exec <container> cscli ...`, which required socket access —
  equivalent to root on the host. The LAPI path replaces it: the credentials
  are only valid against CrowdSec's API, not the host. The container needs
  network access to the LAPI instead, so place it where that URL resolves.
- The container keeps no state at all. The only runtime file is the heartbeat
  the health check reads, written to the fixed path `/tmp/state` on the
  container's tmpfs — not configurable, since there is nothing to relocate.
  There is no `./data` bind mount and no volume. After
  a restart the container is unhealthy until its first successful export,
  covered by the health check's `--start-period`; previously a stale
  heartbeat could mask a broken start for up to `HEALTHCHECK_MAX_AGE_SECONDS`.
- Compose mounts the host's `/etc/hostname` read-only at
  `/run/host/hostname`. This keeps the host identity stable across container
  recreation. `HOSTNAME_OVERRIDE` takes precedence when set.
- Build from the repository root with the command in the root `setup.conf`.
  It passes `APP_VERSION` from `pyproject.toml` plus the current `GIT_SHA`;
  both values are baked into the image and shown in its startup banner.
- The container's `HEALTHCHECK` checks a heartbeat file that is only updated
  after a successful run (`main.py` exit code `0`), so the container turns
  unhealthy when exports keep failing.

## Grafana

`grafana/` holds one dashboard per backend. Developed and tested against
**Grafana 13** with the v2 dashboard schema (`dashboard.grafana.app/v2`);
Grafana validates the schema on import, so an older release rejects them:

- `dashboard_questdb.json` — QuestDB SQL via the
  [QuestDB data source plugin](https://grafana.com/grafana/plugins/questdb-questdb-datasource/).
  Pick the data source with the `datasource` variable and the table with
  `table` (`QUESTDB_TABLE`, default `crowdsec`); the `host` variable filters
  instances in that table. The `table` picker excludes tables ending in
  `_events`, so the events table cannot be selected as the alert table. Points written before the host tag was added do not
  appear when a host is selected.
  Country labels use flag emoji in panels and the country selector; filter values
  remain the original country codes. Unknown values and the non-country codes
  `AP`/`ZZ` display as 🌐. Rendering requires an emoji-capable browser/system font.
  The SQL converts letters to regional indicators using QuestDB's UTF-16
  `substring` offsets (two code units per indicator), verified with QuestDB 9.4.0.
  Panel queries apply this after aggregation to preserve counts and limits.
  The selector separates display text from filter values using the
  [QuestDB label/value regex pattern](https://questdb.com/docs/cookbook/integrations/grafana/variable-dropdown/).
  The JSON is stored fully expanded (two-space indent), which is what Grafana
  emits on export; an earlier hand-folded variant was replaced by it.
  Grafana validates the v2 spec against its CUE schema on import, so an
  unsupported variable kind or field is rejected outright rather than ignored.
  The map uses a dark basemap: Esri's Dark Gray Canvas via the `esri-xyz` layer
  with a custom URL, which the browser must be able to reach
  (`services.arcgisonline.com`). CARTO's `theme: auto` basemap would follow
  Grafana's light/dark theme automatically but now watermarks unauthenticated
  requests with "API KEY REQUIRED", so it is not used. The consequence is that
  the map stays dark in Grafana's light theme. Note the Esri tile order is
  `{z}/{y}/{x}`; the base layer carries no place labels.
  Markers are coloured by host, and the map, "Alert History by Host" and
  "Event History by Scenario" all use `palette-classic-by-name`: the colour is
  derived from the value, so a host keeps the same colour across panels,
  refreshes and filter changes. With `palette-classic` it would follow the
  position in the result set and shift whenever the host set changes.
  The two panels "Top Endpoints" and "Top Target FQDNs" query
  `"${table}_events"`, i.e. they derive the events table from the `table`
  variable rather than introducing a second one. That matches the default
  `EVENTS_TABLE=<QUESTDB_TABLE>_events`; if you set `EVENTS_TABLE` to a name
  that does not follow this pattern, adjust these two queries. Until
  `EVENTS_ENABLED=true` has written once, the table does not exist and both
  panels report it as unknown. They honour the `host` and `scenario` filters;
  the `country` filter does not apply, since geo data lives on the alert row
  only.
- `dashboard_influxdb2.todo` — placeholder, not yet rebuilt. Named `.todo`
  rather than `.json` since it has no dashboard content yet and would fail
  JSON parsing if something globbed `grafana/*.json`.

## Known Limitations

- Dependency versions are declared in the `default` group of this tool's own
  `pyproject.toml`.
- Credentials and tokens are read from `settings.env` as plain text. Keep that
  file private; it is gitignored and must not be committed.
- `get_abuse_contact()` is a stub that returns a constant placeholder email
  for every IP; the `abuse_email` field in InfluxDB carries no real
  information. Real abuse-contact resolution lives in
  [crowdsec-abuse-reporter](../crowdsec-abuse-reporter/README.md).
- No automated test suite exists for this project.
- The exit code is `0` on success (also when there is nothing to export)
  and `1` when the TLS check, the LAPI fetch or a backend write failed, so
  cron and the container health check can detect failed runs.
- With `METRICS_BACKEND=influxdb2` and `INFLUXDB_USE_HTTPS=true`, each run
  checks TLS against `www.howsmyssl.com`. If that check fails, the script asks
  interactively whether to continue; without a terminal (cron) it aborts the
  run. This check does not run for `METRICS_BACKEND=questdb`.
- The QuestDB backend relies on ILP-over-HTTP to auto-create the table and
  columns on first write. TTL and deduplication are declared afterwards, via
  `ALTER TABLE ... SET TTL` / `... DEDUP ENABLE UPSERT KEYS` on the `/exec`
  SQL endpoint after every successful write (see
  [Deduplication](#deduplication)); a failure there only logs a warning,
  since the data itself is already stored.

## Disclaimer

crowdsec-metrics-exporter is an independent community project. It is not
affiliated with, endorsed by, or sponsored by CrowdSec.
