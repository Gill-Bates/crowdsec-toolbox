# Abuse Reporter Configuration

Configuration comes from environment variables, optionally backed by a
`settings.env` file. Copy `docker/settings.env.example` and fill it in.

!!! note "Precedence: environment wins"
    The file is loaded with `override=False`, so an existing environment variable
    beats the file. This is the opposite of the metrics exporter, whose loader
    uses `override=True`.

    `SETTINGS_PATH` selects a different file than the default
    `<project root>/settings.env` — for example a gitignored `settings-*.env`
    site profile.

!!! warning "`app/config.py` is the authoritative list"
    `settings.env.example` has known drift: `CROWDSEC_LAPI_CREDENTIALS_PATH` is
    supported but appears only as a comment. When the two disagree, the code is
    right.

## CrowdSec LAPI

| Variable | Default | Description |
|---|---|---|
| `CROWDSEC_LAPI_URL` | — | LAPI base URL, e.g. `http://crowdsec:8080` |
| `CROWDSEC_LAPI_MACHINE_ID` | — | Watcher machine ID (`login` in CrowdSec's credentials file) |
| `CROWDSEC_LAPI_PASSWORD` | — | Watcher password, plaintext |
| `CROWDSEC_LAPI_CREDENTIALS_PATH` | `/etc/crowdsec/local_api_credentials.yaml` | Fallback credentials file for host runs |
| `CROWDSEC_LAPI_VERIFY_TLS` | `false` in the template | Verify the LAPI TLS certificate |
| `CROWDSEC_LAPI_TIMEOUT` | `30` | Request timeout in seconds |
| `CROWDSEC_FETCH_ALERT_DETAILS` | `true` | Fetch per-alert details |
| `CROWDSEC_DETAIL_LIMIT` | `500` | Cap on detail fetches |

Either supply the three explicit values, or rely on the credentials file for a
direct host run.

## Reporting identity

| Variable | Default | Description |
|---|---|---|
| `HOSTNAME_OVERRIDE` | — | Public reporting identity used in the abuse mail and X-ARF report |
| `PUBLIC_IP_DETECTION` | `true` | When `HOSTNAME_OVERRIDE` is empty, detect the public WAN IP via external services |
| `PUBLIC_IP_TIMEOUT` | `5` | Timeout for that detection, in seconds |

!!! warning "Set `HOSTNAME_OVERRIDE` in a container"
    Without it, autodetection can report the private container IP as the
    reporting identity.

## SMTP

| Variable | Default | Description |
|---|---|---|
| `SMTP_SERVER` | — | Mail server host |
| `SMTP_PORT` | `587` | Mail server port |
| `SMTP_USERNAME` | — | Set together with `SMTP_PASSWORD` to authenticate |
| `SMTP_PASSWORD` | — | Plaintext; authentication requires TLS |
| `SMTP_USE_TLS` | `true` | Use TLS for the connection |
| `SMTP_VERIFY_SSL` | `true` | Verify the server certificate |
| `SMTP_SENDER` | — | Envelope sender address |
| `SENDER_NAME` | — | Display name of the sender |
| `BCC` | — | Optional blind copy recipient |

### Send pacing

| Variable | Default | Description |
|---|---|---|
| `SLEEP_BETWEEN_MAILS` | `10` | Seconds between individual mails |
| `MAIL_CHUNK_SIZE` | `25` | Send this many mails, then pause; `0` disables chunking |
| `SLEEP_BETWEEN_CHUNKS` | `60` | Seconds to pause between chunks |

Pacing exists so a run that has accumulated a large backlog does not look like a
spam burst to the receiving mail servers.

### Never-report list

| Variable | Default | Description |
|---|---|---|
| `WHITELISTED_ASN` | — | ASNs that must never receive an abuse mail; the `AS` prefix is optional (e.g. `AS8881`) |

The startup log lists the configured entries with their provider names, resolved
from the local GeoLite2 ASN database:

```
Configured whitelisted ASNs:
  ASN      Provider
  -------  --------------------------------
  AS8881   1&1 Versatel GmbH
  AS51167  Contabo GmbH
  AS3209   Vodafone GmbH
```

!!! note "`unknown` means the ASN is not in the database"
    The table is printed after the GeoIP step, so the ASN database is guaranteed
    to be on disk by then. A remaining `unknown` is a genuine miss, not a
    startup-ordering artefact.

Matching is done on bare digits, so `AS8881` in `settings.env` and CrowdSec's
`8881` are the same entry. Parsing is deliberately strict: a malformed value is
rejected rather than digit-scraped, because `AS12foo34` must not silently
whitelist AS1234.

## DNS and Abusix

| Variable | Default | Description |
|---|---|---|
| `ABUSIX_TIMEOUT` | `3` | Per-query timeout in seconds |
| `ABUSIX_DNS_LIFETIME` | `5` | Total resolver lifetime in seconds |

DNS servers come from the system resolver only. Under Docker that is usually the
embedded resolver `127.0.0.11`. There is no variable to point at a different
resolver and no public fallback.

## Operations and limits

| Variable | Default | Description |
|---|---|---|
| `DB_RETENTION_DAYS` | `365` | How long records are kept before cleanup |
| `PENDING_REAP_MINUTES` | `60` | Age at which a crashed `pending` claim is reaped |
| `MAX_ALERTS_PER_RUN` | `0` | Cap on alerts processed per run; `0` means unlimited |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |

See [Delivery Guarantees](delivery.md) for what reaping does — and deliberately
does not — retry.

## Storage paths

| Variable | Default | Description |
|---|---|---|
| `ABUSE_DB_PATH` | `data/abuse_alerts.db` (host), `/data/abuse_alerts.db` (container) | SQLite database location |
| `GEOIP_DIR` | `/tmp/geoip` | Where the GeoLite2 databases are kept at runtime |

## Metrics backend

Optional time-series output, using the same variables as the metrics exporter.
`METRICS_BACKEND` accepts `none` (default), `influxdb2` or `questdb`.

See [Metrics Backends](../reference/metrics-backends.md) for the full variable
list, the point schema, deduplication and retention.

| Variable | Default | Description |
|---|---|---|
| `METRICS_BACKEND` | `none` | Selects the backend |
| `METRICS_ONLY` | `false` | Export decisions as `status=observed` points and send no mail |
| `METRICS_INTERVAL` | `60` | Container only: interval of the separate snapshot loop |
| `REQUEST_TIMEOUT` | `30` | Backend write timeout in seconds |

### Write durability

Report points are spooled to SQLite before the backend write is attempted, so an
unreachable backend defers them to the next run instead of losing them. See
[Metrics Backends](../reference/metrics-backends.md#durability-the-outbox).

| Variable | Default | Description |
|---|---|---|
| `METRICS_WRITE_RETRIES` | `2` | Extra attempts for a single write; spaced by `METRICS_RETRY_BACKOFF * 2ⁿ` seconds |
| `METRICS_RETRY_BACKOFF` | `1` | Base backoff in seconds |
| `METRICS_OUTBOX_MAX_ROWS` | `50000` | Spool size bound; oldest points dropped first. `0` disables the bound |
| `METRICS_OUTBOX_MAX_AGE_DAYS` | `30` | Spool age bound. `0` disables it |

!!! note "The bound decides when an outage becomes unhealthy"
    A deferred batch is a warning and the run still exits `0`. Once the spool
    reaches 90% of `METRICS_OUTBOX_MAX_ROWS` the run exits `1`, because the next
    prune would start discarding points. With `METRICS_OUTBOX_MAX_ROWS=0` the
    spool is unbounded and this escalation never fires.

## Container scheduling

Read by `docker/entrypoint.sh`, not by the application. A direct host run ignores
them — see [Docker Deployment](../getting-started/docker.md#scheduling).

| Variable | Default | Description |
|---|---|---|
| `RUN_ONCE` | `false` | Run once and exit |
| `RUN_EVERY_HOUR` | `6` in Compose | Interval in hours; takes precedence over `RUN_INTERVAL` |
| `RUN_INTERVAL` | `21600` | Interval in seconds |
| `RUN_JITTER` | `300` in the image | Random delay after each run, in seconds |
| `API_HEARTBEAT_INTERVAL` | `300` | LAPI heartbeat loop interval |
| `HEALTHCHECK_MAX_AGE_SECONDS` | `28800` | Main heartbeat staleness limit |
| `API_HEARTBEAT_MAX_AGE_SECONDS` | `700` | LAPI heartbeat staleness limit |

!!! note "Adding a variable means updating two files"
    A new or renamed variable has to appear in `settings.env.example` and, if it
    has a default, in the `ENV` block of the Dockerfile.

## Secrets

!!! danger
    `SMTP_PASSWORD`, `CROWDSEC_LAPI_PASSWORD`, `INFLUXDB_TOKEN` and the QuestDB
    credentials are read as plaintext. `settings.env` and `settings-*.env` are
    gitignored and dockerignored; never commit them. Docker reads the file via
    `env_file` — it is not bind-mounted into the container.
