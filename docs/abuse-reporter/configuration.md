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
| `CROWDSEC_LAPI_VALIDATE_CERTIFICATE` | `true` | Verify the LAPI TLS certificate |
| `CROWDSEC_LAPI_TIMEOUT` | `30` | Request timeout in seconds |
| `CROWDSEC_FETCH_ALERT_DETAILS` | `true` | Fetch per-alert details |
| `CROWDSEC_DETAIL_LIMIT` | `500` | Cap on detail fetches |

Either supply the three explicit values, or rely on the credentials file for a
direct host run.

The template uses `http://crowdsec:8080`, which is suitable only on a trusted
private network. Use HTTPS when the LAPI traffic crosses a network you do not
fully trust, and keep certificate verification enabled.

## Reporting identity

| Variable | Default | Description |
|---|---|---|
| `HOSTNAME_OVERRIDE` | — | Public reporting identity shown in the "Reported by" line of the mail text; it is not part of the X-ARF report |
| `PUBLIC_IP_DETECTION` | `true` | When `HOSTNAME_OVERRIDE` is empty, detect the public WAN IP via external services |
| `PUBLIC_IP_TIMEOUT` | `5` | Timeout for that detection, in seconds |

!!! tip "Prefer a fixed `HOSTNAME_OVERRIDE`"
    A fixed value is the reliable choice for a stable reporting identity.
    Automatic detection asks the external services first, so it also works
    inside a container while they are reachable; only if that fails (or
    `PUBLIC_IP_DETECTION=false`) it falls back to a local address, which can be
    a private container IP.

## SMTP

| Variable | Default | Description |
|---|---|---|
| `SMTP_SERVER` | `smtp.example.com` | Mail server host; the container entrypoint refuses to start when it is empty |
| `SMTP_PORT` | `587` | Mail server port |
| `SMTP_USERNAME` | — | Set together with `SMTP_PASSWORD` to authenticate |
| `SMTP_PASSWORD` | — | Plaintext; authentication requires TLS |
| `SMTP_USE_TLS` | `true` | Use TLS for the connection |
| `SMTP_VALIDATE_CERTIFICATE` | `true` | Verify the server certificate |
| `SMTP_SENDER` | `abuse-reporter@example.com` | Envelope sender address; a plain `user@domain.tld`, otherwise startup fails (no `Name <addr>` form, use `SENDER_NAME`) |
| `SENDER_NAME` | — | Display name of the sender |
| `BCC` | — | Optional blind copy recipient |

### Send pacing

| Variable | Default | Description |
|---|---|---|
| `SLEEP_BETWEEN_MAILS` | `0` (`10` in `settings.env.example`) | Seconds between individual mails |
| `MAIL_CHUNK_SIZE` | `0` (`25` in `settings.env.example`) | Send this many mails, then pause; `0` disables chunking |
| `SLEEP_BETWEEN_CHUNKS` | `0` (`60` in `settings.env.example`) | Seconds to pause between chunks |

Pacing is off unless set. It exists so a run that has accumulated a large backlog does not look like a
spam burst to the receiving mail servers.

### Never-report list

| Variable | Default | Description |
|---|---|---|
| `WHITELISTED_ASN` | — | ASNs that must never receive an abuse mail; the `AS` prefix is optional (e.g. `AS8881`). An invalid non-empty entry stops startup. Before each send the ASN from CrowdSec and from the local GeoIP database are both checked; if neither is known, the mail is still sent. |

With `LOG_LEVEL=DEBUG` the startup log lists the configured entries with their provider names, resolved
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
| `DB_RETENTION_DAYS` | `365` | Age in days after which report details are deleted; `0` disables cleanup. The keys of handled reports are kept permanently, see [Retention](delivery.md#retention-keeps-the-guarantee) |
| `PENDING_REAP_MINUTES` | `60` | Age at which a crashed `pending` claim is reaped |
| `MAX_ALERTS_PER_RUN` | `0` | Cap on alerts processed per run; `0` means unlimited |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |

See [Delivery Guarantees](delivery.md) for what reaping does — and deliberately
does not — retry.

## Storage paths

| Variable | Default | Description |
|---|---|---|
| `ABUSE_DB_PATH` | `data/abuse_alerts.db` (host), `/data/abuse_alerts.db` (container) | SQLite database location |
| `GEOIP_DIR` | `data/geolite2` (host), `/tmp/geoip` (container) | Where the GeoLite2 databases are kept at runtime |

## Metrics backend

Optional time-series output, using the same variables as the metrics exporter.
`METRICS_BACKEND` accepts `none` (default), `influxdb2` or `questdb`. QuestDB
must be a **10.x** release: the reporter checks `SELECT build()` before sending
any mail or writing anything and exits `1` otherwise, keeping the outbox intact.
Older data is not migrated.

See [Metrics Backends](../reference/metrics-backends.md) for the full variable
list, the point schema, deduplication and retention.

| Variable | Default | Description |
|---|---|---|
| `METRICS_BACKEND` | `none` | Selects the backend |
| `METRICS_ONLY` | `false` | Export decisions as `status=observed` points and send no mail |
| `METRICS_INTERVAL` | `60` | Container only: interval of the separate snapshot loop in seconds (1 to 31536000) |
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
    spool is unbounded and this escalation never fires. Independently of that,
    a run that drops undelivered points through either bound exits `1`.

!!! note "QuestDB dedup is verified before the first write"
    With `METRICS_BACKEND=questdb` the reporter first creates or checks its
    table with deduplication. If that cannot be verified, nothing is written, the
    outbox keeps every point and the run exits `1` at once. A `QUESTDB_TTL` or
    `QUESTDB_DOWNSAMPLING` rollup that cannot be set up after a write also exits
    `1`, without resending the points. See
    [Retention](../reference/metrics-backends.md#retention).

## Container scheduling

Read by `docker/entrypoint.sh`, not by the application. A direct host run ignores
them — see [Docker Deployment](../getting-started/docker.md#scheduling).

| Variable | Default | Description |
|---|---|---|
| `RUN_ONCE` | `false` | Run once and exit |
| `RUN_EVERY_HOUR` | `6` in `settings.env.example` | Interval in hours (1 to 8760); takes precedence over `RUN_INTERVAL` |
| `RUN_INTERVAL` | `21600` | Interval in seconds (1 to 31536000) |
| `API_HEARTBEAT_INTERVAL` | `300` | LAPI heartbeat loop interval in seconds (1 to 31536000) |
| `HEALTHCHECK_MAX_AGE_SECONDS` | `interval + max jitter + 7200` | Main heartbeat staleness limit; optional, 1 to 31536000. Derived from the run interval unless set |
| `API_HEARTBEAT_MAX_AGE_SECONDS` | `API_HEARTBEAT_INTERVAL + 400` | LAPI heartbeat staleness limit; optional, 1 to 31536000 |
| `METRICS_HEARTBEAT_MAX_AGE_SECONDS` | `10 * METRICS_INTERVAL + 300` | Staleness limit of the last successful metrics snapshot; optional, 1 to 31536000, used only when metrics are enabled |

Jitter is automatic: up to `min(interval / 10, 300)` seconds per run plus a random
start offset of the same size.

!!! note "Adding a variable means updating two files"
    A new or renamed variable has to appear in `settings.env.example` and, if it
    has a default, in the `ENV` block of the Dockerfile.

## Secrets

!!! danger
    `SMTP_PASSWORD`, `CROWDSEC_LAPI_PASSWORD`, `INFLUXDB_TOKEN` and the QuestDB
    credentials are read as plaintext. `settings.env` and `settings-*.env` are
    gitignored and dockerignored; never commit them. Docker reads the file via
    `env_file` — it is not bind-mounted into the container.
