# crowdsec-abuse-reporter

An unattended collector and reporter that turns CrowdSec bans into abuse
reports.

## What it does

1. Fetches the current decisions from the CrowdSec Local API.
2. Enriches each source IP with GeoIP data (GeoLite2 City and ASN) when the
   databases are available.
3. Resolves the responsible abuse contact through the Abusix DNS contact
   database.
4. Emails an [X-ARF v4](https://www.x-arf.org/) report to that contact.
5. Records the `(AlertId, IPAddress)` pair in SQLite so the same ban is reported
   **at most once** per source IP.

Because it talks to the LAPI directly, the container needs no access to
`/var/run/docker.sock`.

## The idempotency key is a pair

The key is `(AlertId, IPAddress)`, not `AlertId` alone: one CrowdSec alert can
bundle bans for several IP addresses, and each of those is a separate report to a
potentially different contact.

!!! danger "A `Range` decision is never collapsed"
    A CrowdSec `Range` decision must not be reduced to its network address and
    reported as the offender. That would accuse the wrong party.

## Run modes

| Mode | Trigger | Behaviour |
|---|---|---|
| Reporting | default | Resolves contacts and sends mail; writes metrics points if a backend is enabled |
| Metrics only | `METRICS_ONLY=true` | Exports current decisions as points with `status=observed`, sends **no mail** |
| One-shot | `RUN_ONCE=true` (container) | One run, then exit |

In the container both loops run concurrently: reports go out on the
`RUN_EVERY_HOUR` schedule while the entrypoint's separate `METRICS_INTERVAL`
loop writes snapshots every minute.

!!! note "Snapshot volume scales with ban duration"
    Each metrics-only run writes one point per active decision, so the point
    count grows with ban duration divided by `METRICS_INTERVAL`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Normal run. Per-report DNS or send failures still exit 0. |
| `1` | Hard failure: configuration, GeoIP cold start, database init, LAPI fetch, or a database error |
| `130` | Interrupted |

The container entrypoint refreshes `/data/heartbeat` only on exit 0, which is
what lets the health check distinguish a working run from a repeatedly failing
one.

## What is stored where

| Data | Location |
|---|---|
| Send claims and status per `(AlertId, IPAddress)` | SQLite, always |
| Abuse-contact cache | SQLite, always |
| Last run start/end, exit code, backend | SQLite `run_state` |
| Report details (recipient, scenario, error) | SQLite when no metrics backend; otherwise the backend |
| Metrics points not yet acknowledged | SQLite `metrics_outbox`, until the backend accepts them |
| GeoLite2 databases | tmpfs, seeded from the image baseline |

With a metrics backend enabled, SQLite holds **control data only** so no report
data is stored twice. See [Metrics Backends](../reference/metrics-backends.md).

## Documentation

- [Configuration](configuration.md) — every supported variable
- [Delivery Guarantees](delivery.md) — the at-most-once claim protocol
- [GeoIP Databases](geoip.md) — the baseline/tmpfs/update model
- [Metrics Backends](../reference/metrics-backends.md) — optional time-series output
- [Grafana Dashboards](../reference/dashboards.md)

!!! important
    crowdsec-abuse-reporter is an independent community project. It is not
    affiliated with, endorsed by, or sponsored by CrowdSec.
