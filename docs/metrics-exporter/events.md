# Per-Event Export

The default export writes one point per **alert**, which carries only aggregate
information. With `EVENTS_ENABLED=true` a second pass writes one point per
**event**, which is where the request-level detail lives.

## How it works

The pass reads `GET /v1/alerts?since=<EVENTS_SINCE>` and writes one point per
event into `EVENTS_TABLE`.

Whether that response already embeds `events[]` depends on the CrowdSec version,
so alerts that arrive without them are enriched individually via
`GET /v1/alerts/{id}`. The event `meta` blocks carry the request details.

## Column schema

| Column | Source meta key | Kind |
|---|---|---|
| `host`, `ip_address`, `scenario` | host identity, `source_ip`, alert scenario | tag |
| `alert_id` | alert `id` | tag |
| `event_seq` | the event's index inside its alert | tag |
| `http_verb`, `http_status`, `target_fqdn`, `target_technology`, `target_user`, `service` | same-named meta keys | tag |
| `http_path` | `http_path` | string field |

`http_path` is a field rather than a tag because scan paths are effectively
unbounded and QuestDB `SYMBOL` columns are a poor fit for high cardinality.

ASN and geo data are **not** duplicated per event. Join on `alert_id` against the
alert table instead.

## Deduplication

The event table has an exact key available, which the alert table does not:

| Table | Upsert keys | Identity |
|---|---|---|
| events (`EVENTS_TABLE`) | `timestamp`, `host`, `alert_id`, `event_seq` | exact per CrowdSec instance — `host` isolates shared-table writers, and `event_seq` is the event's index inside its alert |

See [Metrics Backends](../reference/metrics-backends.md#deduplication) for the
alert table's weaker key and why it is weaker.

!!! warning "Changing the upsert key does not rewrite existing rows"
    QuestDB applies the new key to future inserts; it does not repair rows that
    may already have collided under the earlier key. Events still inside
    `EVENTS_SINCE` are re-sent with host-aware keys, but older collided rows
    cannot be reconstructed from QuestDB alone.

## Cost

!!! warning "Write amplification is window ÷ interval"
    Every run re-sends the whole `EVENTS_SINCE` window and the backend discards
    what it already has. Keep the window comfortably above the export interval so
    nothing falls between two runs — but with a 60 s interval and a 30 m window,
    each event is sent about **30 times** before it ages out.

!!! warning "The events table grows much faster than the alert table"
    Volume scales with the number of events per alert, and a single HTTP scan
    easily produces hundreds. Set `QUESTDB_TTL` accordingly.

## Caveats

- `target_user` only appears for scenarios that parse authentication logs, such
  as `crowdsecurity/sshd`. With HTTP-only scenarios the column stays empty.
- Requested paths are stored **verbatim**. A credential or token that a scanner
  happens to put in a URL is stored along with it.

!!! danger "Paths can contain secrets"
    Treat the events table as potentially containing credentials leaked by
    attackers' own requests, and scope access to it accordingly.

## Dashboard integration

The optional `crowdsec-metrics-exporter/grafana/dashboard_questdb_events.json`
contains the “Top Endpoints” and “Top Target FQDNs” panels. Import it after
`EVENTS_ENABLED=true` has written at least one event. Its event-table selector
defaults to `crowdsec_events`; if `EVENTS_TABLE` has a custom name, select it
from the variable when it ends in `_events`, or update the selector query.

The event table does not include country, so this dashboard has no country
filter. QuestDB adds optional metadata columns when a non-empty value first
arrives; a panel that references a column not yet created can return a SQL
error. See [Grafana Dashboards](../reference/dashboards.md).
