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
| events (`EVENTS_TABLE`) | `timestamp`, `alert_id`, `event_seq` | exact — `event_seq` is the event's index inside its alert, returned by the LAPI in a stable order |

See [Metrics Backends](../reference/metrics-backends.md#deduplication) for the
alert table's weaker key and why it is weaker.

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

The QuestDB dashboard's "Top Endpoints" and "Top Target FQDNs" panels query
`"${table}_events"`, deriving the events table from the `table` variable rather
than introducing a second one. That matches the default
`EVENTS_TABLE=<QUESTDB_TABLE>_events`; if you set `EVENTS_TABLE` to a name that
does not follow this pattern, adjust those two queries.

Until `EVENTS_ENABLED=true` has written once, the table does not exist and both
panels report it as unknown. See [Grafana Dashboards](../reference/dashboards.md).
