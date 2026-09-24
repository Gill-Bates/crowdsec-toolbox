# Grafana Dashboards

Both tools ship ready-made dashboards in their `grafana/` directory. Import the
JSON, pick your data source, and you have a working view of what CrowdSec is
blocking — no provisioning and no plugins beyond the data source itself.

| | Dashboard | Panels | Highlights |
|---|---|---|---|
| Metrics export | `crowdsec-metrics-exporter/grafana/dashboard_questdb.json` | 18 | World map of source IPs coloured per host, alert and event history, top countries, networks/ASN, scenarios, source IPs, and — with the per-event export enabled — top endpoints and target FQDNs |
| Abuse reporting | `crowdsec-abuse-reporter/grafana/dashboard_questdb.json` | 8 | A four-card KPI header (sent, failed, success rate, total), daily reports, top recipients, origin countries, and a paginated detail table |

## Requirements

!!! warning "Grafana 13 and the QuestDB plugin"
    The dashboards use the **v2 dashboard schema**
    (`dashboard.grafana.app/v2`). Grafana validates that schema against its CUE
    definition on import, so an older release rejects them outright rather than
    ignoring an unsupported field.

    The metrics dashboard targets the
    [QuestDB data source plugin](https://grafana.com/grafana/plugins/questdb-questdb-datasource/).

Both dashboards target Grafana 13 (`pluginVersion` 13.0.2).

The abuse dashboard follows a deliberate visual hierarchy: a compact KPI header
(height 4) above a dominant daily chart, with the detail table last. Colour is
semantic only — green means delivered, red means failed, and everything that is
merely a distribution stays neutral blue, so red actually stands out. The daily
chart is **not** stacked, because when a failure happened matters more than its
share of the day's total; `sent` is drawn at low fill opacity and `failed` at
high, so failures dominate visually even when they are rare.

The InfluxDB variants are placeholders:

- `crowdsec-abuse-reporter/grafana/dashboard_influxdb2.json` — not yet built
- `crowdsec-metrics-exporter/grafana/dashboard_influxdb2.todo` — named `.todo`
  rather than `.json` so that globbing `grafana/*.json` cannot pick up a file with
  no dashboard content

## Variables

| Variable | Purpose |
|---|---|
| `datasource` | Picks the QuestDB data source |
| `table` | The alert table — `QUESTDB_TABLE`, default `crowdsec` (exporter) or `crowdsec-abuse` (reporter) |
| `host` | Filters instances within that table; multi-select with an **All** option |
| `scenario` | Shared scenario filter (metrics dashboard) |
| `country` | Shared country filter (metrics dashboard) |

The `table` picker excludes tables ending in `_events`, so the events table cannot
be selected as the alert table. In both dashboards `table` is hidden
(`hide: hideVariable`) because it is deployment configuration rather than a
filter; `datasource` stays visible so an imported dashboard can be pointed at
your QuestDB without opening the settings.

!!! note "The country filter does not reach the event panels"
    The shared host and scenario filters apply throughout. The `country` filter
    applies to every panel except the two event panels, whose table holds no geo
    columns — geo data lives on the alert row only.

Both dashboards match the host with
`coalesce(nullif(host, ''), '(unknown)') IN (${host:sqlstring})`, so points
written before the `host` tag existed group under `(unknown)` and remain
selectable instead of disappearing.

## Event panels

"Top Endpoints" and "Top Target FQDNs" query `"${table}_events"`, deriving the
events table from the `table` variable rather than introducing a second one. That
matches the default `EVENTS_TABLE=<QUESTDB_TABLE>_events`.

!!! warning "A custom `EVENTS_TABLE` needs a query edit"
    If you set `EVENTS_TABLE` to a name that does not follow the
    `<QUESTDB_TABLE>_events` pattern, adjust those two queries.

Until `EVENTS_ENABLED=true` has written once, the table does not exist and both
panels report it as unknown. See
[Per-Event Export](../metrics-exporter/events.md).

## Country flags

Country values render as flag emoji in panels and in the country selector, while
the filter values remain the original country codes. Unknown values and the
non-country codes `AP` and `ZZ` display as 🌐.

Rendering requires an emoji-capable browser or system font. The SQL converts
letters to regional indicators using QuestDB's UTF-16 `substring` offsets (two
code units per indicator), verified with QuestDB 9.4.0. Panel queries apply the
conversion *after* aggregation so counts and limits stay correct.

The selector separates display text from filter values using the
[QuestDB label/value regex pattern](https://questdb.com/docs/cookbook/integrations/grafana/variable-dropdown/).

## Colours stay stable per host

The map, "Alert History by Host" and "Event History by Scenario" all use
`palette-classic-by-name`: the colour is derived from the value, so a host keeps
the same colour across panels, refreshes and filter changes. With plain
`palette-classic` the colour would follow the position in the result set and shift
whenever the host set changed.

## The map basemap

The map uses Esri's Dark Gray Canvas via the `esri-xyz` layer with a custom URL,
which the browser must be able to reach (`services.arcgisonline.com`). The base
layer carries no place labels, and the Esri tile order is `{z}/{y}/{x}`.

!!! note "The map stays dark in Grafana's light theme"
    CARTO's `theme: auto` basemap would follow Grafana's light/dark theme
    automatically, but now watermarks unauthenticated requests with
    "API KEY REQUIRED". Esri is used instead, at the cost of the theme following.

## File format

The JSON is stored fully expanded with a two-space indent, which is what Grafana
emits on export. An earlier hand-folded variant was replaced by it, so a
round-trip through Grafana produces a reviewable diff.
