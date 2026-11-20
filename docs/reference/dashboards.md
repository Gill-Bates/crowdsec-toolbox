# Grafana Dashboards

Both tools ship ready-made QuestDB dashboards in their `grafana/` directories.
The exporter has a core dashboard and a separate optional view for per-event
data. Import the JSON, pick your data source and table, and the dashboard runs
its filters and aggregations in QuestDB.

| Dashboard | File | Panels | Highlights |
|---|---|---:|---|
| Metrics exporter | `crowdsec-metrics-exporter/grafana/dashboard_questdb.json` | 20 | Alerts, hosts, scenarios, origin countries, network providers, source IPs, raw-data retention state |
| Metrics exporter events (optional) | `crowdsec-metrics-exporter/grafana/dashboard_questdb_events.json` | 2 | Top request paths and target FQDNs when per-event export is enabled |
| Abuse reporter | `crowdsec-abuse-reporter/grafana/dashboard_questdb.json` | 7 | A four-card KPI header (sent, failed, success rate, total), daily reports, origin countries and a paginated detail table |

## Requirements

!!! warning "Grafana 13 and the QuestDB plugin"
    The dashboards use the **v2 dashboard schema**
    (`dashboard.grafana.app/v2`). Grafana validates that schema against its CUE
    definition on import, so an older release rejects them outright rather than
    ignoring an unsupported field.

    The metrics dashboard targets the
    [QuestDB data source plugin](https://grafana.com/grafana/plugins/questdb-questdb-datasource/).

All three dashboards target Grafana 13 (`pluginVersion` 13.0.2).

The abuse dashboard follows a deliberate visual hierarchy: a compact KPI header
(height 4) above a dominant daily chart, with the detail table last. Colour is
semantic only — green means delivered, red means failed, and everything that is
merely a distribution stays neutral blue, so red actually stands out. The daily
chart is **not** stacked, because when a failure happened matters more than its
share of the day's total; `sent` is drawn at low fill opacity and `failed` at
high, so failures dominate visually even when they are rare.

The InfluxDB variants are placeholders:

- `crowdsec-metrics-exporter/grafana/dashboard_influxdb2.todo` and
  `crowdsec-abuse-reporter/grafana/dashboard_influxdb2.todo` — named `.todo`
  rather than `.json` so that globbing `grafana/*.json` cannot pick up a file with
  no dashboard content

## Variables

The metrics-exporter core dashboard and abuse-reporter dashboard expose the
same five variables, built the same way, so a filter behaves identically in
both:

| Variable | Purpose |
|---|---|
| `datasource` | Picks the QuestDB data source |
| `table` | Visible alert-table selector — defaults to `crowdsec` (exporter) or `crowdsec-abuse` (reporter) |
| `host` | Filters instances within that table; multi-select with an **All** option |
| `scenario` | Shared scenario filter; multi-select with an **All** option |
| `country` | Shared country filter; multi-select with an **All** option |

The visible `table` picker excludes tables ending in `_events`, downsampling
rollup views (`*_rollup_<interval>_v<n>`) and internal tables such as
`_crowdsec_downsampling`. Its default matches each tool's shipped
`QUESTDB_TABLE`. If one QuestDB instance contains several alert-like tables,
select the one used by the dashboard.

The core metrics and abuse dashboards match the host with
`coalesce(nullif(host, ''), '(unknown)') IN (${host:sqlstring})`, so points
written before the `host` tag existed group under `(unknown)` and remain
selectable instead of disappearing. The `scenario` and `country` filters follow
the same `coalesce(nullif(...), '(unknown)') IN (...)` pattern.

## Optional event dashboard

The separate `dashboard_questdb_events.json` contains “Top Endpoints” and “Top
Target FQDNs”. It has an event-table selector (default `crowdsec_events`), plus
host and scenario filters. It has no country filter because the event table does
not carry country data.

Use this dashboard after setting `EVENTS_ENABLED=true` and the exporter has
written at least one event. QuestDB creates optional event columns when it first
receives a non-empty value for them; a panel that references a column not yet
created can return a SQL error. A custom `EVENTS_TABLE` name must be selected in
the event-table variable; names that do not end in `_events` require adjusting
that variable's query.

## Query execution

Filtering, grouping, aggregation, ranking, sorting, limits and time bucketing
are expressed in QuestDB SQL. The “Scenarios by Host” panel uses Grafana's
Grouping to Matrix only to pivot the already grouped host/scenario result into
columns; the query has no row cap, so selected hosts are compared completely.

The metrics dashboard's history and detail panels read the raw alert table. The
retention panel shows the exporter's raw window and rollup-view state so a range
that exceeds raw retention is visible. The dashboard does not query rollup views;
detail panels need dimensions such as IP, ASN and coordinates that the rollups
discard. The panels' time, host, scenario and country filters and aggregations
still run in QuestDB.

## Country flags

Country values render as flag emoji in panels and in the country selector, while
the filter values remain the original country codes. Unknown values and the
non-country codes `AP` and `ZZ` display as 🌐.

Rendering requires an emoji-capable browser or system font. The SQL converts
letters to regional indicators using QuestDB's UTF-16 `substring` offsets (two
code units per indicator). Both tools require QuestDB 10.x. Panel queries apply the
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

The map uses Esri's fixed `World_Dark_Gray_Base` style through the `esri-xyz`
layer. It stays dark with either Grafana theme. The browser must be able to
reach `services.arcgisonline.com`; tile URLs use `{z}/{y}/{x}`.

!!! note "The map style is fixed"
    CARTO's `theme: auto` basemap would follow Grafana's light/dark theme
    automatically, but now watermarks unauthenticated requests with
    "API KEY REQUIRED". This dashboard uses Esri's dark tiles, so the map also
    stays dark in Grafana's light theme.

## File format

The JSON is stored fully expanded with a two-space indent, which is what Grafana
emits on export, so a round-trip through Grafana produces a reviewable diff.
