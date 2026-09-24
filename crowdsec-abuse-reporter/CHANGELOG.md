## [1.0.1] - 2026-09-25

- ``New`` Grafana dashboard: added `scenario` and `country` filter variables, now available on every panel like on the metrics-exporter dashboard.
- ``Fix`` Grafana dashboard: "Success rate" and "Total reports" no longer count `METRICS_ONLY` observation snapshots as delivery attempts, so both KPIs reflect actual send outcomes.
- ``Fix`` Grafana dashboard: the "Alert" column in the report detail table no longer renders the alert ID as a compressed value (e.g. "6.43 K").
- ``Fix`` Grafana dashboard: removed the "Top abuse recipients" panel, whose data was unreliable, and cleaned up the layout.

<details markdown="1">
<summary>Previous versions...</summary>

## [1.0.0] - 2026-09-24
- Project initialization
