## [1.0.2] - 2026-11-19

- `New` Container health checks now monitor helper loops and successful metrics snapshots. A dead loop stops the container for restart, while service outages only mark it unhealthy.
- `Changed` **Breaking:** QuestDB 10.x is required for report metrics. Older servers fail before mail or metric writes, and their stored data is not migrated.
- `Changed` **Breaking:** `RUN_JITTER` is no longer supported; scheduling uses a fixed interval with automatic jitter capped at 300 seconds.
- `Changed` Python and entrypoint logs now use a consistent single-line UTC format. Compose uses `unless-stopped`; run one-shot jobs with `docker compose run --rm -e RUN_ONCE=true crowdsec-abuse-reporter`.
- `Changed` Image rebuilds fetch the current GeoLite2 City and ASN databases from P3TERX, so identical commits can use different database releases.
- `Fix` Healthcheck limits now follow configured intervals and jitter; leading-zero values are decimal, and oversized settings fail startup.
- `Fix` Full LAPI responses retry with tenfold limits; if completeness remains unproven, usable reports still process and the run exits nonzero. Malformed decisions are skipped.
- `Fix` Outbox saturation, dropped points, or simultaneous spool/backend failures now fail the run; delivered points are not resent when post-write TTL setup fails.
- `Fix` Invalid whitelist entries stop startup; local GeoIP ASN is checked when CrowdSec has none, and reports are still sent if both sources lack an ASN. Expired negative-cache entries become misses even when database cleanup is disabled.
- `Security` Permanent tombstones keep expired sent and `unknown_send_state` reports unclaimable after retention cleanup; ambiguous SMTP outcomes are never retried.
- `Security` Sensitive `Name: value` headers are masked in report emails and X-ARF attachments.

<details markdown="1">
<summary>Previous versions...</summary>

## [1.0.1] - 2026-09-25

- ``New`` Grafana dashboard: added `scenario` and `country` filter variables, now available on every panel like on the metrics-exporter dashboard.
- ``Fix`` Grafana dashboard: "Success rate" and "Total reports" no longer count `METRICS_ONLY` observation snapshots as delivery attempts, so both KPIs reflect actual send outcomes.
- ``Fix`` Grafana dashboard: the "Alert" column in the report detail table no longer renders the alert ID as a compressed value (e.g. "6.43 K").
- ``Fix`` Grafana dashboard: removed the "Top abuse recipients" panel, whose data was unreliable, and cleaned up the layout.

## [1.0.0] - 2026-09-24
- Project initialization
</summary>