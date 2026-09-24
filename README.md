<p align="center">
  <img src=".github/img/crowdsec_toolbox_black.svg#gh-light-mode-only" width="250" alt="CrowdSec Toolbox">
  <img src=".github/img/crowdsec_toolbox_white.svg#gh-dark-mode-only" width="250" alt="CrowdSec Toolbox">
</p>

<h2 align="center">Turn CrowdSec decisions into action and insight</h2>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License"></a>
  <a href="#deployment"><img src="https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white" alt="Python 3.13 or newer"></a>
  <a href="#features-at-a-glance"><img src="https://img.shields.io/badge/Tools-2-4C8BF5" alt="Two standalone tools"></a>
  <a href="#deployment"><img src="https://img.shields.io/badge/Deployment-Docker%20Compose-2496ED?logo=docker&logoColor=white" alt="Docker Compose deployment"></a>
</p>

<p align="center">
  <a href="crowdsec-abuse-reporter/README.md">Abuse reporting</a> ·
  <a href="crowdsec-metrics-exporter/README.md">Metrics export</a> ·
  <a href="#grafana-dashboards">Dashboards</a> ·
  <a href="LICENSE">License</a>
</p>

CrowdSec can identify and block hostile traffic. CrowdSec Toolbox helps you use
those decisions after they are made: send an abuse report to the responsible
network contact, or export decision data to the time-series backend you already
monitor. Each tool is independent, so you can run only the part you need.

## Features at a glance

| | [crowdsec-abuse-reporter](crowdsec-abuse-reporter/README.md) | [crowdsec-metrics-exporter](crowdsec-metrics-exporter/README.md) |
|---|---|---|
| **What it does** | Turns CrowdSec bans into abuse reports | Exports CrowdSec decisions as time series |
| 📥 **Source** | CrowdSec Local API (LAPI), direct | CrowdSec Local API (LAPI), direct |
| 📤 **Output** | X-ARF v4 email to the responsible abuse contact | InfluxDB 2.x or QuestDB (line protocol over HTTP) |
| 🌍 **Enrichment** | GeoIP (GeoLite2 City + ASN) | — |
| 📇 **Contact lookup** | Abusix DNS abuse-contact database | — |
| 🔁 **Idempotency** | SQLite, at-most-once per `(AlertId, IPAddress)` | Backend-side deduplication, no local state |
| 🐳 **Runs as** | Docker container (own image), or cron/host script | Docker container, or cron/host script |
| 📦 **Dependencies** | `httpx`, `dnspython`, `geoip2` | `requests`, `urllib3`, `httpx` |

## Grafana dashboards

Both tools ship ready-made dashboards in their `grafana/` directory — import the
JSON, pick your data source, and you have a working view of what CrowdSec is
blocking. No provisioning, no plugins beyond the data source itself.

| | Dashboard | Panels | Highlights |
|---|---|---|---|
| **Metrics export** | [`dashboard_questdb.json`](crowdsec-metrics-exporter/grafana/dashboard_questdb.json) | 18 | World map of source IPs coloured per host, alert and event history, top countries, networks/ASN, scenarios, source IPs, and — with the per-event export enabled — top endpoints and target FQDNs |
| **Abuse reporting** | [`dashboard_questdb.json`](crowdsec-abuse-reporter/grafana/dashboard_questdb.json) | 8 | A four-card KPI header (sent, failed, success rate, total), daily reports, top recipients, origin countries, and a paginated detail table |

Country values render as flag emoji, and hosts keep a stable colour across
panels. The shared host and scenario filters apply throughout; the country
filter applies to every panel except the two event panels, whose table holds
no geo columns.

### Screenshots

<p align="center">
  <img src="crowdsec-metrics-exporter/grafana/dashboard_metrics_white.png#gh-light-mode-only" width="900" alt="Metrics export dashboard, light theme">
  <img src="crowdsec-metrics-exporter/grafana/dashboard_metrics_dark.png#gh-dark-mode-only" width="900" alt="Metrics export dashboard, dark theme">
</p>

> [!NOTE]
> Both dashboards are developed and tested against **Grafana 13** using the v2
> dashboard schema (`dashboard.grafana.app/v2`). Grafana validates that schema on
> import, so an older release will reject them. The metrics dashboard targets the
> [QuestDB data source plugin](https://grafana.com/grafana/plugins/questdb-questdb-datasource/);
> the InfluxDB variants are placeholders.

## Deployment

Both tools provide Docker and Compose deployments. The metrics exporter can also
run directly as a Python script on the CrowdSec host. They have separate entry
points and their own `pyproject.toml` dependency manifests, so their
deployments can be managed independently. Follow each tool's README for setup,
configuration, and operating notes.

> [!IMPORTANT]
> *CrowdSec Toolbox* is an independent community project. It is not affiliated
> with, endorsed by, or sponsored by CrowdSec.

## License

This repository is released under the [MIT License](LICENSE).

<br>
<p align="center">
  <a href="https://www.buymeacoffee.com/tnsteinerx">
    <img src="https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20beer&emoji=%F0%9F%8D%BA&slug=tnsteinerx&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" alt="Buy Me a Beer">
  </a>
</p>