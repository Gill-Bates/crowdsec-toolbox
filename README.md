<p align="center">
  <img src=".github/img/crowdsec_toolbox_black.svg#gh-light-mode-only" width="250" alt="CrowdSec Toolbox">
  <img src=".github/img/crowdsec_toolbox_white.svg#gh-dark-mode-only" width="250" alt="CrowdSec Toolbox">
</p>

<h2 align="center">Email abuse reports and time-series metrics for the CrowdSec bans you already generate</h2>

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

<p align="center">
  <img src="crowdsec-metrics-exporter/grafana/dashboard_metrics_white.png#gh-light-mode-only" width="900" alt="Metrics export dashboard, light theme">
  <img src="crowdsec-metrics-exporter/grafana/dashboard_metrics_dark.png#gh-dark-mode-only" width="900" alt="Metrics export dashboard, dark theme">
</p>

See the [dashboards reference](https://gill-bates.github.io/crowdsec-toolbox/reference/dashboards/)
for requirements, variables and panel details.

## Deployment

Both tools provide Docker and Compose deployments. The metrics exporter can also
run directly as a Python script on the CrowdSec host. They have separate entry
points and their own `pyproject.toml` dependency manifests, so their
deployments can be managed independently. Follow each tool's README for setup,
configuration, and operating notes.

## License

> [!IMPORTANT]
> *CrowdSec Toolbox* is an independent community project. It is not affiliated
> with, endorsed by, or sponsored by CrowdSec.

This repository is released under the [MIT License](LICENSE).

<br>
<p align="center">
  <a href="https://www.buymeacoffee.com/tnsteinerx">
    <img src="https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20beer&emoji=%F0%9F%8D%BA&slug=tnsteinerx&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" alt="Buy Me a Beer">
  </a>
</p>