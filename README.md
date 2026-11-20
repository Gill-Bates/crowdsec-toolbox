<p align="center">
  <img src=".github/img/crowdsec_toolbox_black.svg#gh-light-mode-only" width="250" alt="CrowdSec Toolbox">
  <img src=".github/img/crowdsec_toolbox_white.svg#gh-dark-mode-only" width="250" alt="CrowdSec Toolbox">
</p>

<h2 align="center">Your Instance - your Data! Generate Dashboards and Reports without paid subscriptions!</h2>

<p align="center">
  <a href="https://github.com/Gill-Bates/crowdsec-toolbox/releases"><img src="https://img.shields.io/github/v/release/Gill-Bates/crowdsec-toolbox?logo=github&logoColor=white" alt="GitHub Release"></a>
  <a href="https://hub.docker.com/r/giiibates/crowdsec-toolbox"><img src="https://img.shields.io/docker/pulls/giiibates/crowdsec-toolbox?logo=docker&logoColor=white" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/giiibates/crowdsec-toolbox"><img src="https://img.shields.io/badge/Platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey?logo=linux&logoColor=white" alt="Supported Platforms"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#deployment"><img src="https://img.shields.io/badge/Quick%20Start-168B75?style=for-the-badge&logo=docker&logoColor=white" alt="Quick Start"></a>
  <a href="https://gill-bates.github.io/crowdsec-toolbox/"><img src="https://img.shields.io/badge/Documentation-34495E?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation"></a>
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
| 📤 **Output** | X-ARF v4.2.0 email to the responsible abuse contact | InfluxDB 2.x or QuestDB 10.x (line protocol over HTTP) |
| 🌍 **Enrichment** | GeoIP (GeoLite2 City + ASN) | — |
| 📇 **Contact lookup** | Abusix DNS abuse-contact database | — |
| 🔁 **Idempotency** | SQLite, at-most-once per `(AlertId, IPAddress)` | Backend-side deduplication, no local state |
| 🐳 **Runs as** | Docker container (own image), or cron/host script | Docker container, or cron/host script |
| 📦 **Dependencies** | `httpx`, `dnspython`, `geoip2` | `requests`, `urllib3`, `httpx` |

## Grafana dashboards

Both tools ship ready-made QuestDB dashboards in their `grafana/` directory.
Import the JSON, pick your QuestDB data source, and you have a working view of
what CrowdSec is blocking. No provisioning, no plugins beyond the data source
itself. InfluxDB dashboards do not exist yet.

<p align="center">
  <img src=".github/img/dashboard_metrics_white.png#gh-light-mode-only" width="900" alt="Metrics export dashboard, light theme">
  <img src=".github/img/dashboard_metrics_dark.png#gh-dark-mode-only" width="900" alt="Metrics export dashboard, dark theme">
</p>

See the [dashboards reference](https://gill-bates.github.io/crowdsec-toolbox/reference/dashboards/)
for requirements, variables and panel details.

## Deployment

Both tools support Docker Compose and direct host runs. On a host, each tool is
a one-shot Python script that you schedule with cron. Follow each tool's README
for setup, configuration, and operating notes.

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
