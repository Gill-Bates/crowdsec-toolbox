---
hide:
  - navigation
---

<p align="center">
  <img src="https://raw.githubusercontent.com/Gill-Bates/crowdsec-toolbox/main/.github/img/crowdsec_toolbox_black.svg" width="300" alt="CrowdSec Toolbox" class="cst-logo-light">
  <img src="https://raw.githubusercontent.com/Gill-Bates/crowdsec-toolbox/main/.github/img/crowdsec_toolbox_white.svg" width="300" alt="CrowdSec Toolbox" class="cst-logo-dark">
</p>

<p align="center">
  <strong>Turn CrowdSec decisions into action and insight</strong>
</p>

<p align="center">
  <a href="https://github.com/Gill-Bates/crowdsec-toolbox/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License"></a>
  <a href="https://github.com/Gill-Bates/crowdsec-toolbox"><img src="https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white" alt="Python 3.13 or newer"></a>
  <a href="https://github.com/Gill-Bates/crowdsec-toolbox"><img src="https://img.shields.io/badge/Deployment-Docker%20Compose-2496ED?logo=docker&logoColor=white" alt="Docker Compose deployment"></a>
</p>

---

## What is CrowdSec Toolbox?

CrowdSec can identify and block hostile traffic. CrowdSec Toolbox helps you use
those decisions *after* they are made: send an abuse report to the responsible
network contact, or export decision data to the time-series backend you already
monitor.

The repository holds two standalone tools. They share a dependency manifest and
these docs, but no application code — each one deploys, upgrades and fails
independently of the other, and you can run only the part you need.

<div class="grid cards" markdown>

-   :material-email-alert:{ .lg .middle } **crowdsec-abuse-reporter**

    ---

    Fetches bans from the CrowdSec Local API, enriches each source IP with
    GeoIP data, resolves the responsible abuse contact through the Abusix DNS
    database, and emails an X-ARF v4 report. SQLite guarantees every ban is
    reported at most once.

    [:octicons-arrow-right-24: Abuse Reporter](abuse-reporter/index.md)

-   :material-chart-line:{ .lg .middle } **crowdsec-metrics-exporter**

    ---

    Reads the alerts behind the active decisions from the Local API and writes
    them to InfluxDB 2.x or QuestDB on every run. Keeps no local state — both
    backends deduplicate, so a repeated run is a no-op.

    [:octicons-arrow-right-24: Metrics Exporter](metrics-exporter/index.md)

</div>

## At a glance

| | crowdsec-abuse-reporter | crowdsec-metrics-exporter |
|---|---|---|
| **What it does** | Turns CrowdSec bans into abuse reports | Exports CrowdSec decisions as time series |
| **Source** | CrowdSec Local API (LAPI), direct | CrowdSec Local API (LAPI), direct |
| **Output** | X-ARF v4 email to the abuse contact | InfluxDB 2.x or QuestDB (line protocol over HTTP) |
| **Enrichment** | GeoIP (GeoLite2 City + ASN) | — |
| **Contact lookup** | Abusix DNS abuse-contact database | — |
| **Idempotency** | SQLite, at-most-once per `(AlertId, IPAddress)` | Backend-side deduplication, no local state |
| **Local state** | SQLite database, heartbeat files | None beyond a heartbeat on tmpfs |
| **Runs as** | Docker container, or cron/host script | Docker container, or cron/host script |
| **Tests** | pytest suite | None |

!!! info "Neither tool needs the Docker socket"
    Both reach CrowdSec over the Local API and authenticate with their own
    watcher credentials. An earlier version of the exporter shelled out to
    `docker exec <container> cscli ...`, which required mounting
    `/var/run/docker.sock` — equivalent to root on the host. That path is gone
    and must not be reintroduced.

## Quick start

Both tools deploy the same way: copy the environment template, fill in your
CrowdSec credentials, start the Compose stack.

```bash
git clone https://github.com/Gill-Bates/crowdsec-toolbox.git
cd crowdsec-toolbox/crowdsec-abuse-reporter/docker
cp settings.env.example settings.env
# edit settings.env: LAPI credentials, SMTP server, sender address
docker compose pull && docker compose up -d
```

[:material-rocket-launch: Installation Guide](getting-started/installation.md){ .md-button .md-button--primary }
[:material-docker: Docker Deployment](getting-started/docker.md){ .md-button }

## Grafana dashboards

Both tools ship ready-made dashboards in their `grafana/` directory. Import the
JSON, pick your data source, and you have a working view of what CrowdSec is
blocking — no provisioning and no plugins beyond the data source itself.

[:material-view-dashboard: Dashboard Reference](reference/dashboards.md){ .md-button }

## Where to go next

- [Metrics Backends](reference/metrics-backends.md) — the InfluxDB and QuestDB
  variables, deduplication and retention behaviour both tools share
- [Delivery Guarantees](abuse-reporter/delivery.md) — the at-most-once contract
  that decides whether an abuse mail may be sent
- [Health Checks](reference/health.md) — what "healthy" means for each container
- [Security Model](reference/security.md) — privilege drop, capabilities, secret handling
- [Build Pipelines](development/pipelines.md) — what CI gates and how images are published

!!! important
    *CrowdSec Toolbox* is an independent community project. It is not affiliated
    with, endorsed by, or sponsored by CrowdSec.

## License

Released under the [MIT License](https://github.com/Gill-Bates/crowdsec-toolbox/blob/main/LICENSE).
