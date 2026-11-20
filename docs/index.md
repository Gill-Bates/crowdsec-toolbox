---
hide:
  - toc
---

<section class="cst-hero" aria-labelledby="home-title">
<div class="cst-hero-brand">
  <img src="https://raw.githubusercontent.com/Gill-Bates/crowdsec-toolbox/main/.github/img/crowdsec_toolbox_black.svg#only-light" width="72" height="70" alt="CrowdSec Toolbox" class="cst-logo">
  <img src="https://raw.githubusercontent.com/Gill-Bates/crowdsec-toolbox/main/.github/img/crowdsec_toolbox_white.svg#only-dark" width="72" height="70" alt="CrowdSec Toolbox" class="cst-logo">
  <span class="cst-eyebrow">Security automation · CrowdSec Toolbox</span>
</div>

<div class="cst-hero-copy">
  <h1 id="home-title">Turn security decisions into actionable signals.</h1>
  <p>Report malicious activity, export security metrics, and gain better visibility into what CrowdSec is blocking.</p>
  <div class="cst-hero-actions">
    <a href="getting-started/index.md" class="md-button md-button--primary">Get Started</a>
    <a href="#tools" class="md-button">Explore the Tools</a>
  </div>
</div>
</section>

## Two tools, one source

CrowdSec Toolbox reads decisions from the CrowdSec Local API. Choose the reporter
to send abuse reports, the exporter to send time-series metrics, or run both.

<h2 id="tools">Choose a workflow</h2>

<div class="grid cards cst-card-grid" markdown>

-   :material-email-alert:{ .cst-product-icon } **Abuse Reporter**

    ---

    Turns CrowdSec bans into X-ARF v4.2.0 reports. It enriches source IPs with GeoIP,
    resolves the responsible abuse contact through Abusix DNS, and records each
    `(AlertId, IPAddress)` pair in SQLite so it is reported at most once.

    `X-ARF v4.2.0` · `GeoIP enrichment` · `At-most-once delivery`

    [Explore Abuse Reporter](abuse-reporter/index.md){ .cst-card-link }

-   :material-chart-line:{ .cst-product-icon } **Metrics Exporter**

    ---

    Reads alerts behind active decisions from the CrowdSec Local API and writes
    them to InfluxDB 2.x or QuestDB. Both backends deduplicate repeated exports;
    the exporter keeps no persistent local state.

    `InfluxDB 2.x` · `QuestDB 10.x` · `Backend deduplication`

    [Explore Metrics Exporter](metrics-exporter/index.md){ .cst-card-link }

</div>

## Built for real-world operations

<div class="grid cards cst-feature-grid" markdown>

-   :material-docker:{ .cst-feature-icon } **Flexible Deployment**

    Run the tools with Docker Compose or directly on a host with cron.

    [Deployment options](getting-started/installation.md){ .cst-card-link }

-   :material-view-dashboard:{ .cst-feature-icon } **Grafana Dashboards**

    Import the shipped dashboards for decision, report, and event data.

    [Dashboard reference](reference/dashboards.md){ .cst-card-link }

-   :material-check-decagram:{ .cst-feature-icon } **Reliable Processing**

    The reporter uses an at-most-once claim protocol; the exporter relies on
    backend deduplication for repeated points.

    [Report delivery](abuse-reporter/delivery.md){ .cst-card-link } · [Metric deduplication](reference/metrics-backends.md#deduplication){ .cst-card-link }

-   :material-shield-check:{ .cst-feature-icon } **Security by Design**

    Both tools authenticate directly to the CrowdSec Local API and do not mount
    the Docker socket.

    [Security model](reference/security.md){ .cst-card-link }

</div>

## Data flow

These ordered paths show which systems each tool reads from and writes to.

<div class="cst-flow-grid">
  <section class="cst-flow" aria-labelledby="flow-abuse-title">
    <h3 id="flow-abuse-title">Abuse reporting</h3>
    <ol class="cst-flow-steps">
      <li>CrowdSec LAPI</li>
      <li>Abuse Reporter</li>
      <li>X-ARF email</li>
    </ol>
  </section>
  <section class="cst-flow" aria-labelledby="flow-metrics-title">
    <h3 id="flow-metrics-title">Metrics export</h3>
    <ol class="cst-flow-steps">
      <li>CrowdSec LAPI</li>
      <li>Metrics Exporter</li>
      <li>InfluxDB 2.x / QuestDB</li>
    </ol>
  </section>
</div>

## At a glance

| | crowdsec-abuse-reporter | crowdsec-metrics-exporter |
|---|---|---|
| **What it does** | Turns CrowdSec bans into abuse reports | Exports CrowdSec decisions as time series |
| **Source** | CrowdSec Local API (LAPI), direct | CrowdSec Local API (LAPI), direct |
| **Output** | X-ARF v4.2.0 email to the abuse contact | InfluxDB 2.x or QuestDB 10.x (line protocol over HTTP) |
| **Enrichment** | GeoIP (GeoLite2 City + ASN) | — |
| **Contact lookup** | Abusix DNS abuse-contact database | — |
| **Idempotency** | SQLite, at-most-once per `(AlertId, IPAddress)` | Backend-side deduplication, no local state |
| **Local state** | SQLite database, heartbeat files | None beyond a heartbeat on tmpfs |
| **Runs as** | Docker container, or cron/host script | Docker container, or cron/host script |
| **Tests** | pytest suite | pytest suite (pure logic) |

!!! info "Neither tool needs the Docker socket"
    Both reach CrowdSec over the Local API and authenticate with their own
    watcher credentials.

## Quick start

Start with the abuse reporter's Compose deployment:

```bash
git clone https://github.com/Gill-Bates/crowdsec-toolbox.git
cd crowdsec-toolbox/crowdsec-abuse-reporter/docker
cp settings.env.example settings.env
# Fill in CrowdSec credentials, SMTP server, and sender address.
docker compose pull && docker compose up -d
```

[:material-rocket-launch: Installation Guide](getting-started/installation.md){ .md-button .md-button--primary }
[:material-docker: Docker Deployment](getting-started/docker.md){ .md-button }

## Grafana dashboards

Both tools ship ready-made QuestDB dashboards in their `grafana/` directories.
Import the JSON, choose a QuestDB data source and table, then follow the
[dashboard reference](reference/dashboards.md) for requirements and filters.

## Where to go next

- [Getting Started](getting-started/index.md) — shared prerequisites and deployment choices
- [Metrics Backends](reference/metrics-backends.md) — point schemas, deduplication, and retention
- [Delivery Guarantees](abuse-reporter/delivery.md) — the report at-most-once contract
- [Health Checks](reference/health.md) — what makes each container healthy
- [Security Model](reference/security.md) — privilege boundaries and secret handling
- [Build Pipelines](development/pipelines.md) — CI gates and image releases

!!! important
    *CrowdSec Toolbox* is an independent community project. It is not affiliated
    with, endorsed by, or sponsored by CrowdSec.

## License

Released under the [MIT License](https://github.com/Gill-Bates/crowdsec-toolbox/blob/main/LICENSE).
