
<p align="center">
  <img src="../.github/img/crowdsec_toolbox_black.svg#gh-light-mode-only" width="250" alt="CrowdSec Toolbox">
  <img src="../.github/img/crowdsec_toolbox_white.svg#gh-dark-mode-only" width="250" alt="CrowdSec Toolbox">
</p>

# crowdsec-metrics-exporter

Exports CrowdSec ban decisions as time series to InfluxDB 2.x or QuestDB. It
reads the alerts behind the currently active decisions from the CrowdSec Local
API and writes them to the configured backend on every run. It needs **no**
access to the Docker socket and keeps no local state.

## Highlights

- **No local state.** Both backends deduplicate on write, so a repeated export
  is a no-op — no database, no watermark, no persistent volume.
- **Two backends, one payload.** InfluxDB 2.x or QuestDB, both fed the same
  InfluxDB Line Protocol data.
- **Per-event export.** Optionally export request-level detail (HTTP path,
  status, target FQDN) alongside the per-alert summary.
- **Ready-made Grafana dashboard.** A world map, alert/event history, top
  scenarios and source IPs, out of the box.

## Quick start

```bash
cd crowdsec-metrics-exporter
source setup.conf    # venv at /opt/jobs/crowdsec_influx + dependencies
cp docker/settings.env.example settings.env
# edit settings.env: CrowdSec LAPI credentials, InfluxDB or QuestDB connection
python main.py
```

Or run it as a container: see the Docker deployment guide linked below.

## Documentation

Full configuration reference, per-event export, metrics backends and Grafana
dashboards live in the
[CrowdSec Toolbox documentation](https://gill-bates.github.io/crowdsec-toolbox/metrics-exporter/).

## Disclaimer

crowdsec-metrics-exporter is an independent community project. It is not
affiliated with, endorsed by, or sponsored by CrowdSec.
