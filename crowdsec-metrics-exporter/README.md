<p align="center">
  <img src="../.github/img/crowdsec_toolbox_black.svg#gh-light-mode-only" width="250" alt="CrowdSec Toolbox">
  <img src="../.github/img/crowdsec_toolbox_white.svg#gh-dark-mode-only" width="250" alt="CrowdSec Toolbox">
</p>

<h1 align="center">crowdsec-metrics-exporter</h1>

<p align="center">
  <strong>Export CrowdSec decisions to InfluxDB 2.x or QuestDB.</strong>
</p>

<p align="center">
  <a href="https://github.com/Gill-Bates/crowdsec-toolbox/releases"><img src="https://img.shields.io/github/v/release/Gill-Bates/crowdsec-toolbox?logo=github&logoColor=white" alt="GitHub Release"></a>
  <a href="https://hub.docker.com/r/giiibates/crowdsec-toolbox"><img src="https://img.shields.io/docker/pulls/giiibates/crowdsec-toolbox?logo=docker&logoColor=white" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/giiibates/crowdsec-toolbox"><img src="https://img.shields.io/badge/Platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey?logo=linux&logoColor=white" alt="Supported Platforms"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#quick-start"><img src="https://img.shields.io/badge/Quick%20Start-168B75?style=for-the-badge&logo=docker&logoColor=white" alt="Quick Start"></a>
  <a href="https://gill-bates.github.io/crowdsec-toolbox/metrics-exporter/"><img src="https://img.shields.io/badge/Documentation-34495E?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation"></a>
</p>

Exports CrowdSec ban decisions as time series to InfluxDB 2.x or QuestDB. It
reads the alerts behind the currently active decisions from the CrowdSec Local
API and writes them to the configured backend on every run. It needs **no**
access to the Docker socket and keeps no local state.

## Highlights

- **No local state.** Both backends deduplicate on write, so a repeated export
  is a no-op — no database, no watermark, no persistent volume.
- **Two backends, one payload.** InfluxDB 2.x or QuestDB, both fed the same
  InfluxDB Line Protocol data.
- **QuestDB 10.x only.** The exporter checks the server version before any
  write and exits `1` for anything else; older data is not migrated.
- **QuestDB downsampling.** Optional `QUESTDB_DOWNSAMPLING` keeps recent rows at
  full resolution and the long-term history in a materialized rollup view.
- **Per-event export.** Optionally export request-level detail (HTTP path,
  status, target FQDN) alongside the per-alert summary.
- **Ready-made Grafana dashboards (QuestDB).** The core dashboard shows alert and host
  history, scenarios and source IPs; a separate optional dashboard shows
  request-level event details.

## Quick start

```bash
cd crowdsec-metrics-exporter
python3.14 -m venv /opt/jobs/crowdsec_influx && source /opt/jobs/crowdsec_influx/bin/activate
pip install --group pyproject.toml:default    # needs pip >= 25.1
cp docker/settings.env.example settings.env
# edit settings.env: CrowdSec LAPI credentials, InfluxDB or QuestDB connection
python main.py
```

Or run it as a container: see the
[Docker deployment guide](https://gill-bates.github.io/crowdsec-toolbox/getting-started/docker/).

## Documentation

Full configuration reference, per-event export, metrics backends and Grafana
dashboards live in the
[CrowdSec Toolbox documentation](https://gill-bates.github.io/crowdsec-toolbox/metrics-exporter/).

## Disclaimer

crowdsec-metrics-exporter is an independent community project. It is not
affiliated with, endorsed by, or sponsored by CrowdSec.
