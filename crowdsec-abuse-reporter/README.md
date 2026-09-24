
<p align="center">
  <img src="../.github/img/crowdsec_toolbox_black.svg#gh-light-mode-only" width="250" alt="CrowdSec Toolbox">
  <img src="../.github/img/crowdsec_toolbox_white.svg#gh-dark-mode-only" width="250" alt="CrowdSec Toolbox">
</p>

# crowdsec-abuse-reporter

Turns CrowdSec bans into abuse reports. It fetches decisions from the CrowdSec
Local API, enriches each source IP with GeoIP data, resolves the responsible
abuse contact via the Abusix DNS contact database, and emails an
[X-ARF v4](https://www.x-arf.org/) report. Every `(AlertId, IPAddress)` pair is
recorded in SQLite, so the same ban is reported **at most once**.

The container needs no access to `/var/run/docker.sock` — it talks to the LAPI
directly.

## Highlights

- **At-most-once delivery.** An atomic SQLite claim protocol makes sure a ban is
  never reported twice, even across a crash.
- **GeoIP enrichment.** GeoLite2 City and ASN data ships with the image, so
  reporting works from the first run.
- **Optional metrics.** Export report outcomes to InfluxDB 2.x or QuestDB
  without duplicating report data.
- **Ready-made Grafana dashboard.** Import it and see delivery status and
  origin countries immediately.
- **Hardened container.** Runs as a non-root user, read-only root filesystem,
  dropped capabilities.

## Quick start

```bash
cd crowdsec-abuse-reporter/docker
cp settings.env.example settings.env
# edit settings.env: CrowdSec LAPI URL/credentials, SMTP server and sender
docker compose pull && docker compose up -d
```

## Documentation

Full configuration reference, delivery guarantees, GeoIP internals, metrics
backends and Grafana dashboards live in the
[CrowdSec Toolbox documentation](https://gill-bates.github.io/crowdsec-toolbox/abuse-reporter/).

## Disclaimer

crowdsec-abuse-reporter is an independent community project. It is not affiliated with,
endorsed by, or sponsored by CrowdSec.
