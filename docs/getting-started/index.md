# Getting Started

Both tools in this repository consume the same source — the CrowdSec **Local API
(LAPI)** — and both authenticate as a registered machine (watcher). That is the
one prerequisite they share, so set it up first and reuse it for whichever tool
you deploy.

## Prerequisites

| Requirement | Abuse reporter | Metrics exporter |
|---|---|---|
| CrowdSec with a reachable Local API | required | required |
| Watcher credentials (machine ID + password) | required | required |
| Python 3.13+ (host runs only) | required | required |
| SMTP server | required | — |
| Outbound DNS to the Abusix zone | required | — |
| InfluxDB 2.x or QuestDB | optional | required |

!!! note "The Docker socket is not a prerequisite"
    Neither container mounts `/var/run/docker.sock`. The LAPI credentials are
    scoped to CrowdSec's API, not to the host.

## Get the LAPI credentials

CrowdSec stores the local machine credentials on the host running the LAPI:

```bash
docker exec -it crowdsec cat /etc/crowdsec/local_api_credentials.yaml
```

The `login` value is the machine ID and `password` is the watcher password. Both
tools accept them as environment variables:

```bash
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_MACHINE_ID=<login>
CROWDSEC_LAPI_PASSWORD=<password>
```

For direct host runs, either tool can instead read the credentials file itself
via `CROWDSEC_LAPI_CREDENTIALS_PATH` (default
`/etc/crowdsec/local_api_credentials.yaml`).

!!! warning "`127.0.0.1` means the container itself"
    Inside a container, `CROWDSEC_LAPI_URL=http://127.0.0.1:8080` points at the
    container, not at CrowdSec. Use the CrowdSec container's name on a shared
    Docker network, or the host's address on the container network.

## Pick a deployment style

=== "Docker Compose (recommended)"

    Each tool ships its own `docker/docker-compose.yml`, its own image and its
    own environment template. This is the supported path for both.

    [:octicons-arrow-right-24: Docker Deployment](docker.md)

=== "Direct host run"

    Both tools also run as plain Python scripts on the CrowdSec host, scheduled
    with cron. There is no entrypoint in this mode, so the `RUN_*` scheduling
    variables do not apply.

    [:octicons-arrow-right-24: Installation](installation.md)

## Configuration files

Real configuration is never committed. Only `settings.env.example` templates are
tracked; `settings.env` and any `settings-*.env` profiles are gitignored and
dockerignored.

| File | Purpose |
|---|---|
| `crowdsec-abuse-reporter/docker/settings.env.example` | Template for the abuse reporter's container config |
| `crowdsec-metrics-exporter/docker/settings.env.example` | Template for the exporter's container config |

!!! danger "Secrets are stored in plain text"
    `SMTP_PASSWORD`, `CROWDSEC_LAPI_PASSWORD`, `INFLUXDB_TOKEN` and the QuestDB
    credentials are read as plaintext from `settings.env`. Keep the file private
    and never commit it. Credentials that were tracked in the former monorepo
    must be treated as exposed until rotated.

## Next steps

- [Installation](installation.md) — venv setup and direct host runs
- [Docker Deployment](docker.md) — building, running and updating the containers
- [Abuse Reporter](../abuse-reporter/index.md) / [Metrics Exporter](../metrics-exporter/index.md) — per-tool guides
