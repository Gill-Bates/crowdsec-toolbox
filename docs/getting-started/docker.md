# Docker Deployment

Each tool has its own image, Compose file and entrypoint under its `docker/`
directory. They share nothing at runtime, so they are deployed and updated
separately.

## Running a tool

```bash
cd crowdsec-abuse-reporter/docker      # or crowdsec-metrics-exporter/docker
cp settings.env.example settings.env
# edit settings.env
docker compose pull && docker compose up -d
```

Released images are published to one Docker Hub repository, with the tool name in
the tag:

```bash
docker pull giiibates/crowdsec-toolbox:abuse-reporter-latest
docker pull giiibates/crowdsec-toolbox:metrics-exporter-latest
```

There is no bare `latest` tag — with two tools in one repository it could only
mean one of them. See [Build Pipelines](../development/pipelines.md#release).

!!! note "The tracked Compose files point elsewhere"
    They reference `docker.cirrio.de`, the private registry the manual
    `setup.conf` build pushes to. Change `image:` to the Docker Hub tag above if
    you want the published image instead.

The tracked Compose files pull a prebuilt image from the registry rather than
building locally. Scheduling lives in `settings.env`, not in the Compose file —
see [Scheduling](#scheduling).

To update an already running deployment:

```bash
docker compose down && docker compose pull && docker compose up -d
```

## Building the images

The build context is **the repository root**, because each Dockerfile copies the
tool's `pyproject.toml` alongside its sources with repo-relative paths. Running
`docker build .` from inside a `docker/` directory is intentionally unsupported.

The canonical commands live in the root `setup.conf`:

```bash
PROJECT="crowdsec-abuse-reporter" && \
cd /opt/crowdsec-toolbox && \
VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("'"${PROJECT}"'/pyproject.toml", "rb"))["project"]["version"])')" && \
GIT_SHA="$(git rev-parse --verify HEAD)" && \
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" && \
docker buildx build \
  --platform linux/amd64 \
  --pull \
  -f "${PROJECT}/docker/Dockerfile" \
  --build-arg APP_VERSION="$VERSION" \
  --build-arg GIT_SHA="$GIT_SHA" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  -t "docker.cirrio.de/${PROJECT}:latest" \
  --push .
```

Substitute `crowdsec-metrics-exporter` for `PROJECT` to build the other image;
the command is otherwise identical.

!!! note "The three build args have no defaults"
    `APP_VERSION`, `GIT_SHA` and `BUILD_DATE` are declared without defaults on
    purpose — the image is never built without them. They land in the startup
    banner and in the image's OCI labels
    (`org.opencontainers.image.version`, `.revision`, `.created`).

`APP_VERSION` comes from `[project].version` in that tool's own `pyproject.toml`, which
is the single source of truth for the version of both tools.

### Build context filtering

Each Dockerfile has a neighbouring `Dockerfile.dockerignore` that BuildKit picks
up automatically. These are **allowlists**: everything is excluded except the
tool's own manifest, its `app/`, its entry point and its entrypoint script.
Secrets, databases, tests, the Grafana dashboards and the sibling tool never
reach the build context.

The repo-root `.dockerignore` is a denylist fallback for legacy non-BuildKit
builders, which ignore the per-Dockerfile file. It exists as defence in depth so
that even `DOCKER_BUILDKIT=0 docker build -f .../Dockerfile .` cannot ship
`settings.env` or a `*.db` file to the daemon.

## Scheduling

Both entrypoints turn a one-shot script into a periodic job. The variables are
read by `entrypoint.sh`, so they belong in `settings.env` and appear only in the
`docker/settings.env.example` templates.

| Variable | Meaning |
|---|---|
| `RUN_ONCE` | `true` runs once and exits |
| `RUN_EVERY_HOUR` | Interval in hours; takes precedence over `RUN_INTERVAL` |
| `RUN_INTERVAL` | Interval in seconds (abuse reporter default `21600` = 6 h, exporter default `60`) |
| `RUN_JITTER` | Up to this many random seconds *after each run*, before the interval sleep |
| `METRICS_INTERVAL` | Abuse reporter only: separate metrics-snapshot loop, default `60` s |
| `API_HEARTBEAT_INTERVAL` | Abuse reporter only: LAPI heartbeat loop, default `300` s |

All values are validated as integers and the entrypoint exits non-zero on bad
input. `RUN_JITTER` applies after a run rather than at container start, and its
in-script default is `0` — the effective default comes from the Dockerfile `ENV`
block and the Compose file.

!!! warning "Scheduling does not belong in `docker-compose.yml`"
    Entries under Compose's `environment:` key override `env_file`, which would
    make an operator's edit in `settings.env` silently ineffective. Compose sets
    only `TZ` for that reason.

## Privilege model

Both containers start as root so the entrypoint can fix ownership of the paths
Docker creates (a missing bind-mount source is created root-owned). They then
`exec gosu app:app` and nothing past that line runs as root. The application
user is uid/gid `10001`.

`/app` deliberately stays root-owned and read-only to the app user: an
app-writable `entrypoint.sh` would let a compromised unprivileged process plant
code that the next container start executes as root.

See [Security Model](../reference/security.md) for the capability set and the
rest of the hardening.

## Persistent data

=== "crowdsec-abuse-reporter"

    Reads `./settings.env` and writes all mutable state to `./data/`, both
    relative to `docker/`:

    | Path | Contents |
    |---|---|
    | `data/abuse_alerts.db` | The at-most-once claim database |
    | `data/heartbeat` | Refreshed only after an exit-0 main run |
    | `data/api_heartbeat` | Written by the background LAPI heartbeat loop |

    The in-container path is hardcoded to `/data` by `entrypoint.sh` and is not
    read from the environment. A deployment that needs the data elsewhere
    bind-mounts a different host path onto `/data`.

    !!! danger "Do not discard `data/`"
        `abuse_alerts.db` is the only record of what has already been reported.

=== "crowdsec-metrics-exporter"

    Keeps **no state at all**. There is no `./data` bind mount and no volume.
    The only runtime file is the heartbeat, at the fixed path `/tmp/state` on the
    container's tmpfs.

    Deduplication happens in the backend, so nothing has to survive container
    recreation. After a restart the container is unhealthy until its first
    successful export, which the health check's `--start-period` covers.

## Networking

The tracked Compose files use a plain bridge network, deliberately free of
site-specific networks and addresses. From that network the container must
reach:

- the CrowdSec LAPI (both tools)
- the SMTP server and the Abusix DNS zone (abuse reporter)
- InfluxDB or QuestDB (exporter, and the reporter when metrics are enabled)

Attach the container to an existing Docker network, and pin an address, if your
setup requires it.

DNS uses only the container's system resolver — under Docker usually the embedded
resolver `127.0.0.11`. There is no environment variable for it and no public
resolver fallback.

### Host identity

Both Compose files mount the host's `/etc/hostname` read-only at
`/run/host/hostname` so the `host` tag stays stable across container recreation.
`HOSTNAME_OVERRIDE` takes precedence when set, and for the abuse reporter it is
the supported way to keep the *reported* node identity stable regardless of the
container's address.

!!! warning "Set `HOSTNAME_OVERRIDE` in a container"
    For the abuse reporter this value is the public reporting identity in the
    X-ARF mail. Left empty, autodetection falls back to the private container IP
    unless `PUBLIC_IP_DETECTION` resolves a WAN address.

## Next steps

- [Health Checks](../reference/health.md) — what turns a container unhealthy
- [Security Model](../reference/security.md) — capabilities and hardening
- [Build Pipelines](../development/pipelines.md) — what CI verifies about these Dockerfiles
