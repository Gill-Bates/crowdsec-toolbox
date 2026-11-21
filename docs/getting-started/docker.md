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

The tracked Compose files pull the moving `latest` image tag rather than
building locally. Scheduling lives in `settings.env`; Compose does not override
those scheduling values.

To update an already running deployment:

```bash
docker compose down && docker compose pull && docker compose up -d
```

## Logs, timezone and shutdown

| Setting | Abuse reporter | Metrics exporter |
|---|---|---|
| Restart policy | `unless-stopped` | `unless-stopped` |
| Stop grace period | `180s` | `2m` |
| Timezone | UTC (no `TZ` setting) | UTC (no `TZ` setting) |
| Log rotation | `json-file`, `50m` per file, 5 files | `json-file`, `50m` per file, 5 files |

Read recent output with
`docker compose logs --tail=100`; add `-f` to follow it. The stop grace periods
allow an in-flight operation to finish before Docker sends SIGKILL. Each image
defines the health check that matches its heartbeat files; Compose does not
replace it with a generic command.

## Building the images

The build context is **the repository root**, because each Dockerfile copies the
tool's `pyproject.toml` alongside its sources with repo-relative paths. Running
`docker build .` from inside a `docker/` directory is intentionally unsupported.

The manual build commands for both tools live in the root `setup.conf`:

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
  --secret id=python_libraries_token,env=PYTHON_LIBRARIES_TOKEN \
  -t "docker.cirrio.de/${PROJECT}:latest" \
  --push .
```

`PYTHON_LIBRARIES_TOKEN` is a GitHub token with read access to the private
`Gill-Bates/python-libraries` repository (fine-grained PAT: `Contents: read`). It reaches the
build only as a BuildKit secret mounted on the one `RUN` that installs `gillbates-logging` (and the other shared packages: `gillbates-questdb-client`, and `gillbates-smtp-client` for the abuse reporter);
it never lands in an `ARG`, `ENV`, layer or the final image, and `git` is purged in the same step.

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
read by `entrypoint.sh`, so they belong in `settings.env`, not in the application
configuration. The templates list the supported scheduling variables and their
deployment defaults.

| Variable | Default | Meaning |
|---|---:|---|
| `RUN_ONCE` | `false` | `true` runs once and exits |
| `RUN_EVERY_HOUR` | `6` for reporter; unset for exporter | Interval in hours; takes precedence over `RUN_INTERVAL` |
| `RUN_INTERVAL` | `21600` for reporter; `60` for exporter | Interval in seconds |
| `METRICS_INTERVAL` | `60` (reporter only) | Separate metrics snapshot interval |
| `API_HEARTBEAT_INTERVAL` | `300` (reporter only) | CrowdSec LAPI heartbeat interval |

In periodic mode, invalid numeric scheduling values stop the entrypoint before
the scheduled loop starts. The reporter also validates the LAPI heartbeat
interval and, when metrics are enabled, the metrics interval before starting
those background loops.

### Automatic jitter

There is no jitter setting. The entrypoint derives the maximum jitter from the
interval: `min(interval / 10, 300)` seconds (0 below 10 seconds). A random start
offset of up to that size delays the first run, so hosts started together do not
fire together. Later runs follow the fixed grid `start + k * interval`, each plus
a random jitter, so run time does not shift the cadence. A run that outlasts its
interval skips the missed slots (a warning names how many) instead of catching
up.

With `EVENTS_ENABLED=true`, the exporter entrypoint warns if `EVENTS_SINCE` is shorter than the
interval plus the maximum jitter, because events could then fall between two runs.

### Container restart and shutdown

| Setting | Reporter behavior |
|---|---|
| `restart: unless-stopped` | Restarts after any exit, including a dead helper loop (exit `1`) and a Docker daemon restart; a container you stopped stays stopped |
| `stop_grace_period: 180s` | Gives an in-flight report time to finish after Docker sends SIGTERM |

`tini` is PID 1 inside the image, so Compose sets no `init: true`. The entrypoint
needs bash 5.1 or newer (`wait -n -p`), which the image provides.

Use `docker compose run --rm -e RUN_ONCE=true crowdsec-abuse-reporter` for a
manual one-shot run: `run` creates the container with restart policy `no`, whereas
`RUN_ONCE=true` under `up` would be restarted after every exit `0`. Do not run a
one-shot while the service uses the same SQLite data.

The exporter uses the same pattern: `restart: unless-stopped`, `tini` as PID 1, and
`docker compose run --rm -e RUN_ONCE=true crowdsec-metrics-exporter` for one export.

## Privilege model

The abuse reporter starts as root so the entrypoint can fix ownership of the paths
Docker creates (a missing bind-mount source is created root-owned). It then
`exec gosu app:app` and nothing past that line runs as root. The metrics exporter
has no bind mount and runs as `10001:10001` from the start, without `gosu`. The
application user of both is uid/gid `10001`.

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

    The in-container path is fixed to `/data` by `entrypoint.sh` and is not
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
- InfluxDB 2.x or QuestDB 10.x (exporter, and the reporter when metrics are enabled); any other QuestDB version makes the run exit `1`

If CrowdSec runs in a separate Compose project, connect both projects to a
shared external Docker network or set `CROWDSEC_LAPI_URL` to an address reachable
from this container. No static container address is required.

DNS uses only the container's system resolver — under Docker usually the embedded
resolver `127.0.0.11`. There is no environment variable for it and no public
resolver fallback.

### Host identity

Both Compose files mount the host's `/etc/hostname` read-only at
`/run/host/hostname` so the `host` tag stays stable across container recreation.
`HOSTNAME_OVERRIDE` takes precedence when set, and for the abuse reporter it is
the supported way to keep the *reported* node identity stable regardless of the
container's address.

For the reporting identity of the abuse reporter, see
[Reporting identity](../abuse-reporter/configuration.md#reporting-identity).

## Next steps

- [Health Checks](../reference/health.md) — what turns a container unhealthy
- [Security Model](../reference/security.md) — capabilities and hardening
- [Build Pipelines](../development/pipelines.md) — what CI verifies about these Dockerfiles
