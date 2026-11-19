<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-11-18 -->

# docker

## Purpose
Everything needed to build and run `crowdsec-abuse-reporter` as a container: the image
definition, the Compose service, the supervising entrypoint that turns a
one-shot script into a periodic job, and the configuration template. The
container talks to the CrowdSec Local API over the network and therefore needs
**no** access to `/var/run/docker.sock`.

## Key Files
| File | Description |
|------|-------------|
| `Dockerfile` | `python:slim` (unpinned, latest), GeoLite2 baseline from P3TERX's moving download paths, non-root user `app` (uid/gid 10001), `tini` as PID 1 (`ENTRYPOINT ["/usr/bin/tini", "--", "./entrypoint.sh"]`), env defaults, HEALTHCHECK |
| `entrypoint.sh` | Root→`gosu` privilege drop, periodic run loop, background LAPI heartbeat and optional metrics loop treated as required children (death ends the container with exit 1), process-group signal forwarding |
| `docker-compose.yml` | Hardened service definition on a plain bridge network; deliberately free of site-specific networks and addresses |
| `settings.env.example` | Template for `./settings.env`; must list every supported variable |
| `Dockerfile.dockerignore` | Allowlist for the repo-root build context under BuildKit — only `crowdsec-abuse-reporter/pyproject.toml`, `app/`, `run.py`, `docker/entrypoint.sh` get in. The manifest entry must name this tool's own `crowdsec-abuse-reporter/pyproject.toml`; a stale root-level `!pyproject.toml` keeps it out of the context and the pip layer fails with "not found". Legacy (non-BuildKit) builders ignore this file; the root `../../.dockerignore` denylist is the fallback for those |
| `.gitignore` | Ignores `data/*` except `.gitkeep` |
| `data/.gitkeep` | Keeps the bind-mount source directory in git |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `data/` | Empty bind-mount source for `/data`; holds only `.gitkeep` in git |

## For AI Agents

### Working In This Directory
- **Privilege model.** The container starts as root purely so the entrypoint can
  `chown` `$DATA_DIR` (Docker creates a missing bind-mount source as root), then
  `exec gosu app:app` for everything after. Nothing past that line runs as root.
  `/app` deliberately stays root-owned and read-only to the app user: an
  app-writable `entrypoint.sh` would let a compromised unprivileged process
  plant code that the next container start executes as root.
- **`DATA_DIR` is hardcoded.** `entrypoint.sh` sets `DATA_DIR="/data"`
  unconditionally; it is not read from the environment. A deployment that
  needs the data elsewhere bind-mounts a different host path onto the
  container's `/data` in its own compose file — it does not override the
  in-container path.
- **Compose hardening.** `read_only: true`, `cap_drop: [ALL]` with only
  `CHOWN`/`SETUID`/`SETGID` added back, `no-new-privileges`, `pids_limit: 128`,
  and a `noexec,nosuid,nodev` tmpfs for `/tmp`. Keep all of it intact. Compose
  also rotates each service's `json-file` logs at 50 MB, retaining five files.
- **Healthcheck contract.** Two files must both be fresh: `/data/heartbeat`
  (written by the entrypoint *only after an exit-0 main run*) and
  `/data/api_heartbeat` (written by `python -m app.heartbeat`). Never touch
  `/data/heartbeat` unconditionally — that would keep the check green while
  processing repeatedly fails. In addition `/tmp/api_heartbeat.pid` (and
  `/tmp/metrics.pid` when metrics are enabled) hold `<pid> <start time>` of the
  helper loops; the check requires the pid to exist, not be a zombie and keep
  its `/proc/<pid>/stat` start time. When `METRICS_BACKEND` is set and not
  `none` (same condition as the entrypoint) `/tmp/metrics_heartbeat`, touched
  after each exit-0 metrics snapshot, must be younger than
  `METRICS_HEARTBEAT_MAX_AGE_SECONDS` (default `10 * METRICS_INTERVAL + 300`).
  **Limits.** The HEALTHCHECK does no arithmetic on config values: the
  entrypoint derives `main = interval + max jitter + 7200`,
  `LAPI = API_HEARTBEAT_INTERVAL + 400` and the metrics limit (0 when off) once,
  with `10#` so leading zeros stay decimal, and writes `<main> <api> <metrics>`
  atomically to `/tmp/health_limits` (a missing file means unhealthy; none is
  written in `RUN_ONCE`). An explicit `HEALTHCHECK_MAX_AGE_SECONDS`,
  `API_HEARTBEAT_MAX_AGE_SECONDS` or `METRICS_HEARTBEAT_MAX_AGE_SECONDS` wins and
  is validated as a positive integer up to 31536000. A backend outage therefore only makes the
  container `unhealthy`, it never restarts it. All new state lives on the
  `/tmp` tmpfs, not on `/data`.
- **Supervision.** The LAPI heartbeat loop and the metrics loop are required
  children. `_await_job` uses `wait -n -p` (bash >= 5.1, checked at start) on
  the current job together with the helper PIDs, so a dead loop is noticed
  during a run and during every sleep: the entrypoint terminates the remaining
  jobs and exits 1 (restart policy restarts the container). A failing
  `python` call inside a loop is tolerated (`|| log WARNING ...`); only the loop
  itself ending counts. TERM/INT still exit 0.
- **Signal handling.** `set -m` gives every background job its own process
  group; `_terminate_children` signals `-PID`, so python/sleep children of a
  helper loop are terminated too (without it they are orphaned until the
  container is torn down). `tini` (no `-g`) forwards the stop signal to the
  entrypoint only. Long sleeps run as background jobs awaited with `wait -n`,
  because bash defers traps until a foreground command returns.
- **Restart policy.** The service uses `restart: unless-stopped`. A one-shot
  run must use `docker compose run --rm -e RUN_ONCE=true crowdsec-abuse-reporter`:
  `run` creates the container with restart policy `no` (verified with Compose
  v5.6.1), whereas `RUN_ONCE=true` under `up` would be restarted after every
  exit 0.
- Adding or renaming an env var means updating `settings.env.example` and, if it
  has a default, the `ENV` block in the `Dockerfile`.
- **Known drift in `settings.env.example`** (do not treat it as a spec):
  `CROWDSEC_LAPI_CREDENTIALS_PATH` is supported by `config.py` but appears only
  as a comment. `app/config.py` is the authoritative list.

### GeoIP baseline
The image fetches GeoLite2 City and ASN from P3TERX's moving `raw/download/` paths.
Each rebuild may therefore contain newer data even when the source commit is unchanged.
The runtime updater in `app/geoip.py` follows the same moving paths.

### Scheduling
`RUN_ONCE=true` runs once and exits. Otherwise the interval comes from
`RUN_EVERY_HOUR` (hours, takes precedence) or `RUN_INTERVAL` (seconds, default
21600 = 6 h). When metrics are enabled, a separate `METRICS_INTERVAL` loop
(default 60 seconds) writes snapshots without sending mail. `METRICS_HEARTBEAT_MAX_AGE_SECONDS` (optional) sets the HEALTHCHECK limit for the last successful snapshot.
Jitter is automatic, there is no setting: the maximum is `min(interval / 10, 300)`
seconds. A random start offset of up to that size delays the first run; later runs
follow the fixed grid `base + k * interval` (no drift from run time), each plus
a random jitter. A run that outlasts its slot skips the missed slots with a
warning. The interval values
are validated as integers and the script exits non-zero on bad input.

### Testing Requirements
`EntrypointHardeningTest` and `EntrypointSupervisionTest` in `../tests/test_hardening.py`
assert against this directory — partly by grepping `entrypoint.sh` and the
Dockerfile, partly by executing the entrypoint with a stub `python`. Changing a validation message there will break those tests.

Build and deploy commands live in the root `setup.conf` and are the source of truth:
```bash
cd <repo root>
docker buildx build --platform linux/amd64 --pull -f crowdsec-abuse-reporter/docker/Dockerfile \
  --build-arg APP_VERSION=... --build-arg GIT_SHA=... --build-arg BUILD_DATE=... \
  -t docker.cirrio.de/crowdsec-abuse-reporter:latest --push .
```
The root `setup.conf` reads `APP_VERSION` from this tool's own `pyproject.toml`, resolves
`GIT_SHA` from `HEAD`, and supplies both values to the image build.

### Common Patterns
- `set -e` with deliberate `set +e` / `set -e` fences around the main run so its
  exit code can be inspected instead of aborting the loop.
- Validation via `case` patterns on the raw string before any arithmetic.

## Dependencies

### Internal
- `../app/`, `../run.py`, `../pyproject.toml` (group `default`) — copied into the image;
  the build context is the repo root
- `../../setup.conf` — the canonical build/push/deploy commands
- `../tests/test_hardening.py` — asserts on `entrypoint.sh`

### External
- Base image `python:slim` (unpinned, latest)
- apt packages: `ca-certificates`, `gosu`, `iproute2`, `tini`
- A Docker network from which the CrowdSec LAPI, SMTP and DNS are reachable
  (the tracked Compose file uses the default bridge); registry
  `docker.cirrio.de`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
