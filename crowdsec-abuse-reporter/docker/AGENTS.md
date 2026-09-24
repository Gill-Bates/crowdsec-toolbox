<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-18 | Updated: 2026-09-23 -->

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
| `Dockerfile` | `python:3-slim` (unpinned, latest), non-root user `app` (uid/gid 10001), env defaults, HEALTHCHECK |
| `entrypoint.sh` | Root→`gosu` privilege drop, periodic run loop, background LAPI heartbeat, signal forwarding |
| `docker-compose.yml` | Hardened service definition on a plain bridge network; deliberately free of site-specific networks and addresses |
| `settings.env.example` | Template for `./settings.env`; must list every supported variable |
| `Dockerfile.dockerignore` | Allowlist for the repo-root build context under BuildKit — only `../pyproject.toml`, `app/`, `run.py`, `entrypoint.sh` get in. The manifest entry must name this tool's own `crowdsec-abuse-reporter/pyproject.toml`; a stale root-level `!pyproject.toml` keeps it out of the context and the pip layer fails with "not found". Legacy (non-BuildKit) builders ignore this file; the root `../../.dockerignore` denylist is the fallback for those |
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
  and a `noexec,nosuid,nodev` tmpfs for `/tmp`. Keep all of it intact.
- **Healthcheck contract.** Two files must both be fresh: `/data/heartbeat`
  (written by the entrypoint *only after an exit-0 main run*) and
  `/data/api_heartbeat` (written by `python -m app.heartbeat`). Never touch
  `/data/heartbeat` unconditionally — that would keep the check green while
  processing repeatedly fails.
- **Signal handling.** `_MAIN_PID`, `_HEARTBEAT_PID` and `_SLEEP_PID` are
  tracked so TERM/INT reach the running job. Long sleeps run as background jobs
  with `wait`, because bash defers traps until a foreground command returns.
- Adding or renaming an env var means updating `settings.env.example` and, if it
  has a default, the `ENV` block in the `Dockerfile`.
- **Known drift in `settings.env.example`** (do not treat it as a spec):
  `CROWDSEC_LAPI_CREDENTIALS_PATH` is supported by `config.py` but appears only
  as a comment. `app/config.py` is the authoritative list.

### Scheduling
`RUN_ONCE=true` runs once and exits. Otherwise the interval comes from
`RUN_EVERY_HOUR` (hours, takes precedence) or `RUN_INTERVAL` (seconds, default
21600 = 6 h). When metrics are enabled, a separate `METRICS_INTERVAL` loop
(default 60 seconds) writes snapshots without sending mail. `RUN_JITTER` adds up to that many random seconds *after each run*,
before the interval sleep — not at container start. Its default inside
`entrypoint.sh` is `0`; the effective default comes from the `ENV` block in the
`Dockerfile` and from `docker-compose.yml`, so a bare shell run of the script
jitters not at all. All three values are validated as integers and the script
exits non-zero on bad input.

### Testing Requirements
`EntrypointHardeningTest` in `../tests/test_hardening.py` asserts against this
directory — partly by grepping `entrypoint.sh` for its guard messages, partly by
executing it. Changing a validation message there will break those tests.
`test_entrypoint_rejects_non_integer_run_jitter` fails on hosts without `gosu`;
that is environmental.

Build and deploy commands live in `../setup.conf` and are the source of truth:
```bash
cd <repo root>
docker buildx build --platform linux/amd64 --pull -f crowdsec-abuse-reporter/docker/Dockerfile \
  --build-arg APP_VERSION=... --build-arg GIT_SHA=... --build-arg BUILD_DATE=... \
  -t docker.cirrio.de/crowdsec-abuse-reporter:latest --push .
```
`setup.conf` reads `APP_VERSION` from this tool's own `pyproject.toml`, resolves
`GIT_SHA` from `HEAD`, and supplies both values to the image build.

### Common Patterns
- `set -e` with deliberate `set +e` / `set -e` fences around the main run so its
  exit code can be inspected instead of aborting the loop.
- Validation via `case` patterns on the raw string before any arithmetic.

## Dependencies

### Internal
- `../app/`, `../run.py`, `../pyproject.toml` (group `default`) — copied into the image;
  the build context is the repo root
- `../setup.conf` — the canonical build/push/deploy commands
- `../tests/test_hardening.py` — asserts on `entrypoint.sh`

### External
- Base image `python:3-slim` (unpinned, latest)
- apt packages: `ca-certificates`, `gosu`, `iproute2`, `tzdata`
- A Docker network from which the CrowdSec LAPI, SMTP and DNS are reachable
  (the tracked Compose file uses the default bridge); registry
  `docker.cirrio.de`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
