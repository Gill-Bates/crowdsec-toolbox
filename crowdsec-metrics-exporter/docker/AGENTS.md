<!-- Parent: ../AGENTS.md -->

# Docker deployment

## Purpose

This directory contains the container image and Compose deployment for the
metrics exporter. The image runs `main.py` periodically through
`entrypoint.sh`, stores only its heartbeat at the fixed path `/tmp/state`
on the container's tmpfs (no host mount, not configurable), and
uses the `default` dependency group from this tool's own `pyproject.toml`.

## Files

| File | Description |
|------|-------------|
| `Dockerfile` | Builds the `python:3.13-slim` image and runs as the non-root user `10001:10001` from the start (`USER`), with `tini` as PID 1; no Docker CLI |
| `docker-compose.yml` | Compose service with a tmpfs (`mode=1777`) at `/tmp` for the heartbeat, `restart: unless-stopped`, no added capabilities; no Docker socket; the only mount is the host's `/etc/hostname` (read-only); scheduling lives in `settings.env` |
| `entrypoint.sh` | Creates `/tmp/state` as the unprivileged user, runs `main.py` once or periodically, and updates the heartbeat |
| `settings.env.example` | Container configuration template |

## Working in this directory

- Build from the repository root because the Dockerfile bind-mounts this
  tool's `pyproject.toml` and copies the exporter sources by repo-relative path.
  Use the root `setup.conf` (build section for this tool), which reads the version from
  `crowdsec-metrics-exporter/pyproject.toml`, resolves the current Git commit,
  and passes both values as build arguments.
- **No Docker socket.** The exporter reaches CrowdSec over the Local API, like
  its sibling. Earlier versions ran `docker exec <container> cscli ...`, which
  needed the host socket — equivalent to root on the host. Do not reintroduce
  it: the LAPI credentials are scoped to CrowdSec's API. Nothing needs
  root, capabilities or supplementary groups, so the image has no privilege
  drop (no `gosu`) and Compose has no `cap_add` or `group_add`.
- The container needs network access to `CROWDSEC_LAPI_URL`. Inside a
  container, `127.0.0.1` is the container itself — use the CrowdSec
  container's name on a shared network, or the host's address.
- Keep secrets in an external `settings.env`. The tracked example contains
  placeholders only. The exporter keeps no state that must survive container
  recreation, since deduplication happens in the backend.
- The Compose service rotates Docker `json-file` logs at 50 MB, retaining five
  files. Preserve this per-container logging policy when changing the service.
- Scheduling is configured in `settings.env`, not in `docker-compose.yml`.
  Compose sets no `environment` entries, because entries there override
  `env_file` and would make an operator's edit in `settings.env` silently
  ineffective. All timestamps are UTC; no `TZ` is set. `RUN_ONCE=true` performs one export
  and exits (`restart: unless-stopped` would restart it, so start it with
  `docker compose run --rm -e RUN_ONCE=true crowdsec-metrics-exporter`, which
  runs with restart policy `no`); otherwise the entrypoint runs periodically using `RUN_INTERVAL`
  or `RUN_EVERY_HOUR` (which takes precedence), with automatic jitter (`min(interval / 10, 300)` s: a random start offset, then a fixed run grid plus random jitter; missed slots of an overrunning run are skipped; with `EVENTS_ENABLED` a warning is logged if `EVENTS_SINCE` is shorter than interval + jitter).
  These scheduling settings are read by `entrypoint.sh`, not by the application
  — a direct host run ignores them. `RUN_EVERY_HOUR` is not in
  `settings.env.example`. The optional `HEALTHCHECK_MAX_AGE_SECONDS` override
  must be at least `max(900, interval + jitter + 300)`; otherwise startup fails.

## Health and failure behavior

The entrypoint atomically writes the health age limit to `/tmp/health_limits`
before the first run; the Docker check reads it from the existing tmpfs. The
limit covers the configured interval, automatic jitter and a 300-second run
reserve, with a 900-second floor. An explicit smaller override stops startup.
The entrypoint only touches the heartbeat when `main.py` exits `0`, and
`main.py` exits `1` when the LAPI fetch or a backend write fails (including the
QuestDB dedup gate and TTL). A container turns unhealthy after that window.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
