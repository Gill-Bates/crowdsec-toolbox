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
| `Dockerfile` | Builds the `python:3-slim` image and runs the non-root `app` user after startup setup; no Docker CLI |
| `docker-compose.yml` | Compose service with a tmpfs for the heartbeat; no Docker socket, no volumes; scheduling lives in `settings.env` |
| `entrypoint.sh` | Validates paths, fixes the data directory ownership, runs exports, and updates the heartbeat |
| `settings.env.example` | Container configuration template |

## Working in this directory

- Build from the repository root because the Dockerfile copies the central
  this tool's `pyproject.toml` and the exporter sources. Use the root
  `setup.conf`, which reads the version from `crowdsec-metrics-exporter/pyproject.toml`, resolves the current Git commit,
  and passes both values as build arguments.
- **No Docker socket.** The exporter reaches CrowdSec over the Local API, like
  its sibling. Earlier versions ran `docker exec <container> cscli ...`, which
  needed the host socket — equivalent to root on the host. Do not reintroduce
  it: the LAPI credentials are scoped to CrowdSec's API. Because nothing needs
  supplementary groups across the privilege drop any more, the entrypoint uses
  plain `gosu app:app` instead of `setpriv --groups`, and Compose needs no
  `group_add`.
- The container needs network access to `CROWDSEC_LAPI_URL`. Inside a
  container, `127.0.0.1` is the container itself — use the CrowdSec
  container's name on a shared network, or the host's address.
- Keep secrets in an external `settings.env`. The tracked example contains
  placeholders only. The exporter keeps no state that must survive container
  recreation, since deduplication happens in the backend.
- Scheduling is configured in `settings.env`, not in `docker-compose.yml`.
  Compose only sets `TZ` under `environment`, because entries
  there override `env_file` and would make an operator's edit in
  `settings.env` silently ineffective. `RUN_ONCE=true` performs one export
  and exits; otherwise the entrypoint runs periodically using `RUN_INTERVAL`
  or `RUN_EVERY_HOUR` (which takes precedence), with optional `RUN_JITTER`.
  These four are read by `entrypoint.sh`, not by the application, so they
  appear in this directory's `settings.env.example` only — a direct host run has no
  entrypoint and ignores them.

## Health and failure behavior

The health check verifies that the heartbeat file is recent. The entrypoint
only touches the heartbeat when `main.py` exits `0`, and `main.py` exits `1`
when the TLS check, the LAPI fetch or a backend write fails. A container
turns unhealthy once exports keep failing for longer than the health-check
window.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
