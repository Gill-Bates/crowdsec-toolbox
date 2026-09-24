# Security Model

Both tools are unattended jobs that hold CrowdSec credentials and, in the abuse
reporter's case, SMTP credentials. The hardening below is deliberate; the notes
marked as invariants should not be relaxed without understanding what they buy.

## No Docker socket

Neither container mounts `/var/run/docker.sock`. Both reach CrowdSec over the
Local API and authenticate with their own watcher credentials.

!!! danger "Do not reintroduce `docker exec cscli`"
    An earlier version of the exporter ran `docker exec <container> cscli ...`,
    which required socket access — equivalent to root on the host. The LAPI
    credentials are scoped to CrowdSec's API only, which is a dramatically
    smaller grant.

    A side effect worth knowing: because nothing needs supplementary groups
    across the privilege drop any more, the exporter's entrypoint uses plain
    `gosu app:app` instead of `setpriv --groups`, and Compose needs no
    `group_add`.

## Privilege drop

Both containers start as root for exactly one reason: Docker creates a missing
bind-mount source directory as root, so the entrypoint has to fix ownership
before the application can write. It then `exec gosu app:app` and **nothing past
that line runs as root**. The application user is uid/gid `10001`.

!!! danger "`/app` stays root-owned and read-only to the app user"
    The container starts as root and executes `entrypoint.sh` before dropping
    privileges. An app-writable entrypoint would let a compromised unprivileged
    process plant code that the next container start executes **as root**.

    `COPY --chmod` in the Dockerfiles normalises the application files to
    world-readable, independent of the checkout's umask, so a `0600` source file
    cannot break imports for the app user. Write permission is deliberately not
    granted.

The abuse reporter's entrypoint chowns the top-level data directory
unconditionally but descends into subdirectories best-effort only: a subdirectory
with restrictive host permissions is not readable even by root under `-R`, and
aborting there would break container start for a recoverable condition.

## Compose hardening

The abuse reporter's Compose service runs with:

| Setting | Effect |
|---|---|
| `read_only: true` | Root filesystem is immutable |
| `cap_drop: [ALL]` | Drops every Linux capability |
| `cap_add: [CHOWN, SETUID, SETGID]` | Restores exactly the three the privilege drop needs |
| `no-new-privileges` | Blocks setuid escalation |
| `pids_limit: 128` | Caps process creation |
| tmpfs for `/tmp` | Mounted `noexec,nosuid,nodev` |

!!! warning "Keep all of it intact"
    The three restored capabilities are the minimum for `chown` + `gosu`. Adding
    more, or dropping `no-new-privileges`, widens the blast radius of a
    compromised dependency.

The exporter needs no writable data directory at all and keeps no state beyond
its tmpfs heartbeat.

## Build context isolation

Each Dockerfile has a neighbouring `Dockerfile.dockerignore` that BuildKit reads
automatically. These are **allowlists** — everything is excluded except the
tool's own `pyproject.toml`, its `app/`, its entry point and its entrypoint
script:

```
*
!crowdsec-abuse-reporter/pyproject.toml
!crowdsec-abuse-reporter/app/
!crowdsec-abuse-reporter/run.py
!crowdsec-abuse-reporter/docker/entrypoint.sh
**/__pycache__/
**/*.py[cod]
```

Secrets, databases, tests, Grafana dashboards and the sibling tool never reach the
build context. The manifest is bind-mounted during `pip install` rather
than copied, so the manifest leaves no layer behind.

The repo-root `.dockerignore` is a denylist fallback for legacy non-BuildKit
builders, which ignore the per-Dockerfile file. It exists as defence in depth: even
`DOCKER_BUILDKIT=0 docker build -f .../Dockerfile .` cannot ship `settings.env`,
a `*.db` file or `.git/` to the daemon.

## Secret handling

!!! danger "All secrets are plaintext in `settings.env`"
    `SMTP_PASSWORD`, `CROWDSEC_LAPI_PASSWORD`, `INFLUXDB_TOKEN` and the QuestDB
    credentials are read as plain text. Consequences:

    - `settings.env` and `settings-*.env` are gitignored **and** dockerignored.
      Never commit them and never copy their values elsewhere.
    - They were tracked in the former monorepo, so credentials from that era must
      be treated as **exposed until rotated**.
    - Docker reads the file via `env_file`; it is not bind-mounted into the
      container.

Secrets are never hardcoded and never logged. The abuse reporter redacts
sensitive values when rendering report bodies, and `app/logger.py` sanitises
control characters out of log lines.

## Network exposure

Neither tool listens on a socket. Both are outbound-only clients, so there is no
inbound attack surface and no authentication layer to configure. What they need to
reach:

| Destination | Tool | Notes |
|---|---|---|
| CrowdSec LAPI | both | `CROWDSEC_LAPI_VERIFY_TLS` controls certificate verification |
| SMTP server | abuse reporter | Authentication requires TLS |
| Abusix DNS zone | abuse reporter | System resolver only, no public fallback |
| InfluxDB / QuestDB | both, when enabled | TLS verification per `*_VALIDATE_CERTIFICATE` |

Every outbound HTTP, DNS and SMTP call carries an explicit timeout.

!!! note "The InfluxDB TLS hardening is load-bearing"
    The exporter's `app/influxdb.py` builds a `TLS12Adapter` on a `urllib3` SSL
    context with custom cipher and TLS-version handling. Do not port it to httpx
    as a side effect of another change. `app/questdb.py` uses httpx precisely
    because QuestDB's endpoint has no equivalent requirement.

## Data sensitivity

!!! warning "Requested paths are stored verbatim"
    With `EVENTS_ENABLED=true`, the exporter stores `http_path` exactly as the
    scanner sent it. A credential or token an attacker happened to put in a URL is
    stored with it. Scope access to the events table accordingly — see
    [Per-Event Export](../metrics-exporter/events.md#caveats).

Abuse reports contain third-party IP addresses and the evidence for the ban. The
reporting identity in the mail comes from `HOSTNAME_OVERRIDE` or public-IP
detection, so set it explicitly rather than leaking a private container address.

## Deliberate lint exceptions

`BLE001` (blind `except Exception`) is ignored repo-wide. The broad handlers at
collector and outer-loop boundaries are intentional so one bad alert or decision
cannot kill an unattended run.

!!! note
    Do not narrow that ignore or add new findings under it. The handlers log and
    continue; they do not swallow failures silently.
