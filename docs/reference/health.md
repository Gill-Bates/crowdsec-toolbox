# Health Checks

Both images define a `HEALTHCHECK`. In both cases it verifies that a heartbeat
file is **recent**, and in both cases the heartbeat is written only after a
successful run — which is what makes a repeatedly failing export or report run
visible instead of silently green.

## crowdsec-abuse-reporter

Two files must **both** be fresh:

| File | Written by | Staleness limit |
|---|---|---|
| `/data/heartbeat` | The entrypoint, only after an exit-0 main run | `HEALTHCHECK_MAX_AGE_SECONDS`, default `28800` (8 h) |
| `/data/api_heartbeat` | `python -m app.heartbeat` in the background loop | `API_HEARTBEAT_MAX_AGE_SECONDS`, default `700` |

Check parameters: `--interval=5m --timeout=10s --start-period=7m --retries=3`.

The two files answer different questions. The main heartbeat says "processing
completed successfully at some point within the reporting interval", which for a
six-hour schedule is necessarily a coarse signal. The LAPI heartbeat runs every
`API_HEARTBEAT_INTERVAL` seconds (default `300`) and detects a prolonged LAPI
outage *between* main runs, long before the main heartbeat would go stale.

!!! danger "Never touch `/data/heartbeat` unconditionally"
    The entrypoint refreshes it only when `run.py` exits `0`. Touching it on every
    loop iteration would keep the health check green while processing failed
    repeatedly — which is precisely the failure the check exists to catch.

Note that `run.py` exits non-zero only for **hard** failures: configuration, GeoIP
cold start, database init, LAPI fetch, database errors. Per-report DNS or SMTP
failures still exit `0`, so they do not turn the container unhealthy. Use the
metrics backend or the logs to see those.

## crowdsec-metrics-exporter

One file:

| File | Written by | Staleness limit |
|---|---|---|
| `/tmp/state/heartbeat` | The entrypoint, only after `main.py` exits `0` | `HEALTHCHECK_MAX_AGE_SECONDS`, default `900` (15 min) |

Check parameters: `--interval=5m --timeout=10s --start-period=3m --retries=3`.

`main.py` exits `1` when the TLS check, the LAPI fetch or a backend write fails, so
the container turns unhealthy once exports keep failing past the staleness limit.

### The heartbeat lives on tmpfs deliberately

`/tmp/state` is a fixed path on the container's tmpfs — no host mount, not
configurable, because there is nothing to relocate.

!!! note "A restarted container is unhealthy until its first successful export"
    That is intentional. Previously a stale heartbeat on persistent storage could
    mask a broken start for up to `HEALTHCHECK_MAX_AGE_SECONDS`. The
    `--start-period` covers the legitimate startup window instead.

## Interpreting an unhealthy container

| Symptom | Likely cause |
|---|---|
| Unhealthy shortly after start | Still inside `--start-period`, or the first run has not succeeded yet |
| Exporter unhealthy after ~15 min | LAPI unreachable, TLS check failing, or backend writes rejected |
| Reporter unhealthy on the API heartbeat only | LAPI outage; main processing may still be fine |
| Reporter unhealthy on both | Main runs are failing hard — check configuration and the database |

See [Troubleshooting](../troubleshooting.md) for the diagnostic steps.
