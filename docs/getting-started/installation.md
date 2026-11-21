# Installation

This page covers running the tools directly on a host. For the container path,
see [Docker Deployment](docker.md).

## Dependency manifests

There is no `requirements.txt` anywhere in this repository, and no root
`pyproject.toml` either. **Every component owns its own manifest**, so each one
can be deployed and upgraded without reference to the others. The tools are not
installable packages; the manifest exists only to declare
[PEP 735](https://peps.python.org/pep-0735/) dependency groups.

| Manifest | Group | Contents |
|---|---|---|
| `crowdsec-abuse-reporter/pyproject.toml` | `default` | `dnspython`, `httpx` |
| | `dev` | `pytest`, `ruff` |
| `crowdsec-metrics-exporter/pyproject.toml` | `default` | `httpx`, `requests`, `urllib3` |
| | `dev` | `pytest`, `ruff` |
| `docs/pyproject.toml` | `default` | Zensical site builder |

Each manifest also carries its own `[project].version` and its own
`[tool.ruff]` section, which extends the shared root `ruff.toml` (deliberate `BLE001` ignore).

!!! warning "pip 25.1 or newer is required"
    `pip install --group` is what reads these groups. Older pip versions fail
    with an unrecognised option.

## crowdsec-abuse-reporter

```bash
apt install python3-pip python3.14-venv --no-install-recommends -y

mkdir -p /opt/python/crowdsec_abuse_reporter
cd /opt/python/crowdsec_abuse_reporter
python3.14 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install --group /opt/crowdsec-toolbox/crowdsec-abuse-reporter/pyproject.toml:default
```

Configure and run it from the project directory:

```bash
cd /opt/crowdsec-toolbox/crowdsec-abuse-reporter
cp docker/settings.env.example settings.env
# edit settings.env
python run.py
```

`run.py` is a thin entry-point shim around `app.main`. On a direct host run the
database defaults to `data/abuse_alerts.db` inside the project directory.

!!! danger "Keep the database when migrating"
    The SQLite database is what prevents a ban from being reported twice.
    Deleting it or starting from an empty one re-reports every ban CrowdSec
    still has a decision for. See [Delivery Guarantees](../abuse-reporter/delivery.md).

### Alternative configuration files

`SETTINGS_PATH` points at an env file other than the default
`<project root>/settings.env` — for example one of the gitignored
`settings-*.env` site profiles. The file is loaded with `override=False`, so an
existing environment variable wins over the file.

## crowdsec-metrics-exporter

```bash
cd /opt/crowdsec-toolbox/crowdsec-metrics-exporter
python3.14 -m venv /opt/jobs/crowdsec_influx
source /opt/jobs/crowdsec_influx/bin/activate
pip install --upgrade pip
pip install --group pyproject.toml:default
cp docker/settings.env.example settings.env
# edit settings.env with your CrowdSec and InfluxDB/QuestDB details
python main.py
```

!!! note "`setup.conf` is not a pure setup script"
    The root `setup.conf` holds these venv lines (production section) next to the
    `docker buildx build ... --push` commands, so running or sourcing the whole
    file builds and pushes the images. Run only the venv lines.

    The venv path deviates from its sibling: `/opt/jobs/crowdsec_influx` with
    `bin/activate`, not `.venv/bin/activate`.

!!! warning "Importing the exporter's config has side effects"
    `app.config` calls its own settings loader at import time with
    `override=True`, so for this tool `settings.env` wins over an existing
    environment variable — the opposite of the abuse reporter's precedence.

## Scheduling a host run

Neither tool daemonises itself. Both are one-shot scripts that exit when done,
so scheduling is cron's job:

```cron
# Abuse reports every six hours
0 */6 * * * cd /opt/crowdsec-toolbox/crowdsec-abuse-reporter && /opt/python/crowdsec_abuse_reporter/.venv/bin/python run.py

# Metrics export every minute
* * * * * cd /opt/crowdsec-toolbox/crowdsec-metrics-exporter && /opt/jobs/crowdsec_influx/bin/python main.py
```

The `RUN_INTERVAL`, `RUN_EVERY_HOUR`, `RUN_ONCE` and
`METRICS_INTERVAL` variables are read by the container entrypoints, **not** by
the applications. A host run ignores them entirely.

## Exit codes

Both tools signal failure through their exit code, which is what makes cron and
the container health checks able to detect a broken run.

| Code | crowdsec-abuse-reporter | crowdsec-metrics-exporter |
|---|---|---|
| `0` | Normal run; per-report DNS or send failures still exit 0 | Success, including "nothing new to export" |
| `1` | Hard failure: config, GeoIP cold start, DB init, LAPI fetch, database error | LAPI fetch, backend write, QuestDB version (not 10.x), dedup gate or TTL failed |
| `130` | Interrupted | — |

## Next steps

- [Abuse Reporter Configuration](../abuse-reporter/configuration.md)
- [Metrics Exporter Configuration](../metrics-exporter/configuration.md)
- [Development Setup](../development/setup.md) — linting and tests
