<!-- Generated: 2026-09-23 | Updated: 2026-09-24 -->

# crowdsec-toolbox

## Purpose
A small collection of standalone tools that extend CrowdSec deployments. Each
tool lives in its own top-level directory, has its own README and deployment
path, and shares no application code with its siblings. Each tool has its own
`pyproject.toml` for independent dependency management.

## Key Files
| File | Description |
|------|-------------|
| `README.md` | Project overview linking to each tool's README |
| `LICENSE` | MIT license for the repository; `docs/license.md` is generated from it in CI |
| `.gitignore` | Repo-wide ignores: caches, venvs, `*.db`, `settings.env`, `settings-*.env`, `BUILD_INFO`, `.omc/`, `.claude/` |
| `.dockerignore` | Fallback denylist for legacy (non-BuildKit) builders; each tool's own `docker/Dockerfile.dockerignore` (e.g. `crowdsec-abuse-reporter/docker/Dockerfile.dockerignore`, `crowdsec-metrics-exporter/docker/Dockerfile.dockerignore`) is the primary allowlist under BuildKit |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `crowdsec-abuse-reporter/` | CrowdSec LAPI bans → Abusix contact lookup → X-ARF abuse mail, at-most-once (see `crowdsec-abuse-reporter/AGENTS.md`) |
| `crowdsec-metrics-exporter/` | CrowdSec decisions via the Local API → InfluxDB 2.x or QuestDB time series (see `crowdsec-metrics-exporter/AGENTS.md`) |
| `docs/` | Central documentation site (mkdocs) — see `docs/AGENTS.md` |

## For AI Agents

### Working In This Directory
- Every component manages its own dependencies:
  `crowdsec-abuse-reporter/pyproject.toml`,
  `crowdsec-metrics-exporter/pyproject.toml` and `docs/pyproject.toml` (the MkDocs
  toolchain). Do not add a root `pyproject.toml` or per-tool `requirements.txt`;
  CI rejects both. Do not extract shared packages — `logger.py`, `config.py` etc.
  are duplicated on purpose so each tool deploys independently.
- Each tool's runtime group is called `default`, its tooling group `dev`. Each
  manifest also carries that component's `[project].version` and its own
  `[tool.ruff]` section (both ignore `BLE001` deliberately); `ruff check .` from
  the repo root resolves those per-directory configs by itself.
- A Dockerfile bind-mounts its own tool's manifest, and the build context is the
  repository root because the `COPY` paths are repo-relative. The neighbouring
  `docker/Dockerfile.dockerignore` allowlist must therefore name
  `<tool>/pyproject.toml` — a root-level `!pyproject.toml` leaves it outside the
  context and the pip layer fails with "not found".
- Python 3.13+. Comments/docstrings in English; user-facing strings are often
  German and must keep their wording and non-ASCII characters.
- Real configuration (`settings.env`, `settings-*.env`) is gitignored; only
  `settings.env.example` templates are tracked. Never commit secrets.
- Do not add Claude co-author trailers to commits or PR descriptions.
- Releases run from a `vX.Y.Z` tag via `.github/workflows/release.yml` and require
  **both** `pyproject.toml` files to declare that exact version; the tagged commit
  must also be contained in `main`. Both images go to one Docker Hub repository
  (`crowdsec-toolbox`), tagged `<tool>-<version>` and `<tool>-latest` — there is
  deliberately no bare `latest`, since it could only mean one of the two tools.

### Testing Requirements
```bash
ruff check crowdsec-abuse-reporter crowdsec-metrics-exporter  # per-tool configs
cd crowdsec-abuse-reporter && python -m pytest         # the only test suite
```
There is no typechecker configured. `crowdsec-metrics-exporter` has no tests.

### Build and Deploy
Each tool's `setup.conf` is the single source of truth for building and
deploying. It reads the version from the tool's local `pyproject.toml` and
supplies build metadata to the Docker image.

```bash
# Build abuse-reporter
cd /opt/crowdsec-toolbox/crowdsec-abuse-reporter && bash setup.conf

# Build metrics-exporter
cd /opt/crowdsec-toolbox/crowdsec-metrics-exporter && bash setup.conf
```

## Dependencies

### External
- CrowdSec Local API (both tools; each authenticates with its own watcher
  credentials)
- InfluxDB 2.x or QuestDB (exporter), SMTP + Abusix DNS (abuse reporter)

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->

