<!-- Generated: 2026-09-23 | Updated: 2026-11-19 -->

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
| `ruff.toml` | Shared ruff baseline (rules, `BLE001` ignore, formatter); the tools and `.github/scripts/ruff.toml` extend it. Not a Python manifest, so the root-`pyproject.toml` ban does not apply |
| `setup.conf` | Reference of the local setup and manual build/push commands; the only `setup.conf` in the repository (tools have none of their own) |
| `.gitignore` | Repo-wide ignores: caches, venvs (`.venv/`, `.venv.*`), `*.db*`, `*.sqlite*`, `*.log`, `settings.env`, `settings-*.env`, `BUILD_INFO`, generated `site/` and `docs/license.md`, `.omc/`, `.claude/`, `.github/skills/`, `*.backup` |
| `.dockerignore` | Fallback denylist for legacy (non-BuildKit) builders (secrets, databases, logs, `data/`, `BUILD_INFO`, `.git/`, `.github/`, `docs/`, `site/`, tests, `AGENTS.md`/`CLAUDE.md`, `grafana/`); each tool's own `docker/Dockerfile.dockerignore` (e.g. `crowdsec-abuse-reporter/docker/Dockerfile.dockerignore`, `crowdsec-metrics-exporter/docker/Dockerfile.dockerignore`) is the primary allowlist under BuildKit |
| `.trivyignore` | Trivy ignore list used by the `ci.yml`, `docs-build.yml`, and `release.yml` scans; currently empty on purpose. Every entry added later needs a reason |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `crowdsec-abuse-reporter/` | CrowdSec LAPI bans → Abusix contact lookup → X-ARF abuse mail, at-most-once (see `crowdsec-abuse-reporter/AGENTS.md`) |
| `crowdsec-metrics-exporter/` | CrowdSec decisions via the Local API → InfluxDB 2.x or QuestDB time series (see `crowdsec-metrics-exporter/AGENTS.md`) |
| `docs/` | Central documentation site (Zensical) — see `docs/AGENTS.md` |
| `.github/` | `workflows/` (`ci.yml` PR gate and release gate, `release.yml`, `docs-build.yml`), `scripts/` (`ci_job_setup.py`, `ci_output.py`, `trivy_report.py`, `failure_issue.py`, `release_tags.py`, `release_notes.py`, `release_publish.cjs` and their tests), `zizmor.yml` (reasoned ignores for the zizmor job), `img/` (logos); pipelines are documented in `docs/development/pipelines.md`. `.github/skills/` is gitignored local tooling |

## For AI Agents

### Working In This Directory
- Every component manages its own dependencies:
  `crowdsec-abuse-reporter/pyproject.toml`,
  `crowdsec-metrics-exporter/pyproject.toml` and `docs/pyproject.toml` (the Zensical
  toolchain). Do not add a root `pyproject.toml` or per-tool `requirements.txt`;
  CI rejects both. Code shared between the tools is never imported across tool
  directories: either it is duplicated on purpose (`config.py` etc., kept in sync by
  `.github/scripts/test_shared_code.py`), or it lives in a package of the private
  `Gill-Bates/python-libraries` repository:

  | Package | Path in `python-libraries` | Used by |
  |---------|----------------------------|---------|
  | `gillbates-logging` | `packages/logging/` | both tools (`logger.py`, `banner.py` are thin bindings) |
  | `gillbates-influxdb-client` | `packages/influxdb-client/` | metrics exporter (`app/influxdb.py`) |
  | `gillbates-questdb-client` | `packages/questdb-client/` | both tools |
  | `gillbates-smtp-client` | `packages/smtp-client/` | abuse reporter |
  | `gillbates-shutdown-handler` | `packages/shutdown-handler/` | both tools (SIGINT/SIGTERM handling in `main.py`) |
  | `gillbates-geoip` | `packages/geoip/` | abuse reporter (`app/geoip.py` is a thin binding) |

  Each package is pinned by git tag in the tool's `[project].dependencies`. For local dev,
  install it editable from a checkout (`pip install -e /opt/python-libraries/packages/<name>`);
  the image and CI install it from the pinned tag (git plus a token: `RELEASE_TOKEN` in CI,
  the BuildKit secret `python_libraries_token` in `docker build`), so the tag must exist
  before a build. The python-libraries CI creates `<name>-vX.Y.Z` once per new version.
- Each tool's runtime group is called `default`, its tooling group `dev`. Each
  manifest also carries that component's `[project].version`, its `[tool.pytest.ini_options]`
  and a `[tool.ruff]` that only sets `extend = "../ruff.toml"` plus tool-specific
  per-file ignores. Shared rules (including the deliberate `BLE001` ignore) live in the
  root `ruff.toml`; `.github/scripts/ruff.toml` extends it too. `ruff check .` from the
  repo root resolves these per-directory configs by itself.
- A Dockerfile bind-mounts its own tool's manifest, and the build context is the
  repository root because the `COPY` paths are repo-relative. The neighbouring
  `docker/Dockerfile.dockerignore` allowlist must therefore name
  `<tool>/pyproject.toml` — a root-level `!pyproject.toml` leaves it outside the
  context and the pip layer fails with "not found".
- Python 3.14+. Comments/docstrings in English; user-facing strings are often
  German and must keep their wording and non-ASCII characters.
- Real configuration (`settings.env`, `settings-*.env`) is gitignored; only
  `settings.env.example` templates are tracked. Never commit secrets.
- Do not add Claude co-author trailers to commits or PR descriptions.
- Releases run from a `vX.Y.Z` tag via `.github/workflows/release.yml` (gated by `ci.yml` through `workflow_call`) and require
  **both** `pyproject.toml` files to declare that exact version; the tagged commit
  must also be contained in `main`. Both images go to one Docker Hub repository
  (`crowdsec-toolbox`), tagged `<tool>-<version>` and `<tool>-latest` — there is
  deliberately no bare `latest`, since it could only mean one of the two tools.

### Testing Requirements
```bash
ruff check .                                           # per-tool configs, plus .github/scripts
ruff format --check .                                  # formatter is enforced too
cd crowdsec-abuse-reporter && python -m pytest
cd crowdsec-metrics-exporter && python -m pytest
```
There is no typechecker configured. Run the suites with each tool's `dev`
group installed: the abuse reporter's X-ARF conformance tests need `jsonschema`
and validate against the X-ARF v4.2.0 schemas vendored in
`crowdsec-abuse-reporter/tests/fixtures/`. The exporter's suite is offline: it uses
mocked LAPI/QuestDB responses and a stub entrypoint to cover configuration,
line protocol, fetch completeness, deduplication and scheduling; it needs no
live services.

### Build and Deploy
The root `setup.conf` is the single source of truth for local setup, building and
deploying; no tool has its own. It is a block-by-block reference, not a script:
never `source` or `bash` the whole file, since it also pushes images and
cleans up. Each build block reads the version from the tool's own
`pyproject.toml` and supplies `APP_VERSION`, `GIT_SHA` and `BUILD_DATE` to the
Docker image as build args.

## Dependencies

### External
- CrowdSec Local API (both tools; each authenticates with its own watcher
  credentials)
- InfluxDB 2.x or QuestDB (exporter), SMTP + Abusix DNS (abuse reporter)

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->

