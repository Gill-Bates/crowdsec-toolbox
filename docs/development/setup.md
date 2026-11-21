# Development Setup

## Repository layout

Each tool lives in its own top-level directory with its own README, Dockerfile,
deployment path **and dependency manifest**. They share this documentation site,
but no application code and no manifest.

```
crowdsec-toolbox/
├── setup.conf                  # canonical build/deploy commands
├── .github/                    # workflows (CI, docs, release), scripts, zizmor config
├── zensical.toml               # site config
├── docs/
│   └── pyproject.toml          # the docs toolchain's own manifest
├── crowdsec-abuse-reporter/
│   ├── pyproject.toml          # this tool's deps, version and ruff config
│   ├── app/                    # application package
│   ├── tests/
│   ├── docker/                 # Dockerfile, compose, entrypoint, env template
│   ├── grafana/                # dashboards
│   └── run.py
└── crowdsec-metrics-exporter/
    ├── pyproject.toml
    ├── app/
    ├── tests/
    ├── docker/
    ├── grafana/
    └── main.py
```

!!! note "There is no root `pyproject.toml`"
    Every component owns its manifest, so each carries its own `[project].version`
    and its own `[tool.ruff]` configuration. CI rejects a reintroduced root
    manifest.

## Environment

```bash
git clone https://github.com/Gill-Bates/crowdsec-toolbox.git
cd crowdsec-toolbox
python3.14 -m venv .venv && source .venv/bin/activate
pip install --upgrade "pip>=25.1"
pip install -e /opt/python-libraries/packages/logging   # private repo, local checkout
pip install --group crowdsec-abuse-reporter/pyproject.toml:default \
            --group crowdsec-abuse-reporter/pyproject.toml:dev \
            --group crowdsec-metrics-exporter/pyproject.toml:default \
            --group crowdsec-metrics-exporter/pyproject.toml:dev
```

Installing both tools' `default` and `dev` groups is what CI does, and it is what
lets ruff resolve imports across the whole repository in one pass.

!!! warning "pip 25.1 or newer"
    `pip install --group` is what reads the PEP 735 groups. The runtime dependency
    `gillbates-logging`, `gillbates-questdb-client` and (abuse reporter only) `gillbates-smtp-client` sit in `[project].dependencies`, which `--group` does not read, hence the
    separate editable install above. CI and the Docker builds install it from the pinned git
    tag of the private `python-libraries` repository with a token (`RELEASE_TOKEN`, see
    [Pipelines](pipelines.md#secrets)).

## Conventions

- **Python 3.14+ only.** Modern idioms: `pathlib`, `|` unions, `StrEnum`,
  `typing.Self`, timezone-aware datetimes. No `typing.Optional`, no `os.path`, no
  pre-3.14 compatibility shims.
- **Comments and docstrings in English.** User-facing strings are frequently
  German and must keep their wording and non-ASCII characters.
- **Keep changes scoped to one tool.** Do not refactor across the toolbox.

!!! danger "The duplication is intentional"
    `config.py` and friends exist separately in both tools on purpose, so each
    deploys and upgrades independently. Do not extract them into a shared package.
    The one exception is the logging core: both tools install the external `gillbates-logging`
    package (`Gill-Bates/python-libraries`, pinned by tag) and keep only a thin
    `app/logger.py`. For local development run
    `pip install -e /opt/python-libraries/packages/logging`.

## Adding a dependency

Add it to the `default` group in that tool's own `pyproject.toml`. Never create a per-tool
`requirements.txt` — CI rejects one, since it would give the manual build in
the root `setup.conf` and the tool's own manifest two dependency sets to disagree about.

## Adding a configuration variable

1. Add it to the tool's `app/config.py`.
2. Add it to `docker/settings.env.example`.
3. If it has a default, add it to the `ENV` block in the Dockerfile.
4. Document it in the relevant configuration page here.

## Linting

```bash
ruff check .           # from the repository root
ruff format --check .  # formatting is enforced too
```

Ruff is the single linter and formatter (line length 120, strict `select` set, each
ignore justified in the manifest). The shared rules live in the root `ruff.toml` (including the
deliberate `BLE001` ignore). Each tool's `pyproject.toml` extends it with
`extend = "../ruff.toml"` and keeps only its own per-file ignores; `.github/scripts/ruff.toml`
extends it for the CI helper scripts. Ruff discovers those per-directory configs itself, so a
single `ruff check .` at the repo root lints each tool under the shared rules.

!!! note "There is no typechecker"
    Do not add mypy or pyright, and do not claim a typecheck ran.

## Documentation

Zensical reads the site config from the repository root and builds pages from
`docs/`.

```bash
pip install --group docs/pyproject.toml:default
zensical serve --config-file zensical.toml                    # live preview on :8000
zensical build --config-file zensical.toml --strict --clean   # what CI runs
```

!!! warning "The strict build checks navigation and links"
    Add every new page to the `nav` in `zensical.toml` and fix broken local links.

`docs/license.md` is generated in CI from the root `LICENSE`; do not create or
commit it by hand.

## Next steps

- [Testing](testing.md)
- [Build Pipelines](pipelines.md)
