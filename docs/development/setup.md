# Development Setup

## Repository layout

Each tool lives in its own top-level directory with its own README, Dockerfile,
deployment path **and dependency manifest**. They share this documentation site,
but no application code and no manifest.

```
crowdsec-toolbox/
├── setup.conf                  # canonical build/deploy commands
├── .github/workflows/          # CI and docs pipelines
├── docs/
│   ├── mkdocs.yml              # site config (here, not at the repo root)
│   └── pyproject.toml          # the docs toolchain's own manifest
├── crowdsec-abuse-reporter/
│   ├── pyproject.toml          # this tool's deps, version and ruff config
│   ├── app/                    # application package
│   ├── tests/                  # the repository's only test suite
│   ├── docker/                 # Dockerfile, compose, entrypoint, env template
│   ├── grafana/                # dashboards
│   └── run.py
└── crowdsec-metrics-exporter/
    ├── pyproject.toml
    ├── app/
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
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade "pip>=25.1"
pip install --group crowdsec-abuse-reporter/pyproject.toml:default \
            --group crowdsec-abuse-reporter/pyproject.toml:dev \
            --group crowdsec-metrics-exporter/pyproject.toml:default \
            --group crowdsec-metrics-exporter/pyproject.toml:dev
```

Installing both tools' `default` and `dev` groups is what CI does, and it is what
lets ruff resolve imports across the whole repository in one pass. Ruff itself
picks up each tool's config from its own manifest, so a single `ruff check .` at
the repo root still applies the right per-tool rules.

!!! warning "pip 25.1 or newer"
    `pip install --group` is what reads the PEP 735 groups. There is no
    `requirements.txt` anywhere and none should be added.

## Conventions

- **Python 3.13+ only.** Modern idioms: `pathlib`, `|` unions, `StrEnum`,
  `typing.Self`, timezone-aware datetimes. No `typing.Optional`, no `os.path`, no
  pre-3.13 compatibility shims.
- **Comments and docstrings in English.** User-facing strings are frequently
  German and must keep their wording and non-ASCII characters.
- **Keep changes scoped to one tool.** Do not refactor across the toolbox.

!!! danger "The duplication is intentional"
    `logger.py`, `config.py` and friends exist separately in both tools on
    purpose, so each deploys and upgrades independently. Do not extract them into
    a shared package.

## Adding a dependency

Add it to the `default` group in that tool's own `pyproject.toml`. Never create a per-tool
`requirements.txt` — CI rejects one, since it would give the manual build in
`setup.conf` and the central manifest two dependency sets to disagree about.

## Adding a configuration variable

1. Add it to the tool's `app/config.py`.
2. Add it to `docker/settings.env.example`.
3. For the abuse reporter, keep **both** `settings.env.example` copies (project
   root and `docker/`) in sync.
4. If it has a default, add it to the `ENV` block in the Dockerfile.
5. Document it in the relevant configuration page here.

## Linting

```bash
ruff check .        # from the repository root
```

Ruff is the single linter. There is no repo-wide configuration: each tool's
`pyproject.toml` carries its own `[tool.ruff]` and `[tool.ruff.lint]` section,
both ignoring `BLE001`. Ruff discovers those per-directory configs itself, so a
single `ruff check .` at the repo root still lints each tool under its own rules.

!!! note "There is no typechecker"
    Do not add mypy or pyright, and do not claim a typecheck ran.

## Documentation

The site is built from `docs/`, and the MkDocs config lives at `docs/mkdocs.yml`
rather than the repository root.

```bash
pip install --group docs/pyproject.toml:default
mkdocs serve -f docs/mkdocs.yml            # live preview on :8000
mkdocs build -f docs/mkdocs.yml --strict   # what CI runs
```

!!! warning "`--strict` fails on broken links and missing nav targets"
    Every new page must be added to the `nav` in `mkdocs.yml`.

`docs/license.md` is generated in CI from the root `LICENSE`; do not create or
commit it by hand.

## Next steps

- [Testing](testing.md)
- [Build Pipelines](pipelines.md)
