<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-23 | Updated: 2026-09-23 -->

# docs

## Purpose
Sources of the central CrowdSec Toolbox documentation site, built with MkDocs
Material and deployed to GitHub Pages
(https://gill-bates.github.io/crowdsec-toolbox/). This is the one place in the
repository where the two otherwise independent tools are documented together:
shared concerns (metrics backends, health checks, security model, dashboards)
live in `reference/`, while per-tool behaviour stays in `abuse-reporter/` and
`metrics-exporter/`.

`docs_dir` is this directory itself (`docs_dir: .`) and the site is written to
`../site`.

## Key Files
| File | Description |
|------|-------------|
| `mkdocs.yml` | MkDocs Material config: site metadata, light/dark palette (indigo), navigation features, plugins and the nav tree; built with `--strict` in CI |
| `index.md` | Landing page: what the toolbox is, per-tool cards, the at-a-glance comparison table, quick start |
| `troubleshooting.md` | Symptom-driven fixes across both tools, grouped by subsystem (container start, LAPI, DNS, mail, backends, Grafana, GeoIP, development) |
| `stylesheets/extra.css` | Theme tweaks (`--cst-primary`/`--cst-accent`, dark-mode backgrounds, grid cards, logo switching) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `getting-started/` | Shared prerequisites and LAPI credentials, host installation, Docker deployment |
| `abuse-reporter/` | Per-tool pages: overview, configuration, delivery guarantees, GeoIP |
| `metrics-exporter/` | Per-tool pages: overview, configuration, per-event export |
| `reference/` | Cross-tool reference: metrics backends, Grafana dashboards, health checks, security model |
| `development/` | Setup, testing, build pipelines |

## For AI Agents

### Working In This Directory
- Every new page must be added to the `nav` in `mkdocs.yml`; `--strict` fails on
  broken links and on a page missing from the nav.
- `docs/license.md` is generated in CI from the root `LICENSE`; do not create or
  commit it by hand. There is no `CHANGELOG.md` in this repository, so unlike the
  sibling projects nothing copies one in.
- Documentation is in **English**, including the pages describing German
  user-facing strings. Do not translate the quoted strings themselves.
- Never include real secrets, tokens or hostnames in examples. The registry
  `docker.cirrio.de` and the deployment paths from `setup.conf` are already
  public in the repo and may be shown as-is.
- Content must stay traceable to the code or the operator READMEs. The tools'
  `app/config.py` files are authoritative for configuration variables — the
  `settings.env.example` templates have known drift (see
  `../crowdsec-abuse-reporter/docker/AGENTS.md`).
- Keep the precedence difference between the two tools intact wherever settings
  loading is described: the abuse reporter loads `settings.env` with
  `override=False` (environment wins), the exporter with `override=True` (file
  wins).
- Invariants that must not be softened into "best practice" advice: the
  at-most-once claim protocol, the never-retry rule for `unknown_send_state`,
  the no-Docker-socket rule, and that a QuestDB upsert key must be a tag column.

### Testing Requirements
```bash
pip install --group docs/pyproject.toml:default   # needs pip >= 25.1
mkdocs build -f docs/mkdocs.yml --strict    # what CI runs
mkdocs serve -f docs/mkdocs.yml             # live preview
```
CI also runs a lychee link check over the built site and a Trivy scan of the
frozen docs environment; see `.github/workflows/docs-build.yml`.

### Common Patterns
- Task-oriented Markdown with fenced shell examples, Material admonitions
  (`!!! note` / `!!! warning` / `!!! danger`), `=== "Tab"` blocks for per-tool
  variants, and "Next steps" links at the end of guides.
- Configuration is documented as tables of variable / default / description.
- `!!! danger` is reserved for things that cause data loss, duplicate abuse
  reports, or a privilege-escalation path — not for ordinary misconfiguration.

## Dependencies

### Internal
- Root `LICENSE`, `README.md`, this directory's own `pyproject.toml` (`default`
  dependency group; there is no root manifest),
  `.github/workflows/docs-build.yml`, `.github/img/` logos
- Both tools' `README.md`, `AGENTS.md` and `docker/AGENTS.md` files are the
  upstream sources for most of this content

### External
- MkDocs, mkdocs-material, mkdocs-minify-plugin,
  mkdocs-git-revision-date-localized-plugin, pymdown-extensions (all pinned in
  the `default` group of `pyproject.toml`), GitHub Pages, lychee, Trivy

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
