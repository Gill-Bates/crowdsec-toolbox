# Build Pipelines

Three GitHub Actions workflows live in `.github/workflows/`.

| Workflow | File | Trigger | Purpose |
|---|---|---|---|
| CI | `ci.yml` | push to any branch, PR to `main`, manual, called by `release.yml` | The gate: lint, tests, Dockerfiles, manifest invariants, workflow lint, source secret scan |
| Deploy Documentation | `docs-build.yml` | docs changes, manual, weekly, after a successful release | Builds this site `--strict`, scans its dependencies, deploys to GitHub Pages |
| Release | `release.yml` | `v*` tag, manual | Runs the CI gate, builds both images multi-arch, publishes them to Docker Hub, creates the GitHub Release |

Every job starts with `.github/scripts/ci_job_setup.py`, which prints the agent
banner and points `TMPDIR`, `TMP` and `TEMP` at the job temp directory. It installs
nothing: the private runner IPs appear only when `psutil` is already importable,
otherwise the banner says so and carries on. All actions
are pinned to a commit SHA. A pull request run is cancelled by a newer push; a push
run is not, because a release reads its result.

## CI

Six jobs run in parallel; `release.yml` calls the same workflow as its gate.

### `check` — Ruff + pytest

Two parallel legs. Both install the `default` and `dev` groups of both tools so ruff
can resolve imports across the whole repository; one runs
`ruff check --output-format=github` followed by `ruff format --check --diff`, the
other runs each tool's full pytest suite from its own directory. The abuse
reporter's entrypoint tests use temporary paths and stub commands; see
[Testing](testing.md#entrypoint-validation-tests).

### `container` — Dockerfiles + entrypoints

Matrixed over both tools:

- `bash -n <tool>/docker/entrypoint.sh` parses the script without executing it,
  and `shellcheck` lints it. The entrypoints are bash (per their shebang).
- `docker build --check -f <tool>/docker/Dockerfile .` runs BuildKit's own linter,
  which resolves stages, `ARG`/`ENV` references and `COPY --from` targets without
  running a single build step.

!!! note "Why not a full build"
    Images are only built by the Release workflow (or manually from `setup.conf`),
    so without these two cheap checks a broken entrypoint or Dockerfile would
    stay invisible until the release build itself — the one run where a failure is most expensive. A full
    multi-arch build is far too slow for a PR; this is the half that still catches
    a typo.

### `workflows` and `zizmor` — workflow lint

`actionlint` (pinned release, checked against its published sha256) with `shellcheck`
over every inline `run:` block, and `zizmor` for unpinned actions, template injection
and over-broad permissions. `zizmor` reads `.github/zizmor.yml`; every ignore there
carries its reason.

### `source-scan` — committed secrets

Trivy scans the source tree for secrets; `.github/scripts/trivy_report.py` fails the
job on findings and verifies that the secret scanner was enabled and received a
non-empty input tree. Trivy's clean JSON report has no per-file scan count, so this
is activation/input evidence rather than proof of every scanned file. Dockerfile
misconfiguration is not scanned because the abuse reporter's image starts as root on
purpose and drops to `app` through `gosu`, which Trivy reports as a HIGH finding.

### `manifest` — single-manifest invariants

Rejects a reintroduced per-tool `requirements.txt` or a committed `BUILD_INFO`,
and checks that `[project].version` is release-shaped
(`X.Y`, `X.Y.Z`, optionally with a `-suffix`).

!!! warning "Why `requirements.txt` is rejected"
    It would give the manual build in the root `setup.conf` and the tool's own
    `pyproject.toml` two dependency sets to disagree about. The job also rejects a
    reintroduced **root** `pyproject.toml`, since every component owns its
    manifest. `BUILD_INFO` is no longer generated; it stays gitignored and CI rejects a committed copy.

## Documentation deployment

`docs-build.yml` builds the site and publishes it to
<https://gill-bates.github.io/crowdsec-toolbox/>.

### Triggers

| Trigger | Behaviour |
|---|---|
| Push to `main` touching `docs/**`, `zensical.toml`, `LICENSE`, the CI scripts, `.trivyignore` or the workflow | Build, scan, deploy |
| Pull request touching the same paths | Build and scan only, no deploy |
| `workflow_dispatch` | Build, scan; deploy from `main`, or from another branch with the `deploy` input |
| Successful `Release` run for a `v*` tag | Rebuild, scan, deploy, so the site follows what was published |
| Weekly schedule (Mondays) | Re-scan the docs dependencies for new CVEs; a failed run opens or updates one tracking issue (`report-failure`) |

!!! note "Why the weekly schedule"
    A new CVE in the docs toolchain would otherwise only surface when something in
    the repository happens to change.

### Jobs

**`build`** installs the `default` group from `docs/pyproject.toml`, generates `docs/license.md` from the root
`LICENSE`, runs `zensical build --config-file zensical.toml --strict --clean`, then checks every link in the built site
with lychee.

!!! warning "`--strict` is the gate"
    It fails on broken internal links and on a page missing from the `nav`. Add
    every new page to `zensical.toml`.

The link check excludes `img.shields.io` (badges are generated on demand by a
throttling third party, and a 503 says nothing about the documentation),
`x-arf.org` (repeated timeouts), `fonts.gstatic.com` and the site's own Pages URL
(absent on the very first deploy).

**`security-scan`** scans the environment the `build` job froze (uploaded as an
artifact) with Trivy at `CRITICAL,HIGH`, and `trivy_report.py` proves the report
named that file with packages.

!!! note "Why the frozen list rather than the manifest"
    Trivy reports on what a manifest *names*, while Zensical resolves additional
    packages. Scanning only `docs/pyproject.toml` would leave the resolved build
    environment unscanned.

    The frozen file is a scan inventory, not an installation pin: the build job
    resolves the group itself, and Zensical is pinned in `docs/pyproject.toml`.

    The filename must contain "requirement" or Trivy's pip analyzer does not pick
    it up at all.

**`deploy`** needs both `build` and `security-scan`, and only runs for `main` on a
push or manual dispatch. A failing dependency scan blocks the deploy.

### GitHub Pages setup

The `deploy` job uses `actions/deploy-pages`, so the repository's Pages source has
to be set to **GitHub Actions** (Settings → Pages). It requests the `pages: write`
and `id-token: write` permissions for that job only.

## Release

`release.yml` publishes both tools to Docker Hub from a version tag.

### One repository, two tools

Both images go into the **same** Docker Hub repository, so the tool name is part
of the tag:

| Tag | Contents |
|---|---|
| `giiibates/crowdsec-toolbox:abuse-reporter-1.0.2` | Immutable version tag |
| `giiibates/crowdsec-toolbox:abuse-reporter-latest` | Moving pointer |
| `giiibates/crowdsec-toolbox:metrics-exporter-1.0.2` | Immutable version tag |
| `giiibates/crowdsec-toolbox:metrics-exporter-latest` | Moving pointer |

!!! warning "There is no bare `latest`"
    With two tools in one repository it could only ever mean one of them, and
    silently picking one would hand the wrong image to anyone who omits the tag.

### The tag is the contract

A `vX.Y.Z` tag releases **both** tools, and the `meta` job requires both
manifests to declare exactly that version. That keeps one git tag mapped to one
reviewable state of the repository.

!!! note "This couples the two version numbers"
    It is the one place where the tools are not fully independent. The tradeoff
    buys a single reviewable release; if they ever need to ship separately, the
    `meta` job is what to split into per-tool tags such as
    `abuse-reporter-v1.1.0`.

### What the release refuses to do

A tag can be pushed from any commit, so `meta`
re-establishes what a tag alone cannot prove, and `gate` runs `ci.yml` on the
tagged commit before any image is built:

- the run must come from a tag, not a branch — otherwise a manual run could
  republish a version from a different commit and move the `-latest` tags with it
- both `pyproject.toml` versions must equal the tag, or the image would
  misreport its own version through `app/version.py`
- the tagged commit must be **contained in `main`**, so a tag cut from an
  unreviewed commit cannot publish
- Docker Hub's existing tags decide whether this is the newest release. An older
  re-run still republishes its own version tag, but must not drag `-latest`
  backwards.

!!! danger "The newest-release probe is fail-closed"
    An empty tag listing must not be read as "nothing newer exists" — a 401, 429
    or 5xx would look identical to a pristine repository and would hand an old
    re-run permission to move `-latest`. Only a 404 on the first page is
    tolerated, which is the one case that genuinely has no tags yet.

### Build, verify, publish

`build` is a matrix over tool × architecture (4 jobs) on **native** runners
rather than QEMU, because these images install apt packages and fetch two
GeoLite2 databases, all of which emulate poorly. Each job builds and loads one
architecture image locally, then smoke-tests and scans it before logging in and
pushing that same image under an architecture-suffixed tag. It records the
digest reported by the successful push.

Each image is then smoke-tested before it can become part of a manifest: the
runtime imports must resolve inside the image, `pip check` must pass, and the
entrypoint must be present and executable. That catches a missing entry in the
`default` dependency group at release time instead of on first container start.

!!! note "The image scan blocks the release"
    Each image is scanned with Trivy at `CRITICAL,HIGH` (fixed CVEs only) before
    it is pushed, so a vulnerable image never reaches Docker Hub. A finding fails
    the job; rebuilding on a fresh base image usually clears it, and an accepted
    exception goes into `.trivyignore` with a reason. `trivy_report.py` also fails
    the job when a report is unreadable or covers no OS and Python packages. The
    JSON report is uploaded as an artifact, also after a failed scan.

`manifest` combines each tool's per-architecture digests under a run-specific
candidate tag, such as `<tool>-candidate-<run-id>`. It reads the index back from
Docker Hub and checks every platform and child digest against this run's image
digests. A mismatch fails before a public version or `-latest` tag is written.

`promote` downloads the same digests and verifies both candidate indexes again.
It then re-reads Docker Hub's complete tag listing and recomputes whether this
release is newest. For each tool, it adds the public version tag from the
verified candidate digest and checks that tag; it moves that tool's
`<tool>-latest` only for a stable, newest release, then checks the result. The
GitHub Release is created only after promotion succeeds. Its notes combine both
changelogs, a Trivy verdict per tool and architecture, and the cloc statistics; the
Trivy reports of all four images are mandatory, so a missing or empty report stops
the notes before a release exists. After successful promotion, `cleanup` removes
architecture fragments and candidate tags.

!!! note "Architecture fragments never count as a release"
    A failed run leaves its `<tool>-<version>-<arch>` tags behind, because
    `cleanup` runs only after promotion succeeds. The newest-release check
    ignores architecture fragments and candidate tags, so an abandoned run
    cannot block `-latest`. A re-run of the same tag may replace its own version
    tag after the candidate index passes verification.

### Secrets

Release jobs reference the GitHub Environment `release`. Configure its tag
restrictions and protection rules in GitHub settings. Make the following secrets
available to release jobs as repository or environment secrets.

| Secret | Used for |
|---|---|
| `DOCKERHUB_USERNAME` | Namespace and registry login |
| `DOCKERHUB_TOKEN` | Docker Hub API tag listing, image pushes, and deletion of temporary architecture and candidate tags during cleanup |
| `RELEASE_TOKEN` | Creating the GitHub Release |

!!! note "Why `RELEASE_TOKEN` and not the default token"
    A release created with `GITHUB_TOKEN` does not emit a `release` event, so no
    other workflow could ever react to a publish. Everything else uses the
    default token.

### Cutting a release

1. Set the same version in both `pyproject.toml` files.
2. Merge to `main`.
3. `git tag v1.0.2 && git push --tags`.

`workflow_dispatch` is for re-runs — select the tag as the ref, not a branch.

## The private registry stays manual

The `docker buildx build` commands in the root `setup.conf` still push to
`docker.cirrio.de`, and the tracked Compose files reference that registry. The
release pipeline publishes to Docker Hub instead; the two paths are independent.

See [Docker Deployment](../getting-started/docker.md#building-the-images) for the
manual commands.
