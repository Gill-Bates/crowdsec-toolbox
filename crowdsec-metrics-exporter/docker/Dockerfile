FROM python:3.14-slim

# Always supplied via `docker buildx build --build-arg ...` (see the root setup.conf);
# no defaults, this image is never built without them.
ARG APP_VERSION
ARG GIT_SHA
ARG BUILD_DATE

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RUN_INTERVAL=60 \
    RUN_ONCE=false \
    APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA}

LABEL org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

WORKDIR /app

# ca-certificates plus tini (PID 1: reaps children, forwards signals).
# No Docker CLI: the exporter reaches CrowdSec over the Local API.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

# Build context is the repository root; dependencies come from the tool's local
# pyproject.toml (`--group` needs pip >= 25.1).
# [project].dependencies (the shared gillbates-logging, gillbates-influxdb-client, gillbates-questdb-client and gillbates-shutdown-handler packages) is not read by `--group`,
# so it is extracted into a requirements file and installed in the same pip call. The
# package lives in the private Gill-Bates/python-libraries repository: the token is a
# BuildKit secret (never ARG/ENV, so it stays out of layers and image history) handed to
# git through a credential helper that exists only for this command. git is installed and
# purged within this RUN, so the final image carries neither git nor the token.
# `set -eu` plus the explicit checks abort the build when the extraction, the install or
# the import fails; there is deliberately no pipe whose failure could be swallowed.
# Bind-mounted instead of copied so the manifest leaves no layer behind.
RUN --mount=type=bind,source=crowdsec-metrics-exporter/pyproject.toml,target=/tmp/pyproject.toml \
    --mount=type=secret,id=python_libraries_token,required=true \
    set -eu; \
    apt-get update; \
    apt-get upgrade -y; \
    apt-get install -y --no-install-recommends git; \
    python -c 'import sys, tomllib; deps = tomllib.load(open(sys.argv[1], "rb"))["project"]["dependencies"]; deps or sys.exit("no [project].dependencies"); print(*deps, sep="\n")' /tmp/pyproject.toml > /tmp/runtime-requirements.txt; \
    test -s /tmp/runtime-requirements.txt; \
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0= \
    GIT_CONFIG_KEY_1=credential.helper \
    GIT_CONFIG_VALUE_1='!f() { echo username=x-access-token; echo "password=$(cat /run/secrets/python_libraries_token)"; }; f' \
    pip install --no-cache-dir --root-user-action=ignore -r /tmp/runtime-requirements.txt --group /tmp/pyproject.toml:default; \
    python -c "import gillbates_logging, gillbates_influxdb_client, gillbates_questdb_client, gillbates_shutdown_handler"; \
    apt-get purge -y --auto-remove git; \
    rm -rf /var/lib/apt/lists/* /tmp/runtime-requirements.txt

# Copy only the runtime files required by the application. Secrets and
# mutable state (settings.env, the heartbeat file) stay outside the image, in
# the environment and on the tmpfs respectively.
COPY --chmod=0755 crowdsec-metrics-exporter/app ./app
COPY --chmod=0644 crowdsec-metrics-exporter/main.py ./
COPY --chmod=0755 crowdsec-metrics-exporter/docker/entrypoint.sh ./entrypoint.sh

# The heartbeat directory is a fixed path on the tmpfs Compose mounts at /tmp
# (/tmp/state, see entrypoint.sh); the image cannot pre-create it, because it
# lives inside a mount that only exists at container start.
# /app stays root-owned and read-only for the app user on purpose: a
# compromised process must not be able to plant code that the next start runs.
# COPY --chmod above normalises the application files to world-readable
# (directories traversable) independent of the checkout's umask, so a 0600
# source file cannot break imports for the unprivileged app user.
USER 10001:10001

# The entrypoint atomically writes the validated schedule limit before the run.
# Both that limit and the heartbeat live only on the existing /tmp tmpfs.
HEALTHCHECK --interval=5m --timeout=10s --start-period=3m --retries=3 \
    CMD sh -ec '\
        if test "${RUN_ONCE:-false}" = true; then exit 0; fi; \
        read -r max_age < /tmp/health_limits || exit 1; \
        case "$max_age" in ""|*[!0-9]*) exit 1;; esac; \
        test -f /tmp/state/heartbeat || exit 1; \
        age=$(($(date +%s) - $(stat -c %Y /tmp/state/heartbeat))); \
        test "$age" -ge 0 && test "$age" -lt "$max_age"'

ENTRYPOINT ["/usr/bin/tini", "--", "./entrypoint.sh"]
