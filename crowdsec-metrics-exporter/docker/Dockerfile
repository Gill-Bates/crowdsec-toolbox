FROM python:3.13-slim

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
# Bind-mounted instead of copied so the manifest leaves no layer behind.
RUN --mount=type=bind,source=crowdsec-metrics-exporter/pyproject.toml,target=/tmp/pyproject.toml \
    pip install --no-cache-dir --root-user-action=ignore --group /tmp/pyproject.toml:default

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
# The container runs unprivileged from the start; no root phase exists.
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
