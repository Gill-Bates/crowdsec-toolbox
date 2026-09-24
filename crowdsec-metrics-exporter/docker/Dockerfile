# syntax=docker/dockerfile:1
FROM python:3-slim

# Always supplied via `docker buildx build --build-arg ...` (see setup.conf);
# no defaults, this image is never built without them.
ARG APP_VERSION
ARG GIT_SHA
ARG BUILD_DATE

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Berlin \
    RUN_INTERVAL=60 \
    RUN_ONCE=false \
    RUN_JITTER=0 \
    HEALTHCHECK_MAX_AGE_SECONDS=900 \
    APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA}

LABEL org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

WORKDIR /app

# ca-certificates/gosu/tzdata are the same minimal runtime set as the sibling
# tool. No Docker CLI: the exporter reaches CrowdSec over the Local API.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates gosu tzdata \
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

# The heartbeat directory is a fixed path on the tmpfs Compose mounts
# (/tmp/state, see entrypoint.sh); the image cannot pre-create it, because it
# lives inside a mount that only exists at container start.
# /app stays root-owned and read-only for the app user on purpose: the
# container starts as root and executes entrypoint.sh before dropping
# privileges, so an app-writable entrypoint would let a compromised
# unprivileged process plant code that the next start runs as root.
# COPY --chmod above normalises the application files to world-readable
# (directories traversable) independent of the checkout's umask, so a 0600
# source file cannot break imports for the unprivileged app user. Write
# permission is deliberately not granted — see the note above.
# Stays root so the entrypoint can create and chown /tmp/state on start, then
# drops to uid:gid 10001:10001 via gosu before running any application code.

# The entrypoint touches /tmp/state/heartbeat only after main.py exits 0, so
# this HEALTHCHECK fails once exports keep failing past
# HEALTHCHECK_MAX_AGE_SECONDS. The file sits on a tmpfs, so a restarted
# container is unhealthy until its first successful export instead of
# inheriting a stale heartbeat; --start-period covers the startup window.
HEALTHCHECK --interval=5m --timeout=10s --start-period=3m --retries=3 \
    CMD sh -ec '\
        test -f /tmp/state/heartbeat || exit 1; \
        age=$(($(date +%s) - $(stat -c %Y /tmp/state/heartbeat))); \
        test "$age" -ge 0 && test "$age" -lt "${HEALTHCHECK_MAX_AGE_SECONDS:-900}"'

ENTRYPOINT ["./entrypoint.sh"]
