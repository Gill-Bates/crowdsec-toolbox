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
    ABUSE_DB_PATH=/data/abuse_alerts.db \
    GEOIP_DIR=/tmp/geoip \
    RUN_INTERVAL=21600 \
    METRICS_INTERVAL=60 \
    RUN_ONCE=false \
    RUN_JITTER=300 \
    HEALTHCHECK_MAX_AGE_SECONDS=28800 \
    API_HEARTBEAT_INTERVAL=300 \
    API_HEARTBEAT_MAX_AGE_SECONDS=700 \
    APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA}

LABEL org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

WORKDIR /app

# iproute2 provides `ip` for the local-address fallback in app/crowdsec.py.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates gosu iproute2 tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

# Build context is the repository root; dependencies come from the tool's local
# pyproject.toml (`--group` needs pip >= 25.1).
# Bind-mounted instead of copied so the manifest leaves no layer behind.
RUN --mount=type=bind,source=crowdsec-abuse-reporter/pyproject.toml,target=/tmp/pyproject.toml \
    pip install --no-cache-dir --root-user-action=ignore --group /tmp/pyproject.toml:default

# Copy only the runtime files required by the application. Secrets and mutable
# state stay outside the image in the mounted data volume.
# --chmod normalises modes independent of the checkout's umask without a
# separate chmod layer duplicating the files.
COPY --chmod=0755 crowdsec-abuse-reporter/app ./app
COPY --chmod=0644 crowdsec-abuse-reporter/run.py ./
COPY --chmod=0755 crowdsec-abuse-reporter/docker/entrypoint.sh ./entrypoint.sh

# GeoLite2 baseline, fetched at build time so a fresh container always has a
# usable database even before the first update check — and so the databases
# never need a persistent volume. The entrypoint copies these into $GEOIP_DIR
# (a tmpfs) at start; the updater in app/geoip.py overwrites that copy in place
# when the mirror has a newer release. Rebuild the image to refresh the
# baseline. Same P3TERX mirror the updater uses (see app/geoip.py).
ADD --chmod=0644 https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb \
    /opt/geoip-baseline/GeoLite2-City.mmdb
ADD --chmod=0644 https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb \
    /opt/geoip-baseline/GeoLite2-ASN.mmdb

# The image-local /data only matters for a run without a mounted volume; in
# Compose it is overlaid by the host-mounted ./data, whose ownership the
# entrypoint fixes at container start (see entrypoint.sh) since Docker
# creates missing bind-mount directories as root.
# /app stays root-owned and read-only for the app user on purpose: the
# container starts as root and executes entrypoint.sh before dropping
# privileges, so an app-writable entrypoint would let a compromised
# unprivileged process plant code that the next start runs as root.
RUN mkdir -p /data \
    && chown -R app:app /data

# Stays root so the entrypoint can chown /data on start, then drops to
# uid:gid 10001:10001 via gosu before running any application code.

VOLUME ["/data"]

HEALTHCHECK --interval=5m --timeout=10s --start-period=7m --retries=3 \
    CMD sh -ec '\
        test -f /data/heartbeat || exit 1; \
        age=$(($(date +%s) - $(stat -c %Y /data/heartbeat))); \
        test "$age" -ge 0 && test "$age" -lt "${HEALTHCHECK_MAX_AGE_SECONDS:-28800}" || exit 1; \
        test -f /data/api_heartbeat || exit 1; \
        api_age=$(($(date +%s) - $(stat -c %Y /data/api_heartbeat))); \
        test "$api_age" -ge 0 && test "$api_age" -lt "${API_HEARTBEAT_MAX_AGE_SECONDS:-700}"'

ENTRYPOINT ["./entrypoint.sh"]
