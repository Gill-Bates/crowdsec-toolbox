# syntax=docker/dockerfile:1
FROM python:3.14-slim

# Always supplied via `docker buildx build --build-arg ...` (see the root setup.conf);
# no defaults, this image is never built without them.
ARG APP_VERSION
ARG GIT_SHA
ARG BUILD_DATE

# The *_MAX_AGE_SECONDS limits are deliberately not set here: the entrypoint
# derives them from the configured intervals (an explicit value wins) and writes
# them to /tmp/health_limits, which the HEALTHCHECK reads.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ABUSE_DB_PATH=/data/abuse_alerts.db \
    GEOIP_DIR=/tmp/geoip \
    RUN_INTERVAL=21600 \
    METRICS_INTERVAL=60 \
    RUN_ONCE=false \
    API_HEARTBEAT_INTERVAL=300 \
    APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA}

LABEL org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

WORKDIR /app

# iproute2 provides `ip` for the local-address fallback in app/crowdsec.py;
# tini is PID 1: it reaps orphaned children and forwards the stop signal.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates gosu iproute2 tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

# Build context is the repository root; dependencies come from the tool's local
# pyproject.toml (`--group` needs pip >= 25.1).
# [project].dependencies (the shared gillbates-logging, gillbates-questdb-client and gillbates-smtp-client packages) is not read by `--group`,
# so it is extracted into a requirements file and installed in the same pip call. The
# package lives in the private Gill-Bates/python-libraries repository: the token is a
# BuildKit secret (never ARG/ENV, so it stays out of layers and image history) handed to
# git through a credential helper that exists only for this command. git is installed and
# purged within this RUN, so the final image carries neither git nor the token.
# `set -eu` plus the explicit checks abort the build when the extraction, the install or
# the import fails; there is deliberately no pipe whose failure could be swallowed.
# Bind-mounted instead of copied so the manifest leaves no layer behind.
RUN --mount=type=bind,source=crowdsec-abuse-reporter/pyproject.toml,target=/tmp/pyproject.toml \
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
    python -c "import gillbates_logging, gillbates_questdb_client, gillbates_smtp_client"; \
    apt-get purge -y --auto-remove git; \
    rm -rf /var/lib/apt/lists/* /tmp/runtime-requirements.txt

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
# when the mirror has a newer release.
# Follow P3TERX's moving paths so each image rebuild picks up the latest files;
# identical source commits may therefore contain different GeoIP data.
ADD --chmod=0644 \
    https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb \
    /opt/geoip-baseline/GeoLite2-City.mmdb
ADD --chmod=0644 \
    https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb \
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

# Liveness of the container's own work, no dependency probe: both heartbeat files
# must be fresh, and while metrics are enabled (same condition as entrypoint.sh)
# so must the metrics snapshot file, which only makes the container unhealthy on
# a backend outage. The limits come from /tmp/health_limits (written by the
# entrypoint, so the rule lives there once); a missing file means unhealthy.
# Each helper pid file holds "<pid> <start time>"; the pid must exist, not be a
# zombie and keep its start time (guards against pid reuse).
HEALTHCHECK --interval=5m --timeout=10s --start-period=7m --retries=3 \
    CMD sh -ec '\
        read -r main_max api_max metrics_max < /tmp/health_limits || exit 1; \
        test -f /data/heartbeat || exit 1; \
        age=$(($(date +%s) - $(stat -c %Y /data/heartbeat))); \
        test "$age" -ge 0 && test "$age" -lt "$main_max" || exit 1; \
        test -f /data/api_heartbeat || exit 1; \
        api_age=$(($(date +%s) - $(stat -c %Y /data/api_heartbeat))); \
        test "$api_age" -ge 0 && test "$api_age" -lt "$api_max" || exit 1; \
        alive() { read -r p t < "$1" || return 1; read -r l < "/proc/$p/stat" || return 1; set -- ${l##*) }; test "$1" != Z || return 1; shift 19; test "$1" = "$t"; }; \
        alive /tmp/api_heartbeat.pid || exit 1; \
        if test -n "${METRICS_BACKEND:-}" && test "${METRICS_BACKEND}" != none; then \
            alive /tmp/metrics.pid || exit 1; \
            test -f /tmp/metrics_heartbeat || exit 1; \
            m_age=$(($(date +%s) - $(stat -c %Y /tmp/metrics_heartbeat))); \
            test "$m_age" -ge 0 && test "$m_age" -lt "$metrics_max" || exit 1; \
        fi'

ENTRYPOINT ["/usr/bin/tini", "--", "./entrypoint.sh"]
