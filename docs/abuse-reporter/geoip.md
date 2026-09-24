# GeoIP Databases

The abuse reporter enriches each source IP with GeoLite2 City and ASN data. The
databases are handled so that a fresh container is immediately useful and no
persistent volume is needed for them.

## The three-stage model

1. **Build-time baseline.** The image fetches `GeoLite2-City.mmdb` and
   `GeoLite2-ASN.mmdb` into `/opt/geoip-baseline`, read-only.
2. **Start-time seed.** `entrypoint.sh` copies them into `GEOIP_DIR`
   (`/tmp/geoip`, a tmpfs) before dropping privileges. Enrichment therefore works
   on the very first run, without waiting for a download.
3. **Runtime update.** `app/geoip.py` checks the mirror conditionally, using
   `If-Modified-Since` derived from the MMDB build epoch, and overwrites the
   tmpfs copy in place when a newer release exists.

The seed step only copies what is missing, so a restart inside the same container
does not discard an already updated database.

Both the baseline and the updater use the same
[P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) mirror.

## Consequences worth knowing

!!! note "Every container start begins from the image baseline"
    The tmpfs copy is discarded on container stop, so each start re-seeds from
    the image and re-checks the mirror. **Rebuild the image to move the baseline
    forward.**

The databases live in RAM: roughly 78 MB total (City ~66 MB, ASN ~12 MB). Compose
gives `/tmp/geoip` a 256 MB tmpfs because an update writes a temporary file
before replacing the target, so the peak exceeds the resident size.

If the baseline is missing, the entrypoint warns and the first run depends on the
update check succeeding.

## Host runs

A direct host run keeps the previous layout under `data/geolite2`. After
upgrading a container deployment, the old `./data/geolite2` directory is leftover
and can be deleted.

## Failure behaviour

A GeoIP **cold start** — no usable database at all — is a hard failure and exits
`1`. A failed *update* check is not: the run continues against the existing
database. See [Exit codes](index.md#exit-codes).
