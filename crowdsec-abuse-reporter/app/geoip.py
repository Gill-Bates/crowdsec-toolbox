#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/geoip.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""MaxMind GeoLite2 download, verification, and lookup for abuse reports.

Downloads City and ASN databases from the P3TERX mirror (no license key).
Both DBs are needed: City → city name + country code; ASN → AS number + provider.
Thread-safe with LRU-cached lookups and a 12-hour freshness stamp.
"""

from __future__ import annotations

import fcntl
import functools
import http.client
import ipaddress
import logging
import os
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import formatdate
from pathlib import Path
from threading import RLock
from typing import Self, TypedDict
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse

from .config import GEOIP_DIR
from .dns_utils import get_effective_nameservers, resolve_hostname

_log = logging.getLogger(__name__)

try:
    import geoip2.database
    import geoip2.errors
    _HAS_GEOIP = True
except ImportError:
    _log.warning("geoip2 package not installed — GeoIP lookups disabled")
    _HAS_GEOIP = False
    geoip2 = None  # type: ignore[assignment]

try:
    import maxminddb
    _HAS_MAXMINDDB = True
except ImportError:
    _HAS_MAXMINDDB = False
    maxminddb = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# P3TERX mirror — updated regularly, no MaxMind license key required
CITY_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
ASN_URL  = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"

_MIN_CITY_SIZE       = 10_000_000   # ~60 MB in production
_MIN_ASN_SIZE        =  1_000_000   # ~8 MB in production
_MAX_DOWNLOAD_BYTES  = 200_000_000
_DOWNLOAD_TIMEOUT_S  = 120.0
_CHECK_INTERVAL_H    = 12
_STAMP_FILE          = ".geoip_last_check"
_LOCK_FILE           = ".geoip-update.lock"
_CACHE_SIZE          = 4096

_ALLOWED_HOSTS = frozenset({
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
})
_DOWNLOAD_LOCK = RLock()


@dataclass(frozen=True, slots=True)
class _Spec:
    name: str
    filename: str
    url: str
    min_size: int
    db_type: str  # substring expected in MMDB database_type field


class _ResolvedHTTPResponse:
    """Small wrapper that mirrors the urlopen response API used by this module."""

    def __init__(
        self,
        response: http.client.HTTPResponse,
        *,
        url: str,
        connection: http.client.HTTPConnection,
    ) -> None:
        self._response = response
        self._connection = connection
        self.url = url
        self.headers = response.headers

    def read(self, amount: int = -1) -> bytes:
        return self._response.read(amount)

    def close(self) -> None:
        self._response.close()
        self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False


class _ResolvedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to a pre-resolved IP but verifies the hostname."""

    def __init__(self, host: str, resolved_host: str, **kwargs) -> None:
        super().__init__(host, **kwargs)
        self._resolved_host = resolved_host

    def connect(self) -> None:
        sock = self._create_connection(
            (self._resolved_host, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = sock
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


_SPECS: dict[str, _Spec] = {
    "city": _Spec("City", "GeoLite2-City.mmdb", CITY_URL, _MIN_CITY_SIZE, "City"),
    "asn":  _Spec("ASN",  "GeoLite2-ASN.mmdb",  ASN_URL,  _MIN_ASN_SIZE,  "ASN"),
}

# ---------------------------------------------------------------------------
# Public return type
# ---------------------------------------------------------------------------
class GeoInfo(TypedDict, total=False):
    city: str | None
    country: str | None
    asn: int | None
    provider: str | None


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------
def _geoip_dir() -> Path:
    """Return the GeoLite2 working directory, creating it if needed.

    This is `GEOIP_DIR` from the configuration, which the container points at a
    tmpfs seeded from the image's build-time copy; direct host runs keep the
    databases under `data/geolite2`.
    """
    GEOIP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    return GEOIP_DIR


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.strip()).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Reader manager (lazy-init, thread-safe)
# ---------------------------------------------------------------------------
class _Reader:
    __slots__ = ("_lock", "_r", "_spec", "_warned")

    def __init__(self, spec: _Spec) -> None:
        self._spec = spec
        self._r: geoip2.database.Reader | None = None  # type: ignore[type-arg]
        self._lock = RLock()
        self._warned = False

    def get(self) -> geoip2.database.Reader | None:  # type: ignore[type-arg]
        if not _HAS_GEOIP:
            return None
        if self._r is not None:
            return self._r
        with self._lock:
            if self._r is not None:
                return self._r
            p = _geoip_dir() / self._spec.filename
            if not p.exists():
                if not self._warned:
                    self._warned = True
                    _log.info("%s DB not found at %s", self._spec.name, p)
                return None
            try:
                self._r = geoip2.database.Reader(str(p))
                _log.debug("Loaded %s reader from %s", self._spec.name, p)
                return self._r
            except Exception as exc:
                _log.warning("Failed to open %s: %s", self._spec.name, exc)
                return None

    def close(self) -> None:
        with self._lock:
            if self._r:
                with suppress(Exception):
                    self._r.close()
                self._r = None
                self._warned = False


_city_reader = _Reader(_SPECS["city"])
_asn_reader  = _Reader(_SPECS["asn"])
_cache_gen   = 0  # incremented on DB update to invalidate LRU caches


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def _verify(path: Path, spec: _Spec) -> bool:
    if not path.exists():
        return False
    size = path.stat().st_size
    if size < spec.min_size:
        _log.warning("%s too small: %d bytes (min %d)", path.name, size, spec.min_size)
        return False
    if not _HAS_GEOIP:
        return True
    try:
        with geoip2.database.Reader(str(path)) as r:
            db_type = r.metadata().database_type
            if spec.db_type not in db_type:
                _log.warning("%s type mismatch: expected %s, got %s", path.name, spec.db_type, db_type)
                return False
            build = datetime.fromtimestamp(r.metadata().build_epoch, tz=UTC).date()
            _log.debug("%s OK (type=%s, build=%s)", path.name, db_type, build)
    except Exception as exc:
        _log.warning("%s verification failed: %s", path.name, exc)
        return False
    return True


def _if_modified_since(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        if _HAS_GEOIP:
            with geoip2.database.Reader(str(path)) as r:
                return formatdate(r.metadata().build_epoch, usegmt=True)
        return formatdate(path.stat().st_mtime, usegmt=True)
    except Exception:
        return ""


def _build_request_path(parsed_url) -> str:
    path = parsed_url.path or "/"
    if parsed_url.query:
        return f"{path}?{parsed_url.query}"
    return path


def _open_resolved_url(
    url: str,
    *,
    headers: dict[str, str],
    nameservers: list[str],
    timeout: float,
    allowed_hosts: frozenset[str],
    max_redirects: int = 5,
) -> _ResolvedHTTPResponse:
    """Open a URL through explicitly selected DNS resolvers.

    This keeps DNS selection local to the download request instead of mutating
    process-global socket resolution state.

    The scheme and host are validated against ``allowed_hosts`` *before* every
    request, including each redirect hop. Validating only the final URL after
    the fact would still issue outbound connections to an attacker-chosen
    redirect target first (SSRF/egress risk).
    """
    current_url = url
    for _ in range(max_redirects + 1):
        parsed = urlparse(current_url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").strip().lower()
        if scheme != "https" or host not in allowed_hosts:
            raise ValueError(f"Unsupported GeoIP download target: {current_url}")

        addresses = resolve_hostname(host, nameservers)
        if not addresses:
            raise URLError(
                f"Could not resolve {host!r} via selected DNS resolvers: "
                f"{', '.join(nameservers)}"
            )

        port = parsed.port or 443
        request_path = _build_request_path(parsed)
        request_headers = dict(headers)
        request_headers["Host"] = host
        last_error: OSError | None = None

        for address in addresses:
            connection = _ResolvedHTTPSConnection(
                host,
                address,
                port=port,
                timeout=timeout,
            )
            try:
                connection.request("GET", request_path, headers=request_headers)
                response = connection.getresponse()
                break
            except OSError as exc:
                connection.close()
                last_error = exc
        else:
            if last_error is None:
                raise URLError(f"Unable to connect to {host!r}")
            raise URLError(str(last_error)) from last_error

        status = response.status
        if status in {301, 302, 303, 307, 308}:
            location = response.getheader("Location", "").strip()
            response.close()
            connection.close()
            if not location:
                raise HTTPError(
                    current_url,
                    status,
                    "Redirect without Location header",
                    response.headers,
                    None,
                )
            current_url = urljoin(current_url, location)
            continue

        if status == 304 or status >= 400:
            response.close()
            connection.close()
            raise HTTPError(
                current_url,
                status,
                response.reason,
                response.headers,
                None,
            )

        return _ResolvedHTTPResponse(
            response,
            url=current_url,
            connection=connection,
        )

    raise HTTPError(current_url, 310, "Too many redirects", None, None)


# ---------------------------------------------------------------------------
# Download (atomic write, size-capped, redirect-validated)
# ---------------------------------------------------------------------------
class _TransientDownloadError(RuntimeError):
    """A GeoIP download failed for a reason worth retrying (network/5xx)."""


_DOWNLOAD_RETRY_STATUS = frozenset({408, 429, 500, 502, 503, 504})
_DOWNLOAD_MAX_ATTEMPTS = 3


def _download(spec: _Spec, *, force: bool = False) -> bool:
    """Download one DB file, retrying transient failures a bounded number of
    times. Returns True when the on-disk file was replaced.

    A cold start with no cached DB is fatal for the whole run, so a single DNS
    or connect blip must not decide the outcome. Non-transient results (304,
    4xx, checksum mismatch) are returned as-is and never repeated.
    """
    delay = 1.0
    for attempt in range(1, _DOWNLOAD_MAX_ATTEMPTS + 1):
        try:
            return _download_once(spec, force=force)
        except _TransientDownloadError as e:
            if attempt == _DOWNLOAD_MAX_ATTEMPTS:
                _log.error(
                    "GeoIP %s download failed after %d attempts: %s",
                    spec.name, _DOWNLOAD_MAX_ATTEMPTS, e,
                )
                return False
            _log.warning(
                "GeoIP %s download failed (attempt %d/%d), retrying in %.0fs: %s",
                spec.name, attempt, _DOWNLOAD_MAX_ATTEMPTS, delay, e,
            )
            time.sleep(delay)
            delay *= 2
    return False


def _download_once(spec: _Spec, *, force: bool = False) -> bool:
    """One download attempt. Raises _TransientDownloadError on retryable errors."""
    target = _geoip_dir() / spec.filename

    # No early return for an existing valid DB: that would make the
    # If-Modified-Since request below unreachable and freeze the database at
    # its first downloaded version forever. ensure_geoip_databases() already
    # decides via the stamp file whether a remote check is due at all.
    _log.info("Checking GeoIP %s from %s …", spec.name, spec.url)

    fd, tmp_str = tempfile.mkstemp(suffix=".mmdb.tmp", dir=str(_geoip_dir()))
    tmp = Path(tmp_str)
    try:
        os.fchmod(fd, 0o644)
        headers: dict[str, str] = {"User-Agent": "crowdsec-abuse-reporter/1.0"}
        if not force and target.exists():
            ims = _if_modified_since(target)
            if ims:
                headers["If-Modified-Since"] = ims

        deadline = time.monotonic() + _DOWNLOAD_TIMEOUT_S
        nameservers = get_effective_nameservers()

        with _open_resolved_url(
            spec.url,
            headers=dict(headers),
            nameservers=nameservers,
            timeout=60,
            allowed_hosts=_ALLOWED_HOSTS,
        ) as resp:
            final_url = getattr(resp, "url", spec.url)
            host = (urlparse(final_url).hostname or "").lower()
            if host not in _ALLOWED_HOSTS:
                raise ValueError(f"Unexpected redirect host: {host!r}")
            ct = resp.headers.get("Content-Type", "")
            if "text/html" in ct:
                raise ValueError(f"Got HTML response for {spec.name}")

            downloaded = 0
            with os.fdopen(fd, "wb") as f:
                fd = -1
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("GeoIP download timed out")
                    chunk = resp.read(65_536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if downloaded > _MAX_DOWNLOAD_BYTES:
                        raise ValueError("Download exceeded safety cap")
                f.flush()
                os.fsync(f.fileno())

        if not _verify(tmp, spec):
            return False

        tmp.replace(target)
        os.chmod(target, 0o644)
        _log.info("GeoIP %s updated (%d bytes)", spec.name, downloaded)
        return True

    except HTTPError as e:
        if e.code == 304:
            _log.debug("GeoIP %s up-to-date (304)", spec.name)
            return False
        if e.code in _DOWNLOAD_RETRY_STATUS:
            raise _TransientDownloadError(f"HTTP {e.code}") from e
        _log.warning("GeoIP %s HTTP error %s", spec.name, e.code)
    except (URLError, TimeoutError, OSError) as e:
        # DNS, connect, TLS and read failures — retry-worthy by nature.
        raise _TransientDownloadError(str(e)) from e
    except Exception as e:
        # Content-level rejections (HTML body, size cap, bad redirect host) are
        # deterministic; repeating them would only waste the run's time budget.
        _log.error("GeoIP %s download failed: %s", spec.name, e)
    finally:
        if fd != -1:
            with suppress(OSError):
                os.close(fd)
        with suppress(OSError):
            tmp.unlink()
    return False


class GeoIPUnavailableError(RuntimeError):
    """Raised when a GeoIP database has never been successfully downloaded
    and the current attempt also failed.

    A refresh failure for a DB that already has a valid cached copy is not
    raised here — the stale copy stays in use and enrichment keeps working.
    Only a cold start with no usable DB on disk is fatal, so a broken/blocked
    download on first boot cannot silently ship abuse reports without any
    GeoIP enrichment forever.
    """


# ---------------------------------------------------------------------------
# Public: ensure databases are present and reasonably fresh
# ---------------------------------------------------------------------------
def ensure_geoip_databases(*, force: bool = False) -> dict[str, bool]:
    """Download/verify both GeoLite2 DBs. Safe to call at every startup.

    Skips the remote check if both DBs are valid and the stamp is < 12 h old.
    Invalidates reader caches when a DB file is replaced.

    Raises:
        GeoIPUnavailableError: A DB has no valid cached copy from a previous
            run *and* the download attempted here also failed — i.e. GeoIP
            has never worked. Callers should treat this as a fatal startup
            error rather than silently running without enrichment.
    """
    global _cache_gen

    gdir = _geoip_dir()
    stamp = gdir / _STAMP_FILE
    lock_path = gdir / _LOCK_FILE

    with _DOWNLOAD_LOCK:
        # Cross-process file lock so parallel container restarts don't race.
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        lock_fd = os.open(str(lock_path), flags, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)

            if not force and stamp.exists():
                try:
                    age_h = (time.time() - float(stamp.read_text().strip())) / 3600
                    if age_h < _CHECK_INTERVAL_H:
                        c_ok = _verify(gdir / _SPECS["city"].filename, _SPECS["city"])
                        a_ok = _verify(gdir / _SPECS["asn"].filename,  _SPECS["asn"])
                        if c_ok and a_ok:
                            _log.debug("GeoIP DBs fresh (%.1fh old) — skipping remote check", age_h)
                            return {"city": True, "asn": True}
                except (OSError, ValueError) as exc:
                    _log.debug("GeoIP check stamp could not be read: %s", exc)

            had_before = {
                name: _verify(gdir / spec.filename, spec)
                for name, spec in _SPECS.items()
            }

            c_new = _download(_SPECS["city"], force=force)
            a_new = _download(_SPECS["asn"],  force=force)

            if c_new or a_new:
                _city_reader.close()
                _asn_reader.close()
                _cache_gen += 1
                _cached_city.cache_clear()
                _cached_asn.cache_clear()
                # Provider names come from the same ASN MMDB and would other-
                # wise keep serving the pre-update database for this process.
                _cached_asn_providers.cache_clear()

            result = {
                "city": _verify(gdir / _SPECS["city"].filename, _SPECS["city"]),
                "asn":  _verify(gdir / _SPECS["asn"].filename,  _SPECS["asn"]),
            }

            if result["city"] and result["asn"]:
                stamp.write_text(str(time.time()))
            else:
                if not result["city"]:
                    _log.warning("GeoIP City DB unavailable — city/country enrichment disabled")
                if not result["asn"]:
                    _log.warning("GeoIP ASN DB unavailable — provider enrichment disabled")

            never_available = [
                name for name, ok in result.items() if not ok and not had_before[name]
            ]
            if never_available:
                raise GeoIPUnavailableError(
                    "GeoIP database(s) could not be downloaded on first startup: "
                    f"{', '.join(sorted(never_available))}"
                )

            return result

        finally:
            with suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


# ---------------------------------------------------------------------------
# Cached lookups
# ---------------------------------------------------------------------------
@functools.lru_cache(maxsize=_CACHE_SIZE)
def _cached_city(ip: str, _gen: int) -> tuple[str | None, str | None]:
    reader = _city_reader.get()
    if not reader:
        return None, None
    try:
        r = reader.city(ip)
        return r.city.name, r.country.iso_code
    except Exception:
        return None, None


@functools.lru_cache(maxsize=_CACHE_SIZE)
def _cached_asn(ip: str, _gen: int) -> tuple[int | None, str | None]:
    reader = _asn_reader.get()
    if not reader:
        return None, None
    try:
        r = reader.asn(ip)
        return r.autonomous_system_number, r.autonomous_system_organization
    except Exception:
        return None, None


def lookup(ip: str) -> GeoInfo:
    """Return GeoInfo for a public IP. Fields are None when unavailable."""
    if not _is_public(ip):
        return GeoInfo(city=None, country=None, asn=None, provider=None)
    city, country = _cached_city(ip, _cache_gen)
    asn, provider = _cached_asn(ip, _cache_gen)
    return GeoInfo(city=city, country=country, asn=asn, provider=provider)


@functools.lru_cache(maxsize=64)
def _cached_asn_providers(asns: tuple[str, ...]) -> dict[str, str]:
    """Resolve ASN -> provider names by iterating the local ASN MMDB once.

    MaxMind's ASN database is keyed by IP network, not ASN number. There is no
    direct ASN lookup API, so we scan the DB until every requested ASN has been
    seen or the file ends. For the small configured whitelist this is fast and
    avoids any external network dependency.
    """
    if not asns or not _HAS_MAXMINDDB:
        return {}

    target = {int(asn) for asn in asns if str(asn).isdigit()}
    if not target:
        return {}

    path = _geoip_dir() / _SPECS["asn"].filename
    if not path.exists():
        return {}

    providers: dict[str, str] = {}
    reader = maxminddb.open_database(str(path))
    try:
        for _network, record in reader:
            if not isinstance(record, dict):
                continue
            asn = record.get("autonomous_system_number")
            provider = str(record.get("autonomous_system_organization") or "").strip()
            if not isinstance(asn, int) or asn not in target or not provider:
                continue
            key = str(asn)
            if key in providers:
                continue
            providers[key] = provider
            if len(providers) == len(target):
                break
    except Exception as exc:
        _log.warning("ASN provider lookup from local MMDB failed: %s", exc)
        return {}
    finally:
        with suppress(Exception):
            reader.close()

    return providers


def lookup_asn_providers(asns: set[str] | frozenset[str]) -> dict[str, str]:
    """Return provider names for normalized ASN digits using the local ASN DB."""
    normalized = tuple(sorted({str(asn).strip() for asn in asns if str(asn).strip()}))
    return _cached_asn_providers(normalized)
