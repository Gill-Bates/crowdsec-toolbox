#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/geoip.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Thin adapter over the shared ``gillbates-geoip`` package.

The package downloads, verifies and queries the GeoLite2 City and ASN databases;
this module binds it to ``GEOIP_DIR``, the app's log helpers and DNS resolver
and keeps the module-level names the rest of the app imports.
"""

import logging

from gillbates_geoip import GeoInfo, GeoIPConfig, GeoIPDatabases, GeoIPUnavailableError, LogSink

from .config import GEOIP_DIR
from .dns_utils import get_effective_nameservers, resolve_hostname

_log = logging.getLogger(__name__)

__all__ = [
    "GeoIPUnavailableError",
    "GeoInfo",
    "ensure_geoip_databases",
    "lookup",
    "lookup_asn_providers",
]

_geo = GeoIPDatabases(
    GeoIPConfig(directory=GEOIP_DIR, user_agent="crowdsec-abuse-reporter/1.0"),
    log=LogSink(debug=_log.debug, info=_log.info, warning=_log.warning, error=_log.error),
    resolver=lambda host: resolve_hostname(host, get_effective_nameservers()),
)


def ensure_geoip_databases(*, force: bool = False) -> dict[str, bool]:
    """Download/verify both GeoLite2 DBs; raises ``GeoIPUnavailableError`` on a cold start."""
    return _geo.ensure(force=force)


def lookup(ip: str) -> GeoInfo:
    """Return GeoInfo for a public IP. Fields are None when unavailable."""
    return _geo.lookup(ip)


def lookup_asn_providers(asns: set[str] | frozenset[str]) -> dict[str, str]:
    """Return provider names for normalized ASN digits using the local ASN DB."""
    return _geo.lookup_asn_providers(asns)
