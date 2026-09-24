#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/dns_utils.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Sequence

import dns.exception
import dns.resolver

_log = logging.getLogger(__name__)

_DNS_QUERY_TIMEOUT_S = 1.0
_RESOLUTION_TIMEOUT_S = 5.0


def _system_nameservers() -> list[str]:
    """Return nameservers from the process' resolver config."""
    try:
        resolver = dns.resolver.Resolver()
    except dns.resolver.NoResolverConfiguration:
        return []
    return [str(nameserver) for nameserver in resolver.nameservers if nameserver]


def get_effective_nameservers() -> list[str]:
    """Return the resolvers for outbound DNS work.

    The application uses the container's system resolver configuration as-is.
    In Docker this typically means the embedded resolver at ``127.0.0.11``,
    which forwards to the daemon/host upstream DNS servers.
    """
    system_resolvers = _system_nameservers()
    if not system_resolvers:
        _log.warning(
            "No system DNS resolver configured inside the container"
        )
    return system_resolvers


def resolve_hostname(
    hostname: str,
    nameservers: Sequence[str],
) -> list[str]:
    """Resolve a hostname through the selected nameservers."""
    if not hostname:
        return []
    try:
        ipaddress.ip_address(hostname)
        return [hostname]
    except ValueError:
        pass

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [str(nameserver) for nameserver in nameservers]
    resolver.timeout = _DNS_QUERY_TIMEOUT_S
    resolver.lifetime = _RESOLUTION_TIMEOUT_S

    addresses: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, rdtype)
        except dns.exception.DNSException:
            continue
        addresses.extend(str(answer) for answer in answers)
    return addresses
