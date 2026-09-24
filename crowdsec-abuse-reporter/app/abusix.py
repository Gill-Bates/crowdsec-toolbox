#!/usr/bin/env python3
#
# crowdsec-abuse-reporter/app/abusix.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import ipaddress

import dns.exception
import dns.resolver

from .abuse import split_recipients
from .config import ABUSIX_DNS_LIFETIME, ABUSIX_TIMEOUT
from .database import get_cached_abuse_contact, set_cached_abuse_contact
from .dns_utils import get_effective_nameservers
from .logger import print_abuse_contact_found, print_dns_query

# Python 3.13 removed IPv6Address.is_6to4 and .is_teredo; check by prefix instead
_6TO4_NETWORK = ipaddress.IPv6Network("2002::/16")
_TEREDO_NETWORK = ipaddress.IPv6Network("2001::/32")


def _build_resolver() -> dns.resolver.Resolver:
    """Build a DNS resolver with bounded timeouts so a slow/unreachable
    nameserver fails fast instead of hanging the run.

    - ``timeout``  caps each individual nameserver attempt.
    - ``lifetime`` caps the total time spent on one lookup (all retries).

    The resolver is taken exclusively from the container's system
    configuration. Under Docker this is normally the embedded resolver,
    which forwards to the daemon/host upstream DNS servers.
    """
    try:
        resolver = dns.resolver.Resolver()
    except dns.resolver.NoResolverConfiguration:
        # No usable /etc/resolv.conf (can happen in minimal containers)
        resolver = dns.resolver.Resolver(configure=False)

    resolver.nameservers = get_effective_nameservers()

    resolver.timeout = ABUSIX_TIMEOUT
    resolver.lifetime = ABUSIX_DNS_LIFETIME
    return resolver


_resolver = _build_resolver()


def get_active_nameservers() -> list[str]:
    """Return the resolver's effective nameservers (for diagnostics/banner)."""
    return list(_resolver.nameservers)


class AbuseContactDnsError(RuntimeError):
    """Raised when the abuse contact lookup fails due to an operational DNS error."""


def get_ip_prefix(ip: str) -> str | None:
    """
    Get the appropriate IP prefix for abuse contact cache key.

    Used for caching abuse contacts per subnet to reduce DNS lookups.
    For IPv4: /24 subnet
    For IPv6: /48 or /64 subnet depending on the address type

    Args:
        ip: IP address string

    Returns:
        Network prefix string suitable for cache key, or None if invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.version == 4:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(network.network_address)

        # 6to4 and Teredo pack the real endpoint into the low bits, so a /48
        # would collapse unrelated hosts onto one cache key. Use /64 for those.
        network = ipaddress.IPv6Network(f"{ip}/48", strict=False)
        if (network.network_address in _6TO4_NETWORK
                or network.network_address in _TEREDO_NETWORK):
            network = ipaddress.IPv6Network(f"{ip}/64", strict=False)
        return str(network.network_address)

    except ValueError:
        return None


def query_abuse_contact_dns(ip: str) -> str | None:
    """
    Query Abuse Contact DB via DNS for a specific IP address.
    Returns abuse contact email or None if not found.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.version == 4:
            reversed_ip = ".".join(reversed(ip.split(".")))
        else:
            reversed_ip = ".".join(reversed(ip_obj.exploded.replace(":", "")))
        query = f"{reversed_ip}.abuse-contacts.abusix.org"

        print_dns_query(ip, f"IPv{ip_obj.version}")

        try:
            answers = _resolver.resolve(query, "TXT")
            for rdata in answers:
                contact = "".join(
                    s.decode("utf-8") if isinstance(s, bytes) else s
                    for s in rdata.strings
                ).strip()
                # Validate through the same path the send uses. The result is
                # cached positively, so accepting anything containing '@' would
                # pin an unsendable address for the whole cache TTL instead of
                # re-querying DNS.
                recipients = split_recipients(contact)
                if recipients:
                    return ",".join(recipients)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.resolver.Timeout, dns.exception.DNSException) as e:
            raise AbuseContactDnsError(str(e)) from e

    except ValueError:
        return None


def extract_abuse_contact(ip: str) -> str | None:
    """
    Extract abuse contact for IP using cache + DNS fallback.
    Implements positive and negative caching per subnet prefix.

    Args:
        ip: IP address to look up

    Returns:
        Abuse contact email or None if not found
    """
    ip_prefix = get_ip_prefix(ip)
    if not ip_prefix:
        return None

    cache_hit, cached_contact = get_cached_abuse_contact(ip_prefix)
    if cache_hit:
        return cached_contact

    contact = query_abuse_contact_dns(ip)

    set_cached_abuse_contact(ip_prefix, contact)

    if contact:
        print_abuse_contact_found(ip, contact)

    return contact
