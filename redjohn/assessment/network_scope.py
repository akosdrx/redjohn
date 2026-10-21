"""Canonical non-HTTP network identities; discovery never creates grants."""

from __future__ import annotations

import ipaddress
import re


def numeric_ip(value: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("numeric_network_ip_required")
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("unsafe_network_ip")
    if value != str(address):
        raise ValueError("canonical_network_ip_required")
    return str(address)


def port_number(value: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError("explicit_network_port_required")
    port = int(value)
    if str(port) != value or not 1 <= port <= 65535:
        raise ValueError("invalid_network_port")
    return port


def dns_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 253
        or value != value.lower()
        or not value.isascii()
        or value.endswith(".")
        or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
            for label in value.split(".")
        )
    ):
        raise ValueError("canonical_ascii_dns_name_required")
    return value


def endpoint(address: str, port: str) -> str:
    address = numeric_ip(address)
    port_number(port)
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def resolver_tuple(value: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise TypeError("invalid_dns_resolver")
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
    else:
        host, separator, port = value.partition(":")
    if not separator or endpoint(host, port) != value:
        raise ValueError("invalid_dns_resolver")
    return host, port
