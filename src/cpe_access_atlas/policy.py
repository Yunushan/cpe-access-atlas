# SPDX-License-Identifier: 0BSD
"""Fail-closed network target policy."""

from __future__ import annotations

import ipaddress
import math
import socket
from collections.abc import Iterable


class PolicyError(ValueError):
    """Raised when a target violates the local-only policy."""


_IPV4_PRIVATE = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_IPV6_ULA = ipaddress.ip_network("fc00::/7")


def parse_single_private_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    candidate = value.strip()
    if not candidate or any(token in candidate for token in ("/", ",", ";", " ")):
        raise PolicyError("provide exactly one private IP literal, not a host list or CIDR")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise PolicyError("hostnames are not accepted; provide one private IP literal") from exc

    if isinstance(address, ipaddress.IPv4Address):
        if not any(address in network for network in _IPV4_PRIVATE):
            raise PolicyError("only RFC1918 IPv4 targets are permitted")
    elif address not in _IPV6_ULA:
        raise PolicyError("only IPv6 unique-local targets are permitted")
    return address


def parse_ports(value: str) -> tuple[int, ...]:
    raw_parts = value.split(",")
    if not 1 <= len(raw_parts) <= 8:
        raise PolicyError("provide between one and eight explicit TCP ports")
    ports: list[int] = []
    for raw in raw_parts:
        part = raw.strip()
        if not part.isdecimal():
            raise PolicyError("ports must be explicit integers; ranges are not accepted")
        port = int(part)
        if not 1 <= port <= 65535:
            raise PolicyError(f"invalid TCP port: {port}")
        if port not in ports:
            ports.append(port)
    return tuple(ports)


def parse_timeout(value: str | float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError("timeout must be a finite number of seconds") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise PolicyError("timeout must be greater than 0 and at most 30 seconds")
    return timeout


def probe_tcp_ports(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.0,
) -> dict[int, bool]:
    address = parse_single_private_address(host)
    timeout = parse_timeout(timeout)
    results: dict[int, bool] = {}
    for port in ports:
        try:
            with socket.create_connection((str(address), int(port)), timeout=timeout):
                results[int(port)] = True
        except (OSError, OverflowError, ValueError):
            results[int(port)] = False
    return results
