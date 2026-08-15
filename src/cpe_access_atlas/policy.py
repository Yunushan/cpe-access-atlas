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
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_IPV6_ULA = ipaddress.ip_network("fc00::/7")


def parse_single_private_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str):
        raise PolicyError("provide exactly one private IP literal")
    candidate = value.strip()
    if (
        not candidate
        or any(character.isspace() for character in candidate)
        or any(token in candidate for token in ("/", ",", ";", "%"))
    ):
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
    if not isinstance(value, str):
        raise PolicyError("ports must be explicit integers; ranges are not accepted")
    raw_parts = value.split(",")
    if not 1 <= len(raw_parts) <= 8:
        raise PolicyError("provide between one and eight explicit TCP ports")
    ports: list[int] = []
    for raw in raw_parts:
        part = raw.strip()
        if not part.isascii() or not part.isdecimal():
            raise PolicyError("ports must be explicit integers; ranges are not accepted")
        try:
            port = int(part)
        except ValueError as exc:
            raise PolicyError("ports must be explicit integers; ranges are not accepted") from exc
        if not 1 <= port <= 65535:
            raise PolicyError(f"invalid TCP port: {port}")
        if port not in ports:
            ports.append(port)
    return tuple(ports)


def parse_timeout(value: str | float) -> float:
    if isinstance(value, bool):
        raise PolicyError("timeout must be a finite number of seconds")
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError("timeout must be a finite number of seconds") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise PolicyError("timeout must be greater than 0 and at most 30 seconds")
    return timeout


def _normalize_port_values(ports: Iterable[int]) -> tuple[int, ...]:
    try:
        iterator = iter(ports)
    except TypeError as exc:
        raise PolicyError("ports must be an iterable of explicit integers") from exc
    raw_ports: list[int] = []
    for _ in range(9):
        try:
            raw_ports.append(next(iterator))
        except StopIteration:
            break
    if not 1 <= len(raw_ports) <= 8:
        raise PolicyError("provide between one and eight explicit TCP ports")
    normalized: list[int] = []
    for port in raw_ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise PolicyError(f"invalid TCP port: {port}")
        if port not in normalized:
            normalized.append(port)
    return tuple(normalized)


def probe_tcp_ports(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.0,
) -> dict[int, bool]:
    address = parse_single_private_address(host)
    timeout = parse_timeout(timeout)
    normalized_ports = _normalize_port_values(ports)
    results: dict[int, bool] = {}
    for port in normalized_ports:
        try:
            with socket.create_connection((str(address), port), timeout=timeout):
                results[port] = True
        except (OSError, OverflowError, ValueError):
            results[port] = False
    return results
