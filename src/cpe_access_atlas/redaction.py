# SPDX-License-Identifier: 0BSD
"""Conservative redaction helpers for contribution reports."""

from __future__ import annotations

import ipaddress
import re


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|authorization|cookie|"
    r"pppoe_password|sip_password|acs_password)\b(\s*[:=]\s*)([^\s,;]+)"
)
_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_SUBSCRIBER_ID = re.compile(r"\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _redact_public_ipv4(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if address.is_private:
        return value
    return "[REDACTED-PUBLIC-IP]"


def redact_text(value: str) -> str:
    value = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        value,
    )
    value = _MAC.sub("[REDACTED-MAC]", value)
    value = _SUBSCRIBER_ID.sub("[REDACTED-SUBSCRIBER-ID]", value)
    return _IPV4.sub(_redact_public_ipv4, value)
