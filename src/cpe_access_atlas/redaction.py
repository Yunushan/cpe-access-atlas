# SPDX-License-Identifier: 0BSD
"""Conservative redaction helpers for contribution reports."""

from __future__ import annotations

import ipaddress
import re

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>[\"']?\b(password|passwd|passphrase|secret|token|"
    r"authorization|cookie|api_key|access_token|refresh_token|private_key|"
    r"pppoe_password|sip_password|acs_password)\b[\"']?)"
    r"(?P<separator>\s*[:=]\s*)(?P<quote>[\"']?)"
    r"(?P<value>[^\s,;}\"']+)(?P=quote)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_SUBSCRIBER_ID = re.compile(r"\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?:%[A-Za-z0-9_.-]+)?(?![A-Za-z0-9])"
)


def _redact_public_ip(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if not address.is_global and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
    ):
        return value
    return "[REDACTED-PUBLIC-IP]"


def redact_text(value: str) -> str:
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group('key')}{match.group('separator')}[REDACTED]",
        value,
    )
    value = _MAC.sub("[REDACTED-MAC]", value)
    value = _SUBSCRIBER_ID.sub("[REDACTED-SUBSCRIBER-ID]", value)
    value = _IPV4.sub(_redact_public_ip, value)
    return _IPV6.sub(_redact_public_ip, value)
