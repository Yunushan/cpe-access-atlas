# SPDX-License-Identifier: 0BSD
"""Conservative redaction helpers for contribution reports."""

from __future__ import annotations

import ipaddress
import re

# The pattern below matches secret *field names* (e.g. "password", "api_key")
# for redaction purposes; it is not a literal hardcoded secret.
_SECRET_NAME = (
    r"(?:password|passwd|passphrase|secret|secret[-_]?key|token|cookie|"  # noqa: S105
    r"api[-_]?key|auth[-_]?token|access[-_]?token|refresh[-_]?token|"
    r"private[-_]?key|pppoe[-_]?password|sip[-_]?password|acs[-_]?password)"
)
_SECRET_KEY = (
    r"(?P<key>[\"']?\b(?:[A-Za-z0-9]+[-_])?"
    rf"{_SECRET_NAME}[\"']?)"
)
_SECRET_SEPARATOR = r"(?P<separator>\s*[:=]\s*)"  # noqa: S105 -- regex fragment, not a credential
_SECRET_ASSIGNMENT_DOUBLE = re.compile(
    rf"(?i){_SECRET_KEY}{_SECRET_SEPARATOR}\"(?:\\.|[^\"\\\r\n])*\""
)
_SECRET_ASSIGNMENT_SINGLE = re.compile(
    rf"(?i){_SECRET_KEY}{_SECRET_SEPARATOR}'(?:\\.|[^'\\\r\n])*'"
)
_SECRET_ASSIGNMENT_UNQUOTED = re.compile(rf"(?i){_SECRET_KEY}{_SECRET_SEPARATOR}[^\s,;}}&\"']+")
_AUTHORIZATION = re.compile(
    r"(?i)(?P<key>[\"']?authorization[\"']?)"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?:(?P<scheme>Bearer|Basic)\s+)?"
    r"(?:(?P<quote>[\"'])(?:\\.|(?!(?P=quote))[^\r\n])*(?P=quote)|"
    r"(?![A-Za-z][A-Za-z0-9_-]*\s+)[^\s,;}\"']+)"
)
_AUTHORIZATION_OTHER = re.compile(
    r"(?i)(?P<key>[\"']?authorization[\"']?)"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?P<scheme>(?!Bearer\b|Basic\b)[A-Za-z][A-Za-z0-9_-]*)\s+[^\r\n}]+"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+")
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


def _replace_secret_assignment(match: re.Match[str]) -> str:
    return f"{match.group('key')}{match.group('separator')}[REDACTED]"


def _replace_quoted_secret(match: re.Match[str], quote: str) -> str:
    return f"{match.group('key')}{match.group('separator')}{quote}[REDACTED]{quote}"


def _replace_authorization(match: re.Match[str]) -> str:
    quote = match.group("quote")
    value = f"{quote}[REDACTED]{quote}" if quote else "[REDACTED]"
    return f"{match.group('key')}{match.group('separator')}{value}"


def _replace_other_authorization(match: re.Match[str]) -> str:
    return f"{match.group('key')}{match.group('separator')}[REDACTED]"


def redact_text(value: str) -> str:
    value = _AUTHORIZATION.sub(_replace_authorization, value)
    value = _AUTHORIZATION_OTHER.sub(_replace_other_authorization, value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _BASIC.sub("Basic [REDACTED]", value)
    value = _SECRET_ASSIGNMENT_DOUBLE.sub(lambda match: _replace_quoted_secret(match, '"'), value)
    value = _SECRET_ASSIGNMENT_SINGLE.sub(lambda match: _replace_quoted_secret(match, "'"), value)
    value = _SECRET_ASSIGNMENT_UNQUOTED.sub(_replace_secret_assignment, value)
    value = _MAC.sub("[REDACTED-MAC]", value)
    value = _SUBSCRIBER_ID.sub("[REDACTED-SUBSCRIBER-ID]", value)
    value = _IPV4.sub(_redact_public_ip, value)
    return _IPV6.sub(_redact_public_ip, value)
