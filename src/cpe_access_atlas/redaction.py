# SPDX-License-Identifier: 0BSD
"""Conservative redaction helpers for contribution reports."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from html import unescape
from io import StringIO

MAX_REPORT_CHARS = 8 * 1024 * 1024


class RedactionError(ValueError):
    """A report cannot be safely processed within the supported input limits."""


# The pattern below matches secret *field names* (e.g. "password", "api_key")
# for redaction purposes; it is not a literal hardcoded secret.
_SECRET_NAME = (
    r"(?:password|passwd|(?:key[-_]?)?passphrase|pre[-_]?shared[-_]?key|"  # noqa: S105
    r"(?:(?:wi[-_]?fi|wlan|wpa[23]?)[-_]?)?psk|"
    r"secret|secret[-_]?key|token|cookie|(?:proxy[-_]?)?authorization|"
    r"api[-_]?key|auth[-_]?token|access[-_]?token|refresh[-_]?token|"
    r"private[-_]?key|pppoe[-_]?password|sip[-_]?password|acs[-_]?password|"
    r"serial(?:[-_]?number)?|subscriber[-_]?id)"
)
_SENSITIVE_SUFFIX = re.compile(rf"(?i)(?:^|[\W_]){_SECRET_NAME}\Z")
# Token boundaries prevent retrying a failed match at every character of a
# long vendor/path name. Quoted JSON keys and command options use the same
# scanner, while XML name/value pairs are handled before this text pass.
_FIELD_KEY = r"[\"']?[^\s:=\"',;{}&<>]+[\"']?"
_ASSIGNMENT = re.compile(
    rf"(?<![^\s:=\"',;{{}}&<>])(?P<key>{_FIELD_KEY})"
    r"(?P<separator>[ \t]*[:=][ \t]*)"
)
_MULTILINE_ASSIGNMENT = re.compile(
    rf"(?<![^\s:=\"',;{{}}&<>])(?P<key>{_FIELD_KEY})(?P<separator>\s*[:=]\s*)"
)
_NEXT_ASSIGNMENT = re.compile(rf"(?:(?<![ \t])[ \t]+|[,;&][ \t]*){_FIELD_KEY}[ \t]*[:=][ \t]*")
_QUOTED_VALUE = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", re.DOTALL)
_REPORT_LINES = re.compile(r"[^\r\n]*(?:\r\n?|\n|\Z)")
_YAML_BLOCK = re.compile(r"[|>](?:[1-9][+-]?|[+-][1-9]?)?[ \t]*(?:#.*)?\Z")
# Consume the complete HTTP value, including obsolete folded continuations.
# Applying the assignment matcher alone would leave every cookie after ';'.
_COOKIE_HEADER = re.compile(
    r"(?im)(?P<key>(?<![\w-])(?:set-cookie|cookie))"
    r"(?P<separator>[ \t]*:[ \t]*)[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*"
)
_AUTHORIZATION_HEADER = re.compile(
    r"(?im)(?P<key>^[ \t]*(?:>[ \t]*)?(?:proxy-)?authorization)"
    r"(?P<separator>[ \t]*:[ \t]*)[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*"
)
_XML_ATTRIBUTE = re.compile(
    r"(?<!\s)(?P<prefix>\s+(?P<name>[\w:.-]+)\s*=\s*)(?P<quote>[\"'])"
    r"(?P<value>.*?)(?P=quote)",
    re.DOTALL,
)
_XML_NAME = re.compile(r"[A-Za-z_][\w:.-]*")
_OPAQUE_SENSITIVE_CONTENT = re.compile(_SECRET_NAME, re.IGNORECASE)
_PRIVATE_KEY_BLOCK = re.compile(
    r"(?P<begin>-----BEGIN (?P<kind>(?:[A-Z0-9]+ )*PRIVATE KEY)-----)"
    r".*?(?P<end>-----END (?P=kind)-----|\Z)",
    re.DOTALL,
)
_AUTHORIZATION = re.compile(
    r"(?i)(?P<key>[\"']?authorization[\"']?)"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?:(?P<scheme>Bearer|Basic)\s+)?"
    r"(?:(?P<quote>[\"'])(?:\\.|(?!(?P=quote))[^\\\r\n])*(?P=quote)|"
    r"(?![A-Za-z][A-Za-z0-9_-]*\s+)[^\s,;}\"']+)"
)
_AUTHORIZATION_OTHER = re.compile(
    r"(?i)(?P<key>[\"']?authorization[\"']?)"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?P<scheme>(?!Bearer\b|Basic\b)[A-Za-z][A-Za-z0-9_-]*)\s+[^\r\n}]+"
    r"(?:\r?\n[ \t]+[^\r\n]*)*"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+")
_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_SUBSCRIBER_ID = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\b")
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


def _is_sensitive_field(name: str) -> bool:
    """Recognize credential suffixes across vendor, namespace and TR-069 paths."""

    name = name.strip("\"'").casefold()
    # Compact identifiers such as SIP_AuthPassword and PPPPassword carry the
    # same credential suffix as separated names. Suffixes like PasswordLength
    # remain public settings rather than being classified as passwords.
    return name.endswith(("password", "passwd")) or _SENSITIVE_SUFFIX.search(name) is not None


def _redact_structured_assignments(value: str) -> str:
    """Mask quoted values before interpreting CR/LF as report line boundaries.

    JSON permits whitespace between a key, colon and quoted value. Quoted
    YAML/text values may also contain literal line separators. Recognize the
    complete scalar in one forward scan, without parsing or rewriting its
    surrounding document. Unquoted values following a cross-line separator
    consume their complete physical line or the next field assignment.
    """

    output = StringIO()
    cursor = position = 0
    while match := _MULTILINE_ASSIGNMENT.search(value, position):
        position = match.end()
        if not _is_sensitive_field(match.group("key")):
            continue
        quoted = _QUOTED_VALUE.match(value, position)
        if quoted:
            output.write(value[cursor:position])
            output.write(f"{value[position]}[REDACTED]{value[position]}")
            cursor = position = quoted.end()
        elif "\n" in match.group("separator") or "\r" in match.group("separator"):
            # The line pattern includes an empty match at EOF.
            line = next(_REPORT_LINES.finditer(value, position))
            end = position + len(line.group().rstrip("\r\n"))
            boundary = _NEXT_ASSIGNMENT.search(value, position, end)
            output.write(value[cursor:position])
            output.write("[REDACTED]")
            cursor = position = end if boundary is None else boundary.start()
    output.write(value[cursor:])
    return output.getvalue()


def _redact_assignments(value: str) -> str:
    """Mask complete values, retaining only recognizable assignment boundaries.

    Unquoted punctuation and spaces may belong to a password. Consume them
    through the end of the line unless another field assignment starts.
    YAML block values consume all more-indented continuation lines. Each
    line/token is traversed a bounded number of times; no recursive parsing
    or repeated scan of a shrinking line suffix is needed.
    """

    if ":" not in value and "=" not in value:
        return value
    output = StringIO()
    block_indent: int | None = None
    for line_match in _REPORT_LINES.finditer(value):
        raw_line = line_match.group()
        line = raw_line.rstrip("\r\n")
        newline = raw_line[len(line) :]
        indentation = len(line) - len(line.lstrip(" \t"))
        if block_indent is not None:
            if not line.strip() or indentation > block_indent:
                continue
            block_indent = None
        yaml_key_start = indentation
        if line.startswith(("- ", "-\t"), indentation):
            yaml_key_start += 1
            while yaml_key_start < len(line) and line[yaml_key_start] in " \t":
                yaml_key_start += 1
        cursor = 0
        while match := _ASSIGNMENT.search(line, cursor):
            if not _is_sensitive_field(match.group("key")):
                output.write(line[cursor : match.end()])
                cursor = match.end()
                continue
            start = match.end()
            output.write(line[cursor:start])
            if start == len(line):
                cursor = start
                continue
            if match.start() == yaml_key_start and _YAML_BLOCK.fullmatch(line[start:]):
                block_indent = yaml_key_start
                output.write("[REDACTED]")
                cursor = len(line)
                break
            quoted = _QUOTED_VALUE.match(line, start)
            if quoted and (
                quoted.end() == len(line)
                or line[quoted.end()].isspace()
                or line[quoted.end()] in ",;}]/>"
            ):
                quote = line[start]
                output.write(f"{quote}[REDACTED]{quote}")
                cursor = quoted.end()
                continue
            boundary = _NEXT_ASSIGNMENT.search(line, start)
            end = len(line) if boundary is None else boundary.start()
            output.write("[REDACTED]")
            cursor = end
        output.write(line[cursor:])
        output.write(newline)
    return output.getvalue()


def _replace_authorization(match: re.Match[str]) -> str:
    quote = match.group("quote")
    value = f"{quote}[REDACTED]{quote}" if quote else "[REDACTED]"
    return f"{match.group('key')}{match.group('separator')}{value}"


def _replace_other_authorization(match: re.Match[str]) -> str:
    return f"{match.group('key')}{match.group('separator')}[REDACTED]"


def _redact_xml_tag(tag: str, sensitive_element: bool = False) -> str:
    """Handle ZTE name/val fields and directly named secret attributes.

    This recognizes quoted XML start tags, not arbitrary binary exports or
    malformed XML. No XML parsing, entity expansion, or network I/O occurs.
    """

    secret_value = sensitive_element or any(
        attribute.group("name").casefold().rsplit(":", 1)[-1] in {"name", "key"}
        and _is_sensitive_field(unescape(attribute.group("value")))
        for attribute in _XML_ATTRIBUTE.finditer(tag)
    )

    def replace_attribute(attribute: re.Match[str]) -> str:
        name = attribute.group("name").casefold().rsplit(":", 1)[-1]
        if _is_sensitive_field(name) or (secret_value and name in {"val", "value"}):
            quote = attribute.group("quote")
            return f"{attribute.group('prefix')}{quote}[REDACTED]{quote}"
        return attribute.group(0)

    return _XML_ATTRIBUTE.sub(replace_attribute, tag)


def _xml_tokens(value: str) -> Iterator[tuple[int, int, str, bool, bool]]:
    """Scan each character at most once, without parsing or expanding XML.

    Yield offsets, name, closing flag, and self-closing flag. Comments, CDATA,
    and processing instructions are opaque, so apparent closing tags inside
    them cannot terminate a secret element. A missing terminator consumes the
    remainder once, rather than retrying a search from every opening tag.
    """

    position = 0
    while (start := value.find("<", position)) >= 0:
        delimiter = next(
            (
                end
                for begin, end in (("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>"))
                if value.startswith(begin, start)
            ),
            None,
        )
        if delimiter is not None:
            end = value.find(delimiter, start + 2)
            position = len(value) if end < 0 else end + len(delimiter)
            yield start, position, "", False, True
            continue
        closing = value.startswith("</", start)
        match = _XML_NAME.match(value, start + 1 + int(closing))
        if match is None:
            position = start + 1
            continue
        name = match.group().casefold()
        position = match.end()
        if position < len(value) and not (value[position].isspace() or value[position] in "/>"):
            continue
        quote = ""
        while position < len(value):
            character = value[position]
            if quote:
                if character == quote:
                    quote = ""
            elif character in "\"'":
                quote = character
            elif character in "<>":
                break
            position += 1
        complete = position < len(value) and value[position] == ">"
        self_closing = complete and value[position - 1] == "/"
        if complete:
            position += 1
        yield start, position, name, closing, self_closing


def _redact_xml(value: str) -> str:
    """Redact attributes and whole sensitive elements in one forward scan."""

    parts: list[str] = []
    cursor = 0
    active_name = ""
    depth = 0
    for start, end, name, closing, self_closing in _xml_tokens(value):
        tag = value[start:end]
        if active_name:
            if name == active_name and not self_closing:
                depth += -1 if closing else 1
                if depth == 0:
                    parts.append(tag)
                    active_name = ""
        else:
            parts.append(value[cursor:start])
            sensitive = _is_sensitive_field(name)
            if not name and _OPAQUE_SENSITIVE_CONTENT.search(tag):
                # Opaque markup cannot terminate an enclosing secret, but it
                # may itself contain credential fields. Mask it wholesale
                # rather than recursively scanning nested malformed markup.
                if tag.startswith("<!--"):
                    tag = "<!--[REDACTED]-->"
                elif tag.startswith("<![CDATA["):
                    tag = "<![CDATA[[REDACTED]]]>"
                else:
                    tag = "<?redacted?>"
            parts.append(_redact_xml_tag(tag, sensitive) if name and not closing else tag)
            if sensitive and not closing and not self_closing:
                parts.append("[REDACTED]")
                active_name, depth = name, 1
        cursor = end
    if not active_name:
        parts.append(value[cursor:])
    return "".join(parts)


def redact_text(value: str) -> str:
    """Assist manual sanitization of bounded text, never certify safe publication."""

    if len(value) > MAX_REPORT_CHARS:
        raise RedactionError("report exceeds the safety size limit")
    value = _PRIVATE_KEY_BLOCK.sub(
        lambda match: f"{match.group('begin')}\n[REDACTED]\n{match.group('end')}", value
    )
    value = _redact_xml(value)
    value = _COOKIE_HEADER.sub(_replace_secret_assignment, value)
    value = _AUTHORIZATION_HEADER.sub(_replace_secret_assignment, value)
    value = _AUTHORIZATION.sub(_replace_authorization, value)
    value = _AUTHORIZATION_OTHER.sub(_replace_other_authorization, value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _BASIC.sub("Basic [REDACTED]", value)
    value = _redact_structured_assignments(value)
    value = _redact_assignments(value)
    value = _MAC.sub("[REDACTED-MAC]", value)
    value = _SUBSCRIBER_ID.sub("[REDACTED-SUBSCRIBER-ID]", value)
    value = _IPV4.sub(_redact_public_ip, value)
    return _IPV6.sub(_redact_public_ip, value)
