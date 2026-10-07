# SPDX-License-Identifier: 0BSD
"""Bounded, read-only web evidence collection for a local ZTE router."""

from __future__ import annotations

import hashlib
import io
import json
import re
import socket
import ssl
import time
from contextlib import suppress
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException, HTTPResponse
from http.cookies import CookieError, SimpleCookie
from typing import Any, TypedDict, cast
from urllib.parse import urlencode

from .policy import parse_single_private_address, parse_timeout

MAX_RESPONSE_BYTES = 1_048_576
MAX_COOKIE_VALUE_CHARS = 4_096
# Normal firmware sessions use one SID. Allow a small auxiliary session set,
# while bounding both retained ASCII data and the complete outbound field.
MAX_COOKIE_COUNT = 16
MAX_RETAINED_COOKIE_BYTES = 8_192
MAX_COOKIE_HEADER_BYTES = 8_192
MAX_STRUCTURAL_IDENTIFIERS = 512
MAX_PAGE_ACCESS_ENTRIES = 512
MAX_JSON_NESTING = 64
MAX_TLS_CA_BYTES = 65_536
MAX_TLS_CA_CERTIFICATES = 8
_CERTIFICATE_PEM = re.compile(
    r"-----BEGIN CERTIFICATE-----\r?\n"
    r"(?:[A-Za-z0-9+/=]+\r?\n)+"
    r"-----END CERTIFICATE-----"
)

_LOGIN_RESPONSE_ROOT = "ajax_response_xml_root"
_ROUTE_TYPE = re.compile(r"_type=([A-Za-z][A-Za-z0-9_.-]{0,95})")
_ROUTE_TAG = re.compile(r"_tag=([A-Za-z][A-Za-z0-9_.-]{0,95})")
_XML_TAG = re.compile(rb"<(?!/|!|\?)(?:[A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)\b")
_PARAMETER_NAME = re.compile(
    rb"<(?:[A-Za-z_][\w.-]*:)?ParaName\b[^<>]{0,256}>\s*"
    rb"([A-Za-z_][A-Za-z0-9_.:-]{0,127})\s*"
    rb"</(?:[A-Za-z_][\w.-]*:)?ParaName\s*>",
    re.IGNORECASE,
)
_HARDWARE_VERSION_PAIR = re.compile(
    rb"<(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}:)?ParaName\b[^<>]{0,256}>[ \t\r\n]{0,64}"
    rb"(?:HardwareVersion|HardwareRevision)[ \t\r\n]{0,64}"
    rb"</(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}:)?ParaName[ \t\r\n]{0,64}>[ \t\r\n]{0,64}"
    rb"<(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}:)?ParaValue\b[^<>]{0,256}>[ \t\r\n]{0,64}"
    rb"([A-Za-z0-9_.-]{1,64})[ \t\r\n]{0,64}"
    rb"</(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}:)?ParaValue[ \t\r\n]{0,64}>",
    re.IGNORECASE,
)
_PAGE_ACCESS_ENTRY = re.compile(
    rb"_PageAccessAuthor\[\s*[\"']([A-Za-z][A-Za-z0-9_.-]{0,95})[\"']\s*\]"
    rb"\s*=\s*\{\s*[\"']VisibilityLevel[\"']\s*:\s*([0-9]{1,2})\s*,"
    rb"\s*[\"']Limitation[\"']\s*:\s*([0-9]{1,2})\s*\}",
    re.IGNORECASE,
)
_HTML_ELEMENT_ID = re.compile(
    rb"\bid\s*=\s*[\"']([A-Za-z_][A-Za-z0-9_.:-]{0,127})[\"']",
    re.IGNORECASE,
)
_HTML_FIELD_NAME = re.compile(
    rb"\bname\s*=\s*[\"']([A-Za-z_][A-Za-z0-9_.:-]{0,127})[\"']",
    re.IGNORECASE,
)
_CONFIG_OBJECT_ID = re.compile(rb"\b(OBJ_[A-Za-z0-9_:-]{1,123})\b", re.IGNORECASE)
_LUA_RESOURCE = re.compile(
    rb"\b([A-Za-z_][A-Za-z0-9_.-]{0,123}\.lua)\b",
    re.IGNORECASE,
)

# Router-controlled identifiers can contain subscriber-specific labels or other
# private values. Only these reviewed, public firmware identifiers may be
# emitted verbatim. Matching is case-insensitive, but output is canonicalized so
# unusual casing cannot be used as an identifier side channel. Unrecognized
# values are represented only by aggregate counts in endpoint evidence.
_SAFE_STRUCTURAL_IDENTIFIERS: dict[str, dict[str, str]] = {
    "html_element_ids": {
        "obj_tr069_id.enablecwmp": "OBJ_TR069_ID.EnableCWMP",
    },
    "html_field_names": {
        "enablecwmp": "EnableCWMP",
    },
    "config_object_ids": {
        "obj_devinfo_id": "OBJ_DEVINFO_ID",
        "obj_tr069_id": "OBJ_TR069_ID",
    },
    "lua_resource_names": {
        "devmgr_statusmgr_lua.lua": "devmgr_statusmgr_lua.lua",
        "tr069_lua.lua": "tr069_lua.lua",
    },
}
_SAFE_COOKIE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SAFE_COOKIE_VALUE = re.compile(r"[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]{0,4096}\Z")
_TOKEN_BODY = re.compile(
    rb"\A\s*(?:<\?xml[^>]*>\s*)?<ajax_response_xml_root\b[^>]*>\s*"
    rb"([A-Za-z0-9+/=_-]{1,128})\s*</ajax_response_xml_root>\s*\Z",
    re.IGNORECASE,
)

_ROOT_RESEARCH_MARKERS: dict[str, tuple[bytes, ...]] = {
    "cwmp": (b"cwmp",),
    "tr069": (b"tr069", b"tr-069"),
    "internet_gateway_device": (b"internetgatewaydevice",),
    "turk_telekom_vendor_parameters": (b"x_tt", b"x-tt"),
    "shell": (b"shell",),
    "ssh": (b"ssh",),
    "telnet": (b"telnet",),
    "root_literal": (b"root",),
    "configuration_export": (b"configdownload", b"configexport", b"backupconfig"),
}
_ROOT_LITERAL = re.compile(rb"(?<![a-z0-9_])root(?![a-z0-9_])")

_READ_ONLY_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("authenticated_root", "/"),
    ("status_view", "/?_type=menuView&_tag=statusMgr&Menu3Location=0"),
    ("status_data", "/?_type=menuData&_tag=devmgr_statusmgr_lua.lua"),
)

# These are server-advertised page views from the exact TTN.10 login shell.
# They are requested only when the authenticated root advertises the same ID.
# A page-view GET renders controls; it does not submit their forms or invoke a
# menuData/configuration endpoint.
_ROOT_RESEARCH_PAGE_IDS: tuple[str, ...] = (
    "tr069",
    "rsc",
    "usrCfgMgr",
    "mirror",
    "capture",
)

# These destination-category values are public protocol/firmware vocabulary.
# They remain useful evidence even when an unrelated short private identifier
# would otherwise match them as a substring during cross-field redaction.
_SAFE_EMITTED_IDENTIFIER_VALUES: dict[str, dict[str, str]] = {
    "route_types": {
        "logindata": "loginData",
        "menuview": "menuView",
        "menudata": "menuData",
    },
    "route_tags": {
        "statusmgr": "statusMgr",
        "devmgr_statusmgr_lua.lua": "devmgr_statusmgr_lua.lua",
        **{page_id.casefold(): page_id for page_id in _ROOT_RESEARCH_PAGE_IDS},
    },
    "xml_element_names": {
        "root": "root",
        "html": "html",
        "a": "a",
        "script": "script",
        "input": "input",
        "address": "address",
        "ajax_response_xml_root": "ajax_response_xml_root",
        "obj_devinfo_id": "OBJ_DEVINFO_ID",
        "instance": "Instance",
        "paraname": "ParaName",
        "paravalue": "ParaValue",
    },
    "parameter_names": {
        "softwareversion": "SoftwareVersion",
        "managementserver.enablecwmp": "ManagementServer.EnableCWMP",
        "servicecontrol": "ServiceControl",
    },
    "page_ids": {
        "homepage": "homePage",
        **{page_id.casefold(): page_id for page_id in _ROOT_RESEARCH_PAGE_IDS},
    },
}


class WebEvidenceError(ValueError):
    """Raised when bounded local web evidence collection cannot continue safely."""


def _make_tls_context(tls_ca_pem: str | None) -> ssl.SSLContext:
    """Build verified trust without honoring TLS session-key logging settings."""

    if tls_ca_pem is not None:
        if (
            not isinstance(tls_ca_pem, str)
            or not tls_ca_pem.isascii()
            or not 0 < len(tls_ca_pem) <= MAX_TLS_CA_BYTES
        ):
            raise WebEvidenceError("TLS CA input must be bounded ASCII certificate-only PEM")
        certificates = list(_CERTIFICATE_PEM.finditer(tls_ca_pem))
        if (
            not 1 <= len(certificates) <= MAX_TLS_CA_CERTIFICATES
            or _CERTIFICATE_PEM.sub("", tls_ca_pem).strip()
        ):
            raise WebEvidenceError("TLS CA input must contain only one to eight PEM certificates")
    try:
        # create_default_context can enable SSLKEYLOGFILE as a side effect.
        # Configure the secure client context directly: never write TLS keys or
        # disable certificate/IP verification, including for caller-supplied CA.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        if tls_ca_pem is None:
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        else:
            context.load_verify_locations(cadata=tls_ca_pem)
    except (OSError, ValueError) as exc:
        raise WebEvidenceError("unable to load verified TLS certificate trust") from exc
    return context


def _prepare_web_transport(
    transport: str,
    acknowledge_local_http_authentication: bool,
    tls_ca_pem: str | None,
) -> ssl.SSLContext | None:
    if transport not in ("https", "http"):
        raise WebEvidenceError("web transport must be https or http")
    if not isinstance(acknowledge_local_http_authentication, bool):
        raise WebEvidenceError("HTTP authentication acknowledgement must be a boolean")
    if transport == "http":
        if tls_ca_pem is not None:
            raise WebEvidenceError("TLS CA input cannot be used with HTTP transport")
        if acknowledge_local_http_authentication is not True:
            raise WebEvidenceError("local HTTP authentication requires explicit acknowledgement")
        return None
    if acknowledge_local_http_authentication:
        raise WebEvidenceError("HTTP authentication acknowledgement requires HTTP transport")
    return _make_tls_context(tls_ca_pem)


def validate_web_evidence_transport(
    transport: str,
    *,
    acknowledge_local_http_authentication: bool = False,
    tls_ca_pem: str | None = None,
) -> None:
    """Validate transport and trust before requesting secrets or opening sockets."""

    _prepare_web_transport(transport, acknowledge_local_http_authentication, tls_ca_pem)


@dataclass(frozen=True)
class _Response:
    status: int
    content_type: str
    body: bytes


class _PageAccessEvidence(TypedDict):
    page_id: str
    visibility_level: int
    limitation: int


class _UniqueStructuralIdentifierRedactions(TypedDict):
    route_types: int
    route_tags: int
    xml_element_names: int
    parameter_names: int
    page_ids: int
    html_element_ids: int
    html_field_names: int
    config_object_ids: int
    lua_resource_names: int


class _EndpointEvidence(TypedDict):
    http_status: int
    response_bytes: int
    response_kind: str
    route_types: list[str]
    route_tags: list[str]
    xml_element_names: list[str]
    parameter_names: list[str]
    page_access_entries: list[_PageAccessEvidence]
    login_page_detected: bool
    html_element_ids: list[str]
    html_field_names: list[str]
    config_object_ids: list[str]
    lua_resource_names: list[str]
    redacted_unique_structural_identifier_counts: _UniqueStructuralIdentifierRedactions
    structural_identifier_limit_reached: bool
    root_research_string_markers: dict[str, bool]
    expected_identity_markers: dict[str, bool]


def _remaining_request_time(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("local HTTP request deadline expired")
    return remaining


class _DeadlineRawReader(io.RawIOBase):
    """Apply one absolute deadline to every socket read, including HTTP headers."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._socket = sock
        # A socket file retains its own reference when HTTPConnection closes a
        # Connection: close socket before HTTPResponse has read the body.
        self._file = sock.makefile("rb", buffering=0)
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: object) -> int:
        self._socket.settimeout(_remaining_request_time(self._deadline))
        result = self._file.readinto(cast(memoryview, buffer))
        return 0 if result is None else result

    def close(self) -> None:
        self._file.close()
        super().close()


class _DeadlineSocket:
    """Supply deadline-aware send and file operations to HTTPConnection."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._socket = sock
        self._deadline = deadline

    def sendall(self, data: bytes) -> None:
        self._socket.settimeout(_remaining_request_time(self._deadline))
        self._socket.sendall(data)

    def makefile(self, mode: str) -> io.BufferedReader:
        if mode != "rb":
            raise ValueError("unsupported local HTTP response mode")
        return io.BufferedReader(_DeadlineRawReader(self._socket, self._deadline))

    def close(self) -> None:
        self._socket.close()


def _read_bounded(response: HTTPResponse) -> bytes:
    raw_length = response.getheader("Content-Length")
    expected_length = None
    # HTTPResponse resolves framing before this call: chunked transfer coding
    # overrides Content-Length, while bodyless responses have an effective
    # length of zero. Save that effective length before read() consumes it.
    if raw_length is not None and not response.chunked:
        try:
            declared_length = int(raw_length)
        except ValueError as exc:
            raise WebEvidenceError("router returned an invalid Content-Length header") from exc
        if declared_length < 0 or declared_length > MAX_RESPONSE_BYTES:
            raise WebEvidenceError("router response exceeds the 1 MiB evidence limit")
        expected_length = response.length
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise WebEvidenceError("router response exceeds the 1 MiB evidence limit")
    if expected_length is not None and len(body) != expected_length:
        raise WebEvidenceError("router response ended before its declared Content-Length")
    return body


def _safe_cookie_pair(name: object, value: object) -> bool:
    return (
        isinstance(name, str)
        and isinstance(value, str)
        and _SAFE_COOKIE_NAME.fullmatch(name) is not None
        and len(value) <= MAX_COOKIE_VALUE_CHARS
        and _SAFE_COOKIE_VALUE.fullmatch(value) is not None
    )


def _cookie_header(cookies: dict[str, str]) -> str:
    """Validate the complete jar before constructing a bounded ASCII header."""

    if len(cookies) > MAX_COOKIE_COUNT:
        raise WebEvidenceError("router session exceeds the 16-cookie limit")
    retained_bytes = 0
    header_bytes = 0
    fields: list[str] = []
    for name, value in cookies.items():
        if not _safe_cookie_pair(name, value):
            raise WebEvidenceError("router session contains an unsafe cookie")
        # The accepted grammar is ASCII, so character counts are byte counts.
        pair_bytes = len(name) + len(value)
        retained_bytes += pair_bytes
        if retained_bytes > MAX_RETAINED_COOKIE_BYTES:
            raise WebEvidenceError("router session exceeds the 8 KiB retained-cookie limit")
        header_bytes += pair_bytes + 1 + (2 if fields else 0)
        if header_bytes > MAX_COOKIE_HEADER_BYTES:
            raise WebEvidenceError("router session exceeds the 8 KiB Cookie-header limit")
        fields.append(f"{name}={value}")
    return "; ".join(fields)


def _remember_cookies(response: HTTPResponse, cookies: dict[str, str]) -> None:
    # Internal callers must supply a valid bounded jar too. Work on a copy so
    # a later response cookie cannot leave earlier replacements committed.
    _cookie_header(cookies)
    candidate = cookies.copy()
    for raw_cookie in response.msg.get_all("Set-Cookie", []):
        parsed = SimpleCookie()
        try:
            parsed.load(raw_cookie)
        except CookieError:
            continue
        for name, morsel in parsed.items():
            value = morsel.value
            if _safe_cookie_pair(name, value):
                candidate[name] = value
                _cookie_header(candidate)
    cookies.clear()
    cookies.update(candidate)


def _request(
    host: str,
    method: str,
    path: str,
    timeout: float,
    cookies: dict[str, str],
    data: bytes | None = None,
    *,
    transport: str = "https",
    tls_context: ssl.SSLContext | None = None,
) -> _Response:
    if transport not in ("https", "http"):
        raise WebEvidenceError("web transport must be https or http")
    if transport == "https":
        tls_context = tls_context if tls_context is not None else _make_tls_context(None)
        if (
            tls_context.verify_mode != ssl.CERT_REQUIRED
            or not tls_context.check_hostname
            or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
            or tls_context.keylog_filename
        ):
            raise WebEvidenceError(
                "TLS requires certificate and IP verification without key logging"
            )
    elif tls_context is not None:
        raise WebEvidenceError("TLS context cannot be used with HTTP transport")
    headers = {
        "Accept": "application/json, text/xml, text/html;q=0.9, */*;q=0.1",
        "Connection": "close",
        "User-Agent": "cpe-access-atlas/read-only-web-evidence",
    }
    cookie_header = _cookie_header(cookies)
    if cookie_header:
        headers["Cookie"] = cookie_header
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(data))

    deadline = time.monotonic() + timeout
    connection = HTTPConnection(host, 443 if transport == "https" else 80, timeout=timeout)
    response: HTTPResponse | None = None
    raw_socket: socket.socket | None = None
    try:
        connection.timeout = _remaining_request_time(deadline)
        connection.connect()
        raw_socket = connection.sock
        if raw_socket is None:
            raise HTTPException("local HTTP connection has no socket")
        if tls_context is not None:
            # TCP and TLS consume one request budget. No HTTP request, cookie,
            # username or challenge response is sent before peer verification.
            raw_socket.settimeout(_remaining_request_time(deadline))
            raw_socket = tls_context.wrap_socket(
                raw_socket, server_hostname=host, do_handshake_on_connect=False
            )
            connection.sock = raw_socket
            raw_socket.settimeout(_remaining_request_time(deadline))
            raw_socket.do_handshake()
        connection.sock = cast(socket.socket, _DeadlineSocket(raw_socket, deadline))
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        body = _read_bounded(response)
        content_type = response.getheader("Content-Type", "")
        result = _Response(status=response.status, content_type=content_type, body=body)
        _remember_cookies(response, cookies)
        return result
    except ssl.SSLCertVerificationError as exc:
        raise WebEvidenceError(
            "TLS peer certificate or IP verification failed; no HTTP fallback was attempted"
        ) from exc
    except (HTTPException, OSError, TimeoutError):
        # Protocol errors can include raw response bytes (for example, a
        # BadStatusLine containing a private page). Keep normal library
        # tracebacks inside the same sanitized boundary as CLI diagnostics.
        raise WebEvidenceError(
            f"unable to complete the bounded local {transport.upper()} request"
        ) from None
    finally:
        if response is not None:
            with suppress(OSError):
                response.close()
        with suppress(OSError):
            connection.close()
        # HTTPConnection can drop its socket reference as soon as it sees
        # Connection: close. Keep the original handle until response cleanup.
        if raw_socket is not None:
            with suppress(OSError):
                raw_socket.close()


def _require_ok(response: _Response, label: str) -> None:
    if response.status != 200:
        raise WebEvidenceError(f"{label} returned HTTP {response.status}; no retry was attempted")


def _reject_authentication_loss(response: _Response) -> None:
    if response.status == 401:
        raise WebEvidenceError(
            "router rejected the authenticated session with HTTP 401; "
            "no further page requests were attempted"
        )
    if _looks_like_login_page(response.body):
        raise WebEvidenceError(
            "router returned the login page after accepting the login response; "
            "no further page requests were attempted"
        )


def _json_object(response: _Response, label: str) -> dict[str, Any]:
    _require_ok(response, label)
    try:
        document = response.body.decode("utf-8")
    except UnicodeDecodeError:
        raise WebEvidenceError(f"{label} did not return valid UTF-8 JSON") from None

    _require_bounded_json_nesting(document, label)
    try:
        value = json.loads(document)
    except RecursionError:
        # Defensive fallback in case the decoder's recursion behavior changes or
        # a non-container input triggers recursion below the explicit depth cap.
        raise WebEvidenceError(
            f"{label} JSON exceeds the {MAX_JSON_NESTING}-level nesting limit"
        ) from None
    except json.JSONDecodeError:
        raise WebEvidenceError(f"{label} did not return valid UTF-8 JSON") from None
    except ValueError:
        # CPython raises a plain ValueError, for example, when a JSON integer
        # exceeds its configured digit limit. Keep all decoder limits inside
        # the same sanitized protocol-error boundary.
        raise WebEvidenceError(f"{label} JSON could not be decoded within safety limits") from None
    if not isinstance(value, dict):
        raise WebEvidenceError(f"{label} did not return a JSON object")
    return value


def _require_bounded_json_nesting(document: str, label: str) -> None:
    """Reject JSON containers nested beyond the parser safety boundary.

    The scan understands JSON string quoting and escaping. Syntax validation is
    intentionally left to ``json.loads``; this pass exists only to establish a
    hard nesting bound before invoking the recursive decoder.
    """

    depth = 0
    in_string = False
    escaped = False
    for character in document:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise WebEvidenceError(
                    f"{label} JSON exceeds the {MAX_JSON_NESTING}-level nesting limit"
                )
        elif character in "]}":
            # Mismatched closing delimiters are handled by the JSON decoder.
            depth = max(0, depth - 1)


def _required_string(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise WebEvidenceError(f"{label} is missing or outside its safety limit")
    return value


def _login_token(response: _Response) -> str:
    _require_ok(response, "login-token request")
    match = _TOKEN_BODY.fullmatch(response.body)
    if match is None:
        raise WebEvidenceError(
            f"login-token response was not the expected {_LOGIN_RESPONSE_ROOT} document"
        )
    return match.group(1).decode("ascii")


def _login_succeeded(value: object) -> bool:
    if value is True or value == 1:
        return True
    return isinstance(value, str) and value.lower() in {"1", "true", "yes"}


def _zte_login_compatibility_digest(password: str, challenge: str) -> str:
    """Return the exact challenge response required by the router firmware.

    This is a vendor-defined interoperability transform for a single local
    login request, not password storage. A password KDF would produce a value
    the device cannot authenticate.
    """

    # This exact vendor challenge response remains a security-sensitive accepted
    # risk: a captured exchange can enable offline guesses of weak passwords.
    # Keep the CodeQL finding visible. Review and compensating controls are tracked
    # in .github/codeql-accepted-risks.json, with protocol evidence in
    # docs/research/zte-h3600p-ttn10-260210.md.
    return hashlib.sha256((password + challenge).encode("utf-8")).hexdigest()


def _response_kind(response: _Response) -> str:
    media_type = response.content_type.partition(";")[0].strip().lower()
    if "json" in media_type:
        return "json"
    if "xml" in media_type:
        return "xml"
    if "html" in media_type:
        return "html"
    stripped = response.body.lstrip()
    if stripped.startswith((b"{", b"[")):
        return "json"
    if stripped.startswith(b"<"):
        return "xml-or-html"
    return "other"


def _sorted_ascii_matches(pattern: re.Pattern[bytes], body: bytes) -> list[str]:
    return sorted({match.group(1).decode("ascii") for match in pattern.finditer(body)})


def _route_values(pattern: re.Pattern[str], body: bytes) -> list[str]:
    text = body.decode("utf-8", errors="ignore")
    return sorted({match.group(1) for match in pattern.finditer(text)})


def _allowlisted_ascii_matches(
    category: str,
    pattern: re.Pattern[bytes],
    body: bytes,
) -> tuple[list[str], set[str], bool]:
    """Return reviewed identifiers and keep unreviewed values internal."""

    values = sorted({match.group(1).decode("ascii").casefold() for match in pattern.finditer(body)})
    allowlist = _SAFE_STRUCTURAL_IDENTIFIERS[category]
    allowed = sorted({allowlist[value] for value in values if value in allowlist})
    redacted = {value for value in values if value not in allowlist}
    return allowed, redacted, len(values) > MAX_STRUCTURAL_IDENTIFIERS


def _allowlisted_identifier_values(
    category: str,
    values: list[str],
) -> tuple[list[str], set[str], bool]:
    """Canonicalize reviewed values and expose unknowns only as aggregates."""

    normalized = {value.casefold() for value in values}
    allowlist = _SAFE_EMITTED_IDENTIFIER_VALUES[category]
    allowed = sorted({allowlist[value] for value in normalized if value in allowlist})
    redacted = normalized.difference(allowlist)
    return allowed, redacted, len(normalized) > MAX_STRUCTURAL_IDENTIFIERS


def _marker_presence(body: bytes) -> dict[str, bool]:
    lowered = body.lower()
    markers = {
        label: any(marker in lowered for marker in markers)
        for label, markers in _ROOT_RESEARCH_MARKERS.items()
    }
    # The normal ajax_response_xml_root wrapper and Buildroot/rootfs strings
    # do not establish the presence of a standalone root token.
    markers["root_literal"] = _ROOT_LITERAL.search(lowered) is not None
    return markers


def _page_access_entries(body: bytes) -> list[_PageAccessEvidence]:
    entries = {
        (match.group(1).decode("ascii"), int(match.group(2)), int(match.group(3)))
        for match in _PAGE_ACCESS_ENTRY.finditer(body)
    }
    return [
        {
            "page_id": page_id,
            "visibility_level": visibility_level,
            "limitation": limitation,
        }
        for page_id, visibility_level, limitation in sorted(entries)
    ]


def _looks_like_login_page(body: bytes) -> bool:
    lowered = body.lower()
    return b"frm_username" in lowered and b"login_entry" in lowered


def _hardware_revision_marker_present(body: bytes, expected_hardware: str) -> bool:
    """Require an exact value in an explicitly labeled hardware XML field.

    The router's status data uses adjacent ParaName/ParaValue elements. Free
    text, a SoftwareVersion value, or a partial version is not hardware evidence.
    This remains a text observation, not physical-revision verification.
    """

    expected = expected_hardware.encode("utf-8")
    return any(match.group(1) == expected for match in _HARDWARE_VERSION_PAIR.finditer(body))


def _endpoint_evidence(
    response: _Response,
    *,
    expected_firmware: str,
    expected_model: str,
    expected_hardware: str,
) -> _EndpointEvidence:
    html_element_ids, redacted_element_ids, element_ids_limited = _allowlisted_ascii_matches(
        "html_element_ids", _HTML_ELEMENT_ID, response.body
    )
    html_field_names, redacted_field_names, field_names_limited = _allowlisted_ascii_matches(
        "html_field_names", _HTML_FIELD_NAME, response.body
    )
    config_object_ids, redacted_object_ids, object_ids_limited = _allowlisted_ascii_matches(
        "config_object_ids", _CONFIG_OBJECT_ID, response.body
    )
    lua_resource_names, redacted_lua_names, lua_names_limited = _allowlisted_ascii_matches(
        "lua_resource_names", _LUA_RESOURCE, response.body
    )
    route_types, redacted_route_types, route_types_limited = _allowlisted_identifier_values(
        "route_types", _route_values(_ROUTE_TYPE, response.body)
    )
    route_tags, redacted_route_tags, route_tags_limited = _allowlisted_identifier_values(
        "route_tags", _route_values(_ROUTE_TAG, response.body)
    )
    xml_element_names, redacted_xml_names, xml_names_limited = _allowlisted_identifier_values(
        "xml_element_names", _sorted_ascii_matches(_XML_TAG, response.body)
    )
    parameter_names, redacted_parameter_names, parameter_names_limited = (
        _allowlisted_identifier_values(
            "parameter_names", _sorted_ascii_matches(_PARAMETER_NAME, response.body)
        )
    )
    raw_page_access_entries = _page_access_entries(response.body)
    _, redacted_page_ids, page_ids_limited = _allowlisted_identifier_values(
        "page_ids", [entry["page_id"] for entry in raw_page_access_entries]
    )

    redacted_identifiers = set().union(
        redacted_route_types,
        redacted_route_tags,
        redacted_xml_names,
        redacted_parameter_names,
        redacted_page_ids,
        redacted_element_ids,
        redacted_field_names,
        redacted_object_ids,
        redacted_lua_names,
    )
    aggregate_limit_reached = len(redacted_identifiers) > MAX_STRUCTURAL_IDENTIFIERS
    page_access_values: set[tuple[str, int, int]] = set()
    for entry in raw_page_access_entries:
        page_id = _SAFE_EMITTED_IDENTIFIER_VALUES["page_ids"].get(entry["page_id"].casefold())
        if page_id is not None:
            page_access_values.add((page_id, entry["visibility_level"], entry["limitation"]))
            if len(page_access_values) > MAX_PAGE_ACCESS_ENTRIES:
                raise WebEvidenceError("router page-access evidence exceeds the 512-entry limit")
    page_access_entries: list[_PageAccessEvidence] = [
        {
            "page_id": page_id,
            "visibility_level": visibility_level,
            "limitation": limitation,
        }
        for page_id, visibility_level, limitation in sorted(page_access_values)
    ]
    return {
        "http_status": response.status,
        "response_bytes": len(response.body),
        "response_kind": _response_kind(response),
        "route_types": route_types,
        "route_tags": route_tags,
        "xml_element_names": xml_element_names,
        "parameter_names": parameter_names,
        "page_access_entries": page_access_entries,
        "login_page_detected": _looks_like_login_page(response.body),
        "html_element_ids": html_element_ids,
        "html_field_names": html_field_names,
        "config_object_ids": config_object_ids,
        "lua_resource_names": lua_resource_names,
        "redacted_unique_structural_identifier_counts": {
            "route_types": len(redacted_route_types),
            "route_tags": len(redacted_route_tags),
            "xml_element_names": len(redacted_xml_names),
            "parameter_names": len(redacted_parameter_names),
            "page_ids": len(redacted_page_ids),
            "html_element_ids": len(redacted_element_ids),
            "html_field_names": len(redacted_field_names),
            "config_object_ids": len(redacted_object_ids),
            "lua_resource_names": len(redacted_lua_names),
        },
        "structural_identifier_limit_reached": any(
            (
                element_ids_limited,
                field_names_limited,
                object_ids_limited,
                lua_names_limited,
                route_types_limited,
                route_tags_limited,
                xml_names_limited,
                parameter_names_limited,
                page_ids_limited,
                aggregate_limit_reached,
            )
        ),
        "root_research_string_markers": _marker_presence(response.body),
        "expected_identity_markers": {
            "firmware": expected_firmware.encode("utf-8") in response.body,
            "model": expected_model.encode("utf-8") in response.body,
            "hardware_revision": _hardware_revision_marker_present(
                response.body, expected_hardware
            ),
        },
    }


def collect_zte_web_evidence(
    host: str,
    username: str,
    password: str,
    *,
    timeout: float,
    expected_firmware: str,
    expected_model: str,
    expected_hardware: str,
    transport: str = "https",
    acknowledge_local_http_authentication: bool = False,
    tls_ca_pem: str | None = None,
) -> dict[str, object]:
    """Authenticate once and collect sanitized GET-only status-page evidence.

    The sole POST is the normal web-console login operation. No configuration,
    CWMP, shell, reboot, reset, upload, or firmware endpoint is requested.
    HTTPS verifies the certificate and target IP. Legacy HTTP requires both
    explicit transport selection and acknowledgement; there is no downgrade.
    """

    address = parse_single_private_address(host)
    bounded_timeout = parse_timeout(timeout)
    if not username or len(username) > 128 or any(character in "\r\n" for character in username):
        raise WebEvidenceError("web username is empty or outside its safety limit")
    if not password or len(password) > 256:
        raise WebEvidenceError("web password is empty or outside its safety limit")
    for label, value in (
        ("expected firmware", expected_firmware),
        ("expected model", expected_model),
        ("expected hardware revision", expected_hardware),
    ):
        _required_string(value, label, 256)

    tls_context = _prepare_web_transport(
        transport, acknowledge_local_http_authentication, tls_ca_pem
    )
    cookies: dict[str, str] = {}
    target = str(address)
    entry = _json_object(
        _request(
            target,
            "GET",
            "/?_type=loginData&_tag=login_entry",
            bounded_timeout,
            cookies,
            transport=transport,
            tls_context=tls_context,
        ),
        "login-entry request",
    )
    locking_time = entry.get("lockingTime", 1)
    if not (
        (isinstance(locking_time, int) and not isinstance(locking_time, bool) and locking_time == 0)
        or locking_time == "0"
    ):
        raise WebEvidenceError(
            "router reports that login is locked or unavailable; no password was sent"
        )
    session_token = _required_string(entry.get("sess_token"), "login session token", 256)
    challenge = _login_token(
        _request(
            target,
            "GET",
            "/?_type=loginData&_tag=login_token",
            bounded_timeout,
            cookies,
            transport=transport,
            tls_context=tls_context,
        )
    )
    password_digest = _zte_login_compatibility_digest(password, challenge)
    login_body = urlencode(
        {
            "Password": password_digest,
            "Username": username,
            "_sessionTOKEN": session_token,
            "action": "login",
        }
    ).encode("ascii")
    login = _json_object(
        _request(
            target,
            "POST",
            "/?_type=loginData&_tag=login_entry",
            bounded_timeout,
            cookies,
            login_body,
            transport=transport,
            tls_context=tls_context,
        ),
        "web login",
    )
    if not _login_succeeded(login.get("login_need_refresh")):
        raise WebEvidenceError(
            "web login was not accepted; check the local credentials or lock state "
            "before making another attempt"
        )

    endpoints: dict[str, _EndpointEvidence] = {}
    identity_markers = {
        "firmware": False,
        "model": False,
        "hardware_revision": False,
    }
    root_markers = dict.fromkeys(_ROOT_RESEARCH_MARKERS, False)
    for name, path in _READ_ONLY_ENDPOINTS:
        response = _request(
            target,
            "GET",
            path,
            bounded_timeout,
            cookies,
            transport=transport,
            tls_context=tls_context,
        )
        _reject_authentication_loss(response)
        endpoint = _endpoint_evidence(
            response,
            expected_firmware=expected_firmware,
            expected_model=expected_model,
            expected_hardware=expected_hardware,
        )
        endpoints[name] = endpoint
        for key in identity_markers:
            identity_markers[key] = (
                identity_markers[key] or endpoint["expected_identity_markers"][key]
            )
        for key in root_markers:
            root_markers[key] = root_markers[key] or endpoint["root_research_string_markers"][key]

    authenticated_root = endpoints["authenticated_root"]
    advertised_access = authenticated_root["page_access_entries"]
    advertised_ids = {entry["page_id"] for entry in advertised_access}
    requested_page_ids: list[str] = []
    for page_id in _ROOT_RESEARCH_PAGE_IDS:
        if page_id not in advertised_ids:
            continue
        response = _request(
            target,
            "GET",
            f"/?_type=menuView&_tag={page_id}&Menu3Location=0",
            bounded_timeout,
            cookies,
            transport=transport,
            tls_context=tls_context,
        )
        _reject_authentication_loss(response)
        endpoint = _endpoint_evidence(
            response,
            expected_firmware=expected_firmware,
            expected_model=expected_model,
            expected_hardware=expected_hardware,
        )
        endpoints[f"page_view_{page_id}"] = endpoint
        requested_page_ids.append(page_id)
        for key in identity_markers:
            identity_markers[key] = (
                identity_markers[key] or endpoint["expected_identity_markers"][key]
            )
        for key in root_markers:
            root_markers[key] = root_markers[key] or endpoint["root_research_string_markers"][key]

    privileged_page_ids = sorted(
        {entry["page_id"] for entry in advertised_access if entry["visibility_level"] >= 3}
    )
    return {
        "transport": f"local-{transport}",
        "tls_peer_verified": transport == "https",
        "tls_trust_source": (
            "not-applicable"
            if transport == "http"
            else "provided-ca"
            if tls_ca_pem is not None
            else "system"
        ),
        "host": target,
        "authenticated": True,
        "login_attempts": 1,
        "endpoints": endpoints,
        "advertised_page_access": advertised_access,
        "advertised_privileged_page_ids": privileged_page_ids,
        "read_only_page_views_requested": requested_page_ids,
        "observed_expected_identity_markers": identity_markers,
        "observed_root_research_string_markers": root_markers,
        "configuration_mutation_attempted": False,
        "cwmp_request_sent": False,
        "credentials_cookies_or_parameter_values_output": False,
        "raw_response_saved": False,
    }
