# SPDX-License-Identifier: 0BSD
"""Bounded, read-only web evidence collection for a local ZTE router."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException, HTTPResponse
from http.cookies import CookieError, SimpleCookie
from typing import Any, TypedDict
from urllib.parse import urlencode

from .policy import parse_single_private_address, parse_timeout

MAX_RESPONSE_BYTES = 1_048_576
MAX_COOKIE_VALUE_CHARS = 4_096
MAX_STRUCTURAL_IDENTIFIERS = 512

_LOGIN_RESPONSE_ROOT = "ajax_response_xml_root"
_ROUTE_TYPE = re.compile(r"_type=([A-Za-z][A-Za-z0-9_.-]{0,95})")
_ROUTE_TAG = re.compile(r"_tag=([A-Za-z][A-Za-z0-9_.-]{0,95})")
_XML_TAG = re.compile(rb"<(?!/|!|\?)(?:[A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)\b")
_PARAMETER_NAME = re.compile(
    rb"<(?:[A-Za-z_][\w.-]*:)?ParaName\b[^>]*>\s*"
    rb"([A-Za-z_][A-Za-z0-9_.:-]{0,127})\s*"
    rb"</(?:[A-Za-z_][\w.-]*:)?ParaName\s*>",
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


class WebEvidenceError(ValueError):
    """Raised when bounded local web evidence collection cannot continue safely."""


@dataclass(frozen=True)
class _Response:
    status: int
    content_type: str
    body: bytes


class _PageAccessEvidence(TypedDict):
    page_id: str
    visibility_level: int
    limitation: int


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
    structural_identifier_limit_reached: bool
    root_research_string_markers: dict[str, bool]
    expected_identity_markers: dict[str, bool]


def _read_bounded(response: HTTPResponse) -> bytes:
    raw_length = response.getheader("Content-Length")
    if raw_length is not None:
        try:
            declared_length = int(raw_length)
        except ValueError as exc:
            raise WebEvidenceError("router returned an invalid Content-Length header") from exc
        if declared_length < 0 or declared_length > MAX_RESPONSE_BYTES:
            raise WebEvidenceError("router response exceeds the 1 MiB evidence limit")
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise WebEvidenceError("router response exceeds the 1 MiB evidence limit")
    return body


def _remember_cookies(response: HTTPResponse, cookies: dict[str, str]) -> None:
    for raw_cookie in response.msg.get_all("Set-Cookie", []):
        parsed = SimpleCookie()
        try:
            parsed.load(raw_cookie)
        except CookieError:
            continue
        for name, morsel in parsed.items():
            value = morsel.value
            if (
                _SAFE_COOKIE_NAME.fullmatch(name)
                and len(value) <= MAX_COOKIE_VALUE_CHARS
                and _SAFE_COOKIE_VALUE.fullmatch(value)
            ):
                cookies[name] = value


def _request(
    host: str,
    method: str,
    path: str,
    timeout: float,
    cookies: dict[str, str],
    data: bytes | None = None,
) -> _Response:
    headers = {
        "Accept": "application/json, text/xml, text/html;q=0.9, */*;q=0.1",
        "Connection": "close",
        "User-Agent": "cpe-access-atlas/read-only-web-evidence",
    }
    if cookies:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(data))

    connection = HTTPConnection(host, 80, timeout=timeout)
    try:
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        body = _read_bounded(response)
        _remember_cookies(response, cookies)
        content_type = response.getheader("Content-Type", "")
        return _Response(status=response.status, content_type=content_type, body=body)
    except (HTTPException, OSError, TimeoutError) as exc:
        raise WebEvidenceError("unable to complete the bounded local HTTP request") from exc
    finally:
        connection.close()


def _require_ok(response: _Response, label: str) -> None:
    if response.status != 200:
        raise WebEvidenceError(f"{label} returned HTTP {response.status}; no retry was attempted")


def _json_object(response: _Response, label: str) -> dict[str, Any]:
    _require_ok(response, label)
    try:
        value = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebEvidenceError(f"{label} did not return valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise WebEvidenceError(f"{label} did not return a JSON object")
    return value


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


def _bounded_ascii_matches(pattern: re.Pattern[bytes], body: bytes) -> tuple[list[str], bool]:
    values = sorted({match.group(1).decode("ascii") for match in pattern.finditer(body)})
    return values[:MAX_STRUCTURAL_IDENTIFIERS], len(values) > MAX_STRUCTURAL_IDENTIFIERS


def _marker_presence(body: bytes) -> dict[str, bool]:
    lowered = body.lower()
    return {
        label: any(marker in lowered for marker in markers)
        for label, markers in _ROOT_RESEARCH_MARKERS.items()
    }


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


def _endpoint_evidence(
    response: _Response,
    *,
    expected_firmware: str,
    expected_model: str,
    expected_hardware: str,
) -> _EndpointEvidence:
    html_element_ids, element_ids_limited = _bounded_ascii_matches(_HTML_ELEMENT_ID, response.body)
    html_field_names, field_names_limited = _bounded_ascii_matches(_HTML_FIELD_NAME, response.body)
    config_object_ids, object_ids_limited = _bounded_ascii_matches(_CONFIG_OBJECT_ID, response.body)
    lua_resource_names, lua_names_limited = _bounded_ascii_matches(_LUA_RESOURCE, response.body)
    return {
        "http_status": response.status,
        "response_bytes": len(response.body),
        "response_kind": _response_kind(response),
        "route_types": _route_values(_ROUTE_TYPE, response.body),
        "route_tags": _route_values(_ROUTE_TAG, response.body),
        "xml_element_names": _sorted_ascii_matches(_XML_TAG, response.body),
        "parameter_names": _sorted_ascii_matches(_PARAMETER_NAME, response.body),
        "page_access_entries": _page_access_entries(response.body),
        "login_page_detected": _looks_like_login_page(response.body),
        "html_element_ids": html_element_ids,
        "html_field_names": html_field_names,
        "config_object_ids": config_object_ids,
        "lua_resource_names": lua_resource_names,
        "structural_identifier_limit_reached": any(
            (
                element_ids_limited,
                field_names_limited,
                object_ids_limited,
                lua_names_limited,
            )
        ),
        "root_research_string_markers": _marker_presence(response.body),
        "expected_identity_markers": {
            "firmware": expected_firmware.encode("utf-8") in response.body,
            "model": expected_model.encode("utf-8") in response.body,
            "hardware_revision": expected_hardware.encode("utf-8") in response.body,
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
) -> dict[str, object]:
    """Authenticate once and collect sanitized GET-only status-page evidence.

    The sole POST is the normal web-console login operation. No configuration,
    CWMP, shell, reboot, reset, upload, or firmware endpoint is requested.
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

    cookies: dict[str, str] = {}
    target = str(address)
    entry = _json_object(
        _request(
            target,
            "GET",
            "/?_type=loginData&_tag=login_entry",
            bounded_timeout,
            cookies,
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
        )
    )
    password_digest = hashlib.sha256((password + challenge).encode("utf-8")).hexdigest()
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
        endpoint = _endpoint_evidence(
            _request(target, "GET", path, bounded_timeout, cookies),
            expected_firmware=expected_firmware,
            expected_model=expected_model,
            expected_hardware=expected_hardware,
        )
        endpoints[name] = endpoint
        if name == "authenticated_root" and endpoint["login_page_detected"]:
            raise WebEvidenceError(
                "router returned the login page after accepting the login response; "
                "no management page probes were attempted"
            )
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
        endpoint = _endpoint_evidence(
            _request(
                target,
                "GET",
                f"/?_type=menuView&_tag={page_id}&Menu3Location=0",
                bounded_timeout,
                cookies,
            ),
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
        "transport": "local-http",
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
