# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import hashlib
import json
import unittest
from email.message import Message
from http.client import HTTPException
from http.cookies import CookieError
from typing import Any, ClassVar
from unittest.mock import patch
from urllib.parse import parse_qs

from cpe_access_atlas.web_evidence import (
    MAX_COOKIE_VALUE_CHARS,
    MAX_RESPONSE_BYTES,
    MAX_STRUCTURAL_IDENTIFIERS,
    WebEvidenceError,
    _endpoint_evidence,
    _json_object,
    _login_succeeded,
    _login_token,
    _read_bounded,
    _remember_cookies,
    _request,
    _required_string,
    _Response,
    _response_kind,
    collect_zte_web_evidence,
)


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str | None = "text/plain",
        content_length: str | None = None,
        cookies: tuple[str, ...] = (),
    ) -> None:
        self.status = status
        self.body = body
        self.msg = Message()
        if content_type is not None:
            self.msg.add_header("Content-Type", content_type)
        if content_length is not None:
            self.msg.add_header("Content-Length", content_length)
        for cookie in cookies:
            self.msg.add_header("Set-Cookie", cookie)

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.msg.get(name, default)

    def read(self, amount: int | None = None) -> bytes:
        return self.body if amount is None else self.body[:amount]


class FakeConnection:
    responses: ClassVar[list[FakeResponse | BaseException]] = []
    requests: ClassVar[list[dict[str, Any]]] = []
    instances: ClassVar[list[FakeConnection]] = []
    request_error: ClassVar[BaseException | None] = None

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.closed = False
        self.__class__.instances.append(self)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None,
        headers: dict[str, str],
    ) -> None:
        if self.__class__.request_error is not None:
            raise self.__class__.request_error
        self.__class__.requests.append(
            {"method": method, "path": path, "body": body, "headers": dict(headers)}
        )

    def getresponse(self) -> FakeResponse:
        response = self.__class__.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def close(self) -> None:
        self.closed = True


def response(
    body: bytes,
    *,
    status: int = 200,
    content_type: str = "text/plain",
) -> _Response:
    return _Response(status=status, content_type=content_type, body=body)


class WebEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeConnection.responses = []
        FakeConnection.requests = []
        FakeConnection.instances = []
        FakeConnection.request_error = None

    def test_collects_sanitized_exact_target_evidence(self) -> None:
        firmware = "H3600P V9.0 TTN.10_260210"
        root = (
            b'<html><a href="/?_type=menuView&_tag=statusMgr">status</a>'
            b"H3600P V9 V9.0 CWMP TR-069 InternetGatewayDevice X_TT "
            b"Shell SSH root configDownload"
            b'<script>_PageAccessAuthor["tr069"] = '
            b"{'VisibilityLevel':3,'Limitation':1};"
            b'_PageAccessAuthor["rsc"] = '
            b"{'VisibilityLevel':3,'Limitation':1};"
            b'_PageAccessAuthor["homePage"] = '
            b"{'VisibilityLevel':1,'Limitation':1};</script></html>"
        )
        status_data = (
            b"<ajax_response_xml_root><OBJ_DEVINFO_ID><Instance>"
            b"<ParaName>SoftwareVersion</ParaName><ParaValue>"
            + firmware.encode()
            + b"</ParaValue></Instance></OBJ_DEVINFO_ID></ajax_response_xml_root>"
        )
        FakeConnection.responses = [
            FakeResponse(
                b'{"lockingTime":0,"sess_token":"session-token"}',
                content_type="application/json; charset=utf-8",
                cookies=("SID=first-cookie; Path=/; HttpOnly",),
            ),
            FakeResponse(
                b"<?xml version='1.0'?><ajax_response_xml_root>challenge8</ajax_response_xml_root>",
                content_type="text/xml",
            ),
            FakeResponse(
                b'{"login_need_refresh":true}',
                content_type="application/json",
                cookies=("SID=authenticated-cookie; Path=/; HttpOnly",),
            ),
            FakeResponse(root, content_type="text/html; charset=utf-8"),
            FakeResponse(b"<html>statusMgr</html>", content_type="text/html"),
            FakeResponse(status_data, content_type="text/xml; charset=utf-8"),
            FakeResponse(
                b'<html>TR-069<input id="OBJ_TR069_ID.EnableCWMP" '
                b'name="EnableCWMP"><address>tr069_lua.lua</address>'
                b"<ParaName>ManagementServer.EnableCWMP</ParaName></html>",
                content_type="text/html",
            ),
            FakeResponse(
                b"<html>H3600P V9 V9.0 Telnet<ParaName>ServiceControl</ParaName></html>",
                content_type="text/html",
            ),
        ]

        with patch("cpe_access_atlas.web_evidence.HTTPConnection", FakeConnection):
            result = collect_zte_web_evidence(
                "192.168.1.1",
                "admin",
                "private-password",
                timeout=5,
                expected_firmware=firmware,
                expected_model="H3600P V9",
                expected_hardware="V9.0",
            )

        self.assertTrue(result["authenticated"])
        self.assertEqual(result["login_attempts"], 1)
        self.assertEqual(
            result["observed_expected_identity_markers"],
            {
                "firmware": True,
                "model": True,
                "hardware_revision": True,
            },
        )
        self.assertTrue(all(result["observed_root_research_string_markers"].values()))
        endpoints = result["endpoints"]
        self.assertEqual(endpoints["authenticated_root"]["route_tags"], ["statusMgr"])
        self.assertEqual(endpoints["status_data"]["parameter_names"], ["SoftwareVersion"])
        self.assertEqual(
            endpoints["page_view_tr069"]["parameter_names"],
            ["ManagementServer.EnableCWMP"],
        )
        self.assertEqual(
            endpoints["page_view_tr069"]["html_element_ids"],
            ["OBJ_TR069_ID.EnableCWMP"],
        )
        self.assertEqual(endpoints["page_view_tr069"]["html_field_names"], ["EnableCWMP"])
        self.assertEqual(endpoints["page_view_tr069"]["config_object_ids"], ["OBJ_TR069_ID"])
        self.assertEqual(endpoints["page_view_tr069"]["lua_resource_names"], ["tr069_lua.lua"])
        self.assertFalse(endpoints["page_view_tr069"]["structural_identifier_limit_reached"])
        self.assertEqual(endpoints["page_view_rsc"]["parameter_names"], ["ServiceControl"])
        self.assertIn("ParaValue", endpoints["status_data"]["xml_element_names"])
        self.assertEqual(result["advertised_privileged_page_ids"], ["rsc", "tr069"])
        self.assertEqual(result["read_only_page_views_requested"], ["tr069", "rsc"])
        self.assertEqual(
            result["advertised_page_access"],
            [
                {"page_id": "homePage", "visibility_level": 1, "limitation": 1},
                {"page_id": "rsc", "visibility_level": 3, "limitation": 1},
                {"page_id": "tr069", "visibility_level": 3, "limitation": 1},
            ],
        )
        self.assertFalse(result["configuration_mutation_attempted"])
        self.assertFalse(result["cwmp_request_sent"])
        self.assertFalse(result["credentials_cookies_or_parameter_values_output"])
        self.assertFalse(result["raw_response_saved"])

        self.assertEqual(
            [item["method"] for item in FakeConnection.requests],
            [
                "GET",
                "GET",
                "POST",
                "GET",
                "GET",
                "GET",
                "GET",
                "GET",
            ],
        )
        self.assertEqual(
            [item["path"] for item in FakeConnection.requests[-2:]],
            [
                "/?_type=menuView&_tag=tr069&Menu3Location=0",
                "/?_type=menuView&_tag=rsc&Menu3Location=0",
            ],
        )
        posted = parse_qs(FakeConnection.requests[2]["body"].decode("ascii"))
        expected_digest = hashlib.sha256(b"private-passwordchallenge8").hexdigest()
        self.assertEqual(posted["Password"], [expected_digest])
        self.assertNotIn("private-password", FakeConnection.requests[2]["body"].decode("ascii"))
        self.assertEqual(posted["_sessionTOKEN"], ["session-token"])
        self.assertEqual(FakeConnection.requests[2]["headers"]["Cookie"], "SID=first-cookie")
        self.assertEqual(
            FakeConnection.requests[3]["headers"]["Cookie"], "SID=authenticated-cookie"
        )
        self.assertTrue(all(instance.closed for instance in FakeConnection.instances))

    def test_collect_rejects_invalid_inputs_before_network_io(self) -> None:
        base = {
            "host": "192.168.1.1",
            "username": "admin",
            "password": "secret",
            "timeout": 5,
            "expected_firmware": "firmware",
            "expected_model": "model",
            "expected_hardware": "hardware",
        }
        invalid = (
            ("username", ""),
            ("username", "bad\nname"),
            ("username", "a" * 129),
            ("password", ""),
            ("password", "a" * 257),
            ("expected_firmware", ""),
            ("expected_model", "a" * 257),
            ("expected_hardware", 3),
        )
        for key, value in invalid:
            with self.subTest(key=key, value_type=type(value).__name__):
                arguments = dict(base)
                arguments[key] = value
                with self.assertRaises(WebEvidenceError):
                    collect_zte_web_evidence(**arguments)
        self.assertEqual(FakeConnection.requests, [])

    def test_collect_rejects_failed_login_without_status_requests(self) -> None:
        with patch(
            "cpe_access_atlas.web_evidence._request",
            side_effect=[
                response(
                    b'{"lockingTime":0,"sess_token":"session"}',
                    content_type="application/json",
                ),
                response(
                    b"<ajax_response_xml_root>challenge</ajax_response_xml_root>",
                    content_type="text/xml",
                ),
                response(b'{"login_need_refresh":false}', content_type="application/json"),
            ],
        ) as request:
            with self.assertRaisesRegex(WebEvidenceError, "login was not accepted"):
                collect_zte_web_evidence(
                    "192.168.1.1",
                    "admin",
                    "secret",
                    timeout=5,
                    expected_firmware="firmware",
                    expected_model="model",
                    expected_hardware="hardware",
                )
        self.assertEqual(request.call_count, 3)

    def test_collect_rejects_login_page_after_nominal_login(self) -> None:
        with patch(
            "cpe_access_atlas.web_evidence._request",
            side_effect=[
                response(
                    b'{"lockingTime":0,"sess_token":"session"}',
                    content_type="application/json",
                ),
                response(
                    b"<ajax_response_xml_root>challenge</ajax_response_xml_root>",
                    content_type="text/xml",
                ),
                response(b'{"login_need_refresh":true}', content_type="application/json"),
                response(
                    b'<html><input id="Frm_Username">login_entry</html>',
                    content_type="text/html",
                ),
            ],
        ) as request:
            with self.assertRaisesRegex(WebEvidenceError, "returned the login page"):
                collect_zte_web_evidence(
                    "192.168.1.1",
                    "admin",
                    "secret",
                    timeout=5,
                    expected_firmware="firmware",
                    expected_model="model",
                    expected_hardware="hardware",
                )
        self.assertEqual(request.call_count, 4)

    def test_collect_stops_before_password_post_when_router_is_locked(self) -> None:
        for locking_time in (1, True, "30", None):
            with self.subTest(locking_time=locking_time):
                with patch(
                    "cpe_access_atlas.web_evidence._request",
                    return_value=response(
                        json.dumps({"lockingTime": locking_time, "sess_token": "session"}).encode(),
                        content_type="application/json",
                    ),
                ) as request:
                    with self.assertRaisesRegex(WebEvidenceError, "login is locked"):
                        collect_zte_web_evidence(
                            "192.168.1.1",
                            "admin",
                            "secret",
                            timeout=5,
                            expected_firmware="firmware",
                            expected_model="model",
                            expected_hardware="hardware",
                        )
                request.assert_called_once()

        with patch(
            "cpe_access_atlas.web_evidence._request",
            side_effect=[
                response(
                    b'{"lockingTime":"0","sess_token":"session"}',
                    content_type="application/json",
                ),
                response(
                    b"<ajax_response_xml_root>challenge</ajax_response_xml_root>",
                    content_type="text/xml",
                ),
                response(b'{"login_need_refresh":false}', content_type="application/json"),
            ],
        ) as request:
            with self.assertRaisesRegex(WebEvidenceError, "login was not accepted"):
                collect_zte_web_evidence(
                    "192.168.1.1",
                    "admin",
                    "secret",
                    timeout=5,
                    expected_firmware="firmware",
                    expected_model="model",
                    expected_hardware="hardware",
                )
        self.assertEqual(request.call_count, 3)

    def test_http_request_wraps_transport_errors_and_closes(self) -> None:
        FakeConnection.request_error = OSError("private transport detail")
        with patch("cpe_access_atlas.web_evidence.HTTPConnection", FakeConnection):
            with self.assertRaisesRegex(WebEvidenceError, "bounded local HTTP"):
                _request("192.168.1.1", "GET", "/", 1, {})
        self.assertTrue(FakeConnection.instances[0].closed)

        self.setUp()
        FakeConnection.responses = [HTTPException("private protocol detail")]
        with patch("cpe_access_atlas.web_evidence.HTTPConnection", FakeConnection):
            with self.assertRaisesRegex(WebEvidenceError, "bounded local HTTP"):
                _request("192.168.1.1", "GET", "/", 1, {})
        self.assertTrue(FakeConnection.instances[0].closed)

    def test_response_size_and_length_guards(self) -> None:
        with self.assertRaisesRegex(WebEvidenceError, "invalid Content-Length"):
            _read_bounded(FakeResponse(b"", content_length="invalid"))
        with self.assertRaisesRegex(WebEvidenceError, "exceeds"):
            _read_bounded(FakeResponse(b"", content_length="-1"))
        with self.assertRaisesRegex(WebEvidenceError, "exceeds"):
            _read_bounded(FakeResponse(b"", content_length=str(MAX_RESPONSE_BYTES + 1)))
        with self.assertRaisesRegex(WebEvidenceError, "exceeds"):
            _read_bounded(FakeResponse(b"a" * (MAX_RESPONSE_BYTES + 1)))
        self.assertEqual(_read_bounded(FakeResponse(b"ok", content_length="2")), b"ok")

    def test_cookie_filtering_and_parse_failure(self) -> None:
        cookies: dict[str, str] = {}
        _remember_cookies(
            FakeResponse(
                b"",
                cookies=(
                    "SID=accepted; Path=/",
                    "OVERSIZED=" + ("x" * (MAX_COOKIE_VALUE_CHARS + 1)) + "; Path=/",
                    'UNSAFE="line\\012break"; Path=/',
                ),
            ),
            cookies,
        )
        self.assertEqual(cookies, {"SID": "accepted"})

        class BrokenCookie:
            def load(self, raw_data: str) -> None:
                raise CookieError("malformed")

        with patch("cpe_access_atlas.web_evidence.SimpleCookie", return_value=BrokenCookie()):
            _remember_cookies(FakeResponse(b"", cookies=("SID=value",)), cookies)
        self.assertEqual(cookies, {"SID": "accepted"})

    def test_json_and_token_validation_errors_are_sanitized(self) -> None:
        with self.assertRaisesRegex(WebEvidenceError, "HTTP 403"):
            _json_object(response(b"{}", status=403), "login")
        with self.assertRaisesRegex(WebEvidenceError, "valid UTF-8 JSON"):
            _json_object(response(b"\xff", content_type="application/json"), "login")
        with self.assertRaisesRegex(WebEvidenceError, "JSON object"):
            _json_object(response(b"[]", content_type="application/json"), "login")
        with self.assertRaisesRegex(WebEvidenceError, "expected ajax_response_xml_root"):
            _login_token(response(b"<wrong>token</wrong>", content_type="text/xml"))
        with self.assertRaisesRegex(WebEvidenceError, "HTTP 500"):
            _login_token(response(b"", status=500))

    def test_helpers_classify_responses_and_login_values(self) -> None:
        self.assertTrue(_login_succeeded(True))
        self.assertTrue(_login_succeeded(1))
        self.assertTrue(_login_succeeded("YES"))
        self.assertFalse(_login_succeeded("no"))
        self.assertEqual(_required_string("value", "field", 10), "value")
        with self.assertRaisesRegex(WebEvidenceError, "outside"):
            _required_string(None, "field", 10)

        cases = (
            (response(b"x", content_type="application/json"), "json"),
            (response(b"x", content_type="text/xml"), "xml"),
            (response(b"x", content_type="text/html"), "html"),
            (response(b"  {}", content_type=""), "json"),
            (response(b" <root/>", content_type=""), "xml-or-html"),
            (response(b"plain", content_type=""), "other"),
        )
        for item, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(_response_kind(item), expected)

    def test_endpoint_evidence_reports_absent_markers_without_values(self) -> None:
        evidence = _endpoint_evidence(
            response(b"plain response", status=404, content_type=""),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )
        self.assertEqual(evidence["http_status"], 404)
        self.assertEqual(evidence["response_kind"], "other")
        self.assertFalse(any(evidence["root_research_string_markers"].values()))
        self.assertFalse(any(evidence["expected_identity_markers"].values()))
        self.assertEqual(evidence["route_types"], [])
        self.assertEqual(evidence["parameter_names"], [])
        self.assertEqual(evidence["page_access_entries"], [])
        self.assertFalse(evidence["login_page_detected"])
        self.assertEqual(evidence["html_element_ids"], [])
        self.assertEqual(evidence["html_field_names"], [])
        self.assertEqual(evidence["config_object_ids"], [])
        self.assertEqual(evidence["lua_resource_names"], [])
        self.assertFalse(evidence["structural_identifier_limit_reached"])

    def test_endpoint_evidence_reports_access_map_and_login_page(self) -> None:
        body = (
            b'<html><input id="Frm_Username">login_entry<script>'
            b"_PageAccessAuthor['tr069']={'VisibilityLevel':3,'Limitation':1};"
            b"_PageAccessAuthor['tr069']={'VisibilityLevel':3,'Limitation':1};"
            b"</script></html>"
        )
        evidence = _endpoint_evidence(
            response(body, content_type="text/html"),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )
        self.assertTrue(evidence["login_page_detected"])
        self.assertEqual(
            evidence["page_access_entries"],
            [{"page_id": "tr069", "visibility_level": 3, "limitation": 1}],
        )

    def test_endpoint_evidence_bounds_structural_identifiers(self) -> None:
        body = b"".join(
            f'<input id="field{index:04d}">'.encode("ascii")
            for index in range(MAX_STRUCTURAL_IDENTIFIERS + 1)
        )
        evidence = _endpoint_evidence(
            response(body, content_type="text/html"),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )
        self.assertEqual(len(evidence["html_element_ids"]), MAX_STRUCTURAL_IDENTIFIERS)
        self.assertTrue(evidence["structural_identifier_limit_reached"])

    def test_result_is_json_serializable(self) -> None:
        minimal = _endpoint_evidence(
            response(b"<root/>", content_type="text/xml"),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )
        self.assertIn('"xml_element_names": ["root"]', json.dumps(minimal, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
