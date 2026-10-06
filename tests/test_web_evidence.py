# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import io
import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
from email.message import Message
from http.client import HTTPConnection as RealHTTPConnection
from http.client import HTTPException, HTTPResponse
from http.cookies import CookieError
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from cpe_access_atlas.web_evidence import (
    _PARAMETER_NAME,
    MAX_COOKIE_COUNT,
    MAX_COOKIE_HEADER_BYTES,
    MAX_COOKIE_VALUE_CHARS,
    MAX_JSON_NESTING,
    MAX_PAGE_ACCESS_ENTRIES,
    MAX_RESPONSE_BYTES,
    MAX_RETAINED_COOKIE_BYTES,
    MAX_STRUCTURAL_IDENTIFIERS,
    MAX_TLS_CA_BYTES,
    WebEvidenceError,
    _cookie_header,
    _DeadlineSocket,
    _endpoint_evidence,
    _hardware_revision_marker_present,
    _json_object,
    _login_succeeded,
    _login_token,
    _make_tls_context,
    _read_bounded,
    _remaining_request_time,
    _remember_cookies,
    _request,
    _required_string,
    _Response,
    _response_kind,
    _zte_login_compatibility_digest,
    collect_zte_web_evidence,
    validate_web_evidence_transport,
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
        self.chunked = False
        self.length = (
            int(content_length)
            if content_length is not None and content_length.isdecimal()
            else None
        )
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

    def close(self) -> None:
        pass


class FakeSocket:
    def close(self) -> None:
        pass


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
        self.sock = FakeSocket()
        self.__class__.instances.append(self)

    def connect(self) -> None:
        pass

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


def parsed_response(wire_bytes: bytes) -> HTTPResponse:
    """Use the standard HTTP parser and body reader without making a connection."""

    class MemorySocket:
        def makefile(self, mode: str) -> io.BytesIO:
            return io.BytesIO(wire_bytes)

    parsed = HTTPResponse(MemorySocket())
    parsed.begin()
    return parsed


class WebEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeConnection.responses = []
        FakeConnection.requests = []
        FakeConnection.instances = []
        FakeConnection.request_error = None

    def test_tls_context_requires_certificate_ip_and_modern_protocol_without_key_logging(
        self,
    ) -> None:
        context = _make_tls_context(None)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertIsNone(context.keylog_filename)
        validate_web_evidence_transport("https")

    def test_public_transport_options_fail_before_network_io(self) -> None:
        cases = (
            {"transport": "ftp"},
            {"transport": "http"},
            {"transport": "http", "acknowledge_local_http_authentication": 1},
            {"transport": "https", "acknowledge_local_http_authentication": True},
            {
                "transport": "http",
                "acknowledge_local_http_authentication": True,
                "tls_ca_pem": "SYNTHETIC-PRIVATE",
            },
            {"tls_ca_pem": b"SYNTHETIC-PRIVATE"},
            {"tls_ca_pem": ""},
            {"tls_ca_pem": "SYNTHETIC-PRIVATE-\u00e9"},
            {"tls_ca_pem": "x" * (MAX_TLS_CA_BYTES + 1)},
            {"tls_ca_pem": "SYNTHETIC-PRIVATE"},
            {"tls_ca_pem": "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----"},
            {"tls_ca_pem": "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n" * 9},
            {
                "tls_ca_pem": "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n"
                "SYNTHETIC-PRIVATE"
            },
        )
        for options in cases:
            with self.subTest(option_names=tuple(options)):
                with patch("cpe_access_atlas.web_evidence.HTTPConnection") as connection:
                    with self.assertRaises(WebEvidenceError) as error:
                        collect_zte_web_evidence(
                            "192.168.1.1",
                            "admin",
                            "secret",
                            timeout=1,
                            expected_firmware="firmware",
                            expected_model="model",
                            expected_hardware="hardware",
                            **options,
                        )
                connection.assert_not_called()
                self.assertNotIn("SYNTHETIC-PRIVATE", str(error.exception))
        validate_web_evidence_transport("http", acknowledge_local_http_authentication=True)

    def test_tls_trust_loading_failure_does_not_expose_details(self) -> None:
        with patch.object(
            ssl.SSLContext, "load_default_certs", side_effect=OSError("SYNTHETIC-PRIVATE")
        ):
            with self.assertRaisesRegex(
                WebEvidenceError, "verified TLS certificate trust"
            ) as error:
                validate_web_evidence_transport("https")
        self.assertNotIn("SYNTHETIC-PRIVATE", str(error.exception))

    def test_low_level_request_rejects_insecure_tls_configuration_before_connecting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contexts = []
            unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            contexts.append(unverified)
            wrong_identity = _make_tls_context(None)
            wrong_identity.check_hostname = False
            contexts.append(wrong_identity)
            old_protocol = _make_tls_context(None)
            old_protocol.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            contexts.append(old_protocol)
            key_logging = _make_tls_context(None)
            key_logging.keylog_filename = str(Path(directory) / "synthetic-keylog.txt")
            contexts.append(key_logging)
            for context in contexts:
                with patch("cpe_access_atlas.web_evidence.HTTPConnection") as connection:
                    with self.assertRaisesRegex(WebEvidenceError, "TLS requires"):
                        _request("192.168.1.1", "GET", "/", 1, {}, tls_context=context)
                connection.assert_not_called()
            # Release the configured handle before Windows removes the fixture.
            key_logging.keylog_filename = None
        for options in (
            {"transport": "ftp"},
            {"transport": "http", "tls_context": _make_tls_context(None)},
        ):
            with patch("cpe_access_atlas.web_evidence.HTTPConnection") as connection:
                with self.assertRaises(WebEvidenceError):
                    _request("192.168.1.1", "GET", "/", 1, {}, **options)
            connection.assert_not_called()

    def test_tcp_tls_and_request_share_one_deadline(self) -> None:
        now = [100.0]
        tcp = Mock(spec=socket.socket)
        tls = Mock(spec=ssl.SSLSocket)
        context = _make_tls_context(None)

        class TimedConnection(FakeConnection):
            def connect(self) -> None:
                self.sock = tcp
                now[0] += 0.6

        def wrap(_self: ssl.SSLContext, sock: object, **options: object) -> object:
            self.assertIs(sock, tcp)
            self.assertEqual(
                options, {"server_hostname": "192.168.1.1", "do_handshake_on_connect": False}
            )
            self.assertAlmostEqual(tcp.settimeout.call_args.args[0], 0.4)
            tcp.close()  # Model wrap_socket transferring the descriptor.
            now[0] += 0.1
            return tls

        def handshake() -> None:
            self.assertAlmostEqual(tls.settimeout.call_args.args[0], 0.3)
            self.assertEqual(FakeConnection.requests, [])
            now[0] += 0.1

        tls.do_handshake.side_effect = handshake
        FakeConnection.responses = [FakeResponse(b"ok")]
        with (
            patch("cpe_access_atlas.web_evidence.HTTPConnection", TimedConnection),
            patch("cpe_access_atlas.web_evidence.time.monotonic", side_effect=lambda: now[0]),
            patch.object(ssl.SSLContext, "wrap_socket", new=wrap),
        ):
            result = _request("192.168.1.1", "GET", "/", 1, {}, tls_context=context)
        self.assertEqual(result.body, b"ok")
        self.assertEqual(FakeConnection.instances[0].port, 443)
        self.assertEqual(len(FakeConnection.requests), 1)
        tls.do_handshake.assert_called_once()
        tls.close.assert_called()
        tcp.close.assert_called()

    def test_exhausted_or_failed_tls_connection_never_sends_an_http_request(self) -> None:
        def exercise_failure(failure: str) -> None:
            self.setUp()
            now = [100.0]
            tcp = Mock(spec=socket.socket)
            tls = Mock(spec=ssl.SSLSocket)
            context = _make_tls_context(None)

            class TimedConnection(FakeConnection):
                def connect(self) -> None:
                    self.sock = tcp
                    now[0] += 1.1 if failure == "tcp-budget" else 0.6

            def wrap(_self: ssl.SSLContext, sock: object, **options: object) -> object:
                if failure == "wrap-error":
                    raise ssl.SSLError("SYNTHETIC-PRIVATE")
                tcp.close()
                now[0] += 0.5 if failure == "wrap-budget" else 0.1
                return tls

            tls.do_handshake.side_effect = TimeoutError("SYNTHETIC-PRIVATE")
            with (
                patch("cpe_access_atlas.web_evidence.HTTPConnection", TimedConnection),
                patch("cpe_access_atlas.web_evidence.time.monotonic", side_effect=lambda: now[0]),
                patch.object(ssl.SSLContext, "wrap_socket", new=wrap),
            ):
                with self.assertRaisesRegex(WebEvidenceError, "bounded local HTTPS") as error:
                    _request("192.168.1.1", "GET", "/", 1, {}, tls_context=context)
            self.assertEqual(FakeConnection.requests, [])
            self.assertEqual(len(FakeConnection.instances), 1)
            self.assertTrue(FakeConnection.instances[0].closed)
            self.assertNotIn("SYNTHETIC-PRIVATE", str(error.exception))
            tcp.close.assert_called()
            if failure in {"wrap-budget", "handshake-error"}:
                tls.close.assert_called()
            if failure != "handshake-error":
                tls.do_handshake.assert_not_called()

        for failure in ("tcp-budget", "wrap-budget", "wrap-error", "handshake-error"):
            with self.subTest(failure=failure):
                exercise_failure(failure)

    def test_collects_sanitized_exact_target_evidence(self) -> None:
        firmware = "H3600P V9.0 TTN.10_260210"
        root = (
            b'<html><div id="r"></div>'
            b'<a href="/?_type=menuView&_tag=statusMgr">status</a>'
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
                transport="http",
                acknowledge_local_http_authentication=True,
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
                # Neither free text nor a SoftwareVersion value verifies hardware.
                "hardware_revision": False,
            },
        )
        self.assertTrue(all(result["observed_root_research_string_markers"].values()))
        endpoints = result["endpoints"]
        self.assertEqual(endpoints["authenticated_root"]["route_tags"], ["statusMgr"])
        self.assertEqual(endpoints["authenticated_root"]["html_element_ids"], [])
        self.assertEqual(
            endpoints["authenticated_root"]["redacted_unique_structural_identifier_counts"][
                "html_element_ids"
            ],
            1,
        )
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
        self.assertEqual(
            endpoints["page_view_tr069"]["redacted_unique_structural_identifier_counts"],
            {
                "route_types": 0,
                "route_tags": 0,
                "xml_element_names": 0,
                "parameter_names": 0,
                "page_ids": 0,
                "html_element_ids": 0,
                "html_field_names": 0,
                "config_object_ids": 0,
                "lua_resource_names": 0,
            },
        )
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
        self.assertEqual(
            posted["Password"],
            ["aa8e88b063bf667aac90fd3ef8d25174681c8d5ab9ddf718970f025b8e4c3a28"],
        )
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

    def test_normal_status_xml_does_not_report_a_root_literal(self) -> None:
        status_xml = (
            b"<ajax_response_xml_root><ParaName>SoftwareVersion</ParaName>"
            b"<ParaValue>H3600P V9.0 TTN.10_260210</ParaValue></ajax_response_xml_root>"
        )
        with patch(
            "cpe_access_atlas.web_evidence._request",
            side_effect=[
                response(b'{"lockingTime":0,"sess_token":"session"}'),
                response(b"<ajax_response_xml_root>challenge</ajax_response_xml_root>"),
                response(b'{"login_need_refresh":true}'),
                response(b"<html>Device status</html>"),
                response(b"<html>Buildroot rootfs</html>"),
                response(status_xml),
            ],
        ):
            result = collect_zte_web_evidence(
                "192.168.1.1",
                "admin",
                "secret",
                timeout=5,
                expected_firmware="H3600P V9.0 TTN.10_260210",
                expected_model="H3600P V9",
                expected_hardware="V9.0",
            )
        self.assertFalse(result["observed_root_research_string_markers"]["root_literal"])
        self.assertFalse(
            result["endpoints"]["status_data"]["root_research_string_markers"]["root_literal"]
        )

    def test_root_literal_requires_a_standalone_token(self) -> None:
        cases = (
            (b"ajax_response_xml_root Buildroot rootfs root_account", False),
            (b"ROOT", True),
            (b'<input value="root">', True),
            (b"<ParaValue>root</ParaValue>", True),
            (b"/root/.ssh", True),
        )
        for body, expected in cases:
            with self.subTest(body=body):
                evidence = _endpoint_evidence(
                    response(body),
                    expected_firmware="firmware",
                    expected_model="model",
                    expected_hardware="hardware",
                )
                self.assertEqual(evidence["root_research_string_markers"]["root_literal"], expected)

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

    def test_authentication_loss_stops_at_each_evidence_endpoint_without_retry(self) -> None:
        root = (
            b'_PageAccessAuthor["tr069"] = {"VisibilityLevel":3,"Limitation":0};'
            b'_PageAccessAuthor["rsc"] = {"VisibilityLevel":3,"Limitation":0};'
        )
        failures = (
            (response(b"SYNTHETIC-PRIVATE-SESSION", status=401), "HTTP 401"),
            (
                response(b'<input id="Frm_Username">login_entry SYNTHETIC-PRIVATE-SESSION'),
                "returned the login page",
            ),
        )
        for failed_index in range(5):
            for failure, message in failures:
                with self.subTest(failed_evidence_endpoint=failed_index, message=message):
                    responses = [
                        response(b'{"lockingTime":0,"sess_token":"session"}'),
                        response(b"<ajax_response_xml_root>challenge</ajax_response_xml_root>"),
                        response(b'{"login_need_refresh":true}'),
                        *[
                            response(root if index == 0 else b"status")
                            for index in range(failed_index)
                        ],
                        failure,
                    ]
                    with patch(
                        "cpe_access_atlas.web_evidence._request", side_effect=responses
                    ) as request:
                        with self.assertRaisesRegex(WebEvidenceError, message) as error:
                            collect_zte_web_evidence(
                                "192.168.1.1",
                                "admin",
                                "secret",
                                timeout=5,
                                expected_firmware="firmware",
                                expected_model="model",
                                expected_hardware="hardware",
                            )
                    self.assertEqual(request.call_count, 4 + failed_index)
                    self.assertEqual(
                        [call.args[1] for call in request.call_args_list].count("POST"), 1
                    )
                    self.assertNotIn("SYNTHETIC-PRIVATE", str(error.exception))

    def test_authorization_denial_does_not_claim_authentication_loss(self) -> None:
        root = b'_PageAccessAuthor["tr069"] = {"VisibilityLevel":3,"Limitation":0};'
        responses = [
            response(b'{"lockingTime":0,"sess_token":"session"}'),
            response(b"<ajax_response_xml_root>challenge</ajax_response_xml_root>"),
            response(b'{"login_need_refresh":true}'),
            response(root, status=403),
            response(b"Forbidden", status=403),
            response(b"Forbidden", status=403),
            response(b"Forbidden", status=403),
        ]
        with patch("cpe_access_atlas.web_evidence._request", side_effect=responses) as request:
            result = collect_zte_web_evidence(
                "192.168.1.1",
                "admin",
                "secret",
                timeout=5,
                expected_firmware="firmware",
                expected_model="model",
                expected_hardware="hardware",
            )
        self.assertTrue(result["authenticated"])
        self.assertEqual(request.call_count, 7)
        self.assertTrue(all(item["http_status"] == 403 for item in result["endpoints"].values()))

    def test_http_request_wraps_transport_errors_and_closes(self) -> None:
        FakeConnection.request_error = OSError("private transport detail")
        with patch("cpe_access_atlas.web_evidence.HTTPConnection", FakeConnection):
            with self.assertRaisesRegex(WebEvidenceError, "bounded local HTTP"):
                _request("192.168.1.1", "GET", "/", 1, {}, transport="http")
        self.assertTrue(FakeConnection.instances[0].closed)

        self.setUp()
        FakeConnection.responses = [HTTPException("private protocol detail")]
        with patch("cpe_access_atlas.web_evidence.HTTPConnection", FakeConnection):
            with self.assertRaisesRegex(WebEvidenceError, "bounded local HTTP"):
                _request("192.168.1.1", "GET", "/", 1, {}, transport="http")
        self.assertTrue(FakeConnection.instances[0].closed)

    def test_expired_deadline_and_missing_http_socket_are_sanitized(self) -> None:
        with self.assertRaises(TimeoutError):
            _remaining_request_time(time.monotonic() - 1)
        with self.assertRaises(ValueError):
            _DeadlineSocket(FakeSocket(), time.monotonic() + 1).makefile("wb")

        class NoSocketConnection(FakeConnection):
            def connect(self) -> None:
                self.sock = None

        with patch("cpe_access_atlas.web_evidence.HTTPConnection", NoSocketConnection):
            with self.assertRaisesRegex(WebEvidenceError, "bounded local HTTP request"):
                _request("127.0.0.1", "GET", "/", 1, {}, transport="http")
        self.assertTrue(FakeConnection.instances[0].closed)

    def test_slow_dripping_headers_and_body_cannot_extend_request_deadline(self) -> None:
        cases = {
            "headers": (
                b"HTTP/1.1 ",
                b"200 OK\r\n",
                b"Content-Length: 2\r\n",
                b"Connection: close\r\n",
                b"\r\nok",
            ),
            "body": (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
                b"a",
                b"b",
                b"c",
                b"d",
                b"e",
            ),
        }
        for phase, chunks in cases.items():
            with self.subTest(phase=phase), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(2)
                port = listener.getsockname()[1]

                def serve(chunks_to_send: tuple[bytes, ...] = chunks) -> None:
                    try:
                        peer, _address = listener.accept()
                    except TimeoutError:
                        return
                    with peer:
                        peer.settimeout(2)
                        request = bytearray()
                        while b"\r\n\r\n" not in request:
                            incoming = peer.recv(4096)
                            if not incoming:
                                return
                            request.extend(incoming)
                        for index, chunk in enumerate(chunks_to_send):
                            if index:
                                time.sleep(0.1)
                            try:
                                peer.sendall(chunk)
                            except OSError:
                                break

                server = threading.Thread(target=serve, daemon=True)
                server.start()
                with patch(
                    "cpe_access_atlas.web_evidence.HTTPConnection",
                    side_effect=lambda host, _port, timeout, server_port=port: RealHTTPConnection(
                        host, server_port, timeout=timeout
                    ),
                ):
                    started = time.monotonic()
                    with self.assertRaisesRegex(WebEvidenceError, "bounded local HTTP request"):
                        _request("127.0.0.1", "GET", "/", 0.25, {}, transport="http")
                    self.assertLess(time.monotonic() - started, 1)
                server.join(timeout=2)
                self.assertFalse(server.is_alive())

    def test_fast_local_http_response_preserves_body_and_cookie(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(2)
            port = listener.getsockname()[1]

            def serve() -> None:
                try:
                    peer, _address = listener.accept()
                except TimeoutError:
                    return
                with peer:
                    peer.settimeout(2)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        incoming = peer.recv(4096)
                        if not incoming:
                            return
                        request.extend(incoming)
                    peer.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                        b"Content-Type: text/plain\r\nSet-Cookie: SID=accepted; Path=/\r\n"
                        b"Connection: close\r\n\r\nok"
                    )

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            cookies: dict[str, str] = {}
            with patch(
                "cpe_access_atlas.web_evidence.HTTPConnection",
                side_effect=lambda host, _port, timeout: RealHTTPConnection(
                    host, port, timeout=timeout
                ),
            ):
                result = _request("127.0.0.1", "GET", "/", 1, cookies, transport="http")
            server.join(timeout=2)
            self.assertFalse(server.is_alive())
            self.assertEqual(result, response(b"ok"))
            self.assertEqual(cookies, {"SID": "accepted"})

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

    def test_real_http_parser_rejects_truncated_content_length(self) -> None:
        for body in (b"", b'{"login_need_refresh":true}', b"<html>partial status</html>"):
            with self.subTest(body=body):
                with parsed_response(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n" + body
                ) as parsed:
                    with self.assertRaisesRegex(WebEvidenceError, "before its declared"):
                        _read_bounded(parsed)

    def test_real_http_parser_uses_effective_framing(self) -> None:
        cases = (
            (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", b"ok"),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", b""),
            (b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok", b"ok"),
            (b"HTTP/1.1 204 No Content\r\n\r\n", b""),
            # A 304 Content-Length describes the selected representation, not
            # a body that should be read from this response.
            (b"HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n", b""),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
                b"ok",
            ),
        )
        for wire_bytes, expected in cases:
            with self.subTest(response=wire_bytes):
                with parsed_response(wire_bytes) as parsed:
                    self.assertEqual(_read_bounded(parsed), expected)

        # HTTPResponse gives chunked coding precedence over a conflicting
        # Content-Length. Do not mistake that ignored value for missing bytes.
        for ignored_length in (b"100", b"invalid", b"1048577"):
            with self.subTest(ignored_length=ignored_length):
                with parsed_response(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: "
                    + ignored_length
                    + b"\r\n\r\n2\r\nok\r\n0\r\n\r\n"
                ) as parsed:
                    self.assertEqual(_read_bounded(parsed), b"ok")

    def test_real_http_parser_rejects_incomplete_chunks_and_caps_decoded_body(self) -> None:
        for chunks in (b"2\r\no", b"2\r\nok\r\n", b"invalid\r\n"):
            with self.subTest(chunks=chunks):
                with parsed_response(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks
                ) as parsed:
                    with self.assertRaises(HTTPException):
                        _read_bounded(parsed)
        body = b"x" * (MAX_RESPONSE_BYTES + 1)
        with parsed_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + f"{len(body):x}\r\n".encode()
            + body
            + b"\r\n0\r\n\r\n"
        ) as parsed:
            with self.assertRaisesRegex(WebEvidenceError, "exceeds"):
                _read_bounded(parsed)

    def test_cookie_filtering_and_parse_failure(self) -> None:
        cookies: dict[str, str] = {}
        _remember_cookies(
            FakeResponse(
                b"",
                cookies=(
                    "SID=accepted; Path=/",
                    "OVERSIZED=" + ("x" * (MAX_COOKIE_VALUE_CHARS + 1)) + "; Path=/",
                    'UNSAFE="line\\012break"; Path=/',
                    "BAD%=ignored; Path=/",
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

    def test_cookie_count_budget_spans_responses_and_replacements_are_transactional(self) -> None:
        cookies: dict[str, str] = {}
        for index in range(MAX_COOKIE_COUNT):
            _remember_cookies(FakeResponse(b"", cookies=(f"C{index}=original",)), cookies)
        self.assertEqual(len(cookies), MAX_COOKIE_COUNT)
        original = cookies.copy()
        with self.assertRaisesRegex(WebEvidenceError, "16-cookie limit") as failure:
            _remember_cookies(
                FakeResponse(b"", cookies=("C0=replaced", "OVERFLOW=private-cookie-value")),
                cookies,
            )
        self.assertEqual(cookies, original)
        self.assertNotIn("OVERFLOW", str(failure.exception))
        self.assertNotIn("private-cookie-value", str(failure.exception))
        for value in ("replacement", "", "another-replacement"):
            _remember_cookies(FakeResponse(b"", cookies=(f"C0={value}; Path=/",)), cookies)
            self.assertEqual(cookies["C0"], value)
            self.assertEqual(len(cookies), MAX_COOKIE_COUNT)

    def test_cookie_byte_budgets_include_names_and_serialization_delimiters(self) -> None:
        cookies: dict[str, str] = {}
        # Two 4093-byte values plus two names, equals signs and '; ' hit 8 KiB exactly.
        for name in ("A", "B"):
            _remember_cookies(FakeResponse(b"", cookies=(f"{name}={'x' * 4093}",)), cookies)
        self.assertEqual(len(_cookie_header(cookies).encode("ascii")), MAX_COOKIE_HEADER_BYTES)
        FakeConnection.responses = [FakeResponse(b"ok")]
        with patch("cpe_access_atlas.web_evidence.HTTPConnection", FakeConnection):
            _request("192.168.1.1", "GET", "/", 1, cookies, transport="http")
        self.assertEqual(
            len(FakeConnection.requests[0]["headers"]["Cookie"].encode("ascii")),
            MAX_COOKIE_HEADER_BYTES,
        )
        original = cookies.copy()
        with self.assertRaisesRegex(WebEvidenceError, "Cookie-header limit"):
            _remember_cookies(FakeResponse(b"", cookies=(f"B={'x' * 4094}",)), cookies)
        self.assertEqual(cookies, original)
        with self.assertRaisesRegex(WebEvidenceError, "Cookie-header limit"):
            _remember_cookies(
                FakeResponse(b"", cookies=(f"B={'x' * 4092}", f"A={'x' * 4095}")),
                cookies,
            )
        self.assertEqual(cookies, original)
        oversized = {"A": "x" * 4096, "B": "x" * 4095}
        self.assertEqual(
            sum(len(name) + len(value) for name, value in oversized.items()),
            MAX_RETAINED_COOKIE_BYTES + 1,
        )
        with self.assertRaisesRegex(WebEvidenceError, "retained-cookie limit"):
            _remember_cookies(FakeResponse(b"", cookies=("SID=replacement",)), oversized)
        with self.assertRaisesRegex(WebEvidenceError, "retained-cookie limit"):
            _cookie_header(oversized)

    def test_direct_cookie_callers_are_validated_before_opening_a_connection(self) -> None:
        unsafe_jars: list[dict[Any, Any]] = [
            {"": "value"},
            {"bad name": "value"},
            {"A" * 129: "value"},
            {None: "value"},
            {"SID": None},
            {"SID": "line\nbreak"},
            {"SID": "non-ascii-\u00e9"},
            {"SID": "x" * (MAX_COOKIE_VALUE_CHARS + 1)},
        ]
        for cookies in unsafe_jars:
            with self.subTest(cookies=cookies):
                original = cookies.copy()
                with patch("cpe_access_atlas.web_evidence.HTTPConnection") as connection:
                    with self.assertRaisesRegex(WebEvidenceError, "unsafe cookie"):
                        _request("192.168.1.1", "GET", "/", 1, cookies, transport="http")
                    connection.assert_not_called()
                with self.assertRaisesRegex(WebEvidenceError, "unsafe cookie"):
                    _remember_cookies(FakeResponse(b"", cookies=("SID=replacement",)), cookies)
                self.assertEqual(cookies, original)
        too_many = {f"C{index}": "value" for index in range(MAX_COOKIE_COUNT + 1)}
        with patch("cpe_access_atlas.web_evidence.HTTPConnection") as connection:
            with self.assertRaisesRegex(WebEvidenceError, "16-cookie limit"):
                _request("192.168.1.1", "GET", "/", 1, too_many, transport="http")
            connection.assert_not_called()

    def test_response_cookie_budget_failure_closes_transport_without_partial_updates(self) -> None:
        cookies = {f"C{index}": "original" for index in range(MAX_COOKIE_COUNT)}
        original = cookies.copy()
        FakeConnection.responses = [
            FakeResponse(b"ok", cookies=("C0=replaced", "EXTRA=private-cookie-value"))
        ]
        with patch("cpe_access_atlas.web_evidence.HTTPConnection", FakeConnection):
            with self.assertRaisesRegex(WebEvidenceError, "16-cookie limit"):
                _request("192.168.1.1", "GET", "/", 1, cookies, transport="http")
        self.assertEqual(cookies, original)
        self.assertEqual(len(FakeConnection.requests), 1)
        self.assertTrue(FakeConnection.instances[0].closed)

    def test_response_rejection_does_not_commit_cookies_before_reading_metadata(self) -> None:
        class BrokenMetadataResponse(FakeResponse):
            def getheader(self, name: str, default: str | None = None) -> str | None:
                if name == "Content-Type":
                    raise HTTPException("private response detail")
                return super().getheader(name, default)

        for item in (
            FakeResponse(b"x" * (MAX_RESPONSE_BYTES + 1), cookies=("SID=replaced",)),
            FakeResponse(b"partial", content_length="100", cookies=("SID=replaced",)),
            BrokenMetadataResponse(b"ok", cookies=("SID=replaced",)),
        ):
            with self.subTest(response=type(item).__name__):
                self.setUp()
                cookies = {"SID": "original"}
                FakeConnection.responses = [item]
                with patch("cpe_access_atlas.web_evidence.HTTPConnection", FakeConnection):
                    with self.assertRaises(WebEvidenceError):
                        _request("192.168.1.1", "GET", "/", 1, cookies, transport="http")
                self.assertEqual(cookies, {"SID": "original"})
                self.assertTrue(FakeConnection.instances[0].closed)

    def test_json_and_token_validation_errors_are_sanitized(self) -> None:
        with self.assertRaisesRegex(WebEvidenceError, "HTTP 403"):
            _json_object(response(b"{}", status=403), "login")
        with self.assertRaisesRegex(WebEvidenceError, "valid UTF-8 JSON"):
            _json_object(response(b"\xff", content_type="application/json"), "login")
        with self.assertRaisesRegex(WebEvidenceError, "valid UTF-8 JSON"):
            _json_object(response(b"{", content_type="application/json"), "login")
        with self.assertRaisesRegex(WebEvidenceError, "JSON object"):
            _json_object(response(b"[]", content_type="application/json"), "login")
        with self.assertRaisesRegex(WebEvidenceError, "expected ajax_response_xml_root"):
            _login_token(response(b"<wrong>token</wrong>", content_type="text/xml"))
        with self.assertRaisesRegex(WebEvidenceError, "HTTP 500"):
            _login_token(response(b"", status=500))

    def test_json_nesting_is_bounded_before_decoding(self) -> None:
        at_limit = (b'{"value":' * MAX_JSON_NESTING) + b"0" + (b"}" * MAX_JSON_NESTING)
        self.assertIsInstance(
            _json_object(response(at_limit, content_type="application/json"), "login"),
            dict,
        )

        excessive_depth = 2_000
        nested = (b'{"value":' * excessive_depth) + b"0" + (b"}" * excessive_depth)
        self.assertLess(len(nested), MAX_RESPONSE_BYTES)
        with patch("cpe_access_atlas.web_evidence.json.loads") as loads:
            with self.assertRaisesRegex(
                WebEvidenceError,
                rf"JSON exceeds the {MAX_JSON_NESTING}-level nesting limit",
            ):
                _json_object(response(nested, content_type="application/json"), "login")
        loads.assert_not_called()

    def test_json_decoder_recursion_error_is_converted_to_protocol_error(self) -> None:
        with patch(
            "cpe_access_atlas.web_evidence.json.loads",
            side_effect=RecursionError("private decoder detail"),
        ):
            with self.assertRaises(WebEvidenceError) as caught:
                _json_object(response(b"{}", content_type="application/json"), "login")
        self.assertIn("nesting limit", str(caught.exception))
        self.assertNotIn("private decoder detail", str(caught.exception))

    def test_json_decoder_value_error_is_converted_to_protocol_error(self) -> None:
        oversized_integer = b'{"value":' + (b"9" * 5_000) + b"}"
        with self.assertRaises(WebEvidenceError) as caught:
            _json_object(
                response(oversized_integer, content_type="application/json"),
                "login",
            )
        self.assertIn("within safety limits", str(caught.exception))
        self.assertNotIn("4300", str(caught.exception))

        with patch(
            "cpe_access_atlas.web_evidence.json.loads",
            side_effect=ValueError("private decoder detail"),
        ):
            with self.assertRaises(WebEvidenceError) as patched_caught:
                _json_object(response(b"{}", content_type="application/json"), "login")
        self.assertNotIn("private decoder detail", str(patched_caught.exception))

    def test_json_nesting_scan_ignores_delimiters_inside_strings(self) -> None:
        delimiters = ("[{" * (MAX_JSON_NESTING + 10)) + r"\"" + ("]}" * (MAX_JSON_NESTING + 10))
        document = json.dumps({"value": delimiters}).encode("utf-8")
        self.assertEqual(
            _json_object(response(document, content_type="application/json"), "login"),
            {"value": delimiters},
        )

    def test_vendor_login_digest_uses_the_exact_order_and_utf8_encoding(self) -> None:
        # Fixed external protocol vectors: do not recompute these expectations
        # with the implementation's hashlib primitive.
        self.assertEqual(
            _zte_login_compatibility_digest("secret", "ABC123xy"),
            "4ba02a5de8fc34296f18bc10aec1f091bdb20b335f5af1bb4144c10303ee66f6",
        )
        self.assertEqual(
            _zte_login_compatibility_digest("pässwörd", "Δ8"),
            "ba5eda932011a0f651b1c2000ddcff984f609385d102a41680e686e3e9eb305c",
        )
        self.assertNotEqual(
            _zte_login_compatibility_digest("ABC123xy", "secret"),
            "4ba02a5de8fc34296f18bc10aec1f091bdb20b335f5af1bb4144c10303ee66f6",
        )

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

    def test_hardware_marker_requires_labeled_exact_xml_value(self) -> None:
        expected = {
            "expected_firmware": "H3600P V9.0 TTN.10_260210",
            "expected_model": "H3600P V9",
            "expected_hardware": "V9.0",
        }
        observations = (
            (
                b"<ParaName>SoftwareVersion</ParaName><ParaValue>V9.0.7</ParaValue>"
                b"<ParaName>BuildVersion</ParaName><ParaValue>TTN.10_260210</ParaValue>",
                False,
            ),
            (
                b"<ParaName>SoftwareVersion</ParaName>"
                b"<ParaValue>H3600P V9.0 TTN.10_260210</ParaValue>",
                False,
            ),
            (b"<ParaName>HardwareVersion</ParaName><ParaValue>V9.0.7</ParaValue>", False),
            (b"<ParaName>OtherVersion</ParaName><ParaValue>V9.0</ParaValue>", False),
            (b"<html>H3600P V9 V9.0</html>", False),
            (b"<ParaName>HardwareVersion</ParaName><ParaValue>V9.0</ParaValue>", True),
            (b"<ParaName>HardwareRevision</ParaName><ParaValue>V9.0</ParaValue>", True),
        )
        for body, hardware_observed in observations:
            with self.subTest(body=body):
                evidence = _endpoint_evidence(
                    response(body),
                    **expected,
                )
                self.assertEqual(
                    evidence["expected_identity_markers"]["hardware_revision"],
                    hardware_observed,
                )

    def test_hardware_marker_rejects_near_limit_malformed_xml(self) -> None:
        fragment = b"<ParaName<"
        suffix = b">HardwareVersion</ParaName><ParaValue>V9.0</ParaValue>"
        body = fragment * ((MAX_RESPONSE_BYTES - len(suffix)) // len(fragment)) + suffix
        self.assertLessEqual(len(body), MAX_RESPONSE_BYTES)
        self.assertFalse(_hardware_revision_marker_present(body, "V9.0"))

        prefix = b"<ParaName>"
        label_and_value = b"HardwareVersion</ParaName><ParaValue>V9.0</ParaValue>"
        body = (
            prefix
            + b" " * (MAX_RESPONSE_BYTES - len(prefix) - len(label_and_value))
            + label_and_value
        )
        self.assertLessEqual(len(body), MAX_RESPONSE_BYTES)
        self.assertFalse(_hardware_revision_marker_present(body, "V9.0"))

    def test_parameter_name_rejects_near_limit_malformed_opening_tags(self) -> None:
        fragment = b"<ParaName<"
        suffix = b">SoftwareVersion</ParaName>"
        body = fragment * ((MAX_RESPONSE_BYTES - len(suffix)) // len(fragment)) + suffix
        self.assertLessEqual(len(body), MAX_RESPONSE_BYTES)
        self.assertEqual(_PARAMETER_NAME.findall(body), [])
        self.assertEqual(
            _PARAMETER_NAME.findall(b'<ns:ParaName id="status">SoftwareVersion</ns:ParaName>'),
            [b"SoftwareVersion"],
        )

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
        self.assertEqual(
            evidence["redacted_unique_structural_identifier_counts"],
            {
                "route_types": 0,
                "route_tags": 0,
                "xml_element_names": 0,
                "parameter_names": 0,
                "page_ids": 0,
                "html_element_ids": 0,
                "html_field_names": 0,
                "config_object_ids": 0,
                "lua_resource_names": 0,
            },
        )
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

    def test_endpoint_evidence_reports_structural_identifier_limit(self) -> None:
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
        self.assertEqual(evidence["html_element_ids"], [])
        self.assertEqual(
            evidence["redacted_unique_structural_identifier_counts"]["html_element_ids"],
            MAX_STRUCTURAL_IDENTIFIERS + 1,
        )
        self.assertTrue(evidence["structural_identifier_limit_reached"])

    def test_endpoint_evidence_bounds_canonical_page_access_entries(self) -> None:
        entries = [
            (
                f'_PageAccessAuthor["tr069"] = '
                f'{{"VisibilityLevel":{index // 100},"Limitation":{index % 100}}};'
            ).encode("ascii")
            for index in range(MAX_PAGE_ACCESS_ENTRIES + 1)
        ]
        duplicate = entries[0].replace(b'"tr069"', b'"TR069"')
        private_id = (
            b'_PageAccessAuthor["SYNTHETIC-PRIVATE-ID"] = {"VisibilityLevel":3,"Limitation":1};'
        )
        body = b"".join(entries[:-1]) + duplicate + private_id
        evidence = _endpoint_evidence(
            response(body),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )
        self.assertEqual(len(evidence["page_access_entries"]), MAX_PAGE_ACCESS_ENTRIES)
        self.assertEqual(evidence["redacted_unique_structural_identifier_counts"]["page_ids"], 1)
        self.assertNotIn("SYNTHETIC-PRIVATE-ID", json.dumps(evidence))

        with self.assertRaisesRegex(WebEvidenceError, "512-entry limit") as error:
            _endpoint_evidence(
                response(body + entries[-1]),
                expected_firmware="firmware",
                expected_model="model",
                expected_hardware="hardware",
            )
        self.assertNotIn("SYNTHETIC-PRIVATE-ID", str(error.exception))
        self.assertIsNone(error.exception.__cause__)

    def test_endpoint_evidence_redacts_unreviewed_identifiers_deterministically(self) -> None:
        private_identifiers = (
            "subscriber_alice_123",
            "CustomerSerialNumber",
            "OBJ_PRIVATE_ACCOUNT_456",
            "customer_alice_backup.lua",
        )
        body = (
            b'<input id="subscriber_alice_123" name="CustomerSerialNumber">'
            b'<input id="obj_tr069_id.enablecwmp" name="enablecwmp">'
            b"OBJ_PRIVATE_ACCOUNT_456 OBJ_TR069_ID "
            b"customer_alice_backup.lua TR069_LUA.LUA"
        )
        first = _endpoint_evidence(
            response(body, content_type="text/html"),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )
        reordered_with_duplicates = (
            b"tr069_lua.lua customer_alice_backup.lua TR069_LUA.LUA "
            b"OBJ_TR069_ID OBJ_PRIVATE_ACCOUNT_456 OBJ_PRIVATE_ACCOUNT_456 "
            b'<input name="enablecwmp" id="OBJ_TR069_ID.EnableCWMP">'
            b'<input name="CustomerSerialNumber" id="subscriber_alice_123">'
        )
        second = _endpoint_evidence(
            response(reordered_with_duplicates, content_type="text/html"),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )

        for key in (
            "html_element_ids",
            "html_field_names",
            "config_object_ids",
            "lua_resource_names",
            "redacted_unique_structural_identifier_counts",
            "structural_identifier_limit_reached",
        ):
            with self.subTest(key=key):
                self.assertEqual(first[key], second[key])
        self.assertEqual(first["html_element_ids"], ["OBJ_TR069_ID.EnableCWMP"])
        self.assertEqual(first["html_field_names"], ["EnableCWMP"])
        self.assertEqual(first["config_object_ids"], ["OBJ_TR069_ID"])
        self.assertEqual(first["lua_resource_names"], ["tr069_lua.lua"])
        self.assertEqual(
            first["redacted_unique_structural_identifier_counts"],
            {
                "route_types": 0,
                "route_tags": 0,
                "xml_element_names": 0,
                "parameter_names": 0,
                "page_ids": 0,
                "html_element_ids": 1,
                "html_field_names": 1,
                "config_object_ids": 1,
                "lua_resource_names": 1,
            },
        )
        serialized = json.dumps(first, sort_keys=True)
        for private_identifier in private_identifiers:
            with self.subTest(private_identifier=private_identifier):
                self.assertNotIn(private_identifier.casefold(), serialized.casefold())

    def test_endpoint_evidence_suppresses_redacted_identifier_aliases(self) -> None:
        private_identifiers = (
            "OBJ_PRIVATE_ACCOUNT_456",
            "customer_alice_backup.lua",
            "subscriber_alice_123",
        )
        body = (
            b'<OBJ_PRIVATE_ACCOUNT_456><a href="/?_type=subscriber_alice_123'
            b'&_tag=customer_alice_backup.lua">x</a></OBJ_PRIVATE_ACCOUNT_456>'
            b"<ParaName>Device.OBJ_PRIVATE_ACCOUNT_456.Value</ParaName>"
            b'<input id="subscriber_alice_123">'
            b'<script>_PageAccessAuthor["customer_alice_backup.lua"] = '
            b'{"VisibilityLevel":3,"Limitation":1};</script>'
        )
        evidence = _endpoint_evidence(
            response(body, content_type="text/html"),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )

        serialized = json.dumps(evidence, sort_keys=True).casefold()
        for private_identifier in private_identifiers:
            with self.subTest(private_identifier=private_identifier):
                self.assertNotIn(private_identifier.casefold(), serialized)
        self.assertEqual(evidence["route_types"], [])
        self.assertEqual(evidence["route_tags"], [])
        self.assertNotIn("OBJ_PRIVATE_ACCOUNT_456", evidence["xml_element_names"])
        self.assertEqual(evidence["parameter_names"], [])
        self.assertEqual(evidence["page_access_entries"], [])

    def test_endpoint_evidence_only_emits_allowlisted_router_identifiers(self) -> None:
        body = (
            b'<html><a href="/?_type=menuView&_tag=statusMgr">known</a>'
            b'<a href="/?_type=CustomerAlice&_tag=Subscriber.Alice">private</a>'
            b"<CustomerAlice><Subscriber.Alice>private</Subscriber.Alice></CustomerAlice>"
            b"<ParaName>SoftwareVersion</ParaName>"
            b"<ParaName>CustomerAlice</ParaName>"
            b"<ParaName>Subscriber.Alice</ParaName>"
            b'<script>_PageAccessAuthor["tr069"] = '
            b'{"VisibilityLevel":3,"Limitation":1};'
            b'_PageAccessAuthor["CustomerAlice"] = '
            b'{"VisibilityLevel":3,"Limitation":1};'
            b'_PageAccessAuthor["Subscriber.Alice"] = '
            b'{"VisibilityLevel":2,"Limitation":1};</script></html>'
        )
        evidence = _endpoint_evidence(
            response(body, content_type="text/html"),
            expected_firmware="firmware",
            expected_model="model",
            expected_hardware="hardware",
        )

        self.assertEqual(evidence["route_types"], ["menuView"])
        self.assertEqual(evidence["route_tags"], ["statusMgr"])
        self.assertEqual(evidence["xml_element_names"], ["ParaName", "a", "html", "script"])
        self.assertEqual(evidence["parameter_names"], ["SoftwareVersion"])
        self.assertEqual(
            evidence["page_access_entries"],
            [{"page_id": "tr069", "visibility_level": 3, "limitation": 1}],
        )
        self.assertEqual(
            evidence["redacted_unique_structural_identifier_counts"],
            {
                "route_types": 1,
                "route_tags": 1,
                "xml_element_names": 2,
                "parameter_names": 2,
                "page_ids": 2,
                "html_element_ids": 0,
                "html_field_names": 0,
                "config_object_ids": 0,
                "lua_resource_names": 0,
            },
        )
        self.assertFalse(evidence["structural_identifier_limit_reached"])
        serialized = json.dumps(evidence, sort_keys=True).casefold()
        self.assertNotIn("customeralice", serialized)
        self.assertNotIn("subscriber.alice", serialized)

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
