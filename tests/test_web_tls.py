# SPDX-License-Identifier: 0BSD
"""Real TLS/HTTP integration, with ephemeral synthetic certificates and loopback I/O."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import traceback
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch
from urllib.parse import parse_qs

from Crypto.Hash import SHA256
from Crypto.IO import PEM
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.asn1 import DerInteger, DerNull, DerObjectId

from cpe_access_atlas.web_evidence import WebEvidenceError, _request, collect_zte_web_evidence

TARGET = "192.168.50.1"
_CONNECT = socket.create_connection


def _der(tag: int, payload: bytes) -> bytes:
    length = len(payload)
    encoded = length.to_bytes(max(1, (length.bit_length() + 7) // 8), "big")
    return (
        bytes([tag])
        + (bytes([length]) if length < 128 else bytes([128 | len(encoded)]) + encoded)
        + payload
    )


def _sequence(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def _oid(value: str) -> bytes:
    return DerObjectId(value).encode()


def _name(value: str) -> bytes:
    return _sequence(_der(0x31, _sequence(_oid("2.5.4.3"), _der(0x0C, value.encode()))))


def _extension(oid: str, value: bytes, *, critical: bool = False) -> bytes:
    return _sequence(_oid(oid), b"\x01\x01\xff" if critical else b"", _der(4, value))


def _certificate(
    key: RSA.RsaKey,
    issuer_key: RSA.RsaKey,
    *,
    ca: bool = False,
    address: str = TARGET,
    expired: bool = False,
) -> str:
    """Minimal X.509 v3 fixture with strict CA, usage, SAN, and key identifiers."""
    now = datetime.now(UTC)
    before, after = now - timedelta(days=30), now + timedelta(days=30)
    if expired:
        after = now - timedelta(days=2)

    def date(value: datetime) -> bytes:
        if value.year < 2050:
            return _der(0x17, value.strftime("%y%m%d%H%M%SZ").encode())
        return _der(0x18, value.strftime("%Y%m%d%H%M%SZ").encode())

    public = key.public_key().export_key(format="DER")
    key_id = hashlib.sha256(public).digest()[:20]
    issuer_id = hashlib.sha256(issuer_key.public_key().export_key(format="DER")).digest()[:20]
    algorithm = _sequence(_oid("1.2.840.113549.1.1.11"), DerNull().encode())
    extensions = [
        _extension(
            "2.5.29.19",
            _sequence(b"\x01\x01\xff", DerInteger(0).encode()) if ca else _sequence(),
            critical=True,
        ),
        _extension("2.5.29.15", _der(3, b"\x01\x06" if ca else b"\x05\xa0"), critical=True),
        _extension("2.5.29.14", _der(4, key_id)),
        _extension("2.5.29.35", _sequence(_der(0x80, issuer_id))),
    ]
    if not ca:
        extensions.extend(
            [
                _extension(
                    "2.5.29.17", _sequence(_der(0x87, ipaddress.ip_address(address).packed))
                ),
                _extension("2.5.29.37", _sequence(_oid("1.3.6.1.5.5.7.3.1"))),
            ]
        )
    unsigned = _sequence(
        _der(0xA0, DerInteger(2).encode()),
        DerInteger(1 if ca else 2).encode(),
        algorithm,
        _name("Synthetic loopback CA"),
        _sequence(date(before), date(after)),
        _name("Synthetic loopback CA" if ca else "Synthetic loopback server"),
        public,
        _der(0xA3, _sequence(*extensions)),
    )
    signature = pkcs1_15.new(issuer_key).sign(SHA256.new(unsigned))
    return PEM.encode(_sequence(unsigned, algorithm, _der(3, b"\0" + signature)), "CERTIFICATE")


def _http(body: bytes, content_type: str = "text/plain") -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
        f"Content-Type: {content_type}\r\nSet-Cookie: SID=synthetic-session; Path=/\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body


class _LoopbackTLS:
    def __init__(
        self,
        context: ssl.SSLContext,
        responses: list[bytes],
        *,
        stall: bool = False,
        connect_delay: float = 0,
        handshake_delay: float = 0,
        response_delay: float = 0,
    ) -> None:
        self.context = context
        self.responses = responses
        self.stall = stall
        self.connect_delay = connect_delay
        self.handshake_delay = handshake_delay
        self.response_delay = response_delay
        self.requests: list[bytes] = []
        self.prefixes: list[bytes] = []
        self.errors: list[Exception] = []
        self.connections: list[tuple[str, int]] = []
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def connect(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        # Only routing changes. TLS still verifies the original RFC1918 IP literal.
        self.connections.append(address)
        if address != (TARGET, 443):
            raise AssertionError(f"unexpected connection/fallback: {address}")
        # Deterministically account for TCP setup time without a remote target.
        time.sleep(self.connect_delay)
        return _CONNECT(("127.0.0.1", self.port), timeout, source_address)

    def serve(self) -> None:
        while not self.stop.is_set():
            try:
                peer, _address = self.listener.accept()
            except TimeoutError:
                continue
            try:
                with peer:
                    peer.settimeout(2)
                    self.prefixes.append(peer.recv(5, socket.MSG_PEEK))
                    if self.stall:
                        self.stop.wait(2)
                        continue
                    self.stop.wait(self.handshake_delay)
                    with self.context.wrap_socket(peer, server_side=True) as tls:
                        request = bytearray()
                        while b"\r\n\r\n" not in request:
                            block = tls.recv(4096)
                            if not block:
                                raise RuntimeError("client closed before complete HTTP headers")
                            request.extend(block)
                        header, body = bytes(request).split(b"\r\n\r\n", 1)
                        lengths = [
                            int(line.split(b":", 1)[1])
                            for line in header.split(b"\r\n")
                            if line.lower().startswith(b"content-length:")
                        ]
                        length = lengths[0] if lengths else 0
                        while len(body) < length:
                            block = tls.recv(4096)
                            if not block:
                                raise RuntimeError("client closed before complete HTTP body")
                            body += block
                        self.requests.append(header + b"\r\n\r\n" + body)
                        self.stop.wait(self.response_delay)
                        tls.sendall(self.responses[len(self.requests) - 1])
            except OSError as error:
                self.errors.append(error)
            except Exception as error:
                self.errors.append(error)

    @contextmanager
    def running(self):
        self.thread.start()
        try:
            with patch("socket.create_connection", side_effect=self.connect):
                yield self
        finally:
            self.stop.set()
            self.thread.join(timeout=3)
            self.listener.close()
            if self.thread.is_alive():
                raise AssertionError("loopback TLS fixture did not stop")


class WebTLSIntegrationTests(unittest.TestCase):
    ca_pem: ClassVar[str]
    server_contexts: ClassVar[dict[str, ssl.SSLContext]]
    directory: ClassVar[Path]

    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        ca_key, server_key = RSA.generate(2048), RSA.generate(2048)
        cls.ca_pem = _certificate(ca_key, ca_key, ca=True)
        key_path = cls.directory / "ephemeral-server-key.pem"
        key_path.write_bytes(server_key.export_key(format="PEM", pkcs=8))
        cls.server_contexts = {}
        for name, arguments in (
            ("trusted", {}),
            ("wrong_ip", {"address": "192.168.50.2"}),
            ("expired", {"expired": True}),
        ):
            cert_path = cls.directory / f"{name}.pem"
            cert_path.write_text(_certificate(server_key, ca_key, **arguments), encoding="ascii")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert_path, key_path)
            cls.server_contexts[name] = context

    def client_context(self, *, trust_ca: bool = True) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        if trust_ca:
            context.load_verify_locations(cadata=self.ca_pem)
        return context

    def test_trusted_tls_collects_once_without_key_logging_or_secret_output(self) -> None:
        responses = [
            _http(b'{"lockingTime":0,"sess_token":"synthetic-token"}', "application/json"),
            _http(
                b"<ajax_response_xml_root>synthetic-challenge</ajax_response_xml_root>", "text/xml"
            ),
            _http(b'{"login_need_refresh":true}', "application/json"),
            _http(b"<html>H3600P V9 synthetic-build</html>", "text/html"),
            _http(b"<html>statusMgr</html>", "text/html"),
            _http(b"<root><ParaName>SoftwareVersion</ParaName></root>", "text/xml"),
        ]
        server = _LoopbackTLS(self.server_contexts["trusted"], responses)
        key_log = self.directory / "must-not-exist.keys"
        with server.running(), patch.dict(os.environ, {"SSLKEYLOGFILE": str(key_log)}):
            result = collect_zte_web_evidence(
                TARGET,
                "synthetic-user",
                "synthetic-password",
                timeout=2,
                expected_model="H3600P",
                expected_firmware="synthetic-build",
                expected_hardware="V9",
                tls_ca_pem=self.ca_pem,
            )
        self.assertEqual(result["transport"], "local-https")
        self.assertIs(result["tls_peer_verified"], True)
        self.assertEqual(result["tls_trust_source"], "provided-ca")
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["login_attempts"], 1)
        self.assertEqual(len(server.requests), 6)
        self.assertEqual(server.connections, [(TARGET, 443)] * 6)
        self.assertEqual(server.errors, [])
        posts = [request for request in server.requests if request.startswith(b"POST ")]
        self.assertEqual(len(posts), 1)
        form = parse_qs(posts[0].split(b"\r\n\r\n", 1)[1].decode())
        self.assertEqual(form["Username"], ["synthetic-user"])
        self.assertEqual(
            form["Password"], [hashlib.sha256(b"synthetic-passwordsynthetic-challenge").hexdigest()]
        )
        self.assertFalse(key_log.exists())
        serialized = json.dumps(result)
        for private in (
            "synthetic-password",
            "synthetic-user",
            "synthetic-token",
            "synthetic-session",
        ):
            self.assertNotIn(private, serialized)

    def test_untrusted_wrong_ip_and_expired_certificates_never_receive_http(self) -> None:
        for name, trusted, verify_code in (
            ("trusted", False, 20),
            ("wrong_ip", True, 64),
            ("expired", True, 10),
        ):
            with self.subTest(certificate=name, trust_ca=trusted):
                server = _LoopbackTLS(self.server_contexts[name], [_http(b"unexpected")])
                with server.running():
                    with self.assertRaises(WebEvidenceError) as raised:
                        _request(
                            TARGET,
                            "POST",
                            "/",
                            1,
                            {"SID": "private-cookie"},
                            b"Username=synthetic-user&Password=must-not-arrive",
                            tls_context=self.client_context(trust_ca=trusted),
                        )
                self.assertIsInstance(raised.exception.__cause__, ssl.SSLCertVerificationError)
                self.assertEqual(raised.exception.__cause__.verify_code, verify_code)
                self.assertEqual(server.requests, [])
                self.assertEqual(server.connections, [(TARGET, 443)])
                self.assertEqual(len(server.prefixes), 1)
                self.assertEqual(server.prefixes[0][:1], b"\x16")
                self.assertNotIn("must-not-arrive", str(raised.exception))

    def test_stalled_handshake_uses_deadline_without_plaintext_fallback(self) -> None:
        server = _LoopbackTLS(self.server_contexts["trusted"], [], stall=True)
        with server.running():
            started = time.monotonic()
            with self.assertRaises(WebEvidenceError) as raised:
                _request(
                    TARGET,
                    "POST",
                    "/",
                    0.2,
                    {},
                    b"must-not-arrive",
                    tls_context=self.client_context(),
                )
            elapsed = time.monotonic() - started
        self.assertIsInstance(raised.exception.__context__, TimeoutError)
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)
        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertIn("unable to complete the bounded local HTTPS request", rendered)
        self.assertNotIn("TimeoutError:", rendered)
        self.assertNotIn("must-not-arrive", rendered)
        self.assertLess(elapsed, 1)
        self.assertEqual(server.requests, [])
        self.assertEqual(server.connections, [(TARGET, 443)])
        self.assertEqual(server.prefixes[0][:1], b"\x16")

    def test_connect_tls_and_response_share_one_deadline(self) -> None:
        # Each phase fits within five seconds, but their sum does not. Leave
        # real TLS and runner scheduling enough headroom to reach HTTP before
        # the shared deadline expires; resetting it per phase would succeed.
        server = _LoopbackTLS(
            self.server_contexts["trusted"],
            [_http(b"too late")],
            connect_delay=1,
            handshake_delay=1,
            response_delay=3.5,
        )
        with server.running():
            with self.assertRaises(WebEvidenceError) as raised:
                _request(TARGET, "GET", "/", 5, {}, tls_context=self.client_context())
        self.assertIsInstance(raised.exception.__context__, TimeoutError)
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)
        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertIn("unable to complete the bounded local HTTPS request", rendered)
        self.assertNotIn("TimeoutError:", rendered)
        self.assertEqual(server.connections, [(TARGET, 443)])
        self.assertEqual(len(server.requests), 1)

    def test_real_tls_preserves_chunked_precedence_and_rejects_truncated_length(self) -> None:
        cases = (
            (b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nshort", None),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n"
                b"Connection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n",
                b"ok",
            ),
        )
        for wire, expected in cases:
            with self.subTest(expected=expected):
                server = _LoopbackTLS(self.server_contexts["trusted"], [wire])
                with server.running():
                    if expected is None:
                        with self.assertRaisesRegex(WebEvidenceError, "Content-Length"):
                            _request(TARGET, "GET", "/", 1, {}, tls_context=self.client_context())
                    else:
                        self.assertEqual(
                            _request(
                                TARGET, "GET", "/", 1, {}, tls_context=self.client_context()
                            ).body,
                            expected,
                        )
                self.assertEqual(server.connections, [(TARGET, 443)])
                self.assertEqual(len(server.requests), 1)


if __name__ == "__main__":
    unittest.main()
