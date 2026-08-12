# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import ipaddress
import itertools
import unittest
from unittest.mock import MagicMock, patch

from cpe_access_atlas.policy import (
    PolicyError,
    parse_ports,
    parse_single_private_address,
    parse_timeout,
    probe_tcp_ports,
)


class PolicyTests(unittest.TestCase):
    def test_accepts_rfc1918_addresses(self) -> None:
        self.assertEqual(
            parse_single_private_address("192.168.1.1"),
            ipaddress.ip_address("192.168.1.1"),
        )
        self.assertEqual(
            parse_single_private_address("172.16.0.1"),
            ipaddress.ip_address("172.16.0.1"),
        )
        self.assertEqual(
            parse_single_private_address("10.0.0.1"),
            ipaddress.ip_address("10.0.0.1"),
        )

    def test_accepts_ipv6_ula(self) -> None:
        self.assertEqual(
            parse_single_private_address("fd00::1"),
            ipaddress.ip_address("fd00::1"),
        )

    def test_rejects_public_loopback_link_local_and_unspecified(self) -> None:
        for value in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "0.0.0.0", "::1"):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_single_private_address(value)

    def test_rejects_hostname_cidr_and_target_list(self) -> None:
        for value in (
            "router.local",
            "192.168.1.0/24",
            "192.168.1.1,192.168.1.2",
            "192.168.1.1 192.168.1.2",
        ):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_single_private_address(value)
        for value in (None, "fd00::1%12", "192.168.1.1\t192.168.1.2"):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_single_private_address(value)  # type: ignore[arg-type]

    def test_explicit_ports_only(self) -> None:
        self.assertEqual(parse_ports("80,443,80"), (80, 443))
        for value in ("1-1024", "0", "65536", "80,abc", ""):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_ports(value)
        with self.assertRaises(PolicyError):
            parse_ports("1,2,3,4,5,6,7,8,9")
        with self.assertRaises(PolicyError):
            parse_ports(None)  # type: ignore[arg-type]
        with self.assertRaises(PolicyError):
            parse_ports("\u0661")
        with self.assertRaises(PolicyError):
            parse_ports("9" * 5000)

    def test_timeout_is_finite_and_bounded(self) -> None:
        self.assertEqual(parse_timeout("1.5"), 1.5)
        for value in ("0", "-1", "31", "nan", "inf", "not-a-number", True, False):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_timeout(value)

    def test_probe_reports_success_and_socket_failure(self) -> None:
        connected = MagicMock()
        with patch(
            "cpe_access_atlas.policy.socket.create_connection",
            side_effect=[connected, OSError("closed")],
        ) as create_connection:
            results = probe_tcp_ports("192.168.1.1", (80, 443), timeout=2)
        self.assertEqual(results, {80: True, 443: False})
        self.assertEqual(create_connection.call_count, 2)

    def test_probe_rejects_public_target_before_opening_socket(self) -> None:
        with patch("cpe_access_atlas.policy.socket.create_connection") as create_connection:
            with self.assertRaises(PolicyError):
                probe_tcp_ports("8.8.8.8", (443,))
        create_connection.assert_not_called()

    def test_probe_rejects_invalid_or_unbounded_ports_before_opening_socket(self) -> None:
        for ports in (
            None,
            (),
            tuple(range(1, 10)),
            itertools.count(1),
            (0,),
            (65536,),
            ("443",),
            (True,),
        ):
            with self.subTest(ports=ports):
                with patch("cpe_access_atlas.policy.socket.create_connection") as create_connection:
                    with self.assertRaises(PolicyError):
                        probe_tcp_ports("192.168.1.1", ports)
                create_connection.assert_not_called()

    def test_probe_deduplicates_valid_ports(self) -> None:
        connected = MagicMock()
        with patch(
            "cpe_access_atlas.policy.socket.create_connection",
            return_value=connected,
        ) as create_connection:
            results = probe_tcp_ports("192.168.1.1", (80, 80, 443))
        self.assertEqual(results, {80: True, 443: True})
        self.assertEqual(create_connection.call_count, 2)


if __name__ == "__main__":
    unittest.main()
