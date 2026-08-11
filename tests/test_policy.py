# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import ipaddress
import unittest

from cpe_access_atlas.policy import PolicyError, parse_ports, parse_single_private_address


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

    def test_explicit_ports_only(self) -> None:
        self.assertEqual(parse_ports("80,443,80"), (80, 443))
        for value in ("1-1024", "0", "65536", "80,abc", ""):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_ports(value)


if __name__ == "__main__":
    unittest.main()
