# SPDX-License-Identifier: 0BSD
"""Structured hostile-input and preservation regressions for offline config work."""

from __future__ import annotations

import io
import struct
import unittest
import zlib
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from xml.etree import ElementTree as ET

import cpe_access_atlas.config as config
from cpe_access_atlas.catalog import find_recipe, load_recipes
from cpe_access_atlas.cli import main
from cpe_access_atlas.config import ConfigError, decode_config, encode_config, patch_root_ssh

TARGET = [
    "--isp",
    "turk-telekom",
    "--model",
    "H3600P",
    "--hardware-revision",
    "V9.0",
    "--firmware",
    "H3600P V9.0 TTN.10_260210",
]


def compressed_chunks(chunks: list[bytes], declared_size: int) -> bytes:
    compressed = [zlib.compress(chunk) for chunk in chunks]
    combined = b"".join(compressed)
    header = struct.pack(
        ">6I",
        config.PAYLOAD_MAGIC,
        0,
        declared_size,
        len(combined),
        declared_size,
        zlib.crc32(combined),
    )
    return (
        header
        + struct.pack(">I", zlib.crc32(header))
        + bytes(32)
        + b"".join(
            struct.pack(">3I", len(chunk), len(packed), int(index < len(chunks) - 1)) + packed
            for index, (chunk, packed) in enumerate(zip(chunks, compressed, strict=True))
        )
    )


class ConfigSafetyTests(unittest.TestCase):
    def test_combined_chunk_budget_is_enforced_before_second_decompression(self) -> None:
        # Small limits make this deterministic without allocating a decompression bomb.
        artifact = compressed_chunks([b"a" * 128, b"b" * 128], 128)
        real_decompressobj = zlib.decompressobj
        with (
            patch.object(config, "_MAX_XML_BYTES", 128),
            patch.object(config.zlib, "decompressobj", wraps=real_decompressobj) as decompress,
        ):
            with self.assertRaisesRegex(ConfigError, "total size limit"):
                decode_config(artifact)
        self.assertEqual(decompress.call_count, 1)

    def test_declared_lengths_cannot_hide_expansion(self) -> None:
        artifact = bytearray(compressed_chunks([b"a" * 128, b"b" * 128], 128))
        first_length = len(zlib.compress(b"a" * 128))
        struct.pack_into(">I", artifact, 60 + 12 + first_length, 0)
        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            decode_config(bytes(artifact))

    def test_valid_multichunk_config_still_round_trips(self) -> None:
        chunks = [b"<DB>", b"<value>kept</value>", b"</DB>"]
        self.assertEqual(decode_config(compressed_chunks(chunks, 28)).xml, b"".join(chunks))

    def test_trailing_data_and_unterminated_containers_are_rejected(self) -> None:
        raw = encode_config(b"<DB/>", base64_wrap=False)
        with self.assertRaisesRegex(ConfigError, "trailing data"):
            decode_config(raw + b"unexpected bytes")
        unfinished = bytearray(raw)
        struct.pack_into(">I", unfinished, 68, 1)
        with self.assertRaisesRegex(ConfigError, "continuation chunk header"):
            decode_config(bytes(unfinished))
        with self.assertRaisesRegex(ConfigError, "trailing data"):
            config._read_chunks(io.BytesIO(struct.pack(">3I", 16, 16, 0) + bytes(17)))

    def test_chunk_lengths_and_compressed_stream_consumption_are_checked(self) -> None:
        raw = encode_config(b"<DB/>", base64_wrap=False)
        invalid_plain_length = bytearray(raw)
        struct.pack_into(">I", invalid_plain_length, 60, 4)
        with self.assertRaisesRegex(ConfigError, "chunk length is invalid"):
            decode_config(bytes(invalid_plain_length))

        short_compressed_budget = bytearray(raw)
        struct.pack_into(">I", short_compressed_budget, 12, len(raw) - 73)
        struct.pack_into(
            ">I", short_compressed_budget, 24, zlib.crc32(short_compressed_budget[:24])
        )
        with self.assertRaisesRegex(ConfigError, "compressed length exceeds"):
            decode_config(bytes(short_compressed_budget))

        extra_zlib_data = bytearray(raw + b"x")
        compressed_length = len(extra_zlib_data) - 72
        struct.pack_into(">I", extra_zlib_data, 12, compressed_length)
        struct.pack_into(">I", extra_zlib_data, 64, compressed_length)
        struct.pack_into(">I", extra_zlib_data, 20, zlib.crc32(extra_zlib_data[72:]))
        struct.pack_into(">I", extra_zlib_data, 24, zlib.crc32(extra_zlib_data[:24]))
        with self.assertRaisesRegex(ConfigError, "chunk contains trailing data"):
            decode_config(bytes(extra_zlib_data))

    def test_encrypted_chunk_total_is_bounded(self) -> None:
        stream = io.BytesIO(
            struct.pack(">3I", 16, 16, 1) + bytes(16) + struct.pack(">3I", 16, 16, 0) + bytes(16)
        )
        with patch.object(config, "_MAX_COMPRESSED_BYTES", 16):
            with self.assertRaisesRegex(ConfigError, "chunk total"):
                config._read_chunks(stream)

    def test_doctype_rejection_does_not_depend_on_encoding(self) -> None:
        xml = '<!DOCTYPE DB [<!ENTITY dummy "synthetic">]><DB>&dummy;</DB>'
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                with self.assertRaisesRegex(ConfigError, "DTDs or entities"):
                    patch_root_ssh(xml.encode(encoding), "DummyPass123")

    def test_utf16_without_doctype_remains_supported(self) -> None:
        output = patch_root_ssh("<DB><Value>şifre</Value></DB>".encode("utf-16"), "DummyPass123")
        self.assertEqual(ET.fromstring(output).findtext("Value"), "şifre")

    def test_unknown_xml_encoding_is_a_controlled_error(self) -> None:
        with self.assertRaisesRegex(ConfigError, "XML is invalid"):
            patch_root_ssh(
                b'<?xml version="1.0" encoding="unknown-encoding"?><DB/>', "DummyPass123"
            )

    def test_unsupported_multibyte_encodings_are_controlled_errors(self) -> None:
        for encoding in ("utf-7", "shift_jis"):
            xml = f'<?xml version="1.0" encoding="{encoding}"?><DB/>'
            with (
                self.subTest(encoding=encoding),
                self.assertRaisesRegex(ConfigError, "XML is invalid"),
            ):
                patch_root_ssh(xml.encode(encoding), "DummyPass123")

    def test_depth_and_node_counts_are_bounded_during_parsing(self) -> None:
        deep = b"<DB>" + b"<n>" * 1500 + b"</n>" * 1500 + b"</DB>"
        with self.assertRaisesRegex(ConfigError, "nesting or element"):
            patch_root_ssh(deep, "DummyPass123")
        for node in (b"<n/>", b"<!--kept-->", b"<?kept value?>"):
            with self.subTest(node=node), patch.object(config, "_MAX_XML_ELEMENTS", 3):
                with self.assertRaisesRegex(ConfigError, "nesting or element"):
                    patch_root_ssh(b"<DB>" + node * 4 + b"</DB>", "DummyPass123")

    def test_unrelated_settings_and_additional_rows_are_preserved(self) -> None:
        source = b"""<DB><!--keep--><?vendor keep?>
        <Tbl name="Internet"><Row No="0"><DM name="VLAN" val="35"/></Row></Tbl>
        <Tbl name="SSHCfg" RowCount="2"><Row No="0"/>
        <Row No="1"><DM name="SSH_Enable" val="0"/></Row></Tbl></DB>"""
        output = patch_root_ssh(source, "DummyPass123")
        root = ET.fromstring(output)
        self.assertIn(b"<!--keep-->", output)
        self.assertIn(b"<?vendor keep?>", output)
        self.assertEqual(root.find("./Tbl[@name='Internet']/Row/DM").get("val"), "35")
        table = root.find("./Tbl[@name='SSHCfg']")
        self.assertEqual(table.get("RowCount"), "2")
        self.assertEqual(len(table.findall("Row")), 2)
        self.assertEqual(table.find("./Row[@No='1']/DM").get("val"), "0")

    def test_ambiguous_ssh_tables_and_fields_are_rejected(self) -> None:
        for xml in (
            b'<DB><Tbl name="SSHCfg"/><Tbl name="SSHCfg"/></DB>',
            b'<DB><Tbl name="SSHCfg"><Row><DM name="SSH_Enable" val="0"/>'
            b'<DM name="SSH_Enable" val="1"/></Row></Tbl></DB>',
        ):
            with self.subTest(xml=xml), self.assertRaisesRegex(ConfigError, "ambiguous duplicate"):
                patch_root_ssh(xml, "DummyPass123")

    def test_patched_xml_cannot_exceed_the_limit(self) -> None:
        with patch.object(config, "_MAX_XML_BYTES", 32):
            with self.assertRaisesRegex(ConfigError, "patched configuration"):
                patch_root_ssh(b"<DB/>", "DummyPass123")

    def test_signature_size_limits_on_decode_inspection_and_encode(self) -> None:
        for size in (0, 129):
            artifact = struct.pack(">3I", config.SIGNATURE_MAGIC, 0, size) + bytes(size)
            for operation in (decode_config, config.inspect_config):
                with self.subTest(size=size, operation=operation.__name__):
                    with self.assertRaisesRegex(ConfigError, "signature length"):
                        operation(artifact)
        with self.assertRaisesRegex(ConfigError, "signature"):
            encode_config(b"<DB/>", signature="a" * 129)

    def test_xml_baselines_are_read_with_a_limit(self) -> None:
        stream = io.BytesIO(b"x" * 17)
        with (
            patch.object(config, "_MAX_XML_BYTES", 16),
            patch.object(Path, "open", return_value=stream),
        ):
            with self.assertRaisesRegex(ConfigError, "safety size limit"):
                config.read_private_config("synthetic.xml", xml=True)


class CodecSelectionTests(unittest.TestCase):
    def test_cli_rejects_unsupported_xml_encoding_without_a_traceback_or_artifact(self) -> None:
        with TemporaryDirectory() as directory:
            source, output = Path(directory) / "input.xml", Path(directory) / "output.bin"
            source.write_bytes(b'<?xml version="1.0" encoding="shift_jis"?><DB/>')
            out, err = io.StringIO(), io.StringIO()
            with patch("cpe_access_atlas.cli.getpass.getpass", return_value="DummyPass123"):
                with redirect_stdout(out), redirect_stderr(err):
                    code = main(
                        [
                            "config-generate",
                            *TARGET,
                            "--input-xml",
                            str(source),
                            "--output",
                            str(output),
                            "--allow-unencrypted",
                            "--i-own-or-administer-this-device",
                        ]
                    )
            self.assertEqual(code, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), "ERROR: configuration XML is invalid\n")
            self.assertFalse(output.exists())

    def assert_rejected_before_secret_input(self, args: list[str], message: str) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "output.bin"
            out, err = io.StringIO(), io.StringIO()
            with patch("cpe_access_atlas.cli.getpass.getpass") as prompt:
                with redirect_stdout(out), redirect_stderr(err):
                    code = main(
                        [
                            "config-generate",
                            *args,
                            "--output",
                            str(target),
                            "--allow-unencrypted",
                            "--i-own-or-administer-this-device",
                        ]
                    )
            self.assertEqual(code, 2)
            self.assertIn(message, err.getvalue())
            self.assertFalse(target.exists())
            prompt.assert_not_called()

    def test_unrelated_model_cannot_select_the_h3600p_codec(self) -> None:
        recipe = next(item for item in load_recipes() if item.vendor == "Zyxel")
        self.assert_rejected_before_secret_input(
            [
                "--isp",
                recipe.isp_id,
                "--model",
                recipe.model,
                "--hardware-revision",
                recipe.hardware_revision,
                "--firmware",
                recipe.firmware,
            ],
            "no compatible offline",
        )

    def test_catalog_capability_and_model_are_both_required(self) -> None:
        recipe = find_recipe("turk-telekom", "H3600P", "V9.0", "H3600P V9.0 TTN.10_260210")
        for change in (
            {"model": "H3600"},
            {"hardware_revision": "V10.0"},
            {"capabilities": ()},
        ):
            with (
                self.subTest(change=change),
                patch(
                    "cpe_access_atlas.cli._recipe_from_args", return_value=replace(recipe, **change)
                ),
            ):
                self.assert_rejected_before_secret_input(TARGET, "no compatible offline")

    def test_output_signature_must_match_selected_codec(self) -> None:
        self.assert_rejected_before_secret_input(
            [*TARGET, "--signature", "OTHER DEVICE"], "signature must match"
        )

    def test_baseline_signature_must_match_before_prompting(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(
                encode_config(
                    b"<DB/>",
                    signature="OTHER DEVICE",
                    encrypted=True,
                    device_key="a" * 32,
                    serial="ZTE12345678",
                    mac="00:11:22:33:44:55",
                )
            )
            self.assert_rejected_before_secret_input(
                [*TARGET, "--input-config", str(source)],
                "baseline signature",
            )
