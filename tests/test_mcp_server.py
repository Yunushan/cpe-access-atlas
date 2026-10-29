from __future__ import annotations

import ast
import json
import unittest
from dataclasses import replace
from io import BytesIO
from itertools import product
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cpe_access_atlas.catalog import find_recipe
from cpe_access_atlas.mcp_server import (
    MCP_PROTOCOL_VERSION,
    TOOL_NAMES,
    _write_message,
    run_stdio,
    serve,
)

ROOT = Path(__file__).parents[1]
TARGET = {
    "isp": "turk-telekom",
    "model": "ZTE H3600P",
    "hardware_revision": "V9.0",
    "firmware": "H3600P V9.0 TTN.10_260210",
}


def _request(method: str, request_id: str | int, params: object = None) -> bytes:
    message: dict[str, object] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


def _modern_params(params: dict[str, object] | None = None) -> dict[str, object]:
    result = dict(params or {})
    result["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
    }
    return result


def _run(payload: bytes) -> tuple[int, list[dict[str, object]], bytes]:
    output = BytesIO()
    code = serve(BytesIO(payload), output)
    lines = output.getvalue().splitlines()
    return code, [json.loads(line) for line in lines], output.getvalue()


class McpServerTests(unittest.TestCase):
    def test_modern_discovery_lists_only_allowlisted_read_only_tools(self) -> None:
        payload = _request("server/discover", 1, _modern_params())
        payload += _request("tools/list", 2, _modern_params())
        code, responses, _ = _run(payload)
        self.assertEqual(code, 0)
        discovery = responses[0]["result"]
        listing = responses[1]["result"]
        self.assertEqual(discovery["supportedVersions"], [MCP_PROTOCOL_VERSION])
        self.assertEqual(discovery["capabilities"], {"tools": {}})
        self.assertEqual(discovery["resultType"], "complete")
        self.assertEqual(discovery["ttlMs"], 300_000)
        self.assertEqual(discovery["cacheScope"], "public")
        self.assertEqual(listing["resultType"], "complete")
        self.assertEqual(listing["ttlMs"], 300_000)
        self.assertEqual(listing["cacheScope"], "public")
        tools = listing["tools"]
        self.assertEqual({item["name"] for item in tools}, set(TOOL_NAMES))
        self.assertEqual(len(tools), len(TOOL_NAMES))
        self.assertNotIn("firmware-inspect", TOOL_NAMES)
        self.assertNotIn("config-generate", TOOL_NAMES)
        self.assertNotIn("web-evidence", TOOL_NAMES)
        self.assertNotIn("uart-evidence", TOOL_NAMES)

    def test_modern_tool_call_returns_versioned_public_provider_data(self) -> None:
        payload = _request("tools/call", 1, _modern_params({"name": "providers", "arguments": {}}))
        code, responses, _ = _run(payload)
        self.assertEqual(code, 0)
        result = responses[0]["result"]
        self.assertEqual(result["resultType"], "complete")
        data = json.loads(result["content"][0]["text"])
        self.assertEqual(data["schema_version"], "1")
        self.assertTrue(data["data"])
        self.assertIn("name", data["data"][0])

    def test_notification_without_request_id_is_ignored(self) -> None:
        notification = (
            json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/cancelled"},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        code, responses, output = _run(notification)
        self.assertEqual(code, 0)
        self.assertEqual(responses, [])
        self.assertEqual(output, b"")

    def test_legacy_request_shape_without_request_metadata_is_rejected(self) -> None:
        payload = _request("tools/call", 1, {"name": "providers", "arguments": {}})
        code, responses, _ = _run(payload)
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["error"]["code"], -32602)

    def test_initialize_request_is_rejected_as_an_unknown_method(self) -> None:
        init = _request("initialize", 1, {"protocolVersion": "1900-01-01"})
        code, responses, _ = _run(init)
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["error"]["code"], -32601)
        self.assertIn(MCP_PROTOCOL_VERSION, responses[0]["error"]["message"])

    def test_parameterized_catalog_tools_use_exact_target_and_read_only_root_gate(self) -> None:
        calls = []
        for request_id, name in enumerate(("status", "evidence", "plan", "root_readiness"), 1):
            calls.append(
                _request(
                    "tools/call",
                    request_id,
                    _modern_params({"name": name, "arguments": TARGET}),
                )
            )
        code, responses, _ = _run(b"".join(calls))
        self.assertEqual(code, 0)
        results = [json.loads(item["result"]["content"][0]["text"]) for item in responses]
        self.assertEqual([item["schema_version"] for item in results], ["1"] * 4)
        self.assertEqual(
            results[0]["data"]["id"], "tr.turk-telekom.zte.h3600p.h3600p-v9-ttn10-260210"
        )
        self.assertIsInstance(results[1]["data"], list)
        self.assertEqual(results[2]["data"]["decision"], "STOP")
        readiness = results[3]["data"]
        self.assertFalse(readiness["device_io_attempted"])
        self.assertFalse(readiness["config_or_firmware_written"])
        self.assertFalse(readiness["checks"]["firmware_artifact_supplied"])

    def test_devices_filter_is_validated_and_applied(self) -> None:
        params = _modern_params({"name": "devices", "arguments": {"isp": "turk-telekom"}})
        code, responses, _ = _run(_request("tools/call", 1, params))
        self.assertEqual(code, 0)
        result = json.loads(responses[0]["result"]["content"][0]["text"])
        self.assertTrue(result["data"])
        self.assertTrue(all(item["provider_id"] == "turk-telekom" for item in result["data"]))

    def test_unknown_tool_and_invalid_arguments_return_invalid_params(self) -> None:
        unknown = _request("tools/call", 1, _modern_params({"name": "apply", "arguments": {}}))
        invalid = _request(
            "tools/call",
            2,
            _modern_params({"name": "providers", "arguments": {"unexpected": True}}),
        )
        code, responses, _ = _run(unknown + invalid)
        self.assertEqual(code, 0)
        self.assertEqual([item["error"]["code"] for item in responses], [-32602, -32602])

    def test_missing_modern_protocol_metadata_is_rejected(self) -> None:
        params = {
            "_meta": {
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
            }
        }
        code, responses, _ = _run(_request("tools/list", 1, params))
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["error"]["code"], -32602)

    def test_unsupported_modern_version_includes_requested_and_supported(self) -> None:
        params = {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "1900-01-01",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
            }
        }
        code, responses, _ = _run(_request("tools/list", 1, params))
        self.assertEqual(code, 0)
        error = responses[0]["error"]
        self.assertEqual(error["code"], -32022)
        self.assertEqual(
            error["data"], {"supported": [MCP_PROTOCOL_VERSION], "requested": "1900-01-01"}
        )

    def test_unsupported_tool_requests_never_reach_catalog_handlers(self) -> None:
        for method in ("tools/list", "tools/call"):
            with self.subTest(method=method):
                params = _modern_params({"name": "providers", "arguments": {}})
                params["_meta"]["io.modelcontextprotocol/protocolVersion"] = "1900-01-01"
                with patch("cpe_access_atlas.mcp_server._tool_data") as handler:
                    code, responses, _ = _run(_request(method, "version-check", params))
                handler.assert_not_called()
                self.assertEqual(code, 0)
                self.assertEqual(responses[0]["id"], "version-check")
                self.assertEqual(responses[0]["error"]["code"], -32022)

    def test_client_identity_can_be_absent_but_supplied_identity_must_be_valid(self) -> None:
        for method in ("server/discover", "tools/list", "tools/call"):
            with self.subTest(method=method):
                params = _modern_params({"name": "providers", "arguments": {}})
                del params["_meta"]["io.modelcontextprotocol/clientInfo"]
                code, responses, _ = _run(_request(method, 1, params))
                self.assertEqual(code, 0)
                self.assertIn("result", responses[0])
                for identity in (None, {}, {"name": "client", "version": 1}):
                    params["_meta"]["io.modelcontextprotocol/clientInfo"] = identity
                    code, responses, _ = _run(_request(method, 2, params))
                    self.assertEqual(code, 0)
                    self.assertEqual(responses[0]["error"]["code"], -32602)

    def test_all_valid_notifications_are_silent_and_do_not_execute_tools(self) -> None:
        messages = [
            {"jsonrpc": "2.0", "method": method, "params": params}
            for method, params in (
                ("tools/call", _modern_params({"name": "providers", "arguments": {}})),
                ("unknown", {}),
            )
        ]
        payload = b"".join((json.dumps(message) + "\n").encode() for message in messages)
        with patch("cpe_access_atlas.mcp_server._tool_data") as handler:
            code, responses, output = _run(payload)
        handler.assert_not_called()
        self.assertEqual((code, responses, output), (0, [], b""))

    def test_malformed_requests_do_not_emit_null_or_invalid_error_ids(self) -> None:
        messages = [
            {"jsonrpc": "1.0", "method": "ping", "id": "preserved"},
            {"jsonrpc": "2.0", "method": 42},
            *({"jsonrpc": "2.0", "method": "ping", "id": value} for value in (None, True, [])),
        ]
        payload = b"".join((json.dumps(message) + "\n").encode() for message in messages)
        code, responses, _ = _run(payload)
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["id"], "preserved")
        self.assertTrue(all("id" not in response for response in responses[1:]))
        self.assertTrue(all(response["error"]["code"] == -32600 for response in responses))

    def test_invalid_params_and_unknown_methods_preserve_request_ids(self) -> None:
        code, responses, _ = _run(_request("tools/list", 7, []) + _request("unknown", 8))
        self.assertEqual(code, 0)
        self.assertEqual([response["id"] for response in responses], [7, 8])
        self.assertEqual([response["error"]["code"] for response in responses], [-32602, -32601])

    def test_nonstandard_json_constants_are_parse_errors_without_an_id(self) -> None:
        code, responses, _ = _run(b'{"jsonrpc":"2.0","id":1,"method":"ping","x":NaN}\n')
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertNotIn("id", responses[0])

    def test_stdio_entrypoint_uses_binary_streams_and_accepts_crlf(self) -> None:
        payload = _request("tools/list", 1, _modern_params()).replace(b"\n", b"\r\n")
        output = BytesIO()
        with (
            patch(
                "cpe_access_atlas.mcp_server.sys.stdin", SimpleNamespace(buffer=BytesIO(payload))
            ),
            patch("cpe_access_atlas.mcp_server.sys.stdout", SimpleNamespace(buffer=output)),
        ):
            code = run_stdio()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["result"]["resultType"], "complete")

    def test_parse_and_framing_errors_stop_if_the_response_cannot_be_written(self) -> None:
        for payload in (b"{bad json}\n", b"unterminated"):
            with (
                self.subTest(payload=payload),
                patch("cpe_access_atlas.mcp_server.MAX_RESPONSE_BYTES", 1),
            ):
                self.assertEqual(serve(BytesIO(payload), BytesIO()), 1)

    def test_device_listing_without_filter_returns_public_catalog_data(self) -> None:
        code, responses, _ = _run(
            _request("tools/call", 1, _modern_params({"name": "devices", "arguments": {}}))
        )
        self.assertEqual(code, 0)
        data = json.loads(responses[0]["result"]["content"][0]["text"])["data"]
        self.assertGreater(len({device["provider_id"] for device in data}), 1)

    def test_recipe_listing_preserves_the_envelope_and_exact_target_fields(self) -> None:
        code, responses, _ = _run(
            _request("tools/call", 1, _modern_params({"name": "recipes", "arguments": {}}))
        )
        self.assertEqual(code, 0)
        result = responses[0]["result"]
        self.assertFalse(result["isError"])
        envelope = json.loads(result["content"][0]["text"])
        self.assertEqual(envelope["schema_version"], "1")
        recipe = next(item for item in envelope["data"] if item["firmware"] == TARGET["firmware"])
        self.assertEqual(recipe["id"], "tr.turk-telekom.zte.h3600p.h3600p-v9-ttn10-260210")
        self.assertEqual(recipe["hardware_revision"], TARGET["hardware_revision"])
        self.assertEqual(recipe["status"], "blocked")

    def test_invalid_json_gets_parse_error_and_server_continues(self) -> None:
        payload = b"{bad json}\n" + _request("server/discover", 1, _modern_params())
        code, responses, _ = _run(payload)
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["result"]["supportedVersions"], [MCP_PROTOCOL_VERSION])

    def test_oversized_input_is_rejected_and_stops_server(self) -> None:
        with patch("cpe_access_atlas.mcp_server.MAX_MESSAGE_BYTES", 32):
            code, responses, _ = _run(b"{" + b"a" * 40 + b"}\n")
        self.assertEqual(code, 1)
        self.assertEqual(responses[0]["error"]["code"], -32700)

    def test_non_utf8_input_is_rejected_without_reflecting_bytes(self) -> None:
        code, responses, output = _run(b"\xff\n")
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertNotIn(b"\\xff", output)

    def test_duplicate_json_keys_and_batch_messages_are_rejected(self) -> None:
        duplicate = b'{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"server/discover"}\n'
        batch = b'[{"jsonrpc":"2.0","id":1,"method":"server/discover"}]\n'
        code, responses, _ = _run(duplicate + batch)
        self.assertEqual(code, 0)
        self.assertEqual([item["error"]["code"] for item in responses], [-32700, -32600])

    def test_notifications_and_cancellation_do_not_write_responses(self) -> None:
        payload = (
            json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        initialized = (
            json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        payload += initialized
        code, responses, output = _run(payload)
        self.assertEqual(code, 0)
        self.assertEqual(responses, [])
        self.assertEqual(output, b"")

    def test_catalog_results_are_redacted_before_they_reach_the_client(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        with patch(
            "cpe_access_atlas.mcp_server._tool_data",
            return_value={"password": "do-not-return-this"},
        ):
            code, responses, output = _run(_request("tools/call", 1, params))
        self.assertEqual(code, 0)
        self.assertFalse(responses[0]["result"]["isError"])
        self.assertNotIn(b"do-not-return-this", output)
        result = json.loads(responses[0]["result"]["content"][0]["text"])
        self.assertNotEqual(result["data"]["password"], "do-not-return-this")

    def test_redaction_that_breaks_json_returns_a_safe_error(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        for value in ("password=example-only", "Authorization: Bearer example-only"):
            with (
                self.subTest(value=value),
                patch(
                    "cpe_access_atlas.mcp_server._tool_data", return_value={"description": value}
                ),
            ):
                code, responses, output = _run(_request("tools/call", 1, params))
            self.assertEqual(code, 0)
            self.assertTrue(responses[0]["result"]["isError"])
            self.assertNotIn(b"example-only", output)
            self.assertEqual(
                responses[0]["result"]["content"][0]["text"],
                "Unable to safely serialize catalog result",
            )

    def test_embedded_catalog_strings_are_redacted_after_json_decoding(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        data = {
            "nested": [
                'hello "password": "example-only" world',
                '{"password":"example-only"}',
                "x\nCookie: example-only",
                {"safe": True, "count": 2, "empty": None},
            ]
        }
        with patch("cpe_access_atlas.mcp_server._tool_data", return_value=data):
            code, responses, output = _run(_request("tools/call", 1, params))
        self.assertEqual(code, 0)
        self.assertFalse(responses[0]["result"]["isError"])
        self.assertNotIn(b"example-only", output)
        result = json.loads(responses[0]["result"]["content"][0]["text"])
        self.assertEqual(result["schema_version"], "1")
        self.assertEqual(result["data"]["nested"][3], data["nested"][3])

    def test_redacted_json_key_collisions_fail_closed(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        with patch(
            "cpe_access_atlas.mcp_server._tool_data",
            return_value={"password=one": 1, "password=two": 2},
        ):
            code, responses, output = _run(_request("tools/call", 1, params))
        self.assertEqual(code, 0)
        self.assertTrue(responses[0]["result"]["isError"])
        self.assertNotIn(b"password=one", output)
        self.assertNotIn(b"password=two", output)

    def test_nested_json_text_is_redacted_at_each_encoding_layer(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        encoded: object = {"password": "example-only"}
        for depth in range(1, 5):
            encoded = json.dumps(encoded)
            for wrapped in (False, True):
                text = f"note: {encoded}" if wrapped else encoded
                with (
                    self.subTest(depth=depth, wrapped=wrapped),
                    patch("cpe_access_atlas.mcp_server._tool_data", return_value={"text": text}),
                ):
                    code, responses, output = _run(_request("tools/call", 1, params))
                self.assertEqual(code, 0)
                self.assertFalse(responses[0]["result"]["isError"])
                self.assertNotIn(b"example-only", output)
                json.loads(responses[0]["result"]["content"][0]["text"])

    def test_nested_json_object_text_preserves_nonsecret_values(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        nested = json.dumps({"items": [json.dumps({"password": "example-only"}), 7, None]})
        with patch("cpe_access_atlas.mcp_server._tool_data", return_value={"text": nested}):
            code, responses, output = _run(_request("tools/call", 1, params))
        self.assertEqual(code, 0)
        self.assertFalse(responses[0]["result"]["isError"])
        self.assertNotIn(b"example-only", output)
        outer = json.loads(responses[0]["result"]["content"][0]["text"])
        decoded = json.loads(outer["data"]["text"])
        self.assertEqual(decoded["items"][1:], [7, None])

    def test_nested_encoded_json_in_a_key_is_redacted(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        key = "key: " + json.dumps(json.dumps({"password": "example-only"}))
        with patch("cpe_access_atlas.mcp_server._tool_data", return_value={key: "safe"}):
            code, responses, output = _run(_request("tools/call", 1, params))
        self.assertEqual(code, 0)
        self.assertFalse(responses[0]["result"]["isError"])
        self.assertNotIn(b"example-only", output)
        result = json.loads(responses[0]["result"]["content"][0]["text"])
        self.assertEqual(list(result["data"].values()), ["safe"])

    def test_nested_credential_text_with_varied_wrappers_never_leaks(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        wrappers = ("", "prefix ", '"', "\\", "{", "}\n", '"x', 'x"', "[]=;")
        for index, (prefix, suffix, depth) in enumerate(product(wrappers, wrappers, range(1, 6))):
            text: object = {"password": "example-only"}
            for _ in range(depth):
                text = json.dumps(text)
            with (
                self.subTest(index=index),
                patch(
                    "cpe_access_atlas.mcp_server._tool_data",
                    return_value={"text": prefix + str(text) + suffix},
                ),
            ):
                code, responses, output = _run(_request("tools/call", 1, params))
                self.assertEqual(code, 0)
                self.assertNotIn(b"example-only", output)
                if not responses[0]["result"]["isError"]:
                    json.loads(responses[0]["result"]["content"][0]["text"])

    def test_incomplete_or_invalid_quoted_text_remains_safe_json(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        for text in ('note: "unterminated', 'note: "line\nfeed"'):
            with (
                self.subTest(text=text),
                patch("cpe_access_atlas.mcp_server._tool_data", return_value={"text": text}),
            ):
                code, responses, _ = _run(_request("tools/call", 1, params))
            self.assertEqual(code, 0)
            self.assertFalse(responses[0]["result"]["isError"])
            result = json.loads(responses[0]["result"]["content"][0]["text"])
            self.assertEqual(result["data"]["text"], text)

    def test_invalid_escaped_quoted_text_fails_closed(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        for text in (r'note: "bad\q"', 'note: "{\\"password\\":\\"example-only\\"'):
            with (
                self.subTest(text=text),
                patch("cpe_access_atlas.mcp_server._tool_data", return_value={"text": text}),
            ):
                code, responses, output = _run(_request("tools/call", 1, params))
            self.assertEqual(code, 0)
            self.assertTrue(responses[0]["result"]["isError"])
            self.assertNotIn(b"example-only", output)

    def test_nonsecret_json_text_keeps_its_original_representation(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        for text in (r'note: "hello\u0020world"', '{ "items" : [1, 2] }'):
            with (
                self.subTest(text=text),
                patch("cpe_access_atlas.mcp_server._tool_data", return_value={"text": text}),
            ):
                code, responses, _ = _run(_request("tools/call", 1, params))
            self.assertEqual(code, 0)
            self.assertFalse(responses[0]["result"]["isError"])
            result = json.loads(responses[0]["result"]["content"][0]["text"])
            self.assertEqual(result["data"]["text"], text)

    def test_decoded_redaction_cannot_expand_result_past_the_limit(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})

        def expand(value: str) -> str:
            return "x" * 200 if value == "safe" else value

        with (
            patch("cpe_access_atlas.mcp_server._tool_data", return_value={"description": "safe"}),
            patch("cpe_access_atlas.mcp_server.MAX_RESULT_BYTES", 128),
            patch("cpe_access_atlas.mcp_server.redact_text", side_effect=expand),
        ):
            code, responses, _ = _run(_request("tools/call", 1, params))
        self.assertEqual(code, 0)
        self.assertTrue(responses[0]["result"]["isError"])
        self.assertEqual(
            responses[0]["result"]["content"][0]["text"],
            "Result exceeds the configured size limit",
        )

    def test_tool_output_limit_fails_closed(self) -> None:
        with patch("cpe_access_atlas.mcp_server.MAX_RESULT_BYTES", 8):
            code, responses, _ = _run(
                _request("tools/call", 1, _modern_params({"name": "providers", "arguments": {}}))
            )
        self.assertEqual(code, 0)
        self.assertTrue(responses[0]["result"]["isError"])

    def test_removed_initialize_and_ping_are_not_implemented(self) -> None:
        messages = _request("initialize", 1, {"protocolVersion": "2025-11-25"})
        messages += _request("ping", 2, _modern_params())
        code, responses, _ = _run(messages)
        self.assertEqual(code, 0)
        self.assertEqual([item["error"]["code"] for item in responses], [-32601, -32601])

    def test_discovery_accepts_optional_client_info_and_requires_capabilities(self) -> None:
        valid = _request("server/discover", 1, _modern_params())
        invalid = _request("server/discover", 2, {"_meta": []})
        missing = _request(
            "server/discover",
            3,
            {"_meta": {"io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION}},
        )
        mismatch = _request(
            "server/discover",
            4,
            {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "1900-01-01",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
                }
            },
        )
        code, responses, _ = _run(valid + invalid + missing + mismatch)
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["result"]["supportedVersions"], [MCP_PROTOCOL_VERSION])
        self.assertEqual(responses[1]["error"]["code"], -32602)
        self.assertEqual(responses[2]["error"]["code"], -32602)
        self.assertEqual(responses[3]["error"]["code"], -32022)

    def test_modern_requests_require_version_and_capabilities_and_validate_optional_identity(
        self,
    ) -> None:
        invalid_metadata = _request("tools/list", 1, {"_meta": []})
        missing_version = _request(
            "tools/list",
            2,
            {
                "_meta": {
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
                }
            },
        )
        unsupported_version = _request(
            "tools/list",
            3,
            {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "1900-01-01",
                    "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        )
        malformed_identity = _request(
            "tools/list",
            4,
            {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": "not-an-object",
                }
            },
        )
        code, responses, _ = _run(
            invalid_metadata + missing_version + unsupported_version + malformed_identity
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            [item["error"]["code"] for item in responses],
            [-32602, -32602, -32022, -32602],
        )

    def test_mcp_protocol_version_is_the_stateless_revision(self) -> None:
        self.assertEqual(MCP_PROTOCOL_VERSION, "2026-07-28")

    def test_server_is_stateless_across_requests(self) -> None:
        discovery = _request("server/discover", 1, _modern_params())
        legacy_request = _request("tools/call", 2, {"name": "providers", "arguments": {}})
        code, responses, _ = _run(discovery + legacy_request)
        self.assertEqual(code, 0)
        self.assertEqual(responses[1]["error"]["code"], -32602)

    def test_tool_calls_validate_argument_types_and_do_not_echo_lookup_errors(self) -> None:
        non_object = _request(
            "tools/call", 1, _modern_params({"name": "providers", "arguments": []})
        )
        unknown_provider = _request(
            "tools/call",
            2,
            _modern_params({"name": "devices", "arguments": {"isp": "private-not-a-provider"}}),
        )
        code, responses, output = _run(non_object + unknown_provider)
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["error"]["code"], -32602)
        self.assertTrue(responses[1]["result"]["isError"])
        self.assertNotIn(b"private-not-a-provider", output)
        self.assertIn("resultType", responses[1]["result"])

    def test_unexpected_data_errors_and_serialization_failures_are_sanitized(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        with patch(
            "cpe_access_atlas.mcp_server._tool_data", side_effect=RuntimeError("private-error")
        ):
            code, responses, output = _run(_request("tools/call", 1, params))
        self.assertEqual(code, 0)
        self.assertTrue(responses[0]["result"]["isError"])
        self.assertNotIn(b"private-error", output)
        with patch("cpe_access_atlas.mcp_server._tool_data", return_value=object()):
            code, responses, _ = _run(_request("tools/call", 2, params))
        self.assertEqual(code, 0)
        self.assertTrue(responses[0]["result"]["isError"])

    def test_redaction_errors_and_expanded_output_limits_fail_closed(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        for error in (ValueError("private"), RecursionError("private")):
            with (
                self.subTest(error=type(error)),
                patch("cpe_access_atlas.mcp_server.redact_text", side_effect=error),
            ):
                code, responses, _ = _run(_request("tools/call", 1, params))
            self.assertEqual(code, 0)
            self.assertTrue(responses[0]["result"]["isError"])
        with (
            patch("cpe_access_atlas.mcp_server._tool_data", return_value={}),
            patch("cpe_access_atlas.mcp_server.MAX_RESULT_BYTES", 128),
            patch("cpe_access_atlas.mcp_server.redact_text", return_value="x" * 129) as redactor,
        ):
            code, responses, _ = _run(_request("tools/call", 2, params))
        self.assertEqual(code, 0)
        self.assertTrue(responses[0]["result"]["isError"])
        redactor.assert_called_once()

    def test_review_only_plan_and_root_gate_preserve_conservative_decisions(self) -> None:
        recipe = find_recipe(**TARGET)
        verified = replace(recipe, status="verified", hardware_revision_status="exact")
        with patch("cpe_access_atlas.mcp_server._target", return_value=verified):
            from cpe_access_atlas.mcp_server import _tool_data

            plan = _tool_data("plan", TARGET)
        self.assertEqual(plan["decision"], "REVIEW REQUIRED")
        root_ready = replace(
            verified,
            access={**verified.access, "local_root_shell": "stable"},
        )
        with patch("cpe_access_atlas.mcp_server._target", return_value=root_ready):
            readiness = _tool_data("root_readiness", TARGET)
        self.assertTrue(readiness["checks"]["catalog_root_method_verified"])
        self.assertEqual(readiness["decision"], "STOP")
        self.assertFalse(readiness["device_io_attempted"])

    def test_serving_requires_newline_and_handles_broken_streams(self) -> None:
        code, responses, _ = _run(b'{"jsonrpc":"2.0","id":1,"method":"ping"}')
        self.assertEqual(code, 1)
        self.assertEqual(responses[0]["error"]["code"], -32700)

        class BrokenInput(BytesIO):
            def readline(self, size: int = -1) -> bytes:
                raise OSError("private input failure")

        self.assertEqual(serve(BrokenInput(), BytesIO()), 1)

        class BrokenOutput(BytesIO):
            def write(self, data: bytes) -> int:
                raise OSError("private output failure")

        self.assertEqual(serve(BytesIO(_request("ping", 1)), BrokenOutput()), 1)

    def test_response_limits_and_invalid_output_data_stop_server(self) -> None:
        with patch("cpe_access_atlas.mcp_server.MAX_RESPONSE_BYTES", 1):
            self.assertEqual(serve(BytesIO(_request("ping", 1)), BytesIO()), 1)
        self.assertFalse(_write_message(BytesIO(), {"invalid": object()}))
        self.assertFalse(_write_message(BytesIO(), {"invalid": chr(0xD800)}))

    def test_oversized_encoded_result_returns_error_and_server_continues(self) -> None:
        params = _modern_params({"name": "providers", "arguments": {}})
        payload = _request("tools/call", 1, params) + _request("ping", 2)
        with (
            patch("cpe_access_atlas.mcp_server._tool_data", return_value=["ordinary"] * 20),
            patch("cpe_access_atlas.mcp_server.MAX_RESULT_BYTES", 1024),
            patch("cpe_access_atlas.mcp_server.MAX_RESPONSE_BYTES", 256),
        ):
            code, responses, _ = _run(payload)
        self.assertEqual(code, 0)
        self.assertEqual(responses[0]["id"], 1)
        self.assertEqual(responses[0]["error"]["code"], -32603)
        self.assertEqual(responses[1]["id"], 2)
        self.assertEqual(responses[1]["error"]["code"], -32601)

    def test_oversized_response_id_uses_bounded_error_without_id(self) -> None:
        output = BytesIO()
        with patch("cpe_access_atlas.mcp_server.MAX_RESPONSE_BYTES", 128):
            self.assertTrue(_write_message(output, {"id": "x" * 200, "result": {}}))
        response = json.loads(output.getvalue())
        self.assertNotIn("id", response)
        self.assertEqual(response["error"]["code"], -32603)

    def test_server_module_has_no_network_subprocess_or_cli_imports(self) -> None:
        path = ROOT / "src" / "cpe_access_atlas" / "mcp_server.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertFalse(imported & {"socket", "subprocess", "urllib", "http", "cli"})


if __name__ == "__main__":
    unittest.main()
