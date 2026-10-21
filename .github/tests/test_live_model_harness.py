"""Synthetic live-model harness contracts, never real provider E2E evidence."""

import importlib.util
import json
import os
import socket
import tempfile
import unittest
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


gateway = load("live_model_gateway_contract", "live-model-gateway.py")
harness = load("live_model_harness_contract", "live-model-e2e.py")


class LiveModelContracts(unittest.TestCase):
    def test_absence_records_blocked_without_dependency_or_model_import(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            self.assertFalse(harness.preflight(Path(directory)))
            result = json.loads((Path(directory) / "preflight.json").read_text())
            self.assertEqual(result["status"], "blocked")
            self.assertFalse(result["live_model_verified"])
            self.assertEqual(len(result["missing"]), 2)
            junit = ET.parse(Path(directory) / "preflight.junit.xml").getroot()
            self.assertEqual(junit.attrib["errors"], "1")
            self.assertEqual(junit.attrib["skipped"], "0")
            self.assertEqual(junit.find("testcase").attrib["classname"], "capability_preflight_no_model_call")

    def test_provider_key_never_enters_preflight_artifact(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "REDJOHN_LIVE_MODEL": "contract-model", "REDJOHN_LIVE_MODEL_API_KEY": "synthetic-secret"
        }, clear=True):
            self.assertTrue(harness.preflight(Path(directory)))
            self.assertNotIn("synthetic-secret", (Path(directory) / "preflight.json").read_text())

    def test_fixed_provider_rejects_other_routes(self):
        with self.assertRaises(ValueError):
            gateway.Gateway("other-provider/model", "synthetic")

    def test_global_call_cap_and_output_cap_apply_to_every_request(self):
        with gateway.Gateway("contract-model", "synthetic") as proxy:
            for _ in range(gateway.MAX_CALLS):
                request = proxy._admit({"model": "contract-model", "max_output_tokens": 9999,
                    "tools": [{"type": "function", "name": "assessment_control"},
                              {"type": "function", "name": "shell"}]}, "/v1/responses")
                self.assertEqual(request["max_output_tokens"], 2048)
                self.assertEqual([tool["name"] for tool in request["tools"]], ["assessment_control"])
            with self.assertRaises(ValueError):
                proxy._admit({"model": "contract-model"}, "/v1/responses")
            self.assertNotIn("synthetic", json.dumps(proxy.snapshot()))

    def test_disallowed_upstream_request_never_consumes_call_allowance(self):
        with gateway.Gateway("contract-model", "synthetic") as proxy:
            for request, path in (({"model": "wrong"}, "/v1/responses"),
                                  ({"model": "contract-model"}, "/v1/files")):
                with self.assertRaises(ValueError):
                    proxy._admit(request, path)
            self.assertEqual(proxy.accepted, 0)

    def test_structured_model_response_rejects_shell_and_builtins(self):
        for tool in ({"type": "function_call", "name": "shell"}, {"type": "computer_call"}):
            with self.assertRaises(ValueError):
                gateway.Gateway.validate_response(json.dumps({"output": [tool]}).encode(), "application/json")

    def test_stream_tool_gate_is_checked_before_any_dispatch(self):
        allowed = b'data: {"item":{"type":"function_call","name":"assessment_control"}}\n\ndata: [DONE]\n'
        gateway.Gateway.validate_response(allowed, "text/event-stream")
        with self.assertRaises(ValueError):
            gateway.Gateway.validate_response(allowed.replace(b"assessment_control", b"shell"), "text/event-stream")

    def test_handler_count_is_bounded_without_upstream_call(self):
        clients = []
        with gateway.Gateway("contract-model", "synthetic") as proxy:
            try:
                for _ in range(3):
                    clients.append(socket.create_connection(proxy._server.server_address, timeout=1))
                    time.sleep(0.05)
                self.assertEqual(proxy.snapshot()["rejected_calls"], 1)
                self.assertEqual(proxy.snapshot()["accepted_calls"], 0)
            finally:
                for client in clients:
                    client.close()

    def test_malformed_schema_and_deep_json_are_normalized(self):
        with gateway.Gateway("contract-model", "synthetic") as proxy:
            for tools in (False, ["bad"], [{"type": "function", "function": False}],
                          [{"type": "function", "name": {"invalid": True}}]):
                with self.assertRaises(ValueError):
                    proxy._admit({"model": "contract-model", "tools": tools}, "/v1/responses")
        for body in (b'{"item":{"type":4}}', b'{"item":{"type":"function_call","name":{}}}',
                     b'[' * 2000 + b']' * 2000):
            with self.assertRaises(ValueError):
                gateway.Gateway.validate_response(body, "application/json")

    def test_response_metadata_schemas_are_not_execution_items(self):
        gateway.Gateway.validate_response(json.dumps({"tools": [{"type": "function", "parameters": {
            "properties": {"type": {"type": "string"}}}}], "output": [{"type": "message"}]}).encode(), "application/json")

    def test_junit_requires_actual_provider_proof_and_retains_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = {"status": "failed", "interfaces": [{"interface": "cli"}, {"interface": "tui"}]}
            harness.junit(output, result)
            suite = ET.parse(output / "live-model.junit.xml").getroot()
            self.assertEqual(suite.attrib["errors"], "2")
            self.assertTrue(all(case.attrib["classname"] != "real_model_interface_e2e" for case in suite.findall("testcase")))
            result["provider_verified"] = True
            harness.junit(output, result)
            suite = ET.parse(output / "live-model.junit.xml").getroot()
            self.assertEqual(suite.attrib["errors"], "1")
            self.assertEqual(suite.attrib["tests"], "3")
            result["status"] = "passed"
            harness.junit(output, result)
            suite = ET.parse(output / "live-model.junit.xml").getroot()
            self.assertEqual(suite.attrib["errors"], "0")
            self.assertEqual(suite.attrib["tests"], "2")


if __name__ == "__main__":
    unittest.main()
