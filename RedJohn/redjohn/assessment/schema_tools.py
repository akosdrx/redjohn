"""Reviewed TInjA and Schemathesis profiles on one captured GET or private POST.

The source scanner may propose requests; the host admits only the selected
input and a bounded payload domain. Schemas are private immutable snapshots,
never remote documents, plugins, links, stateful workflows or executable hooks.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlsplit

from redjohn.assessment.input_replay import (
    CARRIER_NAME,
    PrivateBodyInput,
    carrier_surface,
    validate_post_input,
)
from redjohn.assessment.models import stable_key
from redjohn.assessment.pinned_tools import BinaryPin
from redjohn.assessment.specialists import SpecialistAdapter, SpecialistConfig


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.auth_replay import AuthReplayBinding
    from redjohn.assessment.models import JobSpec, Surface
    from redjohn.assessment.policy import EngagementPolicy


CAPABILITIES = {"tinja": "tinja_validate", "schemathesis": "schemathesis_validate"}


@dataclass(frozen=True)
class SchemaToolConfig(SpecialistConfig):
    schema_file: Path | None = None
    schema_sha256: str = ""
    max_examples: int = 8

    @classmethod
    def from_mapping(cls, tool: str, value: dict[str, Any]) -> SchemaToolConfig:
        if (
            tool not in CAPABILITIES
            or not isinstance(value, dict)
            or set(value)
            - {
                "binary",
                "rate_limit",
                "request_timeout",
                "max_requests",
                "schema_file",
                "schema_sha256",
                "max_examples",
            }
        ):
            raise ValueError("invalid_schema_tool_configuration")
        rate = value.get("rate_limit", 10)
        timeout = value.get("request_timeout", 3)
        requests = value.get("max_requests", 96)
        if (
            type(rate) is not int
            or not 1 <= rate <= 10
            or type(timeout) is not int
            or not 1 <= timeout <= 10
            or type(requests) is not int
            or not 8 <= requests <= 128
        ):
            raise ValueError("invalid_schema_tool_limits")
        file, digest = value.get("schema_file"), value.get("schema_sha256", "")
        examples = value.get("max_examples", 8)
        if (
            type(examples) is not int
            or not 4 <= examples <= 16
            or (
                tool == "tinja"
                and any(k in value for k in ("schema_file", "schema_sha256", "max_examples"))
            )
            or (
                tool == "schemathesis"
                and (
                    not isinstance(file, str)
                    or not Path(file).is_absolute()
                    or not isinstance(digest, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", digest)
                )
            )
        ):
            raise ValueError("schema_snapshot_pin_required")
        return cls(
            tool,
            BinaryPin.from_mapping(tool, value.get("binary")),
            rate_limit=rate,
            request_timeout=timeout,
            max_requests=requests,
            schema_file=Path(file) if file is not None else None,
            schema_sha256=digest,
            max_examples=examples,
        )

    @property
    def revision(self) -> str:
        payload_sha = hashlib.sha256(
            Path(__file__).with_name("tinja_payloads.json").read_bytes()
        ).hexdigest()
        return stable_key(
            [
                "redjohn-schema-tools-v2-private-post-bridge",
                self.tool,
                self.binary.sha256,
                self.schema_sha256,
                self.max_examples,
                self.max_requests,
                payload_sha,
            ]
        )

    def validate_input(self, policy: EngagementPolicy, surface: Surface, spec: JobSpec) -> None:
        if surface.method == "POST":
            validate_post_input(policy, surface, spec)
            if (
                spec.tool_version != self.version
                or spec.template_version != self.revision
                or set(spec.options) != {"hint_ref"}
                or not isinstance(spec.options["hint_ref"], str)
                or not re.fullmatch(r"[a-f0-9]{32}", spec.options["hint_ref"])
            ):
                raise ValueError("schema_tool_current_profile_and_hint_required")
            if self.tool == "schemathesis":
                self.schema(surface)
            return
        SpecialistConfig.validate_input(self, policy, surface, spec)
        pairs = parse_qsl(urlsplit(surface.url).query, keep_blank_values=True)
        if len(pairs) != 1:
            raise ValueError("schema_tools_require_one_query_input")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", pairs[0][1]):
            raise ValueError("schema_tool_benign_baseline_required")
        # TInjA canonicalizes the query. Reject inputs it cannot preserve exactly.
        if urlsplit(surface.url).query.partition("=")[0] != surface.input_name:
            raise ValueError("schema_tool_parameter_mismatch")
        if self.tool == "schemathesis":
            self.schema(surface)

    def schema(self, surface: Surface) -> dict[str, Any]:
        file = self.schema_file
        if file is None or file.is_symlink() or not file.is_file() or file.stat().st_size > 32768:
            raise ValueError("reviewed_schema_snapshot_required")
        try:
            descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("schema_snapshot_regular_file_required")
                raw = stream.read(32769)
        except OSError as exc:
            raise ValueError("schema_snapshot_unavailable") from exc
        if len(raw) > 32768:
            raise ValueError("schema_snapshot_too_large")
        if hashlib.sha256(raw).hexdigest() != self.schema_sha256:
            raise ValueError("schema_snapshot_digest_mismatch")
        data = json.loads(raw)
        try:
            return self._validated_schema(data, surface)
        except (KeyError, TypeError) as exc:
            raise ValueError("schema_document_malformed") from exc

    def _validated_schema(self, data: Any, surface: Surface) -> dict[str, Any]:
        if surface.method == "POST":
            return self._post_projection(data, surface)
        path = urlsplit(surface.url).path
        if (
            not isinstance(data, dict)
            or set(data) != {"openapi", "info", "paths"}
            or data["openapi"] != "3.0.3"
            or not re.fullmatch(r"/[A-Za-z0-9/_-]{0,127}", path)
            or not isinstance(data["info"], dict)
            or data["info"] != {"title": "RedJohn reviewed API", "version": "1"}
            or not isinstance(data["paths"], dict)
            or set(data["paths"]) != {path}
            or not isinstance(data["paths"][path], dict)
            or set(data["paths"][path]) != {"get"}
        ):
            raise ValueError("schema_requires_single_reviewed_get_operation")
        operation = data["paths"][path]["get"]
        if (
            not isinstance(operation, dict)
            or set(operation) != {"operationId", "parameters", "responses"}
            or not isinstance(operation["operationId"], str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", operation["operationId"])
            or not isinstance(operation["parameters"], list)
            or len(operation["parameters"]) != 1
        ):
            raise ValueError("schema_operation_or_parameters_unsupported")
        parameter = operation["parameters"][0]
        if (
            not isinstance(parameter, dict)
            or set(parameter) != {"in", "name", "required", "schema"}
            or parameter["in"] != "query"
            or parameter["name"] != surface.input_name
            or parameter["required"] is not True
        ):
            raise ValueError("schema_parameter_outside_observed_input")
        domain = parameter["schema"]
        if (
            not isinstance(domain, dict)
            or set(domain) != {"type", "minimum", "maximum"}
            or domain["type"] != "integer"
            or type(domain["minimum"]) is not int
            or type(domain["maximum"]) is not int
            or not 0 <= domain["minimum"] < domain["maximum"] <= 100
        ):
            raise ValueError("schema_input_requires_bounded_positive_integer")
        responses = operation["responses"]
        if (
            not isinstance(responses, dict)
            or set(responses) != {"200"}
            or not isinstance(responses["200"], dict)
            or set(responses["200"]) != {"description", "content"}
            or responses["200"]["description"] != "Reviewed response"
            or set(responses["200"]["content"]) != {"application/json"}
            or set(responses["200"]["content"]["application/json"]) != {"schema"}
        ):
            raise ValueError("schema_response_contract_unsupported")
        response_schema = responses["200"]["content"]["application/json"]["schema"]
        if (
            not isinstance(response_schema, dict)
            or set(response_schema) != {"type", "properties", "required", "additionalProperties"}
            or response_schema["type"] != "object"
            or response_schema["additionalProperties"] is not False
            or not isinstance(response_schema["properties"], dict)
            or not 1 <= len(response_schema["properties"]) <= 8
            or sorted(response_schema["properties"]) != sorted(response_schema["required"])
            or any(
                not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", key)
                or not isinstance(value, dict)
                or set(value) != {"type"}
                or value["type"] not in {"integer", "string", "boolean"}
                for key, value in response_schema["properties"].items()
            )
        ):
            raise ValueError("schema_response_shape_unsupported")
        return data

    def _post_projection(self, data: Any, surface: Surface) -> dict[str, Any]:
        """Validate the pinned POST contract, then expose only its public input.

        The upstream generator/checks run unchanged on a GET carrier. The host
        materializes real POST bytes; credentials, fixed fields and files never
        enter the generated schema or worker. This is a RedJohn transport bridge,
        not a claim of native upstream multipart replay.
        """
        path = urlsplit(surface.url).path
        if (
            not isinstance(data, dict)
            or set(data) != {"openapi", "info", "paths"}
            or not isinstance(data["paths"], dict)
            or set(data["paths"]) != {path}
            or not isinstance(data["paths"][path], dict)
            or set(data["paths"][path]) != {"post"}
        ):
            raise ValueError("schema_requires_single_reviewed_post_operation")
        operation = data["paths"][path]["post"]
        if not isinstance(operation, dict) or set(operation) != {
            "operationId",
            "requestBody",
            "responses",
        }:
            raise ValueError("schema_post_operation_unsupported")
        request = operation["requestBody"]
        media = surface.content_type.partition(";")[0].strip().lower()
        if (
            not isinstance(request, dict)
            or set(request) != {"required", "content"}
            or request["required"] is not True
            or not isinstance(request["content"], dict)
            or set(request["content"]) != {media}
            or not isinstance(request["content"][media], dict)
            or set(request["content"][media]) != {"schema"}
        ):
            raise ValueError("schema_post_body_contract_unsupported")
        shape = request["content"][media]["schema"]
        name = surface.input_name
        if surface.input_location == "json":
            if not re.fullmatch(r"/[A-Za-z_][A-Za-z0-9_]{0,63}", name):
                raise ValueError("schema_post_single_top_level_integer_required")
            name = name[1:]
        if (
            not isinstance(shape, dict)
            or set(shape) != {"type", "properties", "required", "additionalProperties"}
            or shape["type"] != "object"
            or shape["required"] != [name]
            or shape["additionalProperties"] is not False
            or not isinstance(shape["properties"], dict)
            or set(shape["properties"]) != {name}
        ):
            raise ValueError("schema_post_selected_input_projection_required")
        projected = {
            **data,
            "paths": {
                path: {
                    "get": {
                        "operationId": operation["operationId"],
                        "parameters": [
                            {
                                "in": "query",
                                "name": CARRIER_NAME,
                                "required": True,
                                "schema": shape["properties"][name],
                            }
                        ],
                        "responses": operation["responses"],
                    }
                }
            },
        }
        return self._validated_schema(projected, carrier_surface(surface, integer=True))


class SchemaToolAdapter(SpecialistAdapter):
    config: SchemaToolConfig

    def validate_capture(self, surface: Surface) -> None:
        super().validate_capture(surface)
        capture = self.store.evidence_get(self.policy.engagement_id, surface.request_ref)
        data = json.loads(capture["excerpt"])
        if data.get("status") != 200:
            raise ValueError("schema_tool_successful_baseline_required")
        if surface.method == "POST" and (
            data.get("response_complete") is not True
            or data.get("body_sha256") != surface.body_sha256
            or data.get("request_content_type", data.get("content_type")) != surface.content_type
        ):
            raise ValueError("schema_tool_complete_post_capture_required")

    def minimum_responses(self) -> int:
        return 1 if self.config.tool == "schemathesis" else 3

    def mutation_allowed(self, surface: Surface, canonical: str) -> bool:
        worker = self.worker_surface(surface)
        if not super().mutation_allowed(worker, canonical):
            return False
        value = parse_qsl(urlsplit(canonical).query, keep_blank_values=True)[0][1]
        if self.config.tool == "tinja":
            payloads = json.loads(Path(__file__).with_name("tinja_payloads.json").read_text())[
                "payloads"
            ]
            return (
                value == parse_qsl(urlsplit(worker.url).query)[0][1]
                or re.fullmatch(r"[A-Z2-7]{16}", value) is not None
                or value in payloads
                or value in {"".join("\\" + c for c in p) for p in payloads}
            )
        schema = self.config.schema(surface)
        domain = schema["paths"][urlsplit(surface.url).path]["get"]["parameters"][0]["schema"]
        return (
            bool(re.fullmatch(r"[0-9]{1,3}", value))
            and domain["minimum"] <= int(value) <= domain["maximum"]
        )

    def worker_surface(self, surface: Surface) -> Surface:
        return carrier_surface(surface, integer=self.config.tool == "schemathesis")

    def request_transform(
        self, surface: Surface, binding: AuthReplayBinding | None
    ) -> (
        Callable[
            [str, str, list[tuple[str, str]], bytes], tuple[str, str, list[tuple[str, str]], bytes]
        ]
        | None
    ):
        if surface.method != "POST":
            return None
        if binding is None:
            raise ValueError("schema_tool_private_body_binding_required")
        selected = PrivateBodyInput.from_binding(
            binding, surface, integer=self.config.tool == "schemathesis"
        )

        def transform(
            url: str, method: str, fields: list[tuple[str, str]], body: bytes
        ) -> tuple[str, str, list[tuple[str, str]], bytes]:
            if method != "GET" or body or not self.mutation_allowed(surface, url):
                raise ValueError("schema_tool_carrier_outside_selected_input")
            value = parse_qsl(urlsplit(url).query, keep_blank_values=True)[0][1]
            self.store.assert_session_revision(self.policy, surface)
            clean = [
                (k, v)
                for k, v in fields
                if k.lower() not in {"content-type", "content-length", "transfer-encoding"}
            ]
            return (
                surface.url,
                "POST",
                [*clean, ("Content-Type", binding.content_type)],
                selected.mutate(value),
            )

        return transform

    def unsupported_profiles(self) -> list[str]:
        return ["file_part_mutation", "duplicate_selected_field", "general_stateful_or_graphql"]

    def argv(
        self, alias: str, proxy: str, surface: Surface, workspace: Path, _payload: str
    ) -> list[str]:
        c = self.config
        if c.tool == "tinja":
            return [
                str(c.binary.path),
                "url",
                "--url",
                alias,
                "--proxyurl",
                proxy,
                "--reportpath",
                str(workspace / "tinja-"),
                "--verbosity",
                "0",
                "--ratelimit",
                str(c.rate_limit),
                "--timeout",
                str(c.request_timeout),
                "--lengthlimit",
                "64",
            ]
        schema = workspace / "reviewed-schema.json"
        schema.write_text(json.dumps(c.schema(surface)))
        config = workspace / "schemathesis.toml"
        config.write_text("[cache]\nenabled = false\n")
        return [
            str(c.binary.path),
            "--config-file",
            str(config),
            "--no-color",
            "run",
            str(schema),
            "--url",
            proxy,
            "--proxy",
            proxy,
            "--workers",
            "1",
            "--phases",
            "fuzzing",
            "--mode",
            "positive",
            "--max-examples",
            str(c.max_examples),
            "--seed",
            "734291",
            "--no-shrink",
            "--continue-on-failure",
            "--generation-database",
            "none",
            "--checks",
            "status_code_conformance,content_type_conformance,response_schema_conformance",
            "--max-redirects",
            "0",
            "--request-retries",
            "0",
            "--request-timeout",
            str(c.request_timeout),
            "--rate-limit",
            str(c.rate_limit) + "/s",
            "--report",
            "json",
            "--report-json-path",
            str(workspace / "schemathesis.json"),
        ]

    def read_output(  # noqa: PLR0911 - two pinned upstream schemas
        self, raw: dict[str, Any], workspace: Path, alias: str, parameter: str, _payload: str
    ) -> dict[str, Any] | None:
        if self.config.tool == "tinja":
            paths = list(workspace.glob("tinja-*_Report.jsonl"))
            if len(paths) != 1 or paths[0].stat().st_size > 1024 * 1024:
                return None
            rows = [json.loads(line) for line in paths[0].read_text().splitlines()]
            if (
                len(rows) != 2
                or not all(isinstance(row, dict) for row in rows)
                or rows[0].get("version") != "v1.2.0"
                or rows[0].get("errorMessages")
            ):
                return None
            page = rows[1]
            if (
                page.get("url") != alias
                or page.get("errorMessages")
                or not isinstance(page.get("default"), dict)
                or page.get("default", {}).get("statusCode") != 200
                or not isinstance(page.get("parameters"), list)
                or len(page.get("parameters", [])) != 1
            ):
                return None
            item = page["parameters"][0]
            if (
                not isinstance(item, dict)
                or item.get("name") != parameter
                or item.get("errorMessages")
                or type(item.get("isParameterVulnerable")) is not bool
            ):
                return None
            return {
                "candidate": item["isParameterVulnerable"],
                "engine": item.get("identifiedEngine", ""),
                "certainty": item.get("certainty", ""),
                "impact": "template_signal_only_rce_unproven",
            }
        path = workspace / "schemathesis.json"
        if not path.is_file() or path.stat().st_size > 65536:
            return None
        data = json.loads(path.read_text())
        if (
            not isinstance(data, dict)
            or data.get("schemathesis_version") != "4.31.1"
            or data.get("complete") is not True
            or data.get("stop_reason") != "completed"
            or data.get("errors") != []
            or data.get("exit_code") != raw.get("exit_code")
            or not isinstance(data.get("operations"), dict)
            or any(
                data["operations"].get(k) != v
                for k, v in {
                    "total": 1,
                    "selected": 1,
                    "tested": 1,
                    "errored": 0,
                    "skipped": 0,
                }.items()
            )
            or not isinstance(data.get("test_cases"), dict)
            or data["test_cases"].get("errored") != 0
            or data["test_cases"].get("without_checks") != 0
            or not isinstance(data.get("failures"), list)
            or len(data["failures"]) > 16
            or any(
                not isinstance(failure, dict)
                or not isinstance(failure.get("type"), str)
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", failure["type"])
                for failure in data["failures"]
            )
            or data.get("exit_code") != int(bool(data["failures"]))
            or not isinstance(data["test_cases"].get("generated"), int)
            or data["test_cases"]["generated"] < 1
        ):
            return None
        return {
            "candidate": bool(data["failures"]),
            "generated": data["test_cases"]["generated"],
            "failure_types": sorted({f["type"] for f in data["failures"]}),
            "impact": "schema_conformance_only",
            "internal_preflight_probes": "not_run_outside_selected_operation",
        }
