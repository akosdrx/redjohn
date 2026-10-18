"""Lazy capability catalogue: installed binary, adapter and live proof differ."""

from __future__ import annotations

import re
import shutil
from dataclasses import asdict, dataclass
from importlib.util import find_spec
from pathlib import Path
from typing import Any, TypedDict


@dataclass(frozen=True)
class Capability:
    id: str
    tool: str
    domains: tuple[str, ...] = ("web",)
    profiles: tuple[str, ...] = ("safe-production", "active-staging", "isolated-lab")
    content_types: tuple[str, ...] = ("",)
    resource_class: str = "worker"
    adapter_implemented: bool = False
    binary_names: tuple[str, ...] = ()
    source: str = ""
    license: str = "not_verified_not_redistributed"
    status: str = "adapter_not_implemented"
    reason: str = "not_implemented"
    cancellation: bool = False
    auth_replay: bool = False
    privilege: str = "unprivileged"
    # A trusted implementation must opt in too; a model/job cannot set this.
    owner_process_only: bool = False


class ExecutionVersions(TypedDict):
    tool_version: str
    template_version: str


CAPABILITIES = (
    Capability(
        "browser_discover",
        "Playwright + Chromium",
        resource_class="browser",
        adapter_implemented=True,
        source="https://playwright.dev/python/",
        license="Apache-2.0",
        status="implemented_fixture_tested",
        reason="requires_browser_extra_and_egress",
        cancellation=True,
        auth_replay=True,
    ),
    Capability(
        "http_observe",
        "RedJohn HTTP observation",
        adapter_implemented=True,
        source="redjohn/assessment/adapters.py",
        license="project",
        status="implemented_fixture_tested",
        reason="explicit_readonly_seed",
        cancellation=True,
        owner_process_only=True,
    ),
    Capability(
        "headers_audit",
        "RedJohn response header check",
        adapter_implemented=True,
        source="redjohn/assessment/adapters.py",
        license="project",
        status="implemented_fixture_tested",
        reason="header_presence_is_candidate_only",
        cancellation=True,
        owner_process_only=True,
    ),
    Capability(
        "nuclei_scan",
        "Nuclei",
        content_types=(
            "",
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ),
        resource_class="scanner",
        adapter_implemented=True,
        binary_names=("nuclei",),
        source="https://github.com/projectdiscovery/nuclei",
        license="MIT_engine_templates_separate",
        status="implemented_fixture_tested",
        reason="requires_binary_and_reviewed_template_lock",
        cancellation=True,
        auth_replay=True,
    ),
    Capability(
        "ffuf_discover",
        "ffuf",
        profiles=("active-staging", "isolated-lab"),
        resource_class="scanner",
        adapter_implemented=True,
        binary_names=("ffuf",),
        source="https://github.com/ffuf/ffuf/tree/v2.1.0",
        license="MIT",
        status="implemented_fixture_tested",
        reason="requires_pinned_binary_and_host_approved_paths",
        cancellation=True,
    ),
    *tuple(
        Capability(
            id=name,
            tool=tool,
            resource_class="scanner",
            adapter_implemented=True,
            binary_names=binaries,
            source=source,
            license="MIT_CLI_optional_datasets_and_provider_data_separate",
            status="implemented_fixture_tested",
            reason="requires_pinned_binary_and_explicit_configuration",
            cancellation=True,
        )
        for name, tool, binaries, source in (
            (
                "httpx_probe",
                "ProjectDiscovery httpx",
                ("httpx-toolkit", "pd-httpx"),
                "https://github.com/projectdiscovery/httpx/tree/v1.12.0",
            ),
            (
                "katana_discover",
                "Katana (standard)",
                ("katana",),
                "https://github.com/projectdiscovery/katana/tree/v1.8.0",
            ),
            (
                "vulnx_intelligence",
                "VulnX",
                ("vulnx",),
                "https://github.com/projectdiscovery/vulnx/tree/v2.0.2",
            ),
        )
    ),
    *tuple(
        Capability(
            id=capability,
            tool=tool,
            domains=("network",),
            profiles=("active-staging", "isolated-lab"),
            resource_class="scanner",
            adapter_implemented=True,
            binary_names=(binary,),
            source=source,
            license="MIT",
            status="implemented_pending_native_e2e",
            reason="requires_explicit_network_or_dns_grants_and_scoped_socks_broker",
            cancellation=True,
        )
        for capability, tool, binary, source in (
            (
                "naabu_ports",
                "Naabu TCP CONNECT",
                "naabu",
                "https://github.com/projectdiscovery/naabu/tree/v2.6.1",
            ),
            (
                "dnsx_resolve",
                "dnsx controlled TCP DNS",
                "dnsx",
                "https://github.com/projectdiscovery/dnsx/tree/v1.3.1",
            ),
        )
    ),
    Capability(
        "dns_discover",
        "Amass / Subfinder alternatives",
        domains=("network",),
        status="deferred_not_required",
        reason="controlled_dnsx_resolve_selected_no_duplicate_orchestrator",
        source="https://github.com/owasp-amass/amass",
    ),
    Capability(
        "session_refresh",
        "RedJohn explicit session refresh",
        profiles=("active-staging", "isolated-lab"),
        adapter_implemented=True,
        source="redjohn/assessment/session_refresh.py",
        license="project",
        status="implemented_fixture_tested",
        reason="requires_private_refresh_provider_and_vault",
        cancellation=True,
        auth_replay=True,
        owner_process_only=True,
    ),
    Capability(
        "workflow_execute",
        "RedJohn reviewed stateful workflow",
        profiles=("active-staging", "isolated-lab"),
        adapter_implemented=True,
        source="redjohn/assessment/workflow_execution.py",
        license="project",
        status="implemented_pending_live_proof",
        reason="requires_explicit_workflow_configuration_and_private_vault",
        cancellation=True,
        auth_replay=True,
        owner_process_only=True,
    ),
    *tuple(
        Capability(
            id=name,
            tool=tool,
            profiles=("active-staging", "isolated-lab"),
            resource_class="scanner",
            adapter_implemented=True,
            binary_names=(binary,),
            source=source,
            license=license_name,
            status="implemented_fixture_tested",
            reason="requires_pinned_tool_observed_input_and_explicit_selection",
            cancellation=True,
            auth_replay=name in {"sqlmap_validate", "tinja_validate", "schemathesis_validate"},
            content_types=(
                "",
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
            )
            if name in {"tinja_validate", "schemathesis_validate"}
            else ("",),
        )
        for name, tool, binary, source, license_name in (
            (
                "arjun_parameters",
                "Arjun",
                "arjun",
                "https://github.com/s0md3v/Arjun/tree/2.2.7",
                "AGPL-3.0_LICENSE_setup_metadata_conflicts",
            ),
            (
                "sqlmap_validate",
                "sqlmap",
                "sqlmap",
                "https://github.com/sqlmapproject/sqlmap/tree/1.10.10",
                "GPL-2.0-or-later_with_upstream_clarifications",
            ),
            (
                "tinja_validate",
                "TInjA",
                "tinja",
                "https://github.com/Hackmanit/TInjA/tree/1.2.0",
                "Apache-2.0",
            ),
            (
                "schemathesis_validate",
                "Schemathesis",
                "schemathesis",
                "https://github.com/schemathesis/schemathesis/tree/v4.31.1",
                "MIT",
            ),
            (
                "dalfox_validate",
                "Dalfox",
                "dalfox",
                "https://github.com/hahwul/dalfox/tree/v3.2.4",
                "MIT",
            ),
        )
    ),
    *tuple(
        Capability(
            name,
            "Interactsh protocol 1.4.1",
            profiles=("active-staging", "isolated-lab"),
            adapter_implemented=True,
            source="redjohn/assessment/oast.py",
            license="project_protocol_MIT_reference",
            status="implemented_fixture_tested",
            reason="requires_owned_receiver_and_reviewed_input",
            cancellation=True,
            auth_replay=True,
            owner_process_only=True,
            content_types=(
                "",
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
            ),
        )
        for name in ("oast_correlate", "oast_poll")
    ),
    Capability(
        "browser_xss_confirmation",
        "RedJohn Chromium XSS confirmation",
        profiles=("active-staging", "isolated-lab"),
        resource_class="browser",
        adapter_implemented=True,
        source="redjohn/assessment/xss_confirmation.py",
        license="project",
        status="implemented_fixture_tested",
        reason="requires_committed_dalfox_candidate",
        cancellation=True,
    ),
    Capability(
        "browser_post_capture",
        "RedJohn approved Chromium POST capture",
        profiles=("active-staging", "isolated-lab"),
        resource_class="browser",
        adapter_implemented=True,
        source="redjohn/assessment/browser_capture.py",
        license="project",
        status="implemented_fixture_tested",
        reason="requires_private_browser_capture_rules_and_vault",
        cancellation=True,
        auth_replay=True,
    ),
    Capability(
        "browser_auth_flow",
        "RedJohn reviewed Chromium authentication workflow",
        profiles=("active-staging", "isolated-lab"),
        resource_class="browser",
        adapter_implemented=True,
        source="redjohn/assessment/browser_workflow_actions.py",
        license="project",
        status="implemented_pending_live_proof",
        reason="requires_private_authentication_flow_and_one_use_inputs",
        cancellation=True,
        auth_replay=True,
    ),
    Capability(
        "mcp_target_read",
        "RedJohn confined host-bound stdio target read",
        adapter_implemented=True,
        source="redjohn/runtime/mcp_target.py",
        license="project",
        status="implemented_pending_live_proof",
        reason="requires_attested_stdio_and_fixed_reviewed_contract",
        cancellation=True,
        owner_process_only=True,
    ),
    *tuple(
        Capability(
            id=capability,
            tool=tool,
            binary_names=(binary,),
            domains=("source",),
            resource_class="scanner",
            adapter_implemented=True,
            source=source,
            license=license_name,
            status="implemented_pending_native_e2e",
            reason="requires_explicit_immutable_local_manifest_and_offline_namespace",
            cancellation=True,
        )
        for capability, tool, binary, source, license_name in (
            (
                "semgrep_source",
                "Semgrep CE (native OCaml)",
                "osemgrep",
                "https://github.com/semgrep/semgrep/tree/v1.181.0",
                "LGPL-2.1_engine_rules_separate",
            ),
            (
                "trivy_source",
                "Trivy filesystem misconfiguration",
                "trivy",
                "https://github.com/aquasecurity/trivy/tree/v0.76.0",
                "Apache-2.0_engine_embedded_checks_separate",
            ),
        )
    ),
    *tuple(
        Capability(id=name, tool=tool, binary_names=bins, domains=domains, source=source)
        for name, tool, bins, domains, source in (
            (
                "wordpress_assess",
                "WPScan",
                ("wpscan",),
                ("cms",),
                "https://github.com/wpscanteam/wpscan",
            ),
            (
                "cloud_assess",
                "Prowler",
                ("prowler",),
                ("cloud",),
                "https://github.com/prowler-cloud/prowler",
            ),
            (
                "kubernetes_benchmark",
                "kube-bench",
                ("kube-bench",),
                ("kubernetes",),
                "https://github.com/aquasecurity/kube-bench",
            ),
        )
    ),
    Capability(
        "nmap_services",
        "Nmap observed-open service identification",
        domains=("network",),
        profiles=("active-staging", "isolated-lab"),
        resource_class="scanner",
        adapter_implemented=True,
        binary_names=("nmap",),
        source="https://github.com/nmap/nmap/tree/0ee561663c1d7d2d4e708cd414dccfd3d9df30d9",
        license="NPSL-0.95_external_operator_install_distribution_not_granted",
        status="implemented_pending_native_e2e",
        reason="requires_recent_scoped_naabu_open_proof_and_pinned_owned_service_probes",
        cancellation=True,
    ),
    *tuple(
        Capability(
            capability,
            tool,
            domains=("source",),
            resource_class="worker",
            adapter_implemented=True,
            source=source,
            license="Apache-2.0",
            status="implemented_preparation_only_live_audit_deferred",
            reason="immutable_input_manifest_only_no_account_or_cluster_audit_authority",
            cancellation=True,
            owner_process_only=True,
        )
        for capability, tool, source in (
            (
                "cloud_prepare",
                "Prowler reviewed preparation",
                "https://github.com/prowler-cloud/prowler/tree/5.45.0",
            ),
            (
                "kubernetes_prepare",
                "kube-bench reviewed preparation",
                "https://github.com/aquasecurity/kube-bench/tree/v0.16.0",
            ),
        )
    ),
    *tuple(
        Capability(
            name,
            tool,
            domains=domains,
            profiles=("isolated-lab",),
            status="deferred_not_required",
            reason=reason,
        )
        for name, tool, domains, reason in (
            ("feroxbuster", "Feroxbuster", ("web",), "optional_ffuf_alternative"),
            ("gobuster", "Gobuster", ("web",), "optional_ffuf_alternative"),
            ("rustscan", "RustScan", ("network",), "optional_naabu_alternative"),
            ("masscan", "Masscan", ("network",), "separate_explicit_network_package"),
            ("autorecon", "AutoRecon", ("network",), "no_second_embedded_orchestrator"),
            ("scoutsuite", "ScoutSuite", ("cloud",), "optional_prowler_alternative"),
            ("kubehunter", "kube-hunter", ("kubernetes",), "disabled_lab_only"),
            (
                "binary_triage",
                "GDB / angr / pwntools",
                ("binary-lab",),
                "no_binary_fixture_supplied",
            ),
            ("commix", "Commix", ("web",), "no_disposable_command_injection_fixture"),
        )
    ),
)


def _source_configurations(
    semgrep: dict[str, Any] | None, trivy: dict[str, Any] | None
) -> dict[str, Any]:
    if semgrep is None and trivy is None:
        return {}
    from redjohn.assessment.source_tools import CAPABILITIES as SOURCE_CAPABILITIES  # noqa: PLC0415
    from redjohn.assessment.source_tools import SourceToolConfig  # noqa: PLC0415 - selected source engines only

    return {
        SOURCE_CAPABILITIES[name]: SourceToolConfig.from_mapping(name, value)
        for name, value in (("semgrep", semgrep), ("trivy", trivy))
        if value is not None
    }


def _network_configurations(
    naabu: dict[str, Any] | None, dnsx: dict[str, Any] | None
) -> dict[str, Any]:
    if naabu is None and dnsx is None:
        return {}
    from redjohn.assessment.network_tools import CAPABILITIES as NETWORK_CAPABILITIES  # noqa: PLC0415
    from redjohn.assessment.network_tools import NetworkToolConfig  # noqa: PLC0415 - selected native engines only

    return {
        NETWORK_CAPABILITIES[name]: NetworkToolConfig.from_mapping(name, value)
        for name, value in (("naabu", naabu), ("dnsx", dnsx))
        if value is not None
    }


def _preparation_configurations(
    prowler: dict[str, Any] | None, kube_bench: dict[str, Any] | None
) -> dict[str, Any]:
    if prowler is None and kube_bench is None:
        return {}
    from redjohn.assessment.preparation_tools import CAPABILITIES as PREPARATION_CAPABILITIES  # noqa: PLC0415
    from redjohn.assessment.preparation_tools import PreparationConfig  # noqa: PLC0415 - explicit opt-in only

    return {
        PREPARATION_CAPABILITIES[name]: PreparationConfig.from_mapping(name, value)
        for name, value in (("prowler", prowler), ("kube-bench", kube_bench))
        if value is not None
    }


class CapabilityRegistry:
    def __init__(  # noqa: PLR0912, PLR0915 - explicit optional configuration gates
        self,
        *,
        repository_root: str | Path | None = None,
        nuclei_binary_path: str | Path | None = None,
        nuclei_lock: dict[str, Any] | None = None,
        session_refresh_configured: bool = False,
        browser_post_capture_configured: bool = False,
        browser_auth_flow_configured: bool = False,
        workflow_execution_configured: bool = False,
        ffuf_config: dict[str, Any] | None = None,
        httpx_config: dict[str, Any] | None = None,
        katana_config: dict[str, Any] | None = None,
        vulnx_config: dict[str, Any] | None = None,
        arjun_config: dict[str, Any] | None = None,
        sqlmap_config: dict[str, Any] | None = None,
        dalfox_config: dict[str, Any] | None = None,
        tinja_config: dict[str, Any] | None = None,
        schemathesis_config: dict[str, Any] | None = None,
        interactsh_config: dict[str, Any] | None = None,
        semgrep_config: dict[str, Any] | None = None,
        trivy_config: dict[str, Any] | None = None,
        naabu_config: dict[str, Any] | None = None,
        dnsx_config: dict[str, Any] | None = None,
        nmap_config: dict[str, Any] | None = None,
        prowler_config: dict[str, Any] | None = None,
        kube_bench_config: dict[str, Any] | None = None,
    ) -> None:
        """Discover local installation presence without executing optional tools.

        An explicit lock/path describes the requested engine, so a missing file
        does not silently select a different PATH installation. In its absence,
        prefer the repository-managed reviewed install, then retain PATH lookup.
        Neither a filename nor lock metadata proves integrity or a live run;
        the scanner adapter still validates the complete lock before execution.
        """
        self._capabilities = {entry.id: entry for entry in CAPABILITIES}
        self._session_refresh_configured = session_refresh_configured
        self._browser_post_capture_configured = browser_post_capture_configured
        self._browser_auth_flow_configured = browser_auth_flow_configured
        self._mcp_target_versions: ExecutionVersions | None = None
        self._workflow_execution_configured = workflow_execution_configured
        self._ffuf_config = None
        self._source_configs = _source_configurations(semgrep_config, trivy_config)
        self._network_configs = _network_configurations(naabu_config, dnsx_config)
        self._preparation_configs = _preparation_configurations(prowler_config, kube_bench_config)
        self._nmap_config = None
        if nmap_config is not None:
            from redjohn.assessment.service_tools import NmapServiceConfig  # noqa: PLC0415 - explicit optional engine only

            self._nmap_config = NmapServiceConfig.from_mapping(nmap_config)
        self._specialist_configs = {}
        if any(value is not None for value in (arjun_config, sqlmap_config, dalfox_config)):
            from redjohn.assessment.specialists import CAPABILITIES as SPECIALISTS  # noqa: PLC0415
            from redjohn.assessment.specialists import SpecialistConfig  # noqa: PLC0415 - selected adapter only

            for name, value in (
                ("arjun", arjun_config),
                ("sqlmap", sqlmap_config),
                ("dalfox", dalfox_config),
            ):
                if value is not None:
                    self._specialist_configs[SPECIALISTS[name]] = SpecialistConfig.from_mapping(
                        name, value
                    )
        if tinja_config is not None or schemathesis_config is not None:
            from redjohn.assessment.schema_tools import CAPABILITIES as SCHEMA_TOOLS  # noqa: PLC0415
            from redjohn.assessment.schema_tools import SchemaToolConfig  # noqa: PLC0415

            for name, value in (("tinja", tinja_config), ("schemathesis", schemathesis_config)):
                if value is not None:
                    self._specialist_configs[SCHEMA_TOOLS[name]] = SchemaToolConfig.from_mapping(
                        name, value
                    )
        self._oast_config = None
        if interactsh_config is not None:
            from redjohn.assessment.oast import OASTConfig  # noqa: PLC0415

            self._oast_config = OASTConfig.from_mapping(interactsh_config)
        self._discovery_configs = {}
        if httpx_config is not None or katana_config is not None:
            from redjohn.assessment.discovery_tools import DiscoveryToolConfig  # noqa: PLC0415 - opt-in adapter

            for name, value in (("httpx", httpx_config), ("katana", katana_config)):
                if value is not None:
                    self._discovery_configs[
                        name + ("_probe" if name == "httpx" else "_discover")
                    ] = DiscoveryToolConfig.from_mapping(name, value)
        self._vulnx_config = None
        if vulnx_config is not None:
            from redjohn.assessment.vulnx import VulnXConfig  # noqa: PLC0415 - opt-in provider

            self._vulnx_config = VulnXConfig.from_mapping(vulnx_config)
        if ffuf_config is not None:
            from redjohn.assessment.ffuf import FFUFConfig  # noqa: PLC0415 - opt-in adapter

            self._ffuf_config = FFUFConfig.from_mapping(ffuf_config)
        root = Path(repository_root) if repository_root is not None else Path(__file__).parents[2]
        self._managed_nuclei = root / ".tools" / "nuclei" / "3.11.1" / "nuclei"
        self._managed_ffuf = root / ".tools" / "ffuf" / "2.1.0" / "ffuf"
        self._managed_pd = {
            "httpx_probe": root / ".tools/httpx/1.12.0/httpx",
            "katana_discover": root / ".tools/katana/1.8.0/katana",
            "vulnx_intelligence": root / ".tools/vulnx/2.0.2/vulnx",
            "arjun_parameters": root / ".tools/arjun/2.2.7/arjun.tar",
            "sqlmap_validate": root / ".tools/sqlmap/1.10.10/sqlmap.tar",
            "dalfox_validate": root / ".tools/dalfox/3.2.4/dalfox",
            "tinja_validate": root / ".tools/tinja/1.2.0/tinja",
            "schemathesis_validate": root / ".tools/schemathesis/4.31.1/schemathesis.tar",
            "semgrep_source": root / ".tools/semgrep/1.181.0/osemgrep",
            "trivy_source": root / ".tools/trivy/0.76.0/trivy",
            "naabu_ports": root / ".tools/naabu/2.6.1/naabu",
            "dnsx_resolve": root / ".tools/dnsx/1.3.1/dnsx",
            "nmap_services": root / ".tools/nmap/7.992/nmap",
        }
        if nuclei_lock is not None and not isinstance(nuclei_lock, dict):
            raise TypeError("invalid_nuclei_registry_lock_metadata")
        binary = (nuclei_lock or {}).get("binary", {})
        bundle = (nuclei_lock or {}).get("bundle", {})
        if not isinstance(binary, dict) or not isinstance(bundle, dict):
            raise TypeError("invalid_nuclei_registry_lock_metadata")
        path = nuclei_binary_path if nuclei_binary_path is not None else binary.get("path")
        self._configured_nuclei = Path(path) if path is not None else None
        tool_version, template_version = binary.get("version", "1"), bundle.get("sha256", "")
        if not isinstance(tool_version, str) or not isinstance(template_version, str):
            raise TypeError("invalid_nuclei_registry_lock_metadata")
        self._nuclei_versions: ExecutionVersions = {
            "tool_version": tool_version,
            "template_version": template_version,
        }
        self._nuclei_lock_configured = all(
            isinstance(value, str) and bool(value)
            for value in (binary.get("path"), binary.get("version"), bundle.get("sha256"))
        )

    def execution_versions(self, capability: str) -> ExecutionVersions:  # noqa: PLR0911
        """Return configured cache/job identities, never runtime version proof."""
        if capability == "mcp_target_read" and self._mcp_target_versions is not None:
            return self._mcp_target_versions.copy()
        if capability in self._preparation_configs:
            preparation = self._preparation_configs[capability]
            return {"tool_version": preparation.version, "template_version": preparation.revision}
        if capability == "nmap_services" and self._nmap_config is not None:
            return {
                "tool_version": self._nmap_config.version,
                "template_version": self._nmap_config.revision,
            }
        if capability in self._network_configs:
            network = self._network_configs[capability]
            return {"tool_version": network.version, "template_version": network.revision}
        if capability in self._source_configs:
            source = self._source_configs[capability]
            return {"tool_version": source.version, "template_version": source.revision}
        if capability in {"oast_correlate", "oast_poll"} and self._oast_config is not None:
            return {
                "tool_version": self._oast_config.version,
                "template_version": self._oast_config.revision,
            }
        if capability in self._specialist_configs:
            specialist = self._specialist_configs[capability]
            return {"tool_version": specialist.version, "template_version": specialist.revision}
        if capability in self._discovery_configs:
            config = self._discovery_configs[capability]
            return {"tool_version": config.version, "template_version": config.revision}
        if capability == "vulnx_intelligence" and self._vulnx_config is not None:
            return {
                "tool_version": self._vulnx_config.version,
                "template_version": self._vulnx_config.revision,
            }
        if capability == "nuclei_scan":
            return self._nuclei_versions.copy()
        if capability == "ffuf_discover" and self._ffuf_config is not None:
            return {
                "tool_version": self._ffuf_config.version,
                "template_version": self._ffuf_config.revision,
            }
        return {"tool_version": "1", "template_version": ""}

    def bind_mcp_target(self, *, contract_sha256: str, server_version: str) -> None:
        """Trusted host metadata binding; grants no target or dispatch authority."""
        if (
            not isinstance(contract_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", contract_sha256) is None
            or not isinstance(server_version, str)
            or re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", server_version) is None
        ):
            raise ValueError("invalid_host_stdio_registry_metadata")
        versions: ExecutionVersions = {
            "tool_version": server_version,
            "template_version": contract_sha256,
        }
        if self._mcp_target_versions is not None and self._mcp_target_versions != versions:
            raise ValueError("host_stdio_registry_binding_already_set")
        self._mcp_target_versions = versions

    def _binary_presence(self, entry: Capability) -> tuple[str | None, str | None]:  # noqa: PLR0911 - explicit pin prevents PATH fallback
        configured = (
            self._preparation_configs[entry.id].binary
            if entry.id in self._preparation_configs
            else self._nmap_config.binary
            if entry.id == "nmap_services" and self._nmap_config is not None
            else self._source_configs[entry.id].binary
            if entry.id in self._source_configs
            else self._network_configs[entry.id].binary
            if entry.id in self._network_configs
            else self._specialist_configs[entry.id].binary
            if entry.id in self._specialist_configs
            else self._discovery_configs[entry.id].binary
            if entry.id in self._discovery_configs
            else self._vulnx_config.binary
            if entry.id == "vulnx_intelligence" and self._vulnx_config is not None
            else None
        )
        if configured is not None:
            return (str(configured.path) if configured.path.is_file() else None, "configured")
        if entry.id in self._managed_pd and self._managed_pd[entry.id].is_file():
            return str(self._managed_pd[entry.id]), "repo_managed"
        if entry.id == "ffuf_discover" and self._ffuf_config is not None:
            ffuf_path = self._ffuf_config.binary_path
            return (str(ffuf_path) if ffuf_path.is_file() else None, "configured")
        if entry.id == "ffuf_discover" and self._managed_ffuf.is_file():
            return str(self._managed_ffuf), "repo_managed"
        if entry.id == "nuclei_scan":
            if self._configured_nuclei is not None:
                return (
                    str(self._configured_nuclei) if self._configured_nuclei.is_file() else None,
                    "configured",
                )
            if self._managed_nuclei.is_file():
                return str(self._managed_nuclei), "repo_managed"
        path = next((path for name in entry.binary_names if (path := shutil.which(name))), None)
        return path, "PATH" if path is not None else None

    def get(self, name: str) -> Capability | None:
        return self._capabilities.get(name)

    def health(self) -> list[dict[str, Any]]:  # noqa: PLR0912 - one explicit gate per optional capability
        rows = []
        for entry in self._capabilities.values():
            row = asdict(entry)
            row["binary_path"], row["binary_path_source"] = self._binary_presence(entry)
            row["binary_presence_only"] = row["binary_path"] is not None
            row["live_verified"] = False  # only run evidence can establish this
            if entry.id == "browser_discover" and find_spec("playwright") is None:
                row.update(status="blocked_missing_dependency", reason="playwright_not_installed")
            elif entry.id in {"oast_correlate", "oast_poll"} and (
                find_spec("cryptography") is None or find_spec("httpx") is None
            ):
                row.update(
                    status="blocked_missing_dependency", reason="oast_crypto_or_httpx_missing"
                )
            elif entry.adapter_implemented and entry.binary_names and not row["binary_path"]:
                row.update(status="blocked_missing_dependency", reason="binary_not_installed")
            elif entry.id == "nuclei_scan" and not self._nuclei_lock_configured:
                row.update(
                    status="blocked_configuration", reason="reviewed_template_lock_not_configured"
                )
            elif entry.id == "session_refresh" and not self._session_refresh_configured:
                row.update(
                    status="blocked_configuration",
                    reason="private_refresh_provider_and_vault_not_configured",
                )
            elif entry.id == "workflow_execute" and not self._workflow_execution_configured:
                row.update(
                    status="blocked_configuration",
                    reason="explicit_workflow_configuration_and_private_vault_missing",
                )
            elif entry.id == "browser_auth_flow" and not self._browser_auth_flow_configured:
                row.update(
                    status="blocked_configuration",
                    reason="private_authentication_flow_and_one_use_inputs_missing",
                )
            elif entry.id == "mcp_target_read" and self._mcp_target_versions is None:
                row.update(
                    status="blocked_host_stdio_binding_required",
                    reason="attested_host_stdio_contract_not_bound",
                )
            elif entry.id == "ffuf_discover" and self._ffuf_config is None:
                row.update(
                    status="blocked_configuration",
                    reason="pinned_ffuf_and_approved_paths_not_configured",
                )
            elif (
                (
                    entry.id in {"httpx_probe", "katana_discover"}
                    and entry.id not in self._discovery_configs
                )
                or (entry.id == "vulnx_intelligence" and self._vulnx_config is None)
                or (
                    entry.id in {"semgrep_source", "trivy_source"}
                    and entry.id not in self._source_configs
                )
                or (
                    entry.id in {"naabu_ports", "dnsx_resolve"}
                    and entry.id not in self._network_configs
                )
                or (entry.id == "nmap_services" and self._nmap_config is None)
                or (
                    entry.id in {"cloud_prepare", "kubernetes_prepare"}
                    and entry.id not in self._preparation_configs
                )
            ):
                row.update(
                    status="blocked_configuration",
                    reason="pinned_binary_and_approved_tool_configuration_missing",
                )
            elif (
                entry.id
                in {
                    "arjun_parameters",
                    "sqlmap_validate",
                    "dalfox_validate",
                    "tinja_validate",
                    "schemathesis_validate",
                }
                and entry.id not in self._specialist_configs
            ):
                row.update(
                    status="blocked_configuration",
                    reason="pinned_specialist_and_selected_input_configuration_missing",
                )
            elif entry.id in {"oast_correlate", "oast_poll"} and self._oast_config is None:
                row.update(
                    status="blocked_configuration",
                    reason="owned_oast_receiver_configuration_missing",
                )
            elif entry.id == "browser_post_capture" and not self._browser_post_capture_configured:
                row.update(
                    status="blocked_configuration",
                    reason="private_browser_capture_rules_and_vault_not_configured",
                )
            elif (
                entry.id == "browser_xss_confirmation"
                and "dalfox_validate" not in self._specialist_configs
            ):
                row.update(
                    status="blocked_configuration",
                    reason="dalfox_confirmation_outbox_not_configured",
                )
            rows.append(row)
        return rows
