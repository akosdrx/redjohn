"""Lazy capability catalogue: installed binary, adapter and live proof differ."""

from __future__ import annotations

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
    *tuple(
        Capability(id=name, tool=tool, binary_names=bins, domains=domains, source=source)
        for name, tool, bins, domains, source in (
            (
                "semgrep_source",
                "Semgrep",
                ("semgrep",),
                ("source",),
                "https://github.com/semgrep/semgrep",
            ),
            (
                "trivy_source",
                "Trivy",
                ("trivy",),
                ("source", "cloud"),
                "https://github.com/aquasecurity/trivy",
            ),
            (
                "naabu_ports",
                "Naabu",
                ("naabu",),
                ("network",),
                "https://github.com/projectdiscovery/naabu",
            ),
            ("nmap_services", "Nmap", ("nmap",), ("network",), "https://nmap.org/"),
            (
                "dns_discover",
                "Amass / Subfinder / dnsx",
                ("amass", "subfinder", "dnsx"),
                ("network",),
                "https://github.com/owasp-amass/amass",
            ),
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


class CapabilityRegistry:
    def __init__(  # noqa: PLR0912 - explicit optional configuration gates
        self,
        *,
        repository_root: str | Path | None = None,
        nuclei_binary_path: str | Path | None = None,
        nuclei_lock: dict[str, Any] | None = None,
        session_refresh_configured: bool = False,
        browser_post_capture_configured: bool = False,
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
        self._ffuf_config = None
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

    def _binary_presence(self, entry: Capability) -> tuple[str | None, str | None]:  # noqa: PLR0911 - explicit pin prevents PATH fallback
        configured = (
            self._specialist_configs[entry.id].binary
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

    def health(self) -> list[dict[str, Any]]:
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
            elif entry.id == "ffuf_discover" and self._ffuf_config is None:
                row.update(
                    status="blocked_configuration",
                    reason="pinned_ffuf_and_approved_paths_not_configured",
                )
            elif (
                entry.id in {"httpx_probe", "katana_discover"}
                and entry.id not in self._discovery_configs
            ) or (entry.id == "vulnx_intelligence" and self._vulnx_config is None):
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
