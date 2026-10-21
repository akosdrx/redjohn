"""Lazy public composition of bounded, explicitly approved offline artifacts.

Parsing is structural only. Operator IO and native execution belong to the
selected scanner lease; composition never opens a database, HTML or Ruby file.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from redjohn.assessment.models import JobSpec
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


def artifact_configurations(
    sbom: dict[str, Any] | None, wordpress: dict[str, Any] | None
) -> dict[str, Any]:
    configurations: dict[str, Any] = {}
    if sbom is not None:
        from redjohn.assessment.trivy_sbom import TrivySBOMConfig  # noqa: PLC0415

        configurations["trivy_sbom"] = TrivySBOMConfig.from_mapping(sbom)
    if wordpress is not None:
        from redjohn.assessment.wpscan_observe import WPScanObserveConfig  # noqa: PLC0415

        configurations["wordpress_observe"] = WPScanObserveConfig.from_mapping(wordpress)
    return configurations


def configured_artifact_job(
    capability: str,
    document: object,
    policy: EngagementPolicy,
    store: AssessmentStore,
    *,
    timeout_seconds: float,
    retest_revision: str,
) -> JobSpec:
    if capability == "trivy_sbom":
        from redjohn.assessment.trivy_sbom import TrivySBOMConfig, trivy_sbom_job  # noqa: PLC0415

        return trivy_sbom_job(
            TrivySBOMConfig.from_mapping(document),
            policy,
            store,
            timeout_seconds=timeout_seconds,
            retest_revision=retest_revision,
        )
    if capability == "wordpress_observe":
        from redjohn.assessment.wpscan_observe import WPScanObserveConfig, wordpress_observe_job  # noqa: PLC0415

        return wordpress_observe_job(
            WPScanObserveConfig.from_mapping(document),
            policy,
            store,
            timeout_seconds=timeout_seconds,
            retest_revision=retest_revision,
        )
    raise ValueError("unknown_artifact_capability")
