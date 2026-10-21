"""Ten logical operations through one bounded schema, without scanner arguments."""

from __future__ import annotations

import json

from agents import RunContextWrapper, function_tool


@function_tool(timeout=30)
async def assessment_control(ctx: RunContextWrapper, operation: str, arguments_json: str) -> str:
    """Use the host-bound engagement control API.

    Operations: surface_search, surface_get, plan_next_batch, jobs_submit_batch,
    jobs_get_status, jobs_cancel, evidence_get, coverage_get, findings_get,
    system_health. Each argument object requires policy_revision. Job submission
    queues reviewed capabilities; only the scheduler starts tools.
    """
    from redjohn.assessment.control import AssessmentControl  # noqa: PLC0415 - lazy host binding
    from redjohn.assessment.models import error_record  # noqa: PLC0415 - lazy host binding

    context = ctx.context if isinstance(ctx.context, dict) else {}
    service = context.get("assessment_service")
    if not isinstance(service, AssessmentControl):
        return json.dumps(
            {
                "ok": False,
                "error": error_record(
                    "engagement_context_required", category="policy", coverage_effect="blocked"
                ),
            }
        )
    if len(arguments_json.encode()) > 65536:
        return json.dumps(
            {"ok": False, "error": error_record("invalid_api_input_size", category="input")}
        )
    try:
        arguments = json.loads(arguments_json)
    except json.JSONDecodeError:
        return json.dumps(
            {"ok": False, "error": error_record("invalid_api_input", category="input")}
        )
    return json.dumps(await service.call(operation, arguments), ensure_ascii=True)
