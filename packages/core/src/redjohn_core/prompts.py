"""Persistent RedJohn instructions and inherited scan-profile context."""

from __future__ import annotations

from pathlib import Path

from .models import Agent, Run
from .skill_registry import MASTER_SKILL, SCAN_PROFILE_SKILLS, SkillRegistry

SYSTEM_PROMPT = (Path(__file__).with_name("data") / "system_prompt.md").read_text(encoding="utf-8")


def agent_system_prompt(agent: Agent, run: Run, registry: SkillRegistry | None = None) -> str:
    registry = registry or SkillRegistry()
    selected_mode = getattr(run, "scan_mode", "standard")
    mode = getattr(selected_mode, "value", str(selected_mode))
    selected_kind = getattr(run, "target_kind", "web_application") or "web_application"
    target_kind = getattr(selected_kind, "value", str(selected_kind))
    target = getattr(run, "authorized_target", "") or ", ".join(run.scope.allowed_targets)
    profile = SCAN_PROFILE_SKILLS.get(mode, SCAN_PROFILE_SKILLS["standard"])
    task = agent.task or run.task or "Assess the authorized target using the selected profile."
    return (
        f"{SYSTEM_PROMPT}\nCurrent session: {run.run_id}\n"
        f"Agent: {agent.name} ({agent.role.value}); parent: {agent.parent_agent_id or '(coordinator)'}\n"
        f"Assessment kind: {target_kind}; authorized target: {target}\n"
        f"Inherited scan mode: {mode} (load {profile}; never escalate)\n"
        f"Assigned task: {task}\n"
        f"Agent target scope: {', '.join(agent.allowed_targets) or '(none)'}\n"
        f"Runtime tools: {', '.join(agent.allowed_tools) or '(none)'}\n\n"
        f"[Master methodology]\n{registry.read(MASTER_SKILL)}\n\n"
        f"[Selected scan profile]\n{registry.read(profile)}"
    )
