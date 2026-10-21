"""``load_skill`` — fetch skill reference material into the conversation."""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from redjohn.skills import load_skills, validate_requested_skills


@function_tool(timeout=10)
async def load_skill(ctx: RunContextWrapper, skills: list[str]) -> str:
    """Return the markdown body of one or more skills as reference material.

    Use this when you need exact syntax / workflow / payload guidance
    right before acting on a technology that wasn't preloaded for your
    agent. The skill content lands inline as a tool result — no
    permanent prompt change, just in-conversation reference.

    For permanent skill assignment, pass ``skills=[…]`` to
    ``create_agent`` when spawning a specialist child instead.

    Args:
        skills: List of domain or assessment skill names (e.g.
            ``["injection", "assessment/sql-injection-validation", "auth"]``).
            Max 8. Names match ``redjohn/skills/<category>/<name>.md`` or
            ``redjohn/skills/assessment/<name>/SKILL.md``.
    """
    requested = list(skills or [])
    err = validate_requested_skills(requested)
    if err:
        return f"load_skill: {err}"
    context = ctx.context if isinstance(ctx.context, dict) else {}
    contents = load_skills(requested, supports_images=context.get("supports_images", True))
    if not contents:
        return "load_skill: no content loaded for requested skills."
    agent_skills = context.get("agent_skills")
    if isinstance(agent_skills, set):
        agent_skills.update(contents.keys())
    sections = [f"## Skill: {name}\n\n{body}" for name, body in contents.items()]
    return "\n\n---\n\n".join(sections)
