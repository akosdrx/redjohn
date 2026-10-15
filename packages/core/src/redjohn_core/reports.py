"""Report generation: Jinja2 HTML + JSON from run data; optional PDF via
the ``pdf`` extra (weasyprint). Artifacts land in ``<profile>/reports/``.

The canonical ``Report`` model lives in models.py (contract anchor, v0.1.1).
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, Literal

from jinja2 import Environment, PackageLoader, select_autoescape

from .errors import RJError, unavailable
from .models import Report, utcnow

if TYPE_CHECKING:
    from .engine import Engine


def _jinja() -> Environment:
    return Environment(
        loader=PackageLoader("redjohn_core", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )


async def _gather(engine: Engine, run_id: str) -> dict[str, Any]:
    store = engine.store
    run = await store.get_run(run_id)
    agents = await store.list_agents(run_id)
    findings = await store.all_findings(run_id)
    evidence = await store.list_evidence(run_id)
    messages = await store.list_messages(run_id)
    invocations = await store.list_invocations(run_id)
    events = await store.list_events(run_id, after_seq=0, limit=100_000)
    return {
        "run": run.model_dump(mode="json"),
        "agents": [a.model_dump(mode="json") for a in agents],
        "findings": [f.model_dump(mode="json") for f in findings],
        "evidence": [e.model_dump(mode="json") for e in evidence],
        "messages": [m.model_dump(mode="json") for m in messages],
        "tool_invocations": [i.model_dump(mode="json") for i in invocations],
        "timeline": [e.model_dump(mode="json") for e in events],
        "generated_at": utcnow().isoformat(),
    }


async def generate_report(
    engine: Engine, run_id: str, fmt: Literal["html", "json", "pdf"]
) -> Report:
    data = await _gather(engine, run_id)
    report = Report(run_id=run_id, format=fmt)
    out_path = engine.settings.reports_dir / f"{report.report_id}.{fmt}"

    # Serialization, Jinja rendering and weasyprint PDF generation are CPU-bound
    # and can take seconds on a large run. Run them off the event loop so the
    # engine's loop (WebSocket streaming, agent coroutines, other reads) is not
    # frozen while a report is generated.
    await asyncio.to_thread(_render_to_file, data, fmt, out_path)

    report.storage_ref = out_path.name
    async with engine.store.write() as s:
        await engine.store.insert_report(
            s, report.report_id, run_id, fmt, report.storage_ref, report.model_dump(mode="json")
        )
    return report


def _render_to_file(data: dict[str, Any], fmt: str, out_path: Any) -> None:
    """Synchronous render + file write; invoked via ``asyncio.to_thread``."""
    if fmt == "json":
        out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elif fmt == "html":
        out_path.write_text(_render_html(data), encoding="utf-8")
    elif fmt == "pdf":
        _render_pdf(_render_html(data), out_path)
    else:  # pragma: no cover - guarded by route validation
        raise RJError("validation_error", f"unknown report format {fmt!r}", status=422)


def _render_html(data: dict[str, Any]) -> str:
    template = _jinja().get_template("report.html.j2")
    return template.render(**data)


def _render_pdf(html: str, out_path: Any) -> None:
    """PDF via the optional weasyprint extra. Render is isolated: the HTML is
    self-contained (no external resources) and base_url is None, so no
    network or filesystem access happens during rendering."""
    try:
        import weasyprint  # type: ignore[import-not-found]
    except ImportError as exc:
        raise unavailable(
            "pdf reports require the optional 'pdf' extra (weasyprint)",
            code="report_format_unavailable",
        ) from exc
    weasyprint.HTML(string=html, base_url=None).write_pdf(str(out_path))
