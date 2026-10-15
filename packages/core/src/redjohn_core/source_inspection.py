"""Bounded read-only source inspection, sensitive-read secret masking, and AST sink analysis."""

from __future__ import annotations

import ast
import base64
import json
import os
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .errors import RJError
from .models import Agent, Run
from .opsec_guard import redact_sensitive_content
from .scope import target_covered

EXCLUDED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist"}

PYTHON_SINK_MAP: dict[str, tuple[str, bool]] = {
    "eval": ("rce", False),
    "exec": ("rce", False),
    "compile": ("rce", False),
    "os.system": ("rce", False),
    "os.popen": ("rce", False),
    "subprocess.Popen": ("rce", True),
    "subprocess.run": ("rce", True),
    "subprocess.call": ("rce", True),
    "subprocess.check_output": ("rce", True),
    "pickle.loads": ("deserialization", False),
    "pickle.load": ("deserialization", False),
    "marshal.loads": ("deserialization", False),
    "yaml.load": ("deserialization", False),
    "yaml.unsafe_load": ("deserialization", False),
    "jsonpickle.decode": ("deserialization", False),
    "cursor.execute": ("sqli", True),
    "session.execute": ("sqli", True),
    "connection.execute": ("sqli", True),
    "db.execute": ("sqli", True),
    "requests.get": ("ssrf", True),
    "requests.post": ("ssrf", True),
    "requests.request": ("ssrf", True),
    "httpx.get": ("ssrf", True),
    "httpx.post": ("ssrf", True),
    "urllib.request.urlopen": ("ssrf", True),
    "send_file": ("path_traversal", True),
    "flask.send_file": ("path_traversal", True),
}

POLYGLOT_SINK_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("rce", "child_process.exec", re.compile(r"\b(?:child_process\.)?(?:exec|execSync|spawn)\s*\(")),
    ("rce", "eval", re.compile(r"\beval\s*\(")),
    ("rce", "php_shell_exec", re.compile(r"\b(?:shell_exec|passthru|system|proc_open|popen)\s*\(")),
    ("deserialization", "php_unserialize", re.compile(r"\bunserialize\s*\(")),
    ("sqli", "raw_sql_query", re.compile(r"\b(?:\$queryRawUnsafe|queryRaw|rawQuery|mysqli_query)\s*\(")),
    ("xss", "dangerouslySetInnerHTML", re.compile(r"\bdangerouslySetInnerHTML\b")),
)

_FUNC_DECL_RE = re.compile(
    r"(?:function\s+([A-Za-z0-9_$]+)|(?:async\s+)?([A-Za-z0-9_$]+)\s*\([^)]*\)\s*\{|func\s+([A-Za-z0-9_]+))"
)


def local_source_path(run: Run, agent: Agent, relative_path: str = ".") -> Path:
    root = Path(getattr(run, "authorized_target", "") or "")
    if not root.is_absolute():
        raise RJError("scope_violation", "This session has no authorized local source directory", status=403)
    root = root.resolve()
    path = (root / relative_path).resolve()
    if not path.is_relative_to(root) or not target_covered(str(path), agent.allowed_targets):
        raise RJError(
            "scope_violation", "Source path is outside the agent's authorized directory", status=403
        )
    return path


def list_source_files(run: Run, agent: Agent, relative_path: str = ".", limit: int = 250) -> str:
    root = local_source_path(run, agent, relative_path)
    if not root.is_dir():
        raise RJError("validation_error", "Source path must be a directory", status=422)
    result: list[str] = []
    cap = min(max(limit, 1), 1000)
    truncated = False
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            d for d in directories if d not in EXCLUDED_DIRECTORIES and not (Path(directory) / d).is_symlink()
        )
        for name in sorted(filenames):
            path = Path(directory) / name
            if path.is_symlink() or not target_covered(str(path.resolve()), agent.allowed_targets):
                continue
            if len(result) >= cap:
                truncated = True
                break
            result.append(str(path.relative_to(root)))
        if truncated:
            break
    return json.dumps({"directory": str(root), "files": result, "truncated": truncated})


def read_source_file(run: Run, agent: Agent, relative_path: str, output_cap: int) -> str:
    path = local_source_path(run, agent, relative_path)
    if not path.is_file():
        raise RJError("validation_error", "Source path must be a regular file", status=422)
    with path.open("rb") as stream:
        data = stream.read(min(output_cap, 262144) + 1)
    truncated = len(data) > min(output_cap, 262144)
    data = data[: min(output_cap, 262144)]
    if b"\x00" in data:
        raise RJError("validation_error", "Use a text source file", status=422)
    text = data.decode("utf-8", errors="replace")
    if os.environ.get("REDJOHN_REDACT_SOURCE_SECRETS", "1") != "0":
        text, _ = redact_sensitive_content(text)
    return text + ("\n[truncated]" if truncated else "")


def _call_qualname(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        curr: ast.AST = func.value
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


def _is_dynamic_expr(expr: ast.AST | None) -> bool:
    if expr is None:
        return False
    if isinstance(expr, ast.Constant):
        return False
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp):
        return True
    if isinstance(expr, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
        return True
    return True


def _scan_python_ast_sinks(
    rel_file: str,
    source_text: str,
    category_filter: str,
) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(source_text, filename=rel_file)
    except SyntaxError:
        return []
    lines = source_text.splitlines()
    hits: list[dict[str, Any]] = []

    def walk_scope(node: ast.AST, scope_stack: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            next_scope = scope_stack
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                next_scope = [*scope_stack, child.name]
            if isinstance(child, ast.Call):
                qname = _call_qualname(child)
                matched_cat = ""
                require_dynamic = False
                if qname in PYTHON_SINK_MAP:
                    matched_cat, require_dynamic = PYTHON_SINK_MAP[qname]
                elif qname.endswith(".execute") and any(
                     p in qname for p in ("cursor", "session", "db", "conn")
                ):
                    matched_cat, require_dynamic = ("sqli", True)

                if matched_cat and (category_filter == "all" or category_filter == matched_cat):
                    first_arg = child.args[0] if child.args else None
                    dynamic_arg = _is_dynamic_expr(first_arg)
                    shell_true = any(
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                        for kw in child.keywords
                    )
                    safe_yaml = qname == "yaml.load" and any(
                        kw.arg == "Loader"
                        and "SafeLoader" in ast.unparse(kw.value)
                        for kw in child.keywords
                    )
                    if not safe_yaml and (not require_dynamic or dynamic_arg or shell_true):
                        lineno = getattr(child, "lineno", 1)
                        snippet = lines[lineno - 1].strip()[:200] if 1 <= lineno <= len(lines) else ""
                        hits.append(
                            {
                                "file": rel_file,
                                "line": lineno,
                                "enclosing_symbol": ".".join(next_scope) or "<module>",
                                "category": matched_cat,
                                "sink": qname,
                                "dynamic_argument": dynamic_arg or shell_true,
                                "shell_true": shell_true,
                                "snippet": snippet,
                            }
                        )
            walk_scope(child, next_scope)

    walk_scope(tree, [])
    return hits


def _scan_polyglot_sinks(
    rel_file: str,
    source_text: str,
    category_filter: str,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    current_symbol = "<top_level>"
    for lineno, raw_line in enumerate(source_text.splitlines(), start=1):
        fn_match = _FUNC_DECL_RE.search(raw_line)
        if fn_match:
            current_symbol = next((g for g in fn_match.groups() if g), current_symbol)
        for cat, sink_name, pattern in POLYGLOT_SINK_PATTERNS:
            if category_filter not in ("all", cat):
                continue
            if pattern.search(raw_line):
                hits.append(
                    {
                        "file": rel_file,
                        "line": lineno,
                        "enclosing_symbol": current_symbol,
                        "category": cat,
                        "sink": sink_name,
                        "dynamic_argument": True,
                        "shell_true": False,
                        "snippet": raw_line.strip()[:200],
                    }
                )
    return hits


def ast_sink_search(
    run: Run,
    agent: Agent,
    relative_path: str = ".",
    category: str = "all",
    limit: int = 100,
) -> str:
    """Search authorized local source files for AST-level dangerous sinks and enclosing symbols.

    Supports categories: 'all', 'rce', 'deserialization', 'sqli', 'ssrf', 'path_traversal', 'xss'.
    """
    target = local_source_path(run, agent, relative_path)
    root = local_source_path(run, agent, ".")
    cap = min(max(limit, 1), 250)
    cat_norm = category.strip().casefold() or "all"

    candidate_files: list[Path] = []
    if target.is_file():
        candidate_files.append(target)
    elif target.is_dir():
        for directory, directories, filenames in os.walk(target, followlinks=False):
            directories[:] = sorted(
                d
                for d in directories
                if d not in EXCLUDED_DIRECTORIES and not (Path(directory) / d).is_symlink()
            )
            for name in sorted(filenames):
                p = Path(directory) / name
                if p.is_symlink() or not target_covered(str(p.resolve()), agent.allowed_targets):
                    continue
                if p.suffix.lower() in (".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go", ".java", ".rb"):
                    candidate_files.append(p)
                    if len(candidate_files) >= 500:
                        break
            if len(candidate_files) >= 500:
                break
    else:
        raise RJError("validation_error", "Source path must be an existing file or directory", status=422)

    all_hits: list[dict[str, Any]] = []
    for file_path in candidate_files:
        try:
            raw_bytes = file_path.read_bytes()[:262144]
        except OSError:
            continue
        if b"\x00" in raw_bytes:
            continue
        text = raw_bytes.decode("utf-8", errors="replace")
        if os.environ.get("REDJOHN_REDACT_SOURCE_SECRETS", "1") != "0":
            text, _ = redact_sensitive_content(text)
        rel = str(file_path.relative_to(root))
        if file_path.suffix.lower() == ".py":
            all_hits.extend(_scan_python_ast_sinks(rel, text, cat_norm))
        else:
            all_hits.extend(_scan_polyglot_sinks(rel, text, cat_norm))
        if len(all_hits) >= cap:
            break

    return json.dumps(
        {
            "directory": str(root),
            "category": cat_norm,
            "files_scanned": len(candidate_files),
            "total_sinks": len(all_hits[:cap]),
            "truncated": len(all_hits) > cap,
            "external_sast_available": {
                "ast_grep": shutil.which("sg") is not None or shutil.which("ast-grep") is not None,
                "semgrep_cli": shutil.which("semgrep") is not None,
                "semgrep_mode": "cli_json_only (avoids semgrep 1.159.0 --x-mcp regression)",
            },
            "sinks": all_hits[:cap],
        }
    )


def scan_local_ast_sinks(
    target_path: str | Path = ".",
    category: str = "all",
    limit: int = 100,
) -> dict[str, Any]:
    """Scan a local file or directory for AST-level dangerous sinks without requiring Run/Agent state."""
    target = Path(target_path).expanduser().resolve()
    if not target.exists():
        raise RJError("validation_error", f"Source path does not exist: {target}", status=422)
    root = target if target.is_dir() else target.parent
    cap = min(max(limit, 1), 250)
    cat_norm = category.strip().casefold() or "all"

    candidate_files: list[Path] = []
    if target.is_file():
        candidate_files.append(target)
    elif target.is_dir():
        for directory, directories, filenames in os.walk(target, followlinks=False):
            directories[:] = sorted(
                d
                for d in directories
                if d not in EXCLUDED_DIRECTORIES and not (Path(directory) / d).is_symlink()
            )
            for name in sorted(filenames):
                p = Path(directory) / name
                if p.is_symlink():
                    continue
                if p.suffix.lower() in (".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go", ".java", ".rb"):
                    candidate_files.append(p)
                    if len(candidate_files) >= 500:
                        break
            if len(candidate_files) >= 500:
                break

    all_hits: list[dict[str, Any]] = []
    for file_path in candidate_files:
        try:
            raw_bytes = file_path.read_bytes()[:262144]
        except OSError:
            continue
        if b"\x00" in raw_bytes:
            continue
        text = raw_bytes.decode("utf-8", errors="replace")
        if os.environ.get("REDJOHN_REDACT_SOURCE_SECRETS", "1") != "0":
            text, _ = redact_sensitive_content(text)
        rel = str(file_path.relative_to(root))
        if file_path.suffix.lower() == ".py":
            all_hits.extend(_scan_python_ast_sinks(rel, text, cat_norm))
        else:
            all_hits.extend(_scan_polyglot_sinks(rel, text, cat_norm))
        if len(all_hits) >= cap:
            break

    return {
        "directory": str(root),
        "category": cat_norm,
        "files_scanned": len(candidate_files),
        "total_sinks": len(all_hits[:cap]),
        "truncated": len(all_hits) > cap,
        "external_sast_available": {
            "ast_grep": shutil.which("sg") is not None or shutil.which("ast-grep") is not None,
            "semgrep_cli": shutil.which("semgrep") is not None,
            "semgrep_mode": "cli_json_only (avoids semgrep 1.159.0 --x-mcp regression)",
        },
        "sinks": all_hits[:cap],
    }



def github_repository(run: Run, agent: Agent) -> tuple[str, str]:
    target = getattr(run, "authorized_target", "") or ""
    parsed = urlsplit(target)
    parts = parsed.path.strip("/").split("/")
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or len(parts) != 2
        or not all(parts)
        or not target_covered(target, agent.allowed_targets)
    ):
        raise RJError("scope_violation", "This session has no authorized GitHub repository", status=403)
    return parts[0], parts[1].removesuffix(".git")


async def github_source(
    run: Run, agent: Agent, *, path: str | None = None, ref: str = "HEAD", limit: int = 250
) -> str:
    owner, repo = github_repository(run, agent)
    if not ref or len(ref) > 200:
        raise RJError("validation_error", "Invalid repository ref", status=422)
    prefix = f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("RJ_GITHUB_TOKEN") or os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if path is None:
        url = f"{prefix}/git/trees/{quote(ref, safe='')}"
        params = {"recursive": "1"}
    else:
        relative = PurePosixPath(path)
        if relative.is_absolute() or ".." in relative.parts or "\\" in path:
            raise RJError("scope_violation", "Repository path must remain inside the repository", status=403)
        url = f"{prefix}/contents/{quote(str(relative), safe='/')}"
        params = {"ref": ref}
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=30) as client:
        async with client.stream("GET", url, params=params, headers=headers) as response:
            if response.status_code != 200:
                raise RJError(
                    "repository_unavailable", f"GitHub returned HTTP {response.status_code}", status=502
                )
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 4_194_304:
                    raise RJError(
                        "repository_response_too_large", "GitHub response exceeds 4 MiB", status=422
                    )
    data = json.loads(raw)
    if path is None:
        files = [entry["path"] for entry in data.get("tree", []) if entry.get("type") == "blob"]
        cap = min(max(limit, 1), 1000)
        return json.dumps(
            {
                "repository": f"{owner}/{repo}",
                "ref": ref,
                "files": files[:cap],
                "truncated": bool(data.get("truncated")) or len(files) > cap,
            }
        )
    if not isinstance(data, dict) or data.get("type") != "file" or data.get("encoding") != "base64":
        raise RJError(
            "validation_error", "Choose a regular repository file with readable content", status=422
        )
    content = base64.b64decode(data["content"])
    if len(content) > 262144 or b"\x00" in content:
        raise RJError("validation_error", "Repository file is binary or exceeds 256 KiB", status=422)
    decoded = content.decode("utf-8", errors="replace")
    if os.environ.get("REDJOHN_REDACT_SOURCE_SECRETS", "1") != "0":
        decoded, _ = redact_sensitive_content(decoded)
    return decoded
