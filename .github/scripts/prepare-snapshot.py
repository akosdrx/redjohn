#!/usr/bin/env python3
"""Build an explicit source-only publishing manifest without touching Git index."""

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXCLUDED = {"node_modules", ".tools", "__pycache__", ".pytest_cache", ".mypy_cache",
            ".ruff_cache", ".venv", "build", "dist", "bin", "archive", "measurements", "screenshots"}
PATTERNS = {
    "private_key_material": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=]{32}"),
    "github_token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})"),
    "openai_token": re.compile(rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}"),
    "aws_access_key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "credential_url": re.compile(rb"https?://[^\s/:'\"]+:[^\s/@'\"]{10,}@"),
}
DOCUMENT_JSON = frozenset({
    "redjohn-capabilities.json", "redjohn-schemas.json", "third-party-references.json",
})


def selected():
    files = set()
    for directory in ("redjohn", "tests", "scripts", "benchmarks", "examples", ".github", "docs"):
        for path in (ROOT / directory).rglob("*"):
            relative = path.relative_to(ROOT)
            if any(part in EXCLUDED for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError("refuse_publishing_symlink:" + str(relative))
            if not path.is_file():
                continue
            if directory == "docs":
                reviewed_json = len(relative.parts) == 2 and path.name in DOCUMENT_JSON
                if (path.suffix != ".md" and not reviewed_json) or "changed-files" in path.name:
                    continue
            if (path.name.startswith(".env") or path.suffix in {".log", ".pyc", ".sqlite3", ".db", ".pem", ".key"}
                    or path.name == ".DS_Store"):
                continue
            files.add(relative.as_posix())
    for name in (
        "README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md",
        "pyproject.toml", "requirements-assessment.lock", "redjohn.spec",
        ".gitignore", ".env.example",
    ):
        if (ROOT / name).is_file():
            files.add(name)
    return sorted(files)


def prepare():
    files = {}
    findings = []
    for name in selected():
        path = ROOT / name
        data = path.read_bytes()
        if len(data) > 2 * 1024 * 1024:
            findings.append({"file": name, "rule": "unexpected_large_source"})
        for rule, pattern in PATTERNS.items():
            if pattern.search(data):
                findings.append({"file": name, "rule": rule})
        files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                       "executable": bool(path.stat().st_mode & 0o111)}
    return {"files": files, "bytes": sum(row["bytes"] for row in files.values()),
            "findings": findings, "scope": "explicit current source tree; no Git index or history mutation",
            "secret_scan_limit": "pattern scan and explicit path allowlist; no claim of universal secret detection"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = prepare()
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"files": len(result["files"]), "bytes": result["bytes"], "findings": result["findings"]}))
    raise SystemExit(1 if result["findings"] else 0)
