"""Vulnerability & Exploit Intelligence MCP server (OSV, NVD v2, CISA KEV, FIRST EPSS, InternetDB, Nuclei).

Provides deterministic, multi-source CVE and package advisory lookup,
Composite Risk Scoring (R_kompozit + KEV Hard Override), CISA SSVC v2 decision trees,
batch OSV dependency auditing with ecosystem normalization, keyless Shodan InternetDB
host recon, and SQLite TTL caching so swarm coordinators immediately route Tier 1/2
RCE and Auth-Bypass CVEs through P1.5 fast-path verification before generic fuzzing.
"""

# Parent PID polling uses asyncio.sleep in a background watcher loop.
# ruff: noqa: ASYNC110

from __future__ import annotations

import argparse
import asyncio
import datetime
import ipaddress
import json
import os
import re
import signal
import socket
import sqlite3
import time
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

import httpx
try:
    from mcp.server import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[no-redef]
    from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[no-redef]
from pydantic import Field

from .tool_catalog import native_tools_root

CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.IGNORECASE)
RCE_CWES = {"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-96", "CWE-434", "CWE-502", "CWE-1336"}
AUTH_BYPASS_CWES = {"CWE-287", "CWE-288", "CWE-290", "CWE-306", "CWE-798", "CWE-862", "CWE-863"}
SQLI_CWES = {"CWE-89", "CWE-564", "CWE-943"}
SSRF_CWES = {"CWE-918"}
LFI_CWES = {"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-98"}

RCE_KEYWORDS = (
    "remote code execution",
    "arbitrary code execution",
    "command injection",
    "os command",
    "deserialization",
    "unserialize",
    "template injection",
    "ssti",
    "arbitrary file upload",
    "unrestricted upload",
    "code injection",
    "eval(",
    "rce",
)
AUTH_KEYWORDS = (
    "authentication bypass",
    "auth bypass",
    "unauthenticated admin",
    "privilege escalation",
    "hardcoded credential",
    "jwt bypass",
)

ECOSYSTEM_ALIASES: dict[str, str] = {
    "composer": "Packagist",
    "packagist": "Packagist",
    "php": "Packagist",
    "magento": "Packagist",
    "shopware": "Packagist",
    "prestashop": "Packagist",
    "laravel": "Packagist",
    "symfony": "Packagist",
    "wordpress": "Packagist",
    "woocommerce": "Packagist",
    "drupal": "Packagist",
    "joomla": "Packagist",
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "javascript": "npm",
    "typescript": "npm",
    "nextjs": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "pip": "PyPI",
    "django": "PyPI",
    "flask": "PyPI",
    "maven": "Maven",
    "java": "Maven",
    "spring": "Maven",
    "struts": "Maven",
    "go": "Go",
    "golang": "Go",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "gem": "RubyGems",
    "rails": "RubyGems",
    "nuget": "NuGet",
    "dotnet": "NuGet",
    ".net": "NuGet",
    "crates.io": "crates.io",
    "crates": "crates.io",
    "rust": "crates.io",
    "cargo": "crates.io",
}

VULN_INTEL_TOOLS = {
    "vuln_query_package",
    "vuln_query_batch",
    "vuln_query_cve",
    "vuln_enrich_priority",
    "vuln_internetdb_host",
    "nuclei_search_templates",
}

INTERNAL_HOSTNAME_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".localdomain")


def normalize_ecosystem(ecosystem: str) -> str:
    """Normalize package ecosystem names to exact OSV.dev case-sensitive identifiers."""
    cleaned = ecosystem.strip()
    if not cleaned:
        return ""
    return ECOSYSTEM_ALIASES.get(cleaned.casefold(), cleaned)


def classify_vulnerability(summary: str, cwes: list[str]) -> tuple[str, str, float, float]:
    """Return (vuln_class, recommended_skill, impact_weight, probe_cost)."""
    cwe_set = {c.upper().strip() for c in cwes}
    lowered = summary.casefold()
    if cwe_set & RCE_CWES or any(k in lowered for k in RCE_KEYWORDS):
        return "rce", "45-rce-exploitation", 10.0, 1.5
    if cwe_set & AUTH_BYPASS_CWES or any(k in lowered for k in AUTH_KEYWORDS):
        return "auth_bypass", "30-auth-access-control", 8.5, 1.5
    if cwe_set & LFI_CWES or "path traversal" in lowered or "local file inclusion" in lowered:
        return "lfi_traversal", "45-rce-exploitation", 7.5, 2.0
    if cwe_set & SSRF_CWES or "server-side request forgery" in lowered or "ssrf" in lowered:
        return "ssrf", "40-injection-engine", 7.5, 2.0
    if cwe_set & SQLI_CWES or "sql injection" in lowered or "sqli" in lowered:
        return "sqli", "40-injection-engine", 7.0, 4.0
    return "other", "70-exploit-intel", 4.5, 2.5


def compute_priority_score(
    *,
    impact_weight: float,
    fingerprint_tier: int,
    in_kev: bool,
    epss_score: float,
    has_nuclei_template: bool,
    probe_cost: float,
) -> float:
    """Compute Expected-Value priority score: (Impact * TierConfidence * Maturity) / Cost."""
    if fingerprint_tier == 1:
        tier_weight = 1.0
    elif fingerprint_tier == 2:
        tier_weight = 0.8
    else:
        tier_weight = 0.35
    maturity = 1.5
    if in_kev:
        maturity = max(maturity, 3.2)
    if has_nuclei_template:
        maturity = max(maturity, 2.8)
    if epss_score >= 0.5:
        maturity = max(maturity, 2.6)
    elif epss_score >= 0.1:
        maturity = max(maturity, 2.0)
    return round((impact_weight * tier_weight * maturity) / max(probe_cost, 0.5), 2)


def compute_composite_risk_score(
    *,
    base_score: float = 0.0,
    impact_weight: float = 4.5,
    epss_score: float = 0.0,
    in_kev: bool = False,
    has_poc: bool = False,
    cve_id: str = "",
) -> tuple[float, str]:
    """Compute 0-100 Composite Risk Score (R_kompozit) with CISA KEV Hard Override.

    Formula:
      R_kompozit = (CVSS_norm * 35) + (EPSS * 30) + (KEV * 20) + (PoC * 10) + (Age_factor * 5)
    KEV Hard Override:
      Any CVE present in CISA KEV is guaranteed >= 76.0 (CRITICAL).
    """
    effective_cvss = base_score if base_score > 0.0 else min(max(impact_weight, 0.0), 10.0)
    cvss_norm = min(max(effective_cvss, 0.0), 10.0) / 10.0
    epss_norm = min(max(epss_score, 0.0), 1.0)
    kev_val = 1.0 if in_kev else 0.0
    poc_val = 1.0 if (has_poc or in_kev) else 0.0

    age_factor = 0.6
    match = CVE_RE.match(cve_id.strip())
    if match:
        cve_year = int(match.group(1))
        current_year = datetime.datetime.now(datetime.UTC).year
        age = max(0, current_year - cve_year)
        if age <= 2:
            age_factor = 1.0
        elif age <= 5:
            age_factor = 0.6
        else:
            age_factor = 0.3

    raw_score = (
        (cvss_norm * 35.0)
        + (epss_norm * 30.0)
        + (kev_val * 20.0)
        + (poc_val * 10.0)
        + (age_factor * 5.0)
    )
    if in_kev:
        raw_score = max(raw_score, 76.0)
    score = round(min(max(raw_score, 0.0), 100.0), 2)

    if score >= 76.0:
        level = "CRITICAL"
    elif score >= 51.0:
        level = "HIGH"
    elif score >= 26.0:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level


def compute_ssvc_decision(
    *,
    in_kev: bool,
    epss_score: float,
    has_poc: bool,
    vuln_class: str,
    base_score: float = 0.0,
) -> str:
    """Evaluate CISA SSVC v2 decision tree: Act, Attend, Track*, or Track."""
    if in_kev or epss_score >= 0.70:
        exploitation = "active"
    elif has_poc or epss_score >= 0.10:
        exploitation = "poc"
    else:
        exploitation = "none"

    automatable = vuln_class in ("rce", "auth_bypass", "sqli", "ssrf")
    total_impact = vuln_class in ("rce", "auth_bypass") or base_score >= 9.0

    if exploitation == "active":
        if automatable or total_impact:
            return "Act"
        return "Attend"
    if exploitation == "poc":
        if automatable and total_impact:
            return "Attend"
        if automatable or total_impact:
            return "Track*"
        return "Track"
    if automatable and total_impact:
        return "Track*"
    return "Track"


class VulnIntelCache:
    """Lightweight SQLite + in-memory TTL cache for CVE/EPSS/KEV/InternetDB intelligence."""

    def __init__(self, db_path: Path | None = None, default_ttl_seconds: int = 21600) -> None:
        env_path = os.environ.get("REDJOHN_VULN_CACHE_DB", "").strip()
        if db_path is not None:
            self.db_path = db_path
        elif env_path:
            self.db_path = Path(env_path)
        else:
            self.db_path = Path.home() / ".redjohn" / "vuln_intel_cache.db"
        self.default_ttl = max(60, default_ttl_seconds)
        self._mem: dict[str, tuple[float, Any]] = {}
        self._sqlite_ok = False
        self._init_db()

    def _init_db(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS vuln_cache ("
                    "cache_key TEXT PRIMARY KEY, "
                    "payload_json TEXT NOT NULL, "
                    "expires_at REAL NOT NULL)"
                )
                conn.commit()
            self._sqlite_ok = True
        except Exception:
            self._sqlite_ok = False

    def get(self, key: str) -> Any | None:
        now = time.time()
        mem_hit = self._mem.get(key)
        if mem_hit is not None:
            exp, val = mem_hit
            if exp > now:
                return val
            self._mem.pop(key, None)
        if not self._sqlite_ok:
            return None
        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                conn.execute("PRAGMA busy_timeout=5000")
                row = conn.execute(
                    "SELECT payload_json, expires_at FROM vuln_cache WHERE cache_key = ?",
                    (key,),
                ).fetchone()
                if not row:
                    return None
                payload_json, expires_at = row
                if float(expires_at) <= now:
                    conn.execute("DELETE FROM vuln_cache WHERE cache_key = ?", (key,))
                    conn.commit()
                    return None
                val = json.loads(payload_json)
                self._mem[key] = (float(expires_at), val)
                return val
        except Exception:
            return None

    def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = time.time() + max(1, ttl)
        self._mem[key] = (expires_at, value)
        if not self._sqlite_ok:
            return
        try:
            payload_json = json.dumps(value)
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute(
                    "INSERT OR REPLACE INTO vuln_cache (cache_key, payload_json, expires_at) "
                    "VALUES (?, ?, ?)",
                    (key, payload_json, expires_at),
                )
                conn.commit()
        except Exception:
            pass


@lru_cache(maxsize=4)
def _cached_nuclei_yaml_index(root_str: str, mtime_ns: int) -> tuple[tuple[str, str, Path], ...]:
    del mtime_ns
    root = Path(root_str)
    entries: list[tuple[str, str, Path]] = []
    seen: set[Path] = set()
    subdirs = (
        "http/cves",
        "http/vulnerabilities",
        "http/misconfiguration",
        "http/exposed-panels",
        "http",
    )
    for sub in subdirs:
        subdir = root / sub
        if subdir.is_dir():
            for path in subdir.rglob("*.yaml"):
                if path not in seen and path.is_file():
                    seen.add(path)
                    rel = str(path.relative_to(root))
                    entries.append((rel, rel.casefold(), path))
                    if len(entries) >= 8000:
                        return tuple(entries)
    for path in root.rglob("*.yaml"):
        if path not in seen and path.is_file():
            seen.add(path)
            rel = str(path.relative_to(root))
            entries.append((rel, rel.casefold(), path))
            if len(entries) >= 8000:
                break
    return tuple(entries)


def _nuclei_yaml_entries(root: Path) -> tuple[tuple[str, str, Path], ...]:
    try:
        resolved = root.resolve()
        return _cached_nuclei_yaml_index(str(resolved), resolved.stat().st_mtime_ns)
    except OSError:
        return ()


def _extract_osv_record(item: dict[str, Any], templates_root: Path | None = None) -> dict[str, Any]:
    osv_id = str(item.get("id", ""))
    aliases = [str(a) for a in item.get("aliases", []) if isinstance(a, str)]
    cve_ids = sorted(
        {a.upper() for a in ([osv_id, *aliases]) if CVE_RE.match(a)}
    )
    summary = str(item.get("summary") or item.get("details") or "")[:400].strip()
    db_specific = item.get("database_specific") or {}
    raw_cwes = db_specific.get("cwe_ids") or []
    cwes = [str(c) for c in raw_cwes if isinstance(c, str)]
    affected_ranges: list[str] = []
    fixed_versions: list[str] = []
    for aff in item.get("affected", []) or []:
        pkg_name = (aff.get("package") or {}).get("name", "")
        for rng in aff.get("ranges", []) or []:
            events = rng.get("events") or []
            parts: list[str] = []
            for ev in events:
                if "introduced" in ev and ev["introduced"] != "0":
                    parts.append(f">={ev['introduced']}")
                if "fixed" in ev:
                    parts.append(f"<{ev['fixed']}")
                    fixed_versions.append(str(ev["fixed"]))
                if "last_affected" in ev:
                    parts.append(f"<={ev['last_affected']}")
            if parts:
                prefix = f"{pkg_name}: " if pkg_name else ""
                affected_ranges.append(prefix + ",".join(parts))
    vuln_class, rec_skill, impact_w, cost = classify_vulnerability(summary, cwes)
    local_templates: list[str] = []
    if templates_root and templates_root.is_dir() and cve_ids:
        entries = _nuclei_yaml_entries(templates_root)
        for cid in cve_ids:
            needle = cid.casefold()
            matches = [rel for rel, rel_lower, _ in entries if needle in rel_lower]
            local_templates.extend(matches[:3])
    refs = [
        str(r.get("url"))
        for r in (item.get("references") or [])[:6]
        if isinstance(r, dict) and r.get("url")
    ]
    primary_cve = cve_ids[0] if cve_ids else ""
    has_tpl = bool(local_templates)
    comp_score, comp_level = compute_composite_risk_score(
        base_score=0.0,
        impact_weight=impact_w,
        epss_score=0.0,
        in_kev=False,
        has_poc=has_tpl,
        cve_id=primary_cve,
    )
    ssvc = compute_ssvc_decision(
        in_kev=False,
        epss_score=0.0,
        has_poc=has_tpl,
        vuln_class=vuln_class,
    )
    return {
        "id": osv_id,
        "cve_ids": cve_ids,
        "summary": summary,
        "cwes": cwes,
        "vuln_class": vuln_class,
        "fast_path_rce": vuln_class in ("rce", "auth_bypass", "lfi_traversal"),
        "recommended_skill": rec_skill,
        "affected_ranges": affected_ranges[:8],
        "fixed_versions": sorted(set(fixed_versions))[:8],
        "local_nuclei_templates": sorted(set(local_templates)),
        "composite_risk_score": comp_score,
        "composite_risk_level": comp_level,
        "ssvc_decision": ssvc,
        "references": refs,
        "_impact_weight": impact_w,
        "_probe_cost": cost,
    }


def search_nuclei_directory(
    root: Path,
    *,
    query: str = "",
    cve_id: str = "",
    tags: list[str] | str | None = None,
    severity: str = "",
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Scan local nuclei-templates directory for matching CVE or technology templates."""
    if not root.is_dir():
        return []
    limit = min(max(limit, 1), 100)
    cve_norm = cve_id.strip().upper()
    cve_lower = cve_norm.casefold()
    query_terms = [t.casefold() for t in query.split() if t.strip()]
    raw_tags = tags.split(",") if isinstance(tags, str) else (tags or [])
    tag_set = {t.strip().casefold() for t in raw_tags if t.strip()}
    sev_set = {s.strip().casefold() for s in severity.split(",") if s.strip()}

    entries = _nuclei_yaml_entries(root)
    results: list[dict[str, Any]] = []
    for rel, rel_lower, path in entries:
        if cve_lower and cve_lower not in rel_lower:
            continue
        if query_terms and not all(term in rel_lower for term in query_terms):
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:2048]
            except OSError:
                continue
            haystack = f"{rel_lower}\n{head.casefold()}"
            if not all(term in haystack for term in query_terms):
                continue
        else:
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:2048]
            except OSError:
                continue
        id_match = re.search(r"(?m)^id:\s*([^\s#]+)", head)
        name_match = re.search(r"(?m)^\s*name:\s*(.+)$", head)
        sev_match = re.search(r"(?m)^\s*severity:\s*([^\s#]+)", head)
        tags_match = re.search(r"(?m)^\s*tags:\s*(.+)$", head)
        tpl_id = id_match.group(1).strip("'\"") if id_match else path.stem
        tpl_name = name_match.group(1).strip().strip("'\"") if name_match else path.stem
        tpl_sev = (sev_match.group(1).strip().casefold() if sev_match else "unknown")
        tpl_tags = [
            t.strip().casefold()
            for t in (tags_match.group(1).split(",") if tags_match else [])
            if t.strip()
        ]
        if sev_set and tpl_sev not in sev_set:
            continue
        if tag_set and not (tag_set & set(tpl_tags)):
            continue
        results.append(
            {
                "template": rel,
                "id": tpl_id,
                "name": tpl_name,
                "severity": tpl_sev,
                "tags": tpl_tags,
            }
        )
        if len(results) >= limit:
            break
    return results


class VulnIntelRuntime:
    def __init__(
        self,
        templates_root: Path | None = None,
        nvd_api_key: str = "",
        cache_db_path: Path | None = None,
    ) -> None:
        self.templates_root = templates_root or (native_tools_root() / "nuclei-templates")
        self.nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY", "")
        self.cache = VulnIntelCache(db_path=cache_db_path)
        self._kev_cache: dict[str, dict[str, Any]] | None = None
        self._kev_lock = asyncio.Lock()

    async def get_kev_catalog(self, client: httpx.AsyncClient) -> dict[str, dict[str, Any]]:
        async with self._kev_lock:
            if self._kev_cache is not None:
                return self._kev_cache
            cached = await asyncio.to_thread(self.cache.get, "cisa_kev_catalog_v1")
            if isinstance(cached, dict) and cached:
                self._kev_cache = cached
                return self._kev_cache
            try:
                resp = await client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=8.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities") or []
                    self._kev_cache = {
                        str(v["cveID"]).upper(): {
                            "date_added": v.get("dateAdded"),
                            "product": v.get("product"),
                            "vendor": v.get("vendorProject"),
                            "short_description": v.get("shortDescription"),
                            "known_ransomware": v.get("knownRansomwareCampaignUse"),
                        }
                        for v in vulns
                        if isinstance(v, dict) and v.get("cveID")
                    }
                    await asyncio.to_thread(
                        self.cache.set, "cisa_kev_catalog_v1", self._kev_cache, 43200
                    )
                    return self._kev_cache
            except Exception:
                pass
            self._kev_cache = {}
            return self._kev_cache


def create_server(runtime: VulnIntelRuntime) -> MCPServer:
    @asynccontextmanager
    async def lifespan(_server: MCPServer):
        parent = os.getppid()

        async def watch_parent() -> None:
            while os.getppid() == parent:
                await asyncio.sleep(1)
            os._exit(0)

        watcher = asyncio.create_task(watch_parent())
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, lambda: os._exit(0))
        try:
            yield {}
        finally:
            watcher.cancel()

    server = MCPServer("RedJohn vulnerability & exploit intelligence", lifespan=lifespan)

    @server.tool()
    async def vuln_query_package(
        package: str,
        version: str = "",
        ecosystem: str = "",
        fingerprint_tier: Annotated[int, Field(ge=1, le=4)] = 1,
    ) -> dict[str, Any]:
        """Query OSV.dev & GHSA for known vulnerabilities affecting a package/component and version.

        Use immediately in P1.5 when 10-recon-endpoint-mapping or source review identifies a
        package, CMS, shop platform (Magento, Shopware, WooCommerce, PrestaShop, Laravel,
        Next.js, Spring, Struts, etc.) and version (tier 1 or 2). Filters withdrawn advisories
        and returns ranked advisories with fast_path_rce, composite_risk_score, and ssvc_decision.
        """
        pkg = package.strip()
        if not pkg or len(pkg) > 200:
            raise ToolError("Provide a non-empty package or component name.")
        if fingerprint_tier > 2:
            return {
                "package": pkg,
                "version": version,
                "fingerprint_tier": fingerprint_tier,
                "status": "refused_low_confidence_tier",
                "detail": (
                    "Tier 3/4 fingerprints cannot support CVE claims per 70-exploit-intel. "
                    "Upgrade the version fingerprint to Tier 1/2 via 10-recon-endpoint-mapping first."
                ),
                "vulnerabilities": [],
            }

        eco_norm = normalize_ecosystem(ecosystem)
        default_ecos = ["Packagist", "npm", "PyPI", "Maven", "Go", "RubyGems", "crates.io", "NuGet"]
        ecosystems_to_try = [eco_norm] if eco_norm else default_ecos

        seen_ids: set[str] = set()
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        withdrawn_filtered = 0
        truncated = False

        async with httpx.AsyncClient(trust_env=False, timeout=12.0) as client:
            tasks = []
            for eco in ecosystems_to_try:
                payload: dict[str, Any] = {"package": {"name": pkg, "ecosystem": eco}}
                if version.strip():
                    payload["version"] = version.strip().lstrip("vV")
                tasks.append(client.post("https://api.osv.dev/v1/query", json=payload))
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for resp in responses:
                if isinstance(resp, BaseException):
                    errors.append(str(resp)[:160])
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.json()
                if body.get("next_page_token"):
                    truncated = True
                for raw in body.get("vulns") or []:
                    if not isinstance(raw, dict):
                        continue
                    if raw.get("withdrawn"):
                        withdrawn_filtered += 1
                        continue
                    vid = str(raw.get("id", ""))
                    if not vid or vid in seen_ids:
                        continue
                    seen_ids.add(vid)
                    rec = _extract_osv_record(raw, runtime.templates_root)
                    rec["priority_score"] = compute_priority_score(
                        impact_weight=rec.pop("_impact_weight"),
                        fingerprint_tier=fingerprint_tier,
                        in_kev=False,
                        epss_score=0.0,
                        has_nuclei_template=bool(rec["local_nuclei_templates"]),
                        probe_cost=rec.pop("_probe_cost"),
                    )
                    records.append(rec)

        records.sort(
            key=lambda r: (r["fast_path_rce"], r["composite_risk_score"], r["priority_score"]),
            reverse=True,
        )
        claim_rung = (
            "likely vulnerable (requires D2 benign proof to confirm)"
            if fingerprint_tier == 1
            else "version in range, impact unverified (banner-sourced)"
        )
        return {
            "package": pkg,
            "version": version,
            "ecosystem_queried": ecosystems_to_try,
            "fingerprint_tier": fingerprint_tier,
            "claim_ladder_rung": claim_rung,
            "total_matches": len(records),
            "withdrawn_filtered": withdrawn_filtered,
            "truncated": truncated or len(records) > 30,
            "fast_path_rce_count": sum(1 for r in records if r["fast_path_rce"]),
            "vulnerabilities": records[:30],
            "network_warnings": errors[:3] if not records and errors else [],
        }

    @server.tool()
    async def vuln_query_batch(
        packages: Annotated[list[dict[str, str]], Field(min_length=1, max_length=100)],
        fingerprint_tier: Annotated[int, Field(ge=1, le=4)] = 1,
    ) -> dict[str, Any]:
        """Batch-audit up to 100 dependencies against OSV.dev (/v1/querybatch) with concurrency isolation.

        Each item in `packages` should provide `{"package": "...", "version": "...", "ecosystem": "..."}`.
        Automatically normalizes ecosystem casing (PyPI, npm, Packagist, Maven, Go, crates.io, NuGet),
        filters withdrawn advisories, and flags pagination truncation.
        """
        if fingerprint_tier > 2:
            return {
                "fingerprint_tier": fingerprint_tier,
                "status": "refused_low_confidence_tier",
                "detail": (
                    "Batch dependency queries require Tier 1 (lockfile/manifest) or Tier 2 fingerprints."
                ),
                "results": [],
            }

        normalized_queries: list[dict[str, Any]] = []
        query_meta: list[dict[str, str]] = []
        for entry in packages[:100]:
            pkg = str(entry.get("package") or entry.get("name") or "").strip()
            ver = str(entry.get("version") or "").strip().lstrip("vV")
            eco = normalize_ecosystem(str(entry.get("ecosystem") or ""))
            if not pkg:
                continue
            q_obj: dict[str, Any] = {"package": {"name": pkg}}
            if eco:
                q_obj["package"]["ecosystem"] = eco
            if ver:
                q_obj["version"] = ver
            normalized_queries.append(q_obj)
            query_meta.append({"package": pkg, "version": ver, "ecosystem": eco})

        if not normalized_queries:
            raise ToolError("Provide at least one valid package entry with a non-empty 'package' name.")

        truncated = False
        withdrawn_filtered = 0
        detail_sem = asyncio.Semaphore(8)
        batch_results: list[dict[str, Any]] = []

        async with httpx.AsyncClient(trust_env=False, timeout=15.0) as client:
            resp = await client.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": normalized_queries},
            )
            if resp.status_code != 200:
                raise ToolError(f"OSV querybatch returned HTTP {resp.status_code}")
            raw_results = resp.json().get("results") or []

            # Collect unique advisory IDs (capped to avoid context flooding)
            unique_ids: list[str] = []
            seen_ids: set[str] = set()
            for res in raw_results:
                if not isinstance(res, dict):
                    continue
                if res.get("next_page_token"):
                    truncated = True
                for v in res.get("vulns") or []:
                    if isinstance(v, dict) and v.get("id"):
                        vid = str(v["id"])
                        if vid not in seen_ids and len(unique_ids) < 60:
                            seen_ids.add(vid)
                            unique_ids.append(vid)

            async def fetch_advisory(adv_id: str) -> tuple[str, dict[str, Any] | None]:
                cached = await asyncio.to_thread(runtime.cache.get, f"osv_adv:{adv_id}")
                if isinstance(cached, dict):
                    return adv_id, cached
                async with detail_sem:
                    try:
                        r = await client.get(f"https://api.osv.dev/v1/vulns/{adv_id}", timeout=8.0)
                        if r.status_code == 200:
                            data = r.json()
                            await asyncio.to_thread(runtime.cache.set, f"osv_adv:{adv_id}", data, 21600)
                            return adv_id, data
                    except Exception:
                        pass
                return adv_id, None

            fetched_pairs = await asyncio.gather(*(fetch_advisory(aid) for aid in unique_ids))
            adv_map = {aid: data for aid, data in fetched_pairs if data is not None}

            for idx, meta in enumerate(query_meta):
                res_obj = (
                    raw_results[idx]
                    if idx < len(raw_results) and isinstance(raw_results[idx], dict)
                    else {}
                )
                pkg_vulns: list[dict[str, Any]] = []
                for v in res_obj.get("vulns") or []:
                    if not isinstance(v, dict) or not v.get("id"):
                        continue
                    vid = str(v["id"])
                    full = adv_map.get(vid, v)
                    if full.get("withdrawn"):
                        withdrawn_filtered += 1
                        continue
                    rec = _extract_osv_record(full, runtime.templates_root)
                    rec["priority_score"] = compute_priority_score(
                        impact_weight=rec.pop("_impact_weight"),
                        fingerprint_tier=fingerprint_tier,
                        in_kev=False,
                        epss_score=0.0,
                        has_nuclei_template=bool(rec["local_nuclei_templates"]),
                        probe_cost=rec.pop("_probe_cost"),
                    )
                    pkg_vulns.append(rec)
                if pkg_vulns:
                    pkg_vulns.sort(
                        key=lambda r: (r["fast_path_rce"], r["composite_risk_score"], r["priority_score"]),
                        reverse=True,
                    )
                    batch_results.append(
                        {
                            "package": meta["package"],
                            "version": meta["version"],
                            "ecosystem": meta["ecosystem"],
                            "vulnerability_count": len(pkg_vulns),
                            "fast_path_rce_count": sum(1 for r in pkg_vulns if r["fast_path_rce"]),
                            "vulnerabilities": pkg_vulns[:15],
                        }
                    )

        batch_results.sort(
            key=lambda b: (b["fast_path_rce_count"], b["vulnerability_count"]),
            reverse=True,
        )
        return {
            "queried_packages": len(normalized_queries),
            "vulnerable_packages": len(batch_results),
            "withdrawn_filtered": withdrawn_filtered,
            "truncated": truncated,
            "results": batch_results,
        }

    @server.tool()
    async def vuln_query_cve(cve_id: str) -> dict[str, Any]:
        """Look up full CVE details across OSV.dev, NVD v2, FIRST EPSS, CISA KEV, and Nuclei templates.

        Computes expected-value priority_score, 0-100 composite_risk_score (with KEV Hard Override >= 76),
        and CISA SSVC v2 decision tier (Act, Attend, Track*, Track).
        """
        clean = cve_id.strip().upper()
        if not CVE_RE.match(clean):
            raise ToolError("Provide a valid CVE identifier (e.g. CVE-2024-12345).")

        cache_key = f"cve_full:{clean}"
        cached = await asyncio.to_thread(runtime.cache.get, cache_key)
        if isinstance(cached, dict):
            return {**cached, "cache_hit": True}

        headers: dict[str, str] = {"Accept": "application/json"}
        if runtime.nvd_api_key:
            headers["apiKey"] = runtime.nvd_api_key

        osv_data: dict[str, Any] = {}
        nvd_item: dict[str, Any] = {}
        epss_data: dict[str, Any] = {}
        kev_entry: dict[str, Any] | None = None

        async with httpx.AsyncClient(trust_env=False, timeout=12.0) as client:
            osv_req = client.get(f"https://api.osv.dev/v1/vulns/{clean}")
            nvd_req = client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": clean},
                headers=headers,
            )
            epss_req = client.get("https://api.first.org/data/v1/epss", params={"cve": clean})
            kev_req = runtime.get_kev_catalog(client)
            osv_resp, nvd_resp, epss_resp, kev_map = await asyncio.gather(
                osv_req, nvd_req, epss_req, kev_req, return_exceptions=True
            )
            if isinstance(osv_resp, httpx.Response) and osv_resp.status_code == 200:
                osv_data = osv_resp.json()
            if isinstance(nvd_resp, httpx.Response) and nvd_resp.status_code == 200:
                vulns = nvd_resp.json().get("vulnerabilities") or []
                if vulns and isinstance(vulns[0], dict):
                    nvd_item = vulns[0].get("cve") or {}
            if isinstance(epss_resp, httpx.Response) and epss_resp.status_code == 200:
                rows = epss_resp.json().get("data") or []
                if rows and isinstance(rows[0], dict):
                    epss_data = rows[0]
            if isinstance(kev_map, dict):
                kev_entry = kev_map.get(clean)

        descriptions = [
            d.get("value", "")
            for d in (nvd_item.get("descriptions") or [])
            if isinstance(d, dict) and d.get("lang") == "en"
        ]
        description = (
            descriptions[0]
            if descriptions
            else str(osv_data.get("details") or osv_data.get("summary") or "")
        )[:1200]

        cwes: list[str] = []
        for w in nvd_item.get("weaknesses") or []:
            for desc in w.get("description") or []:
                val = str(desc.get("value", ""))
                if val.startswith("CWE-"):
                    cwes.append(val)
        for c in (osv_data.get("database_specific") or {}).get("cwe_ids") or []:
            if isinstance(c, str) and c not in cwes:
                cwes.append(c)

        metrics = nvd_item.get("metrics") or {}
        cvss_vector = ""
        base_score = 0.0
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if entries and isinstance(entries[0], dict):
                cvss_data = entries[0].get("cvssData") or {}
                cvss_vector = str(cvss_data.get("vectorString", ""))
                base_score = float(cvss_data.get("baseScore") or 0.0)
                break

        epss_score = float(epss_data.get("epss") or 0.0)
        epss_percentile = float(epss_data.get("percentile") or 0.0)
        vuln_class, rec_skill, impact_w, cost = classify_vulnerability(description, cwes)
        templates = search_nuclei_directory(runtime.templates_root, cve_id=clean, limit=5)

        refs = [
            str(r.get("url"))
            for r in (nvd_item.get("references") or osv_data.get("references") or [])[:10]
            if isinstance(r, dict) and r.get("url")
        ]
        in_kev = kev_entry is not None
        has_poc = bool(templates) or any("exploit" in r.casefold() or "poc" in r.casefold() for r in refs)
        comp_score, comp_level = compute_composite_risk_score(
            base_score=base_score,
            impact_weight=impact_w,
            epss_score=epss_score,
            in_kev=in_kev,
            has_poc=has_poc,
            cve_id=clean,
        )
        ssvc = compute_ssvc_decision(
            in_kev=in_kev,
            epss_score=epss_score,
            has_poc=has_poc,
            vuln_class=vuln_class,
            base_score=base_score,
        )

        result = {
            "cve_id": clean,
            "description": description,
            "cwes": cwes,
            "cvss_vector": cvss_vector,
            "base_score": base_score,
            "vuln_class": vuln_class,
            "fast_path_rce": vuln_class in ("rce", "auth_bypass", "lfi_traversal") or in_kev,
            "recommended_skill": rec_skill,
            "in_cisa_kev": in_kev,
            "cisa_kev_detail": kev_entry,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "priority_score": compute_priority_score(
                impact_weight=impact_w,
                fingerprint_tier=1,
                in_kev=in_kev,
                epss_score=epss_score,
                has_nuclei_template=bool(templates),
                probe_cost=cost,
            ),
            "composite_risk_score": comp_score,
            "composite_risk_level": comp_level,
            "ssvc_decision": ssvc,
            "local_nuclei_templates": [t["template"] for t in templates],
            "references": refs,
            "cache_hit": False,
        }
        await asyncio.to_thread(runtime.cache.set, cache_key, result, 21600)
        return result

    @server.tool()
    async def vuln_enrich_priority(
        cve_ids: Annotated[list[str], Field(min_length=1, max_length=50)],
        fingerprint_tier: Annotated[int, Field(ge=1, le=4)] = 1,
    ) -> dict[str, Any]:
        """Enrich CVE IDs with CISA KEV status, FIRST EPSS probability, Composite Risk Score, and SSVC v2.

        Returns CVEs sorted highest-priority first so the Coordinator delegates
        P1.5 fast-path RCE/KEV verification before generic P5 SQLi probing.
        """
        cleaned = sorted({c.strip().upper() for c in cve_ids if CVE_RE.match(c.strip())})
        if not cleaned:
            raise ToolError("Provide at least one valid CVE-YYYY-NNNNN identifier.")

        epss_map: dict[str, tuple[float, float]] = {}
        async with httpx.AsyncClient(trust_env=False, timeout=10.0) as client:
            kev_task = runtime.get_kev_catalog(client)
            epss_task = client.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": ",".join(cleaned)},
            )
            kev_map, epss_resp = await asyncio.gather(kev_task, epss_task, return_exceptions=True)
            if not isinstance(kev_map, dict):
                kev_map = {}
            if isinstance(epss_resp, httpx.Response) and epss_resp.status_code == 200:
                for row in epss_resp.json().get("data") or []:
                    if isinstance(row, dict) and row.get("cve"):
                        epss_map[str(row["cve"]).upper()] = (
                            float(row.get("epss") or 0.0),
                            float(row.get("percentile") or 0.0),
                        )

        ranked: list[dict[str, Any]] = []
        for cid in cleaned:
            in_kev = cid in kev_map
            epss_score, epss_pct = epss_map.get(cid, (0.0, 0.0))
            kev_info = kev_map.get(cid) or {}
            kev_desc = str(kev_info.get("short_description") or "")
            vclass, rec_skill, impact_w, cost = classify_vulnerability(kev_desc, [])
            if in_kev and vclass == "other":
                impact_w = 9.0
                cost = 1.5
            templates = search_nuclei_directory(runtime.templates_root, cve_id=cid, limit=3)
            has_tpl = bool(templates)
            score = compute_priority_score(
                impact_weight=impact_w,
                fingerprint_tier=fingerprint_tier,
                in_kev=in_kev,
                epss_score=epss_score,
                has_nuclei_template=has_tpl,
                probe_cost=cost,
            )
            comp_score, comp_level = compute_composite_risk_score(
                base_score=0.0,
                impact_weight=impact_w,
                epss_score=epss_score,
                in_kev=in_kev,
                has_poc=has_tpl,
                cve_id=cid,
            )
            ssvc = compute_ssvc_decision(
                in_kev=in_kev,
                epss_score=epss_score,
                has_poc=has_tpl,
                vuln_class=vclass,
            )
            fast_path = (
                in_kev
                or ssvc in ("Act", "Attend")
                or epss_score >= 0.25
                or has_tpl
                or vclass == "rce"
            )
            ranked.append(
                {
                    "cve_id": cid,
                    "priority_score": score,
                    "composite_risk_score": comp_score,
                    "composite_risk_level": comp_level,
                    "ssvc_decision": ssvc,
                    "dispatch_phase": "P1.5-FAST-PATH" if fast_path else "P5-STANDARD",
                    "in_cisa_kev": in_kev,
                    "epss_score": epss_score,
                    "epss_percentile": epss_pct,
                    "local_nuclei_templates": [t["template"] for t in templates],
                    "recommended_skill": "45-rce-exploitation" if fast_path else rec_skill,
                }
            )

        ranked.sort(
            key=lambda item: (item["composite_risk_score"], item["priority_score"]),
            reverse=True,
        )
        return {
            "fingerprint_tier": fingerprint_tier,
            "ranked_cves": ranked,
        }

    @server.tool()
    async def vuln_internetdb_host(
        host_or_ip: str,
        resolve_dns: bool = False,
    ) -> dict[str, Any]:
        """Passive, keyless Shodan InternetDB lookup (https://internetdb.shodan.io/{ip}).

        Returns open ports, CPEs, hostnames, tags, and known CVEs for a public IP in milliseconds
        without sending active packets to the target. Strictly refuses private/RFC1918/loopback IPs
        and internal hostnames (.local, .internal, .lan) to preserve engagement OpSec.
        """
        raw = host_or_ip.strip()
        if not raw or len(raw) > 253:
            raise ToolError("Provide a valid IP address or hostname.")

        ip_str = ""
        try:
            ip_obj = ipaddress.ip_address(raw)
            ip_str = str(ip_obj)
        except ValueError:
            lowered = raw.casefold()
            if lowered == "localhost" or lowered.endswith(INTERNAL_HOSTNAME_SUFFIXES):
                return {
                    "target": raw,
                    "status": "skipped_internal_hostname",
                    "detail": (
                        "Refusing external InternetDB lookup for internal/local hostname (OpSec guard)."
                    ),
                }
            if not resolve_dns:
                return {
                    "target": raw,
                    "status": "requires_ip_or_resolve_dns",
                    "detail": "Pass a public IP address directly or set resolve_dns=True for public domains.",
                }
            try:
                infos = await asyncio.to_thread(
                    socket.getaddrinfo, raw, None, socket.AF_UNSPEC, socket.SOCK_STREAM
                )
                if not infos:
                    raise ToolError(f"Could not resolve hostname {raw!r}")
                resolved_ips = [ipaddress.ip_address(str(info[4][0])) for info in infos]
                non_global = next((ip for ip in resolved_ips if not ip.is_global), None)
                ip_obj = non_global if non_global is not None else resolved_ips[0]
                ip_str = str(ip_obj)
            except Exception as exc:
                raise ToolError(f"DNS resolution failed for {raw!r}: {exc}") from exc

        if not ip_obj.is_global:
            return {
                "target": raw,
                "ip": ip_str,
                "status": "skipped_non_global_ip",
                "detail": (
                    "Shodan InternetDB only indexes public routable IP addresses; private/loopback skipped."
                ),
                "ports": [],
                "cpes": [],
                "vulns": [],
            }

        cache_key = f"internetdb:{ip_str}"
        cached = await asyncio.to_thread(runtime.cache.get, cache_key)
        if isinstance(cached, dict):
            return {**cached, "cache_hit": True}

        async with httpx.AsyncClient(trust_env=False, timeout=8.0) as client:
            resp = await client.get(f"https://internetdb.shodan.io/{ip_str}")
            if resp.status_code == 404:
                empty_res = {
                    "target": raw,
                    "ip": ip_str,
                    "status": "not_indexed",
                    "ports": [],
                    "cpes": [],
                    "hostnames": [],
                    "tags": [],
                    "vulns": [],
                    "enriched_cves": [],
                }
                await asyncio.to_thread(runtime.cache.set, cache_key, empty_res, 10800)
                return empty_res
            if resp.status_code != 200:
                raise ToolError(f"InternetDB returned HTTP {resp.status_code}")
            data = resp.json()
            kev_map = await runtime.get_kev_catalog(client)

        cves = sorted(
            {str(c).upper() for c in (data.get("vulns") or []) if CVE_RE.match(str(c))}
        )
        enriched_cves: list[dict[str, Any]] = []
        for cid in cves[:30]:
            in_kev = cid in kev_map
            templates = search_nuclei_directory(runtime.templates_root, cve_id=cid, limit=3)
            has_tpl = bool(templates)
            comp_score, comp_level = compute_composite_risk_score(
                base_score=8.0 if in_kev else 6.5,
                impact_weight=9.0 if in_kev else 6.5,
                epss_score=0.5 if in_kev else 0.1,
                in_kev=in_kev,
                has_poc=has_tpl,
                cve_id=cid,
            )
            ssvc = compute_ssvc_decision(
                in_kev=in_kev,
                epss_score=0.5 if in_kev else 0.1,
                has_poc=has_tpl,
                vuln_class="rce" if in_kev else "other",
            )
            enriched_cves.append(
                {
                    "cve_id": cid,
                    "in_cisa_kev": in_kev,
                    "composite_risk_score": comp_score,
                    "composite_risk_level": comp_level,
                    "ssvc_decision": ssvc,
                    "local_nuclei_templates": [t["template"] for t in templates],
                }
            )
        enriched_cves.sort(key=lambda x: x["composite_risk_score"], reverse=True)

        result = {
            "target": raw,
            "ip": ip_str,
            "status": "ok",
            "ports": data.get("ports") or [],
            "cpes": data.get("cpes") or [],
            "hostnames": data.get("hostnames") or [],
            "tags": data.get("tags") or [],
            "vulns": cves,
            "enriched_cves": enriched_cves,
            "cache_hit": False,
        }
        await asyncio.to_thread(runtime.cache.set, cache_key, result, 21600)
        return result

    @server.tool()
    def nuclei_search_templates(
        query: str = "",
        cve_id: str = "",
        tags: list[str] | None = None,
        severity: str = "",
        limit: Annotated[int, Field(ge=1, le=100)] = 25,
    ) -> dict[str, Any]:
        """Search local bundled Nuclei templates by CVE ID, product/shop keyword, tags, or severity.

        Pass any returned `template` relative path directly to `nuclei_scan` to run a fast,
        targeted 3-second CVE/RCE check instead of scanning the entire HTTP template tree.
        """
        matches = search_nuclei_directory(
            runtime.templates_root,
            query=query,
            cve_id=cve_id,
            tags=tags,
            severity=severity,
            limit=limit,
        )
        return {
            "templates_root_available": runtime.templates_root.is_dir(),
            "count": len(matches),
            "templates": matches,
        }

    return server


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--templates-root", type=Path, default=None)
    args = parser.parse_args(arguments)
    runtime = VulnIntelRuntime(templates_root=args.templates_root)
    create_server(runtime).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
