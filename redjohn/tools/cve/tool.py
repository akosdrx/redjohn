"""Native CVE, OSV.dev, NVD v2, CISA KEV, and FIRST EPSS intelligence tool."""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import re
from typing import Any

import httpx
from agents import RunContextWrapper, function_tool

from redjohn.assessment.cache import CacheBusyError
from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor
from redjohn.tools.cve.cache import CveCache


logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.IGNORECASE)
RCE_CWES = {
    "CWE-77",
    "CWE-78",
    "CWE-94",
    "CWE-95",
    "CWE-96",
    "CWE-434",
    "CWE-502",
    "CWE-1336",
}
AUTH_BYPASS_CWES = {
    "CWE-287",
    "CWE-288",
    "CWE-290",
    "CWE-306",
    "CWE-798",
    "CWE-862",
    "CWE-863",
}
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


def normalize_ecosystem(ecosystem: str) -> str:
    """Normalize package ecosystem names to OSV.dev case-sensitive identifiers."""
    cleaned = ecosystem.strip()
    if not cleaned:
        return ""
    return ECOSYSTEM_ALIASES.get(cleaned.casefold(), cleaned)


_RCE_TOKEN_RE = re.compile(
    r"\b(?:rce|ssti)\b|remote code execution|arbitrary code execution|command injection|"
    r"os command|deserialization|unserialize|template injection|arbitrary file upload|"
    r"unrestricted upload|code injection|eval\(",
    re.IGNORECASE,
)


def classify_vulnerability(summary: str, cwes: list[str]) -> tuple[str, str, float, float]:
    """Return (vuln_class, recommended_skill, impact_weight, probe_cost)."""
    cwe_set = {c.upper().strip() for c in cwes}
    lowered = summary.casefold()
    if cwe_set & RCE_CWES or _RCE_TOKEN_RE.search(summary):
        return "rce", "rce", 10.0, 1.5
    if cwe_set & AUTH_BYPASS_CWES or any(k in lowered for k in AUTH_KEYWORDS):
        return "auth_bypass", "auth", 8.5, 1.5
    if cwe_set & LFI_CWES or "path traversal" in lowered or "local file inclusion" in lowered:
        return "lfi_traversal", "rce", 7.5, 2.0
    if cwe_set & SSRF_CWES or "server-side request forgery" in lowered or "ssrf" in lowered:
        return "ssrf", "injection", 7.5, 2.0
    if cwe_set & SQLI_CWES or "sql injection" in lowered or "sqli" in lowered:
        return "sqli", "injection", 7.0, 4.0
    return "other", "supply", 4.5, 2.5


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


# Keep the private constructor alias for existing integrations importing it.
_CveCache = CveCache
_CACHE = CveCache()
_RESPONSE_MAX_BYTES = 4 * 1024 * 1024


async def _bounded_request(
    client: httpx.AsyncClient, method: str, url: str, **kwargs: Any
) -> httpx.Response:
    """Bound decoded advisory bodies before parsing provider JSON."""
    async with client.stream(method, url, **kwargs) as response:
        payload = bytearray()
        async for chunk in response.aiter_bytes(chunk_size=16384):
            if len(payload) + len(chunk) > _RESPONSE_MAX_BYTES:
                raise ValueError("advisory_response_body_limit_exceeded")
            payload.extend(chunk)
        headers = {
            key: value
            for key, value in response.headers.items()
            if key.casefold() not in {"content-encoding", "content-length", "transfer-encoding"}
        }
        return httpx.Response(
            response.status_code, headers=headers, content=bytes(payload), request=response.request
        )


def _safe_json_or_none(resp: httpx.Response) -> dict[str, Any] | None:
    """Parse a 200 body as a JSON object, or return None.

    A non-JSON 200 body (captive portal, WAF interstitial — realistic on
    pentest networks) must degrade to "provider unavailable" instead of
    raising and discarding the sources that did answer.
    """
    try:
        data = resp.json()
    except ValueError:
        logger.warning("non-JSON 200 body from %s; skipping provider", resp.request.url)
        return None
    return data if isinstance(data, dict) else None


async def _get_kev_catalog(client: httpx.AsyncClient) -> dict[str, dict[str, Any]]:
    async def fetch() -> dict[str, dict[str, Any]]:
        response = await _bounded_request(
            client,
            "GET",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=8.0,
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
            raise TypeError("invalid_kev_catalog")
        retrieved_at = datetime.datetime.now(datetime.UTC).isoformat()
        return {
            str(value["cveID"]).upper(): {
                "source": "CISA KEV",
                "retrieved_at": retrieved_at,
                "data_version": str(body.get("catalogVersion") or "unknown"),
                "date_added": value.get("dateAdded"),
                "product": value.get("product"),
                "vendor": value.get("vendorProject"),
                "short_description": value.get("shortDescription"),
                "known_ransomware": value.get("knownRansomwareCampaignUse"),
            }
            for value in body["vulnerabilities"]
            if isinstance(value, dict) and CVE_RE.match(str(value.get("cveID", "")))
        }

    try:
        catalog, _ = await _CACHE.get_or_refresh("cisa_kev_catalog_v2", fetch, 43200)
        return dict(catalog)
    except (httpx.HTTPError, ValueError, TypeError, TimeoutError, CacheBusyError):
        logger.debug("CISA KEV provider unavailable", exc_info=True)
        return {}


async def _fetch_epss_batch(
    client: httpx.AsyncClient, cve_ids: list[str]
) -> dict[str, tuple[float, float]]:
    valid = sorted({c.strip().upper() for c in cve_ids if CVE_RE.match(c.strip())})
    if not valid:
        return {}
    try:
        resp = await _bounded_request(
            client,
            "GET",
            "https://api.first.org/data/v1/epss",
            params={"cve": ",".join(valid[:40])},
            timeout=8.0,
        )
        if resp.status_code == 200:
            out: dict[str, tuple[float, float]] = {}
            for row in resp.json().get("data") or []:
                if isinstance(row, dict) and row.get("cve"):
                    out[str(row["cve"]).upper()] = (
                        float(row.get("epss") or 0.0),
                        float(row.get("percentile") or 0.0),
                    )
            return out
    except Exception:
        logger.debug("Could not fetch FIRST EPSS scores", exc_info=True)
    return {}


def _extract_nvd_cve_item(cve_obj: dict[str, Any]) -> dict[str, Any]:
    cid = str(cve_obj.get("id") or "").upper()
    descriptions = [
        str(d.get("value") or "")
        for d in (cve_obj.get("descriptions") or [])
        if isinstance(d, dict) and d.get("lang") == "en"
    ]
    summary = (descriptions[0] if descriptions else "")[:800].strip()

    cwes: list[str] = []
    for w in cve_obj.get("weaknesses") or []:
        if not isinstance(w, dict):
            continue
        for desc in w.get("description") or []:
            if isinstance(desc, dict):
                val = str(desc.get("value") or "")
                if val.startswith("CWE-") and val not in cwes:
                    cwes.append(val)

    metrics = cve_obj.get("metrics") or {}
    cvss_vector = ""
    base_score = 0.0
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries and isinstance(entries[0], dict):
            cvss_data = entries[0].get("cvssData") or {}
            cvss_vector = str(cvss_data.get("vectorString") or "")
            base_score = float(cvss_data.get("baseScore") or 0.0)
            break

    refs = [
        str(r.get("url"))
        for r in (cve_obj.get("references") or [])[:8]
        if isinstance(r, dict) and r.get("url")
    ]
    vuln_class, rec_skill, impact_w, _cost = classify_vulnerability(summary, cwes)
    return {
        "source": "NVD CVE API v2",
        "source_modified_at": cve_obj.get("lastModified"),
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "id": cid,
        "cve_ids": [cid] if cid else [],
        "summary": summary,
        "cwes": cwes,
        "cvss_vector": cvss_vector,
        "base_score": base_score,
        "vuln_class": vuln_class,
        "recommended_skill": rec_skill,
        "affected_ranges": [],
        "fixed_versions": [],
        "references": refs,
        "_impact_weight": impact_w,
    }


def _extract_osv_item(item: dict[str, Any]) -> dict[str, Any]:
    osv_id = str(item.get("id") or "")
    aliases = [str(a) for a in (item.get("aliases") or []) if isinstance(a, str)]
    cve_ids = sorted({a.upper() for a in [osv_id, *aliases] if CVE_RE.match(a)})
    summary = str(item.get("summary") or item.get("details") or "")[:600].strip()
    db_specific = item.get("database_specific") or {}
    raw_cwes = db_specific.get("cwe_ids") or []
    cwes = [str(c) for c in raw_cwes if isinstance(c, str)]

    affected_ranges: list[str] = []
    fixed_versions: list[str] = []
    for aff in item.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg_name = str((aff.get("package") or {}).get("name") or "")
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            parts: list[str] = []
            for ev in rng.get("events") or []:
                if not isinstance(ev, dict):
                    continue
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

    refs = [
        str(r.get("url"))
        for r in (item.get("references") or [])[:6]
        if isinstance(r, dict) and r.get("url")
    ]
    vuln_class, rec_skill, impact_w, _cost = classify_vulnerability(summary, cwes)
    return {
        "source": "OSV API v1",
        "data_version": str(item.get("schema_version") or "unknown"),
        "source_modified_at": item.get("modified"),
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "id": osv_id,
        "cve_ids": cve_ids,
        "summary": summary,
        "cwes": cwes,
        "cvss_vector": "",
        "base_score": 0.0,
        "vuln_class": vuln_class,
        "recommended_skill": rec_skill,
        "affected_ranges": affected_ranges[:8],
        "fixed_versions": sorted(set(fixed_versions))[:8],
        "references": refs,
        "_impact_weight": impact_w,
    }


def _enrich_record(
    rec: dict[str, Any],
    kev_map: dict[str, dict[str, Any]],
    epss_map: dict[str, tuple[float, float]],
) -> dict[str, Any]:
    cve_ids: list[str] = rec.get("cve_ids") or []
    primary_cve = cve_ids[0] if cve_ids else ""
    in_kev = any(cid in kev_map for cid in cve_ids)
    kev_detail = next((kev_map[cid] for cid in cve_ids if cid in kev_map), None)
    epss_score = 0.0
    epss_percentile = 0.0
    for cid in cve_ids:
        if cid in epss_map:
            epss_score, epss_percentile = epss_map[cid]
            break

    refs: list[str] = rec.get("references") or []
    has_poc = in_kev or any("exploit" in r.casefold() or "poc" in r.casefold() for r in refs)
    impact_w = float(rec.pop("_impact_weight", 5.0))
    base_score = float(rec.get("base_score") or 0.0)
    vuln_class = str(rec.get("vuln_class") or "other")

    comp_score, comp_level = compute_composite_risk_score(
        base_score=base_score,
        impact_weight=impact_w,
        epss_score=epss_score,
        in_kev=in_kev,
        has_poc=has_poc,
        cve_id=primary_cve,
    )
    ssvc = compute_ssvc_decision(
        in_kev=in_kev,
        epss_score=epss_score,
        has_poc=has_poc,
        vuln_class=vuln_class,
        base_score=base_score,
    )
    fast_path = vuln_class in ("rce", "auth_bypass", "lfi_traversal") or in_kev or ssvc == "Act"
    rec["in_cisa_kev"] = in_kev
    if kev_detail:
        rec["cisa_kev_detail"] = kev_detail
    rec["epss_score"] = epss_score
    rec["epss_percentile"] = epss_percentile
    rec["composite_risk_score"] = comp_score
    rec["composite_risk_level"] = comp_level
    rec["ssvc_decision"] = ssvc
    rec["fast_path_rce"] = fast_path
    rec["dispatch_tier"] = "TIER_1_IMMEDIATE" if fast_path else "STANDARD"
    return rec


async def _lookup_single_cve(
    cve_id: str, *, governor: ResourceGovernor | None = None
) -> dict[str, Any]:
    clean = cve_id.strip().upper()
    cache_key = f"cve_lookup:{clean}"
    result, cache_hit = await _CACHE.get_or_refresh(
        cache_key,
        lambda: _fetch_single_cve(clean),
        21600,
        admit=(
            lambda: governor.acquire("worker", _RESPONSE_MAX_BYTES * 16, owner_process_only=True)
        )
        if governor is not None
        else None,
    )
    return {**result, "cache_hit": cache_hit}


async def _fetch_single_cve(clean: str) -> dict[str, Any]:
    nvd_headers = {"Accept": "application/json"}
    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    if nvd_key:
        nvd_headers["apiKey"] = nvd_key

    osv_data: dict[str, Any] = {}
    nvd_item: dict[str, Any] = {}
    async with httpx.AsyncClient(trust_env=False, timeout=12.0) as client:
        osv_req = _bounded_request(client, "GET", f"https://api.osv.dev/v1/vulns/{clean}")
        nvd_req = _bounded_request(
            client,
            "GET",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": clean},
            headers=nvd_headers,
        )
        kev_req = _get_kev_catalog(client)
        epss_req = _fetch_epss_batch(client, [clean])
        osv_resp, nvd_resp, kev_map, epss_map = await asyncio.gather(
            osv_req, nvd_req, kev_req, epss_req, return_exceptions=True
        )
        if isinstance(osv_resp, httpx.Response) and osv_resp.status_code == 200:
            osv_body = _safe_json_or_none(osv_resp)
            if osv_body is not None:
                if not isinstance(osv_body.get("id"), str):
                    raise TypeError("invalid_osv_advisory")
                osv_data = osv_body
        if isinstance(nvd_resp, httpx.Response) and nvd_resp.status_code == 200:
            nvd_body = _safe_json_or_none(nvd_resp)
            if nvd_body is not None:
                if not isinstance(nvd_body.get("vulnerabilities"), list):
                    raise TypeError("invalid_nvd_advisory_collection")
                vulns = nvd_body["vulnerabilities"]
                if vulns and isinstance(vulns[0], dict):
                    nvd_item = vulns[0].get("cve") or {}
        if not isinstance(kev_map, dict):
            kev_map = {}
        if not isinstance(epss_map, dict):
            epss_map = {}

    if nvd_item:
        rec = _extract_nvd_cve_item(nvd_item)
        if osv_data:
            osv_rec = _extract_osv_item(osv_data)
            rec["affected_ranges"] = osv_rec["affected_ranges"]
            rec["fixed_versions"] = osv_rec["fixed_versions"]
            for c in osv_rec["cwes"]:
                if c not in rec["cwes"]:
                    rec["cwes"].append(c)
    elif osv_data:
        rec = _extract_osv_item(osv_data)
        if clean not in rec["cve_ids"]:
            rec["cve_ids"].insert(0, clean)
    else:
        # A missing/failed advisory source is not proof of an unaffected target.
        return {
            "success": False,
            "query_type": "cve_id",
            "cve_id": clean,
            "coverage_status": "blocked",
            "error": "advisory_not_available",
            "cache_hit": False,
        }

    enriched = _enrich_record(rec, kev_map, epss_map)
    return {
        "success": True,
        "query_type": "cve_id",
        "cve": enriched,
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "data_version": "osv-v1+nvd-v2+kev-v2+epss-v1",
        "source_status": {
            "osv": "available" if osv_data else "unavailable",
            "nvd": "available" if nvd_item else "unavailable",
            "kev": "available" if kev_map else "unavailable",
            "epss": "available" if epss_map else "unavailable",
        },
        "cache_hit": False,
    }


async def _lookup_product_or_package(
    product: str,
    version: str = "",
    ecosystem: str = "",
    *,
    governor: ResourceGovernor | None = None,
) -> dict[str, Any]:
    pkg = product.strip()
    ver = version.strip().lstrip("vV")
    eco_norm = normalize_ecosystem(ecosystem)
    # Maven/package/prerelease identifiers may be case-sensitive. JSON framing
    # also prevents delimiter collisions between product, version and ecosystem.
    cache_key = json.dumps(["pkg_lookup", pkg, ver, eco_norm], separators=(",", ":"))
    result, cache_hit = await _CACHE.get_or_refresh(
        cache_key,
        lambda: _fetch_product_or_package(pkg, ver, eco_norm),
        21600,
        admit=(
            lambda: governor.acquire("worker", _RESPONSE_MAX_BYTES * 16, owner_process_only=True)
        )
        if governor is not None
        else None,
    )
    return {**result, "cache_hit": cache_hit}


async def _fetch_product_or_package(pkg: str, ver: str, eco_norm: str) -> dict[str, Any]:
    default_ecos = ["Packagist", "npm", "PyPI", "Maven", "Go", "RubyGems", "crates.io", "NuGet"]
    ecosystems_to_try = [eco_norm] if eco_norm else default_ecos

    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    withdrawn_filtered = 0
    sources_available: list[str] = []

    nvd_headers = {"Accept": "application/json"}
    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    if nvd_key:
        nvd_headers["apiKey"] = nvd_key

    async with httpx.AsyncClient(trust_env=False, timeout=12.0) as client:
        osv_tasks = []
        for eco in ecosystems_to_try:
            payload: dict[str, Any] = {"package": {"name": pkg, "ecosystem": eco}}
            if ver:
                payload["version"] = ver
            osv_tasks.append(
                _bounded_request(client, "POST", "https://api.osv.dev/v1/query", json=payload)
            )

        nvd_kw = f"{pkg} {ver}".strip() if ver else pkg
        nvd_task = _bounded_request(
            client,
            "GET",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": nvd_kw, "resultsPerPage": 20},
            headers=nvd_headers,
        )
        kev_task = _get_kev_catalog(client)

        gathered = await asyncio.gather(*osv_tasks, nvd_task, kev_task, return_exceptions=True)
        osv_responses = gathered[:-2]
        nvd_resp = gathered[-2]
        kev_map = gathered[-1] if isinstance(gathered[-1], dict) else {}

        for eco, resp in zip(ecosystems_to_try, osv_responses, strict=True):
            if not isinstance(resp, httpx.Response) or resp.status_code != 200:
                continue
            body = _safe_json_or_none(resp)
            if body is None:
                continue
            if not isinstance(body.get("vulns", []), list):
                raise TypeError("invalid_osv_query_collection")
            sources_available.append(f"osv:{eco}")
            for raw in body.get("vulns") or []:
                if not isinstance(raw, dict):
                    continue
                if raw.get("withdrawn"):
                    withdrawn_filtered += 1
                    continue
                vid = str(raw.get("id") or "")
                if not vid or vid in seen_ids:
                    continue
                seen_ids.add(vid)
                records.append(_extract_osv_item(raw))

        if isinstance(nvd_resp, httpx.Response) and nvd_resp.status_code == 200:
            nvd_body = _safe_json_or_none(nvd_resp)
            if nvd_body is not None:
                if not isinstance(nvd_body.get("vulnerabilities"), list):
                    raise TypeError("invalid_nvd_query_collection")
                sources_available.append("nvd")
                for item in nvd_body["vulnerabilities"]:
                    if not isinstance(item, dict):
                        continue
                    cve_obj = item.get("cve") or {}
                    cid = str(cve_obj.get("id") or "").upper()
                    if not cid or cid in seen_ids:
                        continue
                    if any(cid in (r.get("cve_ids") or []) for r in records):
                        continue
                    seen_ids.add(cid)
                    records.append(_extract_nvd_cve_item(cve_obj))

        all_cves: list[str] = []
        for r in records:
            for cid in r.get("cve_ids") or []:
                if cid not in all_cves:
                    all_cves.append(cid)
        epss_map = await _fetch_epss_batch(client, all_cves[:40])

    if not sources_available or (
        not records and len(sources_available) < len(ecosystems_to_try) + 1
    ):
        return {
            "success": False,
            "query_type": "product_version",
            "coverage_status": "blocked",
            "error": "advisory_providers_unavailable",
            "cache_hit": False,
        }
    enriched_records = [_enrich_record(r, kev_map, epss_map) for r in records]
    enriched_records.sort(
        key=lambda r: (
            bool(r.get("fast_path_rce")),
            float(r.get("composite_risk_score") or 0.0),
            float(r.get("epss_score") or 0.0),
        ),
        reverse=True,
    )

    return {
        "success": True,
        "query_type": "product_version",
        "product": pkg,
        "version": ver,
        "ecosystem": eco_norm or "auto",
        "total_matches": len(enriched_records),
        "withdrawn_filtered": withdrawn_filtered,
        "fast_path_rce_count": sum(1 for r in enriched_records if r.get("fast_path_rce")),
        "vulnerabilities": enriched_records[:25],
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "data_version": "osv-v1+nvd-v2+kev-v2+epss-v1",
        "source_status": {
            "available": sources_available,
            "coverage_status": "partial"
            if len(sources_available) < len(ecosystems_to_try) + 1
            else "completed",
        },
        "cache_hit": False,
    }


async def lookup_cve_json(
    product: str = "",
    version: str = "",
    cve_id: str = "",
    ecosystem: str = "",
    *,
    governor: ResourceGovernor | None = None,
) -> str:
    """Execute CVE & exploit intelligence lookup and return a JSON string."""
    clean_cve = (cve_id or "").strip().upper()
    clean_prod = (product or "").strip()
    if clean_cve and CVE_RE.match(clean_cve):
        res = await _lookup_single_cve(clean_cve, governor=governor)
        return json.dumps(res, ensure_ascii=False, default=str)
    if clean_prod and CVE_RE.match(clean_prod.upper()):
        res = await _lookup_single_cve(clean_prod.upper(), governor=governor)
        return json.dumps(res, ensure_ascii=False, default=str)
    if not clean_prod:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "Provide either a valid `cve_id` (e.g. 'CVE-2024-12345') or a non-empty "
                    "`product` name (e.g. product='prestashop', version='1.7.8.6')."
                ),
            },
            ensure_ascii=False,
        )
    res = await _lookup_product_or_package(
        product=clean_prod,
        version=version or "",
        ecosystem=ecosystem or "",
        governor=governor,
    )
    return json.dumps(res, ensure_ascii=False, default=str)


@function_tool(timeout=35)
async def lookup_cve(
    ctx: RunContextWrapper,
    product: str = "",
    version: str = "",
    cve_id: str = "",
    ecosystem: str = "",
) -> str:
    """Query OSV.dev, NVD v2, CISA KEV, and FIRST EPSS for CVEs and exploit intelligence.

    Call this tool IMMEDIATELY whenever reconnaissance, fingerprinting, or source review
    identifies a software product, CMS, e-commerce platform (e.g., PrestaShop, WordPress,
    WooCommerce, Magento, Shopware, Joomla, Drupal), framework (Laravel, Next.js, Spring,
    Django, Struts), service (OpenSSH, Apache, Nginx, Tomcat), dependency, or CVE ID.

    Returns advisories ranked by Impact-First priority:
    - ``fast_path_rce=True`` (RCE, Command Injection, SSTI, Deserialization, Auth Bypass,
      or active CISA KEV) is always ranked at the top as ``TIER_1_IMMEDIATE`` so you test
      high-impact RCE / Auth Bypass vectors BEFORE spending time on slow blind SQLi.
    - Includes 0-100 ``composite_risk_score`` (with CISA KEV Hard Override >= 76 CRITICAL),
      CISA SSVC v2 decision (``Act``, ``Attend``, ``Track*``, ``Track``), FIRST EPSS
      probability, affected version ranges, fixed versions, and recommended RedJohn skill.

    Args:
        product: Package, CMS, plugin, framework, or server name (e.g. ``"prestashop"``,
            ``"wordpress"``, ``"woocommerce"``, ``"laravel/framework"``, ``"openssh"``).
        version: Detected version string (e.g. ``"1.7.8.6"``, ``"6.4.2"``). Optional.
        cve_id: Specific CVE identifier (e.g. ``"CVE-2022-35914"``). If provided, looks up
            that exact CVE across OSV.dev, NVD v2, CISA KEV, and FIRST EPSS.
        ecosystem: Optional ecosystem hint (``"Packagist"``, ``"npm"``, ``"PyPI"``,
            ``"Maven"``, ``"Go"``, ``"RubyGems"``, ``"NuGet"``, ``"crates.io"``).
    """
    context = ctx.context if isinstance(ctx.context, dict) else {}
    governor = context.get("assessment_governor")
    try:
        if isinstance(governor, ResourceGovernor):
            governor.sample()
            _CACHE.restrict_budget(
                governor.envelope.cache_max_bytes,
                pressure=governor.snapshot()["pressure"] != "normal",
            )
        return await lookup_cve_json(
            product=product,
            version=version,
            cve_id=cve_id,
            ecosystem=ecosystem,
            governor=governor if isinstance(governor, ResourceGovernor) else None,
        )
    except (
        TimeoutError,
        CacheBusyError,
        ResourceAdmissionError,
        httpx.HTTPError,
        ValueError,
        TypeError,
    ):
        return json.dumps(
            {
                "success": False,
                "coverage_status": "blocked",
                "error": "advisory_refresh_unavailable",
                "cache_hit": False,
            }
        )
