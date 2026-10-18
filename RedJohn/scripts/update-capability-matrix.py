#!/usr/bin/env python3
"""Generate the code catalogue without launching tools or probing the network."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from redjohn.assessment.registry import CAPABILITIES


REPORTS = {
    "browser_discover": "redjohn-mime-restart-verification.md",
    "http_observe": "redjohn-verification.md",
    "headers_audit": "redjohn-verification.md",
    "nuclei_scan": "redjohn-mime-restart-verification.md",
    "session_refresh": "redjohn-authenticated-schema-oast-verification.md",
    "browser_post_capture": "redjohn-mime-restart-verification.md",
    "ffuf_discover": "redjohn-ffuf-verification.md",
    "httpx_probe": "redjohn-projectdiscovery-verification.md",
    "katana_discover": "redjohn-projectdiscovery-verification.md",
    "vulnx_intelligence": "redjohn-projectdiscovery-verification.md",
    "arjun_parameters": "redjohn-specialists-verification.md",
    "sqlmap_validate": "redjohn-specialists-verification.md",
    "dalfox_validate": "redjohn-specialists-verification.md",
    "browser_xss_confirmation": "redjohn-specialists-verification.md",
    "tinja_validate": "redjohn-mime-restart-verification.md",
    "schemathesis_validate": "redjohn-mime-restart-verification.md",
    "oast_correlate": "redjohn-mime-restart-verification.md",
    "oast_poll": "redjohn-mime-restart-verification.md",
}


def generate() -> dict[str, str]:
    rows = []
    implemented = sum(capability.adapter_implemented for capability in CAPABILITIES)
    missing = sum(capability.status == "adapter_not_implemented" for capability in CAPABILITIES)
    deferred = sum(capability.status == "deferred_not_required" for capability in CAPABILITIES)
    lines = [
        "# RedJohn képesség-, forrás- és licenckatalógus",
        "",
        (
            "A katalógus az aktuális `assessment/registry.py` kódjából készül. "
            "A megírt adapter, a helyi konfiguráció és a korábbi valódi mérés külön állapot."
        ),
        "",
        (
            "A `redjohn assess health` mutatja az adott gép telepítési/konfigurációs "
            "állapotát motorindítás nélkül. A JSON itt platformfüggetlen kódkatalógus; "
            "a jegyzőkönyvek történeti futásokat igazolnak, jelenlegi futást nem állítanak."
        ),
        "",
        (
            f"{implemented} implementált képesség, {missing} hiányzó opcionális adapter és "
            f"{deferred} tudatosan halasztott alternatíva szerepel a jelenlegi registryben. A master szerinti "
            "teljes fennmaradó munka: [követett állapot](redjohn-completion-status.md)."
        ),
        "",
        "| Capability | Tool | Adapter | Kódstátusz | Forrás / licenc | Mérési jegyzőkönyv |",
        "|---|---|---|---|---|---|",
    ]
    for capability in CAPABILITIES:
        report = REPORTS.get(capability.id)
        row = {**asdict(capability), "live_verified": False, "recorded_verification_report": report}
        rows.append(row)
        source = (
            f"[forrás]({capability.source})"
            if capability.source.startswith("https://")
            else "RedJohn-native"
        )
        proof = f"[mérés]({report})" if report else "nincs valódi integrációs igazolás"
        cells = [
            f"`{capability.id}`",
            capability.tool,
            "igen" if capability.adapter_implemented else "nincs",
            f"`{capability.status}`",
            f"{source} / {capability.license}",
            proof,
        ]
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
    lines.extend(
        [
            "",
            (
                "A `not_verified_not_redistributed` licenc nincs ellenőrizve; "
                "ilyen motort a RedJohn nem terjeszt. A reviewed engine-ek verziója, "
                "digestje és külön adatforrás-feltételei a hivatkozott jegyzőkönyvekben szerepelnek."
            ),
            "",
            "Generálás a repository gyökeréből:",
            "",
            "```sh",
            "PYTHONPATH=RedJohn .venv/bin/python RedJohn/scripts/update-capability-matrix.py",
            "```",
            "",
        ]
    )
    return {
        "redjohn-capabilities.json": json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
        "redjohn-capabilities.md": "\n".join(lines),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2] / "docs"
    for name, content in generate().items():
        target = root / name
        if args.check:
            if not target.is_file() or target.read_text() != content:
                raise SystemExit(f"stale generated capability catalogue: {name}")
        else:
            target.write_text(content)


if __name__ == "__main__":
    main()
