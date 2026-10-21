# RedJohn: httpx / Katana / VulnX módosított fájlok

2026-10-18. 68 módosított/új fájl, a megőrzött mérési bizonyítékokkal együtt.

A korábbi Git-átrendezés nem feladattörlés. Nincs destruktív Git-művelet.
A manifestek önmagukra/ciklusokra mutató hash-ei, az ignored managed binárisok és a privát állapotok kizárva.

[Ellenőrzési jelentés](redjohn-projectdiscovery-verification.md) · [SHA-jegyzék](redjohn-projectdiscovery-changed-files.json)

## Forrás, teszt és dokumentáció

| Fájl | Változás |
|---|---|
| [.github/workflows/redjohn-remote-egress.yml](../.github/workflows/redjohn-remote-egress.yml) | modified |
| [RedJohn/README.md](../RedJohn/README.md) | modified |
| [RedJohn/docs/projectdiscovery-adapters.md](../RedJohn/docs/projectdiscovery-adapters.md) | added |
| [RedJohn/examples/assessment-projectdiscovery.json](../RedJohn/examples/assessment-projectdiscovery.json) | added |
| [RedJohn/redjohn/assessment/browser_proxy.py](../RedJohn/redjohn/assessment/browser_proxy.py) | modified |
| [RedJohn/redjohn/assessment/cli.py](../RedJohn/redjohn/assessment/cli.py) | modified |
| [RedJohn/redjohn/assessment/discovery_tools.py](../RedJohn/redjohn/assessment/discovery_tools.py) | added |
| [RedJohn/redjohn/assessment/pinned_tools.py](../RedJohn/redjohn/assessment/pinned_tools.py) | added |
| [RedJohn/redjohn/assessment/registry.py](../RedJohn/redjohn/assessment/registry.py) | modified |
| [RedJohn/redjohn/assessment/runtime.py](../RedJohn/redjohn/assessment/runtime.py) | modified |
| [RedJohn/redjohn/assessment/scheduler.py](../RedJohn/redjohn/assessment/scheduler.py) | modified |
| [RedJohn/redjohn/assessment/vulnx.py](../RedJohn/redjohn/assessment/vulnx.py) | added |
| [RedJohn/redjohn/tools/hunt/bounded_worker.py](../RedJohn/redjohn/tools/hunt/bounded_worker.py) | modified |
| [RedJohn/scripts/install-projectdiscovery-pinned.py](../RedJohn/scripts/install-projectdiscovery-pinned.py) | added |
| [RedJohn/scripts/projectdiscovery-pins.json](../RedJohn/scripts/projectdiscovery-pins.json) | added |
| [RedJohn/tests/test_projectdiscovery_contract.py](../RedJohn/tests/test_projectdiscovery_contract.py) | added |
| [RedJohn/tests/test_projectdiscovery_live.py](../RedJohn/tests/test_projectdiscovery_live.py) | added |
| [docs/redjohn-implementation-audit.md](../docs/redjohn-implementation-audit.md) | modified |
| [docs/redjohn-projectdiscovery-verification.md](../docs/redjohn-projectdiscovery-verification.md) | added |
| [docs/redjohn-requirements.md](../docs/redjohn-requirements.md) | modified |
| [docs/third-party-references.json](../docs/third-party-references.json) | modified |

## Megőrzött valós mérési bizonyítékok

| Fájl | Változás |
|---|---|
| [docs/measurements/projectdiscovery/cleanup.json](../docs/measurements/projectdiscovery/cleanup.json) | added |
| [docs/measurements/projectdiscovery/linux/auth-e2e.json](../docs/measurements/projectdiscovery/linux/auth-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/automatic-session-e2e.json](../docs/measurements/projectdiscovery/linux/automatic-session-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/binary-integrity.json](../docs/measurements/projectdiscovery/linux/binary-integrity.json) | added |
| [docs/measurements/projectdiscovery/linux/browser-token-e2e.json](../docs/measurements/projectdiscovery/linux/browser-token-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/chain-loopback.json](../docs/measurements/projectdiscovery/linux/chain-loopback.json) | added |
| [docs/measurements/projectdiscovery/linux/chain-remote.json](../docs/measurements/projectdiscovery/linux/chain-remote.json) | added |
| [docs/measurements/projectdiscovery/linux/continuous-refresh-e2e.json](../docs/measurements/projectdiscovery/linux/continuous-refresh-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/derived.json](../docs/measurements/projectdiscovery/linux/derived.json) | added |
| [docs/measurements/projectdiscovery/linux/dns-https.json](../docs/measurements/projectdiscovery/linux/dns-https.json) | added |
| [docs/measurements/projectdiscovery/linux/ffuf-e2e-loopback.json](../docs/measurements/projectdiscovery/linux/ffuf-e2e-loopback.json) | added |
| [docs/measurements/projectdiscovery/linux/ffuf-e2e-remote.json](../docs/measurements/projectdiscovery/linux/ffuf-e2e-remote.json) | added |
| [docs/measurements/projectdiscovery/linux/https-e2e.json](../docs/measurements/projectdiscovery/linux/https-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/httpx-install.json](../docs/measurements/projectdiscovery/linux/httpx-install.json) | added |
| [docs/measurements/projectdiscovery/linux/katana-install.json](../docs/measurements/projectdiscovery/linux/katana-install.json) | added |
| [docs/measurements/projectdiscovery/linux/kernel.txt](../docs/measurements/projectdiscovery/linux/kernel.txt) | added |
| [docs/measurements/projectdiscovery/linux/mypy.txt](../docs/measurements/projectdiscovery/linux/mypy.txt) | added |
| [docs/measurements/projectdiscovery/linux/nuclei-live.json](../docs/measurements/projectdiscovery/linux/nuclei-live.json) | added |
| [docs/measurements/projectdiscovery/linux/post-nuclei-live.json](../docs/measurements/projectdiscovery/linux/post-nuclei-live.json) | added |
| [docs/measurements/projectdiscovery/linux/post-refresh-e2e.json](../docs/measurements/projectdiscovery/linux/post-refresh-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/processes-after-tests.txt](../docs/measurements/projectdiscovery/linux/processes-after-tests.txt) | added |
| [docs/measurements/projectdiscovery/linux/python-packages.txt](../docs/measurements/projectdiscovery/linux/python-packages.txt) | added |
| [docs/measurements/projectdiscovery/linux/remote-auth-e2e.json](../docs/measurements/projectdiscovery/linux/remote-auth-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/source-hash-check.txt](../docs/measurements/projectdiscovery/linux/source-hash-check.txt) | added |
| [docs/measurements/projectdiscovery/linux/tests.junit.xml](../docs/measurements/projectdiscovery/linux/tests.junit.xml) | added |
| [docs/measurements/projectdiscovery/linux/tests.txt](../docs/measurements/projectdiscovery/linux/tests.txt) | added |
| [docs/measurements/projectdiscovery/linux/vulnx-install.json](../docs/measurements/projectdiscovery/linux/vulnx-install.json) | added |
| [docs/measurements/projectdiscovery/linux/vulnx-public.json](../docs/measurements/projectdiscovery/linux/vulnx-public.json) | added |
| [docs/measurements/projectdiscovery/macos/binary-integrity.json](../docs/measurements/projectdiscovery/macos/binary-integrity.json) | added |
| [docs/measurements/projectdiscovery/macos/chain-loopback.json](../docs/measurements/projectdiscovery/macos/chain-loopback.json) | added |
| [docs/measurements/projectdiscovery/macos/derived.json](../docs/measurements/projectdiscovery/macos/derived.json) | added |
| [docs/measurements/projectdiscovery/macos/go-test.txt](../docs/measurements/projectdiscovery/macos/go-test.txt) | added |
| [docs/measurements/projectdiscovery/macos/go-vet.txt](../docs/measurements/projectdiscovery/macos/go-vet.txt) | added |
| [docs/measurements/projectdiscovery/macos/httpx-install.json](../docs/measurements/projectdiscovery/macos/httpx-install.json) | added |
| [docs/measurements/projectdiscovery/macos/katana-install.json](../docs/measurements/projectdiscovery/macos/katana-install.json) | added |
| [docs/measurements/projectdiscovery/macos/mypy-final.txt](../docs/measurements/projectdiscovery/macos/mypy-final.txt) | added |
| [docs/measurements/projectdiscovery/macos/ruff-final.txt](../docs/measurements/projectdiscovery/macos/ruff-final.txt) | added |
| [docs/measurements/projectdiscovery/macos/tests.junit.xml](../docs/measurements/projectdiscovery/macos/tests.junit.xml) | added |
| [docs/measurements/projectdiscovery/macos/tests.txt](../docs/measurements/projectdiscovery/macos/tests.txt) | added |
| [docs/measurements/projectdiscovery/macos/typescript.txt](../docs/measurements/projectdiscovery/macos/typescript.txt) | added |
| [docs/measurements/projectdiscovery/macos/viewer-assets.json](../docs/measurements/projectdiscovery/macos/viewer-assets.json) | added |
| [docs/measurements/projectdiscovery/macos/viewer-build.txt](../docs/measurements/projectdiscovery/macos/viewer-build.txt) | added |
| [docs/measurements/projectdiscovery/macos/vulnx-install.json](../docs/measurements/projectdiscovery/macos/vulnx-install.json) | added |
| [docs/measurements/projectdiscovery/performance-summary.json](../docs/measurements/projectdiscovery/performance-summary.json) | added |
| [docs/measurements/projectdiscovery/preservation.json](../docs/measurements/projectdiscovery/preservation.json) | added |
| [docs/measurements/projectdiscovery/source-hashes.json](../docs/measurements/projectdiscovery/source-hashes.json) | added |
| [docs/measurements/projectdiscovery/test-summary.json](../docs/measurements/projectdiscovery/test-summary.json) | added |
